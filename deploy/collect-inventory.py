#!/usr/bin/env python3
"""Keep an inventory of X.509 certificates observed in the step-ca journal."""

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def certificate_from(message):
    try:
        if message.startswith("{"):
            fields = json.loads(message)
        else:
            fields = dict(
                token.split("=", 1) for token in shlex.split(message)
                if "=" in token
            )
    except ValueError:
        return None

    path = str(fields.get("path", ""))
    status = str(fields.get("status", ""))
    serial = str(fields.get("serial", ""))
    if not (re.fullmatch(r"2[0-9]{2}", status) and re.fullmatch(r"[0-9]+", serial)
            and fields.get("certificate")):
        return None

    if re.fullmatch(r"/acme/[^/]+/(certificate|finalize)/[^/]+", path):
        source = "ACME"
    elif re.fullmatch(r"/(?:1\.0/)?(?:sign|renew|rekey)", path):
        source = "CA API"
    else:
        return None

    try:
        begin = datetime.fromisoformat(fields["valid-from"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(fields["valid-to"].replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return None
    if begin.tzinfo is None or end.tzinfo is None:
        return None

    return {
        "serial": serial,
        "subject": str(fields.get("subject", "")),
        "sans": str(fields.get("sans", "")),
        "source": source,
        "notBefore": begin.astimezone(timezone.utc).isoformat(),
        "notAfter": end.astimezone(timezone.utc).isoformat(),
    }


def read_journal(cursor, certificates):
    args = ["/usr/bin/journalctl", "--unit", "step-ca.service", "--output", "json", "--no-pager"]
    if cursor:
        args.append("--after-cursor=" + cursor)
    with subprocess.Popen(args, stdout=subprocess.PIPE, text=True) as journal:
        for line in journal.stdout:
            entry = json.loads(line)
            cursor = entry["__CURSOR"]
            message = entry.get("MESSAGE")
            if not isinstance(message, str):
                continue
            certificate = certificate_from(message)
            if certificate is not None:
                certificates[certificate["serial"]] = certificate
        code = journal.wait()
    if code:
        raise subprocess.CalledProcessError(code, args[:6])
    return cursor


def collect(path):
    state = {"cursor": "", "certificates": []}
    if path.exists():
        state = json.loads(path.read_text(encoding="utf-8"))
    certificates = {entry["serial"]: entry for entry in state["certificates"]}
    try:
        cursor = read_journal(state["cursor"], certificates)
    except subprocess.CalledProcessError:
        if not state["cursor"]:
            raise
        cursor = read_journal("", certificates)

    payload = {"cursor": cursor, "certificates": list(certificates.values())}
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as tmp:
        staged = Path(tmp.name)
        try:
            json.dump(payload, tmp, ensure_ascii=False)
            tmp.flush()
            os.fsync(tmp.fileno())
            staged.chmod(0o640)
            staged.replace(path)
        finally:
            staged.unlink(missing_ok=True)


if __name__ == "__main__":
    collect(Path(sys.argv[1]))
