#!/usr/bin/env bash
set -euo pipefail

credentials=/etc/step-ca-web/admin
next=$(mktemp "$credentials/.client.XXXXXXXX")
trap 'rm -f -- "$next"' EXIT

/usr/bin/step ca renew --force --out "$next" \
    --ca-url "${STEP_WEB_ADMIN_CA_URL:?}" --root "${STEP_WEB_ADMIN_CA_ROOT:?}" \
    "$credentials/client.crt" "$credentials/client.key"
chgrp step-ca-web-admin "$next"
chmod 0640 "$next"
mv -f "$next" "$credentials/client.crt"
