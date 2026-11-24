package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/xix-support/step-ca-web/internal/ca"
)

const policyAdminPath = "/admin/policy"

type namesPolicy struct {
	DNS []string `json:"dns"`
	IPs []string `json:"ips"`
}

type policyFields struct {
	Allow              namesPolicy `json:"allow"`
	Deny               namesPolicy `json:"deny"`
	AllowWildcardNames bool        `json:"allowWildcardNames"`
}

type policySettings struct {
	policyFields
	Revision string        `json:"revision"`
	Exists   bool          `json:"exists"`
	Previous *policyFields `json:"previous,omitempty"`
}

type policyUpdate struct {
	policyFields
	Revision string `json:"revision"`
}

func policyFrom(doc settingsDocument) policyFields {
	x509 := doc.object("x509")
	allow, deny := x509.object("allow"), x509.object("deny")
	wildcard, _ := x509["allowWildcardNames"].(bool)
	return policyFields{
		Allow:              namesPolicy{DNS: allow.strings("dns"), IPs: allow.strings("ips")},
		Deny:               namesPolicy{DNS: deny.strings("dns"), IPs: deny.strings("ips")},
		AllowWildcardNames: wildcard,
	}
}

func applyPolicyUpdate(doc settingsDocument, fields policyFields) {
	x509 := doc.object("x509")
	allowed := x509.object("allow")
	denied := x509.object("deny")
	for _, list := range []struct {
		doc   settingsDocument
		names namesPolicy
	}{
		{doc: allowed, names: fields.Allow},
		{doc: denied, names: fields.Deny},
	} {
		delete(list.doc, "dns")
		delete(list.doc, "ips")
		if len(list.names.DNS) > 0 {
			list.doc["dns"] = list.names.DNS
		}
		if len(list.names.IPs) > 0 {
			list.doc["ips"] = list.names.IPs
		}
	}
	x509.set("allow", allowed)
	x509.set("deny", denied)
	delete(x509, "allowWildcardNames")
	if fields.AllowWildcardNames {
		x509["allowWildcardNames"] = true
	}
	doc.set("x509", x509)
}

func (s *Server) policyResponse(doc settingsDocument) policySettings {
	response := policySettings{
		policyFields: policyFrom(doc), Revision: doc.revision(),
		Exists: len(doc) > 0,
	}
	if s.cfg.PolicyBackupFile == "" {
		return response
	}
	raw, err := os.ReadFile(s.cfg.PolicyBackupFile)
	if err == nil {
		var previous settingsDocument
		if json.Unmarshal(raw, &previous) == nil {
			fields := policyFrom(previous)
			response.Previous = &fields
		}
	}
	return response
}

func (s *Server) backupPolicy(current settingsDocument) error {
	if s.cfg.PolicyBackupFile == "" {
		return nil
	}
	f, err := os.CreateTemp(filepath.Dir(s.cfg.PolicyBackupFile), ".previous-policy-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := json.NewEncoder(f).Encode(current); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.cfg.PolicyBackupFile)
}

func (s *Server) handlePolicySettings(w http.ResponseWriter, r *http.Request) {
	if !s.settingsReady(w) {
		return
	}

	var update policyUpdate
	if r.Method == http.MethodPut {
		if !s.authorizeSettingsWrite(w, r) || !s.readSettingsUpdate(w, r, &update) {
			return
		}
		s.settingsMu.Lock()
		defer s.settingsMu.Unlock()
	}

	current := settingsDocument{}
	err := s.adminClient.Request(r.Context(), http.MethodGet, policyAdminPath, nil, &current)
	var caErr *ca.CAError
	if err != nil && (!errors.As(err, &caErr) || caErr.StatusCode != http.StatusNotFound) {
		s.settingsError(w, r, err)
		return
	}
	exists := err == nil
	if r.Method == http.MethodGet {
		result := s.policyResponse(current)
		result.Exists = exists
		writeJSON(w, http.StatusOK, result)
		return
	}
	if update.Revision != current.revision() {
		writeError(w, http.StatusConflict, "Settings changed since this page was opened; reload and try again")
		return
	}

	// Applying changes edits nested objects in place. Serialize the previously
	// saved version before working on a separate copy.
	original, err := json.Marshal(current)
	if err != nil {
		s.settingsError(w, r, err)
		return
	}
	next := settingsDocument{}
	if err := json.Unmarshal(original, &next); err != nil {
		s.settingsError(w, r, err)
		return
	}
	applyPolicyUpdate(next, update.policyFields)
	if !exists && len(next) == 0 {
		writeJSON(w, http.StatusOK, s.policyResponse(next))
		return
	}
	if err := s.backupPolicy(current); err != nil {
		s.settingsError(w, r, fmt.Errorf("save previous issuance policy: %w", err))
		return
	}

	var saved settingsDocument
	switch {
	case len(next) == 0:
		err = s.adminClient.Request(r.Context(), http.MethodDelete, policyAdminPath, nil, nil)
		saved = settingsDocument{}
	case exists:
		err = s.adminClient.Request(r.Context(), http.MethodPut, policyAdminPath, next, &saved)
	default:
		err = s.adminClient.Request(r.Context(), http.MethodPost, policyAdminPath, next, &saved)
	}
	if err != nil {
		s.settingsError(w, r, err)
		return
	}
	result := s.policyResponse(saved)
	s.auditSettings(r, "authority issuance policy", result.Revision)
	writeJSON(w, http.StatusOK, result)
}
