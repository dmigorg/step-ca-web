package server

import (
	"errors"
	"net/http"

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
	Revision string `json:"revision"`
	Exists   bool   `json:"exists"`
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

func policyResponse(doc settingsDocument, exists bool) policySettings {
	return policySettings{
		policyFields: policyFrom(doc),
		Revision:     doc.revision(),
		Exists:       exists,
	}
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
		writeJSON(w, http.StatusOK, policyResponse(current, exists))
		return
	}
	if update.Revision != current.revision() {
		writeError(w, http.StatusConflict, "Settings changed since this page was opened; reload and try again")
		return
	}

	applyPolicyUpdate(current, update.policyFields)
	hasPolicy := len(current) > 0
	if !exists && !hasPolicy {
		writeJSON(w, http.StatusOK, policyResponse(current, false))
		return
	}

	var saved settingsDocument
	switch {
	case !hasPolicy:
		err = s.adminClient.Request(r.Context(), http.MethodDelete, policyAdminPath, nil, nil)
		saved = settingsDocument{}
	case exists:
		err = s.adminClient.Request(r.Context(), http.MethodPut, policyAdminPath, current, &saved)
	default:
		err = s.adminClient.Request(r.Context(), http.MethodPost, policyAdminPath, current, &saved)
	}
	if err != nil {
		s.settingsError(w, r, err)
		return
	}
	result := policyResponse(saved, hasPolicy)
	s.auditSettings(r, "authority issuance policy", result.Revision)
	writeJSON(w, http.StatusOK, result)
}
