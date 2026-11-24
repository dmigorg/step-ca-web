package server

import (
	"strings"
	"testing"
)

func TestACMEUpdatePreservesUnrelatedSettings(t *testing.T) {
	t.Parallel()
	doc := settingsDocument{
		"details": map[string]any{"ACME": map[string]any{
			"challenges": []any{"HTTP_01", "DEVICE_ATTEST_01"}, "forceCn": true,
		}},
		"claims": map[string]any{"disableRenewal": true},
	}
	defaults := durations{Min: "5m", Default: "24h", Max: "24h"}
	update := acmeSettingsUpdate{Durations: durations{Default: "2h"}, Challenges: []string{"DNS_01"}}
	if err := applyACMEUpdate(doc, update, defaults); err != nil {
		t.Fatalf("updating ACME settings: %v", err)
	}
	acme := doc.object("details").object("ACME")
	if got := acme["forceCn"]; got != true {
		t.Errorf("forceCn = %v, want true", got)
	}
	methods, _ := acme["challenges"].([]string)
	if got := strings.Join(methods, ","); got != "DNS_01,DEVICE_ATTEST_01" {
		t.Errorf("challenges = %q, want DNS_01,DEVICE_ATTEST_01", got)
	}
	if got := doc.object("claims")["disableRenewal"]; got != true {
		t.Errorf("disableRenewal = %v, want true", got)
	}
}

func TestProtectedDNSChecksWildcardDepthAndApex(t *testing.T) {
	t.Parallel()
	allow := namesPolicy{DNS: []string{"*.example.local"}}
	if err := protectDNS(allow, namesPolicy{}, false, []string{"host.example.local"}); err != nil {
		t.Errorf("protected one-level host rejected: %v", err)
	}
	for _, name := range []string{"example.local", "nested.host.example.local"} {
		if err := protectDNS(allow, namesPolicy{}, false, []string{name}); err == nil {
			t.Errorf("protectDNS(%s) allowed a wildcard to match the wrong number of labels", name)
		}
	}
	if err := protectDNS(allow, namesPolicy{DNS: []string{"host.example.local"}}, false, []string{"host.example.local"}); err == nil {
		t.Error("protectDNS allowed an explicit deny to block a protected name")
	}
}
