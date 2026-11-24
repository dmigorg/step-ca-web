package server

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/xix-support/step-ca-web/internal/config"
	"github.com/xix-support/step-ca-web/internal/session"
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

func TestApplyPolicyUpdateLeavesRuleValidationToCA(t *testing.T) {
	t.Parallel()
	doc := settingsDocument{"x509": map[string]any{
		"allow": map[string]any{"emails": []any{"@example.local"}},
	}}
	applyPolicyUpdate(doc, policyFields{Deny: namesPolicy{DNS: []string{"ca.example.local"}}})
	x509 := doc.object("x509")
	got, _ := x509.object("deny")["dns"].([]string)
	if strings.Join(got, ",") != "ca.example.local" {
		t.Errorf("denied DNS sent to step-ca = %v, want ca.example.local", got)
	}
	if got := x509.object("allow").strings("emails"); strings.Join(got, ",") != "@example.local" {
		t.Errorf("existing allowed emails = %v, want @example.local", got)
	}
}

func TestApplyPolicyUpdateKeepsSuperAdminInDNSAllowlist(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		dns  []string
		want []string
	}{
		{name: "custom names", dns: []string{"*.example.local"}, want: []string{"*.example.local", "step"}},
		{name: "already present", dns: []string{"*.example.local", "STEP"}, want: []string{"*.example.local", "STEP"}},
		{name: "no DNS allowlist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := settingsDocument{}
			applyPolicyUpdate(doc, policyFields{Allow: namesPolicy{DNS: tc.dns}})
			got, _ := doc.object("x509").object("allow")["dns"].([]string)
			if !slices.Equal(got, tc.want) {
				t.Errorf("DNS sent to step-ca = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPolicyResponseHidesDefaultAllowedDNS(t *testing.T) {
	t.Parallel()

	doc := settingsDocument{"x509": map[string]any{
		"allow": map[string]any{"dns": []any{"*.example.local", "step"}},
		"deny":  map[string]any{"dns": []any{"step"}},
	}}
	revision := doc.revision()
	response := policyResponse(doc, true)
	if !slices.Equal(response.Allow.DNS, []string{"*.example.local"}) {
		t.Errorf("visible allow DNS = %v, want [*.example.local]", response.Allow.DNS)
	}
	if !slices.Equal(response.Deny.DNS, []string{"step"}) {
		t.Errorf("visible deny DNS = %v, want [step]", response.Deny.DNS)
	}
	if response.Revision != revision || doc.revision() != revision {
		t.Error("filtering out the default changed the underlying policy revision")
	}
}

func TestSettingsWriteAccessUsesCurrentSession(t *testing.T) {
	t.Parallel()

	const origin = "https://ca.example.local"
	manager := session.NewManager("settings-test-session-secret-32", 3600)
	handler := New(nil, manager, &config.Config{
		CAURL: origin, AdminCertFile: "unused.crt", AdminKeyFile: "unused.key",
		LoginProvisioner: "mainadmin", WebOrigin: origin,
	}).SetupRoutes()

	for _, route := range []string{"/api/settings/acme", "/api/settings/issuance-policy"} {
		for _, test := range []struct {
			name, provisioner, origin string
			want                      int
		}{
			{name: "anonymous", origin: origin, want: http.StatusUnauthorized},
			{name: "other provisioner", provisioner: "another", origin: origin, want: http.StatusForbidden},
			{name: "cross origin", provisioner: "mainadmin", origin: "https://another.example.local", want: http.StatusForbidden},
			{name: "missing origin", provisioner: "mainadmin", want: http.StatusForbidden},
			{name: "admin reaches form validation", provisioner: "mainadmin", origin: origin, want: http.StatusBadRequest},
		} {
			t.Run(route+"/"+test.name, func(t *testing.T) {
				t.Parallel()
				request := httptest.NewRequest(http.MethodPut, route, strings.NewReader("{"))
				if test.origin != "" {
					request.Header.Set("Origin", test.origin)
				}
				if test.provisioner != "" {
					login := httptest.NewRecorder()
					if err := manager.Create(login, &session.SessionData{ProvisionerName: test.provisioner}); err != nil {
						t.Fatal(err)
					}
					request.AddCookie(login.Result().Cookies()[0])
				}

				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != test.want {
					t.Errorf("PUT %s (%s) returned %d, want %d", route, test.name, response.Code, test.want)
				}
			})
		}
	}
}
