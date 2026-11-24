package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestPreparingPolicyBackupDoesNotReplacePreviousPolicy(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "previous.json")
	const saved = `{"x509":{"allow":{"dns":["old.example.local"]}}}`
	if err := os.WriteFile(path, []byte(saved), 0600); err != nil {
		t.Fatal(err)
	}
	server := Server{cfg: &config.Config{PolicyBackupFile: path}}
	staged, err := server.stagePolicyBackup(settingsDocument{"x509": map[string]any{"deny": map[string]any{"dns": []string{"candidate.example.local"}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(staged) })
	if got, err := os.ReadFile(path); err != nil || string(got) != saved {
		t.Fatalf("previous policy after staging = %q, %v, want %s", got, err, saved)
	}
}
