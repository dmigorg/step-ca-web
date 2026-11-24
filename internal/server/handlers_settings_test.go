package server

import (
	"net/http"
	"net/http/httptest"
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
