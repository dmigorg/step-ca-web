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

func TestInventoryRequiresSessionAndReturnsOnlyCertificateData(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "inventory.json")
	data := `{"cursor":"journal-cursor","certificates":[{"serial":"123","subject":"app.example","sans":"app.example","source":"ACME","notBefore":"2026-11-23T12:00:00Z","notAfter":"2026-11-24T12:00:00Z","extra":"discarded"}]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager("inventory-test-session-secret-32", 3600)
	handler := New(nil, manager, &config.Config{InventoryFile: path}).SetupRoutes()

	request := httptest.NewRequest(http.MethodGet, "/api/certificates/issued", nil)
	anonymous := httptest.NewRecorder()
	handler.ServeHTTP(anonymous, request)
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("inventory without session returned %d, want %d", anonymous.Code, http.StatusUnauthorized)
	}

	login := httptest.NewRecorder()
	if err := manager.Create(login, &session.SessionData{}); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range login.Result().Cookies() {
		request.AddCookie(cookie)
	}
	signedIn := httptest.NewRecorder()
	handler.ServeHTTP(signedIn, request)
	if signedIn.Code != http.StatusOK {
		t.Fatalf("inventory with session returned %d, want %d", signedIn.Code, http.StatusOK)
	}
	body := signedIn.Body.String()
	if !strings.Contains(body, `"serial":"123"`) || strings.Contains(body, "journal-cursor") || strings.Contains(body, "discarded") {
		t.Errorf("inventory response = %q, want the certificate fields only", body)
	}
	if got := signedIn.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Errorf("inventory Cache-Control header = %q, want private, no-store", got)
	}
}
