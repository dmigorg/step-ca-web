package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/xix-support/step-ca-web/internal/ca"
)

type settingsDocument map[string]any

type durations struct {
	Min     string `json:"min"`
	Default string `json:"default"`
	Max     string `json:"max"`
}

type acmeSettings struct {
	Revision             string    `json:"revision"`
	Durations            durations `json:"durations"`
	Defaults             durations `json:"defaults"`
	UseDefaultChallenges bool      `json:"useDefaultChallenges"`
	Challenges           []string  `json:"challenges"`
	AdditionalChallenges []string  `json:"additionalChallenges"`
}

type acmeSettingsUpdate struct {
	Revision             string    `json:"revision"`
	Durations            durations `json:"durations"`
	UseDefaultChallenges bool      `json:"useDefaultChallenges"`
	Challenges           []string  `json:"challenges"`
}

const acmeAdminPath = "/admin/provisioners/acme"

func (doc settingsDocument) revision() string {
	// Admin documents have already been decoded from JSON.
	payload, _ := json.Marshal(doc)
	hash := sha256.Sum256(payload)
	return hex.EncodeToString(hash[:])
}

func (doc settingsDocument) object(key string) settingsDocument {
	object, ok := doc[key].(map[string]any)
	if !ok {
		return settingsDocument{}
	}
	return object
}

func (doc settingsDocument) set(key string, value settingsDocument) {
	if len(value) == 0 {
		delete(doc, key)
		return
	}
	doc[key] = map[string]any(value)
}

func (doc settingsDocument) string(key string) string {
	value, _ := doc[key].(string)
	return value
}

func (doc settingsDocument) strings(key string) []string {
	values, _ := doc[key].([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if str, ok := value.(string); ok {
			result = append(result, str)
		}
	}
	return result
}

func (s *Server) settingsReady(w http.ResponseWriter) bool {
	w.Header().Set("Cache-Control", "private, no-store")
	if s.adminClient == nil {
		writeError(w, http.StatusServiceUnavailable, "CA administration is not configured")
		return false
	}
	return true
}

func (s *Server) readSettingsUpdate(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Header.Get("Origin") != strings.TrimRight(s.cfg.WebOrigin, "/") {
		writeError(w, http.StatusForbidden, "Settings changes require a same-origin request")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, http.StatusBadRequest, "Invalid settings request")
		return false
	}
	return true
}

func (s *Server) authorizeSettingsWrite(w http.ResponseWriter, r *http.Request) bool {
	session, err := s.sessMgr.Get(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Sign in to change CA settings")
		return false
	}
	if s.cfg.LoginProvisioner == "" || session.ProvisionerName != s.cfg.LoginProvisioner {
		writeError(w, http.StatusForbidden, "This session cannot change CA settings")
		return false
	}
	return true
}

func (s *Server) settingsError(w http.ResponseWriter, r *http.Request, err error) {
	var caErr *ca.CAError
	if errors.As(err, &caErr) {
		switch caErr.StatusCode {
		case http.StatusBadRequest, http.StatusConflict, http.StatusNotFound:
			writeError(w, caErr.StatusCode, caErr.Message)
			return
		}
	}
	slog.ErrorContext(r.Context(), "CA settings request failed", "err", err)
	writeError(w, http.StatusBadGateway, "The CA Admin API could not complete the request")
}

func (s *Server) auditSettings(r *http.Request, resource, revision string) {
	session, err := s.sessMgr.Get(r)
	if err != nil {
		slog.WarnContext(r.Context(), "CA settings changed", "resource", resource, "revision", revision)
		return
	}
	slog.InfoContext(r.Context(), "CA settings changed", "resource", resource, "revision", revision,
		"login_provisioner", session.ProvisionerName)
}

func (s *Server) effectiveDefaults() durations {
	return durations{Min: s.cfg.CATLSMin, Default: s.cfg.CATLSDefault, Max: s.cfg.CATLSMax}
}

func isServerChallenge(challenge string) bool {
	switch challenge {
	case "HTTP_01", "DNS_01", "TLS_ALPN_01":
		return true
	default:
		return false
	}
}

func readACMESettings(doc settingsDocument, defaults durations) acmeSettings {
	stored := doc.object("claims").object("x509").object("durations")
	challenges := doc.object("details").object("ACME").strings("challenges")
	result := acmeSettings{
		Revision: doc.revision(), Defaults: defaults, UseDefaultChallenges: len(challenges) == 0,
		Durations:  durations{Min: stored.string("min"), Default: stored.string("default"), Max: stored.string("max")},
		Challenges: []string{}, AdditionalChallenges: []string{},
	}
	for _, challenge := range challenges {
		if isServerChallenge(challenge) {
			result.Challenges = append(result.Challenges, challenge)
		} else {
			result.AdditionalChallenges = append(result.AdditionalChallenges, challenge)
		}
	}
	if result.UseDefaultChallenges {
		result.Challenges = []string{"HTTP_01", "DNS_01", "TLS_ALPN_01"}
	}
	return result
}

func validateDurations(values, defaults durations) error {
	selected := []string{values.Min, values.Default, values.Max}
	inherited := []string{defaults.Min, defaults.Default, defaults.Max}
	parsed := make([]time.Duration, len(selected))
	for i, value := range selected {
		if value == "" {
			value = inherited[i]
		}
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return fmt.Errorf("use positive durations such as 5m, 24h or 168h")
		}
		parsed[i] = duration
	}
	if parsed[0] > parsed[1] || parsed[1] > parsed[2] {
		return fmt.Errorf("minimum lifetime must be at most the default, and the default at most the maximum")
	}
	return nil
}

func applyACMEUpdate(doc settingsDocument, update acmeSettingsUpdate, defaults durations) error {
	if err := validateDurations(update.Durations, defaults); err != nil {
		return err
	}
	current := readACMESettings(doc, defaults)
	challenges := make([]string, 0, 3+len(current.AdditionalChallenges))
	if update.UseDefaultChallenges && len(current.AdditionalChallenges) > 0 {
		return fmt.Errorf("CA defaults would remove an advanced challenge; select explicit methods instead")
	}
	if !update.UseDefaultChallenges {
		seen := make(map[string]bool)
		for _, challenge := range update.Challenges {
			if !isServerChallenge(challenge) || seen[challenge] {
				return fmt.Errorf("select distinct supported ACME challenge methods")
			}
			seen[challenge] = true
			challenges = append(challenges, challenge)
		}
		if len(challenges) == 0 {
			return fmt.Errorf("select at least one server challenge or use CA defaults")
		}
		challenges = append(challenges, current.AdditionalChallenges...)
	}

	claims := doc.object("claims")
	x509 := claims.object("x509")
	lifetimes := x509.object("durations")
	for field, value := range map[string]string{"min": update.Durations.Min, "default": update.Durations.Default, "max": update.Durations.Max} {
		delete(lifetimes, field)
		if value != "" {
			lifetimes[field] = value
		}
	}
	x509.set("durations", lifetimes)
	claims.set("x509", x509)
	doc.set("claims", claims)

	details := doc.object("details")
	acme := details.object("ACME")
	delete(acme, "challenges")
	if len(challenges) > 0 {
		acme["challenges"] = challenges
	}
	// Keep the ACME protobuf oneof present even when using all defaults.
	details["ACME"] = map[string]any(acme)
	doc.set("details", details)
	return nil
}

func (s *Server) handleACMESettings(w http.ResponseWriter, r *http.Request) {
	if !s.settingsReady(w) {
		return
	}

	var update acmeSettingsUpdate
	if r.Method == http.MethodPut {
		if !s.authorizeSettingsWrite(w, r) || !s.readSettingsUpdate(w, r, &update) {
			return
		}
		s.settingsMu.Lock()
		defer s.settingsMu.Unlock()
	}

	var current settingsDocument
	if err := s.adminClient.Request(r.Context(), http.MethodGet, acmeAdminPath, nil, &current); err != nil {
		s.settingsError(w, r, err)
		return
	}
	if current.string("name") != "acme" || current.string("type") != "ACME" {
		writeError(w, http.StatusConflict, "The acme provisioner is unavailable")
		return
	}
	defaults := s.effectiveDefaults()
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, readACMESettings(current, defaults))
		return
	}
	if update.Revision != current.revision() {
		writeError(w, http.StatusConflict, "Settings changed since this page was opened; reload and try again")
		return
	}
	if err := applyACMEUpdate(current, update, defaults); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var saved settingsDocument
	if err := s.adminClient.Request(r.Context(), http.MethodPut, acmeAdminPath, current, &saved); err != nil {
		s.settingsError(w, r, err)
		return
	}
	result := readACMESettings(saved, defaults)
	s.auditSettings(r, "ACME provisioner", result.Revision)
	writeJSON(w, http.StatusOK, result)
}
