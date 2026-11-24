package config

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	ListenAddr            string
	HTTPSListen           string
	TLSCert               string
	TLSKey                string
	CAURL                 string
	TLSSkipVerify         bool
	SessionSecret         string
	SessionMaxAge         int
	InventoryFile         string
	LoginProvisioner      string
	AdminCertFile         string
	AdminKeyFile          string
	AdminConfirmationHash []byte
	WebOrigin             string
}

func Parse() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.ListenAddr, "listen", envOrDefault("STEP_WEB_LISTEN", ":8080"), "HTTP listen address")
	flag.StringVar(&cfg.HTTPSListen, "https-listen", envOrDefault("STEP_WEB_HTTPS_LISTEN", ""), "HTTPS listen address (optional)")
	flag.StringVar(&cfg.TLSCert, "tls-cert", os.Getenv("STEP_TLS_CERT"), "TLS certificate PEM file path")
	flag.StringVar(&cfg.TLSKey, "tls-key", os.Getenv("STEP_TLS_KEY"), "TLS private key PEM file path")
	flag.StringVar(&cfg.CAURL, "ca-url", os.Getenv("STEP_CA_URL"), "Upstream step-ca URL (required)")
	flag.BoolVar(&cfg.TLSSkipVerify, "tls-skip-verify", true, "Skip TLS verification for upstream CA")
	flag.StringVar(&cfg.SessionSecret, "session-secret", os.Getenv("STEP_SESSION_SECRET"), "Session encryption secret (auto-generated if empty)")
	sessionSecretFile := flag.String("session-secret-file", os.Getenv("STEP_WEB_SESSION_SECRET_FILE"), "Read the session encryption secret from this file")
	flag.IntVar(&cfg.SessionMaxAge, "session-max-age", 3600, "Session lifetime in seconds")

	flag.StringVar(&cfg.InventoryFile, "inventory-file", os.Getenv("STEP_WEB_INVENTORY_FILE"), "Path to the certificate inventory JSON file")

	flag.StringVar(&cfg.LoginProvisioner, "login-provisioner", os.Getenv("STEP_WEB_LOGIN_PROVISIONER"), "JWK provisioner used for web sign-in")
	flag.StringVar(&cfg.AdminCertFile, "admin-cert", os.Getenv("STEP_WEB_ADMIN_CERT"), "Admin API client certificate chain")
	flag.StringVar(&cfg.AdminKeyFile, "admin-key", os.Getenv("STEP_WEB_ADMIN_KEY"), "Admin API client private key")
	flag.StringVar(&cfg.WebOrigin, "web-origin", os.Getenv("STEP_WEB_ORIGIN"), "HTTPS origin allowed to submit settings changes")
	confirmationFile := flag.String("admin-confirmation-hash-file", os.Getenv("STEP_WEB_ADMIN_CONFIRMATION_HASH_FILE"), "File containing the SHA-256 hash of the random settings confirmation code")

	flag.Parse()

	if cfg.CAURL == "" {
		return nil, fmt.Errorf("--ca-url is required (or set STEP_CA_URL env var)")
	}

	if cfg.ListenAddr == "" && cfg.HTTPSListen == "" {
		return nil, fmt.Errorf("at least one of --listen or --https-listen must be set")
	}

	if cfg.HTTPSListen != "" {
		if cfg.TLSCert == "" || cfg.TLSKey == "" {
			// Will auto-generate self-signed cert
			fmt.Println("WARNING: --https-listen set without --tls-cert/--tls-key, will auto-generate self-signed certificate")
		}
	}

	if *sessionSecretFile != "" {
		if cfg.SessionSecret != "" {
			return nil, fmt.Errorf("configure the session secret either directly or through a file")
		}
		secret, err := readSessionSecret(*sessionSecretFile)
		if err != nil {
			return nil, err
		}
		cfg.SessionSecret = secret
	}

	if cfg.SessionSecret == "" {
		secret, err := generateSecret(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate session secret: %w", err)
		}
		cfg.SessionSecret = secret
		fmt.Println("Generated random session secret (sessions will not survive restarts)")
	}

	if cfg.AdminCertFile != "" || cfg.AdminKeyFile != "" || *confirmationFile != "" || cfg.WebOrigin != "" {
		if cfg.AdminCertFile == "" || cfg.AdminKeyFile == "" || *confirmationFile == "" || cfg.LoginProvisioner == "" {
			return nil, fmt.Errorf("admin settings require a certificate, key, confirmation hash file, and a sign-in provisioner")
		}
		if err := validateAdminURL(cfg.CAURL); err != nil {
			return nil, fmt.Errorf("invalid admin CA URL: %w", err)
		}
		if err := validateAdminURL(cfg.WebOrigin); err != nil {
			return nil, fmt.Errorf("invalid web origin: %w", err)
		}
		raw, err := os.ReadFile(*confirmationFile)
		if err != nil {
			return nil, fmt.Errorf("read admin confirmation hash: %w", err)
		}
		cfg.AdminConfirmationHash, err = hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(cfg.AdminConfirmationHash) != 32 {
			return nil, fmt.Errorf("admin confirmation hash must contain 64 hexadecimal characters")
		}
	}

	return cfg, nil
}

func readSessionSecret(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read session secret file: %w", err)
	}

	secret := strings.TrimSpace(string(data))
	if len(secret) < 32 {
		return "", fmt.Errorf("session secret file must contain at least 32 bytes of key material")
	}
	return secret, nil
}

func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func generateSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func validateAdminURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("expected an HTTPS origin")
	}
	return nil
}
