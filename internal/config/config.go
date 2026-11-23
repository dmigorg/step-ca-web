package config

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ListenAddr    string
	HTTPSListen   string
	TLSCert       string
	TLSKey        string
	CAURL         string
	TLSSkipVerify bool
	SessionSecret string
	SessionMaxAge int
	InventoryFile string
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
