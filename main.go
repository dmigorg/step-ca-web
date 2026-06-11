package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xix-support/step-ca-web/internal/ca"
	"github.com/xix-support/step-ca-web/internal/config"
	"github.com/xix-support/step-ca-web/internal/server"
	"github.com/xix-support/step-ca-web/internal/session"
)

func main() {
	cfg, err := config.Parse()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	caClient := ca.NewClient(cfg.CAURL, cfg.TLSSkipVerify)
	sessMgr := session.NewManager(cfg.SessionSecret, cfg.SessionMaxAge)
	srv := server.New(caClient, sessMgr, cfg)

	handler := srv.SetupRoutes()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var httpServer, httpsServer *http.Server
	errCh := make(chan error, 2)

	if cfg.ListenAddr != "" {
		httpServer = &http.Server{
			Addr:    cfg.ListenAddr,
			Handler: handler,
		}
		go func() {
			log.Printf("HTTP server listening on %s", cfg.ListenAddr)
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("HTTP server error: %w", err)
			}
		}()
	}

	if cfg.HTTPSListen != "" {
		tlsCert, tlsKey := cfg.TLSCert, cfg.TLSKey
		if tlsCert == "" || tlsKey == "" {
			log.Println("Generating self-signed TLS certificate...")
			certPEM, keyPEM, err := generateSelfSignedCert()
			if err != nil {
				log.Fatalf("Failed to generate self-signed certificate: %v", err)
			}
			tmpCert := "cert.pem"
			tmpKey := "key.pem"
			if err := os.WriteFile(tmpCert, certPEM, 0600); err != nil {
				log.Fatalf("Failed to write temp cert: %v", err)
			}
			if err := os.WriteFile(tmpKey, keyPEM, 0600); err != nil {
				log.Fatalf("Failed to write temp key: %v", err)
			}
			tlsCert = tmpCert
			tlsKey = tmpKey
			defer os.Remove(tmpCert)
			defer os.Remove(tmpKey)
			log.Println("Self-signed certificate generated successfully")
		}

		httpsServer = &http.Server{
			Addr:    cfg.HTTPSListen,
			Handler: handler,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
		go func() {
			log.Printf("HTTPS server listening on %s", cfg.HTTPSListen)
			if err := httpsServer.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("HTTPS server error: %w", err)
			}
		}()
	}

	_ = ctx

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("Received signal %v, shutting down...", sig)
	case err := <-errCh:
		log.Printf("Server error: %v", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if httpServer != nil {
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}
	if httpsServer != nil {
		if err := httpsServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTPS server shutdown error: %v", err)
		}
	}

	log.Println("Server stopped")
}

func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Step CA Web Interface"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}
