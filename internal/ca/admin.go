package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// AdminClient authenticates to step-ca using a short-lived X5C token per request.
type AdminClient struct {
	client   *Client
	certFile string
	keyFile  string
}

// NewAdminClient constructs a client with upstream TLS verification enabled.
func NewAdminClient(baseURL, certFile, keyFile string) *AdminClient {
	client := NewClient(strings.TrimRight(baseURL, "/"), false)
	client.httpClient.Timeout = 12 * time.Second
	client.httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &AdminClient{client: client, certFile: certFile, keyFile: keyFile}
}

// Request sends a signed request to the CA Admin API. Each request loads the
// certificate from disk so the web service can pick up a renewed certificate.
func (a *AdminClient) Request(ctx context.Context, method, path string, body, target any) error {
	var input io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode admin request: %w", err)
		}
		input = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.client.baseURL+path, input)
	if err != nil {
		return fmt.Errorf("create admin request: %w", err)
	}
	token, err := a.sign(req.URL.String())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("call admin API: %w", err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
		resp.Body.Close()
		return fmt.Errorf("unexpected admin API redirect: %d", resp.StatusCode)
	}
	return a.client.handleResponse(resp, target)
}

func (a *AdminClient) sign(audience string) (string, error) {
	chain, err := tls.LoadX509KeyPair(a.certFile, a.keyFile)
	if err != nil {
		return "", fmt.Errorf("load admin certificate: %w", err)
	}
	key, ok := chain.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return "", fmt.Errorf("admin credential must use an ECDSA P-256 key")
	}
	leaf, err := x509.ParseCertificate(chain.Certificate[0])
	if err != nil {
		return "", fmt.Errorf("parse admin certificate: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.Subject.CommonName == "" {
		return "", fmt.Errorf("admin certificate must be valid and specify a common name")
	}
	x5c := make([]string, len(chain.Certificate))
	for i, der := range chain.Certificate {
		x5c[i] = base64.StdEncoding.EncodeToString(der)
	}
	options := new(jose.SignerOptions).WithType("JWT").WithHeader("x5c", x5c)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, options)
	if err != nil {
		return "", fmt.Errorf("create admin token signer: %w", err)
	}
	id, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("generate admin token ID: %w", err)
	}
	claims := jwt.Claims{
		ID: id, Issuer: "step-admin-client/1.0", Subject: leaf.Subject.CommonName,
		Audience: jwt.Audience{audience}, IssuedAt: jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute)),
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}
