package ca

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	baseURL         string
	httpClient      *http.Client
	rootFingerprint string
}

type HealthResponse struct {
	Status string `json:"status"`
}

type VersionResponse struct {
	Version                     string `json:"version"`
	RequireClientAuthentication bool   `json:"requireClientAuthentication,omitempty"`
}

type Certificate struct {
	Raw []byte `json:"-"`
}

func (c *Certificate) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return fmt.Errorf("failed to decode PEM certificate")
	}
	c.Raw = block.Bytes
	return nil
}

type RootsResponse struct {
	Certificates []string `json:"crts"`
}

type IntermediatesResponse struct {
	Certificates []string `json:"crts"`
}

type ProvisionerKey struct {
	Type         string          `json:"type"`
	Name         string          `json:"name"`
	Key          json.RawMessage `json:"key,omitempty"`
	EncryptedKey string          `json:"encryptedKey,omitempty"`
	Claims       json.RawMessage `json:"claims,omitempty"`
}

type ProvisionersResponse struct {
	Provisioners []ProvisionerKey `json:"provisioners"`
	NextCursor   string           `json:"nextCursor,omitempty"`
}

type SignRequest struct {
	CSR          string          `json:"csr"`
	OTT          string          `json:"ott"`
	NotAfter     string          `json:"notAfter,omitempty"`
	NotBefore    string          `json:"notBefore,omitempty"`
	TemplateData json.RawMessage `json:"templateData,omitempty"`
}

type SignResponse struct {
	Crt       string   `json:"crt"`
	CA        string   `json:"ca"`
	CertChain []string `json:"certChain,omitempty"`
}

type RevokeRequest struct {
	Serial     string `json:"serial"`
	OTT        string `json:"ott"`
	ReasonCode int    `json:"reasonCode"`
	Reason     string `json:"reason,omitempty"`
	Passive    bool   `json:"passive"`
}

type RevokeResponse struct {
	Status string `json:"status"`
}

type CAError struct {
	StatusCode int
	Message    string
}

func (e *CAError) Error() string {
	return fmt.Sprintf("step-ca error (HTTP %d): %s", e.StatusCode, e.Message)
}

func NewClient(baseURL string, skipTLSVerify bool) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipTLSVerify,
		},
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.httpClient.Do(req)
}

func (c *Client) handleResponse(resp *http.Response, target interface{}) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil {
			msg := errResp.Message
			if msg == "" {
				msg = errResp.Error
			}
			if msg != "" {
				return &CAError{StatusCode: resp.StatusCode, Message: msg}
			}
		}
		return &CAError{StatusCode: resp.StatusCode, Message: string(body)}
	}

	if target != nil && len(body) > 0 {
		if err := json.Unmarshal(body, target); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/health", nil)
	if err != nil {
		return nil, err
	}
	var result HealthResponse
	if err := c.handleResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Version(ctx context.Context) (*VersionResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/version", nil)
	if err != nil {
		return nil, err
	}
	var result VersionResponse
	if err := c.handleResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Roots(ctx context.Context) (*RootsResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/roots", nil)
	if err != nil {
		return nil, err
	}
	var result RootsResponse
	if err := c.handleResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Intermediates(ctx context.Context) (*IntermediatesResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/intermediates", nil)
	if err != nil {
		return nil, err
	}
	var result IntermediatesResponse
	if err := c.handleResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Provisioners(ctx context.Context) (*ProvisionersResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/provisioners", nil)
	if err != nil {
		return nil, err
	}
	var result ProvisionersResponse
	if err := c.handleResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) ProvisionerKey(ctx context.Context, kid string) (string, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/provisioners/"+kid+"/encrypted-key", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return "", &CAError{StatusCode: resp.StatusCode, Message: string(body)}
	}

	var encryptedKey string
	if err := json.Unmarshal(body, &encryptedKey); err != nil {
		return string(body), nil
	}
	return encryptedKey, nil
}

func (c *Client) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/sign", req)
	if err != nil {
		return nil, err
	}
	var result SignResponse
	if err := c.handleResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Revoke(ctx context.Context, req *RevokeRequest) (*RevokeResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/revoke", req)
	if err != nil {
		return nil, err
	}
	var result RevokeResponse
	if err := c.handleResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) CRL(ctx context.Context) ([]byte, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/crl", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, &CAError{StatusCode: resp.StatusCode, Message: string(body)}
	}

	return body, nil
}

func (c *Client) GetRootFingerprint(ctx context.Context) (string, error) {
	if c.rootFingerprint != "" {
		return c.rootFingerprint, nil
	}

	roots, err := c.Roots(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to fetch roots: %w", err)
	}

	if len(roots.Certificates) == 0 {
		return "", fmt.Errorf("no root certificates found")
	}

	block, _ := pem.Decode([]byte(roots.Certificates[0]))
	if block == nil {
		return "", fmt.Errorf("failed to decode root certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse root certificate: %w", err)
	}

	hash := sha256.Sum256(cert.Raw)
	c.rootFingerprint = hex.EncodeToString(hash[:])

	return c.rootFingerprint, nil
}
