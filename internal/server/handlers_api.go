package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/xix-support/step-ca-web/internal/ca"
	"github.com/xix-support/step-ca-web/internal/cnf"
	"github.com/xix-support/step-ca-web/internal/csr"
)

type SignRequest struct {
	CN           string          `json:"cn"`
	SANs         []string        `json:"sans"`
	NotBefore    string          `json:"notBefore,omitempty"`
	NotAfter     string          `json:"notAfter,omitempty"`
	CSR          string          `json:"csr,omitempty"`
	TemplateData json.RawMessage `json:"templateData,omitempty"`
}

type SignResult struct {
	Certificate string   `json:"certificate"`
	PrivateKey  string   `json:"privateKey,omitempty"`
	CAChain     string   `json:"caChain"`
	CertChain   []string `json:"certChain,omitempty"`
}

type RevokeRequest struct {
	Serial     string `json:"serial"`
	ReasonCode int    `json:"reasonCode"`
	Reason     string `json:"reason,omitempty"`
}

type ParseCertRequest struct {
	PEM string `json:"pem"`
}

type CertInfo struct {
	Version        int       `json:"version"`
	Serial         string    `json:"serial"`
	SignatureAlgo  string    `json:"signatureAlgo"`
	PublicKeyAlgo  string    `json:"publicKeyAlgo"`
	PublicKeySize  int       `json:"publicKeySize"`
	Subject        string    `json:"subject"`
	SubjectFull    string    `json:"subjectFull"`
	Issuer         string    `json:"issuer"`
	IssuerFull     string    `json:"issuerFull"`
	NotBefore      time.Time `json:"notBefore"`
	NotAfter       time.Time `json:"notAfter"`
	DNSNames       []string  `json:"dnsNames,omitempty"`
	IPAddresses    []string  `json:"ipAddresses,omitempty"`
	EmailAddresses []string  `json:"emailAddresses,omitempty"`
	URIs           []string  `json:"uris,omitempty"`
	KeyUsage       string    `json:"keyUsage"`
	ExtKeyUsage    []string  `json:"extKeyUsage,omitempty"`
	IsCA           bool      `json:"isCA"`
	SelfSigned     bool      `json:"selfSigned"`
	OCSPServers    []string  `json:"ocspServers,omitempty"`
	CRLDistPoints  []string  `json:"crlDistPoints,omitempty"`
	IssuerURLs     []string  `json:"issuerURLs,omitempty"`
}

type CSRInfo struct {
	Subject        string            `json:"subject"`
	SubjectFull    string            `json:"subjectFull"`
	PublicKeyAlgo  string            `json:"publicKeyAlgo"`
	PublicKeySize  int               `json:"publicKeySize"`
	SignatureAlgo  string            `json:"signatureAlgo"`
	DNSNames       []string          `json:"dnsNames,omitempty"`
	IPAddresses    []string          `json:"ipAddresses,omitempty"`
	EmailAddresses []string          `json:"emailAddresses,omitempty"`
	URIs           []string          `json:"uris,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health, err := s.caClient.Health(r.Context())
	if err != nil {
		log.Printf("Health check failed: %v", err)
		writeError(w, http.StatusBadGateway, "CA unavailable")
		return
	}
	writeJSON(w, http.StatusOK, health)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	version, err := s.caClient.Version(r.Context())
	if err != nil {
		log.Printf("Version check failed: %v", err)
		writeError(w, http.StatusBadGateway, "CA unavailable")
		return
	}
	writeJSON(w, http.StatusOK, version)
}

func (s *Server) handleRoots(w http.ResponseWriter, r *http.Request) {
	roots, err := s.caClient.Roots(r.Context())
	if err != nil {
		log.Printf("Failed to fetch roots: %v", err)
		writeError(w, http.StatusBadGateway, "failed to fetch roots")
		return
	}
	writeJSON(w, http.StatusOK, roots)
}

func (s *Server) handleIntermediates(w http.ResponseWriter, r *http.Request) {
	intermediates, err := s.caClient.Intermediates(r.Context())
	if err != nil {
		log.Printf("Failed to fetch intermediates: %v", err)
		writeError(w, http.StatusBadGateway, "failed to fetch intermediates")
		return
	}
	writeJSON(w, http.StatusOK, intermediates)
}

func (s *Server) handleProvisioners(w http.ResponseWriter, r *http.Request) {
	provisioners, err := s.caClient.Provisioners(r.Context())
	if err != nil {
		log.Printf("Failed to fetch provisioners: %v", err)
		writeError(w, http.StatusBadGateway, "failed to fetch provisioners")
		return
	}
	writeJSON(w, http.StatusOK, provisioners)
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CN == "" {
		writeError(w, http.StatusBadRequest, "common name (cn) is required")
		return
	}

	if len(req.SANs) == 0 {
		req.SANs = []string{req.CN}
	}

	ctx := r.Context()

	sess, err := s.sessMgr.Get(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "session invalid")
		return
	}

	jwk, err := ca.DeserializeJWK(sess.JWKData)
	if err != nil {
		log.Printf("Failed to deserialize JWK: %v", err)
		writeError(w, http.StatusInternalServerError, "session data corrupted")
		return
	}

	var csrPEM string
	var keyPEM string

	if req.CSR != "" {
		// User provided their own CSR
		csrPEM = req.CSR
		keyPEM = ""
		log.Printf("Using user-provided CSR for CN=%s", req.CN)
	} else {
		// Generate CSR server-side
		csrResult, err := csr.Generate(req.CN, req.SANs)
		if err != nil {
			log.Printf("Failed to generate CSR: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to generate CSR")
			return
		}
		csrPEM = string(csrResult.CSRPEM)
		keyPEM = string(csrResult.KeyPEM)
	}

	tg := ca.NewTokenGenerator(s.cfg.CAURL, sess.ProvisionerName, sess.ProvisionerKID, jwk, sess.RootSHA)

	ott, err := tg.GenerateSignToken(req.CN, req.SANs)
	if err != nil {
		log.Printf("Failed to generate OTT: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	signReq := &ca.SignRequest{
		CSR:       csrPEM,
		OTT:       ott,
		NotBefore: req.NotBefore,
		NotAfter:  req.NotAfter,
	}

	if len(req.TemplateData) > 0 {
		signReq.TemplateData = req.TemplateData
	}

	signResp, err := s.caClient.Sign(ctx, signReq)
	if err != nil {
		log.Printf("Failed to sign certificate: %v", err)
		writeError(w, http.StatusBadRequest, fmt.Sprintf("sign failed: %v", err))
		return
	}

	result := SignResult{
		Certificate: signResp.Crt,
		PrivateKey:  keyPEM,
		CAChain:     signResp.CA,
		CertChain:   signResp.CertChain,
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Serial == "" {
		writeError(w, http.StatusBadRequest, "serial number is required")
		return
	}

	ctx := r.Context()

	sess, err := s.sessMgr.Get(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "session invalid")
		return
	}

	jwk, err := ca.DeserializeJWK(sess.JWKData)
	if err != nil {
		log.Printf("Failed to deserialize JWK: %v", err)
		writeError(w, http.StatusInternalServerError, "session data corrupted")
		return
	}

	tg := ca.NewTokenGenerator(s.cfg.CAURL, sess.ProvisionerName, sess.ProvisionerKID, jwk, sess.RootSHA)

	ott, err := tg.GenerateRevokeToken(req.Serial)
	if err != nil {
		log.Printf("Failed to generate revoke OTT: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	revokeReq := &ca.RevokeRequest{
		Serial:     req.Serial,
		OTT:        ott,
		ReasonCode: req.ReasonCode,
		Reason:     req.Reason,
		Passive:    true,
	}

	revokeResp, err := s.caClient.Revoke(ctx, revokeReq)
	if err != nil {
		log.Printf("Failed to revoke certificate: %v", err)
		writeError(w, http.StatusBadRequest, fmt.Sprintf("revoke failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, revokeResp)
}

func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	crlData, err := s.caClient.CRL(r.Context())
	if err != nil {
		log.Printf("Failed to fetch CRL: %v", err)
		writeError(w, http.StatusBadGateway, "failed to fetch CRL")
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Write(crlData)
}

func (s *Server) handleParseCert(w http.ResponseWriter, r *http.Request) {
	var req ParseCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PEM == "" {
		writeError(w, http.StatusBadRequest, "PEM data is required")
		return
	}

	block, _ := pem.Decode([]byte(req.PEM))
	if block == nil {
		writeError(w, http.StatusBadRequest, "invalid PEM data")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to parse certificate")
		return
	}

	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	var uris []string
	for _, u := range cert.URIs {
		uris = append(uris, u.String())
	}

	info := CertInfo{
		Version:        cert.Version,
		Serial:         cert.SerialNumber.String(),
		SignatureAlgo:  cert.SignatureAlgorithm.String(),
		PublicKeyAlgo:  publicKeyAlgoString(cert.PublicKey),
		PublicKeySize:  publicKeySize(cert.PublicKey),
		Subject:        cert.Subject.CommonName,
		SubjectFull:    formatName(cert.Subject),
		Issuer:         cert.Issuer.CommonName,
		IssuerFull:     formatName(cert.Issuer),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		DNSNames:       cert.DNSNames,
		IPAddresses:    ips,
		EmailAddresses: cert.EmailAddresses,
		URIs:           uris,
		KeyUsage:       keyUsageString(cert.KeyUsage),
		ExtKeyUsage:    extKeyUsageStrings(cert.ExtKeyUsage),
		IsCA:           cert.IsCA,
		SelfSigned:     cert.CheckSignatureFrom(cert) == nil,
		OCSPServers:    cert.OCSPServer,
		CRLDistPoints:  cert.CRLDistributionPoints,
		IssuerURLs:     cert.IssuingCertificateURL,
	}

	writeJSON(w, http.StatusOK, info)
}

// --- CSR Parse handler ---

func (s *Server) handleParseCSR(w http.ResponseWriter, r *http.Request) {
	var req ParseCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PEM == "" {
		writeError(w, http.StatusBadRequest, "PEM data is required")
		return
	}

	block, _ := pem.Decode([]byte(req.PEM))
	if block == nil {
		writeError(w, http.StatusBadRequest, "invalid PEM data")
		return
	}

	csrReq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to parse CSR: %v", err))
		return
	}

	if err := csrReq.CheckSignature(); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("CSR signature verification failed: %v", err))
		return
	}

	var ips []string
	for _, ip := range csrReq.IPAddresses {
		ips = append(ips, ip.String())
	}

	var uris []string
	for _, u := range csrReq.URIs {
		uris = append(uris, u.String())
	}

	info := CSRInfo{
		Subject:        csrReq.Subject.CommonName,
		SubjectFull:    formatName(csrReq.Subject),
		PublicKeyAlgo:  publicKeyAlgoString(csrReq.PublicKey),
		PublicKeySize:  publicKeySize(csrReq.PublicKey),
		SignatureAlgo:  csrReq.SignatureAlgorithm.String(),
		DNSNames:       csrReq.DNSNames,
		IPAddresses:    ips,
		EmailAddresses: csrReq.EmailAddresses,
		URIs:           uris,
	}

	writeJSON(w, http.StatusOK, info)
}

// --- Helper functions ---

func formatName(name pkix.Name) string {
	parts := []string{}
	if name.Country != nil {
		for _, v := range name.Country {
			parts = append(parts, "C="+v)
		}
	}
	if name.Province != nil {
		for _, v := range name.Province {
			parts = append(parts, "ST="+v)
		}
	}
	if name.Locality != nil {
		for _, v := range name.Locality {
			parts = append(parts, "L="+v)
		}
	}
	if name.Organization != nil {
		for _, v := range name.Organization {
			parts = append(parts, "O="+v)
		}
	}
	if name.OrganizationalUnit != nil {
		for _, v := range name.OrganizationalUnit {
			parts = append(parts, "OU="+v)
		}
	}
	if name.CommonName != "" {
		parts = append(parts, "CN="+name.CommonName)
	}
	if len(parts) == 0 {
		return "(empty)"
	}
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ", "
		}
		result += p
	}
	return result
}

func publicKeyAlgoString(pub interface{}) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

func publicKeySize(pub interface{}) int {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

func keyUsageString(ku x509.KeyUsage) string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if len(usages) == 0 {
		return "(none)"
	}
	result := ""
	for i, u := range usages {
		if i > 0 {
			result += ", "
		}
		result += u
	}
	return result
}

func extKeyUsageStrings(ekus []x509.ExtKeyUsage) []string {
	var result []string
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			result = append(result, "TLS Web Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			result = append(result, "TLS Web Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			result = append(result, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			result = append(result, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			result = append(result, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			result = append(result, "OCSP Signing")
		default:
			result = append(result, fmt.Sprintf("ExtKeyUsage(%d)", eku))
		}
	}
	return result
}

// --- CNF handlers ---

type ParseCNFRequest struct {
	Content string `json:"content"`
}

type SignCNFRequest struct {
	Content   string `json:"content"`
	NotBefore string `json:"notBefore,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`
}

func (s *Server) handleParseCNF(w http.ResponseWriter, r *http.Request) {
	var req ParseCNFRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "CNF content is required")
		return
	}

	config, err := cnf.Parse(req.Content)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to parse CNF: %v", err))
		return
	}

	result, err := config.ExtractValues()
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to extract values: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSignCNF(w http.ResponseWriter, r *http.Request) {
	var req SignCNFRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "CNF content is required")
		return
	}

	config, err := cnf.Parse(req.Content)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to parse CNF: %v", err))
		return
	}

	parsed, err := config.ExtractValues()
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to extract values: %v", err))
		return
	}

	if err := parsed.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	cn := parsed.CommonName
	sans := parsed.GetAllSANs()
	if len(sans) == 0 {
		sans = []string{cn}
	}

	ctx := r.Context()

	sess, err := s.sessMgr.Get(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "session invalid")
		return
	}

	jwk, err := ca.DeserializeJWK(sess.JWKData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session data corrupted")
		return
	}

	csrResult, err := csr.Generate(cn, sans)
	if err != nil {
		log.Printf("Failed to generate CSR from CNF: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to generate CSR")
		return
	}

	tg := ca.NewTokenGenerator(s.cfg.CAURL, sess.ProvisionerName, sess.ProvisionerKID, jwk, sess.RootSHA)

	ott, err := tg.GenerateSignToken(cn, sans)
	if err != nil {
		log.Printf("Failed to generate OTT: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	signReq := &ca.SignRequest{
		CSR:       string(csrResult.CSRPEM),
		OTT:       ott,
		NotBefore: req.NotBefore,
		NotAfter:  req.NotAfter,
	}

	signResp, err := s.caClient.Sign(ctx, signReq)
	if err != nil {
		log.Printf("Failed to sign certificate from CNF: %v", err)
		writeError(w, http.StatusBadRequest, fmt.Sprintf("sign failed: %v", err))
		return
	}

	result := SignResult{
		Certificate: signResp.Crt,
		PrivateKey:  string(csrResult.KeyPEM),
		CAChain:     signResp.CA,
		CertChain:   signResp.CertChain,
	}

	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
