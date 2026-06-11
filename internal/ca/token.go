package ca

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type TokenGenerator struct {
	KID             string
	ProvisionerName string
	CAURL           string
	RootSHA         string
	JWK             *jose.JSONWebKey
}

type SignTokenClaims struct {
	jwt.Claims
	SANs []string `json:"sans,omitempty"`
	SHA  string   `json:"sha,omitempty"`
}

func DecryptProvisionerKey(encryptedKey string, password []byte) (*jose.JSONWebKey, error) {
	encrypted, err := jose.ParseEncrypted(
		string(encryptedKey),
		[]jose.KeyAlgorithm{jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW},
		[]jose.ContentEncryption{jose.A128GCM, jose.A192GCM, jose.A256GCM, jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted key: %w", err)
	}

	decrypted, err := encrypted.Decrypt(password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key (invalid password?): %w", err)
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal(decrypted, &jwk); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWK: %w", err)
	}

	return &jwk, nil
}

func NewTokenGenerator(caURL, provName, kid string, jwk *jose.JSONWebKey, rootSHA string) *TokenGenerator {
	return &TokenGenerator{
		KID:             kid,
		ProvisionerName: provName,
		CAURL:           caURL,
		RootSHA:         rootSHA,
		JWK:             jwk,
	}
}

func (tg *TokenGenerator) GenerateSignToken(subject string, sans []string) (string, error) {
	now := time.Now()
	jti, err := generateJTI()
	if err != nil {
		return "", err
	}

	claims := SignTokenClaims{
		Claims: jwt.Claims{
			Issuer:    tg.ProvisionerName,
			Subject:   subject,
			Audience:  jwt.Audience{tg.CAURL + "/1.0/sign"},
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		SANs: sans,
		SHA:  tg.RootSHA,
	}

	return tg.signToken(claims)
}

func (tg *TokenGenerator) GenerateRevokeToken(subject string) (string, error) {
	now := time.Now()
	jti, err := generateJTI()
	if err != nil {
		return "", err
	}

	claims := jwt.Claims{
		Issuer:    tg.ProvisionerName,
		Subject:   subject,
		Audience:  jwt.Audience{tg.CAURL + "/1.0/revoke"},
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        jti,
	}

	return tg.signToken(claims)
}

func (tg *TokenGenerator) signToken(claims interface{}) (string, error) {
	alg := jose.SignatureAlgorithm(tg.JWK.Algorithm)
	if alg == "" {
		alg = jose.ES256
	}

	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", tg.KID)

	signingKey := jose.SigningKey{
		Algorithm: alg,
		Key:       tg.JWK.Key,
	}

	signer, err := jose.NewSigner(signingKey, &signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	builder := jwt.Signed(signer)
	builder = builder.Claims(claims)

	token, err := builder.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return token, nil
}

func generateJTI() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random JTI: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func SerializeJWK(jwk *jose.JSONWebKey) ([]byte, error) {
	return json.Marshal(jwk)
}

func DeserializeJWK(data []byte) (*jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWK: %w", err)
	}
	return &jwk, nil
}
