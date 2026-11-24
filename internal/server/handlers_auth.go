package server

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/xix-support/step-ca-web/internal/ca"
	"github.com/xix-support/step-ca-web/internal/session"
)

type LoginRequest struct {
	Password string `json:"password"`
}

type LoginResponse struct {
	Provisioner string `json:"provisioner"`
	KID         string `json:"kid"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}

	ctx := r.Context()

	provisioners, err := s.caClient.Provisioners(ctx)
	if err != nil {
		log.Printf("Failed to fetch provisioners: %v", err)
		writeError(w, http.StatusBadGateway, "failed to connect to CA")
		return
	}

	var jwkProv *ca.ProvisionerKey
	var kid string
	for _, p := range provisioners.Provisioners {
		if p.Type == "JWK" && p.EncryptedKey != "" &&
			(s.cfg.LoginProvisioner == "" || p.Name == s.cfg.LoginProvisioner) {
			if p.Key != nil {
				var keyData struct {
					KID string `json:"kid"`
				}
				if err := json.Unmarshal(p.Key, &keyData); err == nil && keyData.KID != "" {
					kid = keyData.KID
				}
			}
			if kid == "" {
				kid = p.Name
			}
			jwkProv = &p
			break
		}
	}

	if jwkProv == nil {
		writeError(w, http.StatusBadRequest, "no JWK provisioner found")
		return
	}

	encryptedKey := jwkProv.EncryptedKey
	if encryptedKey == "" {
		encKey, err := s.caClient.ProvisionerKey(ctx, kid)
		if err != nil {
			log.Printf("Failed to fetch provisioner key: %v", err)
			writeError(w, http.StatusBadGateway, "failed to fetch provisioner key")
			return
		}
		encryptedKey = encKey
	}

	jwk, err := ca.DecryptProvisionerKey(encryptedKey, []byte(req.Password))
	if err != nil {
		log.Printf("Failed to decrypt provisioner key: %v", err)
		writeError(w, http.StatusUnauthorized, "invalid password")
		return
	}

	rootSHA, err := s.caClient.GetRootFingerprint(ctx)
	if err != nil {
		log.Printf("Failed to get root fingerprint: %v", err)
		writeError(w, http.StatusBadGateway, "failed to get root fingerprint")
		return
	}

	jwkData, err := ca.SerializeJWK(jwk)
	if err != nil {
		log.Printf("Failed to serialize JWK: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	sessData := &session.SessionData{
		ProvisionerName: jwkProv.Name,
		ProvisionerKID:  kid,
		JWKData:         jwkData,
		RootSHA:         rootSHA,
	}

	if err := s.sessMgr.Create(w, sessData); err != nil {
		log.Printf("Failed to create session: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	writeJSON(w, http.StatusOK, LoginResponse{
		Provisioner: jwkProv.Name,
		KID:         kid,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessMgr.Delete(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")
	sess, err := s.sessMgr.Get(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"provisioner":   sess.ProvisionerName,
		"kid":           sess.ProvisionerKID,
	})
}
