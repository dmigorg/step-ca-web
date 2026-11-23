package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"
)

type issuedCertificate struct {
	Serial    string    `json:"serial"`
	Subject   string    `json:"subject"`
	SANs      string    `json:"sans"`
	Source    string    `json:"source"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}

type inventoryResponse struct {
	Certificates []issuedCertificate `json:"certificates"`
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")

	if s.cfg.InventoryFile == "" {
		writeError(w, http.StatusServiceUnavailable, "certificate inventory is not configured")
		return
	}

	raw, err := os.ReadFile(s.cfg.InventoryFile)
	if err != nil {
		slog.ErrorContext(r.Context(), "read certificate inventory", "err", err)
		writeError(w, http.StatusServiceUnavailable, "certificate inventory is unavailable")
		return
	}

	inventory := inventoryResponse{Certificates: []issuedCertificate{}}
	if err := json.Unmarshal(raw, &inventory); err != nil {
		slog.ErrorContext(r.Context(), "decode certificate inventory", "err", err)
		writeError(w, http.StatusServiceUnavailable, "certificate inventory is unavailable")
		return
	}

	writeJSON(w, http.StatusOK, inventory)
}
