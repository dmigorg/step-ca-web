package server

import (
	"net/http"

	"github.com/xix-support/step-ca-web/internal/auth"
	"github.com/xix-support/step-ca-web/internal/ca"
	"github.com/xix-support/step-ca-web/internal/config"
	"github.com/xix-support/step-ca-web/internal/session"
)

type Server struct {
	caClient *ca.Client
	sessMgr  *session.Manager
	cfg      *config.Config
	authMW   func(http.Handler) http.Handler
}

func New(caClient *ca.Client, sessMgr *session.Manager, cfg *config.Config) *Server {
	s := &Server{
		caClient: caClient,
		sessMgr:  sessMgr,
		cfg:      cfg,
	}
	s.authMW = auth.Middleware(sessMgr)
	return s
}

func (s *Server) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /auth/check", s.handleAuthCheck)

	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/version", s.handleVersion)

	mux.Handle("GET /api/roots", s.authMW(http.HandlerFunc(s.handleRoots)))
	mux.Handle("GET /api/intermediates", s.authMW(http.HandlerFunc(s.handleIntermediates)))
	mux.Handle("GET /api/provisioners", s.authMW(http.HandlerFunc(s.handleProvisioners)))

	mux.Handle("POST /api/sign", s.authMW(http.HandlerFunc(s.handleSign)))
	mux.Handle("POST /api/revoke", s.authMW(http.HandlerFunc(s.handleRevoke)))
	mux.Handle("POST /api/parse-cert", s.authMW(http.HandlerFunc(s.handleParseCert)))
	mux.Handle("POST /api/parse-csr", s.authMW(http.HandlerFunc(s.handleParseCSR)))
	mux.Handle("POST /api/parse-cnf", s.authMW(http.HandlerFunc(s.handleParseCNF)))
	mux.Handle("POST /api/sign-cnf", s.authMW(http.HandlerFunc(s.handleSignCNF)))

	mux.HandleFunc("GET /api/crl", s.handleCRL)

	mux.HandleFunc("/", s.handleStatic)

	return mux
}
