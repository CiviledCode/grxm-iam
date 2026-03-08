package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/civiledcode/grxm-iam/auth"
	"github.com/civiledcode/grxm-iam/authority"
	"github.com/civiledcode/grxm-iam/config"
	"github.com/civiledcode/grxm-iam/db"
	"github.com/civiledcode/grxm-iam/token"
	"github.com/civiledcode/grxm-iam/user"
)

// Server represents the HTTP API server.
type Server struct {
	config      *config.IAMConfig
	tokenSource token.TokenSource
	repo        db.UserRepository

	// Registered methods
	loginMethods    map[string]auth.LoginMethod
	registerMethods map[string]auth.RegisterMethod
}

// NewServer creates a new API server instance.
func NewServer(cfg *config.IAMConfig, ts token.TokenSource, repo db.UserRepository) *Server {
	return &Server{
		config:          cfg,
		tokenSource:     ts,
		repo:            repo,
		loginMethods:    make(map[string]auth.LoginMethod),
		registerMethods: make(map[string]auth.RegisterMethod),
	}
}

// RegisterLoginMethod adds a new login method handler.
func (s *Server) RegisterLoginMethod(method auth.LoginMethod) {
	method.Construct(s.config, s.repo)
	s.loginMethods[method.ID()] = method
}

// RegisterRegisterMethod adds a new registration method handler.
func (s *Server) RegisterRegisterMethod(method auth.RegisterMethod) {
	method.Construct(s.config, s.repo)
	s.registerMethods[method.ID()] = method
}

// Start begins listening and serving HTTP requests.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /api/v1/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/register", s.handleRegister)

	authServer := authority.NewServer(s.config, s.repo, s.tokenSource)
	if s.config.Authority.Path != "" {
		mux.Handle(s.config.Authority.Path, authServer.Handler())
		slog.Info("Authority WebSocket enabled", "path", s.config.Authority.Path)
	}

	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)
	slog.Info("Starting API server", "address", addr)
	
	return http.ListenAndServe(addr, mux)
}

type authRequest struct {
	Type   string         `json:"type"`
	Fields map[string]any `json:"fields"`
}

type authResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	dbStatus := "ok"
	if err := s.repo.Ping(ctx); err != nil {
		dbStatus = "error: " + err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	if dbStatus != "ok" {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	json.NewEncoder(w).Encode(map[string]any{
		"status":   "alive",
		"database": dbStatus,
		"time":     time.Now().Format(time.RFC3339),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	method, ok := s.loginMethods[req.Type]
	if !ok {
		s.respondError(w, http.StatusBadRequest, "Unsupported login method")
		return
	}

	// Validate fields against method.Fields() here in the future
	// For now, pass to TryAuth
	userRec, msg := method.TryAuth(req.Fields)
	if userRec == nil {
		s.respondError(w, http.StatusUnauthorized, msg)
		return
	}

	userToken := &user.UserToken{
		UserID:         userRec.ID,
		Roles:          userRec.Roles,
		ExpirationUnix: time.Now().Add(time.Hour * 24).Unix(),
	}

	tokenStr, err := user.ToToken(s.tokenSource, userToken)
	if err != nil {
		slog.Error("Failed to generate token", "error", err)
		s.respondError(w, http.StatusInternalServerError, "Failed to issue token")
		return
	}

	s.respondSuccess(w, tokenStr)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	method, ok := s.registerMethods[req.Type]
	if !ok {
		s.respondError(w, http.StatusBadRequest, "Unsupported registration method")
		return
	}

	userRec, msg := method.TryRegister(req.Fields)
	if userRec == nil {
		s.respondError(w, http.StatusBadRequest, msg)
		return
	}

	userToken := &user.UserToken{
		UserID:         userRec.ID,
		Roles:          userRec.Roles,
		ExpirationUnix: time.Now().Add(time.Hour * 24).Unix(),
	}

	tokenStr, err := user.ToToken(s.tokenSource, userToken)
	if err != nil {
		slog.Error("Failed to generate token", "error", err)
		s.respondError(w, http.StatusInternalServerError, "Failed to issue token")
		return
	}

	s.respondSuccess(w, tokenStr)
}

func (s *Server) respondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(authResponse{Success: false, Message: message})
}

func (s *Server) respondSuccess(w http.ResponseWriter, tokenOrMessage string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(authResponse{Success: true, Token: tokenOrMessage})
}
