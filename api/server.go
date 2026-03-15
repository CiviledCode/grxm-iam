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
	"github.com/civiledcode/grxm-iam/keystore"
	"github.com/civiledcode/grxm-iam/token"
	"github.com/civiledcode/grxm-iam/user"
)

// Server represents the HTTP API server.
type Server struct {
	config      *config.IAMConfig
	tokenSource token.TokenSource
	repo        db.UserRepository
	keyStore    keystore.Store

	// Registered methods
	loginMethods    map[string]auth.LoginMethod
	registerMethods map[string]auth.RegisterMethod
}

// NewServer creates a new API server instance.
func NewServer(cfg *config.IAMConfig, ts token.TokenSource, repo db.UserRepository, ks keystore.Store) *Server {
	return &Server{
		config:          cfg,
		tokenSource:     ts,
		repo:            repo,
		keyStore:        ks,
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
	mux.HandleFunc("POST /api/v1/refresh-token", s.handleRefreshToken)

	authServer := authority.NewServer(s.config, s.repo, s.tokenSource, s.keyStore)
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

func (s *Server) setTokenCookie(w http.ResponseWriter, tokenStr string) {
	cookieName := s.config.Token.CookieName
	if cookieName == "" {
		cookieName = "grxm_token"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    tokenStr,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
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

	expHours := s.config.Token.ExpirationHours
	if expHours == 0 {
		expHours = 24
	}
	refreshHours := s.config.Token.RefreshMaxHours
	if refreshHours == 0 {
		refreshHours = 168
	}

	now := time.Now()
	userToken := &user.UserToken{
		UserID:              userRec.ID,
		Roles:               userRec.Roles,
		ExpirationUnix:      now.Add(time.Hour * time.Duration(expHours)).Unix(),
		RefreshDeadlineUnix: now.Add(time.Hour * time.Duration(refreshHours)).Unix(),
	}

	tokenStr, err := user.ToToken(s.tokenSource, userToken)
	if err != nil {
		slog.Error("Failed to generate token", "error", err)
		s.respondError(w, http.StatusInternalServerError, "Failed to issue token")
		return
	}

	s.setTokenCookie(w, tokenStr)
	s.respondSuccess(w, "Authentication successful")
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

	expHours := s.config.Token.ExpirationHours
	if expHours == 0 {
		expHours = 24
	}
	refreshHours := s.config.Token.RefreshMaxHours
	if refreshHours == 0 {
		refreshHours = 168
	}

	now := time.Now()
	userToken := &user.UserToken{
		UserID:              userRec.ID,
		Roles:               userRec.Roles,
		ExpirationUnix:      now.Add(time.Hour * time.Duration(expHours)).Unix(),
		RefreshDeadlineUnix: now.Add(time.Hour * time.Duration(refreshHours)).Unix(),
	}

	tokenStr, err := user.ToToken(s.tokenSource, userToken)
	if err != nil {
		slog.Error("Failed to generate token", "error", err)
		s.respondError(w, http.StatusInternalServerError, "Failed to issue token")
		return
	}

	s.setTokenCookie(w, tokenStr)
	s.respondSuccess(w, "Authentication successful")
}

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	cookieName := s.config.Token.CookieName
	if cookieName == "" {
		cookieName = "grxm_token"
	}

	cookie, err := r.Cookie(cookieName)
	if err != nil {
		s.respondError(w, http.StatusUnauthorized, "no token cookie found")
		return
	}

	userToken, err := user.FromToken(s.tokenSource, cookie.Value)
	if err != nil {
		s.respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	now := time.Now()
	if now.Unix() > userToken.RefreshDeadlineUnix {
		s.respondError(w, http.StatusUnauthorized, "token refresh deadline exceeded")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	userRec, err := s.repo.GetByID(ctx, userToken.UserID)
	if err != nil || userRec.IsBanned {
		s.respondError(w, http.StatusUnauthorized, "user invalid or banned")
		return
	}

	expHours := s.config.Token.ExpirationHours
	if expHours == 0 {
		expHours = 24
	}

	userToken.ExpirationUnix = now.Add(time.Hour * time.Duration(expHours)).Unix()
	userToken.Roles = userRec.Roles

	newTokenStr, err := user.ToToken(s.tokenSource, userToken)
	if err != nil {
		slog.Error("Failed to generate refreshed token", "error", err)
		s.respondError(w, http.StatusInternalServerError, "Failed to issue token")
		return
	}

	s.setTokenCookie(w, newTokenStr)
	s.respondSuccess(w, "Token refreshed")
}

func (s *Server) respondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(authResponse{Success: false, Message: message})
}

func (s *Server) respondSuccess(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(authResponse{Success: true, Message: message})
}
