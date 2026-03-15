package authority

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/civiledcode/grxm-iam/config"
	"github.com/civiledcode/grxm-iam/db"
	"github.com/civiledcode/grxm-iam/keystore"
	"github.com/civiledcode/grxm-iam/token"
	"golang.org/x/net/websocket"
)

// Server handles authority-level commands via WebSocket.
type Server struct {
	config   *config.IAMConfig
	repo     db.UserRepository
	ts       token.TokenSource
	keyStore keystore.Store
}

// NewServer creates a new authority server instance.
func NewServer(cfg *config.IAMConfig, repo db.UserRepository, ts token.TokenSource, ks keystore.Store) *Server {
	return &Server{config: cfg, repo: repo, ts: ts, keyStore: ks}
}

// Command represents an incoming WebSocket message from an authority.
type Command struct {
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload"`
}

// BanPayload holds data for a ban action.
type BanPayload struct {
	UserID string `json:"user_id"`
	Reason string `json:"reason"`
}

// RolePayload holds data for a role change action.
type RolePayload struct {
	UserID string   `json:"user_id"`
	Roles  []string `json:"roles"`
}

// RoleModifyPayload holds data for appending or removing a specific role.
type RoleModifyPayload struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// Response represents a reply back to the authority.
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Handler returns the websocket handler for authority connections.
func (s *Server) Handler() websocket.Handler {
	return websocket.Handler(func(ws *websocket.Conn) {
		req := ws.Request()
		
		// Authenticate via Authorization Header or Query Parameter
		authHeader := req.Header.Get("Authorization")
		if authHeader != "Bearer "+s.config.Authority.Password {
			if req.URL.Query().Get("auth") != s.config.Authority.Password {
				slog.Warn("Unauthorized authority connection attempt", "remote", req.RemoteAddr)
				ws.Close()
				return
			}
		}

		slog.Info("Authority connected", "remote", req.RemoteAddr)

		for {
			var cmd Command
			err := websocket.JSON.Receive(ws, &cmd)
			if err != nil {
				if err.Error() == "EOF" {
					slog.Info("Authority disconnected", "remote", req.RemoteAddr)
					break
				}
				slog.Error("Error reading websocket command", "error", err)
				break
			}

			var resp Response
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

			switch cmd.Action {
			case "ban":
				var payload BanPayload
				if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
					resp = Response{Success: false, Message: "invalid ban payload"}
				} else {
					slog.Info("Authority action: ban", "user", payload.UserID, "reason", payload.Reason)
					err := s.repo.SetBanStatus(ctx, payload.UserID, true, payload.Reason)
					if err != nil {
						slog.Error("Failed to ban user", "error", err)
						resp = Response{Success: false, Message: "failed to ban user: " + err.Error()}
					} else {
						// Immediately insert into Redis blocklist for the duration of a standard token's lifetime.
						if s.keyStore != nil {
							expHours := s.config.Token.ExpirationHours
							if expHours == 0 {
								expHours = 24
							}
							if err := s.keyStore.BanUser(ctx, payload.UserID, time.Hour*time.Duration(expHours)); err != nil {
								slog.Error("Failed to update keystore blocklist for ban", "error", err)
								// Note: We still return success as the DB operation succeeded, but log the error.
							}
						}
						resp = Response{Success: true, Message: "User banned successfully"}
					}
				}

			case "unban":
				var payload BanPayload
				if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
					resp = Response{Success: false, Message: "invalid unban payload"}
				} else {
					slog.Info("Authority action: unban", "user", payload.UserID)
					err := s.repo.SetBanStatus(ctx, payload.UserID, false, "")
					if err != nil {
						slog.Error("Failed to unban user", "error", err)
						resp = Response{Success: false, Message: "failed to unban user: " + err.Error()}
					} else {
						// Remove from Redis blocklist if present.
						if s.keyStore != nil {
							if err := s.keyStore.UnbanUser(ctx, payload.UserID); err != nil {
								slog.Error("Failed to update keystore blocklist for unban", "error", err)
							}
						}
						resp = Response{Success: true, Message: "User unbanned successfully"}
					}
				}

			case "role":
				var payload RolePayload
				if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
					resp = Response{Success: false, Message: "invalid role payload"}
				} else {
					slog.Info("Authority action: role update", "user", payload.UserID, "roles", payload.Roles)
					err := s.repo.UpdateRoles(ctx, payload.UserID, payload.Roles)
					if err != nil {
						slog.Error("Failed to update user roles", "error", err)
						resp = Response{Success: false, Message: "failed to update roles: " + err.Error()}
					} else {
						resp = Response{Success: true, Message: "Roles updated successfully"}
					}
				}

			case "role_add":
				var payload RoleModifyPayload
				if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
					resp = Response{Success: false, Message: "invalid role_add payload"}
				} else {
					slog.Info("Authority action: role_add", "user", payload.UserID, "role", payload.Role)
					err := s.repo.AddRole(ctx, payload.UserID, payload.Role)
					if err != nil {
						slog.Error("Failed to add user role", "error", err)
						resp = Response{Success: false, Message: "failed to add role: " + err.Error()}
					} else {
						resp = Response{Success: true, Message: "Role added successfully"}
					}
				}

			case "role_delete":
				var payload RoleModifyPayload
				if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
					resp = Response{Success: false, Message: "invalid role_delete payload"}
				} else {
					slog.Info("Authority action: role_delete", "user", payload.UserID, "role", payload.Role)
					err := s.repo.RemoveRole(ctx, payload.UserID, payload.Role)
					if err != nil {
						slog.Error("Failed to remove user role", "error", err)
						resp = Response{Success: false, Message: "failed to remove role: " + err.Error()}
					} else {
						resp = Response{Success: true, Message: "Role removed successfully"}
					}
				}

			case "public_key":
				pem, err := s.ts.PublicKeyPEM()
				if err != nil {
					slog.Error("Failed to get public key", "error", err)
					resp = Response{Success: false, Message: "failed to get public key: " + err.Error()}
				} else {
					resp = Response{Success: true, Message: pem}
				}

			default:
				resp = Response{Success: false, Message: "unknown action"}
			}
			
			cancel()

			if err := websocket.JSON.Send(ws, resp); err != nil {
				slog.Error("Failed to send response to authority", "error", err)
				break
			}
		}
	})
}
