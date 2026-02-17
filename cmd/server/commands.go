package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/auth"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

const adminCookieName = "admin_session"

func commandsHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handleCommandCreate(w, r, cfg)
		case http.MethodGet:
			handleCommandList(w, r, cfg)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func handleCommandCreate(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	if cfg.AdminJWTSecret == "" {
		http.Error(w, "Admin auth not configured", http.StatusInternalServerError)
		return
	}

	claims, _, err := authorizeAdminRequest(w, r, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	_ = claims

	var req transport.CommandCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.AgentID = strings.TrimSpace(req.AgentID)
	req.CommandType = strings.ToLower(strings.TrimSpace(req.CommandType))

	if req.AgentID == "" {
		http.Error(w, "Missing agent_id", http.StatusBadRequest)
		return
	}

	switch req.CommandType {
	case "ping", "echo", "shell", "cmd", "powershell", "restart", "shutdown":
		// ok
	default:
		http.Error(w, "Unsupported command_type", http.StatusBadRequest)
		return
	}

	if (req.CommandType == "echo" || req.CommandType == "shell" || req.CommandType == "cmd" || req.CommandType == "powershell") && strings.TrimSpace(req.Payload) == "" {
		http.Error(w, "Missing payload", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	cmd, err := server.CreateCommand(ctx, req.AgentID, req.CommandType, req.Payload)
	if err != nil {
		log.Printf("CreateCommand error: %v", err)
		http.Error(w, "Failed to create command", http.StatusInternalServerError)
		return
	}

	resp := transport.Command{
		ID:          cmd.ID,
		AgentID:     cmd.AgentID,
		CommandType: cmd.CommandType,
		Payload:     cmd.Payload,
		Status:      cmd.Status,
		CreatedAt:   cmd.CreatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func handleCommandList(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	if cfg.AdminJWTSecret == "" {
		http.Error(w, "Admin auth not configured", http.StatusInternalServerError)
		return
	}

	claims, _, err := authorizeAdminRequest(w, r, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	_ = claims

	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
	if agentID == "" {
		http.Error(w, "Missing agent_id", http.StatusBadRequest)
		return
	}
	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	commands, err := server.ListCommandsByAgent(ctx, agentID, limit)
	if err != nil {
		log.Printf("ListCommands error: %v", err)
		http.Error(w, "Failed to list commands", http.StatusInternalServerError)
		return
	}

	resp := make([]transport.Command, 0, len(commands))
	for _, cmd := range commands {
		resp = append(resp, transport.Command{
			ID:           cmd.ID,
			AgentID:      cmd.AgentID,
			CommandType:  cmd.CommandType,
			Payload:      cmd.Payload,
			Status:       cmd.Status,
			CreatedAt:    cmd.CreatedAt,
			DispatchedAt: cmd.DispatchedAt,
			CompletedAt:  cmd.CompletedAt,
			Output:       cmd.Output,
			Error:        cmd.Error,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func adminLoginHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.AdminJWTSecret == "" {
			http.Error(w, "Admin auth not configured", http.StatusInternalServerError)
			return
		}

		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		user, err := authenticateUser(ctx, body.Username, body.Password)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		if err := issueAdminSessionCookie(w, r, cfg, user.Username); err != nil {
			log.Printf("Admin login token error: %v", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
		_ = server.UpdateLastLogin(ctx, user.Username)
		w.WriteHeader(http.StatusNoContent)
	}
}

func adminLogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie := &http.Cookie{
			Name:     adminCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		}
		http.SetCookie(w, cookie)
		w.WriteHeader(http.StatusNoContent)
	}
}

func commandPollHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.AgentJWTSecret == "" {
			http.Error(w, "Agent auth not configured", http.StatusInternalServerError)
			return
		}

		claims, err := requireAgent(r, cfg.AgentJWTSecret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		agentID := strings.TrimSpace(claims.Subject)
		if agentID == "" {
			http.Error(w, "Missing subject", http.StatusUnauthorized)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		cmd, err := server.DequeueCommand(ctx, agentID)
		if err != nil {
			log.Printf("DequeueCommand error: %v", err)
			http.Error(w, "Failed to fetch command", http.StatusInternalServerError)
			return
		}
		if cmd == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		resp := transport.Command{
			ID:          cmd.ID,
			AgentID:     cmd.AgentID,
			CommandType: cmd.CommandType,
			Payload:     cmd.Payload,
			CreatedAt:   cmd.CreatedAt,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func commandAckHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.AgentJWTSecret == "" {
			http.Error(w, "Agent auth not configured", http.StatusInternalServerError)
			return
		}

		claims, err := requireAgent(r, cfg.AgentJWTSecret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		agentID := strings.TrimSpace(claims.Subject)
		if agentID == "" {
			http.Error(w, "Missing subject", http.StatusUnauthorized)
			return
		}

		var req transport.CommandAckRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		status := strings.ToLower(strings.TrimSpace(req.Status))
		if status != "succeeded" && status != "failed" {
			http.Error(w, "Invalid status", http.StatusBadRequest)
			return
		}
		if req.CommandID <= 0 {
			http.Error(w, "Missing command_id", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := server.AckCommand(ctx, req.CommandID, agentID, status, req.Output, req.Error); err != nil {
			log.Printf("AckCommand error: %v", err)
			http.Error(w, "Failed to acknowledge command", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func requireAdmin(r *http.Request, secret string) (*auth.Claims, error) {
	claims, err := authorizeJWT(r, secret)
	if err != nil {
		return nil, err
	}
	if claims.Role != "admin" {
		return nil, errors.New("Forbidden")
	}
	return claims, nil
}

func authorizeAdminRequest(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) (*auth.Claims, *server.User, error) {
	claims, user, err := authorizeAdminSession(w, r, cfg, false)
	if err != nil {
		return nil, nil, err
	}
	return claims, user, nil
}

func requireAgent(r *http.Request, secret string) (*auth.Claims, error) {
	claims, err := authorizeJWT(r, secret)
	if err != nil {
		return nil, err
	}
	if claims.Role != "agent" {
		return nil, errors.New("Forbidden")
	}
	return claims, nil
}

func authorizeJWT(r *http.Request, secret string) (*auth.Claims, error) {
	token, err := getBearerToken(r)
	if err != nil {
		return nil, err
	}
	return auth.ParseAndValidate(token, secret)
}

func getBearerToken(r *http.Request) (string, error) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return "", errors.New("Missing Authorization header")
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("Invalid Authorization header")
	}
	return strings.TrimSpace(parts[1]), nil
}
