package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/auth"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
)

// ---------------------------------------------------------------------------
// getBearerToken helper
// ---------------------------------------------------------------------------

func TestGetBearerToken_MissingHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := getBearerToken(req)
	if err == nil {
		t.Fatal("expected error when Authorization header is missing")
	}
}

func TestGetBearerToken_InvalidFormat(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	_, err := getBearerToken(req)
	if err == nil {
		t.Fatal("expected error for non-Bearer auth scheme")
	}
}

func TestGetBearerToken_ValidBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer my-jwt-token")
	token, err := getBearerToken(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my-jwt-token" {
		t.Errorf("got %q, want 'my-jwt-token'", token)
	}
}

func TestGetBearerToken_BearerCaseInsensitive(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "BEARER my-jwt-token")
	token, err := getBearerToken(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my-jwt-token" {
		t.Errorf("got %q, want 'my-jwt-token'", token)
	}
}

// ---------------------------------------------------------------------------
// authorizeJWT
// ---------------------------------------------------------------------------

func TestAuthorizeJWT_ValidToken(t *testing.T) {
	const secret = "jwt-test-secret"
	token, err := auth.GenerateToken("agent-xyz", "agent", secret, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	claims, err := authorizeJWT(req, secret)
	if err != nil {
		t.Fatalf("authorizeJWT error: %v", err)
	}
	if claims.Subject != "agent-xyz" {
		t.Errorf("subject: got %q, want 'agent-xyz'", claims.Subject)
	}
}

func TestAuthorizeJWT_WrongSecret(t *testing.T) {
	token, _ := auth.GenerateToken("agent-xyz", "agent", "correct-secret", time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err := authorizeJWT(req, "wrong-secret")
	if err == nil {
		t.Fatal("expected error with wrong JWT secret")
	}
}

func TestAuthorizeJWT_ExpiredToken(t *testing.T) {
	token, _ := auth.GenerateToken("agent-xyz", "agent", "secret", -1*time.Second)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err := authorizeJWT(req, "secret")
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

// ---------------------------------------------------------------------------
// commandsHandler — method dispatch
// ---------------------------------------------------------------------------

func TestCommandsHandler_MethodNotAllowed(t *testing.T) {
	cfg := config.ServerConfig{AdminJWTSecret: "test-secret"}
	handler := commandsHandler(cfg)

	for _, method := range []string{http.MethodDelete, http.MethodPut, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/v1/commands", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", method, w.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// handleCommandCreate — auth failure paths (no DB needed)
// ---------------------------------------------------------------------------

func TestHandleCommandCreate_AdminJWTSecretNotConfigured(t *testing.T) {
	cfg := config.ServerConfig{AdminJWTSecret: ""}
	handler := commandsHandler(cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/commands",
		strings.NewReader(`{"agent_id":"test","command_type":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when AdminJWTSecret is empty, got %d", w.Code)
	}
}

func TestHandleCommandCreate_NoAuthHeaderOrCookie(t *testing.T) {
	cfg := config.ServerConfig{AdminJWTSecret: "test-secret"}
	handler := commandsHandler(cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/commands",
		strings.NewReader(`{"agent_id":"test","command_type":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with no auth credentials, got %d", w.Code)
	}
}

func TestHandleCommandCreate_InvalidBearerToken(t *testing.T) {
	cfg := config.ServerConfig{AdminJWTSecret: "test-secret"}
	handler := commandsHandler(cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/commands",
		strings.NewReader(`{"agent_id":"test","command_type":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer completely.invalid.token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with invalid token, got %d", w.Code)
	}
}

func TestHandleCommandCreate_ExpiredBearerToken(t *testing.T) {
	const secret = "test-secret"
	token, _ := auth.GenerateToken("admin-user", "admin", secret, -1*time.Second)

	cfg := config.ServerConfig{AdminJWTSecret: secret}
	handler := commandsHandler(cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/commands",
		strings.NewReader(`{"agent_id":"test","command_type":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with expired token, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// handleCommandList — auth failure paths (no DB needed)
// ---------------------------------------------------------------------------

func TestHandleCommandList_AdminJWTSecretNotConfigured(t *testing.T) {
	cfg := config.ServerConfig{AdminJWTSecret: ""}
	handler := commandsHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/commands?agent_id=test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when AdminJWTSecret is empty, got %d", w.Code)
	}
}

func TestHandleCommandList_NoAuth(t *testing.T) {
	cfg := config.ServerConfig{AdminJWTSecret: "test-secret"}
	handler := commandsHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/commands?agent_id=test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with no auth, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// requireAgent
// ---------------------------------------------------------------------------

func TestRequireAgent_ValidAgentToken(t *testing.T) {
	const secret = "agent-secret"
	token, _ := auth.GenerateToken("my-agent-id", "agent", secret, time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	claims, err := requireAgent(req, secret)
	if err != nil {
		t.Fatalf("requireAgent error: %v", err)
	}
	if claims.Subject != "my-agent-id" {
		t.Errorf("subject: got %q, want 'my-agent-id'", claims.Subject)
	}
}

func TestRequireAgent_WrongRole(t *testing.T) {
	const secret = "agent-secret"
	token, _ := auth.GenerateToken("admin-user", "admin", secret, time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err := requireAgent(req, secret)
	if err == nil {
		t.Fatal("expected error when token role is 'admin' not 'agent'")
	}
}
