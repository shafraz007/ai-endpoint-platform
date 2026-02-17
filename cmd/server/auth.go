package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/shafraz007/ai-endpoint-platform/internal/auth"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
	"golang.org/x/crypto/bcrypt"
)

func authenticateUser(ctx context.Context, username, password string) (*server.User, error) {
	username = strings.TrimSpace(username)
	if username == "" || strings.TrimSpace(password) == "" {
		return nil, errors.New("missing credentials")
	}

	user, err := server.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}
	return user, nil
}

func issueAdminSessionCookie(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig, username string) error {
	token, err := auth.GenerateToken(username, "admin", cfg.AdminJWTSecret, cfg.AdminJWTTTL)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     adminCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(cfg.AdminJWTTTL.Seconds()),
		Secure:   r.TLS != nil,
	}
	http.SetCookie(w, cookie)
	return nil
}

func authorizeAdminSession(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig, allowMustChange bool) (*auth.Claims, *server.User, error) {
	if cfg.AdminJWTSecret == "" {
		return nil, nil, errors.New("admin auth not configured")
	}

	var claims *auth.Claims
	var err error
	if authHeader := strings.TrimSpace(r.Header.Get("Authorization")); authHeader != "" {
		claims, err = requireAdmin(r, cfg.AdminJWTSecret)
		if err != nil {
			return nil, nil, err
		}
	} else {
		cookie, err := r.Cookie(adminCookieName)
		if err != nil || strings.TrimSpace(cookie.Value) == "" {
			return nil, nil, errors.New("missing admin session")
		}
		claims, err = auth.ParseAndValidate(cookie.Value, cfg.AdminJWTSecret)
		if err != nil {
			return nil, nil, err
		}
		if claims.Role != "admin" {
			return nil, nil, errors.New("forbidden")
		}
	}

	username := strings.TrimSpace(claims.Subject)
	if username == "" {
		return nil, nil, errors.New("missing subject")
	}
	user, err := server.GetUserByUsername(r.Context(), username)
	if err != nil {
		return nil, nil, errors.New("invalid session")
	}
	if user.Role != "admin" {
		return nil, nil, errors.New("forbidden")
	}
	if user.MustChangePassword && !allowMustChange {
		return nil, nil, errors.New("password change required")
	}

	if w != nil {
		_ = issueAdminSessionCookie(w, r, cfg, user.Username)
	}
	return claims, user, nil
}
