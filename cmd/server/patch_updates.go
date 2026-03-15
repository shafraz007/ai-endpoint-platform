package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
)

func agentPatchUpdatesRouter(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/api/agents/")
		parts := strings.Split(path, "/")
		if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "patch-updates" {
			http.NotFound(w, r)
			return
		}
		agentID := strings.TrimSpace(parts[0])

		if len(parts) == 2 && r.Method == http.MethodGet {
			handleAgentPatchUpdatesList(w, r, agentID)
			return
		}

		if len(parts) == 3 && parts[2] == "actions" && r.Method == http.MethodPost {
			handleAgentPatchUpdateAction(w, r, cfg, agentID)
			return
		}

		if len(parts) == 3 && parts[2] == "install" && r.Method == http.MethodPost {
			handleAgentPatchInstallApproved(w, r, cfg, agentID)
			return
		}

		if len(parts) == 3 && parts[2] == "uninstall" && r.Method == http.MethodPost {
			handleAgentPatchUninstall(w, r, cfg, agentID)
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAgentPatchUpdatesList(w http.ResponseWriter, r *http.Request, agentID string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if status == "" {
		status = "pending"
	}

	updates, err := server.ListAgentPatchUpdatesByStatus(ctx, agentID, status)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "invalid status") {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updates)
}

func handleAgentPatchUpdateAction(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig, agentID string) {
	_, user, err := authorizeAdminRequest(w, r, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req struct {
		KBID   string `json:"kb_id"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "approve" {
		action = "approved"
	}
	if action == "postpone" {
		action = "postponed"
	}

	postponeDays := 0
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if policy, pErr := server.GetOSPatchPolicy(ctx); pErr == nil && policy != nil {
		postponeDays = policy.PostponeDays
	}

	if err := server.UpsertAgentPatchOverride(ctx, agentID, req.KBID, action, user.Username, postponeDays); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func handleAgentPatchInstallApproved(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig, agentID string) {
	if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	cmd, approvedCount, rebootBehavior, err := server.QueueInstallApprovedPatchUpdates(ctx, agentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"command_id":      cmd.ID,
		"agent_id":        cmd.AgentID,
		"approved_count":  approvedCount,
		"reboot_behavior": rebootBehavior,
		"queued_at":       cmd.CreatedAt,
	})
}

func handleAgentPatchUninstall(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig, agentID string) {
	if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req struct {
		KBID string `json:"kb_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	cmd, err := server.QueueUninstallPatchUpdateByKB(ctx, agentID, req.KBID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"command_id": cmd.ID,
		"agent_id":   cmd.AgentID,
		"queued_at":  cmd.CreatedAt,
		"message":    "Uninstall command queued.",
	})
}
