package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

func issuesHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleIssueList(w, r, cfg)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func issueRouter(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/api/issues/")
		suffix = strings.TrimSpace(suffix)
		if suffix == "" {
			http.NotFound(w, r)
			return
		}

		if strings.HasSuffix(suffix, "/actions") {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			handleIssueActionCreate(w, r, cfg)
			return
		}

		if strings.HasSuffix(suffix, "/resolve") {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			handleIssueResolve(w, r, cfg)
			return
		}

		if strings.HasSuffix(suffix, "/snooze") {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			handleIssueSnooze(w, r, cfg)
			return
		}

		if strings.HasSuffix(suffix, "/suppress") {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			handleIssueSuppress(w, r, cfg)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleIssueGet(w, r, cfg)
	}
}

func handleIssueList(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, parseErr := strconv.Atoi(raw); parseErr == nil {
			limit = parsed
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	items, err := server.ListAgentIssues(ctx, server.IssueFilter{
		AgentID: strings.TrimSpace(r.URL.Query().Get("agent_id")),
		Status:  strings.TrimSpace(r.URL.Query().Get("status")),
		Limit:   limit,
	})
	if err != nil {
		log.Printf("ListAgentIssues error: %v", err)
		http.Error(w, "Failed to list issues", http.StatusInternalServerError)
		return
	}

	resp := make([]transport.AgentIssue, 0, len(items))
	for _, item := range items {
		resp = append(resp, mapIssueToTransport(item))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleIssueGet(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	issueID, ok := parseIssueIDFromPath(r.URL.Path)
	if !ok {
		http.Error(w, "Invalid issue id", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	item, err := server.GetAgentIssueByID(ctx, issueID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to fetch issue", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mapIssueToTransport(*item))
}

func handleIssueActionCreate(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	_, user, err := authorizeAdminRequest(w, r, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	issueID, ok := parseIssueIDFromActionPath(r.URL.Path)
	if !ok {
		http.Error(w, "Invalid issue id", http.StatusBadRequest)
		return
	}

	var req transport.IssueActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	result, err := server.ExecuteIssueAction(ctx, issueID, server.IssueActionInput{
		ActionID:              req.ActionID,
		Mode:                  req.Mode,
		Kind:                  req.Kind,
		CommandType:           req.CommandType,
		Payload:               req.Payload,
		Name:                  req.Name,
		RunAt:                 req.RunAt,
		RepeatIntervalSeconds: req.RepeatIntervalSeconds,
		RecurrenceRule:        req.RecurrenceRule,
		Enabled:               req.Enabled,
	}, user.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := transport.IssueActionResult{
		IssueID:           result.IssueID,
		Mode:              result.Mode,
		Kind:              result.Kind,
		CommandType:       result.CommandType,
		CreatedCommandID:  result.CreatedCommandID,
		CreatedScheduleID: result.CreatedScheduleID,
		Message:           result.Message,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func handleIssueResolve(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	issueID, ok := parseIssueIDFromResolvePath(r.URL.Path)
	if !ok {
		http.Error(w, "Invalid issue id", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	if err := server.ResolveAgentIssueByID(ctx, issueID); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") || strings.Contains(strings.ToLower(err.Error()), "already resolved") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"issue_id": issueID,
		"message":  "Issue marked as resolved",
	})
}

func handleIssueSnooze(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	issueID, ok := parseIssueIDFromSnoozePath(r.URL.Path)
	if !ok {
		http.Error(w, "Invalid issue id", http.StatusBadRequest)
		return
	}

	var req struct {
		Minutes int `json:"minutes"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
	}

	minutes := req.Minutes
	if minutes <= 0 {
		minutes = 60
	}
	if minutes > 60*24*30 {
		http.Error(w, "Snooze minutes too large", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	snoozedUntil, err := server.SnoozeAgentIssueByID(ctx, issueID, time.Duration(minutes)*time.Minute)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"issue_id":      issueID,
		"snoozed_until": snoozedUntil,
		"message":       "Issue snoozed successfully",
	})
}

func handleIssueSuppress(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	issueID, ok := parseIssueIDFromSuppressPath(r.URL.Path)
	if !ok {
		http.Error(w, "Invalid issue id", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	if err := server.SuppressAgentIssueByID(ctx, issueID); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"issue_id": issueID,
		"message":  "Issue suppressed successfully",
	})
}

func parseIssueIDFromPath(path string) (int64, bool) {
	raw := strings.TrimPrefix(path, "/api/issues/")
	raw = strings.Trim(raw, "/")
	if raw == "" || strings.Contains(raw, "/") {
		return 0, false
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed, true
}

func parseIssueIDFromActionPath(path string) (int64, bool) {
	raw := strings.TrimPrefix(path, "/api/issues/")
	raw = strings.TrimSuffix(raw, "/actions")
	raw = strings.Trim(raw, "/")
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed, true
}

func parseIssueIDFromResolvePath(path string) (int64, bool) {
	raw := strings.TrimPrefix(path, "/api/issues/")
	raw = strings.TrimSuffix(raw, "/resolve")
	raw = strings.Trim(raw, "/")
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed, true
}

func parseIssueIDFromSnoozePath(path string) (int64, bool) {
	raw := strings.TrimPrefix(path, "/api/issues/")
	raw = strings.TrimSuffix(raw, "/snooze")
	raw = strings.Trim(raw, "/")
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed, true
}

func parseIssueIDFromSuppressPath(path string) (int64, bool) {
	raw := strings.TrimPrefix(path, "/api/issues/")
	raw = strings.TrimSuffix(raw, "/suppress")
	raw = strings.Trim(raw, "/")
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed, true
}

func mapIssueToTransport(item server.AgentIssue) transport.AgentIssue {
	actions := make([]transport.IssueRecommendedAction, 0, len(item.RecommendedActions))
	for _, action := range item.RecommendedActions {
		actions = append(actions, transport.IssueRecommendedAction{
			ID:               action.ID,
			Label:            action.Label,
			Description:      action.Description,
			Kind:             action.Kind,
			CommandType:      action.CommandType,
			Payload:          action.Payload,
			SupportsSchedule: action.SupportsSchedule,
		})
	}

	return transport.AgentIssue{
		ID:                 item.ID,
		AgentID:            item.AgentID,
		IssueKey:           item.IssueKey,
		Category:           item.Category,
		Severity:           item.Severity,
		Status:             item.Status,
		Suppressed:         item.Suppressed,
		SnoozedUntil:       item.SnoozedUntil,
		Title:              item.Title,
		Description:        item.Description,
		Source:             item.Source,
		Evidence:           item.Evidence,
		Suggestions:        item.Suggestions,
		ActionPlan:         item.ActionPlan,
		RecommendedActions: actions,
		FirstSeenAt:        item.FirstSeenAt,
		LastSeenAt:         item.LastSeenAt,
		ResolvedAt:         item.ResolvedAt,
		CreatedAt:          item.CreatedAt,
		UpdatedAt:          item.UpdatedAt,
	}
}
