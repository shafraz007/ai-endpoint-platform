package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
)

type categoryRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type policyRequest struct {
	Name                 string               `json:"name"`
	Description          string               `json:"description"`
	ScriptAllowlist      []string             `json:"script_allowlist"`
	ScriptDenylist       []string             `json:"script_denylist"`
	PatchWindows         []server.PatchWindow `json:"patch_windows"`
	MaxConcurrentScripts int                  `json:"max_concurrent_scripts"`
	RequireAdminApproval bool                 `json:"require_admin_approval"`
	OnlineOnly           bool                 `json:"online_only"`
}

type profileRequest struct {
	Name           string            `json:"name"`
	RunAs          string            `json:"run_as"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	Retries        int               `json:"retries"`
	RebootBehavior string            `json:"reboot_behavior"`
	WorkingDir     string            `json:"working_dir"`
	EnvVars        map[string]string `json:"env_vars"`
}

type groupRequest struct {
	Name            string `json:"name"`
	CategoryID      *int   `json:"category_id"`
	PolicyID        *int   `json:"policy_id"`
	ScriptProfileID *int   `json:"script_profile_id"`
	PatchProfileID  *int   `json:"patch_profile_id"`
}

type groupMemberRequest struct {
	AgentID string `json:"agent_id"`
}

func governancePageHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := requireAdminPage(w, r, cfg, false); !ok {
			return
		}
		if settingsTemplate == nil {
			http.Error(w, "Template not loaded", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = settingsTemplate.Execute(w, map[string]interface{}{
			"Now": time.Now().Format("2006-01-02 15:04:05"),
		})
	}
}

func categoriesHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodGet:
			list, err := server.ListCategories(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			respondJSON(w, http.StatusOK, list)
		case http.MethodPost:
			var req categoryRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			created, err := server.CreateCategory(ctx, req.Name, req.Description)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			respondJSON(w, http.StatusCreated, created)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func categoryHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		id, ok := parseIDFromPath(r.URL.Path)
		if !ok {
			http.Error(w, "Invalid category id", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var req categoryRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if err := server.UpdateCategory(ctx, id, req.Name, req.Description); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if err := server.DeleteCategory(ctx, id); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func policiesHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			list, err := server.ListPolicies(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			respondJSON(w, http.StatusOK, list)
		case http.MethodPost:
			var req policyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			policy := server.GroupPolicy{
				Name:                 req.Name,
				Description:          req.Description,
				ScriptAllowlist:      req.ScriptAllowlist,
				ScriptDenylist:       req.ScriptDenylist,
				PatchWindows:         req.PatchWindows,
				MaxConcurrentScripts: req.MaxConcurrentScripts,
				RequireAdminApproval: req.RequireAdminApproval,
				OnlineOnly:           req.OnlineOnly,
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			created, err := server.CreatePolicy(ctx, policy)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			respondJSON(w, http.StatusCreated, created)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func policyHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		id, ok := parseIDFromPath(r.URL.Path)
		if !ok {
			http.Error(w, "Invalid policy id", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var req policyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			policy := server.GroupPolicy{
				Name:                 req.Name,
				Description:          req.Description,
				ScriptAllowlist:      req.ScriptAllowlist,
				ScriptDenylist:       req.ScriptDenylist,
				PatchWindows:         req.PatchWindows,
				MaxConcurrentScripts: req.MaxConcurrentScripts,
				RequireAdminApproval: req.RequireAdminApproval,
				OnlineOnly:           req.OnlineOnly,
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if err := server.UpdatePolicy(ctx, id, policy); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if err := server.DeletePolicy(ctx, id); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func profileHandler(cfg config.ServerConfig, kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		id, hasID := parseIDFromPath(r.URL.Path)
		switch r.Method {
		case http.MethodGet:
			if hasID {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			var list []server.ExecutionProfile
			var err error
			if kind == "script" {
				list, err = server.ListScriptProfiles(r.Context())
			} else {
				list, err = server.ListPatchProfiles(r.Context())
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			respondJSON(w, http.StatusOK, list)
		case http.MethodPost:
			var req profileRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			profile := server.ExecutionProfile{
				Name:           req.Name,
				RunAs:          req.RunAs,
				TimeoutSeconds: req.TimeoutSeconds,
				Retries:        req.Retries,
				RebootBehavior: req.RebootBehavior,
				WorkingDir:     req.WorkingDir,
				EnvVars:        req.EnvVars,
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			var created *server.ExecutionProfile
			var err error
			if kind == "script" {
				created, err = server.CreateScriptProfile(ctx, profile)
			} else {
				created, err = server.CreatePatchProfile(ctx, profile)
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			respondJSON(w, http.StatusCreated, created)
		case http.MethodPut:
			if !hasID {
				http.Error(w, "Missing profile id", http.StatusBadRequest)
				return
			}
			var req profileRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			profile := server.ExecutionProfile{
				Name:           req.Name,
				RunAs:          req.RunAs,
				TimeoutSeconds: req.TimeoutSeconds,
				Retries:        req.Retries,
				RebootBehavior: req.RebootBehavior,
				WorkingDir:     req.WorkingDir,
				EnvVars:        req.EnvVars,
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if kind == "script" {
				if err := server.UpdateScriptProfile(ctx, id, profile); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			} else {
				if err := server.UpdatePatchProfile(ctx, id, profile); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if !hasID {
				http.Error(w, "Missing profile id", http.StatusBadRequest)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if kind == "script" {
				if err := server.DeleteScriptProfile(ctx, id); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			} else {
				if err := server.DeletePatchProfile(ctx, id); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func groupsHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			list, err := server.ListGroups(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			respondJSON(w, http.StatusOK, list)
		case http.MethodPost:
			var req groupRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			group := server.AgentGroup{
				Name:            req.Name,
				CategoryID:      req.CategoryID,
				PolicyID:        req.PolicyID,
				ScriptProfileID: req.ScriptProfileID,
				PatchProfileID:  req.PatchProfileID,
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			created, err := server.CreateGroup(ctx, group)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			respondJSON(w, http.StatusCreated, created)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func groupHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		id, ok := parseIDFromPath(r.URL.Path)
		if !ok {
			http.Error(w, "Invalid group id", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var req groupRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			group := server.AgentGroup{
				Name:            req.Name,
				CategoryID:      req.CategoryID,
				PolicyID:        req.PolicyID,
				ScriptProfileID: req.ScriptProfileID,
				PatchProfileID:  req.PatchProfileID,
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if err := server.UpdateGroup(ctx, id, group); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if err := server.DeleteGroup(ctx, id); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func groupMembersHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		groupID, ok := parseGroupIDFromMembersPath(r.URL.Path)
		if !ok {
			http.Error(w, "Invalid group id", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			list, err := server.ListGroupMembers(r.Context(), groupID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			respondJSON(w, http.StatusOK, list)
		case http.MethodPost:
			var req groupMemberRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if err := server.AddGroupMember(ctx, groupID, req.AgentID); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func groupRouter(cfg config.ServerConfig) http.HandlerFunc {
	memberHandler := groupMemberHandler(cfg)
	membersHandler := groupMembersHandler(cfg)
	baseHandler := groupHandler(cfg)

	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/groups/")
		if strings.Contains(path, "/members/") {
			memberHandler(w, r)
			return
		}
		if strings.HasSuffix(path, "/members") {
			membersHandler(w, r)
			return
		}
		baseHandler(w, r)
	}
}

func groupMemberHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		groupID, ok := parseGroupIDFromMembersPath(r.URL.Path)
		if !ok {
			http.Error(w, "Invalid group id", http.StatusBadRequest)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 4 {
			http.Error(w, "Missing agent id", http.StatusBadRequest)
			return
		}
		agentID := parts[len(parts)-1]
		if agentID == "" {
			http.Error(w, "Missing agent id", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := server.RemoveGroupMember(ctx, groupID, agentID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func parseIDFromPath(path string) (int, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return 0, false
	}
	value := parts[len(parts)-1]
	id, err := strconv.Atoi(value)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

func parseGroupIDFromMembersPath(path string) (int, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 4 {
		return 0, false
	}
	if parts[0] != "api" || parts[1] != "groups" {
		return 0, false
	}
	id, err := strconv.Atoi(parts[2])
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

func respondJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}
