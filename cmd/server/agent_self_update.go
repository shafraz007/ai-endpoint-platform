package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

// agentSelfUpdateRouter handles /api/agent-update/* routes.
//
//	GET  /api/agent-update/version          — latest published version (admin or agent JWT)
//	PUT  /api/agent-update/version          — publish / overwrite a version (admin only)
//	GET  /api/agent-update/versions         — list all published versions (admin only)
//	POST /api/agent-update/upload           — upload binary into AGENT_UPDATE_DIR (admin only)
//	POST /api/agent-update/install/bulk     — queue update command for multiple agents (admin only)
//	GET  /api/agent-update/download/{ver}   — serve binary from AGENT_UPDATE_DIR (agent JWT)
func agentSelfUpdateRouter(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/agent-update/")
		parts := strings.SplitN(path, "/", 3)
		segment := strings.TrimSpace(parts[0])

		switch {
		case segment == "version" && r.Method == http.MethodGet:
			// Accept either admin session/JWT or agent bearer JWT
			if !authorizeAgentOrAdmin(w, r, cfg) {
				return
			}
			handleGetLatestAgentVersion(w, r)

		case segment == "version" && r.Method == http.MethodPut:
			if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			handlePublishAgentVersion(w, r, cfg)

		case segment == "versions" && r.Method == http.MethodGet:
			if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			handleListAgentVersions(w, r)

		case segment == "upload" && r.Method == http.MethodPost:
			if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			handleUploadAgentBinary(w, r, cfg)

		case segment == "install" && len(parts) >= 2 && strings.TrimSpace(parts[1]) == "bulk" && r.Method == http.MethodPost:
			if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			handleBulkAgentUpdateInstall(w, r)

		case segment == "download" && len(parts) >= 2 && r.Method == http.MethodGet:
			version := strings.TrimSpace(parts[1])
			if version == "" {
				http.Error(w, "version is required", http.StatusBadRequest)
				return
			}
			// Only agents (with valid JWT) can pull the binary
			claims, err := requireAgent(r, cfg.AgentJWTSecret)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			log.Printf("Agent %s requested binary download for version %s", claims.Subject, version)
			handleAgentBinaryDownload(w, r, cfg, version)

		default:
			http.NotFound(w, r)
		}
	}
}

// authorizeAgentOrAdmin returns true if the request carries a valid admin JWT/session
// OR a valid agent bearer JWT. On failure it writes the HTTP error and returns false.
func authorizeAgentOrAdmin(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) bool {
	// Try agent JWT first (lightweight — just a bearer token check)
	if cfg.AgentJWTSecret != "" {
		if _, err := requireAgent(r, cfg.AgentJWTSecret); err == nil {
			return true
		}
	}
	// Fall back to admin session / admin JWT
	if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return false
	}
	return true
}

func handleGetLatestAgentVersion(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ver, err := server.GetLatestAgentUpdateVersion(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "no agent version published yet", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to fetch latest version", http.StatusInternalServerError)
		return
	}

	resp := transport.AgentVersionInfo{
		Version:     ver.Version,
		DownloadURL: ver.DownloadURL,
		SHA256:      ver.SHA256,
		Changelog:   ver.Changelog,
		PublishedAt: ver.PublishedAt,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handlePublishAgentVersion(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	var req transport.PublishAgentVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	req.Version = strings.TrimSpace(req.Version)
	req.DownloadURL = strings.TrimSpace(req.DownloadURL)
	req.SHA256 = strings.ToLower(strings.TrimSpace(req.SHA256))

	if req.Version == "" || req.DownloadURL == "" || req.SHA256 == "" {
		http.Error(w, "version, download_url and sha256 are required", http.StatusBadRequest)
		return
	}

	// Validate that a file exists locally when using server-hosted URL
	if strings.HasPrefix(req.DownloadURL, "/api/agent-update/download/") {
		if cfg.AgentUpdateDir == "" {
			http.Error(w, "AGENT_UPDATE_DIR is not configured — cannot use server-hosted download URL", http.StatusBadRequest)
			return
		}
		binPath := filepath.Join(cfg.AgentUpdateDir, sanitizeVersionFilename(req.Version))
		if _, statErr := os.Stat(binPath); statErr != nil {
			http.Error(w, fmt.Sprintf("binary file not found in AGENT_UPDATE_DIR: %s", req.Version), http.StatusBadRequest)
			return
		}
	}

	// Determine who is publishing
	publishedBy := "admin"
	if claims, _, err := authorizeAdminRequest(nil, r, cfg); err == nil && claims != nil {
		if s := strings.TrimSpace(claims.Subject); s != "" {
			publishedBy = s
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ver, err := server.PublishAgentUpdateVersion(ctx, req.Version, req.DownloadURL, req.SHA256, req.Changelog, publishedBy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("Agent version %s published by %s (download: %s)", ver.Version, ver.PublishedBy, ver.DownloadURL)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ver)
}

func handleListAgentVersions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	versions, err := server.ListAgentUpdateVersions(ctx)
	if err != nil {
		http.Error(w, "failed to list versions", http.StatusInternalServerError)
		return
	}
	if versions == nil {
		versions = []server.AgentUpdateVersion{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(versions)
}

func handleAgentBinaryDownload(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig, version string) {
	if cfg.AgentUpdateDir == "" {
		http.Error(w, "server-hosted downloads are not configured (AGENT_UPDATE_DIR not set)", http.StatusServiceUnavailable)
		return
	}

	filename := sanitizeVersionFilename(version)
	filePath := filepath.Join(cfg.AgentUpdateDir, filename)

	f, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "binary not found for version "+version, http.StatusNotFound)
			return
		}
		http.Error(w, "failed to open binary", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		http.Error(w, "failed to stat binary", http.StatusInternalServerError)
		return
	}

	log.Printf("Serving agent binary %s (%d bytes)", version, fi.Size())
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="agent-%s.exe"`, version))
	w.Header().Set("X-Agent-Version", version)
	http.ServeContent(w, r, filename, fi.ModTime(), f)
}

// sanitizeVersionFilename strips path separators from a version string so it
// can safely be used as a filename under AGENT_UPDATE_DIR.
func sanitizeVersionFilename(version string) string {
	safe := strings.ReplaceAll(version, "/", "_")
	safe = strings.ReplaceAll(safe, "\\", "_")
	safe = strings.ReplaceAll(safe, "..", "_")
	return safe
}

// handleAgentUpdateInstall is called from agentPatchUpdatesRouter when the path
// segment is "agent-update" and the sub-action is "install".
// POST /api/agents/{id}/agent-update/install
func handleAgentUpdateInstall(w http.ResponseWriter, r *http.Request, agentID string) {
	type installReq struct {
		TTLMinutes int `json:"ttl_minutes"`
	}

	var body installReq
	if r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.TTLMinutes <= 0 {
		body.TTLMinutes = 60
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	cmd, err := server.QueueAgentUpdateCommand(ctx, agentID, body.TTLMinutes)
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no publishable") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Queued agent_update command %d for agent %s", cmd.ID, agentID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"command_id": cmd.ID,
		"agent_id":   cmd.AgentID,
		"message":    "agent_update command queued",
	})
}

// handleAgentUpdateHistory returns the install history for an agent.
// GET /api/agents/{id}/agent-update/history
func handleAgentUpdateHistory(w http.ResponseWriter, r *http.Request, agentID string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := server.ListAgentUpdateInstalls(ctx, agentID)
	if err != nil {
		http.Error(w, "failed to fetch update history", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows)
}

func handleUploadAgentBinary(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	if strings.TrimSpace(cfg.AgentUpdateDir) == "" {
		http.Error(w, "AGENT_UPDATE_DIR is not configured", http.StatusBadRequest)
		return
	}

	if err := r.ParseMultipartForm(1 << 30); err != nil {
		http.Error(w, "invalid multipart form", http.StatusBadRequest)
		return
	}

	version := strings.TrimSpace(r.FormValue("version"))
	if version == "" {
		http.Error(w, "version is required", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if err := os.MkdirAll(cfg.AgentUpdateDir, 0o755); err != nil {
		http.Error(w, "failed to prepare update directory", http.StatusInternalServerError)
		return
	}

	filename := sanitizeVersionFilename(version)
	targetPath := filepath.Join(cfg.AgentUpdateDir, filename)
	tmpPath := targetPath + ".uploading"

	out, err := os.Create(tmpPath)
	if err != nil {
		http.Error(w, "failed to create binary file", http.StatusInternalServerError)
		return
	}

	h := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(out, h), file)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(tmpPath)
		http.Error(w, "failed to save uploaded file", http.StatusInternalServerError)
		return
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		http.Error(w, "failed to finalize uploaded file", http.StatusInternalServerError)
		return
	}

	sha := fmt.Sprintf("%x", h.Sum(nil))
	downloadURL := "/api/agent-update/download/" + version

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"version":      version,
		"filename":     filename,
		"bytes":        written,
		"sha256":       sha,
		"download_url": downloadURL,
	})
}

func handleBulkAgentUpdateInstall(w http.ResponseWriter, r *http.Request) {
	type bulkReq struct {
		AgentIDs   []string `json:"agent_ids"`
		TTLMinutes int      `json:"ttl_minutes"`
	}

	var req bulkReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if len(req.AgentIDs) == 0 {
		http.Error(w, "agent_ids is required", http.StatusBadRequest)
		return
	}

	if req.TTLMinutes <= 0 {
		req.TTLMinutes = 60
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	created, errs := server.QueueAgentUpdateCommandsBulk(ctx, req.AgentIDs, req.TTLMinutes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"queued_count": len(created),
		"error_count":  len(errs),
		"queued":       created,
		"errors":       errs,
	})
}
