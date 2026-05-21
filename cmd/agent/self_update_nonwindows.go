//go:build !windows

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/auth"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

// handleAgentSelfUpdate performs in-place self-update on Linux by atomically
// replacing the current executable path with a verified downloaded binary.
//
// macOS remains unsupported for now.
func handleAgentSelfUpdate(payload, agentID, currentVersion string, cfg config.AgentConfig) (string, string, string) {
	if runtime.GOOS != "linux" {
		return "failed", "", "agent self-update is only supported on linux and windows"
	}

	var manifest transport.AgentUpdateManifest
	if err := json.Unmarshal([]byte(payload), &manifest); err != nil {
		return "failed", "", "invalid agent_update payload: " + err.Error()
	}

	if strings.TrimSpace(manifest.AgentID) != "" && manifest.AgentID != agentID {
		return "failed", "", fmt.Sprintf("manifest is for agent %q, not %q", manifest.AgentID, agentID)
	}

	if time.Now().UTC().After(manifest.ExpiresAt) {
		return "failed", "", fmt.Sprintf("manifest expired at %s", manifest.ExpiresAt.Format(time.RFC3339))
	}

	if err := verifyAgentUpdateManifestSig(manifest, cfg.JWTSecret); err != nil {
		return "failed", "", "manifest signature invalid: " + err.Error()
	}

	if currentVersion != "" && currentVersion == manifest.Version {
		return "succeeded", "already at version " + manifest.Version, ""
	}

	execPath, err := os.Executable()
	if err != nil {
		return "failed", "", "failed to resolve executable path: " + err.Error()
	}
	execPath = filepath.Clean(execPath)

	targetDir := filepath.Dir(execPath)
	stageName := fmt.Sprintf(".%s.%d.new", filepath.Base(execPath), time.Now().UnixNano())
	stagePath := filepath.Join(targetDir, stageName)

	log.Printf("[agent_update/linux] downloading version %s to %s", manifest.Version, stagePath)
	if err := downloadAgentBinary(manifest, cfg, stagePath); err != nil {
		_ = os.Remove(stagePath)
		return "failed", "", "download failed: " + err.Error()
	}

	if err := os.Chmod(stagePath, 0755); err != nil {
		_ = os.Remove(stagePath)
		return "failed", "", "failed to set executable permission: " + err.Error()
	}

	log.Printf("[agent_update/linux] verifying SHA-256 for %s", stagePath)
	if err := verifyFileSHA256(stagePath, manifest.SHA256); err != nil {
		_ = os.Remove(stagePath)
		return "failed", "", "SHA-256 verification failed: " + err.Error()
	}

	log.Printf("[agent_update/linux] replacing executable %s", execPath)
	if err := os.Rename(stagePath, execPath); err != nil {
		_ = os.Remove(stagePath)
		return "failed", "", "failed to replace executable: " + err.Error()
	}

	agentUpdateStaged.Store(true)

	msg := fmt.Sprintf("linux update to %s staged; agent process will restart", manifest.Version)
	log.Printf("[agent_update/linux] %s", msg)
	return "succeeded", msg, ""
}

func verifyAgentUpdateManifestSig(m transport.AgentUpdateManifest, fallbackKey string) error {
	key := strings.TrimSpace(os.Getenv("UPDATE_MANIFEST_SIGNING_KEY"))
	if key == "" {
		key = strings.TrimSpace(fallbackKey)
	}
	if key == "" {
		return fmt.Errorf("no signing key available for manifest verification")
	}

	type canonical struct {
		Version     string    `json:"version"`
		AgentID     string    `json:"agent_id"`
		DownloadURL string    `json:"download_url"`
		SHA256      string    `json:"sha256"`
		Changelog   string    `json:"changelog"`
		IssuedAt    time.Time `json:"issued_at"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	payload, err := json.Marshal(canonical{
		Version:     m.Version,
		AgentID:     m.AgentID,
		DownloadURL: m.DownloadURL,
		SHA256:      m.SHA256,
		Changelog:   m.Changelog,
		IssuedAt:    m.IssuedAt,
		ExpiresAt:   m.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("failed to canonicalize manifest: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(payload)
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(m.Signature), []byte(expected)) {
		return fmt.Errorf("signature does not match")
	}
	return nil
}

func downloadAgentBinary(manifest transport.AgentUpdateManifest, cfg config.AgentConfig, destPath string) error {
	dlURL := strings.TrimSpace(manifest.DownloadURL)
	if dlURL == "" {
		return fmt.Errorf("manifest download_url is empty")
	}
	if strings.HasPrefix(dlURL, "/") {
		dlURL = strings.TrimRight(cfg.ServerURL, "/") + dlURL
	}

	token, err := auth.GenerateToken(manifest.AgentID, "agent", cfg.JWTSecret, cfg.JWTTTL)
	if err != nil {
		return fmt.Errorf("failed to generate agent token for download: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, dlURL, nil)
	if err != nil {
		return fmt.Errorf("failed to build download request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("download server returned HTTP %s", resp.Status)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create staging file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("failed to write staging file: %w", err)
	}
	return nil
}

func verifyFileSHA256(path, expectedHex string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file for hashing: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("failed to hash file: %w", err)
	}

	actualHex := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actualHex, strings.TrimSpace(expectedHex)) {
		return fmt.Errorf("expected %s, got %s", strings.ToLower(expectedHex), actualHex)
	}
	return nil
}
