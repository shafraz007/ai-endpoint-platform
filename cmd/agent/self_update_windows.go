//go:build windows

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
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/auth"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

// handleAgentSelfUpdate is the Windows implementation of the "agent_update" command.
//
// Flow:
//  1. Parse + verify signed manifest
//  2. Skip if already at target version
//  3. Download binary to ProgramData\armada\updates\{version}.exe with agent JWT
//  4. Verify SHA-256
//  5. Write updater.ps1 to a temp file
//  6. Register a one-time SYSTEM/Highest scheduled task to run the updater
//  7. Signal the main loop to call os.Exit(0) after the ACK is sent
func handleAgentSelfUpdate(payload, agentID, currentVersion string, cfg config.AgentConfig) (string, string, string) {
	var manifest transport.AgentUpdateManifest
	if err := json.Unmarshal([]byte(payload), &manifest); err != nil {
		return "failed", "", "invalid agent_update payload: " + err.Error()
	}

	// Ensure manifest is addressed to this agent
	if strings.TrimSpace(manifest.AgentID) != "" && manifest.AgentID != agentID {
		return "failed", "", fmt.Sprintf("manifest is for agent %q, not %q", manifest.AgentID, agentID)
	}

	// Check expiry
	if time.Now().UTC().After(manifest.ExpiresAt) {
		return "failed", "", fmt.Sprintf("manifest expired at %s", manifest.ExpiresAt.Format(time.RFC3339))
	}

	// Verify HMAC-SHA256 signature
	if err := verifyAgentUpdateManifestSig(manifest, cfg.JWTSecret); err != nil {
		return "failed", "", "manifest signature invalid: " + err.Error()
	}

	// Already at target version — nothing to do
	if currentVersion != "" && currentVersion == manifest.Version {
		return "succeeded", "already at version " + manifest.Version, ""
	}

	// Prepare staging directory
	stagingDir := filepath.Join(os.Getenv("ProgramData"), "armada", "updates")
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		return "failed", "", "failed to create staging dir: " + err.Error()
	}
	stagingPath := filepath.Join(stagingDir, strings.ReplaceAll(manifest.Version, "/", "_")+".exe")

	// Download the binary
	log.Printf("[agent_update] downloading version %s to %s", manifest.Version, stagingPath)
	if err := downloadAgentBinary(manifest, cfg, stagingPath); err != nil {
		_ = os.Remove(stagingPath)
		return "failed", "", "download failed: " + err.Error()
	}

	// Verify SHA-256
	log.Printf("[agent_update] verifying SHA-256 for %s", stagingPath)
	if err := verifyFileSHA256(stagingPath, manifest.SHA256); err != nil {
		_ = os.Remove(stagingPath)
		return "failed", "", "SHA-256 verification failed: " + err.Error()
	}

	// Resolve the current executable path (what we need to replace)
	execPath, err := os.Executable()
	if err != nil {
		_ = os.Remove(stagingPath)
		return "failed", "", "failed to resolve executable path: " + err.Error()
	}
	execPath = filepath.Clean(execPath)

	// Write updater script and register the scheduled task
	log.Printf("[agent_update] staging update: %s → %s", stagingPath, execPath)
	if err := stageWindowsUpdate(manifest.Version, stagingPath, execPath); err != nil {
		_ = os.Remove(stagingPath)
		return "failed", "", "failed to stage update: " + err.Error()
	}

	// Tell the main loop to exit cleanly after the ACK is sent
	agentUpdateStaged.Store(true)

	msg := fmt.Sprintf("update to %s staged; ArmadaAgent service will restart automatically", manifest.Version)
	log.Printf("[agent_update] %s", msg)
	return "succeeded", msg, ""
}

// verifyAgentUpdateManifestSig checks the HMAC-SHA256 signature of the manifest.
// Key resolution: UPDATE_MANIFEST_SIGNING_KEY env var → fallbackKey (cfg.JWTSecret).
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

// downloadAgentBinary downloads the binary from manifest.DownloadURL.
// If the URL is relative (starts with "/"), it is rewritten to cfg.ServerURL.
// The download is authenticated with an agent JWT Bearer token.
func downloadAgentBinary(manifest transport.AgentUpdateManifest, cfg config.AgentConfig, destPath string) error {
	dlURL := strings.TrimSpace(manifest.DownloadURL)
	if dlURL == "" {
		return fmt.Errorf("manifest download_url is empty")
	}

	// Rewrite relative paths to the configured server URL
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

	client := &http.Client{Timeout: 10 * time.Minute} // large binary; generous timeout
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

// verifyFileSHA256 computes the SHA-256 of the file at path and compares it
// to the expected lowercase hex string.
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

// stageWindowsUpdate writes the updater PowerShell script to disk and
// launches it in a detached PowerShell process. This avoids Task Scheduler
// timing/permission issues while still running under the service account.
func stageWindowsUpdate(version, stagingPath, destPath string) error {
	// Build the updater script
	scriptContent := buildUpdaterScript(version, stagingPath, destPath)

	// Write script to temp directory
	scriptPath := filepath.Join(os.Getenv("TEMP"), fmt.Sprintf("armada_update_%s.ps1", strings.ReplaceAll(version, "/", "_")))
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0600); err != nil {
		return fmt.Errorf("failed to write updater script: %w", err)
	}

	// Launch the updater script in a detached process.
	psLaunch := fmt.Sprintf(`Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File','%s') -WindowStyle Hidden`, scriptPath)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psLaunch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to launch detached updater process: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	log.Printf("[agent_update] detached updater process launched; updater: %s", scriptPath)
	return nil
}

// buildUpdaterScript returns the PowerShell script that performs the actual
// file swap and service restart.
func buildUpdaterScript(version, stagingPath, destPath string) string {
	return fmt.Sprintf(`# Armada Agent Self-Update — generated by agent version %s
param()
$ErrorActionPreference = 'Stop'
$logFile = Join-Path $env:ProgramData 'armada\updates\self-update.log'

try {
	$logDir = Split-Path -Parent $logFile
	if ($logDir -and -not (Test-Path $logDir)) {
		New-Item -ItemType Directory -Path $logDir -Force | Out-Null
	}
} catch {}

function Write-UpdateLog {
    param([string]$msg)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [ArmadaAgentUpdate] $msg"
    Write-Output $line
	try {
		Add-Content -Path $logFile -Value $line
	} catch {}
    try {
        Write-EventLog -LogName Application -Source 'ArmadaAgent' -EventId 9001 -EntryType Information -Message $line -ErrorAction SilentlyContinue
    } catch {}
}

try {
    Write-UpdateLog "Starting update to version %s"

    $serviceName = 'ArmadaAgent'
    $src  = '%s'
    $dest = '%s'

	$deadline = (Get-Date).AddSeconds(45)
	$copied = $false
	while ((Get-Date) -lt $deadline -and -not $copied) {
		$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
		if ($svc -and $svc.Status -ne 'Stopped') {
			Write-UpdateLog "Stopping $serviceName service..."
			Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
			Start-Sleep -Seconds 2
		}

		try {
			Write-UpdateLog "Copying $src -> $dest"
			Copy-Item -Path $src -Destination $dest -Force
			$copied = $true
			Write-UpdateLog "Binary copy completed."
		} catch {
			Write-UpdateLog "Copy attempt failed: $($_.Exception.Message). Retrying..."
			Start-Sleep -Seconds 2
		}
	}

	if (-not $copied) {
		throw "timed out replacing $dest"
	}

    Write-UpdateLog "Starting $serviceName service..."
    Start-Service -Name $serviceName

    Write-UpdateLog "Update to version %s complete."

    # Clean up staging binary
    Remove-Item -Path $src -Force -ErrorAction SilentlyContinue

} catch {
    $errMsg = $_.ToString()
    Write-UpdateLog "Update FAILED: $errMsg"
    try {
        Write-EventLog -LogName Application -Source 'ArmadaAgent' -EventId 9002 -EntryType Error -Message "Armada agent update failed: $errMsg" -ErrorAction SilentlyContinue
    } catch {}
} finally {
    # Self-delete this script
    $me = $MyInvocation.MyCommand.Path
    if ($me -and (Test-Path $me)) {
        Remove-Item -Path $me -Force -ErrorAction SilentlyContinue
    }
}
`,
		version, // for the comment
		version, // Write-UpdateLog "Starting update to version X"
		stagingPath,
		destPath,
		version, // Write-UpdateLog "Update to version X complete."
	)
}
