package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

// AgentUpdateVersion is a published agent binary version record stored in the DB.
type AgentUpdateVersion struct {
	ID          int       `json:"id"`
	Version     string    `json:"version"`
	DownloadURL string    `json:"download_url"`
	SHA256      string    `json:"sha256"`
	Changelog   string    `json:"changelog"`
	PublishedAt time.Time `json:"published_at"`
	PublishedBy string    `json:"published_by"`
	IsActive    bool      `json:"is_active"`
}

// GetLatestAgentUpdateVersion returns the most recently published active version,
// or an error with the text "not found" if no version has been published yet.
func GetLatestAgentUpdateVersion(ctx context.Context) (*AgentUpdateVersion, error) {
	query := `
	SELECT id, version, download_url, sha256, changelog, published_at, published_by, is_active
	FROM agent_update_versions
	WHERE is_active = TRUE
	ORDER BY published_at DESC
	LIMIT 1
	`

	var v AgentUpdateVersion
	err := DB.QueryRow(ctx, query).Scan(
		&v.ID, &v.Version, &v.DownloadURL, &v.SHA256,
		&v.Changelog, &v.PublishedAt, &v.PublishedBy, &v.IsActive,
	)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, fmt.Errorf("not found: no agent version has been published")
		}
		return nil, fmt.Errorf("failed to query latest agent version: %w", err)
	}
	return &v, nil
}

// ListAgentUpdateVersions returns all published versions, newest first.
func ListAgentUpdateVersions(ctx context.Context) ([]AgentUpdateVersion, error) {
	query := `
	SELECT id, version, download_url, sha256, changelog, published_at, published_by, is_active
	FROM agent_update_versions
	ORDER BY published_at DESC
	`

	rows, err := DB.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list agent versions: %w", err)
	}
	defer rows.Close()

	var versions []AgentUpdateVersion
	for rows.Next() {
		var v AgentUpdateVersion
		if err := rows.Scan(
			&v.ID, &v.Version, &v.DownloadURL, &v.SHA256,
			&v.Changelog, &v.PublishedAt, &v.PublishedBy, &v.IsActive,
		); err != nil {
			return nil, fmt.Errorf("failed to scan agent version row: %w", err)
		}
		versions = append(versions, v)
	}
	return versions, nil
}

// PublishAgentUpdateVersion upserts a version record. If the version string
// already exists, its download_url, sha256, and changelog are updated in-place.
// All previously active versions remain active — admins can mark old ones
// inactive via future management endpoints. Published_by is the admin username.
func PublishAgentUpdateVersion(ctx context.Context, version, downloadURL, sha256hex, changelog, publishedBy string) (*AgentUpdateVersion, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		return nil, fmt.Errorf("version is required")
	}
	if downloadURL == "" {
		return nil, fmt.Errorf("download_url is required")
	}
	if len(sha256hex) != 64 {
		return nil, fmt.Errorf("sha256 must be a 64-character hex string")
	}

	query := `
	INSERT INTO agent_update_versions (version, download_url, sha256, changelog, published_by, is_active)
	VALUES ($1, $2, $3, $4, $5, TRUE)
	ON CONFLICT (version) DO UPDATE SET
		download_url = EXCLUDED.download_url,
		sha256       = EXCLUDED.sha256,
		changelog    = EXCLUDED.changelog,
		published_by = EXCLUDED.published_by,
		published_at = CURRENT_TIMESTAMP,
		is_active    = TRUE
	RETURNING id, version, download_url, sha256, changelog, published_at, published_by, is_active
	`

	var v AgentUpdateVersion
	if err := DB.QueryRow(ctx, query, version, downloadURL, sha256hex, changelog, publishedBy).Scan(
		&v.ID, &v.Version, &v.DownloadURL, &v.SHA256,
		&v.Changelog, &v.PublishedAt, &v.PublishedBy, &v.IsActive,
	); err != nil {
		return nil, fmt.Errorf("failed to publish agent version: %w", err)
	}
	return &v, nil
}

// BuildSignedAgentUpdateManifest creates a time-limited, agent-bound, HMAC-SHA256-signed
// manifest that the agent's self_update handler will verify before staging.
//
// TTL defaults to 60 minutes if ttlMinutes <= 0.
// The signing key is resolved from UPDATE_MANIFEST_SIGNING_KEY → AGENT_JWT_SECRET.
func BuildSignedAgentUpdateManifest(agentID string, ver *AgentUpdateVersion, ttlMinutes int) (transport.AgentUpdateManifest, error) {
	if ttlMinutes <= 0 {
		ttlMinutes = 60
	}
	now := time.Now().UTC()

	m := transport.AgentUpdateManifest{
		Version:     ver.Version,
		AgentID:     agentID,
		DownloadURL: ver.DownloadURL,
		SHA256:      ver.SHA256,
		Changelog:   ver.Changelog,
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Duration(ttlMinutes) * time.Minute),
	}

	signingKey, err := resolveUpdateManifestSigningKey()
	if err != nil {
		return transport.AgentUpdateManifest{}, err
	}

	payload, err := canonicalAgentUpdateManifestPayload(m)
	if err != nil {
		return transport.AgentUpdateManifest{}, fmt.Errorf("failed to canonicalize agent update manifest: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(signingKey))
	_, _ = mac.Write(payload)
	m.Signature = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	m.SignatureScheme = "hmac-sha256"

	return m, nil
}

// VerifyAgentUpdateManifest checks the HMAC-SHA256 signature and expiry of a
// received manifest. Returns nil if the manifest is authentic and unexpired.
func VerifyAgentUpdateManifest(m transport.AgentUpdateManifest) error {
	if time.Now().UTC().After(m.ExpiresAt) {
		return fmt.Errorf("agent update manifest has expired at %s", m.ExpiresAt.Format(time.RFC3339))
	}

	// Reconstruct verification copy without signature fields
	check := transport.AgentUpdateManifest{
		Version:     m.Version,
		AgentID:     m.AgentID,
		DownloadURL: m.DownloadURL,
		SHA256:      m.SHA256,
		Changelog:   m.Changelog,
		IssuedAt:    m.IssuedAt,
		ExpiresAt:   m.ExpiresAt,
	}

	signingKey, err := resolveUpdateManifestSigningKey()
	if err != nil {
		return err
	}

	payload, err := canonicalAgentUpdateManifestPayload(check)
	if err != nil {
		return fmt.Errorf("failed to canonicalize agent update manifest for verification: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(signingKey))
	_, _ = mac.Write(payload)
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if m.Signature != expected {
		return fmt.Errorf("agent update manifest signature is invalid")
	}
	return nil
}

// canonicalAgentUpdateManifestPayload produces the deterministic JSON bytes
// that are signed / verified (signature fields excluded).
func canonicalAgentUpdateManifestPayload(m transport.AgentUpdateManifest) ([]byte, error) {
	type canonical struct {
		Version     string    `json:"version"`
		AgentID     string    `json:"agent_id"`
		DownloadURL string    `json:"download_url"`
		SHA256      string    `json:"sha256"`
		Changelog   string    `json:"changelog"`
		IssuedAt    time.Time `json:"issued_at"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	return json.Marshal(canonical{
		Version:     m.Version,
		AgentID:     m.AgentID,
		DownloadURL: m.DownloadURL,
		SHA256:      m.SHA256,
		Changelog:   m.Changelog,
		IssuedAt:    m.IssuedAt,
		ExpiresAt:   m.ExpiresAt,
	})
}

// QueueAgentUpdateCommand builds a signed manifest for the given agent,
// inserts an agent_commands row of type "agent_update", and records an
// agent_update_installs row for tracking.
func QueueAgentUpdateCommand(ctx context.Context, agentID string, ttlMinutes int) (*AgentCommand, error) {
	ver, err := GetLatestAgentUpdateVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("no publishable agent version: %w", err)
	}

	manifest, err := BuildSignedAgentUpdateManifest(agentID, ver, ttlMinutes)
	if err != nil {
		return nil, fmt.Errorf("failed to build signed agent update manifest: %w", err)
	}

	payloadBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize agent update manifest: %w", err)
	}

	cmd, err := CreateCommand(ctx, agentID, "agent_update", string(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create agent_update command: %w", err)
	}

	// Record in the installs tracking table (best-effort; non-fatal on failure)
	_, _ = DB.Exec(ctx,
		`INSERT INTO agent_update_installs (agent_id, command_id, target_version, status)
		 VALUES ($1, $2, $3, 'queued')`,
		agentID, cmd.ID, ver.Version,
	)

	return cmd, nil
}

// RecordAgentUpdateInstallResult updates the install tracking row for the given
// command_id when the agent ACKs the command.
func RecordAgentUpdateInstallResult(ctx context.Context, commandID int64, status, output, errText string) error {
	_, err := DB.Exec(ctx,
		`UPDATE agent_update_installs
		 SET status = $1, output = $2, error = $3, completed_at = CURRENT_TIMESTAMP
		 WHERE command_id = $4`,
		status, output, errText, commandID,
	)
	return err
}

// ListAgentUpdateInstalls returns the install history for one agent, newest first.
func ListAgentUpdateInstalls(ctx context.Context, agentID string) ([]map[string]interface{}, error) {
	query := `
	SELECT i.id, i.agent_id, i.command_id, i.target_version, i.status,
	       i.output, i.error, i.queued_at, i.completed_at
	FROM agent_update_installs i
	WHERE i.agent_id = $1
	ORDER BY i.queued_at DESC
	LIMIT 50
	`

	rows, err := DB.Query(ctx, query, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to query agent update installs: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var (
			id            int64
			aid, ver, sta string
			out, errT     string
			cmdID         *int64
			queuedAt      time.Time
			completedAt   *time.Time
		)
		if err := rows.Scan(&id, &aid, &cmdID, &ver, &sta, &out, &errT, &queuedAt, &completedAt); err != nil {
			return nil, err
		}
		results = append(results, map[string]interface{}{
			"id":             id,
			"agent_id":       aid,
			"command_id":     cmdID,
			"target_version": ver,
			"status":         sta,
			"output":         out,
			"error":          errT,
			"queued_at":      queuedAt,
			"completed_at":   completedAt,
		})
	}
	return results, nil
}

// QueueAgentUpdateCommandsBulk queues signed agent_update commands for many agents.
// It returns created command IDs per agent and a map of agent-level errors.
func QueueAgentUpdateCommandsBulk(ctx context.Context, agentIDs []string, ttlMinutes int) (map[string]int64, map[string]string) {
	results := make(map[string]int64)
	errorsByAgent := make(map[string]string)

	for _, rawID := range agentIDs {
		agentID := strings.TrimSpace(rawID)
		if agentID == "" {
			continue
		}

		cmd, err := QueueAgentUpdateCommand(ctx, agentID, ttlMinutes)
		if err != nil {
			errorsByAgent[agentID] = err.Error()
			continue
		}
		results[agentID] = cmd.ID
	}

	return results, errorsByAgent
}
