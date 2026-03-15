package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

type AgentPatchUpdate struct {
	UpdateID       string     `json:"update_id"`
	KBID           string     `json:"kb_id,omitempty"`
	Title          string     `json:"title"`
	Description    string     `json:"description,omitempty"`
	Severity       string     `json:"severity,omitempty"`
	Categories     []string   `json:"categories,omitempty"`
	IsDriver       bool       `json:"is_driver"`
	IsSecurity     bool       `json:"is_security"`
	IsCritical     bool       `json:"is_critical"`
	IsOS           bool       `json:"is_os"`
	IsSoftware     bool       `json:"is_software"`
	RebootRequired bool       `json:"reboot_required"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	Installed      bool       `json:"installed"`
	InstalledAt    *time.Time `json:"installed_at,omitempty"`
	Uninstallable  bool       `json:"uninstallable"`
	ApprovalState  string     `json:"approval_state"`
	PostponedUntil *time.Time `json:"postponed_until,omitempty"`
}

type AggregatedPatchUpdate struct {
	AgentID        string     `json:"agent_id"`
	Hostname       string     `json:"hostname"`
	UpdateID       string     `json:"update_id"`
	KBID           string     `json:"kb_id,omitempty"`
	Title          string     `json:"title"`
	Description    string     `json:"description,omitempty"`
	Severity       string     `json:"severity,omitempty"`
	Categories     []string   `json:"categories,omitempty"`
	IsDriver       bool       `json:"is_driver"`
	IsSecurity     bool       `json:"is_security"`
	IsCritical     bool       `json:"is_critical"`
	IsOS           bool       `json:"is_os"`
	IsSoftware     bool       `json:"is_software"`
	RebootRequired bool       `json:"reboot_required"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	ApprovalState  string     `json:"approval_state"`
	PostponedUntil *time.Time `json:"postponed_until,omitempty"`
}

func UpsertAgentPatchInventory(ctx context.Context, agentID string, updates []transport.PendingUpdate) error {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return fmt.Errorf("agent_id is required")
	}

	tx, err := DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin patch inventory transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := time.Now().UTC()
	seen := map[string]struct{}{}

	for _, item := range updates {
		updateID := strings.TrimSpace(item.UpdateID)
		if updateID == "" {
			continue
		}
		seen[updateID] = struct{}{}

		categories := item.Categories
		if categories == nil {
			categories = []string{}
		}
		categoriesJSON, _ := json.Marshal(categories)
		rawJSON, _ := json.Marshal(item)

		kbID := strings.ToUpper(strings.TrimSpace(item.KBID))

		if _, err := tx.Exec(ctx, `
			INSERT INTO agent_patch_updates (
				agent_id, update_id, kb_id, title, description, severity, categories,
				is_driver, is_security, is_critical, is_os, is_software,
				reboot_required, installed, installed_at, first_seen_at, last_seen_at, raw_json
			)
			VALUES (
				$1, $2, NULLIF($3, ''), $4, $5, $6, $7,
				$8, $9, $10, $11, $12,
				$13, FALSE, NULL, $14, $14, $15
			)
			ON CONFLICT (agent_id, update_id) DO UPDATE SET
				kb_id = EXCLUDED.kb_id,
				title = EXCLUDED.title,
				description = EXCLUDED.description,
				severity = EXCLUDED.severity,
				categories = EXCLUDED.categories,
				is_driver = EXCLUDED.is_driver,
				is_security = EXCLUDED.is_security,
				is_critical = EXCLUDED.is_critical,
				is_os = EXCLUDED.is_os,
				is_software = EXCLUDED.is_software,
				reboot_required = EXCLUDED.reboot_required,
				installed = FALSE,
				installed_at = NULL,
				last_seen_at = EXCLUDED.last_seen_at,
				raw_json = EXCLUDED.raw_json
		`,
			agentID,
			updateID,
			kbID,
			strings.TrimSpace(item.Title),
			strings.TrimSpace(item.Description),
			strings.TrimSpace(item.Severity),
			string(categoriesJSON),
			item.IsDriver,
			item.IsSecurity,
			item.IsCritical,
			item.IsOS,
			item.IsSoftware,
			item.RebootRequired,
			now,
			string(rawJSON),
		); err != nil {
			return fmt.Errorf("failed to upsert patch update %s: %w", updateID, err)
		}
	}

	if len(seen) > 0 {
		ids := make([]string, 0, len(seen))
		for id := range seen {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		if _, err := tx.Exec(ctx, `
			UPDATE agent_patch_updates
			SET installed = TRUE,
			    installed_at = COALESCE(installed_at, $3)
			WHERE agent_id = $1
			  AND installed = FALSE
			  AND NOT (update_id = ANY($2))
		`, agentID, ids, now); err != nil {
			return fmt.Errorf("failed to mark stale updates as installed: %w", err)
		}
	} else {
		if _, err := tx.Exec(ctx, `
			UPDATE agent_patch_updates
			SET installed = TRUE,
			    installed_at = COALESCE(installed_at, $2)
			WHERE agent_id = $1 AND installed = FALSE
		`, agentID, now); err != nil {
			return fmt.Errorf("failed to clear pending updates: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit patch inventory transaction: %w", err)
	}

	return nil
}

func ListAgentPatchUpdates(ctx context.Context, agentID string) ([]AgentPatchUpdate, error) {
	return ListAgentPatchUpdatesByStatus(ctx, agentID, "pending")
}

func ListAgentPatchUpdatesByStatus(ctx context.Context, agentID, status string) ([]AgentPatchUpdate, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}

	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		status = "pending"
	}
	if status != "pending" && status != "installed" && status != "all" {
		return nil, fmt.Errorf("invalid status")
	}

	policy, _ := GetOSPatchPolicy(ctx)

	overrides := map[string]struct {
		Action         string
		PostponedUntil *time.Time
	}{}
	orows, err := DB.Query(ctx, `
		SELECT kb_id, action, postponed_until
		FROM agent_patch_overrides
		WHERE agent_id = $1
	`, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list patch overrides: %w", err)
	}
	for orows.Next() {
		var kbID, action string
		var postponedUntil *time.Time
		if err := orows.Scan(&kbID, &action, &postponedUntil); err != nil {
			orows.Close()
			return nil, fmt.Errorf("failed to scan patch override: %w", err)
		}
		overrides[strings.ToUpper(strings.TrimSpace(kbID))] = struct {
			Action         string
			PostponedUntil *time.Time
		}{Action: strings.ToLower(strings.TrimSpace(action)), PostponedUntil: postponedUntil}
	}
	orows.Close()

	approved := map[string]struct{}{}
	postponed := map[string]struct{}{}
	if policy != nil {
		for _, kb := range policy.ApprovedKBs {
			approved[strings.ToUpper(strings.TrimSpace(kb))] = struct{}{}
		}
		for _, kb := range policy.PostponedKBs {
			postponed[strings.ToUpper(strings.TrimSpace(kb))] = struct{}{}
		}
	}

	query := `
		SELECT update_id, COALESCE(kb_id, ''), title, COALESCE(description, ''), COALESCE(severity, ''), categories,
		       is_driver, is_security, is_critical, is_os, is_software, reboot_required,
		       first_seen_at, last_seen_at, installed, installed_at
		FROM agent_patch_updates
		WHERE agent_id = $1
	`
	orderBy := " ORDER BY is_critical DESC, is_security DESC, is_driver DESC, last_seen_at DESC, title ASC"
	switch status {
	case "pending":
		query += " AND installed = FALSE"
	case "installed":
		query += " AND installed = TRUE"
		orderBy = " ORDER BY COALESCE(installed_at, last_seen_at) DESC, title ASC"
	case "all":
		orderBy = " ORDER BY installed ASC, is_critical DESC, is_security DESC, last_seen_at DESC, title ASC"
	}
	query += orderBy

	rows, err := DB.Query(ctx, query, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list patch updates: %w", err)
	}
	defer rows.Close()

	now := time.Now().UTC()
	items := []AgentPatchUpdate{}
	for rows.Next() {
		var item AgentPatchUpdate
		var categoriesJSON string
		if err := rows.Scan(
			&item.UpdateID,
			&item.KBID,
			&item.Title,
			&item.Description,
			&item.Severity,
			&categoriesJSON,
			&item.IsDriver,
			&item.IsSecurity,
			&item.IsCritical,
			&item.IsOS,
			&item.IsSoftware,
			&item.RebootRequired,
			&item.FirstSeenAt,
			&item.LastSeenAt,
			&item.Installed,
			&item.InstalledAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan patch update: %w", err)
		}
		_ = json.Unmarshal([]byte(categoriesJSON), &item.Categories)

		item.KBID = strings.ToUpper(strings.TrimSpace(item.KBID))
		item.Uninstallable = item.Installed && item.KBID != "" && !item.IsDriver
		item.ApprovalState = "pending_manual"

		if item.KBID != "" {
			if override, ok := overrides[item.KBID]; ok {
				if override.Action == "approved" {
					item.ApprovalState = "approved_manual"
				} else if override.Action == "postponed" {
					item.PostponedUntil = override.PostponedUntil
					if override.PostponedUntil != nil && override.PostponedUntil.After(now) {
						item.ApprovalState = "postponed"
					} else {
						item.ApprovalState = "pending_manual"
					}
				}
			} else {
				if _, ok := approved[item.KBID]; ok {
					item.ApprovalState = "approved_policy"
				}
				if _, ok := postponed[item.KBID]; ok {
					item.ApprovalState = "postponed_policy"
				}
			}
		}

		if policy != nil && policy.KBApprovalMode == "auto" {
			autoAfter := time.Duration(policy.AutoApprovalAfter) * 24 * time.Hour
			if autoAfter <= 0 || item.FirstSeenAt.Add(autoAfter).Before(now) {
				if !strings.HasPrefix(item.ApprovalState, "postponed") {
					item.ApprovalState = "approved_auto"
				}
			}
		}

		if item.Installed {
			item.ApprovalState = "installed"
			item.PostponedUntil = nil
		}

		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate patch updates: %w", err)
	}

	return items, nil
}

func UpsertAgentPatchOverride(ctx context.Context, agentID, kbID, action, updatedBy string, postponeDays int) error {
	agentID = strings.TrimSpace(agentID)
	kbID = strings.ToUpper(strings.TrimSpace(kbID))
	action = strings.ToLower(strings.TrimSpace(action))
	updatedBy = strings.TrimSpace(updatedBy)
	if updatedBy == "" {
		updatedBy = "admin"
	}

	if agentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	if kbID == "" {
		return fmt.Errorf("kb_id is required")
	}

	switch action {
	case "approved", "postponed", "clear":
	default:
		return fmt.Errorf("invalid action")
	}

	if action == "clear" {
		_, err := DB.Exec(ctx, `DELETE FROM agent_patch_overrides WHERE agent_id = $1 AND kb_id = $2`, agentID, kbID)
		return err
	}

	var postponedUntil *time.Time
	if action == "postponed" {
		until := time.Now().UTC().Add(time.Duration(postponeDays) * 24 * time.Hour)
		postponedUntil = &until
	}

	_, err := DB.Exec(ctx, `
		INSERT INTO agent_patch_overrides (agent_id, kb_id, action, postponed_until, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
		ON CONFLICT (agent_id, kb_id) DO UPDATE SET
			action = EXCLUDED.action,
			postponed_until = EXCLUDED.postponed_until,
			updated_by = EXCLUDED.updated_by,
			updated_at = CURRENT_TIMESTAMP
	`, agentID, kbID, action, postponedUntil, updatedBy)
	return err
}

func ListAggregatedPatchUpdates(ctx context.Context, limit int) ([]AggregatedPatchUpdate, error) {
	if limit <= 0 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}

	policy, _ := GetOSPatchPolicy(ctx)

	overrides := map[string]struct {
		Action         string
		PostponedUntil *time.Time
	}{}
	orows, err := DB.Query(ctx, `
		SELECT agent_id, kb_id, action, postponed_until
		FROM agent_patch_overrides
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list patch overrides: %w", err)
	}
	for orows.Next() {
		var agentID, kbID, action string
		var postponedUntil *time.Time
		if err := orows.Scan(&agentID, &kbID, &action, &postponedUntil); err != nil {
			orows.Close()
			return nil, fmt.Errorf("failed to scan patch override: %w", err)
		}
		key := strings.TrimSpace(agentID) + "|" + strings.ToUpper(strings.TrimSpace(kbID))
		overrides[key] = struct {
			Action         string
			PostponedUntil *time.Time
		}{Action: strings.ToLower(strings.TrimSpace(action)), PostponedUntil: postponedUntil}
	}
	orows.Close()

	approved := map[string]struct{}{}
	postponed := map[string]struct{}{}
	if policy != nil {
		for _, kb := range policy.ApprovedKBs {
			approved[strings.ToUpper(strings.TrimSpace(kb))] = struct{}{}
		}
		for _, kb := range policy.PostponedKBs {
			postponed[strings.ToUpper(strings.TrimSpace(kb))] = struct{}{}
		}
	}

	rows, err := DB.Query(ctx, `
		SELECT u.agent_id, COALESCE(a.hostname, ''),
		       u.update_id, COALESCE(u.kb_id, ''), u.title, COALESCE(u.description, ''),
		       COALESCE(u.severity, ''), u.categories,
		       u.is_driver, u.is_security, u.is_critical, u.is_os, u.is_software,
		       u.reboot_required, u.first_seen_at, u.last_seen_at
		FROM agent_patch_updates u
		LEFT JOIN agents a ON a.agent_id = u.agent_id
		WHERE u.installed = FALSE
		ORDER BY u.is_critical DESC, u.is_security DESC, u.last_seen_at DESC, u.agent_id ASC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list aggregated patch updates: %w", err)
	}
	defer rows.Close()

	now := time.Now().UTC()
	items := []AggregatedPatchUpdate{}
	for rows.Next() {
		var item AggregatedPatchUpdate
		var categoriesJSON string
		if err := rows.Scan(
			&item.AgentID,
			&item.Hostname,
			&item.UpdateID,
			&item.KBID,
			&item.Title,
			&item.Description,
			&item.Severity,
			&categoriesJSON,
			&item.IsDriver,
			&item.IsSecurity,
			&item.IsCritical,
			&item.IsOS,
			&item.IsSoftware,
			&item.RebootRequired,
			&item.FirstSeenAt,
			&item.LastSeenAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan aggregated patch update: %w", err)
		}
		_ = json.Unmarshal([]byte(categoriesJSON), &item.Categories)

		item.KBID = strings.ToUpper(strings.TrimSpace(item.KBID))
		item.ApprovalState = "pending_manual"

		if item.KBID != "" {
			key := item.AgentID + "|" + item.KBID
			if override, ok := overrides[key]; ok {
				if override.Action == "approved" {
					item.ApprovalState = "approved_manual"
				} else if override.Action == "postponed" {
					item.PostponedUntil = override.PostponedUntil
					if override.PostponedUntil != nil && override.PostponedUntil.After(now) {
						item.ApprovalState = "postponed"
					} else {
						item.ApprovalState = "pending_manual"
					}
				}
			} else {
				if _, ok := approved[item.KBID]; ok {
					item.ApprovalState = "approved_policy"
				}
				if _, ok := postponed[item.KBID]; ok {
					item.ApprovalState = "postponed_policy"
				}
			}
		}

		if policy != nil && policy.KBApprovalMode == "auto" {
			autoAfter := time.Duration(policy.AutoApprovalAfter) * 24 * time.Hour
			if autoAfter <= 0 || item.FirstSeenAt.Add(autoAfter).Before(now) {
				if !strings.HasPrefix(item.ApprovalState, "postponed") {
					item.ApprovalState = "approved_auto"
				}
			}
		}

		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate aggregated patch updates: %w", err)
	}

	return items, nil
}

func QueueInstallApprovedPatchUpdates(ctx context.Context, agentID string) (*AgentCommand, int, string, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return nil, 0, "", fmt.Errorf("agent_id is required")
	}

	updates, err := ListAgentPatchUpdates(ctx, agentID)
	if err != nil {
		return nil, 0, "", err
	}

	approvedIDs := make([]string, 0, len(updates))
	for _, item := range updates {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(item.ApprovalState)), "approved") {
			updateID := strings.TrimSpace(item.UpdateID)
			if updateID == "" {
				continue
			}
			approvedIDs = append(approvedIDs, updateID)
		}
	}

	if len(approvedIDs) == 0 {
		return nil, 0, "", fmt.Errorf("no approved updates are currently eligible for installation")
	}

	rebootBehavior, err := resolveAgentPatchRebootBehavior(ctx, agentID)
	if err != nil {
		return nil, 0, "", err
	}

	script := buildInstallApprovedUpdatesScript(approvedIDs, rebootBehavior)
	cmd, err := CreateCommand(ctx, agentID, "powershell", script)
	if err != nil {
		return nil, 0, "", err
	}

	return cmd, len(approvedIDs), rebootBehavior, nil
}

func QueueUninstallPatchUpdateByKB(ctx context.Context, agentID, kbID string) (*AgentCommand, error) {
	agentID = strings.TrimSpace(agentID)
	kbID = strings.ToUpper(strings.TrimSpace(kbID))
	if agentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	if kbID == "" {
		return nil, fmt.Errorf("kb_id is required")
	}

	var (
		title      string
		isDriver   bool
		installed  bool
		updateID   string
	)
	err := DB.QueryRow(ctx, `
		SELECT COALESCE(title, ''), is_driver, installed, update_id
		FROM agent_patch_updates
		WHERE agent_id = $1
		  AND UPPER(COALESCE(kb_id, '')) = $2
		ORDER BY COALESCE(installed_at, last_seen_at) DESC
		LIMIT 1
	`, agentID, kbID).Scan(&title, &isDriver, &installed, &updateID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("patch %s not found for agent", kbID)
		}
		return nil, fmt.Errorf("failed to lookup patch %s: %w", kbID, err)
	}

	if !installed {
		return nil, fmt.Errorf("patch %s is not currently marked installed", kbID)
	}
	if isDriver {
		return nil, fmt.Errorf("driver update %s is not uninstallable from this workflow", kbID)
	}

	script := buildUninstallPatchByKBScript(kbID)
	cmd, err := CreateCommand(ctx, agentID, "powershell", script)
	if err != nil {
		return nil, err
	}

	_ = title
	_ = updateID
	return cmd, nil
}

func resolveAgentPatchRebootBehavior(ctx context.Context, agentID string) (string, error) {
	var behavior string
	err := DB.QueryRow(ctx, `
		SELECT COALESCE(pp.reboot_behavior, '')
		FROM agent_group_members gm
		JOIN agent_groups g ON g.id = gm.group_id
		LEFT JOIN patch_profiles pp ON pp.id = g.patch_profile_id
		WHERE gm.agent_id = $1
		ORDER BY g.id ASC
		LIMIT 1
	`, agentID).Scan(&behavior)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "reboot_if_required", nil
		}
		return "", fmt.Errorf("failed to resolve patch reboot behavior: %w", err)
	}

	behavior = strings.ToLower(strings.TrimSpace(behavior))
	switch behavior {
	case "none", "soft", "hard", "reboot_if_required":
		return behavior, nil
	default:
		return "reboot_if_required", nil
	}
}

func buildInstallApprovedUpdatesScript(approvedUpdateIDs []string, rebootBehavior string) string {
	quotedIDs := make([]string, 0, len(approvedUpdateIDs))
	for _, id := range approvedUpdateIDs {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		quotedIDs = append(quotedIDs, "'"+strings.ReplaceAll(trimmed, "'", "''")+"'")
	}

	if len(quotedIDs) == 0 {
		return "Write-Output 'No approved updates selected.'"
	}

	behavior := strings.ToLower(strings.TrimSpace(rebootBehavior))
	if behavior == "" {
		behavior = "reboot_if_required"
	}

	return strings.Join([]string{
		"$ErrorActionPreference = 'Stop'",
		"$ProgressPreference = 'SilentlyContinue'",
		"$approvedIds = @(" + strings.Join(quotedIDs, ",") + ")",
		"Write-Output ('Approved update targets: ' + $approvedIds.Count)",
		"$session = New-Object -ComObject Microsoft.Update.Session",
		"$searcher = $session.CreateUpdateSearcher()",
		"$result = $searcher.Search(\"IsInstalled=0 and IsHidden=0\")",
		"$updates = New-Object -ComObject Microsoft.Update.UpdateColl",
		"foreach ($update in $result.Updates) {",
		"    $id = [string]$update.Identity.UpdateID",
		"    if ($approvedIds -contains $id) { [void]$updates.Add($update) }",
		"}",
		"if ($updates.Count -eq 0) {",
		"    Write-Output 'No pending approved updates found to install.'",
		"    exit 0",
		"}",
		"$downloader = $session.CreateUpdateDownloader()",
		"$downloader.Updates = $updates",
		"$downloadResult = $downloader.Download()",
		"$installer = $session.CreateUpdateInstaller()",
		"$installer.Updates = $updates",
		"$installResult = $installer.Install()",
		"Write-Output ('Updates targeted: ' + $approvedIds.Count)",
		"Write-Output ('Updates installed this run: ' + $updates.Count)",
		"Write-Output ('Download result code: ' + $downloadResult.ResultCode)",
		"Write-Output ('Install result code: ' + $installResult.ResultCode)",
		"$rebootRequired = [bool]$installResult.RebootRequired",
		"Write-Output ('Reboot required: ' + $rebootRequired)",
		"$rebootBehavior = '" + strings.ReplaceAll(behavior, "'", "''") + "'",
		"if ($rebootBehavior -eq 'hard') {",
		"    shutdown /r /t 0 /f /c 'Restart initiated by patch automation'",
		"} elseif ($rebootBehavior -eq 'soft') {",
		"    shutdown /r /t 60 /c 'Restart initiated by patch automation'",
		"} elseif ($rebootBehavior -eq 'reboot_if_required' -and $rebootRequired) {",
		"    shutdown /r /t 30 /c 'Restart initiated by patch automation (reboot required)'",
		"}",
	}, "\n")
}

func buildUninstallPatchByKBScript(kbID string) string {
	kb := strings.ToUpper(strings.TrimSpace(kbID))
	kbNum := strings.TrimPrefix(kb, "KB")
	kbNum = strings.TrimSpace(kbNum)

	if kbNum == "" {
		return "Write-Output 'Invalid KB ID'; exit 1"
	}

	return strings.Join([]string{
		"$ErrorActionPreference = 'Stop'",
		"$kb = '" + strings.ReplaceAll(kb, "'", "''") + "'",
		"$kbNum = '" + strings.ReplaceAll(kbNum, "'", "''") + "'",
		"Write-Output ('Uninstall request queued for ' + $kb)",
		"$arguments = '/uninstall /kb:' + $kbNum + ' /quiet /norestart'",
		"$p = Start-Process -FilePath 'wusa.exe' -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden",
		"Write-Output ('wusa exit code: ' + $p.ExitCode)",
		"if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010 -and $p.ExitCode -ne 2359302) {",
		"    throw ('Uninstall failed with exit code ' + $p.ExitCode)",
		"}",
		"if ($p.ExitCode -eq 3010) { Write-Output 'Reboot required to complete uninstall.' }",
	}, "\n")
}
