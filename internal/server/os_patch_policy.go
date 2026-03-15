package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type OSPatchPolicy struct {
	ID                  int       `json:"id"`
	Enabled             bool      `json:"enabled"`
	TargetScope         string    `json:"target_scope"`
	TargetAgentID       string    `json:"target_agent_id,omitempty"`
	TargetGroupID       *int      `json:"target_group_id,omitempty"`
	KBApprovalMode      string    `json:"kb_approval_mode"`
	AutoApprovalAfter   int       `json:"auto_approval_after_days"`
	PostponeDays        int       `json:"postpone_days"`
	AutoScheduleEnabled bool      `json:"auto_schedule_enabled"`
	AutoScheduleRule    string    `json:"auto_schedule_rule"`
	ScheduleStartAt     time.Time `json:"schedule_start_at"`
	ApprovedKBs         []string  `json:"approved_kbs"`
	PostponedKBs        []string  `json:"postponed_kbs"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type OSPatchPolicyAuditEntry struct {
	ID        int64     `json:"id"`
	PolicyID  *int      `json:"policy_id,omitempty"`
	Action    string    `json:"action"`
	ChangedBy string    `json:"changed_by"`
	Payload   string    `json:"payload"`
	CreatedAt time.Time `json:"created_at"`
}

func defaultOSPatchPolicy() OSPatchPolicy {
	return OSPatchPolicy{
		Enabled:             true,
		TargetScope:         "agent",
		KBApprovalMode:      "manual",
		AutoApprovalAfter:   7,
		PostponeDays:        0,
		AutoScheduleEnabled: true,
		AutoScheduleRule:    "weekdays",
		ScheduleStartAt:     time.Now().UTC().Add(10 * time.Minute),
		ApprovedKBs:         []string{},
		PostponedKBs:        []string{},
	}
}

func normalizeOSPatchPolicy(policy OSPatchPolicy) (OSPatchPolicy, error) {
	policy.TargetScope = strings.ToLower(strings.TrimSpace(policy.TargetScope))
	policy.TargetAgentID = strings.TrimSpace(policy.TargetAgentID)
	policy.KBApprovalMode = strings.ToLower(strings.TrimSpace(policy.KBApprovalMode))
	policy.AutoScheduleRule = strings.ToLower(strings.TrimSpace(policy.AutoScheduleRule))

	switch policy.TargetScope {
	case "agent", "group":
	default:
		return OSPatchPolicy{}, fmt.Errorf("invalid target_scope")
	}

	if policy.TargetScope == "agent" {
		if policy.TargetAgentID == "" {
			return OSPatchPolicy{}, fmt.Errorf("target_agent_id is required for agent scope")
		}
		policy.TargetGroupID = nil
	} else {
		if policy.TargetGroupID == nil || *policy.TargetGroupID <= 0 {
			return OSPatchPolicy{}, fmt.Errorf("target_group_id is required for group scope")
		}
		policy.TargetAgentID = ""
	}

	switch policy.KBApprovalMode {
	case "manual", "auto":
	default:
		return OSPatchPolicy{}, fmt.Errorf("invalid kb_approval_mode")
	}

	if policy.AutoApprovalAfter < 0 {
		return OSPatchPolicy{}, fmt.Errorf("auto_approval_after_days must be >= 0")
	}
	if policy.PostponeDays < 0 {
		return OSPatchPolicy{}, fmt.Errorf("postpone_days must be >= 0")
	}

	switch policy.AutoScheduleRule {
	case "weekdays", "weekly", "monthly":
	default:
		return OSPatchPolicy{}, fmt.Errorf("invalid auto_schedule_rule")
	}

	if policy.ScheduleStartAt.IsZero() {
		return OSPatchPolicy{}, fmt.Errorf("schedule_start_at is required")
	}

	policy.ApprovedKBs = normalizeKBList(policy.ApprovedKBs)
	policy.PostponedKBs = normalizeKBList(policy.PostponedKBs)

	return policy, nil
}

func normalizeKBList(items []string) []string {
	result := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		trimmed := strings.ToUpper(strings.TrimSpace(item))
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func GetOSPatchPolicy(ctx context.Context) (*OSPatchPolicy, error) {
	var policy OSPatchPolicy
	var approvedJSON, postponedJSON string

	err := DB.QueryRow(ctx, `
		SELECT id, enabled, target_scope, COALESCE(target_agent_id, ''), target_group_id,
		       kb_approval_mode, auto_approval_after_days, postpone_days,
		       auto_schedule_enabled, auto_schedule_rule, schedule_start_at,
		       approved_kbs, postponed_kbs, created_at, updated_at
		FROM os_patch_policies
		ORDER BY id DESC
		LIMIT 1
	`).Scan(
		&policy.ID,
		&policy.Enabled,
		&policy.TargetScope,
		&policy.TargetAgentID,
		&policy.TargetGroupID,
		&policy.KBApprovalMode,
		&policy.AutoApprovalAfter,
		&policy.PostponeDays,
		&policy.AutoScheduleEnabled,
		&policy.AutoScheduleRule,
		&policy.ScheduleStartAt,
		&approvedJSON,
		&postponedJSON,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	_ = json.Unmarshal([]byte(approvedJSON), &policy.ApprovedKBs)
	_ = json.Unmarshal([]byte(postponedJSON), &policy.PostponedKBs)

	return &policy, nil
}

func UpsertOSPatchPolicy(ctx context.Context, policy OSPatchPolicy, changedBy string) (*OSPatchPolicy, error) {
	normalized, err := normalizeOSPatchPolicy(policy)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(changedBy) == "" {
		changedBy = "system"
	}

	approvedJSONBytes, err := json.Marshal(normalized.ApprovedKBs)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize approved_kbs: %w", err)
	}
	postponedJSONBytes, err := json.Marshal(normalized.PostponedKBs)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize postponed_kbs: %w", err)
	}

	var saved OSPatchPolicy
	var approvedOut, postponedOut string
	err = DB.QueryRow(ctx, `
		INSERT INTO os_patch_policies (
			enabled, target_scope, target_agent_id, target_group_id,
			kb_approval_mode, auto_approval_after_days, postpone_days,
			auto_schedule_enabled, auto_schedule_rule, schedule_start_at,
			approved_kbs, postponed_kbs
		) VALUES (
			$1, $2, NULLIF($3, ''), $4,
			$5, $6, $7,
			$8, $9, $10,
			$11, $12
		)
		ON CONFLICT (singleton_key) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			target_scope = EXCLUDED.target_scope,
			target_agent_id = EXCLUDED.target_agent_id,
			target_group_id = EXCLUDED.target_group_id,
			kb_approval_mode = EXCLUDED.kb_approval_mode,
			auto_approval_after_days = EXCLUDED.auto_approval_after_days,
			postpone_days = EXCLUDED.postpone_days,
			auto_schedule_enabled = EXCLUDED.auto_schedule_enabled,
			auto_schedule_rule = EXCLUDED.auto_schedule_rule,
			schedule_start_at = EXCLUDED.schedule_start_at,
			approved_kbs = EXCLUDED.approved_kbs,
			postponed_kbs = EXCLUDED.postponed_kbs,
			updated_at = CURRENT_TIMESTAMP
		RETURNING id, enabled, target_scope, COALESCE(target_agent_id, ''), target_group_id,
		          kb_approval_mode, auto_approval_after_days, postpone_days,
		          auto_schedule_enabled, auto_schedule_rule, schedule_start_at,
		          approved_kbs, postponed_kbs, created_at, updated_at
	`,
		normalized.Enabled,
		normalized.TargetScope,
		normalized.TargetAgentID,
		normalized.TargetGroupID,
		normalized.KBApprovalMode,
		normalized.AutoApprovalAfter,
		normalized.PostponeDays,
		normalized.AutoScheduleEnabled,
		normalized.AutoScheduleRule,
		normalized.ScheduleStartAt,
		string(approvedJSONBytes),
		string(postponedJSONBytes),
	).Scan(
		&saved.ID,
		&saved.Enabled,
		&saved.TargetScope,
		&saved.TargetAgentID,
		&saved.TargetGroupID,
		&saved.KBApprovalMode,
		&saved.AutoApprovalAfter,
		&saved.PostponeDays,
		&saved.AutoScheduleEnabled,
		&saved.AutoScheduleRule,
		&saved.ScheduleStartAt,
		&approvedOut,
		&postponedOut,
		&saved.CreatedAt,
		&saved.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert os patch policy: %w", err)
	}

	_ = json.Unmarshal([]byte(approvedOut), &saved.ApprovedKBs)
	_ = json.Unmarshal([]byte(postponedOut), &saved.PostponedKBs)

	_ = createOSPatchPolicyAudit(ctx, saved.ID, "upsert", changedBy, saved)

	return &saved, nil
}

func ResetOSPatchPolicy(ctx context.Context, changedBy string) (*OSPatchPolicy, error) {
	if strings.TrimSpace(changedBy) == "" {
		changedBy = "system"
	}

	defaults := defaultOSPatchPolicy()

	existing, err := GetOSPatchPolicy(ctx)
	if err == nil && existing != nil {
		defaults.TargetScope = existing.TargetScope
		defaults.TargetAgentID = existing.TargetAgentID
		defaults.TargetGroupID = existing.TargetGroupID
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	if defaults.TargetScope == "agent" && strings.TrimSpace(defaults.TargetAgentID) == "" {
		var fallbackAgentID string
		queryErr := DB.QueryRow(ctx, `SELECT agent_id FROM agents ORDER BY last_seen DESC, created_at ASC LIMIT 1`).Scan(&fallbackAgentID)
		if queryErr == nil && strings.TrimSpace(fallbackAgentID) != "" {
			defaults.TargetAgentID = strings.TrimSpace(fallbackAgentID)
		}
	}

	if defaults.TargetScope == "agent" && strings.TrimSpace(defaults.TargetAgentID) == "" {
		return nil, fmt.Errorf("cannot reset os patch policy: no target_agent_id available")
	}

	saved, upsertErr := UpsertOSPatchPolicy(ctx, defaults, changedBy)
	if upsertErr != nil {
		return nil, upsertErr
	}

	_ = createOSPatchPolicyAudit(ctx, saved.ID, "reset", changedBy, saved)
	return saved, nil
}

func ListOSPatchPolicyAudit(ctx context.Context, limit int) ([]OSPatchPolicyAuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	rows, err := DB.Query(ctx, `
		SELECT id, policy_id, action, changed_by, payload, created_at
		FROM os_patch_policy_audit
		ORDER BY created_at DESC, id DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list os patch policy audit: %w", err)
	}
	defer rows.Close()

	entries := []OSPatchPolicyAuditEntry{}
	for rows.Next() {
		var item OSPatchPolicyAuditEntry
		if err := rows.Scan(&item.ID, &item.PolicyID, &item.Action, &item.ChangedBy, &item.Payload, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan os patch policy audit entry: %w", err)
		}
		entries = append(entries, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate os patch policy audit entries: %w", err)
	}

	return entries, nil
}

func createOSPatchPolicyAudit(ctx context.Context, policyID int, action, changedBy string, payload interface{}) error {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		action = "upsert"
	}
	changedBy = strings.TrimSpace(changedBy)
	if changedBy == "" {
		changedBy = "system"
	}

	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte("{}")
	}

	_, execErr := DB.Exec(ctx, `
		INSERT INTO os_patch_policy_audit (policy_id, action, changed_by, payload)
		VALUES ($1, $2, $3, $4)
	`, policyID, action, changedBy, string(body))

	return execErr
}
