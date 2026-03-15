package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shafraz007/ai-endpoint-platform/internal/ai"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

type IssueRecommendedAction struct {
	ID               string
	Label            string
	Description      string
	Kind             string
	CommandType      string
	Payload          string
	SupportsSchedule bool
}

type AgentIssue struct {
	ID                 int64
	AgentID            string
	IssueKey           string
	Category           string
	Severity           string
	Status             string
	Suppressed         bool
	SnoozedUntil       *time.Time
	Title              string
	Description        string
	Source             string
	Evidence           string
	Suggestions        []string
	ActionPlan         []string
	RecommendedActions []IssueRecommendedAction
	FirstSeenAt        time.Time
	LastSeenAt         time.Time
	ResolvedAt         *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type AgentIssueUpsertInput struct {
	AgentID            string
	IssueKey           string
	Category           string
	Severity           string
	Title              string
	Description        string
	Source             string
	Evidence           string
	Suggestions        []string
	ActionPlan         []string
	RecommendedActions []IssueRecommendedAction
	ObservedAt         time.Time
}

type IssueFilter struct {
	AgentID string
	Status  string
	Limit   int
}

type IssueActionInput struct {
	ActionID              string
	Mode                  string
	Kind                  string
	CommandType           string
	Payload               string
	Name                  string
	RunAt                 *time.Time
	RepeatIntervalSeconds int
	RecurrenceRule        string
	Enabled               *bool
}

type IssueActionResult struct {
	IssueID           int64
	Mode              string
	Kind              string
	CommandType       string
	CreatedCommandID  int64
	CreatedScheduleID int64
	Message           string
}

func ListAgentIssues(ctx context.Context, filter IssueFilter) ([]AgentIssue, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	agentID := strings.TrimSpace(filter.AgentID)
	status := strings.ToLower(strings.TrimSpace(filter.Status))

	query := `
	SELECT id, agent_id, issue_key, category, severity, status, COALESCE(suppressed, FALSE), snoozed_until, title, description, source,
		COALESCE(evidence, '{}'), COALESCE(suggestions, '[]'), COALESCE(action_plan, '[]'), COALESCE(recommended_actions, '[]'),
		first_seen_at, last_seen_at, resolved_at, created_at, updated_at
	FROM agent_issues
	WHERE ($1 = '' OR agent_id = $1)
		AND ($2 = '' OR status = $2 OR ($2 = 'suppressed' AND COALESCE(suppressed, FALSE) = TRUE))
	ORDER BY
		CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
		last_seen_at DESC
	LIMIT $3
	`

	rows, err := DB.Query(ctx, query, agentID, status, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list issues: %w", err)
	}
	defer rows.Close()

	issues := make([]AgentIssue, 0, limit)
	for rows.Next() {
		item, err := scanIssue(rows)
		if err != nil {
			return nil, err
		}
		issues = append(issues, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate issues: %w", err)
	}

	return issues, nil
}

func GetAgentIssueByID(ctx context.Context, issueID int64) (*AgentIssue, error) {
	if issueID <= 0 {
		return nil, fmt.Errorf("issue id is required")
	}

	query := `
	SELECT id, agent_id, issue_key, category, severity, status, COALESCE(suppressed, FALSE), snoozed_until, title, description, source,
		COALESCE(evidence, '{}'), COALESCE(suggestions, '[]'), COALESCE(action_plan, '[]'), COALESCE(recommended_actions, '[]'),
		first_seen_at, last_seen_at, resolved_at, created_at, updated_at
	FROM agent_issues
	WHERE id = $1
	`

	row := DB.QueryRow(ctx, query, issueID)
	item, err := scanIssueRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("issue not found")
		}
		return nil, err
	}

	return &item, nil
}

func UpsertAgentIssue(ctx context.Context, input AgentIssueUpsertInput) (*AgentIssue, error) {
	normalized, err := normalizeIssueInput(input)
	if err != nil {
		return nil, err
	}

	suggestionsJSON, _ := json.Marshal(normalized.Suggestions)
	actionPlanJSON, _ := json.Marshal(normalized.ActionPlan)
	actionsJSON, _ := json.Marshal(normalized.RecommendedActions)

	query := `
	INSERT INTO agent_issues (
		agent_id, issue_key, category, severity, status, title, description, source,
		evidence, suggestions, action_plan, recommended_actions,
		first_seen_at, last_seen_at, created_at, updated_at
	)
	VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, $8, $9, $10, $11, $12, $12, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	ON CONFLICT (agent_id, issue_key)
	DO UPDATE SET
		category = EXCLUDED.category,
		severity = EXCLUDED.severity,
		status = CASE
			WHEN agent_issues.suppressed THEN 'resolved'
			WHEN agent_issues.snoozed_until IS NOT NULL AND agent_issues.snoozed_until > EXCLUDED.last_seen_at THEN 'resolved'
			ELSE 'active'
		END,
		title = EXCLUDED.title,
		description = EXCLUDED.description,
		source = EXCLUDED.source,
		evidence = EXCLUDED.evidence,
		suggestions = EXCLUDED.suggestions,
		action_plan = EXCLUDED.action_plan,
		recommended_actions = EXCLUDED.recommended_actions,
		last_seen_at = EXCLUDED.last_seen_at,
		resolved_at = CASE
			WHEN agent_issues.suppressed THEN COALESCE(agent_issues.resolved_at, CURRENT_TIMESTAMP)
			WHEN agent_issues.snoozed_until IS NOT NULL AND agent_issues.snoozed_until > EXCLUDED.last_seen_at THEN COALESCE(agent_issues.resolved_at, CURRENT_TIMESTAMP)
			ELSE NULL
		END,
		updated_at = CURRENT_TIMESTAMP
	RETURNING id, agent_id, issue_key, category, severity, status, COALESCE(suppressed, FALSE), snoozed_until, title, description, source,
		COALESCE(evidence, '{}'), COALESCE(suggestions, '[]'), COALESCE(action_plan, '[]'), COALESCE(recommended_actions, '[]'),
		first_seen_at, last_seen_at, resolved_at, created_at, updated_at
	`

	row := DB.QueryRow(
		ctx,
		query,
		normalized.AgentID,
		normalized.IssueKey,
		normalized.Category,
		normalized.Severity,
		normalized.Title,
		normalized.Description,
		normalized.Source,
		normalized.Evidence,
		string(suggestionsJSON),
		string(actionPlanJSON),
		string(actionsJSON),
		normalized.ObservedAt,
	)

	item, err := scanIssueRow(row)
	if err != nil {
		return nil, err
	}

	return &item, nil
}

func ResolveAgentIssue(ctx context.Context, agentID, issueKey string) error {
	agentID = strings.TrimSpace(agentID)
	issueKey = strings.TrimSpace(issueKey)
	if agentID == "" || issueKey == "" {
		return nil
	}

	_, err := DB.Exec(ctx, `
		UPDATE agent_issues
		SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE agent_id = $1 AND issue_key = $2 AND status <> 'resolved'
	`, agentID, issueKey)
	if err != nil {
		return fmt.Errorf("failed to resolve issue: %w", err)
	}
	return nil
}

func ResolveAgentIssueByID(ctx context.Context, issueID int64) error {
	if issueID <= 0 {
		return fmt.Errorf("issue id is required")
	}

	cmd, err := DB.Exec(ctx, `
		UPDATE agent_issues
		SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1 AND status <> 'resolved'
	`, issueID)
	if err != nil {
		return fmt.Errorf("failed to resolve issue: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("issue not found or already resolved")
	}

	return nil
}

func SnoozeAgentIssueByID(ctx context.Context, issueID int64, duration time.Duration) (*time.Time, error) {
	if issueID <= 0 {
		return nil, fmt.Errorf("issue id is required")
	}
	if duration <= 0 {
		return nil, fmt.Errorf("snooze duration must be greater than zero")
	}

	snoozedUntil := time.Now().UTC().Add(duration)

	var persisted time.Time
	err := DB.QueryRow(ctx, `
		UPDATE agent_issues
		SET status = 'resolved',
			resolved_at = CURRENT_TIMESTAMP,
			suppressed = FALSE,
			suppressed_at = NULL,
			snoozed_until = $2,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
		RETURNING snoozed_until
	`, issueID, snoozedUntil).Scan(&persisted)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("issue not found")
		}
		return nil, fmt.Errorf("failed to snooze issue: %w", err)
	}

	return &persisted, nil
}

func SuppressAgentIssueByID(ctx context.Context, issueID int64) error {
	if issueID <= 0 {
		return fmt.Errorf("issue id is required")
	}

	cmd, err := DB.Exec(ctx, `
		UPDATE agent_issues
		SET status = 'resolved',
			resolved_at = CURRENT_TIMESTAMP,
			suppressed = TRUE,
			suppressed_at = CURRENT_TIMESTAMP,
			snoozed_until = NULL,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`, issueID)
	if err != nil {
		return fmt.Errorf("failed to suppress issue: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("issue not found")
	}

	return nil
}

func EvaluateHeartbeatIssues(ctx context.Context, hb transport.HeartbeatRequest) error {
	agentID := strings.TrimSpace(hb.AgentID)
	if agentID == "" {
		return nil
	}

	if hb.RebootRequired {
		if _, err := UpsertAgentIssue(ctx, AgentIssueUpsertInput{
			AgentID:     agentID,
			IssueKey:    "reboot-required",
			Category:    "patch",
			Severity:    "medium",
			Title:       "Reboot required to complete maintenance",
			Description: "The endpoint reports that a reboot is required. Pending updates or software changes are waiting for restart finalization.",
			Source:      "heartbeat",
			Evidence:    `{"reboot_required":true}`,
			Suggestions: []string{
				"Verify user/business impact window before restarting.",
				"Execute a controlled restart and validate heartbeat recovery.",
			},
			ActionPlan: []string{
				"Review active user sessions and maintenance window.",
				"Run a controlled restart now or schedule it in off-hours.",
				"Confirm services and health metrics after reboot.",
			},
			RecommendedActions: []IssueRecommendedAction{
				{ID: "restart-now", Label: "Restart now", Description: "Run immediate restart command", Kind: "command", CommandType: "restart", SupportsSchedule: true},
				{ID: "post-reboot-health-task", Label: "Post-reboot health check", Description: "Ask AI to validate device health after restart", Kind: "task", Payload: buildIssueAITaskPayload("Post-reboot validation", "After reboot, verify endpoint health, critical services, and summarize any remaining risks."), SupportsSchedule: true},
			},
		}); err != nil {
			return err
		}
	} else if err := ResolveAgentIssue(ctx, agentID, "reboot-required"); err != nil {
		return err
	}

	criticalCount := 0
	securityCount := 0
	for _, update := range hb.PendingUpdates {
		if update.IsCritical {
			criticalCount++
		}
		if update.IsSecurity {
			securityCount++
		}
	}
	if criticalCount > 0 || securityCount > 0 {
		evidence := fmt.Sprintf(`{"critical_updates":%d,"security_updates":%d}`, criticalCount, securityCount)
		if _, err := UpsertAgentIssue(ctx, AgentIssueUpsertInput{
			AgentID:     agentID,
			IssueKey:    "critical-updates-pending",
			Category:    "patch",
			Severity:    "high",
			Title:       "Critical/security updates pending",
			Description: fmt.Sprintf("Pending updates include %d critical and %d security updates.", criticalCount, securityCount),
			Source:      "heartbeat",
			Evidence:    evidence,
			Suggestions: []string{
				"Prioritize patch installation in the next maintenance window.",
				"Restart endpoint after update installation if required.",
			},
			ActionPlan: []string{
				"Review pending update list and affected components.",
				"Schedule update installation task with rollback checkpoints.",
				"Validate patch completion and reboot requirement state.",
			},
			RecommendedActions: []IssueRecommendedAction{
				{ID: "ai-patch-plan", Label: "Generate patch remediation task", Description: "Create AI task to produce a patch action plan", Kind: "task", Payload: buildIssueAITaskPayload("Patch remediation plan", "Analyze pending critical/security updates and provide a safe patch/remediation action plan with validation checklist."), SupportsSchedule: true},
				{ID: "schedule-patch-scan", Label: "Schedule patch scan script", Description: "Schedule a PowerShell patch scan script", Kind: "script", CommandType: "powershell", Payload: "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 30", SupportsSchedule: true},
			},
		}); err != nil {
			return err
		}
	} else if err := ResolveAgentIssue(ctx, agentID, "critical-updates-pending"); err != nil {
		return err
	}

	if strings.TrimSpace(hb.AntivirusName) == "" || strings.TrimSpace(hb.FirewallName) == "" {
		if _, err := UpsertAgentIssue(ctx, AgentIssueUpsertInput{
			AgentID:     agentID,
			IssueKey:    "security-controls-missing",
			Category:    "security",
			Severity:    "high",
			Title:       "Security controls appear missing or unreported",
			Description: "Antivirus or firewall information is missing. Endpoint may be under-protected or telemetry is incomplete.",
			Source:      "heartbeat",
			Evidence:    fmt.Sprintf(`{"antivirus_name":%q,"firewall_name":%q}`, strings.TrimSpace(hb.AntivirusName), strings.TrimSpace(hb.FirewallName)),
			Suggestions: []string{
				"Validate endpoint security tooling installation and service state.",
				"Run a security baseline check and update policy if needed.",
			},
			ActionPlan: []string{
				"Run security health script to confirm AV/firewall status.",
				"Remediate missing controls and enforce policy baseline.",
				"Re-run heartbeat and verify security fields are populated.",
			},
			RecommendedActions: []IssueRecommendedAction{
				{ID: "security-health-script", Label: "Run security health script", Description: "Collect Defender and firewall status", Kind: "script", CommandType: "powershell", Payload: "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,AntispywareEnabled,FirewallEnabled | Format-List", SupportsSchedule: true},
				{ID: "ai-security-plan", Label: "Create security remediation task", Description: "Generate AI remediation workflow", Kind: "task", Payload: buildIssueAITaskPayload("Security baseline remediation", "Create a remediation plan for missing AV/firewall controls with validation and rollback guidance."), SupportsSchedule: true},
			},
		}); err != nil {
			return err
		}
	} else if err := ResolveAgentIssue(ctx, agentID, "security-controls-missing"); err != nil {
		return err
	}

	if hb.PatchScanAt != nil && hb.PatchScanAt.Before(time.Now().Add(-72*time.Hour)) {
		if _, err := UpsertAgentIssue(ctx, AgentIssueUpsertInput{
			AgentID:     agentID,
			IssueKey:    "patch-scan-stale",
			Category:    "patch",
			Severity:    "medium",
			Title:       "Patch scan is stale",
			Description: "Last patch scan is older than 72 hours.",
			Source:      "heartbeat",
			Evidence:    fmt.Sprintf(`{"patch_scan_at":%q}`, hb.PatchScanAt.UTC().Format(time.RFC3339)),
			Suggestions: []string{
				"Trigger patch inventory refresh.",
				"Schedule recurring patch scan workflow.",
			},
			ActionPlan: []string{
				"Run patch inventory collection task.",
				"Schedule periodic scan and compliance report.",
			},
			RecommendedActions: []IssueRecommendedAction{
				{ID: "refresh-patch-ai-task", Label: "Run patch refresh AI task", Description: "Ask agent to refresh patch inventory and summarize risk", Kind: "task", Payload: buildIssueAITaskPayload("Refresh patch posture", "Collect current pending updates, summarize risk, and report recommended maintenance window."), SupportsSchedule: true},
			},
		}); err != nil {
			return err
		}
	} else if err := ResolveAgentIssue(ctx, agentID, "patch-scan-stale"); err != nil {
		return err
	}

	if err := evaluateHeartbeatThresholdIssues(ctx, hb); err != nil {
		return err
	}

	return nil
}

func EvaluateMetricIssues(ctx context.Context, sample MetricSample) error {
	agentID := strings.TrimSpace(sample.AgentID)
	if agentID == "" {
		return nil
	}

	if err := evaluateMetricThresholdIssues(ctx, sample); err != nil {
		return err
	}

	return nil
}

func ExecuteIssueAction(ctx context.Context, issueID int64, input IssueActionInput, createdBy string) (IssueActionResult, error) {
	issue, err := GetAgentIssueByID(ctx, issueID)
	if err != nil {
		return IssueActionResult{}, err
	}

	createdBy = strings.TrimSpace(createdBy)
	if createdBy == "" {
		createdBy = "admin"
	}

	resolved := resolveIssueAction(issue, input)
	if resolved.Mode != "run_now" && resolved.Mode != "schedule" {
		return IssueActionResult{}, fmt.Errorf("mode must be run_now or schedule")
	}

	result := IssueActionResult{
		IssueID:     issue.ID,
		Mode:        resolved.Mode,
		Kind:        resolved.Kind,
		CommandType: resolved.CommandType,
	}

	if resolved.Mode == "run_now" {
		commandType := strings.ToLower(strings.TrimSpace(resolved.CommandType))
		payload := strings.TrimSpace(resolved.Payload)

		switch resolved.Kind {
		case "task":
			commandType = "ai_task"
			payload = ensureAITaskPayloadForAction(issue, payload)
		case "script":
			if commandType == "" {
				commandType = "powershell"
			}
		case "command":
			if commandType == "" {
				return IssueActionResult{}, fmt.Errorf("command_type is required for command action")
			}
		default:
			return IssueActionResult{}, fmt.Errorf("invalid action kind")
		}

		cmd, err := CreateCommand(ctx, issue.AgentID, commandType, payload)
		if err != nil {
			_ = createIssueActionAudit(ctx, issue, resolved, createdBy, 0, 0, "failed", err.Error())
			return IssueActionResult{}, fmt.Errorf("failed to create command: %w", err)
		}
		result.CreatedCommandID = cmd.ID
		result.Message = "Command queued successfully"
		if err := createIssueActionAudit(ctx, issue, resolved, createdBy, cmd.ID, 0, "created", ""); err != nil {
			return IssueActionResult{}, err
		}
		return result, nil
	}

	runAt := time.Now().UTC().Add(5 * time.Minute)
	if resolved.RunAt != nil && !resolved.RunAt.IsZero() {
		runAt = resolved.RunAt.UTC()
	}
	enabled := true
	if resolved.Enabled != nil {
		enabled = *resolved.Enabled
	}

	scheduleKind := resolved.Kind
	commandType := strings.ToLower(strings.TrimSpace(resolved.CommandType))
	payload := strings.TrimSpace(resolved.Payload)
	if scheduleKind == "task" {
		payload = ensureAITaskPayloadForAction(issue, payload)
	}
	if scheduleKind == "script" && commandType == "" {
		commandType = "powershell"
	}
	if scheduleKind == "command" && commandType == "" {
		return IssueActionResult{}, fmt.Errorf("command_type is required for schedule command")
	}

	name := strings.TrimSpace(resolved.Name)
	if name == "" {
		name = fmt.Sprintf("Issue %d remediation - %s", issue.ID, issue.Title)
	}

	schedule := Schedule{
		Name:                  name,
		Kind:                  scheduleKind,
		TargetScope:           "agent",
		TargetAgentID:         issue.AgentID,
		CommandType:           commandType,
		Payload:               payload,
		RunAt:                 runAt,
		NextRunAt:             runAt,
		RepeatIntervalSeconds: resolved.RepeatIntervalSeconds,
		RecurrenceRule:        strings.TrimSpace(resolved.RecurrenceRule),
		Enabled:               enabled,
		CreatedBy:             createdBy,
	}

	createdSchedule, err := CreateSchedule(ctx, schedule)
	if err != nil {
		_ = createIssueActionAudit(ctx, issue, resolved, createdBy, 0, 0, "failed", err.Error())
		return IssueActionResult{}, fmt.Errorf("failed to create schedule: %w", err)
	}

	result.CreatedScheduleID = createdSchedule.ID
	result.Message = "Schedule created successfully"
	if err := createIssueActionAudit(ctx, issue, resolved, createdBy, 0, createdSchedule.ID, "created", ""); err != nil {
		return IssueActionResult{}, err
	}

	return result, nil
}

func normalizeIssueInput(input AgentIssueUpsertInput) (AgentIssueUpsertInput, error) {
	input.AgentID = strings.TrimSpace(input.AgentID)
	input.IssueKey = strings.ToLower(strings.TrimSpace(input.IssueKey))
	input.Category = strings.ToLower(strings.TrimSpace(input.Category))
	input.Severity = strings.ToLower(strings.TrimSpace(input.Severity))
	input.Title = strings.TrimSpace(input.Title)
	input.Description = strings.TrimSpace(input.Description)
	input.Source = strings.ToLower(strings.TrimSpace(input.Source))
	input.Evidence = strings.TrimSpace(input.Evidence)

	if input.AgentID == "" {
		return AgentIssueUpsertInput{}, fmt.Errorf("agent_id is required")
	}
	if input.IssueKey == "" {
		return AgentIssueUpsertInput{}, fmt.Errorf("issue_key is required")
	}
	if input.Category == "" {
		input.Category = "general"
	}
	switch input.Severity {
	case "critical", "high", "medium", "low":
	default:
		input.Severity = "medium"
	}
	if input.Title == "" {
		return AgentIssueUpsertInput{}, fmt.Errorf("title is required")
	}
	if input.Description == "" {
		return AgentIssueUpsertInput{}, fmt.Errorf("description is required")
	}
	if input.Source == "" {
		input.Source = "detector"
	}
	if input.Evidence == "" {
		input.Evidence = "{}"
	}
	if input.ObservedAt.IsZero() {
		input.ObservedAt = time.Now().UTC()
	}
	if input.Suggestions == nil {
		input.Suggestions = []string{}
	}
	if input.ActionPlan == nil {
		input.ActionPlan = []string{}
	}
	if input.RecommendedActions == nil {
		input.RecommendedActions = []IssueRecommendedAction{}
	}

	return input, nil
}

func scanIssue(rows pgx.Rows) (AgentIssue, error) {
	var (
		item            AgentIssue
		suggestionsJSON string
		actionPlanJSON  string
		recommendedJSON string
	)

	if err := rows.Scan(
		&item.ID,
		&item.AgentID,
		&item.IssueKey,
		&item.Category,
		&item.Severity,
		&item.Status,
		&item.Suppressed,
		&item.SnoozedUntil,
		&item.Title,
		&item.Description,
		&item.Source,
		&item.Evidence,
		&suggestionsJSON,
		&actionPlanJSON,
		&recommendedJSON,
		&item.FirstSeenAt,
		&item.LastSeenAt,
		&item.ResolvedAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return AgentIssue{}, fmt.Errorf("failed to scan issue: %w", err)
	}

	if err := decodeIssueJSONFields(&item, suggestionsJSON, actionPlanJSON, recommendedJSON); err != nil {
		return AgentIssue{}, err
	}

	return item, nil
}

func scanIssueRow(row pgx.Row) (AgentIssue, error) {
	var (
		item            AgentIssue
		suggestionsJSON string
		actionPlanJSON  string
		recommendedJSON string
	)

	if err := row.Scan(
		&item.ID,
		&item.AgentID,
		&item.IssueKey,
		&item.Category,
		&item.Severity,
		&item.Status,
		&item.Suppressed,
		&item.SnoozedUntil,
		&item.Title,
		&item.Description,
		&item.Source,
		&item.Evidence,
		&suggestionsJSON,
		&actionPlanJSON,
		&recommendedJSON,
		&item.FirstSeenAt,
		&item.LastSeenAt,
		&item.ResolvedAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return AgentIssue{}, fmt.Errorf("failed to scan issue: %w", err)
	}

	if err := decodeIssueJSONFields(&item, suggestionsJSON, actionPlanJSON, recommendedJSON); err != nil {
		return AgentIssue{}, err
	}

	return item, nil
}

func decodeIssueJSONFields(item *AgentIssue, suggestionsJSON, actionPlanJSON, recommendedJSON string) error {
	if item == nil {
		return fmt.Errorf("item is required")
	}

	if err := json.Unmarshal([]byte(suggestionsJSON), &item.Suggestions); err != nil {
		return fmt.Errorf("failed to decode issue suggestions: %w", err)
	}
	if err := json.Unmarshal([]byte(actionPlanJSON), &item.ActionPlan); err != nil {
		return fmt.Errorf("failed to decode issue action plan: %w", err)
	}
	if err := json.Unmarshal([]byte(recommendedJSON), &item.RecommendedActions); err != nil {
		return fmt.Errorf("failed to decode issue recommended actions: %w", err)
	}

	if item.Suggestions == nil {
		item.Suggestions = []string{}
	}
	if item.ActionPlan == nil {
		item.ActionPlan = []string{}
	}
	if item.RecommendedActions == nil {
		item.RecommendedActions = []IssueRecommendedAction{}
	}

	return nil
}

func resolveIssueAction(issue *AgentIssue, input IssueActionInput) IssueActionInput {
	resolved := input
	resolved.ActionID = strings.TrimSpace(input.ActionID)
	resolved.Mode = strings.ToLower(strings.TrimSpace(input.Mode))
	resolved.Kind = strings.ToLower(strings.TrimSpace(input.Kind))
	resolved.CommandType = strings.ToLower(strings.TrimSpace(input.CommandType))
	resolved.Payload = strings.TrimSpace(input.Payload)
	resolved.Name = strings.TrimSpace(input.Name)
	resolved.RecurrenceRule = strings.ToLower(strings.TrimSpace(input.RecurrenceRule))

	if issue != nil && resolved.ActionID != "" {
		for _, action := range issue.RecommendedActions {
			if strings.EqualFold(strings.TrimSpace(action.ID), resolved.ActionID) {
				if resolved.Kind == "" {
					resolved.Kind = strings.ToLower(strings.TrimSpace(action.Kind))
				}
				if resolved.CommandType == "" {
					resolved.CommandType = strings.ToLower(strings.TrimSpace(action.CommandType))
				}
				if resolved.Payload == "" {
					resolved.Payload = strings.TrimSpace(action.Payload)
				}
				if resolved.Name == "" {
					resolved.Name = strings.TrimSpace(action.Label)
				}
				break
			}
		}
	}

	if resolved.Mode == "" {
		resolved.Mode = "run_now"
	}
	if resolved.Kind == "" {
		resolved.Kind = "command"
	}

	return resolved
}

func ensureAITaskPayloadForAction(issue *AgentIssue, payload string) string {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		payload = "Analyze current issue context and produce remediation plan."
	}
	if _, err := ai.ParseTaskPayload(payload); err == nil {
		return payload
	}

	title := "Issue remediation"
	if issue != nil && strings.TrimSpace(issue.Title) != "" {
		title = issue.Title
	}
	return buildIssueAITaskPayload(title, payload)
}

func buildIssueAITaskPayload(title, instruction string) string {
	task := ai.Task{
		TaskID:      fmt.Sprintf("issue-%d", time.Now().UnixNano()),
		MotherRole:  ai.MotherInstructor,
		ChildIntent: ai.ChildWork,
		Title:       strings.TrimSpace(title),
		Instruction: strings.TrimSpace(instruction),
		Context:     "issue_remediation",
	}
	body, err := json.Marshal(task)
	if err != nil {
		fallback := `{"task_id":"issue-fallback","title":"Issue remediation","instruction":"Analyze and remediate issue","context":"issue_remediation"}`
		return fallback
	}
	return string(body)
}

func createIssueActionAudit(ctx context.Context, issue *AgentIssue, input IssueActionInput, createdBy string, commandID, scheduleID int64, status, errText string) error {
	if issue == nil {
		return fmt.Errorf("issue is required")
	}
	_, err := DB.Exec(ctx, `
		INSERT INTO issue_action_audit (
			issue_id, agent_id, action_id, action_mode, action_kind, command_type, payload,
			created_command_id, created_schedule_id, created_by, status, error
		)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, 0), NULLIF($9, 0), $10, $11, NULLIF($12, ''))
	`,
		issue.ID,
		issue.AgentID,
		strings.TrimSpace(input.ActionID),
		strings.TrimSpace(input.Mode),
		strings.TrimSpace(input.Kind),
		strings.TrimSpace(input.CommandType),
		strings.TrimSpace(input.Payload),
		commandID,
		scheduleID,
		strings.TrimSpace(createdBy),
		strings.TrimSpace(status),
		strings.TrimSpace(errText),
	)
	if err != nil {
		return fmt.Errorf("failed to create issue action audit: %w", err)
	}
	return nil
}
