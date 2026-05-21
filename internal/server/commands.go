package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrPowerCommandBlocked = errors.New("power command blocked by safety guard")

type AgentCommand struct {
	ID           int64
	ScheduleID   *int64
	AgentID      string
	CommandType  string
	Payload      string
	Status       string
	CreatedAt    time.Time
	DispatchedAt *time.Time
	CompletedAt  *time.Time
	Output       string
	Error        string
}

func CreateCommand(ctx context.Context, agentID, commandType, payload string) (*AgentCommand, error) {
	if agentID == "" {
		return nil, fmt.Errorf("agentID is required")
	}
	if commandType == "" {
		return nil, fmt.Errorf("commandType is required")
	}
	if err := validatePowerCommandTarget(ctx, agentID, commandType); err != nil {
		return nil, err
	}

	query := `
	INSERT INTO agent_commands (agent_id, command_type, payload, status)
	VALUES ($1, $2, $3, 'queued')
	RETURNING id, schedule_id, agent_id, command_type, payload, status, created_at
	`

	var cmd AgentCommand
	if err := DB.QueryRow(ctx, query, agentID, commandType, payload).Scan(
		&cmd.ID,
		&cmd.ScheduleID,
		&cmd.AgentID,
		&cmd.CommandType,
		&cmd.Payload,
		&cmd.Status,
		&cmd.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to create command: %w", err)
	}

	return &cmd, nil
}

func validatePowerCommandTarget(ctx context.Context, agentID, commandType string) error {
	if !isPowerCommand(commandType) {
		return nil
	}
	if !powerGuardEnabled() {
		return nil
	}

	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return fmt.Errorf("%w: missing agent id", ErrPowerCommandBlocked)
	}
	if isPowerCommandAgentAllowed(agentID) {
		return nil
	}

	var hostname string
	err := DB.QueryRow(ctx, `SELECT COALESCE(hostname, '') FROM agents WHERE agent_id = $1`, agentID).Scan(&hostname)
	if err != nil {
		return fmt.Errorf("%w: failed to validate target agent", ErrPowerCommandBlocked)
	}

	hostname = strings.TrimSpace(hostname)
	if hostPatternAllowed(hostname) {
		return nil
	}

	return fmt.Errorf("%w: agent_id=%s hostname=%s", ErrPowerCommandBlocked, agentID, hostname)
}

func isPowerCommand(commandType string) bool {
	switch strings.ToLower(strings.TrimSpace(commandType)) {
	case "restart", "shutdown":
		return true
	default:
		return false
	}
}

func powerGuardEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("POWER_COMMAND_GUARD_ENABLED")))
	if raw == "0" || raw == "false" || raw == "no" || raw == "off" {
		return false
	}
	return true
}

func isPowerCommandAgentAllowed(agentID string) bool {
	raw := strings.TrimSpace(os.Getenv("POWER_COMMAND_ALLOWED_AGENT_IDS"))
	if raw == "" {
		return false
	}
	// Special values "all" or "*" allow every agent.
	lower := strings.ToLower(raw)
	if lower == "all" || lower == "*" {
		return true
	}
	for _, part := range strings.Split(raw, ",") {
		if strings.TrimSpace(part) == agentID {
			return true
		}
	}
	return false
}

func hostPatternAllowed(hostname string) bool {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return false
	}

	pattern := strings.TrimSpace(os.Getenv("POWER_COMMAND_ALLOWED_HOSTNAME_REGEX"))
	if pattern == "" {
		pattern = `^[a-f0-9]{12}$`
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(hostname)
}

func CreateAITaskCommandIfNotExists(ctx context.Context, agentID, payload, taskID string) (*AgentCommand, bool, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return nil, false, fmt.Errorf("agentID is required")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, false, fmt.Errorf("taskID is required")
	}

	taskIDPattern := "%\"task_id\":\"" + taskID + "\"%"
	lockKey := agentID + "|" + taskID

	tx, err := DB.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to begin idempotent ai_task transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return nil, false, fmt.Errorf("failed to acquire idempotent ai_task lock: %w", err)
	}

	query := `
	INSERT INTO agent_commands (agent_id, command_type, payload, status)
	SELECT $1::text, 'ai_task', $2::text, 'queued'
	WHERE NOT EXISTS (
		SELECT 1
		FROM agent_commands
		WHERE agent_id = $1::text
			AND command_type = 'ai_task'
			AND payload LIKE $3::text
	)
	RETURNING id, schedule_id, agent_id, command_type, payload, status, created_at
	`

	var cmd AgentCommand
	if err := tx.QueryRow(ctx, query, agentID, payload, taskIDPattern).Scan(
		&cmd.ID,
		&cmd.ScheduleID,
		&cmd.AgentID,
		&cmd.CommandType,
		&cmd.Payload,
		&cmd.Status,
		&cmd.CreatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			if commitErr := tx.Commit(ctx); commitErr != nil {
				return nil, false, fmt.Errorf("failed to commit duplicate ai_task transaction: %w", commitErr)
			}
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to create idempotent ai_task command: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("failed to commit idempotent ai_task command: %w", err)
	}

	return &cmd, true, nil
}

func DequeueCommand(ctx context.Context, agentID string) (*AgentCommand, error) {
	if agentID == "" {
		return nil, fmt.Errorf("agentID is required")
	}

	tx, err := DB.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	query := `
	SELECT id, schedule_id, agent_id, command_type, payload, status, created_at
	FROM agent_commands
	WHERE agent_id = $1 AND status = 'queued'
	ORDER BY created_at ASC
	LIMIT 1
	FOR UPDATE SKIP LOCKED
	`

	var cmd AgentCommand
	if err := tx.QueryRow(ctx, query, agentID).Scan(
		&cmd.ID,
		&cmd.ScheduleID,
		&cmd.AgentID,
		&cmd.CommandType,
		&cmd.Payload,
		&cmd.Status,
		&cmd.CreatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to dequeue command: %w", err)
	}

	var dispatchedAt time.Time
	update := `
	UPDATE agent_commands
	SET status = 'dispatched', dispatched_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
	WHERE id = $1
	RETURNING dispatched_at
	`
	if err := tx.QueryRow(ctx, update, cmd.ID).Scan(&dispatchedAt); err != nil {
		return nil, fmt.Errorf("failed to mark command dispatched: %w", err)
	}

	cmd.Status = "dispatched"
	cmd.DispatchedAt = &dispatchedAt

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit dequeue: %w", err)
	}

	return &cmd, nil
}

// MarkCommandRunning transitions a command to "running" status without setting
// completed_at. This is called as soon as an agent picks up and starts executing
// a command, so the server can surface in-progress state immediately.
func MarkCommandRunning(ctx context.Context, commandID int64, agentID string) error {
	if commandID <= 0 {
		return fmt.Errorf("commandID is required")
	}
	if agentID == "" {
		return fmt.Errorf("agentID is required")
	}

	query := `
	UPDATE agent_commands
	SET status = 'running', updated_at = CURRENT_TIMESTAMP
	WHERE id = $1 AND agent_id = $2 AND status IN ('queued', 'dispatched')
	`

	_, err := DB.Exec(ctx, query, commandID, agentID)
	return err
}

func AckCommand(ctx context.Context, commandID int64, agentID, status, output, errMsg string) error {
	if commandID <= 0 {
		return fmt.Errorf("commandID is required")
	}
	if agentID == "" {
		return fmt.Errorf("agentID is required")
	}

	query := `
	UPDATE agent_commands
	SET status = $1, output = $2, error = $3, completed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
	WHERE id = $4 AND agent_id = $5
	`

	cmdTag, err := DB.Exec(ctx, query, status, output, errMsg, commandID, agentID)
	if err != nil {
		return fmt.Errorf("failed to ack command: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("command not found")
	}

	return nil
}

func ListCommandsByAgent(ctx context.Context, agentID string, limit int) ([]AgentCommand, error) {
	if agentID == "" {
		return nil, fmt.Errorf("agentID is required")
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}

	query := `
	SELECT id, schedule_id, agent_id, command_type, payload, status, created_at, dispatched_at, completed_at,
		COALESCE(output, ''), COALESCE(error, '')
	FROM agent_commands
	WHERE agent_id = $1
	ORDER BY created_at DESC
	LIMIT $2
	`

	rows, err := DB.Query(ctx, query, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list commands: %w", err)
	}
	defer rows.Close()

	var commands []AgentCommand
	for rows.Next() {
		var cmd AgentCommand
		if err := rows.Scan(
			&cmd.ID,
			&cmd.ScheduleID,
			&cmd.AgentID,
			&cmd.CommandType,
			&cmd.Payload,
			&cmd.Status,
			&cmd.CreatedAt,
			&cmd.DispatchedAt,
			&cmd.CompletedAt,
			&cmd.Output,
			&cmd.Error,
		); err != nil {
			return nil, fmt.Errorf("failed to scan command: %w", err)
		}
		commands = append(commands, cmd)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate commands: %w", err)
	}

	return commands, nil
}

func GetCommandByID(ctx context.Context, commandID int64, agentID string) (*AgentCommand, error) {
	if commandID <= 0 {
		return nil, fmt.Errorf("commandID is required")
	}
	if agentID == "" {
		return nil, fmt.Errorf("agentID is required")
	}

	query := `
	SELECT id, schedule_id, agent_id, command_type, payload, status, created_at, dispatched_at, completed_at,
		COALESCE(output, ''), COALESCE(error, '')
	FROM agent_commands
	WHERE id = $1 AND agent_id = $2
	LIMIT 1
	`

	var cmd AgentCommand
	err := DB.QueryRow(ctx, query, commandID, agentID).Scan(
		&cmd.ID,
		&cmd.ScheduleID,
		&cmd.AgentID,
		&cmd.CommandType,
		&cmd.Payload,
		&cmd.Status,
		&cmd.CreatedAt,
		&cmd.DispatchedAt,
		&cmd.CompletedAt,
		&cmd.Output,
		&cmd.Error,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("command not found")
		}
		return nil, fmt.Errorf("failed to fetch command: %w", err)
	}

	return &cmd, nil
}

// CancelCommand cancels a queued command.
// Returns an error if the command is not found, doesn't belong to the agent, or is not in 'queued' status.
func CancelCommand(ctx context.Context, commandID int64, agentID string) (*AgentCommand, error) {
	if commandID <= 0 {
		return nil, fmt.Errorf("commandID is required")
	}
	if agentID == "" {
		return nil, fmt.Errorf("agentID is required")
	}

	// First, verify the command exists and belongs to the agent
	cmd, err := GetCommandByID(ctx, commandID, agentID)
	if err != nil {
		return nil, err
	}

	// Only allow cancelling queued commands
	if cmd.Status != "queued" {
		return nil, fmt.Errorf("cannot cancel command with status '%s' (only 'queued' commands can be cancelled)", cmd.Status)
	}

	// Update the command status to cancelled
	query := `
	UPDATE agent_commands
	SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP
	WHERE id = $1 AND agent_id = $2
	RETURNING id, schedule_id, agent_id, command_type, payload, status, created_at, dispatched_at, completed_at,
		COALESCE(output, ''), COALESCE(error, '')
	`

	var updatedCmd AgentCommand
	if err := DB.QueryRow(ctx, query, commandID, agentID).Scan(
		&updatedCmd.ID,
		&updatedCmd.ScheduleID,
		&updatedCmd.AgentID,
		&updatedCmd.CommandType,
		&updatedCmd.Payload,
		&updatedCmd.Status,
		&updatedCmd.CreatedAt,
		&updatedCmd.DispatchedAt,
		&updatedCmd.CompletedAt,
		&updatedCmd.Output,
		&updatedCmd.Error,
	); err != nil {
		return nil, fmt.Errorf("failed to cancel command: %w", err)
	}

	return &updatedCmd, nil
}

func canRequeueStatus(status string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case "queued", "dispatched", "running":
		return false
	default:
		return true
	}
}

// RequeueCommand clones an existing command into a new queued command.
// Only non-active (historical) commands are eligible for requeue.
func RequeueCommand(ctx context.Context, commandID int64, agentID string) (*AgentCommand, error) {
	if commandID <= 0 {
		return nil, fmt.Errorf("commandID is required")
	}
	if agentID == "" {
		return nil, fmt.Errorf("agentID is required")
	}

	original, err := GetCommandByID(ctx, commandID, agentID)
	if err != nil {
		return nil, err
	}

	if !canRequeueStatus(original.Status) {
		return nil, fmt.Errorf(
			"cannot requeue command with status '%s' (only historical commands can be requeued)",
			original.Status,
		)
	}

	cloned, err := CreateCommand(ctx, original.AgentID, original.CommandType, original.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to requeue command: %w", err)
	}

	return cloned, nil
}
