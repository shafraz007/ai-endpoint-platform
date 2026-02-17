package server

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type AgentCommand struct {
	ID           int64
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

	query := `
	INSERT INTO agent_commands (agent_id, command_type, payload, status)
	VALUES ($1, $2, $3, 'queued')
	RETURNING id, agent_id, command_type, payload, status, created_at
	`

	var cmd AgentCommand
	if err := DB.QueryRow(ctx, query, agentID, commandType, payload).Scan(
		&cmd.ID,
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
	SELECT id, agent_id, command_type, payload, status, created_at
	FROM agent_commands
	WHERE agent_id = $1 AND status = 'queued'
	ORDER BY created_at ASC
	LIMIT 1
	FOR UPDATE SKIP LOCKED
	`

	var cmd AgentCommand
	if err := tx.QueryRow(ctx, query, agentID).Scan(
		&cmd.ID,
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
	SELECT id, agent_id, command_type, payload, status, created_at, dispatched_at, completed_at,
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
