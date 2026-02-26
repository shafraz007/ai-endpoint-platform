package server

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	ChatScopeGlobal = "global"
	ChatScopeAgent  = "agent"
)

type ChatMessage struct {
	ID        int64
	Scope     string
	AgentID   string
	Sender    string
	Message   string
	CreatedAt time.Time
}

func CreateChatMessage(ctx context.Context, scope, agentID, sender, message string) (*ChatMessage, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	agentID = strings.TrimSpace(agentID)
	sender = strings.TrimSpace(sender)
	message = strings.TrimSpace(message)

	if scope != ChatScopeGlobal && scope != ChatScopeAgent {
		return nil, fmt.Errorf("invalid scope")
	}
	if scope == ChatScopeAgent && agentID == "" {
		return nil, fmt.Errorf("agentID is required for agent scope")
	}
	if scope == ChatScopeGlobal {
		agentID = ""
	}
	if sender == "" {
		return nil, fmt.Errorf("sender is required")
	}
	if message == "" {
		return nil, fmt.Errorf("message is required")
	}

	query := `
	INSERT INTO chat_messages (scope, agent_id, sender, message)
	VALUES ($1, NULLIF($2, ''), $3, $4)
	RETURNING id, scope, COALESCE(agent_id, ''), sender, message, created_at
	`

	var item ChatMessage
	if err := DB.QueryRow(ctx, query, scope, agentID, sender, message).Scan(
		&item.ID,
		&item.Scope,
		&item.AgentID,
		&item.Sender,
		&item.Message,
		&item.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to create chat message: %w", err)
	}

	return &item, nil
}

func ListChatMessages(ctx context.Context, scope, agentID string, limit int) ([]ChatMessage, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	agentID = strings.TrimSpace(agentID)

	if scope != ChatScopeGlobal && scope != ChatScopeAgent {
		return nil, fmt.Errorf("invalid scope")
	}
	if scope == ChatScopeAgent && agentID == "" {
		return nil, fmt.Errorf("agentID is required for agent scope")
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	query := `
	SELECT id, scope, COALESCE(agent_id, ''), sender, message, created_at
	FROM chat_messages
	WHERE scope = $1 AND ($1 <> 'agent' OR agent_id = $2)
	ORDER BY created_at DESC
	LIMIT $3
	`

	rows, err := DB.Query(ctx, query, scope, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list chat messages: %w", err)
	}
	defer rows.Close()

	messages := make([]ChatMessage, 0, limit)
	for rows.Next() {
		var item ChatMessage
		if err := rows.Scan(&item.ID, &item.Scope, &item.AgentID, &item.Sender, &item.Message, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan chat message: %w", err)
		}
		messages = append(messages, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate chat messages: %w", err)
	}

	for left, right := 0, len(messages)-1; left < right; left, right = left+1, right-1 {
		messages[left], messages[right] = messages[right], messages[left]
	}

	return messages, nil
}
