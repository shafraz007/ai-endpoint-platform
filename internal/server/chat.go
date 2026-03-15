package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	ChatScopeGlobal = "global"
	ChatScopeAgent  = "agent"
)

type ChatMessage struct {
	ID        int64
	Scope     string
	AgentID   string
	SessionID int64
	Sender    string
	Message   string
	CreatedAt time.Time
}

type GlobalChatSession struct {
	ID            int64
	Title         string
	CreatedBy     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastMessageAt *time.Time
	MessageCount  int64
}

type GlobalChatSessionMemory struct {
	SessionID              int64
	Summary                string
	LastCompactedMessageID int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

func CreateGlobalChatSession(ctx context.Context, createdBy, title string) (*GlobalChatSession, error) {
	createdBy = strings.TrimSpace(createdBy)
	title = strings.TrimSpace(title)
	if createdBy == "" {
		return nil, fmt.Errorf("createdBy is required")
	}
	if title == "" {
		title = "New Chat"
	}

	query := `
	INSERT INTO global_chat_sessions (title, created_by)
	VALUES ($1, $2)
	RETURNING id, title, created_by, created_at, updated_at
	`

	var item GlobalChatSession
	if err := DB.QueryRow(ctx, query, title, createdBy).Scan(
		&item.ID,
		&item.Title,
		&item.CreatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to create global chat session: %w", err)
	}

	return &item, nil
}

func ListGlobalChatSessions(ctx context.Context, limit int) ([]GlobalChatSession, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	query := `
	SELECT
		s.id,
		s.title,
		s.created_by,
		s.created_at,
		s.updated_at,
		MAX(m.created_at) AS last_message_at,
		COUNT(m.id)::BIGINT AS message_count
	FROM global_chat_sessions s
	LEFT JOIN chat_messages m ON m.scope = 'global' AND m.session_id = s.id
	GROUP BY s.id, s.title, s.created_by, s.created_at, s.updated_at
	ORDER BY COALESCE(MAX(m.created_at), s.updated_at) DESC, s.id DESC
	LIMIT $1
	`

	rows, err := DB.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list global chat sessions: %w", err)
	}
	defer rows.Close()

	items := make([]GlobalChatSession, 0, limit)
	for rows.Next() {
		var item GlobalChatSession
		if err := rows.Scan(
			&item.ID,
			&item.Title,
			&item.CreatedBy,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.LastMessageAt,
			&item.MessageCount,
		); err != nil {
			return nil, fmt.Errorf("failed to scan global chat session: %w", err)
		}
		items = append(items, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate global chat sessions: %w", err)
	}

	return items, nil
}

func GetGlobalChatSessionByID(ctx context.Context, sessionID int64) (*GlobalChatSession, error) {
	if sessionID <= 0 {
		return nil, fmt.Errorf("invalid session id")
	}

	query := `
	SELECT
		s.id,
		s.title,
		s.created_by,
		s.created_at,
		s.updated_at,
		MAX(m.created_at) AS last_message_at,
		COUNT(m.id)::BIGINT AS message_count
	FROM global_chat_sessions s
	LEFT JOIN chat_messages m ON m.scope = 'global' AND m.session_id = s.id
	WHERE s.id = $1
	GROUP BY s.id, s.title, s.created_by, s.created_at, s.updated_at
	`

	var item GlobalChatSession
	if err := DB.QueryRow(ctx, query, sessionID).Scan(
		&item.ID,
		&item.Title,
		&item.CreatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.LastMessageAt,
		&item.MessageCount,
	); err != nil {
		return nil, fmt.Errorf("failed to get global chat session: %w", err)
	}

	return &item, nil
}

func UpdateGlobalChatSessionTitleIfDefault(ctx context.Context, sessionID int64, newTitle string) (bool, error) {
	if sessionID <= 0 {
		return false, fmt.Errorf("invalid session id")
	}

	newTitle = strings.TrimSpace(newTitle)
	if newTitle == "" {
		return false, fmt.Errorf("new title is required")
	}
	if len(newTitle) > 120 {
		newTitle = strings.TrimSpace(newTitle[:120])
	}

	result, err := DB.Exec(ctx, `
		UPDATE global_chat_sessions
		SET title = $2,
		    updated_at = NOW()
		WHERE id = $1
		  AND title = 'New Chat'
	`, sessionID, newTitle)
	if err != nil {
		return false, fmt.Errorf("failed to update global chat session title: %w", err)
	}

	return result.RowsAffected() > 0, nil
}

func EnsureGlobalChatSession(ctx context.Context, createdBy string) (*GlobalChatSession, error) {
	sessions, err := ListGlobalChatSessions(ctx, 1)
	if err != nil {
		return nil, err
	}
	if len(sessions) > 0 {
		return &sessions[0], nil
	}
	return CreateGlobalChatSession(ctx, createdBy, "New Chat")
}

func GetGlobalChatSessionMemory(ctx context.Context, sessionID int64) (*GlobalChatSessionMemory, error) {
	if sessionID <= 0 {
		return nil, fmt.Errorf("invalid session id")
	}

	query := `
	SELECT session_id, COALESCE(summary, ''), COALESCE(last_compacted_message_id, 0), created_at, updated_at
	FROM global_chat_session_memory
	WHERE session_id = $1
	`

	var item GlobalChatSessionMemory
	err := DB.QueryRow(ctx, query, sessionID).Scan(
		&item.SessionID,
		&item.Summary,
		&item.LastCompactedMessageID,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get global chat session memory: %w", err)
	}

	return &item, nil
}

func UpsertGlobalChatSessionMemory(ctx context.Context, sessionID int64, summary string, lastCompactedMessageID int64) error {
	if sessionID <= 0 {
		return fmt.Errorf("invalid session id")
	}
	summary = strings.TrimSpace(summary)
	if len(summary) > 8000 {
		summary = strings.TrimSpace(summary[:8000])
	}
	if lastCompactedMessageID < 0 {
		lastCompactedMessageID = 0
	}

	_, err := DB.Exec(ctx, `
		INSERT INTO global_chat_session_memory (session_id, summary, last_compacted_message_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (session_id) DO UPDATE SET
			summary = EXCLUDED.summary,
			last_compacted_message_id = EXCLUDED.last_compacted_message_id,
			updated_at = CURRENT_TIMESTAMP
	`, sessionID, summary, lastCompactedMessageID)
	if err != nil {
		return fmt.Errorf("failed to upsert global chat session memory: %w", err)
	}

	return nil
}

func CreateChatMessage(ctx context.Context, scope, agentID, sender, message string) (*ChatMessage, error) {
	return CreateChatMessageWithSession(ctx, scope, agentID, 0, sender, message)
}

func CreateChatMessageWithSession(ctx context.Context, scope, agentID string, sessionID int64, sender, message string) (*ChatMessage, error) {
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
		if sessionID < 0 {
			sessionID = 0
		}
	} else {
		sessionID = 0
	}
	if sender == "" {
		return nil, fmt.Errorf("sender is required")
	}
	if message == "" {
		return nil, fmt.Errorf("message is required")
	}

	query := `
	INSERT INTO chat_messages (scope, agent_id, session_id, sender, message)
	VALUES ($1::VARCHAR, NULLIF($2, ''), CASE WHEN $1::TEXT = 'global' AND $3::BIGINT > 0 THEN $3::BIGINT ELSE NULL::BIGINT END, $4, $5)
	RETURNING id, scope, COALESCE(agent_id, ''), COALESCE(session_id, 0), sender, message, created_at
	`

	var item ChatMessage
	if err := DB.QueryRow(ctx, query, scope, agentID, sessionID, sender, message).Scan(
		&item.ID,
		&item.Scope,
		&item.AgentID,
		&item.SessionID,
		&item.Sender,
		&item.Message,
		&item.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to create chat message: %w", err)
	}

	return &item, nil
}

func ListChatMessages(ctx context.Context, scope, agentID string, limit int) ([]ChatMessage, error) {
	return ListChatMessagesWithSession(ctx, scope, agentID, 0, limit)
}

func ListChatMessagesWithSession(ctx context.Context, scope, agentID string, sessionID int64, limit int) ([]ChatMessage, error) {
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
	if scope != ChatScopeGlobal {
		sessionID = 0
	}

	query := `
	SELECT id, scope, COALESCE(agent_id, ''), COALESCE(session_id, 0), sender, message, created_at
	FROM chat_messages
	WHERE scope = $1
	  AND ($1 <> 'agent' OR agent_id = $2)
	  AND ($1 <> 'global' OR $4 <= 0 OR session_id = $4)
	ORDER BY created_at DESC
	LIMIT $3
	`

	rows, err := DB.Query(ctx, query, scope, agentID, limit, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list chat messages: %w", err)
	}
	defer rows.Close()

	messages := make([]ChatMessage, 0, limit)
	for rows.Next() {
		var item ChatMessage
		if err := rows.Scan(&item.ID, &item.Scope, &item.AgentID, &item.SessionID, &item.Sender, &item.Message, &item.CreatedAt); err != nil {
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

func ListChatMessagesAfterID(ctx context.Context, scope, agentID string, afterID int64, limit int) ([]ChatMessage, error) {
	return ListChatMessagesAfterIDWithSession(ctx, scope, agentID, 0, afterID, limit)
}

func ListChatMessagesAfterIDWithSession(ctx context.Context, scope, agentID string, sessionID int64, afterID int64, limit int) ([]ChatMessage, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	agentID = strings.TrimSpace(agentID)

	if scope != ChatScopeGlobal && scope != ChatScopeAgent {
		return nil, fmt.Errorf("invalid scope")
	}
	if scope == ChatScopeAgent && agentID == "" {
		return nil, fmt.Errorf("agentID is required for agent scope")
	}
	if afterID < 0 {
		afterID = 0
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if scope != ChatScopeGlobal {
		sessionID = 0
	}

	query := `
	SELECT id, scope, COALESCE(agent_id, ''), COALESCE(session_id, 0), sender, message, created_at
	FROM chat_messages
	WHERE scope = $1
	  AND ($1 <> 'agent' OR agent_id = $2)
	  AND ($1 <> 'global' OR $5 <= 0 OR session_id = $5)
	  AND id > $3
	ORDER BY id ASC
	LIMIT $4
	`

	rows, err := DB.Query(ctx, query, scope, agentID, afterID, limit, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list chat messages after id: %w", err)
	}
	defer rows.Close()

	messages := make([]ChatMessage, 0, limit)
	for rows.Next() {
		var item ChatMessage
		if err := rows.Scan(&item.ID, &item.Scope, &item.AgentID, &item.SessionID, &item.Sender, &item.Message, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan chat message: %w", err)
		}
		messages = append(messages, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate chat messages: %w", err)
	}

	return messages, nil
}
