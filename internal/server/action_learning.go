package server

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	learningNeutralScore          = 0.5
	learningConfidencePriorWeight = 4.0
	learningDecayHalfLifeHours    = 72.0
	learningRecentFailurePenalty  = 0.05
)

type AgentActionRun struct {
	ID            int64     `json:"id"`
	AgentID       string    `json:"agent_id"`
	CommandID     *int64    `json:"command_id,omitempty"`
	CommandType   string    `json:"command_type"`
	ToolKey       string    `json:"tool_key"`
	Status        string    `json:"status"`
	Success       bool      `json:"success"`
	LatencyMS     int64     `json:"latency_ms"`
	OutputExcerpt string    `json:"output_excerpt,omitempty"`
	ErrorText     string    `json:"error_text,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type AgentToolScore struct {
	AgentID    string    `json:"agent_id"`
	ToolKey    string    `json:"tool_key"`
	Attempts   int64     `json:"attempts"`
	Successes  int64     `json:"successes"`
	Failures   int64     `json:"failures"`
	Score      float64   `json:"score"`
	LastStatus string    `json:"last_status"`
	LastError  string    `json:"last_error,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type FleetToolScore struct {
	ToolKey    string    `json:"tool_key"`
	Attempts   int64     `json:"attempts"`
	Successes  int64     `json:"successes"`
	Failures   int64     `json:"failures"`
	AgentCount int64     `json:"agent_count"`
	Score      float64   `json:"score"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func RecordActionOutcome(ctx context.Context, command *AgentCommand, status, output, errMsg string) error {
	if command == nil {
		return fmt.Errorf("command is required")
	}
	agentID := strings.TrimSpace(command.AgentID)
	if agentID == "" {
		return fmt.Errorf("agentID is required")
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "succeeded" && status != "failed" {
		return fmt.Errorf("invalid status")
	}

	toolKey := canonicalToolKey(command.CommandType)
	success := status == "succeeded"
	now := time.Now().UTC()
	latencyMS := int64(0)
	if !command.CreatedAt.IsZero() {
		latencyMS = now.Sub(command.CreatedAt).Milliseconds()
		if latencyMS < 0 {
			latencyMS = 0
		}
	}

	excerpt := summarizeOutput(output, 800)
	errText := summarizeOutput(errMsg, 800)

	insertRunQuery := `
	INSERT INTO agent_action_runs (
		agent_id, command_id, command_type, tool_key, status, success, latency_ms, output_excerpt, error_text
	)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	if _, err := DB.Exec(ctx, insertRunQuery,
		agentID,
		command.ID,
		strings.TrimSpace(command.CommandType),
		toolKey,
		status,
		success,
		latencyMS,
		excerpt,
		errText,
	); err != nil {
		return fmt.Errorf("failed to insert action run: %w", err)
	}

	successCount := int64(0)
	failureCount := int64(0)
	if success {
		successCount = 1
	} else {
		failureCount = 1
	}

	upsertScoreQuery := `
	INSERT INTO agent_tool_scores (
		agent_id, tool_key, attempts, successes, failures, score, last_status, last_error, updated_at
	)
	VALUES ($1, $2, 1, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
	ON CONFLICT (agent_id, tool_key)
	DO UPDATE SET
		attempts = agent_tool_scores.attempts + 1,
		successes = agent_tool_scores.successes + EXCLUDED.successes,
		failures = agent_tool_scores.failures + EXCLUDED.failures,
		score = (agent_tool_scores.successes + EXCLUDED.successes)::double precision /
			NULLIF((agent_tool_scores.attempts + 1)::double precision, 0),
		last_status = EXCLUDED.last_status,
		last_error = EXCLUDED.last_error,
		updated_at = CURRENT_TIMESTAMP
	`

	initialScore := 0.0
	if success {
		initialScore = 1.0
	}

	if _, err := DB.Exec(ctx, upsertScoreQuery,
		agentID,
		toolKey,
		successCount,
		failureCount,
		initialScore,
		status,
		errText,
	); err != nil {
		return fmt.Errorf("failed to upsert tool score: %w", err)
	}

	return nil
}

func canonicalToolKey(commandType string) string {
	switch strings.ToLower(strings.TrimSpace(commandType)) {
	case "ai_task":
		return "core.ai_task"
	case "echo":
		return "core.echo"
	case "powershell":
		return "execution.powershell"
	case "cmd":
		return "execution.cmd"
	case "shell":
		return "execution.shell"
	case "ping":
		return "diagnostics.network"
	case "restart", "shutdown":
		return "control.power"
	default:
		if strings.TrimSpace(commandType) == "" {
			return "command.unknown"
		}
		return "command." + strings.ToLower(strings.TrimSpace(commandType))
	}
}

func summarizeOutput(raw string, max int) string {
	cleaned := strings.TrimSpace(strings.ReplaceAll(raw, "\x00", ""))
	if cleaned == "" {
		return ""
	}
	if max <= 0 {
		max = 800
	}
	if len(cleaned) <= max {
		return cleaned
	}
	if max <= 3 {
		return cleaned[:max]
	}
	return cleaned[:max-3] + "..."
}

func ListAgentActionRuns(ctx context.Context, agentID string, limit int) ([]AgentActionRun, error) {
	agentID = strings.TrimSpace(agentID)
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
	SELECT id, agent_id, command_id, command_type, tool_key, status, success, latency_ms,
		COALESCE(output_excerpt, ''), COALESCE(error_text, ''), created_at
	FROM agent_action_runs
	WHERE agent_id = $1
	ORDER BY created_at DESC
	LIMIT $2
	`

	rows, err := DB.Query(ctx, query, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query agent action runs: %w", err)
	}
	defer rows.Close()

	runs := make([]AgentActionRun, 0, limit)
	for rows.Next() {
		var run AgentActionRun
		if err := rows.Scan(
			&run.ID,
			&run.AgentID,
			&run.CommandID,
			&run.CommandType,
			&run.ToolKey,
			&run.Status,
			&run.Success,
			&run.LatencyMS,
			&run.OutputExcerpt,
			&run.ErrorText,
			&run.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan action run: %w", err)
		}
		runs = append(runs, run)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating action runs: %w", err)
	}

	return runs, nil
}

func ListAgentToolScores(ctx context.Context, agentID string, limit int) ([]AgentToolScore, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return nil, fmt.Errorf("agentID is required")
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	fetchLimit := limit
	if fetchLimit < 200 {
		fetchLimit = 200
	}

	query := `
	SELECT agent_id, tool_key, attempts, successes, failures, score,
		COALESCE(last_status, ''), COALESCE(last_error, ''), updated_at
	FROM agent_tool_scores
	WHERE agent_id = $1
	ORDER BY updated_at DESC, attempts DESC
	LIMIT $2
	`

	rows, err := DB.Query(ctx, query, agentID, fetchLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to query agent tool scores: %w", err)
	}
	defer rows.Close()

	scores := make([]AgentToolScore, 0, fetchLimit)
	for rows.Next() {
		var score AgentToolScore
		if err := rows.Scan(
			&score.AgentID,
			&score.ToolKey,
			&score.Attempts,
			&score.Successes,
			&score.Failures,
			&score.Score,
			&score.LastStatus,
			&score.LastError,
			&score.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan tool score: %w", err)
		}
		score.Score = computeEffectiveToolScore(score, time.Now().UTC())
		scores = append(scores, score)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating tool scores: %w", err)
	}

	if len(scores) > 1 {
		sort.Slice(scores, func(i, j int) bool {
			if scores[i].Score == scores[j].Score {
				if scores[i].UpdatedAt.Equal(scores[j].UpdatedAt) {
					return scores[i].ToolKey < scores[j].ToolKey
				}
				return scores[i].UpdatedAt.After(scores[j].UpdatedAt)
			}
			return scores[i].Score > scores[j].Score
		})
	}

	if len(scores) > limit {
		scores = scores[:limit]
	}

	return scores, nil
}

func ListFleetToolScores(ctx context.Context, excludeAgentID string, limit int) ([]FleetToolScore, error) {
	excludeAgentID = strings.TrimSpace(excludeAgentID)
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	fetchLimit := limit
	if fetchLimit < 200 {
		fetchLimit = 200
	}

	query := `
	SELECT tool_key,
		COALESCE(SUM(attempts), 0) AS attempts,
		COALESCE(SUM(successes), 0) AS successes,
		COALESCE(SUM(failures), 0) AS failures,
		COUNT(DISTINCT agent_id) AS agent_count,
		MAX(updated_at) AS updated_at
	FROM agent_tool_scores
	WHERE ($1 = '' OR agent_id <> $1)
	GROUP BY tool_key
	ORDER BY MAX(updated_at) DESC, SUM(attempts) DESC
	LIMIT $2
	`

	rows, err := DB.Query(ctx, query, excludeAgentID, fetchLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to query fleet tool scores: %w", err)
	}
	defer rows.Close()

	scores := make([]FleetToolScore, 0, fetchLimit)
	now := time.Now().UTC()
	for rows.Next() {
		var score FleetToolScore
		if err := rows.Scan(
			&score.ToolKey,
			&score.Attempts,
			&score.Successes,
			&score.Failures,
			&score.AgentCount,
			&score.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan fleet tool score: %w", err)
		}

		rawScore := 0.0
		if score.Attempts > 0 {
			rawScore = float64(score.Successes) / float64(score.Attempts)
		}
		score.Score = computeEffectiveToolScore(AgentToolScore{
			Attempts:  score.Attempts,
			Score:     rawScore,
			UpdatedAt: score.UpdatedAt,
		}, now)
		scores = append(scores, score)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating fleet tool scores: %w", err)
	}

	if len(scores) > 1 {
		sort.Slice(scores, func(i, j int) bool {
			if scores[i].Score == scores[j].Score {
				if scores[i].AgentCount == scores[j].AgentCount {
					if scores[i].UpdatedAt.Equal(scores[j].UpdatedAt) {
						return scores[i].ToolKey < scores[j].ToolKey
					}
					return scores[i].UpdatedAt.After(scores[j].UpdatedAt)
				}
				return scores[i].AgentCount > scores[j].AgentCount
			}
			return scores[i].Score > scores[j].Score
		})
	}

	if len(scores) > limit {
		scores = scores[:limit]
	}

	return scores, nil
}

func computeEffectiveToolScore(score AgentToolScore, now time.Time) float64 {
	base := clamp01(score.Score)
	confidence := float64(score.Attempts) / (float64(score.Attempts) + learningConfidencePriorWeight)
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}

	decay := 1.0
	if !score.UpdatedAt.IsZero() {
		age := now.Sub(score.UpdatedAt)
		if age > 0 {
			ageHours := age.Hours()
			decay = math.Exp(-math.Ln2 * (ageHours / learningDecayHalfLifeHours))
		}
	}

	effective := learningNeutralScore + (base-learningNeutralScore)*confidence*decay
	if strings.EqualFold(strings.TrimSpace(score.LastStatus), "failed") {
		effective -= learningRecentFailurePenalty * decay
	}

	return clamp01(effective)
}

func clamp01(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}
