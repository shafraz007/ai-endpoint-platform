package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shafraz007/ai-endpoint-platform/internal/ai"
)

type Schedule struct {
	ID                    int64
	Name                  string
	Kind                  string
	TargetScope           string
	TargetAgentID         string
	TargetGroupID         *int
	CommandType           string
	Payload               string
	RunAt                 time.Time
	RepeatIntervalSeconds int
	RecurrenceRule        string
	Enabled               bool
	LastRunAt             *time.Time
	NextRunAt             time.Time
	CreatedBy             string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type DispatchResult struct {
	SchedulesProcessed int
	CommandsCreated    int
}

func CreateSchedule(ctx context.Context, schedule Schedule) (*Schedule, error) {
	normalized, err := normalizeSchedule(schedule)
	if err != nil {
		return nil, err
	}

	query := `
	INSERT INTO schedules (
		name, kind, target_scope, target_agent_id, target_group_id,
		command_type, payload, run_at, repeat_interval_seconds,
		recurrence_rule, enabled, last_run_at, next_run_at, created_by
	)
	VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7, $8, $9, NULLIF($10, ''), $11, $12, $13, NULLIF($14, ''))
	RETURNING id, name, kind, target_scope, COALESCE(target_agent_id, ''), target_group_id,
		COALESCE(command_type, ''), payload, run_at, repeat_interval_seconds, COALESCE(recurrence_rule, ''),
		enabled, last_run_at, next_run_at, COALESCE(created_by, ''), created_at, updated_at
	`

	var created Schedule
	if err := DB.QueryRow(
		ctx,
		query,
		normalized.Name,
		normalized.Kind,
		normalized.TargetScope,
		normalized.TargetAgentID,
		normalized.TargetGroupID,
		normalized.CommandType,
		normalized.Payload,
		normalized.RunAt,
		normalized.RepeatIntervalSeconds,
		normalized.RecurrenceRule,
		normalized.Enabled,
		normalized.LastRunAt,
		normalized.NextRunAt,
		normalized.CreatedBy,
	).Scan(
		&created.ID,
		&created.Name,
		&created.Kind,
		&created.TargetScope,
		&created.TargetAgentID,
		&created.TargetGroupID,
		&created.CommandType,
		&created.Payload,
		&created.RunAt,
		&created.RepeatIntervalSeconds,
		&created.RecurrenceRule,
		&created.Enabled,
		&created.LastRunAt,
		&created.NextRunAt,
		&created.CreatedBy,
		&created.CreatedAt,
		&created.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to create schedule: %w", err)
	}

	return &created, nil
}

func ListSchedules(ctx context.Context, limit int) ([]Schedule, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	query := `
	SELECT id, name, kind, target_scope, COALESCE(target_agent_id, ''), target_group_id,
		COALESCE(command_type, ''), payload, run_at, repeat_interval_seconds, COALESCE(recurrence_rule, ''),
		enabled, last_run_at, next_run_at, COALESCE(created_by, ''), created_at, updated_at
	FROM schedules
	ORDER BY next_run_at ASC, id ASC
	LIMIT $1
	`

	rows, err := DB.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list schedules: %w", err)
	}
	defer rows.Close()

	var schedules []Schedule
	for rows.Next() {
		var item Schedule
		if err := rows.Scan(
			&item.ID,
			&item.Name,
			&item.Kind,
			&item.TargetScope,
			&item.TargetAgentID,
			&item.TargetGroupID,
			&item.CommandType,
			&item.Payload,
			&item.RunAt,
			&item.RepeatIntervalSeconds,
			&item.RecurrenceRule,
			&item.Enabled,
			&item.LastRunAt,
			&item.NextRunAt,
			&item.CreatedBy,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan schedule: %w", err)
		}
		schedules = append(schedules, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate schedules: %w", err)
	}

	return schedules, nil
}

func UpdateSchedule(ctx context.Context, id int64, schedule Schedule) (*Schedule, error) {
	if id <= 0 {
		return nil, fmt.Errorf("id is required")
	}

	normalized, err := normalizeSchedule(schedule)
	if err != nil {
		return nil, err
	}

	query := `
	UPDATE schedules
	SET name = $2,
		kind = $3,
		target_scope = $4,
		target_agent_id = NULLIF($5, ''),
		target_group_id = $6,
		command_type = $7,
		payload = $8,
		run_at = $9,
		repeat_interval_seconds = $10,
		recurrence_rule = NULLIF($11, ''),
		enabled = $12,
		next_run_at = $13,
		updated_at = CURRENT_TIMESTAMP
	WHERE id = $1
	RETURNING id, name, kind, target_scope, COALESCE(target_agent_id, ''), target_group_id,
		COALESCE(command_type, ''), payload, run_at, repeat_interval_seconds, COALESCE(recurrence_rule, ''),
		enabled, last_run_at, next_run_at, COALESCE(created_by, ''), created_at, updated_at
	`

	var updated Schedule
	if err := DB.QueryRow(
		ctx,
		query,
		id,
		normalized.Name,
		normalized.Kind,
		normalized.TargetScope,
		normalized.TargetAgentID,
		normalized.TargetGroupID,
		normalized.CommandType,
		normalized.Payload,
		normalized.RunAt,
		normalized.RepeatIntervalSeconds,
		normalized.RecurrenceRule,
		normalized.Enabled,
		normalized.NextRunAt,
	).Scan(
		&updated.ID,
		&updated.Name,
		&updated.Kind,
		&updated.TargetScope,
		&updated.TargetAgentID,
		&updated.TargetGroupID,
		&updated.CommandType,
		&updated.Payload,
		&updated.RunAt,
		&updated.RepeatIntervalSeconds,
		&updated.RecurrenceRule,
		&updated.Enabled,
		&updated.LastRunAt,
		&updated.NextRunAt,
		&updated.CreatedBy,
		&updated.CreatedAt,
		&updated.UpdatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("schedule not found")
		}
		return nil, fmt.Errorf("failed to update schedule: %w", err)
	}

	return &updated, nil
}

func DeleteSchedule(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("id is required")
	}

	cmd, err := DB.Exec(ctx, `DELETE FROM schedules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete schedule: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("schedule not found")
	}

	return nil
}

func DispatchDueSchedules(ctx context.Context, now time.Time, limit int) (DispatchResult, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	tx, err := DB.Begin(ctx)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("failed to begin schedule dispatch transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	rows, err := tx.Query(ctx, `
		SELECT id, name, kind, target_scope, COALESCE(target_agent_id, ''), target_group_id,
			COALESCE(command_type, ''), payload, run_at, repeat_interval_seconds, COALESCE(recurrence_rule, ''),
			enabled, last_run_at, next_run_at, COALESCE(created_by, ''), created_at, updated_at
		FROM schedules
		WHERE enabled = true AND next_run_at <= $1
		ORDER BY next_run_at ASC, id ASC
		LIMIT $2
		FOR UPDATE SKIP LOCKED
	`, now, limit)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("failed to query due schedules: %w", err)
	}
	defer rows.Close()

	var due []Schedule
	for rows.Next() {
		var schedule Schedule
		if err := rows.Scan(
			&schedule.ID,
			&schedule.Name,
			&schedule.Kind,
			&schedule.TargetScope,
			&schedule.TargetAgentID,
			&schedule.TargetGroupID,
			&schedule.CommandType,
			&schedule.Payload,
			&schedule.RunAt,
			&schedule.RepeatIntervalSeconds,
			&schedule.RecurrenceRule,
			&schedule.Enabled,
			&schedule.LastRunAt,
			&schedule.NextRunAt,
			&schedule.CreatedBy,
			&schedule.CreatedAt,
			&schedule.UpdatedAt,
		); err != nil {
			return DispatchResult{}, fmt.Errorf("failed to scan due schedule: %w", err)
		}
		due = append(due, schedule)
	}

	if err := rows.Err(); err != nil {
		return DispatchResult{}, fmt.Errorf("failed to iterate due schedules: %w", err)
	}

	result := DispatchResult{}
	for _, schedule := range due {
		agentIDs, err := resolveScheduleTargetsTx(ctx, tx, schedule)
		if err != nil {
			return DispatchResult{}, fmt.Errorf("failed to resolve schedule targets for %d: %w", schedule.ID, err)
		}

		commandType, payload, err := buildDispatchCommand(schedule)
		if err != nil {
			return DispatchResult{}, fmt.Errorf("failed to build command for schedule %d: %w", schedule.ID, err)
		}

		for _, agentID := range agentIDs {
			if strings.TrimSpace(agentID) == "" {
				continue
			}
			if shouldDeduplicatePowerCommand(commandType) {
				exists, err := hasInFlightCommandTx(ctx, tx, agentID, commandType)
				if err != nil {
					return DispatchResult{}, fmt.Errorf("failed to check in-flight command for schedule %d and agent %s: %w", schedule.ID, agentID, err)
				}
				if exists {
					continue
				}
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO agent_commands (agent_id, schedule_id, command_type, payload, status)
				VALUES ($1, $2, $3, $4, 'queued')
			`, agentID, schedule.ID, commandType, payload); err != nil {
				return DispatchResult{}, fmt.Errorf("failed to create command for schedule %d and agent %s: %w", schedule.ID, agentID, err)
			}
			result.CommandsCreated++
		}

		nextRunAt, enabled, err := computeNextRunState(schedule, now)
		if err != nil {
			return DispatchResult{}, fmt.Errorf("failed to compute next run for schedule %d: %w", schedule.ID, err)
		}

		if _, err := tx.Exec(ctx, `
			UPDATE schedules
			SET last_run_at = $2,
				next_run_at = $3,
				enabled = $4,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = $1
		`, schedule.ID, now, nextRunAt, enabled); err != nil {
			return DispatchResult{}, fmt.Errorf("failed to update schedule state for %d: %w", schedule.ID, err)
		}

		result.SchedulesProcessed++
	}

	if err := tx.Commit(ctx); err != nil {
		return DispatchResult{}, fmt.Errorf("failed to commit schedule dispatch: %w", err)
	}

	return result, nil
}

func normalizeSchedule(schedule Schedule) (Schedule, error) {
	schedule.Name = strings.TrimSpace(schedule.Name)
	schedule.Kind = strings.ToLower(strings.TrimSpace(schedule.Kind))
	schedule.TargetScope = strings.ToLower(strings.TrimSpace(schedule.TargetScope))
	schedule.TargetAgentID = strings.TrimSpace(schedule.TargetAgentID)
	schedule.CommandType = strings.ToLower(strings.TrimSpace(schedule.CommandType))
	schedule.Payload = strings.TrimSpace(schedule.Payload)
	schedule.RecurrenceRule = strings.ToLower(strings.TrimSpace(schedule.RecurrenceRule))
	schedule.CreatedBy = strings.TrimSpace(schedule.CreatedBy)

	if schedule.Name == "" {
		return Schedule{}, fmt.Errorf("name is required")
	}

	switch schedule.Kind {
	case "command", "task", "script":
	default:
		return Schedule{}, fmt.Errorf("invalid kind")
	}

	switch schedule.TargetScope {
	case "agent", "group":
	default:
		return Schedule{}, fmt.Errorf("invalid target_scope")
	}

	if schedule.TargetScope == "agent" {
		if schedule.TargetAgentID == "" {
			return Schedule{}, fmt.Errorf("target_agent_id is required for agent scope")
		}
		schedule.TargetGroupID = nil
	} else {
		if schedule.TargetGroupID == nil || *schedule.TargetGroupID <= 0 {
			return Schedule{}, fmt.Errorf("target_group_id is required for group scope")
		}
		schedule.TargetAgentID = ""
	}

	if schedule.Payload == "" {
		return Schedule{}, fmt.Errorf("payload is required")
	}

	if schedule.RunAt.IsZero() {
		return Schedule{}, fmt.Errorf("run_at is required")
	}

	if schedule.RepeatIntervalSeconds < 0 {
		return Schedule{}, fmt.Errorf("repeat_interval_seconds must be >= 0")
	}

	if schedule.RecurrenceRule != "" {
		switch schedule.RecurrenceRule {
		case "weekly", "weekdays", "monthly", "first_day_of_month", "last_day_of_month", "first_weekday_of_month", "last_weekday_of_month":
		default:
			return Schedule{}, fmt.Errorf("invalid recurrence_rule")
		}
	}

	if schedule.RepeatIntervalSeconds > 0 && schedule.RecurrenceRule != "" {
		return Schedule{}, fmt.Errorf("repeat_interval_seconds and recurrence_rule are mutually exclusive")
	}
	if schedule.RecurrenceRule != "" {
		schedule.RepeatIntervalSeconds = 0
	}

	if schedule.NextRunAt.IsZero() {
		schedule.NextRunAt = schedule.RunAt
	}

	if schedule.Kind == "command" {
		if schedule.CommandType == "" {
			return Schedule{}, fmt.Errorf("command_type is required for kind=command")
		}
	}

	if schedule.Kind == "task" {
		schedule.CommandType = "ai_task"
	}

	if schedule.Kind == "script" && schedule.CommandType == "" {
		schedule.CommandType = "powershell"
	}

	return schedule, nil
}

func resolveScheduleTargetsTx(ctx context.Context, tx pgx.Tx, schedule Schedule) ([]string, error) {
	if schedule.TargetScope == "agent" {
		return []string{schedule.TargetAgentID}, nil
	}

	if schedule.TargetGroupID == nil || *schedule.TargetGroupID <= 0 {
		return nil, fmt.Errorf("invalid target_group_id")
	}

	rows, err := tx.Query(ctx, `
		SELECT agent_id
		FROM agent_group_members
		WHERE group_id = $1
		ORDER BY agent_id ASC
	`, *schedule.TargetGroupID)
	if err != nil {
		return nil, fmt.Errorf("failed to query group members: %w", err)
	}
	defer rows.Close()

	agentIDs := []string{}
	for rows.Next() {
		var agentID string
		if err := rows.Scan(&agentID); err != nil {
			return nil, fmt.Errorf("failed to scan group member: %w", err)
		}
		agentIDs = append(agentIDs, agentID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate group members: %w", err)
	}

	return agentIDs, nil
}

func buildDispatchCommand(schedule Schedule) (string, string, error) {
	commandType := strings.ToLower(strings.TrimSpace(schedule.CommandType))
	payload := strings.TrimSpace(schedule.Payload)

	if payload == "" {
		return "", "", fmt.Errorf("payload is required")
	}

	switch schedule.Kind {
	case "task":
		taskPayload, err := ensureAITaskPayload(schedule, payload)
		if err != nil {
			return "", "", err
		}
		return "ai_task", taskPayload, nil
	case "script", "patch", "command":
		if commandType == "" {
			return "", "", fmt.Errorf("command_type is required")
		}
		return commandType, payload, nil
	default:
		return "", "", fmt.Errorf("unsupported schedule kind")
	}
}

func shouldDeduplicatePowerCommand(commandType string) bool {
	commandType = strings.ToLower(strings.TrimSpace(commandType))
	switch commandType {
	case "restart", "shutdown":
		return true
	default:
		return false
	}
}

func hasInFlightCommandTx(ctx context.Context, tx pgx.Tx, agentID, commandType string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM agent_commands
			WHERE agent_id = $1
			  AND status IN ('queued', 'dispatched')
			  AND LOWER(command_type) = LOWER($2)
		)
	`, agentID, commandType).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to query in-flight commands: %w", err)
	}

	return exists, nil
}

func ensureAITaskPayload(schedule Schedule, payload string) (string, error) {
	if task, err := ai.ParseTaskPayload(payload); err == nil && task != nil {
		return payload, nil
	}

	title := strings.TrimSpace(schedule.Name)
	if title == "" {
		title = "Scheduled task"
	}

	task := ai.Task{
		TaskID:      fmt.Sprintf("schedule-%d-%d", schedule.ID, time.Now().Unix()),
		MotherRole:  ai.MotherScheduler,
		ChildIntent: ai.ChildWork,
		Title:       title,
		Instruction: strings.TrimSpace(payload),
		Context:     "scheduler",
	}

	if schedule.RunAt.IsZero() {
		now := time.Now().UTC()
		task.ScheduledAt = &now
	} else {
		runAt := schedule.RunAt.UTC()
		task.ScheduledAt = &runAt
	}

	body, err := json.Marshal(task)
	if err != nil {
		return "", fmt.Errorf("failed to serialize ai_task payload: %w", err)
	}

	return string(body), nil
}

func computeNextRunState(schedule Schedule, now time.Time) (time.Time, bool, error) {
	nextRunAt := schedule.NextRunAt
	enabled := schedule.Enabled

	if schedule.RecurrenceRule != "" {
		next, err := computeCalendarNextRun(schedule, now)
		if err != nil {
			return time.Time{}, false, err
		}
		return next, enabled, nil
	}

	if schedule.RepeatIntervalSeconds > 0 {
		interval := time.Duration(schedule.RepeatIntervalSeconds) * time.Second
		if nextRunAt.IsZero() {
			nextRunAt = now.Add(interval)
		} else {
			for !nextRunAt.After(now) {
				nextRunAt = nextRunAt.Add(interval)
			}
		}
		return nextRunAt, enabled, nil
	}

	enabled = false
	return now, enabled, nil
}

func computeCalendarNextRun(schedule Schedule, now time.Time) (time.Time, error) {
	anchor := schedule.RunAt
	if anchor.IsZero() {
		anchor = schedule.NextRunAt
	}
	if anchor.IsZero() {
		anchor = now
	}

	loc := anchor.Location()
	nowInLoc := now.In(loc)

	switch schedule.RecurrenceRule {
	case "weekly":
		return nextWeekly(anchor, nowInLoc), nil
	case "weekdays":
		return nextWeekday(anchor, nowInLoc), nil
	case "monthly":
		return nextMonthly(anchor, nowInLoc), nil
	case "first_day_of_month":
		return nextFirstDayOfMonth(anchor, nowInLoc), nil
	case "last_day_of_month":
		return nextLastDayOfMonth(anchor, nowInLoc), nil
	case "first_weekday_of_month":
		return nextFirstWeekdayOfMonth(anchor, nowInLoc), nil
	case "last_weekday_of_month":
		return nextLastWeekdayOfMonth(anchor, nowInLoc), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported recurrence_rule")
	}
}

func nextWeekly(anchor, now time.Time) time.Time {
	targetWeekday := anchor.Weekday()
	candidate := time.Date(now.Year(), now.Month(), now.Day(), anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), now.Location())
	for !candidate.After(now) || candidate.Weekday() != targetWeekday {
		candidate = candidate.AddDate(0, 0, 1)
	}
	return candidate
}

func nextWeekday(anchor, now time.Time) time.Time {
	candidate := time.Date(now.Year(), now.Month(), now.Day(), anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), now.Location())
	for !candidate.After(now) || candidate.Weekday() == time.Saturday || candidate.Weekday() == time.Sunday {
		candidate = candidate.AddDate(0, 0, 1)
	}
	return candidate
}

func nextMonthly(anchor, now time.Time) time.Time {
	day := anchor.Day()
	month := now.Month()
	year := now.Year()
	for {
		lastDay := daysInMonth(year, month)
		targetDay := day
		if targetDay > lastDay {
			targetDay = lastDay
		}
		candidate := time.Date(year, month, targetDay, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), now.Location())
		if candidate.After(now) {
			return candidate
		}
		month = month + 1
		if month > time.December {
			month = time.January
			year++
		}
	}
}

func nextFirstDayOfMonth(anchor, now time.Time) time.Time {
	month := now.Month()
	year := now.Year()
	for {
		candidate := time.Date(year, month, 1, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), now.Location())
		if candidate.After(now) {
			return candidate
		}
		month = month + 1
		if month > time.December {
			month = time.January
			year++
		}
	}
}

func nextLastDayOfMonth(anchor, now time.Time) time.Time {
	month := now.Month()
	year := now.Year()
	for {
		lastDay := daysInMonth(year, month)
		candidate := time.Date(year, month, lastDay, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), now.Location())
		if candidate.After(now) {
			return candidate
		}
		month = month + 1
		if month > time.December {
			month = time.January
			year++
		}
	}
}

func nextFirstWeekdayOfMonth(anchor, now time.Time) time.Time {
	month := now.Month()
	year := now.Year()
	for {
		day := 1
		candidate := time.Date(year, month, day, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), now.Location())
		for candidate.Weekday() == time.Saturday || candidate.Weekday() == time.Sunday {
			day++
			candidate = time.Date(year, month, day, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), now.Location())
		}
		if candidate.After(now) {
			return candidate
		}
		month = month + 1
		if month > time.December {
			month = time.January
			year++
		}
	}
}

func nextLastWeekdayOfMonth(anchor, now time.Time) time.Time {
	month := now.Month()
	year := now.Year()
	for {
		day := daysInMonth(year, month)
		candidate := time.Date(year, month, day, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), now.Location())
		for candidate.Weekday() == time.Saturday || candidate.Weekday() == time.Sunday {
			day--
			candidate = time.Date(year, month, day, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), now.Location())
		}
		if candidate.After(now) {
			return candidate
		}
		month = month + 1
		if month > time.December {
			month = time.January
			year++
		}
	}
}

func daysInMonth(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}
