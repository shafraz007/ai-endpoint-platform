package server

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type ScheduleExecutionReportFilter struct {
	From       time.Time
	To         time.Time
	ScheduleID *int64
	AgentID    string
	GroupID    *int
	Limit      int
}

type ScheduleExecutionReport struct {
	CommandID       int64
	ScheduleID      int64
	ScheduleName    string
	TargetScope     string
	TargetAgentID   string
	TargetGroupID   *int
	TargetGroupName string
	AgentID         string
	AgentHostname   string
	CommandType     string
	SchedulePayload string
	CommandPayload  string
	Status          string
	Output          string
	Error           string
	CreatedAt       time.Time
	CompletedAt     *time.Time
}

func ListScheduleExecutionReports(ctx context.Context, filter ScheduleExecutionReportFilter) ([]ScheduleExecutionReport, error) {
	if filter.From.IsZero() {
		filter.From = time.Now().UTC().Add(-24 * time.Hour)
	}
	if filter.To.IsZero() {
		filter.To = time.Now().UTC()
	}
	if filter.To.Before(filter.From) {
		return nil, fmt.Errorf("to must be greater than or equal to from")
	}
	if filter.Limit <= 0 {
		filter.Limit = 200
	}
	if filter.Limit > 2000 {
		filter.Limit = 2000
	}

	query := `
	SELECT
		ac.id,
		ac.schedule_id,
		s.name,
		s.target_scope,
		COALESCE(s.target_agent_id, ''),
		s.target_group_id,
		COALESCE(g.name, ''),
		ac.agent_id,
		COALESCE(a.hostname, ''),
		ac.command_type,
		COALESCE(s.payload, ''),
		COALESCE(ac.payload, ''),
		ac.status,
		COALESCE(ac.output, ''),
		COALESCE(ac.error, ''),
		ac.created_at,
		ac.completed_at
	FROM agent_commands ac
	INNER JOIN schedules s ON s.id = ac.schedule_id
	LEFT JOIN agent_groups g ON g.id = s.target_group_id
	LEFT JOIN agents a ON a.agent_id = ac.agent_id
	WHERE ac.schedule_id IS NOT NULL
	  AND ac.created_at >= $1
	  AND ac.created_at <= $2
	  AND ($3::BIGINT IS NULL OR ac.schedule_id = $3)
	  AND ($4::TEXT = '' OR ac.agent_id = $4)
	  AND ($5::INT IS NULL OR (s.target_scope = 'group' AND s.target_group_id = $5))
	ORDER BY ac.created_at DESC, ac.id DESC
	LIMIT $6
	`

	rows, err := DB.Query(
		ctx,
		query,
		filter.From.UTC(),
		filter.To.UTC(),
		filter.ScheduleID,
		strings.TrimSpace(filter.AgentID),
		filter.GroupID,
		filter.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query schedule execution reports: %w", err)
	}
	defer rows.Close()

	reports := make([]ScheduleExecutionReport, 0, 64)
	for rows.Next() {
		var item ScheduleExecutionReport
		var scheduleID *int64
		if err := rows.Scan(
			&item.CommandID,
			&scheduleID,
			&item.ScheduleName,
			&item.TargetScope,
			&item.TargetAgentID,
			&item.TargetGroupID,
			&item.TargetGroupName,
			&item.AgentID,
			&item.AgentHostname,
			&item.CommandType,
			&item.SchedulePayload,
			&item.CommandPayload,
			&item.Status,
			&item.Output,
			&item.Error,
			&item.CreatedAt,
			&item.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan schedule execution report row: %w", err)
		}
		if scheduleID != nil {
			item.ScheduleID = *scheduleID
		}
		reports = append(reports, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate schedule execution reports: %w", err)
	}

	return reports, nil
}
