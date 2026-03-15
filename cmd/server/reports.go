package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/ai"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
)

type scheduleExecutionReportResponse struct {
	CommandID       int64      `json:"command_id"`
	ScheduleID      int64      `json:"schedule_id"`
	ScheduleName    string     `json:"schedule_name"`
	TargetScope     string     `json:"target_scope"`
	TargetAgentID   string     `json:"target_agent_id,omitempty"`
	TargetGroupID   *int       `json:"target_group_id,omitempty"`
	TargetGroupName string     `json:"target_group_name,omitempty"`
	AgentID         string     `json:"agent_id"`
	AgentHostname   string     `json:"agent_hostname,omitempty"`
	CommandType     string     `json:"command_type"`
	SchedulePayload string     `json:"schedule_payload"`
	CommandPayload  string     `json:"command_payload"`
	Status          string     `json:"status"`
	Result          string     `json:"result"`
	Output          string     `json:"output,omitempty"`
	Error           string     `json:"error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
}

func reportsPageHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := requireAdminPage(w, r, cfg, false); !ok {
			return
		}
		if reportsTemplate == nil {
			http.Error(w, "Template not loaded", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = reportsTemplate.Execute(w, map[string]interface{}{
			"Now": time.Now().Format("2006-01-02 15:04:05"),
		})
	}
}

func scheduleExecutionReportsHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		filter, err := parseScheduleExecutionReportFilter(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		reports, err := server.ListScheduleExecutionReports(r.Context(), filter)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := make([]scheduleExecutionReportResponse, 0, len(reports))
		for _, item := range reports {
			result := strings.ToLower(strings.TrimSpace(item.Status))
			if result == "" {
				result = "unknown"
			}
			displayOutput := formatReportOutput(item.CommandType, item.Output)
			resp = append(resp, scheduleExecutionReportResponse{
				CommandID:       item.CommandID,
				ScheduleID:      item.ScheduleID,
				ScheduleName:    item.ScheduleName,
				TargetScope:     item.TargetScope,
				TargetAgentID:   item.TargetAgentID,
				TargetGroupID:   item.TargetGroupID,
				TargetGroupName: item.TargetGroupName,
				AgentID:         item.AgentID,
				AgentHostname:   item.AgentHostname,
				CommandType:     item.CommandType,
				SchedulePayload: item.SchedulePayload,
				CommandPayload:  item.CommandPayload,
				Status:          item.Status,
				Result:          result,
				Output:          displayOutput,
				Error:           item.Error,
				CreatedAt:       item.CreatedAt,
				CompletedAt:     item.CompletedAt,
			})
		}

		respondJSON(w, http.StatusOK, resp)
	}
}

func parseScheduleExecutionReportFilter(r *http.Request) (server.ScheduleExecutionReportFilter, error) {
	q := r.URL.Query()
	var filter server.ScheduleExecutionReportFilter
	filter.AgentID = strings.TrimSpace(q.Get("agent_id"))

	limit := 300
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return filter, fmt.Errorf("invalid limit")
		}
		limit = parsed
	}
	filter.Limit = limit

	from, err := parseDateTimeQuery(q.Get("from"))
	if err != nil {
		return filter, fmt.Errorf("invalid from")
	}
	to, err := parseDateTimeQuery(q.Get("to"))
	if err != nil {
		return filter, fmt.Errorf("invalid to")
	}

	if from.IsZero() {
		from = time.Now().UTC().Add(-24 * time.Hour)
	}
	if to.IsZero() {
		to = time.Now().UTC()
	}
	filter.From = from
	filter.To = to

	if raw := strings.TrimSpace(q.Get("schedule_id")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			return filter, fmt.Errorf("invalid schedule_id")
		}
		filter.ScheduleID = &parsed
	}

	if raw := strings.TrimSpace(q.Get("group_id")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return filter, fmt.Errorf("invalid group_id")
		}
		filter.GroupID = &parsed
	}

	return filter, nil
}

func parseDateTimeQuery(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			if layout == "2006-01-02" {
				return time.Date(parsed.Year(), parsed.Month(), parsed.Day(), 0, 0, 0, 0, time.UTC), nil
			}
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid datetime")
}

func formatReportOutput(commandType, output string) string {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return ""
	}

	if strings.ToLower(strings.TrimSpace(commandType)) != "ai_task" {
		return trimmed
	}

	var childResult ai.ChildResult
	if err := json.Unmarshal([]byte(trimmed), &childResult); err != nil {
		return trimmed
	}

	summary := strings.TrimSpace(childResult.Summary)
	details := strings.TrimSpace(childResult.Details)
	switch {
	case summary != "" && details != "":
		return summary + "\n" + details
	case summary != "":
		return summary
	case details != "":
		return details
	default:
		return trimmed
	}
}
