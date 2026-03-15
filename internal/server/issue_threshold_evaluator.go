package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

type metricWindowAggregation struct {
	Count int
	Min   float64
	Max   float64
	Avg   float64
}

type driveUsageSnapshot struct {
	DeviceID    string  `json:"DeviceID"`
	PercentUsed float64 `json:"PercentUsed"`
	Used        float64 `json:"Used"`
	Free        float64 `json:"Free"`
	Size        float64 `json:"Size"`
}

func evaluateHeartbeatThresholdIssues(ctx context.Context, hb transport.HeartbeatRequest) error {
	profile, err := GetActiveIssueThresholdProfile(ctx)
	if err != nil || profile == nil {
		return err
	}

	agentID := strings.TrimSpace(hb.AgentID)
	if agentID == "" {
		return nil
	}

	for _, rule := range profile.Rules {
		if !rule.Enabled || rule.Source != "heartbeat" {
			continue
		}
		triggered, evidence, supported, evalErr := evaluateHeartbeatRule(rule, hb)
		if evalErr != nil {
			return evalErr
		}
		if !supported {
			continue
		}
		if err := applyThresholdRuleIssue(ctx, agentID, rule, triggered, evidence); err != nil {
			return err
		}
	}

	return nil
}

func evaluateMetricThresholdIssues(ctx context.Context, sample MetricSample) error {
	profile, err := GetActiveIssueThresholdProfile(ctx)
	if err != nil || profile == nil {
		return err
	}

	agentID := strings.TrimSpace(sample.AgentID)
	if agentID == "" {
		return nil
	}

	for _, rule := range profile.Rules {
		if !rule.Enabled || rule.Source != "metrics" {
			continue
		}

		agg, supported, evalErr := queryMetricWindowAggregation(ctx, agentID, rule)
		if evalErr != nil {
			return evalErr
		}
		if !supported {
			continue
		}

		triggered := compareThreshold(rule.Comparator, agg, rule.ThresholdValue)
		evidence := fmt.Sprintf(
			`{"signal":%q,"window_minutes":%d,"threshold":%.2f,"comparator":%q,"count":%d,"min":%.2f,"max":%.2f,"avg":%.2f}`,
			rule.Signal,
			rule.DurationMin,
			rule.ThresholdValue,
			rule.Comparator,
			agg.Count,
			agg.Min,
			agg.Max,
			agg.Avg,
		)
		if err := applyThresholdRuleIssue(ctx, agentID, rule, triggered, evidence); err != nil {
			return err
		}
	}

	return nil
}

func evaluateHeartbeatRule(rule IssueThresholdRule, hb transport.HeartbeatRequest) (bool, string, bool, error) {
	switch rule.Signal {
	case "disk_usage_percent":
		drives := make([]driveUsageSnapshot, 0)
		if strings.TrimSpace(hb.Drives) == "" {
			return false, "", false, nil
		}
		if err := json.Unmarshal([]byte(hb.Drives), &drives); err != nil {
			return false, "", false, nil
		}
		if len(drives) == 0 {
			return false, "", false, nil
		}

		maxUsage := -1.0
		maxDevice := ""
		for _, item := range drives {
			if item.PercentUsed > maxUsage {
				maxUsage = item.PercentUsed
				maxDevice = strings.TrimSpace(item.DeviceID)
			}
		}
		if maxUsage < 0 {
			return false, "", false, nil
		}

		triggered := compareSingleValue(rule.Comparator, maxUsage, rule.ThresholdValue)
		evidence := fmt.Sprintf(
			`{"signal":%q,"threshold":%.2f,"comparator":%q,"max_usage_percent":%.2f,"device_id":%q}`,
			rule.Signal,
			rule.ThresholdValue,
			rule.Comparator,
			maxUsage,
			maxDevice,
		)
		return triggered, evidence, true, nil
	default:
		return false, "", false, nil
	}
}

func queryMetricWindowAggregation(ctx context.Context, agentID string, rule IssueThresholdRule) (metricWindowAggregation, bool, error) {
	column, ok := metricSignalColumn(rule.Signal)
	if !ok {
		return metricWindowAggregation{}, false, nil
	}

	windowMinutes := rule.DurationMin
	if windowMinutes <= 0 {
		windowMinutes = 1
	}
	windowStart := time.Now().Add(-time.Duration(windowMinutes) * time.Minute)

	query := fmt.Sprintf(`
		SELECT
			COUNT(%s),
			COALESCE(MIN(%s), 0),
			COALESCE(MAX(%s), 0),
			COALESCE(AVG(%s), 0)
		FROM agent_metrics
		WHERE agent_id = $1 AND timestamp >= $2 AND %s IS NOT NULL
	`, column, column, column, column, column)

	var agg metricWindowAggregation
	if err := DB.QueryRow(ctx, query, agentID, windowStart).Scan(&agg.Count, &agg.Min, &agg.Max, &agg.Avg); err != nil {
		return metricWindowAggregation{}, false, fmt.Errorf("failed to aggregate metric signal %s: %w", rule.Signal, err)
	}

	if agg.Count == 0 {
		return metricWindowAggregation{}, false, nil
	}

	return agg, true, nil
}

func metricSignalColumn(signal string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(signal)) {
	case "memory_used_percent":
		return "memory_used_percent", true
	case "cpu_percent", "cpu_load_percent":
		return "cpu_percent", true
	case "cpu_temperature_c":
		return "cpu_temperature_c", true
	case "disk_temperature_c":
		return "disk_temperature_c", true
	case "disk_usage_percent":
		return "disk_usage_percent", true
	case "fan_cpu_rpm":
		return "fan_cpu_rpm", true
	case "fan_system_rpm":
		return "fan_system_rpm", true
	default:
		return "", false
	}
}

func compareThreshold(comparator string, agg metricWindowAggregation, threshold float64) bool {
	switch strings.ToLower(strings.TrimSpace(comparator)) {
	case "gt":
		return agg.Min > threshold
	case "gte":
		return agg.Min >= threshold
	case "lt":
		return agg.Max < threshold
	case "lte":
		return agg.Max <= threshold
	default:
		return false
	}
}

func compareSingleValue(comparator string, value, threshold float64) bool {
	switch strings.ToLower(strings.TrimSpace(comparator)) {
	case "gt":
		return value > threshold
	case "gte":
		return value >= threshold
	case "lt":
		return value < threshold
	case "lte":
		return value <= threshold
	default:
		return false
	}
}

func applyThresholdRuleIssue(ctx context.Context, agentID string, rule IssueThresholdRule, triggered bool, evidence string) error {
	if !triggered {
		return ResolveAgentIssue(ctx, agentID, rule.IssueKey)
	}

	severity := strings.ToLower(strings.TrimSpace(rule.Severity))
	if severity == "warning" {
		severity = "medium"
	}

	suggestions := []string{
		"Validate current workload and confirm the threshold breach trend.",
		"Run targeted diagnostics and remediate root cause safely.",
	}
	if strings.HasPrefix(strings.ToLower(rule.Signal), "fan_") {
		suggestions = []string{
			"Inspect fan health, dust levels, and cooling airflow.",
			"Review thermal policies and hardware monitoring telemetry.",
		}
	}
	if strings.Contains(strings.ToLower(rule.Signal), "temperature") {
		suggestions = []string{
			"Validate thermal sensor readings and ambient conditions.",
			"Reduce workload and inspect cooling path before escalation.",
		}
	}

	actions := []IssueRecommendedAction{
		{
			ID:               "threshold-health-task",
			Label:            "Create threshold remediation task",
			Description:      "Generate AI-guided remediation checklist",
			Kind:             "task",
			Payload:          buildIssueAITaskPayload(rule.Title, "Analyze this threshold breach and provide immediate containment + durable remediation steps with validation."),
			SupportsSchedule: true,
		},
	}

	if strings.Contains(strings.ToLower(rule.Signal), "cpu") || strings.Contains(strings.ToLower(rule.Signal), "memory") {
		actions = append(actions, IssueRecommendedAction{
			ID:               "threshold-process-snapshot",
			Label:            "Run process snapshot",
			Description:      "Collect top process resource usage",
			Kind:             "command",
			CommandType:      "powershell",
			Payload:          "Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name,Id,CPU,WS,PM | Format-Table -AutoSize",
			SupportsSchedule: true,
		})
	}

	_, err := UpsertAgentIssue(ctx, AgentIssueUpsertInput{
		AgentID:     agentID,
		IssueKey:    rule.IssueKey,
		Category:    rule.Category,
		Severity:    severity,
		Title:       rule.Title,
		Description: rule.Description,
		Source:      "threshold_profile",
		Evidence:    evidence,
		Suggestions: suggestions,
		ActionPlan: []string{
			"Validate breach persistence against the configured threshold window.",
			"Execute remediation actions and observe recovery trend.",
			"Document root cause and adjust policy/profile if required.",
		},
		RecommendedActions: actions,
		ObservedAt:         time.Now().UTC(),
	})
	if err != nil {
		return err
	}

	if rule.IssueKey == "hw-disk-temp-critical" {
		_ = ResolveAgentIssue(ctx, agentID, "hw-disk-temp-warning")
	}

	return nil
}
