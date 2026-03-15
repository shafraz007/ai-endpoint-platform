package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
)

type chatToolDefinition struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	InputSchema string   `json:"input_schema"`
	Methods     []string `json:"methods,omitempty"`
}

type chatToolExecuteRequest struct {
	Tool      string                 `json:"tool"`
	Arguments map[string]interface{} `json:"arguments"`
}

type chatToolExecuteResponse struct {
	OK         bool        `json:"ok"`
	Tool       string      `json:"tool"`
	Result     interface{} `json:"result,omitempty"`
	Error      string      `json:"error,omitempty"`
	DurationMS int64       `json:"duration_ms"`
}

func chatToolsHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _, err := authorizeAdminRequest(w, r, cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(listChatTools())
		case http.MethodPost:
			var req chatToolExecuteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), 95*time.Second)
			defer cancel()

			started := time.Now()
			result, execErr := executeChatTool(ctx, cfg, strings.TrimSpace(r.Header.Get("Authorization")), strings.TrimSpace(r.Header.Get("Cookie")), req)
			resp := chatToolExecuteResponse{
				OK:         execErr == nil,
				Tool:       req.Tool,
				DurationMS: time.Since(started).Milliseconds(),
			}
			if execErr != nil {
				resp.Error = execErr.Error()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			resp.Result = result
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func listChatTools() []chatToolDefinition {
	return []chatToolDefinition{
		{
			Name:        "fleet_health",
			Description: "Summarize fleet status including online/offline counts and top active issues.",
			InputSchema: `{}`,
			Methods:     []string{"POST"},
		},
		{
			Name:        "resolve_issue",
			Description: "Resolve an issue by issue id.",
			InputSchema: `{"issue_id":123}`,
			Methods:     []string{"POST"},
		},
		{
			Name:        "set_patch_policy",
			Description: "Update OS patch policy with partial fields (enabled, approval, schedule, KB lists).",
			InputSchema: `{"enabled":true,"kb_approval_mode":"manual","auto_approval_after_days":7}`,
			Methods:     []string{"POST"},
		},
		{
			Name:        "db_query",
			Description: "Run a read-only SQL SELECT query against the platform database.",
			InputSchema: `{"sql":"SELECT ...","limit":50}`,
			Methods:     []string{"POST"},
		},
		{
			Name:        "web_fetch",
			Description: "Fetch public web content by URL (http/https) and return plain text excerpt.",
			InputSchema: `{"url":"https://...","max_chars":4000}`,
			Methods:     []string{"POST"},
		},
		{
			Name:        "server_api",
			Description: "Call allowed local admin APIs to read/update server actions/settings.",
			InputSchema: `{"method":"GET|POST|PUT|PATCH","path":"/api/...","body":{}}`,
			Methods:     []string{"POST"},
		},
	}
}

func executeChatTool(ctx context.Context, cfg config.ServerConfig, authHeader, cookieHeader string, req chatToolExecuteRequest) (interface{}, error) {
	tool := strings.ToLower(strings.TrimSpace(req.Tool))
	switch tool {
	case "fleet_health":
		return executeFleetHealthTool(ctx)
	case "resolve_issue":
		return executeResolveIssueTool(ctx, req.Arguments)
	case "set_patch_policy":
		return executeSetPatchPolicyTool(ctx, req.Arguments)
	case "db_query":
		return executeDBQueryTool(ctx, req.Arguments)
	case "web_fetch":
		return executeWebFetchTool(ctx, req.Arguments)
	case "server_api":
		return executeServerAPITool(ctx, cfg, authHeader, cookieHeader, req.Arguments)
	default:
		return nil, fmt.Errorf("unsupported tool: %s", req.Tool)
	}
}

func executeFleetHealthTool(ctx context.Context) (interface{}, error) {
	snapshot, err := collectGlobalFleetSnapshot(ctx)
	if err != nil {
		return nil, err
	}

	issues, err := server.ListAgentIssues(ctx, server.IssueFilter{Status: "active", Limit: 8})
	if err != nil {
		return nil, err
	}

	topIssues := make([]map[string]interface{}, 0, len(issues))
	for _, item := range issues {
		topIssues = append(topIssues, map[string]interface{}{
			"id":        item.ID,
			"agent_id":  item.AgentID,
			"issue_key": item.IssueKey,
			"severity":  item.Severity,
			"status":    item.Status,
			"title":     item.Title,
		})
	}

	return map[string]interface{}{
		"snapshot": map[string]interface{}{
			"total":    snapshot.Total,
			"online":   snapshot.Online,
			"offline":  snapshot.Offline,
			"active":   snapshot.Active,
			"critical": snapshot.Critical,
			"high":     snapshot.High,
			"medium":   snapshot.Medium,
			"low":      snapshot.Low,
		},
		"top_active_issues": topIssues,
	}, nil
}

func executeResolveIssueTool(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	issueID := int64(intArg(args, "issue_id", 0))
	if issueID <= 0 {
		return nil, fmt.Errorf("issue_id must be greater than zero")
	}

	if err := server.ResolveAgentIssueByID(ctx, issueID); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"issue_id": issueID,
		"status":   "resolved",
	}, nil
}

func executeSetPatchPolicyTool(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	policy, err := server.GetOSPatchPolicy(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			agents, listErr := server.GetAllAgents(ctx)
			if listErr != nil || len(agents) == 0 {
				return nil, fmt.Errorf("no existing patch policy and no agents available to infer defaults")
			}
			policy = &server.OSPatchPolicy{
				Enabled:             true,
				TargetScope:         "agent",
				TargetAgentID:       strings.TrimSpace(agents[0].AgentID),
				KBApprovalMode:      "manual",
				AutoApprovalAfter:   7,
				PostponeDays:        0,
				AutoScheduleEnabled: true,
				AutoScheduleRule:    "weekdays",
				ScheduleStartAt:     time.Now().UTC().Add(10 * time.Minute),
				ApprovedKBs:         []string{},
				PostponedKBs:        []string{},
			}
		} else {
			return nil, err
		}
	}

	updated := *policy
	if raw, ok := args["enabled"]; ok {
		if value, parseErr := boolArg(raw); parseErr == nil {
			updated.Enabled = value
		} else {
			return nil, parseErr
		}
	}
	if value := strings.TrimSpace(stringArg(args, "target_scope")); value != "" {
		updated.TargetScope = value
	}
	if value := strings.TrimSpace(stringArg(args, "target_agent_id")); value != "" {
		updated.TargetAgentID = value
	}
	if raw, ok := args["target_group_id"]; ok {
		groupID := intArg(map[string]interface{}{"v": raw}, "v", 0)
		if groupID > 0 {
			updated.TargetGroupID = &groupID
		}
	}
	if value := strings.TrimSpace(stringArg(args, "kb_approval_mode")); value != "" {
		updated.KBApprovalMode = value
	}
	if raw, ok := args["auto_approval_after_days"]; ok {
		updated.AutoApprovalAfter = intArg(map[string]interface{}{"v": raw}, "v", updated.AutoApprovalAfter)
	}
	if raw, ok := args["postpone_days"]; ok {
		updated.PostponeDays = intArg(map[string]interface{}{"v": raw}, "v", updated.PostponeDays)
	}
	if raw, ok := args["auto_schedule_enabled"]; ok {
		if value, parseErr := boolArg(raw); parseErr == nil {
			updated.AutoScheduleEnabled = value
		} else {
			return nil, parseErr
		}
	}
	if value := strings.TrimSpace(stringArg(args, "auto_schedule_rule")); value != "" {
		updated.AutoScheduleRule = value
	}
	if value := strings.TrimSpace(stringArg(args, "schedule_start_at")); value != "" {
		parsed, parseErr := time.Parse(time.RFC3339, value)
		if parseErr != nil {
			return nil, fmt.Errorf("schedule_start_at must be RFC3339")
		}
		updated.ScheduleStartAt = parsed
	}
	if values, parseErr := stringSliceArg(args, "approved_kbs"); parseErr == nil && values != nil {
		updated.ApprovedKBs = values
	} else if parseErr != nil {
		return nil, parseErr
	}
	if values, parseErr := stringSliceArg(args, "postponed_kbs"); parseErr == nil && values != nil {
		updated.PostponedKBs = values
	} else if parseErr != nil {
		return nil, parseErr
	}

	saved, err := server.UpsertOSPatchPolicy(ctx, updated, "chat-tools")
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"id":                       saved.ID,
		"enabled":                  saved.Enabled,
		"target_scope":             saved.TargetScope,
		"target_agent_id":          saved.TargetAgentID,
		"target_group_id":          saved.TargetGroupID,
		"kb_approval_mode":         saved.KBApprovalMode,
		"auto_approval_after_days": saved.AutoApprovalAfter,
		"postpone_days":            saved.PostponeDays,
		"auto_schedule_enabled":    saved.AutoScheduleEnabled,
		"auto_schedule_rule":       saved.AutoScheduleRule,
		"schedule_start_at":        saved.ScheduleStartAt,
		"approved_kbs":             saved.ApprovedKBs,
		"postponed_kbs":            saved.PostponedKBs,
	}, nil
}

func executeDBQueryTool(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	sqlText := strings.TrimSpace(stringArg(args, "sql"))
	if sqlText == "" {
		return nil, fmt.Errorf("sql is required")
	}

	if err := validateReadOnlySQL(sqlText); err != nil {
		return nil, err
	}

	limit := intArg(args, "limit", 50)
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	rows, err := server.DB.Query(ctx, sqlText)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns := rows.FieldDescriptions()
	colNames := make([]string, 0, len(columns))
	for _, col := range columns {
		colNames = append(colNames, string(col.Name))
	}

	items := make([]map[string]interface{}, 0, limit)
	for rows.Next() {
		values, scanErr := rows.Values()
		if scanErr != nil {
			return nil, scanErr
		}
		rowMap := make(map[string]interface{}, len(colNames))
		for i := range colNames {
			if i < len(values) {
				rowMap[colNames[i]] = normalizeSQLValue(values[i])
			}
		}
		items = append(items, rowMap)
		if len(items) >= limit {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"columns": colNames,
		"rows":    items,
		"count":   len(items),
	}, nil
}

func validateReadOnlySQL(sqlText string) error {
	normalized := strings.ToLower(strings.TrimSpace(sqlText))
	if normalized == "" {
		return fmt.Errorf("sql is required")
	}
	if strings.Contains(normalized, ";") {
		return fmt.Errorf("multiple statements are not allowed")
	}
	if !strings.HasPrefix(normalized, "select") && !strings.HasPrefix(normalized, "with") {
		return fmt.Errorf("only read-only SELECT/WITH queries are allowed")
	}
	blocked := []string{" insert ", " update ", " delete ", " drop ", " alter ", " create ", " truncate ", " grant ", " revoke ", " call ", " execute ", " do "}
	check := " " + normalized + " "
	for _, term := range blocked {
		if strings.Contains(check, term) {
			return fmt.Errorf("query contains blocked term: %s", strings.TrimSpace(term))
		}
	}
	return nil
}

func normalizeSQLValue(value interface{}) interface{} {
	switch v := value.(type) {
	case []byte:
		return string(v)
	default:
		return v
	}
}

func executeWebFetchTool(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	urlValue := strings.TrimSpace(stringArg(args, "url"))
	if urlValue == "" {
		return nil, fmt.Errorf("url is required")
	}
	lowerURL := strings.ToLower(urlValue)
	if !strings.HasPrefix(lowerURL, "http://") && !strings.HasPrefix(lowerURL, "https://") {
		return nil, fmt.Errorf("url must start with http:// or https://")
	}

	maxChars := intArg(args, "max_chars", 4000)
	if maxChars <= 0 {
		maxChars = 4000
	}
	if maxChars > 20000 {
		maxChars = 20000
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlValue, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ai-endpoint-platform-chat-tools/1.0")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	text := string(bodyBytes)
	if strings.Contains(contentType, "text/html") || strings.Contains(text, "<html") {
		text = stripHTML(text)
	}
	text = strings.TrimSpace(text)
	if len(text) > maxChars {
		text = strings.TrimSpace(text[:maxChars])
	}

	return map[string]interface{}{
		"url":          urlValue,
		"status":       resp.StatusCode,
		"content_type": contentType,
		"content":      text,
	}, nil
}

var htmlTagRE = regexp.MustCompile(`(?s)<[^>]*>`)

func stripHTML(input string) string {
	withoutTags := htmlTagRE.ReplaceAllString(input, " ")
	withoutTags = strings.ReplaceAll(withoutTags, "\n", " ")
	withoutTags = strings.ReplaceAll(withoutTags, "\r", " ")
	return strings.Join(strings.Fields(withoutTags), " ")
}

func executeServerAPITool(ctx context.Context, cfg config.ServerConfig, authHeader, cookieHeader string, args map[string]interface{}) (interface{}, error) {
	method := strings.ToUpper(strings.TrimSpace(stringArg(args, "method")))
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return nil, fmt.Errorf("unsupported method: %s", method)
	}

	path := strings.TrimSpace(stringArg(args, "path"))
	if path == "" || !strings.HasPrefix(path, "/api/") {
		return nil, fmt.Errorf("path must start with /api/")
	}
	if strings.HasPrefix(path, "/api/chat/tools") {
		return nil, fmt.Errorf("recursive chat tools path is blocked")
	}
	if !isAllowedServerAPIToolPath(path) {
		return nil, fmt.Errorf("path is not allowed for server_api tool")
	}

	var body io.Reader
	if rawBody, exists := args["body"]; exists {
		encoded, err := json.Marshal(rawBody)
		if err != nil {
			return nil, fmt.Errorf("invalid body: %w", err)
		}
		body = bytes.NewBuffer(encoded)
	}

	baseURL := "http://127.0.0.1:" + strings.TrimSpace(cfg.Port)
	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}

	respText := strings.TrimSpace(string(respBytes))
	if len(respText) > 20000 {
		respText = respText[:20000]
	}

	return map[string]interface{}{
		"status": resp.StatusCode,
		"path":   path,
		"method": method,
		"body":   respText,
	}, nil
}

func isAllowedServerAPIToolPath(path string) bool {
	allowedPrefixes := []string{
		"/api/issues",
		"/api/schedules",
		"/api/os-patch/policy",
		"/api/os-patch/updates",
		"/api/categories",
		"/api/policies",
		"/api/profiles",
		"/api/groups",
		"/api/threshold-profiles",
		"/api/reports/executions",
		"/api/agents",
	}
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func stringArg(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	value, ok := args[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func intArg(args map[string]interface{}, key string, defaultValue int) int {
	if args == nil {
		return defaultValue
	}
	value, ok := args[key]
	if !ok || value == nil {
		return defaultValue
	}
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			return defaultValue
		}
		return int(i)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return defaultValue
		}
		return parsed
	default:
		return defaultValue
	}
}

func boolArg(value interface{}) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		normalized := strings.ToLower(strings.TrimSpace(v))
		switch normalized {
		case "true", "1", "yes", "on":
			return true, nil
		case "false", "0", "no", "off":
			return false, nil
		default:
			return false, fmt.Errorf("invalid boolean value: %s", v)
		}
	default:
		return false, fmt.Errorf("invalid boolean value type")
	}
}

func stringSliceArg(args map[string]interface{}, key string) ([]string, error) {
	if args == nil {
		return nil, nil
	}
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array of strings", key)
	}
	result := make([]string, 0, len(list))
	for _, item := range list {
		value, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s must contain only strings", key)
		}
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	return result, nil
}
