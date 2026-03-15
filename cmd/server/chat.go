package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/shafraz007/ai-endpoint-platform/internal/ai"
	"github.com/shafraz007/ai-endpoint-platform/internal/auth"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/queue"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

const (
	personalChatContextFetchLimit    = 60
	personalChatRecentTurns          = 10
	personalChatSummaryLineLimit     = 8
	personalChatInstructionMaxChars  = 4000
	globalChatLearningWindow         = 60
	globalSessionTitleMinUserTurns   = 3
	globalSessionMemoryMinTurns      = 3
	globalSessionSummaryEveryTurns   = 4
	globalSessionSummaryMaxChars     = 1800
	globalWorkflowMinTimeout         = 12 * time.Second
	globalDetachedWriteTimeout       = 5 * time.Second
	personalChatShadowPublishTimeout = 1500 * time.Millisecond
)

type globalWorkflowTraceKey string

const globalWorkflowTraceIDKey globalWorkflowTraceKey = "global_workflow_trace_id"

func withGlobalWorkflowTraceID(ctx context.Context, sessionID int64) context.Context {
	traceID := fmt.Sprintf("gwf-%d-%d", sessionID, time.Now().UnixNano())
	return context.WithValue(ctx, globalWorkflowTraceIDKey, traceID)
}

func getGlobalWorkflowTraceID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if value := ctx.Value(globalWorkflowTraceIDKey); value != nil {
		if traceID, ok := value.(string); ok {
			return strings.TrimSpace(traceID)
		}
	}
	return ""
}

func chatMessagesHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleChatList(w, r, cfg)
		case http.MethodPost:
			handleChatCreate(w, r, cfg)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func chatSessionsHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, user, err := authorizeAdminRequest(w, r, cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodGet:
			limit := 50
			if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
				if parsed, parseErr := strconv.Atoi(raw); parseErr == nil {
					limit = parsed
				}
			}

			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()

			sessions, err := server.ListGlobalChatSessions(ctx, limit)
			if err != nil {
				http.Error(w, "Failed to list chat sessions", http.StatusInternalServerError)
				return
			}

			if len(sessions) == 0 {
				created, createErr := server.CreateGlobalChatSession(ctx, user.Username, "New Chat")
				if createErr == nil && created != nil {
					sessions = append(sessions, *created)
				}
			}

			response := make([]transport.GlobalChatSession, 0, len(sessions))
			for _, item := range sessions {
				response = append(response, transport.GlobalChatSession{
					ID:            item.ID,
					Title:         item.Title,
					CreatedBy:     item.CreatedBy,
					CreatedAt:     item.CreatedAt,
					UpdatedAt:     item.UpdatedAt,
					LastMessageAt: item.LastMessageAt,
					MessageCount:  item.MessageCount,
				})
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		case http.MethodPost:
			var req transport.GlobalChatSessionCreateRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()

			title := strings.TrimSpace(req.Title)
			if title == "" {
				title = "New Chat"
			}

			created, err := server.CreateGlobalChatSession(ctx, user.Username, title)
			if err != nil {
				http.Error(w, "Failed to create chat session", http.StatusInternalServerError)
				return
			}

			resp := transport.GlobalChatSession{
				ID:           created.ID,
				Title:        created.Title,
				CreatedBy:    created.CreatedBy,
				CreatedAt:    created.CreatedAt,
				UpdatedAt:    created.UpdatedAt,
				MessageCount: created.MessageCount,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func parseChatSessionID(r *http.Request) int64 {
	raw := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if raw == "" {
		return 0
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

func chatStreamHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		scope := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope")))
		agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
		sessionID := parseChatSessionID(r)
		if scope == "" {
			scope = server.ChatScopeGlobal
		}

		afterID := int64(0)
		if raw := strings.TrimSpace(r.URL.Query().Get("since_id")); raw != "" {
			if parsed, parseErr := strconv.ParseInt(raw, 10, 64); parseErr == nil && parsed > 0 {
				afterID = parsed
			}
		}

		if scope != server.ChatScopeGlobal && scope != server.ChatScopeAgent {
			http.Error(w, "invalid scope", http.StatusBadRequest)
			return
		}
		if scope == server.ChatScopeAgent && agentID == "" {
			http.Error(w, "agent_id is required for agent scope", http.StatusBadRequest)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		_, _ = fmt.Fprintf(w, "retry: 2000\n\n")
		flusher.Flush()

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				queryCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
				messages, err := server.ListChatMessagesAfterIDWithSession(queryCtx, scope, agentID, sessionID, afterID, 100)
				cancel()
				if err != nil {
					_, _ = fmt.Fprintf(w, ": stream_error %s\n\n", strings.ReplaceAll(err.Error(), "\n", " "))
					flusher.Flush()
					continue
				}

				if len(messages) == 0 {
					_, _ = fmt.Fprint(w, ": keepalive\n\n")
					flusher.Flush()
					continue
				}

				for _, item := range messages {
					payload, err := json.Marshal(transport.ChatMessage{
						ID:        item.ID,
						Scope:     item.Scope,
						AgentID:   item.AgentID,
						SessionID: item.SessionID,
						Sender:    item.Sender,
						Message:   item.Message,
						CreatedAt: item.CreatedAt,
					})
					if err != nil {
						continue
					}

					_, _ = fmt.Fprintf(w, "id: %d\nevent: message\ndata: %s\n\n", item.ID, payload)
					if item.ID > afterID {
						afterID = item.ID
					}
				}

				flusher.Flush()
			}
		}
	}
}

func handleChatList(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	_, _, err := authorizeAdminRequest(w, r, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	scope := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope")))
	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
	sessionID := parseChatSessionID(r)
	if scope == "" {
		scope = server.ChatScopeGlobal
	}

	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, parseErr := strconv.Atoi(raw); parseErr == nil {
			limit = parsed
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	messages, err := server.ListChatMessagesWithSession(ctx, scope, agentID, sessionID, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := make([]transport.ChatMessage, 0, len(messages))
	for _, item := range messages {
		response = append(response, transport.ChatMessage{
			ID:        item.ID,
			Scope:     item.Scope,
			AgentID:   item.AgentID,
			SessionID: item.SessionID,
			Sender:    item.Sender,
			Message:   item.Message,
			CreatedAt: item.CreatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func handleChatCreate(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	_, user, err := authorizeAdminRequest(w, r, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req transport.ChatMessageCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	scope := strings.ToLower(strings.TrimSpace(req.Scope))
	sessionID := req.SessionID
	if scope == server.ChatScopeGlobal && sessionID <= 0 {
		session, ensureErr := server.EnsureGlobalChatSession(ctx, user.Username)
		if ensureErr == nil && session != nil {
			sessionID = session.ID
		}
	}

	item, err := server.CreateChatMessageWithSession(ctx, req.Scope, req.AgentID, sessionID, user.Username, req.Message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if item.Scope == server.ChatScopeAgent {
		if governanceReply, handled, govErr := buildGovernanceCommandQueryReply(ctx, item.AgentID, item.Message); govErr != nil {
			log.Printf("governance query evaluation failed: %v", govErr)
			http.Error(w, "Failed to evaluate governance policy", http.StatusInternalServerError)
			return
		} else if handled {
			agentSender := "agent:" + item.AgentID
			if _, err := server.CreateChatMessage(ctx, server.ChatScopeAgent, item.AgentID, agentSender, governanceReply); err != nil {
				log.Printf("failed to create governance query chat message: %v", err)
			}
		} else {
			allowed, denyReason, checkErr := isAgentChatCommandAllowed(ctx, item.AgentID, item.Message)
			if checkErr != nil {
				log.Printf("chat governance check failed: %v", checkErr)
				http.Error(w, "Failed to evaluate governance policy", http.StatusInternalServerError)
				return
			}
			if !allowed {
				agentSender := "agent:" + item.AgentID
				blockedMessage := "Command blocked by governance policy"
				if strings.TrimSpace(denyReason) != "" {
					blockedMessage = blockedMessage + ": " + denyReason
				}
				if _, err := server.CreateChatMessage(ctx, server.ChatScopeAgent, item.AgentID, agentSender, blockedMessage); err != nil {
					log.Printf("failed to create governance denial chat message: %v", err)
				}
			} else if err := queueAgentChatTask(ctx, cfg, item); err != nil {
				log.Printf("queue agent chat task failed: %v", err)
				http.Error(w, "Failed to queue agent response", http.StatusInternalServerError)
				return
			}
		}
	}

	if item.Scope == server.ChatScopeGlobal {
		tryAutoNameGlobalSessionFromContext(ctx, item.SessionID)

		messageCopy := *item
		go func(msg server.ChatMessage) {
			globalCtx, globalCancel := context.WithTimeout(context.Background(), resolveGlobalWorkflowTimeout(cfg))
			defer globalCancel()
			globalCtx = withGlobalWorkflowTraceID(globalCtx, msg.SessionID)
			if err := handleGlobalChatWorkflow(globalCtx, cfg, &msg); err != nil {
				traceID := getGlobalWorkflowTraceID(globalCtx)
				if traceID != "" {
					log.Printf("global chat workflow error (trace_id=%s): %v", traceID, err)
				} else {
					log.Printf("global chat workflow error: %v", err)
				}
				_ = createGlobalSystemChatMessageDetached(msg.SessionID, "I received your message, but I hit a temporary processing delay. Please retry in a few seconds.")
			}
		}(messageCopy)
	}

	resp := transport.ChatMessage{
		ID:        item.ID,
		Scope:     item.Scope,
		AgentID:   item.AgentID,
		SessionID: item.SessionID,
		Sender:    item.Sender,
		Message:   item.Message,
		CreatedAt: item.CreatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("chat create encode error: %v", err)
	}
}

func tryAutoNameGlobalSessionFromContext(ctx context.Context, sessionID int64) {
	if sessionID <= 0 {
		return
	}

	lookupCtx, lookupCancel := context.WithTimeout(ctx, 2*time.Second)
	defer lookupCancel()

	session, err := server.GetGlobalChatSessionByID(lookupCtx, sessionID)
	if err != nil || session == nil {
		return
	}

	if strings.TrimSpace(session.Title) != "New Chat" {
		return
	}

	messagesCtx, messagesCancel := context.WithTimeout(ctx, 3*time.Second)
	recent, err := server.ListChatMessagesWithSession(messagesCtx, server.ChatScopeGlobal, "", sessionID, 80)
	messagesCancel()
	if err != nil || len(recent) == 0 {
		return
	}

	userTurns := collectGlobalUserMessages(recent)
	if len(userTurns) < globalSessionTitleMinUserTurns {
		return
	}

	newTitle := suggestGlobalSessionTitleFromContext(userTurns)
	if strings.TrimSpace(newTitle) == "" {
		return
	}

	updateCtx, updateCancel := context.WithTimeout(ctx, 2*time.Second)
	defer updateCancel()

	if _, err := server.UpdateGlobalChatSessionTitleIfDefault(updateCtx, sessionID, newTitle); err != nil {
		log.Printf("global chat session title auto-update skipped: %v", err)
	}
}

func collectGlobalUserMessages(messages []server.ChatMessage) []string {
	userTurns := make([]string, 0, len(messages))
	for _, item := range messages {
		sender := strings.ToLower(strings.TrimSpace(item.Sender))
		if sender == "" || strings.HasPrefix(sender, "system:") || strings.HasPrefix(sender, "agent:") {
			continue
		}
		text := strings.TrimSpace(item.Message)
		if text == "" {
			continue
		}
		userTurns = append(userTurns, text)
	}
	return userTurns
}

func suggestGlobalSessionTitleFromContext(userTurns []string) string {
	if len(userTurns) < globalSessionTitleMinUserTurns {
		return ""
	}

	start := len(userTurns) - 4
	if start < 0 {
		start = 0
	}
	window := strings.Join(userTurns[start:], " ")
	window = strings.TrimSpace(window)
	if window == "" {
		return ""
	}

	title := compactContextText(window)
	if title == "" {
		return ""
	}
	if len(title) > 72 {
		title = strings.TrimSpace(title[:72])
		if idx := strings.LastIndex(title, " "); idx > 24 {
			title = strings.TrimSpace(title[:idx])
		}
	}

	title = strings.TrimSpace(title)
	if title == "" {
		return ""
	}

	return title
}

func compactContextText(value string) string {
	var builder strings.Builder
	lastWasSpace := false
	for _, r := range strings.TrimSpace(value) {
		switch {
		case unicode.IsLetter(r), unicode.IsNumber(r):
			builder.WriteRune(r)
			lastWasSpace = false
		case r == '-', r == '/', r == '_', r == '.':
			builder.WriteRune(r)
			lastWasSpace = false
		default:
			if !lastWasSpace {
				builder.WriteRune(' ')
				lastWasSpace = true
			}
		}
	}

	parts := strings.Fields(builder.String())
	if len(parts) == 0 {
		return ""
	}

	return strings.Join(parts, " ")
}

func handleGlobalChatWorkflow(ctx context.Context, cfg config.ServerConfig, item *server.ChatMessage) error {
	if item == nil {
		return nil
	}

	message := strings.TrimSpace(item.Message)
	if message == "" {
		return nil
	}

	if toolReply, handled := tryHandleGlobalChatToolCommand(ctx, cfg, message); handled {
		if err := createGlobalSystemChatMessage(ctx, item.SessionID, toolReply); err != nil {
			return err
		}
		memoryCtx, memoryCancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer memoryCancel()
		if err := maybeRefreshGlobalSessionMemory(memoryCtx, item.SessionID); err != nil {
			log.Printf("global session memory refresh skipped: %v", err)
		}
		return nil
	}

	reply, err := buildGlobalAdaptiveReply(ctx, cfg, item.SessionID, message)
	if err != nil {
		return err
	}

	if err := createGlobalSystemChatMessage(ctx, item.SessionID, reply); err != nil {
		return err
	}

	memoryCtx, memoryCancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer memoryCancel()
	if err := maybeRefreshGlobalSessionMemory(memoryCtx, item.SessionID); err != nil {
		log.Printf("global session memory refresh skipped: %v", err)
	}

	return nil
}

func tryHandleGlobalChatToolCommand(ctx context.Context, cfg config.ServerConfig, message string) (string, bool) {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return "", false
	}

	if strings.EqualFold(trimmed, "/tools") {
		tools := listChatTools()
		lines := make([]string, 0, len(tools)+1)
		lines = append(lines, "Available tools:")
		for _, t := range tools {
			lines = append(lines, "- "+t.Name+": "+strings.TrimSpace(t.Description))
		}
		lines = append(lines, `Use: /tool <name> {"key":"value"}`)
		return strings.Join(lines, "\n"), true
	}

	if !strings.HasPrefix(strings.ToLower(trimmed), "/tool ") {
		return "", false
	}

	rest := strings.TrimSpace(trimmed[len("/tool "):])
	if rest == "" {
		return `Usage: /tool <name> {"key":"value"}` + "\nExample: /tool fleet_health {}", true
	}

	toolName := rest
	argsJSON := "{}"
	if space := strings.IndexAny(rest, " \t"); space > 0 {
		toolName = strings.TrimSpace(rest[:space])
		argsJSON = strings.TrimSpace(rest[space+1:])
	}
	if argsJSON == "" {
		argsJSON = "{}"
	}

	args := map[string]interface{}{}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return "Invalid tool JSON arguments: " + err.Error(), true
	}

	authHeader := ""
	secret := strings.TrimSpace(cfg.AdminJWTSecret)
	if secret != "" {
		token, err := auth.GenerateToken("admin", "admin", secret, 5*time.Minute)
		if err == nil && strings.TrimSpace(token) != "" {
			authHeader = "Bearer " + strings.TrimSpace(token)
		}
	}

	result, err := executeChatTool(ctx, cfg, authHeader, "", chatToolExecuteRequest{
		Tool:      toolName,
		Arguments: args,
	})
	if err != nil {
		return "Tool execution failed: " + err.Error(), true
	}

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf("Tool %s executed successfully.", toolName), true
	}

	output := string(encoded)
	if len(output) > 12000 {
		output = output[:12000] + "\n... (truncated)"
	}

	return "Tool result (" + toolName + "):\n" + output, true
}

func buildGlobalChatGuidanceReply(message string) string {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return "Hi! I'm your AI assistant. Start a new chat or continue an existing one, and I'll keep context within that session."
	}

	return "I'm plain AI chat mode right now. Ask anything, and I'll respond conversationally with session memory."
}

type globalFleetSnapshot struct {
	Total    int
	Online   int
	Offline  int
	Active   int
	Critical int
	High     int
	Medium   int
	Low      int
}

type globalResearchContext struct {
	Snapshot                *globalFleetSnapshot
	RecentChat              []server.ChatMessage
	Issues                  []server.AgentIssue
	Schedules               []server.Schedule
	RecentReports           []server.ScheduleExecutionReport
	HotAgentMetrics         []string
	DiskRiskDevices         []globalDiskRiskDevice
	OnlineAgentsScanned     int
	OnlineAgentsWithDisk    int
	OnlineAgentsMissingDisk int
}

type globalDiskRiskDevice struct {
	AgentID     string
	Hostname    string
	DiskUsedPct float64
}

func buildGlobalAdaptiveReply(ctx context.Context, cfg config.ServerConfig, sessionID int64, message string) (string, error) {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return buildGlobalChatGuidanceReply(""), nil
	}

	research := collectGlobalResearchContext(ctx, sessionID)

	if shouldForceGroundedGlobalReply(trimmed) {
		return buildGlobalSuperTechFallback(trimmed, research), nil
	}

	sessionSummary := ""
	if sessionID > 0 {
		memoryCtx, memoryCancel := context.WithTimeout(ctx, 2*time.Second)
		memory, _ := server.GetGlobalChatSessionMemory(memoryCtx, sessionID)
		memoryCancel()
		if memory != nil {
			sessionSummary = strings.TrimSpace(memory.Summary)
		}
	}

	recentCtx, recentCancel := context.WithTimeout(ctx, 4*time.Second)
	recent, _ := server.ListChatMessagesWithSession(recentCtx, server.ChatScopeGlobal, "", sessionID, globalChatLearningWindow)
	recentCancel()

	if cfg.GlobalAIEnabled {
		if aiReply, aiErr := buildGlobalAIResearchReply(ctx, cfg, trimmed, recent, sessionSummary, research); aiErr == nil && strings.TrimSpace(aiReply) != "" {
			cleanReply := strings.TrimSpace(aiReply)
			if isUngroundedGlobalReply(cleanReply) {
				traceID := getGlobalWorkflowTraceID(ctx)
				if traceID != "" {
					log.Printf("global AI reply rejected as ungrounded (trace_id=%s session_id=%d)", traceID, sessionID)
				} else {
					log.Printf("global AI reply rejected as ungrounded (session_id=%d)", sessionID)
				}
				return buildGlobalSuperTechFallback(trimmed, research), nil
			}
			return cleanReply, nil
		} else if aiErr != nil {
			traceID := getGlobalWorkflowTraceID(ctx)
			if traceID != "" {
				log.Printf("global AI reply build failed (trace_id=%s session_id=%d provider=%s model=%s endpoint=%s): %v", traceID, sessionID, strings.TrimSpace(cfg.GlobalAIProvider), strings.TrimSpace(cfg.GlobalAIModel), strings.TrimSpace(cfg.GlobalAIEndpoint), aiErr)
			} else {
				log.Printf("global AI reply build failed (session_id=%d provider=%s model=%s endpoint=%s): %v", sessionID, strings.TrimSpace(cfg.GlobalAIProvider), strings.TrimSpace(cfg.GlobalAIModel), strings.TrimSpace(cfg.GlobalAIEndpoint), aiErr)
			}
		}
	}

	return buildGlobalSuperTechFallback(trimmed, research), nil
}

func isUngroundedGlobalReply(reply string) bool {
	text := strings.ToLower(strings.TrimSpace(reply))
	if text == "" {
		return false
	}

	patterns := []string{
		"i don't have real-time",
		"i do not have real-time",
		"i don't have access",
		"i do not have access",
		"i don't have direct access",
		"i do not have direct access",
		"text-based ai assistant",
		"cannot access your system",
		"can't access your system",
	}

	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}

	return false
}

func shouldForceGroundedGlobalReply(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	if lower == "" {
		return false
	}

	return containsAnyTerm(lower,
		"disk", "storage", "drive", "free space", "used space", "capacity", "volume",
		"patch", "update", "kb", "hotfix", "compliance", "vulnerability",
		"issue", "incident", "alert", "critical", "high severity", "risk",
		"schedule", "scheduled", "job", "cron", "run window", "maintenance window",
		"telemetry", "metric", "cpu", "memory", "ram", "network", "latency", "packet", "throughput",
	)
}

func buildGlobalAIResearchReply(ctx context.Context, cfg config.ServerConfig, userMessage string, recentChat []server.ChatMessage, sessionSummary string, research globalResearchContext) (string, error) {
	type chatMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type chatRequest struct {
		Model       string    `json:"model"`
		Messages    []chatMsg `json:"messages"`
		Temperature float64   `json:"temperature,omitempty"`
	}
	type chatResponse struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	type ollamaNativeRequest struct {
		Model    string    `json:"model"`
		Messages []chatMsg `json:"messages"`
		Stream   bool      `json:"stream"`
	}
	type ollamaNativeResponse struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Error string `json:"error,omitempty"`
	}

	provider := strings.ToLower(strings.TrimSpace(cfg.GlobalAIProvider))
	if provider == "" {
		endpoint := strings.ToLower(strings.TrimSpace(cfg.GlobalAIEndpoint))
		if strings.Contains(endpoint, "127.0.0.1:11434") || strings.Contains(endpoint, "localhost:11434") {
			provider = "ollama"
		} else {
			provider = "openai"
		}
	}

	if provider != "ollama" && strings.TrimSpace(cfg.GlobalAIAPIKey) == "" {
		return "", fmt.Errorf("global chat AI key not configured")
	}

	systemPrompt := strings.Join([]string{
		"You are Super Tech, the AI assistant for this endpoint platform.",
		"Be concise, accurate, and operationally useful.",
		"Use the provided platform context (agents, telemetry, issues, schedules, reports) as authoritative runtime data.",
		"Do not say you lack access to system/device information when platform context is provided.",
		"If specific details are unavailable in context, state what is missing and provide the best next actionable query.",
	}, " ")
	if strings.TrimSpace(sessionSummary) != "" {
		systemPrompt += "\n\nSession memory summary (use this as persistent context, but prioritize recent user instructions):\n" + strings.TrimSpace(sessionSummary)
	}

	if researchContext := formatGlobalResearchContextForPrompt(research); strings.TrimSpace(researchContext) != "" {
		systemPrompt += "\n\nLive platform context:\n" + researchContext
	}

	messages := make([]chatMsg, 0, len(recentChat)+2)
	messages = append(messages, chatMsg{Role: "system", Content: systemPrompt})

	if len(recentChat) > 0 {
		start := 0
		if len(recentChat) > 30 {
			start = len(recentChat) - 30
		}
		for _, item := range recentChat[start:] {
			text := strings.TrimSpace(item.Message)
			if text == "" {
				continue
			}
			if len(text) > 1200 {
				text = strings.TrimSpace(text[:1200])
			}
			sender := strings.ToLower(strings.TrimSpace(item.Sender))
			switch {
			case strings.HasPrefix(sender, "system:global"):
				messages = append(messages, chatMsg{Role: "assistant", Content: text})
			case strings.HasPrefix(sender, "system:"), strings.HasPrefix(sender, "agent:"):
				continue
			default:
				messages = append(messages, chatMsg{Role: "user", Content: text})
			}
		}
	}

	messages = append(messages, chatMsg{Role: "user", Content: userMessage})

	model := strings.TrimSpace(cfg.GlobalAIModel)
	if model == "" {
		model = "llama3.2"
	}
	reqPayload := chatRequest{Model: model, Messages: messages, Temperature: 0.4}
	body, marshalErr := json.Marshal(reqPayload)
	if marshalErr != nil {
		return "", marshalErr
	}

	requestURL := strings.TrimSpace(cfg.GlobalAIEndpoint)
	if requestURL == "" {
		return "", fmt.Errorf("global chat AI endpoint is not configured")
	}
	if !strings.Contains(requestURL, "/") {
		requestURL = "http://" + requestURL
	}
	if provider == "openai" {
		requestURL = strings.TrimRight(requestURL, "/")
		if !strings.Contains(strings.ToLower(requestURL), "/chat/completions") {
			requestURL = requestURL + "/v1/chat/completions"
		}
	}

	timeout := cfg.GlobalAITimeout
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, reqErr := http.NewRequestWithContext(requestCtx, http.MethodPost, requestURL, bytes.NewBuffer(body))
	if reqErr != nil {
		return "", reqErr
	}
	req.Header.Set("Content-Type", "application/json")
	if provider != "ollama" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(cfg.GlobalAIAPIKey))
	}

	client := &http.Client{Timeout: timeout}
	resp, doErr := client.Do(req)
	if doErr != nil {
		retryReq, retryReqErr := http.NewRequestWithContext(requestCtx, http.MethodPost, requestURL, bytes.NewBuffer(body))
		if retryReqErr == nil {
			retryReq.Header.Set("Content-Type", "application/json")
			if provider != "ollama" {
				retryReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(cfg.GlobalAIAPIKey))
			}
			resp, doErr = client.Do(retryReq)
		}
	}
	if doErr != nil {
		return "", doErr
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		_ = resp.Body.Close()
		retryReq, retryReqErr := http.NewRequestWithContext(requestCtx, http.MethodPost, requestURL, bytes.NewBuffer(body))
		if retryReqErr == nil {
			retryReq.Header.Set("Content-Type", "application/json")
			if provider != "ollama" {
				retryReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(cfg.GlobalAIAPIKey))
			}
			retryResp, retryErr := client.Do(retryReq)
			if retryErr == nil {
				resp = retryResp
				defer resp.Body.Close()
			}
		}
	}

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", readErr
	}

	if provider == "ollama" {
		var native ollamaNativeResponse
		if err := json.Unmarshal(respBody, &native); err == nil {
			if resp.StatusCode >= 200 && resp.StatusCode < 300 && strings.TrimSpace(native.Message.Content) != "" {
				return strings.TrimSpace(native.Message.Content), nil
			}
			if resp.StatusCode >= 400 && strings.TrimSpace(native.Error) != "" {
				return "", fmt.Errorf("%s", strings.TrimSpace(native.Error))
			}
		}

		if resp.StatusCode == http.StatusNotFound {
			nativeURL := normalizeOllamaNativeChatURL(requestURL)
			if nativeURL != "" && nativeURL != requestURL {
				nativePayload := ollamaNativeRequest{Model: model, Messages: messages, Stream: false}
				nativeBody, err := json.Marshal(nativePayload)
				if err != nil {
					return "", err
				}
				nativeReq, err := http.NewRequestWithContext(requestCtx, http.MethodPost, nativeURL, bytes.NewBuffer(nativeBody))
				if err != nil {
					return "", err
				}
				nativeReq.Header.Set("Content-Type", "application/json")
				nativeResp, err := client.Do(nativeReq)
				if err != nil {
					return "", err
				}
				defer nativeResp.Body.Close()
				nativeRespBody, err := io.ReadAll(nativeResp.Body)
				if err != nil {
					return "", err
				}
				var nativeChat ollamaNativeResponse
				if err := json.Unmarshal(nativeRespBody, &nativeChat); err != nil {
					return "", err
				}
				if nativeResp.StatusCode >= 400 {
					if strings.TrimSpace(nativeChat.Error) != "" {
						return "", fmt.Errorf("%s", strings.TrimSpace(nativeChat.Error))
					}
					return "", fmt.Errorf("global AI request failed: HTTP %d", nativeResp.StatusCode)
				}
				if strings.TrimSpace(nativeChat.Message.Content) == "" {
					return "", fmt.Errorf("empty AI response")
				}
				return strings.TrimSpace(nativeChat.Message.Content), nil
			}
		}
	}

	var parsed chatResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		if resp.StatusCode >= 400 {
			return "", fmt.Errorf("global AI request failed: HTTP %d", resp.StatusCode)
		}
		return "", err
	}
	if resp.StatusCode >= 400 {
		if parsed.Error != nil && strings.TrimSpace(parsed.Error.Message) != "" {
			return "", fmt.Errorf("%s", strings.TrimSpace(parsed.Error.Message))
		}
		return "", fmt.Errorf("global AI request failed: HTTP %d", resp.StatusCode)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("empty AI response")
	}
	content := strings.TrimSpace(parsed.Choices[0].Message.Content)
	if content == "" {
		return "", fmt.Errorf("empty AI response")
	}

	return content, nil
}

func formatGlobalResearchContextForPrompt(research globalResearchContext) string {
	lines := make([]string, 0, 24)

	if research.Snapshot != nil {
		s := *research.Snapshot
		lines = append(lines,
			fmt.Sprintf("Fleet snapshot: total=%d online=%d offline=%d", s.Total, s.Online, s.Offline),
			fmt.Sprintf("Active issues: total=%d critical=%d high=%d medium=%d low=%d", s.Active, s.Critical, s.High, s.Medium, s.Low),
		)
	}

	if len(research.Issues) > 0 {
		lines = append(lines, "Top active issues:")
		limit := len(research.Issues)
		if limit > 8 {
			limit = 8
		}
		for _, issue := range research.Issues[:limit] {
			lines = append(lines, fmt.Sprintf("- issue_id=%d agent=%s severity=%s category=%s status=%s title=%s", issue.ID, strings.TrimSpace(issue.AgentID), strings.TrimSpace(issue.Severity), strings.TrimSpace(issue.Category), strings.TrimSpace(issue.Status), strings.TrimSpace(issue.Title)))
		}
	}

	if len(research.Schedules) > 0 {
		lines = append(lines, "Recent schedules:")
		limit := len(research.Schedules)
		if limit > 8 {
			limit = 8
		}
		for _, schedule := range research.Schedules[:limit] {
			lines = append(lines, fmt.Sprintf("- schedule_id=%d name=%s kind=%s command_type=%s enabled=%t", schedule.ID, strings.TrimSpace(schedule.Name), strings.TrimSpace(schedule.Kind), strings.TrimSpace(schedule.CommandType), schedule.Enabled))
		}
	}

	if len(research.RecentReports) > 0 {
		lines = append(lines, "Recent schedule execution reports:")
		limit := len(research.RecentReports)
		if limit > 8 {
			limit = 8
		}
		for _, report := range research.RecentReports[:limit] {
			lines = append(lines, fmt.Sprintf("- command_id=%d schedule_id=%d status=%s created_at=%s", report.CommandID, report.ScheduleID, strings.TrimSpace(report.Status), report.CreatedAt.UTC().Format(time.RFC3339)))
		}
	}

	if len(research.HotAgentMetrics) > 0 {
		lines = append(lines, "Live telemetry highlights:")
		lines = append(lines, research.HotAgentMetrics...)
	}

	if len(lines) == 0 {
		return "No live platform records were available in this request window."
	}

	text := strings.Join(lines, "\n")
	if len(text) > 5000 {
		text = text[:5000]
	}
	return text
}

func collectGlobalResearchContext(ctx context.Context, sessionID int64) globalResearchContext {
	_ = ctx
	result := globalResearchContext{}

	snapshotCtx, snapshotCancel := context.WithTimeout(context.Background(), 4*time.Second)
	snapshot, snapshotErr := collectGlobalFleetSnapshot(snapshotCtx)
	snapshotCancel()
	if snapshotErr == nil {
		result.Snapshot = &snapshot
	}

	recentCtx, recentCancel := context.WithTimeout(context.Background(), 4*time.Second)
	recent, recentErr := server.ListChatMessagesWithSession(recentCtx, server.ChatScopeGlobal, "", sessionID, globalChatLearningWindow)
	recentCancel()
	if recentErr == nil {
		result.RecentChat = recent
	}

	issuesCtx, issuesCancel := context.WithTimeout(context.Background(), 4*time.Second)
	issues, issuesErr := server.ListAgentIssues(issuesCtx, server.IssueFilter{Status: "active", Limit: 8})
	issuesCancel()
	if issuesErr == nil {
		result.Issues = issues
	}

	schedulesCtx, schedulesCancel := context.WithTimeout(context.Background(), 4*time.Second)
	schedules, schedulesErr := server.ListSchedules(schedulesCtx, 8)
	schedulesCancel()
	if schedulesErr == nil {
		result.Schedules = schedules
	}

	reportsCtx, reportsCancel := context.WithTimeout(context.Background(), 4*time.Second)
	reports, reportsErr := server.ListScheduleExecutionReports(reportsCtx, server.ScheduleExecutionReportFilter{
		From:  time.Now().UTC().Add(-24 * time.Hour),
		To:    time.Now().UTC(),
		Limit: 20,
	})
	reportsCancel()
	if reportsErr == nil {
		result.RecentReports = reports
	}

	agentsCtx, agentsCancel := context.WithTimeout(context.Background(), 4*time.Second)
	agents, agentsErr := server.GetAllAgents(agentsCtx)
	agentsCancel()
	if agentsErr == nil {
		count := 0
		for _, item := range agents {
			if !strings.EqualFold(strings.TrimSpace(item.Status), "online") {
				continue
			}
			result.OnlineAgentsScanned++
			metricCtx, metricCancel := context.WithTimeout(context.Background(), 2*time.Second)
			metric, metricErr := server.GetLatestMetrics(metricCtx, strings.TrimSpace(item.AgentID))
			metricCancel()
			if metricErr != nil || metric == nil {
				result.OnlineAgentsMissingDisk++
				continue
			}
			diskUsage := "n/a"
			if metric.DiskUsagePercent != nil {
				diskUsage = fmt.Sprintf("%.1f%%", *metric.DiskUsagePercent)
				result.OnlineAgentsWithDisk++
				if *metric.DiskUsagePercent >= 85.0 {
					result.DiskRiskDevices = append(result.DiskRiskDevices, globalDiskRiskDevice{
						AgentID:     strings.TrimSpace(item.AgentID),
						Hostname:    strings.TrimSpace(item.Hostname),
						DiskUsedPct: *metric.DiskUsagePercent,
					})
				}
			} else {
				result.OnlineAgentsMissingDisk++
			}
			result.HotAgentMetrics = append(result.HotAgentMetrics,
				fmt.Sprintf("- %s (%s): cpu=%.1f%% mem=%.1f%% disk=%s net_rx=%.1fKB/s net_tx=%.1fKB/s",
					strings.TrimSpace(item.Hostname), strings.TrimSpace(item.AgentID), metric.CPUPercent, metric.MemoryUsedPercent, diskUsage,
					metric.NetBytesRecvPerSec/1024.0, metric.NetBytesSentPerSec/1024.0,
				),
			)
			count++
			if count >= 3 {
				break
			}
		}

		if len(result.DiskRiskDevices) > 1 {
			sort.Slice(result.DiskRiskDevices, func(i, j int) bool {
				return result.DiskRiskDevices[i].DiskUsedPct > result.DiskRiskDevices[j].DiskUsedPct
			})
		}
	}

	return result
}

func buildGlobalSuperTechFallback(userMessage string, research globalResearchContext) string {
	lower := strings.ToLower(strings.TrimSpace(userMessage))
	learning := buildGlobalLearningHint(research.RecentChat)

	intent := "general"
	switch {
	case containsAnyTerm(lower, "disk", "storage", "drive", "free space", "used space", "capacity", "volume"):
		intent = "disk"
	case containsAnyTerm(lower, "patch", "update", "kb", "hotfix", "compliance", "vulnerability"):
		intent = "patch"
	case containsAnyTerm(lower, "issue", "incident", "alert", "critical", "risk"):
		intent = "issues"
	case containsAnyTerm(lower, "schedule", "scheduled", "job", "cron", "run window", "maintenance window"):
		intent = "schedules"
	case containsAnyTerm(lower, "telemetry", "metric", "cpu", "memory", "ram", "network", "latency", "packet", "throughput"):
		intent = "telemetry"
	}

	fleet := "n/a"
	if research.Snapshot != nil {
		s := *research.Snapshot
		fleet = fmt.Sprintf("total=%d online=%d offline=%d active_issues=%d critical=%d high=%d medium=%d low=%d", s.Total, s.Online, s.Offline, s.Active, s.Critical, s.High, s.Medium, s.Low)
	}

	focus := "n/a"
	if strings.TrimSpace(learning) != "" {
		focus = strings.TrimSpace(learning)
	}

	issuesEvidence := "n/a"
	if len(research.Issues) > 0 {
		parts := make([]string, 0, 3)
		limit := len(research.Issues)
		if limit > 3 {
			limit = 3
		}
		for _, issue := range research.Issues[:limit] {
			parts = append(parts, fmt.Sprintf("id=%d sev=%s cat=%s status=%s", issue.ID, strings.TrimSpace(issue.Severity), strings.TrimSpace(issue.Category), strings.TrimSpace(issue.Status)))
		}
		issuesEvidence = fmt.Sprintf("count=%d top=[%s]", len(research.Issues), strings.Join(parts, " | "))
	}

	schedulesEvidence := "n/a"
	if len(research.Schedules) > 0 {
		parts := make([]string, 0, 3)
		limit := len(research.Schedules)
		if limit > 3 {
			limit = 3
		}
		for _, schedule := range research.Schedules[:limit] {
			parts = append(parts, fmt.Sprintf("id=%d kind=%s enabled=%t", schedule.ID, strings.TrimSpace(schedule.Kind), schedule.Enabled))
		}
		schedulesEvidence = fmt.Sprintf("count=%d top=[%s]", len(research.Schedules), strings.Join(parts, " | "))
	}

	telemetryEvidence := "n/a"
	if len(research.HotAgentMetrics) > 0 {
		first := strings.TrimSpace(research.HotAgentMetrics[0])
		telemetryEvidence = strings.TrimPrefix(first, "- ")
	}

	diskRiskEvidence := "n/a"
	if len(research.DiskRiskDevices) > 0 {
		parts := make([]string, 0, 3)
		limit := len(research.DiskRiskDevices)
		if limit > 3 {
			limit = 3
		}
		for _, device := range research.DiskRiskDevices[:limit] {
			name := strings.TrimSpace(device.Hostname)
			if name == "" {
				name = device.AgentID
			}
			parts = append(parts, fmt.Sprintf("%s(%s)=%.1f%%", name, device.AgentID, device.DiskUsedPct))
		}
		diskRiskEvidence = fmt.Sprintf("count=%d top=[%s]", len(research.DiskRiskDevices), strings.Join(parts, " | "))
	} else if research.OnlineAgentsWithDisk > 0 {
		diskRiskEvidence = fmt.Sprintf("count=0 checked=%d", research.OnlineAgentsWithDisk)
	}

	gapParts := make([]string, 0, 4)
	if research.Snapshot == nil {
		gapParts = append(gapParts, "fleet_snapshot")
	}
	if len(research.HotAgentMetrics) == 0 {
		gapParts = append(gapParts, "telemetry")
	}
	if intent == "disk" && research.OnlineAgentsWithDisk == 0 {
		gapParts = append(gapParts, "disk_usage_percent")
	}
	if len(gapParts) == 0 {
		gapParts = append(gapParts, "none")
	}
	dataGaps := strings.Join(gapParts, ",")

	action1 := "Specify one objective (disk, patch, issues, schedules, telemetry) for targeted triage."
	action2 := "Use current fleet and issue evidence to prioritize remediation."
	action3 := "Re-run after updates to confirm risk reduction."

	switch intent {
	case "disk":
		action1 = "Prioritize devices above 92% used, then 85-92%."
		action2 = "Check patch cache, temp files, and log growth before cleanup."
		action3 = "Re-check disk telemetry after cleanup to confirm recovery."
	case "patch":
		action1 = "Address critical/high patch-related issues first."
		action2 = "Review repeated install failures and servicing stack state."
		action3 = "Validate post-remediation issue status transitions."
	case "issues":
		action1 = "Prioritize unresolved issues by severity and blast radius."
		action2 = "Assign owners and immediate mitigation per top issue."
		action3 = "Track status changes until closure."
	case "schedules":
		action1 = "Validate schedule enablement and next-run windows."
		action2 = "Inspect last 24h execution reports for failures."
		action3 = "Adjust schedule parameters and rerun validation."
	case "telemetry":
		action1 = "Compare current telemetry to baseline windows."
		action2 = "Prioritize sustained CPU/memory/network anomalies."
		action3 = "Correlate anomalies with active issues and recent changes."
	}

	lines := []string{
		"Summary:",
		"- intent=" + intent,
		"- fleet=" + fleet,
		"- focus=" + focus,
		"Evidence:",
		"- issues=" + issuesEvidence,
		"- schedules=" + schedulesEvidence,
		"- telemetry=" + telemetryEvidence,
		"- disk_risk=" + diskRiskEvidence,
		"Gaps:",
		"- data_gaps=" + dataGaps,
		"Next Actions:",
		"- action_1=" + action1,
		"- action_2=" + action2,
		"- action_3=" + action3,
	}

	return strings.Join(lines, "\n")
}

func normalizeOllamaNativeChatURL(requestURL string) string {
	trimmed := strings.TrimSpace(requestURL)
	if trimmed == "" {
		return ""
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "/v1/chat/completions") {
		idx := strings.Index(lower, "/v1/chat/completions")
		return strings.TrimRight(trimmed[:idx], "/") + "/api/chat"
	}
	if strings.HasSuffix(lower, "/v1") {
		return strings.TrimRight(trimmed, "/") + "/api/chat"
	}
	if strings.Contains(lower, "/api/chat") {
		return trimmed
	}
	return strings.TrimRight(trimmed, "/") + "/api/chat"
}

func resolveGlobalWorkflowTimeout(cfg config.ServerConfig) time.Duration {
	timeout := cfg.GlobalAITimeout + (5 * time.Second)
	if timeout < globalWorkflowMinTimeout {
		timeout = globalWorkflowMinTimeout
	}
	if timeout > 120*time.Second {
		timeout = 120 * time.Second
	}
	return timeout
}

func containsAnyTerm(value string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}

func buildGlobalLearningHint(messages []server.ChatMessage) string {
	if len(messages) == 0 {
		return ""
	}

	keywordBuckets := map[string][]string{
		"patching":    {"patch", "update", "kb", "hotfix"},
		"performance": {"cpu", "memory", "ram", "disk", "performance"},
		"network":     {"network", "internet", "dns", "ip", "latency"},
		"security":    {"security", "critical", "threat", "vulnerability"},
		"operations":  {"triage", "priority", "risk", "investigate", "root cause", "remediate"},
	}

	scores := map[string]int{}
	for _, item := range messages {
		sender := strings.ToLower(strings.TrimSpace(item.Sender))
		if sender == "" || strings.HasPrefix(sender, "system:") {
			continue
		}
		text := strings.ToLower(strings.TrimSpace(item.Message))
		if text == "" {
			continue
		}
		for topic, terms := range keywordBuckets {
			for _, term := range terms {
				if strings.Contains(text, term) {
					scores[topic]++
					break
				}
			}
		}
	}

	if len(scores) == 0 {
		return ""
	}

	type scoredTopic struct {
		Topic string
		Score int
	}
	ranked := make([]scoredTopic, 0, len(scores))
	for topic, score := range scores {
		if score > 0 {
			ranked = append(ranked, scoredTopic{Topic: topic, Score: score})
		}
	}
	if len(ranked) == 0 {
		return ""
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].Score == ranked[j].Score {
			return ranked[i].Topic < ranked[j].Topic
		}
		return ranked[i].Score > ranked[j].Score
	})

	limit := 2
	if len(ranked) < limit {
		limit = len(ranked)
	}
	parts := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		parts = append(parts, ranked[i].Topic)
	}

	return "Recent operator focus (learned from chat history): " + strings.Join(parts, " + ") + "."
}

func maybeRefreshGlobalSessionMemory(ctx context.Context, sessionID int64) error {
	if sessionID <= 0 {
		return nil
	}

	messages, err := server.ListChatMessagesWithSession(ctx, server.ChatScopeGlobal, "", sessionID, 120)
	if err != nil {
		return err
	}
	if len(messages) == 0 {
		return nil
	}

	userTurns := collectGlobalUserMessages(messages)
	if len(userTurns) < globalSessionMemoryMinTurns {
		return nil
	}

	memory, err := server.GetGlobalChatSessionMemory(ctx, sessionID)
	if err != nil {
		return err
	}

	newUserTurns := 0
	for _, item := range messages {
		if memory != nil && item.ID <= memory.LastCompactedMessageID {
			continue
		}
		sender := strings.ToLower(strings.TrimSpace(item.Sender))
		if sender == "" || strings.HasPrefix(sender, "system:") || strings.HasPrefix(sender, "agent:") {
			continue
		}
		if strings.TrimSpace(item.Message) != "" {
			newUserTurns++
		}
	}

	if memory != nil && strings.TrimSpace(memory.Summary) != "" && newUserTurns < globalSessionSummaryEveryTurns {
		return nil
	}

	newSummary := summarizeGlobalSessionMemory(messages, "")
	if memory != nil {
		newSummary = summarizeGlobalSessionMemory(messages, memory.Summary)
	}
	if strings.TrimSpace(newSummary) == "" {
		return nil
	}

	lastMessageID := messages[len(messages)-1].ID
	return server.UpsertGlobalChatSessionMemory(ctx, sessionID, newSummary, lastMessageID)
}

func summarizeGlobalSessionMemory(messages []server.ChatMessage, existingSummary string) string {
	if len(messages) == 0 {
		return strings.TrimSpace(existingSummary)
	}

	start := 0
	if len(messages) > 40 {
		start = len(messages) - 40
	}
	window := messages[start:]

	userAsks := make([]string, 0, 6)
	assistantOutputs := make([]string, 0, 4)
	for _, item := range window {
		text := strings.TrimSpace(item.Message)
		if text == "" {
			continue
		}
		text = truncateSummaryText(compactContextText(text), 220)
		if text == "" {
			continue
		}

		sender := strings.ToLower(strings.TrimSpace(item.Sender))
		switch {
		case strings.HasPrefix(sender, "system:global"):
			assistantOutputs = append(assistantOutputs, text)
		case strings.HasPrefix(sender, "system:"), strings.HasPrefix(sender, "agent:"):
			continue
		default:
			userAsks = append(userAsks, text)
		}
	}

	if len(userAsks) > 6 {
		userAsks = userAsks[len(userAsks)-6:]
	}
	if len(assistantOutputs) > 4 {
		assistantOutputs = assistantOutputs[len(assistantOutputs)-4:]
	}

	lines := make([]string, 0, 16)
	if strings.TrimSpace(existingSummary) != "" {
		lines = append(lines, "Prior memory:")
		lines = append(lines, "- "+truncateSummaryText(compactContextText(existingSummary), 700))
	}

	if len(userAsks) > 0 {
		lines = append(lines, "Recent user asks:")
		for _, item := range userAsks {
			lines = append(lines, "- "+item)
		}
	}

	if len(assistantOutputs) > 0 {
		lines = append(lines, "Recent assistant outputs:")
		for _, item := range assistantOutputs {
			lines = append(lines, "- "+item)
		}
	}

	summary := strings.TrimSpace(strings.Join(lines, "\n"))
	if len(summary) > globalSessionSummaryMaxChars {
		summary = strings.TrimSpace(summary[:globalSessionSummaryMaxChars])
	}
	return summary
}

func truncateSummaryText(value string, maxChars int) string {
	trimmed := strings.TrimSpace(value)
	if maxChars <= 0 || len(trimmed) <= maxChars {
		return trimmed
	}
	trimmed = strings.TrimSpace(trimmed[:maxChars])
	if idx := strings.LastIndex(trimmed, " "); idx > maxChars/3 {
		trimmed = strings.TrimSpace(trimmed[:idx])
	}
	return trimmed
}

func collectGlobalFleetSnapshot(ctx context.Context) (globalFleetSnapshot, error) {
	snapshot := globalFleetSnapshot{}

	agents, err := server.GetAllAgents(ctx)
	if err != nil {
		return snapshot, err
	}
	issues, err := server.ListAgentIssues(ctx, server.IssueFilter{Status: "active", Limit: 500})
	if err != nil {
		return snapshot, err
	}

	snapshot.Total = len(agents)
	for _, item := range agents {
		if strings.EqualFold(strings.TrimSpace(item.Status), "online") {
			snapshot.Online++
		} else {
			snapshot.Offline++
		}
	}

	snapshot.Active = len(issues)
	for _, issue := range issues {
		switch strings.ToLower(strings.TrimSpace(issue.Severity)) {
		case "critical":
			snapshot.Critical++
		case "high":
			snapshot.High++
		case "medium":
			snapshot.Medium++
		default:
			snapshot.Low++
		}
	}

	return snapshot, nil
}

func createGlobalSystemChatMessage(ctx context.Context, sessionID int64, message string) error {
	if strings.TrimSpace(message) == "" {
		return nil
	}
	traceID := getGlobalWorkflowTraceID(ctx)
	writeCtx := ctx
	if writeCtx == nil {
		writeCtx = context.Background()
	}

	if err := writeCtx.Err(); err != nil {
		if detachedErr := createGlobalSystemChatMessageDetached(sessionID, message); detachedErr == nil {
			return nil
		}
		if traceID != "" {
			return fmt.Errorf("failed to create global system chat message (trace_id=%s): context not writable: %w", traceID, err)
		}
		return fmt.Errorf("failed to create global system chat message: context not writable: %w", err)
	}

	if deadline, ok := writeCtx.Deadline(); ok && time.Until(deadline) < 1500*time.Millisecond {
		if detachedErr := createGlobalSystemChatMessageDetached(sessionID, message); detachedErr == nil {
			return nil
		}
	}

	_, err := server.CreateChatMessageWithSession(writeCtx, server.ChatScopeGlobal, "", sessionID, "system:global", message)
	if err != nil {
		errText := strings.ToLower(err.Error())
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || strings.Contains(errText, "context deadline exceeded") || strings.Contains(errText, "context canceled") {
			if detachedErr := createGlobalSystemChatMessageDetached(sessionID, message); detachedErr == nil {
				return nil
			}
		}
		if traceID != "" {
			return fmt.Errorf("failed to create global system chat message (trace_id=%s): %w", traceID, err)
		}
		return fmt.Errorf("failed to create global system chat message: %w", err)
	}
	return nil
}

func createGlobalSystemChatMessageDetached(sessionID int64, message string) error {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), globalDetachedWriteTimeout)
	defer cancel()
	_, err := server.CreateChatMessageWithSession(ctx, server.ChatScopeGlobal, "", sessionID, "system:global", trimmed)
	if err != nil {
		return fmt.Errorf("failed to create detached global system chat message: %w", err)
	}
	return nil
}

func queueAgentChatTask(ctx context.Context, cfg config.ServerConfig, message *server.ChatMessage) error {
	if message == nil {
		return fmt.Errorf("message is required")
	}
	if strings.TrimSpace(message.AgentID) == "" {
		return fmt.Errorf("agentID is required")
	}

	instruction := strings.TrimSpace(message.Message)
	if contextInstruction, err := buildPersonalChatInstruction(ctx, message.AgentID, instruction); err != nil {
		log.Printf("personal chat memory context build failed, using latest message only: %v", err)
	} else if strings.TrimSpace(contextInstruction) != "" {
		instruction = contextInstruction
	}

	task := ai.Task{
		TaskID:      fmt.Sprintf("chatmsg-%d", message.ID),
		MotherRole:  ai.MotherInstructor,
		ChildIntent: ai.ChildSuggest,
		Title:       "Respond to personal chat",
		Instruction: instruction,
		Context:     "personal_chat",
	}

	payload, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("failed to serialize ai_task payload: %w", err)
	}

	if cfg.QueueEnabled && cfg.QueueAgentChatActive {
		if err := tryShadowPublishAgentChatTask(ctx, cfg, message, task); err == nil {
			return nil
		} else {
			log.Printf("agent chat queue primary publish failed, falling back to db command path: %v", err)
		}

		_, err = server.CreateCommand(ctx, message.AgentID, "ai_task", string(payload))
		if err != nil {
			return fmt.Errorf("failed to queue ai_task command: %w", err)
		}

		return nil
	}

	if err := tryShadowPublishAgentChatTask(ctx, cfg, message, task); err != nil {
		log.Printf("agent chat shadow publish skipped: %v", err)
	}

	_, err = server.CreateCommand(ctx, message.AgentID, "ai_task", string(payload))
	if err != nil {
		return fmt.Errorf("failed to queue ai_task command: %w", err)
	}

	return nil
}

func tryShadowPublishAgentChatTask(ctx context.Context, cfg config.ServerConfig, message *server.ChatMessage, task ai.Task) error {
	publisher, err := queue.NewPublisher(queue.Config{
		Enabled:       cfg.QueueEnabled,
		Provider:      cfg.QueueProvider,
		NATSURL:       cfg.QueueNATSURL,
		SubjectPrefix: cfg.QueueSubjectPrefix,
		Timeout:       personalChatShadowPublishTimeout,
	})
	if err != nil {
		return err
	}

	if !publisher.Enabled() {
		return nil
	}

	type shadowPayload struct {
		Type      string    `json:"type"`
		Version   int       `json:"version"`
		MessageID int64     `json:"message_id"`
		AgentID   string    `json:"agent_id"`
		SessionID int64     `json:"session_id,omitempty"`
		Scope     string    `json:"scope"`
		Attempt   int       `json:"attempt"`
		MaxAttempts int     `json:"max_attempts"`
		DedupeKey string    `json:"dedupe_key"`
		Task      ai.Task   `json:"task"`
		CreatedAt time.Time `json:"created_at"`
	}

	maxAttempts := cfg.QueueAgentChatMaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 4
	}

	dedupeKey := strings.TrimSpace(task.TaskID)
	if dedupeKey == "" {
		dedupeKey = fmt.Sprintf("chatmsg-%d", message.ID)
	}

	body, err := json.Marshal(shadowPayload{
		Type:      "agent_chat_task",
		Version:   1,
		MessageID: message.ID,
		AgentID:   message.AgentID,
		SessionID: message.SessionID,
		Scope:     message.Scope,
		Attempt:   0,
		MaxAttempts: maxAttempts,
		DedupeKey: dedupeKey,
		Task:      task,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("shadow payload marshal failed: %w", err)
	}

	publishCtx, cancel := context.WithTimeout(ctx, personalChatShadowPublishTimeout)
	defer cancel()

	subject := strings.TrimSpace(cfg.QueueAgentChatSubject)
	if subject == "" {
		subject = "agent.chat.shadow"
	}

	if err := publisher.Publish(publishCtx, subject, body); err != nil {
		return fmt.Errorf("shadow publish failed: %w", err)
	}

	return nil
}

func buildPersonalChatInstruction(ctx context.Context, agentID, currentMessage string) (string, error) {
	currentMessage = strings.TrimSpace(currentMessage)
	if currentMessage == "" {
		return "", nil
	}

	messages, err := server.ListChatMessages(ctx, server.ChatScopeAgent, agentID, personalChatContextFetchLimit)
	if err != nil {
		return "", err
	}

	if len(messages) == 0 {
		return currentMessage, nil
	}

	older := messages
	recent := messages
	if len(messages) > personalChatRecentTurns {
		split := len(messages) - personalChatRecentTurns
		older = messages[:split]
		recent = messages[split:]
	} else {
		older = nil
	}

	lines := make([]string, 0, len(recent))
	for _, msg := range recent {
		sender := normalizeChatSender(msg.Sender)
		content := truncateText(strings.TrimSpace(msg.Message), 220)
		if content == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("- %s: %s", sender, content))
	}

	var olderSummary string
	if len(older) > 0 {
		summaryLines := make([]string, 0, personalChatSummaryLineLimit)
		start := 0
		if len(older) > personalChatSummaryLineLimit {
			start = len(older) - personalChatSummaryLineLimit
		}
		for _, msg := range older[start:] {
			sender := normalizeChatSender(msg.Sender)
			content := truncateText(strings.TrimSpace(msg.Message), 140)
			if content == "" {
				continue
			}
			summaryLines = append(summaryLines, fmt.Sprintf("- %s discussed: %s", sender, content))
		}
		olderSummary = strings.Join(summaryLines, "\n")
	}

	b := &strings.Builder{}
	b.WriteString("Current user message:\n")
	b.WriteString(currentMessage)
	b.WriteString("\n\nConversation memory:\n")
	if strings.TrimSpace(olderSummary) != "" {
		b.WriteString("Earlier summary:\n")
		b.WriteString(olderSummary)
		b.WriteString("\n\n")
	}
	b.WriteString("Recent turns:\n")
	if len(lines) == 0 {
		b.WriteString("- (none)")
	} else {
		b.WriteString(strings.Join(lines, "\n"))
	}
	b.WriteString("\n\nRespond to the Current user message using the conversation memory when relevant.")

	instruction := b.String()
	if len(instruction) > personalChatInstructionMaxChars {
		instruction = instruction[:personalChatInstructionMaxChars]
	}

	return instruction, nil
}

func normalizeChatSender(sender string) string {
	s := strings.TrimSpace(strings.ToLower(sender))
	if strings.HasPrefix(s, "agent:") {
		return "assistant"
	}
	return "user"
}

func truncateText(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 || len(value) <= max {
		return value
	}
	if max <= 3 {
		return value[:max]
	}
	return strings.TrimSpace(value[:max-3]) + "..."
}

func isAgentChatCommandAllowed(ctx context.Context, agentID, message string) (bool, string, error) {
	commandName, isCommand := extractCommandNameFromChat(message)
	if !isCommand {
		return true, "", nil
	}

	policy, err := server.GetMergedCommandPolicyForAgent(ctx, agentID)
	if err != nil {
		return false, "", err
	}

	if matchesPolicyRule(commandName, policy.Denylist) {
		return false, fmt.Sprintf("%s is denied", commandName), nil
	}

	if len(policy.Allowlist) > 0 && !matchesPolicyRule(commandName, policy.Allowlist) {
		return false, fmt.Sprintf("%s is not in allowlist", commandName), nil
	}

	return true, "", nil
}

func buildGovernanceCommandQueryReply(ctx context.Context, agentID, message string) (string, bool, error) {
	commandName, ok := extractGovernanceQueryCommand(message)
	if !ok {
		return "", false, nil
	}

	policy, err := server.GetMergedCommandPolicyForAgent(ctx, agentID)
	if err != nil {
		return "", false, err
	}

	allowed := true
	reason := "allowed (no matching deny rule)"

	if matchesPolicyRule(commandName, policy.Denylist) {
		allowed = false
		reason = "blocked by denylist"
	} else if len(policy.Allowlist) > 0 && !matchesPolicyRule(commandName, policy.Allowlist) {
		allowed = false
		reason = "not present in allowlist"
	}

	status := "ALLOWED"
	if !allowed {
		status = "NOT ALLOWED"
	}

	allowText := "(empty)"
	if len(policy.Allowlist) > 0 {
		allowText = strings.Join(policy.Allowlist, ", ")
	}

	denyText := "(empty)"
	if len(policy.Denylist) > 0 {
		denyText = strings.Join(policy.Denylist, ", ")
	}

	reply := fmt.Sprintf(
		"Governance check for command '%s': %s\nReason: %s\nAllowlist: %s\nDenylist: %s",
		commandName,
		status,
		reason,
		allowText,
		denyText,
	)

	return reply, true, nil
}

func extractGovernanceQueryCommand(message string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(message))
	if lower == "" {
		return "", false
	}

	if !strings.Contains(lower, "allow") || !strings.Contains(lower, "command") {
		return "", false
	}

	commandBefore := regexp.MustCompile(`(?i)\b([a-z0-9._-]+)\s+command\b`)
	if matches := commandBefore.FindStringSubmatch(lower); len(matches) == 2 {
		candidate := strings.TrimSpace(matches[1])
		if candidate != "" && candidate != "is" && candidate != "the" {
			return candidate, true
		}
	}

	commandAfter := regexp.MustCompile(`(?i)\bcommand\s+([a-z0-9._-]+)\b`)
	if matches := commandAfter.FindStringSubmatch(lower); len(matches) == 2 {
		candidate := strings.TrimSpace(matches[1])
		if candidate != "" {
			return candidate, true
		}
	}

	return "", false
}

func extractCommandNameFromChat(message string) (string, bool) {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return "", false
	}

	lower := strings.ToLower(trimmed)

	if strings.HasPrefix(lower, "cmd:") {
		payload := strings.TrimSpace(trimmed[len("cmd:"):])
		return firstCommandToken(payload)
	}

	if strings.HasPrefix(lower, "powershell:") {
		payload := strings.TrimSpace(trimmed[len("powershell:"):])
		return firstCommandToken(payload)
	}

	if strings.HasPrefix(lower, "shell:") {
		payload := strings.TrimSpace(trimmed[len("shell:"):])
		return firstCommandToken(payload)
	}

	if strings.Contains(lower, "ping") {
		if detectPingTarget(message) != "" {
			return "ping", true
		}
	}

	return "", false
}

func firstCommandToken(payload string) (string, bool) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return "", false
	}

	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return "", false
	}

	command := strings.ToLower(strings.TrimSpace(parts[0]))
	if command == "" {
		return "", false
	}
	return command, true
}

func matchesPolicyRule(command string, rules []string) bool {
	command = strings.ToLower(strings.TrimSpace(command))
	if command == "" {
		return false
	}

	for _, rule := range rules {
		normalized := strings.ToLower(strings.TrimSpace(rule))
		if normalized == "" {
			continue
		}
		if normalized == "*" || normalized == command {
			return true
		}
		if strings.HasSuffix(normalized, "*") {
			prefix := strings.TrimSuffix(normalized, "*")
			if prefix != "" && strings.HasPrefix(command, prefix) {
				return true
			}
		}
	}

	return false
}

func detectPingTarget(message string) string {
	lower := strings.ToLower(message)
	if strings.Contains(lower, "google dns") || strings.Contains(lower, "google public dns") {
		return "8.8.8.8"
	}

	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	if ip := ipRegex.FindString(message); ip != "" {
		return ip
	}

	targetRegex := regexp.MustCompile(`(?i)\bping(?:\s+to)?\s+([a-z0-9.-]+)\b`)
	matches := targetRegex.FindStringSubmatch(message)
	if len(matches) == 2 {
		candidate := strings.TrimSpace(matches[1])
		if candidate != "" {
			return candidate
		}
	}

	return ""
}
