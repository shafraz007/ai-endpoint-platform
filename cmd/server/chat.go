package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/ai"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

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

func handleChatList(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	_, _, err := authorizeAdminRequest(w, r, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	scope := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope")))
	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
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

	messages, err := server.ListChatMessages(ctx, scope, agentID, limit)
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

	item, err := server.CreateChatMessage(ctx, req.Scope, req.AgentID, user.Username, req.Message)
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
			} else if err := queueAgentChatTask(ctx, item); err != nil {
				log.Printf("queue agent chat task failed: %v", err)
				http.Error(w, "Failed to queue agent response", http.StatusInternalServerError)
				return
			}
		}
	}

	resp := transport.ChatMessage{
		ID:        item.ID,
		Scope:     item.Scope,
		AgentID:   item.AgentID,
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

func queueAgentChatTask(ctx context.Context, message *server.ChatMessage) error {
	if message == nil {
		return fmt.Errorf("message is required")
	}
	if strings.TrimSpace(message.AgentID) == "" {
		return fmt.Errorf("agentID is required")
	}

	task := ai.Task{
		TaskID:      fmt.Sprintf("chatmsg-%d", message.ID),
		MotherRole:  ai.MotherInstructor,
		ChildIntent: ai.ChildSuggest,
		Title:       "Respond to personal chat",
		Instruction: message.Message,
		Context:     "personal_chat",
	}

	payload, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("failed to serialize ai_task payload: %w", err)
	}

	_, err = server.CreateCommand(ctx, message.AgentID, "ai_task", string(payload))
	if err != nil {
		return fmt.Errorf("failed to queue ai_task command: %w", err)
	}

	return nil
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
