package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/agent"
	"github.com/shafraz007/ai-endpoint-platform/internal/ai"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
)

func executePersonalChatV2(task *ai.Task, cfg config.AgentConfig, sysInfo *agent.SystemInfo, osInfo *agent.OSInfo) (string, error) {
	result := ai.ChildResult{
		TaskID:      task.TaskID,
		ChildIntent: task.ChildIntent,
		State:       "completed",
		Summary:     "Agent response",
		Timestamp:   time.Now(),
	}

	userPrompt := strings.TrimSpace(extractCurrentUserMessage(task.Instruction))
	if userPrompt == "" {
		userPrompt = strings.TrimSpace(task.Instruction)
	}

	if commandResponse, handled := tryHandlePersonalChatCommand(userPrompt, cfg); handled {
		result.Details = commandResponse
		appendPersonalChatMemory(userPrompt, commandResponse)
		if task.RequiresApproval {
			result.State = "awaiting_approval"
		}
		return marshalChildResult(result)
	}

	response, aiErr := generateAIChatResponse(userPrompt, cfg, sysInfo, osInfo)
	if aiErr != nil {
		log.Printf("AI chat v2 response failed, using fallback: %v", aiErr)
		fallbackInput := strings.TrimSpace(userPrompt)
		if fallbackInput == "" {
			fallbackInput = strings.TrimSpace(task.Instruction)
		}
		response = buildPersonalChatTimeoutIsolatedReply(fallbackInput, cfg, sysInfo, osInfo, aiErr)
	}

	if looksLikeFabricatedCommandResult(response) {
		response = "I did not execute a local command for this request. Use an explicit command prefix: `cmd:`, `powershell:`, or `shell:`."
	}

	result.Details = response
	appendPersonalChatMemory(userPrompt, response)
	if task.RequiresApproval {
		result.State = "awaiting_approval"
	}

	return marshalChildResult(result)
}

func marshalChildResult(result ai.ChildResult) (string, error) {
	body, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to serialize ai_task result: %w", err)
	}

	return string(body), nil
}
