package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/agent"
	"github.com/shafraz007/ai-endpoint-platform/internal/ai"
	"github.com/shafraz007/ai-endpoint-platform/internal/auth"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/logging"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

const maxCommandOutput = 64 * 1024

func main() {
	cfg := config.LoadAgentConfig()
	logCloser, err := logging.Setup("agent", cfg.LogDir, cfg.LogToConsole)
	if err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}
	defer logCloser.Close()

	// Get system information
	sysInfo, err := agent.GetSystemInfo()
	if err != nil {
		log.Fatalf("Failed to get system info: %v", err)
	}

	// Collect OS and security information
	osInfo := agent.CollectOSInfo()
	log.Printf("OS Info collected - Edition: %s, Build: %s", osInfo.OSEdition, osInfo.OSBuild)

	log.Printf("Agent started - ID: %s, Hostname: %s, Version: %s", sysInfo.AgentID, sysInfo.Hostname, sysInfo.AgentVersion)
	log.Printf("Server URL: %s, Heartbeat interval: %v", cfg.ServerURL, cfg.HeartbeatInterval)

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: cfg.RequestTimeout,
	}

	metricsCollector := agent.NewMetricsCollector()

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	heartbeatTicker := time.NewTicker(cfg.HeartbeatInterval)
	defer heartbeatTicker.Stop()

	metricsTicker := time.NewTicker(cfg.MetricsInterval)
	defer metricsTicker.Stop()

	var commandTick <-chan time.Time
	if cfg.JWTSecret != "" {
		commandTicker := time.NewTicker(cfg.CommandPollInterval)
		defer commandTicker.Stop()
		commandTick = commandTicker.C
	} else {
		log.Printf("Command polling disabled: AGENT_JWT_SECRET not set")
	}

	go func() {
		<-sigChan
		log.Println("Shutdown signal received")
		cancel()
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("Agent stopped")
			return
		case <-heartbeatTicker.C:
			hb := transport.HeartbeatRequest{
				AgentID:              sysInfo.AgentID,
				Hostname:             sysInfo.Hostname,
				Domain:               sysInfo.Domain,
				PublicIP:             sysInfo.PublicIP,
				PrivateIP:            sysInfo.PrivateIP,
				LastLogin:            sysInfo.LastLogin,
				LastReboot:           sysInfo.LastReboot,
				Timezone:             sysInfo.Timezone,
				AgentVersion:         sysInfo.AgentVersion,
				LastSeen:             time.Now(),
				Timestamp:            time.Now(),
				Status:               "online",
				HardwareVendor:       sysInfo.HardwareVendor,
				HardwareModel:        sysInfo.HardwareModel,
				HardwareSerialNumber: sysInfo.HardwareSerialNumber,
				Motherboard:          sysInfo.Motherboard,
				BIOSManufacturer:     sysInfo.BIOSManufacturer,
				BIOSVersion:          sysInfo.BIOSVersion,
				BIOSVersionDate:      sysInfo.BIOSVersionDate,
				Processor:            sysInfo.Processor,
				Memory:               sysInfo.Memory,
				VideoCard:            sysInfo.VideoCard,
				Sound:                sysInfo.Sound,
				SystemDrive:          sysInfo.SystemDrive,
				MACAddresses:         sysInfo.MACAddresses,
				Disks:                sysInfo.DisksJSON,
				Drives:               sysInfo.DrivesJSON,
				OSEdition:            osInfo.OSEdition,
				OSVersion:            osInfo.OSVersion,
				OSBuild:              osInfo.OSBuild,
				Windows11Eligible:    osInfo.Windows11Eligible,
				TLS12Compatible:      osInfo.TLS12Compatible,
				DotNetVersion:        osInfo.DotNetVersion,
				OfficeVersion:        osInfo.OfficeVersion,
				AntivirusName:        osInfo.AntivirusName,
				AntiSpywareName:      osInfo.AntiSpywareName,
				FirewallName:         osInfo.FirewallName,
			}
			sendHeartbeatWithRetry(httpClient, cfg, hb)
		case <-metricsTicker.C:
			sendMetrics(httpClient, cfg, sysInfo.AgentID, metricsCollector)
		case <-commandTick:
			pollAndExecuteCommand(httpClient, cfg, sysInfo.AgentID, sysInfo, osInfo)
		}
	}
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Warning: Failed to get hostname: %v", err)
		return "unknown"
	}
	return hostname
}

func sendHeartbeatWithRetry(httpClient *http.Client, cfg config.AgentConfig, hb transport.HeartbeatRequest) {
	var lastErr error

	for attempt := 1; attempt <= cfg.MaxRetries; attempt++ {
		if err := sendHeartbeat(httpClient, cfg.ServerURL, hb); err == nil {
			return // Success
		} else {
			lastErr = err
			if attempt < cfg.MaxRetries {
				backoff := time.Duration(attempt) * cfg.RetryBackoffSeconds
				log.Printf("Heartbeat attempt %d failed: %v, retrying in %v", attempt, err, backoff)
				time.Sleep(backoff)
			}
		}
	}

	log.Printf("Failed to send heartbeat after %d attempts: %v", cfg.MaxRetries, lastErr)
}

func sendHeartbeat(httpClient *http.Client, serverURL string, hb transport.HeartbeatRequest) error {
	jsonData, err := json.Marshal(hb)
	if err != nil {
		return err
	}

	url := strings.TrimRight(serverURL, "/") + "/api/heartbeat"

	resp, err := httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}

	log.Printf("Heartbeat sent successfully")
	return nil
}

func sendMetrics(httpClient *http.Client, cfg config.AgentConfig, agentID string, collector *agent.MetricsCollector) {
	if cfg.JWTSecret == "" {
		return
	}

	snapshot, err := collector.Sample()
	if err != nil {
		log.Printf("Metrics sample failed: %v", err)
		return
	}

	token, err := auth.GenerateToken(agentID, "agent", cfg.JWTSecret, cfg.JWTTTL)
	if err != nil {
		log.Printf("Failed to generate agent token: %v", err)
		return
	}

	metrics := transport.MetricsSample{
		AgentID:              agentID,
		Timestamp:            time.Now(),
		CPUPercent:           snapshot.CPUPercent,
		MemoryUsedPercent:    snapshot.MemoryUsedPercent,
		MemoryUsedBytes:      snapshot.MemoryUsedBytes,
		MemoryTotalBytes:     snapshot.MemoryTotalBytes,
		NetBytesSentPerSec:   snapshot.NetBytesSentPerSec,
		NetBytesRecvPerSec:   snapshot.NetBytesRecvPerSec,
		NetPacketsSentPerSec: snapshot.NetPacketsSentPerSec,
		NetPacketsRecvPerSec: snapshot.NetPacketsRecvPerSec,
	}

	jsonData, err := json.Marshal(metrics)
	if err != nil {
		log.Printf("Failed to serialize metrics: %v", err)
		return
	}

	url := strings.TrimRight(cfg.ServerURL, "/") + "/api/metrics"
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create metrics request: %v", err)
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(request)
	if err != nil {
		log.Printf("Metrics send failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		log.Printf("Metrics send HTTP %s", resp.Status)
	}
}

func pollAndExecuteCommand(httpClient *http.Client, cfg config.AgentConfig, agentID string, sysInfo *agent.SystemInfo, osInfo *agent.OSInfo) {
	if cfg.JWTSecret == "" {
		return
	}

	token, err := auth.GenerateToken(agentID, "agent", cfg.JWTSecret, cfg.JWTTTL)
	if err != nil {
		log.Printf("Failed to generate agent token: %v", err)
		return
	}

	url := strings.TrimRight(cfg.ServerURL, "/") + "/api/commands/next"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Printf("Failed to create command poll request: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("Command poll failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("Command poll HTTP %s", resp.Status)
		return
	}

	var cmd transport.Command
	if err := json.NewDecoder(resp.Body).Decode(&cmd); err != nil {
		log.Printf("Failed to decode command: %v", err)
		return
	}

	status, output, errMsg := executeCommand(cmd, cfg, sysInfo, osInfo)
	ack := transport.CommandAckRequest{
		CommandID: cmd.ID,
		Status:    status,
		Output:    output,
		Error:     errMsg,
	}

	if err := sendCommandAck(httpClient, cfg.ServerURL, token, ack); err != nil {
		log.Printf("Failed to ack command: %v", err)
	}
}

func executeCommand(cmd transport.Command, cfg config.AgentConfig, sysInfo *agent.SystemInfo, osInfo *agent.OSInfo) (string, string, string) {
	switch strings.ToLower(cmd.CommandType) {
	case "ping":
		return "succeeded", "pong", ""
	case "echo":
		return "succeeded", cmd.Payload, ""
	case "shell":
		output, err := runShellCommand(cmd.Payload, cfg.CommandTimeout)
		if err != nil {
			return "failed", output, err.Error()
		}
		return "succeeded", output, ""
	case "cmd":
		output, err := runCmdCommand(cmd.Payload, cfg.CommandTimeout)
		if err != nil {
			return "failed", output, err.Error()
		}
		return "succeeded", output, ""
	case "powershell":
		output, err := runPowerShellCommand(cmd.Payload, cfg.CommandTimeout)
		if err != nil {
			return "failed", output, err.Error()
		}
		return "succeeded", output, ""
	case "restart":
		if err := restartSystem(); err != nil {
			return "failed", "", fmt.Sprintf("restart failed: %v", err)
		}
		return "succeeded", "System restart initiated", ""
	case "shutdown":
		if err := shutdownSystem(); err != nil {
			return "failed", "", fmt.Sprintf("shutdown failed: %v", err)
		}
		return "succeeded", "System shutdown initiated", ""
	case "ai_task":
		output, err := executeAITask(cmd.Payload, cfg, sysInfo, osInfo)
		if err != nil {
			return "failed", "", err.Error()
		}
		return "succeeded", output, ""
	default:
		return "failed", "", "unsupported command type"
	}
}

func executeAITask(payload string, cfg config.AgentConfig, sysInfo *agent.SystemInfo, osInfo *agent.OSInfo) (string, error) {
	task, err := ai.ParseTaskPayload(payload)
	if err != nil {
		return "", err
	}

	result := ai.ChildResult{
		TaskID:      task.TaskID,
		ChildIntent: task.ChildIntent,
		State:       "completed",
		Timestamp:   time.Now(),
	}

	if strings.EqualFold(strings.TrimSpace(task.Context), "personal_chat") {
		if commandResponse, handled := tryHandlePersonalChatCommand(task.Instruction, cfg); handled {
			result.Summary = "Agent response"
			result.Details = commandResponse
			if task.RequiresApproval {
				result.State = "awaiting_approval"
			}

			body, err := json.Marshal(result)
			if err != nil {
				return "", fmt.Errorf("failed to serialize ai_task result: %w", err)
			}

			return string(body), nil
		}

		response, aiErr := generateAIChatResponse(task.Instruction, cfg, sysInfo, osInfo)
		if aiErr != nil {
			log.Printf("AI chat response failed, using fallback: %v", aiErr)
			response = "I received your message: " + task.Instruction
		}

		result.Summary = "Agent response"
		result.Details = response
		if task.RequiresApproval {
			result.State = "awaiting_approval"
		}

		body, err := json.Marshal(result)
		if err != nil {
			return "", fmt.Errorf("failed to serialize ai_task result: %w", err)
		}

		return string(body), nil
	}

	switch task.ChildIntent {
	case ai.ChildWork:
		result.Summary = "Child agent executed the requested work task"
		result.Details = task.Instruction
	case ai.ChildResolve:
		result.Summary = "Child agent analyzed and resolved the requested issue"
		result.Details = task.Instruction
	case ai.ChildSuggest:
		result.Summary = "Child agent generated a suggestion for the requested objective"
		result.Details = task.Instruction
	case ai.ChildIdentify:
		result.Summary = "Child agent identified findings from the provided context"
		result.Details = task.Instruction
	case ai.ChildComplain:
		result.State = "blocked"
		result.Summary = "Child agent reported a blocker or concern"
		result.Details = task.Instruction
	default:
		return "", fmt.Errorf("unsupported child_intent")
	}

	if task.RequiresApproval {
		result.State = "awaiting_approval"
	}

	body, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to serialize ai_task result: %w", err)
	}

	return string(body), nil
}

func tryHandlePersonalChatCommand(message string, cfg config.AgentConfig) (string, bool) {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return "", false
	}

	lower := strings.ToLower(trimmed)

	if strings.HasPrefix(lower, "cmd:") {
		cmd := strings.TrimSpace(trimmed[len("cmd:"):])
		if cmd == "" {
			return "Command execution failed: empty cmd command", true
		}
		return executeAndFormatCommand("cmd", cmd, cfg)
	}

	if strings.HasPrefix(lower, "powershell:") {
		cmd := strings.TrimSpace(trimmed[len("powershell:"):])
		if cmd == "" {
			return "Command execution failed: empty powershell command", true
		}
		return executeAndFormatCommand("powershell", cmd, cfg)
	}

	if strings.HasPrefix(lower, "shell:") {
		cmd := strings.TrimSpace(trimmed[len("shell:"):])
		if cmd == "" {
			return "Command execution failed: empty shell command", true
		}
		return executeAndFormatCommand("shell", cmd, cfg)
	}

	if strings.Contains(lower, "ping") {
		target := detectPingTarget(trimmed)
		if target != "" {
			cmd := fmt.Sprintf("ping -n 4 %s", target)
			return executeAndFormatCommand("cmd", cmd, cfg)
		}
	}

	return "", false
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

func executeAndFormatCommand(commandType, command string, cfg config.AgentConfig) (string, bool) {
	var (
		output string
		err    error
	)

	switch commandType {
	case "cmd":
		output, err = runCmdCommand(command, cfg.CommandTimeout)
	case "powershell":
		output, err = runPowerShellCommand(command, cfg.CommandTimeout)
	case "shell":
		output, err = runShellCommand(command, cfg.CommandTimeout)
	default:
		return "Unsupported command type", true
	}

	trimmedOutput := strings.TrimSpace(output)
	if err != nil {
		if trimmedOutput == "" {
			trimmedOutput = err.Error()
		}
		return fmt.Sprintf("Command execution failed (%s):\n%s", command, trimmedOutput), true
	}

	if trimmedOutput == "" {
		trimmedOutput = "(no output)"
	}

	return fmt.Sprintf("Command executed (%s):\n%s", command, trimmedOutput), true
}

func generateAIChatResponse(userMessage string, cfg config.AgentConfig, sysInfo *agent.SystemInfo, osInfo *agent.OSInfo) (string, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.AIProvider))
	if provider == "" {
		provider = "openai"
	}

	if provider != "ollama" && strings.TrimSpace(cfg.AIAPIKey) == "" {
		return "", fmt.Errorf("AGENT_AI_API_KEY is not configured")
	}

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

	messages := []chatMsg{{Role: "system", Content: cfg.AISystemPrompt}}
	if deviceContext := buildPersonalChatContext(sysInfo, osInfo); deviceContext != "" {
		messages = append(messages, chatMsg{Role: "system", Content: deviceContext})
	}
	messages = append(messages, chatMsg{Role: "user", Content: userMessage})

	reqPayload := chatRequest{
		Model:       strings.TrimSpace(cfg.AIModel),
		Messages:    messages,
		Temperature: 0.4,
	}
	if reqPayload.Model == "" {
		reqPayload.Model = "gpt-4o-mini"
	}

	requestURL, headers, err := buildAIRequestTargetAndHeaders(provider, cfg)
	if err != nil {
		return "", err
	}

	body, err := json.Marshal(reqPayload)
	if err != nil {
		return "", fmt.Errorf("failed to serialize AI request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.CommandTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("failed to create AI request: %w", err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: cfg.RequestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("AI request failed: %w", err)
	}
	defer resp.Body.Close()

	var response chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to parse AI response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if response.Error != nil && strings.TrimSpace(response.Error.Message) != "" {
			return "", fmt.Errorf("AI API error: %s", response.Error.Message)
		}
		return "", fmt.Errorf("AI API HTTP %d", resp.StatusCode)
	}

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("AI response has no choices")
	}

	content := strings.TrimSpace(response.Choices[0].Message.Content)
	if content == "" {
		return "", fmt.Errorf("AI response content is empty")
	}

	return content, nil
}

func buildPersonalChatContext(sysInfo *agent.SystemInfo, osInfo *agent.OSInfo) string {
	if sysInfo == nil && osInfo == nil {
		return ""
	}

	parts := []string{
		"You are the AI assistant for THIS endpoint device. Use this local device profile when answering health/status questions.",
	}

	if sysInfo != nil {
		parts = append(parts,
			fmt.Sprintf("Agent ID: %s", strings.TrimSpace(sysInfo.AgentID)),
			fmt.Sprintf("Hostname: %s", strings.TrimSpace(sysInfo.Hostname)),
			fmt.Sprintf("Domain: %s", strings.TrimSpace(sysInfo.Domain)),
			fmt.Sprintf("Private IP: %s", strings.TrimSpace(sysInfo.PrivateIP)),
			fmt.Sprintf("Public IP: %s", strings.TrimSpace(sysInfo.PublicIP)),
			fmt.Sprintf("Timezone: %s", strings.TrimSpace(sysInfo.Timezone)),
			fmt.Sprintf("OS/Hardware: %s | %s | CPU: %s | RAM: %s", strings.TrimSpace(sysInfo.HardwareVendor), strings.TrimSpace(sysInfo.HardwareModel), strings.TrimSpace(sysInfo.Processor), strings.TrimSpace(sysInfo.Memory)),
			fmt.Sprintf("System drive: %s", strings.TrimSpace(sysInfo.SystemDrive)),
		)
	}

	if osInfo != nil {
		parts = append(parts,
			fmt.Sprintf("Windows Edition: %s", strings.TrimSpace(osInfo.OSEdition)),
			fmt.Sprintf("Windows Version: %s", strings.TrimSpace(osInfo.OSVersion)),
			fmt.Sprintf("Windows Build: %s", strings.TrimSpace(osInfo.OSBuild)),
			fmt.Sprintf("Windows 11 Eligible: %s", strings.TrimSpace(osInfo.Windows11Eligible)),
			fmt.Sprintf("Security: AV=%s | AntiSpyware=%s | Firewall=%s", strings.TrimSpace(osInfo.AntivirusName), strings.TrimSpace(osInfo.AntiSpywareName), strings.TrimSpace(osInfo.FirewallName)),
		)
	}

	parts = append(parts, "If the user asks about device health/status, explicitly reference this endpoint profile (hostname, OS edition/version/build, CPU, RAM) in the answer. Mention limits only when necessary.")

	return strings.Join(parts, "\n")
}

func buildAIRequestTargetAndHeaders(provider string, cfg config.AgentConfig) (string, map[string]string, error) {
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	switch provider {
	case "ollama":
		endpoint := strings.TrimSpace(cfg.AIEndpoint)
		if endpoint == "" {
			endpoint = "http://localhost:11434/v1/chat/completions"
		}
		return endpoint, headers, nil

	case "azure_openai", "azure":
		endpoint := strings.TrimSpace(cfg.AIEndpoint)
		deployment := strings.TrimSpace(cfg.AIDeployment)
		if endpoint == "" || deployment == "" {
			return "", nil, fmt.Errorf("AGENT_AI_ENDPOINT and AGENT_AI_DEPLOYMENT are required for Azure OpenAI")
		}

		base := strings.TrimRight(endpoint, "/")
		target := fmt.Sprintf("%s/openai/deployments/%s/chat/completions", base, url.PathEscape(deployment))

		parsed, err := url.Parse(target)
		if err != nil {
			return "", nil, fmt.Errorf("invalid Azure AI endpoint: %w", err)
		}

		query := parsed.Query()
		if query.Get("api-version") == "" {
			apiVersion := strings.TrimSpace(cfg.AIApiVersion)
			if apiVersion == "" {
				apiVersion = "2024-02-15-preview"
			}
			query.Set("api-version", apiVersion)
		}
		parsed.RawQuery = query.Encode()

		headers["api-key"] = cfg.AIAPIKey
		return parsed.String(), headers, nil

	case "openai":
		fallthrough
	default:
		endpoint := strings.TrimSpace(cfg.AIEndpoint)
		if endpoint == "" {
			return "", nil, fmt.Errorf("AGENT_AI_ENDPOINT is not configured")
		}
		headers["Authorization"] = "Bearer " + cfg.AIAPIKey
		return endpoint, headers, nil
	}
}

func runShellCommand(command string, timeout time.Duration) (string, error) {
	if runtime.GOOS == "windows" {
		return executeThroughShell(timeout, "cmd", "/C", command)
	}

	return executeThroughShell(timeout, "sh", "-c", command)
}

func runCmdCommand(command string, timeout time.Duration) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("cmd command_type is only supported on Windows")
	}

	return executeThroughShell(timeout, "cmd", "/C", command)
}

func runPowerShellCommand(command string, timeout time.Duration) (string, error) {
	if runtime.GOOS == "windows" {
		return executeThroughShell(timeout, "powershell", "-NoProfile", "-Command", command)
	}

	return executeThroughShell(timeout, "pwsh", "-NoProfile", "-Command", command)
}

func executeThroughShell(timeout time.Duration, executable string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	execCmd := exec.CommandContext(ctx, executable, args...)
	outputBytes, err := execCmd.CombinedOutput()
	output := truncateOutput(string(outputBytes))

	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("command timed out")
	}
	if err != nil {
		return output, err
	}

	return output, nil
}

func truncateOutput(output string) string {
	if len(output) <= maxCommandOutput {
		return output
	}
	return output[:maxCommandOutput] + "\n...truncated"
}

func restartSystem() error {
	if runtime.GOOS == "windows" {
		// Windows: shutdown /r /t 10 /c "Restart initiated by agent"
		cmd := exec.Command("shutdown", "/r", "/t", "10", "/c", "Restart initiated by agent")
		if err := cmd.Run(); err != nil {
			return err
		}
	} else {
		// Unix/Linux: Use shutdown command
		cmd := exec.Command("shutdown", "-r", "+1", "Restart initiated by agent")
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

func shutdownSystem() error {
	if runtime.GOOS == "windows" {
		// Windows: shutdown /s /t 10 /c "Shutdown initiated by agent"
		cmd := exec.Command("shutdown", "/s", "/t", "10", "/c", "Shutdown initiated by agent")
		if err := cmd.Run(); err != nil {
			return err
		}
	} else {
		// Unix/Linux: Use shutdown command
		cmd := exec.Command("shutdown", "-h", "+1", "Shutdown initiated by agent")
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

func sendCommandAck(httpClient *http.Client, serverURL, token string, ack transport.CommandAckRequest) error {
	jsonData, err := json.Marshal(ack)
	if err != nil {
		return err
	}

	url := strings.TrimRight(serverURL, "/") + "/api/commands/ack"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("ack HTTP %s", resp.Status)
	}

	return nil
}
