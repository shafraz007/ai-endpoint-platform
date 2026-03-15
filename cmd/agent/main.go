package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
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

const personalChatMemoryMaxTurns = 20
const pendingCommandTTL = 5 * time.Minute

type personalChatTurn struct {
	user      string
	assistant string
}

type personalChatCommandProposal struct {
	Action      string
	CommandType string
	Command     string
	CreatedAt   time.Time
}

var (
	personalChatMemoryMu sync.Mutex
	personalChatMemory   []personalChatTurn
	pendingCommandMu     sync.Mutex
	pendingCommand       *personalChatCommandProposal
)

func main() {
	cfg := config.LoadAgentConfig()
	logCloser, err := logging.Setup("agent", cfg.LogDir, cfg.LogToConsole)
	if err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}
	defer logCloser.Close()

	releaseSingleton, err := acquireProcessSingleton("ai-endpoint-platform-agent")
	if err != nil {
		log.Fatalf("Agent startup blocked: %v", err)
	}
	defer releaseSingleton()

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

	lastPatchScanAt := time.Time{}
	lastPatchScanAtPtr := (*time.Time)(nil)
	cachedPendingUpdates := []transport.PendingUpdate{}
	cachedRebootRequired := false

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
			lastLogin, lastReboot := agent.GetLoginAndRebootTimes()
			sysInfo.LastLogin = lastLogin
			sysInfo.LastReboot = lastReboot

			if lastPatchScanAt.IsZero() || time.Since(lastPatchScanAt) >= 30*time.Minute {
				updates, rebootRequired, scanErr := agent.CollectPendingUpdates()
				if scanErr != nil {
					log.Printf("Pending update scan failed: %v", scanErr)
				} else {
					mapped := make([]transport.PendingUpdate, 0, len(updates))
					for _, item := range updates {
						mapped = append(mapped, transport.PendingUpdate{
							UpdateID:       item.UpdateID,
							KBID:           item.KBID,
							Title:          item.Title,
							Description:    item.Description,
							Severity:       item.Severity,
							Categories:     item.Categories,
							IsDriver:       item.IsDriver,
							IsSecurity:     item.IsSecurity,
							IsCritical:     item.IsCritical,
							IsOS:           item.IsOS,
							IsSoftware:     item.IsSoftware,
							RebootRequired: item.RebootRequired,
						})
					}
					now := time.Now().UTC()
					lastPatchScanAt = now
					lastPatchScanAtPtr = &lastPatchScanAt
					cachedPendingUpdates = mapped
					cachedRebootRequired = rebootRequired
				}
			}

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
				PatchScanAt:          lastPatchScanAtPtr,
				RebootRequired:       cachedRebootRequired,
				PendingUpdates:       cachedPendingUpdates,
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
		CPUTemperatureC:      snapshot.CPUTemperatureC,
		DiskTemperatureC:     snapshot.DiskTemperatureC,
		DiskUsagePercent:     snapshot.DiskUsagePercent,
		FanCPURPM:            snapshot.FanCPURPM,
		FanSystemRPM:         snapshot.FanSystemRPM,
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
		trimmed := strings.TrimSpace(payload)
		if trimmed == "" {
			return "", err
		}

		title := trimmed
		if len(title) > 96 {
			title = title[:96]
		}

		task = &ai.Task{
			TaskID:      fmt.Sprintf("adhoc-%d", time.Now().Unix()),
			MotherRole:  ai.MotherScheduler,
			ChildIntent: ai.ChildWork,
			Title:       title,
			Instruction: trimmed,
			Context:     "scheduler",
		}
	}

	result := ai.ChildResult{
		TaskID:      task.TaskID,
		ChildIntent: task.ChildIntent,
		State:       "completed",
		Timestamp:   time.Now(),
	}

	if strings.EqualFold(strings.TrimSpace(task.Context), "personal_chat") {
		if strings.EqualFold(strings.TrimSpace(cfg.AIChatEngine), "legacy") {
			userPrompt := extractCurrentUserMessage(task.Instruction)
			if userPrompt == "" {
				userPrompt = strings.TrimSpace(task.Instruction)
			}

			if commandResponse, handled := tryHandlePersonalChatCommand(userPrompt, cfg); handled {
				result.Summary = "Agent response"
				result.Details = commandResponse
				appendPersonalChatMemory(userPrompt, commandResponse)
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
				fallbackInput := strings.TrimSpace(userPrompt)
				if fallbackInput == "" {
					fallbackInput = strings.TrimSpace(task.Instruction)
				}
				response = buildPersonalChatTimeoutIsolatedReply(fallbackInput, cfg, sysInfo, osInfo, aiErr)
			}
			if looksLikeFabricatedCommandResult(response) {
				response = "I did not execute a local command for this request. Use an explicit command prefix: `cmd:`, `powershell:`, or `shell:`."
			}
			appendPersonalChatMemory(userPrompt, response)

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

		return executePersonalChatV2(task, cfg, sysInfo, osInfo)
	}

	if task.ChildIntent != ai.ChildComplain {
		response, aiErr := generateAIChatResponse(task.Instruction, cfg, sysInfo, osInfo)
		if aiErr == nil {
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

		log.Printf("AI task response failed for intent %s, using fallback: %v", task.ChildIntent, aiErr)
	}

	switch task.ChildIntent {
	case ai.ChildWork:
		result.Summary = "Agent response"
		result.Details = buildFallbackTaskDetails(task.Instruction, sysInfo, osInfo)
	case ai.ChildResolve:
		result.Summary = "Agent response"
		result.Details = buildFallbackTaskDetails(task.Instruction, sysInfo, osInfo)
	case ai.ChildSuggest:
		result.Summary = "Agent response"
		result.Details = buildFallbackTaskDetails(task.Instruction, sysInfo, osInfo)
	case ai.ChildIdentify:
		result.Summary = "Agent response"
		result.Details = buildFallbackTaskDetails(task.Instruction, sysInfo, osInfo)
	case ai.ChildComplain:
		result.State = "blocked"
		result.Summary = "Child agent reported a blocker or concern"
		result.Details = buildFallbackTaskDetails(task.Instruction, sysInfo, osInfo)
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

	if proposed, ok := getPendingCommandProposal(); ok {
		if isNegativeConfirmation(trimmed) {
			clearPendingCommandProposal()
			return "Understood. I cancelled the pending command request.", true
		}

		if isAffirmativeConfirmation(trimmed) {
			clearPendingCommandProposal()
			return executeProposedCommand(*proposed, cfg)
		}

		display := formatDisplayCommand(proposed.CommandType, proposed.Command)
		return fmt.Sprintf("I have a pending request to run: %s. Reply with 'confirm' to run it or 'cancel' to skip.", display), true
	}

	if proposal, ok, errText := buildCommandProposal(trimmed); ok {
		if errText != "" {
			return errText, true
		}
		setPendingCommandProposal(proposal)
		display := formatDisplayCommand(proposal.CommandType, proposal.Command)
		return fmt.Sprintf("I can run this command: %s. Reply with 'confirm' to proceed or 'cancel' to abort.", display), true
	}

	return "", false
}

func executeProposedCommand(proposal personalChatCommandProposal, cfg config.AgentConfig) (string, bool) {
	switch proposal.Action {
	case "execute_command":
		return executeAndFormatCommand(proposal.CommandType, proposal.Command, cfg)
	default:
		return "Command execution failed: unsupported command request", true
	}
}

func buildCommandProposal(message string) (personalChatCommandProposal, bool, string) {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return personalChatCommandProposal{}, false, ""
	}

	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "cmd:") {
		cmd := strings.TrimSpace(trimmed[len("cmd:"):])
		if cmd == "" {
			return personalChatCommandProposal{}, true, "Command execution failed: empty cmd command"
		}
		return personalChatCommandProposal{Action: "execute_command", CommandType: "cmd", Command: cmd, CreatedAt: time.Now()}, true, ""
	}

	if strings.HasPrefix(lower, "powershell:") {
		cmd := strings.TrimSpace(trimmed[len("powershell:"):])
		if cmd == "" {
			return personalChatCommandProposal{}, true, "Command execution failed: empty powershell command"
		}
		return personalChatCommandProposal{Action: "execute_command", CommandType: "powershell", Command: cmd, CreatedAt: time.Now()}, true, ""
	}

	if strings.HasPrefix(lower, "shell:") {
		cmd := strings.TrimSpace(trimmed[len("shell:"):])
		if cmd == "" {
			return personalChatCommandProposal{}, true, "Command execution failed: empty shell command"
		}
		return personalChatCommandProposal{Action: "execute_command", CommandType: "shell", Command: cmd, CreatedAt: time.Now()}, true, ""
	}

	return personalChatCommandProposal{}, false, ""
}

func isCPUTemperatureRequest(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	if lower == "" {
		return false
	}
	if !(strings.Contains(lower, "temp") || strings.Contains(lower, "temperature")) {
		return false
	}
	if strings.Contains(lower, "cpu") || strings.Contains(lower, "processor") {
		return true
	}
	return strings.Contains(lower, "current") && strings.Contains(lower, "temperature")
}

func setPendingCommandProposal(proposal personalChatCommandProposal) {
	pendingCommandMu.Lock()
	defer pendingCommandMu.Unlock()
	pendingCommand = &proposal
}

func getPendingCommandProposal() (*personalChatCommandProposal, bool) {
	pendingCommandMu.Lock()
	defer pendingCommandMu.Unlock()
	if pendingCommand == nil {
		return nil, false
	}
	if time.Since(pendingCommand.CreatedAt) > pendingCommandTTL {
		pendingCommand = nil
		return nil, false
	}
	copyProposal := *pendingCommand
	return &copyProposal, true
}

func clearPendingCommandProposal() {
	pendingCommandMu.Lock()
	defer pendingCommandMu.Unlock()
	pendingCommand = nil
}

func isAffirmativeConfirmation(message string) bool {
	value := strings.ToLower(strings.TrimSpace(message))
	if value == "" {
		return false
	}
	if regexp.MustCompile(`^(yes|y|ok|okay|sure|confirm|confirmed|proceed|run it|do it|execute|go ahead)$`).MatchString(value) {
		return true
	}
	return strings.Contains(value, "please proceed") || strings.Contains(value, "please run") || strings.Contains(value, "please execute")
}

func isNegativeConfirmation(message string) bool {
	value := strings.ToLower(strings.TrimSpace(message))
	if value == "" {
		return false
	}
	if regexp.MustCompile(`^(no|n|cancel|stop|abort|don't run|do not run)$`).MatchString(value) {
		return true
	}
	return strings.Contains(value, "cancel it") || strings.Contains(value, "stop it")
}

func looksLikeFabricatedCommandResult(response string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(response))
	if trimmed == "" {
		return false
	}

	if strings.HasPrefix(trimmed, "command executed (") {
		return true
	}
	if strings.HasPrefix(trimmed, "command execution failed (") {
		return true
	}

	return false
}

func isInstallPendingUpdatesRequest(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	if lower == "" {
		return false
	}

	if !(strings.Contains(lower, "install") && strings.Contains(lower, "update")) {
		return false
	}

	if strings.Contains(lower, "pending") {
		return true
	}

	if strings.Contains(lower, "windows update") || strings.Contains(lower, "all updates") {
		return true
	}

	return false
}

func executeInstallPendingUpdates(cfg config.AgentConfig) (string, bool) {
	command := `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and Type='Software'")

if ($result.Updates.Count -eq 0) {
    Write-Output "No pending software updates found."
    exit 0
}

$updates = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($update in $result.Updates) {
    [void]$updates.Add($update)
}

$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $updates
$downloadResult = $downloader.Download()

$installer = $session.CreateUpdateInstaller()
$installer.Updates = $updates
$installResult = $installer.Install()

Write-Output ("Updates found: " + $updates.Count)
Write-Output ("Download result code: " + $downloadResult.ResultCode)
Write-Output ("Install result code: " + $installResult.ResultCode)
Write-Output ("Reboot required: " + $installResult.RebootRequired)

for ($i = 0; $i -lt $updates.Count; $i++) {
    $title = $updates.Item($i).Title
    $code = $installResult.GetUpdateResult($i).ResultCode
    Write-Output ("- " + $title + " => ResultCode=" + $code)
}`

	return executeAndFormatCommand("powershell", command, cfg)
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

func isExplicitPingCommand(message string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(message))
	if trimmed == "" {
		return false
	}

	if strings.HasPrefix(trimmed, "ping ") || strings.HasPrefix(trimmed, "ping to ") {
		return true
	}

	prefixPattern := regexp.MustCompile(`^[/!]ping\s+`)
	if prefixPattern.MatchString(trimmed) {
		return true
	}

	naturalPattern := regexp.MustCompile(`(?i)\b(?:please\s+|kindly\s+|can\s+you\s+|could\s+you\s+|would\s+you\s+)?ping(?:\s+to)?\s+(?:google\s+(?:public\s+)?dns|(?:\d{1,3}\.){3}\d{1,3}|[a-z0-9-]+(?:\.[a-z0-9-]+)+)\b`)
	return naturalPattern.MatchString(trimmed)
}

func executeAndFormatCommand(commandType, command string, cfg config.AgentConfig) (string, bool) {
	var (
		output string
		err    error
	)
	displayCommand := formatDisplayCommand(commandType, command)

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
		return fmt.Sprintf("Command execution failed (%s):\n%s", displayCommand, trimmedOutput), true
	}

	if trimmedOutput == "" {
		trimmedOutput = "(no output)"
	}

	return fmt.Sprintf("Command executed (%s):\n%s", displayCommand, trimmedOutput), true
}

func formatDisplayCommand(commandType, command string) string {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return commandType
	}

	isMultiline := strings.Contains(trimmed, "\n") || strings.Contains(trimmed, "\r")
	if isMultiline {
		switch strings.ToLower(strings.TrimSpace(commandType)) {
		case "powershell":
			return "powershell script"
		case "cmd":
			return "cmd script"
		case "shell":
			return "shell script"
		default:
			return strings.ToLower(strings.TrimSpace(commandType)) + " script"
		}
	}

	normalized := strings.Join(strings.Fields(trimmed), " ")
	const maxLen = 80
	if len(normalized) > maxLen {
		return normalized[:maxLen-3] + "..."
	}

	return normalized
}

func generateAIChatResponse(userMessage string, cfg config.AgentConfig, sysInfo *agent.SystemInfo, osInfo *agent.OSInfo) (string, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.AIProvider))
	if provider == "" {
		if strings.Contains(strings.ToLower(strings.TrimSpace(cfg.AIEndpoint)), "localhost:11434") || strings.Contains(strings.ToLower(strings.TrimSpace(cfg.AIEndpoint)), "127.0.0.1:11434") {
			provider = "ollama"
		} else {
			provider = "openai"
		}
	}

	if provider != "ollama" && strings.TrimSpace(cfg.AIAPIKey) == "" {
		endpoint := strings.ToLower(strings.TrimSpace(cfg.AIEndpoint))
		if strings.Contains(endpoint, "localhost:11434") || strings.Contains(endpoint, "127.0.0.1:11434") {
			provider = "ollama"
		} else {
			return "", fmt.Errorf("AGENT_AI_API_KEY is not configured")
		}
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

	messages := []chatMsg{{Role: "system", Content: cfg.AISystemPrompt}}
	messages = append(messages, chatMsg{Role: "system", Content: "Respond in a natural human style: brief empathy, clear conclusions, then practical next steps. Keep it concise and avoid robotic phrasing."})
	messages = append(messages, chatMsg{Role: "system", Content: "Use combined intelligence: (1) AI reasoning, (2) local endpoint data/diagnostics, and (3) prior conversation memory as learning context. Prefer local evidence over assumptions."})
	messages = append(messages, chatMsg{Role: "system", Content: "If the prompt includes sections like 'Current user message' and 'Conversation memory', answer only the current user message and do not repeat wrapper text. If a requested diagnostic is unavailable, clearly state what could not be collected."})
	if deviceContext := buildPersonalChatContext(sysInfo, osInfo); deviceContext != "" {
		messages = append(messages, chatMsg{Role: "system", Content: deviceContext})
	}
	if toolContext := buildPersonalChatLiveToolContext(userMessage, cfg, sysInfo, osInfo); strings.TrimSpace(toolContext) != "" {
		messages = append(messages, chatMsg{Role: "system", Content: toolContext})
	}
	if !strings.Contains(userMessage, "Conversation memory:") {
		for _, turn := range snapshotPersonalChatMemory() {
			if strings.TrimSpace(turn.user) != "" {
				messages = append(messages, chatMsg{Role: "user", Content: turn.user})
			}
			if strings.TrimSpace(turn.assistant) != "" {
				messages = append(messages, chatMsg{Role: "assistant", Content: turn.assistant})
			}
		}
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

	requestPayload := any(reqPayload)
	if provider == "ollama" {
		lowerRequestURL := strings.ToLower(strings.TrimSpace(requestURL))
		if strings.Contains(lowerRequestURL, "/api/chat") {
			requestPayload = ollamaNativeRequest{
				Model:    reqPayload.Model,
				Messages: reqPayload.Messages,
				Stream:   false,
			}
		}
	}

	body, err := json.Marshal(requestPayload)
	if err != nil {
		return "", fmt.Errorf("failed to serialize AI request: %w", err)
	}

	aiTimeout := cfg.AIRequestTimeout
	if aiTimeout <= 0 {
		aiTimeout = cfg.CommandTimeout
	}
	if aiTimeout <= 0 {
		aiTimeout = 60 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), aiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("failed to create AI request: %w", err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	requestTimeout := cfg.RequestTimeout
	if provider == "ollama" && aiTimeout > requestTimeout {
		requestTimeout = aiTimeout
	}
	if requestTimeout <= 0 {
		requestTimeout = aiTimeout
	}

	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("AI request failed: %w", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read AI response: %w", err)
	}

	if provider == "ollama" {
		var nativeResponse ollamaNativeResponse
		if err := json.Unmarshal(bodyBytes, &nativeResponse); err == nil {
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if content := strings.TrimSpace(nativeResponse.Message.Content); content != "" {
					return content, nil
				}
			}

			if resp.StatusCode >= 400 {
				if msg := strings.TrimSpace(nativeResponse.Error); msg != "" {
					if resp.StatusCode == http.StatusNotFound {
						// Try Ollama native /api/chat endpoint when /v1/chat/completions isn't enabled.
					} else {
						return "", fmt.Errorf("AI API error: %s", msg)
					}
				}
			}
		}

		if resp.StatusCode == http.StatusNotFound {
			nativeURL := normalizeOllamaNativeChatURL(requestURL)
			if nativeURL != "" && nativeURL != requestURL {
				nativePayload := ollamaNativeRequest{
					Model:    reqPayload.Model,
					Messages: reqPayload.Messages,
					Stream:   false,
				}
				nativeBody, marshalErr := json.Marshal(nativePayload)
				if marshalErr != nil {
					return "", fmt.Errorf("failed to serialize Ollama native request: %w", marshalErr)
				}

				nativeReq, nativeReqErr := http.NewRequestWithContext(ctx, http.MethodPost, nativeURL, bytes.NewBuffer(nativeBody))
				if nativeReqErr != nil {
					return "", fmt.Errorf("failed to create Ollama native request: %w", nativeReqErr)
				}
				nativeReq.Header.Set("Content-Type", "application/json")

				nativeResp, nativeDoErr := client.Do(nativeReq)
				if nativeDoErr != nil {
					return "", fmt.Errorf("AI request failed: %w", nativeDoErr)
				}
				defer nativeResp.Body.Close()

				nativeRespBytes, nativeReadErr := io.ReadAll(nativeResp.Body)
				if nativeReadErr != nil {
					return "", fmt.Errorf("failed to read Ollama native response: %w", nativeReadErr)
				}

				var nativeResponseRetry ollamaNativeResponse
				if err := json.Unmarshal(nativeRespBytes, &nativeResponseRetry); err != nil {
					return "", fmt.Errorf("failed to parse Ollama native response: %w", err)
				}

				if nativeResp.StatusCode < 200 || nativeResp.StatusCode >= 300 {
					if msg := strings.TrimSpace(nativeResponseRetry.Error); msg != "" {
						return "", fmt.Errorf("AI API error: %s", msg)
					}
					return "", fmt.Errorf("AI API HTTP %d", nativeResp.StatusCode)
				}

				content := strings.TrimSpace(nativeResponseRetry.Message.Content)
				if content == "" {
					return "", fmt.Errorf("AI response content is empty")
				}

				return content, nil
			}
		}
	}

	var response chatResponse
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
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

func normalizeOllamaNativeChatURL(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}

	parsed.Path = "/api/chat"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
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

func snapshotPersonalChatMemory() []personalChatTurn {
	personalChatMemoryMu.Lock()
	defer personalChatMemoryMu.Unlock()

	if len(personalChatMemory) == 0 {
		return nil
	}

	snapshot := make([]personalChatTurn, len(personalChatMemory))
	copy(snapshot, personalChatMemory)
	return snapshot
}

func appendPersonalChatMemory(userText, assistantText string) {
	userText = strings.TrimSpace(userText)
	assistantText = strings.TrimSpace(assistantText)
	if userText == "" && assistantText == "" {
		return
	}

	personalChatMemoryMu.Lock()
	defer personalChatMemoryMu.Unlock()

	personalChatMemory = append(personalChatMemory, personalChatTurn{
		user:      truncateMemoryText(userText, 400),
		assistant: truncateMemoryText(assistantText, 500),
	})
	if len(personalChatMemory) > personalChatMemoryMaxTurns {
		personalChatMemory = personalChatMemory[len(personalChatMemory)-personalChatMemoryMaxTurns:]
	}
}

func extractCurrentUserMessage(instruction string) string {
	instruction = strings.TrimSpace(instruction)
	if instruction == "" {
		return ""
	}

	currentMarker := regexp.MustCompile(`(?is)current\s+user\s+message\s*:\s*(.*?)\s*conversation\s+memory\s*:`)
	if matches := currentMarker.FindStringSubmatch(instruction); len(matches) == 2 {
		value := strings.TrimSpace(matches[1])
		if value != "" {
			return value
		}
	}

	currentOnly := regexp.MustCompile(`(?is)current\s+user\s+message\s*:\s*(.*)$`)
	if matches := currentOnly.FindStringSubmatch(instruction); len(matches) == 2 {
		value := strings.TrimSpace(matches[1])
		if memoryIndex := strings.Index(strings.ToLower(value), "conversation memory:"); memoryIndex >= 0 {
			value = strings.TrimSpace(value[:memoryIndex])
		}
		if value != "" {
			return value
		}
	}

	if memoryIndex := strings.Index(strings.ToLower(instruction), "conversation memory:"); memoryIndex >= 0 {
		value := strings.TrimSpace(instruction[:memoryIndex])
		if value != "" {
			return value
		}
	}

	return instruction
}

func truncateMemoryText(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 || len(value) <= max {
		return value
	}
	if max <= 3 {
		return value[:max]
	}
	return strings.TrimSpace(value[:max-3]) + "..."
}

func buildFallbackTaskDetails(instruction string, sysInfo *agent.SystemInfo, osInfo *agent.OSInfo) string {
	trimmed := strings.TrimSpace(instruction)
	if trimmed == "" {
		trimmed = "Task received."
	}

	if !isDeviceHealthRequest(trimmed) {
		return trimmed
	}

	parts := []string{"Device health summary:"}

	if sysInfo != nil {
		parts = append(parts,
			fmt.Sprintf("- Hostname: %s", strings.TrimSpace(sysInfo.Hostname)),
			fmt.Sprintf("- CPU: %s", strings.TrimSpace(sysInfo.Processor)),
			fmt.Sprintf("- RAM: %s", strings.TrimSpace(sysInfo.Memory)),
		)
	}

	if osInfo != nil {
		parts = append(parts,
			fmt.Sprintf("- Windows Edition: %s", strings.TrimSpace(osInfo.OSEdition)),
			fmt.Sprintf("- Windows Version/Build: %s (%s)", strings.TrimSpace(osInfo.OSVersion), strings.TrimSpace(osInfo.OSBuild)),
			fmt.Sprintf("- Security: AV=%s | AntiSpyware=%s | Firewall=%s", strings.TrimSpace(osInfo.AntivirusName), strings.TrimSpace(osInfo.AntiSpywareName), strings.TrimSpace(osInfo.FirewallName)),
		)
	}

	if len(parts) == 1 {
		return trimmed
	}

	return strings.Join(parts, "\n")
}

func buildPersonalChatFallbackReply(message string, sysInfo *agent.SystemInfo, osInfo *agent.OSInfo) string {
	_ = message
	_ = sysInfo
	_ = osInfo
	return "AI response is temporarily unavailable. Please try again in a moment."
}

func buildTechnicianAnalysisFromMemory(message string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(message))
	if lower == "" {
		return "", false
	}

	memory := snapshotPersonalChatMemory()
	if len(memory) == 0 {
		return "", false
	}

	if isGenericErrorExplanationRequest(lower) {
		for i := len(memory) - 1; i >= 0; i-- {
			assistant := memory[i].assistant
			if summary, ok := buildEventSummaryFromAssistantOutput(assistant); ok {
				return summary, true
			}
			if explanation, ok := explainCommandFailureFromOutput(assistant); ok {
				return explanation, true
			}
		}

		return "I can explain the latest error once error output is available in recent chat memory. Run the related command (or paste its output), then ask again.", true
	}

	if isPacketLossExplanationRequest(lower) {
		for i := len(memory) - 1; i >= 0; i-- {
			assistant := memory[i].assistant
			if strings.Contains(strings.ToLower(assistant), "packets: sent") {
				lossMatch := regexp.MustCompile(`(?i)lost\s*=\s*(\d+)\s*\((\d+)%\s*loss\)`).FindStringSubmatch(assistant)
				rttMatch := regexp.MustCompile(`(?i)minimum\s*=\s*(\d+)ms,\s*maximum\s*=\s*(\d+)ms,\s*average\s*=\s*(\d+)ms`).FindStringSubmatch(assistant)

				if len(lossMatch) == 3 {
					lossPct := lossMatch[2]
					if lossPct == "0" {
						if len(rttMatch) == 4 {
							return fmt.Sprintf("Packet loss is healthy: 0%% (no packet loss). Latency range is %sms to %sms with %sms average, which indicates stable connectivity.", rttMatch[1], rttMatch[2], rttMatch[3]), true
						}
						return "Packet loss is healthy: 0% (no packet loss), so connectivity looks stable.", true
					}

					return fmt.Sprintf("Packet loss is %s%%, which indicates network instability. I recommend re-running the ping test and then checking DNS path, gateway health, and any Wi-Fi/ISP drops.", lossPct), true
				}
			}
		}

		return "I can explain packet loss after a ping result is available. Run `cmd: ping -n 4 8.8.8.8`, then ask me to explain it.", true
	}

	if isEventResultExplanationRequest(lower) {
		for i := len(memory) - 1; i >= 0; i-- {
			assistant := memory[i].assistant
			if summary, ok := buildEventSummaryFromAssistantOutput(assistant); ok {
				return summary, true
			}
		}

		return "I can explain the event results once I have event output in recent chat memory. Run the Event Viewer command, then ask me again.", true
	}

	return "", false
}

func buildEventSummaryFromAssistantOutput(assistant string) (string, bool) {
	if !strings.Contains(strings.ToLower(assistant), "providername") || !strings.Contains(strings.ToLower(assistant), "id") {
		return "", false
	}

	providers := regexp.MustCompile(`(?m)^ProviderName\s*:\s*(.+)$`).FindAllStringSubmatch(assistant, -1)
	ids := regexp.MustCompile(`(?m)^Id\s*:\s*(\d+)$`).FindAllStringSubmatch(assistant, -1)

	providerCounts := make(map[string]int)
	providerOrder := make([]string, 0, 4)
	for _, match := range providers {
		if len(match) != 2 {
			continue
		}
		name := strings.TrimSpace(match[1])
		if name == "" {
			continue
		}
		if _, exists := providerCounts[name]; !exists {
			providerOrder = append(providerOrder, name)
		}
		providerCounts[name]++
	}

	idCounts := make(map[string]int)
	for _, match := range ids {
		if len(match) == 2 {
			idCounts[match[1]]++
		}
	}

	summaryParts := []string{"Event summary (last captured results):"}
	if len(providerOrder) > 0 {
		maxProviders := 3
		if len(providerOrder) < maxProviders {
			maxProviders = len(providerOrder)
		}
		for idx := 0; idx < maxProviders; idx++ {
			name := providerOrder[idx]
			summaryParts = append(summaryParts, fmt.Sprintf("- %s: %d event(s)", name, providerCounts[name]))
		}
	}

	if idCounts["10010"] > 0 {
		summaryParts = append(summaryParts, "- Repeated DCOM 10010 timeouts were observed; these are often startup/service timing issues unless frequent during normal uptime.")
	}
	if idCounts["7009"] > 0 {
		summaryParts = append(summaryParts, "- Service Control Manager 7009 indicates service start timeout; check Intel Platform License Manager service startup/dependencies.")
	}
	if idCounts["11"] > 0 {
		summaryParts = append(summaryParts, "- Kerberos ID 11 entries suggest smart-card/domain mapping issues on non-domain context.")
	}

	summaryParts = append(summaryParts, "If you want, I can suggest the next focused command for one provider/ID.")
	return strings.Join(summaryParts, "\n"), true
}

func explainCommandFailureFromOutput(assistant string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(assistant))
	if !strings.Contains(lower, "command execution failed") {
		return "", false
	}

	if strings.Contains(lower, "access denied") || strings.Contains(lower, "permissiondenied") || strings.Contains(lower, "0x80041003") {
		return "The last command failed due to insufficient permissions (Access denied). Run the command from an elevated/admin context or adjust the required privileges, then retry.", true
	}

	if strings.Contains(lower, "timed out") || strings.Contains(lower, "timeout") {
		return "The last command appears to have timed out. We can retry with a narrower query or longer timeout, then validate the output step-by-step.", true
	}

	return "The last command failed. Share or rerun the command output and I’ll break down the root cause and the next safest fix.", true
}

func buildTechnicianActionSuggestion(message string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(message))
	if lower == "" {
		return "", false
	}

	if strings.Contains(lower, "ping") || strings.Contains(lower, "latency") || strings.Contains(lower, "packet loss") || strings.Contains(lower, "reachability") {
		target := detectPingTarget(message)
		if target == "" {
			target = "8.8.8.8"
		}
		return fmt.Sprintf("I can run a connectivity check for you. To execute it, send: `cmd: ping -n 4 %s`\nAfter it runs, I’ll interpret packet loss and latency like a technician.", target), true
	}

	if isCPUTemperatureRequest(message) {
		return "I can check CPU temperature sensors. To execute it, send: `powershell: Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature`\nThen I’ll help interpret whether the readings look normal.", true
	}

	if isEventViewerErrorRequest(message) {
		return "I can check recent Event Viewer errors. To execute it, send: `powershell: Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=(Get-Date).AddHours(-24)} | Select-Object -First 20 TimeCreated, Id, ProviderName, Message | Format-List`\nAfter it runs, I’ll summarize the likely root causes and next fixes.", true
	}

	if strings.Contains(lower, "install") && strings.Contains(lower, "update") {
		return "I can guide a Windows update install, but it can require reboot. If you want to proceed, send an explicit command starting with `powershell:` and I’ll walk through it step-by-step.", true
	}

	if strings.Contains(lower, "restart") || strings.Contains(lower, "reboot") {
		return "I can help restart this device safely. If you want to run it, send: `cmd: shutdown /r /t 10`\nI can also help check pending user sessions first.", true
	}

	if strings.Contains(lower, "disk") && (strings.Contains(lower, "free") || strings.Contains(lower, "space") || strings.Contains(lower, "usage") || strings.Contains(lower, "drive")) {
		return "I can check disk free space for all drives. To execute it, send: `powershell: Get-PSDrive -PSProvider FileSystem | Select-Object Name,@{Name='UsedGB';Expression={[math]::Round(($_.Used/1GB),2)}},@{Name='FreeGB';Expression={[math]::Round(($_.Free/1GB),2)}},@{Name='FreePct';Expression={if(($_.Used+$_.Free)-gt 0){[math]::Round((($_.Free/($_.Used+$_.Free))*100),1)} else {0}}} | Format-Table -AutoSize`\nAfter it runs, I’ll help identify any drives near capacity.", true
	}

	return "", false
}

func isPacketLossExplanationRequest(lower string) bool {
	return (strings.Contains(lower, "packet loss") || strings.Contains(lower, "latency") || strings.Contains(lower, "ping result")) &&
		(strings.Contains(lower, "explain") || strings.Contains(lower, "understand") || strings.Contains(lower, "analyze") || strings.Contains(lower, "diagnose"))
}

func isEventResultExplanationRequest(lower string) bool {
	hasEventContext := strings.Contains(lower, "event") || strings.Contains(lower, "event viewer") || strings.Contains(lower, "logs")
	hasExplainIntent := strings.Contains(lower, "explain") || strings.Contains(lower, "understand") || strings.Contains(lower, "analyze") || strings.Contains(lower, "summarize")
	hasResultTerm := strings.Contains(lower, "result") || strings.Contains(lower, "results") || strings.Contains(lower, "output")
	return hasEventContext && (hasExplainIntent || hasResultTerm)
}

func isGenericErrorExplanationRequest(lower string) bool {
	hasExplainIntent := strings.Contains(lower, "explain") || strings.Contains(lower, "understand") || strings.Contains(lower, "analyze") || strings.Contains(lower, "diagnose")
	hasErrorTerm := strings.Contains(lower, "error") || strings.Contains(lower, "issue") || strings.Contains(lower, "problem") || strings.Contains(lower, "failed")
	return hasExplainIntent && hasErrorTerm
}

func isEventViewerErrorRequest(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	if lower == "" {
		return false
	}

	hasEventTerm := strings.Contains(lower, "event viewer") || strings.Contains(lower, "event log") || strings.Contains(lower, "event logs") || strings.Contains(lower, "windows logs")
	hasErrorTerm := strings.Contains(lower, "error") || strings.Contains(lower, "errors") || strings.Contains(lower, "critical") || strings.Contains(lower, "warning")
	hasRecentTerm := strings.Contains(lower, "recent") || strings.Contains(lower, "latest") || strings.Contains(lower, "today") || strings.Contains(lower, "last")

	if hasEventTerm && (hasErrorTerm || hasRecentTerm) {
		return true
	}

	if strings.Contains(lower, "check") && hasEventTerm {
		return true
	}

	return false
}

func isDeviceHealthRequest(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	if lower == "" {
		return false
	}

	if strings.Contains(lower, "check device health") || strings.Contains(lower, "device health") {
		return true
	}

	healthTerms := []string{"health", "status", "diagnostic", "diagnostics"}
	deviceTerms := []string{"device", "endpoint", "system", "computer", "pc", "machine", "laptop", "workstation"}

	return containsAny(lower, healthTerms) && containsAny(lower, deviceTerms)
}

func containsAny(value string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(value, term) {
			return true
		}
	}

	return false
}

func buildAIRequestTargetAndHeaders(provider string, cfg config.AgentConfig) (string, map[string]string, error) {
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	switch provider {
	case "ollama":
		endpoint := strings.TrimSpace(cfg.AIEndpoint)
		if endpoint == "" {
			endpoint = "http://localhost:11434/api/chat"
		}

		lower := strings.ToLower(endpoint)
		if (strings.Contains(lower, "localhost:11434") || strings.Contains(lower, "127.0.0.1:11434")) && strings.Contains(lower, "/v1/chat/completions") {
			if native := normalizeOllamaNativeChatURL(endpoint); native != "" {
				endpoint = native
			}
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
