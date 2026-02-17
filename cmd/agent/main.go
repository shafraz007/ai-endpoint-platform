package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/agent"
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

	log.Printf("Agent started - ID: %s, Hostname: %s, Version: %s", sysInfo.AgentID, sysInfo.Hostname, sysInfo.AgentVersion)
	log.Printf("Server URL: %s, Heartbeat interval: %v", cfg.ServerURL, cfg.HeartbeatInterval)

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: cfg.RequestTimeout,
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	heartbeatTicker := time.NewTicker(cfg.HeartbeatInterval)
	defer heartbeatTicker.Stop()

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
			}
			sendHeartbeatWithRetry(httpClient, cfg, hb)
		case <-commandTick:
			pollAndExecuteCommand(httpClient, cfg, sysInfo.AgentID)
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

func pollAndExecuteCommand(httpClient *http.Client, cfg config.AgentConfig, agentID string) {
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

	status, output, errMsg := executeCommand(cmd, cfg)
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

func executeCommand(cmd transport.Command, cfg config.AgentConfig) (string, string, string) {
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
	default:
		return "failed", "", "unsupported command type"
	}
}

func runShellCommand(command string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var execCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// Detect if this is a PowerShell command
		if isPowerShellCommand(command) {
			execCmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", command)
		} else {
			execCmd = exec.CommandContext(ctx, "cmd", "/C", command)
		}
	} else {
		execCmd = exec.CommandContext(ctx, "sh", "-c", command)
	}

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

func isPowerShellCommand(command string) bool {
	command = strings.ToLower(command)
	// Check for PowerShell cmdlet patterns
	powerShellPatterns := []string{
		"get-",
		"set-",
		"new-",
		"remove-",
		"invoke-",
		"| select-object",
		"| measure-object",
		"| where-object",
		"| sort-object",
		"| group-object",
		"| format-",
		"-Property",
		"-Filter",
		"-Name",
		"foreach-object",
	}

	for _, pattern := range powerShellPatterns {
		if strings.Contains(command, pattern) {
			return true
		}
	}
	return false
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
