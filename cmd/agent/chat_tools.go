package main

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/agent"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
)

const maxChatFallbackDiagnosticsChars = 1800

type personalChatToolRequest struct {
	Disk     bool
	Process  bool
	Memory   bool
	Network  bool
	Services bool
	Updates  bool
	Events   bool
}

func buildPersonalChatLiveToolContext(userMessage string, cfg config.AgentConfig, sysInfo *agent.SystemInfo, osInfo *agent.OSInfo) string {
	request := inferPersonalChatToolRequest(userMessage)
	if !request.Disk && !request.Process && !request.Memory && !request.Network && !request.Services && !request.Updates && !request.Events {
		return ""
	}

	lines := []string{
		"Live device diagnostics (subject endpoint) collected for this request:",
		"Collected at: " + time.Now().UTC().Format(time.RFC3339),
	}

	if sysInfo != nil {
		if host := strings.TrimSpace(sysInfo.Hostname); host != "" {
			lines = append(lines, "Hostname: "+host)
		}
		if agentID := strings.TrimSpace(sysInfo.AgentID); agentID != "" {
			lines = append(lines, "AgentID: "+agentID)
		}
	}

	if runtime.GOOS != "windows" {
		lines = append(lines, "Diagnostics tooling: limited (non-Windows runtime).")
		return strings.Join(lines, "\n")
	}

	timeout := resolveDiagnosticsTimeout(cfg)

	if request.Disk {
		lines = append(lines, "[disk]")
		lines = append(lines, runToolPowerShell(`
$items = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,
    @{N='SizeGB';E={if($_.Size){[math]::Round($_.Size/1GB,2)}else{0}}},
    @{N='FreeGB';E={if($_.FreeSpace){[math]::Round($_.FreeSpace/1GB,2)}else{0}}},
    @{N='UsedPct';E={if($_.Size -gt 0){[math]::Round((($_.Size-$_.FreeSpace)/$_.Size)*100,1)}else{0}}}
$items | ConvertTo-Json -Depth 4 -Compress
`, timeout))
	}

	if request.Memory {
		lines = append(lines, "[memory]")
		lines = append(lines, runToolPowerShell(`
$os = Get-CimInstance Win32_OperatingSystem
$totalGB = [math]::Round(($os.TotalVisibleMemorySize / 1MB),2)
$freeGB = [math]::Round(($os.FreePhysicalMemory / 1MB),2)
$usedGB = [math]::Round(($totalGB - $freeGB),2)
[pscustomobject]@{ total_gb = $totalGB; used_gb = $usedGB; free_gb = $freeGB } | ConvertTo-Json -Compress
`, timeout))
	}

	if request.Process {
		lines = append(lines, "[top_processes]")
		lines = append(lines, runToolPowerShell(`
Get-Process | Sort-Object CPU -Descending | Select-Object -First 8 Name, Id, CPU,
    @{N='WorkingSetMB';E={[math]::Round($_.WorkingSet64/1MB,1)}} | ConvertTo-Json -Depth 4 -Compress
`, timeout))
	}

	if request.Network {
		lines = append(lines, "[network]")
		lines = append(lines, runToolPowerShell(`
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 8 Name, Status, LinkSpeed, MacAddress
$ips = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Select-Object -First 8 InterfaceAlias, IPv4Address, IPv4DefaultGateway
[pscustomobject]@{ adapters = $adapters; ip_config = $ips } | ConvertTo-Json -Depth 6 -Compress
`, timeout))
	}

	if request.Services {
		lines = append(lines, "[services]")
		lines = append(lines, runToolPowerShell(`
Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | Select-Object -First 12 Name, DisplayName, Status, StartType | ConvertTo-Json -Depth 4 -Compress
`, timeout))
	}

	if request.Updates {
		lines = append(lines, "[updates]")
		updates, rebootRequired, err := agent.CollectPendingUpdates()
		if err != nil {
			lines = append(lines, "unavailable: "+strings.TrimSpace(err.Error()))
		} else {
			preview := updates
			if len(preview) > 8 {
				preview = preview[:8]
			}
			lines = append(lines, fmt.Sprintf("pending_count=%d reboot_required=%t", len(updates), rebootRequired))
			lines = append(lines, fmt.Sprintf("preview=%+v", preview))
		}
	}

	if request.Events {
		lines = append(lines, "[events]")
		lines = append(lines, runToolPowerShell(`
Get-WinEvent -LogName System -MaxEvents 8 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Json -Depth 6 -Compress
`, timeout))
	}

	lines = append(lines, "Use these diagnostics directly in your response for the subject device.")
	return strings.Join(lines, "\n")
}

func buildPersonalChatTimeoutIsolatedReply(userMessage string, cfg config.AgentConfig, sysInfo *agent.SystemInfo, osInfo *agent.OSInfo, aiErr error) string {
	if aiErr == nil || !isTimeoutLikeError(aiErr) {
		return buildPersonalChatFallbackReply(userMessage, sysInfo, osInfo)
	}

	liveDiagnostics := strings.TrimSpace(buildPersonalChatLiveToolContext(userMessage, cfg, sysInfo, osInfo))
	if liveDiagnostics != "" {
		if len(liveDiagnostics) > maxChatFallbackDiagnosticsChars {
			liveDiagnostics = strings.TrimSpace(liveDiagnostics[:maxChatFallbackDiagnosticsChars]) + "\n...truncated"
		}
		return "AI response timed out before full analysis completed. Sharing latest live diagnostics:\n\n" + liveDiagnostics + "\n\nRetry once more for full interpretation."
	}

	snapshot := strings.TrimSpace(buildFallbackTaskDetails(userMessage, sysInfo, osInfo))
	if snapshot == "" || snapshot == strings.TrimSpace(userMessage) {
		return "AI response timed out before completion. The request is still valid—please retry in a moment for full analysis."
	}

	if len(snapshot) > maxChatFallbackDiagnosticsChars {
		snapshot = strings.TrimSpace(snapshot[:maxChatFallbackDiagnosticsChars]) + "\n...truncated"
	}

	return "AI response timed out before full analysis completed. Sharing currently available device snapshot:\n\n" + snapshot + "\n\nRetry once more for full interpretation."
}

func isTimeoutLikeError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(lower, "deadline exceeded") || strings.Contains(lower, "timed out") || strings.Contains(lower, "timeout")
}

func inferPersonalChatToolRequest(message string) personalChatToolRequest {
	lower := strings.ToLower(strings.TrimSpace(message))
	if lower == "" {
		return personalChatToolRequest{}
	}

	if containsAnyTerm(lower, "run diagnostics now", "diagnostics report", "full diagnostics", "full health report") {
		return personalChatToolRequest{
			Disk:     true,
			Process:  true,
			Memory:   true,
			Network:  true,
			Services: true,
			Updates:  true,
			Events:   true,
		}
	}

	req := personalChatToolRequest{}

	if containsAnyTerm(lower, "disk", "drive", "storage", "free space", "used space", "capacity") {
		req.Disk = true
	}
	if containsAnyTerm(lower, "process", "cpu", "utilization", "top process", "performance") {
		req.Process = true
		req.Memory = true
	}
	if containsAnyTerm(lower, "memory", "ram") {
		req.Memory = true
	}
	if containsAnyTerm(lower, "network", "ip", "latency", "packet", "dns", "connection", "adapter", "internet") {
		req.Network = true
	}
	if containsAnyTerm(lower, "service", "services") {
		req.Services = true
	}
	if containsAnyTerm(lower, "patch", "update", "hotfix", "kb") {
		req.Updates = true
	}
	if containsAnyTerm(lower, "event", "log", "error", "warning", "critical") {
		req.Events = true
	}

	if containsAnyTerm(lower, "health", "status", "diagnostic", "diagnostics", "analytics", "analyze", "analysis", "information", "info", "telemetry") {
		if !req.Disk && !req.Process && !req.Memory && !req.Network && !req.Services && !req.Updates && !req.Events {
			req.Disk = true
			req.Process = true
			req.Memory = true
			req.Network = true
			req.Updates = true
		}
	}

	return req
}

func resolveDiagnosticsTimeout(cfg config.AgentConfig) time.Duration {
	timeout := cfg.CommandTimeout
	if timeout <= 0 {
		return 12 * time.Second
	}
	if timeout < 5*time.Second {
		return 5 * time.Second
	}
	if timeout > 20*time.Second {
		return 20 * time.Second
	}
	return timeout
}

func runToolPowerShell(script string, timeout time.Duration) string {
	output, err := runPowerShellCommand(strings.TrimSpace(script), timeout)
	trimmed := strings.TrimSpace(output)
	if err != nil {
		if trimmed == "" {
			return "unavailable: " + strings.TrimSpace(err.Error())
		}
		return "partial: " + trimmed + " | error: " + strings.TrimSpace(err.Error())
	}
	if trimmed == "" {
		return "no_data"
	}
	return trimmed
}

func containsAnyTerm(value string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}
