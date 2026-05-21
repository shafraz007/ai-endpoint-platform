package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

func detectRuntimeType() string {
	if runtime.GOOS == "windows" {
		return "windows-host"
	}
	isContainer := false
	if _, err := os.Stat("/.dockerenv"); err == nil {
		isContainer = true
	}
	suffix := "-host"
	if isContainer {
		suffix = "-container"
	}
	if runtime.GOOS == "linux" {
		if distro := detectLinuxDistro(); distro != "" {
			return "linux-" + distro + suffix
		}
		return "linux" + suffix
	}
	return runtime.GOOS + suffix
}

// detectLinuxDistro reads /etc/os-release and returns the distro ID
// (e.g. "ubuntu", "debian", "rhel", "fedora", "opensuse-leap").
func detectLinuxDistro() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ID=") {
			id := strings.TrimPrefix(line, "ID=")
			id = strings.Trim(id, `"`)
			return strings.ToLower(strings.TrimSpace(id))
		}
	}
	return ""
}

// detectLinuxPackageManager returns the name of the first available
// package manager binary found in PATH.
func detectLinuxPackageManager() string {
	for _, candidate := range []struct{ binary, name string }{
		{"apt-get", "apt"},
		{"dnf", "dnf"},
		{"yum", "yum"},
		{"zypper", "zypper"},
		{"pacman", "pacman"},
		{"apk", "apk"},
	} {
		if _, err := exec.LookPath(candidate.binary); err == nil {
			return candidate.name
		}
	}
	return ""
}

func collectAdvertisedCapabilities() (string, []transport.AgentTool, []string, map[string]float64) {
	runtimeType := detectRuntimeType()
	tools := []transport.AgentTool{
		{
			Name:        "core.ai_task",
			Version:     "1.0.0",
			Kind:        "builtin",
			Description: "Execute structured AI tasks with local diagnostics and memory context.",
		},
		{
			Name:        "core.echo",
			Version:     "1.0.0",
			Kind:        "builtin",
			Description: "Return simple test payloads for connectivity and queue validation.",
		},
		{
			Name:        "diagnostics.disk",
			Version:     "1.0.0",
			Kind:        "builtin",
			Description: "Inspect disk inventory and storage usage for the local endpoint.",
		},
		{
			Name:        "diagnostics.memory",
			Version:     "1.0.0",
			Kind:        "builtin",
			Description: "Inspect memory capacity and usage for the local endpoint.",
		},
		{
			Name:        "diagnostics.network",
			Version:     "1.0.0",
			Kind:        "builtin",
			Description: "Inspect local network configuration and connectivity details.",
		},
		{
			Name:        "diagnostics.services",
			Version:     "1.0.0",
			Kind:        "builtin",
			Description: "Inspect service state on the local endpoint.",
		},
		{
			Name:        "diagnostics.updates",
			Version:     "1.0.0",
			Kind:        "builtin",
			Description: "Inspect pending update posture and reboot requirements.",
		},
	}
	capabilities := []string{
		"ai.task",
		"command.echo",
		"diagnostics.disk",
		"diagnostics.memory",
		"diagnostics.network",
		"diagnostics.services",
		"diagnostics.updates",
		runtimeType,
	}
	toolConfidence := map[string]float64{
		"core.ai_task":         0.90,
		"core.echo":            1.00,
		"diagnostics.disk":     0.92,
		"diagnostics.memory":   0.92,
		"diagnostics.network":  0.90,
		"diagnostics.services": 0.88,
		"diagnostics.updates":  0.88,
	}

	if runtime.GOOS == "windows" {
		tools = append(tools,
			transport.AgentTool{Name: "execution.powershell", Version: "1.0.0", Kind: "builtin", Description: "Execute PowerShell commands on the Windows host."},
			transport.AgentTool{Name: "execution.cmd", Version: "1.0.0", Kind: "builtin", Description: "Execute cmd commands on the Windows host."},
			transport.AgentTool{Name: "diagnostics.eventlog", Version: "1.0.0", Kind: "builtin", Description: "Inspect Windows event logs for diagnostic evidence."},
			transport.AgentTool{Name: "diagnostics.defender", Version: "1.0.0", Kind: "builtin", Description: "Inspect Windows Defender and security posture signals."},
		)
		capabilities = append(capabilities,
			"execution.powershell",
			"execution.cmd",
			"diagnostics.eventlog",
			"diagnostics.defender",
		)
		toolConfidence["execution.powershell"] = 0.95
		toolConfidence["execution.cmd"] = 0.92
		toolConfidence["diagnostics.eventlog"] = 0.90
		toolConfidence["diagnostics.defender"] = 0.93
	} else {
		tools = append(tools,
			transport.AgentTool{Name: "execution.shell", Version: "1.0.0", Kind: "builtin", Description: "Execute POSIX shell commands on the local runtime."},
			transport.AgentTool{Name: "diagnostics.proc", Version: "1.0.0", Kind: "builtin", Description: "Inspect process state through proc-style runtime tooling."},
			transport.AgentTool{Name: "diagnostics.netstat", Version: "1.0.0", Kind: "builtin", Description: "Inspect sockets and network listeners on the local runtime."},
		)
		capabilities = append(capabilities,
			"execution.shell",
			"diagnostics.proc",
			"diagnostics.netstat",
		)
		toolConfidence["execution.shell"] = 0.93
		toolConfidence["diagnostics.proc"] = 0.88
		toolConfidence["diagnostics.netstat"] = 0.88

		// Advertise the available Linux package manager as a patch tool
		// so the server can route OS patch schedules to the correct agents.
		if runtime.GOOS == "linux" {
			if pm := detectLinuxPackageManager(); pm != "" {
				toolKey := "patch." + pm
				tools = append(tools, transport.AgentTool{
					Name:        toolKey,
					Version:     "1.0.0",
					Kind:        "builtin",
					Description: fmt.Sprintf("Scan and install OS package updates using %s on Linux.", pm),
				})
				capabilities = append(capabilities, toolKey, "patch.linux")
				toolConfidence[toolKey] = 0.90
			}
		}
	}

	return runtimeType, tools, capabilities, toolConfidence
}
