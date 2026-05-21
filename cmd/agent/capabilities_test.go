package main

import (
	"runtime"
	"strings"
	"testing"

	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

func hasTool(tools []transport.AgentTool, name string) bool {
	for _, item := range tools {
		if item.Name == name {
			return true
		}
	}
	return false
}

func hasCapability(capabilities []string, name string) bool {
	for _, item := range capabilities {
		if item == name {
			return true
		}
	}
	return false
}

func TestCollectAdvertisedCapabilities_IncludesCoreCapabilities(t *testing.T) {
	runtimeType, tools, capabilities, confidence := collectAdvertisedCapabilities()

	if strings.TrimSpace(runtimeType) == "" {
		t.Fatal("expected runtime type")
	}
	if !hasTool(tools, "core.ai_task") {
		t.Fatal("expected core.ai_task tool")
	}
	if !hasTool(tools, "core.echo") {
		t.Fatal("expected core.echo tool")
	}
	if !hasCapability(capabilities, "ai.task") {
		t.Fatal("expected ai.task capability")
	}
	if !hasCapability(capabilities, "command.echo") {
		t.Fatal("expected command.echo capability")
	}
	if confidence["core.ai_task"] <= 0 {
		t.Fatalf("expected confidence for core.ai_task, got %v", confidence["core.ai_task"])
	}
}

func TestCollectAdvertisedCapabilities_IncludesRuntimeSpecificCapabilities(t *testing.T) {
	runtimeType, tools, capabilities, _ := collectAdvertisedCapabilities()

	if runtime.GOOS == "windows" {
		if runtimeType != "windows-host" {
			t.Fatalf("runtime type: got %q want windows-host", runtimeType)
		}
		if !hasTool(tools, "execution.powershell") {
			t.Fatal("expected execution.powershell tool on Windows")
		}
		if !hasTool(tools, "diagnostics.eventlog") {
			t.Fatal("expected diagnostics.eventlog tool on Windows")
		}
		if !hasCapability(capabilities, "execution.powershell") {
			t.Fatal("expected execution.powershell capability on Windows")
		}
		return
	}

	if !strings.Contains(runtimeType, runtime.GOOS) {
		t.Fatalf("runtime type %q does not include GOOS %q", runtimeType, runtime.GOOS)
	}
	if !hasTool(tools, "execution.shell") {
		t.Fatal("expected execution.shell tool on non-Windows")
	}
	if !hasTool(tools, "diagnostics.proc") {
		t.Fatal("expected diagnostics.proc tool on non-Windows")
	}
	if !hasCapability(capabilities, "execution.shell") {
		t.Fatal("expected execution.shell capability on non-Windows")
	}
}
