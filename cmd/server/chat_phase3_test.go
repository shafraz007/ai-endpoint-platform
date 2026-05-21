package main

import (
	"strings"
	"testing"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/server"
)

func TestBuildPersonalChatLearningContext_IncludesScoresAndRuns(t *testing.T) {
	scores := []server.AgentToolScore{
		{
			ToolKey:    "core.echo",
			Attempts:   3,
			Successes:  3,
			Failures:   0,
			Score:      1.0,
			LastStatus: "succeeded",
		},
		{
			ToolKey:    "execution.shell",
			Attempts:   2,
			Successes:  1,
			Failures:   1,
			Score:      0.5,
			LastStatus: "failed",
			LastError:  "exit status 127",
		},
	}
	runs := []server.AgentActionRun{
		{
			ToolKey:   "execution.shell",
			Status:    "failed",
			LatencyMS: 1100,
			ErrorText: "exit status 127",
			CreatedAt: time.Now().UTC(),
		},
	}
	fleet := []server.FleetToolScore{
		{
			ToolKey:    "execution.powershell",
			Attempts:   20,
			Successes:  18,
			Failures:   2,
			AgentCount: 6,
			Score:      0.9,
		},
	}

	got := buildPersonalChatLearningContext(scores, runs, fleet)
	if !strings.Contains(got, "Tool reliability:") {
		t.Fatalf("expected tool reliability section, got %q", got)
	}
	if !strings.Contains(got, "core.echo: 3/3 success (100%), last succeeded") {
		t.Fatalf("expected core.echo score summary, got %q", got)
	}
	if !strings.Contains(got, "execution.shell: 1/2 success (50%), last failed: exit status 127") {
		t.Fatalf("expected execution.shell score summary, got %q", got)
	}
	if !strings.Contains(got, "Recent action outcomes:") {
		t.Fatalf("expected action outcomes section, got %q", got)
	}
	if !strings.Contains(got, "execution.shell failed in 1100ms: exit status 127") {
		t.Fatalf("expected recent run summary, got %q", got)
	}
	if !strings.Contains(got, "Fleet reliability (peer learning):") {
		t.Fatalf("expected fleet reliability section, got %q", got)
	}
	if !strings.Contains(got, "execution.powershell: 18/20 success (90%) across 6 agent(s)") {
		t.Fatalf("expected fleet score summary, got %q", got)
	}
	if !strings.Contains(got, "Experiment feedback loop:") {
		t.Fatalf("expected experiment feedback loop section, got %q", got)
	}
	if !strings.Contains(got, "Feedback: execution.shell recently failed in 1100ms") {
		t.Fatalf("expected experiment feedback line, got %q", got)
	}
}

func TestBuildPersonalChatLearningContext_EmptyWhenNoSignals(t *testing.T) {
	if got := buildPersonalChatLearningContext(nil, nil, nil); got != "" {
		t.Fatalf("expected empty context, got %q", got)
	}
}

func TestBuildPersonalChatLearningContext_FiltersFleetDuplicates(t *testing.T) {
	scores := []server.AgentToolScore{{ToolKey: "execution.cmd", Attempts: 3, Successes: 2, Score: 0.66, LastStatus: "succeeded"}}
	fleet := []server.FleetToolScore{{ToolKey: "execution.cmd", Attempts: 12, Successes: 10, AgentCount: 4, Score: 0.83}}

	got := buildPersonalChatLearningContext(scores, nil, fleet)
	if strings.Contains(got, "across 4 agent(s)") {
		t.Fatalf("expected duplicate fleet tool to be filtered, got %q", got)
	}
}

func TestBuildPersonalChatLearningContext_ExperimentExploreLineForLowSample(t *testing.T) {
	scores := []server.AgentToolScore{{ToolKey: "execution.powershell", Attempts: 1, Successes: 1, Score: 0.9, LastStatus: "succeeded"}}

	got := buildPersonalChatLearningContext(scores, nil, nil)
	if !strings.Contains(got, "Explore execution.powershell") {
		t.Fatalf("expected experiment explore line, got %q", got)
	}
}
