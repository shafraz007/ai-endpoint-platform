package server

import (
	"testing"
	"time"
)

func TestCanonicalToolKey(t *testing.T) {
	tests := []struct {
		name        string
		commandType string
		want        string
	}{
		{name: "ai task", commandType: "ai_task", want: "core.ai_task"},
		{name: "powershell", commandType: "powershell", want: "execution.powershell"},
		{name: "cmd", commandType: "cmd", want: "execution.cmd"},
		{name: "shell", commandType: "shell", want: "execution.shell"},
		{name: "echo", commandType: "echo", want: "core.echo"},
		{name: "restart", commandType: "restart", want: "control.power"},
		{name: "unknown", commandType: "custom_action", want: "command.custom_action"},
		{name: "empty", commandType: "  ", want: "command.unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := canonicalToolKey(tc.commandType)
			if got != tc.want {
				t.Fatalf("canonicalToolKey(%q) = %q; want %q", tc.commandType, got, tc.want)
			}
		})
	}
}

func TestSummarizeOutput(t *testing.T) {
	if got := summarizeOutput("  hello\x00world  ", 50); got != "helloworld" {
		t.Fatalf("summarizeOutput sanitize mismatch: got %q", got)
	}

	if got := summarizeOutput("", 50); got != "" {
		t.Fatalf("expected empty string for empty input; got %q", got)
	}

	got := summarizeOutput("abcdefghijklmnopqrstuvwxyz", 10)
	if got != "abcdefg..." {
		t.Fatalf("expected truncated output, got %q", got)
	}
}

func TestComputeEffectiveToolScore_RecencyDecayAndConfidence(t *testing.T) {
	now := time.Now().UTC()

	stalePerfect := AgentToolScore{
		ToolKey:    "execution.cmd",
		Attempts:   20,
		Score:      1.0,
		LastStatus: "succeeded",
		UpdatedAt:  now.Add(-10 * 24 * time.Hour),
	}
	recentGood := AgentToolScore{
		ToolKey:    "execution.powershell",
		Attempts:   3,
		Score:      0.8,
		LastStatus: "succeeded",
		UpdatedAt:  now.Add(-15 * time.Minute),
	}

	staleScore := computeEffectiveToolScore(stalePerfect, now)
	recentScore := computeEffectiveToolScore(recentGood, now)

	if recentScore <= staleScore {
		t.Fatalf("expected recent score (%0.4f) to outrank stale score (%0.4f)", recentScore, staleScore)
	}
}

func TestComputeEffectiveToolScore_AppliesFailurePenalty(t *testing.T) {
	now := time.Now().UTC()
	succeeded := AgentToolScore{
		ToolKey:    "execution.shell",
		Attempts:   6,
		Score:      0.7,
		LastStatus: "succeeded",
		UpdatedAt:  now.Add(-10 * time.Minute),
	}
	failed := succeeded
	failed.LastStatus = "failed"

	succeededScore := computeEffectiveToolScore(succeeded, now)
	failedScore := computeEffectiveToolScore(failed, now)

	if failedScore >= succeededScore {
		t.Fatalf("expected failed score (%0.4f) to be lower than succeeded score (%0.4f)", failedScore, succeededScore)
	}
}

func TestClamp01(t *testing.T) {
	if got := clamp01(-0.5); got != 0 {
		t.Fatalf("clamp01(-0.5) = %0.2f; want 0", got)
	}
	if got := clamp01(1.5); got != 1 {
		t.Fatalf("clamp01(1.5) = %0.2f; want 1", got)
	}
	if got := clamp01(0.42); got != 0.42 {
		t.Fatalf("clamp01(0.42) = %0.2f; want 0.42", got)
	}
}
