package server

import (
	"errors"
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// isPowerCommand
// ---------------------------------------------------------------------------

func TestIsPowerCommand(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"restart", true},
		{"shutdown", true},
		{"RESTART", true},
		{"Shutdown", true},
		{" restart ", true},
		{"ping", false},
		{"shell", false},
		{"echo", false},
		{"ai_task", false},
		{"", false},
	}

	for _, tc := range cases {
		got := isPowerCommand(tc.input)
		if got != tc.want {
			t.Errorf("isPowerCommand(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// powerGuardEnabled
// ---------------------------------------------------------------------------

func TestPowerGuardEnabled_DefaultIsOn(t *testing.T) {
	t.Setenv("POWER_COMMAND_GUARD_ENABLED", "")
	if !powerGuardEnabled() {
		t.Fatal("expected guard to be ON when env var is empty")
	}
}

func TestPowerGuardEnabled_ExplicitOff(t *testing.T) {
	for _, val := range []string{"0", "false", "False", "FALSE", "no", "No", "off", "OFF"} {
		t.Setenv("POWER_COMMAND_GUARD_ENABLED", val)
		if powerGuardEnabled() {
			t.Errorf("expected guard to be OFF for POWER_COMMAND_GUARD_ENABLED=%q", val)
		}
	}
}

func TestPowerGuardEnabled_ExplicitOn(t *testing.T) {
	for _, val := range []string{"1", "true", "True", "yes", "on"} {
		t.Setenv("POWER_COMMAND_GUARD_ENABLED", val)
		if !powerGuardEnabled() {
			t.Errorf("expected guard to be ON for POWER_COMMAND_GUARD_ENABLED=%q", val)
		}
	}
}

// ---------------------------------------------------------------------------
// isPowerCommandAgentAllowed
// ---------------------------------------------------------------------------

func TestIsPowerCommandAgentAllowed_EmptyList(t *testing.T) {
	t.Setenv("POWER_COMMAND_ALLOWED_AGENT_IDS", "")
	if isPowerCommandAgentAllowed("any-agent-id") {
		t.Fatal("expected false when allowlist is empty")
	}
}

func TestIsPowerCommandAgentAllowed_InList(t *testing.T) {
	t.Setenv("POWER_COMMAND_ALLOWED_AGENT_IDS", "agent-a, agent-b, agent-c")
	for _, id := range []string{"agent-a", "agent-b", "agent-c"} {
		if !isPowerCommandAgentAllowed(id) {
			t.Errorf("expected %q to be allowed", id)
		}
	}
}

func TestIsPowerCommandAgentAllowed_NotInList(t *testing.T) {
	t.Setenv("POWER_COMMAND_ALLOWED_AGENT_IDS", "agent-a,agent-b")
	if isPowerCommandAgentAllowed("agent-x") {
		t.Fatal("expected agent-x to be blocked")
	}
}

func TestIsPowerCommandAgentAllowed_AllKeyword(t *testing.T) {
	for _, val := range []string{"all", "ALL", "All", "*"} {
		t.Setenv("POWER_COMMAND_ALLOWED_AGENT_IDS", val)
		if !isPowerCommandAgentAllowed("any-random-agent-id") {
			t.Errorf("expected every agent to be allowed when set to %q", val)
		}
	}
}

// ---------------------------------------------------------------------------
// hostPatternAllowed
// ---------------------------------------------------------------------------

func TestHostPatternAllowed_DefaultDockerPattern(t *testing.T) {
	t.Setenv("POWER_COMMAND_ALLOWED_HOSTNAME_REGEX", "")

	allowed := []string{
		"fbcb2a445853",
		"38f290817577",
		"73bf5b7de2a8",
		"0bb2907c1990",
		"abcdef012345",
	}
	for _, h := range allowed {
		if !hostPatternAllowed(h) {
			t.Errorf("expected Docker-style hostname %q to be allowed by default pattern", h)
		}
	}
}

func TestHostPatternAllowed_DefaultBlocksNonDocker(t *testing.T) {
	t.Setenv("POWER_COMMAND_ALLOWED_HOSTNAME_REGEX", "")

	blocked := []string{
		"Venom",
		"WIN-DESKTOP",
		"my-laptop",
		"",
		"ABCDEF012345",  // uppercase — default pattern is lowercase only
		"fbcb2a4458530", // 13 chars — too long
	}
	for _, h := range blocked {
		if hostPatternAllowed(h) {
			t.Errorf("expected hostname %q to be blocked by default pattern", h)
		}
	}
}

func TestHostPatternAllowed_CustomPattern(t *testing.T) {
	t.Setenv("POWER_COMMAND_ALLOWED_HOSTNAME_REGEX", "^test-.*$")
	if !hostPatternAllowed("test-host") {
		t.Fatal("expected 'test-host' to match custom pattern")
	}
	if hostPatternAllowed("prod-host") {
		t.Fatal("expected 'prod-host' to be blocked by custom pattern")
	}
}

func TestHostPatternAllowed_InvalidRegex(t *testing.T) {
	t.Setenv("POWER_COMMAND_ALLOWED_HOSTNAME_REGEX", "[invalid(regex")
	if hostPatternAllowed("anything") {
		t.Fatal("expected invalid regex to block all hostnames")
	}
}

// ---------------------------------------------------------------------------
// ErrPowerCommandBlocked sentinel
// ---------------------------------------------------------------------------

func TestErrPowerCommandBlocked_IsSentinel(t *testing.T) {
	// Plain errors.New with same message should NOT match via errors.Is
	different := errors.New(ErrPowerCommandBlocked.Error())
	if errors.Is(different, ErrPowerCommandBlocked) {
		t.Fatal("plain errors.New with same message should not match ErrPowerCommandBlocked via errors.Is")
	}

	// Sentinel should equal itself
	if !errors.Is(ErrPowerCommandBlocked, ErrPowerCommandBlocked) {
		t.Fatal("sentinel should equal itself via errors.Is")
	}
}

func TestErrPowerCommandBlocked_WrappedWithFmtErrorf(t *testing.T) {
	// fmt.Errorf with %w should be unwrappable via errors.Is
	wrapped := fmt.Errorf("some context: %w", ErrPowerCommandBlocked)
	if !errors.Is(wrapped, ErrPowerCommandBlocked) {
		t.Fatal("wrapped ErrPowerCommandBlocked should match via errors.Is")
	}
}
