package config

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helper function tests (via unexported accessors since same package)
// ---------------------------------------------------------------------------

func TestGetEnv_Default(t *testing.T) {
	t.Setenv("TEST_GET_ENV_VAR", "")
	got := getEnv("TEST_GET_ENV_VAR", "default-value")
	if got != "default-value" {
		t.Errorf("got %q, want 'default-value'", got)
	}
}

func TestGetEnv_Override(t *testing.T) {
	t.Setenv("TEST_GET_ENV_VAR", "overridden")
	got := getEnv("TEST_GET_ENV_VAR", "default-value")
	if got != "overridden" {
		t.Errorf("got %q, want 'overridden'", got)
	}
}

func TestGetBoolEnv_DefaultTrue(t *testing.T) {
	t.Setenv("TEST_BOOL_VAR", "")
	if !getBoolEnv("TEST_BOOL_VAR", true) {
		t.Fatal("expected default true")
	}
}

func TestGetBoolEnv_DefaultFalse(t *testing.T) {
	t.Setenv("TEST_BOOL_VAR", "")
	if getBoolEnv("TEST_BOOL_VAR", false) {
		t.Fatal("expected default false")
	}
}

func TestGetBoolEnv_ParseTrue(t *testing.T) {
	for _, v := range []string{"true", "1", "TRUE", "True"} {
		t.Setenv("TEST_BOOL_VAR", v)
		if !getBoolEnv("TEST_BOOL_VAR", false) {
			t.Errorf("expected true for value %q", v)
		}
	}
}

func TestGetBoolEnv_ParseFalse(t *testing.T) {
	for _, v := range []string{"false", "0", "FALSE", "False"} {
		t.Setenv("TEST_BOOL_VAR", v)
		if getBoolEnv("TEST_BOOL_VAR", true) {
			t.Errorf("expected false for value %q", v)
		}
	}
}

func TestGetBoolEnv_InvalidFallsBackToDefault(t *testing.T) {
	t.Setenv("TEST_BOOL_VAR", "not-a-bool")
	if !getBoolEnv("TEST_BOOL_VAR", true) {
		t.Fatal("expected default=true on invalid bool string")
	}
}

func TestGetIntEnv_Default(t *testing.T) {
	t.Setenv("TEST_INT_VAR", "")
	got := getIntEnv("TEST_INT_VAR", 42)
	if got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

func TestGetIntEnv_ValidValue(t *testing.T) {
	t.Setenv("TEST_INT_VAR", "100")
	got := getIntEnv("TEST_INT_VAR", 42)
	if got != 100 {
		t.Errorf("got %d, want 100", got)
	}
}

func TestGetIntEnv_InvalidFallsToDefault(t *testing.T) {
	t.Setenv("TEST_INT_VAR", "not-a-number")
	got := getIntEnv("TEST_INT_VAR", 7)
	if got != 7 {
		t.Errorf("got %d, want 7 on invalid int", got)
	}
}

func TestGetDurationEnv_Default(t *testing.T) {
	t.Setenv("TEST_DUR_VAR", "")
	got := getDurationEnv("TEST_DUR_VAR", 15)
	if got != 15 {
		t.Errorf("got %d, want 15 (raw duration units)", got)
	}
}

func TestGetDurationEnv_ValidValue(t *testing.T) {
	t.Setenv("TEST_DUR_VAR", "60")
	got := getDurationEnv("TEST_DUR_VAR", 15)
	if got != 60 {
		t.Errorf("got %d, want 60", got)
	}
}

func TestGetDurationEnv_InvalidFallsToDefault(t *testing.T) {
	t.Setenv("TEST_DUR_VAR", "not-a-duration")
	got := getDurationEnv("TEST_DUR_VAR", 30)
	if got != 30 {
		t.Errorf("got %d, want 30 on invalid duration", got)
	}
}

// ---------------------------------------------------------------------------
// LoadServerConfig — smoke-test key defaults
// ---------------------------------------------------------------------------

func TestLoadServerConfig_Defaults(t *testing.T) {
	// Clear relevant env vars so we get defaults
	envVars := []string{
		"SERVER_PORT", "DATABASE_URL", "AGENT_JWT_SECRET", "ADMIN_JWT_SECRET",
		"OFFLINE_TIMEOUT_SECONDS", "SCHEDULER_DISPATCH_INTERVAL_SECONDS",
		"POWER_COMMAND_GUARD_ENABLED",
	}
	for _, v := range envVars {
		t.Setenv(v, "")
	}

	cfg := LoadServerConfig()

	if cfg.Port != "8070" {
		t.Errorf("default Port: got %q, want '8070'", cfg.Port)
	}
	if cfg.OfflineTimeout != 90*time.Second {
		t.Errorf("default OfflineTimeout: got %v, want 90s", cfg.OfflineTimeout)
	}
	if cfg.SchedulerDispatchInterval != 10*time.Second {
		t.Errorf("default SchedulerDispatchInterval: got %v, want 10s", cfg.SchedulerDispatchInterval)
	}
	if cfg.SchedulerBatchSize != 50 {
		t.Errorf("default SchedulerBatchSize: got %d, want 50", cfg.SchedulerBatchSize)
	}
	if cfg.QueueProvider != "nats" {
		t.Errorf("default QueueProvider: got %q, want 'nats'", cfg.QueueProvider)
	}
}

func TestLoadServerConfig_PortOverride(t *testing.T) {
	t.Setenv("SERVER_PORT", "9090")
	cfg := LoadServerConfig()
	if cfg.Port != "9090" {
		t.Errorf("PORT override: got %q, want '9090'", cfg.Port)
	}
}

// ---------------------------------------------------------------------------
// LoadAgentConfig — smoke-test key defaults
// ---------------------------------------------------------------------------

func TestLoadAgentConfig_Defaults(t *testing.T) {
	envVars := []string{
		"SERVER_URL", "HEARTBEAT_INTERVAL_SECONDS", "COMMAND_POLL_INTERVAL_SECONDS",
		"AGENT_JWT_SECRET", "AGENT_AI_PROVIDER",
	}
	for _, v := range envVars {
		t.Setenv(v, "")
	}

	cfg := LoadAgentConfig()

	if cfg.ServerURL != "http://localhost:8070" {
		t.Errorf("default ServerURL: got %q, want 'http://localhost:8070'", cfg.ServerURL)
	}
	if cfg.HeartbeatInterval != 30*time.Second {
		t.Errorf("default HeartbeatInterval: got %v, want 30s", cfg.HeartbeatInterval)
	}
	if cfg.CommandPollInterval != 30*time.Second {
		t.Errorf("default CommandPollInterval: got %v, want 30s", cfg.CommandPollInterval)
	}
	if cfg.AIProvider != "ollama" {
		t.Errorf("default AIProvider: got %q, want 'ollama'", cfg.AIProvider)
	}
}

func TestLoadAgentConfig_ServerURLOverride(t *testing.T) {
	t.Setenv("SERVER_URL", "http://custom-server:1234")
	cfg := LoadAgentConfig()
	if cfg.ServerURL != "http://custom-server:1234" {
		t.Errorf("ServerURL override: got %q", cfg.ServerURL)
	}
}
