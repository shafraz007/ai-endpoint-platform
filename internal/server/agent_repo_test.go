package server

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMarkAgentsOffline is an integration-style test that requires a running
// PostgreSQL instance reachable via DATABASE_URL. It inserts test agents,
// runs MarkAgentsOffline and verifies rows are updated.
func TestMarkAgentsOffline(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB integration test")
	}

	if err := InitDB(dbURL); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer CloseDB()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Prepare test agents
	old := time.Now().Add(-2 * time.Hour)
	recent := time.Now()
	ids := []string{"test-agent-offline-1", "test-agent-offline-2"}

	// Insert one old (should be marked offline) and one recent (should remain)
	if _, err := DB.Exec(ctx, `
        INSERT INTO agents (agent_id, hostname, public_ip, private_ip, last_seen, date_added, agent_version, status)
        VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, 'test', 'online')
        ON CONFLICT (agent_id) DO UPDATE SET last_seen = EXCLUDED.last_seen, status = EXCLUDED.status
    `, ids[0], "host-old", "127.0.0.1", "10.0.0.1", old); err != nil {
		t.Fatalf("failed to insert old agent: %v", err)
	}

	if _, err := DB.Exec(ctx, `
        INSERT INTO agents (agent_id, hostname, public_ip, private_ip, last_seen, date_added, agent_version, status)
        VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, 'test', 'online')
        ON CONFLICT (agent_id) DO UPDATE SET last_seen = EXCLUDED.last_seen, status = EXCLUDED.status
    `, ids[1], "host-recent", "127.0.0.1", "10.0.0.2", recent); err != nil {
		t.Fatalf("failed to insert recent agent: %v", err)
	}

	// Ensure cleanup
	t.Cleanup(func() {
		DB.Exec(context.Background(), "DELETE FROM agents WHERE agent_id = $1 OR agent_id = $2", ids[0], ids[1])
	})

	cutoff := time.Now().Add(-1 * time.Hour)
	affected, err := MarkAgentsOffline(ctx, cutoff)
	if err != nil {
		t.Fatalf("MarkAgentsOffline error: %v", err)
	}

	if affected < 1 {
		t.Fatalf("expected at least 1 agent to be marked offline, got %d", affected)
	}
}

func TestUpsertAgentStoresCapabilityRegistry(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB integration test")
	}

	if err := InitDB(dbURL); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer CloseDB()

	agentID := "test-agent-capability-registry"
	t.Cleanup(func() {
		DB.Exec(context.Background(), "DELETE FROM agents WHERE agent_id = $1", agentID)
	})

	err := UpsertAgent(
		agentID,
		"capability-host",
		"",
		"127.0.0.1",
		"10.0.0.10",
		"online",
		"test-version",
		nil,
		nil,
		"UTC",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"test-cpu",
		"8 GB",
		"",
		"",
		"",
		"",
		"[]",
		"[]",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		false,
		false,
		nil,
		"windows-host",
		`[{"name":"core.ai_task","version":"1.0.0"}]`,
		`["ai.task","execution.powershell"]`,
		`{"core.ai_task":0.9}`,
	)
	if err != nil {
		t.Fatalf("UpsertAgent failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	agent, err := GetAgentByID(ctx, agentID)
	if err != nil {
		t.Fatalf("GetAgentByID failed: %v", err)
	}
	if agent.RuntimeType != "windows-host" {
		t.Fatalf("runtime type: got %q want windows-host", agent.RuntimeType)
	}
	if !strings.Contains(agent.ToolsJSON, "core.ai_task") {
		t.Fatalf("expected tools_json to contain core.ai_task, got %q", agent.ToolsJSON)
	}
	if !strings.Contains(agent.CapabilitiesJSON, "execution.powershell") {
		t.Fatalf("expected capabilities_json to contain execution.powershell, got %q", agent.CapabilitiesJSON)
	}
	if !strings.Contains(agent.ToolConfidenceJSON, "core.ai_task") {
		t.Fatalf("expected tool_confidence_json to contain core.ai_task, got %q", agent.ToolConfidenceJSON)
	}
}
