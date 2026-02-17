package agent

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

const agentIDFile = "agent_id"

// GetAgentID retrieves or creates a unique agent ID
func GetAgentID() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("unable to get user config directory: %w", err)
	}

	appDir := filepath.Join(dir, "ai-endpoint-agent")
	if err := os.MkdirAll(appDir, 0750); err != nil {
		return "", fmt.Errorf("unable to create config directory: %w", err)
	}

	fullPath := filepath.Join(appDir, agentIDFile)

	// Try to read existing agent ID
	data, err := os.ReadFile(fullPath)
	if err == nil {
		id := string(data)
		log.Printf("Loaded existing agent ID from %s", fullPath)
		return id, nil
	}

	// Create new agent ID
	id := uuid.New().String()
	err = os.WriteFile(fullPath, []byte(id), 0644)
	if err != nil {
		return "", fmt.Errorf("unable to write agent ID file: %w", err)
	}

	log.Printf("Created new agent ID at %s", fullPath)
	return id, nil
}
