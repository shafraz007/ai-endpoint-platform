package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

type ServerConfig struct {
	Port           string
	DatabaseURL    string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxHeaderBytes int
	AgentJWTSecret string
	AdminJWTSecret string
	AdminJWTTTL    time.Duration
	LogDir         string
	LogToConsole   bool
	// Time after which an agent is considered offline
	OfflineTimeout time.Duration
	// Interval to run offline checks
	OfflineCheckInterval time.Duration
}

type AgentConfig struct {
	ServerURL           string
	HeartbeatInterval   time.Duration
	RequestTimeout      time.Duration
	MaxRetries          int
	RetryBackoffSeconds time.Duration
	JWTSecret           string
	JWTTTL              time.Duration
	CommandPollInterval time.Duration
	CommandTimeout      time.Duration
	MetricsInterval     time.Duration
	LogDir              string
	LogToConsole        bool
	AIEndpoint          string
	AIAPIKey            string
	AIModel             string
	AISystemPrompt      string
	AIProvider          string
	AIApiVersion        string
	AIDeployment        string
}

func LoadServerConfig() ServerConfig {
	return ServerConfig{
		Port:                 getEnv("SERVER_PORT", "8070"),
		DatabaseURL:          getEnv("DATABASE_URL", "postgres://aiuser:aipassword@localhost:5432/aiendpoint?sslmode=disable"),
		ReadTimeout:          getDurationEnv("READ_TIMEOUT_SECONDS", 15) * time.Second,
		WriteTimeout:         getDurationEnv("WRITE_TIMEOUT_SECONDS", 15) * time.Second,
		MaxHeaderBytes:       getIntEnv("MAX_HEADER_BYTES", 1024*1024),
		AgentJWTSecret:       getEnv("AGENT_JWT_SECRET", ""),
		AdminJWTSecret:       getEnv("ADMIN_JWT_SECRET", ""),
		AdminJWTTTL:          getDurationEnv("ADMIN_JWT_TTL_SECONDS", 3600) * time.Second,
		LogDir:               getEnv("LOG_DIR", "logs"),
		LogToConsole:         getBoolEnv("LOG_TO_CONSOLE", true),
		OfflineTimeout:       getDurationEnv("OFFLINE_TIMEOUT_SECONDS", 90) * time.Second,
		OfflineCheckInterval: getDurationEnv("OFFLINE_CHECK_INTERVAL_SECONDS", 30) * time.Second,
	}
}

func LoadAgentConfig() AgentConfig {
	return AgentConfig{
		ServerURL:           getEnv("SERVER_URL", "http://localhost:8070"),
		HeartbeatInterval:   getDurationEnv("HEARTBEAT_INTERVAL_SECONDS", 30) * time.Second,
		RequestTimeout:      getDurationEnv("REQUEST_TIMEOUT_SECONDS", 10) * time.Second,
		MaxRetries:          getIntEnv("MAX_RETRIES", 3),
		RetryBackoffSeconds: getDurationEnv("RETRY_BACKOFF_SECONDS", 2) * time.Second,
		JWTSecret:           getEnv("AGENT_JWT_SECRET", ""),
		JWTTTL:              getDurationEnv("AGENT_JWT_TTL_SECONDS", 300) * time.Second,
		CommandPollInterval: getDurationEnv("COMMAND_POLL_INTERVAL_SECONDS", 30) * time.Second,
		CommandTimeout:      getDurationEnv("COMMAND_TIMEOUT_SECONDS", 60) * time.Second,
		MetricsInterval:     getDurationEnv("METRICS_INTERVAL_SECONDS", 5) * time.Second,
		LogDir:              getEnv("LOG_DIR", "logs"),
		LogToConsole:        getBoolEnv("LOG_TO_CONSOLE", true),
		AIEndpoint:          getEnv("AGENT_AI_ENDPOINT", "https://api.openai.com/v1/chat/completions"),
		AIAPIKey:            getEnv("AGENT_AI_API_KEY", ""),
		AIModel:             getEnv("AGENT_AI_MODEL", "gpt-4o-mini"),
		AISystemPrompt:      getEnv("AGENT_AI_SYSTEM_PROMPT", "You are an endpoint child AI agent. Reply concisely, actionably, and safely."),
		AIProvider:          getEnv("AGENT_AI_PROVIDER", "openai"),
		AIApiVersion:        getEnv("AGENT_AI_API_VERSION", "2024-02-15-preview"),
		AIDeployment:        getEnv("AGENT_AI_DEPLOYMENT", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue int64) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
			return time.Duration(parsed)
		}
		log.Printf("Invalid duration for %s, using default: %d\n", key, defaultValue)
	}
	return time.Duration(defaultValue)
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
		log.Printf("Invalid integer for %s, using default: %d\n", key, defaultValue)
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			return parsed
		}
		log.Printf("Invalid boolean for %s, using default: %t\n", key, defaultValue)
	}
	return defaultValue
}
