package config

import (
	"log"
	"os"
	"strconv"
	"strings"
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
	// Interval to evaluate due schedules
	SchedulerDispatchInterval time.Duration
	// Max schedules to process per dispatch cycle
	SchedulerBatchSize   int
	GlobalAIEnabled      bool
	GlobalAIEndpoint     string
	GlobalAIAPIKey       string
	GlobalAIModel        string
	GlobalAIProvider     string
	GlobalAISystemPrompt string
	GlobalAITimeout      time.Duration
	QueueEnabled         bool
	QueueProvider        string
	QueueNATSURL         string
	QueueSubjectPrefix   string
	QueueAgentChatActive bool
	QueueAgentChatSubject string
	QueueAgentChatConsumerGroup string
	QueueAgentChatMaxAttempts int
	QueueAgentChatDLQSubject string
}

type AgentConfig struct {
	ServerURL           string
	HeartbeatInterval   time.Duration
	RequestTimeout      time.Duration
	AIRequestTimeout    time.Duration
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
	AIChatEngine        string
}

func LoadServerConfig() ServerConfig {
	return ServerConfig{
		Port:                      getEnv("SERVER_PORT", "8070"),
		DatabaseURL:               getEnv("DATABASE_URL", "postgres://aiuser:aipassword@localhost:5432/aiendpoint?sslmode=disable"),
		ReadTimeout:               getDurationEnv("READ_TIMEOUT_SECONDS", 15) * time.Second,
		WriteTimeout:              getDurationEnv("WRITE_TIMEOUT_SECONDS", 15) * time.Second,
		MaxHeaderBytes:            getIntEnv("MAX_HEADER_BYTES", 1024*1024),
		AgentJWTSecret:            getEnv("AGENT_JWT_SECRET", ""),
		AdminJWTSecret:            getEnv("ADMIN_JWT_SECRET", ""),
		AdminJWTTTL:               getDurationEnv("ADMIN_JWT_TTL_SECONDS", 3600) * time.Second,
		LogDir:                    getEnv("LOG_DIR", "logs"),
		LogToConsole:              getBoolEnv("LOG_TO_CONSOLE", true),
		OfflineTimeout:            getDurationEnv("OFFLINE_TIMEOUT_SECONDS", 90) * time.Second,
		OfflineCheckInterval:      getDurationEnv("OFFLINE_CHECK_INTERVAL_SECONDS", 30) * time.Second,
		SchedulerDispatchInterval: getDurationEnv("SCHEDULER_DISPATCH_INTERVAL_SECONDS", 10) * time.Second,
		SchedulerBatchSize:        getIntEnv("SCHEDULER_BATCH_SIZE", 50),
		GlobalAIEnabled:           getBoolEnv("GLOBAL_CHAT_AI_ENABLED", true),
		GlobalAIEndpoint:          getEnv("GLOBAL_CHAT_AI_ENDPOINT", getEnv("AGENT_AI_ENDPOINT", "http://127.0.0.1:11434/v1/chat/completions")),
		GlobalAIAPIKey:            getEnv("GLOBAL_CHAT_AI_API_KEY", getEnv("AGENT_AI_API_KEY", "")),
		GlobalAIModel:             getEnv("GLOBAL_CHAT_AI_MODEL", getEnv("AGENT_AI_MODEL", "llama3.2")),
		GlobalAIProvider:          getEnv("GLOBAL_CHAT_AI_PROVIDER", getEnv("AGENT_AI_PROVIDER", "ollama")),
		GlobalAISystemPrompt:      getEnv("GLOBAL_CHAT_AI_SYSTEM_PROMPT", "You are a fleet operations research assistant for endpoint administrators. Be conversational and practical. Use provided fleet data, issue statistics, and conversation memory before answering. Prioritize evidence, risks, and next-best actions. Never claim an action was executed unless execution confirmation exists in chat. For execution, instruct the admin to use governed formats and confirmation tokens."),
		GlobalAITimeout:           getDurationEnv("GLOBAL_CHAT_AI_TIMEOUT_SECONDS", 90) * time.Second,
		QueueEnabled:              getBoolEnv("QUEUE_ENABLED", false),
		QueueProvider:             strings.ToLower(strings.TrimSpace(getEnv("QUEUE_PROVIDER", "nats"))),
		QueueNATSURL:              strings.TrimSpace(getEnv("NATS_URL", "nats://localhost:4222")),
		QueueSubjectPrefix:        strings.TrimSpace(getEnv("QUEUE_SUBJECT_PREFIX", "chat")),
		QueueAgentChatActive:      getBoolEnv("QUEUE_AGENT_CHAT_ACTIVE", false),
		QueueAgentChatSubject:     strings.TrimSpace(getEnv("QUEUE_AGENT_CHAT_SUBJECT", "agent.chat.shadow")),
		QueueAgentChatConsumerGroup: strings.TrimSpace(getEnv("QUEUE_AGENT_CHAT_CONSUMER_GROUP", "agent-chat-workers")),
		QueueAgentChatMaxAttempts: getIntEnv("QUEUE_AGENT_CHAT_MAX_ATTEMPTS", 4),
		QueueAgentChatDLQSubject: strings.TrimSpace(getEnv("QUEUE_AGENT_CHAT_DLQ_SUBJECT", "agent.chat.shadow.dlq")),
	}
}

func LoadAgentConfig() AgentConfig {
	return AgentConfig{
		ServerURL:           getEnv("SERVER_URL", "http://localhost:8070"),
		HeartbeatInterval:   getDurationEnv("HEARTBEAT_INTERVAL_SECONDS", 30) * time.Second,
		RequestTimeout:      getDurationEnv("REQUEST_TIMEOUT_SECONDS", 10) * time.Second,
		AIRequestTimeout:    getDurationEnv("AGENT_AI_TIMEOUT_SECONDS", 0) * time.Second,
		MaxRetries:          getIntEnv("MAX_RETRIES", 3),
		RetryBackoffSeconds: getDurationEnv("RETRY_BACKOFF_SECONDS", 2) * time.Second,
		JWTSecret:           getEnv("AGENT_JWT_SECRET", ""),
		JWTTTL:              getDurationEnv("AGENT_JWT_TTL_SECONDS", 300) * time.Second,
		CommandPollInterval: getDurationEnv("COMMAND_POLL_INTERVAL_SECONDS", 30) * time.Second,
		CommandTimeout:      getDurationEnv("COMMAND_TIMEOUT_SECONDS", 60) * time.Second,
		MetricsInterval:     getDurationEnv("METRICS_INTERVAL_SECONDS", 5) * time.Second,
		LogDir:              getEnv("LOG_DIR", "logs"),
		LogToConsole:        getBoolEnv("LOG_TO_CONSOLE", true),
		AIEndpoint:          getEnv("AGENT_AI_ENDPOINT", "http://127.0.0.1:11434/api/chat"),
		AIAPIKey:            getEnv("AGENT_AI_API_KEY", ""),
		AIModel:             getEnv("AGENT_AI_MODEL", "llama3.2"),
		AISystemPrompt:      getEnv("AGENT_AI_SYSTEM_PROMPT", "You are an endpoint AI technician assistant. Sound natural and human, with clear and calm language. Combine AI reasoning with local endpoint diagnostics and prior conversation memory (learning) before answering. Diagnose step-by-step, keep explanations concise, and propose safe next actions. Never claim you executed a command unless execution actually happened."),
		AIProvider:          getEnv("AGENT_AI_PROVIDER", "ollama"),
		AIApiVersion:        getEnv("AGENT_AI_API_VERSION", "2024-02-15-preview"),
		AIDeployment:        getEnv("AGENT_AI_DEPLOYMENT", ""),
		AIChatEngine:        getEnv("AGENT_AI_CHAT_ENGINE", "v2"),
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
