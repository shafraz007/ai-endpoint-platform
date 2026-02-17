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
	// Time after which an agent is considered offline
	OfflineTimeout      time.Duration
	// Interval to run offline checks
	OfflineCheckInterval time.Duration
}

type AgentConfig struct {
	ServerURL           string
	HeartbeatInterval   time.Duration
	RequestTimeout      time.Duration
	MaxRetries          int
	RetryBackoffSeconds time.Duration
}

func LoadServerConfig() ServerConfig {
	return ServerConfig{
		Port:           getEnv("SERVER_PORT", "8070"),
		DatabaseURL:    getEnv("DATABASE_URL", "postgres://aiuser:aipassword@localhost:5432/aiendpoint?sslmode=disable"),
		ReadTimeout:    getDurationEnv("READ_TIMEOUT_SECONDS", 15) * time.Second,
		WriteTimeout:   getDurationEnv("WRITE_TIMEOUT_SECONDS", 15) * time.Second,
		MaxHeaderBytes: getIntEnv("MAX_HEADER_BYTES", 1024*1024),
		OfflineTimeout:      getDurationEnv("OFFLINE_TIMEOUT_SECONDS", 90) * time.Second,
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
