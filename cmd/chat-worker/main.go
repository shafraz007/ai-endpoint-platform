package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/ai"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/logging"
	"github.com/shafraz007/ai-endpoint-platform/internal/queue"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
)

type chatTaskEnvelope struct {
	Type      string    `json:"type"`
	Version   int       `json:"version"`
	MessageID int64     `json:"message_id"`
	AgentID   string    `json:"agent_id"`
	SessionID int64     `json:"session_id,omitempty"`
	Scope     string    `json:"scope"`
	Attempt   int       `json:"attempt"`
	MaxAttempts int     `json:"max_attempts"`
	DedupeKey string    `json:"dedupe_key"`
	Task      ai.Task   `json:"task"`
	CreatedAt time.Time `json:"created_at"`
}

type deadLetterEnvelope struct {
	Type        string    `json:"type"`
	Version     int       `json:"version"`
	MessageID   int64     `json:"message_id"`
	AgentID     string    `json:"agent_id"`
	SessionID   int64     `json:"session_id,omitempty"`
	Scope       string    `json:"scope"`
	Attempt     int       `json:"attempt"`
	MaxAttempts int       `json:"max_attempts"`
	DedupeKey   string    `json:"dedupe_key"`
	Reason      string    `json:"reason"`
	Task        ai.Task   `json:"task"`
	FailedAt    time.Time `json:"failed_at"`
}

type workerQueueRuntime struct {
	publisher    queue.Publisher
	publishSubject string
	dlqSubject   string
	maxAttempts  int
}

var workerRuntime workerQueueRuntime

var retryBackoffSchedule = []time.Duration{1 * time.Second, 5 * time.Second, 30 * time.Second, 2 * time.Minute}

func main() {
	cfg := config.LoadServerConfig()
	logCloser, err := logging.Setup("chat-worker", cfg.LogDir, cfg.LogToConsole)
	if err != nil {
		log.Fatalf("failed to setup logging: %v", err)
	}
	defer logCloser.Close()

	if !cfg.QueueEnabled {
		log.Fatal("chat worker requires QUEUE_ENABLED=true")
	}
	if !cfg.QueueAgentChatActive {
		log.Fatal("chat worker requires QUEUE_AGENT_CHAT_ACTIVE=true for phase 2 cutover")
	}

	if err := server.InitDB(cfg.DatabaseURL); err != nil {
		log.Fatalf("database initialization failed: %v", err)
	}
	defer server.CloseDB()

	subject := buildWorkerSubject(cfg)
	publishSubject := strings.TrimSpace(cfg.QueueAgentChatSubject)
	if publishSubject == "" {
		publishSubject = "agent.chat.shadow"
	}
	dlqSubject := strings.TrimSpace(cfg.QueueAgentChatDLQSubject)
	if dlqSubject == "" {
		dlqSubject = "agent.chat.shadow.dlq"
	}
	maxAttempts := cfg.QueueAgentChatMaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 4
	}
	publisher, err := queue.NewPublisher(queue.Config{
		Enabled:       true,
		Provider:      cfg.QueueProvider,
		NATSURL:       cfg.QueueNATSURL,
		SubjectPrefix: cfg.QueueSubjectPrefix,
		Timeout:       2 * time.Second,
	})
	if err != nil {
		log.Fatalf("failed to initialize queue publisher: %v", err)
	}
	workerRuntime = workerQueueRuntime{
		publisher:      publisher,
		publishSubject: publishSubject,
		dlqSubject:     dlqSubject,
		maxAttempts:    maxAttempts,
	}
	consumerGroup := strings.TrimSpace(cfg.QueueAgentChatConsumerGroup)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("chat worker starting (provider=%s subject=%s group=%s dlq=%s max_attempts=%d)", cfg.QueueProvider, subject, consumerGroup, dlqSubject, maxAttempts)

	err = queue.Subscribe(ctx, queue.SubscriberConfig{
		Provider: cfg.QueueProvider,
		NATSURL:  cfg.QueueNATSURL,
		Subject:  subject,
		QueueGroup: consumerGroup,
		Timeout:  5 * time.Second,
	}, handleQueueMessage)
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("queue subscription failed: %v", err)
	}

	log.Println("chat worker stopped")
}

func buildWorkerSubject(cfg config.ServerConfig) string {
	subject := strings.TrimSpace(cfg.QueueAgentChatSubject)
	if subject == "" {
		subject = "agent.chat.shadow"
	}

	prefix := strings.Trim(strings.TrimSpace(cfg.QueueSubjectPrefix), ".")
	if prefix == "" {
		return subject
	}
	return prefix + "." + subject
}

func handleQueueMessage(ctx context.Context, subject string, payload []byte) error {
	var envelope chatTaskEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		log.Printf("chat worker dropped invalid payload on %s: %v", subject, err)
		return nil
	}

	if strings.TrimSpace(envelope.Type) != "agent_chat_task" {
		return nil
	}

	agentID := strings.TrimSpace(envelope.AgentID)
	if agentID == "" {
		log.Printf("chat worker dropped payload with empty agent_id (message_id=%d)", envelope.MessageID)
		return nil
	}

	taskPayload, err := json.Marshal(envelope.Task)
	if err != nil {
		log.Printf("chat worker failed to marshal task payload (message_id=%d): %v", envelope.MessageID, err)
		return nil
	}

	createCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	taskID := strings.TrimSpace(envelope.Task.TaskID)
	if taskID == "" {
		cmd, err := server.CreateCommand(createCtx, agentID, "ai_task", string(taskPayload))
		if err != nil {
			log.Printf("chat worker failed to create ai_task command (agent_id=%s message_id=%d): %v", agentID, envelope.MessageID, err)
			return err
		}

		log.Printf("chat worker queued ai_task command_id=%d agent_id=%s message_id=%d", cmd.ID, agentID, envelope.MessageID)
		return nil
	}

	cmd, created, err := server.CreateAITaskCommandIfNotExists(createCtx, agentID, string(taskPayload), taskID)
	if err != nil {
		log.Printf("chat worker failed to create ai_task command (agent_id=%s message_id=%d): %v", agentID, envelope.MessageID, err)
		handleRetryOrDeadLetter(ctx, envelope, err)
		return nil
	}
	if !created {
		log.Printf("chat worker skipped duplicate ai_task (agent_id=%s message_id=%d task_id=%s)", agentID, envelope.MessageID, taskID)
		return nil
	}

	log.Printf("chat worker queued ai_task command_id=%d agent_id=%s message_id=%d", cmd.ID, agentID, envelope.MessageID)
	return nil
}

func handleRetryOrDeadLetter(ctx context.Context, envelope chatTaskEnvelope, processErr error) {
	attempt := envelope.Attempt
	maxAttempts := envelope.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = workerRuntime.maxAttempts
	}
	if maxAttempts <= 0 {
		maxAttempts = 4
	}

	if attempt < maxAttempts {
		envelope.Attempt = attempt + 1
		envelope.MaxAttempts = maxAttempts
		envelope.DedupeKey = resolveDedupeKey(envelope)
		backoff := retryBackoff(envelope.Attempt)
		log.Printf("chat worker retrying message_id=%d attempt=%d/%d in %s", envelope.MessageID, envelope.Attempt, maxAttempts, backoff)

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		if err := publishChatTaskEnvelope(ctx, envelope); err == nil {
			return
		} else {
			log.Printf("chat worker retry publish failed (message_id=%d attempt=%d): %v", envelope.MessageID, envelope.Attempt, err)
		}
	}

	if err := publishDeadLetter(ctx, envelope, processErr); err != nil {
		log.Printf("chat worker dead-letter publish failed (message_id=%d): %v", envelope.MessageID, err)
	}
}

func publishChatTaskEnvelope(ctx context.Context, envelope chatTaskEnvelope) error {
	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal retry envelope: %w", err)
	}

	pubCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := workerRuntime.publisher.Publish(pubCtx, workerRuntime.publishSubject, body); err != nil {
		return fmt.Errorf("failed to publish retry message: %w", err)
	}

	return nil
}

func publishDeadLetter(ctx context.Context, envelope chatTaskEnvelope, processErr error) error {
	dead := deadLetterEnvelope{
		Type:        "agent_chat_task_dead_letter",
		Version:     1,
		MessageID:   envelope.MessageID,
		AgentID:     envelope.AgentID,
		SessionID:   envelope.SessionID,
		Scope:       envelope.Scope,
		Attempt:     envelope.Attempt,
		MaxAttempts: envelope.MaxAttempts,
		DedupeKey:   resolveDedupeKey(envelope),
		Reason:      strings.TrimSpace(processErr.Error()),
		Task:        envelope.Task,
		FailedAt:    time.Now().UTC(),
	}

	body, err := json.Marshal(dead)
	if err != nil {
		return fmt.Errorf("failed to marshal dead-letter envelope: %w", err)
	}

	pubCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := workerRuntime.publisher.Publish(pubCtx, workerRuntime.dlqSubject, body); err != nil {
		return fmt.Errorf("failed to publish dead-letter message: %w", err)
	}

	log.Printf("chat worker sent dead-letter message_id=%d dedupe_key=%s reason=%s", envelope.MessageID, dead.DedupeKey, dead.Reason)
	return nil
}

func resolveDedupeKey(envelope chatTaskEnvelope) string {
	if key := strings.TrimSpace(envelope.DedupeKey); key != "" {
		return key
	}
	if taskID := strings.TrimSpace(envelope.Task.TaskID); taskID != "" {
		return taskID
	}
	return fmt.Sprintf("chatmsg-%d", envelope.MessageID)
}

func retryBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return retryBackoffSchedule[0]
	}
	index := attempt - 1
	if index >= len(retryBackoffSchedule) {
		index = len(retryBackoffSchedule) - 1
	}
	return retryBackoffSchedule[index]
}
