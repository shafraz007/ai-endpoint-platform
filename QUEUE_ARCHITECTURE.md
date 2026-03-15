# Queue Architecture Blueprint (NATS JetStream)

## Current Implementation Status (2026-03-15)

- Active runtime currently uses lightweight core NATS publish/subscribe wrappers in `internal/queue`.
- Agent chat queue path is active in production flow:
   - Server publishes `agent_chat_task` payloads to `chat.agent.chat.shadow` (prefix + subject).
   - `cmd/chat-worker` consumes with optional queue group (`QUEUE_AGENT_CHAT_CONSUMER_GROUP`).
   - Worker creates idempotent `ai_task` commands in DB for agent execution.
- Retry and dead-letter flow is implemented:
   - Backoff schedule: `1s, 5s, 30s, 2m`.
   - Max attempts configurable via `QUEUE_AGENT_CHAT_MAX_ATTEMPTS` (default `4`).
   - Terminal failures publish DLQ event to `QUEUE_AGENT_CHAT_DLQ_SUBJECT` (default `agent.chat.shadow.dlq`).

JetStream sections below remain the forward target architecture for durable streams, replay, and deeper queue semantics.

## Goal
Use an event-driven queue layer to remove request-path timeouts, handle load spikes, and enable horizontal scale for chat, commands, and telemetry.

## Why NATS JetStream
- Lightweight and fast for Go services.
- Durable streams with ack/retry semantics.
- Pull/Push consumers for controlled backpressure.
- Easy local/dev setup and production clustering.

---

## Target Topology

### Components
1. **API Server (`cmd/server`)**
   - Validates request.
   - Persists initial record to PostgreSQL (`queued` state).
   - Publishes job event to NATS.
   - Returns `202 Accepted` + `job_id`/`message_id`.

2. **Worker Services (new binaries or modes)**
   - `chat-worker`: handles agent/global AI chat processing.
   - `command-worker`: handles device command orchestration.
   - `telemetry-worker`: handles non-critical heavy processing.

3. **PostgreSQL**
   - Source of truth for user-visible state, results, and audit trail.

4. **NATS JetStream**
   - Durable streams and consumers.
   - Retry + DLQ handling.

---

## Streams and Subjects

### Stream: `CHAT_STREAM`
Subjects:
- `chat.requested.agent`
- `chat.requested.global`
- `chat.completed`
- `chat.failed`

Retention:
- WorkQueue

### Stream: `COMMAND_STREAM`
Subjects:
- `command.requested`
- `command.completed`
- `command.failed`

Retention:
- WorkQueue

### Stream: `TELEMETRY_STREAM`
Subjects:
- `telemetry.ingest`
- `telemetry.processed`
- `telemetry.failed`

Retention:
- Limits (time/size bound)

### Stream: `DLQ_STREAM`
Subjects:
- `dlq.chat`
- `dlq.command`
- `dlq.telemetry`

Retention:
- Limits with long TTL for investigation/replay.

---

## Message Envelope (Common)

```json
{
  "event_id": "uuid",
  "event_type": "chat.requested.agent",
  "occurred_at": "2026-03-14T12:34:56Z",
  "trace_id": "trace-uuid",
  "attempt": 1,
  "max_attempts": 5,
  "idempotency_key": "chat:<message_id>",
  "tenant_id": "default",
  "payload": {}
}
```

### Chat Requested Payload
```json
{
  "scope": "agent",
  "agent_id": "dc0621ed-4d62-4308-8332-ad7136030483",
  "session_id": 123,
  "message_id": 456,
  "sender": "admin",
  "message": "Quick health summary in 3 bullets"
}
```

---

## Consumer and Retry Policy

### Chat Worker Consumer (`chat-worker`)
- `AckWait`: 120s (tune to AI timeout budget).
- `MaxDeliver`: configured by `QUEUE_AGENT_CHAT_MAX_ATTEMPTS`.
- Backoff sequence: `1s, 5s, 30s, 2m` (current implementation).
- On success: publish `chat.completed`, persist final message state (`completed`).
- On permanent failure (after max): publish `dlq.chat`, persist state (`failed`).

### Ordering
- Per-agent ordering key: `agent_id`.
- For global chat: `session_id` ordering key.
- Prevent parallel processing of same key by single-consumer partition strategy.

---

## Backpressure + Load Shedding

1. Limit worker concurrency (e.g., 8 AI tasks per worker instance).
2. Use queue depth metrics to autoscale workers.
3. If queue depth exceeds threshold:
   - Return softer UX message (“processing backlog”) for non-critical requests.
   - Prioritize interactive chats over bulk tasks.

---

## Idempotency Rules

1. Store `event_id` and `idempotency_key` in a processed-events table.
2. Worker checks if key is already completed before processing.
3. Re-delivered messages become no-ops (ack and exit).

---

## Data Model Additions (PostgreSQL)

### Table: `job_queue_audit`
- `id` (bigserial)
- `event_id` (uuid, unique)
- `idempotency_key` (text, indexed)
- `event_type` (text)
- `status` (`queued|processing|completed|failed|dead_letter`)
- `attempt` (int)
- `error_message` (text)
- `trace_id` (text)
- `created_at`, `updated_at`

### Optional: `dead_letter_events`
- event payload + failure metadata for replay tooling.

---

## API Behavior Changes

### Current
- API writes chat and often waits for processing side-effects.

### New
- API writes user message, enqueues event, returns immediately.
- UI receives eventual system response via existing polling/stream endpoints.

For `POST /api/chat/messages`:
- Return `202` for queued asynchronous processing (or `201` for message creation with `status=queued`).
- Include:
  - `message_id`
  - `processing_status`
  - `trace_id`

---

## Integration Points in Current Codebase

1. **`cmd/server/chat.go`**
   - Replace direct `queueAgentChatTask`/inline global workflow trigger with publish-to-queue.

2. **`internal/server/chat.go` and repo layer**
   - Add message/job status transitions.

3. **New package: `internal/queue`**
   - NATS client wrapper.
   - Publisher and consumer helpers.
   - Envelope encode/decode and retry helpers.

4. **New command binary: `cmd/chat-worker`**
   - Consumes `chat.requested.*`.
   - Executes existing processing logic currently in server path.

---

## Observability and SLOs

Track metrics:
- Queue depth per stream/subject.
- Message age (oldest unacked).
- Processing latency p50/p95/p99.
- Retry rate and DLQ rate.
- Success/failure by worker type.

Logs:
- Always include `trace_id`, `event_id`, `message_id`, `attempt`.

Alerting examples:
- `chat.requested.agent` oldest age > 60s for 5m.
- DLQ rate > 1% over 15m.
- Retry rate spike > 3x baseline.

---

## Rollout Plan (Safe)

### Phase 1: Shadow publish
- Keep current behavior.
- Also publish events to JetStream.
- Validate message schemas, metrics, and throughput.

### Phase 2: Worker active for agent chat
- API enqueues and returns quickly.
- Worker performs processing.
- Keep feature flag to revert instantly.

### Phase 3: Global chat + commands
- Migrate global workflow and command orchestration.
- Add priority queues.

### Phase 4: Full reliability hardening
- Enable DLQ replay tool.
- Add autoscaling by queue depth.

---

## Minimal Initial Config

Environment variables (example):
- `QUEUE_PROVIDER=nats`
- `NATS_URL=nats://localhost:4222`
- `QUEUE_ENABLED=true`
- `QUEUE_SUBJECT_PREFIX=chat`
- `QUEUE_AGENT_CHAT_ACTIVE=true`
- `QUEUE_AGENT_CHAT_SUBJECT=agent.chat.shadow`
- `QUEUE_AGENT_CHAT_CONSUMER_GROUP=agent-chat-workers`
- `QUEUE_AGENT_CHAT_MAX_ATTEMPTS=4`
- `QUEUE_AGENT_CHAT_DLQ_SUBJECT=agent.chat.shadow.dlq`

Existing timeout controls remain relevant:
- `AGENT_AI_TIMEOUT_SECONDS`
- `COMMAND_TIMEOUT_SECONDS`

---

## Immediate Next Implementation Step

Start with **agent chat only**:
1. Use `scripts/replay-chat-dlq.ps1` for controlled DLQ reprocessing into `agent.chat.shadow`.
2. Emit queue health metrics (retry count, DLQ count, processing latency).
3. Add alert thresholds for retry spikes and DLQ growth.
4. Evaluate JetStream migration path for durable replay and stronger delivery guarantees.
