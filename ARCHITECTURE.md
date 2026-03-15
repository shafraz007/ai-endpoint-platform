# AI Endpoint Platform - Architecture & Design

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Web Browsers                             │
│                    (http://localhost:8070)                       │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Server (Go HTTP)      │
                    │  Port: 8070             │
                    │  Core routes:           │
                    │  - /agents              │
                    │  - /agents/{id}         │
                    │  - /settings            │
                    │  - /reports             │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   PostgreSQL Database   │
                    │   Persistent state:     │
                    │   agents, commands,     │
                    │   metrics, chat,        │
                    │   governance, schedules,│
                    │   issues (alerts), patch│
                    │   policies, audit       │
                    └────────────┬────────────┘
                                 │
                     Poll + ACK command flow
                                 │
                ┌────────────────┼────────────────┐
                │                │                │
             ┌──▼──┐          ┌──▼──┐          ┌──▼──┐
             │Agent│          │Agent│          │Agent│
             │ A   │          │ B   │          │ N   │
             └─────┘          └─────┘          └─────┘
```

## Core Runtime Flows

### 1) Inventory + Presence
- Agent sends heartbeat to `POST /api/heartbeat`.
- Server upserts agent identity/system fields and updates status/last seen.
- Offline checker marks stale agents offline.

### 2) Commands + Acknowledgements
- Admin (or scheduler/chat) enqueues commands in DB.
- For personal chat in queue mode, server publishes an `agent_chat_task` event and returns immediately.
- `cmd/chat-worker` consumes queue events (optionally via consumer group), creates idempotent `ai_task` commands, and applies retry/DLQ policy on failure.
- Agent polls `GET /api/commands/next` with agent JWT.
- Agent executes command and acknowledges via `POST /api/commands/ack`.
- For personal-chat `ai_task` commands, server relays progress and final response to chat.

### 3) Chat + Governance
- Global and personal chat are stored server-side.
- Personal chat requests become `ai_task` commands.
- Governance checks command intents before queueing executable chat actions.
- Deterministic policy queries (for example, "is format command allowed") are answered server-side.

### 4) Scheduling + Reports
- Scheduler dispatcher runs periodically and enqueues due schedule actions.
- Scheduler skips duplicate in-flight power commands (`restart` / `shutdown`) for an agent when same type is already `queued` or `dispatched`.
- Schedule executions are persisted and exposed in reports API/UI.
- OS patch behavior is configured through dedicated patch policy endpoints (not schedule kind `patch`).

### 5) Issues (Alerts) and Remediation
- Heartbeat and metrics pipelines evaluate detector rules and upsert durable issues in `agent_issues`.
- Issues are deduplicated by `(agent_id, issue_key)` and transition between `active` and `resolved` as conditions change.
- Each issue stores evidence, suggestions, action plan, and recommended remediation actions.
- Admins can execute immediately or schedule remediation through `POST /api/issues/{id}/actions`.
- Action operations are audited in `issue_action_audit` with linked command and schedule IDs.

## Key Modules

### Agent
- `cmd/agent/main.go`: startup, heartbeat loop, command polling/execution, AI task handling
- `internal/agent/systeminfo.go`: endpoint profile collection
- `internal/agent/osinfo.go`: OS and security details
- `internal/agent/metrics.go`: metrics sampling

### Server
- `cmd/server/main.go`: routing, migrations, background loops
- `cmd/server/chat.go`: chat APIs + personal chat task queueing
- `cmd/server/commands.go`: command APIs, dequeue, ack relay to chat
- `internal/server/*.go`: persistence layer for agents, commands, chat, governance, schedules, issues, reports, users

### Queue Worker
- `cmd/chat-worker/main.go`: queue consumer for agent chat tasks, idempotent command creation, retry backoff, and DLQ publish
- `internal/queue/publisher.go`: NATS publisher abstraction used by server + worker
- `internal/queue/subscriber.go`: lightweight NATS subscriber with queue-group support

## Migration Strategy

Migrations are additive and executed automatically on startup. Current line includes:
- `001` agents
- `002` commands
- `003` users
- `004` metrics
- `005` OS/security fields
- `006` governance
- `007` chat messages
- `008-010` schedules + command linkage
- `011-012` OS patch policy + audit
- `013` agent patch inventory
- `014` agent issues + issue action audit

## Current Priorities

1. Add DLQ replay tooling and operational runbook
2. Expand queue observability (retry/DLQ counters and alert thresholds)
3. Reduce timeout-isolated chat fallbacks via tuned AI/tool execution budgets
