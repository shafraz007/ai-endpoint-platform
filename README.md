# AI Endpoint Platform

A distributed agent-server architecture for comprehensive endpoint monitoring and management. The system consists of autonomous agents deployed on target machines that collect system information and report to a central server.

## Architecture Overview

### Components

**Agent (Client)** 🤖
- Autonomous process running on individual machines (Windows, Linux, macOS)
- Collects comprehensive system information
- Sends periodic heartbeats to the server
- Self-manages lifecycle and configuration
- Lightweight and efficient resource usage

**Server (Hub)** 🏢
- Central coordination point for all agents
- Receives and persists agent data in PostgreSQL
- Detects offline agents automatically
- Provides REST API and web UI for monitoring
- Manages agent relationships and policies

**Database** 💾
- PostgreSQL v12+ for persistent storage
- Optimized schema with indexed queries
- Automatic migration system for version upgrades

## Features

### Current

#### Agent Features
- ✅ Automatic agent ID generation and persistence
- ✅ System information collection (hostname, domain, timezone, IPs)
- ✅ Hardware information collection (Windows via CIM/WMI)
- ✅ Storage information (physical disks, logical drives with usage)
- ✅ Network information (MAC addresses, IP addresses)
- ✅ Periodic heartbeat sending (configurable, default 30s)
- ✅ Graceful shutdown handling
- ✅ Real-time metrics sampling (CPU, memory, network)

#### Server Features
- ✅ Agent heartbeat reception and processing
- ✅ Agent data persistence with automatic migrations
- ✅ Agent status tracking (online/offline)
- ✅ Automatic offline detection (30-second timeout)
- ✅ REST API endpoints for agent management
- ✅ Web UI with tabbed interface (Overview, Hardware, Disks, Commands)
- ✅ Real-time status indicators
- ✅ Admin login with DB-backed users and session cookies
- ✅ Commands queue (server → agent) with acknowledgements
- ✅ Daily rotating logs for server and agent
- ✅ Metrics storage and streaming (SSE) for live charts
- ✅ Global and personal chat with unread notification badges
- ✅ Governance enforcement for chat-triggered command execution
- ✅ Deterministic governance query responses in chat
- ✅ Schedules for `task`, `command`, and `script` workloads
- ✅ OS patch policy management (separate from schedules)
- ✅ Schedule execution reports and audit trail
- ✅ Queue-backed agent chat worker (`cmd/chat-worker`) with consumer-group support
- ✅ Chat task retry + dead-letter handling with configurable max attempts and DLQ subject

### In Progress

- 🔲 Rich multi-step progress streaming for long-running agent tasks
- 🔲 Additional proactive agent-initiated insights

## Technology Stack

- **Language**: Go 1.25.0
- **Database**: PostgreSQL 12+
- **Framework**: Standard library net/http
- **UI**: HTML/CSS/JavaScript (vanilla)

## Installation & Setup

### Prerequisites
- Go 1.25.0 or higher
- PostgreSQL 12 or higher

### Quick Start

1. Create database:
```bash
createdb ai_agents
```

2. Set environment variables:
```bash
export DATABASE_URL=postgres://ai_endpoint_user:your_password@localhost:5432/ai_agents?sslmode=disable
export SERVER_PORT=8070
```

3. Start server (migrations run automatically):
```bash
go run ./cmd/server
```

4. Start agent:
```bash
export SERVER_URL=http://localhost:8070
go run ./cmd/agent
```

## Configuration

### Agent Environment Variables
```bash
SERVER_URL=http://localhost:8070
HEARTBEAT_INTERVAL_SECONDS=30
REQUEST_TIMEOUT_SECONDS=10
MAX_RETRIES=3
RETRY_BACKOFF_SECONDS=2
AGENT_JWT_SECRET=your_agent_shared_secret
AGENT_JWT_TTL_SECONDS=300
COMMAND_POLL_INTERVAL_SECONDS=30
COMMAND_TIMEOUT_SECONDS=60
METRICS_INTERVAL_SECONDS=5
AGENT_AI_ENDPOINT=http://127.0.0.1:11434/v1/chat/completions
AGENT_AI_API_KEY=
AGENT_AI_MODEL=llama3.2
AGENT_AI_SYSTEM_PROMPT=You are an endpoint child AI agent. Reply concisely, actionably, and safely.
AGENT_AI_PROVIDER=ollama
AGENT_AI_API_VERSION=2024-02-15-preview
AGENT_AI_DEPLOYMENT=
LOG_DIR=logs
LOG_TO_CONSOLE=true
```

Provider notes:
- OpenAI-compatible:
	- `AGENT_AI_PROVIDER=openai`
	- `AGENT_AI_ENDPOINT=https://api.openai.com/v1/chat/completions`
	- Uses `Authorization: Bearer <AGENT_AI_API_KEY>`
- Azure OpenAI:
	- `AGENT_AI_PROVIDER=azure_openai`
	- `AGENT_AI_ENDPOINT=https://<resource>.openai.azure.com`
	- `AGENT_AI_DEPLOYMENT=<deployment_name>`
	- `AGENT_AI_API_VERSION=2024-02-15-preview` (or your supported version)
	- Uses `api-key: <AGENT_AI_API_KEY>` header
- Ollama (local, free):
  - `AGENT_AI_PROVIDER=ollama`
	- `AGENT_AI_ENDPOINT=http://localhost:11434/api/chat` (preferred native endpoint)
  - `AGENT_AI_MODEL=llama3.2` (or any model you pulled)
  - `AGENT_AI_API_KEY=` (not required)
	- `http://localhost:11434/v1/chat/completions` remains supported for compatibility.

### Ollama Quick Start (Windows)

1. Install Ollama from `https://ollama.com/download/windows`
2. Pull a model:
	- `ollama pull llama3.2`
3. Verify local API:
	- `ollama list`
	- `curl http://localhost:11434/api/tags`
4. Set agent environment variables:
	- `AGENT_AI_PROVIDER=ollama`
	- `AGENT_AI_ENDPOINT=http://localhost:11434/v1/chat/completions`
	- `AGENT_AI_MODEL=llama3.2`
	- `AGENT_AI_API_KEY=`
5. Restart agent process.

### Windows Agent Service Installer (Elevated)

Use the one-shot installer to run agent as a Windows service (LocalSystem by default) and set machine-level env vars:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-agent-service.ps1 `
	-BuildFromSource `
	-SourceDir . `
	-ServiceName AIEndpointAgent `
	-ServerURL "http://<server>:8070" `
	-AgentJWTSecret "<agent_jwt_secret>" `
	-AgentAIProvider "ollama" `
	-AgentAIEndpoint "http://127.0.0.1:11434/api/chat" `
	-AgentAIModel "llama3.2" `
	-AgentAIChatEngine "v2" `
	-UseLocalSystem
```

The script always sets required startup env vars:
- `SERVER_URL`
- `AGENT_JWT_SECRET`
- `LOG_DIR`
- `LOG_TO_CONSOLE`

Optional runtime/AI env vars are also supported via parameters:
- `HEARTBEAT_INTERVAL_SECONDS`, `REQUEST_TIMEOUT_SECONDS`, `AGENT_AI_TIMEOUT_SECONDS`
- `MAX_RETRIES`, `RETRY_BACKOFF_SECONDS`, `AGENT_JWT_TTL_SECONDS`
- `COMMAND_POLL_INTERVAL_SECONDS`, `COMMAND_TIMEOUT_SECONDS`, `METRICS_INTERVAL_SECONDS`
- `AGENT_AI_PROVIDER`, `AGENT_AI_ENDPOINT`, `AGENT_AI_MODEL`, `AGENT_AI_API_KEY`
- `AGENT_AI_SYSTEM_PROMPT`, `AGENT_AI_API_VERSION`, `AGENT_AI_DEPLOYMENT`, `AGENT_AI_CHAT_ENGINE`

Troubleshooting (Windows service):
- Service fails to start with `Error 1067`: verify `AGENT_JWT_SECRET` and `SERVER_URL` are present at machine scope.
- Service appears running but no heartbeat: verify outbound connectivity to server (`Test-NetConnection <server> -Port 8070`).
- No logs visible: ensure `LOG_DIR` exists and service account has write access.
- Service account issue (`Error 1057`/`1069`): reconfigure service credentials or switch to `-UseLocalSystem`.
- Validate service quickly:
	- `Get-Service AIEndpointAgent`
	- `Get-CimInstance Win32_Process | Where-Object { $_.Name -ieq 'agent.exe' }`
	- `Get-ChildItem "C:\ProgramData\AIEndpoint\logs"`

### Server Environment Variables
```bash
DATABASE_URL=postgres://ai_endpoint_user:your_password@localhost:5432/ai_agents?sslmode=disable
SERVER_PORT=8070
OFFLINE_TIMEOUT_SECONDS=90
OFFLINE_CHECK_INTERVAL_SECONDS=30
SCHEDULER_DISPATCH_INTERVAL_SECONDS=10
SCHEDULER_BATCH_SIZE=50
AGENT_JWT_SECRET=your_agent_shared_secret
ADMIN_JWT_SECRET=your_admin_shared_secret
ADMIN_JWT_TTL_SECONDS=3600
QUEUE_ENABLED=true
QUEUE_PROVIDER=nats
NATS_URL=nats://localhost:4222
QUEUE_SUBJECT_PREFIX=chat
QUEUE_AGENT_CHAT_ACTIVE=true
QUEUE_AGENT_CHAT_SUBJECT=agent.chat.shadow
QUEUE_AGENT_CHAT_CONSUMER_GROUP=agent-chat-workers
QUEUE_AGENT_CHAT_MAX_ATTEMPTS=4
QUEUE_AGENT_CHAT_DLQ_SUBJECT=agent.chat.shadow.dlq
LOG_DIR=logs
LOG_TO_CONSOLE=true
```

### Queue Worker (chat-worker)

Start queue worker for asynchronous personal chat execution:

```bash
export QUEUE_ENABLED=true
export QUEUE_PROVIDER=nats
export NATS_URL=nats://localhost:4222
export QUEUE_SUBJECT_PREFIX=chat
export QUEUE_AGENT_CHAT_ACTIVE=true
export QUEUE_AGENT_CHAT_SUBJECT=agent.chat.shadow
export QUEUE_AGENT_CHAT_CONSUMER_GROUP=agent-chat-workers
export QUEUE_AGENT_CHAT_MAX_ATTEMPTS=4
export QUEUE_AGENT_CHAT_DLQ_SUBJECT=agent.chat.shadow.dlq
go run ./cmd/chat-worker
```

DLQ inspection helper:

```powershell
.\scripts\show-chat-dlq.ps1 -Tail 80
```

### Admin Login

- Login page: `GET /`
- Session timeout page: `GET /session-timeout`
- Session is stored in an HttpOnly cookie and refreshed on each authenticated request.
- Default admin user (first run): username `admin`, password `admin` (forced change on first login).

## Offline Detection

Agents are marked offline when:
1. No heartbeat received for 90 seconds (configurable)
2. Detected by periodic background checker (runs every 30 seconds)

Agent status updated to "offline" in database and reflected in UI.

## System Information Collection

### Windows (via CIM/WMI)
- **ComputerSystemProduct**: Vendor, Model, Serial Number
- **BaseBoard**: Motherboard
- **Win32_BIOS**: Manufacturer, Version, Release Date
- **Win32_DiskDrive**: Physical disks
- **Win32_LogicalDisk**: Mounted drives with capacity/usage

### Other Platforms
- Linux/macOS agent binaries are supported via cross-compilation.
- Some diagnostics collection paths are Windows-first; on non-Windows runtimes, unavailable diagnostics are reported explicitly in chat responses.

## Build Agent Binaries (Linux/macOS)

One-command PowerShell helper (from repository root):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-agent-all.ps1
```

This builds:
- `bin/agent-linux-amd64`
- `bin/agent-linux-arm64`
- `bin/agent-darwin-amd64`
- `bin/agent-darwin-arm64`

Optional flags:
- `-OutDir <path>` to change output directory
- `-NoClean` to keep existing artifacts

## Commands (Server to Agent)

The server can queue commands for agents. Agents poll for commands and acknowledge results.

### JWT Requirements

- Agent tokens must include `sub=<agent_id>` and `role=agent`.
- Admin tokens must include `role=admin`.
- Both are signed with HS256 using `AGENT_JWT_SECRET` (agent) and `ADMIN_JWT_SECRET` (admin).

### Endpoints

- `POST /login` - username/password login (form)
- `POST /admin/login` - username/password login (JSON for API clients)
- `POST /admin/logout` - clear admin session cookie
- `GET /session-timeout` - re-authenticate when session expires
- `POST /api/commands` (admin) - create a command
- `GET /api/commands?agent_id=...` (admin) - list recent commands
- `GET /api/commands/next` (agent) - poll for next command
- `POST /api/commands/ack` (agent) - acknowledge execution
- `POST /api/heartbeat` (agent) - send heartbeat
- `POST /api/metrics` (agent) - ingest metrics sample
- `GET /api/metrics?agent_id=...` (admin) - list metrics history
- `GET /api/metrics/stream?agent_id=...` (admin) - SSE stream of latest metrics
- `GET /api/chat/messages?scope=global|agent&agent_id=...&limit=...` (admin) - list chat messages
- `POST /api/chat/messages` (admin) - post a chat message
- `GET /api/schedules?limit=...` (admin) - list schedules
- `POST /api/schedules` (admin) - create a schedule
- `PUT /api/schedules/{id}` (admin) - update a schedule
- `DELETE /api/schedules/{id}` (admin) - delete a schedule
- `GET /api/os-patch/policy` (admin) - get merged OS patch policy
- `POST /api/os-patch/policy` (admin) - save OS patch policy
- `POST /api/os-patch/policy/reset` (admin) - reset OS patch policy
- `GET /api/os-patch/policy/audit` (admin) - list OS patch policy audit entries
- `GET /api/reports/executions` (admin) - list schedule execution reports
- `GET /api/issues?agent_id=...&status=active|resolved&limit=...` (admin) - list detected issues (alerts)
- `GET /api/issues/{id}` (admin) - get full issue details and recommended actions
- `POST /api/issues/{id}/actions` (admin) - execute or schedule remediation action from issue plan

Metrics history endpoint supports optional filters:
- `range=10m|1h|4h|12h|24h` (preferred)
- `since=<RFC3339 timestamp>`
- `limit=<n>`

## Automated Issue Detection, Remediation, and Protection

The server automatically identifies issues from heartbeat + metrics telemetry and stores them as durable issue records in `agent_issues`.

### Built-in detectors
- Sustained high CPU usage
- Sustained high memory usage
- Network packet-storm anomaly
- Reboot required
- Critical/security updates pending
- Missing security controls (antivirus/firewall)
- Stale patch scan data

### Protection mechanisms
- Issue deduplication by `(agent_id, issue_key)` to prevent duplicate event storms
- Auto-resolve when conditions recover
- Severity-based prioritization
- Action audit trail in `issue_action_audit` for compliance and rollback visibility
- Scheduler-side power command deduplication: duplicate in-flight `restart`/`shutdown` commands (status `queued` or `dispatched`) for the same agent are skipped to prevent reboot/shutdown loops

### Issue Lifecycle (Alerts)
- Detection: heartbeat and metrics pipelines evaluate conditions and upsert issues into `agent_issues`
- De-duplication: repeated detections update `last_seen_at` on the same `(agent_id, issue_key)` issue
- Resolution: issues auto-resolve when detector conditions are no longer present
- Actioning: admins can run-now or schedule recommended/custom actions via `/api/issues/{id}/actions`
- Auditing: every action request is recorded in `issue_action_audit` with creator, mode, result, and related command/schedule IDs

### Execute or Schedule Remediation from Issue Actions

Run an issue action now:
```bash
curl -X POST http://localhost:8070/api/issues/42/actions \
	-H "Content-Type: application/json" \
	-H "Authorization: Bearer <admin_token>" \
	-d '{
		"action_id":"cpu-process-snapshot",
		"mode":"run_now"
	}'
```

Schedule a remediation action:
```bash
curl -X POST http://localhost:8070/api/issues/42/actions \
	-H "Content-Type: application/json" \
	-H "Authorization: Bearer <admin_token>" \
	-d '{
		"action_id":"memory-ai-analysis",
		"mode":"schedule",
		"run_at":"2026-03-01T23:00:00Z",
		"recurrence_rule":"weekdays",
		"enabled":true
	}'
```

You can also submit custom actions without `action_id` by providing:
- `kind`: `command | task | script`
- `command_type`: e.g. `powershell`, `cmd`, `shell`, `restart`, `ai_task`
- `payload`: command/script text or ai_task instruction/payload

This allows admins to run now or schedule commands, AI tasks, and scripts directly from generated recommendations/action plans.

## Chat Windows

- Global chat window is available on the agents dashboard (`/agents`).
- Personal chat window is available on each agent detail page (`/agents/{agent_id}`).
- Both chats are admin-authenticated and use live streaming with polling fallback.
- Chat windows render the full loaded message list (chat pagination controls removed).
- Both chats load latest messages at the bottom, show unread/new-message indicators when you are scrolled up, and provide a quick jump-to-bottom control.
- Personal chat supports command intents:
	- `cmd: <command>`
	- `powershell: <command>`
	- `shell: <command>`
- Personal chat posts an immediate progress event (`Working on your request...`) with the quoted request when a queued task starts processing.
- Personal chat AI responses include endpoint profile context (agent identity, OS/hardware, and security fields) to improve device-specific answers.
- Personal chat AI responses can include live diagnostics context for the subject endpoint (disk, memory, top processes, network, updates, services, and recent system events) based on your prompt.
- Global chat now supports governed fleet actions with explicit proposal and confirmation flow.
- Global chat can run in AI researcher mode with conversation memory + live fleet statistics + active issue context.

### How to Use Global Chat Actions

- Ask for fleet summary/status:
	- `fleet summary`
	- `global status`
- Propose a governed action (no execution yet):
	- `cmd: ipconfig /flushdns @online`
	- `powershell: Get-Service wuauserv @all`
	- `cmd: hostname @agent:<agent_id>`
	- `restart @online`
- The system returns a proposal token like `#G-12` with target count and governance results.
- Execute only after explicit confirmation:
	- `confirm #G-12`
- Abort a pending proposal:
	- `cancel #G-12`
- Proposal rules:
	- token is bound to the proposing admin
	- proposal expires automatically after 5 minutes
	- governance denylist/allowlist checks are evaluated per target agent before queueing

### Global Chat Research Assistant (AI + Memory + System Data)

- For non-command global chat prompts, the server can use an AI researcher response pipeline.
- The AI prompt includes:
	- recent global conversation memory
	- live fleet statistics (total/online/offline + severity distribution)
	- current active issue highlights
- Governed execution flow remains unchanged: AI can advise, but execution still requires explicit proposal and `confirm #G-<id>`.

Environment variables:
- `GLOBAL_CHAT_AI_ENABLED` (default: `true`)
- `GLOBAL_CHAT_AI_PROVIDER` (default inherits `AGENT_AI_PROVIDER`, usually `ollama`)
- `GLOBAL_CHAT_AI_ENDPOINT` (default inherits `AGENT_AI_ENDPOINT`)
- `GLOBAL_CHAT_AI_MODEL` (default inherits `AGENT_AI_MODEL`)
- `GLOBAL_CHAT_AI_API_KEY` (default inherits `AGENT_AI_API_KEY`)
- `GLOBAL_CHAT_AI_TIMEOUT_SECONDS` (default: `25`)
- `GLOBAL_CHAT_AI_SYSTEM_PROMPT` (optional custom researcher prompt)

### How to Use Personal Chat

- Use natural language for general conversation and endpoint questions (for example: `how is device health` or `what's the current cpu temperature`).
- To force a full diagnostics snapshot immediately, use: `run diagnostics now` (also supports `diagnostics report` / `full diagnostics`).
- For actions/commands, chat uses a confirmation gate:
	1. You ask with an explicit prefix (for example: `cmd: ping -n 4 8.8.8.8`)
	2. Agent proposes the command
	3. You reply `confirm` to execute or `cancel` to abort
- Explicit command formats are still supported:
	- `cmd: <command>`
	- `powershell: <command>`
	- `shell: <command>`
- If you reply `confirm`/`cancel` without a pending request, the agent tells you no command is waiting.
- Pending command proposals expire automatically after a short timeout (5 minutes).

### Conversation Behavior

- Personal chat keeps recent memory to stay context-aware and conversational.
- If an AI backend is unavailable or times out, the agent falls back to local conversational responses and command intent handling.
- On timeout, personal chat returns a quick fallback response and may include an immediately available device snapshot for context.
- When `AGENT_AI_ENDPOINT` points to local Ollama (`http://localhost:11434/...`), the agent auto-uses Ollama behavior even if provider defaults were not set as expected.

## Governance-Enforced Chat Commands

- For agent-scope chat messages that resolve to executable commands, the server evaluates governance policy before queueing:
	- denylist (`script_denylist`) is applied first
	- allowlist (`script_allowlist`) is applied next when non-empty
- If blocked, the server writes an immediate personal chat response explaining the policy block reason.
- Matching supports exact command names and prefix wildcard rules (for example: `net*`).

### Governance Query Prompts

- Prompts like `is format command allowed in device profile` are answered deterministically by the server from merged policy state.
- Response includes:
	- verdict (`ALLOWED` or `NOT ALLOWED`)
	- reason (`blocked by denylist`, `not present in allowlist`, and so on)
	- effective allowlist and denylist for that agent

### Command Types

- `ping` - returns `pong`
- `echo` - returns payload as output
- `shell` - executes payload with the platform default shell (`cmd /C` on Windows, `sh -c` on Linux/macOS)
- `cmd` - executes payload with `cmd /C` (Windows only)
- `powershell` - executes payload with PowerShell (`powershell` on Windows, `pwsh` on Linux/macOS if installed)
- `restart` - initiates system restart
- `shutdown` - initiates system shutdown
- `ai_task` - structured Mother→Child AI task payload with child result returned in command acknowledgement output

## Scheduling (Task/Command/Script/Patch)

- Schedules are stored in PostgreSQL and dispatched by a server background loop.
- Supported `kind` values: `task`, `command`, `script`, `patch`.
- Supported targets:
	- `target_scope=agent` with `target_agent_id`
	- `target_scope=group` with `target_group_id` (dispatches to all agents in that group)
- Dispatch behavior:
	- one-time schedules (`repeat_interval_seconds=0`) execute once and auto-disable
	- recurring schedules execute every `repeat_interval_seconds`
	- `task` schedules are queued as `ai_task`
	- `script` and `patch` schedules default to `powershell` when `command_type` is omitted

Example schedule payload:

```json
{
	"name": "Nightly health ping",
	"kind": "command",
	"target_scope": "group",
	"target_group_id": 1,
	"command_type": "ping",
	"payload": "8.8.8.8",
	"run_at": "2026-02-27T01:00:00Z",
	"repeat_interval_seconds": 86400,
	"enabled": true,
	"next_run_at": "2026-02-27T01:00:00Z"
}
```

### MCP Mother/Child AI Task (MVP)

Use `command_type=ai_task` with JSON payload:

```json
{
	"task_id": "task-001",
	"mother_role": "coordinator",
	"child_intent": "work",
	"title": "Investigate endpoint issue",
	"instruction": "Collect process and service status related to VPN client",
	"context": "Ticket INC-2026-001",
	"requires_approval": true,
	"scheduled_at": "2026-02-26T10:30:00Z"
}
```

Allowed `mother_role` values:
- `instructor`
- `guardian`
- `approver`
- `coordinator`
- `scheduler`

Allowed `child_intent` values:
- `work`
- `resolve`
- `suggest`
- `identify`
- `complain`

The agent returns a structured JSON result in command `output` including:
- task id
- child intent
- state (`completed`, `blocked`, or `awaiting_approval`)
- summary/details
- timestamp

## Real-Time Metrics

Agents sample CPU, memory, and network statistics every `METRICS_INTERVAL_SECONDS` and post to the server.
The UI renders live charts using Server-Sent Events (SSE) and reads recent history from PostgreSQL.
Network throughput is displayed as `MB/s`.

## Project Structure

```
├── cmd/
│   ├── agent/          # Agent entry point
│   └── server/         # Server entry point
├── internal/
│   ├── agent/          # System info collection
│   ├── migrations/     # Database migrations
│   ├── server/         # Server logic
│   └── transport/      # Request/response types
└── README.md
```

## Migration Strategy

### Current Deployment Line

Migrations are additive and run automatically on startup.
Current schema baseline includes:
- `001` agents
- `002` commands
- `003` users
- `004` metrics
- `005` OS/security columns
- `006` governance tables
- `007` chat messages
- `008-010` schedules and command linkage
- `011-012` OS patch policy + audit

### Future Versions

New migrations added as needed with automatic execution on startup.

## Version History

## Release Notes

- See [RELEASE_NOTES.md](RELEASE_NOTES.md) for the consolidated latest release summary.
- See [RELEASE_PR_NOTE.md](RELEASE_PR_NOTE.md) for detailed PR/release rollout notes.

### v1.x (2026)
- Initial agent/server release with heartbeat and inventory
- Admin auth, commands, metrics, governance, chat, schedules, and reports
- Dedicated OS patch policy workflows with server-side persistence and audit
