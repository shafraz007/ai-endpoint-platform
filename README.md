# AI Endpoint Platform v1.0.0

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

### v1.0.0 (Current)

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

### Planned Features (v1.1.0+)

- 🔲 Real-time data streaming
- 🔲 Agent grouping/policies
- 🔲 Advanced monitoring (alerts, thresholds)
- 🔲 Multi-server setup (federation, load balancing)

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
export SERVER_PORT=8080
```

3. Start server (migrations run automatically):
```bash
go run ./cmd/server
```

4. Start agent:
```bash
export SERVER_URL=http://localhost:8080
go run ./cmd/agent
```

## Configuration

### Agent Environment Variables
```bash
SERVER_URL=http://localhost:8080
HEARTBEAT_INTERVAL_SECONDS=30
REQUEST_TIMEOUT_SECONDS=10
MAX_RETRIES=3
RETRY_BACKOFF_SECONDS=2
AGENT_JWT_SECRET=your_agent_shared_secret
AGENT_JWT_TTL_SECONDS=300
COMMAND_POLL_INTERVAL_SECONDS=30
COMMAND_TIMEOUT_SECONDS=60
METRICS_INTERVAL_SECONDS=5
AGENT_AI_ENDPOINT=https://api.openai.com/v1/chat/completions
AGENT_AI_API_KEY=your_provider_api_key
AGENT_AI_MODEL=gpt-4o-mini
AGENT_AI_SYSTEM_PROMPT=You are an endpoint child AI agent. Reply concisely, actionably, and safely.
AGENT_AI_PROVIDER=openai
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
  - `AGENT_AI_ENDPOINT=http://localhost:11434/v1/chat/completions`
  - `AGENT_AI_MODEL=llama3.2` (or any model you pulled)
  - `AGENT_AI_API_KEY=` (not required)

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

### Server Environment Variables
```bash
DATABASE_URL=postgres://ai_endpoint_user:your_password@localhost:5432/ai_agents?sslmode=disable
SERVER_PORT=8080
OFFLINE_TIMEOUT_SECONDS=90
OFFLINE_CHECK_INTERVAL_SECONDS=30
AGENT_JWT_SECRET=your_agent_shared_secret
ADMIN_JWT_SECRET=your_admin_shared_secret
ADMIN_JWT_TTL_SECONDS=3600
LOG_DIR=logs
LOG_TO_CONSOLE=true
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
- Linux/macOS implementations coming in v1.1.0

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
- `POST /api/metrics` (agent) - ingest metrics sample
- `GET /api/metrics?agent_id=...` (admin) - list metrics history
- `GET /api/metrics/stream?agent_id=...` (admin) - SSE stream of latest metrics
- `GET /api/chat/messages?scope=global|agent&agent_id=...&limit=...` (admin) - list chat messages
- `POST /api/chat/messages` (admin) - post a chat message

Metrics history endpoint supports optional filters:
- `range=10m|1h|4h|12h|24h` (preferred)
- `since=<RFC3339 timestamp>`
- `limit=<n>`

## Chat Windows

- Global chat window is available on the agents dashboard (`/agents`).
- Personal chat window is available on each agent detail page (`/agents/{agent_id}`).
- Both chats are admin-authenticated and poll every 5 seconds.
- Personal chat supports command intents:
	- `cmd: <command>`
	- `powershell: <command>`
	- `shell: <command>`
	- natural language ping requests (for example: `please ping sp.parcelat.com`)
- Personal chat AI responses include endpoint profile context (agent identity, OS/hardware, and security fields) to improve device-specific answers.

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

### v1.0.0 (First Deployment)

Single consolidated migration `001_create_agents_table_v1_0_0` creates complete schema:
- All fields present from start
- No incremental ALTER TABLE
- Clean initial state

### Future Versions

New migrations added as needed with automatic execution on startup.

## Version History

### v1.0.0 (2026-02-17)
- Initial release
- Full agent-server architecture
- Hardware and storage monitoring
- Web UI with offline detection
- PostgreSQL persistence
