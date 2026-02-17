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
LOG_DIR=logs
LOG_TO_CONSOLE=true
```

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

### Command Types

- `ping` - returns `pong`
- `echo` - returns payload as output
- `shell` - executes payload as a shell command
- `restart` - initiates system restart
- `shutdown` - initiates system shutdown

On Windows, PowerShell commands are supported by prefixing with PowerShell cmdlets (e.g., `Get-Process`).

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
