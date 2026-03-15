# Agent Auto-Creation & Heartbeat System

## Feature: Automatic Agent Creation on First Heartbeat

When an agent sends its first heartbeat to the server, it is **automatically created** in the database if it doesn't already exist.

### How It Works

The server uses PostgreSQL's **UPSERT** (INSERT ... ON CONFLICT) pattern via `server.UpsertAgent(...)`:

```sql
INSERT INTO agents (agent_id, hostname, domain, public_ip, private_ip, ...)
VALUES ($1, $2, $3, ...)
ON CONFLICT (agent_id)
DO UPDATE SET
  hostname = EXCLUDED.hostname,
  domain = EXCLUDED.domain,
  ...
```

### Behavior

1. **First Heartbeat**: If agent doesn't exist (by `agent_id`), it is **created** with all the data from the heartbeat
2. **Subsequent Heartbeats**: Agent record is **updated** with latest data (IP, status, last_seen, etc.)

### Data Sent by Agent

Each heartbeat includes (including extended endpoint context fields):
- `agent_id` - Unique identifier (UUID)
- `hostname` - Machine hostname
- `domain` - Domain/FQDN
- `public_ip` - Public IP address
- `private_ip` - Private network IP
- `last_login` - Last user login timestamp
- `last_reboot` - Last system reboot time
- `timezone` - System timezone
- `agent_version` - Agent software version
- `status` - Current status (online/offline)
- `last_seen` - Timestamp of last heartbeat
- OS/security details (edition/version/build, AV, firewall, etc.)
- Hardware + storage snapshots (disks/drives)

### Database Schema

The `agents` table has:
- Primary Key: `id` (auto-increment)
- Unique Key: `agent_id` (for conflict detection)
- All fields with proper types and default values
- Automatic timestamps and status transitions used by offline checker

### Running the System

**Terminal 1 - Start Server:**
```bash
go run ./cmd/server
```

Output:
```
2026/02/16 09:04:39 PostgreSQL connected successfully
2026/02/16 09:04:39 ✓ Migration 001_create_agents_table_v1_0_0 already applied
...
2026/02/16 09:04:39 ✓ Migration 014_create_agent_issues_table_v2_0_0 already applied
2026/02/16 09:04:39 Starting server on port 8070
```

**Terminal 2 - Start Agent:**
```bash
go run ./cmd/agent
```

Output:
```
2026/02/16 09:04:23 Agent started - ID: dc0621ed-4d62-4308-8332-ad7136030483, Hostname: Venom, Version: 1.0.0
2026/02/16 09:04:23 Server URL: http://localhost:8070, Heartbeat interval: 30s
2026/02/16 09:04:24 Heartbeat sent successfully
```

**Server receives:**
```
2026/02/16 09:04:24 Heartbeat received from agent: dc0621ed-4d62-4308-8332-ad7136030483 (Venom)
```

### Migration System

Current migration line includes:

1. **001-005** - agent, command, users, metrics, OS/security fields
2. **006-007** - governance and chat tables
3. **008-010** - schedule engine and command linkage
4. **011-012** - OS patch policy and audit tables
5. **013-014** - patch inventory, alert/issue tables, and issue action audit

### Issue System Integration (Alerts)

Heartbeat payloads are also used to drive server-side durable alert detection.

- The server evaluates heartbeat and patch posture signals and upserts alerts into `agent_issues`.
- Alerts are deduplicated by `(agent_id, issue_key)` and move between `active` and `resolved` as endpoint state changes.
- Recommended remediation actions can be executed immediately or scheduled through issue action APIs.
- All remediation actions are recorded in `issue_action_audit` for traceability.

For power actions generated from schedules, the dispatcher now skips duplicate in-flight `restart`/`shutdown` commands per agent when the same command type is already `queued` or `dispatched`.

### Queue-backed Personal Chat Integration

Personal chat execution now supports asynchronous queue flow:

1. Admin posts personal chat message.
2. Server publishes `agent_chat_task` to queue subject (`chat.agent.chat.shadow` by default).
3. `cmd/chat-worker` consumes queue events, creates idempotent `ai_task` command records, and retries transient failures.
4. Agent dequeues `ai_task`, executes AI/tool logic, and acknowledges output.
5. Server relays progress + final response back into personal chat stream.

Worker retry/DLQ controls:
- `QUEUE_AGENT_CHAT_MAX_ATTEMPTS` (default `4`)
- `QUEUE_AGENT_CHAT_DLQ_SUBJECT` (default `agent.chat.shadow.dlq`)

Operational helper:

```powershell
.\scripts\show-chat-dlq.ps1 -Tail 80
```

Migrations are tracked in `schema_migrations` table and run automatically on server startup.

### Key Features

✅ Automatic agent creation on first heartbeat
✅ UPSERT pattern ensures idempotent updates
✅ Database migrations with change tracking
✅ No manual table creation needed
✅ Backward compatible additive migration system
✅ Comprehensive system information collection
