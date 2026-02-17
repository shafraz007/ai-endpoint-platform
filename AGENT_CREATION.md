# Agent Auto-Creation & Heartbeat System

## Feature: Automatic Agent Creation on First Heartbeat

When an agent sends its first heartbeat to the server, it is **automatically created** in the database if it doesn't already exist.

### How It Works

The server uses PostgreSQL's **UPSERT** (INSERT ... ON CONFLICT) pattern:

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

Each heartbeat includes:
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

### Database Schema

The `agents` table has:
- Primary Key: `id` (auto-increment)
- Unique Key: `agent_id` (for conflict detection)
- All fields with proper types and default values
- Automatic timestamps: `date_added`, `updated_at`, `created_at`

### Running the System

**Terminal 1 - Start Server:**
```bash
go run ./cmd/server
```

Output:
```
2026/02/16 09:04:39 PostgreSQL connected successfully
2026/02/16 09:04:39 ✓ Migration 001_create_agents_table already applied
2026/02/16 09:04:39 ✓ Migration 002_add_agent_fields already applied
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

Two migrations handle the database schema:

1. **001_create_agents_table** - Creates the agents table with all columns
2. **002_add_agent_fields** - Adds any missing columns (for backward compatibility)

Migrations are tracked in `schema_migrations` table and run automatically on server startup.

### Key Features

✅ Automatic agent creation on first heartbeat
✅ UPSERT pattern ensures idempotent updates
✅ Database migrations with change tracking
✅ No manual table creation needed
✅ Backward compatible migration system
✅ Comprehensive system information collection
