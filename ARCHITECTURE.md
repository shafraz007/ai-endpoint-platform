# AI Endpoint Platform - Architecture & Design

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Web Browsers                             │
│                    (http://localhost:8080)                       │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Server (Go HTTP)      │
                    │  Port: 8080             │
                    │  Routes:                │
                    │  - /agents              │
                    │  - /agents/{id}         │
                    │  - /api/agents/...      │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   PostgreSQL Database   │
                    │   Database: ai_agents   │
                    │   Connection Pool       │
                    └────────────┬────────────┘
                                 │
                ┌────────────────┼────────────────┐
            ┌───▼────┐       ┌───▼────┐       ┌───▼────┐
            │ agents │       │ agents │       │ agents │
            │ table  │       │ table  │       │ table  │
            └───┬────┘       └───┬────┘       └───┬────┘
                │               │               │
        ┌───────▼────────┬──────▼────────┬──────▼───────┐
        │                │               │               │
    ┌───▴────┐       ┌───▴────┐      ┌──▴────┐      ┌──▴────┐
    │ Agent 1 │       │ Agent 2 │      │Agent 3 │      │Agent N │
    │(Windows)│       │(Linux)  │      │(macOS) │      │(...)   │
    └─────────┘       └─────────┘      └────────┘      └────────┘
         │                 │                 │              │
         └─────────────────┴─────────────────┴──────────────┘
                    Heartbeat (every 30s)
                    POST /api/agents/heartbeat
```

## Component Architecture

### Agent Architecture

**Responsibilities:**
- System information collection
- Hardware detection (Windows/Linux/macOS)
- Network communication with server
- Periodic heartbeat transmission
- Graceful shutdown handling

**Key Files:**
- `cmd/agent/main.go` - Entry point, heartbeat loop
- `internal/agent/systeminfo.go` - System information collection
- `internal/config/config.go` - Configuration loading

### Server Architecture

**Responsibilities:**
- Receive and persist heartbeat data
- Track agent status (online/offline)
- Offline agent detection
- Web UI and REST API
- Database migrations

**Key Files:**
- `cmd/server/main.go` - Entry point, routing
- `internal/server/agents.go` - Agent data model
- `internal/server/agent_repo.go` - Database access
- `internal/migrations/migrations.go` - Schema management

## Migration Strategy

### v1.0.0 - Initial Deployment

Single consolidated migration creates complete schema:
```
Migration: 001_create_agents_table_v1_0_0

Creates:
✓ agents table with all v1.0.0 fields
✓ indexes for optimal query performance
✓ schema_migrations tracking table

All migrations run automatically on server startup.
```

### Benefits of Consolidated Migration

1. **Clean Initial State** - No incremental ALTER TABLE operations
2. **Consistent Deployments** - All instances start with identical schema
3. **Simplified Migrations** - Single point of setup
4. **Easier Backups** - Full schema in one operation

## Version Roadmap

```
v1.0.0 (Current - Feb 2026)
├─ Agent & Server architecture
├─ System information collection
├─ Hardware monitoring (Windows)
├─ Storage monitoring (disks/drives)
├─ Web UI (Overview, Hardware, Disks tabs)
├─ Offline detection
├─ PostgreSQL persistence
└─ Automatic migrations

v1.1.0 (Planned)
├─ Commands from server → agent
├─ Real-time data streaming (WebSocket)
├─ Agent grouping/policies
├─ Advanced monitoring (alerts, trends)
├─ Linux/macOS hardware collection
└─ Authentication & authorization

v2.0.0 (Future)
├─ Multi-tenant support
├─ Agent plugins system
├─ Distributed tracing
├─ Event sourcing
└─ Async command queue
```

## Next Development Priorities

1. **Graceful Shutdown** - Complete offline checker shutdown
2. **Command Execution** - Server → agent task execution
3. **Real-time Streaming** - WebSocket support for live updates
4. **Linux Support** - Hardware collection for Linux agents
5. **Authentication** - JWT-based API security
