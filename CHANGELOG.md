# Changelog

All notable changes to the AI Endpoint Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-02-17

### Added

- OS & Security tab in agent detail page with comprehensive system information
- OS information fields: OS edition, version, build, Windows 11 eligibility, .NET version, Office version
- Security information fields: Antivirus, Anti-spyware, Firewall status
- New database migration (005) to add OS and security columns to agents table
- TLS 1.2 compatibility tracking and display
- Agent-side OS info collection using PowerShell commands (OS details, .NET version, Office version, antivirus/firewall status)
- OS info sent during agent heartbeat and stored in database
- Automatic detection of Windows Defender, Windows Firewall, and Windows Security Center

### Changed

- Chart layout now displays vertically instead of grid layout
- Metrics auto-refresh removed (manual refresh required)
- Agent heartbeat expanded to include OS and security information
- Metrics auto-refresh removed (static display, manual refresh required)

## [1.0.2] - 2026-02-17

### Added

- Metrics ingestion and history APIs (`POST /api/metrics`, `GET /api/metrics`, `GET /api/metrics/stream`)
- Agent metrics collector for CPU, memory, and network throughput sampling
- Metrics dashboard tab with chart-based visualizations
- Explicit remote command types: `cmd` and `powershell`

### Changed

- Metrics history now supports duration filters: `10m`, `1h`, `4h`, `12h`, `24h`
- Network throughput chart unit updated from `KB/s` to `MB/s`
- Windows shell execution behavior is deterministic (`shell` uses `cmd /C`; `powershell` uses PowerShell explicitly)

## [1.0.1] - 2026-02-17

### Added

- Admin login with DB-backed users and session cookies
- Login, change-password, and session-timeout pages
- Default admin seeding (admin/admin) with forced password change
- Server → agent command pipeline (queue, poll, acknowledge)
- Command types: ping, echo, shell, cmd, powershell, restart, shutdown
- Explicit cmd/powershell execution support for remote commands
- Daily rotating logs for server and agent
- Commands tab in agent detail UI with history

### Changed

- Agents UI now requires admin login
- Admin session uses sliding expiration on authenticated requests
- Default admin seeding uses conflict-safe insert to avoid HA race noise
- Metrics history API supports duration-based range filters (`10m`, `1h`, `4h`, `12h`, `24h`)
- Network throughput chart displays `MB/s` instead of `KB/s`

## [1.0.0] - 2026-02-17

### Initial Release

**First production release of AI Endpoint Platform with parent-child MCP-like architecture.**

#### Added - Agent Features

- ✅ Automatic agent ID generation and persistence
- ✅ Autonomous system information collection:
  - Hostname, domain, timezone detection
  - Public and private IP address discovery
  - OS detection (Windows, Linux, macOS)
  - Last login and reboot timestamp tracking
- ✅ Comprehensive hardware information collection (Windows):
  - Computer system product (vendor, model, serial number) via Win32_ComputerSystemProduct
  - Motherboard information via Win32_BaseBoard
  - BIOS details (manufacturer, version, release date) via Win32_BIOS
  - Processor information via Win32_Processor
  - Memory capacity via Win32_ComputerSystem
  - Video card information via Win32_VideoController
  - Sound device information via Win32_SoundDevice
  - System drive information via Win32_LogicalDisk
- ✅ Physical disk information collection:
  - Index, Model, Size, Interface Type, Status, Partition count
  - Via Win32_DiskDrive WMI class
  - Returned as JSON array for flexible storage
- ✅ Logical drive information collection:
  - Drive letter, Total capacity, Free space, Usage percentage
  - Via Win32_LogicalDisk WMI class
  - Real-time calculation of usage statistics
- ✅ Network information collection:
  - MAC addresses via Win32_NetworkAdapterConfiguration
  - Multiple adapter support
- ✅ Periodic heartbeat mechanism:
  - Configurable interval (default 30 seconds)
  - Comprehensive payload with all collected data
  - Automatic retry on failure
- ✅ Graceful shutdown handling (SIGINT, SIGTERM)
- ✅ Configuration via environment variables
- ✅ Local configuration persistence (~/.config/ai-endpoint-agent/)
- ✅ WMI query optimization:
  - Uses PowerShell Get-CimInstance (more reliable than wmic)
  - Works in virtualized environments
  - 5-second timeout per query
  - Silent error handling with graceful fallback

#### Added - Server Features

- ✅ HTTP REST API for agent heartbeat reception
- ✅ Agent data persistence to PostgreSQL
- ✅ Automatic database migrations on startup
  - Single consolidated v1.0.0 migration
  - Complete schema creation in one operation
  - Migration tracking via schema_migrations table
- ✅ Agent status tracking (online/offline)
- ✅ Automatic offline agent detection:
  - Configurable timeout (default 30 seconds)
  - Background checker goroutine (runs every 5 seconds)
  - Graceful status updates without blocking
- ✅ REST API endpoints:
  - `POST /api/agents/heartbeat` - Receive heartbeat data
  - `GET /api/agents` - List all agents (JSON)
  - `GET /api/agents/{id}` - Get agent details (JSON)
- ✅ Web UI with responsive design:
  - `GET /agents` - Agents list view
  - `GET /agents/{id}` - Agent detail view
- ✅ Web UI tabbed interface:
  - Overview tab: Basic agent information
  - Hardware tab: System specifications and hardware details
  - Disks tab: Physical disks and logical drives with usage visualization
- ✅ Real-time status indicators (online/offline badges)
- ✅ Dark gradient theme with modern styling
- ✅ Progress bars for disk usage visualization
- ✅ Responsive grid layout for equipment specifications
- ✅ Safe HTML rendering of JSON data (using template.JS wrapper)
- ✅ Proper JavaScript handling of numeric zero values (nullish coalescing operator)

#### Added - Database

- ✅ PostgreSQL schema with comprehensive agents table:
  - 31 columns covering all collected information
  - JSON storage for complex data (disks, drives)
  - Proper timestamp management
  - Status tracking for online/offline detection
- ✅ Optimized indexes:
  - idx_agents_agent_id (primary lookup)
  - idx_agents_last_seen (offline detection queries)
  - idx_agents_status (status filtering)
  - idx_agents_hostname (agent search)
- ✅ Connection pooling via pgx/v5
- ✅ Automatic connection timeout handling
- ✅ Transaction support for data consistency

#### Added - Documentation

- ✅ Comprehensive README.md
- ✅ Architecture documentation (ARCHITECTURE.md)
- ✅ Changelog (this file)
- ✅ Inline code comments
- ✅ Configuration documentation
- ✅ API reference
- ✅ Troubleshooting guide
- ✅ Deployment checklist

#### Technical Details

**Agent:**
- Language: Go 1.25.0
- Default heartbeat interval: 30 seconds
- System info collection timeout: 5 seconds per WMI query
- Memory footprint: ~20-30 MB per agent process

**Server:**
- Language: Go 1.25.0
- Default port: 8080
- Offline detection timeout: 30 seconds
- Checker interval: 5 seconds
- Heartbeat payload: ~1-2 KB

**Database:**
- PostgreSQL 12+
- pgx/v5 driver
- Single consolidated migration for v1.0.0

### Known Limitations

- ❌ No authentication (local network assumed)
- ❌ HTTP only (no HTTPS/TLS in v1.0.0)
- ❌ Single server only (no clustering)
- ❌ No agent-to-server commands
- ❌ No WebSocket support (polling only)
- ❌ Linux/macOS hardware collection not implemented
- ❌ No graceful shutdown for offline checker (cleanup on exit)
- ❌ Hard-coded pagination (not yet implemented)

### Infrastructure

- Single server instance
- Single PostgreSQL database
- In-memory agent status caching via database queries
- No message queue or distributed components

## [1.1.0] - Planned

- Server → agent command execution
- WebSocket support for real-time updates
- Agent grouping and policies
- Advanced monitoring (alerts, thresholds, trend analysis)
- Multi-server federation support
- Load balancing capabilities
- Linux/macOS hardware collection
- Authentication (JWT-based)
- Rate limiting
- Request/response compression

## [2.0.0] - Future

- Multi-tenant support
- Agent plugin system
- Distributed tracing
- Event sourcing architecture
- Async command queue
- Message broker integration
- Mobile agent support
- Machine learning for anomaly detection
- Advanced dashboarding
- RBAC (Role-Based Access Control)

---

## Upgrade Path

### From Earlier Versions to 1.0.0

This is the initial release. There is no upgrade path from earlier versions.

For new deployments:
1. Create PostgreSQL database
2. Set environment variables
3. Run server (migrations run automatically)
4. Start agents

## Migration Details

### v1.0.0 Migration: `001_create_agents_table_v1_0_0`

This is a **consolidated migration** that creates the complete v1.0.0 schema in a single operation:

```sql
CREATE TABLE agents (
    -- ... 31 columns for complete agent data ...
);

CREATE INDEX idx_agents_agent_id ON agents(agent_id);
CREATE INDEX idx_agents_last_seen ON agents(last_seen);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_hostname ON agents(hostname);
```

**Benefits:**
- Clean initial state (no incremental ALTER TABLE)
- Consistent across deployments
- Simplified and faster setup
- No leftover migration artifacts

## Performance Baseline

### Agent
- System info collection: 2-3 seconds
- Heartbeat transmission: 100-500ms
- Memory usage: 20-30 MB
- CPU usage: <5% idle, 10-20% during heartbeat

### Server
- Heartbeat processing: <10ms
- Database write: 10-50ms
- Offline detection: 10-100ms (every 5 seconds)
- Web UI page load: 50-200ms

## Breaking Changes

This is the initial release. No breaking changes from previous versions (N/A).

## Contributors

Initial development team:
- ai-endpoint-platform development team

## License

(To be specified)
