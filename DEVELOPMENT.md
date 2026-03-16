# Development Guide

This document provides guidance for developers working on the Armada Platform.

## Prerequisites

- **Go** 1.25.0 or higher
- **PostgreSQL** 12 or higher
- **Git** for version control
- **Your favorite editor** (VS Code, GoLand, Vim, etc.)

## Development Environment Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd ai-endpoint-platform
```

### 2. Install Go Dependencies

```bash
go mod tidy
go mod download
```

### 3. Set Up PostgreSQL

```bash
# Create database
createdb ai_agents

# Create development user (optional)
psql -U postgres -c "CREATE USER aidev WITH PASSWORD 'devpassword';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE ai_agents TO aidev;"
```

### 4. Configure Environment Variables

Create a `.env.development` file (example):

```bash
# Database
DATABASE_URL=postgres://aidev:devpassword@localhost:5432/ai_agents?sslmode=disable

# Server
SERVER_PORT=8070
OFFLINE_TIMEOUT_SECONDS=90
OFFLINE_CHECK_INTERVAL_SECONDS=30
AGENT_JWT_SECRET=dev_agent_secret
ADMIN_JWT_SECRET=dev_admin_secret
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

# Agent
SERVER_URL=http://localhost:8070
HEARTBEAT_INTERVAL_SECONDS=30
REQUEST_TIMEOUT_SECONDS=10
AGENT_JWT_SECRET=dev_agent_secret
AGENT_JWT_TTL_SECONDS=300
COMMAND_POLL_INTERVAL_SECONDS=30
COMMAND_TIMEOUT_SECONDS=60
METRICS_INTERVAL_SECONDS=5
AGENT_AI_PROVIDER=ollama
AGENT_AI_ENDPOINT=http://127.0.0.1:11434/api/chat
AGENT_AI_MODEL=llama3.2
AGENT_AI_API_KEY=
```

Source it before running:
```bash
source .env.development
```

### 5. Run Migrations

Migrations run automatically on server startup, but you can verify manually:

```bash
go run ./cmd/server
# Check logs for: "Starting server on port 8070"
```

## Building the Project

### Build Agent

```bash
go build -o bin/agent ./cmd/agent
./bin/agent
```

### Build Server

```bash
go build -o bin/server ./cmd/server
./bin/server
```

### Build Both

```bash
go build -o bin/agent ./cmd/agent && go build -o bin/server ./cmd/server
```

## Running the Project

### Terminal 1: Start Server

```bash
export DATABASE_URL=postgres://aidev:devpassword@localhost:5432/ai_agents?sslmode=disable
export SERVER_PORT=8070
export AGENT_JWT_SECRET=dev_agent_secret
export ADMIN_JWT_SECRET=dev_admin_secret
go run ./cmd/server
```

Expected output:
```
2026-02-27T10:30:00Z PostgreSQL connected successfully
2026-02-27T10:30:00Z ✓ Migration 012_create_os_patch_policy_audit_table_v1_8_1 already applied
2026-02-27T10:30:00Z Starting server on port 8070
```

### Terminal 2: Start Agent

```bash
export SERVER_URL=http://localhost:8070
export AGENT_JWT_SECRET=dev_agent_secret
go run ./cmd/agent
```

Expected output:
```
2026-02-17T10:30:05Z Loaded existing agent ID from ~/.config/ai-endpoint-agent/agent_id
2026-02-17T10:30:05Z Agent started - ID: <uuid>, Hostname: <hostname>, Version: 1.0.0
2026-02-17T10:30:05Z Server URL: http://localhost:8070, Heartbeat interval: 30s
2026-02-17T10:30:35Z Heartbeat sent successfully
```

### Terminal 3: Start Chat Worker

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

Expected output:
```
PostgreSQL connected successfully
chat worker starting (provider=nats subject=chat.agent.chat.shadow group=agent-chat-workers dlq=agent.chat.shadow.dlq max_attempts=4)
```

### Terminal 3: View Web UI

```bash
open http://localhost:8070/
```

Default admin login
- Username: `admin`
- Password: `admin`
- You will be prompted to change the password on first login.

## Code Organization

### cmd/ - Entry Points

```
cmd/
├── agent/
│   └── main.go          # Agent entry point, heartbeat loop
└── server/
    ├── main.go          # Server entry point, routing
    └── templates/       # HTML templates for web UI
        ├── agents.html
        ├── agent-detail.html
        ├── login.html
        ├── change-password.html
        ├── session-timeout.html
        ├── settings.html
        └── reports.html
```

### internal/ - Core Logic

```
internal/
├── agent/
│   ├── systeminfo.go    # System/hardware information collection
│   ├── osinfo.go        # OS/security details
│   └── metrics.go       # Local metrics sampling
├── config/
│   └── config.go        # Configuration loading from environment
├── migrations/
│   └── migrations.go    # Database schema management
├── server/
│   ├── agents.go        # Agent APIs and query helpers
│   ├── commands.go      # Command queue persistence
│   ├── chat.go          # Chat persistence
│   ├── governance.go    # Governance persistence
│   ├── schedules.go     # Schedule persistence + dispatch helpers
│   ├── reports.go       # Execution report persistence
│   └── users.go         # Admin user persistence
├── transport/
│   └── types.go         # Request/response types
└── auth/
    └── jwt.go           # JWT helpers
```

## Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./internal/agent -v
go test ./internal/server -v

# Run with coverage
go test -cover ./...

# Run specific test
go test -run TestMarkAgentsOffline ./internal/server -v
```

### Writing Tests

Example test structure:

```go
func TestOfflineDetection(t *testing.T) {
    // Arrange
    db := setupTestDB(t)
    defer db.Close()
    
    // Act
    err := MarkAgentsOffline(context.Background(), db)
    
    // Assert
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
}
```

### Integration Testing

For tests requiring database:

```bash
export DB_HOST=localhost
export DB_NAME=test_ai_agents
go test -run Integration ./... -v
```

Queue smoke helpers:

```powershell
.\tmp_report_smoke.ps1
.\scripts\show-chat-dlq.ps1 -Tail 80
```

## Code Style & Standards

### Go Code Style

- Follow [Effective Go](https://golang.org/doc/effective_go)
- Use `gofmt` for formatting:
  ```bash
  go fmt ./...
  ```
- Use `go vet` for code analysis:
  ```bash
  go vet ./...
  ```

### Naming Conventions

**Packages:**
```go
package agent      // snake_case in filesystem, lowercase in code
```

**Functions:**
```go
func GetSystemInfo() (*SystemInfo, error)      // PascalCase, exported
func getHardwareVendor() string                // camelCase, unexported
```

**Types:**
```go
type Agent struct {}               // PascalCase
type HeartbeatRequest struct {}    // PascalCase
```

**Constants:**
```go
const (
    DefaultHeartbeatInterval = 30 * time.Second
    DefaultTimeout           = 5 * time.Second
    agentVersion             = "1.0.0"
)
```

### Error Handling

```go
// Good: Wrap errors with context
return fmt.Errorf("failed to get system info: %w", err)

// Avoid: Generic errors
return errors.New("error")

// Good: Handle specific errors
if err != nil && errors.Is(err, sql.ErrNoRows) {
    // not found
}
```

### Comments

```go
// Package agent provides system information collection for the endpoint agent.
package agent

// GetSystemInfo collects comprehensive system information from the local machine.
// Returns SystemInfo struct with hostname, IP addresses, hardware details, etc.
// Returns error if critical information cannot be collected.
func GetSystemInfo() (*SystemInfo, error) {
    // ...
}

// getHardwareVendor retrieves computer vendor information from WMI.
// Returns "unknown" if WMI query fails (graceful degradation).
func getHardwareVendor() string {
    // ...
}
```

## Database Development

### Making Schema Changes

1. **For Development Only** - Drop and recreate:
   ```bash
   psql -U postgres -d ai_agents -c "DROP TABLE IF EXISTS agents CASCADE;"
   ```

2. **For Feature Development** - Alter table:
   ```go
   // In migrations.go, add new migration function:
   func addNewColumn(ctx context.Context, db *pgxpool.Pool) error {
       query := `ALTER TABLE agents ADD COLUMN new_field VARCHAR(255);`
       _, err := db.Exec(ctx, query)
       return err
   }
        ├── systeminfo.go    # System/hardware information collection
        ├── osinfo.go        # OS/security details
        └── metrics.go       # Local metrics sampling
   // Add to migrations slice:
   {
       Name: "002_add_new_column",
       Up:   addNewColumn,
   }
        ├── agents.go        # Agent APIs and query helpers
        ├── commands.go      # Command queue persistence
        ├── chat.go          # Chat persistence
        ├── governance.go    # Governance persistence
        ├── schedules.go     # Schedule persistence + dispatch helpers
        ├── reports.go       # Execution report persistence
        └── users.go         # Admin user persistence
   ```bash
   go run ./cmd/server
    └── auth/
        └── jwt.go           # JWT helpers
    "SELECT * FROM agents WHERE agent_id = $1", 
    agentID).Scan(&agent.ID, ...)

// Bad - don't do this
query := fmt.Sprintf("SELECT * FROM agents WHERE agent_id = '%s'", agentID)
```

## Working with WMI (Windows)

### Testing WMI Queries

```powershell
# Test a WMI query directly
Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object Vendor, Name, IdentifyingNumber

# Wrap in PowerShell script (like the agent does)
$ErrorActionPreference = 'SilentlyContinue'
$result = Get-CimInstance -ClassName Win32_ComputerSystemProduct
if ($result) {
    Write-Output $result.Vendor
}
```

### Common WMI Classes

| Class | Purpose | Example |
|-------|---------|---------|
| Win32_ComputerSystemProduct | Vendor, Model, Serial | Lenovo ThinkPad |
| Win32_BaseBoard | Motherboard | 21JK00DGAD |
| Win32_BIOS | BIOS info | LENOVO R2AET54W |
| Win32_DiskDrive | Physical disks | WD PC SN740 |
| Win32_LogicalDisk | Drive volumes | C:, D: |
| Win32_Processor | CPU | Intel Core i7 |
| Win32_ComputerSystem | Total memory | 16 GB |

## Adding Features

### Step-by-Step Example: Add CPU Cores

1. **Agent Collection** (`internal/agent/systeminfo.go`):
```go
func getProcessorCores() string {
    output := runWMIQuery("Processor", "NumberOfCores")
    return output
}
```

2. **Update SystemInfo** (`internal/agent/systeminfo.go`):
```go
type SystemInfo struct {
    // ... existing fields ...
    ProcessorCores string
}
```

3. **Update Heartbeat** (`cmd/agent/main.go`):
```go
hb := transport.HeartbeatRequest{
    // ... existing fields ...
    ProcessorCores: sysInfo.ProcessorCores,
}
```

4. **Update Transport** (`internal/transport/types.go`):
```go
type HeartbeatRequest struct {
    // ... existing fields ...
    ProcessorCores string
}
```

5. **Add Database Column** (`internal/migrations/migrations.go`):
```go
func addProcessorCoresColumn(ctx context.Context, db *pgxpool.Pool) error {
    query := `ALTER TABLE agents ADD COLUMN processor_cores VARCHAR(255);`
    _, err := db.Exec(ctx, query)
    return err
}

// Add to migrations array
{
    Name: "002_add_processor_cores",
    Up:   addProcessorCoresColumn,
}
```

6. **Update Agent Model** (`internal/server/agents.go`):
```go
type Agent struct {
    // ... existing fields ...
    ProcessorCores string `db:"processor_cores"`
}
```

7. **Update Repository** (`internal/server/agent_repo.go`):
```go
// In SELECT query
SELECT id, agent_id, ..., processor_cores FROM agents

// In INSERT/UPDATE
INSERT INTO agents (..., processor_cores) VALUES (..., $X)
UPDATE agents SET processor_cores = $X WHERE id = $Y
```

8. **Update Template** (`cmd/server/templates/agent-detail.html`):
```html
<div class="info-label">Processor Cores</div>
<div class="info-value">{{if .Agent.ProcessorCores}}{{.Agent.ProcessorCores}}{{else}}<span class="empty">Not available</span>{{end}}</div>
```

9. **Test End-to-End**:
```bash
# Build both
go build -o agent ./cmd/agent && go build -o server ./cmd/server

# Run server with fresh DB
./server

# In another terminal, run agent
./agent

# Check web UI at http://localhost:8070/agents
```

## Debugging

### Enable Debug Logging

Add to agent/server code:
```go
log.Printf("DEBUG: Variable value: %v", value)
```

Run with output visible:
```bash
go run ./cmd/agent 2>&1 | tee debug.log
```

### Database Inspection

```bash
# Connect to database
psql -U postgres -d ai_agents

# Common queries
SELECT id, hostname, status, last_seen FROM agents;
SELECT * FROM agents WHERE hostname = 'WORKSTATION-01';
SELECT name FROM schema_migrations;
SELECT COUNT(*) FROM agents WHERE status = 'online';
```

### Network Debugging

Check heartbeat traffic:
```bash
# macOS/Linux
tcpdump -i lo port 8070

# Windows (PowerShell as admin)
netstat -an | findstr :8070
```

### Testing with cURL

```bash
# Send test heartbeat
curl -X POST http://localhost:8070/api/heartbeat \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent-123",
    "hostname": "test-machine",
    "status": "online"
  }'

# Get agents list
curl http://localhost:8070/api/agents

# Get specific agent
curl http://localhost:8070/api/agents/test-agent-123
```

### Issue System Validation (Alerts)

Use these checks when working on issue detection, issue lifecycle, and remediation workflows:

```bash
# List active issues
curl -H "Authorization: Bearer <admin_token>" \
    "http://localhost:8070/api/issues?status=active&limit=100"

# List issues for one agent
curl -H "Authorization: Bearer <admin_token>" \
    "http://localhost:8070/api/issues?agent_id=test-agent-123&status=active&limit=100"

# Execute a recommended action immediately
curl -X POST http://localhost:8070/api/issues/42/actions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer <admin_token>" \
    -d '{"action_id":"cpu-process-snapshot","mode":"run_now"}'
```

Notes:
- Issues are deduplicated by `(agent_id, issue_key)` in `agent_issues`.
- Recovery conditions auto-resolve issues by setting status to `resolved`.
- Scheduler dispatch skips duplicate in-flight `restart`/`shutdown` commands per agent while same command type remains `queued` or `dispatched`.

## Performance Profiling

### CPU Profile

```bash
go run -cpuprofile=cpu.prof ./cmd/agent
go tool pprof cpu.prof
```

### Memory Profile

```bash
go run -memprofile=mem.prof ./cmd/server
go tool pprof mem.prof
```

## Creating Pull Requests

1. **Create feature branch**:
   ```bash
   git checkout -b feature/add-cpu-cores
   ```

2. **Make changes** following code style guidelines

3. **Run tests**:
   ```bash
   go test ./...
   go vet ./...
   go fmt ./...
   ```

4. **Commit with clear message**:
   ```bash
   git commit -m "feat: add CPU cores to processor information"
   ```

5. **Push and create PR**:
   ```bash
   git push origin feature/add-cpu-cores
   ```

## Release Process

1. Update version in code (if needed)
2. Update CHANGELOG.md
3. Run full test suite
4. Create git tag: `git tag v1.1.0`
5. Push tag: `git push origin v1.1.0`

## Troubleshooting Development Issues

### Issue: "database connection refused"

```bash
# Check PostgreSQL is running
psql -U postgres -c "SELECT 1"

# Check environment variables
echo $DB_HOST $DB_PORT $DB_NAME
```

### Issue: "Migration already applied"

Development only - reset database:
```go
RecreateAndRunMigrations(ctx, db)
```

Or manually:
```bash
psql -U postgres -d ai_agents -c "DROP TABLE IF EXISTS agents, schema_migrations CASCADE;"
```

### Issue: "Port 8070 already in use"

Change port:
```bash
export SERVER_PORT=8081
go run ./cmd/server
```

Or kill process:
```bash
lsof -ti:8070 | xargs kill -9    # macOS/Linux
netstat -ano | findstr :8070     # Windows (find PID then taskkill)
```

## Resources

- [Go Documentation](https://golang.org/doc/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [pgx Driver Documentation](https://pkg.go.dev/github.com/jackc/pgx/v5)
- [Effective Go](https://golang.org/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)

## Contributing Guidelines

1. Follow code style guidelines
2. Write tests for new features
3. Update documentation
4. Use clear commit messages
5. Reference issues in commits
6. Keep PRs focused on single feature/fix
