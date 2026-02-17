# Development Guide

This document provides guidance for developers working on the AI Endpoint Platform.

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
SERVER_PORT=8080
OFFLINE_TIMEOUT_SECONDS=90
OFFLINE_CHECK_INTERVAL_SECONDS=30
AGENT_JWT_SECRET=dev_agent_secret
ADMIN_JWT_SECRET=dev_admin_secret
ADMIN_JWT_TTL_SECONDS=3600

# Agent
SERVER_URL=http://localhost:8080
HEARTBEAT_INTERVAL_SECONDS=30
REQUEST_TIMEOUT_SECONDS=10
AGENT_JWT_SECRET=dev_agent_secret
AGENT_JWT_TTL_SECONDS=300
COMMAND_POLL_INTERVAL_SECONDS=30
COMMAND_TIMEOUT_SECONDS=60
METRICS_INTERVAL_SECONDS=5
```

Source it before running:
```bash
source .env.development
```

### 5. Run Migrations

Migrations run automatically on server startup, but you can verify manually:

```bash
go run ./cmd/server
# Check logs for: "✓ Migration 001_create_agents_table_v1_0_0 completed"
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
export SERVER_PORT=8080
export AGENT_JWT_SECRET=dev_agent_secret
export ADMIN_JWT_SECRET=dev_admin_secret
go run ./cmd/server
```

Expected output:
```
2026-02-17T10:30:00Z Running migration 001_create_agents_table_v1_0_0...
2026-02-17T10:30:00Z ✓ Migration 001_create_agents_table_v1_0_0 completed
2026-02-17T10:30:00Z Server listening on :8080
```

### Terminal 2: Start Agent

```bash
export SERVER_URL=http://localhost:8080
export AGENT_JWT_SECRET=dev_agent_secret
go run ./cmd/agent
```

Expected output:
```
2026-02-17T10:30:05Z Loaded existing agent ID from ~/.config/ai-endpoint-agent/agent_id
2026-02-17T10:30:05Z Agent started - ID: <uuid>, Hostname: <hostname>, Version: 1.0.0
2026-02-17T10:30:05Z Server URL: http://localhost:8080, Heartbeat interval: 30s
2026-02-17T10:30:35Z Heartbeat sent successfully
```

### Terminal 3: View Web UI

```bash
open http://localhost:8080/
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
        └── session-timeout.html
```

### internal/ - Core Logic

```
internal/
├── agent/
│   └── systeminfo.go    # System/hardware information collection
├── config/
│   └── config.go        # Configuration loading from environment
├── migrations/
│   └── migrations.go    # Database schema management
├── server/
│   ├── agents.go        # Agent data model
│   ├── agent_repo.go    # Database access (repository pattern)
│   └── handlers.go      # HTTP request handlers
├── transport/
│   └── types.go         # Request/response types
└── device/
    └── device.go        # Device detection/info
```

### pkg/ - Public Packages

```
pkg/
└── (future use)
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
   
   // Add to migrations slice:
   {
       Name: "002_add_new_column",
       Up:   addNewColumn,
   }
   ```

3. **Test Migration**:
   ```bash
   go run ./cmd/server
   ```

### Database Querying

Use parameterized queries to prevent SQL injection:

```go
// Good
err := db.QueryRow(ctx, 
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

# Check web UI at http://localhost:8080/agents
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
tcpdump -i lo port 8080

# Windows (PowerShell as admin)
netstat -an | findstr :8080
```

### Testing with cURL

```bash
# Send test heartbeat
curl -X POST http://localhost:8080/api/agents/heartbeat \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent-123",
    "hostname": "test-machine",
    "status": "online"
  }'

# Get agents list
curl http://localhost:8080/api/agents

# Get specific agent
curl http://localhost:8080/api/agents/test-agent-123
```

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

### Issue: "Port 8080 already in use"

Change port:
```bash
export SERVER_PORT=8081
go run ./cmd/server
```

Or kill process:
```bash
lsof -ti:8080 | xargs kill -9    # macOS/Linux
netstat -ano | findstr :8080     # Windows (find PID then taskkill)
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
