# Production Deployment Guide

This guide covers deploying the Armada Platform to production environments.

## Pre-Deployment Checklist

### Infrastructure Requirements

- [ ] **Server Hardware**
  - Minimum: 2 vCPU, 4 GB RAM
  - Recommended: 4 vCPU, 8 GB RAM for 50+ agents
  - Storage: 50 GB available (scales with agent count and retention policy)
  - Network: Stable connection with low latency

- [ ] **Database Server**
  - PostgreSQL 12 or higher
  - Minimum: 2 vCPU, 4 GB RAM
  - Storage: 100 GB SSD (adjust based on retention policy)
  - Separate from server if possible (recommended for production)

- [ ] **Network Infrastructure**
  - Firewall rules configured
  - Agents can reach server on port 8070 (or custom port)
  - API clients can access server endpoints
  - Database reachable from server

- [ ] **SSL/TLS Certificates** (for HTTPS)
  - Valid certificates for server hostname
  - Certificate chain
  - Private key with appropriate permissions

### Code & Dependencies

- [ ] Code reviewed and tested
- [ ] All tests passing (`go test ./...`)
- [ ] Dependencies locked (`go.mod`, `go.sum` committed)
- [ ] Version tagged in git (`git tag v1.0.0`)
- [ ] Binary built with release flags

### Documentation Review

- [ ] README.md reviewed
- [ ] ARCHITECTURE.md understood by ops team
- [ ] Configuration options documented
- [ ] API endpoints tested
- [ ] Runbooks created
- [ ] Admin login and password rotation documented

## Pre-Deployment Steps

### 1. Build Release Binaries

```bash
# Build optimized binaries
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/server ./cmd/server
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/agent ./cmd/agent
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/chat-worker ./cmd/chat-worker
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/agent-linux-arm64 ./cmd/agent

# For macOS agents
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o bin/agent-darwin-amd64 ./cmd/agent
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o bin/agent-darwin-arm64 ./cmd/agent

# For Windows
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/server.exe ./cmd/server
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/agent.exe ./cmd/agent
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/chat-worker.exe ./cmd/chat-worker
```

PowerShell helper for all Linux/macOS agent builds:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-agent-all.ps1
```

### 2. Test Release Build

```bash
# Test in staging environment
export DATABASE_URL=postgres://ai_endpoint_user:<your_secure_password>@staging-db.internal:5432/ai_agents?sslmode=disable
export SERVER_PORT=8070
./bin/server

# In another terminal
export SERVER_URL=http://localhost:8070
./bin/agent
```

### 3. Verify Migrations

```bash
# Test migrations on staging database
./bin/server

# Check schema_migrations table
psql -h staging-db.internal -U postgres -d ai_agents \
  -c "SELECT name, applied_at FROM schema_migrations;"
```

### 4. Backup Existing Data (if upgrading)

```bash
# Backup current database
pg_dump -h prod-db.internal -U postgres ai_agents > backup_pre_deploy.sql

# Verify backup
gzip backup_pre_deploy.sql
ls -lh backup_pre_deploy.sql.gz
```

## Deployment Steps

### Option 1: Linux Server (Recommended for Production)

#### 1. Create System User (if needed)

```bash
# Create dedicated user for the application
sudo useradd -r -s /bin/false ai-endpoint

# Create directories
sudo mkdir -p /opt/ai-endpoint-platform/bin
sudo mkdir -p /var/log/ai-endpoint-platform
sudo mkdir -p /etc/ai-endpoint-platform

# Set permissions
sudo chown -R ai-endpoint:ai-endpoint /opt/ai-endpoint-platform
sudo chown -R ai-endpoint:ai-endpoint /var/log/ai-endpoint-platform
```

#### 2. Copy Binaries

```bash
# Copy server binary
sudo cp bin/server /opt/ai-endpoint-platform/bin/server
sudo chmod 755 /opt/ai-endpoint-platform/bin/server

# Copy agent binary
sudo cp bin/agent /opt/ai-endpoint-platform/bin/agent
sudo chmod 755 /opt/ai-endpoint-platform/bin/agent

# Copy chat-worker binary
sudo cp bin/chat-worker /opt/ai-endpoint-platform/bin/chat-worker
sudo chmod 755 /opt/ai-endpoint-platform/bin/chat-worker

# Verify
ls -la /opt/ai-endpoint-platform/bin/
```

#### 3. Configure Environment

Create `/etc/ai-endpoint-platform/server.env`:

```bash
# Database Configuration
DATABASE_URL=postgres://ai_endpoint_user:<your_secure_password>@prod-db.internal:5432/ai_agents?sslmode=require

# Server Configuration
SERVER_PORT=8070

# Agent Monitoring (seconds)
OFFLINE_TIMEOUT_SECONDS=90
OFFLINE_CHECK_INTERVAL_SECONDS=30

# JWT Secrets (required for command API)
AGENT_JWT_SECRET=<shared_agent_secret>
ADMIN_JWT_SECRET=<admin_secret>
ADMIN_JWT_TTL_SECONDS=3600

# Queue / chat worker
QUEUE_ENABLED=true
QUEUE_PROVIDER=nats
NATS_URL=nats://localhost:4222
QUEUE_SUBJECT_PREFIX=chat
QUEUE_AGENT_CHAT_ACTIVE=true
QUEUE_AGENT_CHAT_SUBJECT=agent.chat.shadow
QUEUE_AGENT_CHAT_CONSUMER_GROUP=agent-chat-workers
QUEUE_AGENT_CHAT_MAX_ATTEMPTS=4
QUEUE_AGENT_CHAT_DLQ_SUBJECT=agent.chat.shadow.dlq

# Signed update manifest + rollout controls
UPDATE_MANIFEST_SIGNING_KEY=<strong_shared_signing_key>
UPDATE_ROLLOUT_POLICY_VERSION=1
UPDATE_ROLLOUT_RING_COUNT=4
UPDATE_ROLLOUT_ACTIVE_RING=4
UPDATE_ROLLOUT_RING_SALT=prod
UPDATE_ROLLOUT_HEALTH_GATE_ENABLED=true
UPDATE_ROLLOUT_HEALTH_WINDOW_MINUTES=180
UPDATE_ROLLOUT_HEALTH_MIN_SAMPLES=5
UPDATE_ROLLOUT_HEALTH_MAX_FAILURE_RATE_PCT=40
UPDATE_ROLLOUT_AUTO_ROLLBACK_ENABLED=true
UPDATE_ROLLOUT_AUTO_ROLLBACK_RING_STEP=1

# Logging
LOG_DIR=/var/log/ai-endpoint-platform
LOG_TO_CONSOLE=false
```

Default admin user
- First run seeds a default admin: username `admin`, password `admin`.
- Admins must change the password on first login.
- Login page: `/` and session timeout page: `/session-timeout`.

Permissions:
```bash
sudo chown ai-endpoint:ai-endpoint /etc/ai-endpoint-platform/server.env
sudo chmod 600 /etc/ai-endpoint-platform/server.env
```

#### 4. Create Systemd Service

Create `/etc/systemd/system/ai-endpoint-server.service`:

```ini
[Unit]
Description=Armada Platform Server
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=ai-endpoint
WorkingDirectory=/opt/ai-endpoint-platform
EnvironmentFile=/etc/ai-endpoint-platform/server.env
ExecStart=/opt/ai-endpoint-platform/bin/server
Restart=on-failure
RestartSec=10
StandardOutput=append:/var/log/ai-endpoint-platform/server.log
StandardError=append:/var/log/ai-endpoint-platform/server.log

# Security
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectDevices=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ai-endpoint-server
sudo systemctl start ai-endpoint-server

# Check status
sudo systemctl status ai-endpoint-server
sudo journalctl -u ai-endpoint-server -f
```

#### 4b. Create Chat Worker Service

Create `/etc/systemd/system/ai-endpoint-chat-worker.service`:

```ini
[Unit]
Description=Armada Platform Chat Worker
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=ai-endpoint
WorkingDirectory=/opt/ai-endpoint-platform
EnvironmentFile=/etc/ai-endpoint-platform/server.env
ExecStart=/opt/ai-endpoint-platform/bin/chat-worker
Restart=on-failure
RestartSec=10
StandardOutput=append:/var/log/ai-endpoint-platform/chat-worker.log
StandardError=append:/var/log/ai-endpoint-platform/chat-worker.log

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ai-endpoint-chat-worker
sudo systemctl start ai-endpoint-chat-worker
sudo systemctl status ai-endpoint-chat-worker
```

#### 5. Configure Reverse Proxy (HTTPS)

Using nginx:

```nginx
upstream ai_endpoint {
    server localhost:8070;
    keepalive 32;
}

server {
    listen 80;
    server_name ai-endpoint.example.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ai-endpoint.example.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/ai-endpoint.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ai-endpoint.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # Reverse Proxy
    location / {
        proxy_pass http://ai_endpoint;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 90;
    }
    
    # Health Check Endpoint
    location /healthz {
        proxy_pass http://ai_endpoint;
        access_log off;
    }
}
```

Verify config and reload:
```bash
sudo nginx -t
sudo systemctl reload nginx
```

### Option 2: Windows Server Deployment

#### 1. Create Application Directory

```powershell
$appPath = "C:\Program Files\ArmadaPlatform"
New-Item -ItemType Directory -Force -Path $appPath
```

#### 2. Copy Files

```powershell
Copy-Item -Path "bin\server.exe" -Destination $appPath
Copy-Item -Path "bin\agent.exe" -Destination $appPath
```

#### 3. Set Environment Variables

```powershell
[Environment]::SetEnvironmentVariable("DATABASE_URL", "postgres://ai_endpoint_user:<your_secure_password>@prod-db.internal:5432/ai_agents?sslmode=require", "Machine")
[Environment]::SetEnvironmentVariable("SERVER_PORT", "8070", "Machine")
[Environment]::SetEnvironmentVariable("OFFLINE_TIMEOUT_SECONDS", "90", "Machine")
[Environment]::SetEnvironmentVariable("OFFLINE_CHECK_INTERVAL_SECONDS", "30", "Machine")
[Environment]::SetEnvironmentVariable("AGENT_JWT_SECRET", "<shared_agent_secret>", "Machine")
[Environment]::SetEnvironmentVariable("ADMIN_JWT_SECRET", "<admin_secret>", "Machine")
```

#### 4. Create Windows Service

```powershell
# Using NSSM (Non-Sucking Service Manager)
nssm install ArmadaServer `
  "C:\Program Files\ArmadaPlatform\server.exe"

nssm set ArmadaServer AppEnvironmentExtra `
  "DATABASE_URL=postgres://ai_endpoint_user:<your_secure_password>@prod-db.internal:5432/ai_agents?sslmode=require;SERVER_PORT=8070;OFFLINE_TIMEOUT_SECONDS=90;OFFLINE_CHECK_INTERVAL_SECONDS=30;AGENT_JWT_SECRET=<shared_agent_secret>;ADMIN_JWT_SECRET=<admin_secret>"

# Configure Log
nssm set ArmadaServer AppStdout `
  "C:\Program Files\ArmadaPlatform\logs\server.log"

nssm set ArmadaServer AppStderr `
  "C:\Program Files\ArmadaPlatform\logs\server.log"

# Start Service
nssm start ArmadaServer
```

Or using PowerShell directly:

```powershell
# Create scheduled task
$action = New-ScheduledTaskAction `
  -Execute "C:\Program Files\ArmadaPlatform\server.exe"

$trigger = New-ScheduledTaskTrigger -AtStartup

Register-ScheduledTask `
  -TaskName "ArmadaServer" `
  -Action $action `
  -Trigger $trigger `
  -RunLevel Highest

# Start task
Start-ScheduledTask -TaskName "ArmadaServer"
```

#### 5. Install Agent as Windows Service (Administrator Privilege)

Run from an elevated PowerShell window on each endpoint (or via RMM/automation):

`ArmadaAgent` service mode is the default and recommended Windows deployment mode.

Build from source mode:

```powershell
Set-Location C:\Program Files\ArmadaPlatform\source
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-agent-service.ps1 `
  -BuildFromSource `
  -SourceDir . `
  -ServiceName ArmadaAgent `
  -InstallDir "C:\Program Files\Armada" `
  -ServerURL "http://<server>:8070" `
  -AgentJWTSecret "<shared_agent_secret>" `
  -LogDir "C:\ProgramData\Armada\logs" `
  -UseLocalSystem
```

Use prebuilt `agent.exe` mode (no build step):

```powershell
Copy-Item "D:\releases\agent.exe" "C:\Program Files\Armada\agent.exe" -Force
Set-Location C:\Program Files\ArmadaPlatform\source
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-agent-service.ps1 `
  -ServiceName ArmadaAgent `
  -InstallDir "C:\Program Files\Armada" `
  -ServerURL "http://<server>:8070" `
  -AgentJWTSecret "<shared_agent_secret>" `
  -LogDir "C:\ProgramData\Armada\logs" `
  -UseLocalSystem
```

Notes for prebuilt mode:
- Do not pass `-BuildFromSource`.
- Installer expects binary at `<InstallDir>\agent.exe`.
- If `agent.exe` is already in `InstallDir`, skip the `Copy-Item` line.
- For WinGet rollout templates and bootstrap script, see `deployments/winget/README.md`.

Notes:
- Default `-UseLocalSystem` runs agent with elevated local privileges.
- Script sets required machine env vars (`SERVER_URL`, `AGENT_JWT_SECRET`, `LOG_DIR`, `LOG_TO_CONSOLE`).
- Script can optionally set all supported agent runtime and AI env vars (timeouts/retries/provider/model/endpoint).
- For a custom service account, use `-UseLocalSystem:$false -ServiceUser <user> -ServicePassword <password>`.

Troubleshooting:
- `Error 1067` after start: check machine env values and restart service:

```powershell
[Environment]::GetEnvironmentVariable("SERVER_URL","Machine")
[Environment]::GetEnvironmentVariable("AGENT_JWT_SECRET","Machine")
Restart-Service ArmadaAgent
```

- `7009/7000` (service did not respond in time): ensure endpoint uses latest service-capable `agent.exe` and reinstall service configuration from elevated PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-agent-service.ps1 -BuildFromSource -SourceDir . -ServiceName ArmadaAgent -ServerURL "http://<server>:8070" -AgentJWTSecret "<shared_agent_secret>" -UseLocalSystem
Start-Service ArmadaAgent
```

- Service starts but endpoint is not visible in server UI:

```powershell
Test-NetConnection <server> -Port 8070
Get-ChildItem "C:\ProgramData\Armada\logs" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 5
```

- Credential-based service fails (`1057`/`1069`):
  - validate account password,
  - ensure account has `Log on as a service`,
  - or switch to LocalSystem during incident recovery.

- Prevent duplicate endpoint identities:
  - run the agent either as service or manual process, not both,
  - after service install, stop any manually started `agent.exe` process.

- Re-run installer to repair configuration:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-agent-service.ps1 -BuildFromSource -SourceDir . -ServiceName ArmadaAgent -ServerURL "http://<server>:8070" -AgentJWTSecret "<shared_agent_secret>" -UseLocalSystem
```

### Option 3: Docker Deployment

Create `Dockerfile`:

```dockerfile
FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY . .

RUN go build -ldflags="-s -w" -o /build/server ./cmd/server
RUN go build -ldflags="-s -w" -o /build/agent ./cmd/agent

FROM alpine:latest

RUN apk --no-cache add ca-certificates postgresql-client

COPY --from=builder /build/server /app/server
COPY --from=builder /build/agent /app/agent

WORKDIR /app

EXPOSE 8070

CMD ["./server"]
```

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: ai_agents
      POSTGRES_USER: ai_endpoint_user
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ai_endpoint_user"]
      interval: 10s
      timeout: 5s
      retries: 5

  server:
    build: .
    environment:
      DATABASE_URL: postgres://ai_endpoint_user:${DB_PASSWORD}@db:5432/ai_agents?sslmode=disable
      SERVER_PORT: 8070
      AGENT_JWT_SECRET: ${AGENT_JWT_SECRET}
      ADMIN_JWT_SECRET: ${ADMIN_JWT_SECRET}
    ports:
      - "8070:8070"
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

volumes:
  postgres_data:
```

Deploy:
```bash
docker-compose up -d
docker-compose logs -f server
```

## Post-Deployment Verification

### 1. Verify Server is Running

```bash
# Check process
ps aux | grep server

# Check listening port
netstat -tlnp | grep 8070
# or on Windows
netstat -ano | findstr :8070

# Check service status
sudo systemctl status ai-endpoint-server
```

### 2. Verify Database Connection

```bash
# Test connection
psql -h prod-db.internal -U postgres -d ai_agents \
  -c "SELECT 1;"

# Verify schema
psql -h prod-db.internal -U postgres -d ai_agents \
  -c "\dt"

# Check migrations
psql -h prod-db.internal -U postgres -d ai_agents \
  -c "SELECT * FROM schema_migrations;"
```

### 3. Test Health Endpoints

```bash
# Test health endpoint
curl -X GET http://localhost:8070/healthz

# Test API
curl -X GET http://localhost:8070/api/agents

# Test Web UI
curl -X GET http://localhost:8070/agents

# Check response
# Should return: empty agents list [] or HTML page
```

### 4. Deploy and Test Agent

```bash
# On agent machine
export SERVER_URL=https://ai-endpoint.example.com
export AGENT_JWT_SECRET=<shared_agent_secret>
export METRICS_INTERVAL_SECONDS=5
./agent

# Watch server logs for heartbeat
sudo journalctl -u ai-endpoint-server -f
# Should see: "Heartbeat received from agent-id"
```

### 5. Verify in Web UI

1. Open https://ai-endpoint.example.com/agents
2. Should show one agent with status "online"
3. Click agent to see details
4. Verify Overview, Hardware, and Disks tabs show data

## Database Backup Strategy

### Automated Daily Backups

Create `/usr/local/bin/backup-ai-agents.sh`:

```bash
#!/bin/bash

BACKUP_DIR="/backups/ai-agents"
RETENTION_DAYS=30
DB_HOST="prod-db.internal"
DB_NAME="ai_agents"
DB_USER="postgres"

# Create backup
BACKUP_FILE="${BACKUP_DIR}/ai_agents_$(date +%Y%m%d_%H%M%S).sql"
mkdir -p "$BACKUP_DIR"

pg_dump -h "$DB_HOST" -U "$DB_USER" "$DB_NAME" | gzip > "${BACKUP_FILE}.gz"

# Check if backup successful
if [ $? -eq 0 ]; then
    echo "Backup successful: ${BACKUP_FILE}.gz"
    
    # Delete old backups
    find "$BACKUP_DIR" -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete
else
    echo "Backup failed!" >&2
    exit 1
fi
```

Schedule with cron:

```bash
# Edit crontab
sudo crontab -e

# Add this line (daily at 2 AM)
0 2 * * * /usr/local/bin/backup-ai-agents.sh >> /var/log/ai-agents-backup.log 2>&1
```

### Restore from Backup

```bash
# Stop server
sudo systemctl stop ai-endpoint-server

# Restore database
gunzip < /backups/ai-agents/ai_agents_YYYYMMDD_HHMMSS.sql.gz | \
  psql -h prod-db.internal -U postgres ai_agents

# Restart server
sudo systemctl start ai-endpoint-server
```

## Monitoring & Alerting

### Key Metrics to Monitor

1. **Server Health**
   - CPU usage (alert > 80%)
   - Memory usage (alert > 85%)
   - Disk usage (alert > 85%)
   - Process running status

2. **Application Health**
   - HTTP response time (alert > 1000ms)
   - Error rate (alert > 1%)
   - Database connection pool
   - Active agents count

3. **Database Health**
   - Connection count
   - Query performance
   - Replication lag (if applicable)
   - Disk usage

### Platform Issue Monitoring (Built-in Alerts)

The platform has a built-in durable issue system (alerting) backed by `agent_issues` and `issue_action_audit`.

Operational checks:
- Track active issues by severity (`critical`, `high`, `medium`, `low`)
- Watch for issue churn (`active` <-> `resolved`) to detect unstable endpoints
- Review failed remediation actions from `issue_action_audit` and investigate repeated failures
- Validate scheduler safety for power operations: duplicate in-flight `restart`/`shutdown` commands are skipped per agent

Recommended API checks:
- `GET /api/issues?status=active&limit=200`
- `GET /api/issues?status=resolved&limit=200`
- `GET /api/issues?agent_id=<agent_id>&status=active&limit=100`

### Health Check Endpoint (/healthz)

The server exposes `/healthz` and returns `{"status":"healthy"}`. It does not check database connectivity by default.

### Example: Prometheus Monitoring

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'ai-endpoint'
    static_configs:
      - targets: ['ai-endpoint.example.com:8070']
    metrics_path: '/metrics'
```

### Example: Log Aggregation

```bash
# Using rsyslog for centralized logging
echo "*.* @@log-server.internal:514" >> /etc/rsyslog.d/30-ai-endpoint.conf
sudo systemctl restart rsyslog
```

## Security Hardening

### 1. Firewall Rules

```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 8070/tcp    # Server (internal only)
sudo ufw allow 443/tcp     # HTTPS (via reverse proxy)
sudo ufw allow 5432/tcp from prod-db.internal  # Database

# Enable firewall
sudo ufw enable
```

### 2. SSL/TLS Configuration

- Use TLS 1.2 or higher
- Strong ciphers only
- Certificate pinning (for agent → server)
- Auto-renewal via Let's Encrypt

### 3. Database Security

```sql
-- Create restricted user
CREATE USER ai_endpoint_user WITH PASSWORD 'strong_password';

-- Grant only necessary privileges
GRANT CONNECT ON DATABASE ai_agents TO ai_endpoint_user;
GRANT USAGE ON SCHEMA public TO ai_endpoint_user;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO ai_endpoint_user;

-- Restrict to specific tables
GRANT SELECT, INSERT, UPDATE ON agents TO ai_endpoint_user;
```

### 4. Environment Variables

- Never commit secrets to git
- Use `.env` files with restricted permissions (600)
- Use environment-specific files (.prod.env, .staging.env)
- Rotate credentials regularly

### 5. Access Control

For future versions (v1.1.0+):
- Implement API key authentication
- Use JWT tokens for agents
- Implement RBAC
- Add audit logging

## Scaling Considerations

### Current Limits (v1.0.0)

- **Single Server**: ~200 agents before resource constraints
- **Single Database**: ~1M records before significant slowdown
- **Memory**: 8 GB server handles ~100 concurrent requests

### Scaling Strategies

#### Vertical Scaling (Easier for v1.0.0)
1. Increase CPU cores (up to 8)
2. Increase RAM (up to 32 GB)
3. Use SSD storage
4. Optimize database (indexes, connection pooling)

#### Horizontal Scaling (Plan for v1.1.0)
1. Multiple server instances behind load balancer
2. Database read replicas
3. Message queue for decoupling (Kafka, RabbitMQ)
4. Agent-specific database shards

#### Database Optimization
```sql
-- Analyze tables for query planning
ANALYZE agents;

-- Check missing indexes
SELECT schemaname, tablename FROM pg_tables 
WHERE schemaname = 'public';

-- Monitor slow queries
SET log_min_duration_statement = 1000;
```

## Rollback Procedure

If deployment encounters issues:

### Quick Rollback

```bash
# 1. Stop current server
sudo systemctl stop ai-endpoint-server

# 2. Copy previous binary
sudo cp /opt/ai-endpoint-platform/bin/server.v1.0.0.bak \
        /opt/ai-endpoint-platform/bin/server

# 3. Start previous version
sudo systemctl start ai-endpoint-server

# 4. Verify
sudo journalctl -u ai-endpoint-server -f
```

### Database Rollback

```bash
# 1. Restore from backup
sudo systemctl stop ai-endpoint-server

gunzip < /backups/ai-agents/ai_agents_YYYYMMDD_HHMMSS.sql.gz | \
  psql -h prod-db.internal -U postgres ai_agents

# 2. Verify data
psql -h prod-db.internal -U postgres ai_agents \
  -c "SELECT COUNT(*) FROM agents;"

# 3. Restart
sudo systemctl start ai-endpoint-server
```

## Troubleshooting Deployment Issues

### Issue: "Database connection refused"

**Diagnosis:**
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -h prod-db.internal -U postgres -d postgres -c "SELECT 1"

# Check firewall
sudo ufw status
netstat -tlnp | grep 5432
```

**Solution:**
1. Verify PostgreSQL service is running
2. Check firewall allows port 5432
3. Verify credentials in environment file
4. Check database exists: `psql -l | grep ai_agents`

### Issue: "Server won't start"

**Diagnosis:**
```bash
# Check logs
sudo journalctl -u ai-endpoint-server -n 50

# Check port is available
lsof -i :8070

# Verify binary
/opt/ai-endpoint-platform/bin/server -h
```

**Solution:**
1. Kill process using port 8070
2. Check permissions on binary (755)
3. Verify environment variables loaded

### Issue: "Agents can't connect to server"

**Diagnosis:**
```bash
# From agent machine
ping prod-db.internal    # No - this is DB
curl -v http://ai-endpoint.example.com:8070/api/agents

# Check firewall rules
sudo ufw status
sudo iptables -L -n | grep 8070

# Test reverse proxy
curl -v http://localhost:8070
```

**Solution:**
1. Verify reverse proxy is running
2. Check firewall allows agent to reach server
3. Verify agent SERVER_URL is correct

## Post-Deployment Checklist

- [ ] Server running and accepting connections
- [ ] Database populated with schema
- [ ] Migrations applied successfully
- [ ] At least one agent connected and reporting
- [ ] Web UI accessible and showing agent data
- [ ] HTTPS enabled and working
- [ ] Automated backups configured
- [ ] Monitoring/alerting configured
- [ ] Logs being collected
- [ ] Security hardening applied
- [ ] Runbooks created for operations team
- [ ] Disaster recovery plan documented
- [ ] Performance baseline captured
- [ ] Load testing completed (if applicable)

## Maintenance Tasks

### Weekly
- [ ] Review error logs for issues
- [ ] Check disk usage trends
- [ ] Verify backups are completing
- [ ] Check database performance

### Monthly
- [ ] Review and update security patches
- [ ] Analyze agent connectivity patterns
- [ ] Review monitoring alerts
- [ ] Performance optimization review

### Quarterly
- [ ] Disaster recovery drill
- [ ] Capacity planning review
- [ ] Security audit
- [ ] Load testing


## Operations

### Agent Version Update

This section describes how to update agent versions, both manually and via auto-deployment.

#### Manual Update Steps

1. Build binary with embedded version (example for Windows):
```powershell
$ver = "1.0.7.exe"
go build -ldflags "-s -w -X main.agentVersion=$ver" -o "agent-updates/$ver" ./cmd/agent
```
2. Compute binary hash:
```powershell
$sha = (Get-FileHash "agent-updates/$ver" -Algorithm SHA256).Hash.ToLower()
```
3. Upload binary to server-hosted update storage (`AGENT_UPDATE_DIR`):
  - `POST /api/agent-update/upload` (admin)
4. Publish version metadata:
  - `PUT /api/agent-update/version` (admin)
5. Queue the update command:
  - Single agent: `POST /api/agents/{id}/agent-update/install` (admin)
  - Bulk agents: `POST /api/agent-update/install/bulk` (admin)
6. Monitor rollout:
  - `GET /api/agents/{id}/agent-update/history`
  - `GET /api/commands?agent_id={id}&limit=...`

UI paths:
- Per-agent update workflow: `/agents/{id}` -> `Commands` tab -> `Agent Self-Update`
- Bulk queue update workflow: `/agents/manage` -> select agents -> `Queue Update (Selected)`

#### API Release Runbook (Copy/Paste)

```powershell
$base = "http://<server>:8070"
$adminJwt = "<admin_jwt>"
$agentId = "<agent_id>"
$ver = "1.0.7.exe"
$filePath = "agent-updates/$ver"
$sha = (Get-FileHash $filePath -Algorithm SHA256).Hash.ToLower()

# 1) Upload
$upload = curl.exe -s -X POST "$base/api/agent-update/upload" `
  -H "Authorization: Bearer $adminJwt" `
  -F "version=$ver" `
  -F "file=@$filePath" | ConvertFrom-Json

# 2) Publish
$publishBody = @{
  version      = $ver
  download_url = $upload.download_url
  sha256       = $sha
  changelog    = "Release $ver"
} | ConvertTo-Json

Invoke-RestMethod -Method Put -Uri "$base/api/agent-update/version" `
  -Headers @{ Authorization = "Bearer $adminJwt"; "Content-Type" = "application/json" } `
  -Body $publishBody

# 3) Queue for one agent
Invoke-RestMethod -Method Post -Uri "$base/api/agents/$agentId/agent-update/install" `
  -Headers @{ Authorization = "Bearer $adminJwt"; "Content-Type" = "application/json" } `
  -Body '{"ttl_minutes":60}'
```

#### Final End-to-End Run (Production PowerShell)

Use this when you want one complete operational flow from token generation to queue verification.

```powershell
$ErrorActionPreference = "Stop"

# Inputs
$base = "https://<server>:8070"
$agentId = "<agent_id>"
$ver = "1.0.7.exe"
$filePath = "agent-updates/$ver"

# 1) Resolve ADMIN_JWT_SECRET (prefer secret manager/vault in production)
$secret = [Environment]::GetEnvironmentVariable("ADMIN_JWT_SECRET", "Machine")
if ([string]::IsNullOrWhiteSpace($secret)) {
  throw "ADMIN_JWT_SECRET not found. Load it from your production secret source."
}

# 2) Generate short-lived admin JWT
$adminJwt = go run .\scripts\jwtgen\main.go -subject admin -role admin -secret $secret -ttl 600
if ([string]::IsNullOrWhiteSpace($adminJwt)) {
  throw "Failed to generate admin JWT"
}

# 3) Compute hash and upload binary
if (!(Test-Path $filePath)) {
  throw "Binary not found: $filePath"
}
$sha = (Get-FileHash $filePath -Algorithm SHA256).Hash.ToLower()

$upload = curl.exe -s -X POST "$base/api/agent-update/upload" `
  -H "Authorization: Bearer $adminJwt" `
  -F "version=$ver" `
  -F "file=@$filePath" | ConvertFrom-Json

if (-not $upload.download_url) {
  throw "Upload failed or missing download_url"
}

# 4) Publish metadata
$publishBody = @{
  version      = $ver
  download_url = $upload.download_url
  sha256       = $sha
  changelog    = "Release $ver"
} | ConvertTo-Json

$published = Invoke-RestMethod -Method Put -Uri "$base/api/agent-update/version" `
  -Headers @{ Authorization = "Bearer $adminJwt"; "Content-Type" = "application/json" } `
  -Body $publishBody

# 5) Queue update for one agent
$queued = Invoke-RestMethod -Method Post -Uri "$base/api/agents/$agentId/agent-update/install" `
  -Headers @{ Authorization = "Bearer $adminJwt"; "Content-Type" = "application/json" } `
  -Body '{"ttl_minutes":60}'

$commandId = $queued.command_id
if (-not $commandId) {
  throw "Queue response missing command_id"
}

# 6) Verify queued command status
$cmds = Invoke-RestMethod -Method Get -Uri "$base/api/commands?agent_id=$agentId&limit=20" `
  -Headers @{ Authorization = "Bearer $adminJwt" }

$target = $cmds | Where-Object { $_.id -eq $commandId } | Select-Object -First 1
$target | Format-List id,agent_id,command_type,status,created_at

# 7) Optional rollback action: cancel if still queued
if ($target -and $target.status -eq "queued") {
  $cancelled = Invoke-RestMethod -Method Post `
    -Uri "$base/api/agents/$agentId/commands/$commandId/cancel" `
    -Headers @{ Authorization = "Bearer $adminJwt"; "Content-Type" = "application/json" }

  $cancelled | Format-List id,agent_id,command_type,status,created_at
}

# 8) Monitor install results
Invoke-RestMethod -Method Get -Uri "$base/api/agents/$agentId/agent-update/history" `
  -Headers @{ Authorization = "Bearer $adminJwt" } | ConvertTo-Json -Depth 6
```

Operational notes:
- Use HTTPS for production (`$base = "https://..."`).
- Keep token TTL short (`300-900` seconds).
- Do not persist JWTs in scripts, commit history, or logs.

#### Final End-to-End Run (Production Bash/Linux)

Use this when operating from a Linux jump host or directly on the server.

```bash
set -euo pipefail

# Preflight: required tools
for cmd in curl jq sha256sum go; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "Missing required tool: $cmd" >&2
    exit 1
  }
done

# Inputs
BASE="https://<server>:8070"
AGENT_ID="<agent_id>"
VER="1.0.7-linux"
FILE_PATH="agent-updates/${VER}"

# 1) Resolve ADMIN_JWT_SECRET (prefer secret manager/vault in production)
# Example if using a systemd env file:
ADMIN_JWT_SECRET="$(sudo awk -F= '/^ADMIN_JWT_SECRET=/{print $2}' /etc/ai-endpoint-platform/server.env | tail -n1)"

if [ -z "${ADMIN_JWT_SECRET}" ]; then
  echo "ADMIN_JWT_SECRET not found. Load it from your production secret source." >&2
  exit 1
fi

# 2) Generate short-lived admin JWT
ADMIN_JWT="$(go run ./scripts/jwtgen/main.go -subject admin -role admin -secret "${ADMIN_JWT_SECRET}" -ttl 600)"

if [ -z "${ADMIN_JWT}" ]; then
  echo "Failed to generate admin JWT" >&2
  exit 1
fi

# 3) Compute hash and upload binary
if [ ! -f "${FILE_PATH}" ]; then
  echo "Binary not found: ${FILE_PATH}" >&2
  exit 1
fi

SHA="$(sha256sum "${FILE_PATH}" | awk '{print tolower($1)}')"

UPLOAD_JSON="$(curl -fsS -X POST "${BASE}/api/agent-update/upload" \
  -H "Authorization: Bearer ${ADMIN_JWT}" \
  -F "version=${VER}" \
  -F "file=@${FILE_PATH}")"

DOWNLOAD_URL="$(printf '%s' "${UPLOAD_JSON}" | jq -r '.download_url // empty')"
if [ -z "${DOWNLOAD_URL}" ]; then
  echo "Upload failed or missing download_url" >&2
  echo "${UPLOAD_JSON}" >&2
  exit 1
fi

# 4) Publish metadata
PUBLISH_BODY="$(jq -nc \
  --arg version "${VER}" \
  --arg download_url "${DOWNLOAD_URL}" \
  --arg sha256 "${SHA}" \
  --arg changelog "Release ${VER}" \
  '{version:$version,download_url:$download_url,sha256:$sha256,changelog:$changelog}')"

curl -fsS -X PUT "${BASE}/api/agent-update/version" \
  -H "Authorization: Bearer ${ADMIN_JWT}" \
  -H "Content-Type: application/json" \
  -d "${PUBLISH_BODY}" >/dev/null

# 5) Queue update for one agent
QUEUE_JSON="$(curl -fsS -X POST "${BASE}/api/agents/${AGENT_ID}/agent-update/install" \
  -H "Authorization: Bearer ${ADMIN_JWT}" \
  -H "Content-Type: application/json" \
  -d '{"ttl_minutes":60}')"

COMMAND_ID="$(printf '%s' "${QUEUE_JSON}" | jq -r '.command_id // empty')"
if [ -z "${COMMAND_ID}" ]; then
  echo "Queue response missing command_id" >&2
  echo "${QUEUE_JSON}" >&2
  exit 1
fi

# 6) Verify queued command status
COMMANDS_JSON="$(curl -fsS "${BASE}/api/commands?agent_id=${AGENT_ID}&limit=20" \
  -H "Authorization: Bearer ${ADMIN_JWT}")"

TARGET_STATUS="$(printf '%s' "${COMMANDS_JSON}" | jq -r --argjson id "${COMMAND_ID}" '.[] | select(.id==$id) | .status' | head -n1)"
echo "command_id=${COMMAND_ID} status=${TARGET_STATUS:-unknown}"

# 7) Optional rollback action: cancel if still queued
if [ "${TARGET_STATUS:-}" = "queued" ]; then
  curl -fsS -X POST "${BASE}/api/agents/${AGENT_ID}/commands/${COMMAND_ID}/cancel" \
    -H "Authorization: Bearer ${ADMIN_JWT}" \
    -H "Content-Type: application/json" | jq '{id,agent_id,command_type,status,created_at}'
fi

# 8) Monitor install results
curl -fsS "${BASE}/api/agents/${AGENT_ID}/agent-update/history" \
  -H "Authorization: Bearer ${ADMIN_JWT}" | jq '.'
```

Linux notes:
- Requires `curl`, `jq`, `sha256sum`, and `go` on the operator host.
- Keep token TTL short (`300-900` seconds).
- Do not persist JWTs in shell history or files.

#### Example: Venom Windows Agent Validation

Use this as a Windows-specific smoke test after publishing a `.exe` release. Replace the agent ID if the Venom endpoint was reprovisioned.

```powershell
$ErrorActionPreference = "Stop"

$base = "https://<server>:8070"
$agentId = "08685de0-10c8-434b-a8db-265ea6cc01f2"   # Historical Venom Windows agent
$version = "1.0.7.exe"

$secret = [Environment]::GetEnvironmentVariable("ADMIN_JWT_SECRET", "Machine")
$adminJwt = go run .\scripts\jwtgen\main.go -subject admin -role admin -secret $secret -ttl 600
$headers = @{ Authorization = "Bearer $adminJwt"; "Content-Type" = "application/json" }

# 1) Inspect recent commands and confirm Windows payloads use .exe versions
$commands = Invoke-RestMethod -Method Get -Uri "$base/api/commands?agent_id=$agentId&limit=10" `
  -Headers @{ Authorization = "Bearer $adminJwt" }

$commands | Select-Object id, command_type, status, created_at, payload

# 2) If a queued linux payload appears by mistake, cancel it before dispatch
$badQueued = $commands | Where-Object {
  $_.status -eq "queued" -and $_.command_type -eq "agent_update" -and $_.payload -match "linux"
} | Select-Object -First 1

if ($badQueued) {
  Invoke-RestMethod -Method Post -Uri "$base/api/agents/$agentId/commands/$($badQueued.id)/cancel" `
    -Headers $headers | Format-List id,agent_id,command_type,status,created_at
}

# 3) Queue the expected Windows release
$queued = Invoke-RestMethod -Method Post -Uri "$base/api/agents/$agentId/agent-update/install" `
  -Headers $headers `
  -Body '{"ttl_minutes":60}'

$queued | Format-List

# 4) Review update history and confirm the target version is a .exe build
Invoke-RestMethod -Method Get -Uri "$base/api/agents/$agentId/agent-update/history" `
  -Headers @{ Authorization = "Bearer $adminJwt" } | ConvertTo-Json -Depth 6
```

Windows validation notes:
- For Windows agents, queued update payloads should reference `.exe` versions, not linux artifacts.
- A successful Windows self-update typically reports output similar to `update to <version>.exe staged; ArmadaAgent service will restart automatically`.
- If the agent was reprovisioned, get the current agent ID from `/api/agents` or the Web UI before running this example.

#### How to Get `<admin_jwt>`

Option 1 (recommended for API automation): generate with `jwtgen` using `ADMIN_JWT_SECRET`.

```powershell
# Replace with your actual server ADMIN_JWT_SECRET value
$secret = "<admin_jwt_secret>"
go run .\scripts\jwtgen\main.go -subject admin -role admin -secret $secret -ttl 3600
```

Option 2 (browser/UI session): log in at `/` with admin credentials.
- This creates an `admin_session` cookie (works for UI and same-origin requests), but does not directly print a bearer JWT token.
- For CLI/API calls with `Authorization: Bearer ...`, use Option 1.

Security notes:
- Keep `ADMIN_JWT_SECRET` private and rotate regularly.
- Use short token TTL for operational runs.
- Do not paste tokens into commit history, scripts checked into git, or chat logs.

#### Auto-Deployment (Self-Update)

1. Publish new agent binary to `AGENT_UPDATE_DIR` on the server.
2. Ensure rollout policy and health-gate settings are configured:
  - `UPDATE_ROLLOUT_POLICY_VERSION`, `UPDATE_ROLLOUT_RING_COUNT`, etc.
3. Use admin API or UI to queue update commands for eligible agents.
4. Monitor rollout progress in Reports UI and via API endpoints:
  - `GET /api/agents/{id}/agent-update/history`
  - `GET /api/reports/os-patch-rollout?limit=30`
  - `GET /api/agent-update/versions`
5. If failures occur, health-gate and auto-rollback will protect the fleet.

#### Troubleshooting

- Service fails to start: check environment variables, permissions, and logs.
- Agent not visible: verify connectivity, logs, and correct binary placement.
- Duplicate identities: ensure agent runs only as a service, not manual process.
- For Windows, use `scripts/install-agent-service.ps1` to reinstall service and repair configuration.
- For Linux, restart systemd service after binary swap when running under service supervision.
- macOS self-update via `agent_update` command is not supported yet; use out-of-band replacement.

#### Install Agent as Linux Service (systemd)

Run these steps on each Linux endpoint as root or sudo.

**1. Copy binary**

```bash
sudo mkdir -p /opt/armada
sudo cp agent-linux-amd64 /opt/armada/agent
# ARM64 endpoints:
# sudo cp agent-linux-arm64 /opt/armada/agent
sudo chmod 755 /opt/armada/agent
```

**2. Create env file**

Create `/etc/armada/agent.env` (permissions `600`):

```bash
sudo mkdir -p /etc/armada

sudo tee /etc/armada/agent.env > /dev/null <<'EOF'
SERVER_URL=http://<server>:8070
AGENT_JWT_SECRET=<shared_agent_secret>
LOG_DIR=/var/log/armada
LOG_TO_CONSOLE=false

# Optional tuning
# HEARTBEAT_INTERVAL_SECONDS=30
# COMMAND_POLL_INTERVAL_SECONDS=30
# METRICS_INTERVAL_SECONDS=60
# REQUEST_TIMEOUT_SECONDS=10
# MAX_RETRIES=3

# Optional AI
# AGENT_AI_PROVIDER=ollama
# AGENT_AI_ENDPOINT=http://localhost:11434/v1/chat/completions
# AGENT_AI_MODEL=llama3.2
EOF

sudo chown root:root /etc/armada/agent.env
sudo chmod 600 /etc/armada/agent.env
```

**3. Create log directory**

```bash
sudo mkdir -p /var/log/armada
```

**4. Create systemd unit**

Create `/etc/systemd/system/armada-agent.service`:

```bash
sudo tee /etc/systemd/system/armada-agent.service > /dev/null <<'EOF'
[Unit]
Description=Armada Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# HOME must be set so the agent can resolve os.UserConfigDir() for its identity file.
# Without this, systemd services have no $HOME and the agent fails to start.
Environment=HOME=/root
EnvironmentFile=/etc/armada/agent.env
ExecStart=/opt/armada/agent
Restart=on-failure
RestartSec=10
StandardOutput=append:/var/log/armada/agent.log
StandardError=append:/var/log/armada/agent.log

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=yes
# ReadWritePaths must include:
#   /var/log/armada  — agent log files
#   /opt/armada      — self-update stages new binary here before rename
#   /root/.config    — GetAgentID() stores agent_id in os.UserConfigDir() → /root/.config
ReadWritePaths=/var/log/armada /opt/armada /root/.config

[Install]
WantedBy=multi-user.target
EOF
```

**5. Enable and start**

```bash
sudo systemctl daemon-reload
sudo systemctl enable armada-agent
sudo systemctl start armada-agent

# Verify
sudo systemctl status armada-agent
sudo journalctl -u armada-agent -f
```

**Updating the binary** (e.g. after self-update or manual swap):

```bash
sudo systemctl stop armada-agent
sudo cp agent-linux-amd64 /opt/armada/agent
sudo chmod 755 /opt/armada/agent
sudo systemctl start armada-agent
sudo systemctl status armada-agent
```

**Uninstall:**

```bash
sudo systemctl stop armada-agent
sudo systemctl disable armada-agent
sudo rm /etc/systemd/system/armada-agent.service
sudo systemctl daemon-reload
sudo rm -rf /opt/armada /etc/armada /var/log/armada
```

**Troubleshooting:**

- Agent not appearing in UI: check `SERVER_URL` and `AGENT_JWT_SECRET` in `/etc/armada/agent.env`, then `sudo systemctl restart armada-agent`.
- View recent logs: `sudo journalctl -u armada-agent -n 50`.
- Test connectivity: `curl -s http://<server>:8070/healthz`.

#### Install Agent on TinyCore Linux (BusyBox / No systemd)

TinyCore Linux uses a BusyBox init system with no systemd. The filesystem is RAM-based; only `/opt` (and other configured persistent paths) survive reboots. Run `filetool.sh -b` after every file change to save to disk.

> **Architecture note:** TinyCore may be installed as 32-bit (`i686`) even on 64-bit hardware (e.g., Intel Atom). Verify with `uname -m` before copying the binary:
> - `i686` → use the `linux/386` binary (e.g., `agent-updates/1.0.8-linux-386`)
> - `x86_64` → use the `linux/amd64` binary (e.g., `agent-updates/1.0.8`)

**1. Verify architecture**

```bash
uname -m
# i686   → linux/386 binary
# x86_64 → linux/amd64 binary
```

**2. Copy binary via SCP (binary mode — always)**

From your Windows machine:

```powershell
# i686 / 32-bit TinyCore
scp agent-updates/1.0.8-linux-386 tc@<tinycore-ip>:/tmp/agent

# x86_64 TinyCore
scp agent-updates/1.0.8 tc@<tinycore-ip>:/tmp/agent
```

> **Important:** always use `scp`. Never transfer via copy-paste or FTP ASCII mode — text-mode transfers corrupt the ELF binary and produce `syntax error: unexpected ")"` at runtime.

On TinyCore:

```bash
mkdir -p /opt/armada
cp /tmp/agent /opt/armada/agent
chmod 755 /opt/armada/agent
```

**3. Create env file**

```bash
mkdir -p /opt/armada

cat > /opt/armada/agent.env <<'EOF'
SERVER_URL=http://<server>:8070
AGENT_JWT_SECRET=<shared_agent_secret>
LOG_DIR=/opt/armada/logs
LOG_TO_CONSOLE=false

# JWT token TTL (seconds). Default is 300 (5 min).
# TinyCore has no NTP by default — clock skew causes HTTP 401 on all
# authenticated endpoints (command poll, metrics) while heartbeat still
# succeeds (heartbeat has no JWT check).
# Set a large TTL to tolerate clock drift until NTP is available.
# This is an AGENT-SIDE variable — setting it on the server has no effect.
AGENT_JWT_TTL_SECONDS=86400

# Optional tuning
# HEARTBEAT_INTERVAL_SECONDS=30
# COMMAND_POLL_INTERVAL_SECONDS=30
# METRICS_INTERVAL_SECONDS=60
# REQUEST_TIMEOUT_SECONDS=10
# MAX_RETRIES=3

# Optional AI
# AGENT_AI_PROVIDER=ollama
# AGENT_AI_ENDPOINT=http://localhost:11434/v1/chat/completions
# AGENT_AI_MODEL=llama3.2
EOF

chmod 600 /opt/armada/agent.env
mkdir -p /opt/armada/logs
```

**4. Sync the system clock (required for JWT auth)**

TinyCore has no NTP running by default. The agent generates JWT tokens that expire in 5 minutes — if the system clock is wrong, tokens appear expired on the server and all authenticated API calls return **HTTP 401**. The heartbeat endpoint has no auth and will still succeed even with a wrong clock, which makes this easy to miss.

```bash
# Check current time vs expected
date

# Option A: BusyBox ntpd (usually built-in)
ntpd -q -p pool.ntp.org

# Option B: install ntpdate via TCE
tce-load -wi ntpdate
ntpdate pool.ntp.org

# Option C: set manually (replace with current UTC time)
date -s "2026-04-07 10:30:00"

# Verify
date
```

**5. Create `armada-agent.sh` (BusyBox-compatible control script)**

TinyCore BusyBox does not have a `start` command. Use a POSIX `case` script:

```bash
cat > /opt/armada/armada-agent.sh <<'EOF'
#!/bin/sh
# Armada Agent control script — BusyBox / TinyCore compatible

PID_FILE=/var/run/armada-agent.pid

start() {
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "armada-agent already running (pid $(cat $PID_FILE))"
    return 0
  fi
  set -a
  . /opt/armada/agent.env
  set +a
  /opt/armada/agent >> /opt/armada/logs/agent.log 2>&1 &
  echo $! > "$PID_FILE"
  echo "armada-agent started (pid $!)"
}

stop() {
  if [ -f "$PID_FILE" ]; then
    kill "$(cat "$PID_FILE")" 2>/dev/null && echo "armada-agent stopped"
    rm -f "$PID_FILE"
  else
    echo "armada-agent not running"
  fi
}

status() {
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "armada-agent running (pid $(cat $PID_FILE))"
  else
    echo "armada-agent not running"
  fi
}

case "$1" in
  start)   start ;;
  stop)    stop ;;
  restart) stop; sleep 1; start ;;
  status)  status ;;
  *)       echo "Usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
EOF

chmod 755 /opt/armada/armada-agent.sh
```

Control commands:

```bash
/opt/armada/armada-agent.sh start
/opt/armada/armada-agent.sh stop
/opt/armada/armada-agent.sh restart
/opt/armada/armada-agent.sh status
```

**6. Auto-start on boot via `/opt/bootlocal.sh`**

```bash
cat >> /opt/bootlocal.sh <<'EOF'

# Sync clock (required for agent JWT auth)
ntpd -q -p pool.ntp.org 2>/dev/null || true

# Start Armada Agent
/opt/armada/armada-agent.sh start
EOF

chmod 755 /opt/bootlocal.sh
```

**7. Persist all changes to disk**

```bash
filetool.sh -b
```

> Run `filetool.sh -b` after **every** file change. TinyCore's RAM filesystem loses all changes on reboot unless explicitly persisted.

**8. Start and verify**

```bash
# Start agent immediately
/opt/armada/armada-agent.sh start

# Check status
/opt/armada/armada-agent.sh status

# Follow logs
tail -f /opt/armada/logs/agent.log
```

**Troubleshooting:**

- **HTTP 401 on command poll / metrics, but heartbeat succeeds**: clock skew. The agent generates a JWT with an `exp` claim based on its local clock. If the clock is behind the server's clock, the token arrives already expired — the server returns 401. Heartbeat has no JWT check, so it always succeeds regardless of clock skew, which makes this easy to miss.
  - **Fix A (preferred):** sync the clock — `ntpd -q -p pool.ntp.org` or `date -s "<current-utc-time>"`.
  - **Fix B (tolerance workaround):** add `AGENT_JWT_TTL_SECONDS=86400` to `/opt/armada/agent.env` so tokens are valid for 24 hours, absorbing the skew. This is already included in the env file template above.
  - **Common mistake:** setting `AGENT_JWT_TTL_SECONDS` on the **server container** has no effect — it is an agent-side variable only. The server never reads it.
- **`syntax error: unexpected ")"`**: wrong architecture binary. Run `uname -m` — if `i686`, use the `linux/386` binary, not `linux/amd64`.
- **Binary looks like text / garbled**: file was transferred in text mode. Always use `scp`.
- **Agent not visible in UI**: verify `SERVER_URL` and `AGENT_JWT_SECRET` in `/opt/armada/agent.env`, then restart with `armada-agent.sh restart`.
- **Changes lost after reboot**: you forgot `filetool.sh -b`. Re-apply changes and save.
- **Test connectivity**: `wget -q -O- http://<server>:8070/healthz` (TinyCore uses `wget`, not `curl`, by default).

#### Manage Queued Commands (Cancel/Skip)

To cancel or skip a queued command that hasn't been dispatched yet (e.g., incorrect binary in update queue):

**API Endpoint:**
```
POST /api/agents/{agent_id}/commands/{command_id}/cancel
DELETE /api/agents/{agent_id}/commands/{command_id}/cancel
```

**Authentication:** Admin JWT or session cookie required

**Response (200 OK):**
```json
{
  "id": 372,
  "agent_id": "08685de0-10c8-434b-a8db-265ea6cc01f2",
  "command_type": "agent_update",
  "payload": "{\"version\":\"1.0.4-linux\"}",
  "status": "cancelled",
  "created_at": "2026-03-20T19:00:00Z"
}
```

**Error Cases:**
- `404 Not Found`: Command not found for this agent
- `400 Bad Request`: Command is not in 'queued' status (e.g., already dispatched/completed)
- `401 Unauthorized`: Missing/invalid admin credentials

**Example (cURL):**
```bash
# Cancel command 372 for agent
curl -X POST https://ai-endpoint.example.com/api/agents/08685de0-10c8-434b-a8db-265ea6cc01f2/commands/372/cancel \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json"
```

**Example (PowerShell):**
```powershell
$headers = @{
    "Authorization" = "Bearer <admin_token>"
    "Content-Type" = "application/json"
}

$response = Invoke-WebRequest `
  -Uri "https://ai-endpoint.example.com/api/agents/08685de0-10c8-434b-a8db-265ea6cc01f2/commands/372/cancel" `
  -Method POST `
  -Headers $headers

Write-Host "Command cancelled: $($response.Content | ConvertFrom-Json | Select-Object status)"
```

**Use Cases:**
- Correct incorrect batches of queued updates (e.g., wrong binary version in FIFO queue)
- Skip problematic commands before agent picks them up
- Incident response when wrong command was queued

**Important Notes:**
- Only `queued` status commands can be cancelled
- Dispatched/completed commands cannot be cancelled
- Cancellation happens immediately (no agent interaction needed)
- Useful for fixing command queue issues before agents pick them up

#### Requeue Historical Commands

To requeue a previously finished command (for example, `failed`, `cancelled`, or `succeeded`) as a fresh queued command:

**API Endpoint:**
```
POST /api/agents/{agent_id}/commands/{command_id}/requeue
```

**Authentication:** Admin JWT or session cookie required

**Response (201 Created):**
```json
{
  "id": 401,
  "agent_id": "08685de0-10c8-434b-a8db-265ea6cc01f2",
  "command_type": "agent_update",
  "payload": "{\"version\":\"1.0.8\"}",
  "status": "queued",
  "created_at": "2026-03-29T10:52:01Z"
}
```

**Notes:**
- Requeue creates a new command row; it does not mutate the original command.
- Active commands (`queued` / `dispatched`) are not eligible for requeue.

#### Self-Update History Reports

Reports now include a dedicated **Self Update History** tab with filter controls.

**API Endpoint:**
```
GET /api/reports/self-updates?from=<datetime>&to=<datetime>&status=<status>&target_version=<version>&agent_id=<id>&hostname=<substring>&limit=<n>
```

**Purpose:**
- Query self-update queue/install history across agents
- Filter by date range, status, target version, exact agent ID, and hostname substring

#### References

- [README.md](README.md): Agent install and update details
- [RELEASE_NOTES.md](RELEASE_NOTES.md): Latest release summary
- [RELEASE_PR_NOTE.md](RELEASE_PR_NOTE.md): Detailed rollout notes

## Getting Help

- Check [README.md](README.md) for troubleshooting
- Review [ARCHITECTURE.md](ARCHITECTURE.md) for design details
- Check [DEVELOPMENT.md](DEVELOPMENT.md) for build instructions
- Review logs: `sudo journalctl -u ai-endpoint-server -f`
