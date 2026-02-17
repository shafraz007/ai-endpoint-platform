# Production Deployment Guide

This guide covers deploying the AI Endpoint Platform v1.0.0 to production environments.

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
  - Agents can reach server on port 8080 (or custom port)
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

## Pre-Deployment Steps

### 1. Build Release Binaries

```bash
# Build optimized binaries
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/server ./cmd/server
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/agent ./cmd/agent

# For Windows
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/server.exe ./cmd/server
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/agent.exe ./cmd/agent
```

### 2. Test Release Build

```bash
# Test in staging environment
export DATABASE_URL=postgres://ai_endpoint_user:<your_secure_password>@staging-db.internal:5432/ai_agents?sslmode=disable
export SERVER_PORT=8080
./bin/server

# In another terminal
export SERVER_URL=http://localhost:8080
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

# Verify
ls -la /opt/ai-endpoint-platform/bin/
```

#### 3. Configure Environment

Create `/etc/ai-endpoint-platform/server.env`:

```bash
# Database Configuration
DATABASE_URL=postgres://ai_endpoint_user:<your_secure_password>@prod-db.internal:5432/ai_agents?sslmode=require

# Server Configuration
SERVER_PORT=8080

# Agent Monitoring (seconds)
OFFLINE_TIMEOUT_SECONDS=90
OFFLINE_CHECK_INTERVAL_SECONDS=30
```

Permissions:
```bash
sudo chown ai-endpoint:ai-endpoint /etc/ai-endpoint-platform/server.env
sudo chmod 600 /etc/ai-endpoint-platform/server.env
```

#### 4. Create Systemd Service

Create `/etc/systemd/system/ai-endpoint-server.service`:

```ini
[Unit]
Description=AI Endpoint Platform Server
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

#### 5. Configure Reverse Proxy (HTTPS)

Using nginx:

```nginx
upstream ai_endpoint {
    server localhost:8080;
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
$appPath = "C:\Program Files\AIEndpointPlatform"
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
[Environment]::SetEnvironmentVariable("SERVER_PORT", "8080", "Machine")
[Environment]::SetEnvironmentVariable("OFFLINE_TIMEOUT_SECONDS", "90", "Machine")
[Environment]::SetEnvironmentVariable("OFFLINE_CHECK_INTERVAL_SECONDS", "30", "Machine")
```

#### 4. Create Windows Service

```powershell
# Using NSSM (Non-Sucking Service Manager)
nssm install AIEndpointServer `
  "C:\Program Files\AIEndpointPlatform\server.exe"

nssm set AIEndpointServer AppEnvironmentExtra `
  "DATABASE_URL=postgres://ai_endpoint_user:<your_secure_password>@prod-db.internal:5432/ai_agents?sslmode=require;SERVER_PORT=8080;OFFLINE_TIMEOUT_SECONDS=90;OFFLINE_CHECK_INTERVAL_SECONDS=30"

# Configure Log
nssm set AIEndpointServer AppStdout `
  "C:\Program Files\AIEndpointPlatform\logs\server.log"

nssm set AIEndpointServer AppStderr `
  "C:\Program Files\AIEndpointPlatform\logs\server.log"

# Start Service
nssm start AIEndpointServer
```

Or using PowerShell directly:

```powershell
# Create scheduled task
$action = New-ScheduledTaskAction `
  -Execute "C:\Program Files\AIEndpointPlatform\server.exe"

$trigger = New-ScheduledTaskTrigger -AtStartup

Register-ScheduledTask `
  -TaskName "AIEndpointServer" `
  -Action $action `
  -Trigger $trigger `
  -RunLevel Highest

# Start task
Start-ScheduledTask -TaskName "AIEndpointServer"
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

EXPOSE 8080

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
      SERVER_PORT: 8080
    ports:
      - "8080:8080"
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
netstat -tlnp | grep 8080
# or on Windows
netstat -ano | findstr :8080

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
curl -X GET http://localhost:8080/healthz

# Test API
curl -X GET http://localhost:8080/api/agents

# Test Web UI
curl -X GET http://localhost:8080/agents

# Check response
# Should return: empty agents list [] or HTML page
```

### 4. Deploy and Test Agent

```bash
# On agent machine
export SERVER_URL=https://ai-endpoint.example.com
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
      - targets: ['ai-endpoint.example.com:8080']
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
sudo ufw allow 8080/tcp    # Server (internal only)
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
lsof -i :8080

# Verify binary
/opt/ai-endpoint-platform/bin/server -h
```

**Solution:**
1. Kill process using port 8080
2. Check permissions on binary (755)
3. Verify environment variables loaded

### Issue: "Agents can't connect to server"

**Diagnosis:**
```bash
# From agent machine
ping prod-db.internal    # No - this is DB
curl -v http://ai-endpoint.example.com:8080/api/agents

# Check firewall rules
sudo ufw status
sudo iptables -L -n | grep 8080

# Test reverse proxy
curl -v http://localhost:8080
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

## Getting Help

- Check [README.md](README.md) for troubleshooting
- Review [ARCHITECTURE.md](ARCHITECTURE.md) for design details
- Check [DEVELOPMENT.md](DEVELOPMENT.md) for build instructions
- Review logs: `sudo journalctl -u ai-endpoint-server -f`
