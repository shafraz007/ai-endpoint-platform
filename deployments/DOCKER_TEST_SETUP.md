# Docker Agent Test Environment Setup

This directory contains Docker configurations for deploying and testing Dockerized Armada Agents in a containerized Linux environment.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- **Ollama running on host** (port 11434)
- **Armada Server running on host** (port 8070)
- ~256MB available disk space
- ~256MB available RAM

## Quick Start

### 1. Ensure Host Services Running

Before starting the Docker agent, verify your host has:

```powershell
# Check Ollama
curl http://localhost:11434/api/tags

# Check Server
curl http://localhost:8070/healthz
```

Both should return 200 OK.

### 2. Launch Agent Container

From the `deployments/` directory:

```bash
docker-compose -f docker-compose.test.yml up -d
```

This starts:
- **Agent** (docker container) — connects to the shared Armada server stack on `armada-shared`

Chat processing is handled by the single `armada-chat-worker` service in `deployments/server/docker-compose.server.yml`.

### 3. Verify Agent Health

```bash
# Check container is running
docker-compose -f docker-compose.test.yml ps

# Watch agent logs (should show heartbeats every 30s)
docker-compose -f docker-compose.test.yml logs -f agent
```

Expected output:
```
Agent started - ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Heartbeat sent to http://armada-server:8070
```

### 4. Configure Connection (Optional)

If your server/Ollama are on a different machine:

```powershell
# Set custom server URL
$env:SERVER_URL="http://192.168.1.100:8070"
docker-compose -f docker-compose.test.yml up -d

# Or custom Ollama endpoint
$env:AGENT_AI_ENDPOINT="http://192.168.1.100:11434/api/chat"
docker-compose -f docker-compose.test.yml up -d
```

Or edit `docker-compose.test.yml` directly.

### 5. Stop and Clean Up

```bash
# Stop container (data persists)
docker-compose -f docker-compose.test.yml down

# Stop and remove volumes (full reset)
docker-compose -f docker-compose.test.yml down -v
```

## Architecture

```
┌─────────────────────────────────────┐
│        HOST MACHINE                 │
├─────────────────────────────────────┤
│                                     │
│  ┌──────────────┐  ┌────────────┐  │
│  │ Armada       │  │  Ollama    │  │
│  │ Server       │  │  :11434    │  │
│  │ :8070        │  │            │  │
│  └──────┬───────┘  └────────┬───┘  │
│         │                   │       │
└─────────┼───────────────────┼───────┘
          │                   │
    ┌─────┴───────────────────┴────┐
    │  Docker Network Bridge        │
    │  (host.docker.internal)       │
    └─────────────┬─────────────────┘
                  │
          ┌───────▼────────┐
          │ Armada Agent   │
          │ (Container)    │
          │ • Heartbeat    │
          │ • Commands     │
          │ • Chat via LLM │
          └────────────────┘
```

## Testing Development Phases

This agent-only environment supports isolated testing of:

### Phase 1: Tool Registry
- Agent discovers and advertises tools on heartbeat
- Watch agent logs for tool advertisements  
- Server API: `curl http://localhost:8070/api/agents/{id}/tools`

### Phase 2: Task Orchestration
- Server sends tasks to agent via heartbeat
- Agent executor processes tasks
- Watch agent logs for task execution

### Phase 3: Action Memory
- Agent tracks action outcomes
- Success/failure recorded
- Watch agent logs

### Phase 4: Collaboration
- Agent requests help from other agents
- Flows through server

### Phase 5: Adaptive AI Context
- Agent chat enriched with local diagnostics
- AI responses ranked by tool success history

## Environment Variables

Override in shell or edit `docker-compose.test.yml`:

- **Agent:**
   - `SERVER_URL` — where to find Armada Server (default: `http://armada-server:8070`)
   - `AGENT_JWT_SECRET` — must match server (default: `armada-test-secret-2024`)
   - `AGENT_AI_ENDPOINT` — where to find Ollama (default: `http://host.docker.internal:11434/api/chat`)
   - `AGENT_AI_MODEL` — model name (default: `llama3.2`)
   - `HEARTBEAT_INTERVAL_SECONDS` — heartbeat frequency (default: 30)

## Troubleshooting

### Agent can't connect to server

```powershell
# Verify server is running
curl http://localhost:18070/healthz

# Check agent logs for errors
docker-compose -f docker-compose.test.yml logs agent

# If on Windows, ensure Docker Desktop is configured for host.docker.internal
# Verify from inside container
docker-compose -f docker-compose.test.yml exec agent curl http://armada-server:8070/healthz
```

### Agent can't reach Ollama

```powershell
# Verify Ollama is running on host
curl http://localhost:11434/api/tags

# Check agent logs
docker-compose -f docker-compose.test.yml logs agent | grep -i ollama

# If on Windows Docker Desktop, test host bridge
docker-compose -f docker-compose.test.yml exec agent curl http://host.docker.internal:11434/api/tags
```

### JWT authentication failed

Ensure `AGENT_JWT_SECRET` matches between agent and server:

```powershell
# On host, check server config
$env:AGENT_JWT_SECRET

# Update agent in docker-compose.test.yml:
AGENT_JWT_SECRET: your-same-secret
```

### Port conflicts

If 11434 or 8070 are in use on host, change the port in your host services, not the Docker config (agent connects via `host.docker.internal`).

### Container won't start

```powershell
# Check build errors
docker-compose -f docker-compose.test.yml build

# Check runtime errors
docker-compose -f docker-compose.test.yml logs agent
```

## Next Steps

1. **Ensure Ollama is running** on `http://localhost:11434`
2. **Ensure Server is running** on `http://localhost:8070`
3. **Build agent image**:
   ```bash
   docker-compose -f docker-compose.test.yml build
   ```

4. **Start server stack** (includes the shared `armada-chat-worker`):
   ```bash
   docker compose -f deployments/server/docker-compose.server.yml up -d --build
   ```

5. **Start agents**:
   ```bash
   docker-compose -f docker-compose.test.yml up -d
   ```

6. **Watch heartbeats**:
   ```bash
   docker-compose -f docker-compose.test.yml logs -f agent
   ```

7. **Begin Phase 1 implementation** with this environment
