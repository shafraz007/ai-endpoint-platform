# Server + Chat Worker in Docker (using existing Postgres/NATS/Ollama containers)

This setup runs **Armada Server and chat-worker** in Docker.
Postgres, NATS, and Ollama are expected to already be running in their own containers.

## 1) Create shared network (once)

```bash
docker network create armada-shared
```

Attach your existing dependency containers (`postgres`, `nats`, `ollama`) to `armada-shared`.

By default, this compose file connects to dependency containers through host-published ports:
- `DATABASE_URL=postgres://aiuser:aipassword@host.docker.internal:5432/aiendpoint?sslmode=disable`
- `NATS_URL=nats://host.docker.internal:4222`
- `GLOBAL_CHAT_AI_ENDPOINT=http://host.docker.internal:11434/v1/chat/completions`

If your dependencies are reachable by container DNS name on `armada-shared`, override env values accordingly.

## 2) Start server/chat-worker containers

From repository root:

```bash
docker compose -f deployments/server/docker-compose.server.yml up -d --build
```

Server will be exposed at:
- `http://localhost:18070` (default)

Containers started:
- `armada-server`
- `armada-chat-worker`

All Docker agents on `armada-shared` use this single shared `armada-chat-worker`.

If you want host port 8070 instead:

```bash
SERVER_PUBLISHED_PORT=8070 docker compose -f deployments/server/docker-compose.server.yml up -d --build
```

## 3) Configure agent SERVER_URL

For Dockerized agents on the same `armada-shared` network:
- `SERVER_URL=http://armada-server:8070`

For host/native agents (outside Docker):
- `SERVER_URL=http://localhost:8070`

## 4) Verify health

```bash
curl http://localhost:18070/healthz
```

## Notes

- `deployments/docker-compose.test.yml` now defaults to:
  - `SERVER_URL=http://armada-server:8070`
  - `AGENT_AI_ENDPOINT=http://ollama:11434/api/chat`
  - external network `armada-shared`
- `deployments/docker-compose.test.yml` is agents-only; chat queue consumption stays centralized in `armada-chat-worker` from this stack.
- Override with environment variables if your dependency container names differ.

## Useful commands

```bash
# Logs
docker compose -f deployments/server/docker-compose.server.yml logs -f armada-server
docker compose -f deployments/server/docker-compose.server.yml logs -f armada-chat-worker

# Stop
docker compose -f deployments/server/docker-compose.server.yml down
```
