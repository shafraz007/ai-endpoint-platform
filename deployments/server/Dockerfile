# ─── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /app

# git is needed for some go module fetches
RUN apk add --no-cache git

# Resolve dependencies first (layer-cached)
COPY go.mod go.sum ./
RUN go mod download

# Copy full source
COPY . .

# Pure-Go static binary — no cgo required on Linux
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o server ./cmd/server

# ─── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20

WORKDIR /app

# TLS root certs for outbound HTTPS calls (AI endpoints, etc.)
RUN apk add --no-cache ca-certificates tzdata

# Non-root user for security
RUN addgroup -S armada && adduser -S armada -G armada

# Binary
COPY --from=builder /app/server .

# HTML templates — loaded at runtime via relative path "cmd/server/templates/..."
COPY --from=builder /app/cmd/server/templates ./cmd/server/templates

# Log directory
RUN mkdir -p logs && chown -R armada:armada /app

USER armada

# ─── Defaults (override via env or docker-compose) ─────────────────────────────
ENV SERVER_PORT=8070
ENV DATABASE_URL=postgres://aiuser:aipassword@host.docker.internal:5432/aiendpoint?sslmode=disable
ENV AGENT_JWT_SECRET=change-me-agent-secret
ENV ADMIN_JWT_SECRET=change-me-admin-secret
ENV LOG_TO_CONSOLE=true
ENV LOG_DIR=logs
ENV QUEUE_ENABLED=true
ENV QUEUE_PROVIDER=nats
ENV NATS_URL=nats://host.docker.internal:4222
ENV OFFLINE_TIMEOUT_SECONDS=90
ENV OFFLINE_CHECK_INTERVAL_SECONDS=30

EXPOSE 8070

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8070/healthz || exit 1

CMD ["./server"]
