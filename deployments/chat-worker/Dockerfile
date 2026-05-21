# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build chat-worker binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o chat-worker ./cmd/chat-worker

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates libc6-compat curl

# Copy binary from builder
COPY --from=builder /app/chat-worker .

# Create logs directory
RUN mkdir -p logs

# Default environment variables
ENV DATABASE_URL=postgres://aiuser:aipassword@host.docker.internal:5432/aiendpoint?sslmode=disable
ENV AGENT_JWT_SECRET=armada-test-secret-2024
ENV NATS_URL=nats://localhost:4222
ENV QUEUE_ENABLED=true
ENV QUEUE_PROVIDER=nats
ENV QUEUE_SUBJECT_PREFIX=chat
ENV QUEUE_AGENT_CHAT_ACTIVE=true
ENV QUEUE_AGENT_CHAT_SUBJECT=agent.chat.shadow
ENV QUEUE_AGENT_CHAT_CONSUMER_GROUP=agent-chat-workers
ENV LOG_TO_CONSOLE=true
ENV LOG_DIR=logs

CMD ["./chat-worker"]
