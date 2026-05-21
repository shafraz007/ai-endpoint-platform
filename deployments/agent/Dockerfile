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

# Build agent binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o agent ./cmd/agent

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates libc6-compat

# Copy binary from builder
COPY --from=builder /app/agent .

# Create logs directory
RUN mkdir -p logs

# Default environment variables
ENV SERVER_URL=http://armada-server:8070
ENV AGENT_JWT_SECRET=test-secret
ENV AGENT_AI_PROVIDER=ollama
ENV AGENT_AI_ENDPOINT=http://ollama:11434/api/chat
ENV AGENT_AI_MODEL=llama3.2
ENV LOG_TO_CONSOLE=true
ENV LOG_DIR=logs

CMD ["./agent"]
