package queue

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type SubscriberConfig struct {
	Provider string
	NATSURL  string
	Subject  string
	QueueGroup string
	Timeout  time.Duration
}

type MessageHandler func(ctx context.Context, subject string, payload []byte) error

func Subscribe(ctx context.Context, cfg SubscriberConfig, handler MessageHandler) error {
	if handler == nil {
		return fmt.Errorf("message handler is required")
	}

	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		provider = "nats"
	}

	switch provider {
	case "nats":
		return subscribeNATS(ctx, cfg, handler)
	default:
		return fmt.Errorf("unsupported queue provider: %s", provider)
	}
}

func subscribeNATS(ctx context.Context, cfg SubscriberConfig, handler MessageHandler) error {
	subject := strings.TrimSpace(cfg.Subject)
	if subject == "" {
		return fmt.Errorf("subject is required")
	}
	if strings.ContainsAny(subject, " \t\r\n") {
		return fmt.Errorf("subject contains whitespace")
	}

	queueGroup := strings.TrimSpace(cfg.QueueGroup)
	if strings.ContainsAny(queueGroup, " \t\r\n") {
		return fmt.Errorf("queue group contains whitespace")
	}

	address, err := parseNATSAddress(cfg.NATSURL)
	if err != nil {
		return err
	}

	readTimeout := cfg.Timeout
	if readTimeout <= 0 {
		readTimeout = 5 * time.Second
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if err := runNATSSubscribeSession(ctx, address, subject, queueGroup, readTimeout, handler); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			if ctx.Err() != nil {
				return nil
			}

			wait := 1500 * time.Millisecond
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	}
}

func runNATSSubscribeSession(ctx context.Context, address, subject, queueGroup string, readTimeout time.Duration, handler MessageHandler) error {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("nats dial failed: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	if err := writeNATSLine(writer, `CONNECT {"lang":"go","version":"phase2-chat-worker"}`); err != nil {
		return err
	}
	subLine := "SUB " + subject + " 1"
	if queueGroup != "" {
		subLine = "SUB " + subject + " " + queueGroup + " 1"
	}
	if err := writeNATSLine(writer, subLine); err != nil {
		return err
	}
	if err := writeNATSLine(writer, "PING"); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("nats flush failed: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		line, err := reader.ReadString('\n')
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("nats connection closed")
			}
			return fmt.Errorf("nats read failed: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "INFO "):
			continue
		case line == "PING":
			if err := writeNATSLine(writer, "PONG"); err != nil {
				return err
			}
			if err := writer.Flush(); err != nil {
				return fmt.Errorf("nats flush failed: %w", err)
			}
			continue
		case line == "+OK" || line == "PONG":
			continue
		case strings.HasPrefix(line, "-ERR"):
			return fmt.Errorf("nats server error: %s", line)
		case strings.HasPrefix(line, "MSG "):
			payloadSubject, payload, err := readNATSMessage(reader, line)
			if err != nil {
				return err
			}
			if err := handler(ctx, payloadSubject, payload); err != nil {
				continue
			}
		default:
			continue
		}
	}
}

func readNATSMessage(reader *bufio.Reader, headerLine string) (string, []byte, error) {
	parts := strings.Fields(headerLine)
	if len(parts) < 4 {
		return "", nil, fmt.Errorf("invalid nats msg header: %s", headerLine)
	}

	subject := strings.TrimSpace(parts[1])
	if subject == "" {
		return "", nil, fmt.Errorf("invalid nats msg subject")
	}

	lengthPart := parts[len(parts)-1]
	length := ParsePort(lengthPart, -1)
	if length < 0 {
		return "", nil, fmt.Errorf("invalid nats msg length: %s", lengthPart)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return "", nil, fmt.Errorf("failed reading nats payload: %w", err)
	}

	trail := make([]byte, 2)
	if _, err := io.ReadFull(reader, trail); err != nil {
		return "", nil, fmt.Errorf("failed reading nats payload terminator: %w", err)
	}

	return subject, payload, nil
}

func writeNATSLine(writer *bufio.Writer, line string) error {
	if _, err := writer.WriteString(line + "\r\n"); err != nil {
		return fmt.Errorf("nats write failed: %w", err)
	}
	return nil
}
