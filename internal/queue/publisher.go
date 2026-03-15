package queue

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Enabled       bool
	Provider      string
	NATSURL       string
	SubjectPrefix string
	Timeout       time.Duration
}

type Publisher interface {
	Enabled() bool
	Publish(ctx context.Context, subject string, payload []byte) error
}

type noopPublisher struct{}

func (noopPublisher) Enabled() bool {
	return false
}

func (noopPublisher) Publish(ctx context.Context, subject string, payload []byte) error {
	return nil
}

type natsPublisher struct {
	address string
	prefix  string
	timeout time.Duration
}

func (n *natsPublisher) Enabled() bool {
	return true
}

func (n *natsPublisher) Publish(ctx context.Context, subject string, payload []byte) error {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return fmt.Errorf("subject is required")
	}
	if strings.ContainsAny(subject, " \t\r\n") {
		return fmt.Errorf("subject contains whitespace")
	}

	fullSubject := subject
	if n.prefix != "" {
		fullSubject = n.prefix + "." + subject
	}

	timeout := n.timeout
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", n.address)
	if err != nil {
		return fmt.Errorf("nats dial failed: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	} else {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	}

	frame := fmt.Sprintf("PUB %s %d\r\n", fullSubject, len(payload))
	if _, err := conn.Write([]byte(frame)); err != nil {
		return fmt.Errorf("nats write frame failed: %w", err)
	}
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("nats write payload failed: %w", err)
	}
	if _, err := conn.Write([]byte("\r\n")); err != nil {
		return fmt.Errorf("nats write terminator failed: %w", err)
	}

	return nil
}

func NewPublisher(cfg Config) (Publisher, error) {
	if !cfg.Enabled {
		return noopPublisher{}, nil
	}

	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		provider = "nats"
	}

	switch provider {
	case "nats":
		address, err := parseNATSAddress(cfg.NATSURL)
		if err != nil {
			return nil, err
		}
		prefix := sanitizePrefix(cfg.SubjectPrefix)
		return &natsPublisher{
			address: address,
			prefix:  prefix,
			timeout: cfg.Timeout,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported queue provider: %s", provider)
	}
}

func parseNATSAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("nats url is required")
	}

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("invalid nats url: %w", err)
		}
		if u.Scheme != "nats" && u.Scheme != "tls" {
			return "", fmt.Errorf("unsupported nats scheme: %s", u.Scheme)
		}
		host := strings.TrimSpace(u.Host)
		if host == "" {
			return "", fmt.Errorf("nats host is required")
		}
		if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
			host = net.JoinHostPort(host, "4222")
		}
		return host, nil
	}

	if _, _, err := net.SplitHostPort(raw); err != nil {
		raw = net.JoinHostPort(raw, "4222")
	}
	return raw, nil
}

func sanitizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.Trim(prefix, ".")
	if prefix == "" {
		return ""
	}
	parts := strings.Split(prefix, ".")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		part = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
				return r
			}
			if r == '.' {
				return -1
			}
			return '_'
		}, part)
		if part != "" {
			clean = append(clean, part)
		}
	}
	if len(clean) == 0 {
		return ""
	}
	return strings.Join(clean, ".")
}

func ParsePort(raw string, fallback int) int {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 || value > 65535 {
		return fallback
	}
	return value
}
