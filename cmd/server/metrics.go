package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

const metricsStreamInterval = 5 * time.Second

func metricsRouter(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			metricsIngestHandler(cfg)(w, r)
		case http.MethodGet:
			metricsListHandler(cfg)(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func metricsIngestHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.AgentJWTSecret == "" {
			http.Error(w, "Agent auth not configured", http.StatusInternalServerError)
			return
		}

		claims, err := requireAgent(r, cfg.AgentJWTSecret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		agentID := strings.TrimSpace(claims.Subject)
		if agentID == "" {
			http.Error(w, "Missing subject", http.StatusUnauthorized)
			return
		}

		var req transport.MetricsSample
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.AgentID) == "" {
			req.AgentID = agentID
		}
		if req.AgentID != agentID {
			http.Error(w, "Agent mismatch", http.StatusUnauthorized)
			return
		}
		if req.Timestamp.IsZero() {
			req.Timestamp = time.Now()
		}

		sample := server.MetricSample{
			AgentID:              req.AgentID,
			Timestamp:            req.Timestamp,
			CPUPercent:           req.CPUPercent,
			MemoryUsedPercent:    req.MemoryUsedPercent,
			MemoryUsedBytes:      int64(req.MemoryUsedBytes),
			MemoryTotalBytes:     int64(req.MemoryTotalBytes),
			NetBytesSentPerSec:   req.NetBytesSentPerSec,
			NetBytesRecvPerSec:   req.NetBytesRecvPerSec,
			NetPacketsSentPerSec: req.NetPacketsSentPerSec,
			NetPacketsRecvPerSec: req.NetPacketsRecvPerSec,
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := server.InsertMetrics(ctx, sample); err != nil {
			log.Printf("InsertMetrics error: %v", err)
			http.Error(w, "Failed to store metrics", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func metricsListHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, _, err := authorizeAdminSession(w, r, cfg, false); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
		if agentID == "" {
			http.Error(w, "Missing agent_id", http.StatusBadRequest)
			return
		}

		var since *time.Time
		var selectedRange time.Duration
		if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
			parsed, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				http.Error(w, "Invalid since value", http.StatusBadRequest)
				return
			}
			since = &parsed
		} else if raw := strings.TrimSpace(r.URL.Query().Get("range")); raw != "" {
			duration, ok := parseMetricsRange(raw)
			if !ok {
				http.Error(w, "Invalid range value", http.StatusBadRequest)
				return
			}
			selectedRange = duration
			start := time.Now().Add(-duration)
			since = &start
		}

		limit := 120
		hasExplicitLimit := false
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				limit = parsed
				hasExplicitLimit = true
			}
		}
		if !hasExplicitLimit && selectedRange > 0 {
			limit = defaultMetricsLimitForRange(selectedRange)
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		samples, err := server.ListMetricsByAgent(ctx, agentID, since, limit)
		if err != nil {
			log.Printf("ListMetrics error: %v", err)
			http.Error(w, "Failed to list metrics", http.StatusInternalServerError)
			return
		}

		resp := make([]transport.MetricsSample, 0, len(samples))
		for _, sample := range samples {
			resp = append(resp, metricSampleToTransport(sample))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func parseMetricsRange(raw string) (time.Duration, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "10m":
		return 10 * time.Minute, true
	case "1h":
		return time.Hour, true
	case "4h":
		return 4 * time.Hour, true
	case "12h":
		return 12 * time.Hour, true
	case "24h":
		return 24 * time.Hour, true
	default:
		return 0, false
	}
}

func defaultMetricsLimitForRange(duration time.Duration) int {
	approx := int(duration/metricsStreamInterval) + 1
	if approx < 120 {
		return 120
	}
	if approx > 2000 {
		return 2000
	}
	return approx
}

func metricsStreamHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, _, err := authorizeAdminSession(w, r, cfg, false); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
		if agentID == "" {
			http.Error(w, "Missing agent_id", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		sendSample := func(sample transport.MetricsSample) {
			payload, err := json.Marshal(sample)
			if err != nil {
				return
			}
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write(payload)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}

		ctx := r.Context()
		// Send initial sample if available
		if sample, err := latestMetrics(ctx, agentID); err == nil {
			sendSample(sample)
		}

		ticker := time.NewTicker(metricsStreamInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sample, err := latestMetrics(ctx, agentID)
				if err != nil {
					continue
				}
				sendSample(sample)
			}
		}
	}
}

func latestMetrics(ctx context.Context, agentID string) (transport.MetricsSample, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	sample, err := server.GetLatestMetrics(ctx, agentID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return transport.MetricsSample{}, err
		}
		return transport.MetricsSample{}, err
	}
	return metricSampleToTransport(*sample), nil
}

func metricSampleToTransport(sample server.MetricSample) transport.MetricsSample {
	return transport.MetricsSample{
		AgentID:              sample.AgentID,
		Timestamp:            sample.Timestamp,
		CPUPercent:           sample.CPUPercent,
		MemoryUsedPercent:    sample.MemoryUsedPercent,
		MemoryUsedBytes:      uint64(sample.MemoryUsedBytes),
		MemoryTotalBytes:     uint64(sample.MemoryTotalBytes),
		NetBytesSentPerSec:   sample.NetBytesSentPerSec,
		NetBytesRecvPerSec:   sample.NetBytesRecvPerSec,
		NetPacketsSentPerSec: sample.NetPacketsSentPerSec,
		NetPacketsRecvPerSec: sample.NetPacketsRecvPerSec,
	}
}
