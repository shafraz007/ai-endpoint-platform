package server

import (
	"context"
	"errors"
	"time"
)

type MetricSample struct {
	AgentID              string
	Timestamp            time.Time
	CPUPercent           float64
	MemoryUsedPercent    float64
	MemoryUsedBytes      int64
	MemoryTotalBytes     int64
	NetBytesSentPerSec   float64
	NetBytesRecvPerSec   float64
	NetPacketsSentPerSec float64
	NetPacketsRecvPerSec float64
}

func InsertMetrics(ctx context.Context, sample MetricSample) error {
	if DB == nil {
		return errors.New("database not initialized")
	}

	query := `
	INSERT INTO agent_metrics (
		agent_id, timestamp, cpu_percent, memory_used_percent,
		memory_used_bytes, memory_total_bytes,
		net_bytes_sent_per_sec, net_bytes_recv_per_sec,
		net_packets_sent_per_sec, net_packets_recv_per_sec
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := DB.Exec(
		ctx,
		query,
		sample.AgentID,
		sample.Timestamp,
		sample.CPUPercent,
		sample.MemoryUsedPercent,
		sample.MemoryUsedBytes,
		sample.MemoryTotalBytes,
		sample.NetBytesSentPerSec,
		sample.NetBytesRecvPerSec,
		sample.NetPacketsSentPerSec,
		sample.NetPacketsRecvPerSec,
	)
	return err
}

func GetLatestMetrics(ctx context.Context, agentID string) (*MetricSample, error) {
	if DB == nil {
		return nil, errors.New("database not initialized")
	}
	query := `
	SELECT agent_id, timestamp, cpu_percent, memory_used_percent,
		memory_used_bytes, memory_total_bytes,
		net_bytes_sent_per_sec, net_bytes_recv_per_sec,
		net_packets_sent_per_sec, net_packets_recv_per_sec
	FROM agent_metrics
	WHERE agent_id = $1
	ORDER BY timestamp DESC
	LIMIT 1
	`

	row := DB.QueryRow(ctx, query, agentID)
	var sample MetricSample
	if err := row.Scan(
		&sample.AgentID,
		&sample.Timestamp,
		&sample.CPUPercent,
		&sample.MemoryUsedPercent,
		&sample.MemoryUsedBytes,
		&sample.MemoryTotalBytes,
		&sample.NetBytesSentPerSec,
		&sample.NetBytesRecvPerSec,
		&sample.NetPacketsSentPerSec,
		&sample.NetPacketsRecvPerSec,
	); err != nil {
		return nil, err
	}
	return &sample, nil
}

func ListMetricsByAgent(ctx context.Context, agentID string, since *time.Time, limit int) ([]MetricSample, error) {
	if DB == nil {
		return nil, errors.New("database not initialized")
	}
	if limit <= 0 {
		limit = 120
	}

	query := `
	SELECT agent_id, timestamp, cpu_percent, memory_used_percent,
		memory_used_bytes, memory_total_bytes,
		net_bytes_sent_per_sec, net_bytes_recv_per_sec,
		net_packets_sent_per_sec, net_packets_recv_per_sec
	FROM agent_metrics
	WHERE agent_id = $1 AND ($2::timestamp IS NULL OR timestamp >= $2)
	ORDER BY timestamp DESC
	LIMIT $3
	`

	rows, err := DB.Query(ctx, query, agentID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	samples := make([]MetricSample, 0, limit)
	for rows.Next() {
		var sample MetricSample
		if err := rows.Scan(
			&sample.AgentID,
			&sample.Timestamp,
			&sample.CPUPercent,
			&sample.MemoryUsedPercent,
			&sample.MemoryUsedBytes,
			&sample.MemoryTotalBytes,
			&sample.NetBytesSentPerSec,
			&sample.NetBytesRecvPerSec,
			&sample.NetPacketsSentPerSec,
			&sample.NetPacketsRecvPerSec,
		); err != nil {
			return nil, err
		}
		samples = append(samples, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Reverse to ascending time for charting
	for i, j := 0, len(samples)-1; i < j; i, j = i+1, j-1 {
		samples[i], samples[j] = samples[j], samples[i]
	}

	return samples, nil
}
