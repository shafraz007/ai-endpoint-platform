package server

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
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
	CPUTemperatureC      *float64
	DiskTemperatureC     *float64
	DiskUsagePercent     *float64
	FanCPURPM            *float64
	FanSystemRPM         *float64
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
		net_packets_sent_per_sec, net_packets_recv_per_sec,
		cpu_temperature_c, disk_temperature_c, disk_usage_percent,
		fan_cpu_rpm, fan_system_rpm
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
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
		sample.CPUTemperatureC,
		sample.DiskTemperatureC,
		sample.DiskUsagePercent,
		sample.FanCPURPM,
		sample.FanSystemRPM,
	)
	return err
}

func EnsureAgentExistsForMetrics(ctx context.Context, agentID string) error {
	if DB == nil {
		return errors.New("database not initialized")
	}
	if agentID == "" {
		return errors.New("agentID is required")
	}

	query := `
	INSERT INTO agents (agent_id, hostname, status, last_seen, date_added)
	VALUES ($1, $2, 'online', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	ON CONFLICT (agent_id) DO NOTHING
	`

	_, err := DB.Exec(ctx, query, agentID, agentID)
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
		net_packets_sent_per_sec, net_packets_recv_per_sec,
		cpu_temperature_c, disk_temperature_c, disk_usage_percent,
		fan_cpu_rpm, fan_system_rpm
	FROM agent_metrics
	WHERE agent_id = $1
	ORDER BY timestamp DESC
	LIMIT 1
	`

	row := DB.QueryRow(ctx, query, agentID)
	var sample MetricSample
	var cpuTemp pgtype.Float8
	var diskTemp pgtype.Float8
	var diskUsage pgtype.Float8
	var fanCPU pgtype.Float8
	var fanSystem pgtype.Float8
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
		&cpuTemp,
		&diskTemp,
		&diskUsage,
		&fanCPU,
		&fanSystem,
	); err != nil {
		return nil, err
	}
	sample.CPUTemperatureC = float8Ptr(cpuTemp)
	sample.DiskTemperatureC = float8Ptr(diskTemp)
	sample.DiskUsagePercent = float8Ptr(diskUsage)
	sample.FanCPURPM = float8Ptr(fanCPU)
	sample.FanSystemRPM = float8Ptr(fanSystem)
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
		net_packets_sent_per_sec, net_packets_recv_per_sec,
		cpu_temperature_c, disk_temperature_c, disk_usage_percent,
		fan_cpu_rpm, fan_system_rpm
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
		var cpuTemp pgtype.Float8
		var diskTemp pgtype.Float8
		var diskUsage pgtype.Float8
		var fanCPU pgtype.Float8
		var fanSystem pgtype.Float8
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
			&cpuTemp,
			&diskTemp,
			&diskUsage,
			&fanCPU,
			&fanSystem,
		); err != nil {
			return nil, err
		}
		sample.CPUTemperatureC = float8Ptr(cpuTemp)
		sample.DiskTemperatureC = float8Ptr(diskTemp)
		sample.DiskUsagePercent = float8Ptr(diskUsage)
		sample.FanCPURPM = float8Ptr(fanCPU)
		sample.FanSystemRPM = float8Ptr(fanSystem)
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

func float8Ptr(value pgtype.Float8) *float64 {
	if !value.Valid {
		return nil
	}
	v := value.Float64
	return &v
}
