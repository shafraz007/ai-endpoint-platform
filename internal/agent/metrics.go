package agent

import (
	"errors"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	gnet "github.com/shirou/gopsutil/v3/net"
)

type MetricsSnapshot struct {
	CPUPercent           float64
	MemoryUsedPercent    float64
	MemoryUsedBytes      uint64
	MemoryTotalBytes     uint64
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

type MetricsCollector struct {
	lastNet  *gnet.IOCountersStat
	lastTime time.Time
}

func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{}
}

func (c *MetricsCollector) Sample() (*MetricsSnapshot, error) {
	cpuPercents, err := cpu.Percent(0, false)
	if err != nil || len(cpuPercents) == 0 {
		return nil, errors.New("failed to read cpu percent")
	}
	memStat, err := mem.VirtualMemory()
	if err != nil {
		return nil, errors.New("failed to read memory stats")
	}
	netStats, err := gnet.IOCounters(false)
	if err != nil || len(netStats) == 0 {
		return nil, errors.New("failed to read network stats")
	}

	now := time.Now()
	current := netStats[0]
	elapsed := now.Sub(c.lastTime).Seconds()
	var sentPerSec float64
	var recvPerSec float64
	var sentPacketsPerSec float64
	var recvPacketsPerSec float64

	if c.lastNet != nil && elapsed > 0 {
		sentPerSec = float64(current.BytesSent-c.lastNet.BytesSent) / elapsed
		recvPerSec = float64(current.BytesRecv-c.lastNet.BytesRecv) / elapsed
		sentPacketsPerSec = float64(current.PacketsSent-c.lastNet.PacketsSent) / elapsed
		recvPacketsPerSec = float64(current.PacketsRecv-c.lastNet.PacketsRecv) / elapsed
	}

	c.lastNet = &current
	c.lastTime = now

	diskUsagePercent := sampleMaxDiskUsagePercent()
	cpuTemp, diskTemp := sampleTemperatureTelemetry()

	return &MetricsSnapshot{
		CPUPercent:           cpuPercents[0],
		MemoryUsedPercent:    memStat.UsedPercent,
		MemoryUsedBytes:      memStat.Used,
		MemoryTotalBytes:     memStat.Total,
		NetBytesSentPerSec:   sentPerSec,
		NetBytesRecvPerSec:   recvPerSec,
		NetPacketsSentPerSec: sentPacketsPerSec,
		NetPacketsRecvPerSec: recvPacketsPerSec,
		CPUTemperatureC:      cpuTemp,
		DiskTemperatureC:     diskTemp,
		DiskUsagePercent:     diskUsagePercent,
		FanCPURPM:            nil,
		FanSystemRPM:         nil,
	}, nil
}

func sampleMaxDiskUsagePercent() *float64 {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return nil
	}

	maxUsage := -1.0
	for _, partition := range partitions {
		if strings.TrimSpace(partition.Mountpoint) == "" {
			continue
		}
		usage, usageErr := disk.Usage(partition.Mountpoint)
		if usageErr != nil {
			continue
		}
		if usage.UsedPercent > maxUsage {
			maxUsage = usage.UsedPercent
		}
	}

	if maxUsage < 0 {
		return nil
	}
	value := maxUsage
	return &value
}

func sampleTemperatureTelemetry() (*float64, *float64) {
	entries, err := host.SensorsTemperatures()
	if err != nil {
		return nil, nil
	}

	maxCPU := -1.0
	maxDisk := -1.0
	for _, entry := range entries {
		label := strings.ToLower(strings.TrimSpace(entry.SensorKey))
		if entry.Temperature <= 0 {
			continue
		}

		if strings.Contains(label, "cpu") || strings.Contains(label, "core") || strings.Contains(label, "package") {
			if entry.Temperature > maxCPU {
				maxCPU = entry.Temperature
			}
		}
		if strings.Contains(label, "disk") || strings.Contains(label, "hdd") || strings.Contains(label, "ssd") || strings.Contains(label, "nvme") || strings.Contains(label, "drive") {
			if entry.Temperature > maxDisk {
				maxDisk = entry.Temperature
			}
		}
	}

	var cpuTempPtr *float64
	var diskTempPtr *float64
	if maxCPU > 0 {
		value := maxCPU
		cpuTempPtr = &value
	}
	if maxDisk > 0 {
		value := maxDisk
		diskTempPtr = &value
	}

	return cpuTempPtr, diskTempPtr
}
