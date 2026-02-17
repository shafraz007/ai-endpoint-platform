package agent

import (
	"errors"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
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

	return &MetricsSnapshot{
		CPUPercent:           cpuPercents[0],
		MemoryUsedPercent:    memStat.UsedPercent,
		MemoryUsedBytes:      memStat.Used,
		MemoryTotalBytes:     memStat.Total,
		NetBytesSentPerSec:   sentPerSec,
		NetBytesRecvPerSec:   recvPerSec,
		NetPacketsSentPerSec: sentPacketsPerSec,
		NetPacketsRecvPerSec: recvPacketsPerSec,
	}, nil
}
