package transport

import "time"

// HeartbeatRequest is the full heartbeat payload from agents
type HeartbeatRequest struct {
	AgentID      string     `json:"agent_id"`
	Hostname     string     `json:"hostname"`
	Domain       string     `json:"domain"`
	PublicIP     string     `json:"public_ip"`
	PrivateIP    string     `json:"private_ip"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
	LastSeen     time.Time  `json:"last_seen"`
	LastReboot   *time.Time `json:"last_reboot,omitempty"`
	Timezone     string     `json:"timezone"`
	AgentVersion string     `json:"agent_version"`
	Status       string     `json:"status"`
	Timestamp    time.Time  `json:"timestamp"`
	// Hardware Information
	HardwareVendor       string `json:"hardware_vendor,omitempty"`
	HardwareModel        string `json:"hardware_model,omitempty"`
	HardwareSerialNumber string `json:"hardware_serial_number,omitempty"`
	Motherboard          string `json:"motherboard,omitempty"`
	BIOSManufacturer     string `json:"bios_manufacturer,omitempty"`
	BIOSVersion          string `json:"bios_version,omitempty"`
	BIOSVersionDate      string `json:"bios_version_date,omitempty"`
	Processor            string `json:"processor,omitempty"`
	Memory               string `json:"memory,omitempty"`
	VideoCard            string `json:"video_card,omitempty"`
	Sound                string `json:"sound,omitempty"`
	SystemDrive          string `json:"system_drive,omitempty"`
	MACAddresses         string `json:"mac_addresses,omitempty"`
	// Disk and drive information serialized as JSON
	Disks  string `json:"disks,omitempty"`
	Drives string `json:"drives,omitempty"`
}

// Command represents a pending command for an agent.
type Command struct {
	ID           int64      `json:"id"`
	AgentID      string     `json:"agent_id"`
	CommandType  string     `json:"command_type"`
	Payload      string     `json:"payload"`
	Status       string     `json:"status,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	DispatchedAt *time.Time `json:"dispatched_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	Output       string     `json:"output,omitempty"`
	Error        string     `json:"error,omitempty"`
}

// CommandCreateRequest creates a new command for an agent.
type CommandCreateRequest struct {
	AgentID     string `json:"agent_id"`
	CommandType string `json:"command_type"`
	Payload     string `json:"payload"`
}

// CommandAckRequest acknowledges command execution results from an agent.
type CommandAckRequest struct {
	CommandID int64  `json:"command_id"`
	Status    string `json:"status"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
}

// MetricsSample represents a single time-series sample for an agent.
type MetricsSample struct {
	AgentID              string    `json:"agent_id"`
	Timestamp            time.Time `json:"timestamp"`
	CPUPercent           float64   `json:"cpu_percent"`
	MemoryUsedPercent    float64   `json:"memory_used_percent"`
	MemoryUsedBytes      uint64    `json:"memory_used_bytes"`
	MemoryTotalBytes     uint64    `json:"memory_total_bytes"`
	NetBytesSentPerSec   float64   `json:"net_bytes_sent_per_sec"`
	NetBytesRecvPerSec   float64   `json:"net_bytes_recv_per_sec"`
	NetPacketsSentPerSec float64   `json:"net_packets_sent_per_sec"`
	NetPacketsRecvPerSec float64   `json:"net_packets_recv_per_sec"`
}
