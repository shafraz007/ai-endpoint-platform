package transport

import "time"

type PendingUpdate struct {
	UpdateID       string   `json:"update_id"`
	KBID           string   `json:"kb_id,omitempty"`
	Title          string   `json:"title"`
	Description    string   `json:"description,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	Categories     []string `json:"categories,omitempty"`
	IsDriver       bool     `json:"is_driver"`
	IsSecurity     bool     `json:"is_security"`
	IsCritical     bool     `json:"is_critical"`
	IsOS           bool     `json:"is_os"`
	IsSoftware     bool     `json:"is_software"`
	RebootRequired bool     `json:"reboot_required"`
}

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
	// OS Information
	OSEdition         string          `json:"os_edition,omitempty"`
	OSVersion         string          `json:"os_version,omitempty"`
	OSBuild           string          `json:"os_build,omitempty"`
	Windows11Eligible string          `json:"windows_11_eligible,omitempty"`
	TLS12Compatible   bool            `json:"tls_12_compatible,omitempty"`
	DotNetVersion     string          `json:"dotnet_version,omitempty"`
	OfficeVersion     string          `json:"office_version,omitempty"`
	AntivirusName     string          `json:"antivirus_name,omitempty"`
	AntiSpywareName   string          `json:"antispyware_name,omitempty"`
	FirewallName      string          `json:"firewall_name,omitempty"`
	PatchScanAt       *time.Time      `json:"patch_scan_at,omitempty"`
	RebootRequired    bool            `json:"reboot_required"`
	PendingUpdates    []PendingUpdate `json:"pending_updates,omitempty"`
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
	CPUTemperatureC      *float64  `json:"cpu_temperature_c,omitempty"`
	DiskTemperatureC     *float64  `json:"disk_temperature_c,omitempty"`
	DiskUsagePercent     *float64  `json:"disk_usage_percent,omitempty"`
	FanCPURPM            *float64  `json:"fan_cpu_rpm,omitempty"`
	FanSystemRPM         *float64  `json:"fan_system_rpm,omitempty"`
}

type ChatMessage struct {
	ID        int64     `json:"id"`
	Scope     string    `json:"scope"`
	AgentID   string    `json:"agent_id,omitempty"`
	SessionID int64     `json:"session_id,omitempty"`
	Sender    string    `json:"sender"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

type ChatMessageCreateRequest struct {
	Scope     string `json:"scope"`
	AgentID   string `json:"agent_id,omitempty"`
	SessionID int64  `json:"session_id,omitempty"`
	Message   string `json:"message"`
}

type GlobalChatSession struct {
	ID            int64      `json:"id"`
	Title         string     `json:"title"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastMessageAt *time.Time `json:"last_message_at,omitempty"`
	MessageCount  int64      `json:"message_count"`
}

type GlobalChatSessionCreateRequest struct {
	Title string `json:"title"`
}

type Schedule struct {
	ID                    int64      `json:"id"`
	Name                  string     `json:"name"`
	Kind                  string     `json:"kind"`
	TargetScope           string     `json:"target_scope"`
	TargetAgentID         string     `json:"target_agent_id,omitempty"`
	TargetGroupID         *int       `json:"target_group_id,omitempty"`
	CommandType           string     `json:"command_type,omitempty"`
	Payload               string     `json:"payload"`
	RunAt                 time.Time  `json:"run_at"`
	RepeatIntervalSeconds int        `json:"repeat_interval_seconds"`
	RecurrenceRule        string     `json:"recurrence_rule,omitempty"`
	Enabled               bool       `json:"enabled"`
	LastRunAt             *time.Time `json:"last_run_at,omitempty"`
	NextRunAt             time.Time  `json:"next_run_at"`
	CreatedBy             string     `json:"created_by,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

type ScheduleCreateRequest struct {
	Name                  string    `json:"name"`
	Kind                  string    `json:"kind"`
	TargetScope           string    `json:"target_scope"`
	TargetAgentID         string    `json:"target_agent_id,omitempty"`
	TargetGroupID         *int      `json:"target_group_id,omitempty"`
	CommandType           string    `json:"command_type,omitempty"`
	Payload               string    `json:"payload"`
	RunAt                 time.Time `json:"run_at"`
	RepeatIntervalSeconds int       `json:"repeat_interval_seconds"`
	RecurrenceRule        string    `json:"recurrence_rule,omitempty"`
	Enabled               bool      `json:"enabled"`
	NextRunAt             time.Time `json:"next_run_at"`
}

type ScheduleUpdateRequest struct {
	Name                  string    `json:"name"`
	Kind                  string    `json:"kind"`
	TargetScope           string    `json:"target_scope"`
	TargetAgentID         string    `json:"target_agent_id,omitempty"`
	TargetGroupID         *int      `json:"target_group_id,omitempty"`
	CommandType           string    `json:"command_type,omitempty"`
	Payload               string    `json:"payload"`
	RunAt                 time.Time `json:"run_at"`
	RepeatIntervalSeconds int       `json:"repeat_interval_seconds"`
	RecurrenceRule        string    `json:"recurrence_rule,omitempty"`
	Enabled               bool      `json:"enabled"`
	NextRunAt             time.Time `json:"next_run_at"`
}

type IssueRecommendedAction struct {
	ID               string `json:"id"`
	Label            string `json:"label"`
	Description      string `json:"description"`
	Kind             string `json:"kind"`
	CommandType      string `json:"command_type,omitempty"`
	Payload          string `json:"payload,omitempty"`
	SupportsSchedule bool   `json:"supports_schedule"`
}

type AgentIssue struct {
	ID                 int64                    `json:"id"`
	AgentID            string                   `json:"agent_id"`
	IssueKey           string                   `json:"issue_key"`
	Category           string                   `json:"category"`
	Severity           string                   `json:"severity"`
	Status             string                   `json:"status"`
	Suppressed         bool                     `json:"suppressed"`
	SnoozedUntil       *time.Time               `json:"snoozed_until,omitempty"`
	Title              string                   `json:"title"`
	Description        string                   `json:"description"`
	Source             string                   `json:"source"`
	Evidence           string                   `json:"evidence"`
	Suggestions        []string                 `json:"suggestions"`
	ActionPlan         []string                 `json:"action_plan"`
	RecommendedActions []IssueRecommendedAction `json:"recommended_actions"`
	FirstSeenAt        time.Time                `json:"first_seen_at"`
	LastSeenAt         time.Time                `json:"last_seen_at"`
	ResolvedAt         *time.Time               `json:"resolved_at,omitempty"`
	CreatedAt          time.Time                `json:"created_at"`
	UpdatedAt          time.Time                `json:"updated_at"`
}

type IssueActionRequest struct {
	ActionID              string     `json:"action_id,omitempty"`
	Mode                  string     `json:"mode"`
	Kind                  string     `json:"kind,omitempty"`
	CommandType           string     `json:"command_type,omitempty"`
	Payload               string     `json:"payload,omitempty"`
	Name                  string     `json:"name,omitempty"`
	RunAt                 *time.Time `json:"run_at,omitempty"`
	RepeatIntervalSeconds int        `json:"repeat_interval_seconds,omitempty"`
	RecurrenceRule        string     `json:"recurrence_rule,omitempty"`
	Enabled               *bool      `json:"enabled,omitempty"`
}

type IssueActionResult struct {
	IssueID           int64  `json:"issue_id"`
	Mode              string `json:"mode"`
	Kind              string `json:"kind"`
	CommandType       string `json:"command_type,omitempty"`
	CreatedCommandID  int64  `json:"created_command_id,omitempty"`
	CreatedScheduleID int64  `json:"created_schedule_id,omitempty"`
	Message           string `json:"message"`
}
