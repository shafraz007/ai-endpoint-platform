package transport

import "time"

// HeartbeatRequest is the full heartbeat payload from agents
type HeartbeatRequest struct {
	AgentID              string    `json:"agent_id"`
	Hostname             string    `json:"hostname"`
	Domain               string    `json:"domain"`
	PublicIP             string    `json:"public_ip"`
	PrivateIP            string    `json:"private_ip"`
	LastLogin            *time.Time `json:"last_login,omitempty"`
	LastSeen             time.Time `json:"last_seen"`
	LastReboot           *time.Time `json:"last_reboot,omitempty"`
	Timezone             string    `json:"timezone"`
	AgentVersion         string    `json:"agent_version"`
	Status               string    `json:"status"`
	Timestamp            time.Time `json:"timestamp"`
	// Hardware Information
	HardwareVendor       string    `json:"hardware_vendor,omitempty"`
	HardwareModel        string    `json:"hardware_model,omitempty"`
	HardwareSerialNumber string    `json:"hardware_serial_number,omitempty"`
	Motherboard          string    `json:"motherboard,omitempty"`
	BIOSManufacturer     string    `json:"bios_manufacturer,omitempty"`
	BIOSVersion          string    `json:"bios_version,omitempty"`
	BIOSVersionDate      string    `json:"bios_version_date,omitempty"`
	Processor            string    `json:"processor,omitempty"`
	Memory               string    `json:"memory,omitempty"`
	VideoCard            string    `json:"video_card,omitempty"`
	Sound                string    `json:"sound,omitempty"`
	SystemDrive          string    `json:"system_drive,omitempty"`
	MACAddresses         string    `json:"mac_addresses,omitempty"`
	// Disk and drive information serialized as JSON
	Disks                string    `json:"disks,omitempty"`
	Drives               string    `json:"drives,omitempty"`
}
