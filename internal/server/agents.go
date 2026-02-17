package server

import (
	"context"
	"fmt"
	"time"
)

// Agent represents a monitored agent device
type Agent struct {
	ID               int
	AgentID          string
	Hostname         string
	Domain           string
	PublicIP         string
	PrivateIP        string
	LastLogin        *time.Time
	LastSeen         time.Time
	LastReboot       *time.Time
	Timezone         string
	AgentVersion     string
	Status           string
	DateAdded        time.Time
	UpdatedAt        time.Time
	CreatedAt        time.Time
	// Hardware Information
	HardwareVendor       string
	HardwareModel        string
	HardwareSerialNumber string
	Motherboard          string
	BIOSManufacturer     string
	BIOSVersion          string
	BIOSVersionDate      string
	Processor            string
	Memory               string
	VideoCard            string
	Sound                string
	SystemDrive          string
	MACAddresses         string
	// Disk and drive JSON blobs
	Disks               string
	Drives              string
}

// GetAllAgents retrieves all agents from the database
func GetAllAgents(ctx context.Context) ([]Agent, error) {
	query := `
	SELECT 
		id, agent_id, hostname, domain, public_ip, private_ip,
		last_login, last_seen, last_reboot, timezone, agent_version,
		status, date_added, updated_at, created_at,
		COALESCE(hardware_vendor, ''), COALESCE(hardware_model, ''),
		COALESCE(hardware_serial_number, ''), COALESCE(motherboard, ''),
		COALESCE(bios_manufacturer, ''), COALESCE(bios_version, ''),
		COALESCE(bios_version_date, ''), COALESCE(processor, ''),
		COALESCE(memory, ''), COALESCE(video_card, ''),
		COALESCE(sound, ''), COALESCE(system_drive, ''),
		COALESCE(mac_addresses, '')
		, COALESCE(disks, ''), COALESCE(drives, '')
	FROM agents
	ORDER BY last_seen DESC
	`

	rows, err := DB.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query agents: %w", err)
	}
	defer rows.Close()

	var agents []Agent

	for rows.Next() {
		var agent Agent
		err := rows.Scan(
			&agent.ID,
			&agent.AgentID,
			&agent.Hostname,
			&agent.Domain,
			&agent.PublicIP,
			&agent.PrivateIP,
			&agent.LastLogin,
			&agent.LastSeen,
			&agent.LastReboot,
			&agent.Timezone,
			&agent.AgentVersion,
			&agent.Status,
			&agent.DateAdded,
			&agent.UpdatedAt,
			&agent.CreatedAt,
			&agent.HardwareVendor,
			&agent.HardwareModel,
			&agent.HardwareSerialNumber,
			&agent.Motherboard,
			&agent.BIOSManufacturer,
			&agent.BIOSVersion,
			&agent.BIOSVersionDate,
			&agent.Processor,
			&agent.Memory,
			&agent.VideoCard,
			&agent.Sound,
			&agent.SystemDrive,
			&agent.MACAddresses,
			&agent.Disks,
			&agent.Drives,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan agent: %w", err)
		}
		agents = append(agents, agent)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating agents: %w", err)
	}

	return agents, nil
}

// GetAgentByID retrieves a single agent by its agent_id
func GetAgentByID(ctx context.Context, agentID string) (*Agent, error) {
	query := `
	SELECT 
		id, agent_id, hostname, domain, public_ip, private_ip,
		last_login, last_seen, last_reboot, timezone, agent_version,
		status, date_added, updated_at, created_at,
		COALESCE(hardware_vendor, ''), COALESCE(hardware_model, ''),
		COALESCE(hardware_serial_number, ''), COALESCE(motherboard, ''),
		COALESCE(bios_manufacturer, ''), COALESCE(bios_version, ''),
		COALESCE(bios_version_date, ''), COALESCE(processor, ''),
		COALESCE(memory, ''), COALESCE(video_card, ''),
		COALESCE(sound, ''), COALESCE(system_drive, ''),
		COALESCE(mac_addresses, '')
		, COALESCE(disks, ''), COALESCE(drives, '')
	FROM agents
	WHERE agent_id = $1
	`

	var agent Agent

	err := DB.QueryRow(ctx, query, agentID).Scan(
		&agent.ID,
		&agent.AgentID,
		&agent.Hostname,
		&agent.Domain,
		&agent.PublicIP,
		&agent.PrivateIP,
		&agent.LastLogin,
		&agent.LastSeen,
		&agent.LastReboot,
		&agent.Timezone,
		&agent.AgentVersion,
		&agent.Status,
		&agent.DateAdded,
		&agent.UpdatedAt,
		&agent.CreatedAt,
		&agent.HardwareVendor,
		&agent.HardwareModel,
		&agent.HardwareSerialNumber,
		&agent.Motherboard,
		&agent.BIOSManufacturer,
		&agent.BIOSVersion,
		&agent.BIOSVersionDate,
		&agent.Processor,
		&agent.Memory,
		&agent.VideoCard,
		&agent.Sound,
		&agent.SystemDrive,
		&agent.MACAddresses,
		&agent.Disks,
		&agent.Drives,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to query agent: %w", err)
	}

	return &agent, nil
}
