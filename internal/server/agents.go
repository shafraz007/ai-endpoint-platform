package server

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Agent represents a monitored agent device
type Agent struct {
	ID             int
	AgentID        string
	Hostname       string
	Domain         string
	PublicIP       string
	PrivateIP      string
	LastLogin      *time.Time
	LastSeen       time.Time
	LastReboot     *time.Time
	RebootRequired bool
	PatchScanAt    *time.Time
	Timezone       string
	AgentVersion   string
	Status         string
	DateAdded      time.Time
	UpdatedAt      time.Time
	CreatedAt      time.Time
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
	// OS Information
	OSEdition         string
	OSVersion         string
	OSBuild           string
	Windows11Eligible string
	TLS12Compatible   bool
	DotNetVersion     string
	OfficeVersion     string
	// Security Information
	AntivirusName   string
	AntiSpywareName string
	FirewallName    string
	// Disk and drive JSON blobs
	Disks              string
	Drives             string
	RuntimeType        string
	ToolsJSON          string
	CapabilitiesJSON   string
	ToolConfidenceJSON string
	LearnedScoresJSON  string
}

// GetAllAgents retrieves all agents from the database
func GetAllAgents(ctx context.Context) ([]Agent, error) {
	query := `
	SELECT 
		id, agent_id, hostname,
		COALESCE(domain, ''), COALESCE(public_ip, ''), COALESCE(private_ip, ''),
		last_login, last_seen, last_reboot,
		COALESCE(reboot_required, FALSE), patch_scan_at,
		COALESCE(timezone, ''), COALESCE(agent_version, ''), COALESCE(status, ''),
		date_added, updated_at, created_at,
		COALESCE(hardware_vendor, ''), COALESCE(hardware_model, ''),
		COALESCE(hardware_serial_number, ''), COALESCE(motherboard, ''),
		COALESCE(bios_manufacturer, ''), COALESCE(bios_version, ''),
		COALESCE(bios_version_date, ''), COALESCE(processor, ''),
		COALESCE(memory, ''), COALESCE(video_card, ''),
		COALESCE(sound, ''), COALESCE(system_drive, ''),
		COALESCE(mac_addresses, ''),
		COALESCE(os_edition, ''), COALESCE(os_version, ''),
		COALESCE(os_build, ''), COALESCE(windows_11_eligible, ''),
		COALESCE(tls_12_compatible, FALSE), COALESCE(dotnet_version, ''),
		COALESCE(office_version, ''), COALESCE(antivirus_name, ''),
		COALESCE(antispyware_name, ''), COALESCE(firewall_name, '')
		, COALESCE(disks, ''), COALESCE(drives, '')
		, COALESCE(runtime_type, ''), COALESCE(tools_json::text, '[]'), COALESCE(capabilities_json::text, '[]'), COALESCE(tool_confidence_json::text, '{}')
		, COALESCE((SELECT jsonb_object_agg(ts.tool_key, ts.score) FROM agent_tool_scores ts WHERE ts.agent_id = agents.agent_id)::text, '{}')
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
			&agent.RebootRequired,
			&agent.PatchScanAt,
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
			&agent.OSEdition,
			&agent.OSVersion,
			&agent.OSBuild,
			&agent.Windows11Eligible,
			&agent.TLS12Compatible,
			&agent.DotNetVersion,
			&agent.OfficeVersion,
			&agent.AntivirusName,
			&agent.AntiSpywareName,
			&agent.FirewallName,
			&agent.Disks,
			&agent.Drives,
			&agent.RuntimeType,
			&agent.ToolsJSON,
			&agent.CapabilitiesJSON,
			&agent.ToolConfidenceJSON,
			&agent.LearnedScoresJSON,
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
		id, agent_id, hostname,
		COALESCE(domain, ''), COALESCE(public_ip, ''), COALESCE(private_ip, ''),
		last_login, last_seen, last_reboot,
		COALESCE(reboot_required, FALSE), patch_scan_at,
		COALESCE(timezone, ''), COALESCE(agent_version, ''), COALESCE(status, ''),
		date_added, updated_at, created_at,
		COALESCE(hardware_vendor, ''), COALESCE(hardware_model, ''),
		COALESCE(hardware_serial_number, ''), COALESCE(motherboard, ''),
		COALESCE(bios_manufacturer, ''), COALESCE(bios_version, ''),
		COALESCE(bios_version_date, ''), COALESCE(processor, ''),
		COALESCE(memory, ''), COALESCE(video_card, ''),
		COALESCE(sound, ''), COALESCE(system_drive, ''),
		COALESCE(mac_addresses, ''),
		COALESCE(os_edition, ''), COALESCE(os_version, ''),
		COALESCE(os_build, ''), COALESCE(windows_11_eligible, ''),
		COALESCE(tls_12_compatible, FALSE), COALESCE(dotnet_version, ''),
		COALESCE(office_version, ''), COALESCE(antivirus_name, ''),
		COALESCE(antispyware_name, ''), COALESCE(firewall_name, '')
		, COALESCE(disks, ''), COALESCE(drives, '')
		, COALESCE(runtime_type, ''), COALESCE(tools_json::text, '[]'), COALESCE(capabilities_json::text, '[]'), COALESCE(tool_confidence_json::text, '{}')
		, COALESCE((SELECT jsonb_object_agg(ts.tool_key, ts.score) FROM agent_tool_scores ts WHERE ts.agent_id = agents.agent_id)::text, '{}')
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
		&agent.RebootRequired,
		&agent.PatchScanAt,
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
		&agent.OSEdition,
		&agent.OSVersion,
		&agent.OSBuild,
		&agent.Windows11Eligible,
		&agent.TLS12Compatible,
		&agent.DotNetVersion,
		&agent.OfficeVersion,
		&agent.AntivirusName,
		&agent.AntiSpywareName,
		&agent.FirewallName,
		&agent.Disks,
		&agent.Drives,
		&agent.RuntimeType,
		&agent.ToolsJSON,
		&agent.CapabilitiesJSON,
		&agent.ToolConfidenceJSON,
		&agent.LearnedScoresJSON,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to query agent: %w", err)
	}

	return &agent, nil
}

func DeleteAgent(ctx context.Context, agentID string) (bool, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return false, fmt.Errorf("agentID is required")
	}

	result, err := DB.Exec(ctx, `DELETE FROM agents WHERE agent_id = $1`, agentID)
	if err != nil {
		return false, fmt.Errorf("failed to delete agent: %w", err)
	}

	return result.RowsAffected() > 0, nil
}
