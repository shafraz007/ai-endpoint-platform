package server

import (
	"context"
	"fmt"
	"log"
	"time"
)

// UpsertAgent inserts or updates an agent in the database
func UpsertAgent(agentID, hostname, domain, publicIP, privateIP, status, agentVersion string, lastLogin, lastReboot *time.Time, timezone string, hardwareVendor, hardwareModel, hardwareSerialNumber, motherboard, biosManufacturer, biosVersion, biosVersionDate, processor, memory, videoCard, sound, systemDrive, macAddresses, disks, drives, osEdition, osVersion, osBuild, windows11Eligible, dotnetVersion, officeVersion, antivirusName, antispywareName, firewallName string, tls12Compatible bool) error {
	if agentID == "" {
		return fmt.Errorf("agentID cannot be empty")
	}
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}

	query := `
	INSERT INTO agents (
		agent_id, hostname, domain, public_ip, private_ip, 
		last_login, last_seen, last_reboot, timezone, 
		agent_version, status, date_added,
		hardware_vendor, hardware_model, hardware_serial_number, motherboard,
		bios_manufacturer, bios_version, bios_version_date, processor,
		memory, video_card, sound, system_drive, mac_addresses,
		disks, drives,
		os_edition, os_version, os_build, windows_11_eligible, tls_12_compatible,
		dotnet_version, office_version, antivirus_name, antispyware_name, firewall_name
	)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)
	ON CONFLICT (agent_id)
	DO UPDATE SET
		hostname = EXCLUDED.hostname,
		domain = EXCLUDED.domain,
		public_ip = EXCLUDED.public_ip,
		private_ip = EXCLUDED.private_ip,
		last_login = EXCLUDED.last_login,
		last_seen = EXCLUDED.last_seen,
		last_reboot = EXCLUDED.last_reboot,
		timezone = EXCLUDED.timezone,
		agent_version = EXCLUDED.agent_version,
		status = EXCLUDED.status,
		hardware_vendor = EXCLUDED.hardware_vendor,
		hardware_model = EXCLUDED.hardware_model,
		hardware_serial_number = EXCLUDED.hardware_serial_number,
		motherboard = EXCLUDED.motherboard,
		bios_manufacturer = EXCLUDED.bios_manufacturer,
		bios_version = EXCLUDED.bios_version,
		bios_version_date = EXCLUDED.bios_version_date,
		processor = EXCLUDED.processor,
		memory = EXCLUDED.memory,
		video_card = EXCLUDED.video_card,
		sound = EXCLUDED.sound,
		system_drive = EXCLUDED.system_drive,
		mac_addresses = EXCLUDED.mac_addresses,
		disks = EXCLUDED.disks,
		drives = EXCLUDED.drives,
		os_edition = EXCLUDED.os_edition,
		os_version = EXCLUDED.os_version,
		os_build = EXCLUDED.os_build,
		windows_11_eligible = EXCLUDED.windows_11_eligible,
		tls_12_compatible = EXCLUDED.tls_12_compatible,
		dotnet_version = EXCLUDED.dotnet_version,
		office_version = EXCLUDED.office_version,
		antivirus_name = EXCLUDED.antivirus_name,
		antispyware_name = EXCLUDED.antispyware_name,
		firewall_name = EXCLUDED.firewall_name,
		updated_at = CURRENT_TIMESTAMP
	`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := DB.Exec(ctx, query,
		agentID,
		hostname,
		domain,
		publicIP,
		privateIP,
		lastLogin,
		time.Now(),
		lastReboot,
		timezone,
		agentVersion,
		status,
		time.Now(),
		hardwareVendor,
		hardwareModel,
		hardwareSerialNumber,
		motherboard,
		biosManufacturer,
		biosVersion,
		biosVersionDate,
		processor,
		memory,
		videoCard,
		sound,
		systemDrive,
		macAddresses,
		disks,
		drives,
		osEdition,
		osVersion,
		osBuild,
		windows11Eligible,
		tls12Compatible,
		dotnetVersion,
		officeVersion,
		antivirusName,
		antispywareName,
		firewallName,
	)

	if err != nil {
		log.Printf("Error upserting agent %s: %v", agentID, err)
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// MarkAgentsOffline sets agents whose last_seen is before the cutoff to 'offline'.
// Returns the number of agents updated.
func MarkAgentsOffline(ctx context.Context, cutoff time.Time) (int64, error) {
	query := `
		UPDATE agents
		SET status = 'offline', updated_at = CURRENT_TIMESTAMP
		WHERE last_seen < $1
			AND status <> 'offline'
		`

	cmdTag, err := DB.Exec(ctx, query, cutoff)
	if err != nil {
		log.Printf("Error marking agents offline: %v", err)
		return 0, fmt.Errorf("database error: %w", err)
	}

	return cmdTag.RowsAffected(), nil
}
