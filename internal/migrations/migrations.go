package migrations

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Migration struct {
	Name string
	Up   func(context.Context, *pgxpool.Pool) error
}

var migrations = []Migration{
	{
		Name: "001_create_agents_table_v1_0_0",
		Up:   createAgentsTableV1,
	},
	{
		Name: "002_create_agent_commands_table_v1_1_0",
		Up:   createAgentCommandsTableV1,
	},
	{
		Name: "003_create_users_table_v1_2_0",
		Up:   createUsersTableV1,
	},
	{
		Name: "004_create_agent_metrics_table_v1_3_0",
		Up:   createAgentMetricsTableV1,
	},
	{
		Name: "005_add_os_and_security_columns_v1_4_0",
		Up:   addOSAndSecurityColumnsV1,
	},
}

func RunMigrations(ctx context.Context, db *pgxpool.Pool) error {
	// Create migrations tracking table
	err := createMigrationsTable(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Run pending migrations
	for _, migration := range migrations {
		applied, err := isMigrationApplied(ctx, db, migration.Name)
		if err != nil {
			return fmt.Errorf("failed to check migration status: %w", err)
		}

		if applied {
			log.Printf("✓ Migration %s already applied", migration.Name)
			continue
		}

		log.Printf("Running migration %s...", migration.Name)
		err = migration.Up(ctx, db)
		if err != nil {
			return fmt.Errorf("migration %s failed: %w", migration.Name, err)
		}

		// Record migration as applied
		err = recordMigration(ctx, db, migration.Name)
		if err != nil {
			return fmt.Errorf("failed to record migration: %w", err)
		}

		log.Printf("✓ Migration %s completed", migration.Name)
	}

	return nil
}

func createMigrationsTable(ctx context.Context, db *pgxpool.Pool) error {
	query := `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) UNIQUE NOT NULL,
		applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)
	`

	_, err := db.Exec(ctx, query)
	return err
}

func isMigrationApplied(ctx context.Context, db *pgxpool.Pool, name string) (bool, error) {
	var count int
	err := db.QueryRow(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE name = $1", name).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func recordMigration(ctx context.Context, db *pgxpool.Pool, name string) error {
	_, err := db.Exec(ctx, "INSERT INTO schema_migrations (name) VALUES ($1)", name)
	return err
}

func createAgentsTableV1(ctx context.Context, db *pgxpool.Pool) error {
	// v1.0.0 - Complete schema for agents table with all fields
	// This is the initial production schema including:
	// - Basic agent info (id, hostname, domain, IPs, timezone)
	// - Status tracking (last_seen, last_login, last_reboot, status)
	// - Hardware info (vendor, model, serial, motherboard, BIOS details, processor, memory, etc.)
	// - Storage info (disks, drives as JSON)
	// - Network info (MAC addresses)
	// - Versioning and timestamps
	query := `
	CREATE TABLE IF NOT EXISTS agents (
		id SERIAL PRIMARY KEY,
		agent_id VARCHAR(255) UNIQUE NOT NULL,
		hostname VARCHAR(255) NOT NULL,
		domain VARCHAR(255),
		public_ip VARCHAR(45),
		private_ip VARCHAR(45),
		last_login TIMESTAMP,
		last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_reboot TIMESTAMP,
		timezone VARCHAR(50),
		agent_version VARCHAR(50),
		status VARCHAR(50) DEFAULT 'offline',
		
		-- Hardware Information
		hardware_vendor VARCHAR(255),
		hardware_model VARCHAR(255),
		hardware_serial_number VARCHAR(255),
		motherboard VARCHAR(255),
		bios_manufacturer VARCHAR(255),
		bios_version VARCHAR(255),
		bios_version_date VARCHAR(255),
		processor VARCHAR(255),
		memory VARCHAR(255),
		video_card VARCHAR(255),
		sound VARCHAR(255),
		system_drive VARCHAR(255),
		
		-- Network Information
		mac_addresses TEXT,
		
		-- Storage Information (JSON formatted)
		disks TEXT,           -- JSON array of physical disks
		drives TEXT,          -- JSON array of logical drives/volumes
		
		-- Timestamps
		date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	-- Indexes for common queries
	CREATE INDEX IF NOT EXISTS idx_agents_agent_id ON agents(agent_id);
	CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);
	CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
	CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents(hostname);
	`

	_, err := db.Exec(ctx, query)
	return err
}

func createAgentCommandsTableV1(ctx context.Context, db *pgxpool.Pool) error {
	query := `
	CREATE TABLE IF NOT EXISTS agent_commands (
		id BIGSERIAL PRIMARY KEY,
		agent_id VARCHAR(255) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
		command_type VARCHAR(50) NOT NULL,
		payload TEXT,
		status VARCHAR(20) NOT NULL DEFAULT 'queued',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		dispatched_at TIMESTAMP,
		completed_at TIMESTAMP,
		output TEXT,
		error TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_agent_commands_agent_id ON agent_commands(agent_id);
	CREATE INDEX IF NOT EXISTS idx_agent_commands_status ON agent_commands(status);
	CREATE INDEX IF NOT EXISTS idx_agent_commands_created_at ON agent_commands(created_at);
	`

	_, err := db.Exec(ctx, query)
	return err
}

func createUsersTableV1(ctx context.Context, db *pgxpool.Pool) error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role VARCHAR(50) NOT NULL DEFAULT 'admin',
		must_change_password BOOLEAN NOT NULL DEFAULT true,
		last_login TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
	`

	_, err := db.Exec(ctx, query)
	return err
}

func createAgentMetricsTableV1(ctx context.Context, db *pgxpool.Pool) error {
	query := `
	CREATE TABLE IF NOT EXISTS agent_metrics (
		id BIGSERIAL PRIMARY KEY,
		agent_id VARCHAR(255) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
		timestamp TIMESTAMP NOT NULL,
		cpu_percent DOUBLE PRECISION NOT NULL,
		memory_used_percent DOUBLE PRECISION NOT NULL,
		memory_used_bytes BIGINT NOT NULL,
		memory_total_bytes BIGINT NOT NULL,
		net_bytes_sent_per_sec DOUBLE PRECISION NOT NULL,
		net_bytes_recv_per_sec DOUBLE PRECISION NOT NULL,
		net_packets_sent_per_sec DOUBLE PRECISION NOT NULL,
		net_packets_recv_per_sec DOUBLE PRECISION NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent_id ON agent_metrics(agent_id);
	CREATE INDEX IF NOT EXISTS idx_agent_metrics_timestamp ON agent_metrics(timestamp);
	CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent_time ON agent_metrics(agent_id, timestamp);
	`

	_, err := db.Exec(ctx, query)
	return err
}

func addOSAndSecurityColumnsV1(ctx context.Context, db *pgxpool.Pool) error {
	query := `
	ALTER TABLE agents ADD COLUMN IF NOT EXISTS os_edition VARCHAR(255);
	ALTER TABLE agents ADD COLUMN IF NOT EXISTS os_version VARCHAR(50);
	ALTER TABLE agents ADD COLUMN IF NOT EXISTS os_build VARCHAR(50);
	ALTER TABLE agents ADD COLUMN IF NOT EXISTS windows_11_eligible VARCHAR(255);
	ALTER TABLE agents ADD COLUMN IF NOT EXISTS tls_12_compatible BOOLEAN DEFAULT FALSE;
	ALTER TABLE agents ADD COLUMN IF NOT EXISTS dotnet_version VARCHAR(255);
	ALTER TABLE agents ADD COLUMN IF NOT EXISTS office_version VARCHAR(255);
	ALTER TABLE agents ADD COLUMN IF NOT EXISTS antivirus_name VARCHAR(255);
	ALTER TABLE agents ADD COLUMN IF NOT EXISTS antispyware_name VARCHAR(255);
	ALTER TABLE agents ADD COLUMN IF NOT EXISTS firewall_name VARCHAR(255);
	`

	_, err := db.Exec(ctx, query)
	return err
}

// RecreateAndRunMigrations drops existing migration state and tables then
// re-applies all migrations from scratch. Use with caution on production.
func RecreateAndRunMigrations(ctx context.Context, db *pgxpool.Pool) error {
	// Drop tables that may have been created by previous runs
	dropQuery := `
	DROP TABLE IF EXISTS agent_commands CASCADE;
	DROP TABLE IF EXISTS agents CASCADE;
	DROP TABLE IF EXISTS schema_migrations CASCADE;
	`

	if _, err := db.Exec(ctx, dropQuery); err != nil {
		return fmt.Errorf("failed to drop existing tables: %w", err)
	}

	log.Println("Dropped existing migration tables, running migrations from scratch")
	return RunMigrations(ctx, db)
}
