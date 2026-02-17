package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/agent"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

func main() {
	cfg := config.LoadAgentConfig()

	// Get system information
	sysInfo, err := agent.GetSystemInfo()
	if err != nil {
		log.Fatalf("Failed to get system info: %v", err)
	}

	log.Printf("Agent started - ID: %s, Hostname: %s, Version: %s", sysInfo.AgentID, sysInfo.Hostname, sysInfo.AgentVersion)
	log.Printf("Server URL: %s, Heartbeat interval: %v", cfg.ServerURL, cfg.HeartbeatInterval)

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: cfg.RequestTimeout,
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()

	go func() {
		<-sigChan
		log.Println("Shutdown signal received")
		cancel()
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("Agent stopped")
			return
		case <-ticker.C:
			hb := transport.HeartbeatRequest{
				AgentID:              sysInfo.AgentID,
				Hostname:             sysInfo.Hostname,
				Domain:               sysInfo.Domain,
				PublicIP:             sysInfo.PublicIP,
				PrivateIP:            sysInfo.PrivateIP,
				LastLogin:            sysInfo.LastLogin,
				LastReboot:           sysInfo.LastReboot,
				Timezone:             sysInfo.Timezone,
				AgentVersion:         sysInfo.AgentVersion,
				LastSeen:             time.Now(),
				Timestamp:            time.Now(),
				Status:               "online",
				HardwareVendor:       sysInfo.HardwareVendor,
				HardwareModel:        sysInfo.HardwareModel,
				HardwareSerialNumber: sysInfo.HardwareSerialNumber,
				Motherboard:          sysInfo.Motherboard,
				BIOSManufacturer:     sysInfo.BIOSManufacturer,
				BIOSVersion:          sysInfo.BIOSVersion,
				BIOSVersionDate:      sysInfo.BIOSVersionDate,
				Processor:            sysInfo.Processor,
				Memory:               sysInfo.Memory,
				VideoCard:            sysInfo.VideoCard,
				Sound:                sysInfo.Sound,
				SystemDrive:          sysInfo.SystemDrive,
				MACAddresses:         sysInfo.MACAddresses,
				Disks:                sysInfo.DisksJSON,
				Drives:               sysInfo.DrivesJSON,
			}
			sendHeartbeatWithRetry(httpClient, cfg, hb)
		}
	}
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Warning: Failed to get hostname: %v", err)
		return "unknown"
	}
	return hostname
}

func sendHeartbeatWithRetry(httpClient *http.Client, cfg config.AgentConfig, hb transport.HeartbeatRequest) {
	var lastErr error

	for attempt := 1; attempt <= cfg.MaxRetries; attempt++ {
		if err := sendHeartbeat(httpClient, cfg.ServerURL, hb); err == nil {
			return // Success
		} else {
			lastErr = err
			if attempt < cfg.MaxRetries {
				backoff := time.Duration(attempt) * cfg.RetryBackoffSeconds
				log.Printf("Heartbeat attempt %d failed: %v, retrying in %v", attempt, err, backoff)
				time.Sleep(backoff)
			}
		}
	}

	log.Printf("Failed to send heartbeat after %d attempts: %v", cfg.MaxRetries, lastErr)
}

func sendHeartbeat(httpClient *http.Client, serverURL string, hb transport.HeartbeatRequest) error {
	jsonData, err := json.Marshal(hb)
	if err != nil {
		return err
	}

	url := serverURL + "/api/heartbeat"

	resp, err := httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}

	log.Printf("Heartbeat sent successfully")
	return nil
}
