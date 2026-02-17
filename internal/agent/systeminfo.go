package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const agentVersion = "1.0.0"

// SystemInfo contains system information collected from the agent
type SystemInfo struct {
	AgentID      string
	Hostname     string
	Domain       string
	PublicIP     string
	PrivateIP    string
	LastLogin    *time.Time
	LastReboot   *time.Time
	Timezone     string
	AgentVersion string
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
	// Physical Disks and Logical Drives JSON (stringified)
	// DisksJSON contains physical disk information (hardware devices)
	// DrivesJSON contains logical drives/volumes (mounted partitions like C:, D:, etc)
	DisksJSON  string
	DrivesJSON string
}

// GetSystemInfo collects system information from the agent
func GetSystemInfo() (*SystemInfo, error) {
	agentID, err := GetAgentID()
	if err != nil {
		return nil, fmt.Errorf("failed to get agent ID: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	domain := getDomain()
	publicIP := getPublicIP()
	privateIP := getPrivateIP()
	timezone := getTimezone()
	lastReboot := getLastReboot()

	// Collect hardware information
	hardwareVendor := getHardwareVendor()
	hardwareModel := getHardwareModel()
	hardwareSerialNumber := getHardwareSerialNumber()
	motherboard := getMotherboard()
	biosManufacturer := getBIOSManufacturer()
	biosVersion := getBIOSVersion()
	biosVersionDate := getBIOSVersionDate()
	processor := getProcessor()
	memory := getMemory()
	videoCard := getVideoCard()
	sound := getSound()
	systemDrive := getSystemDrive()
	macAddresses := getMACAddresses()

	// Disk/drive data: attempt platform-specific collection
	disksJSON := "[]"
	drivesJSON := "[]"
	if runtime.GOOS == "windows" {
		if d := getWindowsPhysicalDisksJSON(); d != "" {
			disksJSON = d
		}
		if dv := getWindowsLogicalDrivesJSON(); dv != "" {
			drivesJSON = dv
		}
	}

	return &SystemInfo{
		AgentID:              agentID,
		Hostname:             hostname,
		Domain:               domain,
		PublicIP:             publicIP,
		PrivateIP:            privateIP,
		LastReboot:           lastReboot,
		Timezone:             timezone,
		AgentVersion:         agentVersion,
		HardwareVendor:       hardwareVendor,
		HardwareModel:        hardwareModel,
		HardwareSerialNumber: hardwareSerialNumber,
		Motherboard:          motherboard,
		BIOSManufacturer:     biosManufacturer,
		BIOSVersion:          biosVersion,
		BIOSVersionDate:      biosVersionDate,
		Processor:            processor,
		Memory:               memory,
		VideoCard:            videoCard,
		Sound:                sound,
		SystemDrive:          systemDrive,
		MACAddresses:         macAddresses,
		DisksJSON:            disksJSON,
		DrivesJSON:           drivesJSON,
	}, nil
}

// getWindowsPhysicalDisksJSON queries physical disks and returns JSON array string.
// Physical disks represent actual hardware devices (disk drives) on the system.
func getWindowsPhysicalDisksJSON() string {
	// Use PowerShell to query physical disk information via WMI
	// Parse the output in Go and manually build JSON for reliability
	psScript := `
$ErrorActionPreference = 'SilentlyContinue'
try {
    $physicalDisks = @(Get-WmiObject Win32_DiskDrive -ErrorAction SilentlyContinue)
    foreach ($disk in $physicalDisks) {
        Write-Output "$($disk.Index)|$($disk.Model)|$($disk.Size)|$($disk.InterfaceType)|$($disk.Status)|$($disk.Partitions)"
    }
} catch {
}
`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NoLogo", "-NonInteractive", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		// Silently return empty array - drives will still work
		return "[]"
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var disks []map[string]interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) >= 6 {
			var idx, size, partitions int64
			fmt.Sscanf(parts[0], "%d", &idx)
			fmt.Sscanf(parts[2], "%d", &size)
			fmt.Sscanf(parts[5], "%d", &partitions)

			disk := map[string]interface{}{
				"Index":         idx,
				"Model":         parts[1],
				"Size":          size,
				"InterfaceType": parts[3],
				"Status":        parts[4],
				"Partitions":    partitions,
			}
			disks = append(disks, disk)
		}
	}

	b, _ := json.Marshal(disks)
	return string(b)
}

// getWindowsLogicalDrivesJSON queries logical drives (volumes) and returns JSON array with capacity info.
// Logical drives represent partitions/volumes mounted on the system (C:, D:, etc.)
func getWindowsLogicalDrivesJSON() string {
	// Use PowerShell to query logical disk information with timeout and error handling
	psScript := `
$ErrorActionPreference = 'SilentlyContinue'
$drives = @()
try {
    $logicalDisks = @(Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue)
    foreach ($disk in $logicalDisks) {
        $size = [long]$disk.Size
        $free = [long]$disk.FreeSpace
        $used = $size - $free
        $percent = 0
        if ($size -gt 0) {
            $percent = [int](($used * 100) / $size)
        }
        $driveObj = @{
            DeviceID = $disk.Name
            Size = $size
            Free = $free
            Used = $used
            PercentUsed = $percent
        }
        $drives += $driveObj
    }
    if ($drives.Count -eq 0) {
        @() | ConvertTo-Json
    } else {
        $drives | ConvertTo-Json
    }
} catch {
    @() | ConvertTo-Json
}
`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		// Silently return empty array
		return "[]"
	}

	jsonStr := strings.TrimSpace(string(output))
	if jsonStr == "" || jsonStr == "null" || jsonStr == "[]" {
		return "[]"
	}

	// Validate that output is valid JSON
	var result interface{}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return "[]"
	}

	return jsonStr
}

func getDomain() string {
	// Try to get domain from environment
	if domain := os.Getenv("USERDOMAIN"); domain != "" {
		return domain
	}

	// Try FQDN
	if fqdn, err := os.Hostname(); err == nil {
		if addrs, err := net.LookupHost(fqdn); err == nil && len(addrs) > 0 {
			return fqdn
		}
	}

	return "unknown"
}

func getPrivateIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Printf("Warning: Failed to determine private IP: %v", err)
		return "unknown"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func getPublicIP() string {
	// This is a placeholder - in production, you'd call an external service
	// For now, return "unknown" as it requires external API calls
	// You could use services like https://ipinfo.io or https://icanhazip.com
	return "unknown"
}

func getTimezone() string {
	name, _ := time.Now().Zone()
	return name
}

func getLastReboot() *time.Time {
	// Windows: Use `wmic os get lastbootuptime`
	// Linux: Use `/proc/uptime` or `systemctl show`
	// macOS: Use `sysctl kern.boottime`

	if runtime.GOOS == "windows" {
		return getLastRebootWindows()
	} else if runtime.GOOS == "linux" {
		return getLastRebootLinux()
	}

	return nil
}

func getLastRebootWindows() *time.Time {
	// Placeholder - in production, parse wmic output
	// cmd: wmic os get lastbootuptime /format:value
	return nil
}

func getLastRebootLinux() *time.Time {
	// Placeholder - in production, parse /proc/uptime
	return nil
}

// Hardware information collection functions
func getHardwareVendor() string {
	// Windows: Use WMI ComputerSystemProduct.Vendor
	// Linux: Read from /sys/devices/virtual/dmi/id/sys_vendor
	// macOS: Use system_profiler
	// Mobile: Placeholder
	if runtime.GOOS == "windows" {
		return getWindowsHardwareVendor()
	} else if runtime.GOOS == "linux" {
		return getLinuxHardwareVendor()
	} else if runtime.GOOS == "darwin" {
		return getMacHardwareVendor()
	}
	return "unknown"
}

func getHardwareModel() string {
	// Windows: Use WMI ComputerSystemProduct.Name
	// Linux: Read from /sys/devices/virtual/dmi/id/product_name
	// macOS: Use system_profiler
	// Mobile: Placeholder
	if runtime.GOOS == "windows" {
		return getWindowsHardwareModel()
	} else if runtime.GOOS == "linux" {
		return getLinuxHardwareModel()
	} else if runtime.GOOS == "darwin" {
		return getMacHardwareModel()
	}
	return "unknown"
}

func getHardwareSerialNumber() string {
	// Windows: Use WMI ComputerSystemProduct.IdentifyingNumber
	// Linux: Read from /sys/devices/virtual/dmi/id/product_serial
	// macOS: Use system_profiler
	// Mobile: Placeholder
	if runtime.GOOS == "windows" {
		return getWindowsSerialNumber()
	} else if runtime.GOOS == "linux" {
		return getLinuxSerialNumber()
	} else if runtime.GOOS == "darwin" {
		return getMacSerialNumber()
	}
	return "unknown"
}

func getMotherboard() string {
	// Windows: Use WMI BaseBoard.Product
	// Linux: Read from /sys/devices/virtual/dmi/id/board_name
	// macOS: Use system_profiler
	// Mobile: Placeholder
	if runtime.GOOS == "windows" {
		return getWindowsMotherboard()
	} else if runtime.GOOS == "linux" {
		return getLinuxMotherboard()
	} else if runtime.GOOS == "darwin" {
		return getMacMotherboard()
	}
	return "unknown"
}

func getBIOSManufacturer() string {
	// Windows: Use WMI BIOS.Manufacturer
	// Linux: Read from /sys/devices/virtual/dmi/id/bios_vendor
	// macOS: Use system_profiler
	// Mobile: Placeholder
	if runtime.GOOS == "windows" {
		return getWindowsBIOSManufacturer()
	} else if runtime.GOOS == "linux" {
		return getLinuxBIOSManufacturer()
	} else if runtime.GOOS == "darwin" {
		return getMacBIOSManufacturer()
	}
	return "unknown"
}

func getBIOSVersion() string {
	// Windows: Use WMI BIOS.SMBIOSBIOSVersion
	// Linux: Read from /sys/devices/virtual/dmi/id/bios_version
	// macOS: Use system_profiler
	// Mobile: Placeholder
	if runtime.GOOS == "windows" {
		return getWindowsBIOSVersion()
	} else if runtime.GOOS == "linux" {
		return getLinuxBIOSVersion()
	} else if runtime.GOOS == "darwin" {
		return getMacBIOSVersion()
	}
	return "unknown"
}

func getBIOSVersionDate() string {
	// Windows: Use WMI BIOS.ReleaseDate
	// Linux: Read from /sys/devices/virtual/dmi/id/bios_date
	// macOS: Use system_profiler
	// Mobile: Placeholder
	if runtime.GOOS == "windows" {
		return getWindowsBIOSDate()
	} else if runtime.GOOS == "linux" {
		return getLinuxBIOSDate()
	} else if runtime.GOOS == "darwin" {
		return getMacBIOSDate()
	}
	return "unknown"
}

func getMemory() string {
	// Windows: Use WMI ComputerSystem.TotalPhysicalMemory
	// Linux: Parse /proc/meminfo
	// macOS: Use sysctl
	// Mobile: Placeholder
	if runtime.GOOS == "windows" {
		return getWindowsMemory()
	} else if runtime.GOOS == "linux" {
		return getLinuxMemory()
	} else if runtime.GOOS == "darwin" {
		return getMacMemory()
	}
	return "unknown"
}

func getVideoCard() string {
	// Windows: Use WMI Win32_VideoController.Name
	// Linux: Use lspci to find video devices
	// macOS: Use system_profiler
	// Mobile: Placeholder
	if runtime.GOOS == "windows" {
		return getWindowsVideoCard()
	} else if runtime.GOOS == "linux" {
		return getLinuxVideoCard()
	} else if runtime.GOOS == "darwin" {
		return getMacVideoCard()
	}
	return "unknown"
}

func getSound() string {
	// Windows: Use WMI Win32_SoundDevice.Name
	// Linux: Use lspci to find audio devices
	// macOS: Use system_profiler
	// Mobile: Placeholder
	if runtime.GOOS == "windows" {
		return getWindowsSound()
	} else if runtime.GOOS == "linux" {
		return getLinuxSound()
	} else if runtime.GOOS == "darwin" {
		return getMacSound()
	}
	return "unknown"
}

// ============ WINDOWS IMPLEMENTATIONS ============

func getWindowsHardwareVendor() string {
	// Get ComputerSystemProduct.Vendor
	output := runWMIQuery("ComputerSystemProduct", "Vendor")
	return output
}

func getWindowsHardwareModel() string {
	// Get ComputerSystemProduct.Name
	output := runWMIQuery("ComputerSystemProduct", "Name")
	return output
}

func getWindowsSerialNumber() string {
	// Get ComputerSystemProduct.IdentifyingNumber
	output := runWMIQuery("ComputerSystemProduct", "IdentifyingNumber")
	return output
}

func getWindowsMotherboard() string {
	// Get BaseBoard.Product
	output := runWMIQuery("BaseBoard", "Product")
	return output
}

func getWindowsBIOSManufacturer() string {
	// Get BIOS.Manufacturer
	output := runWMIQuery("BIOS", "Manufacturer")
	return output
}

func getWindowsBIOSVersion() string {
	// Get BIOS.SMBIOSBIOSVersion
	output := runWMIQuery("BIOS", "SMBIOSBIOSVersion")
	return output
}

func getWindowsBIOSDate() string {
	// Get BIOS.ReleaseDate and format it
	output := runWMIQuery("BIOS", "ReleaseDate")
	rel := strings.TrimSpace(output)
	// ReleaseDate format from CIM: "MM/DD/YYYY HH:MM:SS"
	// Extract just the date part
	parts := strings.Fields(rel)
	if len(parts) > 0 {
		dateParts := strings.Split(parts[0], "/")
		if len(dateParts) == 3 {
			// Convert from MM/DD/YYYY to YYYY-MM-DD
			return fmt.Sprintf("%s-%s-%s", dateParts[2], dateParts[0], dateParts[1])
		}
	}
	return rel
}

func getWindowsMemory() string {
	// Get ComputerSystem.TotalPhysicalMemory and convert to GB
	output := runWMIQuery("ComputerSystem", "TotalPhysicalMemory")
	memBytes := strings.TrimSpace(output)

	// Parse bytes and convert to GB
	var bytes int64
	fmt.Sscanf(memBytes, "%d", &bytes)
	if bytes > 0 {
		gb := bytes / (1024 * 1024 * 1024)
		return fmt.Sprintf("%d GB", gb)
	}
	return "unknown"
}

func getWindowsVideoCard() string {
	// Get Win32_VideoController.Name (first one if multiple)
	output := runWMIQuery("Win32_VideoController", "Name")
	if output != "" {
		// If multiple cards, get the first one
		cards := strings.Split(output, "\n")
		for _, card := range cards {
			card := strings.TrimSpace(card)
			if card != "" {
				return card
			}
		}
	}
	return "unknown"
}

func getWindowsSound() string {
	// Get Win32_SoundDevice.Name (first one if multiple)
	output := runWMIQuery("Win32_SoundDevice", "Name")
	if output != "" {
		// If multiple devices, get the first one
		devices := strings.Split(output, "\n")
		for _, device := range devices {
			device := strings.TrimSpace(device)
			if device != "" {
				return device
			}
		}
	}
	return "unknown"
}

// Helper function to run WMI queries
func runWMIQuery(wmiClass, property string) string {
	// Use PowerShell CIM (newer WMI) for queries with proper error handling
	// CIM is more reliable than Get-WmiObject and works in virtualized environments
	// Map WMI class names to CIM equivalents (add Win32_ prefix if not present)
	cimClass := wmiClass
	if !strings.HasPrefix(cimClass, "Win32_") {
		cimClass = "Win32_" + cimClass
	}

	psScript := fmt.Sprintf(`
$ErrorActionPreference = 'SilentlyContinue'
try {
	$result = Get-CimInstance -ClassName %s -ErrorAction SilentlyContinue
	if ($result) {
		$value = $result.%s
		if ($value) {
			Write-Output $value
		}
	}
} catch {
	# Silently fail
}
`, cimClass, property)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		// Silently return empty string - WMI info not critical to operation
		return ""
	}

	result := strings.TrimSpace(string(output))
	return result
}

// ============ LINUX IMPLEMENTATIONS (PLACEHOLDER) ============

func getLinuxHardwareVendor() string {
	// TODO: Read from /sys/devices/virtual/dmi/id/sys_vendor
	return "unknown"
}

func getLinuxHardwareModel() string {
	// TODO: Read from /sys/devices/virtual/dmi/id/product_name
	return "unknown"
}

func getLinuxSerialNumber() string {
	// TODO: Read from /sys/devices/virtual/dmi/id/product_serial
	return "unknown"
}

func getLinuxMotherboard() string {
	// TODO: Read from /sys/devices/virtual/dmi/id/board_name
	return "unknown"
}

func getLinuxBIOSManufacturer() string {
	// TODO: Read from /sys/devices/virtual/dmi/id/bios_vendor
	return "unknown"
}

func getLinuxBIOSVersion() string {
	// TODO: Read from /sys/devices/virtual/dmi/id/bios_version
	return "unknown"
}

func getLinuxBIOSDate() string {
	// TODO: Read from /sys/devices/virtual/dmi/id/bios_date
	return "unknown"
}

func getLinuxMemory() string {
	// TODO: Parse /proc/meminfo for MemTotal
	return "unknown"
}

func getLinuxVideoCard() string {
	// TODO: Parse lspci for video devices
	return "unknown"
}

func getLinuxSound() string {
	// TODO: Parse lspci for audio devices
	return "unknown"
}

// ============ macOS IMPLEMENTATIONS (PLACEHOLDER) ============

func getMacHardwareVendor() string {
	// TODO: Use system_profiler SPHardwareDataType
	return "unknown"
}

func getMacHardwareModel() string {
	// TODO: Use system_profiler SPHardwareDataType
	return "unknown"
}

func getMacSerialNumber() string {
	// TODO: Use system_profiler SPHardwareDataType
	return "unknown"
}

func getMacMotherboard() string {
	// TODO: Use system_profiler SPHardwareDataType
	return "unknown"
}

func getMacBIOSManufacturer() string {
	// TODO: Use system_profiler SPHardwareDataType
	return "unknown"
}

func getMacBIOSVersion() string {
	// TODO: Use system_profiler SPHardwareDataType
	return "unknown"
}

func getMacBIOSDate() string {
	// TODO: Use system_profiler SPHardwareDataType
	return "unknown"
}

func getMacMemory() string {
	// TODO: Use sysctl hw.memsize
	return "unknown"
}

func getMacVideoCard() string {
	// TODO: Use system_profiler SPDisplaysDataType
	return "unknown"
}

func getMacSound() string {
	// TODO: Use system_profiler SPAudioDataType
	return "unknown"
}

func getProcessor() string {
	// Get processor info with core count
	if runtime.GOOS == "windows" {
		return getWindowsProcessor()
	} else if runtime.GOOS == "linux" {
		return getLinuxProcessor()
	} else if runtime.GOOS == "darwin" {
		return getMacProcessor()
	}
	// Fallback for other platforms
	numCPU := runtime.NumCPU()
	return fmt.Sprintf("%d cores", numCPU)
}

// ============ WINDOWS PROCESSOR IMPLEMENTATION ============

func getWindowsProcessor() string {
	// Get Win32_Processor.Name
	output := runWMIQuery("Win32_Processor", "Name")
	if output != "" {
		return output
	}
	// Fallback to core count
	numCPU := runtime.NumCPU()
	return fmt.Sprintf("%d cores", numCPU)
}

// ============ LINUX PROCESSOR IMPLEMENTATION (PLACEHOLDER) ============

func getLinuxProcessor() string {
	// TODO: Parse /proc/cpuinfo for processor name
	numCPU := runtime.NumCPU()
	return fmt.Sprintf("%d cores", numCPU)
}

// ============ macOS PROCESSOR IMPLEMENTATION (PLACEHOLDER) ============

func getMacProcessor() string {
	// TODO: Use sysctl machdep.cpu.brand_string or system_profiler
	numCPU := runtime.NumCPU()
	return fmt.Sprintf("%d cores", numCPU)
}

func getSystemDrive() string {
	// Windows: Usually C:\
	// Linux: Usually /
	if runtime.GOOS == "windows" {
		return "C:\\"
	}
	return "/"
}

func getMACAddresses() string {
	// Get all network interface MAC addresses
	var macs []string
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Warning: Failed to get network interfaces: %v", err)
		return "unknown"
	}

	for _, iface := range interfaces {
		if iface.HardwareAddr.String() != "" {
			macs = append(macs, fmt.Sprintf("%s (%s)", iface.HardwareAddr.String(), iface.Name))
		}
	}

	if len(macs) == 0 {
		return "unknown"
	}

	// Join all MAC addresses with semicolon
	macStr := ""
	for i, mac := range macs {
		if i > 0 {
			macStr += "; "
		}
		macStr += mac
	}
	return macStr
}
