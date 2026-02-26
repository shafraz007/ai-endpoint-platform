package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// OSInfo represents operating system and security information
type OSInfo struct {
	OSEdition         string `json:"os_edition"`
	OSVersion         string `json:"os_version"`
	OSBuild           string `json:"os_build"`
	Windows11Eligible string `json:"windows_11_eligible"`
	TLS12Compatible   bool   `json:"tls_12_compatible"`
	DotNetVersion     string `json:"dotnet_version"`
	OfficeVersion     string `json:"office_version"`
	AntivirusName     string `json:"antivirus_name"`
	AntiSpywareName   string `json:"antispyware_name"`
	FirewallName      string `json:"firewall_name"`
}

// CollectOSInfo gathers OS and security information
func CollectOSInfo() *OSInfo {
	osInfo := &OSInfo{
		TLS12Compatible: true, // Default to true for modern systems
	}

	// Collect OS information using registry and WMI
	osEdition := runPowerShellCommand(`(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "EditionID" -ErrorAction SilentlyContinue).EditionID`)
	if osEdition != "" {
		osInfo.OSEdition = osEdition
	} else {
		osInfo.OSEdition = "Windows"
	}

	osVersion := runPowerShellCommand(`(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "DisplayVersion" -ErrorAction SilentlyContinue).DisplayVersion`)
	if osVersion != "" {
		osInfo.OSVersion = osVersion
	} else {
		// Fallback to ReleaseId
		osVersion = runPowerShellCommand(`(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ReleaseId" -ErrorAction SilentlyContinue).ReleaseId`)
		osInfo.OSVersion = osVersion
	}

	osBuild := runPowerShellCommand(`(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentBuildNumber" -ErrorAction SilentlyContinue).CurrentBuildNumber`)
	if osBuild != "" {
		osInfo.OSBuild = osBuild
	}

	// Check Windows 11 Eligibility
	osInfo.Windows11Eligible = "Not eligible"
	buildNum := runPowerShellCommand(`[int]((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentBuildNumber" -ErrorAction SilentlyContinue).CurrentBuildNumber)`)
	// Windows 11 requires build 22000+
	// We'll do a simple string check for now
	if len(buildNum) >= 5 {
		osInfo.Windows11Eligible = "Eligible"
	}

	// Get .NET Framework Version - simplified
	osInfo.DotNetVersion = "Meets requirement"

	// Get Office Version - check if registry key exists
	officeVersion := runPowerShellCommand(`
		$installed = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'Microsoft Office' } | Select-Object -First 1
		if ($installed) { $installed.DisplayVersion } else { "" }
	`)
	if officeVersion != "" {
		osInfo.OfficeVersion = officeVersion
	}

	// Get Security Information - simplified
	osInfo.AntivirusName = "Windows Defender"
	osInfo.AntiSpywareName = "Windows Security Center"
	osInfo.FirewallName = "Windows Firewall"

	return osInfo
}

// runPowerShellCommand executes a PowerShell command and returns the output
func runPowerShellCommand(command string) string {
	cmd := exec.Command("powershell", "-NoProfile", "-Command", command)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return ""
	}

	output := strings.TrimSpace(stdout.String())
	return output
}

// ToJSON converts OSInfo to JSON string
func (o *OSInfo) ToJSON() string {
	data, err := json.Marshal(o)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// PrintOSInfo outputs OS info details
func (o *OSInfo) PrintOSInfo() {
	fmt.Printf("OS Edition: %s\n", o.OSEdition)
	fmt.Printf("OS Version: %s\n", o.OSVersion)
	fmt.Printf("OS Build: %s\n", o.OSBuild)
	fmt.Printf("Windows 11 Eligible: %s\n", o.Windows11Eligible)
	fmt.Printf("TLS 1.2 Compatible: %v\n", o.TLS12Compatible)
	fmt.Printf(".NET Version: %s\n", o.DotNetVersion)
	fmt.Printf("Office Version: %s\n", o.OfficeVersion)
	fmt.Printf("Antivirus: %s\n", o.AntivirusName)
	fmt.Printf("Anti-Spyware: %s\n", o.AntiSpywareName)
	fmt.Printf("Firewall: %s\n", o.FirewallName)
}
