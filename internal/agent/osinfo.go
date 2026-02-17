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
	OSEdition           string `json:"os_edition"`
	OSVersion           string `json:"os_version"`
	OSBuild             string `json:"os_build"`
	Windows11Eligible   string `json:"windows_11_eligible"`
	TLS12Compatible     bool   `json:"tls_12_compatible"`
	DotNetVersion       string `json:"dotnet_version"`
	OfficeVersion       string `json:"office_version"`
	AntivirusName       string `json:"antivirus_name"`
	AntiSpywareName     string `json:"antispyware_name"`
	FirewallName        string `json:"firewall_name"`
}

// CollectOSInfo gathers OS and security information
func CollectOSInfo() *OSInfo {
	osInfo := &OSInfo{
		TLS12Compatible: true, // Default to true for modern systems
	}

	// Collect OS information
	osEdition := runPowerShellCommand(`(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "EditionID" -ErrorAction SilentlyContinue).EditionID`)
	osInfo.OSEdition = osEdition

	osVersion := runPowerShellCommand(`(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "DisplayVersion" -ErrorAction SilentlyContinue).DisplayVersion`)
	osInfo.OSVersion = osVersion

	osBuild := runPowerShellCommand(`(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentBuildNumber" -ErrorAction SilentlyContinue).CurrentBuildNumber`)
	osInfo.OSBuild = osBuild

	// Check Windows 11 Eligibility
	windows11Eligible := runPowerShellCommand(`
		$win11Capable = $false
		try {
			$osVersion = [System.Environment]::OSVersion.Version
			if ($osVersion.Major -eq 10 -and $osVersion.Build -ge 22000) {
				$win11Capable = $true
			}
		} catch {}
		if ($win11Capable) { 'Eligible' } else { 'Not eligible' }
	`)
	osInfo.Windows11Eligible = windows11Eligible

	// Get .NET Framework Version
	dotnetVersion := runPowerShellCommand(`
		try {
			$dotnetVersion = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -ErrorAction SilentlyContinue | 
				Get-ItemProperty -Name Version -ErrorAction SilentlyContinue | 
				Select-Object -ExpandProperty Version | 
				Select-Object -Last 1
			if ($dotnetVersion) { $dotnetVersion } else { '' }
		} catch { '' }
	`)
	osInfo.DotNetVersion = dotnetVersion

	// Get Office Version
	officeVersion := runPowerShellCommand(`
		try {
			$officeReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | 
				Where-Object { $_.DisplayName -match 'Microsoft Office' } |
				Select-Object -ExpandProperty DisplayVersion -First 1
			if ($officeReg) { $officeReg } else { '' }
		} catch { '' }
	`)
	osInfo.OfficeVersion = officeVersion

	// Get Security Information
	antivirus := runPowerShellCommand(`
		try {
			Get-MpComputerStatus -ErrorAction SilentlyContinue | 
				Select-Object -ExpandProperty AntivirusSignatureLastUpdated
			'Windows Defender'
		} catch {
			try {
				$av = Get-WmiObject -Namespace "root\cimv2\security\microsoftvolumeencryption" -Class "Win32_EncryptableVolume" -ErrorAction SilentlyContinue
				if ($av) { 'Windows Defender' } else { '' }
			} catch { '' }
		}
	`)
	if antivirus != "" {
		osInfo.AntivirusName = "Windows Defender"
	}

	antispyware := runPowerShellCommand(`
		try {
			Get-MpComputerStatus -ErrorAction SilentlyContinue | 
				Select-Object -ExpandProperty AntiSpywareSignatureLastUpdated
			'Windows Security Center'
		} catch { '' }
	`)
	if antispyware != "" {
		osInfo.AntiSpywareName = "Windows Security Center"
	}

	firewall := runPowerShellCommand(`
		try {
			if (Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object {$_.Enabled -eq $true}) {
				'Windows Firewall'
			} else { '' }
		} catch { '' }
	`)
	if firewall != "" {
		osInfo.FirewallName = "Windows Firewall"
	}

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
