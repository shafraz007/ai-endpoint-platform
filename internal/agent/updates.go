package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

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

type pendingUpdateEnvelope struct {
	RebootRequired bool            `json:"reboot_required"`
	Updates        []PendingUpdate `json:"updates"`
}

// CollectPendingUpdates returns the list of pending OS updates for the
// current platform.  Windows uses the COM-based Windows Update API;
// Linux dispatches to the available package manager (apt/dnf/yum/zypper).
// Other platforms return an empty list.
func CollectPendingUpdates() ([]PendingUpdate, bool, error) {
	switch runtime.GOOS {
	case "windows":
		return collectWindowsUpdates()
	case "linux":
		return collectLinuxUpdates()
	default:
		return []PendingUpdate{}, false, nil
	}
}

// collectWindowsUpdates uses the Windows Update COM API via PowerShell.
func collectWindowsUpdates() ([]PendingUpdate, bool, error) {
	psScript := `$ErrorActionPreference = 'SilentlyContinue'
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0")

    $items = @()
    foreach ($u in $result.Updates) {
        $kb = ''
        if ($u.KBArticleIDs -and $u.KBArticleIDs.Count -gt 0 -and $u.KBArticleIDs[0]) {
            $kb = ('KB' + [string]$u.KBArticleIDs[0]).ToUpper()
        }

        $cats = @()
        foreach ($c in $u.Categories) {
            if ($c -and $c.Name) { $cats += [string]$c.Name }
        }

        $catText = ($cats -join ' | ')
        $isDriver = ($u.Type -eq 2 -or [string]$u.Type -eq 'Driver' -or $catText -match 'Driver')
        $isSecurity = ($catText -match 'Security')
        $isCritical = ($catText -match 'Critical')
        $isOS = ($catText -match 'Windows|Operating System')

        $items += [pscustomobject]@{
            update_id       = [string]$u.Identity.UpdateID
            kb_id           = $kb
            title           = [string]$u.Title
            description     = [string]$u.Description
            severity        = [string]$u.MsrcSeverity
            categories      = $cats
            is_driver       = [bool]$isDriver
            is_security     = [bool]$isSecurity
            is_critical     = [bool]$isCritical
            is_os           = [bool]$isOS
            is_software     = [bool](-not $isDriver)
            reboot_required = [bool]$u.RebootRequired
        }
    }

    $rebootFlag = $false
    if (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue) {
        $rebootFlag = $true
    }

    [pscustomobject]@{
        reboot_required = [bool]$rebootFlag
        updates = $items
    } | ConvertTo-Json -Depth 8 -Compress
} catch {
    [pscustomobject]@{ reboot_required = $false; updates = @() } | ConvertTo-Json -Depth 8 -Compress
}`

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NoLogo", "-NonInteractive", "-Command", psScript)
	out, err := cmd.Output()
	if err != nil {
		return nil, false, err
	}

	envelope := pendingUpdateEnvelope{Updates: []PendingUpdate{}}
	if err := json.Unmarshal(out, &envelope); err != nil {
		return nil, false, err
	}

	for i := range envelope.Updates {
		envelope.Updates[i].UpdateID = strings.TrimSpace(envelope.Updates[i].UpdateID)
		envelope.Updates[i].KBID = strings.ToUpper(strings.TrimSpace(envelope.Updates[i].KBID))
		envelope.Updates[i].Title = strings.TrimSpace(envelope.Updates[i].Title)
		envelope.Updates[i].Description = strings.TrimSpace(envelope.Updates[i].Description)
		envelope.Updates[i].Severity = strings.TrimSpace(envelope.Updates[i].Severity)
	}

	return envelope.Updates, envelope.RebootRequired, nil
}

// detectLinuxPackageManagerForUpdates returns the name of the first Linux
// package manager binary found in PATH that this package can handle.
func detectLinuxPackageManagerForUpdates() string {
	for _, candidate := range []struct{ binary, name string }{
		{"apt-get", "apt"},
		{"dnf", "dnf"},
		{"yum", "yum"},
		{"zypper", "zypper"},
	} {
		if _, err := exec.LookPath(candidate.binary); err == nil {
			return candidate.name
		}
	}
	return ""
}

// collectLinuxUpdates dispatches to the available package manager.
func collectLinuxUpdates() ([]PendingUpdate, bool, error) {
	switch detectLinuxPackageManagerForUpdates() {
	case "apt":
		return collectAptUpdates()
	case "dnf":
		return collectDnfYumUpdates("dnf")
	case "yum":
		return collectDnfYumUpdates("yum")
	case "zypper":
		return collectZypperUpdates()
	default:
		return []PendingUpdate{}, false, nil
	}
}

// collectAptUpdates uses "apt-get -s upgrade" (simulate, no root required)
// to enumerate pending packages on Debian/Ubuntu systems.
func collectAptUpdates() ([]PendingUpdate, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "apt-get", "-s", "-q", "upgrade")
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, false, err
	}

	var updates []PendingUpdate
	for _, line := range strings.Split(string(out), "\n") {
		// apt-get -s upgrade prints "Inst pkgname [oldver] (newver source [arch])"
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		pkgName := parts[1]
		isSecurity := strings.Contains(line, "-security")
		isKernel := strings.HasPrefix(pkgName, "linux-image") ||
			strings.HasPrefix(pkgName, "linux-headers") ||
			pkgName == "linux-generic" || pkgName == "linux-firmware"

		cats := []string{}
		if isSecurity {
			cats = append(cats, "Security")
		}
		if isKernel {
			cats = append(cats, "Kernel")
		}
		u := PendingUpdate{
			UpdateID:       pkgName,
			Title:          pkgName,
			Categories:     cats,
			IsSecurity:     isSecurity,
			IsCritical:     isSecurity,
			IsOS:           isKernel,
			IsSoftware:     !isKernel,
			RebootRequired: isKernel,
		}
		if isSecurity {
			u.Severity = "Important"
		}
		updates = append(updates, u)
	}

	// On Debian/Ubuntu a pending reboot is signalled by this file.
	rebootRequired := false
	if _, statErr := os.Stat("/var/run/reboot-required"); statErr == nil {
		rebootRequired = true
	}

	if updates == nil {
		updates = []PendingUpdate{}
	}
	return updates, rebootRequired, nil
}

// collectDnfYumUpdates uses "dnf/yum check-update" on RHEL/Fedora/CentOS systems.
// dnf/yum exits with code 100 when updates are available — treat that as non-error.
func collectDnfYumUpdates(pm string) ([]PendingUpdate, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, pm, "check-update", "--quiet")
	out, _ := cmd.Output() // exit 100 = updates available; ignore exit code

	var updates []PendingUpdate
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		// format: name.arch  version  repo
		nameArch := parts[0]
		// Skip header/info lines that lack an arch suffix (e.g. "Last metadata...")
		if !strings.Contains(nameArch, ".") {
			continue
		}
		version := parts[1]
		repo := parts[2]

		pkgName := nameArch
		if idx := strings.LastIndex(nameArch, "."); idx > 0 {
			pkgName = nameArch[:idx]
		}
		isSecurity := strings.Contains(strings.ToLower(repo), "security")
		isKernel := strings.HasPrefix(pkgName, "kernel")

		cats := []string{}
		if isSecurity {
			cats = append(cats, "Security")
		}
		if isKernel {
			cats = append(cats, "Kernel")
		}
		u := PendingUpdate{
			UpdateID:       pkgName + "-" + version,
			Title:          pkgName,
			Categories:     cats,
			IsSecurity:     isSecurity,
			IsCritical:     isSecurity,
			IsOS:           isKernel,
			IsSoftware:     !isKernel,
			RebootRequired: isKernel,
		}
		if isSecurity {
			u.Severity = "Important"
		}
		updates = append(updates, u)
	}

	if updates == nil {
		updates = []PendingUpdate{}
	}
	return updates, false, nil
}

// collectZypperUpdates uses "zypper list-updates" on SUSE/openSUSE systems.
func collectZypperUpdates() ([]PendingUpdate, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "zypper", "--quiet", "--no-color", "list-updates")
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, false, err
	}

	var updates []PendingUpdate
	for _, line := range strings.Split(string(out), "\n") {
		// Data rows: "v  | repo | name | current-ver | avail-ver | arch"
		// Header/separator rows have no meaningful package name in column 3.
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			continue
		}
		pkgName := strings.TrimSpace(parts[2])
		if pkgName == "" || pkgName == "Name" || strings.Contains(pkgName, "---") {
			continue
		}
		isKernel := strings.HasPrefix(pkgName, "kernel")
		cats := []string{}
		if isKernel {
			cats = append(cats, "Kernel")
		}
		u := PendingUpdate{
			UpdateID:       pkgName,
			Title:          pkgName,
			Categories:     cats,
			IsOS:           isKernel,
			IsSoftware:     !isKernel,
			RebootRequired: isKernel,
		}
		updates = append(updates, u)
	}

	if updates == nil {
		updates = []PendingUpdate{}
	}
	return updates, false, nil
}
