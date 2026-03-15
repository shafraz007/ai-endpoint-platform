package agent

import (
	"context"
	"encoding/json"
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

func CollectPendingUpdates() ([]PendingUpdate, bool, error) {
	if runtime.GOOS != "windows" {
		return []PendingUpdate{}, false, nil
	}

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
