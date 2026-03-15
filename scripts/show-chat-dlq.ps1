Param(
    [string]$LogPath = "logs/chat-worker-$(Get-Date -Format 'yyyy-MM-dd').log",
    [int]$Tail = 50,
    [switch]$Follow,
    [switch]$UseNatsCli,
    [string]$Subject = "chat.agent.chat.shadow.dlq"
)

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if ($UseNatsCli) {
        $nats = Get-Command nats -ErrorAction SilentlyContinue
        if (-not $nats) {
            Write-Host "nats CLI not found in PATH. Showing log-based DLQ events instead." -ForegroundColor Yellow
        } else {
            Write-Host "Subscribing to DLQ subject: $Subject" -ForegroundColor Cyan
            & nats sub $Subject
            return
        }
    }

    if (-not (Test-Path $LogPath)) {
        Write-Host "Log file not found: $LogPath" -ForegroundColor Yellow
        return
    }

    Write-Host "Showing DLQ log entries from: $LogPath" -ForegroundColor Cyan
    if ($Follow) {
        Get-Content $LogPath -Tail $Tail -Wait | Select-String -Pattern "dead-letter|retrying message_id|retry publish failed"
    } else {
        Get-Content $LogPath -Tail $Tail | Select-String -Pattern "dead-letter|retrying message_id|retry publish failed"
    }
}
finally {
    Pop-Location
}
