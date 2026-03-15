param(
    [string]$BaseUrl = "http://localhost:8070",
    [string]$Secret = "",
    [int]$WaitSeconds = 3
)

$ErrorActionPreference = "Stop"

function Get-AdminToken {
    param(
        [string]$JwtSecret
    )

    if (-not $JwtSecret) {
        $JwtSecret = $env:ADMIN_JWT_SECRET
    }
    if (-not $JwtSecret) {
        $JwtSecret = "AdbRaQ@d@bdra"
    }

    $token = (go run ./scripts/jwtgen -subject admin -role admin -secret $JwtSecret -ttl 3600).Trim()
    if (-not $token) {
        throw "failed to generate admin JWT"
    }
    return $token
}

function Ensure-ServerHealthy {
    param(
        [string]$Url
    )

    try {
        $health = Invoke-RestMethod -Uri "$Url/healthz" -Method GET -ErrorAction Stop
        if ($health.status -eq "healthy") {
            return
        }
    } catch {}

    Start-Process -FilePath go -ArgumentList "run","./cmd/server" -WorkingDirectory "." | Out-Null
    Start-Sleep -Seconds 4
    $health = Invoke-RestMethod -Uri "$Url/healthz" -Method GET -ErrorAction Stop
    if ($health.status -ne "healthy") {
        throw "server is not healthy"
    }
}

Ensure-ServerHealthy -Url $BaseUrl

$token = Get-AdminToken -JwtSecret $Secret
$headers = @{ Authorization = ("Bearer " + $token); "Content-Type" = "application/json" }

$session = Invoke-RestMethod -Uri "$BaseUrl/api/chat/sessions" -Headers $headers -Method POST -Body '{"title":"Global Smoke"}'
$sessionId = [int64]$session.id

$messages = @(
    "/tools",
    "/tool fleet_health {}",
    "Please remember that our priority is patch compliance and critical issue reduction.",
    "We prioritize critical issues first, then high severity.",
    "Summarize my preferences."
)

foreach ($m in $messages) {
    $payload = @{ scope = "global"; session_id = $sessionId; message = $m } | ConvertTo-Json
    Invoke-RestMethod -Uri "$BaseUrl/api/chat/messages" -Headers $headers -Method POST -Body $payload | Out-Null
    Start-Sleep -Seconds $WaitSeconds
}

$list = Invoke-RestMethod -Uri ("$BaseUrl/api/chat/messages?scope=global&session_id=" + $sessionId + "&limit=80") -Headers $headers -Method GET
$toolsHit = @($list | Where-Object { $_.sender -eq "system:global" -and $_.message -match "Available tools" }).Count
$fleetHit = @($list | Where-Object { $_.sender -eq "system:global" -and $_.message -match "Tool result \(fleet_health\)" }).Count

if ($toolsHit -lt 1) {
    throw "missing /tools reply"
}
if ($fleetHit -lt 1) {
    throw "missing fleet_health tool reply"
}

# Memory refresh is async; poll a few times.
$memoryRow = $null
for ($i = 0; $i -lt 6; $i++) {
    $dbReq = @{ tool = "db_query"; arguments = @{ sql = ("SELECT session_id, COALESCE(length(summary),0) AS summary_len, last_compacted_message_id FROM global_chat_session_memory WHERE session_id = " + $sessionId) } } | ConvertTo-Json -Depth 6
    $dbResp = Invoke-RestMethod -Uri "$BaseUrl/api/chat/tools" -Headers $headers -Method POST -Body $dbReq
    $rows = @($dbResp.result.rows)
    if ($rows.Count -gt 0) {
        $memoryRow = $rows[0]
        break
    }
    Start-Sleep -Seconds 2
}

if (-not $memoryRow) {
    throw "session memory row not found"
}

Write-Output ("smoke_ok=1 session_id=" + $sessionId)
Write-Output ("tools_reply_hits=" + $toolsHit)
Write-Output ("fleet_reply_hits=" + $fleetHit)
Write-Output ("memory_summary_len=" + $memoryRow.summary_len)
Write-Output ("memory_last_compacted_message_id=" + $memoryRow.last_compacted_message_id)
