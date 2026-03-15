Param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,
    [string]$TargetSubject = "chat.agent.chat.shadow",
    [string]$NatsUrl = "",
    [switch]$DryRun,
    [switch]$KeepAttempt,
    [int]$MaxAttempts = 4
)

$ErrorActionPreference = "Stop"

function Resolve-NatsUrl {
    param([string]$Current)

    $resolved = $Current
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        $resolved = $env:NATS_URL
    }
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        $resolved = "nats://localhost:4222"
    }
    return $resolved.Trim()
}

function Resolve-JsonRecords {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "input file not found: $Path"
    }

    $raw = Get-Content -Path $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return @()
    }

    $trimmed = $raw.Trim()
    if ($trimmed.StartsWith("[")) {
        $decoded = $trimmed | ConvertFrom-Json
        if ($decoded -is [System.Array]) {
            return $decoded
        }
        return @($decoded)
    }

    $items = @()
    $lines = Get-Content -Path $Path -Encoding UTF8
    foreach ($line in $lines) {
        $entry = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }
        $items += ($entry | ConvertFrom-Json)
    }
    return $items
}

function Resolve-DedupeKey {
    param($Dead)

    $existing = ""
    if ($null -ne $Dead.dedupe_key) {
        $existing = [string]$Dead.dedupe_key
    }
    if (-not [string]::IsNullOrWhiteSpace($existing)) {
        return $existing.Trim()
    }

    if ($null -ne $Dead.task -and $null -ne $Dead.task.task_id) {
        $taskId = [string]$Dead.task.task_id
        if (-not [string]::IsNullOrWhiteSpace($taskId)) {
            return $taskId.Trim()
        }
    }

    if ($null -ne $Dead.message_id) {
        return "chatmsg-$([string]$Dead.message_id)"
    }

    return "chatmsg-unknown"
}

function Convert-DeadLetterToTask {
    param(
        $Dead,
        [switch]$KeepAttempt,
        [int]$FallbackMaxAttempts
    )

    if ($null -eq $Dead) {
        throw "dead-letter item is null"
    }

    $type = ""
    if ($null -ne $Dead.type) {
        $type = [string]$Dead.type
    }
    if ($type.Trim().ToLower() -ne "agent_chat_task_dead_letter") {
        throw "unsupported dead-letter type: $type"
    }

    $max = $FallbackMaxAttempts
    if ($null -ne $Dead.max_attempts) {
        $parsed = 0
        if ([int]::TryParse([string]$Dead.max_attempts, [ref]$parsed) -and $parsed -gt 0) {
            $max = $parsed
        }
    }
    if ($max -le 0) {
        $max = 4
    }

    $attempt = 1
    if ($KeepAttempt) {
        $parsedAttempt = 0
        if ($null -ne $Dead.attempt -and [int]::TryParse([string]$Dead.attempt, [ref]$parsedAttempt) -and $parsedAttempt -gt 0) {
            $attempt = $parsedAttempt
        }
    }

    $sessionId = 0
    if ($null -ne $Dead.session_id) {
        [void][int64]::TryParse([string]$Dead.session_id, [ref]$sessionId)
    }

    return [ordered]@{
        type         = "agent_chat_task"
        version      = 1
        message_id   = [int64]$Dead.message_id
        agent_id     = [string]$Dead.agent_id
        session_id   = [int64]$sessionId
        scope        = [string]$Dead.scope
        attempt      = $attempt
        max_attempts = $max
        dedupe_key   = (Resolve-DedupeKey -Dead $Dead)
        task         = $Dead.task
        created_at   = (Get-Date).ToUniversalTime().ToString("o")
    }
}

$resolvedNatsUrl = Resolve-NatsUrl -Current $NatsUrl
$records = Resolve-JsonRecords -Path $InputPath
if ($records.Count -eq 0) {
    Write-Host "No DLQ records found in input." -ForegroundColor Yellow
    exit 0
}

$publishCount = 0
$skipCount = 0
$natsCommand = Get-Command nats -ErrorAction SilentlyContinue
if (-not $DryRun -and -not $natsCommand) {
    throw "nats CLI not found in PATH. Install nats CLI or run with -DryRun."
}

foreach ($record in $records) {
    try {
        $taskEnvelope = Convert-DeadLetterToTask -Dead $record -KeepAttempt:$KeepAttempt -FallbackMaxAttempts $MaxAttempts
        $payload = $taskEnvelope | ConvertTo-Json -Depth 20 -Compress

        if ($DryRun) {
            Write-Output ("DRYRUN message_id={0} agent_id={1} attempt={2}/{3} subject={4}" -f $taskEnvelope.message_id, $taskEnvelope.agent_id, $taskEnvelope.attempt, $taskEnvelope.max_attempts, $TargetSubject)
        }
        else {
            & nats --server $resolvedNatsUrl pub $TargetSubject $payload | Out-Null
            Write-Output ("REPLAYED message_id={0} agent_id={1} attempt={2}/{3} subject={4}" -f $taskEnvelope.message_id, $taskEnvelope.agent_id, $taskEnvelope.attempt, $taskEnvelope.max_attempts, $TargetSubject)
        }

        $publishCount++
    }
    catch {
        $skipCount++
        Write-Output ("SKIPPED reason={0}" -f $_.Exception.Message)
    }
}

Write-Output ("done published={0} skipped={1} dry_run={2}" -f $publishCount, $skipCount, [bool]$DryRun)