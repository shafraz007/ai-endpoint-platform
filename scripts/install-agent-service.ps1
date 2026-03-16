param(
    [string]$ServiceName = "ArmadaAgent",
    [string]$InstallDir = "C:\Program Files\Armada",
    [string]$ServerURL = "http://localhost:8070",
    [string]$AgentJWTSecret = "",
    [string]$LogDir = "C:\ProgramData\Armada\logs",
    [string]$LogToConsole = "false",
    [string]$HeartbeatIntervalSeconds = "",
    [string]$RequestTimeoutSeconds = "",
    [string]$AgentAITimeoutSeconds = "",
    [string]$MaxRetries = "",
    [string]$RetryBackoffSeconds = "",
    [string]$AgentJWTTTLSeconds = "",
    [string]$CommandPollIntervalSeconds = "",
    [string]$CommandTimeoutSeconds = "",
    [string]$MetricsIntervalSeconds = "",
    [string]$AgentAIProvider = "",
    [string]$AgentAIEndpoint = "",
    [string]$AgentAIModel = "",
    [string]$AgentAIAPIKey = "",
    [string]$AgentAISystemPrompt = "",
    [string]$AgentAIAPIVersion = "",
    [string]$AgentAIDeployment = "",
    [string]$AgentAIChatEngine = "",
    [switch]$BuildFromSource,
    [string]$SourceDir = ".",
    [switch]$UseLocalSystem = $true,
    [string]$ServiceUser = "",
    [string]$ServicePassword = ""
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script in an elevated PowerShell window (Run as Administrator)."
    }
}

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Set-MachineEnv {
    param(
        [string]$Name,
        [string]$Value
    )
    [Environment]::SetEnvironmentVariable($Name, $Value, "Machine")
}

function Set-MachineEnvIfProvided {
    param(
        [string]$Name,
        [string]$Value
    )
    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        Set-MachineEnv -Name $Name -Value $Value
    }
}

function Service-Exists {
    param([string]$Name)
    return $null -ne (Get-Service -Name $Name -ErrorAction SilentlyContinue)
}

Assert-Admin

if ([string]::IsNullOrWhiteSpace($AgentJWTSecret)) {
    throw "AgentJWTSecret is required. Pass -AgentJWTSecret or set a secure value."
}

$installDirResolved = $InstallDir.Trim()
$logDirResolved = $LogDir.Trim()
$exePath = Join-Path $installDirResolved "agent.exe"

Ensure-Directory -Path $installDirResolved
Ensure-Directory -Path $logDirResolved

if ($BuildFromSource) {
    Push-Location $SourceDir
    try {
        Write-Host "Building agent binary..." -ForegroundColor Cyan
        go build -o $exePath ./cmd/agent
    }
    finally {
        Pop-Location
    }
}

if (-not (Test-Path $exePath)) {
    throw "Agent binary not found at $exePath. Use -BuildFromSource or copy the binary first."
}

Write-Host "Setting machine environment variables..." -ForegroundColor Cyan
Set-MachineEnv -Name "SERVER_URL" -Value $ServerURL
Set-MachineEnv -Name "AGENT_JWT_SECRET" -Value $AgentJWTSecret
Set-MachineEnv -Name "LOG_DIR" -Value $logDirResolved
Set-MachineEnv -Name "LOG_TO_CONSOLE" -Value $LogToConsole
Set-MachineEnvIfProvided -Name "HEARTBEAT_INTERVAL_SECONDS" -Value $HeartbeatIntervalSeconds
Set-MachineEnvIfProvided -Name "REQUEST_TIMEOUT_SECONDS" -Value $RequestTimeoutSeconds
Set-MachineEnvIfProvided -Name "AGENT_AI_TIMEOUT_SECONDS" -Value $AgentAITimeoutSeconds
Set-MachineEnvIfProvided -Name "MAX_RETRIES" -Value $MaxRetries
Set-MachineEnvIfProvided -Name "RETRY_BACKOFF_SECONDS" -Value $RetryBackoffSeconds
Set-MachineEnvIfProvided -Name "AGENT_JWT_TTL_SECONDS" -Value $AgentJWTTTLSeconds
Set-MachineEnvIfProvided -Name "COMMAND_POLL_INTERVAL_SECONDS" -Value $CommandPollIntervalSeconds
Set-MachineEnvIfProvided -Name "COMMAND_TIMEOUT_SECONDS" -Value $CommandTimeoutSeconds
Set-MachineEnvIfProvided -Name "METRICS_INTERVAL_SECONDS" -Value $MetricsIntervalSeconds
Set-MachineEnvIfProvided -Name "AGENT_AI_PROVIDER" -Value $AgentAIProvider
Set-MachineEnvIfProvided -Name "AGENT_AI_ENDPOINT" -Value $AgentAIEndpoint
Set-MachineEnvIfProvided -Name "AGENT_AI_MODEL" -Value $AgentAIModel
Set-MachineEnvIfProvided -Name "AGENT_AI_API_KEY" -Value $AgentAIAPIKey
Set-MachineEnvIfProvided -Name "AGENT_AI_SYSTEM_PROMPT" -Value $AgentAISystemPrompt
Set-MachineEnvIfProvided -Name "AGENT_AI_API_VERSION" -Value $AgentAIAPIVersion
Set-MachineEnvIfProvided -Name "AGENT_AI_DEPLOYMENT" -Value $AgentAIDeployment
Set-MachineEnvIfProvided -Name "AGENT_AI_CHAT_ENGINE" -Value $AgentAIChatEngine

$binPathQuoted = '"' + $exePath + '"'

if (-not (Service-Exists -Name $ServiceName)) {
    Write-Host "Creating service $ServiceName ..." -ForegroundColor Cyan
    sc.exe create $ServiceName binPath= $binPathQuoted start= auto | Out-Null
}
else {
    Write-Host "Updating service $ServiceName ..." -ForegroundColor Cyan
    sc.exe config $ServiceName binPath= $binPathQuoted start= auto | Out-Null
}

if ($UseLocalSystem) {
    Write-Host "Configuring service account: LocalSystem (elevated)" -ForegroundColor Yellow
    sc.exe config $ServiceName obj= "LocalSystem" | Out-Null
}
else {
    if ([string]::IsNullOrWhiteSpace($ServiceUser) -or [string]::IsNullOrWhiteSpace($ServicePassword)) {
        throw "When -UseLocalSystem:$false, provide -ServiceUser and -ServicePassword."
    }
    Write-Host "Configuring service account: $ServiceUser" -ForegroundColor Cyan
    sc.exe config $ServiceName obj= $ServiceUser password= $ServicePassword | Out-Null
}

Write-Host "Setting service recovery policy..." -ForegroundColor Cyan
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

Write-Host "Starting service $ServiceName ..." -ForegroundColor Cyan
Start-Service -Name $ServiceName
Start-Sleep -Seconds 2

$finalSvc = Get-Service -Name $ServiceName

Write-Output ("service_name=" + $ServiceName)
Write-Output ("service_status=" + $finalSvc.Status)
Write-Output ("agent_path=" + $exePath)
Write-Output ("log_dir=" + $logDirResolved)
Write-Output ("env_server_url=" + $ServerURL)
Write-Output ("env_log_to_console=" + $LogToConsole)
Write-Output "done=1"
