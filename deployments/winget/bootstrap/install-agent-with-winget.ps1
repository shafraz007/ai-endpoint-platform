param(
    [Parameter(Mandatory = $true)]
    [string]$AgentBinaryUrl,
    [Parameter(Mandatory = $true)]
    [string]$InstallerScriptUrl,
    [Parameter(Mandatory = $true)]
    [string]$ServerURL,
    [Parameter(Mandatory = $true)]
    [string]$AgentJWTSecret,
    [string]$ServiceName = "AIEndpointAgent",
    [string]$InstallDir = "C:\Program Files\AIEndpoint",
    [string]$LogDir = "C:\ProgramData\AIEndpoint\logs",
    [switch]$UseLocalSystem = $true,
    [string]$ServiceUser = "",
    [string]$ServicePassword = ""
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run in elevated PowerShell (Administrator)."
    }
}

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

Assert-Admin

Ensure-Dir -Path $InstallDir
Ensure-Dir -Path $LogDir

$workDir = "C:\ProgramData\AIEndpoint\bootstrap"
Ensure-Dir -Path $workDir

$agentPath = Join-Path $InstallDir "agent.exe"
$installerPath = Join-Path $workDir "install-agent-service.ps1"

Write-Host "Refreshing WinGet sources..." -ForegroundColor Cyan
winget source update | Out-Null

Write-Host "Downloading agent binary..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $AgentBinaryUrl -OutFile $agentPath

Write-Host "Downloading service installer script..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $InstallerScriptUrl -OutFile $installerPath

$args = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $installerPath,
    "-ServiceName", $ServiceName,
    "-InstallDir", $InstallDir,
    "-ServerURL", $ServerURL,
    "-AgentJWTSecret", $AgentJWTSecret,
    "-LogDir", $LogDir
)

if ($UseLocalSystem) {
    $args += "-UseLocalSystem"
}
else {
    if ([string]::IsNullOrWhiteSpace($ServiceUser) -or [string]::IsNullOrWhiteSpace($ServicePassword)) {
        throw "ServiceUser and ServicePassword are required when UseLocalSystem is false."
    }
    $args += @("-UseLocalSystem:$false", "-ServiceUser", $ServiceUser, "-ServicePassword", $ServicePassword)
}

Write-Host "Running service installer..." -ForegroundColor Cyan
powershell @args

Write-Output "done=1"
