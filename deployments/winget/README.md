# WinGet Deployment (Private Source)

This folder provides a practical starting point for deploying `agent.exe` with WinGet in enterprise environments.

## What is included

- `bootstrap/install-agent-with-winget.ps1`
  - Endpoint-side bootstrap script.
  - Uses `winget` for prerequisite install flow and then applies service configuration with `install-agent-service.ps1`.
- `templates/*.yaml`
  - Private WinGet manifest templates (`version`, `installer`, `locale`).

## Recommended rollout model

1. Host release artifacts on HTTPS:
   - `agent.exe`
   - `install-agent-service.ps1`
2. Deploy the bootstrap script through RMM/Intune/SCCM.
3. Optionally publish a private WinGet package using the template manifests.

## Quick bootstrap usage

Run as Administrator on endpoint:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deployments\winget\bootstrap\install-agent-with-winget.ps1 `
  -AgentBinaryUrl "https://downloads.example.com/armada/1.0.0/agent.exe" `
  -InstallerScriptUrl "https://downloads.example.com/armada/1.0.0/install-agent-service.ps1" `
  -ServerURL "http://your-server:8070" `
  -AgentJWTSecret "<shared_agent_secret>" `
  -UseLocalSystem
```

## Private WinGet manifest notes

Templates are pre-filled for this repository with:
- `PackageIdentifier: Shafraz007.ArmadaAgent`
- Publisher metadata and GitHub support URLs
- GitHub release URL convention for installer binaries

Before publishing, update:
- `PackageVersion`
- `InstallerUrl` (if your artifact name or hosting path differs)
- `InstallerSha256`

`installer` template assumes a bootstrap installer artifact named `ArmadaAgentBootstrap.exe`.
If you keep deployment as PowerShell-only, use the bootstrap script directly without publishing a WinGet package.

## Security notes

- Use HTTPS artifact hosting only.
- Do not hardcode secrets in static manifests for public repos.
- Prefer passing secrets via RMM secure variables or protected deployment channels.

## Operations runbook

### 1. Prepare release

- Build or collect `agent.exe`.
- Keep `install-agent-service.ps1` available.
- Decide version, for example `v1.0.0`.

### 2. Publish artifacts

Upload release artifacts to HTTPS or GitHub Releases:
- `agent.exe`
- `install-agent-service.ps1`
- optional bootstrap installer binary

Example URL pattern:

- `https://github.com/shafraz007/ai-endpoint-platform/releases/download/v1.0.0/agent.exe`
- `https://github.com/shafraz007/ai-endpoint-platform/releases/download/v1.0.0/install-agent-service.ps1`

### 3. Update WinGet package metadata

Edit manifest templates under `templates/`:
- set `PackageVersion`
- set `InstallerUrl`
- set `InstallerSha256`

### 4. Publish to private WinGet source

- Add or update manifests in your enterprise WinGet source.
- Sync the source so endpoints can discover the package.

### 5. Refresh WinGet on endpoint

Run as Administrator:

```powershell
winget source update
```

### 6. Install via bootstrap script

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deployments\winget\bootstrap\install-agent-with-winget.ps1 `
  -AgentBinaryUrl "https://github.com/shafraz007/ai-endpoint-platform/releases/download/v1.0.0/agent.exe" `
  -InstallerScriptUrl "https://github.com/shafraz007/ai-endpoint-platform/releases/download/v1.0.0/install-agent-service.ps1" `
  -ServerURL "http://your-server:8070" `
  -AgentJWTSecret "<shared_agent_secret>" `
  -UseLocalSystem
```

### 7. What bootstrap does

- creates install/log directories
- downloads `agent.exe`
- downloads `install-agent-service.ps1`
- runs the service installer
- sets machine-level environment variables
- creates or updates `ArmadaAgent`
- starts the service

### 8. Verify endpoint

```powershell
Get-Service ArmadaAgent
Test-NetConnection your-server -Port 8070
Get-ChildItem "C:\ProgramData\Armada\logs"
```

### 9. Verify server side

- Open `/agents`
- Confirm endpoint is shown as `online`
- Confirm heartbeat/log activity is visible

### 10. Upgrade flow

- publish new versioned artifact
- update WinGet manifest version and hash
- run:

```powershell
winget upgrade Shafraz007.ArmadaAgent
```

### 11. Rollback flow

- redeploy previous artifact version
- rerun installer against previous binary
- restart service:

```powershell
Restart-Service ArmadaAgent
```

### 12. Troubleshooting quick checks

```powershell
[Environment]::GetEnvironmentVariable("SERVER_URL","Machine")
[Environment]::GetEnvironmentVariable("AGENT_JWT_SECRET","Machine")
Get-Service ArmadaAgent
Get-ChildItem "C:\ProgramData\Armada\logs" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 5
```
