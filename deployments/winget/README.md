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
  -AgentBinaryUrl "https://downloads.example.com/aiendpoint/1.0.0/agent.exe" `
  -InstallerScriptUrl "https://downloads.example.com/aiendpoint/1.0.0/install-agent-service.ps1" `
  -ServerURL "http://your-server:8070" `
  -AgentJWTSecret "<shared_agent_secret>" `
  -UseLocalSystem
```

## Private WinGet manifest notes

The templates in `templates/` are intentionally placeholders:
- Replace `PackageIdentifier`, `Publisher`, URLs, hashes, version.
- `installer` template assumes a bootstrap installer binary URL (`AIEndpointAgentBootstrap.exe`).
- If you keep deployment as PowerShell-only, use the bootstrap script directly without publishing a package.

## Security notes

- Use HTTPS artifact hosting only.
- Do not hardcode secrets in static manifests for public repos.
- Prefer passing secrets via RMM secure variables or protected deployment channels.
