param(
    [string]$DatabaseUrl = 'postgres://aiuser:aipassword@localhost:5432/aiendpoint?sslmode=disable'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

Push-Location $repoRoot
try {
    $previousDatabaseUrl = $env:DATABASE_URL
    $env:DATABASE_URL = $DatabaseUrl

    Write-Host "Running full test suite with DATABASE_URL=$DatabaseUrl" -ForegroundColor Cyan
    go test ./...

    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    Write-Host "Full test suite passed." -ForegroundColor Green
}
finally {
    $env:DATABASE_URL = $previousDatabaseUrl
    Pop-Location
}
