param(
    [string]$OutDir = "bin",
    [switch]$NoClean
)

$ErrorActionPreference = "Stop"

$targets = @(
    @{ GOOS = "linux"; GOARCH = "amd64"; Output = "agent-linux-amd64" },
    @{ GOOS = "linux"; GOARCH = "arm64"; Output = "agent-linux-arm64" },
    @{ GOOS = "darwin"; GOARCH = "amd64"; Output = "agent-darwin-amd64" },
    @{ GOOS = "darwin"; GOARCH = "arm64"; Output = "agent-darwin-arm64" }
)

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

if (-not $NoClean) {
    foreach ($target in $targets) {
        $artifact = Join-Path $OutDir $target.Output
        if (Test-Path $artifact) {
            Remove-Item $artifact -Force
        }
    }
}

$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
$previousCGO = $env:CGO_ENABLED

try {
    foreach ($target in $targets) {
        $env:GOOS = $target.GOOS
        $env:GOARCH = $target.GOARCH
        $env:CGO_ENABLED = "0"

        $outputPath = Join-Path $OutDir $target.Output
        Write-Host ("Building {0}/{1} -> {2}" -f $target.GOOS, $target.GOARCH, $outputPath)

        go build -ldflags "-s -w" -o $outputPath ./cmd/agent
    }
}
finally {
    if ($null -eq $previousGOOS) { Remove-Item Env:GOOS -ErrorAction SilentlyContinue } else { $env:GOOS = $previousGOOS }
    if ($null -eq $previousGOARCH) { Remove-Item Env:GOARCH -ErrorAction SilentlyContinue } else { $env:GOARCH = $previousGOARCH }
    if ($null -eq $previousCGO) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue } else { $env:CGO_ENABLED = $previousCGO }
}

Write-Host "Build complete. Artifacts:"
Get-ChildItem -Path $OutDir -File | Where-Object { $_.Name -like "agent-linux-*" -or $_.Name -like "agent-darwin-*" } | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
