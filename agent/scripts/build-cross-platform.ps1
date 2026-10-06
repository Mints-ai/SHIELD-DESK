# Cross-platform compilation script for ShieldDesk Endpoint Agent
$ErrorActionPreference = "Stop"

$OutputDir = Join-Path $PSScriptRoot "..\bin"
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

$AgentDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $AgentDir

Write-Host "Building ShieldDesk Endpoint Agent for multiple platforms..." -ForegroundColor Cyan

try {
    # 1. Windows amd64
    Write-Host "--> Building windows/amd64..." -ForegroundColor Yellow
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    go build -ldflags="-s -w" -o (Join-Path $OutputDir "shielddesk-agent-windows-amd64.exe") ./cmd

    # 2. Linux amd64
    Write-Host "--> Building linux/amd64..." -ForegroundColor Yellow
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    go build -ldflags="-s -w" -o (Join-Path $OutputDir "shielddesk-agent-linux-amd64") ./cmd

    # 3. Linux arm64
    Write-Host "--> Building linux/arm64..." -ForegroundColor Yellow
    $env:GOOS = "linux"
    $env:GOARCH = "arm64"
    $env:CGO_ENABLED = "0"
    go build -ldflags="-s -w" -o (Join-Path $OutputDir "shielddesk-agent-linux-arm64") ./cmd

    # 4. Darwin arm64 (Apple Silicon)
    Write-Host "--> Building darwin/arm64..." -ForegroundColor Yellow
    $env:GOOS = "darwin"
    $env:GOARCH = "arm64"
    $env:CGO_ENABLED = "0"
    go build -ldflags="-s -w" -o (Join-Path $OutputDir "shielddesk-agent-darwin-arm64") ./cmd
} finally {
    Pop-Location
}

# Reset environment variables
$env:GOOS = ""
$env:GOARCH = ""
$env:CGO_ENABLED = ""

Write-Host "[SUCCESS] All cross-platform binaries compiled to: $OutputDir" -ForegroundColor Green
Get-ChildItem $OutputDir | Select-Object Name, Length
