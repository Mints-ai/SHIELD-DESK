<#
.SYNOPSIS
    ShieldDesk Universal Endpoint Agent — Windows Deployment Script
.DESCRIPTION
    Builds and enrolls the ShieldDesk Go Agent as a background worker on Windows.
#>

param (
    [string]$Token = "",
    [string]$ControlPlaneUrl = "http://localhost:3000",
    [string]$TenantId = "acme-tenant",
    [string]$Hostname = $env:COMPUTERNAME,
    [string]$AgentId = ""
)

$origDir = Get-Location
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $scriptDir) { $scriptDir = $origDir.Path }

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "     SHIELDDESK UNIVERSAL ENDPOINT AGENT (WINDOWS)        " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "[+] Enrolling Host: $Hostname"
if ($Token) {
    Write-Host "[+] Enrollment Token: $Token"
} else {
    Write-Host "[+] Tenant ID:      $TenantId"
    Write-Host "[+] Agent ID:       $AgentId"
}
Write-Host "[+] Control Plane:  $ControlPlaneUrl"

# Terminate any existing running agent instance to prevent file lock during compilation
$existingProc = Get-Process -Name "shielddesk-agent" -ErrorAction SilentlyContinue
if ($existingProc) {
    Write-Host "[*] Stopping previous shielddesk-agent instance (PID: $($existingProc.Id))..." -ForegroundColor Yellow
    Stop-Process -Id $existingProc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

# Verify Go installation or existing pre-compiled binary
$binaryPath = Join-Path $scriptDir "shielddesk-agent.exe"
$hasGo = [bool](Get-Command go -ErrorAction SilentlyContinue)

Push-Location $scriptDir
try {
    if ($hasGo) {
        # Compile Agent binary inside the agent module directory
        Write-Host "[*] Compiling ShieldDesk Endpoint Agent..." -ForegroundColor Cyan
        go build -ldflags="-s -w" -o shielddesk-agent.exe ./cmd
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to compile agent binary."
            exit 1
        }
        Write-Host "[+] Binary successfully built: $binaryPath" -ForegroundColor Green
    } elseif (Test-Path $binaryPath) {
        Write-Host "[!] Go compiler not found, using existing pre-built binary: $binaryPath" -ForegroundColor Yellow
    } else {
        Write-Error "Go runtime is not installed or not in PATH, and no pre-built shielddesk-agent.exe was found. Please install Go 1.21+."
        exit 1
    }

    # Also mirror binary to caller's directory if invoked from repository root
    if ($origDir.Path -ne $scriptDir -and (Test-Path $origDir.Path)) {
        Copy-Item -Path $binaryPath -Destination (Join-Path $origDir.Path "shielddesk-agent.exe") -Force -ErrorAction SilentlyContinue
    }

    # Launch Agent
    Write-Host "[*] Launching ShieldDesk Endpoint Agent daemon..." -ForegroundColor Cyan
    $argList = if ($Token) {
        @("-token", $Token, "-control-url", $ControlPlaneUrl, "-hostname", $Hostname)
    } elseif ($AgentId) {
        @("-control-url", $ControlPlaneUrl, "-tenant-id", $TenantId, "-agent-id", $AgentId, "-hostname", $Hostname)
    } else {
        @("-control-url", $ControlPlaneUrl, "-tenant-id", $TenantId, "-hostname", $Hostname)
    }

    Start-Process -FilePath $binaryPath -ArgumentList $argList -WorkingDirectory $scriptDir -NoNewWindow
    Write-Host "[+] Agent running in background and transmitting telemetry." -ForegroundColor Green
}
finally {
    Pop-Location
}
