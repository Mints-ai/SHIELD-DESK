<#
.SYNOPSIS
    ShieldDesk Universal Endpoint Agent — Windows Deployment Script
.DESCRIPTION
    Builds and enrolls the ShieldDesk Go Agent as a background worker on Windows.
#>

param (
    [string]$Token = "",
    [string]$ControlPlaneUrl = "",
    [string]$TenantId = "",
    [string]$Hostname = $env:COMPUTERNAME,
    [string]$AgentId = "",
    [switch]$Dev = $false
)

$origDir = Get-Location
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $scriptDir) { $scriptDir = $origDir.Path }

# Safety & Parameter Validation
if ($Dev) {
    if (-not $ControlPlaneUrl) { $ControlPlaneUrl = "http://localhost:3000" }
    if (-not $TenantId) { $TenantId = "acme-tenant" }
} else {
    if (-not $ControlPlaneUrl) {
        Write-Error "CRITICAL: -ControlPlaneUrl is required. Specify https://your-control-plane (or pass -Dev for local lab evaluation)."
        exit 1
    }
    if (-not ($ControlPlaneUrl.StartsWith("https://", [System.StringComparison]::OrdinalIgnoreCase))) {
        Write-Error "SECURITY ERROR: Control plane URL must use HTTPS in production. Plain HTTP is rejected."
        exit 1
    }
    if (-not $Token -and -not $TenantId) {
        Write-Error "CRITICAL: Either -Token (enrollment token) or -TenantId is required for installation."
        exit 1
    }
}


Write-Host "==========================================================" -ForegroundColor Green
Write-Host "     SHIELDDESK UNIVERSAL ENDPOINT AGENT (WINDOWS)        " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "[+] Enrolling Host: $Hostname"
if ($Token) {
    Write-Host "[+] Enrollment Token: [CONFIGURED - SECURELY REDACTED]"
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
