<#
.SYNOPSIS
    ShieldDesk Universal Endpoint Agent — Windows Deployment Script
.DESCRIPTION
    Builds and enrolls the ShieldDesk Go Agent as a background worker on Windows.
#>

param (
    [string]$ControlPlaneUrl = "http://localhost:3000",
    [string]$TenantId = "acme-tenant",
    [string]$Hostname = $env:COMPUTERNAME,
    [string]$AgentId = [guid]::NewGuid().ToString()
)

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "     SHIELDDESK UNIVERSAL ENDPOINT AGENT (WINDOWS)        " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "[+] Enrolling Host: $Hostname"
Write-Host "[+] Tenant ID:      $TenantId"
Write-Host "[+] Agent ID:       $AgentId"
Write-Host "[+] Control Plane:  $ControlPlaneUrl"

# Verify Go installation
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error "Go runtime is not installed or not in PATH. Please install Go 1.21+."
    exit 1
}

# Compile Agent binary
Write-Host "[*] Compiling ShieldDesk Endpoint Agent..." -ForegroundColor Cyan
go build -o shielddesk-agent.exe cmd/main.go
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to compile agent binary."
    exit 1
}
Write-Host "[+] Binary successfully built: shielddesk-agent.exe" -ForegroundColor Green

# Launch Agent
Write-Host "[*] Launching ShieldDesk Endpoint Agent daemon..." -ForegroundColor Cyan
Start-Process -FilePath ".\shielddesk-agent.exe" -ArgumentList "-control-url $ControlPlaneUrl -tenant-id $TenantId -agent-id $AgentId -hostname $Hostname" -NoNewWindow
Write-Host "[+] Agent running in background and transmitting telemetry." -ForegroundColor Green
