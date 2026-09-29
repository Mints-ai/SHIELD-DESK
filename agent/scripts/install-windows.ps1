# ShieldDesk Universal Endpoint Agent - Windows Automated Installation Script
# Usage:
#   powershell -ExecutionPolicy Bypass -File install-windows.ps1 -ControlPlane "https://control.shielddesk.io" -EnrollToken "sdt_..."
param(
    [Parameter(Mandatory=$true)]
    [string]$ControlPlane,

    [Parameter(Mandatory=$true)]
    [string]$EnrollToken,

    [string]$InstallDir = "C:\Program Files\ShieldDesk\Agent",
    [string]$ServiceName = "ShieldDeskAgent"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ShieldDesk Universal Endpoint Agent - Windows Setup    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Require Administrative Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrative privileges required. Please run this script in an elevated PowerShell session (Run as Administrator)."
    exit 1
}

# 2. Prepare Installation Directory
if (-not (Test-Path $InstallDir)) {
    Write-Host "[1/5] Creating directory $InstallDir..." -ForegroundColor Yellow
    New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
}

$BinaryPath = Join-Path $InstallDir "shielddesk-agent.exe"

# 3. Stop existing service if running
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "[2/5] Stopping existing $ServiceName service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
}

# 4. Compile or copy agent binary (if local binary exists, copy it; else download)
$LocalAgentBin = Join-Path $PSScriptRoot "..\cmd\agent.exe"
if (Test-Path $LocalAgentBin) {
    Write-Host "[3/5] Installing local agent binary..." -ForegroundColor Green
    Copy-Item -Path $LocalAgentBin -Destination $BinaryPath -Force
} else {
    Write-Host "[3/5] Fetching compiled agent binary from control plane..." -ForegroundColor Yellow
    $DownloadUrl = "$ControlPlane/api/agent/binary/windows-amd64"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $BinaryPath -TimeoutSec 30
    } catch {
        Write-Warning "Could not fetch precompiled binary from $DownloadUrl. Falling back to local Go build..."
        if (Get-Command go -ErrorAction SilentlyContinue) {
            Write-Host "Compiling agent from local Go source..." -ForegroundColor Green
            $AgentSrcDir = (Resolve-Path (Join-Path $PSScriptRoot "..\cmd")).Path
            go build -o $BinaryPath $AgentSrcDir
        } else {
            Write-Error "Neither Go compiler nor remote binary download available. Please place shielddesk-agent.exe into $InstallDir manually."
            exit 1
        }
    }
}

# 5. Create or Update Windows Service
Write-Host "[4/5] Registering Windows Service ($ServiceName)..." -ForegroundColor Yellow
$ServiceArgs = "-control-url `"$ControlPlane`" -enroll-token `"$EnrollToken`""
$BinWithArgs = "`"$BinaryPath`" $ServiceArgs"

if ($existingService) {
    sc.exe config $ServiceName binPath= $BinWithArgs | Out-Null
} else {
    New-Service -Name $ServiceName `
                -BinaryPathName $BinWithArgs `
                -DisplayName "ShieldDesk Endpoint Agent" `
                -Description "ShieldDesk Universal Endpoint Agent for autonomous telemetry collection and governed containment." `
                -StartupType Automatic | Out-Null
}

# 6. Start Service & Verify Health
Write-Host "[5/5] Starting $ServiceName service..." -ForegroundColor Green
Start-Service -Name $ServiceName

Start-Sleep -Seconds 3
$status = (Get-Service -Name $ServiceName).Status
if ($status -eq "Running") {
    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host " [SUCCESS] ShieldDesk Endpoint Agent is RUNNING as a service!" -ForegroundColor Green
    Write-Host " Endpoint is now enrolled and streaming telemetry to:" -ForegroundColor Green
    Write-Host " $ControlPlane" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Green
} else {
    Write-Warning "Service status is: $status. Check Windows Event Viewer Application logs for details."
}
