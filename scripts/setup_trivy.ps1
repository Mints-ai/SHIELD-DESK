# setup_trivy.ps1
# Automates downloading and setting up Aqua Trivy for ShieldDesk on Windows

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$trivyVersion = "0.74.0"
$url = "https://github.com/aquasecurity/trivy/releases/download/v$trivyVersion/trivy_${trivyVersion}_windows-64bit.zip"
$toolsFolder = Join-Path $PSScriptRoot "..\tools\trivy"
$zipFile = Join-Path $env:TEMP "trivy_${trivyVersion}_temp.zip"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  ShieldDesk Trivy Security Scanner Setup    " -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Ensure tools/trivy exists
if (!(Test-Path $toolsFolder)) {
    Write-Host "Creating directory $toolsFolder..." -ForegroundColor DarkGray
    New-Item -ItemType Directory -Force -Path $toolsFolder | Out-Null
}

# 2. Check if already installed
$localExe = Join-Path $toolsFolder "trivy.exe"
if (Test-Path $localExe) {
    Write-Host "Trivy binary found at $localExe" -ForegroundColor Green
    & $localExe --version
    Write-Host "Trivy is already installed and ready." -ForegroundColor Green
    exit 0
}

# 3. Download Trivy release
Write-Host "Downloading Trivy v$trivyVersion from GitHub releases..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $url -OutFile $zipFile -UseBasicParsing
    Write-Host "Download complete ($((Get-Item $zipFile).Length / 1MB | ForEach-Object { $_.ToString('N1') }) MB)." -ForegroundColor Green
} catch {
    Write-Error "Failed to download Trivy archive. Please check internet connection: $($_.Exception.Message)"
    exit 1
}

# 4. Extract into tools/trivy
Write-Host "Extracting Trivy into tools/trivy..." -ForegroundColor Yellow
try {
    Expand-Archive -Path $zipFile -DestinationPath $toolsFolder -Force
    Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
} catch {
    Write-Error "Failed to extract Trivy archive: $($_.Exception.Message)"
    exit 1
}

# 5. Verify installation
if (Test-Path $localExe) {
    Write-Host "`n--- INSTALLATION SUCCESSFUL ---" -ForegroundColor Green
    Write-Host "Trivy binary ready at: $localExe" -ForegroundColor White
    & $localExe --version
    Write-Host "`nShieldDesk can now run live offline/online CVE scans natively!" -ForegroundColor Cyan
} else {
    Write-Error "Extraction finished but trivy.exe was not found in $toolsFolder"
    exit 1
}
