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

# 2. Check if already installed and optimized
$localExe = Join-Path $toolsFolder "trivy.exe"

function Optimize-TrivyBinary {
    param([string]$targetExe)
    Write-Host "`nOptimizing binary size with portable UPX compression..." -ForegroundColor Yellow
    $upxZip = Join-Path $env:TEMP "upx-5.2.1-win64.zip"
    $upxExtract = Join-Path $env:TEMP "upx-extract-$([System.Guid]::NewGuid().ToString('N'))"
    $upxUrl = "https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-win64.zip"

    try {
        Write-Host "Fetching portable UPX compressor..." -ForegroundColor DarkGray
        Invoke-WebRequest -Uri $upxUrl -OutFile $upxZip -UseBasicParsing
        Expand-Archive -Path $upxZip -DestinationPath $upxExtract -Force
        $upxExe = Join-Path $upxExtract "upx-5.2.1-win64\upx.exe"

        if (Test-Path $upxExe) {
            $preSize = (Get-Item $targetExe).Length
            Write-Host "Compressing trivy.exe (reducing size by ~75%)..." -ForegroundColor Cyan
            & $upxExe -8 --force-overwrite $targetExe | Out-Null
            $postSize = (Get-Item $targetExe).Length
            $finalSizeMb = [math]::Round($postSize / 1MB, 2)
            $savedMb = [math]::Round(($preSize - $postSize) / 1MB, 2)
            Write-Host "Compression successful! Final binary size: $finalSizeMb MB ($savedMb MB saved)." -ForegroundColor Green
        }
    } catch {
        Write-Host "Note: UPX optimization skipped ($($_.Exception.Message)). Standard binary preserved." -ForegroundColor DarkYellow
    } finally {
        Remove-Item $upxZip -Force -ErrorAction SilentlyContinue
        Remove-Item $upxExtract -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (Test-Path $localExe) {
    $currentSizeMb = [math]::Round((Get-Item $localExe).Length / 1MB, 2)
    Write-Host "Trivy binary found at $localExe ($currentSizeMb MB)" -ForegroundColor Green

    # If the binary is uncompressed (>100MB), automatically compress it
    if ($currentSizeMb -gt 100) {
        Write-Host "Detected uncompressed binary. Optimizing..." -ForegroundColor Yellow
        Optimize-TrivyBinary -targetExe $localExe
    }

    & $localExe --version
    Write-Host "Trivy is ready." -ForegroundColor Green
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
    # Clean up redundant nested unzipped folders
    Remove-Item (Join-Path $toolsFolder "trivy_*") -Recurse -Force -ErrorAction SilentlyContinue
} catch {
    Write-Error "Failed to extract Trivy archive: $($_.Exception.Message)"
    exit 1
}

# 5. Compress and verify installation
if (Test-Path $localExe) {
    Optimize-TrivyBinary -targetExe $localExe

    Write-Host "`n--- INSTALLATION & OPTIMIZATION SUCCESSFUL ---" -ForegroundColor Green
    Write-Host "Trivy binary ready at: $localExe ($([math]::Round((Get-Item $localExe).Length / 1MB, 2)) MB)" -ForegroundColor White
    & $localExe --version
    Write-Host "`nShieldDesk can now run live offline/online CVE scans natively with minimal disk overhead!" -ForegroundColor Cyan
} else {
    Write-Error "Extraction finished but trivy.exe was not found in $toolsFolder"
    exit 1
}

