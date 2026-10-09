# setup_nats.ps1
# Automates downloading and setting up NATS JetStream server for ShieldDesk on Windows

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$natsVersion = "2.10.22"
$url = "https://github.com/nats-io/nats-server/releases/download/v$natsVersion/nats-server-v$natsVersion-windows-amd64.zip"
$toolsFolder = Join-Path $PSScriptRoot "..\tools\nats"
$zipFile = Join-Path $env:TEMP "nats_${natsVersion}_temp.zip"
$extractTemp = Join-Path $env:TEMP "nats_extract_$([System.Guid]::NewGuid().ToString('N'))"

Write-Host "" -ForegroundColor White
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host "   ShieldDesk NATS JetStream Server Setup      " -ForegroundColor Green
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Ensure tools/nats directory exists
if (!(Test-Path $toolsFolder)) {
    Write-Host "  Creating directory $toolsFolder..." -ForegroundColor DarkGray
    New-Item -ItemType Directory -Force -Path $toolsFolder | Out-Null
}

$localExe = Join-Path $toolsFolder "nats-server.exe"
$dataFolder = Join-Path $toolsFolder "data"
if (!(Test-Path $dataFolder)) {
    New-Item -ItemType Directory -Force -Path $dataFolder | Out-Null
}

# 2. Check if already installed
if (Test-Path $localExe) {
    $currentSizeMb = [math]::Round((Get-Item $localExe).Length / 1MB, 2)
    Write-Host "  NATS server binary found at $localExe ($currentSizeMb MB)" -ForegroundColor Green
    Write-Host ""

    try {
        $versionOutput = & $localExe -v 2>&1
        Write-Host "  Version: $versionOutput" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Binary found but version check failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }

    Write-Host ""
    Write-Host "  NATS JetStream is ready for ShieldDesk real-time pub/sub." -ForegroundColor Green
    exit 0
}

# 3. Download NATS server archive
Write-Host "  Downloading NATS server v$natsVersion from GitHub releases..." -ForegroundColor Yellow
Write-Host "  URL: $url" -ForegroundColor DarkGray

try {
    $progressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $url -OutFile $zipFile -UseBasicParsing
    $progressPreference = 'Continue'
    $downloadedSizeMb = [math]::Round((Get-Item $zipFile).Length / 1MB, 2)
    Write-Host "  Download complete ($downloadedSizeMb MB)." -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Failed to download NATS: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Please download manually from: https://github.com/nats-io/nats-server/releases/latest" -ForegroundColor Yellow
    exit 1
}

# 4. Extract the binary
Write-Host "  Extracting NATS server into $toolsFolder..." -ForegroundColor Yellow
try {
    New-Item -ItemType Directory -Force -Path $extractTemp | Out-Null
    Expand-Archive -Path $zipFile -DestinationPath $extractTemp -Force
    
    # Locate nats-server.exe inside the extracted structure
    $foundExe = Get-ChildItem -Path $extractTemp -Filter "nats-server.exe" -Recurse | Select-Object -First 1
    if ($foundExe) {
        Copy-Item -Path $foundExe.FullName -Destination $localExe -Force
        Write-Host "  Extraction complete." -ForegroundColor Green
    } else {
        throw "nats-server.exe not found in downloaded zip archive."
    }
} catch {
    Write-Host "  [ERROR] Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
    Remove-Item $extractTemp -Recurse -Force -ErrorAction SilentlyContinue
}

# 5. Verify the binary exists and works
if (Test-Path $localExe) {
    $finalSizeMb = [math]::Round((Get-Item $localExe).Length / 1MB, 2)
    Write-Host ""
    try {
        $versionOutput = & $localExe -v 2>&1
        Write-Host "  Version: $versionOutput" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Could not verify version: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
    Write-Host "  Binary size: $finalSizeMb MB" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ShieldDesk can now run live distributed event streaming across microservices!" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "  [ERROR] nats-server.exe installation failed." -ForegroundColor Red
    exit 1
}
