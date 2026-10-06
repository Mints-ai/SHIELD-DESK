# setup_gitleaks.ps1
# Automates downloading and setting up Gitleaks secret scanner for ShieldDesk on Windows

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$gitleaksVersion = "8.30.1"
$url = "https://github.com/gitleaks/gitleaks/releases/download/v$gitleaksVersion/gitleaks_${gitleaksVersion}_windows_x64.zip"
$toolsFolder = Join-Path $PSScriptRoot "..\tools\gitleaks"
$zipFile = Join-Path $env:TEMP "gitleaks_${gitleaksVersion}_temp.zip"

Write-Host "" -ForegroundColor White
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host "   ShieldDesk Gitleaks Secret Scanner Setup   " -ForegroundColor Green
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Ensure tools/gitleaks directory exists
if (!(Test-Path $toolsFolder)) {
    Write-Host "  Creating directory $toolsFolder..." -ForegroundColor DarkGray
    New-Item -ItemType Directory -Force -Path $toolsFolder | Out-Null
}

$localExe = Join-Path $toolsFolder "gitleaks.exe"

# 2. Check if already installed
if (Test-Path $localExe) {
    $currentSizeMb = [math]::Round((Get-Item $localExe).Length / 1MB, 2)
    Write-Host "  Gitleaks binary found at $localExe ($currentSizeMb MB)" -ForegroundColor Green
    Write-Host ""

    # Verify it works
    try {
        $versionOutput = & $localExe version 2>&1
        Write-Host "  Version: $versionOutput" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Binary found but version check failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }

    Write-Host ""
    Write-Host "  Gitleaks is already installed. ShieldDesk is ready for secret scanning." -ForegroundColor Green
    exit 0
}

# 3. Download Gitleaks
Write-Host "  Downloading Gitleaks v$gitleaksVersion from GitHub releases..." -ForegroundColor Yellow
Write-Host "  URL: $url" -ForegroundColor DarkGray

try {
    $progressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $url -OutFile $zipFile -UseBasicParsing
    $progressPreference = 'Continue'
    $downloadedSizeMb = [math]::Round((Get-Item $zipFile).Length / 1MB, 2)
    Write-Host "  Download complete ($downloadedSizeMb MB)." -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Failed to download Gitleaks: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Please download manually from: https://github.com/gitleaks/gitleaks/releases/latest" -ForegroundColor Yellow
    exit 1
}

# 4. Extract the binary
Write-Host "  Extracting Gitleaks into $toolsFolder..." -ForegroundColor Yellow
try {
    Expand-Archive -Path $zipFile -DestinationPath $toolsFolder -Force
    Write-Host "  Extraction complete." -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
    Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
    exit 1
}

# 5. Clean up zip
Remove-Item $zipFile -Force -ErrorAction SilentlyContinue

# 6. Verify the binary exists and works
if (Test-Path $localExe) {
    $finalSizeMb = [math]::Round((Get-Item $localExe).Length / 1MB, 2)
    Write-Host ""
    try {
        $versionOutput = & $localExe version 2>&1
        Write-Host "  Version: $versionOutput" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Could not verify version: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
    Write-Host "  Binary size: $finalSizeMb MB" -ForegroundColor DarkGray
} else {
    Write-Host "  [ERROR] gitleaks.exe not found after extraction. Archive structure may differ." -ForegroundColor Red
    Write-Host "  Contents of $toolsFolder :" -ForegroundColor DarkGray
    Get-ChildItem $toolsFolder | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    exit 1
}

# 7. Copy .gitleaks.toml if not present at project root
$projectRoot = Join-Path $PSScriptRoot ".."
$tomlDest = Join-Path $projectRoot ".gitleaks.toml"
$tomlSource = Join-Path $toolsFolder ".gitleaks.toml"

if (!(Test-Path $tomlDest) -and (Test-Path $tomlSource)) {
    Copy-Item $tomlSource $tomlDest
    Write-Host "  Copied .gitleaks.toml to project root." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  ShieldDesk can now run live offline/online secret detection scans natively!" -ForegroundColor Green
Write-Host ""
