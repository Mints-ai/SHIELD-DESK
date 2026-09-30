# setup_trivy.ps1
# This script automates the download and installation of Trivy for Windows

# Force TLS 1.2 for GitHub downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$trivyVersion = "0.50.1" 
$url = "https://github.com/aquasecurity/trivy/releases/download/v$trivyVersion/trivy_$trivyVersion_windows-64bit.zip"
$destFolder = "C:\trivy"
$zipFile = "C:\trivy\trivy.zip"

Write-Host "--- ShieldDesk Trivy Installer ---" -ForegroundColor Cyan

# 1. Create destination folder
if (!(Test-Path $destFolder)) {
    Write-Host "Creating folder $destFolder..."
    New-Item -ItemType Directory -Force -Path $destFolder | Out-Null
}

# 2. Download Trivy
Write-Host "Downloading Trivy v$trivyVersion from GitHub..." -ForegroundColor Yellow
try {
    # Using a more robust download method
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($url, $zipFile)
    Write-Host "Download complete." -ForegroundColor Green
} catch {
    Write-Host "Download failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Error "Failed to download Trivy. Please check your internet connection or firewall."
    exit
}

# 3. Extract Trivy
Write-Host "Extracting files..." -ForegroundColor Yellow
try {
    Expand-Archive -Path $zipFile -DestinationPath $destFolder -Force
    Remove-Item $zipFile
} catch {
    Write-Error "Failed to extract Trivy zip file."
    exit
}

Write-Host "`n--- INSTALLATION SUCCESSFUL ---" -ForegroundColor Green
Write-Host "Trivy is now installed at: $destFolder" -ForegroundColor White
Write-Host "`nIMPORTANT NEXT STEPS:" -ForegroundColor Cyan
Write-Host "1. Open 'Edit the system environment variables'"
Write-Host "2. Edit the 'Path' variable in System Variables"
Write-Host "3. Add 'C:\trivy' to the list"
Write-Host "4. RESTART VS Code completely" -ForegroundColor Yellow
Write-Host "--------------------------------------------"

