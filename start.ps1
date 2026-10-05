# ============================================================
#  ShieldDesk -- One-Command Dev Launcher
#  Starts: Ollama LLM | Python CVE Brain | Next.js UI
#  Usage:  .\start.ps1
#  Stop:   Ctrl+C  (kills all three automatically)
# ============================================================

$ErrorActionPreference = "Continue"
$ROOT   = $PSScriptRoot
$PYTHON = Join-Path $ROOT "ai-chat-desk"

function Write-Banner {
    Write-Host ""
    Write-Host "  =================================================" -ForegroundColor DarkGreen
    Write-Host "   ShieldDesk  --  AI Security Operations Platform" -ForegroundColor Green
    Write-Host "              by Mints Global" -ForegroundColor DarkGray
    Write-Host "  =================================================" -ForegroundColor DarkGreen
    Write-Host ""
}

function Write-Status {
    param($Icon, $Label, $Msg, $Color)
    Write-Host "  $Icon  " -NoNewline -ForegroundColor $Color
    Write-Host "$Label" -NoNewline -ForegroundColor White
    Write-Host " -- $Msg" -ForegroundColor DarkGray
}

# ---- Prerequisite checks -----------------------------------
function Check-Prerequisites {
    Write-Host "  Checking prerequisites..." -ForegroundColor DarkGray
    $missing = @()
    if (-not (Get-Command "ollama"  -ErrorAction SilentlyContinue)) { $missing += "ollama  (https://ollama.com)" }
    if (-not (Get-Command "python"  -ErrorAction SilentlyContinue)) { $missing += "python  (Python 3.10+)" }
    if (-not (Get-Command "node"    -ErrorAction SilentlyContinue)) { $missing += "node    (Node.js 20+)" }
    if ($missing.Count -gt 0) {
        Write-Host ""
        Write-Host "  [MISSING TOOLS]" -ForegroundColor Red
        $missing | ForEach-Object { Write-Host "      * $_" -ForegroundColor Yellow }
        Write-Host ""
        exit 1
    }
    Write-Host "  [OK] All tools found." -ForegroundColor Green
}

# ---- Start a background job ---------------------------------
function Start-Service {
    param($Name, $Cmd, $WorkDir)
    $job = Start-Job -Name $Name -ScriptBlock {
        param($dir, $command)
        Set-Location $dir
        Invoke-Expression $command 2>&1
    } -ArgumentList $WorkDir, $Cmd
    return $job
}

# ---- Wait for a TCP port to open ---------------------------
function Wait-ForPort {
    param($Port, $Label, $TimeoutSec = 90)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect("127.0.0.1", $Port)
            $tcp.Close()
            Write-Status "OK" $Label "ready on port $Port" "Green"
            return $true
        } catch {
            Start-Sleep -Milliseconds 700
        }
    }
    Write-Status "!!" $Label "did not start within ${TimeoutSec}s" "Red"
    return $false
}

# ---- Stream all job output until Ctrl+C --------------------
function Stream-Jobs {
    param($Jobs)
    while ($true) {
        foreach ($job in $Jobs) {
            $lines = Receive-Job $job -ErrorAction SilentlyContinue
            if ($lines) {
                $prefix = switch ($job.Name) {
                    "Ollama"      { "[Ollama    ] " }
                    "PythonBrain" { "[Python AI ] " }
                    "NextJS"      { "[Next.js   ] " }
                    "GoScanner"   { "[Go Scanner] " }
                    default       { "[Service   ] " }
                }
                $col = switch ($job.Name) {
                    "Ollama"      { "Magenta" }
                    "PythonBrain" { "Yellow"  }
                    "NextJS"      { "Cyan"    }
                    "GoScanner"   { "Green"   }
                    default       { "White"   }
                }
                $lines -split "`n" | Where-Object { $_.Trim() -ne "" } | ForEach-Object {
                    Write-Host "$prefix$_" -ForegroundColor $col
                }
            }
        }
        Start-Sleep -Milliseconds 300
    }
}

# ---- Cleanup on Ctrl+C / exit ------------------------------
function Stop-AllServices {
    param($Jobs)
    Write-Host ""
    Write-Host "  Stopping all ShieldDesk services..." -ForegroundColor DarkGray
    foreach ($job in $Jobs) {
        Stop-Job   $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        Write-Host "  [STOPPED] $($job.Name)" -ForegroundColor DarkGray
    }
    # Kill any child processes that outlived the jobs
    Get-Process -Name "ollama" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "  All services stopped. Goodbye!" -ForegroundColor DarkGreen
    Write-Host ""
}

# ============================================================
#  MAIN
# ============================================================

Write-Banner
Check-Prerequisites

Write-Host ""
Write-Host "  Launching services..." -ForegroundColor White
Write-Host ""

# Verify Trivy scanner readiness
$hasTrivy = (Get-Command "trivy" -ErrorAction SilentlyContinue) -or (Test-Path "$ROOT\tools\trivy\trivy.exe") -or (Test-Path "C:\trivy\trivy.exe")
if ($hasTrivy) {
    Write-Status "OK" "Trivy Engine" "native scanner detected" "Green"
} else {
    Write-Host "  [WARN] Trivy binary missing. Run 'npm run setup:trivy' to download scanner." -ForegroundColor Yellow
}

$ollamaJob = Start-Service "Ollama"      "ollama serve"   $ROOT
$pythonJob = Start-Service "PythonBrain" "python server.py" $PYTHON
$nextJob   = Start-Service "NextJS"      "npm run dev"    $ROOT

$allJobs = @($ollamaJob, $pythonJob, $nextJob)

Write-Host ""
Write-Host "  Waiting for all ports to open..." -ForegroundColor DarkGray
Write-Host ""

$ok1 = Wait-ForPort 11434 "Ollama LLM"
$ok2 = Wait-ForPort 8000  "Python CVE Brain"
$ok3 = Wait-ForPort 3000  "Next.js UI"

Write-Host ""
if ($ok1 -and $ok2 -and $ok3) {
    Write-Host "  [ALL UP] All services are running!" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Some services may not have started -- check logs below." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  +-------------------------------------------------+" -ForegroundColor DarkGreen
Write-Host "  |  ShieldDesk UI   -->  http://localhost:3000     |" -ForegroundColor Green
Write-Host "  |  Python AI Brain -->  http://localhost:8000     |" -ForegroundColor Yellow
Write-Host "  |  Trivy Scanner   -->  Embedded (/api/scans)     |" -ForegroundColor Green
Write-Host "  |  Ollama LLM      -->  http://localhost:11434    |" -ForegroundColor Magenta
Write-Host "  +-------------------------------------------------+" -ForegroundColor DarkGreen
Write-Host ""
Write-Host "  Press Ctrl+C to stop everything." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  ---- Live Logs Below ----" -ForegroundColor DarkGray
Write-Host ""

try {
    Stream-Jobs $allJobs
} finally {
    Stop-AllServices $allJobs
}
