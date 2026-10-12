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
    if (-not (Get-Command "python"  -ErrorAction SilentlyContinue)) { $missing += "python  (Python 3.10+)" }
    if (-not (Get-Command "node"    -ErrorAction SilentlyContinue)) { $missing += "node    (Node.js 20+)" }
    if ($missing.Count -gt 0) {
        Write-Host ""
        Write-Host "  [MISSING TOOLS]" -ForegroundColor Red
        $missing | ForEach-Object { Write-Host "      * $_" -ForegroundColor Yellow }
        Write-Host ""
        exit 1
    }
    if (-not (Get-Command "ollama" -ErrorAction SilentlyContinue)) {
        Write-Host "  [INFO] ollama CLI not detected (optional for cloud/deterministic AI fallback)." -ForegroundColor DarkYellow
    }
    Write-Host "  [OK] Required tools verified." -ForegroundColor Green
}

# ---- Load Environment Variables (.env.local / .env) ---------
$envMap = @{}
$envCandidates = @(Join-Path $ROOT ".env.local"), @(Join-Path $ROOT ".env")
foreach ($ef in $envCandidates) {
    if (Test-Path $ef) {
        Get-Content $ef | Where-Object { $_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$' -and $_ -notmatch '^\s*#' } | ForEach-Object {
            $k = $Matches[1].Trim()
            $v = $Matches[2].Trim()
            $v = $v -replace '^["'']|["'']$', ''
            if (-not $envMap.ContainsKey($k)) {
                $envMap[$k] = $v
            }
        }
    }
}

# ---- Start a background job ---------------------------------
function Start-Service {
    param($Name, $Cmd, $WorkDir, $EnvVars = $null)
    $job = Start-Job -Name $Name -ScriptBlock {
        param($dir, $command, $vars)
        if ($vars) {
            foreach ($key in $vars.Keys) {
                [System.Environment]::SetEnvironmentVariable($key, $vars[$key], "Process")
            }
        }
        Set-Location $dir
        Invoke-Expression $command 2>&1
    } -ArgumentList $WorkDir, $Cmd, $EnvVars
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
                    "NATS"        { "[NATS      ] " }
                    "Ollama"      { "[Ollama    ] " }
                    "PythonBrain" { "[Python AI ] " }
                    "NextJS"      { "[Next.js   ] " }
                    "GoScanner"   { "[Go Scanner] " }
                    "GoThreat"    { "[Go Threat ] " }
                    "GoWebhook"   { "[Go Webhook] " }
                    "GoIngest"    { "[Go Ingest ] " }
                    "GoPatch"     { "[SSH Patch ] " }
                    "GoAgent"     { "[Go Agent  ] " }
                    default       { "[Service   ] " }
                }
                $col = switch ($job.Name) {
                    "NATS"        { "Cyan"    }
                    "Ollama"      { "Magenta" }
                    "PythonBrain" { "Yellow"  }
                    "NextJS"      { "Cyan"    }
                    "GoScanner"   { "Green"   }
                    "GoThreat"    { "DarkCyan"}
                    "GoWebhook"   { "DarkYellow" }
                    "GoIngest"    { "Blue"    }
                    "GoPatch"     { "Green"   }
                    "GoAgent"     { "Green"   }
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
    Get-Process -Name "ollama", "ingest", "threat", "webhook", "orchestrator", "nats-server", "shielddesk-agent" -ErrorAction SilentlyContinue |
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

# Ensure no orphaned microservices from previous sessions are blocking ports
Get-Process -Name "ingest", "threat", "webhook", "orchestrator", "nats-server", "shielddesk-agent" -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

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

# Verify NATS JetStream server readiness
$natsLocal = Join-Path $ROOT "tools\nats\nats-server.exe"
$hasNats = (Get-Command "nats-server" -ErrorAction SilentlyContinue) -or (Test-Path $natsLocal)
$natsJob = $null
if ($hasNats) {
    Write-Status "OK" "NATS Engine" "server binary detected" "Green"
    $natsExe = if (Test-Path $natsLocal) { $natsLocal } else { "nats-server" }
    $natsData = Join-Path $ROOT "tools\nats\data"
    if (!(Test-Path $natsData)) { New-Item -ItemType Directory -Force -Path $natsData | Out-Null }
    $natsCmd = "cmd.exe /c `"`"$natsExe`" -js -sd `"$natsData`" -p 4222 -m 8222`""
    $natsJob = Start-Service "NATS" $natsCmd $ROOT $envMap
    Wait-ForPort 4222 "NATS JetStream" 20 | Out-Null
} else {
    Write-Host "  [INFO] NATS server not found. Run 'npm run setup:nats' to activate distributed streaming." -ForegroundColor DarkYellow
}

$hasOllama = [bool](Get-Command "ollama" -ErrorAction SilentlyContinue)
$ollamaJob = $null
if ($hasOllama) {
    $ollamaJob  = Start-Service "Ollama"      "ollama serve"   $ROOT        $envMap
} else {
    Write-Host "  [INFO] Skipping local Ollama process; cloud/API models active." -ForegroundColor DarkYellow
}
$pythonJob  = Start-Service "PythonBrain" "python server.py" $PYTHON    $envMap
$nextJob    = Start-Service "NextJS"      "npm run dev"    $ROOT        $envMap
$threatDir  = Join-Path $ROOT "services\threat"
$threatExe  = Join-Path $threatDir "threat.exe"
$threatCmd  = if (Test-Path $threatExe) { "cmd.exe /c threat.exe" } else { "go run ." }
$threatJob  = Start-Service "GoThreat"    $threatCmd       $threatDir   $envMap
$webhookDir = Join-Path $ROOT "services\webhooks"
$webhookExe = Join-Path $webhookDir "webhook.exe"
$webhookCmd = if (Test-Path $webhookExe) { "cmd.exe /c webhook.exe" } else { "go run ." }
$webhookJob = Start-Service "GoWebhook"   $webhookCmd      $webhookDir  $envMap
$ingestDir  = Join-Path $ROOT "services\ingest"
$ingestExe  = Join-Path $ingestDir "ingest.exe"
$ingestCmd  = if (Test-Path $ingestExe) { "cmd.exe /c ingest.exe" } else { "go run ." }
$ingestJob  = Start-Service "GoIngest"    $ingestCmd       $ingestDir   $envMap
$patchDir   = Join-Path $ROOT "ssh-patch-orchestrator"
$patchExe   = Join-Path $patchDir "orchestrator.exe"
$patchCmd   = if (Test-Path $patchExe) { "cmd.exe /c orchestrator.exe server --port 8006" } else { "go run ./cmd/orchestrator server --port 8006" }
$patchJob   = Start-Service "GoPatch"     $patchCmd        $patchDir    $envMap
$agentDir   = Join-Path $ROOT "agent"
$agentExe   = Join-Path $ROOT "bin\shielddesk-agent.exe"
$agentCmd   = if (Test-Path $agentExe) { "cmd.exe /c `"$agentExe`" -agent-id ea111111-1111-1111-1111-111111111111 -control-url http://localhost:3000" } else { "go run ./cmd -agent-id ea111111-1111-1111-1111-111111111111 -control-url http://localhost:3000" }
$agentJob   = Start-Service "GoAgent"     $agentCmd        $agentDir    $envMap

$allJobs = @($pythonJob, $nextJob, $threatJob, $webhookJob, $ingestJob, $patchJob, $agentJob)
if ($ollamaJob) { $allJobs += $ollamaJob }
if ($natsJob) { $allJobs += $natsJob }

Write-Host ""
Write-Host "  Waiting for all ports to open..." -ForegroundColor DarkGray
Write-Host ""

$ok1 = if ($hasOllama) { Wait-ForPort 11434 "Ollama LLM" } else { $true }
$ok2 = Wait-ForPort 8000  "Python CVE Brain"
$ok3 = Wait-ForPort 3000  "Next.js UI"
$ok4 = Wait-ForPort 8003  "Go Threat Engine"
$ok5 = Wait-ForPort 8080  "Go Webhook Service"
$ok6 = Wait-ForPort 8004  "Go Ingest Telemetry" 60
$ok7 = Wait-ForPort 8006  "SSH Patch Orchestrator" 30

Write-Host ""
if ($ok1 -and $ok2 -and $ok3 -and $ok4 -and $ok5 -and $ok6 -and $ok7) {
    Write-Host "  [ALL UP] All services are running!" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Some services may not have started -- check logs below." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  +-------------------------------------------------+" -ForegroundColor DarkGreen
Write-Host "  |  ShieldDesk UI   -->  http://localhost:3000     |" -ForegroundColor Green
Write-Host "  |  Python AI Brain -->  http://localhost:8000     |" -ForegroundColor Yellow
Write-Host "  |  Go Threat Engine-->  http://localhost:8003     |" -ForegroundColor Cyan
Write-Host "  |  Go Ingest & PII -->  http://localhost:8004     |" -ForegroundColor Blue
Write-Host "  |  SSH Patch Orch  -->  http://localhost:8006     |" -ForegroundColor Green
Write-Host "  |  Go Webhook Svc  -->  http://localhost:8080     |" -ForegroundColor DarkYellow
Write-Host "  |  Go Agent (EDR)  -->  Streaming FIN-WS-042      |" -ForegroundColor Green
if ($hasNats) {
Write-Host "  |  NATS JetStream  -->  http://localhost:8222     |" -ForegroundColor Cyan
}
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
