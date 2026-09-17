# ShieldDesk Automated PostgreSQL Setup Script
param(
    [string]$SuperUser = "postgres",
    [string]$SuperPass = "shielddesk_dev",
    [string]$DbUser = "shielddesk",
    [string]$DbPass = "shielddesk_dev",
    [string]$DbName = "shielddesk",
    [string]$DbHost = "127.0.0.1",
    [string]$DbPort = "5432"
)

$ErrorActionPreference = "Stop"

$candidatePaths = @(
    "D:\postgres\bin\psql.exe",
    "C:\Program Files\PostgreSQL\16\bin\psql.exe",
    "C:\Program Files\PostgreSQL\17\bin\psql.exe",
    "psql.exe"
)

$psqlPath = $null
foreach ($cand in $candidatePaths) {
    if (Test-Path $cand) {
        $psqlPath = $cand
        break
    }
    if (Get-Command $cand -ErrorAction SilentlyContinue) {
        $psqlPath = $cand
        break
    }
}

if (-not $psqlPath) {
    Write-Host "PostgreSQL tool psql.exe was not found." -ForegroundColor Red
    exit 1
}

Write-Host "Using PostgreSQL tool at: $psqlPath" -ForegroundColor Green

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$schemaFile = Join-Path $scriptDir "db\schema.sql"
$seedFile   = Join-Path $scriptDir "db\seed.sql"

$env:PGPASSWORD = $SuperPass
Write-Host "Ensuring user and database exist..." -ForegroundColor Cyan
& $psqlPath -h $DbHost -p $DbPort -U $SuperUser -c "CREATE USER $DbUser WITH PASSWORD '$DbPass';" 2>$null
& $psqlPath -h $DbHost -p $DbPort -U $SuperUser -c "CREATE DATABASE $DbName OWNER $DbUser;" 2>$null
& $psqlPath -h $DbHost -p $DbPort -U $SuperUser -c "GRANT ALL PRIVILEGES ON DATABASE $DbName TO $DbUser;" 2>$null

Write-Host "Applying schema.sql..." -ForegroundColor Cyan
$env:PGPASSWORD = $DbPass
& $psqlPath -h $DbHost -p $DbPort -U $DbUser -d $DbName -f $schemaFile

Write-Host "Applying seed.sql..." -ForegroundColor Cyan
& $psqlPath -h $DbHost -p $DbPort -U $DbUser -d $DbName -f $seedFile

Write-Host "SUCCESS: Database is configured and seeded!" -ForegroundColor Green
& $psqlPath -h $DbHost -p $DbPort -U $DbUser -d $DbName -c "SELECT incident_code, severity, status, title FROM incidents;"
