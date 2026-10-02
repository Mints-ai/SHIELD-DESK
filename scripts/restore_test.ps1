param(
  [Parameter(Mandatory = $true)]
  [string]$BackupPath,
  [Parameter(Mandatory = $true)]
  [string]$TargetDatabaseUrl
)

$ErrorActionPreference = 'Stop'
$parsed = [Uri]$TargetDatabaseUrl
$databaseName = [Uri]::UnescapeDataString(($parsed.AbsolutePath.TrimStart('/').Split('?')[0]))
if (-not $databaseName.StartsWith('shielddesk_restore_test_', [StringComparison]::OrdinalIgnoreCase)) {
  throw 'Restore target database name must begin with shielddesk_restore_test_.'
}
if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
  throw "Backup file does not exist: $BackupPath"
}

$pgRestore = Get-Command pg_restore -ErrorAction SilentlyContinue
if (-not $pgRestore) { throw 'pg_restore is required.' }
& $pgRestore.Source --no-owner --no-privileges --dbname=$TargetDatabaseUrl $BackupPath
if ($LASTEXITCODE -ne 0) { throw 'Restore failed. Inspect target logs before retrying.' }
Write-Output "Restore completed to explicitly disposable database '$databaseName'. Run application/schema checks and record observed RPO/RTO."
