param(
  [Parameter(Mandatory = $true)]
  [string]$BackupPath
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
  throw "Backup file does not exist: $BackupPath"
}

$resolved = (Resolve-Path -LiteralPath $BackupPath).Path
$hash = Get-FileHash -LiteralPath $resolved -Algorithm SHA256
Write-Output "SHA256 $($hash.Hash)  $resolved"

if ([IO.Path]::GetExtension($resolved) -eq '.dump') {
  $pgRestore = Get-Command pg_restore -ErrorAction SilentlyContinue
  if (-not $pgRestore) { throw 'pg_restore is required to inspect PostgreSQL custom-format archives.' }
  & $pgRestore.Source --list $resolved | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'pg_restore could not read the archive directory.' }
  Write-Output 'PostgreSQL archive directory is readable.'
}
