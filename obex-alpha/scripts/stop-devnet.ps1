$ErrorActionPreference = "Stop"

$pidFile = Join-Path $PSScriptRoot ".devnet_pids.txt"
if (-Not (Test-Path $pidFile)) {
  Write-Host "No PID file found."
  exit 0
}
$pids = Get-Content $pidFile | Where-Object { $_ -match '^\d+$' }
foreach ($pid in $pids) {
  try {
    Stop-Process -Id [int]$pid -Force -ErrorAction SilentlyContinue
  } catch {}
}
Remove-Item $pidFile -ErrorAction SilentlyContinue
Write-Host "Devnet stopped."


