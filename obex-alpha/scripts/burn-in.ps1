param(
  [int]$Slots = 10000,
  [string[]]$Nodes = @("http://127.0.0.1:8081","http://127.0.0.1:8082","http://127.0.0.1:8083","http://127.0.0.1:8084","http://127.0.0.1:8085"),
  [string]$OutDir = (Join-Path $PSScriptRoot "burnin")
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "Starting burn-in across $($Nodes.Length) nodes for $Slots slots..."

# Fetch parent header (slot 0) from first node and use obex_tool to drive slots
Push-Location (Split-Path -Parent $PSScriptRoot)
cargo run -p obex_tool -- BurnIn --slots $Slots --nodes ($Nodes -join ',') | Tee-Object -FilePath (Join-Path $OutDir "burnin.log")

# Capture /metrics from each node
foreach ($n in $Nodes) {
  $uri = "$n/metrics"
  try {
    $m = Invoke-WebRequest -Uri $uri -TimeoutSec 5 -UseBasicParsing
    $name = ($n -replace '[:/\\]','_') + "_metrics.txt"
    $m.Content | Out-File -FilePath (Join-Path $OutDir $name) -Encoding utf8
  } catch {
    Write-Warning "Failed to fetch metrics from $n"
  }
}

Write-Host "Burn-in complete. Logs and metrics in $OutDir"
Pop-Location


