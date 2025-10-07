param(
  [string]$WorkspaceRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"

Write-Host "Running benches..."
Push-Location $WorkspaceRoot
cargo bench | Out-Host

# Extract gates from PERF_GATES.md
$gates = Get-Content (Join-Path (Split-Path -Parent $WorkspaceRoot) "PERF_GATES.md") -Raw

function Get-ThresholdMs {
  param([string]$pattern)
  $m = [regex]::Match($gates, $pattern)
  if ($m.Success) { return [int]$m.Groups[1].Value }
  return $null
}

$gate_alpha_i_ms = Get-ThresholdMs "α\-I verify .*?≤\s*(\d+) ms"
$gate_header_ms = Get-ThresholdMs "header_validate .*?≤\s*(\d+) ms"

if (-not $gate_alpha_i_ms) { $gate_alpha_i_ms = 70 }
if (-not $gate_header_ms) { $gate_header_ms = 100 }

# Read Criterion estimates (mean point estimate, ns)
function Read-MeanNs {
  param([string]$nameOrPrefix)
  $critRoot = Join-Path $WorkspaceRoot "target/criterion"
  if (-not (Test-Path $critRoot)) { return $null }
  # Prefer exact match, else first starting-with match
  $exact = Join-Path $critRoot $nameOrPrefix
  $candPaths = @()
  if (Test-Path $exact) { $candPaths += $exact }
  $candPaths += (Get-ChildItem -Path $critRoot -Directory -Filter ("{0}*" -f $nameOrPrefix) | Select-Object -ExpandProperty FullName)
  foreach ($c in $candPaths | Select-Object -Unique) {
    $est = Join-Path $c "new/estimates.json"
    if (Test-Path $est) {
      $json = Get-Content $est -Raw | ConvertFrom-Json
      if ($json.mean.point_estimate) { return [double]$json.mean.point_estimate }
    }
  }
  return $null
}

$alpha_i_ns = Read-MeanNs "alpha_i_verify"
$header_ns = Read-MeanNs "validate_header"

if (-not $alpha_i_ns -or -not $header_ns) {
  Write-Error "Missing Criterion estimates. Ensure benches ran and paths exist."
}

$alpha_i_ms = [math]::Round($alpha_i_ns / 1e6, 2)
$header_ms = [math]::Round($header_ns / 1e6, 2)

Write-Host ("α-I verify mean: {0} ms (gate ≤ {1} ms)" -f $alpha_i_ms, $gate_alpha_i_ms)
Write-Host ("header_validate mean: {0} ms (gate ≤ {1} ms)" -f $header_ms, $gate_header_ms)

$fail = $false
if ($alpha_i_ms -gt $gate_alpha_i_ms) { $fail = $true; Write-Warning "α-I verify exceeded gate." }
if ($header_ms -gt $gate_header_ms) { $fail = $true; Write-Warning "header_validate exceeded gate." }

Pop-Location
if ($fail) { exit 1 } else { Write-Host "Perf gates OK"; exit 0 }


