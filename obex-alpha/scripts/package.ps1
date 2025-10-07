param(
  [string]$WorkspaceRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$OutDir = (Join-Path $PSScriptRoot "dist"),
  [string]$NetworkId = "obex-alpha-testnet"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Push-Location $WorkspaceRoot

Write-Host "Building release binaries..."
cargo build --release -p obex_node -p obex_tool | Out-Host

$bins = @(
  (Join-Path $WorkspaceRoot "target/release/obex_node.exe"),
  (Join-Path $WorkspaceRoot "target/release/obex_tool.exe")
)

foreach ($b in $bins) {
  if (Test-Path $b) {
    Copy-Item $b -Destination $OutDir -Force
    $sha = Get-FileHash -Algorithm SHA256 $b
    $name = Split-Path $b -Leaf
    Set-Content -Path (Join-Path $OutDir ("$name.sha256")) -Value $sha.Hash -Encoding ascii
  }
}

Write-Host "Bundling genesis and peers..."
$genesisSrc = Join-Path $WorkspaceRoot "genesis/genesis.toml"
$genesisDst = Join-Path $OutDir "genesis.toml"
Copy-Item $genesisSrc -Destination $genesisDst -Force

# Placeholder "signing" by embedding a SHA256 of genesis
$gsha = Get-FileHash -Algorithm SHA256 $genesisDst
Set-Content -Path (Join-Path $OutDir "genesis.toml.sha256") -Value $gsha.Hash -Encoding ascii

# Peer seeds (placeholder empty list; populate as needed)
Set-Content -Path (Join-Path $OutDir "peers.txt") -Value "" -Encoding ascii

# Operator runbook
$runbook = @"
Obex Alpha — Operator Runbook

Start node:
  obex_node --listen 0.0.0.0:8080 --data-dir data/obex-node --peers <comma-separated URLs>

Health & Observability:
  GET /healthz → readiness
  GET /metrics → OpenMetrics text

Endpoints:
  GET /alpha_i/{slot}/{pk}
  GET /alpha_i_index/{slot}
  GET /alpha_iii/{slot}
  GET /header/{slot}
  POST /header
  POST /advance

Notes:
  - Beacon v1 (hash-edge) enforced
  - Size caps enforced before crypto
  - Header-first validation; pulls α-III leaves and α-I records when peers expose indexes
"@

Set-Content -Path (Join-Path $OutDir "RUNBOOK.txt") -Value $runbook -Encoding utf8

Write-Host "Packaging complete: $OutDir"
Pop-Location


