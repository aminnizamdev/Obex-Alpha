$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

Write-Host "Building obex_node (release)..."
cargo build --release -p obex_node | Out-Host

New-Item -ItemType Directory -Force -Path (Join-Path $repo "data") | Out-Null

$pids = @()
for ($i = 1; $i -le 5; $i++) {
  $port = 8080 + $i
  $dir = Join-Path $repo ("data\node$($i)")
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $exe = Join-Path $repo "target\release\obex_node.exe"
  $args = @("--listen", "127.0.0.1:$port", "--data-dir", $dir)
  $proc = Start-Process -FilePath $exe -ArgumentList $args -PassThru -WindowStyle Hidden
  $pids += $proc.Id
}

Set-Content -Path (Join-Path $PSScriptRoot ".devnet_pids.txt") -Value ($pids -join "`n")
Write-Host ("Nodes started on 8081-8085. PIDs: {0}" -f ($pids -join ', '))


