param()
$ErrorActionPreference = 'Stop'

# Project root is two levels up from this script (..\..)
$root = (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent)
$out = Join-Path $root 'Superscript_Obex_Devnet_Complete.txt'
$tmp = $out + '.tmp'

if (Test-Path -LiteralPath $tmp) {
    Remove-Item -LiteralPath $tmp -Force
}

$files = Get-ChildItem -Path $root -Recurse -File | Where-Object {
    $_.FullName -ne $out -and
    $_.Name -ne 'System_Instructions.md' -and
    $_.Name -ne 'Superscript_Obex_Testnet.txt' -and
    $_.Name -ne 'Superscript_Obex_Devnet_Complete.txt'
}

${fs} = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
try {
    $enc = New-Object System.Text.UTF8Encoding($false)
    $sw = New-Object System.IO.StreamWriter(${fs}, $enc)
    try {
        foreach ($f in $files) {
            $rel = $f.FullName.Substring($root.Length + 1) -replace '[\\/]', '>'
            $body = $null
            try {
                # Prefer text as UTF-8 for readability
                $body = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8
            } catch {
                # Fallback to base64 for any non-text/binary or unreadable as UTF-8
                $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
                $body = [System.Convert]::ToBase64String($bytes)
            }
            $sw.WriteLine($rel)
            $sw.WriteLine($body)
            $sw.WriteLine()
        }
    } finally {
        $sw.Flush()
        $sw.Dispose()
    }
} finally {
    ${fs}.Dispose()
}

# Best-effort move into place; if the target is locked, leave the .tmp file for manual rename
try {
    if (Test-Path -LiteralPath $out) {
        Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    }
    Move-Item -LiteralPath $tmp -Destination $out -Force
} catch {
    Write-Host "Target in use, leaving output at $tmp"
}


