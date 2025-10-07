param(
    [string]$Remote = 'https://github.com/aminnizamdev/Obex-Alpha.git'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
Set-Location -LiteralPath $root

if (-not (Test-Path -LiteralPath (Join-Path $root '.git'))) {
    git init | Out-Null
}

# Ensure local user is set to allow committing in this repo context
try {
    git config user.name | Out-Null
} catch {
    git config user.name 'obex-local'
}
try {
    git config user.email | Out-Null
} catch {
    git config user.email 'obex-local@noreply.local'
}

# Prepare commit
git add -A
try {
    git commit -m 'sync: push current local state (APIs, docs, scripts, node updates)'
} catch {
    # No changes to commit or commit already exists
}

# Remote setup
try {
    $null = git remote get-url origin
    git remote set-url origin $Remote
} catch {
    git remote add origin $Remote
}

git branch -M main

# First attempt normal push
if (-not (git push --set-upstream origin main)) {
    # Retry with force-with-lease if non-fast-forward
    git push --force-with-lease --set-upstream origin main
}


