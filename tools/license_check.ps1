# tools/license_check.ps1 — license gate for everything CuttleOS ships.
#
# 1. cargo deny (deny.toml) on all three Cargo workspaces: the main
#    workspace, the bare-metal kernel and the image packager. Fails on any
#    dependency outside the permissive allow list (no GPL/LGPL/AGPL/MPL...).
# 2. tools/third_party_notices.py --check: the bootloader stages, which
#    cargo deny cannot see, pass the same policy (plus its documented
#    exceptions), and THIRD_PARTY_NOTICES.md is current.
#
# Prints one line per check and exits non-zero if any fails.
#
# Usage:
#   powershell -File tools\license_check.ps1
#
# One-time setup:
#   cargo install cargo-deny --locked

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$config = Join-Path $root 'deny.toml'
$failed = $false

$workspaces = @(
    @{ Name = 'workspace'; Manifest = (Join-Path $root 'Cargo.toml') },
    @{ Name = 'kernel'; Manifest = (Join-Path $root 'target_enterprise_kernel\Cargo.toml') },
    @{ Name = 'packager'; Manifest = (Join-Path $root 'factory_builder_pkg\Cargo.toml') }
)
foreach ($ws in $workspaces) {
    $out = & cargo deny --manifest-path $ws.Manifest --config $config check licenses bans sources 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Output ("cargo-deny {0}: ok" -f $ws.Name)
    } else {
        $failed = $true
        Write-Output ("cargo-deny {0}: FAIL" -f $ws.Name)
        $out | ForEach-Object { Write-Output "  $_" }
    }
}

$notices = & python -I (Join-Path $PSScriptRoot 'third_party_notices.py') --check 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Output 'third-party notices: ok'
} else {
    $failed = $true
    Write-Output 'third-party notices: FAIL'
    $notices | ForEach-Object { Write-Output "  $_" }
}

if ($failed) { exit 1 }
exit 0
