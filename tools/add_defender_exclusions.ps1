# tools/add_defender_exclusions.ps1 — one-time Defender setup for Cuttle dev.
#
# Adds path exclusions so Microsoft Defender stops scanning cargo build output
# while it's being written. Without these, the symptoms are:
#   - "error finalizing incremental compilation session directory ... file in use"
#   - cargo builds 2-5x slower than they should be
#   - Smart App Control flags transient bootloader sub-binaries during the
#     nightly factory_builder_pkg build
#
# Idempotent — running twice is a no-op for already-present exclusions.
#
# REQUIRES ELEVATION. Add-MpPreference fails silently from a non-admin shell.
# Two ways to invoke:
#
#   1. Open PowerShell as Administrator, then:
#      cd D:\RustProjects\Cuttle
#      powershell -ExecutionPolicy Bypass -File tools\add_defender_exclusions.ps1
#
#   2. From a regular PowerShell, spawn an elevated child (triggers UAC):
#      Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy','Bypass','-File','D:\RustProjects\Cuttle\tools\add_defender_exclusions.ps1'

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "ERROR: not running as Administrator. Add-MpPreference requires elevation." -ForegroundColor Red
    Write-Host "Re-run with:"
    Write-Host "  Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy','Bypass','-File','$PSCommandPath'"
    exit 1
}

# Paths to exclude. Each is one filesystem subtree Defender will skip.
$paths = @(
    'D:\RustProjects\Cuttle',
    'D:\RustProjects\RustOSa',
    "$env:USERPROFILE\.cargo\registry",
    "$env:USERPROFILE\.cargo\git",
    "$env:LOCALAPPDATA\Temp"
)

# Optional: process exclusions. These cost more (Defender skips scanning files
# THIS PROCESS writes anywhere) but help if your workspace ever moves. We add
# the toolchain binaries that produce build artefacts.
$processes = @(
    'cargo.exe',
    'rustc.exe',
    'link.exe',
    'lld-link.exe',
    'rust-lld.exe'
)

$existing = (Get-MpPreference).ExclusionPath
$existingProcs = (Get-MpPreference).ExclusionProcess

Write-Host "=== Defender path exclusions ===" -ForegroundColor Cyan
foreach ($p in $paths) {
    if ($existing -and ($existing -contains $p)) {
        Write-Host "  already excluded: $p" -ForegroundColor DarkGray
    } else {
        try {
            Add-MpPreference -ExclusionPath $p -ErrorAction Stop
            Write-Host "  added:            $p" -ForegroundColor Green
        } catch {
            Write-Host "  FAILED:           $p ($($_.Exception.Message))" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "=== Defender process exclusions ===" -ForegroundColor Cyan
foreach ($proc in $processes) {
    if ($existingProcs -and ($existingProcs -contains $proc)) {
        Write-Host "  already excluded: $proc" -ForegroundColor DarkGray
    } else {
        try {
            Add-MpPreference -ExclusionProcess $proc -ErrorAction Stop
            Write-Host "  added:            $proc" -ForegroundColor Green
        } catch {
            Write-Host "  FAILED:           $proc ($($_.Exception.Message))" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Done. Verify with: powershell -ExecutionPolicy Bypass -File tools\check_environment.ps1" -ForegroundColor Cyan
