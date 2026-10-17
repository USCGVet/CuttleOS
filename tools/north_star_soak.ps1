# tools/north_star_soak.ps1 — north-star cadence soak (TASK-123/125/127 / G4–G6).
#
# N consecutive [bundle.kernel] morph cycles under the daemon:
#   diversify → verify → sign → deploy → attest
# Default N=5. Optional -Boot: leave sources morphed, layout-seeded kernel
# build, QEMU boot, require core banners + HALT (TASK-127).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\north_star_soak.ps1
#   powershell -ExecutionPolicy Bypass -File tools\north_star_soak.ps1 -Iters 1 -Boot
#   powershell -ExecutionPolicy Bypass -File tools\north_star_soak.ps1 -Iters 2 -EmitImage
#   # Durable seals (TASK-149/150): seal baselines first, then:
#   powershell -File tools\seal_factory_baselines.ps1
#   $env:PROTEUS_DURABLE_SEALS_DIR = (Resolve-Path seals).Path
#   powershell -File tools\north_star_soak.ps1 -Iters 1 -RequireDurableSeals
#
# Wall-clock: full enrolled kernel bundle × N workspace verifies
# (typically tens of minutes). -Boot adds kernel build + QEMU.
# Requires factory_signing_key.bin; -Boot also needs QEMU + nightly kernel.

param(
    [int]$Iters = 5,
    # TASK-126: build kernel ELF + binmorph per cycle (positional bps). Slow.
    [switch]$EmitImage,
    # TASK-127: after N accepts, QEMU-boot the still-morphed sources.
    [switch]$Boot,
    # TASK-150: post-verify require durable_seals on accepted entries.
    # Needs PROTEUS_DURABLE_SEALS_DIR set (or pass -SealsDir) during morph.
    [switch]$RequireDurableSeals,
    # Optional seals dir; sets PROTEUS_DURABLE_SEALS_DIR for the soak process.
    [string]$SealsDir = ""
)

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if ($Iters -lt 1 -or $Iters -gt 20) {
    Write-Error "Iters must be in 1..=20 (got $Iters)"
    exit 2
}

$env:PROTEUS_NORTH_STAR_SOAK = '1'
$env:PROTEUS_SOAK_ITERS = "$Iters"
if ($EmitImage) {
    $env:PROTEUS_SOAK_EMIT_IMAGE = '1'
    Write-Host "north_star_soak: EmitImage ON (kernel ELF per cycle)"
} else {
    Remove-Item Env:PROTEUS_SOAK_EMIT_IMAGE -ErrorAction SilentlyContinue
}
if ($Boot) {
    $env:PROTEUS_NORTH_STAR_BOOT = '1'
    Write-Host "north_star_soak: Boot ON (QEMU after soak)"
} else {
    Remove-Item Env:PROTEUS_NORTH_STAR_BOOT -ErrorAction SilentlyContinue
}
if ($SealsDir) {
    $abs = if ([System.IO.Path]::IsPathRooted($SealsDir)) {
        $SealsDir
    } else {
        Join-Path $Root $SealsDir
    }
    if (-not (Test-Path $abs)) {
        Write-Error "SealsDir does not exist: $abs (run tools\seal_factory_baselines.ps1 first)"
        exit 2
    }
    $env:PROTEUS_DURABLE_SEALS_DIR = (Resolve-Path $abs).Path
    Write-Host "north_star_soak: DURABLE_SEALS_DIR=$($env:PROTEUS_DURABLE_SEALS_DIR)"
}
if ($RequireDurableSeals) {
    $env:PROTEUS_SOAK_REQUIRE_DURABLE_SEALS = '1'
    Write-Host "north_star_soak: RequireDurableSeals ON"
} else {
    # Leave parent env alone if already set; only clear when switch off and we own it.
    if (-not $env:PROTEUS_SOAK_REQUIRE_DURABLE_SEALS) {
        Remove-Item Env:PROTEUS_SOAK_REQUIRE_DURABLE_SEALS -ErrorAction SilentlyContinue
    }
}

Write-Host "north_star_soak: iters=$Iters (full [bundle.kernel]; require_diversity; boot=$Boot; seals_req=$RequireDurableSeals)"
cargo test -p proteus-morph-engine --test north_star_soak -- --nocapture
exit $LASTEXITCODE
