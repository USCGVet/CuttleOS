# tools/seal_factory_baselines.ps1 — seal factory baselines into a seals dir
# (TASK-149).
#
# One command produces DurableSeal JSON for fleet morph attach without
# hand-running `morph seal` per file.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\seal_factory_baselines.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\seal_factory_baselines.ps1 -DryRun
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\seal_factory_baselines.ps1 -OutDir path\to\seals
#
# After a real write, sets nothing permanently; prints:
#   $env:CUTTLE_DURABLE_SEALS_DIR = '<abs path>'
#
# Files sealed (when present at workspace root):
#   factory_expected.toml  → factory_expected.json  (label: factory_expected)
#   scheduler.toml         → scheduler.json         (label: scheduler)
#
# Roundtrips each written seal with `morph verify-seal` (unless -DryRun).

param(
    [string]$OutDir = "seals",
    [switch]$DryRun,
    # Also seal paths relative to workspace root (label = leaf basename without ext).
    [string[]]$Extra = @()
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Resolve-Morph {
    $exe = Join-Path $Root "target\debug\morph.exe"
    if (Test-Path $exe) { return $exe }
    $exeRel = Join-Path $Root "target\release\morph.exe"
    if (Test-Path $exeRel) { return $exeRel }
    # Build debug morph once.
    Write-Host "seal_factory_baselines: building morph (debug)..."
    & cargo build -p cuttle-morph-engine --bin morph --quiet
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build morph failed exit=$LASTEXITCODE"
    }
    if (-not (Test-Path $exe)) {
        throw "morph binary missing after build: $exe"
    }
    return $exe
}

$targets = @(
    @{ Path = "factory_expected.toml"; Label = "factory_expected"; OutName = "factory_expected.json" },
    @{ Path = "scheduler.toml";        Label = "scheduler";        OutName = "scheduler.json" }
)
foreach ($e in $Extra) {
    if ([string]::IsNullOrWhiteSpace($e)) { continue }
    $leaf = [System.IO.Path]::GetFileNameWithoutExtension($e)
    if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = "extra" }
    $targets += @{
        Path    = $e
        Label   = $leaf
        OutName = "$leaf.json"
    }
}

$outAbs = if ([System.IO.Path]::IsPathRooted($OutDir)) {
    $OutDir
} else {
    Join-Path $Root $OutDir
}

Write-Host "seal_factory_baselines: root=$Root"
Write-Host "seal_factory_baselines: out=$outAbs dry_run=$DryRun"

$present = @()
foreach ($t in $targets) {
    $src = Join-Path $Root $t.Path
    if (Test-Path $src) {
        $present += [pscustomobject]@{
            Src     = $src
            Label   = $t.Label
            OutName = $t.OutName
            Rel     = $t.Path
        }
    } else {
        Write-Host "  SKIP missing: $($t.Path)"
    }
}

if ($present.Count -eq 0) {
    Write-Error "no baseline files found (expected factory_expected.toml and/or scheduler.toml)"
    exit 2
}

if ($DryRun) {
    Write-Host "DRY-RUN would seal:"
    foreach ($p in $present) {
        Write-Host "  $($p.Label)  $($p.Rel)  ->  $(Join-Path $outAbs $p.OutName)"
    }
    Write-Host ""
    Write-Host "# After real run, attach on morph/daemon/soak:"
    Write-Host "`$env:CUTTLE_DURABLE_SEALS_DIR = '$outAbs'"
    exit 0
}

New-Item -ItemType Directory -Force -Path $outAbs | Out-Null
$morph = Resolve-Morph

$sealed = 0
foreach ($p in $present) {
    $sealPath = Join-Path $outAbs $p.OutName
    Write-Host "  seal: label=$($p.Label) in=$($p.Rel) out=$sealPath"
    & $morph seal --label $p.Label --in $p.Src --out $sealPath
    if ($LASTEXITCODE -ne 0) {
        throw "morph seal failed for $($p.Label) exit=$LASTEXITCODE"
    }
    & $morph verify-seal --seal $sealPath --in $p.Src
    if ($LASTEXITCODE -ne 0) {
        throw "morph verify-seal failed for $($p.Label) exit=$LASTEXITCODE"
    }
    $sealed++
}

Write-Host ""
Write-Host "seal_factory_baselines: sealed $sealed file(s) into $outAbs"
Write-Host "# Attach on morph cycle / daemon / north-star soak:"
Write-Host "`$env:CUTTLE_DURABLE_SEALS_DIR = '$outAbs'"
Write-Host "# Optional scorecard gate (TASK-148):"
Write-Host "`$env:CUTTLE_VERIFY_REQUIRE_DURABLE_SEALS = '1'"
Write-Host "# Optional soak gate (TASK-150):"
Write-Host "`$env:CUTTLE_SOAK_REQUIRE_DURABLE_SEALS = '1'"
exit 0
