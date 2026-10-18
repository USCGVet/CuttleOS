# tools/proof_scorecard.ps1 — run Cuttle proof bars and print a scorecard.
#
# Default (always-on): fast unit/poison gates + seal_baselines + durable_cap_bits
# (TASK-153/163). Mega-proofs (TASK-110/128): use -Mega or individual switches.
# Legacy full suite: -Full.
#
# Always-on bars (seconds, no QEMU):
#   static_poison_corpus, mtd_gate_unit, kernel_churn_gate_unit,
#   attest_diversity_v9, semantic_poison_enrolled, durable_cap_bits (TASK-163),
#   seal_baselines (TASK-153), north_star_soak_helpers
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\proof_scorecard.ps1
#   powershell -ExecutionPolicy Bypass -File tools\proof_scorecard.ps1 -Mega
#   powershell -ExecutionPolicy Bypass -File tools\proof_scorecard.ps1 -QemuSmoke -MorphedQemu
#   powershell -ExecutionPolicy Bypass -File tools\proof_scorecard.ps1 -NorthStarBoot
#
# Exit code:
#   0  — every *selected* bar PASSed (SKIP is ok for bars not requested)
#   1  — one or more selected bars FAILed
# PowerShell may surface cargo stderr as NativeCommandError; trust the
# printed [PASS]/[FAIL] lines and the final exit code from this script.
#
# --- Weekly mega automation (TASK-118 + TASK-128 + TASK-134) ---
# Needs QEMU on PATH and Defender exclusions
# (tools/add_defender_exclusions.ps1 once elevated).
# Full operator copy-paste: docs/runbook.md § Task Scheduler install.
#
#   # Preferred: wrapper logs exit code under experiments/scorecard_logs/
#   schtasks /Create /F /TN "CuttleWeeklyMega" `
#     /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File D:\rustprojects\cuttle\tools\run_mega_weekly.ps1" `
#     /SC WEEKLY /D SUN /ST 03:00
#
#   # Direct (no log file):
#   powershell -NoProfile -ExecutionPolicy Bypass `
#     -File D:\rustprojects\cuttle\tools\proof_scorecard.ps1 -Mega
#
#   # GitHub Actions-style (pwsh):
#   - name: Cuttle weekly mega
#     run: pwsh -File tools/proof_scorecard.ps1 -Mega
#
# -Mega selects (TASK-128):
#   always-on unit bars +
#   qemu_smoke, morphed_qemu_proof, bundle_morph_proof, verify_attest,
#   north_star_soak_boot (N=1 full [bundle.kernel] morph + diversity gate
#   + layout-seeded QEMU boot of still-morphed sources).
#
# Wall-clock (warm host, TCG, Defender exclusions on):
#   always-on only .............. seconds
#   -Mega (no cold kernel) ...... typically 15–45 minutes
#   -NorthStarBoot alone ........ ~1–5 minutes warm; longer cold
# Override soak length: $env:CUTTLE_SOAK_ITERS = "2" (default N=1 under -Mega/-NorthStarBoot).
#
# Optional verify gates on production workspace attest (TASK-125/148/151):
#   $env:CUTTLE_VERIFY_REQUIRE_DIVERSITY = "1"       # fail if accepted lack diversity
#   $env:CUTTLE_VERIFY_REQUIRE_DURABLE_SEALS = "1"   # fail if accepted lack durable_seals
# Default for both is OFF — Mega stays green without seals attached.
# To attach seals during morph/daemon/soak first:
#   powershell -File tools\seal_factory_baselines.ps1
#   $env:CUTTLE_DURABLE_SEALS_DIR = (Resolve-Path seals).Path
# See docs/runbook.md § Weekly + seal baselines + seals lived checklist.
#
# Optional morph+seals attach bar (TASK-158; ~1 min, not on -Mega default):
#   powershell -File tools\proof_scorecard.ps1 -SealCycle
#   # or: $env:CUTTLE_SCORECARD_SEAL_CYCLE = "1"

param(
    [switch]$Full,
    [switch]$Mega,
    [switch]$Mtd,
    [switch]$PoisonSemantic,
    [switch]$QemuSmoke,
    [switch]$MorphedQemu,
    [switch]$BundleMorphProof,
    [switch]$VerifyAttest,
    [switch]$SoakShort,
    [switch]$SoakBundleMini,
    [switch]$BundleSoakBoot,
    [switch]$NorthStarSoak,
    # TASK-127: full-bundle cadence soak + QEMU boot (sets NORTH_STAR_BOOT).
    [switch]$NorthStarBoot,
    # TASK-158: one target_minimal cycle with seals dir (slow-ish; default off).
    [switch]$SealCycle
)

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if ($Full) {
    $Mtd = $true
    $PoisonSemantic = $true
    $MorphedQemu = $true
    $SoakShort = $true
    $SoakBundleMini = $true
    $BundleSoakBoot = $true
    $QemuSmoke = $true
    $BundleMorphProof = $true
    $VerifyAttest = $true
    # TASK-127: cadence+boot is the stronger north-star bar (includes soak).
    $NorthStarBoot = $true
}

if ($Mega) {
    $QemuSmoke = $true
    $MorphedQemu = $true
    $BundleMorphProof = $true
    $VerifyAttest = $true
    # TASK-128: weekly mega includes north-star cadence+boot (G4-G6).
    # N=1 by default (see NorthStarBoot block); not a second 5-iter soak.
    $NorthStarBoot = $true
    # TASK-158: SealCycle stays opt-in (not on Mega) — ~1 min morph+verify.
}

# Env override for SealCycle without CLI switch.
if ($env:CUTTLE_SCORECARD_SEAL_CYCLE -eq "1") {
    $SealCycle = $true
}

$script:results = @()

function Add-Result {
    param($name, $status, $detail, $ms = 0)
    $script:results += [pscustomobject]@{
        Name   = $name
        Status = $status
        Detail = $detail
        Ms     = $ms
    }
    $time = if ($ms -gt 0) { " (${ms}ms)" } else { "" }
    Write-Host "[$status] $name - $detail$time"
}

function Run-CargoTest {
    param($label, [string[]]$cargoArgs, $envName, $envVal)
    if ($envName) {
        Set-Item -Path "Env:$envName" -Value $envVal
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $null = & cargo @cargoArgs 2>&1
    $code = $LASTEXITCODE
    $sw.Stop()
    if ($envName) {
        Remove-Item "Env:$envName" -ErrorAction SilentlyContinue
    }
    if ($code -eq 0) {
        Add-Result $label "PASS" "exit 0" $sw.ElapsedMilliseconds
    } else {
        Add-Result $label "FAIL" "exit $code" $sw.ElapsedMilliseconds
    }
}

Write-Host "=== Cuttle proof scorecard ==="
Write-Host "workspace: $Root"
if ($Mega) {
    Write-Host "mode: -Mega (TASK-128) — includes qemu_smoke, morphed_qemu,"
    Write-Host "      bundle_morph_proof, verify_attest, north_star_soak_boot"
    Write-Host "      expected wall: ~15–45 min warm TCG (QEMU required)"
}
if ($NorthStarBoot -and -not $Mega) {
    Write-Host "mode: -NorthStarBoot only (N=1 default unless CUTTLE_SOAK_ITERS set)"
}
Write-Host ""

Write-Host "-- always-on --"
Run-CargoTest "static_poison_corpus" @(
    "test", "-p", "cuttle-verifier", "--test", "poison_corpus",
    "poison_", "--", "--test-threads=1"
) $null $null

Run-CargoTest "mtd_gate_unit" @(
    "test", "-p", "diversity_demo", "--lib", "mtd_gate"
) $null $null

# TASK-122 / north-star G5: kernel churn gate unit thresholds (no QEMU).
Run-CargoTest "kernel_churn_gate_unit" @(
    "test", "-p", "diversity_demo", "--lib", "kernel_churn_gate"
) $null $null

# TASK-124/125 / north-star G3+G5: diversity evidence + require gate (no QEMU).
Run-CargoTest "attest_diversity_v9" @(
    "test", "-p", "cuttle-morph-engine", "--test", "attest_v9",
    "--", "--test-threads=1"
) $null $null

Run-CargoTest "semantic_poison_enrolled" @(
    "test", "-p", "cuttle-verifier", "--test", "poison_corpus",
    "semantic_poison_files"
) $null $null

# TASK-163: durable capability bit KATs (contract only; always-on, ms).
Run-CargoTest "durable_cap_bits" @(
    "test", "-p", "cuttle-contracts", "durable_cap_bits_kat",
    "--", "--test-threads=1"
) $null $null

# TASK-153: seal factory baselines (fast; always-on). seal+verify-seal via helper.
# Temp OutDir so operator workspace `seals/` is not clobbered.
$fe = Join-Path $Root "factory_expected.toml"
$sch = Join-Path $Root "scheduler.toml"
if (-not (Test-Path $fe) -and -not (Test-Path $sch)) {
    Add-Result "seal_baselines" "SKIP" "no factory_expected.toml or scheduler.toml"
} else {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $tmpSeals = Join-Path $env:TEMP ("cuttle_scorecard_seals_" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    $sealScript = Join-Path $Root "tools\seal_factory_baselines.ps1"
    # Run in-process so exit code is reliable; ignore stderr noise from cargo.
    try {
        & $sealScript -OutDir $tmpSeals *> $null
        $code = $LASTEXITCODE
    } catch {
        $code = 1
        Write-Host "seal_baselines: exception: $_"
    }
    $sw.Stop()
    if ($code -eq 0) {
        $n = @(Get-ChildItem -Path $tmpSeals -Filter "*.json" -ErrorAction SilentlyContinue).Count
        Add-Result "seal_baselines" "PASS" "sealed+verified $n baseline(s)" $sw.ElapsedMilliseconds
    } else {
        Add-Result "seal_baselines" "FAIL" "seal_factory_baselines exit $code" $sw.ElapsedMilliseconds
    }
    Remove-Item -Recurse -Force $tmpSeals -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "-- mega-proofs (use -Mega / -Full or per-switch) --"

if ($QemuSmoke) {
    Run-CargoTest "qemu_smoke" @(
        "test", "-p", "factory_builder", "--test", "qemu_smoke",
        "--", "--ignored", "--nocapture", "boots_under_qemu_and_emits_banner"
    ) $null $null
} else {
    Add-Result "qemu_smoke" "SKIP" "pass -QemuSmoke, -Mega, or -Full"
}

if ($MorphedQemu) {
    Run-CargoTest "morphed_qemu_proof" @(
        "test", "-p", "diversity_demo", "--test", "morphed_qemu_proof",
        "--", "--nocapture"
    ) "CUTTLE_MORPHED_QEMU_PROOF" "1"
} else {
    Add-Result "morphed_qemu_proof" "SKIP" "pass -MorphedQemu, -Mega, or -Full"
}

if ($BundleMorphProof) {
    Run-CargoTest "bundle_morph_proof" @(
        "test", "-p", "diversity_demo", "--test", "bundle_morph_proof",
        "--", "--nocapture"
    ) "CUTTLE_BUNDLE_MORPH_PROOF" "1"
} else {
    Add-Result "bundle_morph_proof" "SKIP" "pass -BundleMorphProof, -Mega, or -Full"
}

if ($VerifyAttest) {
    # TASK-130: prove the *workspace* production attest chain (not soak
    # CUTTLE_ATTEST_DIR). Default requires ext_tlv (v8+). Mixed/legacy
    # chains may need --allow-missing-ext-tlv; that is labeled explicitly
    # so Mega never silently treats legacy as strict.
    $attestLog = Join-Path $Root "attest.log.jsonl"
    if (-not (Test-Path $attestLog)) {
        Add-Result "verify_attest" "SKIP" "no workspace attest.log.jsonl (run morph cycles first)"
    } else {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $out = & cargo run -p cuttle-morph-engine --quiet -- verify-attest 2>&1 | Out-String
        $code = $LASTEXITCODE
        $sw.Stop()
        if ($code -eq 0) {
            # Prefer strict; optionally note diversity / durable seals if env set.
            $detail = ($out.Trim() -replace '\s+', ' ')
            $strictExtras = @()
            $strictFail = $null
            if ($env:CUTTLE_VERIFY_REQUIRE_DIVERSITY -eq "1") {
                $outD = & cargo run -p cuttle-morph-engine --quiet -- verify-attest --require-diversity 2>&1 | Out-String
                if ($LASTEXITCODE -eq 0) {
                    $strictExtras += "require-diversity"
                } else {
                    $strictFail = "strict ok but --require-diversity failed (mixed pre-v9?)"
                }
            }
            # TASK-148: fleets that always attach seals can opt in.
            if (-not $strictFail -and $env:CUTTLE_VERIFY_REQUIRE_DURABLE_SEALS -eq "1") {
                $outS = & cargo run -p cuttle-morph-engine --quiet -- verify-attest --require-durable-seals 2>&1 | Out-String
                if ($LASTEXITCODE -eq 0) {
                    $strictExtras += "require-durable-seals"
                } else {
                    $strictFail = "strict ok but --require-durable-seals failed (missing seals on accepted?)"
                }
            }
            if ($strictFail) {
                Add-Result "verify_attest" "FAIL" $strictFail $sw.ElapsedMilliseconds
            } elseif ($strictExtras.Count -gt 0) {
                Add-Result "verify_attest" "PASS" ("$detail +" + ($strictExtras -join " +")) $sw.ElapsedMilliseconds
            } else {
                Add-Result "verify_attest" "PASS" $detail $sw.ElapsedMilliseconds
            }
        } else {
            # Pre-v8 / mixed: explicit legacy path (never silent).
            $out2 = & cargo run -p cuttle-morph-engine --quiet -- verify-attest --allow-missing-ext-tlv 2>&1 | Out-String
            $code2 = $LASTEXITCODE
            if ($code2 -eq 0) {
                Add-Result "verify_attest" "PASS" "LEGACY allow-missing-ext-tlv (upgrade chain to v8+)" $sw.ElapsedMilliseconds
                Write-Host "verify_attest: WARN production chain lacks ext_tlv on some entries; re-morph to cut over"
            } else {
                Add-Result "verify_attest" "FAIL" "strict exit $code / legacy exit $code2" $sw.ElapsedMilliseconds
            }
        }
    }
} else {
    Add-Result "verify_attest" "SKIP" "pass -VerifyAttest, -Mega, or -Full"
}

Write-Host ""
Write-Host "-- optional soaks --"

if ($Mtd) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $null = & cargo run -p diversity_demo --quiet -- `
        --cycles 4 --target target_enterprise --module tls `
        --fast-mode --skip-verify --require-mtd-gate `
        --results experiments/diversity_demo/results/scorecard_mtd 2>&1
    $code = $LASTEXITCODE
    $sw.Stop()
    if ($code -eq 0) {
        Add-Result "mtd_require_gate_fast" "PASS" "require-mtd-gate exit 0" $sw.ElapsedMilliseconds
    } else {
        Add-Result "mtd_require_gate_fast" "FAIL" "exit $code" $sw.ElapsedMilliseconds
    }
} else {
    Add-Result "mtd_require_gate_fast" "SKIP" "pass -Mtd or -Full"
}

if ($PoisonSemantic) {
    Run-CargoTest "semantic_poison_e2e" @(
        "test", "-p", "cuttle-verifier", "--test", "poison_corpus",
        "semantic_poison_e2e_all_reject", "--", "--nocapture"
    ) "CUTTLE_VERIFIER_POISON_E2E" "1"
} else {
    Add-Result "semantic_poison_e2e" "SKIP" "pass -PoisonSemantic or -Full"
}

if ($SoakShort) {
    Run-CargoTest "soak_short_daemon" @(
        "test", "-p", "cuttle-morph-engine", "--test", "soak_short",
        "--", "--nocapture"
    ) "CUTTLE_SOAK_SHORT" "1"
} else {
    Add-Result "soak_short_daemon" "SKIP" "pass -SoakShort or -Full"
}

if ($SoakBundleMini) {
    Run-CargoTest "soak_bundle_mini" @(
        "test", "-p", "cuttle-morph-engine", "--test", "soak_bundle_mini",
        "--", "--nocapture"
    ) "CUTTLE_SOAK_BUNDLE_MINI" "1"
} else {
    Add-Result "soak_bundle_mini" "SKIP" "pass -SoakBundleMini or -Full"
}

if ($BundleSoakBoot) {
    Run-CargoTest "bundle_soak_boot" @(
        "test", "-p", "cuttle-morph-engine", "--test", "bundle_soak_boot",
        "--", "--nocapture"
    ) "CUTTLE_BUNDLE_SOAK_BOOT" "1"
} else {
    Add-Result "bundle_soak_boot" "SKIP" "pass -BundleSoakBoot or -Full"
}

# TASK-123 / north-star G6: N× full [bundle.kernel] daemon cadence.
# Always-on helpers run without the env gate; gated soak needs -NorthStarSoak.
Run-CargoTest "north_star_soak_helpers" @(
    "test", "-p", "cuttle-morph-engine", "--test", "north_star_soak",
    "--", "--nocapture"
) $null $null

if ($NorthStarSoak) {
    $env:CUTTLE_SOAK_ITERS = if ($env:CUTTLE_SOAK_ITERS) { $env:CUTTLE_SOAK_ITERS } else { "5" }
    Remove-Item Env:CUTTLE_NORTH_STAR_BOOT -ErrorAction SilentlyContinue
    Run-CargoTest "north_star_soak_daemon" @(
        "test", "-p", "cuttle-morph-engine", "--test", "north_star_soak",
        "north_star_bundle_kernel_daemon_soak", "--", "--nocapture"
    ) "CUTTLE_NORTH_STAR_SOAK" "1"
} else {
    Add-Result "north_star_soak_daemon" "SKIP" "pass -NorthStarSoak"
}

# TASK-127/128: cadence + boot one path (default 1 cycle under -Mega/-NorthStarBoot).
# Set CUTTLE_SOAK_ITERS to raise N. Requires QEMU + factory_signing_key.bin.
if ($NorthStarBoot) {
    if (-not $env:CUTTLE_SOAK_ITERS) {
        $env:CUTTLE_SOAK_ITERS = "1"
    }
    $env:CUTTLE_NORTH_STAR_BOOT = "1"
    Write-Host "north_star_soak_boot: CUTTLE_SOAK_ITERS=$($env:CUTTLE_SOAK_ITERS) BOOT=1"
    Run-CargoTest "north_star_soak_boot" @(
        "test", "-p", "cuttle-morph-engine", "--test", "north_star_soak",
        "north_star_bundle_kernel_daemon_soak", "--", "--nocapture"
    ) "CUTTLE_NORTH_STAR_SOAK" "1"
    Remove-Item Env:CUTTLE_NORTH_STAR_BOOT -ErrorAction SilentlyContinue
} else {
    Add-Result "north_star_soak_boot" "SKIP" "pass -NorthStarBoot, -Mega, or -Full"
}

# TASK-158: morph cycle attaches durable seals (integration; default SKIP).
if ($SealCycle) {
    Write-Host "seal_cycle: running cycle_durable_seals (~1 min cold verify)"
    Run-CargoTest "seal_cycle" @(
        "test", "-p", "cuttle-morph-engine", "--test", "cycle_durable_seals",
        "--", "--nocapture"
    ) $null $null
} else {
    Add-Result "seal_cycle" "SKIP" "pass -SealCycle or CUTTLE_SCORECARD_SEAL_CYCLE=1"
}

Write-Host ""
Write-Host "=== Scorecard ==="
$script:results | Format-Table -AutoSize

$fail = @($script:results | Where-Object { $_.Status -eq "FAIL" }).Count
$pass = @($script:results | Where-Object { $_.Status -eq "PASS" }).Count
$skip = @($script:results | Where-Object { $_.Status -eq "SKIP" }).Count
$totalMs = ($script:results | Measure-Object -Property Ms -Sum).Sum
Write-Host "summary: pass=$pass fail=$fail skip=$skip wall_ms=$totalMs"

# TASK-138: machine-readable summary for CI / dashboards.
$logDir = Join-Path $Root "experiments\scorecard_logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$bars = @()
foreach ($r in $script:results) {
    $bars += [ordered]@{
        name   = $r.Name
        status = $r.Status
        detail = $r.Detail
        ms     = [int]$r.Ms
    }
}
$mode = if ($Mega) { "Mega" } elseif ($Full) { "Full" } elseif ($NorthStarBoot) { "NorthStarBoot" } else { "Default" }
$summary = [ordered]@{
    schema    = 1
    mode      = $mode
    workspace = $Root
    ts_unix   = [int][double]::Parse((Get-Date -UFormat %s))
    pass      = $pass
    fail      = $fail
    skip      = $skip
    wall_ms   = [int64]$totalMs
    exit      = $(if ($fail -gt 0) { 1 } else { 0 })
    bars      = $bars
}
$jsonPath = Join-Path $logDir "scorecard_last.json"
($summary | ConvertTo-Json -Depth 6) | Set-Content -Path $jsonPath -Encoding utf8
Write-Host "scorecard json: $jsonPath"

if ($fail -gt 0) { exit 1 } else { exit 0 }
