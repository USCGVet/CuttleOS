# tools/check_environment.ps1 — verify the Cuttle dev environment is sane.
#
# Reports GREEN/RED status for each item the hourly loop depends on:
#   - Defender path exclusions for Cuttle + RustOSa + cargo registry + Temp
#   - PowerShell execution policy (CurrentUser scope)
#   - QEMU on PATH or at the known fallback location
#   - cargo + rustc available
#   - nightly toolchain installed (needed for factory_builder_pkg + target_enterprise_kernel)
#
# Read-only. Safe to run any time, no elevation needed.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\check_environment.ps1
#   powershell -ExecutionPolicy Bypass -File tools\check_environment.ps1 -Json

[CmdletBinding()]
param([switch]$Json)

$results = @()

function Add-Result($name, $ok, $detail) {
    $script:results += [pscustomobject]@{ name = $name; ok = $ok; detail = $detail }
}

# 1. Defender path exclusions. Non-admin shells can only read the exclusion
#    list partially — Get-MpPreference returns null for ExclusionPath when not
#    elevated. We flag that case distinctly so the user knows the result is
#    "unknown" not "missing".
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
$elevated = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$required = @(
    'D:\RustProjects\Cuttle',
    'D:\RustProjects\RustOSa',
    "$env:USERPROFILE\.cargo\registry",
    "$env:LOCALAPPDATA\Temp"
)

if (-not $elevated) {
    foreach ($r in $required) {
        Add-Result "defender_path[$r]" $false 'UNKNOWN - re-run as Admin to verify, or run tools\add_defender_exclusions.ps1 elevated'
    }
} else {
    try {
        $excl = (Get-MpPreference -ErrorAction Stop).ExclusionPath
        foreach ($r in $required) {
            $present = $excl -and ($excl -contains $r)
            Add-Result "defender_path[$r]" $present $(if ($present) { 'present' } else { 'MISSING - run tools\add_defender_exclusions.ps1 elevated' })
        }
    } catch {
        Add-Result "defender_path[*]" $false "Get-MpPreference failed: $($_.Exception.Message)"
    }
}

# 2. PowerShell execution policy (CurrentUser).
$policy = Get-ExecutionPolicy -Scope CurrentUser
$policyOk = ($policy -in @('RemoteSigned','Unrestricted','Bypass'))
Add-Result 'powershell_execution_policy' $policyOk "CurrentUser=$policy"

# 3. QEMU.
$qemu = Get-Command qemu-system-x86_64.exe -ErrorAction SilentlyContinue
if ($qemu) {
    Add-Result 'qemu_on_path' $true $qemu.Source
} else {
    $fallback = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
    if (Test-Path $fallback) {
        Add-Result 'qemu_fallback' $true $fallback
    } else {
        Add-Result 'qemu_on_path' $false 'not found; install QEMU 7+ for kernel smoke tests'
    }
}

# 4. cargo + rustc.
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
Add-Result 'cargo_on_path' ($null -ne $cargo) $(if ($cargo) { $cargo.Source } else { 'missing — install rustup' })

$rustc = Get-Command rustc -ErrorAction SilentlyContinue
Add-Result 'rustc_on_path' ($null -ne $rustc) $(if ($rustc) { $rustc.Source } else { 'missing' })

# 5. nightly toolchain (for factory_builder_pkg + target_enterprise_kernel).
if ($cargo) {
    $toolchains = & rustup toolchain list 2>&1
    $hasNightly = ($toolchains -join "`n") -match 'nightly'
    Add-Result 'rustup_nightly' $hasNightly $(if ($hasNightly) { 'installed' } else { 'missing — run: rustup toolchain install nightly --component rust-src' })

    # rust-src component on nightly (build-std needs it).
    $components = & rustup component list --toolchain nightly --installed 2>&1
    $hasRustSrc = ($components -join "`n") -match 'rust-src'
    Add-Result 'rustup_nightly_rust_src' $hasRustSrc $(if ($hasRustSrc) { 'installed' } else { 'missing — run: rustup component add rust-src --toolchain nightly' })
}

# 6. Workspace builds (cheap sanity, ~1s if already built).
if ($cargo) {
    Push-Location 'D:\RustProjects\Cuttle'
    try {
        $null = cargo build --workspace 2>&1
        $buildOk = ($LASTEXITCODE -eq 0)
        Add-Result 'workspace_builds' $buildOk $(if ($buildOk) { 'cargo build --workspace exit 0' } else { "exit $LASTEXITCODE" })
    } finally {
        Pop-Location
    }
}

# Output.
if ($Json) {
    $results | ConvertTo-Json -Compress
} else {
    Write-Host ""
    Write-Host "Cuttle environment check" -ForegroundColor Cyan
    Write-Host "=========================="
    $green = 0; $red = 0
    foreach ($r in $results) {
        $color = if ($r.ok) { 'Green' } else { 'Red' }
        $glyph = if ($r.ok) { 'OK  ' } else { 'FAIL' }
        if ($r.ok) { $green++ } else { $red++ }
        Write-Host ("  [{0}] {1,-40} {2}" -f $glyph, $r.name, $r.detail) -ForegroundColor $color
    }
    Write-Host ""
    Write-Host "Summary: $green ok, $red failing" -ForegroundColor $(if ($red -eq 0) { 'Green' } else { 'Yellow' })
}

exit $(if (($results | Where-Object { -not $_.ok }).Count -eq 0) { 0 } else { 1 })
