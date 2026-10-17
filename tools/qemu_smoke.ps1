# tools/qemu_smoke.ps1 — token-efficient kernel boot + serial proof.
#
# Packages target_enterprise_kernel, boots it under QEMU, captures the serial
# log, and emits ONE summary line:
#     boot=OK image_sha=abc12345 log_sha=def67890 banners=2 log=<path>
#
# Or on failure:
#     boot=FAIL reason=<message> log=<path>
#
# Banner-required: the log must contain "PROTEUS-TE OK" (boot) and
# "PROTEUS-TE HALT" (clean exit). Counts both; "banners=2" means both present.
#
# Usage:
#   powershell -File tools\qemu_smoke.ps1
#   powershell -File tools\qemu_smoke.ps1 -ExpectedBanners @("IOMMU init OK","DMA_MAP test OK")
#   powershell -File tools\qemu_smoke.ps1 -Json
#
# One-time setup (Windows defaults to Restricted):
#   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

[CmdletBinding()]
param(
    [string[]]$ExpectedBanners = @(),
    [switch]$Json,
    [int]$TimeoutSec = 30
)

$ErrorActionPreference = 'Continue'

# Delegates to the existing ignored smoke test. No stderr redirect — Windows
# PowerShell 5.1 wraps native-command stderr as ErrorRecords. Cargo's stderr
# (warnings, errors) is visible directly to whoever runs this script.
$out = cargo test -p factory_builder --test qemu_smoke -- --ignored --nocapture boots_under_qemu_and_emits_banner
$exit = $LASTEXITCODE

# The smoke test prints lines like:
#   image_bytes=2589696 image_sha256=abc...
#   serial_log=<path>
#   observed: PROTEUS-TE OK
#   observed: PROTEUS-TE HALT
# We extract the values.

$imageSha = ($out | Select-String -Pattern 'image_sha256=([0-9a-f]+)' | Select-Object -First 1).Matches.Groups[1].Value
$logPath  = ($out | Select-String -Pattern 'serial_log=(.+)$' | Select-Object -First 1).Matches.Groups[1].Value

if (-not $imageSha) { $imageSha = 'unknown' }
if (-not $logPath)  { $logPath  = 'unknown' }

# Compute log sha256 + count banners.
$logSha = 'missing'
$bannerCount = 0
$missingBanners = @()
if ($logPath -ne 'unknown' -and (Test-Path $logPath)) {
    $logSha = (Get-FileHash -Algorithm SHA256 -Path $logPath).Hash.ToLower().Substring(0, 16)
    $logText = Get-Content -Raw -Path $logPath -ErrorAction SilentlyContinue
    if ($logText -match 'PROTEUS-TE OK')   { $bannerCount++ } else { $missingBanners += 'PROTEUS-TE OK' }
    if ($logText -match 'PROTEUS-TE HALT') { $bannerCount++ } else { $missingBanners += 'PROTEUS-TE HALT' }
    foreach ($b in $ExpectedBanners) {
        if ($logText -match [regex]::Escape($b)) { $bannerCount++ } else { $missingBanners += $b }
    }
}

$boot = if ($exit -eq 0 -and $missingBanners.Count -eq 0) { 'OK' } else { 'FAIL' }
$reason = if ($missingBanners.Count -gt 0) { "missing_banners=$($missingBanners -join '|')" } else { '' }

if ($Json) {
    $obj = @{
        boot         = $boot
        image_sha    = $imageSha.Substring(0, [Math]::Min(16, $imageSha.Length))
        log_sha      = $logSha
        banners      = $bannerCount
        log          = $logPath
        exit         = $exit
    }
    if ($reason) { $obj.reason = $reason }
    $obj | ConvertTo-Json -Compress
} else {
    if ($boot -eq 'OK') {
        "boot=OK image_sha=$($imageSha.Substring(0,[Math]::Min(16,$imageSha.Length))) log_sha=$logSha banners=$bannerCount log=$logPath"
    } else {
        "boot=FAIL $reason log=$logPath exit=$exit"
    }
}

exit $(if ($boot -eq 'OK') { 0 } else { 1 })
