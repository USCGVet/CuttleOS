# tools/run_mega_weekly.ps1 — wrapper for Task Scheduler / cron (TASK-134).
#
# Runs the weekly north-star scorecard (-Mega), tees output to
# experiments/scorecard_logs/mega_<timestamp>.log, exits with scorecard code.
#
# Install (elevated or user account that can build):
#   schtasks /Create /F /TN "ProteusWeeklyMega" `
#     /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File D:\rustprojects\proteus\tools\run_mega_weekly.ps1" `
#     /SC WEEKLY /D SUN /ST 03:00
#
# Manual:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\run_mega_weekly.ps1
#
# Optional pre-set envs (TASK-151; default off — leave unset for green Mega):
#   $env:PROTEUS_VERIFY_REQUIRE_DIVERSITY = "1"
#   $env:PROTEUS_VERIFY_REQUIRE_DURABLE_SEALS = "1"
#   $env:PROTEUS_DURABLE_SEALS_DIR = "D:\rustprojects\proteus\seals"  # after seal_factory_baselines.ps1

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$logDir = Join-Path $Root "experiments\scorecard_logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$log = Join-Path $logDir "mega_$stamp.log"

Write-Host "Proteus weekly mega starting; log=$log"
& powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File (Join-Path $Root "tools\proof_scorecard.ps1") -Mega *>&1 |
  Tee-Object -FilePath $log
$code = $LASTEXITCODE
Add-Content -Path $log -Value "`nEXIT=$code wall_end=$(Get-Date -Format o)"

# TASK-141: co-locate machine-readable summary with this run's log.
$jsonSrc = Join-Path $logDir "scorecard_last.json"
$jsonDst = Join-Path $logDir "mega_${stamp}.json"
if (Test-Path $jsonSrc) {
    Copy-Item -Force $jsonSrc $jsonDst
    Add-Content -Path $log -Value "SCORECARD_JSON=$jsonDst"
    Write-Host "scorecard json co-located: $jsonDst"
} else {
    Write-Host "WARN: scorecard_last.json missing after Mega"
}

Write-Host "Proteus weekly mega finished EXIT=$code"
exit $code
