# tools/soak_short.ps1 — short morph-daemon soak (3 accept cycles).
#
# From workspace root:
#   powershell -ExecutionPolicy Bypass -File tools\soak_short.ps1
#   powershell -ExecutionPolicy Bypass -File tools\soak_short.ps1 -Iters 5

param(
    [int]$Iters = 3
)

$ErrorActionPreference = 'Continue'
$env:CUTTLE_SOAK_SHORT = '1'
$env:CUTTLE_SOAK_ITERS = "$Iters"
cargo test -p cuttle-morph-engine --test soak_short -- --nocapture
exit $LASTEXITCODE
