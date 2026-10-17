# tools/soak_bundle_mini.ps1 — mini-bundle morph soak (tls+wal+net).
param([int]$Iters = 2)
$ErrorActionPreference = 'Continue'
$env:PROTEUS_SOAK_BUNDLE_MINI = '1'
$env:PROTEUS_SOAK_ITERS = "$Iters"
cargo test -p proteus-morph-engine --test soak_bundle_mini -- --nocapture
exit $LASTEXITCODE
