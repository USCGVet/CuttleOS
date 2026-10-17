# tools/bundle_soak_boot.ps1
# Mini-bundle daemon soak (tls/wal/net) then QEMU boot with layout seed.
param([int]$Iters = 2)
$ErrorActionPreference = 'Continue'
$env:PROTEUS_BUNDLE_SOAK_BOOT = '1'
$env:PROTEUS_SOAK_ITERS = "$Iters"
cargo test -p proteus-morph-engine --test bundle_soak_boot -- --nocapture
exit $LASTEXITCODE
