# tools/bundle_morph_proof.ps1 — full [bundle.kernel] morph + QEMU proof (TASK-103).
#
# Parses scheduler.toml enrollment, diversifies every module (stack-pad
# off), builds the enterprise kernel under a layout seed, boots QEMU,
# asserts composition + high-value banners, restores pristines.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\bundle_morph_proof.ps1
#
# Requires: QEMU, nightly + rust-src for x86_64-unknown-none, factory_builder_pkg.
# Wall-clock: typically 1–3 minutes depending on module count and cold caches.

$ErrorActionPreference = 'Continue'
$env:PROTEUS_BUNDLE_MORPH_PROOF = '1'
cargo test -p diversity_demo --test bundle_morph_proof -- --nocapture
exit $LASTEXITCODE
