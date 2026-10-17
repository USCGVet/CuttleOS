# tools/morphed_qemu_proof.ps1 — morphed-kernel QEMU proof (B2).
#
# Diversifies the load-bearing production path (tls/kat/net/tcp/http,
# wal/nvme/virtio_blk/ahci_*, vfs/quota, timer/tick/watchdog,
# attest_tlv/base64), builds under a per-cycle layout seed, boots
# QEMU, asserts feature banners + TIMEBASE / VFS+QUOTA / AHCI storage
# composition + PROTEUS-TE OK/HALT, restores pristines.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\morphed_qemu_proof.ps1
#
# Requires: QEMU, nightly + rust-src for x86_64-unknown-none, factory_builder_pkg.

$ErrorActionPreference = 'Continue'
$env:PROTEUS_MORPHED_QEMU_PROOF = '1'
cargo test -p diversity_demo --test morphed_qemu_proof -- --nocapture
exit $LASTEXITCODE
