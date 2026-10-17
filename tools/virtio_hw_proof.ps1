# tools/virtio_hw_proof.ps1 — TASK-104 hardware-truth virtio-blk under QEMU.
#
# Builds/packages the enterprise kernel and boots with a real
# virtio-blk-pci device (via factory_builder qemu_smoke, which now
# always attaches vd0). Asserts `VIRTIO_HW probe OK blk=found`.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\virtio_hw_proof.ps1

$ErrorActionPreference = 'Continue'
cargo test -p factory_builder --test qemu_smoke -- --ignored --nocapture boots_under_qemu_and_emits_banner
exit $LASTEXITCODE
