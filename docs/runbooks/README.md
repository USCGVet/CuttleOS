# CuttleOS Triad Operational Runbooks & SLOs

This document provides step-by-step operational runbooks for every structured `ALERT` code emitted by [`tools/triad_controller.py`](../../tools/triad_controller.py) and [`tools/cuttle_fleet.py`](../../tools/cuttle_fleet.py), along with lifecycle procedures for key ceremony rotation/revocation, manual A/B slot recovery, and Service Level Objectives (SLOs).

---

## Service Level Objectives (SLOs)

| Metric | Prometheus Series | Target SLO |
| :--- | :--- | :--- |
| **Quorum Write Latency (p99)** | `cuttle_triad_write_latency_seconds_bucket` | `<= 250 ms` under normal 3/3 or 2/3 rolling-morph operation |
| **Appliance Availability Share** | `cuttle_triad_quorum_online_nodes >= 2` | `>= 99.9%` continuous quorum availability (`0 ms` downtime during 1-node rolling MTD morphs) |
| **3/3 Full Redundancy Share** | `cuttle_triad_quorum_online_nodes == 3` | `>= 98.0%` of wall-clock time outside scheduled 45s rolling morph waves |
| **Single-Node Time-to-Heal** | `cuttle_triad_heals_total` / `cuttle_triad_morph_duration_seconds` | `<= 30 s` from tamper/fault detection to `ONLINE` rejoin |

---

## Structured Alert Runbooks (`ALERT_CODES`)

Every `ALERT` event emitted by the controller includes a machine-parseable `code` and `structured_json` field matching one of the anchored sections below.

### `QUORUM_LOST` {#quorum_lost}

- **Symptom**: Fewer than 2 of 3 Triad nodes are in `ONLINE` state (`cuttle_triad_quorum_online_nodes < 2`). Mutating SQL/App writes and quorum reads fail closed with HTTP `400` / `quorum lost`.
- **Single-Node vs. Two-Node Outage**:
  - **Single-Node Outage (2/3 Degraded)**: Appliance remains 100% available for reads and writes. Rolling morphs are automatically paused (`need 2 healthy peers for majority`).
  - **Two-Node Outage (1/3 or 0/3 Quorum Lost)**: Appliance fails closed to prevent split-brain writes.
- **Triage & Recovery**:
  1. Inspect per-node serial logs in `target/cuttle_images/triad/node{1,2,3}/serial_node*.log`.
  2. Verify host resource limits (`apply_host_resource_limits`) and QEMU accelerator health (`--accel tcg` if WHPX is wedged on the host).
  3. Restart the controller cleanly (`python tools/triad_controller.py`); on boot, `_resolve_pending_wal_at_boot()` and `_verify_restored_tx_seq_at_boot()` reconcile all 3 nodes from `triad_wal.json`.

### `NODE_ISOLATED` {#node_isolated}

- **Symptom**: A node exceeded `MAX_CONSECUTIVE_HEALS` (`3`) without converging or failed to apply its least-privilege kernel role profile (`service role <role>`) after 3 attempts, and was marked `OFFLINE`.
- **Triage & Recovery**:
  1. Check `cuttle_triad_heals_total{node="<id>"}` on `GET /metrics` and inspect the isolated node's `serial_node<id>.log`.
  2. Verify the underlying disk images (`ahci_node<id>.img`, `virtio_node<id>.img`, `nvme_node<id>.img`) are writable and the host filesystem has free space.
  3. Trigger a manual morph/bounce via `POST /api/morph/<id>` (with `X-Cuttle-Session`) once the underlying host/storage fault is cleared.

### `AB_ROLLBACK` {#ab_rollback}

- **Symptom**: Either:
  1. A newly morphed kernel image staged into the inactive A/B slot (`slot_a_nodeN.img` or `slot_b_nodeN.img`) failed to reach `interactive shell ready` within the boot deadline and the controller automatically rolled back to the previous known-good slot image, or
  2. An operator or update attempted to load a `release_version` lower than the HMAC-sealed `min_allowed_version.json` anti-rollback counter.
- **Manual A/B Rollback & Anti-Rollback Procedure**:
  1. Inspect `node<id>/release.json` (`slot`, `release_version`, `image_sha256`, `seed`) and `min_allowed_version.json`.
  2. Notice that automatic A/B slot fallback restores the previous working slot (`slot_a` or `slot_b`) of the *same* or permitted `release_version` without violating `min_allowed_version`.
  3. To manually pin a node to its backup slot image while offline, copy `slot_a_node<id>.img` (or `slot_b_node<id>.img`) to `bios_node<id>.img` with a `release_version >= min_allowed_version`. Never decrement `min_allowed_version.json` in production.

### `CONTROLLER_LOCK_CONFLICT` {#controller_lock_conflict}

- **Symptom**: A second `TriadController` process attempted to attach to a `state_dir` whose `controller.lock` is already held by an active controller process.
- **Triage & Recovery**:
  1. Inspect `state_dir/controller.lock` to view the owning `pid` and `started_unix` timestamp.
  2. Do **not** delete `controller.lock` while the owning process is alive; stop the existing controller process first (`Ctrl+C` or `kill <pid>`) so it flushes state and releases the OS file lock cleanly.

### `WAL_CORRUPT` {#wal_corrupt}

- **Symptom**: `triad_wal.json` failed JSON parsing or schema/invariant validation at startup. The controller copied the damaged file to `triad_wal.json.bad` and refused to start.
- **WAL Corruption Recovery**:
  1. Inspect `triad_wal.json.bad` and any pre-migration backup `triad_wal.json.pre-v*`.
  2. If a pre-migration backup (`triad_wal.json.pre-v1`) is intact, or if all 3 node AHCI SQL partitions (`ahci_node{1,2,3}.img`) agree 3/3 on their on-disk state, restore from the verified backup or archive `triad_wal.json.bad` and allow the 3/3 online majority to re-checkpoint on boot.

### `SCHEMA_MISMATCH` {#schema_mismatch}

- **Symptom**: `triad_wal.json` or `cron_jobs.json` carries a `state_schema` version newer than `CURRENT_STATE_SCHEMA` (`2`), or a node attempted to replay a lossy legacy v1 checkpoint.
- **Triage & Recovery**:
  1. Upgrade the controller binary to a release supporting the newer `state_schema`, or
  2. If rolling back the controller software intentionally, restore the `.pre-v1` backup file created automatically before the schema migration ran.

### `NODE_HUNG` {#node_hung}

- **Symptom**: A node's QEMU process remained alive (`proc.poll() is None`) but missed `MAX_HEARTBEAT_MISSES` (`3`) consecutive serial liveness probes (`check_node_heartbeat`). The controller marked the node `HUNG`, terminated the wedged QEMU process, and launched `heal_and_remorph_node`.
- **Triage & Recovery**:
  1. Verify that automatic recovery completed (`ONLINE` event logged and `cuttle_triad_quorum_online_nodes == 3`).
  2. Inspect `serial_node<id>.log` prior to the hang to check for guest deadlocks or host I/O stalls.

### `SPLIT_BRAIN` {#split_brain}

- **Symptom**: All 3 online nodes returned pairwise-distinct state probes (`o1 != o2 != o3`), or the 2 surviving nodes in a 2/3 degraded Triad disagreed (`o_a != o_b`). The controller entered fail-closed `SPLIT-BRAIN` status and refused to overwrite any node or accept new mutating writes.
- **Split-Brain Triage**:
  1. Query `GET /api/triad` and inspect the controller log for the per-table row diff diagnosis (`SQL table '<name>' mismatch diagnosis`).
  2. Compare the committed `triad_wal.json` (`triad_tx_seq` and `triad_state_digest`) against each node's `node_state_digest`.
  3. Identify the node(s) whose on-disk state matches `triad_state_digest`, stop the controller, replace the diverged node's AHCI image or remove its stale disk image so 2/3 majority matches `triad_state_digest`, and restart the controller to heal the 3rd node from the verified majority + WAL.

### `DISK_SLOT_REPAIRED` {#disk_slot_repaired}

- **Symptom**: On boot, a guest emitted `SHELL resume REPAIRED: primary slot failed verification; state restored from shadow slot`. The primary AHCI state slot (`LBA 1040..=1092`) suffered bit-rot or torn damage at rest, and `ShellStore` automatically verified and healed it from the intact shadow slot (`LBA 1096..=1148`).
- **Triage & Recovery**:
  1. No data was lost; the node resumed online with intact `AB_FORMAT_V3` AEAD-authenticated state.
  2. Check host storage health (SMART counters, filesystem errors on `node<id>/ahci_node<id>.img`) for recurring media degradation.
  3. If the same node emits repeated `DISK_SLOT_REPAIRED` alerts, replace the backing storage volume and trigger `POST /api/morph/<id>`.

### `DISK_QUARANTINE_RESTORED` {#disk_quarantine_restored}

- **Symptom**: On boot, a guest emitted `SHELL resume RECOVERED: state set aside by an earlier unverified boot was restored`. State previously copied to the quarantine area (`LBA 1216..=1323`) was cryptographically authenticated under the active device key and restored.
- **Triage & Recovery**:
  1. Confirm the recovered node matches the 2-of-3 Triad majority (`GET /api/triad` shows `3/3 TMR MAJORITY LOCKED`).
  2. Review `serial_node<id>.log` and deployment history to confirm why an earlier boot ran with a mismatched key or interrupted state.

### `DISK_SEAL_REJECTED` {#disk_seal_rejected}

- **Symptom**: Either:
  1. A guest emitted `SHELL resume REJECTED: HMAC-SHA256 seal verification failed (tampered disk)` and preserved the unverifiable sectors in `LBA 1216..=1323` before booting blank,
  2. A guest booted without an out-of-band `fw_cfg` device key (`PROVISIONING WARNING` / `SHELL resume EPHEMERAL`), failing closed on all durable writes (`EROFS`), or
  3. Remote attestation quote HMAC verification (`attest <nonce>`) failed on the node.
- **Forensics & Recovery**:
  1. Inspect the automatically extracted forensic quarantine snapshot `node<id>/quarantine_node<id>_*.bin` (`108` sectors copied from `LBA 1216..=1323`) before taking destructive action.
  2. Verify `node<id>/device_key_node<id>.bin` and `master_key_path` (`device_secret_key.bin`) have not been replaced or corrupted.
  3. Once 2/3 peers hold a verified majority, the controller automatically outvotes and heals the rejected node from the majority + WAL.

### `DISK_STORAGE_FAULT` {#disk_storage_fault}

- **Symptom**: A guest kernel halted fail-closed with `STORAGE FAULT: ...` because an AHCI read, write, flush, or layout check failed during boot or runtime persistence.
- **Automated Recovery & Forensics**:
  1. The controller automatically terminates the halted VM, archives the faulted disk image to `node<id>/ahci_node<id>.fault_<ts>_<n>.img`, provisions a fresh zeroed 1 MiB `ahci_node<id>.img`, and runs `heal_and_remorph_node` to rebuild the node from the 2-of-3 majority + WAL.
  2. Inspect host disk space (`df -h` / volume free space) and the archived `.fault_*.img` image (including any encrypted `CTTLPENC` panic record at `LBA 1536..=1567`).
- **Faults that are not device errors** (the text after `STORAGE FAULT:`). In each of these the node halted instead of starting over, so on a standalone node (no Triad to heal from) the data is still on the disk: fix the cause and reboot, and image the disk before replacing it. The only writes recovery makes before such a halt are repairs of a slot or a page from its own verified copy.
  - `state cannot be authenticated and the page store holds data (nothing was started over; check the device key)`: the state slots did not verify under this boot's device key, and the disk has a page store (`LBA 2048..`, disks of 4096 sectors or more) with SQL rows and file contents in it. The usual cause is a wrong or missing `-fw_cfg` device key. With the right key the next boot restores everything. On a disk without a page store the same condition is `SHELL resume REJECTED` and the node starts over, because there the unverifiable slots fit in the quarantine area.
  - `page store does not hold the epoch the committed state anchors (nothing was started over)`: the state verified, and a page it refers to is damaged with no redo copy, or the page-store superblocks are older than the state. Starting over would overwrite the pages that are intact.
  - `state disk unusable at boot`: also raised when the state had to be read from the shadow slot and the device refused the rewrite of the primary slot. The shadow slot is then the only complete copy and the next commit would stage over it, so the node does not serve.
  - `an earlier commit failed; the store takes no more writes until the next boot recovers it`: a second commit was attempted after a failed one. The kernel halts on the first failure, so seeing this means a caller carried on after an error.
  - `whole-disk rollback detected (commit counter below floor)`: raised when an authenticated `AB_FORMAT_V3` disk commit record reports a `tpm_nv_counter` older than `C_tpm - 1` (outside the 1-step power-cut window between `TPM2_NV_Increment` and the `IN_FLIGHT` commit sector) or a `commit_seq` below an external floor.
  - `TPM-anchored disk requires TPM 2.0 at 0xFED40000 (device absent)`: the disk commit record has `tpm_anchored = true`, so the node fails closed rather than booting without its hardware anti-rollback anchor. Re-attach the node's TPM 2.0 device (`0xFED4_0000` TIS).
  - `TPM 2.0 communication or NV error while verifying anti-rollback anchor` and `hardware TPM 2.0 anti-rollback counter advance failed (NV 0x01500010)`: a present TPM failed TIS startup, NV read, or NV increment. Inspect TPM hardware / `swtpm` socket health and reboot; never ignore TPM errors on an anchored node.
  - `TPM 2.0 anti-rollback counter mismatch (missing NV 0x01500010 or unanchored disk; supply opt/cuttle_tpm_reanchor to re-anchor)`: either an anchored disk found NV index `0x0150_0010` missing/unwritten, or a blank replacement / restored unanchored disk was attached while TPM NV `0x0150_0010` holds an active counter `C_tpm > 0`. To intentionally re-anchor a replacement or restored disk, mint a one-time 48-byte `CTTLRA01` token bound to `(seal_key, C_tpm)` with `cargo run -p factory_builder -- mint-tpm-reanchor --master-key <device_secret_key.bin> --tpm-counter <C_tpm> --out <reanchor.bin>` and boot once with `-fw_cfg name=opt/cuttle_tpm_reanchor,file=<reanchor.bin>` (which increments `0x0150_0010` to `C_tpm + 1`, spending the token so it cannot be replayed, and remove the `-fw_cfg` flag afterward).
  - `disk commit counter is ahead of hardware TPM 2.0 NV 0x01500010`: the disk comes from a node or TPM with a higher counter than the attached TPM. Attach the matching TPM or re-anchor explicitly.
  - `TPM re-anchor token invalid (opt/cuttle_tpm_reanchor must be 48 bytes)` and `TPM re-anchor token rejected (magic, counter, or HMAC mismatch)`: a wrong-size, wrong-key, wrong-counter, or already-spent `opt/cuttle_tpm_reanchor` token was supplied.
- **Related serial lines** (no halt):
  - `PROVISIONING OK: device master key loaded from TPM 2.0 NV 0x01500011`: `0x0150_0011` (`TPMA_NV_POLICYREAD | TPMA_NV_READ_STCLEAR`, SHA-256 `PCR0+PCR7` policy + `CTK1` AEAD) unsealed the 32-byte master key and read-locked the NV index (`TPMA_NV_READLOCKED`) for the rest of the boot.
  - `NVME_HW REFUSED: namespace is not formatted with plain 512-byte blocks`: the NVMe namespace uses 4 KiB blocks or per-block metadata; the driver will not use it.
  - `STORAGE_BACKEND OK kind=<ahci|nvme|virtio> sectors=<N>`: logged once on boot when the durable state disk is chosen (either via `opt/cuttle_storage_backend` pin or deterministic `auto` selection by authenticated Cuttle commit record).
  - `STORAGE REFUSED: opt/cuttle_storage_backend is not one of ahci, nvme, virtio, auto`, `STORAGE REFUSED: pinned storage backend is not attached`, `STORAGE REFUSED: present storage controller failed initialization or sector probe`, `STORAGE REFUSED: multiple attached disks hold Cuttle state stores; pin opt/cuttle_storage_backend`, `STORAGE REFUSED: refusing Fresh boot on blank disk while another attached disk holds unauthenticated Cuttle state`, and `STORAGE REFUSED: no block storage backend attached`: boot-time state-disk selection refused to guess or fall through across controllers; followed by `STORAGE FAULT: state disk unusable at boot`.
  - `CONTINUITY resume NOTICE: continuity region unreadable; ...` and `CONTINUITY NOTICE: continuity region could not be written; ...`: a bad sector in the boot-counter hint region (`LBA 1024..1032`). The boot continues; the sealed state decides the boot generation.

### `DISK_ROLLBACK_DETECTED` {#disk_rollback_detected}

- **Symptom**: During boot or post-morph catch-up, a node's `HMAC-SHA256`-authenticated `attest <nonce>` quote reported a durable `commit_seq` lower than the per-node high-water mark recorded in `triad_wal.json` (`node_commit_seq`), indicating whole-disk snapshot rollback or an unrecorded disk wipe.
- **Automated Recovery & Triage**:
  1. Single-node rollback: the controller marks the node `tampered`, discards its stale `tx_seq`, and heals it from the 2-of-3 untampered majority + WAL onto a freshly morphed binary, establishing a new monotonic `commit_seq` baseline.
  2. Multi-node rollback: SQL-backed Triads replay the committed `triad_wal.json` onto rolled-back nodes; if fewer than 2 untampered peers remain on non-SQL state, the controller fails closed with `QUORUM_LOST`.
  3. Investigate hypervisor snapshot automation or storage-layer replication to determine why an older `ahci_node<id>.img` snapshot was presented.

---

## Key Ceremony Rotation & Revocation (`R3`)

1. **Generate a New Root/Build Signing Keypair**:
   - Run `cargo run -p factory_builder --bin key_ceremony -- generate --out-secret <secure_key_path> --out-pub <pub_hex_path>`.
2. **Revoke a Compromised or Retired Signing Key**:
   - Append the retired 32-byte Ed25519 public key (64 hex chars) to `revoked_pubkeys = ["<hex64>"]` in `factory_builder/build_policy.toml` and `target_enterprise_kernel/kernel_policy.toml`.
   - Re-sign both policy TOMLs (`policy_signature_ed25519`) with the active signing key.
   - Verify with `cargo test --workspace` that `revoked_key_rejected_by_loader_and_factory` passes and any manifest signed by the revoked key is rejected before boot.
