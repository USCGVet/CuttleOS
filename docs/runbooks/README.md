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

---

## Key Ceremony Rotation & Revocation (`R3`)

1. **Generate a New Root/Build Signing Keypair**:
   - Run `cargo run -p factory_builder --bin key_ceremony -- generate --out-secret <secure_key_path> --out-pub <pub_hex_path>`.
2. **Revoke a Compromised or Retired Signing Key**:
   - Append the retired 32-byte Ed25519 public key (64 hex chars) to `revoked_pubkeys = ["<hex64>"]` in `factory_builder/build_policy.toml` and `target_enterprise_kernel/kernel_policy.toml`.
   - Re-sign both policy TOMLs (`policy_signature_ed25519`) with the active signing key.
   - Verify with `cargo test --workspace` that `revoked_key_rejected_by_loader_and_factory` passes and any manifest signed by the revoked key is rejected before boot.
