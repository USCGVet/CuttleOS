# Claude Recommendations

Review of commits `c2f95b7` (round-2 fixes) and `99275bb` (status lines). Line numbers are from `99275bb`.

**Test status at review time**
- `cargo test --workspace --no-fail-fast`: 2,422 passed, 0 failed (up from 2,410, thanks to the dedicated regression tests).
- `cargo test -p factory_builder --test qemu_smoke -- --ignored`: 2 passed (29 s).
- `target_enterprise_kernel` release build: OK.
- `tools/triad_controller.py`: parses, and the live three-VM `--self-test` passed.

## Verification of last round's items

| # | Item | Verdict | Notes |
|---|---|---|---|
| 1 | Legacy disks: false tamper alarm, no migration | **Partly fixed; new issue** | Legacy keys are now derived with the old `proteus-*` labels, and the message is accurate. But the legacy check also accepts the public default key; see #1 below. |
| 2 | No concurrent-write test | **Verified fixed** | Self-test step 3c runs 4 barrier-synchronized conflicting writes and checks replicas and WAL order. |
| 3 | Transactions partly shared | **Verified fixed** | There are separate owner IDs for the console, vault, cron, triad and UDP, and other owners read committed rows. Named regression tests exist. |
| 4 | Cooldown assumes a fixed timer rate | **Verified fixed** | `calibrate_apic_irqs_per_sec` (PIT-calibrated) is used at boot in `smp_hw.rs`. |
| 5 | `/api/sh` bypasses the WAL | **Verified fixed** | Only read-only commands are allowed; everything else gets a 403. Covered by self-test step 3a. |
| 6 | 15-bit vault nonce | **Verified fixed** | Writes are refused with `EOVERFLOW` before the nonce would wrap. |
| 7 | Regression tests folded into existing tests | **Verified fixed** | All 12 named regression tests exist, and the test count went up. |

---

## High priority

### 1. The legacy seal check accepts the public default key
- **Where:** `target_enterprise/src/shell.rs:1414` (shell WAL), `:1591` (FS partition); `target_enterprise/src/sql.rs:1673` and `:1713` (SQL partition)
- **Problem:** for legacy-format (`PRTS*`) images, a seal counts as valid if it matches the device seal key, the device-derived legacy key, **or** `DEFAULT_LEGACY_DURABLE_SEAL_KEY`. That last one is a public constant in the source.
- **Effect:** a legacy-format image sealed with a key anyone can read passes the tamper check, so the seal no longer guarantees the state came from this device.
- **Fix:** remove the public-constant fallback from all three paths. Accept only the device-derived keys. Treat any legacy image that verifies only under the public default as unauthenticated ("legacy format, state not migrated"). Extend `regression_item1_legacy_prts_disk_migration_and_seal_verification` to assert that such an image is refused.
- `Status: Fixed — test: shell::tests::regression_item1_legacy_prts_disk_migration_and_seal_verification — commit: 70d44fc`

---

## Low priority

### 2. Keep the default keys out of non-test builds
- **Where:** `target_enterprise/src/shell.rs:308-309` (`OsShell::empty()` seeds `seal_key` and `legacy_seal_key` with public constants)
- **Problem:** correctness depends on every kernel path overwriting these defaults before any disk check. Today the restore path does (`banners_compose.rs:627`), but a future path could forget.
- **Fix:** initialize these keys to "unset" (e.g. `Option`) and refuse any seal or verify operation while a key is unset, as was done for `DEFAULT_NET_AUTH_KEY`, or gate the default constants behind `#[cfg(test)]`.
- `Status: Fixed — test: shell::tests::regression_round3_item2_unset_shell_keys_refuse_seal_and_verify — commit: 70d44fc`

---

## Process notes
- Status lines now name dedicated tests and commits, and the claims checked out against the code, except #1 above. Good progress.
- `CLAUDE.md`, `GEMINI.md` and `docs/` are still untracked. Ask the user before committing them.

## Not reviewed this round
- The SQL owner-selection logic in `exec_as`, in detail
- The per-request `CPL=3` service hook, in detail
- CuttleGuard and CuttleChronos beyond the paths above
- The UDP `:8081` triad protocol
- `binmorph`
- `docs/sql-engine-plan.md` progress (M0 not started)
