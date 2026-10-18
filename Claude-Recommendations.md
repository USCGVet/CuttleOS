# Claude Recommendations

Review of commits `9e511b8` (fixes for items 1–9) and `b168d5a` (status lines). Line numbers are from `b168d5a`.

**Test status at review time**
- `cargo test --workspace --no-fail-fast`: 2,410 passed, 0 failed. The count is unchanged from last round, because the new checks were added as assertions inside existing tests.
- `cargo test -p factory_builder --test qemu_smoke -- --ignored`: 2 passed (32 s).
- `target_enterprise_kernel` release build: OK.
- `tools/triad_controller.py`: parses, and the live three-VM `--self-test` passed.

## Verification of last round's items

| # | Item | Verdict | Notes |
|---|---|---|---|
| 1 | Vault secrets in plain text (triad) | **Verified fixed** | WAL entries are now `ENC_WAL_V1` (random nonce, keystream, MAC), and event-log text is redacted. The self-test asserts that neither the WAL file nor the events contain the secret. |
| 2 | Mailbox truncation | **Verified fixed** | `stage_mailbox_request` rejects oversized input with `PayloadTooLarge`, which maps to HTTP 413. Covered by a unit test and an HTTP test. |
| 3 | `ROLLBACK` limited to 8 rows | **Verified fixed** | Writes beyond the undo capacity are refused with an error, and DDL is refused inside a transaction. |
| 4 | One shared transaction | **Partly fixed** | HTTP sessions now own their transactions (`exec_as(owner)`). Remaining: see #3 below. |
| 5 | Concurrent triad write order | **Fixed in code; no test** | `wal_lock` now covers send → accept → WAL append. No test issues concurrent writes, so the fix is unproven. See #2 below. |
| 6 | Login cooldown too short | **Partly fixed** | It's now timer-based with exponential backoff (8 → 256 ticks). Remaining: see #4 below. |
| 7 | Vault keystream reuse | **Verified fixed** | A per-write nonce is mixed into the keystream and increases on every write to a key. Minor note in #6 below. |
| 8 | Pre-rebrand disks flagged as tampered | **Not resolved** | See #1 below. The named tests don't exercise a legacy disk. |
| 9 | TLS key zeroization | **Verified in code** | `zeroize_secret_bytes` (volatile writes plus a fence) is used at every site. The named TLS test can't observe zeroization, so per `GEMINI.md` this should be marked "Unverified", not "Fixed". |

---

## Medium priority

### 1. Legacy disks still raise a false tamper alarm, and nothing is migrated (item 8, not resolved)
- **Where:** `target_enterprise_kernel/src/banners_compose.rs:646`; magic checks at `target_enterprise/src/shell.rs:1352`, `:1508` and `target_enterprise/src/sql.rs:1627`
- **Problem:** the rebrand also changed every key-derivation label (`proteus-durable-seal-v1` → `cuttle-durable-seal-v1`, `proteus-ahci-wal-seal-v1` → `cuttle-ahci-wal-seal-v1`, and so on), so a seal written by an older build can never verify under the new key. The new branch prints "legacy ... migrating" only when the magic starts with `PRTS` *and isn't* `PRTSSHL1`. A legacy shell disk (`PRTSSHL1`) therefore still prints `REJECTED ... (tampered disk)`. Other legacy formats print "migrating", but their seals fail, so their state is discarded.
- **Effect:** operators upgrading from a pre-rebrand build still see a false tamper alarm, and the "migrating" message claims a migration that doesn't happen.
- **Fix:** for `PRTS*` images, verify with keys derived from the old `proteus-*` labels, then re-seal under the new key, which is a real migration. Otherwise print "legacy format, state not migrated" for every `PRTS*` magic. Add a test that builds a legacy-sealed image and asserts the chosen behavior.
- `Status: Fixed — test: shell::tests::regression_item1_legacy_prts_disk_migration_and_seal_verification — commit: c2f95b7`

### 2. No test exercises concurrent triad writes (item 5)
- **Where:** `tools/triad_controller.py` (`execute_triad_sql` write path and `--self-test`)
- **Problem:** the fix is correct by inspection, but nothing proves it.
- **Fix:** add a self-test step that fires two or more conflicting writes in parallel threads, for example `UPDATE`s to the same key, then asserts all online replicas return identical `SELECT * FROM kv` output and the WAL order matches.
- `Status: Fixed — test: tools/triad_controller.py --self-test (step 3c: 4-thread barrier parallel conflicting writes to 'concurrent.key' verifying identical replica SELECT * FROM kv and WAL order) — commit: c2f95b7`

### 3. Transactions are still partly shared (item 4, remaining)
- **Where:** `target_enterprise/src/sql.rs:604` (`exec` = owner 0) and `:626` (`SELECT` skips the ownership check)
- **Problem:**
  - (a) The console, UDP commands, the triad controller (which uses the serial console) and the built-in apps (vault, cron, guard) all run as owner `0`. While someone has a console `BEGIN` open, internal writes such as cron jobs or vault puts join that transaction and are discarded by its `ROLLBACK`.
  - (b) `SELECT` from other sessions sees uncommitted rows (dirty reads).
- **Fix:** give the built-in apps and the triad path their own owner IDs, separate from the interactive console. For reads, either document read-uncommitted as the isolation level or serve committed rows to other owners. `committed_row()` already exists for persistence and could be reused.
- `Status: Fixed — test: sql::tests::regression_item3_sql_read_committed_prevents_dirty_reads, shell::tests::regression_item3_subsystem_owner_isolation_during_console_tx, lived_net::tests::regression_item3_http_session_sql_isolation_and_read_committed — commit: c2f95b7`

### 4. The login cooldown assumes a fixed timer rate (item 6, remaining)
- **Where:** `target_enterprise_kernel/src/smp_hw.rs:1013` (`APIC_IRQS_PER_COOLDOWN_TICK = 937`)
- **Problem:** "one cooldown tick ≈ 1 second" is hard-coded from QEMU's timer rate. On real hardware the APIC timer frequency differs, so the cooldown will be longer or shorter than intended.
- **Fix:** derive the interrupts-per-second figure from the calibrated timer (the `apic_timer_cal` module) at boot, or use a monotonic clock in nanoseconds.
- `Status: Fixed — test: timer::tests::regression_item4_calibrated_apic_cooldown_ticks — commit: c2f95b7`

### 5. `/api/sh` bypasses the WAL and the write lock
- **Where:** `tools/triad_controller.py:1508` (`/api/sh`)
- **Problem:** `/api/sh` sends any command except `halt`/`reboot` straight to every online node. That includes state-changing ones such as `sql INSERT/UPDATE/DELETE`, `vault put/del`, `write`, `rm`, `grant`, `fw`, `seccomp` and `cron add`. These skip `wal_lock`, the WAL and the accept check that `/api/sql` and `/api/vault` enforce.
- **Effect:** nodes that are morphing or offline never receive these changes, concurrent ones can land in different orders, and the next quorum check sees divergence and heals a node.
- **Fix:** allow only read-only commands on `/api/sh` (the same list as `is_readonly_command`), and send state-changing ones to `/api/sql` or `/api/app`, or route them through the WAL path. Add a self-test step for it.
- `Status: Fixed — test: tools/triad_controller.py --self-test (step 3a: /api/sh allows 'status' with 200 and refuses 'sql DELETE', 'vault put', 'write', 'cron add' with 403) — commit: c2f95b7`

---

## Low priority

### 6. The vault nonce is 15 bits
- **Where:** `target_enterprise/src/shell.rs:2898`
- **Problem:** the nonce wraps after 32,767 writes to the same key. After a wrap, a new version can reuse an older version's keystream.
- **Fix:** store a wider nonce, for example 64 bits in its own column instead of packed into `rev`, or refuse writes once a key's nonce would wrap.
- `Status: Fixed — test: shell::tests::regression_item6_vault_nonce_exhaustion_refuses_wrap — commit: c2f95b7`

### 7. Regression tests are folded into existing tests
- **Where:** most items in `9e511b8`
- **Problem:** the new checks were added as assertions inside existing tests, so the test count didn't change, and it's hard to show "this test failed before the fix" as `GEMINI.md` requires.
- **Fix:** add one dedicated, clearly named regression test per item (e.g. `regression_item2_mailbox_rejects_oversized_body`).
- `Status: Fixed — test: svc_runtime::tests::regression_item2_mailbox_rejects_oversized_body, lived_net::tests::regression_item2_http_oversized_body_returns_413, sql::tests::regression_prev_item3_rollback_undo_overflow_and_ddl_in_tx_refused, shell::tests::regression_prev_item6_login_exponential_backoff_cooldown, shell::tests::regression_prev_item7_vault_per_write_nonce_diversifies_keystream, durable_seal::tests::regression_prev_item9_zeroize_secret_bytes_wipes_buffer (plus the 6 new item #1-#6 standalone regression tests; total workspace test count increased from 2,410 to 2,421; note on previous item #9: direct post-return stack-spill inspection inside handle_https_port_443 is Unverified because safe Rust tests cannot inspect popped stack frames, while zeroize_secret_bytes itself is tested directly) — commit: c2f95b7`

---

## Not reviewed this round
- The per-request `CPL=3` service hook, in detail
- CuttleGuard lockdown and CuttleChronos (cron) logic beyond the paths above
- The UDP `:8081` triad protocol
- `binmorph`
- `docs/sql-engine-plan.md` progress (M0 not started yet)
