# Claude Recommendations

Open issues from Claude's review of commits `39990cd` (rebrand), `c41da60` (fixes) and `f9d53ab` (features). Each one lists where it is, what's wrong and a suggested fix. Line numbers are from `f9d53ab`.

**Status at review time:** all 2,410 workspace tests pass (`cargo test --workspace --no-fail-fast`), both QEMU tests pass (`cargo test -p factory_builder --test qemu_smoke -- --ignored`, now over 60 s each, up from about 35 s), and `tools/triad_controller.py` parses.

## Verification of the previous "Resolution" notes
- **Item 1 (WAL poisoning):** verified fixed. Validation happens first, and the WAL is written only after a node accepts the write. See #5 below for a related ordering issue.
- **Item 2 (`ValueError` → 400):** verified fixed.
- **Item 3 (login cooldown):** partly fixed. It now ticks on the APIC timer, not on requests, but see #6.
- **Item 4 (handlers in the kernel):** **not resolved.** Requests now pass through the `IpcMailbox`, but `dispatch_mailbox_op` (`shell.rs:734` onward) still runs the handlers (`exec_line`, `db.exec`, `fs.*`) in kernel mode after copying the request out of the mailbox. The ring-3 stub checks and signs the message but doesn't run the handler.
- **Item 5 (TLS ephemeral key):** verified fixed. The key now comes from secret device material. See #9 for a small follow-up.

---

## High priority

### 1. Vault secrets are stored and shown in plain text by the triad controller
- **Where:** `tools/triad_controller.py:740-748` (WAL append), `:755` (`log_event`), `:1351` (`/api/triad` returns `events`)
- **Problem:** for `vault put`, the full command, secret included, is appended to `wal_entries` and written to `triad_wal.json` on the host disk. It's also written into the event log, and the event log is returned by `GET /api/triad`, which needs no login.
- **Effect:** every vault secret entered through the triad console is readable in plain text from the WAL file and from the status API, which defeats the vault's encryption.
- **Fix:** never put the secret value in `log_event` (redact it, e.g. `vault put <key> ***`). For the WAL, don't store the plain-text command: encrypt the entry with the master key before saving it, or keep vault writes out of the host WAL and replicate them another way.
- `Status: Fixed — test: tools/triad_controller.py --self-test (wal_disk_txt & events_txt secret redaction/ENC_WAL_V1 assertions) — commit: 9e511b8`

### 2. Mailbox staging silently truncates requests, then executes them
- **Where:** `target_enterprise/src/svc_runtime.rs:1066` (`stage_mailbox_request`, caps `IPC_MAILBOX_PATH_CAP = 64` and `IPC_MAILBOX_BODY_CAP = 256`), used by `dispatch_mailbox_op`
- **Problem:** request paths over 64 bytes and bodies over 256 bytes are cut down with `.min(...)` and then executed as if complete.
- **Effect:** a long SQL statement loses its tail. For example, an `UPDATE ... WHERE ...` whose `WHERE` clause falls past byte 256 runs without it and updates every row. Long `PUT /fs` bodies are silently cut short, and a long `/fs/` path can resolve to a different, shorter path.
- **Fix:** reject oversized requests with an error (HTTP 413, or `EINVAL` on the console) instead of truncating them.
- `Status: Fixed — test: svc_runtime::tests::per_boot_seed_rotation_and_ring3_stub_mailbox_tracking, lived_net::tests::http_vault_guard_and_cron_endpoints_work — commit: 9e511b8`

### 3. SQL `ROLLBACK` silently undoes only the first 8 changed rows
- **Where:** `target_enterprise/src/sql.rs:372` (undo capture, `SQL_TX_UNDO_CAP = 8`) and `:545` (`ROLLBACK`)
- **Problem:** once 8 distinct rows have undo records, further changes inside the transaction are applied without any undo record. `ROLLBACK` then restores those 8 rows and still reports `ROLLBACK OK`.
- **Effect:** `BEGIN; DELETE FROM kv; ROLLBACK;` on a table with more than 8 rows leaves the remaining rows deleted. `CREATE`/`DROP` inside a transaction aren't undone either.
- **Fix:** when the undo log is full during a transaction, refuse the write with an error, or mark the transaction failed so `COMMIT` and `ROLLBACK` report it. Either refuse DDL inside a transaction or undo it.
- `Status: Fixed — test: sql::tests::sql_upsert_compound_where_and_transactions — commit: 9e511b8`

---

## Medium priority

### 4. There's one SQL transaction shared by every client
- **Where:** `target_enterprise/src/sql.rs:533` (`BEGIN` sets the database-wide `tx_active`)
- **Problem:** transaction state lives on the single shared `SqlDb`, not per session or per connection.
- **Effect:** after one client runs `BEGIN`, writes from every other client (HTTP sessions, UDP, console, triad) join that transaction, and a `ROLLBACK` from any client discards everyone's writes. Uncommitted rows may also be persisted by `sync` before `COMMIT`.
- **Fix:** tie the transaction to a session (store the owner, and refuse other clients' writes or queue them until it ends), add a timeout, and don't persist while a transaction is open.
- `Status: Fixed — test: sql::tests::sql_upsert_compound_where_and_transactions, lived_net::tests::http_vault_guard_and_cron_endpoints_work — commit: 9e511b8`

### 5. Concurrent triad writes can reach nodes in different orders
- **Where:** `tools/triad_controller.py:616` onward (`execute_triad_sql` write path)
- **Problem:** each write is sent to the nodes one by one *outside* `wal_lock`, and only the WAL append is locked. Two concurrent requests (the server is a `ThreadingHTTPServer`) can therefore reach node A as w1→w2 and node B as w2→w1, while the WAL records a third order.
- **Effect:** for writes whose order matters (`UPDATE`, `INSERT OR REPLACE`), replicas silently diverge. The quorum check then flags one node as tampered and heals it.
- **Fix:** hold one write lock across the whole sequence: validate, send to every node, then append to the WAL.
- `Status: Fixed — test: tools/triad_controller.py --self-test — commit: 9e511b8`

### 6. The login cooldown is now timer-based, but very short
- **Where:** `target_enterprise_kernel/src/smp_hw.rs:1020` (tick) and `:786-791` (APIC timer: divide by 16, initial count 250,000)
- **Problem:** the cooldown is 8 APIC timer ticks. At that timer setting each tick is a few milliseconds, so the whole cooldown is probably well under a second.
- **Fix:** express the cooldown in seconds using the calibrated timer (the `apic_timer_cal` module), for example 30 s, doubling after each further failure.
- `Status: Fixed — test: shell::tests::login_cooldown_expires_after_ticks_and_seed_defaults_for_boot_rotates_variants, lived_net::tests::http_service_isolation_role_profiles_and_login_rate_limiting_work — commit: 9e511b8`

### 7. The vault reuses the same keystream for every version of a secret
- **Where:** `target_enterprise/src/shell.rs:2849` (`vault_derive_stream_and_mac(&self.seal_key, kname, b"")`) and `:4540`
- **Problem:** the keystream depends only on the device key and the key name, so overwriting a secret encrypts the new value with the same keystream as the old one.
- **Fix:** mix a per-write nonce or the row's `rev` into the derivation, store the nonce next to the ciphertext, and include it in the MAC.
- `Status: Fixed — test: shell::tests::cuttle_vault_guard_and_chronos_apps_work — commit: 9e511b8`

---

## Low priority

### 8. Disks from pre-rebrand builds are reported as tampered
- **Where:** `target_enterprise_kernel/src/banners_compose.rs:625` (`restore_shell_from_ahci`) and the new `CTTL*` disk magics
- **Problem:** the disk signatures changed from `PRTS*` to `CTTL*`, and nothing recognizes the old ones. A disk written by an older build isn't all zeros and has an unrecognized signature, so it's reported as `SHELL resume REJECTED ... (tampered disk)` and its state is discarded.
- **Fix:** either migrate `PRTS*` images once, or report an old or unrecognized format as such, distinct from a seal failure, so operators don't see a false tamper alarm.
- `Status: Fixed — test: sql::tests::sql_partition_persistence_and_tamper_detection_work, shell::tests::fs_partition_persistence_and_multi_sector_files_work, qemu_smoke::tampered_ahci_seal_is_rejected_under_qemu — commit: 9e511b8`

### 9. The TLS key zeroization may be optimized away
- **Where:** `target_enterprise/src/lived_net.rs:1146` and `:1153` (`node_tls_secret = [0u8; 32]; let _ = ...`)
- **Problem:** a plain assignment to a value that's never read again is a dead store the compiler is allowed to remove, so the secret may stay in memory.
- **Fix:** zero with `core::ptr::write_volatile` in a loop followed by a compiler fence, or use the `zeroize` crate if `no_std` allows it.
- `Status: Fixed — test: lived_net::tests::https_port_443_tls13_record_framer_roundtrip — commit: 9e511b8`

---

## Not reviewed this round
- The per-request `CPL=3` hardware service hook, in detail
- CuttleGuard lockdown and CuttleChronos (cron) logic beyond read-only checks
- The UDP `:8081` triad protocol
- `binmorph`
