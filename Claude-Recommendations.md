# Claude Recommendations

This round was not a normal review round. The user asked me to review the core OS and improve it directly, with one bar: *would you trust your own data on it*. So this file has two parts:

1. **What I changed** in the working tree (nothing is committed), each with the test that proves it.
2. **What is still open** for the builder, by priority.

**Scope.** I read the core at `d279d75`: the kernel crate (`target_enterprise_kernel/src`) and the storage, filesystem, SQL, shell-persistence, memory and SMP modules of `target_enterprise/src`. Three read-only reviewer passes covered the storage library, the memory/interrupt/SMP core, and the drivers and key provisioning; I checked every finding below against the code before acting on it or listing it. I did **not** review the diff of the 22 commits `917109c..d279d75` as a whole, and I did **not** verify last round's status lines (see the table below).

Line numbers are from the working tree as I left it.

## Test status

Host: the user's Windows 11 machine; stable 1.93.1; pinned `nightly-2026-10-22`; QEMU, TCG.

- `cargo test --workspace --no-fail-fast`: **exit 0; 4,470 passed, 16 ignored** by cargo's own counts (4,390 passed, 16 ignored before my changes, same host, same day). Both figures include the verifier's nested release run of `target_enterprise`, whose one deliberate failing probe (`watchdog::stage8_verifier_gate_probe::must_run_in_verifier`) appears in the log in both runs.
  The run predates one last kernel-only change (the panic handler's ordering). The kernel is outside the workspace; the suites that read its ELF (`cuttle-binmorph`, `cuttle-mtd-metrics`) were re-run on the final build and passed.
- `target_enterprise` unit tests: **1,835 passed** (1,796 before this round; 39 new).
- `cargo test -p factory_builder --test qemu_smoke -- --ignored`: **3 passed**. `tampered_ahci_seal_is_rejected_under_qemu` was rewritten; see "Behaviour changes" below.
- `(cd target_enterprise_kernel && cargo build --release)`: **passed**, no warnings from the crate. The production variant (`factory_builder build-kernel --prod`) also builds.
- `python -c "import ast; ..."` on `tools/triad_controller.py`: **passed**.
- `python tools/triad_controller.py --unit-test`: **passed** (it drives the real shell through `shell_harness`).
- **Live, on real VMs** (beyond the required checks): `python tools/triad_controller.py --self-test --accel tcg` (3 VMs): **passed**. Two caveats:
  - `target/cuttle_images/run_bios.img` was from 23 October, so the self-test would have run an old kernel. I rebuilt it from the current ELF first (Low list).
  - The run logged `TMR parity vote could not verify 2/3 majority: unreadable state probe` on all three nodes three times, each right after a restart step. The test does not treat that as a failure, and I did not establish whether those alerts predate this round.
  - It ran before one last change to the panic handler's ordering; the QEMU smoke tests were re-run after it.
- `tools/cuttle_fleet.py --self-test` (18 VMs): **not run.**

One trap I walked into: building the `--prod` kernel leaves that variant at `target_enterprise_kernel/target/x86_64-unknown-none/release/`, and three workspace tests that read "the real kernel ELF" then fail on their size thresholds. They pass again once the default kernel is rebuilt. It is listed below as Medium #9.

## Verification of last round's items

I did not do this step this round. Every item is carried over unverified.

| # | Item | Builder's status | Verdict |
|---|---|---|---|
| 1–14 | Round 9 items in the previous version of this file | Fixed (`d9869f1`, `a3ce4bf`, `fddcbf6`, `82fd583`, `a6ca484`) | **Not verified this round** |
| R1–R15 | `Cuttle-OS-Recommendations.md` | Fixed (`82fd583`, `a6ca484`, `d9869f1`) | **Not verified this round** |

One of them I touched in passing: Round 9 #13 asked the multi-seed QEMU test to check persisted state on disk. It does (it pins the first journal record at `LBA 1041`), and that assertion caught a byte-order change I had made to the journal; I restored the order.

---

## What I changed

All of it is in the working tree, uncommitted. The idea behind most of it: the code that decides whether data survives was inlined in the kernel, where it cannot be unit-tested, and the one "power cut at every sector" test re-implemented the write sequence in the test body instead of calling it. That logic now lives in one library module and is tested against a disk model that misbehaves the way disks do.

### New: `target_enterprise/src/state_store.rs`

- **Commit** (`commit`): stage the image in the shadow slot, flush, read back; write the `IN_FLIGHT` record, flush, read back; install the primary slot, flush, read back; write the `QUIESCENT` record, flush, read back. Four flush barriers (there were five); the module docs say what each is for.
- **Recovery** (`recover`): authenticate the commit record, then use the primary slot if it matches, otherwise the shadow slot if it matches (roll-forward for `IN_FLIGHT`, a reported repair for `QUIESCENT`), otherwise refuse and leave the disk untouched. An unreadable sector counts as a damaged one.
- **Node policy** (`ShellStore`): pack and commit a live `OsShell`; decide at boot what the shell starts from; copy state that cannot be authenticated to a quarantine area (`LBA 1152..=1205`) before starting over, and restore it on a later boot that can authenticate it.
- **Disk model for tests** (`testdisk::MemDisk`): a volatile write cache, a power cut at a chosen operation that tears the sector being written and keeps all, none or a random subset of unflushed writes, reported I/O errors, silently dropped writes, unreadable sectors.

### Defects fixed

| # | Defect (before) | Fix | Proof |
|---|---|---|---|
| 1 | A commit failure was discarded (`let _ = persist_shell_to_ahci(..)` at four call sites) and `sync` printed `sync: ok` regardless. | `persist_shell_if_changed` returns only when the state is on disk; a failed commit stops the node with `STORAGE FAULT: <reason>`. | `state_store::node_tests::failed_commit_is_reported_and_the_next_boot_is_consistent`; `state_store::tests::io_error_at_every_operation_fails_the_commit_and_recovers_cleanly` |
| 2 | The 512-byte journal sector overflowed once the state held a few firewall rules, tasks, cron jobs and IMA digests, or two 200-byte files. From then on **every** commit failed to pack and nothing (files and SQL included) reached the disk again, silently. | Commands that add a journal record check an exact size budget first and refuse with `ENOSPC`; file copies in the journal are optional and never crowd out a state record. | `state_store::node_tests::every_state_the_shell_accepts_can_be_packed_and_restored` (fails with `Journal(OutOfCapacity)` after `fw block 10.4.0.0/16` when the budget is disabled); `...many_and_large_files_persist_and_restore_byte_for_byte` |
| 3 | Only seven counters triggered a commit. File writes, firewall rules, tasks, capability grants, cron jobs and IMA digests were not saved until something else changed; a SQL `COMMIT` did not trigger one either, so a committed transaction could be lost. | The trigger is `OsShell::durable_fingerprint`, built from the same record enumeration the journal writes, a mutation counter inside the filesystem, and the SQL committed sequence. | `state_store::node_tests::every_durable_change_moves_the_fingerprint`; `...committed_transaction_is_on_disk_and_uncommitted_one_is_not` |
| 4 | Network replies were transmitted before the commit. | Commit first, then transmit (main loop and boot service window). | Ordering is in `main.rs` and `net_service.rs`; the property it relies on is #1. Not separately tested under QEMU. |
| 5 | Boot panicked with `SHELL resume: cross-boot AHCI state drift` whenever the boot counter and the saved generation were not exactly one apart. A power cut between the counter update and the first commit of a boot (several seconds) made every later boot panic. | The generation comes from the sealed state; the counter is a hint and is rewritten to follow it. | `state_store::node_tests::boot_counter_ahead_of_or_behind_the_saved_generation_still_restores` |
| 6 | If the continuity header was lost, the counter restarted at 1, the restore was skipped (`if boots > 1`), and fixture state was committed over the real state. | Restore no longer depends on the counter. | Same test as #5 (the "behind" case). |
| 7 | Boot panicked unless `/var/boot.ok` read `ready` and the `kv` row `boot.state` was `ready|1`; both are ordinary user-writable state. | Removed. A resumed boot never asserts on stored content. | Code removal in `banner_shell_compose`; QEMU multi-seed test still passes. |
| 8 | A damaged primary slot was rejected even when the shadow slot held a verified copy; an all-zero primary slot, or an all-zero filesystem or SQL superblock, was treated as "nothing stored" and then overwritten. | Recovery checks both slots against the commit record; a missing partition is an error. | `state_store::tests::damage_to_any_primary_sector_is_healed_from_shadow_and_reported`; `state_store::node_tests::damaged_or_zeroed_primary_slot_is_healed_not_treated_as_a_blank_disk`; `...a_partition_zeroed_in_both_slots_is_rejected_not_silently_reset`; QEMU `tampered_ahci_seal_is_rejected_under_qemu` |
| 9 | A rejected disk was overwritten in the same boot. One boot without the `-fw_cfg` device key therefore destroyed the stored state. | The slots are copied to the quarantine area first; a later boot that can authenticate the copy restores it. | `state_store::node_tests::state_survives_boots_without_the_device_key`; `...unverifiable_state_is_preserved_before_the_node_starts_over`; QEMU tamper test (boot 3) |
| 10 | Every AHCI error or timeout was a panic, the HBA was re-probed and the port restarted on every commit, and only `TFD.ERR` was checked. | `try_issue_with_prdtl` returns a fault and checks the `PxIS` error bits, `TFD` ERR/DF and the transferred byte count; the port is probed once; capacity comes from IDENTIFY and every LBA is range-checked. | Engine side: `state_store::tests::unreadable_sector_in_either_slot_or_the_commit_record_does_not_stop_recovery`. Driver side: exercised by the three QEMU tests; error paths not injected under QEMU. |
| 11 | Restoring the filesystem partition ignored `open`/`write` failures. With the journal's small-file copies already holding 256-byte reservations, a large file could fail to restore, be dropped without an error, and then be absent from the next commit. | Two passes: validate every directory entry, remove existing user files, then recreate each file with a reservation that is guaranteed to fit. Any failure fails the restore. | `shell::tests::filesystem_restore_recreates_every_file_when_the_pool_is_tight` |
| 12 | `write`, `writehex` at offset 0 and HTTP `PUT /fs` truncated the file before knowing the new contents fit; a failed write left it empty. HTTP reported `201` with `wrote 0 bytes`. | `MemRamFs::can_replace` is asked first; the reply is `ENOSPC` (HTTP 507) and the file is unchanged. | `vfs::tests::can_replace_predicts_truncating_overwrite_exactly`; `shell::tests::overwrite_that_does_not_fit_leaves_the_existing_file_untouched` |
| 13 | `CREATE INDEX` had no capacity check. On a nearly full database the save then dropped rows silently (`break`) or indexed past the buffer. | Capacity check added; `try_save_partition` writes every committed row or returns `TooLarge`. | `sql::tests::create_index_respects_partition_capacity_and_a_full_database_saves_every_row` |
| 14 | The SQL transaction idle timeout advanced once per received Ethernet frame. Sixteen unrelated frames rolled back an open transaction; the client's remaining statements then ran in autocommit and were saved: half a transaction on disk. | The timeout and cron tick on the calibrated timer epoch (about one second). After a timeout the owner's statements are refused until it sends `ROLLBACK`, `COMMIT` (which reports the loss) or `BEGIN`. | `sql::tests::idle_timeout_aborts_the_transaction_until_its_owner_acknowledges_it`. The kernel-side tick change is not tested under QEMU. |
| 15 | The boot service window restored the shell itself, served mutating requests, never committed, and its state was then discarded. | The store is booted once, before the window; the window commits before replying; `banner_shell_compose` no longer resets a shell that holds real state. | QEMU smoke tests; no test sends a mutating request during the window. |
| 16 | The continuity region was rewritten in place with no flush, and `resumed_boots + 1` could overflow. | Flush after the region and after the header; saturating add. | Not tested (the region is now only a hint). |
| 17 | The panic handler attempted the crash dump (MMIO and disk) before printing the message, so a panic caused by either could hang silently. | Order is now: stop the other CPUs and scrub keys, print the message, then attempt the dump. | Not tested. |
| 18 | The commit path used the AP SHA-256 offload, which can return a stale digest after a timeout. | The store hashes on the boot CPU. | Covered by the store tests; the offload itself is unchanged (Low list). |
| 19 | Console input arriving during a commit was dropped (polled UART, 16-byte FIFO). This became visible once every mutating command committed. | A 512-byte receive ring, pumped from the AHCI wait loops. | QEMU `morphed_kernel_boots_and_persists_state_across_multiple_seeds_under_qemu` (its interactive part failed without it). |

The central guarantee, old state or new state after a power cut and never a mixture, is `state_store::tests::power_cut_at_every_operation_recovers_old_or_new_never_a_mixture` (every device operation, four cache-loss models), `...power_cut_during_a_second_consecutive_commit_never_loses_the_first`, and on a real shell `state_store::node_tests::power_cut_during_commit_boots_into_old_or_new_state_never_a_mixture`. I checked that these have teeth: removing the flush after the shadow slot makes the first one fail.

### Behaviour changes the builder should know about

- **One tampered slot is repaired, not rejected.** `tampered_ahci_seal_is_rejected_under_qemu` used to flip one byte at `LBA 1041` and expect `SHELL resume REJECTED`. It now has two cases: that same flip must produce `SHELL resume REPAIRED` and `SHELL resume OK` with both slots identical afterwards; the same flip in both slots must produce `SHELL resume REJECTED`, no `SHELL resume OK`, and the rejected sectors byte for byte in the quarantine area. The tampered bytes are never used in either case. The old assertion is kept for the case where it still holds.
- **Every durable change commits before its reply.** A mutating console command now takes about a second under TCG (Medium #1). Each `writehex` chunk is one such command.
- **Cron ticks are timer epochs** (about one second), no longer one per command or frame.
- **New replies:** `error: ENOSPC (durable state journal full; ...)`, `error: ENOSPC (file does not fit; nothing was changed)` (HTTP 507), `error: transaction timed out and was rolled back; ...`.
- **New serial lines:** `SHELL resume REPAIRED`, `SHELL resume RECOVERED`, `SHELL resume NOTICE: ...`, `SHELL resume WARNING: ...`, `CUTTLE-TE PANIC: STORAGE FAULT: ...`. `SHELL resume OK` and `SHELL resume REJECTED: HMAC-SHA256 seal verification failed (tampered disk)` are unchanged; both are now printed right after the `CONTINUITY` lines.
- **On-disk format is unchanged**, including the journal's record order. New on disk: the quarantine area at `LBA 1152..=1205`.
- `durable_seal::ab_journal::decide_ab_recovery` is no longer called by the kernel. I left it and its test in place with a doc note.

---

## High priority

### 1. The host controller does not know about repair, rejection, quarantine or a storage halt
- **Where:**
  - `tools/triad_controller.py`: no occurrence of `SHELL resume REPAIRED`, `SHELL resume REJECTED`, `SHELL resume RECOVERED` or `STORAGE FAULT`; boot classification at `:1973-1975` reads only the `CONTINUITY` lines.
  - `docs/runbooks/README.md`: no entry for any of them.
  - The kernel side is `shell_store_boot` and `storage_fault` in `target_enterprise_kernel/src/banners_compose.rs`.
- **Problem:** the node now repairs a damaged primary slot, sets unverifiable state aside, and halts when a commit fails. Each of these is one serial line and, for the first two, one audit event. Nothing on the host reads them.
- **Effect:**
  - A repaired slot is evidence that sectors changed outside a commit. Today nobody is told, so self-healing hides the event it should surface.
  - A node halted by `STORAGE FAULT` looks like any hung node; the heal path will reboot the same disk.
  - The quarantine area is released at the next verified boot, whether or not anyone looked at it.
- **Fix:**
  - Parse these lines when a node boots and add alert codes and runbook entries for them.
  - Treat `STORAGE FAULT` as a failed disk (replace the image, then heal), not as a hang.
  - On `REJECTED`, copy the quarantine sectors out of the node's AHCI image on the host before the node's next verified boot releases them.
  - Add controller unit tests with fake serial logs for each line.
- Status: Fixed — test: `tools/triad_controller.py --unit-test` (`run_stage8_security_and_wal_unit_tests`: `stage4_serial_events` REPAIRED/RECOVERED/REJECTED/EPHEMERAL + 108-sector quarantine archive, `stage4_storage_fault` disk replacement + WAL rebuild, runbook anchor check) — commit: `b995e5e`

### 2. The fleet self-test has not been run against this kernel
- **Where:** `tools/cuttle_fleet.py --self-test`; the `web` and `index` jobs, which sync files with many `writehex` chunks.
- **Problem:** this round changed what the controllers drive: commit timing (every mutating console command now commits, including each `writehex` chunk), cron cadence, the transaction-timeout replies and the boot sequence. The Triad self-test passed on three VMs. The 18-VM fleet self-test was not run, and it is the one that exercises file sync and cron.
- **Effect:** I do not know whether the fleet's timeouts and cron expectations still hold. The Triad run also logged three `unreadable state probe` alerts that I could not attribute (see Test status).
- **Fix:**
  - Run the fleet self-test with `--accel tcg` before building on this.
  - Compare the Triad self-test's alert log with a run of `d279d75` to settle whether the probe alerts are new.
  - If file sync is too slow, fix it in the driver (Medium #1), not by loosening the commit rule.
- Status: Fixed — test: `tools/triad_controller.py --unit-test` (`stage4_serial_framing`, `stage4_clean_shutdown`), `tools/triad_controller.py --self-test --accel tcg` (`0` `unreadable state probe` alerts; root cause was `_background_scheduler` firing after `shutdown()`), `tools/cuttle_fleet.py --self-test --accel tcg` (18 VMs across `web`, `sql`, `index`, `cron`) — commit: `7c321a6`, `b995e5e`

---

## Medium priority

### 1. A commit is about 110 single-sector AHCI commands
- **Where:** `AhciHwPort::try_write_sector` / `try_read_sector` in `target_enterprise_kernel/src/hw_storage_drivers.rs`; `write_slot` and `slot_digests` in `target_enterprise/src/state_store.rs`.
- **Problem:** each of the 26 sectors of a slot is one `WRITE DMA`, and each read-back one `READ DMA`, through a single 512-byte DMA buffer. Under TCG a commit takes about a second.
- **Effect:** slow writes, long stretches in which the kernel serves nothing, and a longer window in which a power cut interrupts a commit (recovery handles it, but shorter is better).
- **Fix:** give `SectorIo` a multi-sector read and write, back it with a 13 KiB DMA buffer and one PRD entry, and use READ/WRITE DMA EXT so the 28-bit LBA limit goes too. Keep the per-sector fault model in the tests.
- Status: Fixed — test: `state_store::tests::power_cut_at_every_operation_recovers_old_or_new_never_a_mixture`, `state_store::tests::io_error_at_every_operation_fails_the_commit_and_recovers_cleanly`, `qemu_smoke::morphed_kernel_boots_and_persists_state_across_multiple_seeds_under_qemu` — commit: `7c321a6`

### 2. The journal is one 512-byte sector
- **Where:** `SHELL_JOURNAL_BYTES` at `target_enterprise/src/shell.rs:129`; the layout in `state_store::AHCI_STATE_LAYOUT`.
- **Problem:** the worst-case state records (12 worker tasks, 8 firewall rules, 6 IMA digests, 4 cron jobs, two watermarks) need about 1,120 bytes. The budget now refuses the command that would overflow, which is correct but arrives early: a full task table and a full firewall table leave room for one cron job.
- **Effect:** `ENOSPC` on ordinary configurations.
- **Fix:** a version-2 layout with a journal of at least three sectors (there is free space on the disk), a format version in the commit record, and a migration test. The same change can lift the 4 KiB limits on files and SQL.
- Status: Fixed — test: `state_store::node_tests::v1_disk_migrates_cleanly_to_v2_and_survives_mid_migration_power_cut`, `state_store::node_tests::large_files_up_to_10kib_and_sql_up_to_8kib_persist_in_v2`, `state_store::node_tests::v3_encrypted_store_leaves_zero_plaintext_on_disk_and_migrates_v2` — commit: `d3f1925`, `fdb1522`

### 3. Rolling the whole disk back is not detected
- **Where:** `commit_seq` in `AbCommitHeader`; `ShellStore::boot`.
- **Problem:** `commit_seq` now continues across boots, but it is anchored only on the disk it protects. An older, validly sealed image of the whole disk (both slots and the commit sector) boots as valid.
- **Effect:** a single node cannot tell that its state went backwards. The Triad vote catches it only if the other two nodes disagree.
- **Fix:** keep the high-water `commit_seq` somewhere the disk cannot rewrite: a TPM NV counter, or the controller (it already tracks `tx_seq` per node) refusing a node that reports a lower one.
- Status: Fixed — test: `state_store::node_tests::anti_rollback_min_commit_seq_rejects_stale_disk_snapshot`, `shell::tests::attest_quote_binds_commit_seq_and_rejects_tampered_commit_seq`, `tools/triad_controller.py --unit-test` (`stage4_commit_seq`), `tools/triad_controller.py --self-test --accel tcg` (step 6c `DISK_ROLLBACK_DETECTED`) — commit: `fdb1522`, `b995e5e`

### 4. The kernel installs no IDT until the last boot step, and CPU exceptions bypass the panic path
- **Where:** `init_runtime_idt_and_isrs` at `target_enterprise_kernel/src/smp_hw.rs:1074`, first reached from `banner_smp_hw` (`:2391`); `ISR_CPU_FAULT_DIAG` at `:1132`.
- **Problem:** the disk restore, the boot service window and most of boot run on whatever IDT the bootloader left. After the IDT is installed, vectors 0–31 share one stub that prints `!EXC` and halts that CPU, recording nothing.
- **Effect:** an exception early in boot is a triple fault: a reset loop with no message. Later, a fault is indistinguishable from any other, skips the key scrub and crash dump, and leaves the other CPUs running.
- **Fix:** install the IDT, GDT and TSS right after `set_phys_offset`; give each vector a stub that records vector, error code, RIP and CR2 and enters the panic path.
- Status: Fixed — test: `qemu_smoke::boots_under_qemu_and_emits_banner` (`verify_early_bsp_idt_active`), `qemu_smoke::tampered_ahci_seal_is_rejected_under_qemu` (Case 4 Ring-0 `ud2` `#UD` `vec=6` `CTTLPENC` encrypted crash dump) — commit: `946910d`

### 5. The boot service window has no absolute deadline
- **Where:** `target_enterprise_kernel/src/net_service.rs:805-815` (`max_idle` at `:808`), and the legacy path at `:1274`.
- **Problem:** the window closes only after 2,000,000 idle polls, and every frame resets the count. It also exposes the full mutating surface before the boot self-tests have finished.
- **Effect:** steady traffic keeps a node in the window indefinitely, so it never reaches the main loop. (What it serves there is now committed.)
- **Fix:** an absolute deadline, and status/ICMP/ARP only until the main loop.
- Status: Fixed — test: `qemu_smoke::nvme_only_persistence_and_network_flood_resilience_under_qemu` — commit: `b917e2f`

### 6. A node without its device key still accepts and saves writes
- **Where:** `target_enterprise_kernel/src/provisioning.rs:334` (`FwCfgKeyStatus::Absent => (generate_hw_entropy_master_key(), false)`).
- **Problem:** with the key absent or malformed the node runs on a throwaway key. It cannot read its disk, starts from defaults, and commits new state sealed with a key that will not exist after the reboot. `Absent` logs nothing.
- **Effect:** the original state is now preserved in quarantine and comes back when the key does, but everything written during the keyless boot is unreadable afterwards, and it was acknowledged.
- **Fix:** without a provisioned key, refuse durable writes (or refuse to serve), and say so on the console.
- Status: Fixed — test: `shell::tests::unprovisioned_shell_refuses_all_durable_mutations_across_console_and_http_roles`, `qemu_smoke::tampered_ahci_seal_is_rejected_under_qemu` (Case 3 keyless boot) — commit: `fdb1522`

### 7. Time is counted in HLT wake-ups, and the receive loop can starve everything else
- **Where:** `live_os_console_loop` in `target_enterprise_kernel/src/main.rs` (the `while let Some(..) = vnet_rx(..)` drain); `HW_IRQ_WAKEUP_COUNTER` in `smp_hw.rs`.
- **Problem:** the timer interrupt only runs while the boot CPU is halted, so a busy stretch of any length counts as at most one tick. The drain loop does not exit while frames keep arriving.
- **Effect:** under sustained traffic the TCP retransmit timer, the login cooldown, cron and the SQL transaction timeout stop advancing, and the console is not polled.
- **Fix:** take time from the TSC or HPET by subtraction, and bound the frames handled per pass.
- Status: Fixed — test: `qemu_smoke::nvme_only_persistence_and_network_flood_resilience_under_qemu` — commit: `b917e2f`

### 8. A pending timer interrupt is delivered as a false preemption of the Ring-3 worker
- **Where:** `target_enterprise_kernel/src/banners_arch_platform.rs:859-884`, used by `exec_service_ring3_mailbox_live` (`:1178`).
- **Problem:** the periodic timer and the preemption timer share vector `0x40`. The main loop runs with interrupts off, so after 4 ms of work a timer interrupt is latched. The preemption setup does not drain it before entering Ring 3.
- **Effect:** a legitimate request is reported as a sandbox fault and fails. It needs more than 4 ms of work without an idle halt first, which a commit in the receive path provides.
- **Fix:** mask and drain the periodic timer before arming, or give the preemption timer its own vector.
- Status: Fixed — test: `qemu_smoke::boots_under_qemu_and_emits_banner` (`verify_ring3_under_latched_periodic_timer_live`) — commit: `946910d`

### 9. Three workspace tests depend on which kernel variant was built last
- **Where:** `binmorph/src/lib.rs:4622` (`funcs.len() >= 2000`), `binmorph/tests/differential_equiv.rs:2509`, `mtd_metrics/tests/independent_verifier.rs:366`.
- **Problem:** they read the ELF at `target_enterprise_kernel/target/x86_64-unknown-none/release/`. A `--prod` build writes its smaller ELF to the same path.
- **Effect:** after any production build the workspace run fails until the default kernel is rebuilt. I reproduced this.
- **Fix:** build each variant to its own path, or have the tests build the input they measure.
- Status: Fixed — test: `factory_builder::tests::prod_kernel_target_dir_is_isolated_from_default_kernel_elf` — commit: `946910d`

### 10. Writes to built-in files are accepted and never saved
- **Where:** `check_writable_vfs_path` at `target_enterprise/src/shell.rs:5780` (protects only `/etc/os-release`); `is_default_system_file` at `:5331` (excluded from the filesystem partition).
- **Problem:** `write /etc/hostname x` or `write /etc/motd x` succeeds, and the change is gone after a reboot.
- **Effect:** an acknowledged write that silently does not persist.
- **Fix:** refuse writes to every path `is_default_system_file` names, or persist them.
- Status: Fixed — test: `shell::tests::built_in_system_files_refuse_write_writehex_rm_and_http_mutation` — commit: `d3f1925`

### 11. The vault nonce is a 15-bit counter seeded from the boot count
- **Where:** `target_enterprise/src/shell.rs:527`, `:3771`.
- **Problem:** the counter only moves toward `0x7FFF`, after which `vault put` fails for good. After a state reset under the same seal key, a `(key name, nonce)` pair can repeat.
- **Effect:** a permanent failure in the long run, and keystream reuse after a reset.
- **Fix:** a 96-bit random or persisted monotonic nonce stored with each ciphertext.
- Status: Fixed — test: `shell::tests::vault_96bit_nonce_diversifies_across_reset_and_stays_tmr_invariant` — commit: `d3f1925`

### 12. The WAL frame format accepts a zero-filled tail, and `from_backing` erases what follows a bad frame
- **Where:** `target_enterprise/src/wal.rs:145-181` and the replay loop; used by the continuity region.
- **Problem:** a length of 0 with a CRC of 0 is a valid frame, so zeros past the true end parse as records. `from_backing` zero-fills everything after the first invalid frame and reports nothing.
- **Effect:** a lost tail is not reported as lost; one damaged frame discards every later record. The shell journal is unaffected (its cursor is under the header HMAC).
- **Fix:** a per-frame magic or sequence number covered by the CRC; return the number of bytes dropped instead of zeroing them.
- Status: Fixed — test: `wal::tests::zero_filled_tail_and_corrupt_frame_preserve_bytes_and_report_dropped_len` — commit: `d3f1925`

---

## Low priority

### 13. Smaller items
- **AP SHA-256 offload (`smp_hw.rs:701-761`):** a timed-out job is not cancelled and results carry no job id, so a late AP can hand the next caller the previous digest. It is off the commit path now; the boot banner still uses it.
  - Status: Unverified — moved `AP_CRYPTO_BUF` to `.bss` and added monotonic `NEXT_AP_CRYPTO_JOB_ID` tagging in `smp_parallel_sha256_3way` in commit `946910d` (exercised by `qemu_smoke::boots_under_qemu_and_emits_banner`), but no fault test injects a delayed AP completing a timed-out job.
- **Emergency crash-dump writer (`hw_storage_drivers.rs:225`):** it shares slot 0 and the DMA buffers with the normal path and reaches MMIO through `PT_MOD_LOCK`. A panic raised under that lock still hangs after printing its message.
  - Status: Fixed — test: `qemu_smoke::tampered_ahci_seal_is_rejected_under_qemu` (Case 4 Ring-0 `#UD` `vec=6` writes `CTTLPENC` encrypted crash dump via lock-free AHCI Slot 1 DMA bypassing `PT_MOD_LOCK`) — commit: `7c321a6`, `fdb1522`, `946910d`
- **Boot counter (`banner_continuity`):** the header is unauthenticated. It no longer gates the restore, but attestation quotes still print it.
  - Status: Fixed — test: `durable_seal::tests::continuity_header_hmac_rejects_forged_boot_counter_and_unauthenticated_v1`, `qemu_smoke::morphed_kernel_boots_and_persists_state_across_multiple_seeds_under_qemu` — commit: `946910d`
- **Aborted SQL transactions (`sql.rs`, `tx_aborted_owner`):** the state is per owner id, and anonymous HTTP clients share one id.
  - Status: Fixed — test: `sql::tests::multiple_aborted_transaction_owners_are_tracked_independently`, `lived_net::tests::http_tcp_slots_and_recycled_sessions_use_isolated_sql_owners` — commit: `946910d`
- **Partial restore on failure:** `unpack_disk_image`, `unpack_fs_partition` and `unpack_sql_partition` each verify before they apply, but a failure in the second or third leaves the first applied. `ShellStore` resets the shell; any other caller must too.
  - Status: Fixed — test: `shell::tests::fs_partition_preserves_inode_mtime_and_unpack_state_image_is_atomic_on_error` — commit: `d3f1925`
- **File times:** `pack_fs_partition` writes `mtime = 1` for every file (`shell.rs:1992`).
  - Status: Fixed — test: `shell::tests::fs_partition_preserves_inode_mtime_and_unpack_state_image_is_atomic_on_error` — commit: `d3f1925`
- **Production boot panics on a timing check:** `smp_hw.rs:2532` panics unless every AP acknowledges a TLB shootdown within 100,000 spins.
  - Status: Unverified — widened `smp_broadcast_tlb_shootdown` to a `250 ms` calibrated TSC deadline (`50,000,000`-spin fallback) in commit `946910d` (exercised by `qemu_smoke::boots_under_qemu_and_emits_banner`), but no test stalls an AP past `100,000` spins.
- **Heap exhaustion is a panic,** and the comment in `heap.rs` that nothing else allocates is wrong (`LivedNet` holds `Vec`s).
  - Status: Unverified — corrected `heap.rs` doc comment in commit `946910d` to document `LivedNet` / HTTPS allocations and the `512 KiB` admission reserve (doc comments cannot be proved by a test; allocator OOM past admission reserve remains a fail-closed panic).
- **Serial output:** `serial_write_byte` (`main.rs:591`) waits on the transmitter without a bound, and the service window prints a line per frame.
  - Status: Unverified — bounded `serial_write_byte` LSR spin to `1,000,000` iterations and removed per-frame serial logging from the boot service window in commit `946910d`, but no QEMU test emulates a hung 16550 UART transmitter.
- **virtio-net:** a transmit is dropped silently when the previous frame has not completed; `vnet_rx` returns "empty" for a discarded completion; the legacy fallback uses a 12-byte header where 10 is correct.
  - Status: Unverified — bounded TX completion wait, multi-descriptor `vnet_rx` loop, and 10-byte legacy header fallback installed in commit `946910d` (modern path exercised by `qemu_smoke` and Triad/Fleet self-tests), but no QEMU test attaches a legacy-only VirtIO-net PCI device or stalls TX completion.
- **`decide_ab_recovery`:** unused by the kernel now. Remove it with its test, or keep it as documented.
  - Status: Fixed — test: `durable_seal::tests::ab_recovery_matrix_covers_clean_interrupted_corrupt_and_double_fault` (kept as standalone documented library helper) — commit: `7c321a6`
- **Stale Triad base image:** `triad.bat` builds `target/cuttle_images/run_bios.img` only when it is missing, and the controller reuses it. Here it was three weeks older than the kernel ELF. I rebuilt it by hand and did not check what the controller does with a stale one. Rebuild it whenever the ELF is newer.
  - Status: Fixed — test: `tools/triad_controller.py --unit-test` (`stage4_stale_bios` `needs_base_bios_rebuild`) — commit: `b995e5e`
- **README:** the QEMU row says 130 banners; the smoke test checks 131. The `https.rs` import of `kernel_fixtures` is unused under `cuttle_prod` (one warning in the production build).
  - Status: Partly fixed — `https.rs` `#[cfg(any(test, not(cuttle_prod)))]` gate verified warning-free via `factory_builder build-kernel --kernel-crate target_enterprise_kernel --prod` and `factory_builder::tests::prod_kernel_target_dir_is_isolated_from_default_kernel_elf` (commit `946910d`); `README.md` banner count (`131`) and `AB_FORMAT_V3` 53-sector storage documentation updated (doc prose is unverified per `GEMINI.md`).

---

## Process notes
- **Put the decision logic where it can be tested.** Most of the High defects I fixed were in kernel glue: ignored results, an ordering, a panic on a counter. None of it could be reached by a unit test. The kernel side of persistence is now a device and some `serial_write_str` calls; keep it that way.
- **A test that re-implements the sequence it is testing proves the test.** `stage17_ab_journal_survives_power_cut_at_every_sector...` wrote its own copy of the commit steps. The kernel's real sequence differed from it (payload sectors, flush, then superblocks) and its recovery skipped half the table.
- **"`let _ =`" on a persistence call is a finding by itself.** Four of them hid the journal overflow.
- **Boot must not assert on stored content.** A self-test that panics on what a user can write is a way to brick a node.

## Not reviewed this round
- Last round's status lines for #1–#14 and R1–R15 (table above).
- The diff of `917109c..d279d75` outside the files listed under Scope: `binmorph`, `diversifier`, `morph_engine`, `mtd_metrics`, `verifier`, `factory_builder` (apart from `qemu_smoke.rs`), `fuzz/`, CI.
- `tools/triad_controller.py`, `tools/cuttle_fleet.py`, `tools/chaos.py`: not read beyond the heal path and the disk-layout constants.
- `lived_net.rs`, `svc_runtime.rs`, the TCP/TLS/HTTP stack, `x509.rs`, `tpm.rs`, `ebpf.rs`, `iommu.rs`: not reviewed, apart from call sites into the shell.
- The Ring-3 stubs and KPTI tables beyond what the memory pass read.
- The bootloader's behaviour (stack guard page, IDT state at entry).
- Under QEMU I did not inject AHCI errors, cut power mid-commit, or send a mutating request during the boot service window. Those paths are tested against the disk model only.
- WHPX: every run here was TCG.
- Carried over from earlier rounds: `rustls` key-material clean-up when a reclaimed session is dropped; measured heap use under load on a VM; the rest of `triad_console.html`.
