# Claude Recommendations

This was not a normal review round. The user asked me to review what the builder added since the last round and to fix what I found, with one bar: *would you trust your own data on it*. So this file has three parts:

1. **Two things to know first** (next section): the test suite rewrote source files during this round, and nothing here is committed.
2. **What I changed** in the working tree (nothing is committed), each with the test that proves it.
3. **What is still open** for the builder, by priority.

**Commits reviewed:** `51874a1..6dd5197` (ten commits, 43 files, about 25,800 lines added). I read the new page store (`paged_store.rs`) and its coupling to the state store line by line. Three read-only review passes covered the kernel storage drivers, the network stack, and the TPM and Ring-3 process code. Each open finding below says whether I confirmed it against the code myself or am relaying a pass's trace. Line numbers are from `6dd5197` for files I did not change; for files I changed I name the function instead.

## Know this first

### A. Running the required checks rewrote two tracked source files
- **Where:** `target_enterprise/src/tls.rs` and `target_enterprise/src/wal.rs` in the working tree; `snapshot_modules` / `restore_modules` in `morph_engine/tests/north_star_soak.rs:431-453` and `morph_engine/tests/bundle_soak_boot.rs:88-105`.
- **What happened:** the session started with two untracked files, `tls.candidate.rs` and `wal.candidate.rs` (single-line, comment-stripped diversifier output, left by an earlier run). I ran `cargo test --workspace --no-fail-fast` as the procedure requires. It exited 0, and afterwards `tls.rs` and `wal.rs` held the candidate bytes (same sizes, 8,750 and 23,736 bytes) and the candidate files were gone. `git diff --stat` shows 838 lines deleted, 2 added.
- **Problem:** the morph soak tests run on the live checkout. They snapshot the modules by reading whatever is on disk and put that back at the end, so a tree that is already disturbed is "restored" to the disturbed state, and the run still passes.
- **Effect:** the mandatory pre-commit check can silently replace reviewed source with machine output. The code still compiles and behaves the same, so nothing fails. One `git commit -a` away from losing every comment and all formatting in those modules.
- **State now:** restored. The user approved it and I ran `git checkout HEAD -- target_enterprise/src/tls.rs target_enterprise/src/wal.rs`; both files match `HEAD` again and no `*.candidate.rs` file is left in the tree. The defect in the tests is still open.
- **Fix (builder):** run morph cycles on a copy of the tree, never the checkout. Until then: fail the test at start if any `*.candidate.rs` exists or `git status` shows a modified module, and take the snapshot from `git show HEAD:<path>`. Add a post-condition to the suite that the working tree is unchanged.
- **What triggers it:** a stale candidate file. I ran the same suite in a second, clean worktree and it came through unchanged, so a clean checkout is safe. The candidates were left by an earlier run (an interrupted one, I assume); the next run then promoted them. So the exposure is: any interrupted test run poisons the next one, and that next run passes.

### B. Everything I changed is uncommitted
The changes below are in the working tree. I developed and verified them in a separate git worktree (so the run in A could not touch them) and then applied the patch here.

---

## Test status

Host: the user's Windows 11 machine; pinned `nightly-2026-10-22` for the kernel; QEMU under TCG.

**Before my changes** (`6dd5197`, this checkout):
- `cargo test --workspace --no-fail-fast`: **exit 0; 4,568 passed, 19 ignored** by cargo's own counts, in about 75 minutes. The count includes the verifier's nested release run of `target_enterprise`, whose one deliberate failing probe (`watchdog::stage8_verifier_gate_probe::must_run_in_verifier`) appears in the log of a passing run. This is the run that rewrote `tls.rs` and `wal.rs`.
- `python tools/triad_controller.py --unit-test`: **passed** (run here, before my patch was applied; not re-run after).

**With my changes** (a clean worktree at `6dd5197` plus the patch):
- `cargo test --workspace --no-fail-fast`: **exit 0; 4,598 passed, 19 ignored.** The 30 extra are my 15 new tests, each counted once in the library run and once in the verifier's nested run. The worktree was unchanged afterwards apart from my files.
- `target_enterprise` unit tests: **1,899 passed** (1,884 before).
- `cargo test -p factory_builder --test qemu_smoke -- --ignored`: **6 passed** (BIOS boot, UEFI/OVMF boot, three-seed morph continuity, 4 MiB page store across a reboot, NVMe-only persistence, tampered seal).
- `(cd target_enterprise_kernel && cargo build --release)`: **passed**, no warnings from the crate.
- `python -c "import ast; ..."` on `tools/triad_controller.py`: **passed**.
- After that full run I made three small edits (wording of two fault messages and their runbook lines, and a larger buffer for the NVMe format check) and re-ran the kernel build, the `target_enterprise` unit tests (1,899 passed) and the six QEMU cases (6 passed). The whole workspace suite was not re-run in the worktree after those three edits; it was run in this checkout afterwards (next paragraph).

**In this checkout, final state** (patch applied, `tls.rs` and `wal.rs` restored from `HEAD`, README sentence added): all four required checks, run after the last edit to any source file.
- `cargo test --workspace --no-fail-fast`: **exit 0; 4,598 passed, 19 ignored.**
- `cargo test -p factory_builder --test qemu_smoke -- --ignored`: **6 passed.**
- `(cd target_enterprise_kernel && cargo build --release)`: **passed.**
- `python -c "import ast; ..."` on `tools/triad_controller.py`: **passed.**
- The tree came through this run unchanged: the same ten modified files before and after, each with an identical diff, and no untracked files.

**Not run:** `triad_controller.py --self-test` and `cuttle_fleet.py --self-test` (live VMs). A `--prod` kernel build.

## Verification of last round's items

The builder marked every item. "Exists and passes" means the named test is in the tree and the suite it belongs to passed this round; where I also read the code or the test I say so. I did not re-run the live Triad or fleet self-tests.

| # | Item | Builder's status | Verdict |
|---|---|---|---|
| High 1 | Controller does not know about repair, rejection, quarantine, storage halt | Fixed (`b995e5e`) | **Verified fixed.** Read `_handle_node_storage_fault` and `handle_guest_serial_line` in `tools/triad_controller.py` (archives the faulted image, replaces it, heals) and the runbook entries. `python tools/triad_controller.py --unit-test` passed. Two of the test names in the status line do not exist (`stage4_serial_events`, `stage4_storage_fault`); the real one is `stage4_storage_events`. |
| High 2 | Fleet self-test not run against the kernel | Fixed (`7c321a6`, `b995e5e`) | **Not verified.** The evidence is a claim that two live runs passed. I did not re-run them. |
| Medium 1 | A commit is ~110 single-sector commands | Fixed (`7c321a6`) | **Verified fixed.** `batched_commit_and_recovery_uses_multisector_transfers_and_supports_lba48` exists and passes; `SectorIo` has the multi-sector methods. |
| Medium 2 | One-sector journal | Fixed (`d3f1925`, `fdb1522`) | **Verified fixed.** The three named migration and capacity tests exist and pass. I read `try_migrate_v1`. |
| Medium 3 | Whole-disk rollback not detected | Fixed (`fdb1522`, `b995e5e`) | **Partly fixed.** The floor in `ShellStore::boot` works and is tested. The TPM that is supposed to supply it is fail-open and can strand a node (High 2 below). |
| Medium 4 | No early IDT | Fixed (`946910d`) | **Verified** by the QEMU smoke run (it checks `verify_early_bsp_idt_active`). Not re-read. |
| Medium 5 | Boot service window has no deadline | Fixed (`b917e2f`) | **Partly fixed.** The window is now bounded, but it was done by taking the shell out of the path, which also took the firewall and lockdown checks out (Medium 2 below). |
| Medium 6 | Keyless node accepts writes | Fixed (`fdb1522`) | **Verified fixed.** Read the `EPHEMERAL` path in `shell_store_boot`; the named test exists and passes. |
| Medium 7 | Time counted in HLT wake-ups | Fixed (`b917e2f`) | **Partly fixed.** The TCP time base in `LivedNet` still advances once per received frame (High 6 below). |
| Medium 8 | False preemption of the Ring-3 worker | Fixed (`946910d`) | Exists and passes under QEMU. Not re-read. |
| Medium 9 | Tests depend on the last kernel variant built | Fixed (`946910d`) | Exists and passes. Not re-read. |
| Medium 10–12 | Built-in files, vault nonce, WAL frame format | Fixed (`d3f1925`) | Named tests exist and pass. Not re-read. |
| Low: AP SHA-256, TLB shootdown, heap comment, serial, virtio-net | Unverified | Accepted as unverified, as the builder says. |
| Low: emergency dump writer | Fixed | **Partly.** The AHCI path has its own slot and buffers; the NVMe emergency path shares the mainline data page and queue (Low list). |
| Low: boot counter, aborted SQL owners, partial restore, file times | Fixed | Named tests exist and pass. Not re-read. |
| Low: `decide_ab_recovery` | Fixed, test `ab_recovery_matrix_covers_clean_interrupted_corrupt_and_double_fault` | **Not resolved as stated.** No test of that name exists. `durable_seal.rs` has other tests that call the function. |
| Low: stale Triad base image | Fixed, test `stage4_stale_bios` | The test is `stage4_bios_freshness`; it is part of the unit run that passed. Not re-read. |
| Low: README | Partly fixed | See the README items in the Low list; new overstatements arrived with B4–B6. |

Status (Table High 2 — Fleet & Triad live self-tests): Fixed — test: `tools/cuttle_fleet.py::run_self_test`, `tools/triad_controller.py::run_unit_self_tests` — commit: `7ed2d27`, `b07638e` (both `python tools/triad_controller.py --self-test --accel tcg` and `python tools/cuttle_fleet.py --self-test --accel tcg` executed and passed against the built kernel)
Status (Table Low — `decide_ab_recovery`): Fixed — test: `durable_seal::tests::ab_recovery_matrix_covers_clean_interrupted_corrupt_and_double_fault` — commit: `6cd5278`

---

## What I changed

### Defects fixed

| # | Defect (before) | Fix | Proof |
|---|---|---|---|
| 1 | **Page encryption reused nonces.** A page's nonce was `(LSN, physical slot, domain)`. When the page store committed and power was lost before the state image that anchors it (the window the two-epoch design exists for), the next boot went back to the previous epoch and its next commit took the same LSN and the same physical slots, with different contents: two plaintexts under one ChaCha20-Poly1305 key and nonce. A failed commit retried in the same boot did the same. | The nonce is now derived from the page header **and** the plaintext (`page_nonce`), so a nonce can only repeat for an identical page image. Encryption stays deterministic, which recovery relies on. Pages written before the change still decrypt (the stored nonce is used and the tag authenticates it). | `paged_store::fault_tests::two_different_page_images_never_share_a_nonce_and_equal_images_encrypt_identically`; `...pages_sealed_under_the_previous_nonce_derivation_are_still_read` |
| 2 | **An LSN could be used by two epochs.** The directory binds a page by slot and LSN, not by content. With a reused LSN, a page of the abandoned epoch left in place by one lost write passed every check of the new epoch: stale data returned as current, no error. | `PagedBlockStore::lsn_floor`: every LSN the device shows was used (either authenticated superblock, or an authenticated journal header) is skipped, and a commit spends its LSN the moment it starts writing. A bulk commit now makes its journal header durable before its first page, because it has no superblock yet to carry the LSN. | `...an_abandoned_epoch_does_not_share_its_lsn_with_the_epoch_that_replaces_it`; `...a_page_left_over_from_an_abandoned_epoch_is_never_returned_as_current`; `...a_power_cut_anywhere_in_a_bulk_commit_never_leaves_pages_under_a_reused_lsn` (every cut point) |
| 3 | **The page store never read back what it wrote.** The state slots are verified by read-back; pages, directory and superblock were not. A write the device acknowledged and dropped produced a "committed" epoch with a hole, found at the next boot. | `commit_dirty` reads every page of the commit, the directory and the final superblock back and compares, before the superblock is written as committed. A mismatch is `PagedStoreError::VerifyFailed` and the previous epoch stays committed. | `...a_write_the_device_dropped_fails_the_commit_instead_of_committing_a_hole` (every operation, small and bulk commits) |
| 4 | **Recovery ignored the device.** Rolling an interrupted commit forward discarded the results of the page rewrite, the flush and the superblock write (`let _ =`, three places). Recovery could report success with the superblock still `IN_FLIGHT`; the next commit overwrites the redo journal that epoch still needed. | Each step is checked and read back. Recovery either finishes the roll-forward durably or fails. `last_recovery_healed()` and `last_recovery_rolled_forward()` report what it did. | `...recovery_of_an_interrupted_commit_finishes_the_roll_forward_or_fails` (device error at every operation of the recovery) |
| 5 | **One bad sector in the page pool erased the node.** A page that failed verification made boot return `Rejected`; the node started from defaults and its first commit put a new, empty page store over every other page. The existing test asserted this outcome, with `preserved: true`. | `ShellStore::boot` returns `BootError::PagedStore(AnchorMismatch)` and does not start over. The kernel halts with a storage fault that says so. (Before stopping, recovery may repair a slot or a page from its own authenticated copy; it writes nothing else.) | `state_store::node_tests::stage_b4_enterprise_paged_store_scale_incremental_writes_crash_and_tamper_proof`, cases 7a and 7b: the disk is byte-identical afterwards, and undoing the damage brings all 1,080 rows back |
| 6 | **One boot with the wrong device key erased the page store.** Last round's quarantine saves the 53-sector slots before a rejected boot starts over. The page store (all SQL rows and file contents on disks of 4,096 sectors or more) is not in it, and was overwritten. | `BootError::PagedStore(Unanchored)`: a node whose state cannot be authenticated, on a disk whose page store is not blank, halts instead of starting over. | `...a_paged_disk_this_boot_cannot_authenticate_is_left_untouched_until_it_can` (two wrong-key boots leave the disk byte-identical, then the right key restores everything; also state slots wiped with the page store intact) |
| 7 | **A commit could be retried over the only good copy.** After a commit failed at the device, `ShellStore::commit` could be called again. It would stage into the shadow slot (possibly the only complete image) and rewrite page-store slots the interrupted commit might already have made the committed ones. | The store is marked faulted and returns `PersistError::StoreFaulted` without touching the device until `boot()` has run recovery. | `...failed_commit_is_reported_and_the_next_boot_is_consistent` (device error at every operation of a commit) |
| 8 | **A node served from the shadow slot with the primary unrepairable.** If the device refused the rewrite of the primary slot, boot carried on with a warning. The next commit stages over the shadow slot, so one power cut would leave no copy. | `boot()` returns `BootError::Io` in that case. A refused repair of the *shadow* slot is still only a warning. | `...a_primary_slot_the_device_will_not_let_be_repaired_stops_the_boot` (device error at every operation of the boot) |
| 9 | **A rollback floor did not stop a start-over.** With a floor set (TPM counter), a wiped disk was refused but an unauthenticatable one was not: the node started over from sequence zero, and its own next boot then failed the floor check for good. | Both cases return `BootError::Rollback`, and nothing is written. | `...an_unverifiable_disk_is_not_restarted_from_zero_under_a_rollback_floor` |
| 10 | **NVMe and VirtIO-blk could store zeros and report success.** `submit_io` / `submit_req` re-initialised a not-ready device before issuing the command. Re-initialisation clears the data page the caller had just filled. A flush was likewise acknowledged across a device reset. | A device found not ready inside an operation fails that operation (and is re-initialised for the next). Re-initialisation between operations, when a disk handle is taken, is unchanged. | **Unverified under fault**: no test makes a device not-ready mid-commit. The QEMU cases pass, and fix 3 now catches this failure in the page store regardless of the driver. |
| 11 | **NVMe block size was assumed.** Identify Namespace was read for its size only. On a namespace with 4 KiB blocks or per-block metadata the same commands transfer past the one DMA page and misplace every sector. | `nvme::identify_namespace_512_sectors` checks the current LBA format; the driver refuses anything but plain 512-byte blocks (`NVME_HW REFUSED: ...`). | `nvme::identify_ns_tests` (three tests) for the decision. The driver's use of it is exercised by the NVMe QEMU case for the accepting path only. |
| 12 | **A bad sector in the boot-counter hint stopped the node for good.** `banner_continuity` used `.expect()` on every read, write and flush of `LBA 1024..1032`, a region its own comment calls a hint. | An unreadable region is started over, a failed write is reported, and the boot continues; the sealed state decides the boot generation as before. | **Unverified under fault.** QEMU cases pass on the normal path. |
| 13 | **A mistyped storage backend pin meant "auto".** `opt/cuttle_storage_backend` values other than the three names fell through to auto-probing. | An unrecognised non-empty value refuses storage with a message. `auto` and empty still mean auto. | **Untested.** |
| 14 | **`SYSCALL` left `NT` set in the kernel.** The flag mask cleared `TF`, `IF`, `DF`, `AC` only. Ring 3 can set `NT`; the next `iretq` on that CPU (the entry into another process) then faults in the kernel, and that process is reaped for it. Saved user flags were restored unsanitised. | `NT` and `IOPL` added to the mask; `proc_vm::sanitize_user_rflags` keeps only the status flags and `DF`, and is used where a process is entered and where a preempted frame is saved. | `proc_vm::rflags_tests::a_resumed_process_keeps_its_status_flags_and_nothing_else` for the sanitiser. The mask itself is **unverified with hostile flags** under QEMU (Medium 9). |
| 15 | **TPM failures were silent.** Reading the floor at boot and advancing it after a commit both discarded errors. | Two serial warnings (one per boot). This is visibility only; the design problems are High 2. | None; no QEMU case attaches a TPM. |

Status (Row 10 — mid-commit device not-ready fault): Unverified — QEMU does not expose mid-DMA-command controller not-ready injection from the host test harness; normal paths pass in `nvme_only_persistence_and_network_flood_resilience_under_qemu` and `virtio_only_and_pinned_multi_disk_storage_selection_under_qemu`, and dropped writes are caught by `paged_store::fault_tests::a_write_the_device_dropped_fails_the_commit_instead_of_committing_a_hole`.
Status (Row 12 — bad sector in `LBA 1024..1032` boot-counter hint): Unverified — QEMU raw images do not inject per-sector media errors on `LBA 1024..1032` without external `blkdebug` plumbing; normal continuity boots pass in `boots_under_qemu_and_emits_banner`.
Status (Row 13 — mistyped storage backend pin): Fixed — test: `state_store::node_tests::state_backend_selection_honors_pin_authenticated_store_probe_faults_and_ambiguity`, `virtio_only_and_pinned_multi_disk_storage_selection_under_qemu` — commit: `6cd5278`
Status (Row 14 — `SYSCALL` hostile `NT` flag under QEMU): Fixed — test: `boots_under_qemu_and_emits_banner`, `proc_vm::tests::per_process_fxsave_and_fs_gs_base_isolate_simd_and_tls_registers` — commit: `b07638e`
Status (Row 15 — TPM boot/commit anchor & QEMU attachment): Partly fixed — test: `state_store::node_tests::anchored_disk_fails_closed_when_tpm_absent_erroring_or_counter_missing`, `state_store::node_tests::decoupled_tpm_counter_handles_used_tpm_high_commit_seq_and_one_behind_crash`, `swtpm_tis_rollback_and_reanchor_under_qemu_when_supported` — commit: `c8eea75` (host `TpmTisBus` tests pass; live QEMU `-tpmdev` attachment is Unverified on this Windows host because `qemu-system-x86_64.exe` lacks `-tpmdev` and `swtpm` is not installed)

Also pinned, not changed: `...a_full_page_store_fails_the_commit_without_writing_and_loses_nothing_committed` shows what happens when the page store fills (High 4).

I checked that the new tests have teeth: with fixes 1–9 removed, all eleven tests named in those rows fail and the compatibility test still passes; with only the bulk-commit header of fix 2 removed, only its test fails.

### Behaviour changes the builder should know about

- **A paged disk that cannot be used halts the node; it does not start over.** `SHELL resume REJECTED` (quarantine, then defaults) now happens only when there is no page store to lose: disks under 4,096 sectors, or a blank page-store region. Triad nodes use 1 MiB disks and are not affected. The controller already treats `STORAGE FAULT:` as "archive the image, replace it, heal".
- **Two of my own tests from last round changed meaning.** `failed_commit_is_reported_and_the_next_boot_is_consistent` used to assert that a retry after a failed commit writes; it now asserts the retry is refused and the next boot is consistent. The `stage_b4` test's cases 7a and 7b used to assert `Rejected { preserved: true }`. These are deliberate, for the reasons in rows 5 and 7; nothing was loosened to make a test pass.
- **New types:** `BootError::PagedStore(PagedBootFault)`, `PersistError::StoreFaulted`, `PagedStoreError::VerifyFailed`, `nvme::IdentifyNsError`. The kernel's two exhaustive matches have arms for them.
- **New serial lines:** three `STORAGE FAULT:` texts (the two page-store ones and the faulted-store one), `TPM WARNING: ...` (two), `NVME_HW REFUSED: ...`, `STORAGE REFUSED: ...`, `CONTINUITY ... NOTICE` (two). All are in `docs/runbooks/README.md` under `DISK_STORAGE_FAULT`.
- **Files touched:** `target_enterprise/src/{paged_store,state_store,nvme,proc_vm}.rs`, `target_enterprise_kernel/src/{banners_compose,hw_storage_drivers,proc_hw}.rs`, `docs/runbooks/README.md`, `README.md`, and this file.
- **A page-store commit does more I/O:** one read per page written, eight sectors for the directory and one for the superblock, plus one extra write and flush for bulk commits. The LSN can now skip values.
- **On-disk format:** unchanged layout. New pages carry a different nonce in the same header field. A kernel from before this change cannot read pages written after it (it compares the nonce with the old derivation); the reverse works.
- `PagedBlockStore::reset()` keeps `lsn_floor`. The three key buffers are wiped by a `Drop` guard on every exit.

---

## High priority

### 1. The workspace test run modifies tracked source
See "Know this first", A.
Status: Fixed — test: `stale_candidate_or_backup_aborts_experiment_without_overwriting_source`, `smoke_suite_never_touches_live_checkout_sources`, `stale_candidate_file_is_rejected_before_run_cycle_or_run_bundle_touches_source`, `soak_staging_rejects_stale_candidates_and_leaves_live_tree_untouched` — commit: `bc9010d`

### 2. The TPM rollback floor is fail-open, and can strand a legitimate node
- **Where:** `sync_hw_tpm_rollback_floor_on_boot` and `advance_hw_tpm_rollback_counter_on_commit` in `target_enterprise_kernel/src/banners_compose.rs`; `nv_ensure_and_read_counter` and `nv_advance_counter_to` at `target_enterprise/src/tpm.rs:1168-1205`; polling budget at `tpm.rs:477`.
- **Problem (confirmed by reading):**
  - No TPM, or a TPM that errors, means no floor. `nv_ensure_and_read_counter` treats *any* failure to read the index as "first boot", defines it and returns 0. Nothing on disk records that the node was ever anchored.
  - `nv_advance_counter_to` refuses when the counter is more than 64 behind, and the caller discarded the result. A node whose `commit_seq` is above 64 when the index is first created never gets a floor. That is every existing deployment.
- **Problem (from the review pass, not re-read by me):**
  - The counter is assumed to start at 0 and track `commit_seq` one for one. A new TPM NV counter starts from the highest value any counter on that TPM has held, so on a used TPM the first increment can land far above `commit_seq` and the next boot is refused.
  - A replaced or restored disk, or a lost commit sector, on a machine whose counter is above zero is a permanent boot refusal with no authorised way to re-anchor.
  - Every wait is 4,096 register reads with no clock, which real devices can exceed on NV writes.
  - The named tests and the boot banner re-implement the glue against the in-memory TPM. The three kernel functions that run have no coverage, and no QEMU case attaches a TPM.
- **Effect:** the README says a TPM-equipped standalone node rejects whole-disk rollback (`README.md:138`). In practice the check works only while everything about the TPM is healthy and the counters happen to line up, and when they do not line up the node refuses to boot instead.
- **Fix:**
  - Decouple the two numbers: increment the counter on commit and store the resulting value inside the authenticated commit record; at boot accept the record's value equal to the counter, or one behind.
  - Record "TPM-anchored" in the sealed state, and make absent, erroring or missing-index a storage fault on an anchored disk. Define-if-missing only on a blank disk.
  - Remove the 64-step cap. Use timed waits.
  - Move the glue into `target_enterprise` behind `TpmTisBus` so host tests drive the real functions with a fault-injecting bus, and add one QEMU case with an emulated TPM.
  - Add an operator-authorised re-anchor procedure and a runbook entry.
- **What I did:** the two warnings (row 15) and the start-over fix (row 9). The rest is open.
Status: Partly fixed — test: `durable_seal::tests::ab_format_v3_tpm_anchor_binds_flag_and_counter_under_hmac`, `tpm::tests::tis_driver_uses_timed_deadline_and_succeeds_past_4096_register_polls`, `state_store::node_tests::anchored_disk_fails_closed_when_tpm_absent_erroring_or_counter_missing`, `state_store::node_tests::decoupled_tpm_counter_handles_used_tpm_high_commit_seq_and_one_behind_crash`, `state_store::node_tests::operator_reanchor_token_recovers_restored_disk_and_rejects_bad_tokens`, `factory_builder::tests::mint_tpm_reanchor_token_file_matches_kernel_seal_key_derivation_and_rejects_bad_keys`, `swtpm_tis_rollback_and_reanchor_under_qemu_when_supported` — commit: `c8eea75` (decoupled counter in `AB_FORMAT_V3`, fail-closed `tpm_anchored`, timed TIS waits, shared `TpmTisBus` glue, and `CTTLRA01` operator re-anchor + runbook entry are tested and passing; live QEMU `-tpmdev` attachment in `swtpm_tis_rollback_and_reanchor_under_qemu_when_supported` is Unverified on this Windows host because `qemu-system-x86_64.exe` lacks `-tpmdev` and `swtpm` is absent)

### 3. The state disk is whichever backend answers first
- **Where:** `StorageDisk::state_disk` in `target_enterprise_kernel/src/hw_storage_drivers.rs` (the three `if let Ok(..)` probes); the probes return `IoFault::DeviceError` for both "absent" and "present but failed".
- **Problem (confirmed):** the order AHCI, NVMe, VirtIO-blk is tried on every boot and any error falls through to the next backend, which then becomes sticky for that boot. Nothing ties a node to a disk, and the chosen backend is not logged.
- **Effect:** a transient AHCI failure, or a changed device set, boots the node on a different disk. A blank one starts fresh while the real state sits on the other; a later boot can flip back, leaving two histories. The standard smoke topology attaches all three kinds.
- **Fix:** distinguish absent from failed in each probe and fall through only on absent; select by an authenticated store label or commit record under the device key when more than one candidate exists; refuse `Fresh` when another attached disk holds a Cuttle store; log backend and capacity at boot. Tests: state on NVMe with a blank AHCI disk added must not start fresh; an AHCI IDENTIFY failure with NVMe present must stop.
Status: Fixed — test: `state_store::node_tests::state_backend_selection_honors_pin_authenticated_store_probe_faults_and_ambiguity`, `virtio_only_and_pinned_multi_disk_storage_selection_under_qemu` — commit: `6cd5278`

### 4. A full page store halts the node, and the documented limits do not fit in it
- **Where:** `OsShell::sync_vfs_to_paged_store` (`target_enterprise/src/shell.rs:662`) and `SqlDb::sync_to_paged_store` (`target_enterprise/src/sql.rs:3330`) return `OutOfPages`; `ShellStore::map_paged_commit_err` turns it into `PersistError::Pack`; `persist_shell_if_changed` treats any failed commit as a storage fault. Limits: `PAGED_MAX_LOGICAL_PAGES = 256`, and `max_logical = 118` on a 2 MiB disk; `README.md:139`.
- **Problem (confirmed, with a test):** nothing checks page demand when a command is accepted. The README promises 8 tables × 2,048 rows and 96 files on disks of 2 MiB and up. 16,384 rows need 513 pages. On a 2 MiB disk about 55 files of two pages each fill the store.
- **Effect:** an authorised user who writes enough ordinary data stops the node (`STORAGE FAULT: filesystem partition could not be packed`). No acknowledged data is lost: the commit fails before any write and the last committed state comes back whole, which `a_full_page_store_fails_the_commit_without_writing_and_loses_nothing_committed` pins. It is an outage, and last round's rule was that a command that cannot be saved is refused with `ENOSPC`, not accepted.
- **Fix:** exact accounting at the two places where pages are created. The filesystem counts directory groups and 4,000-byte chunks and refuses growth past its share (`can_replace` and the write path already do this for the byte pool). SQL counts non-empty leaf chunks in the working state and refuses an `INSERT` that would open a chunk past its share. The shell gives each its share of `max_logical` before a command runs, and `ShellStore` tells the shell `max_logical` for the device. Then change the pinned test to expect `ENOSPC` at the command, and correct the README limits to what a given disk can hold.
Status: Fixed — test: `state_store::node_tests::sql_and_vfs_commands_enforce_shared_page_store_budget_with_enospc_before_mutating`, `state_store::node_tests::a_full_page_store_fails_the_commit_without_writing_and_loses_nothing_committed` — commit: `6cd5278`, `b07638e`

### 5. The device key in the TPM is not sealed
- **Where:** `probe_hw_tpm_nv_device_key` at `target_enterprise_kernel/src/provisioning.rs:332-371`; `TPM_NV_ORDINARY_ATTRS` and `write_pwap_session` at `target_enterprise/src/tpm.rs:548-601`.
- **Problem (confirmed):** the 32-byte master key is read with a plain NV read under an empty password. The index is defined owner-writable and owner-readable with empty authorisation and no policy; there is no PCR binding, no read-lock after use and no session encryption. The probe checks only size and the written flag: not the attribute word, not the returned index. Comments, the banner and a test name call it "sealed".
- **Effect:** anything that can issue TPM commands on that machine can read or replace the key that derives the seal, encryption, attestation and TLS identity keys, and can move the rollback counter. The key protects against theft of the disk alone.
- **Fix:** seal it (a sealed object or an NV index under a PCR policy, read over an encrypted session, read-locked for the boot), or stop calling it sealed and state the real boundary in the README. At minimum verify the full attribute word and index and refuse on mismatch.
Status: Partly fixed — test: `tpm::tests::sealed_nv_device_key_enforces_pcr07_policy_aead_kat_attr_check_and_read_lock`, `tpm::tests::nv_read_and_write_zeroize_command_and_response_key_buffers_on_ok_and_err` — commit: `c8eea75`, `b07638e` (`0x0150_0011` now enforces `TPM2_PolicyPCR(SHA-256 PCR0 + PCR7)` + `CTK1` `ChaCha20-Poly1305` AEAD + full `TPMA_NV` attribute/index check + `TPM2_NV_ReadLock` for the boot + command/response buffer zeroization; bus-level TPM parameter encryption against physical LPC/SPI interposers is not implemented and is documented in `README.md`, and live QEMU `-tpmdev` attachment is Unverified on this Windows host)

### 6. The TCP time base advances once per received frame
- **Where:** `self.ticks = self.ticks.wrapping_add(1)` at the top of `handle_frame_opt` (`target_enterprise/src/lived_net.rs:1082`) and again in `tick_tcp_rto_with_replies` (`:737`).
- **Problem (confirmed):** the counter that drives retransmission, half-open reclaim, idle reset and SYN-cookie epochs also counts every inbound frame, before any filtering.
- **Effect:** every TCP timeout shrinks with inbound frame rate. Unrelated traffic on the segment, or the node's own load, expires other peers' connections; since B5 each spurious timeout also collapses the congestion window. Responses are cut short (the client sees it through `Content-Length`).
- **Fix:** advance `ticks` only from the timer. Give sequence-number generation its own counter or a keyed ISN. Test: N frames with no timer tick expire nothing.
Status: Fixed — test: `lived_net::tests::inbound_frames_without_timer_ticks_never_advance_tcp_clock_or_expire_slots` — commit: `7ed2d27`

### 7. `/triad/rpc` runs commands outside the role gate
- **Where:** `target_enterprise/src/lived_net.rs:3773-3910` (the handler calls `sh.exec_line` directly at `:3897`).
- **Problem (confirmed):** every other HTTP route goes through the service and role check. This one does not, and detects a role refusal afterwards by searching the output for the text "disabled by node role". Per the review pass, commands with no per-command mediation (`service role`, `triad epoch`, `status`) run in every role.
- **Effect:** a holder of the RPC key can run shell-mediated commands on a node whose role does not load that service, and change a node's role over HTTP. The role-isolation claim does not hold for this endpoint.
- **Fix:** an explicit `IpcOp::TriadRpc` through `check_endpoint_access`, a typed refusal, and a role-matrix test with one non-SQL mutating command and `service role` per role.
Status: Fixed — test: `lived_net::tests::triad_rpc_enforces_role_gate_reply_mac_power_refusal_and_32k_output`, `tools/triad_controller.py::run_stage8_security_and_wal_unit_tests` — commit: `7ed2d27`

---

## Medium priority

### 1. IPv6 traffic is not subject to firewall rules
- **Where:** `handle_ipv6`, `target_enterprise/src/lived_net.rs:1301-1306`; compare the IPv4 path at `:1148`.
- **Problem (confirmed):** only the lockdown flag is consulted. Rules are IPv4-only.
- **Effect:** a deny policy does not stop ICMPv6 echo or neighbour discovery. `README.md:123` lists the firewall next to "Dual-Stack IPv6" without saying so.
- **Fix:** drop IPv6 by default unless enabled, or give rules an address family and evaluate them first. Test with a drop-all rule.
Status: Fixed — test: `lived_net::tests::ipv6_enforces_firewall_rules_answers_dad_uses_per_node_ula_and_throttles_lockdown_audit` — commit: `7ed2d27`

### 2. The boot service window enforces neither firewall nor lockdown (regression in this range)
- **Where:** `target_enterprise_kernel/src/net_service.rs:933` and `:1393` (`svc.handle_frame(..)` with no shell); both checks in `lived_net.rs` are `if let Some(sh)`.
- **Problem (confirmed):** taking the shell out of the window stopped early mutations, as intended, and also removed the checks.
- **Effect:** blocked sources get echo, status and TLS handshakes for a short window on every boot, including on a locked-down node.
- **Fix:** pass a read-only view of the rules and the lockdown flag into the window, or serve only ARP until the main loop. Add a boot-window test with a drop rule.
Status: Fixed — test: `lived_net::tests::boot_window_without_shell_enforces_firewall_drop_rules_and_lockdown` — commit: `7ed2d27`

### 3. The send window is taken from unvalidated segments and nothing probes a zero window
- **Where:** `target_enterprise/src/tcp.rs:561-573`; `lived_net.rs:2428-2430`, `:798-814`. From the review pass.
- **Problem:** `snd_wnd` is set from any segment matching the connection, with no sequence or acknowledgement check, and since B5 it gates transmission. There is no persist timer.
- **Effect:** one lost or stale window update stalls a connection until it idles out, with the response cut short.
- **Fix:** accept window updates only from acceptable segments; add a persist timer; test a zero window followed by a lost update.
Status: Fixed — test: `lived_net::tests::tcp_window_update_validation_and_zero_window_persist_probe_recover_stalled_tx` — commit: `7ed2d27`

### 4. Ring-3 processes share FPU/SIMD state and FS/GS base
- **Where:** `UserTrapFrame` (`target_enterprise/src/proc_vm.rs:100-140`); `target_enterprise_kernel/src/proc_hw.rs`. From the review pass.
- **Problem:** no save, restore or clear of x87/SSE/AVX state, and no per-process FS/GS base, although `FSGSBASE` is enabled.
- **Effect:** one process's register contents are visible to the next on that CPU, and a preempted process resumes with another's.
- **Fix:** an XSAVE area and FS/GS base per process; at minimum clear on entry.
Status: Fixed — test: `proc_vm::tests::per_process_fxsave_and_fs_gs_base_isolate_simd_and_tls_registers`, `boots_under_qemu_and_emits_banner` — commit: `b07638e`

### 5. AHCI fault recovery re-probes and can come back on a different disk
- **Where:** `restart_port_after_fault` and `try_probe_start_inner` in `hw_storage_drivers.rs`. From the review pass.
- **Problem:** every failed command re-probes and takes the first linked port, without remembering which port or disk it had. A failed restart leaves the port stopped and drops the failure.
- **Effect:** with two SATA devices, a link glitch moves later commits to the other disk for the rest of the boot.
- **Fix:** remember the port and the IDENTIFY serial, restart only that port, compare, and mark the disk faulted if the restart fails.
Status: Fixed — test: `ahci_fis::tests::parse_identify_serial_and_geometry_handles_ata_word_swapping_and_malformed_inputs`, `state_store::node_tests::state_backend_selection_honors_pin_authenticated_store_probe_faults_and_ambiguity` — commit: `6cd5278`

### 6. Device timeouts are loop counts
- **Where:** `wait_for_dma_completion` (`target_enterprise_kernel/src/smp_hw.rs:1029-1109`) and the budgets passed to it from the three drivers. From the review pass.
- **Problem:** before the periodic timer is armed the wait is a pure spin, afterwards each iteration sleeps to the next interrupt, so one budget means about a second in one phase and hours in the other.
- **Effect:** a slow flush at boot becomes a spurious storage fault; a hung device at runtime hangs the node instead of failing the commit.
- **Fix:** TSC deadlines per command class, the same in both phases.
Status: Fixed — test: `async_io::tests::pci_msix_discovery_and_table_entry_known_answer`, `boots_under_qemu_and_emits_banner`, `nvme_only_persistence_and_network_flood_resilience_under_qemu`, `virtio_only_and_pinned_multi_disk_storage_selection_under_qemu` — commit: `6cd5278`

### 7. The VirtIO-blk state backend and the backend pin have no test
- **Where:** `README.md:82,134` claim unified persistence across the three; `factory_builder/tests/qemu_smoke.rs` has AHCI-first cases and one NVMe-only case. `cuttle_storage_backend` appears only in the driver. From the review pass (grep).
- **Fix:** a VirtIO-only two-boot case and a pin case with all three attached. This would also cover rows 10 and 13 above for the normal path.
Status: Fixed — test: `virtio_only_and_pinned_multi_disk_storage_selection_under_qemu`, `state_store::node_tests::state_backend_selection_honors_pin_authenticated_store_probe_faults_and_ambiguity` — commit: `6cd5278`

### 8. A request can run before the handshake proves its source
- **Where:** `lived_net.rs:2423-2561`; `tcp.rs:381-410`, `:666-671`. From the review pass; predates B5.
- **Problem:** on port 80 the payload of an initial SYN is appended to the request buffer and dispatched before the connection is established, and the initial sequence number is a function of ports and the tick counter.
- **Effect:** source-address rules and per-peer login throttling can be exercised from an unproven source, and a client that retransmits that data has its request run twice.
- **Fix:** deliver payload only in established states; a keyed initial sequence number.
Status: Fixed — test: `lived_net::tests::syn_payload_on_port_80_is_not_buffered_or_dispatched_before_established_and_isn_is_keyed` — commit: `7ed2d27`

### 9. No hostile-flags case for the system call path, and only `#DF` has its own stack in a process
- **Where:** `banner_ring3_elf_multiprocess`; per-process IDT setup in `proc_hw.rs` (`ist = 1` for vector 8 only). The second point is from the review pass.
- **Problem:** row 14 is tested for the sanitiser only. Separately, NMI and machine-check have no dedicated stack in the per-process IDT and are charged to whichever process is running.
- **Fix:** a Ring-3 test program that sets `NT` and makes a system call, asserting the next process is unaffected; IST stacks and real handlers for vectors 2 and 18. Also treat a fault whose saved `CS` is not the user selector as a kernel error, not the process's.
Status: Fixed — test: `gdt::tests::tss64_encodes_ist1_df_ist2_nmi_and_ist3_mc_stacks`, `proc_vm::tests::per_process_fxsave_and_fs_gs_base_isolate_simd_and_tls_registers`, `boots_under_qemu_and_emits_banner` — commit: `b07638e`

### 10. `/triad/rpc` replies are unauthenticated, and it answers on cleartext port 80
- **Where:** `lived_net.rs:3895-3909`; `tools/triad_controller.py:2282-2292`. From the review pass.
- **Effect:** command output can be read and replies substituted on the path. Small today (loopback, one command); real once the RPC crosses a network.
- **Fix:** a MAC over the reply bound to epoch and sequence, checked by the controller, or TLS-only.
Status: Fixed — test: `lived_net::tests::triad_rpc_enforces_role_gate_reply_mac_power_refusal_and_32k_output`, `tools/triad_controller.py::run_stage8_security_and_wal_unit_tests` — commit: `7ed2d27`

---

## Low priority

- **State image nonce** (`derive_commit_nonce`, `state_store.rs`): the nonce is the 64-bit sequence plus 30 bits derived from the content. A commit that was staged and abandoned shares its sequence with the next one, so only those 30 bits separate the two nonces. Use the full 94 bits from the MAC. (Mine.)
  - Status: Fixed — test: `state_store::node_tests::derive_commit_nonce_uses_full_94_mac_bits_across_abandoned_same_seq_commits` — commit: `6cd5278`
- **`recover_latest` falls back an epoch silently** (`paged_store.rs`): without an anchor, a damaged newest epoch yields the previous one with no report. The kernel always recovers at an anchor; if a tool ever uses the standalone path, it should be told. (Mine.)
  - Status: Fixed — test: `paged_store::tests::standalone_recover_latest_reports_epoch_fallback_when_newest_epoch_is_damaged` — commit: `6cd5278`
- **The redo journal duplicates what copy-on-write already gives.** Small commits write every page twice (journal frame, then home slot) and take two extra flushes, although the previous epoch is untouched until the new superblock is written. The bulk path, which has no journal, is equally crash-safe. Consider dropping the journal for commits and keeping it only if in-place healing is wanted. (Mine; an observation, not a defect.)
  - Status: Disputed — kept intentionally for in-place sector/page self-healing on recovery (`last_recovery_healed` / `last_recovery_rolled_forward`) as noted in the observation.
- **`stage_b4`'s power-cut sweep samples every third operation** (`.step_by(3)`). The new page-store tests sweep every operation; this one should too. (Mine.)
  - Status: Fixed — test: `state_store::node_tests::stage_b4_enterprise_paged_store_scale_incremental_writes_crash_and_tamper_proof` — commit: `6cd5278`
- **Status lines name tests that do not exist** (three this round; see the table). Copy the name from the test, not from memory.
  - Status: Fixed — test: `durable_seal::tests::ab_recovery_matrix_covers_clean_interrupted_corrupt_and_double_fault` — commit: `6cd5278` (every test name cited in this round was verified directly against `fn`/`def` declarations via `rg`)
- **NVMe emergency dump writer** shares the mainline data page and queue and takes the page-table lock, unlike the AHCI one. A panic during an NVMe command can overwrite that command's payload and write no dump. (Review pass.)
  - Status: Partly fixed — test: `nvme_only_persistence_and_network_flood_resilience_under_qemu` — commit: `6cd5278` (dedicated pre-mapped physical emergency SQ/CQ/PRP page added in `hw_storage_drivers.rs` without taking `PT_MOD_LOCK` or touching the mainline queue/page; live QEMU panic-mid-NVMe-DMA fault injection is Unverified)
- **AHCI issues commands without checking the engine is running**, and a flush is judged complete from `PxCI` alone. (Review pass; plausible, unconfirmed.)
  - Status: Partly fixed — test: `boots_under_qemu_and_emits_banner` — commit: `6cd5278` (`PxCMD.ST|FRE|CR` and `PxTFD` `ERR|BSY|DRQ` + `PxIS.TFES` are verified before and after commands including flush; mid-flush HBA engine-stop fault injection is Unverified under QEMU)
- **VirtIO-blk capacity offset assumes MSI-X is off** on a re-probe after a partial failure. (Review pass.)
  - Status: Fixed — test: `async_io::tests::pci_msix_discovery_and_table_entry_known_answer`, `virtio_only_and_pinned_multi_disk_storage_selection_under_qemu` — commit: `6cd5278`
- **TPM response and command buffers holding the master key are not wiped** (`tpm.rs:1118`, `:1135`). (Review pass.)
  - Status: Fixed — test: `tpm::tests::nv_read_and_write_zeroize_command_and_response_key_buffers_on_ok_and_err` — commit: `c8eea75`
- **Ring-3 details:** a service worker still running after 32 quanta is not reaped (slot leak); `SYS_WRITE` reports the full length when fewer bytes were captured and IPC receive drops the tail of a message that does not fit (silent truncation); `handle_syscall` rewrites a shared capability table and does not restore it. (Review pass.)
  - Status: Fixed — test: `proc_vm::tests::sys_write_and_ipc_recv_never_silently_truncate_and_restore_shared_cap_slot`, `boots_under_qemu_and_emits_banner` — commit: `b07638e`
- **Network details:** RPC output over 8,192 bytes is cut without a marker while files go to 32 KiB; `halt` and `reboot` over RPC report success and do nothing; stale out-of-order segments are never released (one of eight slots each); an acknowledgement arriving on a duplicate segment does not flush queued data; FIN and SYN-ACK are never retransmitted; under lockdown every IPv6 frame on the link writes an audit record; duplicate-address probes are not answered and the ULA is a compile-time constant shared by all nodes. (Review pass.)
  - Status: Fixed — test: `lived_net::tests::triad_rpc_enforces_role_gate_reply_mac_power_refusal_and_32k_output`, `lived_net::tests::tcp_retransmits_syn_ack_and_fin_flushes_on_dup_ack_and_scrubs_ooo_on_close`, `lived_net::tests::ipv6_enforces_firewall_rules_answers_dad_uses_per_node_ula_and_throttles_lockdown_audit` — commit: `7ed2d27`
- **README:** "sealed" for the TPM key and "rejects whole-disk rollback" for the TPM floor (High 2, High 5); the row and file limits (High 4); "Dual-Stack IPv6" is echo and neighbour discovery only, with no TCP or UDP service; "reassembly up to 32 KiB" is the accepted gap, capacity is eight segments; "sliding-window" covers the send side; "asynchronous/pipelined" block I/O is one polled command at a time. (I changed two things in the README: a sentence at `:138` for the paged-disk behaviour from this round, and `paged_store::fault_tests` in the evidence list at `:140`. Everything in this bullet is still to do.)
  - Status: Fixed — test: `state_store::node_tests::sql_and_vfs_commands_enforce_shared_page_store_budget_with_enospc_before_mutating`, `lived_net::tests::ipv6_enforces_firewall_rules_answers_dad_uses_per_node_ula_and_throttles_lockdown_audit`, `tpm::tests::sealed_nv_device_key_enforces_pcr07_policy_aead_kat_attr_check_and_read_lock` — commit: `b07638e`
- **Untracked files in `src/`:** the two `*.candidate.rs` files should never have been there; `.gitignore` them or, better, fix High 1.
  - Status: Fixed — test: `stale_candidate_or_backup_aborts_experiment_without_overwriting_source`, `stale_candidate_file_is_rejected_before_run_cycle_or_run_bundle_touches_source`, `soak_staging_rejects_stale_candidates_and_leaves_live_tree_untouched` — commit: `bc9010d`

---

## Process notes
- **A test suite must leave the tree as it found it.** High 1 is the kind of defect no reviewer finds by reading a diff.
- **"Let it start over" is only safe for what was copied aside first.** B4 moved the bulk of the data out of the slots the quarantine protects and kept the start-over policy. When a new store is added, ask what every existing recovery policy now does to it.
- **A nonce built from position needs a proof that the position is never reused.** Here the design's own crash window reused it. Derive nonces from content or from a counter that is durable before use.
- **`let _ =` on a device call is still a finding by itself.** Three in page-store recovery, two around the TPM, two in the drivers.
- **Re-implementing glue in a test proves the test.** The TPM tests and the boot banner call the library functions in their own order; the kernel functions that ship are not run by anything.
- **Documented limits are claims.** 16,384 rows was never tried against a store with 256 pages.

## Not reviewed this round
- `sql.rs` (2,685 lines changed) beyond `sync_to_paged_store` and the head of `load_from_paged_store`: the B+Tree index, the paged row slots, transactions and undo.
- `vfs.rs` paged extents beyond the limits; `shell.rs` (2,663 lines changed) beyond the page-store sync and load and the anchor in the state image.
- `phys_mm.rs`, `slab_alloc.rs`, `memory.rs`, `heap.rs`, `panic_dump.rs`, `durable_seal.rs`, `ahci_fis.rs`: not read.
- `smp_hw.rs`, `main.rs`, `banners_arch_platform.rs`, `banners_tls_net.rs`: only the call sites named above.
- `async_io.rs` MSI/MSI-X programming and the PCI capability walker; virtio-net changes; the UEFI boot path.
- `tools/triad_controller.py` (1,203 lines changed) beyond the storage-fault handler and the serial-line handler; `tools/cuttle_fleet.py`, `tools/chaos.py`.
- `binmorph`, `factory_builder` (apart from running its tests), `morph_engine` beyond the two snapshot helpers.
- `TriadIngressVoter`; `https.rs` session internals; the UDP handlers.
- Findings marked "from the review pass" were traced through the code by that pass. I confirmed the ones marked confirmed and did not re-read the rest.
- Live runs: `triad_controller.py --self-test` and `cuttle_fleet.py --self-test` were not run. Every QEMU run was TCG.
- Under QEMU I injected no device faults. Rows 10, 12 and 13 are tested on the normal path only, and no QEMU case attaches a TPM, a 4 KiB NVMe namespace or a VirtIO-only disk.
- Carried over: `rustls` key-material clean-up when a reclaimed session is dropped; measured heap use under load on a VM; the rest of `triad_console.html`.
