# Claude Recommendations

Review of the 4 commits after `2aa69b0`, up to `db46a14`: `e76900c` (RUSTFLAGS and federation), `9e097a5` (HTTP/TCP framing, CloseWait, RTO, hex VFS sync, TLS provisioning), `64118bd` (Triad WAL checkpointing, pending entries, ACLs, fleet) and `db46a14` (status lines). The range is 25 files, +2,953 / −735 lines. Line numbers are from `db46a14`. The checkout had no uncommitted changes.

**Test status at review time** (the user's Windows 11 host, stable 1.93.1, nightly 1.97.0 of 2026-05-08, QEMU installed; the first round where all four required checks could be attempted here)
- `cargo test --workspace --no-fail-fast`: **2,447 passed, 0 failed, 15 ignored.** This matches the builder's count.
- `(cd target_enterprise_kernel && cargo build --release)`: **passed.**
- `cargo test -p factory_builder --test qemu_smoke -- --ignored`: **1 passed, 1 failed.**
  - `boots_under_qemu_and_emits_banner` passed.
  - `tampered_ahci_seal_is_rejected_under_qemu` failed while packaging. Rebuilding `factory_builder_pkg` runs the `bootloader 0.11.17` build script, and its BIOS stage-4 and UEFI stages fail to compile on this nightly (the `x86_64` crate implements `Step::forward_overflowing`, which this nightly doesn't have).
  - The failure is the same from Git Bash and from PowerShell. It comes from the toolchain, not from this round's code (see #4).
- **Python:**
  - AST parse: passed.
  - `https_check.py --self-test`: passed.
  - `cuttle_fleet.run_fleet_unit_tests`: passed.
  - `triad_controller.py --unit-test` as written **did not run.** `TriadController.__init__` repackages `run_bios.img` through `cargo run -p factory_builder` because the kernel ELF had just been rebuilt, and that hits the same bootloader failure.
  - With `BASE_ELF` patched to a missing path in-process (the controller's new no-image fallback), `run_unit_self_tests()` **passed.**
- Not run: the live Triad and fleet self-tests (VMs; packaging is also blocked).

## Verification of last round's items

| # | Item | Verdict | Notes |
|---|---|---|---|
| 1 | WAL compaction rewrites history | **Partly fixed** | Key-level compaction is gone. A majority-agreed checkpoint plus tail replaces it, and the vote sorts rows. But the checkpoint is built from console `SELECT` output, which is lossy (new #2). The named test runs 2–4 statements and calls `checkpoint_wal()` directly. The status line says it runs more than `MAX_WAL_ENTRIES` mixed statements. |
| 2 | No pending/applied marker | **Partly fixed** | Done: pending and committed status, undo when the write-ahead save fails, a 2-of-3 quorum to commit, rebuilding minority acceptors, and boot-time resolution. The rollback branch is tested. The commit branch at boot is untested and defeats rollback detection (new #3). |
| 3 | HTTP connections keep reading after a terminal response | **Verified fixed** | A per-slot `http_input_closed` flag. Port 80 sends FIN once drained, and port 443 stops after `close_sent()`. `Transfer-Encoding` gets 501. Bad or duplicate `Content-Length` and malformed heads get 400. `Connection` is parsed as a token list. Tests send trailing bytes and assert FIN. Small TCP note in #9. |
| 4 | `wfe` heal can't copy most files | **Not resolved on real nodes** | The kernel side works and is tested: `cathex`/`writehex`, plus VFS growth and compaction. But the controller parses an output format that only its fake shell produces, so on a real VM every file read fails (new #1). The fake shell still doesn't match the kernel, and there's no real-VM test. |
| 5 | Windows secret ACL timing | **Partly fixed** | The ACL is applied to the empty temp file before the secret is written, and an icacls failure now raises. `run.bat` uses the SID and checks the exit code. I confirmed here that `write_secret_file` produces an owner-only ACL. Remaining: Python still names the principal from `USERDOMAIN\USERNAME` (the commit message says SID), and the test checks ordering and failure only, not the resulting ACL or POSIX mode (#7, #8). |
| 6 | Fingerprint edge cases | **Verified fixed** | Adoption requires the majority to match the saved digest, only rolled-back nodes are replayed, the parity digest is recorded only if `tx_seq` didn't move, and an unreadable probe at boot is retried. Two-node-rollback test added. Caveat: pending resolution runs first and can bypass all of this (#3). |
| 7 | Backpressure becomes 413s | **Partly fixed** | The per-request limit moved into the framer, so complete pipelined requests no longer count toward 8 KiB. Buffer-level caps remain (64 KiB on :80, 32 KiB plaintext on :443). Past them, queued requests are still discarded with a 413 instead of backpressure, and the two ports still differ. Acceptable for now. |
| 8 | `CloseWait` handling | **Verified fixed** | `tcp.rs` rejects data and FIN in `CloseWait`. FIN is sent only once the framer reports `Incomplete`. The test never sends more than 8 pipelined requests (#7). |
| 9 | Idle reclaim | **Partly fixed** | Reclaim now sends RST, and the idle tick is refreshed only after a segment is accepted (the test would fail on the old code). The timer now advances on LAPIC interrupts, but its constants are interrupt counts, not seconds (#6). |
| 10 | Wrong-size device key silently downgrades | **Verified fixed** | A distinct `PROVISIONING ERROR … size=N` line. The classification is unit-tested. The kernel print path isn't covered by a test. |
| 11 | `compose_kernel_rustflags` edge cases | **Verified fixed** | Each missing cfg is added individually, caches are wiped only for seeded builds, `CARGO_ENCODED_RUSTFLAGS` is removed, and there's a partial-cfg test. One edge case in #9. |
| 12 | Small kernel-crypto items | **Verified fixed** | `sign_der` returns a `Result`, the kernel uses `try_derive`, and `hw_words` is zeroed with volatile writes and a fence. |
| 13 | Federation threshold counts ids | **Verified fixed** | Duplicate decoded keys are rejected, and the threshold counts distinct verified keys. The denylist now has all five RFC 8032 §7.1 keys (I re-derived the three new ones with OpenSSL) plus the old test seeds, and the fallback key is checked. Tests use `OsRng` keys. |
| 14 | Heal robustness | **Verified fixed** | Tables are recreated from schema, replays are wrapped, heals are capped at 3 (then ALERT and OFFLINE), and early returns reset state. Tests passed here. |
| 15 | Secret loader and cron migration | **Verified fixed** | Per-client token isolation (the fleet test passed here) and a WARN for each dropped cron job (tested). |
| 16 | Console and fleet leftovers | **Verified fixed** | Direct links are hidden in fleet mode or when ports aren't forwarded, and legacy `localStorage` keys are cleared. The synthetic web load is now `guard status` over serial. That exercises svc-http mediation, but not the TCP/HTTP path. |
| 17 | Serial reads cut short | **Verified fixed (logic)** | `cat` and `ls` wait for the prompt, timeouts clear buffered lines, and a `wfe` mismatch is confirmed by a second probe. It has no effect on `wfe` until #1 is fixed. |
| 18 | `https_check.py` TLS 1.2 check | **Verified fixed** | A server alert is now required. The self-test passed here. |
| 19 | Atomic WAL write | **Verified fixed** | Temp-file cleanup in `finally`, and a POSIX directory fsync. Tested. |
| 20 | Tests that don't check what their names say | **Partly fixed** | Done: the 413 test sends trailing bytes, the fixture test was renamed and no longer pins the threshold, and tests were added for partial RUSTFLAGS, a crash after write-ahead and a two-node rollback. Remaining: the HTTPS high-water section never reaches high water, the contention test is unchanged, there's no test past `MAX_WAL_ENTRIES`, and the ACL test checks ordering only (#7). |
| 21 | Docs that overstate the code | **Partly fixed** | Done: `TlsEntropyStatus` is gone, the KAT headers are corrected, and 413s on :443 have their own audit label (`net:https:overflow`, asserted). The new README text overstates in other places (#8). |

---

## High priority

### 1. The controller can't parse the kernel's `cathex`/`writehex` output, so the web-node vote and heal are switched off on real VMs
- **Where:**
  - Controller: `tools/triad_controller.py:1319` (`_read_node_file_bytes` regex), `:1321-1330` (`cat` fallback), `:1359` and `:1369` (`writehex` success checks), and `:1261-1262`.
  - Kernel output: `target_enterprise/src/shell.rs:2714` (`hex len=N off=O data=…`) and `:2854` (`wrote N bytes to P at offset O`). The format is asserted by `shell::tests::cathex_and_writehex_roundtrip_empty_binary_and_multichunk_files`.
  - Fake shell: `tools/triad_controller.py:3441-3479`, which returns `"<len> <hex>"` and `"writehex: …"`.
- **Problem:** The controller expects `^\d+ <hex>$` and the marker `writehex:`. Only the unit test's fake shell produces those; the kernel never does.
  - On a real node every `cathex` falls through to the `cat` fallback. `send_shell_cmd` strips the trailing newline, so the length check fails for any file that ends in `\n`. Every default file does (`/etc/hostname`, `/etc/os-release`, `/etc/motd`, `/proc/net`).
  - `writehex` succeeds on the node, but the controller then falls back to `write`, which appends a newline, or returns False.
  - Paths with spaces can't work either: the kernel's `cathex`/`writehex` split the path at the first space. The status line says space-path sync works.
  - I checked the regex and the fallback against the kernel's exact output in Python. They don't match, and `cat` gives 9 bytes against `ls`'s 10.
- **Effect:**
  - `_state_probe` returns None on every `wfe` node, so `compute_and_verify_raid_parity` never votes. Web Triads silently lose divergence detection.
  - Round 6 at least voted on `cat` digests, so this is a regression.
  - The live fleet self-test asserts `SERVED CONTENT VERIFIED` (`tools/cuttle_fleet.py:1075`) and should now fail. Only the unit tests were run.
- **Fix:**
  - Parse the kernel's real format, or change the kernel to a fixed, documented one. Use one shared definition so the two can't drift.
  - Remove the `cat`/`write` fallbacks, which exist only for test fakes.
  - Generate the fake shell's replies from the kernel format; better, drive the real `OsShell` from a small test binary.
  - Either support quoted paths in `cathex`/`writehex`, or reject paths with spaces and drop the claim.
  - Run `cuttle_fleet.py --self-test` before marking this fixed.
  - Status: Fixed — test: `shell::tests::cathex_and_writehex_roundtrip_empty_binary_and_multichunk_files`, `lived_net::tests::every_endpoint_without_credentials_and_role_isolated_services_are_refused`, `https_interop::every_mutating_endpoint_and_node_role_enforces_auth_over_https`, `triad_controller.run_unit_self_tests` (`RealOsShellHarness` via `target_enterprise/examples/shell_harness.rs`, `/api/sh` `cathex`/`writehex` auth and role checks), `python tools/cuttle_fleet.py --self-test` (`SERVED CONTENT VERIFIED` across 18 live VMs) — commit: `924d655`

### 2. The WAL checkpoint is built from console output that is silently truncated and can't be split safely, so healed nodes lose rows
- **Where:**
  - `tools/triad_controller.py:742-827` (`checkpoint_wal`): the `SELECT` at `:785` and `ln.split("|")` at `:801`.
  - Console reply buffer: `target_enterprise_kernel/src/main.rs:846` (1,024 bytes).
  - `SELECT` formatting: `target_enterprise/src/sql.rs:1305-1335`. `append_bytes` at `:2213` truncates with no marker.
  - Quotes: `target_enterprise/src/sql.rs:2082-2100` rejects a `'` inside `'…'` and has no `''` escape.
- **Problem:** The checkpoint rebuilds each vote table as `DELETE FROM t` plus one `INSERT` per row of `SELECT * FROM t` read over the serial console.
  - **Truncation:** The console caps a reply at 1,024 bytes without saying so. Tables hold up to 64 rows of 24-byte text, so `kv` passes 1 KiB at roughly 20–40 rows. Rows beyond that are left out of the checkpoint.
  - **`|` in values:** A value containing `|` is split into extra cells.
  - **Quotes:** A value stored with double quotes that contains `'` is re-emitted as `'it''s'`, which the kernel's parser rejects, so the row is dropped on replay.
  - **No `CREATE TABLE`:** The checkpoint doesn't record the schema of non-`kv` tables. Rebuilding relies on `provision_sql` or a peer's `.schema`.
  - Checkpoints run automatically once there are more than 64 WAL entries, which happens soon in normal use.
- **Effect:** It's the same class of failure as last round's #1. After a checkpoint, every heal, catch-up and boot replay builds a table with rows missing. The node is outvoted and healed again. After 3 heals it's isolated OFFLINE, and a 2-node replay at boot can make the lossy state the majority.
  - The vote probe itself is also cut at 1 KiB, so divergence beyond the first 1 KiB is invisible. That's older, but the checkpoint turns it into data loss.
  - The fake SQL shells in the tests have no size limit and don't escape, which is why the tests pass.
- **Fix:**
  - Have the kernel provide a lossless, length-framed dump of each vote table, for example hex-encoded cells with a row count and digest, read in chunks. Build the checkpoint from that. Refuse to checkpoint unless the dump's row count and digest match all three nodes.
  - Make the probe use the same dump (or a kernel-computed table digest) instead of truncated `SELECT` text.
  - Include each table's DDL in the checkpoint.
  - Add a test that crosses `MAX_WAL_ENTRIES` with more than 1 KiB of rows, including a value containing `|`, heals a node, and asserts 3/3. The fake shell must apply the same 1 KiB limit as the kernel.
  - Status: Fixed — test: `sql::tests::dump_command_paginates_hex_rows_and_parser_accepts_hex_and_doubled_quote_literals`, `triad_controller.run_unit_self_tests` (`cp_ctrl` against `RealOsShellHarness` with 1,024-byte console cap, 67 statements crossing `MAX_WAL_ENTRIES` with 47 rows > 1 KiB, `|` and `'` values, 2/3 majority checkpoint with 1 node offline, non-`kv` table/index DDL checkpointing, and 3/3 convergence after heal) — commit: `4b31598`

---

## Medium priority

### 3. Resolving a pending entry at boot trusts "digest changed" and overwrites the saved digests, which turns off rollback detection
- **Where:** `tools/triad_controller.py:2243-2333` (`_resolve_pending_wal_at_boot`), especially `:2266-2283`, `:2301-2308` and `:2325-2331`. It runs before `_verify_restored_tx_seq_at_boot` (`:2496`).
- **Problem:**
  - A node counts as having applied the pending statement whenever its fingerprint differs from the pre-write digest, for any reason. Two "post" nodes count as a majority even if they disagree with each other.
  - Both branches then set every online node's `restored_node_digests` and `triad_state_digest` to that node's current fingerprint. The last node wins, and all nodes are marked restored.
  - `_verify_restored_tx_seq_at_boot` then compares each node with the digest that was just recorded from it, so it always passes. `_adopt_tx_seq_from_majority` finds no pending nodes.
  - The commit branch (`:2288`) has no test. The status line claims "2/3 majority partial commit reconciliation", but only the rollback path is tested.
- **Effect:** If the controller crashed mid-write, and two disks were also rolled back or changed while it was down, the pending statement is marked committed and replayed onto the one correct node. The rolled-back state is recorded as trusted. The vote then heals the correct node, and after 3 heals isolates it. This is the round-6 #6 protection bypassed. It needs two conditions together, so it's Medium.
- **Fix:**
  - Treat a node as "post" only if its fingerprint equals what replaying the pending statement onto the pre-write state would give. A practical version: the post nodes must agree with each other, and one must match a scratch rebuild (checkpoint + committed tail + pending entry).
  - Never overwrite `restored_node_digests` or `triad_state_digest` with per-node values here. Set the triad digest only from an agreed majority, and leave other nodes for the normal verify and adopt steps.
  - Add tests for commit-at-boot, and for pending entries combined with a two-node rollback.
  - Status: Fixed — test: `triad_controller.run_unit_self_tests` (`_resolve_pending_wal_at_boot` rollback branch, 2/3 commit-at-boot branch, pending entry combined with 2-node rollback to genesis, and `finally` pending cleanup on node execution exception) — commit: `2d68dc6`

### 4. Kernel packaging depends on a floating nightly; QEMU smoke and the controller unit tests fail on this host
- **Where:**
  - `factory_builder_pkg/rust-toolchain.toml` and `target_enterprise_kernel/rust-toolchain.toml` (`channel = "nightly"`).
  - `factory_builder_pkg/Cargo.toml` (`bootloader 0.11.17`, bumped in `75969d3` "for current nightlies").
  - `tools/triad_controller.py:524-547` (the controller runs `cargo run -p factory_builder` in `__init__`).
- **Problem:**
  - On this host the packager's cached build predates the bump (binary from 10-17, bootloader build outputs from 09-21). Any rebuild compiles bootloader 0.11.17's stage crates, which fail on the installed nightly of 2026-05-08.
  - The builder's "qemu_smoke: 2 passed" lines can't be reproduced here, and the commits don't say which toolchain was used.
  - The controller unit tests also need this packaging step whenever the kernel ELF has changed, so a unit test depends on building a bootloader.
- **Effect:** Two of the four required checks fail on the user's machine for reasons unrelated to the code under review. A fresh clone on a slightly older nightly fails the same way.
- **Fix:**
  - Pin a dated nightly that's known to work with bootloader 0.11.17 in both toolchain files, and state it in the README. For now, `rustup update nightly` on this host should unblock it.
  - Have the builder record `rustc +nightly -vV` in each commit's "Checks run".
  - Make `run_unit_self_tests()` construct controllers without touching `BASE_ELF`/`BASE_BIOS` or invoking cargo, through an explicit test parameter (see #5).
  - Status: Fixed — test: `cargo test -p factory_builder --test qemu_smoke -- --ignored`, `triad_controller.run_unit_self_tests` (`unit_test=True` avoids `BASE_ELF`/`BASE_BIOS` packaging) — commit: `07f8e3c`

---

## Low priority

### 5. The production controller silently substitutes a fake kernel image and a default QEMU path
- **Where:** `tools/triad_controller.py:502-507` (a `RuntimeError` from `find_qemu`/`resolve_accelerator` is swallowed, then `qemu-system-x86_64` and TCG are used) and `:550-553` (a missing `BASE_ELF` becomes a 64-byte fake ELF inside a zero-filled fake BIOS).
- **Problem:** These fallbacks were added so the unit tests can run without a kernel image. They also apply to `main()`, the fleet provider and `--self-test`.
- **Effect:** A missing QEMU or a missing kernel build no longer stops startup with a clear error. VMs boot a garbage image and stay OFFLINE, and the WHPX check is skipped.
- **Fix:** Keep the strict behaviour by default. Pass an explicit `unit_test=True` (or inject the image bytes and QEMU path) from `run_unit_self_tests()` only.
- Status: Fixed — test: `triad_controller.run_unit_self_tests` (asserts `TriadController(unit_test=False)` raises `RuntimeError` when `find_qemu` fails or `BASE_ELF` is missing) — commit: `07f8e3c`

### 6. TCP timers count interrupts, not time
- **Where:** `target_enterprise_kernel/src/main.rs:854-868`, `target_enterprise_kernel/src/smp_hw.rs:224` (one shared counter for LAPIC timer vector `0x40` and doorbell IPI `0x41`), and `target_enterprise/src/lived_net.rs:63,267,270`.
- **Problem:**
  - A tick is now "any LAPIC interrupt since the last loop pass". That includes the doorbell IPIs that kthread scheduling sends to the APs.
  - The constants are raw tick counts. The calibrated rate is about 250 Hz on QEMU and about 62 Hz on slower APIC buses.
  - So half-open and `LastAck` slots are reclaimed after 16 ticks (about 64 ms on QEMU), and the idle timeout is anywhere from about 16 s to about 66 s depending on hardware.
- **Effect:** A client whose handshake round trip takes longer than about 64 ms (any real WAN client) loses its slot before the final ACK arrives. That's latent today, because all access goes through QEMU user networking on loopback. IPI bursts also shorten every timeout.
- **Fix:** Advance TCP time from the timer interrupt only (its own counter or the calibrated clock). Express the timeouts in milliseconds and convert them with `calibrate_apic_irqs_per_sec`. Make half-open reclaim at least about 1–3 s.
- Status: Fixed — test: `lived_net::tests::tcp_timers_scale_with_calibrated_apic_hz_and_keep_half_open_for_2s`, `qemu_smoke::boots_under_qemu_and_emits_banner` (asserts `read_hw_irq_wakeups() == 0` after Doorbell IPIs before timer vector `0x40` fires) — commit: `c51b86d`

### 7. Tests that don't prove what the status lines claim
- **`https_tx_cap_backpressure_and_idle_rto_reclaim_slots` section 3** (`target_enterprise/tests/https_interop.rs:372-402`): 24 `/app` responses total about 30 KiB. The 8-responses-per-segment cap is reached long before the 16 KiB high-water mark, and 30 KiB is under `MAX_TX_BYTES` (64 KiB). The test would pass with the high-water check deleted. Send more than 64 KiB of responses, or assert that `pending_tx` never went above high water plus one response.
- **`close_wait_ignores_data_after_fin_and_finishes_pipelined_requests`** (`lived_net.rs:3972`) sends one request before FIN. Send more than 8, and assert that all are answered before the server's FIN.
- **#1 checkpoint test** (`triad_controller.py:3307-3408`): two statements and a direct `checkpoint_wal()` call. There's no automatic trigger past `MAX_WAL_ENTRIES` and no 1 KiB limit (see #2).
- **#2:** the commit branch of `_resolve_pending_wal_at_boot` is untested (see #3).
- **#5 ACL test** (`:3207-3241`): checks ordering and failure handling only. On Windows, assert that `icacls` lists exactly the current SID. On POSIX, assert `stat().st_mode & 0o777 == 0o600`.
- **#20 contention test:** unchanged, and still passes on the pre-round-5 code.
- **VFS:** there's no direct test that growing a file shifts the files after it correctly, or that unlinking a file in the middle compacts the pool without corrupting its neighbours (`vfs.rs:496-536`, `:709-741`). The shell test only grows the last file, and never unlinks a file that has others after it.
- **New commands:** no test calls `cathex`/`writehex` through `/api/sh` without a token, or across every node role. `writehex` should get 403 and `cathex` should follow the read-only policy. This is a project standard.
- Status: Fixed — test: `https_interop::https_tx_cap_backpressure_and_idle_rto_reclaim_slots`, `lived_net::tests::close_wait_ignores_data_after_fin_and_finishes_pipelined_requests`, `vfs::tests::growing_and_unlinking_middle_file_shifts_and_compacts_neighbors_intact`, `lived_net::tests::every_endpoint_without_credentials_and_role_isolated_services_are_refused`, `https_interop::every_mutating_endpoint_and_node_role_enforces_auth_over_https`, `triad_controller.run_unit_self_tests` — commit: `924d655`, `4b31598`, `2d68dc6`, `1da1aad`

### 8. Docs and status lines that overstate the code
- **`README.md:105`:** gives the fail-closed banner as `HTTPS DISABLED reason=no hardware entropy`. The kernel prints `HTTPS DISABLED: no hardware entropy (RDRAND and TPM absent)` (`net_service.rs:524`).
- **`README.md:106` (boot proofs):**
  - It credits `tls_provider::self_test()` with HMAC-SHA256 RFC 4231 §4.2–4.4 and HKDF RFC 5869 A.1–A.3. The provider self-test runs one case each: §4.3 and A.1.
  - Those wider vectors are in `kat.rs` (RFC 4231 §4.2–4.5, RFC 5869 A.1–A.2) and in `tls_kat.rs` (HKDF cases 1 and 3, through `tls::`, not the provider).
- **`README.md:106` (tests):** says the tests check "NIST SP 800-38A §F.2.1/F.2.5" and "Wycheproof P-256/X25519 edge cases". Neither appears in any `.rs` file.
- **`64118bd`:** says "current-user SID ACLs via icacls". `restrict_file_permissions` uses `USERDOMAIN\USERNAME` (`triad_controller.py:136-142`); only `run.bat` uses the SID.
- **Status lines:** #1 (">`MAX_WAL_ENTRIES` mixed statements"), #2 ("2/3 majority partial commit reconciliation"), #4 ("space-path … sync") and #5 ("SID ACL check … POSIX 0600 mode check") describe tests that don't do those things.
- **Fix:** Correct the README to match the code. Rewrite the status lines to name what each test actually checks. Use the SID in Python as well, through `whoami /user` or `GetTokenInformation`.
- Status: Fixed — test: `triad_controller.run_unit_self_tests` (asserts `D:PAI(A;;FA;;;{sid})` in `icacls /save` output after `restrict_file_permissions` grants `*{sid}:(F)` via `whoami /user`), `tls_kat::provider_known_answer_self_test` — commit: `1da1aad`

### 9. Smaller items
- **`factory_builder/src/lib.rs:481`:** an inherited `RUSTFLAGS` that is set but blank isn't overridden. Cargo then uses the empty value and ignores the kernel's `.cargo/config.toml` flags, and the build stops at the soft-float `compile_error!`. Always set `RUSTFLAGS` (or remove it) on the child.
- **`target_enterprise/src/tcp.rs:544`:** a server-initiated close moves `Established` straight to `LastAck`, with no FIN-WAIT or TIME-WAIT. If the client's FIN arrives after our FIN has been ACKed, it finds no slot and is dropped, so the client retransmits until it times out. Use FIN-WAIT-1/2, or answer a late FIN with an ACK.
- **`triad_controller.py:753`:** checkpoints need all three nodes ONLINE at the same `tx_seq`. While any node is down the WAL grows without limit. Log it, and cap growth by allowing a checkpoint with two agreeing nodes plus the down node's catch-up from the checkpoint.
- **Single pending tracker (`:1641-1662`, vault path `:1821-1841`):** only one pending tx is tracked. An exception after the write-ahead (other than in the hook) leaves `wal_pending_tx` set. The next write replaces it, and the earlier entry is then saved as `committed`. Clear or resolve the pending entry in a `finally` around the node execution.
- **Heap:** the new per-slot limits (64 KiB HTTP input on :80; 18 + 32 + 64 KiB TLS buffers on :443) allow about 2.5–5 MiB of buffers across 16 slots, including `Vec` doubling, out of an 8 MiB heap. Measure the worst case under load, or cap total buffered bytes across all slots.
- Status: Fixed — test: `factory_builder::tests::configure_kernel_cargo_env_always_sets_rustflags_even_when_inherited_is_blank`, `tcp::tests::server_close_from_established_enters_fin_wait_and_acks_late_client_fin`, `lived_net::tests::connection_close_header_enters_fin_wait_and_acks_late_client_fin`, `lived_net::tests::cross_slot_buffer_cap_and_capacity_shrink_bound_heap_footprint`, `triad_controller.run_unit_self_tests` (2/3 majority checkpoint with 1 node offline + `finally` pending cleanup on exception) — commit: `4b31598`, `2d68dc6`, `07f8e3c`, `a5df92c`

---

## Process notes
- Status lines named their commits and tests, and the code changes match what the commit messages describe. Several "test:" claims describe more than the tests check (#7, #8).
- This is the second round running where a fake serial shell let a controller change pass its unit tests while not working against the real kernel (High #1; round-6 #4 asked for exactly this to be fixed). For any controller change that sends kernel commands:
  - derive the fake's replies from the kernel's real format;
  - run `cuttle_fleet.py --self-test`, or a `wfe` Triad self-test, before marking it fixed.
- `64118bd` bundles 13 items and +1,455 lines of tooling. `GEMINI.md` asks for small, focused commits.

## Not reviewed this round
- The live Triad and fleet self-tests (they need VMs, and packaging is blocked here by #4). The `tampered_ahci_seal_is_rejected_under_qemu` path, for the same reason.
- `triad_controller.py --unit-test` as invoked by the builder. I ran `run_unit_self_tests()` with `BASE_ELF` patched in-process instead.
- Heap headroom with 16 fully loaded slots at the new limits (#9), and rustls key-material clean-up when a reclaimed session is dropped.
- The rest of `triad_console.html`, and the provider's proxying and poll loop.
- Carried over: the SQL owner-selection logic in `exec_as`, the per-request `CPL=3` service hook, CuttleGuard and CuttleChronos beyond earlier paths, the UDP `:8081` triad protocol, and `binmorph`.
