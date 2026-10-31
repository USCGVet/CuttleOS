# Claude Recommendations

Review of the 8 commits after `db46a14`, up to `e9c10f5`: `924d655` (#1), `4b31598` (#2, #9.3), `2d68dc6` (#3, #9.4), `07f8e3c` (#4, #5, #9.1), `c51b86d` (#6), `a5df92c` (#9.2, #9.5), `1da1aad` (#7) and `e9c10f5` (#8 and status lines). Excluding this file, the range is 14 files, +2,816 / −494 lines. Line numbers are from `e9c10f5`. The checkout had no uncommitted changes, and `main` matches `origin/main`.

**Test status at review time** (the user's Windows 11 host; stable 1.93.1; pinned `nightly-2026-10-22` = `rustc 1.101.0-nightly (1a2c4797e 2026-10-21)`; QEMU, TCG)
- `cargo test --workspace --no-fail-fast`: **2,454 passed, 0 failed, 15 ignored** (up from 2,447).
- `(cd target_enterprise_kernel && cargo build --release)`: **passed.**
- `cargo test -p factory_builder --test qemu_smoke -- --ignored`: **2 passed** (`boots_under_qemu_and_emits_banner`, `tampered_ahci_seal_is_rejected_under_qemu`).
- **Python:**
  - AST parse: passed.
  - `https_check.py --self-test`: passed.
  - `triad_controller.py --unit-test`: passed as invoked, with no workaround needed this time.
  - `cuttle_fleet.run_fleet_unit_tests`: passed.
- **Live, on real VMs** (beyond the required checks):
  - `triad_controller.py --self-test` (3 VMs): **passed**. It covers SQL writes during a morph, tamper and heal, restarts, and a wiped disk.
  - `cuttle_fleet.py --self-test` (18 VMs): **passed**, including `SERVED CONTENT VERIFIED` on the web Triad.
- All four required checks pass on this host for the first time.

## Verification of last round's items

| # | Item | Verdict | Notes |
|---|---|---|---|
| 1 | Controller can't parse `cathex`/`writehex` output | **Verified fixed** | Shared reply regexes, and the `cat`/`write` fallbacks are gone. The kernel accepts quoted and space-containing paths. Unit tests drive the real `OsShell` through `examples/shell_harness.rs`, and the Python format helpers are checked against it. `/api/sh` is tested without credentials and for its read-only policy. The live fleet self-test passed here with `SERVED CONTENT VERIFIED`. The harness doesn't model the serial input limit (#4). |
| 2 | Checkpoint built from truncated console output | **Partly fixed** | Done: a new `.dump` command (hex-framed cells, row count, kernel table digest, DDL), read 3 rows at a time. The probe and the checkpoint both use it, and the checkpoint records DDL. Tested past `MAX_WAL_ENTRIES` with more than 1 KiB of rows and with `\|` and `'` values. Remaining: binary and non-printable values (new #1), and wide tables overflowing the first chunk (new #2). The status line names `dump_command_paginates_hex_rows_and_parser_accepts_hex_and_doubled_quote_literals`; the actual test is `sql::tests::sqldump_chunked_lossless_and_doubled_quotes_hex_literals` (passes). |
| 3 | Pending-entry resolution bypasses rollback detection | **Verified fixed** | A pending entry counts as applied only if a quorum of nodes agree on one fingerprint and it equals a replay of the entry onto the pre-write state. Saved digests are no longer overwritten with per-node values. Tests cover commit-at-boot and a pending entry combined with a two-node rollback. A `finally` resolves the pending entry if node execution raises. |
| 4 | Floating nightly breaks packaging | **Verified fixed** | Both toolchain files pin `nightly-2026-10-22`, documented in the README. Unit tests no longer package images. All required checks pass here. |
| 5 | Production controller substitutes a fake image | **Verified fixed** | Strict by default: a `RuntimeError` when QEMU or `BASE_ELF` is missing. `unit_test=True` is used only by `run_unit_self_tests()`, and there's a test. |
| 6 | TCP timers count interrupts, not time | **Verified fixed** | Doorbell IPIs now have their own EOI stub, so only timer interrupts are counted. I checked the stub's machine code (its RIP-relative load resolves to `0x8388`). Timeouts are in milliseconds and converted with the calibrated rate, which is set after calibration. Half-open slots are reclaimed after 2 s. There's a boot-time assertion and a unit test. |
| 7 | Tests that didn't prove their claims | **Verified fixed** | The HTTPS high-water test now exceeds `MAX_TX_BYTES` and asserts the peak queue size. Also: 12 pipelined requests in the CloseWait test, a test growing and unlinking a middle VFS file, an ACL test that asserts the SID ACE, a reworked contention test, and unauthenticated `cathex`/`writehex` tests. (The role loop varies only the controller's role, not the harness shell's; the kernel's role enforcement is covered by the Rust test.) |
| 8 | Docs that overstate the code | **Verified fixed** | The README banner and KAT attributions match the code, and the Python ACL now uses the SID from `whoami /user`. |
| 9 | Smaller items | **Verified fixed** | `RUSTFLAGS` is always set (test). Server-initiated close goes through FIN-WAIT-1/2 (two tests). A 2/3 checkpoint can run while a node is down. Pending cleanup runs in `finally`. A 512 KiB cap now applies across all slots, and buffers are shrunk with `shrink_to_fit` (test). |

---

## High priority

### 1. A vote-table cell that isn't printable ASCII turns off the vote, or is dropped when a node is healed
- **Where:**
  - Kernel: `target_enterprise/src/sql.rs:2373-2400` (`parse_literal`; new in `4b31598`), where `X'..'` hex literals store arbitrary bytes.
  - Controller: `tools/triad_controller.py:1707` (dump cells are decoded as UTF-8), `:1056-1063` (checkpoint cells written as quoted text), `:2360-2363` (`_replay_checkpoint_on_node` skips statements that aren't printable ASCII), and `:1859-1943` (the vote).
- **Problem:**
  - **Invalid UTF-8:** if any cell isn't valid UTF-8, `_dump_node_sql_table` returns None for that node. `_state_probe` then returns None. The vote needs all three probes, so it skips the whole Triad without logging anything. `quorum_status` reads `2/3 DEGRADED TMR MAJORITY ACTIVE (OS-1 + OS-2 + OS-3)`.
  - **Valid UTF-8 but not printable ASCII** (for example a newline, or `é`): the cell reaches the checkpoint as a quoted `INSERT`, and replay then skips that statement because it isn't printable ASCII. So the row is missing on every healed or rebuilt node.
- **I reproduced both** with the real Rust shell (`shell_harness`):
  - A plain-text row injected onto one node is caught and healed.
  - The same injection with a non-UTF-8 cell is never detected: no heal, and only the "degraded" status.
  - A checkpoint `INSERT` for a cell holding a newline fails `is_printable_ascii_command`.
- **Effect:** One unreadable value switches off divergence detection for the whole Triad, with no alert. It can be stored through the normal SQL API, which `X'..'` now invites. A tampered node that holds such a value is never outvoted or healed. Rows with control characters or non-ASCII text are silently lost on every rebuild from a checkpoint.
- **Fix:**
  - Keep TEXT cells as bytes end to end in the controller; don't decode them as UTF-8.
  - Write checkpoint cells as `X'<hex>'` literals (always, or at least for any byte outside printable ASCII). The statement then stays printable and replays losslessly.
  - When two nodes agree and the third node's probe stays unreadable after retries, treat the third node as divergent and heal it, rather than skipping the vote. Log an ALERT whenever a vote can't run.
  - Add tests with the real shell: a vote-table row holding `X'ff'` on one node gets healed, and a row holding `X'0a'` survives checkpoint → heal → 3/3.
- `Status: Fixed — test: tools/triad_controller.py::run_unit_self_tests (High #1a X'ff' tamper heal, #1b X'0a'/X'fffe' checkpoint -> heal -> 3/3, #1c unreadable None probe retry/ALERT/heal via RealOsShellHarness) — commit: 66955c7`

---

## Medium priority

### 2. The first `.dump` chunk can overflow the console buffer for wide tables, and the controller accepts the truncated row
- **Where:**
  - `target_enterprise/src/sql.rs:815-1031` (`exec_dump`): the DDL and index DDL go only into the offset-0 header, and the rows are written at `:1011` through `append_bytes`, which truncates silently.
  - `target_enterprise/src/shell.rs:1785`: on the real serial path the prompt is appended into the same 1,024-byte reply buffer.
  - `tools/triad_controller.py:1691-1712`: `_dump_node_sql_table` doesn't check cells per row.
- **Problem:** A table with a 16-character name, four TEXT columns with 16-character names, an index and 24-byte values needs about 1,095 bytes for its first chunk (header, DDL, index DDL and 3 rows).
  - I confirmed it with the real shell: the reply is exactly 1,024 bytes, and the third row is cut mid-cell with its last column missing.
  - If the cut leaves an even number of hex digits, the controller accepts a row with fewer cells and a shortened value. Every node truncates the same way, so the probes agree, and the checkpoint records an `INSERT` with too few values. That statement fails on replay, and the row is lost on heal.
  - On the real console the prompt also has to fit, so the usable space is about 1,016 bytes.
  - The default tables (`kv`, and `idx` with 3 short columns) fit. Wide custom `vote_tables` don't.
- **Effect:** Silent row loss on heal for wide vote tables. It's the same class as last round's High #2, with a narrower trigger.
- **Fix:**
  - In `exec_dump`, size each row before writing it, stop adding rows when the next one wouldn't fit in `out.len()` minus the prompt, and report the actual `count`. The controller already advances by `count`.
  - Or send the DDL in a separate header-only call.
  - In the controller, reject a row whose cell count isn't the column count.
  - Add a max-width test that goes through `feed_byte`, so the prompt shares the buffer as it does on the kernel.
- `Status: Fixed — test: shell::tests::sqldump_max_width_table_via_feed_byte_never_truncates_rows_or_prompt, tools/triad_controller.py::run_unit_self_tests (Medium #2a max-width 4-column table checkpoint/heal via RealOsShellHarness, #2b truncated row cell-count rejection) — commit: 556ec3b`

### 3. The "immutable system file" guard compares the raw path, so equivalent spellings get through
- **Where:** `target_enterprise/src/shell.rs:2748` (`writehex`), `:2823` (`write`), `:2880` (`rm`) and `:937` (HTTP `VfsWrite`). Each compares the argument byte-for-byte with `/etc/os-release`. The VFS then normalizes the path before opening it.
- **Problem:** A path that normalizes to `/etc/os-release` but is spelled differently (an extra `/` or a `./` segment) passes the check and then opens the protected file. I confirmed with the real shell that `writehex`, `write` and `rm` all modify or remove `/etc/os-release` this way. The bug predates this round for `write`, `rm` and HTTP; `writehex` (round 7) inherited it.
- **Effect:** The "immutable" protection is bypassable by anyone with VFS write permission. The file itself is low-value, but the pattern (checking policy before normalizing) is the defect, and any future protected path would have the same hole.
- **Fix:** Normalize the path once, with the same `normalise_path` the VFS uses, and run every policy check on the normalized form, in one helper used by all shell and HTTP write and delete paths. Add tests for alternate spellings.
- `Status: Fixed — test: shell::tests::immutable_system_file_guard_normalizes_paths_across_shell_and_http — commit: 5f2db72`

---

## Low priority

### 4. `writehex` lines can exceed the shell's 256-byte input limit, and the harness doesn't model it
- **Where:** `tools/triad_controller.py:1613` (96-byte chunks become 192 hex characters plus the path and offset). `target_enterprise/src/shell.rs:1802` drops characters beyond `SHELL_LINE_MAX` (256) silently. `target_enterprise/examples/shell_harness.rs:46-47` calls `exec_line` directly.
- **Problem:** For paths longer than about 45 characters, the `writehex` line is cut. The kernel then rejects odd-length hex, or writes a short chunk. The controller detects that and fails the sync, so the file can never be healed: the node is healed three times and then isolated. `FS_PATH_MAX` is 256, so such paths are legal.
- The harness skips `feed_byte`, so it models neither the input limit nor the prompt sharing the reply buffer (#2). Those are the two places where the real serial path differs.
- **Fix:**
  - Compute the chunk size from the line limit, the quoted path length and the offset width.
  - Make the kernel reject an over-long line with an error instead of dropping characters (the "never silently truncate" standard).
  - Drive the harness byte by byte through `feed_byte`.
- `Status: Fixed — test: shell::tests::feed_byte_rejects_overlong_command_line_without_truncating, tools/triad_controller.py --unit-test (RealOsShellHarness overlong rejection & >60-char path writehex sync) — commit: 7d88d4b`

### 5. The new probe format invalidates digests saved by the previous version
- **Where:** `tools/triad_controller.py:1740` (the probe text now includes `#rows=` and the kernel digest), `:900-914` (the WAL file has no format version), and the boot-time verify and adopt steps.
- **Problem:** Digests saved by round-7 code can never match the new probes. On the first boot after upgrading, every node fails verification and all three are rebuilt from the WAL. The default `target/cuttle_images/triad` state on this machine has 7 entries and no checkpoint, so it would rebuild cleanly. A state directory holding a round-7 checkpoint (built from truncated `SELECT` output) would rebuild all three nodes from that lossy checkpoint.
- **Fix:** Store a probe/digest format version in `triad_wal.json`. On a mismatch, recompute the digests from a 3/3-agreeing majority instead of treating every node as rolled back, and refuse to replay a pre-`.dump` checkpoint.
- `Status: Fixed — test: tools/triad_controller.py --unit-test (RealOsShellHarness probe_format_version v2 3/3 digest upgrade & pre-.dump checkpoint refusal) — commit: 849a638`

### 6. Each write now triggers a full chunked dump of every vote table, one node at a time
- **Where:** `tools/triad_controller.py:2126` (the vote runs after every SQL write), `:1859` (nodes probed one after another) and `:976` (checkpoint dumps taken while holding `wal_lock`).
- **Problem:** A probe costs about one serial round trip per 3 rows, per table, per node. In the live test, writes took about 1.5–2 s with a 6-row `kv` table. A 64-row table needs 22 round trips per node, which by the same per-command cost (about 130 ms) means roughly 10 s per write per full table. Checkpoints block all writes for that long.
- **Fix:** Add a digest-only `.dump` mode (header with `rows=` and `digest=`, no rows) for the vote, and fetch rows only for checkpoints or to diagnose a mismatch. Probe the three nodes in parallel; each already has its own `cmd_lock`.

### 7. Smaller items
- **`RealOsShellHarness` (`triad_controller.py:458`):** reuses whatever `shell_harness.exe` already exists. If `shell.rs` or `sql.rs` changes and only `--unit-test` is run, the tests use a stale binary. Always run `cargo build --example shell_harness` (it's incremental) before starting it.
- **Unquoted paths with spaces (`shell.rs:4964-5025`):** `cathex` and `writehex` guess where a path with spaces ends by looking for numeric tokens. That's ambiguous when a path's own words are numeric. The controller always quotes, so require quotes for paths with spaces and drop the guessing.
- **Silent text truncation (`sql.rs:75-84`, `:2390-2400`):** TEXT values and the new `X'..'` literals longer than 24 bytes are cut silently. That predates `X'..'`, but it breaks the "never silently truncate" standard. Return an error.
- **Global buffer cap (`lived_net.rs:1220`, `:1438`):** when the 512 KiB budget across slots is used up, the next client gets `413 Content Too Large` and its connection is closed, even if its request was small. Use 503, and consider a per-peer share so one client can't use up the whole budget.

---

## Process notes
- Every status line named a test and a commit, and apart from one wrong test name (#2) the claims matched the code and the tests. Each finding got its own focused commit, which made this round much easier to review than the earlier bundled ones.
- `924d655` reports `cuttle_fleet.py --self-test`, which the earlier rounds lacked. Later controller commits (`4b31598`, `2d68dc6`, `1da1aad`) didn't re-run it; it passed here at `e9c10f5`. Re-run both live self-tests whenever the controller's vote, probe or heal paths change.
- High #1 and Medium #2 are both cases where the real serial path or the data domain is wider than the harness and tests assume. When adding a wire format (`.dump`, `X'..'`), test it against binary data and at the size limits.

## Not reviewed this round
- `rustls` key-material clean-up when a reclaimed session is dropped. Measured heap use under load on a VM (the new 512 KiB cap bounds the buffers, but I didn't measure it).
- `writehex`/`cathex` on a real VM with a path longer than 45 characters (#4 is from the code and arithmetic, not a live run).
- The rest of `triad_console.html`, and the provider's proxying and poll loop.
- Carried over: the SQL owner-selection logic in `exec_as`, the per-request `CPL=3` service hook, CuttleGuard and CuttleChronos beyond earlier paths, the UDP `:8081` triad protocol, and `binmorph`.
