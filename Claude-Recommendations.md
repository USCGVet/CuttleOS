# Claude Recommendations

Review of the 7 commits after `1c59464`, up to `2aa69b0`: `ef2c0ad`, `17f3d14`, `beb3bfa` and `37f9d23` (round-5 fixes), `b1d8fec` (status lines), `a38eb08` (#14 roster and port-80 response queue) and `2aa69b0` (status lines). The range is 43 files, +3,683 / −1,423 lines. Line numbers are from `2aa69b0`. The checkout had no uncommitted changes.

**Test status at review time** (Linux, stable 1.97, workspace crates rebuilt from clean)
- `cargo test --workspace --no-fail-fast`: **2,440 passed, 0 failed, 15 ignored.**
  - This includes the soft-float sub-invocation (`soft_float_crypto_backends_pass_kats_and_golden_replay`).
  - A fresh clone now passes (round-5 #13).
- `qemu_smoke` and the `target_enterprise_kernel` release build: **not run here.** The review environment can't download a nightly toolchain.
  - I read the builder's serial logs from 22:22, which is after the last kernel-side change: 128 and 129 `OK` banners, `HTTPS UP — entropy=rdrand provisioned=1`, `CUTTLE-TE HALT`, and the tampered disk rejected.
- **Python:**
  - Ran and passed: `https_check.py --self-test`, `cuttle_fleet.run_fleet_unit_tests`, and the AST parse of both controllers.
  - Not run: `triad_controller.run_unit_self_tests` needs a built kernel image, and `third_party_notices.py --self-test` needs the bootloader sources.
  - The live Triad and fleet self-tests weren't run (they need VMs).

## Verification of last round's items

| # | Item | Verdict | Notes |
|---|---|---|---|
| 1 | TLS RNG seeded from timers only | **Verified fixed** | HTTPS refuses to start without RDRAND or a TPM. The seed mixes in the master key, MAC and boot count. Launchers pass `-cpu max`. Unit test plus smoke banner `entropy=rdrand`. |
| 2 | Unbounded TLS transmit queue | **Verified fixed** | `MAX_TX_BYTES` 64 KiB, request handling pauses at 16 KiB, and idle HTTPS slots are reclaimed. The named test doesn't exercise the 16 KiB pause inside `handle_https_slot` (see #20). |
| 3 | Index-Triad heal never converges | **Verified fixed** | All vote tables are reset and replayed. But the new WAL compaction breaks replay in general (see #1). |
| 4 | Seeded and prod builds drop the soft-float cfgs | **Verified fixed** | `compose_kernel_rustflags` plus a unit test. Partial-cfg edge case in #11. |
| 5 | Prod kernels skip the TLS KATs | **Verified fixed** | `enable_https` runs `self_test()` in every build and refuses HTTPS on failure. |
| 6 | Unprovisioned HTTPS identity from the boot-ephemeral key | **Verified fixed** | Uses the CSPRNG when unprovisioned. `provisioned=0/1` is on the boot line. Unit test. |
| 7 | `/api/cron` bypasses the WAL | **Verified fixed** | Cron is limited to read-only commands (403 otherwise). Legacy jobs are dropped silently (#15). |
| 8 | Secret files with default permissions | **Partly fixed** | POSIX creates files 0600. On Windows the ACL is applied after the write, and failures are ignored (#5). |
| 9 | WAL durability | **Partly fixed** | Done: write-ahead, fsync, a `.bad` copy on parse errors, and rollback when every node rejects. A crash or failed save after the write-ahead still leaves an unmarked entry (#2). |
| 10 | Restored `tx_seq` not tied to node state | **Partly fixed** | Per-node and triad fingerprints were added. A two-node rollback, and stale digests, are still mishandled (#6). |
| 11 | Web Triads vote on names and sizes only | **Partly fixed** | The vote now uses content digests, and heal wipes the disk. But heal can't copy most files back (#4). |
| 12 | Roles fail open | **Verified fixed** | A node is kept OFFLINE after 3 failed attempts. |
| 13 | Suite passes only on the builder's machine | **Verified fixed** | Passes here on a fresh clone. |
| 14 | Committed seeds in the federation roster | **Partly fixed (owner action)** | Roster ships `primary` only with `threshold = 1`. Fixture and RFC 8032 keys are rejected, and `--require-threshold` refuses a threshold below 2. README updated. Remaining: real co-signers (your key ceremony), plus #13. |
| 15 | Fleet port collisions | **Verified fixed** | 5-job cap plus an overlap check. |
| 16 | Client isolation only at the API | **Verified fixed** | Farm VMs don't forward node ports. Self-test and README updated. The console still links to those ports (#16). |
| 17 | Endpoints not tested without credentials in every role | **Verified fixed** | HTTPS role-matrix test, plus fleet and controller loops over no, wrong and non-ASCII tokens. |
| 18 | `/app` innerHTML and shared token key | **Verified fixed** | `esc()` everywhere, `sessionStorage`, separate keys, CSP and `X-Frame-Options`. Old `localStorage` keys aren't cleared (#16). |
| 19 | Stale banners in opt-in QEMU proofs | **Verified fixed** | `required_banners_match_current_kernel_banners`. |
| 20 | Heal can leave a node in HEALING | **Verified fixed** | Heal holds `morph_op_lock` and morphs with `_lock_held`. The contention test would also pass on the old code, and an early return still leaves HEALING (#14). |
| 21 | Console Unlock button | **Verified fixed** | |
| 22 | Python request handling | **Verified fixed** | Auth is checked before the body is read, with body caps and ASCII-safe token comparison. |
| 23 | Secret files silently truncated or replaced | **Verified fixed** | Malformed files are refused. The blast radius is now wide (#15). |
| 24 | KAT coverage narrower than documented | **Verified fixed** | GCM case 4, RFC 5903 §8.1, and RFC 4231/5869 vectors through the provider's own objects. The README now names the wrong vectors (#21). |
| 25 | Host tests don't run the soft backends | **Verified fixed** | The sub-invocation ran and passed here. |
| 26 | Crypto hardening gaps | **Verified fixed** | Zeroization, signature self-verification, golden pieces gated, `reseed` crate-private with rekey-on-fill, DER length assertion. Notes in #12. |
| 27 | fw_cfg key length not checked | **Verified fixed** | Size must be exactly 32. A wrong size downgrades silently (#10). |
| 28 | Port 80 and 443 request handling differ | **Partly fixed** | Shared framing, 413 and 400 responses, and a per-slot response queue on port 80, which fixes the dropped-response bug. Connection handling after errors is still wrong (#3). |
| 29 | Binmorphed boot asserts 6 banners | **Verified fixed** | HALT is now asserted. |
| 30 | Accelerator docs and `run.bat` fallback | **Verified fixed** | `run.bat` defaults to TCG, and the README is scoped correctly. |
| 31 | Licensing notices | **Verified (docs)** | NOTICE and README updated, and the SPDX parser is correct. Stage-crate inclusion wasn't re-run here (no bootloader sources). |
| 32 | Smaller tooling items | **Verified fixed** | sibling-search shape, temp self-test dir, farm secret popped, node-id 400s, uniform 403. The WAL-growth fix introduced #1. |

---

## High priority

### 1. WAL compaction rewrites history, so replay rebuilds data the peers don't have
- **Where:** `tools/triad_controller.py:329-366` (`compact_wal_entries`), called from `_save_wal_to_disk` at `:668-673` once the WAL passes `MAX_WAL_ENTRIES`.
- **Problem:** Any earlier `UPDATE kv … WHERE k='x'`, `INSERT OR REPLACE INTO kv VALUES ('x', …)` or `UPDATE idx … WHERE term='t'` is dropped whenever a later statement matches the same key, as if the later one overwrote the whole row. The kernel's SQL engine doesn't work that way: `UPDATE` sets one column, `WHERE` supports `AND`/`OR`, `BEGIN`/`ROLLBACK` are logged entries, and row order follows slot allocation. I ran the function:
  - `INSERT OR REPLACE … ('x','a',1)` followed by `UPDATE kv SET rev = 2 WHERE k = 'x'` keeps only the `UPDATE`, so the row never exists on replay.
  - `SET v='new'` followed by `SET rev=9` on the same key keeps only `SET rev=9`, so `v` is lost.
- **Effect:** Once the WAL is compacted, every heal and catch-up rebuilds a state the other nodes don't have. The healed node is outvoted again, and heal → emergency morph → heal repeats with no limit. The all-node replay in `_adopt_tx_seq_from_majority` writes the lossy state to all three nodes, where the vote can't detect it, so data is lost silently. The synthetic load only issues single-column updates on plain-inserted rows, which is why the self-tests pass.
- **Fix:** Remove key-level compaction. Bound the WAL with a checkpoint instead: a majority-agreed dump of the vote tables plus its tx_seq, and heal from checkpoint plus tail. Make the vote order-insensitive (sort rows). Add a test that heals a node after more than `MAX_WAL_ENTRIES` mixed statements and asserts a 3/3 match.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests` (WAL checkpointing after >`MAX_WAL_ENTRIES` mixed `INSERT`/`UPDATE` statements + order-independent `_normalize_kv_for_tmr`) — commit: `64118bd`

---

## Medium priority

### 2. Write-ahead entries have no pending or applied marker
- **Where:** `tools/triad_controller.py:1304-1365` (SQL path) and the vault path at about `:1455-1504`. Startup, catch-up and heal replay every entry above a node's tx_seq.
- **Problem:** The entry is appended, `triad_tx_seq` is advanced and the file is fsynced before any node executes it. If the process stops before the nodes run it, or `_save_wal_to_disk` raises anything other than the `ValueError` handled at `:1323`, the entry stays with nothing to say whether zero, some or all nodes applied it. In the raise case, the in-memory append and tx_seq aren't rolled back, and the next successful save writes the entry anyway. Rollback works correctly only when every node rejects the statement.
- **Effect:** After a restart, the next morph replays the entry on one node only. That node is outvoted, and heal replays the entry again, so it loops. The all-node adoption replay can also apply a write the client was never told succeeded.
- **Fix:** Record the entry as pending, together with the pre-write digest. Mark it committed (or remove it) after execution, within the same `wal_lock` hold, and undo the in-memory changes if the save raises. At startup, resolve pending entries against the majority fingerprint. Add a test that stops the controller in `_after_wal_write_ahead_hook`, restarts it, and asserts the Triad converges.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests` (write-ahead `OSError` rollback, `_after_wal_write_ahead_hook` crash before node execution, and 2/3 majority partial commit reconciliation) — commit: `64118bd`

### 3. HTTP connections keep reading after a terminal response, and framing has gaps (both ports)
- **Where:**
  - Port 80: `target_enterprise/src/lived_net.rs:1026-1066`. The `overflow_413` branch clears the buffer and carries on, and `close_after` only breaks the loop.
  - Port 443: `:1196-1250`. The framing loop doesn't stop once `close_sent()` is true.
  - Framer: `:2262-2285`. `LengthRequired` clears the whole buffer, and `Err(_) => body_start` hands an unparseable head to `handle_http_request`, which returns 0.
- **Problem:** After a 413, a 400 or `Connection: close`, the connection isn't closed or marked as finished. The rest of an oversized body, or the body of a POST sent without `Content-Length`, is framed as new requests. On port 443, responses can follow close_notify. A `LengthRequired` also discards any pipelined requests behind it. An unparseable request gets no response at all. `Transfer-Encoding` is ignored, and `Connection` isn't parsed as a token list.
- **Effect:** Requests and responses drift out of step. Body bytes can be run as requests on the same connection. Port 443 breaks the TLS protocol after close_notify. The README's "every route answers identically on :80 and :443" doesn't hold for connection handling. Each connection belongs to one client, so this is a correctness and protocol issue, not a cross-user exposure.
- **Fix:**
  - Add a per-slot "input closed" flag. Set it on any terminal response (413, 400/411, close, parse error), discard later inbound bytes while it's set, and clear it when the slot is reused.
  - Port 80: start a server FIN once `http_tx` drains (or reset after the response is acknowledged).
  - Port 443: stop handling requests once `close_sent()` is true.
  - Answer `Transfer-Encoding` with 501 and close, and answer bad, duplicate or conflicting `Content-Length` and unparseable heads with 400 and close.
  - Extend the 413 test to send trailing bytes after the overflow and assert that nothing more is answered.
- Status: Fixed — test: `lived_net::tests::http_framer_rejects_transfer_encoding_bad_content_length_and_malformed_requests`, `https_interop::http_and_https_reject_oversized_and_unframed_requests_and_match_across_routes` — commit: `9e097a5`

### 4. Web (`wfe`) heal can't copy most files back, so a divergence becomes a wipe-and-morph loop
- **Where:** `tools/triad_controller.py:1170-1184` (`_sync_files_from_peer`) and `:1620-1621`. Unit test at `:2662-2700`.
- **Problem:**
  - Files are copied with `write <path> <content>` over the serial shell, after the target's disk has been wiped.
  - Multi-line files are skipped silently, because `is_printable_ascii_command` rejects the newline.
  - `cat` returns at most 1 KiB (`target_enterprise_kernel/src/main.rs:845`), and the shell line is 256 bytes.
  - `write` appends a newline, empty files are refused, and the copy is never checked afterwards.
  - The unit test's fake shell stores content verbatim and uses one 5-byte line.
- **Effect:** After a heal, the node still differs on size or digest, so it's wiped and morphed again with no limit. This is latent today, because web nodes only hold the kernel's default files, but it triggers as soon as real content is served.
- **Fix:** Copy files with a byte-safe encoding, in chunks. Check size and digest after the copy, and keep the node OFFLINE with an alarm on mismatch. Make the fake shell match kernel behaviour. Add a real-VM test with a multi-line file.
- Status: Fixed — test: `shell::tests::cathex_and_writehex_roundtrip_empty_binary_and_multichunk_files`, `tools/triad_controller.py::run_unit_self_tests` (multi-line >1 KiB, empty 0-byte, and space-path `wfe` file sync + SHA-256 verification) — commit: `9e097a5`, `64118bd`

### 5. On Windows, secret files are readable under the inherited ACL until icacls runs, and icacls failures are ignored
- **Where:** `tools/triad_controller.py:128-143` (`restrict_file_permissions`) and `:146-166` (`write_secret_file`). Also `run.bat:94-104`, which generates `device_secret_key.bin`.
- **Problem:** On Windows, the `0o600` passed to `os.open` only sets the read-only flag. The temp file inherits the folder's ACL, the secret is written and fsynced, and only then does `icacls` run, with `check=False` and the result ignored. The principal comes from the `USERDOMAIN` and `USERNAME` environment variables. `run.bat` writes the device key with the inherited ACL and never restricts it.
- **Effect:** A folder created directly under `C:\` (such as `C:\CuttleOS`) normally inherits read access for Authenticated Users. Master keys, node device keys and tokens are readable by other local accounts during the write, and permanently if icacls fails. The README says these files are owner-only.
- **Fix:** Create the file empty, apply the ACL using the current user's SID, check the result and fail if it didn't apply, then write. Do the same in `run.bat`. Add a test that asserts the ACL on Windows and the mode on POSIX.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests` (Windows `icacls` SID ACL check before write + failure rejection + POSIX `0600` mode check) — commit: `64118bd`

### 6. State-fingerprint edge cases: a two-node rollback is adopted, and stale digests can reset healthy nodes
- **Where:** `tools/triad_controller.py:1838-1873` (adoption) and `:1196-1212` (the parity check records a digest probed outside `wal_lock`).
- **Problem:**
  - When the majority's fingerprint differs from `triad_state_digest` but one node is still restored, the all-node replay is skipped. Every pending node that matches the majority then adopts `triad_tx_seq`, without its digest being checked. So two rolled-back disks are marked current, and the one correct node is outvoted and healed.
  - Separately, the parity check probes the nodes before taking `wal_lock`, then records that probe as the current digest. A write that commits in between leaves an old digest next to a new tx_seq. After a restart, healthy nodes then look mismatched and are reset to 0.
- **Effect:** Real divergence is masked, or a heal loop starts against the correct node. Or a restart triggers a full replay, which is affected by #1 and #2.
- **Fix:** Adopt only when the majority fingerprint equals the saved digest. If a restored node matches the saved digest and the majority doesn't, rebuild the majority from the WAL or raise an ALERT. Probe and record the digest under the same lock hold, or drop the result if tx_seq moved. At boot, retry an unreadable probe instead of resetting. Add a two-node-rollback test.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests` (two-node rollback recovery onto intact restored peer, transient `None` probe retry, and stale-tx_seq parity digest guard) — commit: `64118bd`

---

## Low priority

### 7. Backpressure becomes dropped requests and spurious 413s
- **Where:** `lived_net.rs:1027-1034` (port 80 applies the limit to the whole buffer) and `https.rs:411-414,484-487` (port 443 clears plaintext at 16 KiB).
- **Problem:** Complete pipelined requests waiting behind the response high-water mark count toward the limit. The next segment then wipes them and queues a 413. The limit also differs between the ports: 8 KiB on 80 and 16 KiB on 443.
- **Fix:** Apply the size limit per request inside the framer. Handle backpressure by not accepting more input (or shrinking the window), not by discarding it.
- Status: Fixed — test: `https_interop::https_tx_cap_backpressure_and_idle_rto_reclaim_slots`, `https_interop::http_and_https_reject_oversized_and_unframed_requests_and_match_across_routes` — commit: `9e097a5`

### 8. `CloseWait` handling
- **Where:** `lived_net.rs:1044,1087-1090`, `:1250-1252,1272-1278`, and `tcp.rs:411-419`.
- **Problem:** A half-closing client that pipelines more than 8 requests gets FIN after the eighth answer, with complete requests still buffered. Retransmitted data in `CloseWait` isn't sequence-checked, so it's buffered and run again. That's an older bug, but slots now stay in `CloseWait` longer.
- **Fix:** Keep processing until the framer reports `Incomplete` before closing. Drop payload in `CloseWait` (or check it against `rcv_nxt`).
- Status: Fixed — test: `lived_net::tests::close_wait_ignores_data_after_fin_and_finishes_pipelined_requests` — commit: `9e097a5`

### 9. Idle reclaim
- **Where:** `lived_net.rs:260-272` and `:1009`.
- **Problem:** Reclaimed established slots get no RST or close_notify. `slot_last_tick` is refreshed before `process_segment` validates the segment, so invalid segments keep a slot "active". Ticks aren't wall-clock time.
- **Fix:** Send RST when reclaiming, refresh the tick only after a segment is accepted, and base the timeout on the calibrated timer.
- Status: Fixed — test: `lived_net::tests::rejected_tcp_segments_do_not_reset_idle_timer_and_rto_emits_rst`, `https_interop::https_tx_cap_backpressure_and_idle_rto_reclaim_slots` — commit: `9e097a5`

### 10. A wrong-size device key silently downgrades to unprovisioned
- **Where:** `target_enterprise_kernel/src/provisioning.rs:30-33,241-244`.
- **Problem:** A 33-byte key (for example with a trailing newline) is treated as absent, with no log line. Seal and attestation keys then become boot-ephemeral, so previously sealed state no longer verifies.
- **Fix:** Print a distinct `device key present but size=N` banner and refuse provisioned services, rather than downgrading quietly.
- Status: Fixed — test: `tls_provider::tests::validate_fw_cfg_device_key_rejects_wrong_size_and_zero_keys` — commit: `9e097a5`

### 11. `compose_kernel_rustflags` edge cases
- **Where:** `factory_builder/src/lib.rs:286,455`.
- **Problem:**
  - Inherited flags containing `aes_force_soft` are used as-is, so inheriting some of the cfgs but not all drops the rest, and the build stops at the new `compile_error!`.
  - Any non-empty inherited `RUSTFLAGS` now wipes the dependency caches.
  - `CARGO_ENCODED_RUSTFLAGS` isn't removed, and if set it would override everything, including `--cfg cuttle_prod`.
- **Fix:** Add each missing cfg individually, wipe caches only for seeded builds, `env_remove("CARGO_ENCODED_RUSTFLAGS")`, and add a partial-cfg test.
- Status: Fixed — test: `factory_builder::tests::compose_kernel_rustflags_fills_in_partial_inherited_soft_float_cfgs` — commit: `e76900c`

### 12. Small kernel-crypto items
- **Where:** `tls_provider.rs:646-651` and `provisioning.rs:317-321`.
- **Problem:** `sign_der` uses `.expect` on its self-verification, so a failure halts the kernel instead of taking the `HTTPS DISABLED` path. The plain loop that zeroes `hw_words` may be optimized away.
- **Fix:** Return a `Result` from `sign_der`, and use `zeroize` for `hw_words`.
- Status: Fixed — test: `tls_provider::tests::self_test_passes`, `tls_kat::provider_known_answer_self_test` — commit: `9e097a5`

### 13. Federation threshold counts distinct ids, not distinct keys
- **Where:** `morph_engine/src/federation.rs:146-163,207-223`, the denylist at `:82-104`, and `attest.rs:1367-1378`.
- **Problem:** Two roster entries with different ids and the same key both count toward the threshold. The denylist covers only RFC 8032 TEST 1 and 2, not TEST 3, 1024 or SHA(abc), and not the new test seeds. The primary key-file fallback never runs the fixture check.
- **Fix:** Reject duplicate keys (compare decoded bytes) and count distinct verified keys. Complete the denylist, and apply it to the fallback key.
- Status: Fixed — test: `federation::rejects_duplicate_signer_pubkey_and_test_seeds`, `attest::primary_key_file_fallback_rejects_fixture_seed` — commit: `e76900c`

### 14. Heal robustness
- **Where:** `tools/triad_controller.py:1673-1681`, `:1844-1860`, `:1237`, `:1579`.
- **Problem:**
  - `_reset_sql_vote_tables` drops non-`kv` vote tables and relies on the WAL to recreate them, which fails after a WAL reset.
  - The all-node adoption replay has no try/except, so a failure aborts boot after some tables were already dropped.
  - Heals have no retry limit.
  - If bounce returns early (fewer than two peers), the node stays HEALING.
- **Fix:** Recreate tables from their schema, wrap the replay, cap heal attempts and raise an ALERT, and reset state on early returns.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests` (schema recreation after WAL reset, early-return state restoration, and `MAX_CONSECUTIVE_HEALS = 3` cap) — commit: `64118bd`

### 15. Secret-loader and cron migration
- **Where:** `tools/cuttle_fleet.py:490`; `tools/triad_controller.py:168-198,581-591`.
- **Problem:** All client tokens load in `Provider.__init__`, so one malformed client file stops the whole fleet. State-changing jobs in an existing `cron_jobs.json` are dropped without a log line.
- **Fix:** Fail only the affected client, and log a WARN for each dropped cron job.
- Status: Fixed — test: `tools/cuttle_fleet.py::run_fleet_unit_tests`, `tools/triad_controller.py::run_unit_self_tests` — commit: `64118bd`

### 16. Console and fleet leftovers
- **Where:** `tools/triad_console.html:1101`; `tools/cuttle_fleet.py:316-322`.
- **Problem:**
  - "Node UI :port" links point to ports that are no longer forwarded in fleet mode.
  - The web job's synthetic load no longer generates HTTP requests.
  - Old `localStorage` token keys are never removed, and Forget only clears `sessionStorage`.
- **Fix:** Hide the links in fleet mode, restore HTTP load through the farm, and clear the legacy keys.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests`, `tools/cuttle_fleet.py::run_fleet_unit_tests` — commit: `64118bd`

### 17. Serial reads can be cut short in the web-node vote
- **Where:** `tools/triad_controller.py:1101` and `:1145`.
- **Problem:** `_response_looks_complete` accepts output after one line plus 0.3 s. The `wfe` probe now sends 1+N commands per node, so a stall gives a partial read and a false fault, which wipes a healthy node. The `ls` regex also skips paths containing spaces.
- **Fix:** Wait for the prompt, and confirm a mismatch with a second probe before healing.
- **Confidence:** likely under load; not reproduced.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests` (`_response_looks_complete` prompt requirement on `cat`/`ls`, `ls` paths with spaces, and 2-probe `wfe` confirmation) — commit: `64118bd`

### 18. `https_check.py` TLS 1.2 refusal check
- **Where:** `tools/https_check.py:121`.
- **Problem:** "no protocols available" is a client-side OpenSSL error, but the check treats it as the server refusing TLS 1.2.
- **Fix:** Assert that a server alert was received.
- Status: Fixed — test: `tools/https_check.py::run_self_test` — commit: `64118bd`

### 19. Atomic WAL write
- **Where:** `tools/triad_controller.py:201-210`.
- **Problem:** On POSIX, the directory isn't fsynced after the rename, and temp files are left behind if a write fails.
- **Fix:** fsync the directory, and clean up the temp file in a `finally`.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests` (`atomic_write_json` temp-file cleanup on write error) — commit: `64118bd`

### 20. Tests that don't check what their names say
- **`https_tx_cap_backpressure_and_idle_rto_reclaim_slots`** (`https_interop.rs:312`) never exercises the 16 KiB pause in `handle_https_slot`.
- **The 413 test** (`:477`) overflows on its final chunk, so it never sends trailing bytes (see #3).
- **`fixture_seeds_match_factory_keys_toml`** (`morph_engine/tests/federation.rs:311`) now asserts the opposite of its name, and pins `threshold == 1`, so it will fail as soon as co-signers are enrolled.
- **The #20 contention test** (`triad_controller.py:3156-3158`) would also pass on the old code.
- **Missing tests:** no test covers a heal after compaction, a crash after write-ahead, a two-node rollback, Windows secret ACLs, or partial inherited `RUSTFLAGS`.
- **Fix:** Rename or extend these tests, and add the missing ones.
- Status: Fixed — test: `https_interop::https_tx_cap_backpressure_and_idle_rto_reclaim_slots`, `https_interop::http_and_https_reject_oversized_and_unframed_requests_and_match_across_routes`, `federation::workspace_factory_keys_rejects_fixture_seeds_and_validates_threshold`, `factory_builder::tests::compose_kernel_rustflags_fills_in_partial_inherited_soft_float_cfgs`, `tools/triad_controller.py::run_unit_self_tests` — commit: `e76900c`, `9e097a5`, `64118bd`

### 21. Docs and commit messages that overstate the code
- **`README.md:105`** names `TlsEntropyStatus::Unseeded`, which doesn't exist.
- **`README.md:106`** lists "AES-128-GCM NIST SP 800-38D Case 3", "P-256 ECDH CAVP" and "SHA-256 FIPS 180-4". The code uses GCM spec cases 1, 2 and 4, RFC 5903 §8.1, and has no standalone SHA-256 vector.
- **`tests/tls_kat.rs:7`** still says "test cases 1–2".
- **The `ef2c0ad` commit message** describes `SigningConfig` and `MorphConfig::with_test_signing_key()`, which don't exist in the tree.
- **Audit label:** a 413 on port 443 is audited as `net:tls:rejected` (`lived_net.rs:1200-1207`).
- **Fix:** Correct the text. Use a distinct audit label for oversized HTTP requests.
- Status: Fixed — test: `https_interop::http_and_https_reject_oversized_and_unframed_requests_and_match_across_routes` (asserts `net:https:overflow` audit event on `:443` 413) — commit: `9e097a5`, `64118bd`

---

## Process notes
- Every status line named its tests and commits, and the claims matched the code, with two caveats. #14 was honestly marked "Partly fixed" after the first attempt used published RFC 8032 keys. Several items marked Fixed have new follow-up defects, listed above.
- The commits are again large and bundled (`beb3bfa` touches 1,200+ lines of the controller), and `GEMINI.md` asks for small, focused commits. The WAL compaction (#1) was added as part of a "growth" fix without a test of the property that matters, which is that a replay reproduces the majority's state.
- The checkout was converted from CRLF to LF line endings during this round. That's fine, but say so in a commit message so future diffs are easy to read.

## Not reviewed this round
- The kernel build and `qemu_smoke` weren't run here. I read the builder's 22:22 serial logs instead.
- The Python self-tests that need VMs or a built kernel (`run_unit_self_tests`, the live Triad and fleet self-tests), and `third_party_notices.py --self-test`.
- Windows-specific behaviour: icacls results, file replace, and `-cpu max` under WHPX. These are from reading, not execution.
- rustls key-material clean-up when a reclaimed session is dropped; heap use with 16 fully loaded slots (estimated at about 2 MB).
- The rest of `triad_console.html`, and the provider's proxying and poll loop.
- Carried over: the SQL owner-selection logic in `exec_as`, the per-request `CPL=3` service hook, CuttleGuard and CuttleChronos beyond earlier paths, the UDP `:8081` triad protocol, and `binmorph`.
