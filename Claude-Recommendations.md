# Claude Recommendations

Review of the 26 commits after `3dae6cf`, up to `917109c`:
- **Round 8 fixes:** `66955c7` (#1), `556ec3b` (#2), `5f2db72` (#3), `7d88d4b` (#4), `849a638` (#5), `04838f7` (#6) and `3788fbb` (#7), plus seven status-line commits.
- **A side branch merged in `e2ccfcb`:** `35cff85`, `ee99e53`, `bc2e012` and `d445ae7`.
  - It was based on `1c59464`, 20 commits behind `3dae6cf`.
  - The merge is clean: against `3dae6cf` it adds only the branch's changes, and the few lines it removed were replaced by stricter quorum checks.
- **New features and docs:** `c2d9d35`, `284dd9a`, `50f5fba`, `1d4e870`, `0669eff`, `0886ce2` and `917109c`.

Excluding this file, the range is 21 files, +10,068 / −413 lines. Line numbers are from `917109c`. The checkout had no uncommitted changes, and `main` matches `origin/main`.

I split the new feature areas across four parallel reviewer passes and checked every finding below against the code. "I reproduced" means I ran it myself. "A reviewer harness reproduced" means a scratch harness built outside the repo did, and I confirmed the cause in the code.

An untracked `Cuttle-OS-Recommendations.md`, from a second recommender, appeared in the repo root during the review. It isn't part of this round.

**Test status at review time** (the user's Windows 11 host; stable 1.93.1; pinned `nightly-2026-10-22`; QEMU 11.1, TCG)
- `cargo test --workspace --no-fail-fast`: **2,478 passed, 0 failed, 16 ignored** (up from 2,454 / 15).
- `(cd target_enterprise_kernel && cargo build --release)`: **passed.**
- `cargo test -p factory_builder --test qemu_smoke -- --ignored`: **3 passed**, including the new `morphed_kernel_boots_and_persists_state_across_multiple_seeds_under_qemu`.
- **Python:** AST parse, `https_check.py --self-test`, `triad_controller.py --unit-test`, `cuttle_fleet.run_fleet_unit_tests` and `verify_metrics_independent.py --self-test` all passed.
- **Live, on real VMs** (beyond the required checks):
  - `triad_controller.py --self-test` (3 VMs): **failed** at its `/api/guard status` step (High #1). I then answered only that one read with a reviewer wrapper (no repo change). Every remaining step passed: SQL writes during a morph, restarts, a legacy WAL, and a wiped disk that was detected, healed and re-morphed.
  - `cuttle_fleet.py --self-test` (18 VMs): failed with the default `auto` accelerator. WHPX guests on this host produced no output within 8 s, so the controller fell back to TCG, and the test's accelerator assertion doesn't allow that (Low). **Passed** with `--accel tcg`.
- **GitHub Actions:** all 12 runs since the workflow was added in `284dd9a` failed, including the run for `917109c` (Medium #4).

## Verification of last round's items

| # | Item | Verdict | Notes |
|---|---|---|---|
| 1 | A non-printable vote cell turned off the vote, or was dropped on heal | **Verified fixed** | Cells stay bytes end to end, and probes encode them as `T:<hex>` / `I:<int>`. Checkpoint cells use a quoted literal when it is printable and shorter, otherwise `X'<hex>'`. A `None` probe is retried. One unreadable node beside two agreeing nodes is healed; two unreadable nodes log an ALERT. Tests 1a–1c run on the real shell. The worst-case checkpoint statement (a 16-character table with four 24-byte binary cells) is 253 bytes with the `/*t*/` prefix, inside the 256-byte line limit. |
| 2 | The first `.dump` chunk overflowed for wide tables | **Verified fixed** | Rows are sized against the buffer minus the 8-byte prompt, and `count=` reports the rows actually written. The limit is clamped to 1..=3, so the single-digit patch is safe. The controller rejects rows with the wrong cell count. The Rust test goes through `feed_byte`, and the controller test checkpoints and heals a max-width table. |
| 3 | The immutable-file guard compared the raw path | **Verified fixed** | One helper normalizes with `vfs::normalise_path`. The normalized path is used for both the check and the open or unlink in `write`, `writehex`, `rm`, `VfsWrite` and `VfsDelete`. Seven spellings are tested on all five. The remaining raw `fs.open` writes are restore paths for HMAC-sealed data. |
| 4 | `writehex` lines exceeded the 256-byte input limit | **Partly fixed** | Done: the kernel rejects an over-long line with an error and an audit event, the harness drives `feed_byte`, and chunks are sized from the line limit. Remaining: paths near `FS_PATH_MAX` still don't fit, and a path of 244–256 characters stops the web Triad's vote (Medium #12). The test uses a 68-character path. |
| 5 | The new probe format invalidated saved digests | **Partly fixed** | Done: the WAL records the probe and checkpoint format versions, a pre-`.dump` checkpoint is refused, and a Triad whose three nodes agree upgrades its digests. Remaining: the genesis guard doesn't recognize multi-table probes, so the upgrade adopts a wiped Triad (Medium #11). Also, `04838f7` changed the digest input after v2 was defined without bumping the version (Low). |
| 6 | Each write triggered a full dump of every vote table | **Verified fixed** | `.dump <table> digest` returns only the header. The vote probes all nodes in parallel, and checkpoint dumps run outside `wal_lock` and re-check `tx_seq` afterwards. Tests count the commands and check the lock. Two side effects: the vote now rests on each node's own FNV-1a digest (Medium #3), and the rows fetched "to diagnose" a mismatch are thrown away (Low). |
| 7 | Smaller items | **Verified fixed** | The harness is rebuilt on every run. Paths with spaces must be quoted, and the guessing is gone. TEXT and `X'..'` literals over 24 bytes are rejected, and the truncating `from_text` has no callers left. A full budget now returns 503, with a 256 KiB per-peer share (tested). The per-peer share keys on source IP, which can't tell clients apart behind QEMU's NAT (Low). |

---

## High priority

### 1. Reads whose output differs per node by design are refused as split-brain (regression from `bc2e012`)
- **Where:**
  - `tools/triad_controller.py:2300-2336` (SQL reads) and `:2542-2566` (app reads). Both changed in `bc2e012` and were merged in `e2ccfcb`.
  - Per-node output in `target_enterprise/src/shell.rs`:
    - `:3429-3452`: `guard status` prints `cpl3_runs`, `audit_denied` and `pcr10`.
    - `:3159-3165`: `vault list` returns each node's ciphertext.
    - `:3466-3490`: `guard alerts` lists each node's own audit events.
- **Problem:**
  - Both read paths now require two byte-identical raw outputs. Otherwise they refuse, log an ALERT and set `parity_syndrome_ok = False`. Before `bc2e012`, they returned the most common output.
  - Outputs differ by design wherever a node reports its own measurements or its own ciphertext.
  - The reverse problem also exists: the SQL path counts error replies as answers. `send_shell_cmd` returns strings such as `"error: command timed out"`, so two identical errors become a "2-of-3 Majority Verified" result.
- **I reproduced it on real VMs:**
  - `--self-test` fails at `/api/guard status` (`:6156-6164`). The three nodes report different `pcr10` values (`39269efa…`, `d7a24534…`, `48c4687c…`), different `cpl3_runs` (17/15/15) and different `audit_denied` counts (3/4/4).
  - After one `vault put`, `SELECT * FROM kv` through `execute_triad_sql` returns `1/3 SPLIT-BRAIN REFUSED`, because each node's `v:` row holds its own ciphertext. `vault list` is refused the same way. `cron list` agrees.
  - Unit tests pass because the three harness shells run the same build. The live self-test would have caught this, but it wasn't run after `bc2e012` or the merge.
- **Effect:** on a real Triad:
  - The console's Guard button and `/api/guard status` always fail.
  - `SELECT` on `kv` fails as soon as any vault secret exists.
  - Every such read logs a false split-brain ALERT and marks parity as failed until the next parity run.
- **Fix:**
  - Vote on normalized output:
    - For SQL, reuse `_normalize_kv_for_tmr`, which replaces vault rows with `<HW_SEALED>` and sorts rows.
    - For app reads, compare only replicated fields (posture, role, running count, key names), and return per-node diagnostics alongside without a quorum claim.
  - Leave error replies out of the vote. With fewer than two good answers, return an availability error, not split-brain.
  - Let only `compute_and_verify_raid_parity` change `parity_syndrome_ok`.
  - Add tests:
    - a unit test where the nodes differ only in per-node fields;
    - a unit test with two timeouts;
    - a live self-test step that runs a voted `SELECT` after a `vault put`.
  - Run `--self-test` before marking any controller change done.

Status: Fixed — test: `run_unit_self_tests`, `triad_controller.py --self-test` — commit: `d9869f1`

### 2. The "Ring-3 user-space request parser" runs in Ring 0
- **Where:**
  - `target_enterprise/src/svc_runtime.rs:1165-1321`: `parse_and_validate_ring3_mailbox`, documented as running "in Ring-3 user space". It is called directly from `target_enterprise/src/shell.rs:782-792`.
  - The only hardware `CPL=3` step is the hook at `svc_runtime.rs:1106-1120`.
  - Claims: `README.md:115`, `experiments/redteam/RESULTS.json:198` and the `0669eff` message.
- **Problem:**
  - The parser is an ordinary method call inside `dispatch_mailbox_op`. On the kernel it runs at CPL=0, with no privilege change and no separate address space.
  - The stub the hook runs at `CPL=3` receives only `(canary << 32) | seq`. The request path and body are never mapped to user mode.
  - `user_l4` is a software `PageTable<8>` model that the kernel never loads. The kernel's only CR3 write is in the SMP AP trampoline (`target_enterprise_kernel/src/smp_hw.rs:927`).
- **Effect:**
  - The advertised user-space isolation of request parsing doesn't exist.
  - A parser fault is a Ring-0 fault and halts the node.
  - The engines still consume the same bytes in Ring 0.
- **Fix, one of:**
  - Implement it:
    - copy the request into the service's user address space;
    - load that page table;
    - run the parser at CPL=3 and return only a verdict;
    - re-check in the kernel;
    - add a QEMU banner that proves CPL=3 at parse time.
  - Or rename it to what it is, a kernel-mode lexical pre-filter, and correct README:115, RESULTS.json:198 and the doc comments.

Status: Fixed — test: `svc_runtime::tests::ring3_mailbox_parser_blocks_sql_injection_shell_chaining_path_traversal_and_exec_abuse`, `lived_net::tests::http_request_prefilter_accepts_binary_vfs_valid_sql_and_shell_and_returns_400_without_counter_inflation` — commit: `a3ce4bf`

---

## Medium priority

### 3. The Triad vote now trusts a 64-bit FNV-1a digest computed by each node
- **Where:**
  - `tools/triad_controller.py:1894-1939` and `:1996-2041`: `_state_probe` votes on `.dump <table> digest` headers only.
  - `target_enterprise/src/sql.rs:912-982`: the digest is a 64-bit FNV-1a hash.
- **Problem:**
  - Until `04838f7`, the controller compared the rows themselves. It now compares `#rows` plus a non-cryptographic hash that each node computes over its own rows.
  - My Round 8 #6 suggestion asked for a digest-only mode without saying the digest had to be collision resistant. That gap was mine.
- **Effect:**
  - Accidental divergence is still caught.
  - A deliberate change to one node's rows can be chosen so that the row count and FNV-1a value stay the same. The vote then never flags or heals that node.
  - A node running attacker code can lie under any scheme; this change weakens the data-only case.
  - The WAL's `triad_state_digest` is now a hash of these headers, so it has the same strength.
- **Fix:**
  - Make `.dump <table> digest` return a SHA-256 (already linked for the seals) over the canonical row encoding.
  - Mirror it in `format_kernel_sqldump_reply` and pin it with a golden test.
  - Bump `WAL_PROBE_FORMAT_VERSION`.

Status: Fixed — test: `sql::tests::sqldump_digest_only_mode_matches_full_dump_header_and_rejects_bad_args`, `run_unit_self_tests`, `triad_controller.py --self-test` — commit: `d9869f1`

### 4. CI has failed on every run because the QEMU tests can't find QEMU on Linux
- **Where:**
  - `factory_builder/tests/qemu_smoke.rs:30-50`: `find_qemu` runs Windows' `where`, then tries `C:/Program Files/qemu`.
  - `qemu_smoke.rs:94-102` (skip), `:530-532` and `:636-638` (panic).
  - `.github/workflows/ci.yml:29-39`: the toolchain fallback.
- **Problem:**
  - `ubuntu-latest` has no `where`, so QEMU is never found. `boots_under_qemu_and_emits_banner` prints SKIP and passes, while the tamper and multi-seed tests panic.
  - All 12 runs since `284dd9a` failed at that step (exit 101, within a second). Every earlier step passed.
  - If the pinned nightly can't be installed, the workflow quietly rewrites both toolchain files to a floating nightly. Round 7 #4 removed exactly that failure mode, and a different compiler changes the very `.text` the suites measure.
- **Effect:**
  - CI has never verified a QEMU boot.
  - A red pipeline has become normal.
  - Where QEMU really is missing, the main smoke test passes without running.
- **Fix:**
  - Find QEMU portably by searching `PATH` for `qemu-system-x86_64[.exe]`.
  - In CI, set an env var (for example `CUTTLE_REQUIRE_QEMU=1`) that turns every SKIP into a failure.
  - Fail the toolchain step instead of falling back.
  - Treat a red run as blocking.

Status: Fixed — test: `qemu_smoke::find_qemu_searches_path_portably`, `qemu_smoke::boots_under_qemu_and_emits_banner` — commit: `82fd583`

### 5. Degraded split-brain refuses reads but still commits writes, and the failure model says otherwise
- **Where:**
  - `tools/triad_controller.py:2338-2441`: writes count accepting nodes, with no agreement check.
  - `TRIAD_FAILURE_MODEL` at `:4133-4173`. Its only test (`:4188-4189`) checks the dictionary's size.
  - The `917109c` campaign at `:5764-5866`.
- **Problem:**
  - With one node down and the other two disagreeing, reads fail closed, but a write is accepted, recorded in the WAL and applied to both divergent replicas. A reviewer harness reproduced this with fakes. `TRIAD_FAILURE_MODEL` says "reads and writes fail closed".
  - Other entries describe code the controller doesn't have:
    - "reconstructed via D_lost = D_peer ^ P": the heal only logs the XOR result's hash (`:2976-2987`), then rebuilds from the WAL.
    - "heal refused (ImaVerificationFailed)": this is the Rust voter's error, not controller behaviour.
    - "orphan triad_wal.json.tmp … reconciled at boot": nothing reads or removes temp files.
  - The campaign's Stage B (`:5797-5801`) plants `triad_wal.json.tmp`, a name the controller never uses. Its real temp files are `.triad_wal.json.<pid>.<hex>.tmp` (`:243`).
  - Stage C calls the heal directly, so detection isn't tested.
- **Effect:**
  - Writes can deepen a split-brain.
  - The failure model reads as a tested guarantee when it isn't one.
- **Fix:**
  - Refuse writes while the latest parity verdict is a split-brain, or check agreement under `wal_lock` before the write-ahead. Add a test.
  - Tie every `TRIAD_FAILURE_MODEL` entry to a behavioural test, or remove it.
  - Use the real temp-file name in the campaign, and drive detection through `compute_and_verify_raid_parity`.

Status: Fixed — test: `run_fault_injection_unit_tests`, `run_unit_self_tests` — commit: `d9869f1`

### 6. The new request filter rejects valid requests and doesn't match what the engines parse
- **Where:**
  - `target_enterprise/src/svc_runtime.rs:1767-1780` (body bytes), `:1787-1858` (SQL) and `:1937-1995` (shell).
  - Routing at `target_enterprise/src/lived_net.rs:2032` and `:2087-2095` classifies with `SqlDb::is_readonly_query`, which disagrees with the filter.
- **Problem:** a reviewer harness reproduced each of these through `dispatch_mailbox_op`, and I confirmed the rules in the code.
  - `PUT /fs` refuses any body containing a control byte other than tab, LF or CR, so binary uploads fail.
  - `POST /sh` refuses `write /var/note it's`, `a;b` and `fish&chips`, which the console runs as given. `POST /cron` accepts the same text and runs it on the next tick.
  - `POST /sql` refuses an empty body, `SELECT … ;;`, `.TABLES` and `.dump`. The last two are classified as mutating.
  - Every rejection is reported as `EPERM (service isolation policy violation)` (`lived_net.rs:3030`) and counted as a served request.
  - The engines run one statement or command per line and don't interpret `--`, `/* */`, `;`-chaining, pipes or `$()`. So "blocks stacked SQL injection, comment smuggling and shell chaining" refers to syntax that has no effect downstream.
  - The one real effect is incidental: rejecting `/*` keeps SqlDb's in-band `/*triad*/` and `/*t*/` owner prefixes (`/*t*/` is new in `7d88d4b`) away from HTTP callers.
- **Effect:**
  - Documented endpoints reject legitimate input.
  - Whether a request is accepted depends on the transport.
  - Telemetry records malformed input as isolation violations.
- **Fix:**
  - Classify with one shared function, and don't reject syntax the engines don't interpret.
  - Allow binary `VfsWrite` bodies, or document text-only and return 400 or 415.
  - Validate before any counter changes, and return a distinct 400.
  - Remove the owner override at its source: refuse the prefix in `exec_as` for callers other than the Triad controller, and add a test.
  - Add should-pass tests through `LivedNet`.

Status: Fixed — test: `sql::tests::sql_owner_triad_prefix_refused_for_non_triad_and_non_console_owners`, `lived_net::tests::http_request_prefilter_accepts_binary_vfs_valid_sql_and_shell_and_returns_400_without_counter_inflation` — commit: `a3ce4bf`

### 7. `TriadIngressVoter` is an unused library, and its test overwrites the voter's state to pass
- **Where:**
  - `target_enterprise/src/lived_net.rs`: `:2613-2618` (doc), `:2752-2821` (vote), `:2830-2918` (rolling morph) and `:2965-2971` (heal).
  - The test sets `voter.node_seq = [2, 2, 2];` at `:6072`.
  - Claims: `README.md:117`, `RESULTS.json:197`.
- **Problem:**
  - Only two unit tests use it; the kernel, the controller and the fleet don't. Its single `cluster_key` doesn't match live nodes, which seal with per-node keys.
  - It mixes two counters:
    - `node_seq` counts mutating votes, including requests every node rejected.
    - The heal compares against and copies `SqlDb.tx_seq`, which counts statements and starts at 7.
  - A reviewer harness reproduced the result: after a valid heal `node_seq` becomes `[2, 2, 9]`, and the next catch-up of an up-to-date node is refused. The test hides this by overwriting `node_seq`; I confirmed the override.
  - An isolated node can rejoin through `begin_rolling_morph` and `complete_catchup` without the heal, because catch-up trusts the hash and sequence number the caller supplies.
  - A two-node rollback wins the vote and moves `node_hash` backwards.
- **Effect:**
  - The "anti-rollback hardening" in `917109c` isn't proven.
  - A test was written around a defect.
  - The docs describe a gateway capability the system doesn't have.
- **Fix:**
  - Use one counter: each node's committed tx id, advanced only on success.
  - Remove the override, and assert that the later catch-up succeeds.
  - Require `Online` in `begin_rolling_morph`, and bind catch-up to a hash the node reports.
  - Label it an unintegrated library in README and RESULTS.json until something uses it.

Status: Fixed — test: `lived_net::tests::triad_sustained_adversarial_campaign_concurrent_morph_partial_wal_and_raid5_heal` — commit: `a3ce4bf`

### 8. `BTreePager` is an unused prototype documented as SQL storage, and its seal doesn't detect rollback
- **Where:**
  - `target_enterprise/src/btree_pager.rs:225-281` (seal and verify) and `:746-764` (heal).
  - It has no callers outside its own tests. `target_enterprise/src/lib.rs:43` and `:118-120` only re-export it.
  - Claims: `README.md:112`, `:116` and `RESULTS.json:199`.
- **Problem:**
  - It isn't connected to `SqlDb` (still four 64-row tables in one 4 KiB partition), the VFS, the disks or the kernel. It has no load path and no production key.
  - The HMAC binds the page number, but nothing checks an expected LSN, epoch or tree ID, and the root and page-count metadata aren't sealed. A reviewer harness reproduced three consequences:
    - restoring an older sealed page brings back a deleted row and drops a newer one;
    - healing with stale parity restores an old value;
    - a page from another pager with the same key verifies.
  - Smaller issues:
    - A validly sealed page with an out-of-range link panics on the next insert.
    - Deletes never free pages: after filling and emptying the pager, only 64 inserts fit.
    - `scan_range` truncates silently.
- **Effect:**
  - README's "scales structured storage beyond a single 4 KiB table partition" describes a capability that doesn't exist.
  - "Sealed" overstates what the seal protects.
- **Fix:** label it a standalone prototype, or integrate it with:
  - a sealed manifest holding the tree ID, epoch, root, page count and per-page LSN;
  - a per-tree derived key;
  - link validation;
  - a load path;
  - a QEMU test.

Status: Fixed — test: `btree_pager::tests::btree_pager_rejects_rollback_stale_parity_cross_tree_swap_corrupt_links_and_reclaims_deleted_pages`, `btree_pager::tests::btree_pager_scales_to_512_rows_across_split_4kib_leaf_pages_and_verifies_hmac_seals` — commit: `a3ce4bf`

### 9. binmorph still injects `ret`-family bytes, and the "independent verifier" doesn't check the metrics
- **Where:**
  - binmorph:
    - `binmorph/src/lib.rs:1389-1587` (register renaming) and `:2196-2308` (scheduling).
    - `:3546-3555`: only pass 6 checks for `ret` bytes. The `35cff85` fix is at `:3489-3491`.
  - Verifier: `tools/verify_metrics_independent.py:232-290` and `mtd_metrics/tests/independent_verifier.rs:104-284`.
  - Claims: `README.md:65`, `:151` and `:156`; `RESULTS.json:153`, `:156` and `:175-177`.
- **Problem, in binmorph:**
  - Register renaming and rescheduling re-encode ModRM, REX and displacement bytes without checking for `ret`-family bytes.
  - binmorph's own test `try_swap_r14_r15_applies_consistently` (`:3874-3883`) expects `49 89 CE` → `49 89 CF`.
  - Two reviewer harnesses measured 31 functions gaining interior C3/CF bytes at seed 42 on the current kernel. `35cff85` fixed this only inside pass 6.
  - README:65 promises "100% scrubbing", and README:156 says "0 injected".
- **Problem, in the verifier:**
  - The script recomputes none of what `cuttle_mtd_metrics` produces: gadget survival, chain viability, pairwise survival. It computes different byte-level proxies instead.
  - No test compares the two. `cross_check_mtd_metrics_against_independent_python_verifier` calls no `cuttle_mtd_metrics` function.
  - RESULTS.json credits the script with a "table-driven x86-64 decoder" it doesn't have.
  - Its "interior C3/CF" count includes every such byte except a function's last, including real early `ret`s (about 1,386 of 2,953 at HEAD). It reports only totals, so it can't support "0 injected".
  - Its checks are bare `assert`s, so under `python -O` a no-op binmorph passes. It also passes when there is no kernel ELF.
  - The Rust tests' bounds sit just below the recorded output.
- **Effect:**
  - Two README rows overstate scrubbing.
  - A bug in the metric code would still pass "independent verification".
- **Fix:**
  - In binmorph, reject any rename or reschedule that adds a `ret`-family byte (compare per-function counts pass by pass), and add a real-kernel test that per-function counts never increase.
  - Either re-scope the script as a binmorph-output auditor and say so, or add a real cross-check against `churn()` and the other metrics.
  - Use explicit exit codes, and fail when the kernel ELF is missing.
  - Correct README:65, README:156 and RESULTS.json.

Status: Fixed — test: `cuttle_binmorph::tests::real_kernel_functions_never_gain_ret_family_or_c3_cf_bytes_across_seeds`, `independent_verifier::cross_check_real_compiled_kernel_elf_with_independent_python_verifier_and_dataflow_chains`, `independent_verifier::cross_check_mtd_metrics_against_independent_python_verifier` — commit: `fddcbf6`

### 10. The differential-equivalence suite silently drops a third of the kernel and misses two kinds of morph bug
- **Where:**
  - `binmorph/tests/differential_equiv.rs:2346-2373`: sections are mapped raw.
  - `:2402-2457`: functions that fault are dropped.
  - Thresholds at `:2477-2496`.
  - Claims: `README.md:161` and `RESULTS.json:140-152`.
- **Problem: relocations are never applied.**
  - The kernel is a PIE with 4,542 `R_X86_64_RELATIVE` relocations into `.got` and `.data.rel.ro`, and each of those slots is 0 in the file.
  - Functions that load a global or function pointer fault and are dropped without being counted. The dropped set leans toward pointer-heavy code.
  - I reproduced it: 754 functions are verified as shipped, and 1,111 when the relocations are applied in a scratch copy.
  - The `.data/.bss` copy-on-write support added in `0886ce2` exercises 0 functions as shipped, and 20 with relocations applied.
- **Problem: two guards can be removed without the suite noticing.** I re-ran the reviewer's mutants:
  - Without the upper-32 guard (`lib.rs:3287`, used at `:3432`), 19,053 verified (function, seed) morphs change and the suite reports 0 mismatches.
  - Without the RIP-relative guard in the cross-width pass (`lib.rs:3197`, `:3207`), 552 change and it reports 0 mismatches.
  - In a micro-oracle, both mutants produce real divergences (26 and 25 of 64 seeds), and HEAD produces none.
  - Only `0886ce2`'s unit test guards against the second, and it just asserts that the pass changes nothing.
- **Problem: coverage and docs.**
  - The suite executes only about 15% of the changed bytes in `.text`.
  - README and RESULTS.json still cite the 522-function run. The current run prints 754 functions, 632 faults caught and 10 input profiles, against 6 in RESULTS.json. The synthetic run is 32 inputs × 64 seeds.
- **Effect:**
  - "Verified on 754 real kernel functions" covers about a third of the rewritten code.
  - A reintroduced upper-32 or RIP-shift bug would ship green.
- **Fix:**
  - Apply the RELATIVE relocations (bias 0) to both images, and assert that the count matches `.rela.dyn`.
  - Fix the emulator's call handling first. With relocations applied, two functions diverge because the emulator follows calls into morphed callees; the reviewer traced this to the harness, not binmorph.
  - Add corpus functions for:
    - a 32-bit self-test after a 64-bit write with a non-zero upper half;
    - an interior `[rip+disp32]` inside a shiftable window.
  - Report "N verified of M rewritten", and regenerate the doc numbers from a run.

Status: Fixed — test: `differential_equiv::differential_equivalence_on_real_compiled_kernel_elf_functions`, `differential_equiv::differential_equivalence_across_all_passes_and_64_seeds`, `differential_equiv::differential_equivalence_catches_injected_semantic_bugs_meta_test` — commit: `fddcbf6`

### 11. Round 8 #5 residual: an upgrade boot adopts a wiped Triad when more than one table is voted
- **Where:** `tools/triad_controller.py:119-129` (`_is_genesis_sql_probe`), used at `:3246` (upgrade), `:3107` and `:3351`.
- **Problem:** the digest-only genesis marker only matches a probe of at most two lines. With `vote_tables = ["kv", "idx"]`, as in the fleet's `index` job, a genesis probe has three lines, so it is never recognized.
- **I reproduced it on the real shell.** Setup: a legacy (pre-v2) WAL holding three committed writes, with all three nodes back at genesis.
  - With one vote table, boot replays the WAL (6 rows).
  - With two, it logs `Probe format upgraded to v2: 3/3 nodes agree`, adopts the empty state at `tx_seq=3`, and drops the three rows with no ALERT.
- **Effect:** in that narrow upgrade case, every committed write is lost silently.
- **Fix:**
  - Check genesis per table: split on `\n--\n` and compare each header with that table's genesis digest.
  - Refuse the 3/3 upgrade when every table is at genesis and the WAL has entries.
  - Add a multi-table test.

Status: Fixed — test: `run_unit_self_tests` — commit: `d9869f1`

### 12. Round 8 #4 residual: a path near the 256-byte limit stops the web Triad's vote
- **Where:**
  - `tools/triad_controller.py:1698`: `cathex` refuses commands over 256 bytes.
  - `:2021-2028`: the web probe returns `None` if any file is unreadable.
  - `contracts/src/storage_and_fs.rs:102`: `FS_PATH_MAX = 256`.
- **Problem:**
  - `cathex <path> <offset> 128` doesn't fit in 256 bytes for paths over about 243 characters, and the cutoff is lower at larger offsets.
  - Such paths are legal: the console's `write` creates them up to 248 characters.
- **I reproduced it on the real shell,** with the same file on all three web nodes:
  - A 243-character path votes 3/3.
  - At 244, 246 and 248 characters every probe returns `None`, and each vote logs `TMR parity vote could not verify 2/3 majority`.
- **Effect:** a single long file name turns off divergence detection for the web Triad. Unlike Round 8 #1, it is now loud.
- **Fix:**
  - Cap VFS paths so the longest controller command always fits, and reject longer paths when a file is created. Or address files without repeating the path.
  - Test at the maximum length.

Status: Fixed — test: `shell::tests::writable_vfs_path_enforces_200_byte_cap_and_fits_cathex_writehex_line_limit`, `run_unit_self_tests` — commit: `d9869f1`

### 13. Docs overstate the Triad and the boot tests
- **Where:** `README.md:9-21` (the new overview) and `:162-163`; `experiments/redteam/RESULTS.json:188-200`.
- **Problem:**
  - "Every read and write is checked by a 2-of-3 majority vote plus 4 KiB RAID-style XOR parity":
    - Writes are counted, not voted on.
    - Parity is never used to check or repair anything. The heal logs the XOR result's hash, then rebuilds from the WAL.
    - `reconstruct_sql_partition_from_xor_parity` (`tools/triad_controller.py:2247-2268`) is called only from tests, and handles only nodes 1 and 2.
  - "native UDP `:8081` quorum state-hash checks … detect the divergence":
    - The controller never sends `TRIAD_*` datagrams.
    - Each node sits on its own NATed network with only TCP 80 and 443 forwarded.
    - `triad_node_id` is set only in tests.
    - Detection is actually the controller's serial-console vote.
  - "reboot into a freshly scrambled binary in ~140 ms": 140 ms is the binmorph step; a boot takes seconds.
  - The multi-seed QEMU row and RESULTS.json say three boots "emitted all 130 required boot banners + SHELL resume OK" with intact `CTTLSHL1`/`CTTLFS01`/`CTTLSQL1` state. The test:
    - checks 18 milestone banners;
    - checks `SHELL resume OK` only on boots 2–3;
    - writes no SQL or file state for later boots to read back.
  - RESULTS.json labels the `bc2e012` test "in_kernel_triad_and_raid", but the XOR is computed in the test body.
  - RESULTS.json claims XOR reconstruction "across all 3 node losses", but node 3 raises an error.
- **Fix:**
  - Describe what actually runs: a serial-console digest vote and a WAL rebuild, with parity for information only.
  - Make the boot-test row match its assertions, or make the test assert all 130 banners and persist state that later boots must read back.

Status: Fixed — test: `qemu_smoke::morphed_kernel_boots_and_persists_state_across_multiple_seeds_under_qemu`, `run_unit_self_tests`, `run_fault_injection_unit_tests` — commit: `82fd583`, `a6ca484`

---

## Low priority

### 14. Smaller items
- **Dataflow chain metric (`mtd_metrics/src/chainsim.rs:384-451`, `:540-567`):**
  - It treats `call` and `jmp` as no-ops, and counts any register write as control of that register.
  - Its static check accepts a different gadget at the same offset.
  - So the recorded 0.068 and 0.55 don't measure ROP-chain survival. The error favours the attacker, so it doesn't inflate the defence claims.
  - Those figures and the seed-42 metrics came from an older kernel (`.text` 719,232 B, against 725,160 B today).
  - `1d4e870` dropped the table-header scope that applied to the older rows (25.8%, 0/2,000, 1.15%, 8.80%).
  - Record the build and seed with every number, and regenerate the numbers from a script.
- **Probe format version (`tools/triad_controller.py:116`):** `04838f7` changed the digest input from full rows to headers after v2 was defined. Bump the version whenever the probe text changes, and add a golden test that pins the probe text for a known table.
- **Mismatch diagnosis (`:2128-2132`):** the full rows fetched after a digest mismatch are thrown away. Either log the differing rows or drop the fetch.
- **Per-peer budget (`target_enterprise/src/lived_net.rs:65`, `:354`):** it keys on source IP. The Triad VMs use QEMU user-mode NAT (`tools/triad_controller.py:1309-1316`), where every client appears as 10.0.2.2, so there it just halves the budget.
- **`do_POST` (`:3979-3990`, changed in `917109c` without mention):**
  - It reads unauthenticated bodies of up to 64 KiB before answering 401, and the handler has no socket timeout.
  - It is local only, but set `TriadHttpHandler.timeout` and add a stalled-body test.
- **`reconstruct_sql_partition_from_xor_parity` (`:2247-2268`):**
  - It has no production caller, writes unverified bytes, skips fsync, and zero-fills short peer images.
  - Delete it, or verify and fsync before wiring it in.
- **Fleet self-test (`tools/cuttle_fleet.py:1079-1084`):**
  - It expects WHPX whenever the probe reports WHPX available, but the controller legitimately falls back to TCG when a WHPX guest stays silent. That is why it failed on `auto` here.
  - Assert the accelerator each node actually reports.
- **Parser bookkeeping (`target_enterprise/src/shell.rs:787-792`):** the post-parse checks compare values derived from the same `op`, so they can't fail. The "bytecode digest" is an FNV-1a hash that nothing verifies.
- **Metrics details:**
  - Pairwise positional survival is asymmetric, and fewer than 2 variants returns zeros (`mtd_metrics/src/lib.rs:495-535`).
  - The script exits 0 when arguments are missing.
  - Several of its docstrings describe window lengths and checks it doesn't perform.
- **`TRIAD_ACK` de-duplication (`lived_net.rs:1018-1046`):** it remembers only the last `(seq, hash)` per peer. This affects telemetry only, on a path the live Triad doesn't use.
- **binmorph tidy-up:**
  - `fn _noop_guard() {}` at `binmorph/src/lib.rs:3598` is dead code.
  - `rewrite_elf_bytes` duplicates `diversify_elf`'s ELF walk.
- **Boot provisioning (`tools/triad_controller.py:3454`):** after the merge, `_provision_sql` fails with "quorum lost" if fewer than 2 nodes boot, and it is never retried.

Status: Fixed — test: `run_unit_self_tests`, `run_fault_injection_unit_tests`, `cuttle_mtd_metrics::tests::pairwise_diversity_reports_unique_seeds_and_nonzero_byte_diff`, `cuttle_mtd_metrics::chainsim::tests::dataflow_chain_sim_breaks_under_register_permutation`, `lived_net::tests::tcp_per_peer_slot_cap_exempts_qemu_slirp_nat_gateway_and_caps_external_peers`, `lived_net::tests::triad_ack_dedup_remembers_multiple_recent_seq_per_peer`, `python tools/cuttle_fleet.py --self-test --accel tcg` — commit: `d9869f1`, `a3ce4bf`, `fddcbf6`, `a6ca484`

---

## Process notes
- **Status lines:** all seven named a test and a commit. The claims for #1, #2, #3, #6 and #7 matched the code and tests. #4 and #5 left residuals at the edges their tests didn't reach: a 68-character path and a single-table spec.
- **How High #1 got in:**
  - The live self-test wasn't run after `bc2e012` or the merge. Last round's notes asked for it.
  - The harness can't catch per-node differences, because its three shells run the same build.
  - Make `triad_controller.py --self-test` and `cuttle_fleet.py --self-test` part of done for any controller change.
- **The side branch** was based on a 10-day-old commit, and before the merge its controller changes were tested only against fakes.
- **New capability claims:** README and RESULTS.json overstate all four new capabilities: the Ring-3 parser, the B+Tree pager, the ingress voter and the independent verifier. Before adding a capability row, link the test that exercises it in the product path. A unit test of an unused library doesn't count.
- **CI** has been red for its whole life. Fix the QEMU step first, then treat a red run as blocking.

## Not reviewed this round
- `Cuttle-OS-Recommendations.md`, the second recommender's untracked file.
- The content of the `svc_runtime` isolation-matrix test, beyond the fact that its expected results come from the same policy tables the code enforces.
- The internals of the CPL=3 stub.
- The `exec_as` owner-selection logic, beyond the Triad prefix.
- CuttleGuard and CuttleChronos, beyond earlier paths.
- GitHub Actions logs. They require authentication, so I read only step results and annotations.
- WHPX: every live run on this host fell back to TCG.
- Carried over from earlier rounds:
  - `rustls` key-material clean-up when a reclaimed session is dropped.
  - Measured heap use under load on a VM.
  - The rest of `triad_console.html`, and the provider's proxying and poll loop.
