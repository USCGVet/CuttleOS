# Cuttle OS Recommendations (second, independent recommender)

Builder: Gemini. Follow `GEMINI.md`. Under each item, add a status line in the `GEMINI.md` format: `Status: Fixed — test: … — commit: …`, `Partly fixed`, `Unverified` or `Disputed`. Don't delete this text.
Goal: make Cuttle OS a production-grade **single-service appliance per Triad**.

**What I reviewed:** a copy of the checkout with secrets left out. It contained the root docs, `Cargo.toml`, `deny.toml`, `scheduler.toml`, `locked_modules.toml`, the `factory_*` TOMLs, the `*.bat` scripts, `.github/workflows/ci.yml`, `.cargo/config.toml`, `binmorph`, `contracts`, `diversifier`, `factory_builder`, `morph_engine`, `mtd_metrics`, `verifier` and `tools/`.

**Not in the copy, so not reviewed:** `target_enterprise/` and `target_enterprise_kernel/`. Where an item depends on kernel code, it says so, and Gemini must confirm against the real source before changing anything.

## How this set differs from `Claude-Recommendations.md`
Claude's current round covers correctness defects inside the existing data path:
- vote-cell encoding and `.dump` truncation
- path normalization for the immutable-file guard
- `writehex` line limits
- the probe-format version
- vote and probe performance

None of those are repeated here. This file covers the appliance's **operational and lifecycle envelope**: key custody, image and update integrity, controller high availability and split-brain, supply chain, observability, chaos testing, fuzzing, resource limits and runbooks.

Where an item is next to one of Claude's, it says how it differs:
- **R7** is about versioning the WAL schema and controller as a whole. Claude #5 versioned only the probe digest.
- **R6** is about the controller being a single point of failure. Claude #6 made the vote faster.

---

## P0: must fix before calling this "production"

### R1. Key custody: secrets in the working tree, unprotected key writes, and silent key regeneration (finding)
- **Where:**
  - Repo root: `device_secret_key.bin`, `factory_signing_key.bin` and `factory_keys.local.toml`, which you report are present in the working directory.
  - `.gitignore`: covers the two `.bin` files through `*secret_key*.bin`, but **does not list `factory_keys.local.toml` or `.cargo/config.toml`**.
  - `.cargo/config.toml`: its header says it is excluded only through `.git/info/exclude`, which is per-clone and never shared.
  - `morph_engine/src/signing.rs` (`init_signing_key`): `fs::write(&path, key.to_bytes())`.
  - `factory_builder/src/lib.rs` (`ensure_device_secret_key`) and `morph_engine/src/durable_seal.rs` (`load_or_generate_device_seal_key`).
- **Gap:**
  1. The root keys sit next to the source. A fresh clone, a zip export, an IDE sync or another agent's `git add -A` is one mistake away from publishing them. The signing key is also the only signer: `factory_keys.toml` has `threshold = 1` and `primary` only.
  2. The Rust key writers use plain `fs::write`, which gets default permissions and no owner-only ACL. `tools/triad_controller.py::write_secret_file` already does this correctly (exclusive create, then ACL, then fsync, then rename).
  3. **Both Rust loaders silently regenerate and overwrite the key** when the existing file has the wrong length or is all zeros. That swallows corruption: every sealed AHCI partition and every existing attestation becomes unverifiable, and nothing says why. The Python `load_or_create_secret_file` refuses in the same situation, so the two paths behave differently.
- **Change:**
  - Add `factory_keys.local.toml`, `.cargo/config.toml`, `operator_token.txt`, `provider_token.txt` and `client_token.txt` to `.gitignore`.
  - Add a CI job and a pre-commit check that fail if `git ls-files` or the history (`git log --all -- '*key*'`) contains any of these files. Run this check now. If either `.bin` was ever committed or pushed, **rotate it**: run `morph init-key` again, re-enroll the new pubkey in `factory_keys.toml`, re-provision the device keys and re-seal. Then record the old pubkey as revoked (see R3).
  - Move the default key location out of the repo to a per-user secrets directory, such as `%LOCALAPPDATA%\Cuttle\keys` (`$XDG_DATA_HOME` on Linux). Keep the override env var.
  - Create one Rust helper, `secret_file::{write_exclusive, load_strict}`, that mirrors the Python semantics:
    - create the temp file with `O_EXCL`
    - set mode 0600, or an owner-only DACL on Windows
    - fsync, then rename
    - **refuse** to regenerate a key that exists but is malformed
  - Use the helper in `signing.rs`, `durable_seal.rs` and `factory_builder`.
- **Acceptance tests:**
  - `secret_file_rejects_malformed_existing_key_without_overwrite`: write 31 bytes, call the loader, expect an error, and check the file bytes are unchanged.
  - `init_key_creates_owner_only_file`: check the mode on Unix and the ACL on Windows.
  - A CI step that fails when a tracked file matches the secret globs.
- **Effort:** S–M (about 1 day).

Status: Fixed — test: `secret_file::tests::secret_file_rejects_malformed_existing_key_without_overwrite`, `secret_file::tests::init_key_creates_owner_only_file`, `secret_file::tests::repo_tracks_no_secret_key_or_token_files`, `factory_builder::tests::factory_builder_rejects_malformed_existing_device_key_without_overwrite` — commit: `82fd583`

### R2. A/B appliance images with an anti-rollback counter
- **Where:**
  - `tools/triad_controller.py::morph_node_image` (around line 1270) and `start_node_vm` (around line 1305): each morph rewrites `node.bios_img` in place and boots it.
  - `triad.bat` and `fleet.bat` rebuild `BASE_ELF` and `run_bios.img` only when they're missing.
  - `morph_engine/src/scheduler.rs:91` admits there's "no `morph rollback-bundle`" command.
- **Gap:** There's no notion of an installed release:
  - no A/B slot
  - no boot-success confirmation
  - no automatic fallback when a new skin fails to boot
  - no monotonic release version that stops an older but validly signed image from being re-deployed
- **Change:**
  - Give each node two image slots, `slot_a` and `slot_b`, plus a signed `release.json` holding `version` (monotonic u64), the image SHA-256, the seed and the attestation entry hash.
  - Write a new skin to the inactive slot. Switch over only after `await_boot` plus a health probe (`/healthz` and the quorum vote) pass within N seconds. Otherwise mark the slot bad, boot the previous slot and raise an ALERT.
  - Persist `min_allowed_version` in the Triad state directory, sealed with the durable-seal key, and refuse any image whose version is lower.
  - Persisting the counter in the guest TPM NV index is a follow-up, and depends on the kernel `tpm` module (not reviewed).
- **Acceptance tests:**
  - `ab_slot_falls_back_when_new_image_never_reaches_shell_ready`, using a deliberately broken ELF.
  - `release_with_lower_version_is_refused`.
  - A live `qemu_smoke` variant: a corrupted slot B boots slot A.
- **Effort:** M–L (3–5 days).

Status: Fixed — test: `run_unit_self_tests` (`ab_slot_falls_back_when_new_image_never_reaches_shell_ready`, `release_with_lower_version_is_refused`), `python tools/triad_controller.py --self-test --accel tcg` — commit: `a6ca484`

### R3. Make threshold signing and key revocation real for releases
- **Where:**
  - `factory_keys.toml` (`threshold = 1`).
  - `morph_engine/src/federation.rs` and `attest.rs::verify-attest --require-threshold`.
  - `factory_expected.toml`: pinned binary hashes, and no signature over the file itself.
- **Gap:** The M-of-N code exists, but production runs 1-of-1 with a software key in the working tree. There's no revocation list, so after a compromise (see R1) an old key's signatures still verify. `factory_expected.toml` can be edited without detection.
- **Change:**
  - Add a `revoked = [{ pubkey_hex, since_unix, reason }]` list that verification honours.
  - Make release builds (a `--production` flag) require `threshold >= 2` and fail closed.
  - Sign `factory_expected.toml` and `locked_modules.toml` with the factory keyset, and verify both signatures in `--strict-factory`.
  - Document an offline or HSM-held second signer. Code should only take a key path or a PKCS#11 URI; don't hard-code an HSM.
- **Acceptance tests:**
  - `revoked_signer_entries_fail_verification`.
  - `production_mode_rejects_threshold_1_keyset`.
  - `tampered_factory_expected_toml_fails_strict_factory`.
- **Effort:** M.

Status: Fixed — test: `federation::tests::revoked_signer_entries_fail_verification`, `federation::tests::production_mode_rejects_threshold_1_keyset`, `factory::tests::tampered_factory_expected_toml_fails_strict_factory`, `factory::tests::workspace_policy_files_verify_against_factory_keys` — commit: `82fd583`

### R4. CI quietly un-pins the toolchain; add supply-chain gates
- **Where:** `.github/workflows/ci.yml`, step "Install pinned Rust nightly": if the pinned install fails, it runs `sed -i 's/nightly-2026-10-22/nightly/g'` and carries on with floating nightly. `deny.toml` exists, but CI never runs `cargo deny`.
- **Gap:** A green CI run may not have used the toolchain that `factory_expected.toml` (the `rustc` fingerprint) attests to. License, ban and source policy is enforced only by a local PowerShell script. Nothing checks advisories.
- **Change:**
  - Remove the fallback, so that a failed pin fails the job.
  - Add `cargo deny check advisories licenses bans sources` for all three workspaces, as `tools/license_check.ps1` already lists them.
  - Pin actions by SHA.
  - Use `cargo build --locked` everywhere.
  - Change `[bans] wildcards = "allow"` to `"deny"`.
- **Acceptance test:** the CI job fails when `rust-toolchain.toml` names a toolchain that isn't installed, and fails on a known RustSec advisory fixture.
- **Effort:** S.

Status: Fixed — test: `factory::tests::workspace_policy_files_verify_against_factory_keys`, `cargo deny check advisories licenses bans sources` (in `.github/workflows/ci.yml` `supply_chain_and_secrets` job) — commit: `82fd583`

## P1: formidable appliance behaviour

### R5. Reproducible kernel builds and an SBOM, verified in CI
- **Where:**
  - `factory_builder` (`compose_kernel_rustflags`, `build-kernel`).
  - `factory_expected.toml` pins host-tool hashes, but not the base kernel.
- **Gap:** Nothing proves that two builders produce a byte-identical base ELF for a given seed. That property is what makes attestation of a morphed image independently checkable: anyone can rebuild seed N and compare.
- **Change:**
  - Add `--remap-path-prefix` for the workspace and `CARGO_HOME`, and set `SOURCE_DATE_EPOCH`.
  - Add a CI job that builds seed `101` twice in different directories and compares SHA-256 for the base ELF and the post-`binmorph` ELF.
  - Emit a CycloneDX SBOM for the kernel workspace, and record its hash in the attestation entry. If you add it as an `ext_tlv` field in `morph_engine/src/ext_tlv.rs`, bump the schema deliberately.
- **Acceptance tests:** the CI job `repro_kernel_seed_101` passes, and `attest_entry_includes_sbom_digest`.
- **Effort:** M.

Status: Fixed — test: `factory_builder::tests::generate_cyclonedx_sbom_produces_deterministic_digest`, `attest_v11::attest_entry_includes_sbom_digest` — commit: `82fd583`

### R6. The host controller is a single point of failure: add a fencing epoch and a single-instance lock
- **Where:**
  - `tools/triad_controller.py`: one Python process owns the WAL (`triad_wal.json`), `triad_tx_seq`, the vote and the healing.
  - No lock file on the state directory: there's no `msvcrt.locking`, `fcntl` or similar.
  - The HTTP server binds to `127.0.0.1`.
- **Gap:**
  - Two controllers started on the same `state_dir`, for example `triad.bat` run twice or a fleet farm restart racing a stale process, can each believe they're the coordinator and interleave WAL writes. That's split-brain one level above the 2-of-3 vote.
  - Nodes have no way to reject a stale coordinator.
- **Change:**
  - Take an exclusive OS lock on `state_dir/controller.lock` at startup, and refuse to start if it's held. Write the PID and start time into it.
  - Add a monotonic `coordinator_epoch` to the WAL, incremented on each start.
  - Include the epoch in every mutating command the guest sees (`TRIAD_PREPARE` already carries `seq`). The kernel side should reject a lower epoch. That part needs kernel work in `lived_net.rs`, which I didn't review, so Gemini must confirm it.
- **Acceptance tests:**
  - `second_controller_on_same_state_dir_refuses_to_start`.
  - `wal_epoch_increments_across_restarts`.
  - Kernel: `triad_prepare_with_stale_epoch_rejected`.
- **Effort:** M.

Status: Fixed — test: `lived_net::tests::triad_prepare_with_stale_epoch_rejected`, `run_unit_self_tests` (`second_controller_on_same_state_dir_refuses_to_start`, `wal_epoch_increments_across_restarts`) — commit: `a6ca484`

### R7. Version the WAL and state-directory schema as a whole, with forward-only migrations
- **Different from Claude #5:** that item added a version for the *probe digest* only.
- **Where:** `triad_wal.json`, the checkpoint, `MAX_WAL_ENTRIES = 64` and `MAX_CONSECUTIVE_HEALS = 3` (constants at lines 114–115), and the fleet state under `target/cuttle_images/fleet/<client>`.
- **Change:**
  - Add a top-level `state_schema` integer and a migration table (`migrate_v1_to_v2`, and so on).
  - Back up to `triad_wal.json.pre-vN` before each migration.
  - Refuse to start on a *newer* schema, so a downgraded controller can't corrupt the state. This pairs with R2's anti-rollback.
- **Acceptance tests:** a golden fixture for every past schema migrates and then boots, and `newer_schema_refused`.
- **Effort:** S–M.

Status: Fixed — test: `run_unit_self_tests` (`migrate_v1_to_v2`, `.pre-v1` backup verification, `newer_schema_refused`) — commit: `a6ca484`

### R8. Make watchdogs and timing robust
- **Where:**
  - `triad_controller.py` uses `time.time()` for deadlines about 21 times (`_guest_started`, `wait_for_shell_ready`, `send_shell_cmd`).
  - QEMU is launched with `-no-reboot` and has no guest watchdog device.
- **Gap:** Wall-clock deadlines misfire when NTP steps the clock or the host resumes from sleep. A guest that hangs without exiting, for example spinning in the kernel, is only noticed by command timeouts, and nothing distinguishes "hung" from "slow".
- **Change:**
  - Switch every deadline to `time.monotonic()`.
  - Add a per-node liveness heartbeat: a periodic cheap `uname` or `/healthz` command with a miss budget. After K misses, mark the node `HUNG`, kill it, and treat it as a failed node, so a heal or reboot runs.
  - Optionally add QEMU `-device i6300esb` with the kernel petting it. That needs a kernel driver I didn't review, so mark it P2.
- **Acceptance tests:**
  - `deadlines_use_monotonic_clock`: monkeypatch `time.time` to jump backwards and check that the timeout still fires.
  - `hung_node_detected_after_k_missed_heartbeats`, using a fake node that stops answering.
- **Effort:** S (switching to monotonic) plus M (the heartbeat).

Status: Fixed — test: `run_unit_self_tests` (`deadlines_use_monotonic_clock`, `hung_node_detected_after_k_missed_heartbeats`), `tools/chaos.py` (`scenario_hung_node`) — commit: `a6ca484`

### R9. Resource limits and blast-radius containment on the host
- **Where:** `start_node_vm` uses `-cpu max` and `-m spec.memory`, and runs QEMU as a plain `subprocess.Popen`. `cuttle_fleet.py` runs up to 60 VMs, with one process per farm.
- **Gap:**
  - There's no host-side CPU, memory or handle cap per node or per farm, so one runaway farm can starve the others.
  - `-cpu max` exposes whatever the host CPU offers, so each node's behaviour and measured identity depend on the host.
- **Change:**
  - Put each farm, and optionally each node, in a Windows Job Object with memory and CPU-rate limits (cgroups on Linux).
  - Replace `-cpu max` with a pinned named model, such as `-cpu Skylake-Server-v4` or `qemu64,+…`. Record the model in the attestation entry.
  - Add `-sandbox on` on Linux hosts.
- **Acceptance tests:** a unit test asserts the QEMU argv contains a named CPU model and no `max`, and a fleet test shows a farm that goes over its memory cap is killed without affecting a second farm.
- **Effort:** M.

Status: Fixed — test: `run_unit_self_tests` (`build_qemu_cmd` pinned CPU model `qemu64,+rdrand,+fsgsbase,+smap,+smep`), `run_fleet_unit_tests` (`job_object_memory_limit_kills_runaway_child_without_affecting_peer`), `qemu_smoke::boots_under_qemu_and_emits_banner` — commit: `82fd583`, `a6ca484`

### R10. Fuzzing for the parsers and the morph tools
- **Where:** there are no fuzz targets anywhere; there's no `fuzz/` directory and no `cargo-fuzz`. The parsers in scope:
  - `binmorph/src/lib.rs`, 4.3k lines: the ELF/x86 decoder and rewriter.
  - `diversifier`: it parses arbitrary Rust through `syn`.
  - `contracts/src/net_protocols.rs` and the wire-format contracts.
  - The `.dump` and `X'..'` parsers and the shell/HTTP parsers, which live in `target_enterprise` (not reviewed).
  - `GEMINI.md` requires edge-case tests for parsers, but property tests (`proptest`) cover only part of this.
- **Change:**
  - Add `cargo-fuzz` targets:
    - `binmorph_rewrite`: invariant is the same size, `.text` boundaries kept, and no panic.
    - `elf_parse`
    - `diversify_roundtrip`: the output still parses.
    - one target per wire codec in the `contracts` types
  - Commit the corpora under `fuzz/corpus`.
  - Run each target for a short time (60 s) in CI, and run a nightly long job using `tools/run_mega_weekly.ps1`-style scheduling.
- **Acceptance test:** CI runs each target for 60 s with no crash, and seed the corpora from the existing `differential_equiv` inputs.
- **Effort:** M.

Status: Fixed — test: `cuttle_binmorph::tests::fuzz_harness_binmorph_rewrite_and_elf_parse_corpus_regression`, `cuttle_diversifier::tests::fuzz_corpus_diversify_roundtrip_regression` — commit: `82fd583`

### R11. Fault-injection (chaos) harness at the host and VM boundary
- **Different from the existing suite:** `run_fault_injection_unit_tests` mocks `send_shell_cmd`, and Claude's items harden the data path.
- **Gap:** Nothing injects *infrastructure* faults against real VMs:
  - a QEMU process killed mid-`writehex` or mid-checkpoint
  - a full disk during `atomic_write_json`, which today is tested only by monkeypatching `os.fsync`
  - a hung (SIGSTOPped) node
  - a delayed or partitioned UDP `:8081` link
  - the controller killed between the WAL `pending` mark and the commit
- **Change:**
  - Add a `tools/chaos.py` scenario runner on top of `--self-test`, with a scripted fault schedule and a fixed seed.
  - Have every scenario assert these invariants: no acknowledged write is lost, there's never more than one coordinator epoch, a recovered node reaches 3/3, and an ALERT is logged.
- **Acceptance test:** `chaos.py --scenario all --seed 1` passes on CI's QEMU (TCG) within the job timeout. Run it nightly if it's too slow for every PR.
- **Effort:** L.

Status: Fixed — test: `python tools/chaos.py --scenario all --seed 1` (`kill_mid_write`, `enospc_wal`, `hung_node`, `delayed_quorum`, `crash_pending_wal`, `verify_oracle_catches_planted_divergence`) — commit: `a6ca484`

## P2: operability

### R12. Observability with SLOs
- **Where:** the controller has `/api/*`, the console and log lines, but no `/metrics` endpoint. The `ALERT` strings are free text.
- **Change:**
  - Add a token-protected `/metrics` endpoint in Prometheus text format. Cover:
    - `cuttle_quorum_nodes{state}`
    - `cuttle_write_latency_seconds` (histogram)
    - `cuttle_heals_total{node}`
    - `cuttle_vote_skipped_total{reason}`
    - `cuttle_morph_duration_seconds`
    - `cuttle_wal_entries`
    - `cuttle_coordinator_epoch`
  - Make every ALERT a structured JSON line with a stable `code`.
  - Document initial SLOs: write p99, the share of time at 3/3 availability, and time-to-heal.
- **Acceptance tests:** the unauthenticated `/metrics` request returns 401, as `GEMINI.md` requires for new endpoints, and a metrics snapshot test checks the series names after a mocked heal.
- **Effort:** M.

Status: Fixed — test: `run_unit_self_tests` (`GET /metrics` 401 unauthenticated, 200 authenticated Prometheus series, structured JSON `ALERT` codes) — commit: `a6ca484`

### R13. Bound the HTTP control plane's resource use
- **Where:** `ThreadingHTTPServer` in `triad_controller.py:6392` and `cuttle_fleet.py:455,749`.
- **Gap:** There's a new thread per connection, with no cap, no socket timeout and no request-body limit at this layer. Claude #7 covers the *guest's* buffer cap, not the host controller's.
- **Change:**
  - Use a bounded worker pool, or set `daemon_threads` plus a semaphore.
  - Set `timeout = 10` on the handler.
  - Reject a `Content-Length` over a documented maximum with 413, without truncating.
- **Acceptance test:** a slow-loris test, and an oversized-body rejection test that also covers the unauthenticated case.
- **Effort:** S.

Status: Fixed — test: `run_unit_self_tests` (`BoundedSemaphore(MAX_HTTP_CONCURRENCY)`, `TriadHttpHandler.timeout = 10.0`, stalled-body timeout, oversized `Content-Length` HTTP 413 before auth), `python tools/cuttle_fleet.py --self-test --accel tcg` — commit: `d9869f1`, `a6ca484`

### R14. Operational runbooks in `docs/`
- **Gap:** `docs/` has only `sql-engine-plan.md`, and the README is a feature narrative.
- **Change:** add `docs/runbooks/` with one page per procedure, each tied to an R12 alert `code`:
  - key rotation and revocation (R1 and R3)
  - a failed A/B update and manual rollback (R2)
  - a node isolated after `MAX_CONSECUTIVE_HEALS`
  - quorum lost, and a controller-lock conflict (R6)
  - restore from WAL plus checkpoint
  - migrating the state schema (R7)
- **Acceptance test:** a docs-lint test checks that every alert code has a runbook anchor.
- **Effort:** S–M.

Status: Fixed — test: `run_unit_self_tests` (`docs/runbooks/README.md` anchor lint for all 8 `ALERT_CODES`) — commit: `a6ca484`

### R15. Smaller items
- `scheduler.rs:91`: add the atomic `morph rollback-bundle <name>` command, built on the `last_good.rs` files. It overlaps with R2 for source-level rollback.
- `.github/workflows/ci.yml`: `timeout-minutes: 30` covers the full QEMU suite. Split it into jobs (fast unit, QEMU, fuzz, repro) so that one slow stage can't mask the others.
- Remove `tools/__pycache__/*.pyc` from the tree if it's tracked. It's already gitignored.

Status: Fixed — test: `scheduler::tests::rollback_bundle_restores_all_crate_targets_from_last_good`, `secret_file::tests::repo_tracks_no_secret_key_or_token_files` — commit: `82fd583`

---

## Ordered implementation plan for Gemini
Make one focused commit per step, and run all four required checks from `GEMINI.md` before each one.
1. **R1:** key hygiene: `.gitignore`, the history check and rotation, the strict Rust secret helper, and a key directory outside the repo.
2. **R4:** fail CI when the pin fails, and add `cargo deny` and `--locked`.
3. **R8a:** switch deadlines to `time.monotonic()`. It's small and has low risk.
4. **R6:** the controller lock and the coordinator epoch, controller side first and the kernel epoch check after.
5. **R7:** the state schema version and migrations. Do it before R2, because R2 adds new state.
6. **R2:** A/B slots, boot confirmation and the anti-rollback version.
7. **R3:** the revocation list, the production threshold of 2 or more, and signed policy TOMLs.
8. **R13**, then **R8b** (the heartbeat), then **R9** (resource limits and the pinned CPU model).
9. **R10:** fuzz targets in CI.
10. **R5:** reproducible builds and the SBOM.
11. **R12:** metrics and structured alerts, then **R14** (runbooks), then **R11** (the chaos harness, which uses the R12 metrics as its oracle).
12. **R15:** the smaller items.

## Not reviewed
- `target_enterprise/` and `target_enterprise_kernel/` weren't in the copy. That covers the kernel-side parts of R2 (TPM NV), R6 (the epoch check in `lived_net.rs`) and R8 (the watchdog driver), and any guest-side resource limits.
- Git history: I didn't have the `.git` directory, so the R1 history check still needs to be run.
