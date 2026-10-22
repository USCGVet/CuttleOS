# Claude Recommendations

Review of the 11 commits after `a623b5a`, up to `1c59464`: `79b8161` and `ca26a6d` (round-4 fix and status line), `5e504e8` and `75969d3` (nightly build fixes), `c39fec8`, `c47de8f`, `2c2dd0a`, `9e34b6b` and `fc50b63` (Triad controller, fleet provider, ops console, WHPX), `04677dd` (hand-written TLS replaced with rustls and a RustCrypto provider) and `1c59464` (Apache-2.0 licensing). The range is 50 files, +15,196 / −3,933 lines. Line numbers are from `1c59464`.

**Test status at review time.** The review ran on Linux from a copy of the checkout's git data. The checkout had no uncommitted changes.
- `cargo test --workspace --no-fail-fast` (stable 1.97): **2,419 passed, 1 failed, 15 ignored.**
  - The failure is `morph_engine/tests/cycle_durable_seals.rs`. It can't pass on any machine except the builder's; see #13.
  - The commits report 2,428 passed on Windows. This run executed 2,420 tests. I didn't investigate the difference.
- `cargo test -p factory_builder --test qemu_smoke -- --ignored`: **not run.** The review environment couldn't download a nightly toolchain.
- `target_enterprise_kernel` release build: **not run**, for the same reason.
- `tools/triad_controller.py`: **parses**, and so does `tools/cuttle_fleet.py`. The Python self-tests weren't run, because they need QEMU and built kernel images.

## Verification of last round's items

| # | Item | Verdict | Notes |
|---|---|---|---|
| 1 | Session tokens and attestation quotes created with an unset attest key | **Verified fixed** | `try_create_session`, `compute_attestation_mac` and `cmd_attest` refuse while `attest_key` is unset and record an audit entry. HTTP `/session/login` (`lived_net.rs:1434`) returns 503. `regression_round4_item1_unset_attest_key_refuses_session_and_quote` exercises the shell paths and passes. The HTTP 503 branch has no direct test, but it sits behind the earlier device-key check, so this is minor. |

---

## High priority

### 1. The TLS random generator is most likely seeded from timers only, and a weak seed is never refused
- **Where:**
  - `target_enterprise_kernel/src/provisioning.rs:91-154` (`read_hw_entropy_u64`) uses RDRAND only when CPUID reports it. Otherwise it falls back to TSC, CMOS and PIT readings.
  - `provisioning.rs:274-289` (`tls_rng_seed`) adds TPM bytes only if a TPM answers.
  - `net_service.rs:513` seeds `SYSTEM_RNG` from that result.
  - None of the launchers passes `-cpu` or attaches a TPM or `virtio-rng`: `run.bat`, `tools/triad_controller.py`, `factory_builder/tests/qemu_smoke.rs`.
- **Problem:** QEMU's default CPU model doesn't advertise RDRAND, and no launcher provides a TPM. So in every shipped configuration the CSPRNG seed most likely comes only from timer and clock readings. `tls_rng_seed` can't fail. "Fails closed until seeded" (`tls_provider.rs:21`, `README.md:105`) covers "never seeded", not "weakly seeded". Nothing node-specific (device key, MAC, boot counter) goes into the seed.
- **Effect:** Ephemeral key-exchange secrets and handshake randoms come from a stream with low, unmeasured entropy, so HTTPS forward secrecy depends on it. The README names RDRAND and TPM as sources that are probably absent in practice. On unprovisioned boots the master key comes from the same fallback (see #6).
- **Fix:**
  - Give every launcher a real entropy source: a CPU model with RDRAND (for example `-cpu max` under TCG; check WHPX), or `virtio-rng` or swtpm with a driver.
  - Have the seed function report which sources contributed. Refuse to start HTTPS when neither RDRAND nor TPM contributed, the same way net-auth refuses without a device key.
  - Mix in a key derived from the device master key, plus the MAC and the persisted boot counter.
  - Print the entropy source on the `HTTPS UP` line, assert it in `qemu_smoke`, and add a host test of the refusal path with a mocked source.
- Status: Fixed — test: `tls_provider::tests::derive_tls_rng_seed_requires_rdrand_or_tpm_and_mixes_node_context`, `required_banners_include_https_up_with_rdrand_and_provisioned`, `boots_under_qemu_and_emits_banner` — commit: `17f3d14`, `beb3bfa`, `37f9d23`

### 2. The per-connection TLS transmit queue has no limit, so an unauthenticated client can exhaust the kernel heap
- **Where:**
  - `target_enterprise/src/https.rs:255,294-299,470-491`: `tx` grows with every encrypted response.
  - `lived_net.rs:1123-1146`: up to 8 responses are encrypted per inbound segment.
  - `lived_net.rs:1188` (`flush_https_tx`): at most 2 segments drain per call (`MAX_REPLIES = 3`).
  - `lived_net.rs:233-254` (`tick_tcp_rto`) reclaims only `SynReceived` and `LastAck` slots.
  - `heap.rs:13`: fixed 8 MiB heap, and no allocation-failure handling.
- **Problem:** The receive and plaintext buffers are capped (`MAX_RX_BYTES`, `MAX_PLAINTEXT_BYTES`), but the transmit queue isn't. A client that sends requests faster than it reads the responses makes `tx` grow without limit, on up to 16 slots. Established slots are never timed out. `heap.rs:10-11` assumes "tens of KiB" per connection, and that assumption doesn't hold.
- **Effect:** A failed allocation in this `no_std` kernel ends in a panic, so one network client with no credentials can halt a node. Port 80 has no such queue, so this exposure is new with HTTPS.
- **Fix:**
  - Cap pending `tx` per session (for example 64 KiB). Stop handling further requests while the queue is over the cap, leaving them in the plaintext buffer.
  - Give established HTTPS slots an idle timeout.
  - Add a test that drives many large-response requests without draining and asserts that `tx` stays bounded and nothing panics.
- Status: Fixed — test: `https_tx_cap_backpressure_and_idle_rto_reclaim_slots` — commit: `17f3d14`, `37f9d23`

### 3. Heal on an index Triad never converges: the vote compares `kv` and `idx`, but the heal rebuilds only `kv`
- **Where:**
  - `tools/triad_controller.py:862-869`: the vote reads every table in `spec.vote_tables`.
  - `tools/triad_controller.py:1311-1325`: the heal drops and recreates only `kv`, then replays the whole WAL.
  - `tools/fleet.toml:39-46`: the `index` job votes on `["kv", "idx"]` and creates `idx` through the WAL.
- **Problem:** `idx` is never dropped. Replaying the full WAL re-runs `CREATE TABLE idx`, which fails because the table exists, and re-runs the provisioning `INSERT INTO idx` statements, which add duplicate rows. `_adopt_tx_seq_from_majority` (`:1369`) also compares only `kv`.
- **Effect:** After any heal on an index Triad, including the console's tamper drill, the healed node's `idx` differs from its peers. The next vote outvotes it again, so ALERT, HEAL and emergency morph repeat, and each round adds more duplicates. The pro plan ships this job.
- **Fix:** Have the heal rebuild every table in `spec.vote_tables`, provisioning included. Alternatively, restore the SQL partition from a clean image and replay the WAL. Add a fleet self-test that runs the tamper drill on the index job and asserts a 3/3 match with no second ALERT.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests`, `tools/cuttle_fleet.py::run_self_test` — commit: `beb3bfa`

---

## Medium priority

### 4. Seeded and `--prod` kernel builds silently drop the soft-float crypto cfgs
- **Where:** `factory_builder/src/lib.rs:403,439` sets `RUSTFLAGS` whenever `layout_seed.is_some() || prod`. The cfgs live only in `target_enterprise_kernel/.cargo/config.toml:8-14` (`build.rustflags`).
- **Problem:** Cargo ignores `build.rustflags` when `RUSTFLAGS` is set. Every morph-cycle and production build therefore loses `aes_force_soft`, `polyval_force_soft`, `chacha20_force_soft`, `poly1305_force_soft` and `curve25519_dalek_backend="serial"`, and compiles the SIMD backends into a soft-float kernel.
- **Effect:** The images that actually rotate in production use a crypto backend configuration that no KAT or smoke boot has validated, against the config's own comment that no SIMD is emitted. Depending on the nightly, the seeded build may fail outright (see the comment at `target_enterprise/Cargo.toml:17-19`).
- **Fix:** Have factory_builder append the cfgs from one shared constant to the `RUSTFLAGS` it composes. Add a unit test that the composed flags contain them, and add a `compile_error!` in `target_enterprise` for `target_os = "none"` builds that lack the cfgs. Run `factory_builder build-kernel --layout-seed 1 --prod` to confirm.
- Status: Fixed — test: `tests::compose_kernel_rustflags_always_includes_soft_float_crypto_cfgs`, `boots_under_qemu_and_emits_banner` — commit: `17f3d14`

### 5. Production kernels skip the TLS known-answer tests, but the docs say every boot runs them
- **Where:** `target_enterprise_kernel/src/main.rs:588-592`, where `banner_tls_kat` and `banner_tls_cert` are `#[cfg(not(cuttle_prod))]`. HTTPS itself is enabled in all builds. The claims are at `tls_provider.rs:16-17` ("the kernel runs that self-test at every boot") and `README.md:106` ("Every boot runs the provider's known-answer vectors").
- **Problem:** The builds that ship serve HTTPS without a power-on crypto self-test. Combined with #4, these are also the builds with an untested backend configuration.
- **Effect:** A miscompiled or mis-morphed primitive goes undetected exactly where it matters, and the docs overstate what runs.
- **Fix:** Run `tls_provider::self_test()` unconditionally at the start of `enable_https`, and refuse HTTPS if it fails. Keep only the banner output under the cfg. Add a prod-build boot assertion for `HTTPS UP`, or correct the docs.
- Status: Fixed — test: `provider_known_answer_self_test`, `boots_under_qemu_and_emits_banner` — commit: `17f3d14`

### 6. Unprovisioned boots serve HTTPS from the boot-ephemeral master key, and the boot line doesn't say so
- **Where:** `provisioning.rs:261` (`let (master, _) = device_master_key_state();` ignores the provisioned flag) and `net_service.rs:514-524`.
- **Problem:** On an unprovisioned boot, the certificate's public key derives from the same weak-entropy master key (#1) that also derives the seal and attest keys, and that public key is published. The `HTTPS UP` line looks the same either way. Net-auth already refuses to run without a provisioned key; HTTPS doesn't.
- **Fix:** On unprovisioned boots, generate the TLS key from the CSPRNG independently of the master key, or disable HTTPS. Add `provisioned=0|1` to the `HTTPS UP` line and test both cases.
- Status: Fixed — test: `https::tests::derive_tls_identity_secret_uses_rng_when_unprovisioned_and_master_when_provisioned`, `required_banners_include_https_up_with_rdrand_and_provisioned`, `boots_under_qemu_and_emits_banner` — commit: `17f3d14`, `37f9d23`

### 7. `/api/cron` lets state-changing commands bypass the WAL, and they are re-applied on every boot
- **Where:**
  - `tools/triad_controller.py:1093-1132`: `cron add` is sent to each node and recorded as desired state.
  - `:705-718`: it is re-applied after every boot, morph and heal.
  - The kernel forbids only recursive and power commands (`target_enterprise/src/shell.rs:3411-3423`).
- **Problem:** `/api/sh` is deliberately read-only (`:131`, with a self-test that refuses `cron add` there). `/api/cron` is a second path that schedules any other command, including SQL writes, to run on each node on its own timer, outside `wal_lock` and the WAL. The desired-cron list is also updated after `wal_lock` is released (`:1131-1132`) and written non-atomically (`:1166`).
- **Effect:** Nodes drift apart on their own schedules, so the vote raises ALERT and HEAL. The heal then re-applies the same job, so the drift never ends. The rule that state changes go through the WAL is bypassed.
- **Fix:** Restrict cron commands to the `is_readonly_shell_command` allowlist or a named set of approved jobs. Update the desired-cron state inside the `wal_lock` critical section and write it atomically. Test that a mutating cron command is refused.
- Status: Fixed — test: `tools/triad_controller.py::run_self_test` — commit: `beb3bfa`

### 8. Token and master-key files are written with default permissions
- **Where:** `tools/triad_controller.py:344-350` (master key and `operator_token.txt`); `tools/cuttle_fleet.py:146-154` (`load_or_create_secret`, used for client tokens and per-client `master_key.bin`) and `:462` (`provider_token.txt`).
- **Problem:** `write_text` and `write_bytes` create these files with default permissions (0644 under the usual umask; inherited folder ACLs on Windows). Farm mode also writes an unused per-Triad `operator_token.txt` for every farm Triad.
- **Effect:** On a shared host, other local users can read the provider token, every client token and every client's master key, from which all of that client's node keys derive. Binding to 127.0.0.1 doesn't protect against local users, and loopback-only means the clients themselves are local.
- **Fix:** Create secret files exclusively, with mode 0600 on POSIX and a user-only ACL on Windows. Stop writing unused tokens. Document where secrets live and who can read them.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests`, `tools/cuttle_fleet.py::run_self_test` — commit: `beb3bfa`, `37f9d23`

### 9. WAL durability: a corrupt WAL is silently discarded, and writes are recorded after they execute
- **Where:**
  - `tools/triad_controller.py:405-433`: any load error resets the WAL to empty with no log or alarm, and entries that fail `is_printable_ascii_command` are dropped silently.
  - `:435-443`: the save does tmp + replace, but with no flush or fsync.
  - `:982-1020`: statements run on the nodes first, then the WAL is appended and saved, then `node_tx_seq` is saved in a second write.
- **Problem:** The heal source can vanish without notice, and the next write overwrites the file. Dropping entries on load is silent input truncation. After an unclean stop between the steps, nodes can hold a write the WAL never recorded, or the persisted `node_tx_seq` can trail what the node actually holds.
- **Effect:** Later heals rebuild nodes without the lost writes, so the healed node disagrees with its peers. The false ALERT/HEAL that `c39fec8` fixed comes back in a narrower window.
- **Fix:**
  - Write ahead: append and fsync before executing on the nodes.
  - On a parse error, refuse to start (or keep a `.bad` copy and alarm). Never drop entries silently.
  - fsync the temp file before `replace`.
  - Add a test that stops the controller between steps and checks recovery.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests`, `tools/triad_controller.py::run_self_test` — commit: `beb3bfa`

### 10. Restored and adopted `tx_seq` is trusted without checking it against the node's data
- **Where:** `tools/triad_controller.py:421-427` (a restored value is trusted if it is in `0..triad_tx_seq`) and `:1369-1382` (legacy WAL adoption by 2-of-3 agreement).
- **Problem:** Nothing ties the persisted `tx_seq` to what the node's disk actually holds. If all disks are rolled back, or two stale nodes agree, they keep or adopt the Triad's `tx_seq` and never replay. The `c39fec8` claim that "a node that disagrees keeps 0 and is healed" has no test: self-test 6b covers only the case where all nodes agree.
- **Effect:** Real divergence from the WAL can be masked, giving stale reads with no alarm, or it can turn into a heal loop against the one correct node.
- **Fix:** Persist a per-node state fingerprint (for example a digest of the vote tables) alongside `node_tx_seq`, and restore or adopt only when it matches at boot. Add a legacy-WAL test with one divergent node.
- Status: Fixed — test: `tools/triad_controller.py::run_self_test` — commit: `beb3bfa`

### 11. Web (`wfe`) Triads vote on file names and sizes only, and their heal can't repair persisted files
- **Where:** `tools/triad_controller.py:858-860` uses `ls`, which prints only `path (len B)` (`shell.rs:2620-2633`). The non-SQL heal at `:1286-1294` is an emergency morph that boots onto the same disk image. The claims are at `:855-856` and in the README ("compares the content it serves").
- **Problem:** A same-length change to a served file is invisible to the vote. When divergence is detected, the "heal" reboots onto a disk that still holds the divergent files.
- **Effect:** Content tampering on web Triads goes undetected, and detected divergence becomes a repeating heal and morph loop. The docs overstate what is compared.
- **Fix:** Vote on a content digest of each served file. On a non-SQL heal, restore the file-system partition from a healthy peer or a clean image before rebooting. Change the docs to say what is actually compared.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests` — commit: `beb3bfa`, `37f9d23`

### 12. Node roles fail open
- **Where:** `tools/triad_controller.py:712-715`, where a failed `service role <role>` only logs a WARN and the node then goes ONLINE (`:1236`, `:1268`, `:1408`).
- **Problem:** Each boot starts in the `full` role. If applying the role fails, the node joins the pool running every service.
- **Effect:** The least-privilege split between `wfe` and `sql` is silently not enforced on that node, and the vote doesn't notice.
- **Fix:** Treat a failed role application as a boot failure: keep the node OFFLINE, retry, then alarm. Better still, pass the role at boot (for example over fw_cfg) so the kernel never runs as `full`. Add a test that forces the failure.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests` — commit: `beb3bfa`

### 13. The full workspace suite can pass only on the builder's machine
- **Where:** `morph_engine/tests/cycle_durable_seals.rs:52-56` requires `factory_signing_key.bin` in the repo root. The file is gitignored, and this checkout doesn't have it. Verification (`morph_engine/src/attest.rs:1382-1404`, `:1434-1444`) trusts the `primary` public key in the committed `factory_keys.toml`.
- **Problem:** On a fresh clone the test fails because the key is missing. With a freshly generated key it still fails ("primary signature over entry content does not verify"), because the roster's `primary` is the builder's own key. A run also leaves an untracked `experiments/diversity_demo/results/` that isn't gitignored.
- **Effect:** Nobody else can reproduce "0 failed", including the reviewer and the owner's own checkout. The required check therefore depends on a secret only one machine holds.
- **Fix:** Have the test generate a temporary signing key and a matching temporary roster, and point the verifier at them. Gitignore the results directory.
- Status: Fixed — test: `cycle_attaches_durable_seals_from_dir` — commit: `ef2c0ad`

### 14. The committed federation roster trusts two signers whose private seeds are in the repo (pre-existing)
- **Where:** `factory_keys.toml:13-19` (`placeholder-a`, `placeholder-b`, `threshold = 2`); `morph_engine/tests/fixtures/federation/placeholder_a.seed` and `placeholder_b.seed`; `morph_engine/src/federation.rs:150-181`, which counts any distinct valid signers.
- **Problem:** I confirmed that both committed seeds derive the roster's placeholder public keys. Together they meet the 2-of-3 threshold without `primary`. The module doc (`federation.rs:6-8`) also says `primary` is a test seed, which the roster contradicts.
- **Effect:** `verify-attest --require-threshold` with the shipped roster adds no protection beyond the primary key. That flag is documented as the defense against a stolen primary key, and README:30 advertises M-of-N threshold attestation.
- **Fix:** Keep the fixture signers only in test rosters. Have verification reject a roster that contains a known fixture key. Fix the module doc.
- Status: Partly fixed — committed fixture seeds and RFC 8032 §7.1 example keys are removed from `factory_keys.toml` and rejected by `KNOWN_FIXTURE_PUBKEYS`, `factory_keys.toml` ships with only `primary` (`threshold = 1`), and `verify-attest --require-threshold` rejects `threshold < 2` (test: `federation::tests::rejects_known_fixture_pubkeys`, `threshold_check_rejects_roster_containing_known_fixture_pubkey`, `fixture_seeds_match_factory_keys_toml` — commit: `ef2c0ad`, `37f9d23`, `a38eb08`); enrolling real independent human co-signer keys in `factory_keys.toml` and raising `threshold` to `2` requires an operator key ceremony.

### 15. Fleet port blocks collide for plans with 6 to 9 jobs, which validation allows
- **Where:** `tools/cuttle_fleet.py:71-72` (allows 1 to 9 jobs) and `:117-128` (`base = vm_port_base + slot*100 + t*10`, with `https_base = base + 50`).
- **Problem:** Job 5 and later get HTTP ports that equal earlier jobs' HTTPS ports. Their HTTPS ports run into the next client's block. Nothing checks for overlap between the farm, provider and VM port ranges either.
- **Effect:** Port-forward bind failures leave VMs or whole Triads OFFLINE, and one client's plan can break a neighbouring client.
- **Fix:** Cap plans at 5 jobs, or use a layout with no overlap (for example a separate HTTPS range). Validate all port ranges when the config loads, and add a config test.
- Status: Fixed — test: `tools/cuttle_fleet.py::run_fleet_unit_tests` — commit: `beb3bfa`

### 16. The client-isolation claim holds only at the provider API
- **Where:** `README.md:159-169` and `tools/cuttle_fleet.py:3,17-21` ("isolated farm per client"). Every node forwards :80 and :443 to 127.0.0.1 (`tools/triad_controller.py:583`), and read-only SQL and status routes need no session (`lived_net.rs:1495-1575`, as the README itself says).
- **Problem:** Any local process can read any client's node status and, on SQL-serving roles, its tables, straight from the node port without a token. All farms run as one OS user, and every client's master key sits under one fleet directory (see #8). The fleet self-test checks isolation only through the provider API (`cuttle_fleet.py:881-888`).
- **Fix:** Either scope the wording ("API-scoped; node ports on loopback are reachable by any local process"), or stop forwarding node ports in fleet mode, proxy node access through the farm with scoping, and require a session for reads on fleet nodes. Add a self-test that reads client B's node port directly and expects a refusal.
- Status: Fixed — test: `tools/cuttle_fleet.py::run_self_test` — commit: `beb3bfa`, `37f9d23`

### 17. New endpoints aren't tested without credentials in every role
- **Where:**
  - **Fleet:** `tools/cuttle_fleet.py:825-857`. The farm's `POST /api/shutdown`, `POST /api/load` and `POST /api/t/<job>/…`, and the provider's `/api/c/<id>/stop` and `/load`, are never called without a token or with a wrong one. Unauthenticated calls hit only the `sql` job, never `wfe`, `index` or `cron`.
  - **Controller:** `/api/whoami` and the other endpoints are never tried with a wrong token.
  - **HTTPS:** `target_enterprise/tests/https_interop.rs:244-262` checks 401 for three routes on the default role only.
- **Effect:** The definition of done isn't met for this round's new listeners. The current routing is probably fine, but nothing guards against regressions.
- **Fix:** Loop every endpoint × {no token, wrong token} × every role, at the provider, the farm and the controller. Run the existing port-80 unauthenticated tests over port 443 as well.
- Status: Fixed — test: `every_mutating_endpoint_and_node_role_enforces_auth_over_https`, `tools/triad_controller.py::run_self_test`, `tools/cuttle_fleet.py::run_self_test` — commit: `17f3d14`, `beb3bfa`

### 18. The legacy `/app` dashboard puts node-supplied text into `innerHTML`, on the same storage key `/console` uses for the operator token
- **Where:** `tools/triad_controller.py:1642-1666` (`${n.morph_stats}`, `${n.last_smp}`, `${e.msg}` into `innerHTML`; pre-existing) and `:1619-1624`; `tools/triad_console.html:696` (`'cuttle_triad_token' // the latter is shared with /app`). New event text now includes node output (`:715`, `:1436`).
- **Problem:** The new console renders safely; it uses `textContent` throughout. But it shares its persisted token with a page that doesn't.
- **Effect:** A tampered node, which is exactly the threat the Triad exists to contain, can inject markup into the operator's `/app` page on the controller origin, where the token is readable.
- **Fix:** Render `/app` with `textContent`, or retire it in favour of `/console`. Use a separate storage key, or keep the token in memory or `sessionStorage`. Add CSP and `frame-ancestors` headers.
- Status: Fixed — test: `tools/triad_controller.py::run_self_test`, `tools/cuttle_fleet.py::run_self_test` — commit: `beb3bfa`

### 19. Four opt-in QEMU proofs require a banner the kernel no longer prints
- **Where:** `experiments/diversity_demo/tests/bundle_morph_proof.rs:46`, `experiments/diversity_demo/tests/morphed_qemu_proof.rs:102`, `morph_engine/tests/north_star_soak.rs:62`, `morph_engine/tests/bundle_soak_boot.rs:44` (`"TLS server_hello OK len="`, removed in `04677dd`). Also `morphed_qemu_proof.rs:263-273` returns success with "SKIP" when the seeded build fails.
- **Effect:** These env-gated tests fail whenever enabled. They are the only boot tests of layout-seeded kernels, so the production diversity path currently has no working boot test.
- **Fix:** Update the four banner lists to the current banners. Make a build failure a test failure when the env gate is on.
- Status: Fixed — test: `required_banners_match_current_kernel_banners` — commit: `ef2c0ad`, `17f3d14`

---

## Low priority

### 20. A heal can leave a node stuck in HEALING
- **Where:** `tools/triad_controller.py:1289-1293` and `:1328-1330`. The heal waits on `morph_op_lock` and releases it, then calls `bounce_and_morph_node`, which takes the lock without blocking and returns False if it's busy (`:1191-1193`).
- **Effect:** If a wave or auto-morph grabs the lock in between, the node is never morphed and stays out of the pool, and nothing retries it.
- **Fix:** Morph under the lock already held, or retry until the morph succeeds. Test the heal with a concurrent wave.
- Status: Fixed — test: `tools/triad_controller.py::run_self_test` — commit: `beb3bfa`

### 21. The standalone console's "Unlock" button doesn't work
- **Where:** `tools/triad_console.html:2128` (`addEventListener('click', tryToken)`) with `:818` (`tryToken(inputSel = '#tokIn', …)`).
- **Problem:** The click event is passed as the selector, so the handler throws. Enter works.
- **Fix:** `addEventListener('click', () => tryToken())`.
- Status: Fixed — test: `tools/triad_controller.py::run_self_test` — commit: `beb3bfa`

### 22. Request handling in the Python servers
- **Where:** `tools/cuttle_fleet.py:375,476-480,636-637` and `tools/triad_controller.py:1777-1789,1902-1903`.
- **Problem:**
  - A non-ASCII token header makes `hmac.compare_digest` raise, so the client gets a dropped connection instead of a 401.
  - Bodies are read before authentication, with no size cap.
  - A negative or non-numeric `Content-Length` reads to EOF or sends no response.
- **Fix:** Compare bytes, or reject non-ASCII with 401. Authenticate first. Cap `Content-Length` and answer 400 or 413.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests`, `tools/triad_controller.py::run_self_test`, `tools/cuttle_fleet.py::run_self_test` — commit: `beb3bfa`

### 23. Secret files are silently truncated or replaced
- **Where:** `tools/cuttle_fleet.py:146-154` and `tools/triad_controller.py:341-346`.
- **Problem:** A longer file is cut to size without notice. A short or corrupt file is silently replaced with a new random key.
- **Effect:** Replacing a master key changes every derived node key, so that client's sealed data becomes unreadable.
- **Fix:** Refuse to start on a malformed secret file, and alarm.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests`, `tools/cuttle_fleet.py::run_fleet_unit_tests` — commit: `beb3bfa`

### 24. TLS known-answer coverage is narrower than documented
- **Where:** `tls_provider.rs:15-17` and `README.md:106`.
- **Problem:**
  - The P-256 ECDH check (`tls_provider.rs:852-871`) only tests that two fixed keys agree; it isn't a published vector.
  - The provider's own SHA-256, HMAC and HKDF objects have no direct vectors. The RFC 4231, 5869 and 8448 tests exercise `tls.rs`, which calls the `hkdf` crate directly.
  - AES-GCM uses only test cases 1 and 2, with no AAD and no partial block.
- **Fix:**
  - Add the RFC 5903 §8.1 P-256 vector.
  - Run the RFC 4231 and 5869 vectors through the provider's HMAC and HKDF objects.
  - Add GCM test case 4.
  - Correct the docs.
- Status: Fixed — test: `provider_known_answer_self_test` — commit: `17f3d14`, `37f9d23`

### 25. Host tests don't run the crypto backends the kernel ships
- **Where:** The cfgs exist only in the kernel's config. `tls_kat` and `https_interop` run on the host's AES-NI, CLMUL and AVX2 backends.
- **Fix:** Add a CI step that runs both test files with the five force-soft cfgs in `RUSTFLAGS`.
- Status: Fixed — test: `soft_float_crypto_backends_pass_kats_and_golden_replay` — commit: `17f3d14`

### 26. Crypto hardening gaps
- **Where and problem:**
  - **Zeroization:** `aes-gcm` is enabled without its zeroize features (`target_enterprise/Cargo.toml:31`). `seed_system_rng` (`tls_provider.rs:124-137`) and the TLS identity secret (`provisioning.rs:261-267`, `net_service.rs:514`) aren't cleared after use.
  - **ECDSA:** signatures from `EcdsaP256Signer::sign` (`tls_provider.rs:606-613`) and the certificate self-signature (`https.rs:184`) aren't verified before release. The RFC 6979 nonces are deterministic and every morph variant signs the same certificate data, so one faulty signature from a mis-morphed build would leak the key.
  - **Deterministic test provider:** `golden_provider`, `reset_golden_rng` and `golden_server` (`tls_provider.rs:141,702`; `https.rs:683-708`) are public in every build.
  - **RNG state:** `KernelRng::reseed` and `SYSTEM_RNG` are public (`tls_provider.rs:84-86,113`). The generator is never reseeded and has no fast key erasure.
  - **DER lengths:** the certificate encoder writes a wrong DER length above 0xFFFF (`https.rs:113`). That is unreachable today.
- **Fix:**
  - Enable the zeroize features, and wrap the secrets in `Zeroizing`.
  - Verify each signature before releasing it, or use hedged signing.
  - Gate the golden pieces behind `cfg(any(test, not(cuttle_prod)))`.
  - Make `reseed` crate-private, rekey after each fill, and reseed periodically.
  - Use the `der` crate, which is already in the lockfile, or reject oversize input.
- Status: Fixed — test: `tls_provider::tests::kernel_rng_rekeys_after_every_fill`, `https::tests::der_panics_on_content_over_65535_bytes`, `provider_known_answer_self_test` — commit: `17f3d14`

### 27. The kernel doesn't check the device key's length from fw_cfg (pre-existing; the TLS identity now depends on it)
- **Where:** `provisioning.rs:27-28` says short entries return `None`, but `fw_cfg_select` (`main.rs:1080-1100`) discards the entry size, and the reader always takes 32 bytes.
- **Effect:** A short key file is accepted as provisioned.
- **Fix:** Return the size from `fw_cfg_select`, require exactly 32 bytes, and test the parse.
- Status: Fixed — test: `tls_provider::tests::validate_fw_cfg_device_key_rejects_wrong_size_and_zero_keys` — commit: `17f3d14`

### 28. HTTP request handling differs between ports, and HTTPS framing has gaps
- **Where:**
  - Port 80 silently truncates requests longer than 1 KiB (`lived_net.rs:1006-1010`, `n = inbound_payload.len().min(room)`; pre-existing). Port 443 accepts up to 16 KiB.
  - A POST without `Content-Length` is treated as complete with whatever bytes have arrived (`lived_net.rs:2140`).
  - An oversize request ends the TLS session without an HTTP 413.
  - "Every HTTP route answers identically on :80 and :443" (`README.md:105`) is tested on `/healthz` only (`https_interop.rs:143-154`).
- **Fix:** Reject oversize requests on both ports with 413. Require `Content-Length` on bodies. Run the identity test across the public routes, or soften the wording.
- Status: Fixed — test: `http_and_https_reject_oversized_and_unframed_requests_and_match_across_routes` — commit: `17f3d14`, `37f9d23`, `a38eb08`

### 29. The binmorphed boot in `qemu_smoke` asserts only 6 banners
- **Where:** `factory_builder/tests/qemu_smoke.rs:994-1010`, which discards the `done` result and doesn't assert HALT.
- **Problem:** The `04677dd` claim of "129/129 banners … including the 7-pass binmorphed kernel" overstates this. The 129 applies to the unmorphed boot only.
- **Fix:** Assert the full banner list and HALT for the morphed boot, or correct the claim.
- Status: Fixed — test: `boots_under_qemu_and_emits_banner` — commit: `17f3d14`

### 30. Accelerator docs and fallback
- **Where:** `README.md:176-178`, `run.bat:41-48`, `tools/triad_controller.py:557,661`.
- **Problem:**
  - "Every launcher takes an accelerator" is untrue: four launchers still hard-code TCG.
  - `run.bat auto` has no stuck-BIOS fallback, so on the hosts the README describes it can now hang where it used to boot.
  - The accelerator reported per node is the one requested, not the one QEMU actually used.
  - The "no guest output" check counts any line without `qemu-system` as guest output, and the self-test stubs it out.
- **Fix:**
  - Scope the README sentence.
  - Default `run.bat` to `tcg`, or add the fallback.
  - Report the accelerator QEMU actually uses.
  - Match a guest-specific marker in the output check, and unit-test it against captured output.
- Status: Fixed — test: `tools/triad_controller.py::run_unit_self_tests` — commit: `beb3bfa`, `37f9d23`

### 31. Licensing notices
- **Where:** `tools/third_party_notices.py:128-142`, `:147-187`, `:60-70`, `:223,236`; `README.md:212,217`; `NOTICE:6-7`.
- **Problem:**
  - The notices omit the bootloader stage crates themselves and never policy-check them. All five are MIT OR Apache-2.0 today.
  - `spdx_allowed` accepts malformed or lowercase expressions such as `"MIT and GPL-3.0"`.
  - README and NOTICE call `ucs2` the only non-permissive component, but every BIOS image also embeds the OFL-1.1 Noto font.
  - The `ucs2` note says MPL-2.0 places "no obligation", then lists one (§3.2).
  - `--check` depends on the caller's default toolchain and the unpinned nightly.
- **Fix:**
  - Add each stage's root package to the notices and the policy check.
  - Fail if any tokens are left over after parsing.
  - Qualify NOTICE ("except as noted in THIRD_PARTY_NOTICES.md") and mention the font in the README.
  - Reword the MPL note.
  - Run `rustc` from the kernel crate and leave the nightly version out of the compared text.
- Status: Fixed — test: `tools/third_party_notices.py::run_self_test` — commit: `37f9d23`

### 32. Smaller tooling items
- `sibling_search_dirs` (`morph_engine/src/cycle.rs:569`) accepts any exe whose fourth ancestor directory is named `build`, so it can widen the search on non-cargo layouts. Match the full `<profile>/build/<pkg>/<hash>/<out|deps>` shape, and add a negative test.
- `--self-test` deletes the real Triad state in `target/cuttle_images/triad` (`tools/triad_controller.py:2049-2061`). Use a temp `state_dir`.
- The farm secret leaks into QEMU and binmorph children through the environment (`tools/cuttle_fleet.py:494`). Remove it from the environment after reading it.
- `/api/morph/<nid>` and `/api/tamper/<nid>` (`tools/triad_controller.py:1979-1991`) don't range-check the id: `0` morphs OS-3. This is now reachable with client tokens through the proxy. Validate 1-3 and return 400.
- The provider answers 404 for an unknown client before checking scope (`tools/cuttle_fleet.py:651-655`), so a client token can find out which client ids exist.
- The WAL grows without bound under the default `synthetic_load = true` (`tools/fleet.toml:15`), and a heal replays the whole WAL while holding `wal_lock`. Add checkpointing, and default synthetic load off or move it to an unvoted table.
- The "refused" checks in `tools/https_check.py` (`:176-179`) pass on a timeout. Assert a handshake alert instead.
- Status: Fixed — test: `cycle::tests::sibling_search_dirs_rejects_non_cargo_build_ancestor`, `tools/triad_controller.py::run_unit_self_tests`, `tools/triad_controller.py::run_self_test`, `tools/cuttle_fleet.py::run_self_test`, `tools/https_check.py::run_self_test` — commit: `ef2c0ad`, `beb3bfa`

---

## Process notes
- The round-4 status line named its test and commit, and the claim matched the code.
- The commits from `5e504e8` onward carry `Co-Authored-By: Claude Opus 5.5`. `GEMINI.md` assigns building to Gemini and says "Neither of you grades your own work." If a Claude session built these, this review is less independent than the process intends. Confirm who the builder is.
- Most of this round wasn't review-driven, and several commits are very large: `04677dd` replaces TLS, removes contracts (schema 59), adds a heap and locks new modules in one commit, and `2c2dd0a` adds 3,350 lines. `GEMINI.md` asks for small, focused commits; smaller commits would make regressions like #2, #3 and #4 easier to catch.
- `c47de8f`, `2c2dd0a` and `9e34b6b` skipped the cargo checks with "No Rust changes". That is reasonable, but the GEMINI.md rule says to run all checks before every commit.

## Not reviewed this round
- The kernel release build and `qemu_smoke`. These must be run on a machine with nightly before this round is accepted.
- The Python self-tests (`triad_controller.py --self-test`, `cuttle_fleet.py --self-test`), WHPX behaviour, and any live VM. Everything above is from reading the code, apart from the workspace test run and a headless browser check of #21.
- rustls internals beyond the unbuffered API's use in `https.rs`; the `x509.rs` parser.
- `cargo deny` and `tools/license_check.ps1` weren't run, and the freshness of `THIRD_PARTY_NOTICES.md` wasn't checked.
- Interrupt-time allocation and SMP use of the heap lock (`heap.rs:5-7`).
- Carried over: the SQL owner-selection logic in `exec_as` in detail, the per-request `CPL=3` service hook in detail, CuttleGuard and CuttleChronos beyond earlier paths, the UDP `:8081` triad protocol, and `binmorph`.
