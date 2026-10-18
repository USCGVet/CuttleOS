# Claude Recommendations

Review of commits `70d44fc` (round-3 fixes), `44e7c3b` (status lines) and `a623b5a` (adds `CLAUDE.md`, `GEMINI.md` and `docs/sql-engine-plan.md`). Line numbers are from `a623b5a`.

**Test status at review time**
- `cargo test --workspace --no-fail-fast`: 2,423 passed, 0 failed.
- `cargo test -p factory_builder --test qemu_smoke -- --ignored`: 2 passed (27 s).
- `target_enterprise_kernel` release build: OK.
- `tools/triad_controller.py`: parses. Unchanged this round, so the live `--self-test` wasn't re-run; it passed last round.

## Verification of last round's items

| # | Item | Verdict | Notes |
|---|---|---|---|
| 1 | Legacy seal check accepted the public default key | **Verified fixed** | The default keys are now `#[cfg(test)]`-only, and the legacy verify paths accept only device-derived keys. The regression test asserts that an image sealed with the public key is refused. |
| 2 | Default keys in non-test builds | **Partly fixed** | Keys start unset (all zeros), and WAL, file-system and SQL seal/verify refuse an unset key. Remaining: see #1 below. |

Also checked: `CLAUDE.md` and `GEMINI.md` were committed unchanged.

---

## Low priority

### 1. Session tokens and attestation quotes are created even if the attest key is unset
- **Where:** `target_enterprise/src/shell.rs:651` (`create_session`), `:4385` (`compute_attestation_mac`) and `:4414` (`cmd_attest`)
- **Problem:** these three paths use `attest_key` without checking `is_seal_key_set`. The verify path at `:4397` does check.
- **Effect:** if any future kernel path reaches them before `attest_key` is set, they would mint session tokens and sign quotes with an all-zero key, so tokens would be predictable and quotes forgeable. Today's known kernel paths set the key first, so this is a hardening gap, not a live bug.
- **Fix:** refuse to create a session or produce a quote while `attest_key` is unset, returning an error and an audit entry, the same as the seal paths. Add a regression test alongside `regression_round3_item2_unset_shell_keys_refuse_seal_and_verify`.
- `Status: Fixed — test: shell::tests::regression_round4_item1_unset_attest_key_refuses_session_and_quote — commit: 79b8161`

---

## Process notes
- Every status line this round named a dedicated test and commit, and the claims matched the code.
- The SQL engine plan (`docs/sql-engine-plan.md`) is committed. Next step per the plan: M0, the crate skeleton and test harnesses.

## Not reviewed this round
- The SQL owner-selection logic in `exec_as`, in detail
- The per-request `CPL=3` service hook, in detail
- CuttleGuard and CuttleChronos beyond earlier paths
- The UDP `:8081` triad protocol
- `binmorph`
