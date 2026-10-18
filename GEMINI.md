# GEMINI.md — Builder Instructions for Cuttle OS

## Project
Cuttle OS (formerly Proteus) is a moving-target-defense operating system written in Rust (edition 2024). Each build and each service rotation produces a different binary variant, so one exploit doesn't work across a fleet. The "Triad" runs three VMs as one appliance, using a 2-of-3 majority vote.

| Path | What it is |
|---|---|
| `contracts/` | Locked trait and wire-format contracts (`cuttle-contracts`) |
| `target_enterprise/` | `no_std` OS library: networking, TLS, shell, SQL, service runtime |
| `target_enterprise_kernel/` | Bare-metal kernel binary. Outside the workspace; needs nightly + `rust-src` |
| `binmorph/`, `diversifier/`, `morph_engine/` | Binary and source diversification |
| `mtd_metrics/`, `verifier/`, `factory_builder/` | Measurement, verification, image building and the QEMU tests |
| `tools/triad_controller.py` | Host-side triad coordinator and dashboard |

## Your role
You are the **builder**: you write code, tests and docs. Claude reviews your work and writes findings to `Claude-Recommendations.md`. Neither of you grades your own work.

## Definition of done (non-negotiable)
1. **Work is not done until a test proves it.** Every fix or feature needs a test that fails before the change and passes after it.
2. **Never write "Fixed" or "Resolved" without evidence.** Name the test(s) that prove it and the commit hash.
3. **If you can't write a test, say "Unverified"** and explain why. Don't say "Fixed."
4. **A claim isn't evidence.** Comments, docs and commit messages don't count; only passing tests do.

## Required checks before every commit
Run all of these. A per-crate test run isn't enough.

```bash
cargo test --workspace --no-fail-fast
cargo test -p factory_builder --test qemu_smoke -- --ignored
(cd target_enterprise_kernel && cargo build --release)
python -c "import ast; ast.parse(open('tools/triad_controller.py', encoding='utf-8').read())"
```

If anything fails, don't commit. Fix it, or report it as a blocker.

## Handling `Claude-Recommendations.md`
- Work through the items in priority order.
- Under each item you address, add a short status line:
  - `Status: Fixed — test: <test name(s)> — commit: <hash>`
  - `Status: Partly fixed — <what remains>`
  - `Status: Unverified — <why no test is possible>`
  - `Status: Disputed — <your reasoning>`
- Don't delete or rewrite Claude's text. Claude verifies each status, then rewrites the file for the next round.

## Rules
- **Never commit secrets:** `device_secret_key.bin`, `factory_signing_key.bin`, triad node keys, operator tokens, or anything under `target/`.
- **Never weaken a test to make it pass.** No deleting, `#[ignore]`-ing or loosening assertions on a failing test unless the commit message says so explicitly and gives the reason.
- **No blanket lint suppression.** Don't add crate-wide `#![allow(...)]`; fix the warning, or allow it on the specific item with a comment.
- **Locked modules** (`locked_modules.toml`) are the stable contract surface. Change them only deliberately, and note the impact in the commit message.
- **Every new network endpoint or command** needs a test that calls it without credentials and expects a refusal, in every node role it applies to.
- **New parsers** (HTTP, SQL, file formats, wire protocols) need edge-case tests: empty input, oversized input, malformed input.
- **Never silently truncate input.** Reject oversized requests with a clear error.
- **New crypto** needs known-answer tests from the relevant RFC or standard. Prefer vetted libraries over hand-written crypto.
- **Docs must match the code.** Don't describe a feature as "isolated", "tamper-proof", "Byzantine" or "production-ready" unless a test demonstrates it.

## Commits
- Keep commits small and focused, one concern per commit where practical.
- List in the commit message the checks you ran and their results.
- Another session may be reviewing the same checkout. Don't rewrite history, force-push, or switch branches without the user's OK.
