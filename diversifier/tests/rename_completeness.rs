//! Rename-completeness regression corpus (TASK-016).
//!
//! # Bug history
//!
//! TASK-015's real-mode runs surfaced a reproducible diversifier failure:
//! the local-variable rename pass renamed `let` bindings but missed
//! references that lived inside macro invocations. Canonical reproducer:
//! `target_enterprise/src/tls.rs::hkdf_expand_label` has
//! `let total_label_len = ...; assert!(total_label_len <= 255, ...);`.
//! After rename, the `let` site became `let total_label_len_v..._0 = ...;`
//! but the `assert!(total_label_len <= 255)` reference inside the macro
//! token stream was untouched, producing `error[E0425]: cannot find
//! value 'total_label_len' in this scope`. Every real-mode diversity
//! demo cycle against `tls.rs` was rejected by `build_kernel`.
//!
//! # The fix this test enforces
//!
//! Macro grammar is opaque to the rename visitor — `Expr::Macro` and
//! `Stmt::Macro` are skipped by the per-function transform. The
//! TASK-016 fix is conservative: pre-collect every identifier that
//! occurs inside any macro body in the function (including names
//! captured by `format_args`-style literal interpolation, e.g.
//! `format!("{x}")`), and refuse to rename any local binding whose
//! original name is in that set. Refusing a rename is a missed
//! diversification opportunity, not a correctness bug.
//!
//! # What this corpus exercises
//!
//! Each fixture targets a syntactic shape historically associated with
//! rename-completeness bugs in source-level mutators:
//!
//! 1. `macro_capture` — the canonical bug. `let` bindings referenced
//!    inside `assert!` and `format!` (both `{name}` capture form and
//!    `{}` positional form with the local as a separate argument).
//! 2. `nested_closures` — closures inside closures, each introducing
//!    new bindings, referencing both their own params and outer
//!    captures.
//! 3. `if_let` — pattern bindings in `if let Some(x) = ...` scoped to
//!    the then-branch only, used alongside outer `let` bindings.
//! 4. `shadowing` — successive `let x = x + 1` rebinds, including a
//!    block-introduced shadow that references the outer name on the
//!    RHS.
//! 5. `method_call_chain` — iterator chains with closure args, where
//!    the closure body references a let-bound outer name.
//! 6. `struct_update` — `S { a: foo, ..base }` form where `base` is a
//!    let binding read on the RHS.
//! 7. `macro_args_mixed` — `println!("...{x}... {}", y)` with the
//!    capture name AND the positional-arg ident both being let
//!    bindings of the same function. Both must be left alone (or
//!    renamed consistently — the conservative fix opts for "left
//!    alone").
//!
//! For each fixture and each of 8 seeds derived via `Seed::derive`,
//! the test:
//!
//!  - Runs the diversifier.
//!  - Parses the output with `syn::parse_file` (catches syntactic
//!    regressions like an unbalanced brace).
//!  - Hands the output to `rustc --emit=metadata --crate-type=lib
//!    --edition=2024` for a semantic compile check. Failure here is
//!    the rename-completeness bug regressing.
//!
//! 7 fixtures × 8 seeds = 56 round-trips. Comfortably above the
//! task's `≥ 40` floor.

use proteus_diversifier::{diversify, Seed};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// A monotonic per-process counter, used to give each rustc
/// invocation a unique scratch filename. Avoids races when cargo
/// runs multiple tests in parallel from this binary.
static SCRATCH_COUNTER: AtomicU32 = AtomicU32::new(0);

fn scratch_dir() -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proteus_rename_completeness_{}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&p);
    p
}

/// Compile-check a Rust source string by invoking `rustc` with
/// `--emit=metadata`. Returns `Ok(())` on a clean compile, or an
/// `Err` containing rustc's stderr.
fn rustc_check(label: &str, source: &str) -> Result<(), String> {
    let n = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = scratch_dir();
    let src_path = dir.join(format!("{}_{}.rs", label, n));
    std::fs::write(&src_path, source)
        .map_err(|e| format!("write {}: {}", src_path.display(), e))?;

    let out_path = dir.join(format!("{}_{}.rmeta", label, n));

    let output = Command::new("rustc")
        .arg("--edition=2024")
        .arg("--crate-type=lib")
        .arg("--emit=metadata")
        // Suppress warnings so a fixture's `unused` doesn't cause
        // failures and so rustc's stderr is empty on success.
        .arg("-A")
        .arg("warnings")
        .arg("-o")
        .arg(&out_path)
        .arg(&src_path)
        .output()
        .map_err(|e| format!("rustc invoke failed: {}", e))?;

    // Keep the scratch file on failure for debugging, remove on success.
    if output.status.success() {
        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&out_path);
        Ok(())
    } else {
        Err(format!(
            "rustc exit {}:\n--- stderr ---\n{}\n--- source ({}) ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
            src_path.display(),
            source
        ))
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The canonical bug. `let total_label_len` is referenced inside an
/// `assert!` macro body — the historical rename pass missed it. The
/// `format!` variants exercise both `{name}` capture form and `{}, name`
/// positional form, both of which appear in real `target_enterprise`
/// modules (e.g. `panic_dump`, eventual `kpti`).
const FIXTURE_MACRO_CAPTURE: &str = r#"
pub fn assert_label_len(label: &[u8]) -> usize {
    const PREFIX: &[u8] = b"tls13 ";
    let total_label_len = PREFIX.len() + label.len();
    assert!(total_label_len <= 255, "hkdf_expand_label: label too long");
    let mut buf = [0u8; 16];
    buf[0] = total_label_len as u8;
    total_label_len
}

pub fn fmt_captured(name: u32) -> String {
    let count = name + 1;
    format!("count={count}")
}

pub fn fmt_positional(name: u32) -> String {
    let value = name * 2;
    format!("value={}", value)
}

pub fn debug_arg(name: u32) -> String {
    let things = (name, name + 1);
    format!("things={things:?}")
}
"#;

/// Closures inside closures, each introducing fresh bindings, each
/// referencing outer captures. The classic worst-case for any rename
/// pass that doesn't track lexical scope precisely.
const FIXTURE_NESTED_CLOSURES: &str = r#"
pub fn run(seed: u32) -> u32 {
    let outer = seed;
    let f = |x: u32| -> u32 {
        let inner = x + outer;
        let g = |y: u32| -> u32 {
            let inner2 = y + inner;
            inner2 + outer
        };
        g(2) + inner
    };
    f(3) + outer
}

pub fn capture_mut_in_closure(seed: u32) -> u32 {
    let mut count = 0u32;
    let mut bump = || {
        count += seed;
    };
    bump();
    bump();
    count
}
"#;

/// `if let` bindings are scoped to the then-branch only. Outer `let`
/// bindings of the same name must not have their then-branch
/// references rewritten to the outer rename. Also covers `while let`.
const FIXTURE_IF_LET: &str = r#"
pub fn run(v: Option<u32>) -> u32 {
    let base = 10u32;
    if let Some(x) = v {
        let total = base + x;
        total
    } else {
        base
    }
}

pub fn shadow_in_if_let(v: Option<u32>) -> u32 {
    let x = 5u32;
    let result = if let Some(x) = v {
        x + 1
    } else {
        x
    };
    result + x
}

pub fn while_let_drain(items: &mut Vec<u32>) -> u32 {
    let initial = 0u32;
    let mut acc = initial;
    while let Some(top) = items.pop() {
        acc += top;
    }
    acc + initial
}
"#;

/// Successive `let`-rebinds that read the previous binding on the RHS.
/// Each `let x = x + 1` must rewrite the RHS against the *previous*
/// binding then introduce a *new* fresh binding for subsequent reads.
const FIXTURE_SHADOWING: &str = r#"
pub fn run() -> u32 {
    let x = 1u32;
    let x = x + 1;
    let x = x * 2;
    let x = {
        let y = x * 3;
        y + 1
    };
    x
}

pub fn shadow_across_blocks(input: u32) -> u32 {
    let result = input;
    let result = {
        let result = result + 10;
        result * 2
    };
    let result = result.wrapping_add(1);
    result
}
"#;

/// Iterator method-call chains with closures. The closure's parameter
/// is a fresh binding; references in the closure body to outer
/// let-bindings must continue to resolve through the scope chain.
const FIXTURE_METHOD_CALL_CHAIN: &str = r#"
pub fn run(data: &[u8]) -> u32 {
    let scale = 3u32;
    let total: u32 = data.iter().copied().map(|b| (b as u32) * scale).sum();
    let trimmed = data.iter().filter(|b| **b > 0).count();
    total + (trimmed as u32)
}

pub fn fold_with_outer(data: &[u32]) -> u32 {
    let seed = 7u32;
    data.iter().fold(seed, |acc, x| acc + *x + seed)
}
"#;

/// Struct-update syntax: `S { field: expr, ..base }`. The `base`
/// position is an expression that may be a path referring to a `let`
/// binding. The rename pass must rewrite that path.
///
/// ALSO covers struct-field SHORTHAND emission: `S { foo }` is sugar
/// for `S { foo: foo }` (syn's `FieldValue { colon_token: None,
/// member: foo, expr: Expr::Path(foo) }`). `quote!`'s `ToTokens`
/// impl emits only the member when `colon_token` is `None`, silently
/// dropping any rename applied to the inner expression. TASK-016
/// real-mode runs hit this with
/// `Ok(ClientHelloView { session_id, x25519_pub })` in
/// `parse_client_hello` after `session_id` / `x25519_pub` locals
/// were renamed. Fix: normalise shorthand to explicit form in
/// `transform_expr`'s `Expr::Struct` arm before walking.
const FIXTURE_STRUCT_UPDATE: &str = r#"
pub struct Conf {
    pub a: u32,
    pub b: u32,
    pub c: u32,
}

pub fn run(input: Conf) -> Conf {
    let base = input;
    let updated_a = base.a + 1;
    Conf {
        a: updated_a,
        ..base
    }
}

pub fn chain_update(seed: u32) -> Conf {
    let base = Conf { a: seed, b: seed + 1, c: seed + 2 };
    let next = Conf { b: base.b * 10, ..base };
    next
}

pub struct View<'a> {
    pub session_id: &'a [u8],
    pub x25519_pub: Option<[u8; 32]>,
}

pub fn shorthand_struct_expr<'a>(buf: &'a [u8]) -> View<'a> {
    let session_id = &buf[..buf.len().min(8)];
    let x25519_pub: Option<[u8; 32]> = None;
    // Canonical shorthand site — both field names match local bindings.
    View { session_id, x25519_pub }
}

pub fn shorthand_pat_let(c: Conf) -> u32 {
    // `let S { a } = expr;` shorthand binding form. Reads of `a` in
    // the body must continue to resolve to the same binding the
    // pattern introduced after rename.
    let Conf { a, b, c: _ } = c;
    a + b
}
"#;

/// Mixed macro arguments: `println!("{x}... {}", y)` — `x` is an
/// implicit capture (inside the literal), `y` is a positional argument
/// (a real `Ident` token). Both are local `let` bindings; both must
/// remain consistent after diversification.
const FIXTURE_MACRO_ARGS_MIXED: &str = r#"
pub fn run(seed: u32) -> String {
    let captured = seed + 1;
    let positional = seed * 2;
    let line = format!("captured={captured} positional={}", positional);
    line
}

pub fn write_record(seed: u32) {
    let nonce = seed.wrapping_mul(0x9e3779b9);
    let len = nonce.count_ones();
    // dbg! captures by reference. The local `nonce` token literally
    // appears in dbg!'s expansion tokens; if the rename pass missed
    // it, this would fail to compile.
    let _ = (nonce, len);
    eprintln!("nonce={nonce:#x} len={len}");
}
"#;

const FIXTURES: &[(&str, &str)] = &[
    ("macro_capture", FIXTURE_MACRO_CAPTURE),
    ("nested_closures", FIXTURE_NESTED_CLOSURES),
    ("if_let", FIXTURE_IF_LET),
    ("shadowing", FIXTURE_SHADOWING),
    ("method_call_chain", FIXTURE_METHOD_CALL_CHAIN),
    ("struct_update", FIXTURE_STRUCT_UPDATE),
    ("macro_args_mixed", FIXTURE_MACRO_ARGS_MIXED),
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn corpus_originals_all_compile() {
    // Sanity: every fixture must compile *before* diversification.
    // If this fails the fixture is broken, not the diversifier.
    for (name, src) in FIXTURES {
        syn::parse_file(src)
            .unwrap_or_else(|e| panic!("fixture '{}' fails to parse: {}", name, e));
        if let Err(e) = rustc_check(&format!("orig_{}", name), src) {
            panic!(
                "fixture '{}' original source does not compile:\n{}",
                name, e
            );
        }
    }
}

#[test]
fn corpus_all_seeds_compile() {
    // The load-bearing assertion: for every fixture, every seed in
    // 0..8, the diversified output parses AND compiles. A regression
    // of the TASK-016 rename-completeness bug fails this test on the
    // 'macro_capture' fixture immediately.
    let mut total = 0u32;
    let mut failures: Vec<String> = Vec::new();

    for (name, src) in FIXTURES {
        for cycle in 0..8u64 {
            let seed = Seed::derive(cycle, name);
            let out = match diversify(src, &seed) {
                Ok(s) => s,
                Err(e) => {
                    failures.push(format!(
                        "{}/cycle{}: diversifier returned Err: {}",
                        name, cycle, e
                    ));
                    continue;
                }
            };
            if let Err(e) = syn::parse_file(&out) {
                failures.push(format!(
                    "{}/cycle{}: syn::parse_file rejected diversified output: {}\n---\n{}",
                    name, cycle, e, out
                ));
                continue;
            }
            if let Err(e) = rustc_check(&format!("{}_{}", name, cycle), &out) {
                failures.push(format!(
                    "{}/cycle{}: rustc rejected diversified output:\n{}",
                    name, cycle, e
                ));
                continue;
            }
            total += 1;
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} round-trips passed, {} failed.\n\n{}",
            total,
            failures.len(),
            failures.join("\n\n")
        );
    }

    // 7 fixtures * 8 seeds = 56. The task floor is 40.
    assert!(
        total >= 40,
        "expected ≥ 40 round-trips per task acceptance, got {}",
        total
    );
}

/// A targeted regression: explicitly assert that the canonical bug
/// reproducer — a `let` binding referenced inside an `assert!` macro
/// — survives a diversification cycle. This isolates the failure
/// signal from the broader corpus test above so the cause is obvious
/// if it ever regresses.
#[test]
fn assert_macro_reference_survives_diversification() {
    let src = r#"
pub fn hkdf_label(label: &[u8]) -> usize {
    let total_label_len = 6 + label.len();
    assert!(total_label_len <= 255, "label too long");
    total_label_len
}
"#;
    for cycle in 0..8u64 {
        let seed = Seed::derive(cycle, "hkdf_label_regression");
        let out = diversify(src, &seed)
            .unwrap_or_else(|e| panic!("cycle {}: diversify err: {}", cycle, e));
        rustc_check(&format!("hkdf_label_regression_{}", cycle), &out)
            .unwrap_or_else(|e| panic!("cycle {}: rustc rejected:\n{}", cycle, e));
    }
}

/// Format-args implicit captures (`{name}`) must also pin the binding
/// against renaming. Regression test focused on this distinct path
/// through the fix (string-literal scanner inside the macro-ident
/// pre-pass).
#[test]
fn format_args_capture_survives_diversification() {
    let src = r#"
pub fn render(seed: u32) -> String {
    let counter = seed + 1;
    let summary = format!("counter={counter}");
    summary
}
"#;
    for cycle in 0..8u64 {
        let seed = Seed::derive(cycle, "format_args_capture");
        let out = diversify(src, &seed)
            .unwrap_or_else(|e| panic!("cycle {}: diversify err: {}", cycle, e));
        rustc_check(&format!("fmt_capture_{}", cycle), &out)
            .unwrap_or_else(|e| panic!("cycle {}: rustc rejected:\n{}", cycle, e));
    }
}
