//! Optional per-function stack-frame padding pass.
//!
//! When enabled via [`crate::DiversifyOptions::with_stack_pad`], injects a
//! `core::hint::black_box([0u8; N])` stack allocation (`N ∈ [32, 224)`) at the
//! start of eligible functions (`Item::Fn` and `ImplItem::Fn`), derived
//! deterministically from `SHA-256(HASH_TAG, seed, ":", fn_name)`.
//!
//! Skips `unsafe fn`, `const fn`, `main`, and ABI-pinned functions
//! (`#[no_mangle]`, `#[export_name]`, `#[naked]`). Disabled by default in
//! [`crate::DiversifyOptions`] because compiler layout randomization and
//! linker section shuffling already randomize function offsets without adding
//! stack-pad instructions.

use sha2::{Digest, Sha256};
use syn::{Attribute, Block, Expr, File, ImplItem, Item, ItemImpl, Signature, Stmt};

use crate::Seed;

/// Domain-separation tag. Bump the version suffix if the decision
/// logic or the pad-format changes — attestations from before/after
/// the change are then unambiguously distinguishable.
const HASH_TAG: &[u8] = b"cuttle-stack-pad-v1";

/// Minimum pad size in bytes. Below ~32 the prologue's `sub rsp, N`
/// encoding tends to fold into existing 16-byte stack alignment and
/// fails to change function size.
const MIN_PAD_BYTES: usize = 32;

/// Width of the pad-size range. Total = `MIN_PAD_BYTES + PAD_RANGE_BYTES`
/// = 224 byte upper bound (exclusive).
const PAD_RANGE_BYTES: usize = 192;

/// One pad decision. Used by tests to assert determinism without
/// rebuilding the AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PadDecision {
    /// `fn_name` for free fns; `"Type::method"` for impl-block methods.
    pub fn_name: String,
    /// Pad size in bytes. Always in `[MIN_PAD_BYTES, MIN_PAD_BYTES + PAD_RANGE_BYTES)`.
    pub bytes: usize,
}

/// Apply stack-frame padding to every morphable function in `file`.
/// Returns the per-function decisions for logging / audit.
pub fn apply(file: &mut File, seed: &Seed) -> Vec<PadDecision> {
    let mut log = Vec::new();
    for item in file.items.iter_mut() {
        match item {
            Item::Fn(f) => {
                // Strip-then-inject: morph output must be bounded across
                // cycles (see strip_old_pads docs / 2026-07-29 soak
                // finding). Strip unconditionally — even fns that are
                // signature-skipped for injection may carry old pads.
                strip_old_pads(&mut f.block);
                if should_skip_signature(&f.sig, &f.attrs) {
                    continue;
                }
                let name = f.sig.ident.to_string();
                let bytes = decide_pad_bytes(seed, &name);
                inject_pad(&mut f.block, &name, bytes);
                log.push(PadDecision {
                    fn_name: name,
                    bytes,
                });
            }
            Item::Impl(im) => {
                let parent = item_impl_self_name(im);
                for ii in im.items.iter_mut() {
                    if let ImplItem::Fn(m) = ii {
                        strip_old_pads(&mut m.block);
                        if should_skip_signature(&m.sig, &m.attrs) {
                            continue;
                        }
                        let name = format!("{}::{}", parent, m.sig.ident);
                        let bytes = decide_pad_bytes(seed, &name);
                        inject_pad(&mut m.block, &name, bytes);
                        log.push(PadDecision {
                            fn_name: name,
                            bytes,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    log
}

/// Per-function pad-size decision. Public for direct unit testing.
pub fn decide_pad_bytes(seed: &Seed, fn_name: &str) -> usize {
    let mut h = Sha256::new();
    h.update(HASH_TAG);
    h.update(seed.0);
    h.update(b":");
    h.update(fn_name.as_bytes());
    let digest = h.finalize();
    let idx = u16::from_le_bytes([digest[0], digest[1]]) as usize;
    MIN_PAD_BYTES + (idx % PAD_RANGE_BYTES)
}

/// True if this fn cannot safely receive a stack pad.
fn should_skip_signature(sig: &Signature, attrs: &[Attribute]) -> bool {
    if sig.unsafety.is_some() {
        return true;
    }
    if sig.constness.is_some() {
        return true;
    }
    if sig.ident == "main" {
        return true;
    }
    if sig.asyncness.is_some() {
        // Async fns desugar to state machines; injecting a stack pad
        // into the surface fn body actually goes into the state-machine
        // setup, which is rarely useful and may not change the
        // resumable-future's layout. Skip for now; revisit if/when a
        // donor module uses async heavily.
        return true;
    }
    for a in attrs {
        let p = a.path();
        if p.is_ident("no_mangle") || p.is_ident("export_name") || p.is_ident("naked") {
            return true;
        }
    }
    false
}

fn inject_pad(block: &mut Block, fn_name: &str, bytes: usize) {
    // Pad identifier is unique per function (hash-derived) so that two
    // separate pads (one per function) don't accidentally shadow each
    // other in any pathological inlining scenario. This is belt-and-
    // braces — Rust's local scoping already prevents the issue — but
    // costs nothing.
    let mut h = Sha256::new();
    h.update(b"cuttle-pad-ident-v1");
    h.update(fn_name.as_bytes());
    let digest = h.finalize();
    let mut suffix = String::with_capacity(8);
    for byte in &digest[..4] {
        suffix.push_str(&format!("{:02x}", byte));
    }
    let ident_str = format!("__cuttle_stack_pad_{}", suffix);
    let pad_ident = syn::Ident::new(&ident_str, proc_macro2::Span::call_site());
    // `core::hint::black_box` is stable (Rust 1.66+) and is the
    // canonical compiler-opaque barrier. It prevents the DCE pass from
    // eliminating the unused local, which is what we need: without
    // `black_box`, the local would be optimised away and the function
    // size would not change.
    let stmt: Stmt = syn::parse_quote! {
        let #pad_ident: [u8; #bytes] = ::core::hint::black_box([0u8; #bytes]);
    };
    block.stmts.insert(0, stmt);
}

/// Strip previously-injected Cuttle stack pads from a block.
///
/// Soak finding (2026-07-29, cycle ~244 of the 1000-cycle duration
/// soak): pads were never removed, so every morph cycle added a fresh
/// pad on top of the old ones — sources grew ~27x in 243 cycles
/// (dns.rs 22KB -> 609KB, tls.rs 71KB -> 1.9MB) until syn's recursive
/// visitors in the *verifier* overflowed the default 8MB stack and
/// every cycle began rejecting. Morph output must be bounded: each
/// cycle strips the prior generation's pads before injecting its own.
fn strip_old_pads(block: &mut Block) {
    block.stmts.retain(|stmt| {
        // Match: `let __cuttle_stack_pad_<hex> ... = ...;`
        if let Stmt::Local(local) = stmt {
            if let syn::Pat::Type(pt) = &local.pat {
                if let syn::Pat::Ident(pi) = &*pt.pat {
                    if pi.ident.to_string().starts_with("__cuttle_stack_pad_") {
                        return false;
                    }
                }
            }
        }
        true
    });
    // Recurse into nested blocks (if/while/for/loop bodies) so pads
    // injected at any depth are stripped at that depth.
    for stmt in &mut block.stmts {
        strip_from_stmt(stmt);
    }
}

fn strip_from_stmt(stmt: &mut Stmt) {
    match stmt {
        Stmt::Expr(e, _) => strip_from_expr(e),
        Stmt::Item(item) => {
            if let syn::Item::Fn(f) = item {
                strip_old_pads(&mut f.block);
            }
        }
        _ => {}
    }
}

fn strip_from_expr(expr: &mut Expr) {
    match expr {
        Expr::Block(b) => strip_old_pads(&mut b.block),
        Expr::If(i) => {
            strip_old_pads(&mut i.then_branch);
            if let Some((_, els)) = &mut i.else_branch {
                strip_from_expr(els);
            }
        }
        Expr::While(w) => strip_old_pads(&mut w.body),
        Expr::ForLoop(f) => strip_old_pads(&mut f.body),
        Expr::Loop(l) => strip_old_pads(&mut l.body),
        Expr::Match(m) => {
            for arm in &mut m.arms {
                strip_from_expr(&mut arm.body);
            }
        }
        Expr::Unsafe(u) => strip_old_pads(&mut u.block),
        _ => {}
    }
}

fn item_impl_self_name(im: &ItemImpl) -> String {
    if let syn::Type::Path(p) = &*im.self_ty {
        if let Some(seg) = p.path.segments.last() {
            return seg.ident.to_string();
        }
    }
    "_anon_impl".to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_str;

    /// 2026-07-29 soak regression: repeated apply() calls must be
    /// size-BOUNDED — each cycle strips the previous pads before
    /// injecting fresh ones. Pre-fix, N cycles grew sources ~linearly
    /// (~27x over 243 cycles) until the verifier's syn recursion
    /// overflowed the default stack and every cycle rejected.
    #[test]
    fn repeated_apply_is_size_bounded() {
        let src = r#"
fn alpha(a: u32) -> u32 { a + 1 }
fn beta(b: u32) -> u32 {
    let mut x = b;
    if x > 3 { x += 1; } else { x -= 1; }
    for i in 0..x { x += i; }
    x
}
"#;
        let seed = Seed([7u8; 32]);
        let mut file: File = parse_str(src).unwrap();
        apply(&mut file, &seed);
        let once = quote::quote!(#file).to_string();
        for _ in 0..50 {
            apply(&mut file, &seed);
        }
        let fifty = quote::quote!(#file).to_string();
        assert_eq!(
            once.len(),
            fifty.len(),
            "50 apply cycles must produce the same size as 1 (pads stripped before re-injection)"
        );
        // And it still has pads.
        assert!(fifty.contains("__cuttle_stack_pad_"));
        // Count pad lets: must equal the per-cycle count, not 50x.
        let count = fifty.matches("__cuttle_stack_pad_").count();
        let once_count = once.matches("__cuttle_stack_pad_").count();
        assert_eq!(count, once_count);
    }

    fn seed_from(s: u8) -> Seed {
        Seed([s; 32])
    }

    #[test]
    fn decide_pad_bytes_is_deterministic_for_same_seed_and_name() {
        let s = seed_from(42);
        let a = decide_pad_bytes(&s, "hkdf_expand_label");
        let b = decide_pad_bytes(&s, "hkdf_expand_label");
        assert_eq!(a, b);
    }

    #[test]
    fn decide_pad_bytes_varies_across_seeds() {
        let mut seen = std::collections::BTreeSet::new();
        for seed_byte in 0u8..40 {
            seen.insert(decide_pad_bytes(&seed_from(seed_byte), "f"));
        }
        // 40 random seeds against 192 buckets should give us many
        // distinct values. Tolerate hash collisions, but require
        // diversity well above the "4 distinct layouts" baseline.
        assert!(
            seen.len() >= 20,
            "expected ≥ 20 distinct pad sizes across 40 seeds, got {}",
            seen.len()
        );
    }

    #[test]
    fn decide_pad_bytes_in_range() {
        let s = seed_from(7);
        for name in &["a", "longer_name", "Type::method", "x", ""] {
            let n = decide_pad_bytes(&s, name);
            assert!(n >= MIN_PAD_BYTES, "{name} -> {n} below MIN");
            assert!(n < MIN_PAD_BYTES + PAD_RANGE_BYTES, "{name} -> {n} above MAX");
        }
    }

    fn extract_first_stmt(src: &str) -> String {
        let file: File = parse_str(src).unwrap();
        let f = file
            .items
            .iter()
            .find_map(|it| if let Item::Fn(f) = it { Some(f) } else { None })
            .expect("expected one fn");
        let first = f.block.stmts.first().expect("expected ≥ 1 stmt");
        quote::quote!(#first).to_string()
    }

    #[test]
    fn apply_inserts_pad_at_top_of_free_fn() {
        let src = "fn f(x: u32) -> u32 { x + 1 }";
        let mut file: File = parse_str(src).unwrap();
        let log = apply(&mut file, &seed_from(1));
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].fn_name, "f");
        let out = quote::quote!(#file).to_string();
        assert!(
            out.contains("__cuttle_stack_pad_"),
            "pad ident missing in output: {out}"
        );
        assert!(out.contains("core :: hint :: black_box"));
    }

    #[test]
    fn apply_skips_unsafe_fn() {
        let src = "unsafe fn boom() { }";
        let mut file: File = parse_str(src).unwrap();
        let log = apply(&mut file, &seed_from(1));
        assert!(log.is_empty(), "unsafe fn should be skipped");
        let out = quote::quote!(#file).to_string();
        assert!(!out.contains("__cuttle_stack_pad_"));
    }

    #[test]
    fn apply_skips_const_fn() {
        let src = "const fn c() -> u32 { 0 }";
        let mut file: File = parse_str(src).unwrap();
        let log = apply(&mut file, &seed_from(1));
        assert!(log.is_empty(), "const fn should be skipped");
    }

    #[test]
    fn apply_skips_main() {
        let src = "fn main() { }";
        let mut file: File = parse_str(src).unwrap();
        let log = apply(&mut file, &seed_from(1));
        assert!(log.is_empty(), "main fn should be skipped");
    }

    #[test]
    fn apply_skips_no_mangle() {
        let src = "#[no_mangle] fn abi_locked() { }";
        let mut file: File = parse_str(src).unwrap();
        let log = apply(&mut file, &seed_from(1));
        assert!(log.is_empty(), "#[no_mangle] fn should be skipped");
    }

    #[test]
    fn apply_skips_async_fn() {
        let src = "async fn a() { }";
        let mut file: File = parse_str(src).unwrap();
        let log = apply(&mut file, &seed_from(1));
        assert!(log.is_empty(), "async fn should be skipped");
    }

    #[test]
    fn apply_handles_impl_block_methods() {
        let src = "struct S; impl S { fn m(&self) -> u32 { 0 } fn n(&self) -> u32 { 1 } }";
        let mut file: File = parse_str(src).unwrap();
        let log = apply(&mut file, &seed_from(3));
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].fn_name, "S::m");
        assert_eq!(log[1].fn_name, "S::n");
        // Different fn_name -> different pad bytes (hash collisions
        // possible but vanishingly rare for short names; if this test
        // ever flakes, that's the signal).
        assert_ne!(log[0].bytes, log[1].bytes);
    }

    #[test]
    fn apply_skips_impl_block_unsafe_methods() {
        let src = "struct S; impl S { unsafe fn m(&self) -> u32 { 0 } fn n(&self) -> u32 { 1 } }";
        let mut file: File = parse_str(src).unwrap();
        let log = apply(&mut file, &seed_from(3));
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].fn_name, "S::n");
    }

    #[test]
    fn pad_size_varies_across_seeds_for_same_fn() {
        let mut seen = std::collections::BTreeSet::new();
        for s in 0u8..32 {
            let mut file: File = parse_str("fn g() -> u32 { 0 }").unwrap();
            apply(&mut file, &seed_from(s));
            let stmt = extract_first_stmt(&quote::quote!(#file).to_string());
            seen.insert(stmt);
        }
        assert!(
            seen.len() >= 12,
            "expected ≥ 12 distinct pad statements across 32 seeds, got {}",
            seen.len()
        );
    }

    #[test]
    fn diversifier_output_with_padding_still_parses() {
        // End-to-end sanity: take a non-trivial source, run the full
        // diversify pipeline, ensure the output still round-trips
        // through syn (i.e., we produced valid Rust).
        let src = r#"
            #![no_std]
            pub fn add(a: u32, b: u32) -> u32 { a + b }
            pub fn sub(a: u32, b: u32) -> u32 { a - b }
            fn helper(x: u32) -> u32 { x.wrapping_mul(3) }
            pub struct S;
            impl S {
                pub fn m(&self) -> u32 { helper(7) }
            }
        "#;
        let out = crate::diversify_with_options(
            src,
            &seed_from(42),
            &crate::DiversifyOptions::with_stack_pad(),
        )
        .unwrap()
        .0;
        let _: File = parse_str(&out).expect("diversified output must reparse");
        assert!(out.contains("__cuttle_stack_pad_"));
        assert!(out.contains("core :: hint :: black_box"));
    }

    #[test]
    fn pad_is_first_statement_in_body() {
        let mut file: File = parse_str("fn f() -> u32 { let x = 1; x }").unwrap();
        apply(&mut file, &seed_from(5));
        let f = file
            .items
            .iter()
            .find_map(|it| if let Item::Fn(f) = it { Some(f) } else { None })
            .unwrap();
        let first_stmt_ref = &f.block.stmts[0];
        let first_stmt = quote::quote!(#first_stmt_ref).to_string();
        assert!(
            first_stmt.contains("__cuttle_stack_pad_"),
            "first stmt should be the pad, got: {first_stmt}"
        );
    }
}
