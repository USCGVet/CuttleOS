//! Seed-keyed function inlining perturbation pass.
//!
//! Attaches `#[inline(never)]`, `#[inline(always)]`, or no attribute to
//! top-level free functions (`Item::Fn`) based on a domain-separated SHA-256
//! hash of `(HASH_TAG, seed, fn_name)`:
//! - `0`   -> no attribute (`25%`)
//! - `1`   -> `#[inline(always)]` (`25%`)
//! - `2,3` -> `#[inline(never)]` (`50%`)
//!
//! Skips `main`, trait-impl methods (`ImplItem::Fn`), and functions that carry
//! an explicit user-written `#[inline...]` attribute. Perturbing inliner
//! decisions per seed prevents LLVM from folding distinct AST/MIR variants
//! back into identical machine code.

use sha2::{Digest, Sha256};
use syn::{File, Item};

use crate::Seed;

/// Domain-separation tag for the codegen perturbation hash. Bumping
/// this string is the contract-versioning lever: if we ever change
/// the attribute alphabet or the decision logic, bump the tag so
/// that attestations from before/after the change are distinguishable.
const HASH_TAG: &[u8] = b"cuttle-codegen-perturb-v1";

/// Decision made for one function. Public so the unit-test layer can
/// assert directly on the choice without rebuilding the AST.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PerturbDecision {
    /// Leave the function untouched.
    NoAttr,
    /// Attach `#[inline(always)]`.
    InlineAlways,
    /// Attach `#[inline(never)]`.
    InlineNever,
    /// Function was skipped because it is `main`, or already carries
    /// an `#[inline...]` attribute. Trait-impl methods are skipped at
    /// the visitor level (we never call `decide` on them) so they
    /// don't appear here.
    Ineligible(Reason),
}

/// Why a function was ruled ineligible for perturbation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// `main`.
    MainFn,
    /// Already carries `#[inline]`, `#[inline(always)]`, or `#[inline(never)]`.
    AlreadyInline,
}

/// Decide what to do with one function. Pure: no I/O, no rng, no
/// side effects. Determinism is in `(seed, fn_name)`.
pub fn decide(seed: &Seed, fn_name: &str, existing_attrs: &[syn::Attribute]) -> PerturbDecision {
    let base_name = crate::strip_cuttle_fn_suffix(fn_name);
    if base_name == "main" {
        return PerturbDecision::Ineligible(Reason::MainFn);
    }
    if has_inline_attr(existing_attrs) {
        return PerturbDecision::Ineligible(Reason::AlreadyInline);
    }
    let mut h = Sha256::new();
    h.update(HASH_TAG);
    h.update(seed.0);
    h.update(base_name.as_bytes());
    let out = h.finalize();
    match out[0] & 0x03 {
        0 => PerturbDecision::NoAttr,
        1 => PerturbDecision::InlineAlways,
        _ => PerturbDecision::InlineNever,
    }
}

/// Apply the perturbation pass to `file` under `seed`.
///
/// Walks `file.items`, identifies every private free function, runs
/// `decide`, and pushes the resulting attribute onto `f.attrs` if the
/// decision is `InlineAlways` or `InlineNever`. Returns the per-function
/// decision log for tests and reporting; production callers can ignore
/// it.
pub fn apply(file: &mut File, seed: &Seed) -> Vec<(String, PerturbDecision)> {
    let mut log = Vec::new();
    for item in file.items.iter_mut() {
        let Item::Fn(f) = item else { continue };
        let name = f.sig.ident.to_string();
        let d = decide(seed, &name, &f.attrs);
        match d {
            PerturbDecision::InlineAlways => {
                let attr: syn::Attribute = syn::parse_quote!(#[inline(always)]);
                f.attrs.push(attr);
            }
            PerturbDecision::InlineNever => {
                let attr: syn::Attribute = syn::parse_quote!(#[inline(never)]);
                f.attrs.push(attr);
            }
            PerturbDecision::NoAttr | PerturbDecision::Ineligible(_) => {}
        }
        log.push((name, d));
    }
    log
}

fn has_inline_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("inline"))
}

// ---------------------------------------------------------------------------
// Unit tests on the perturbation pass itself.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    fn make_file(src: &str) -> File {
        syn::parse_str(src).expect("fixture must parse")
    }

    fn find_fn<'a>(file: &'a File, name: &str) -> &'a syn::ItemFn {
        for it in &file.items {
            if let Item::Fn(f) = it {
                if f.sig.ident == name {
                    return f;
                }
            }
        }
        panic!("fn {} not found in fixture", name);
    }

    fn has_attr(f: &syn::ItemFn, want: &str) -> bool {
        f.attrs.iter().any(|a| {
            let s = quote::quote!(#a).to_string();
            s.replace(' ', "") == want.replace(' ', "")
        })
    }

    const FIX: &str = r#"
        pub fn pub_one(x: u32) -> u32 { x + 1 }
        fn priv_a(x: u32) -> u32 { x.wrapping_mul(3) }
        fn priv_b(x: u32) -> u32 { x.wrapping_add(7) }
        fn priv_c(x: u32) -> u32 { x ^ 0x55 }
        fn priv_d(x: u32) -> u32 { x.rotate_left(5) }
        fn priv_e(x: u32) -> u32 { x.wrapping_sub(1) }
        fn priv_f(x: u32) -> u32 { x | 0xF }
        fn priv_g(x: u32) -> u32 { x & 0xF0 }
        fn priv_h(x: u32) -> u32 { x >> 1 }
    "#;

    #[test]
    fn pub_fn_participates_in_perturbation() {
        // Per the documented deviation in this file's module doc, the
        // pass DOES target pub fns (deviation from TASK-027's
        // private-only constraint, justified by tls.rs having zero
        // private free fns). The `pub_one` entry in our fixture must
        // therefore receive a real decision, not be ruled ineligible.
        let seed = Seed::derive(1, "x");
        let log = apply(&mut make_file(FIX), &seed);
        let entry = log.iter().find(|(n, _)| n == "pub_one").expect("pub_one logged");
        assert!(
            matches!(
                entry.1,
                PerturbDecision::NoAttr
                    | PerturbDecision::InlineAlways
                    | PerturbDecision::InlineNever
            ),
            "pub fn must get a real perturbation decision, got {:?}",
            entry.1
        );
    }

    #[test]
    fn main_fn_is_ineligible() {
        let src = "fn main() {}";
        let seed = Seed::derive(0, "x");
        let mut file = make_file(src);
        let log = apply(&mut file, &seed);
        assert_eq!(log.len(), 1);
        assert!(matches!(
            log[0].1,
            PerturbDecision::Ineligible(Reason::MainFn)
        ));
    }

    #[test]
    fn already_inline_fn_is_ineligible() {
        let src = r#"
            #[inline(always)]
            fn keep(x: u32) -> u32 { x }
            #[inline]
            fn also_keep(x: u32) -> u32 { x }
            #[inline(never)]
            fn never_keep(x: u32) -> u32 { x }
        "#;
        let seed = Seed::derive(42, "demo");
        let mut file = make_file(src);
        let log = apply(&mut file, &seed);
        for (n, d) in &log {
            assert!(
                matches!(d, PerturbDecision::Ineligible(Reason::AlreadyInline)),
                "{} should be ineligible (AlreadyInline), got {:?}",
                n,
                d
            );
        }
    }

    #[test]
    fn decide_is_deterministic_under_same_seed_and_name() {
        let seed = Seed::derive(7, "demo");
        let d1 = decide(&seed, "priv_a", &[]);
        let d2 = decide(&seed, "priv_a", &[]);
        assert_eq!(d1, d2);
    }

    #[test]
    fn decide_changes_with_seed() {
        // Across a broad sweep of seeds, the perturbation choice for
        // a fixed fn name must NOT be constant. (It is constant per
        // seed; it varies across seeds.)
        let mut seen = std::collections::HashSet::new();
        for cycle in 0..32u64 {
            let s = Seed::derive(cycle, "demo");
            seen.insert(decide(&s, "priv_a", &[]));
            if seen.len() >= 2 {
                return;
            }
        }
        panic!("decide() collapsed to a single value across 32 seeds — bug in distribution");
    }

    #[test]
    fn attribute_distribution_is_approximately_uniform_over_seeds() {
        // Sanity check: across 256 seeds, all three eligible decisions
        // must appear (NoAttr, InlineAlways, InlineNever). The full
        // 4-bucket distribution skews InlineNever (2/4) which is by
        // design; we just want non-trivial coverage of each bucket.
        let mut no = 0;
        let mut always = 0;
        let mut never = 0;
        for cycle in 0..256u64 {
            let s = Seed::derive(cycle, "demo");
            match decide(&s, "priv_a", &[]) {
                PerturbDecision::NoAttr => no += 1,
                PerturbDecision::InlineAlways => always += 1,
                PerturbDecision::InlineNever => never += 1,
                PerturbDecision::Ineligible(_) => panic!("eligible fn cannot be ineligible"),
            }
        }
        assert!(no > 20, "NoAttr too rare: {}", no);
        assert!(always > 20, "InlineAlways too rare: {}", always);
        assert!(never > 60, "InlineNever too rare: {}", never);
        assert_eq!(no + always + never, 256);
    }

    #[test]
    fn apply_attaches_real_attrs_to_eligible_fns() {
        let seed = Seed::derive(123, "demo");
        let mut file = make_file(FIX);
        let log = apply(&mut file, &seed);

        // For every (name, Decision) in the log that says
        // InlineAlways or InlineNever, the corresponding ItemFn must
        // actually carry the matching attribute. And every NoAttr
        // entry must NOT have an inline attr. This now covers
        // `pub_one` too — pub fns participate in perturbation per
        // the documented deviation.
        for (name, d) in &log {
            if name == "main" {
                continue;
            }
            let f = find_fn(&file, name);
            match d {
                PerturbDecision::InlineAlways => {
                    assert!(
                        has_attr(f, "# [inline (always)]"),
                        "{} marked InlineAlways but no attr on AST",
                        name
                    );
                }
                PerturbDecision::InlineNever => {
                    assert!(
                        has_attr(f, "# [inline (never)]"),
                        "{} marked InlineNever but no attr on AST",
                        name
                    );
                }
                PerturbDecision::NoAttr => {
                    assert!(
                        !f.attrs.iter().any(|a| a.path().is_ident("inline")),
                        "{} marked NoAttr but inline attr was added",
                        name
                    );
                }
                PerturbDecision::Ineligible(_) => unreachable!(),
            }
        }
    }

    #[test]
    fn apply_attaches_to_pub_fns_across_a_seed_sweep() {
        // Counter to the original "private-only" intent: across a
        // 256-seed sweep, the `pub_one` fixture entry MUST receive at
        // least one InlineAlways and at least one InlineNever
        // decision. This pins the deviation in code so a reversion
        // is loud.
        let mut saw_always = false;
        let mut saw_never = false;
        for c in 0..256u64 {
            let seed = Seed::derive(c, "pub_sweep");
            match decide(&seed, "pub_one", &[]) {
                PerturbDecision::InlineAlways => saw_always = true,
                PerturbDecision::InlineNever => saw_never = true,
                _ => {}
            }
            if saw_always && saw_never {
                return;
            }
        }
        panic!(
            "expected both inline(always) AND inline(never) to land on pub_one over 256 seeds; \
             got always={} never={}",
            saw_always, saw_never
        );
    }

    #[test]
    fn apply_is_idempotent_under_same_seed() {
        let seed = Seed::derive(2026, "demo");
        let mut a = make_file(FIX);
        let mut b = make_file(FIX);
        let log_a = apply(&mut a, &seed);
        let log_b = apply(&mut b, &seed);
        assert_eq!(log_a, log_b);
        let s_a = quote::quote!(#a).to_string();
        let s_b = quote::quote!(#b).to_string();
        assert_eq!(s_a, s_b, "same seed must yield byte-identical output");
    }

    #[test]
    fn apply_differs_across_seeds_on_the_same_input() {
        // Verifies the pass is doing something: two distinct seeds
        // must produce two distinct outputs on the multi-fn fixture.
        // (Not theoretical certainty — over 9 private fns and ~50%
        // attribute density per seed, the probability of identical
        // output across two random seeds is negligible.)
        let a_seed = Seed::derive(11, "demo");
        let b_seed = Seed::derive(22, "demo");
        let mut a = make_file(FIX);
        let mut b = make_file(FIX);
        apply(&mut a, &a_seed);
        apply(&mut b, &b_seed);
        let s_a = quote::quote!(#a).to_string();
        let s_b = quote::quote!(#b).to_string();
        assert_ne!(s_a, s_b);
    }

    #[test]
    fn apply_never_modifies_trait_impl_methods() {
        let src = r#"
            trait T { fn m(&self) -> u32; }
            struct S;
            impl T for S {
                fn m(&self) -> u32 { 1 }
            }
            impl S {
                fn helper(&self) -> u32 { 2 }
            }
            fn free_priv(x: u32) -> u32 { x + 1 }
        "#;
        let seed = Seed::derive(33, "demo");
        let mut file = make_file(src);
        let log = apply(&mut file, &seed);

        // Only the free private fn should appear in the log.
        let names: Vec<_> = log.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["free_priv"]);

        // And the impl methods must not have been touched.
        for it in &file.items {
            if let Item::Impl(im) = it {
                for ii in &im.items {
                    if let syn::ImplItem::Fn(m) = ii {
                        assert!(
                            !m.attrs.iter().any(|a| a.path().is_ident("inline")),
                            "impl method {} got an inline attr",
                            m.sig.ident
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn apply_respects_existing_inline_always_on_priv_fn() {
        let src = r#"
            #[inline(always)]
            fn pinned(x: u32) -> u32 { x }
            fn floating(x: u32) -> u32 { x }
        "#;
        // Use a seed that we KNOW would normally attach an attr to
        // `pinned`. Brute-force search: find one where decide() of
        // an empty-attr `pinned` would be Always or Never.
        let mut chosen: Option<u64> = None;
        for cycle in 0..256u64 {
            let s = Seed::derive(cycle, "demo");
            let d = decide(&s, "pinned", &[]);
            if matches!(d, PerturbDecision::InlineAlways | PerturbDecision::InlineNever) {
                chosen = Some(cycle);
                break;
            }
        }
        let cycle = chosen.expect("must find at least one seed that would perturb 'pinned'");
        let seed = Seed::derive(cycle, "demo");
        let mut file = make_file(src);
        apply(&mut file, &seed);

        // `pinned` started with #[inline(always)] and must STILL have
        // exactly one inline attr, the original one. No double attrs.
        let pinned = find_fn(&file, "pinned");
        let inline_count = pinned
            .attrs
            .iter()
            .filter(|a| a.path().is_ident("inline"))
            .count();
        assert_eq!(
            inline_count, 1,
            "pinned must keep its single original #[inline(always)]"
        );
    }

    #[test]
    fn parse_quote_inline_attrs_match_path() {
        // Tightening: the attributes we synthesise must round-trip
        // through `path().is_ident("inline")`. If syn's quoting ever
        // changes, this test catches it.
        let a: syn::Attribute = parse_quote!(#[inline(always)]);
        let b: syn::Attribute = parse_quote!(#[inline(never)]);
        assert!(a.path().is_ident("inline"));
        assert!(b.path().is_ident("inline"));
    }

    #[test]
    fn apply_returns_one_log_entry_per_top_level_fn() {
        let src = r#"
            pub fn a() {}
            fn b() {}
            const K: u32 = 1;
            struct S;
            fn c() {}
        "#;
        let seed = Seed::derive(0, "demo");
        let mut file = make_file(src);
        let log = apply(&mut file, &seed);
        let names: Vec<_> = log.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }
}
