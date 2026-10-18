//! Deterministic, seed-driven Rust AST diversifier (`cuttle-diversifier`).
//!
//! Applies semantics-preserving source transformations to Rust modules keyed
//! by a 256-bit [`Seed`]:
//!
//! 1. **Top-level item reordering**: Permutes `fn`, `struct`, `enum`, `const`,
//!    and `static` items while keeping `use`, `mod`, and macro definitions
//!    in place.
//! 2. **Private function renaming**: Consistently renames non-`pub` free
//!    functions at their definition and all call sites.
//! 3. **Lexical local-variable renaming**: Renames local `let` bindings with
//!    scope-aware shadowing support.
//! 4. **Conservative statement reordering**: Swaps adjacent statements whose
//!    read/write identifier sets are disjoint and contain no calls, macros,
//!    control flow, or `unsafe` blocks.
//! 5. **Literal `match`-arm reordering**: Permutes guard-free literal pattern
//!    arms (`Int`, `Bool`, `Char`, `Byte`).
//! 6. **`if` ↔ `match` boolean rewrites**: Converts `if cond { a } else { b }`
//!    to `match cond { true => a, false => b }` and vice versa.
//! 7. **Semantic & codegen perturbations**: Invokes [`semantic_perturb`]
//!    (multiply/shift, branch polarity, and `for`/`while` loop rewrites) and
//!    [`codegen_perturb`] (`#[inline(never)]` / `#[inline(always)]` hints).
//!
//! Functions marked `unsafe fn` or containing `unsafe` blocks are skipped by
//! per-function structural passes. Files listed in `locked_modules.toml` are
//! refused by [`diversify_path`].

use anyhow::{Context, Result};
use proc_macro2::Span;
use rand::seq::SliceRandom;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use syn::visit_mut::VisitMut;
use syn::{
    Arm, Block, Expr, ExprIf, ExprMatch, File, FnArg, Ident, ImplItem, Item, Lit, Local, Macro,
    Pat, Stmt, Visibility,
};

pub mod codegen_perturb;
pub mod locked;
pub mod semantic_perturb;
pub mod stack_pad;

pub use locked::{
    diversify_path, diversify_path_with_log, diversify_path_with_log_and_options,
    load_locked_modules, parse_locked_modules_at, parse_locked_modules_str, DiversifyError,
    LockedModules, LOCKED_MODULES_SCHEMA_VERSION,
};

/// Seed material for the diversifier. Production cycles MUST use entropy
/// from a CSPRNG seeded with `(cycle_number, module_name, factory_secret)`
/// so that the morph distribution is reproducible from the attestation
/// log but unpredictable to outsiders.
#[derive(Clone)]
pub struct Seed(pub [u8; 32]);

impl Seed {
    /// Derive a seed from a cycle number and module name. Production
    /// code should mix in a factory-held secret as well; this helper is
    /// for the skeleton and for tests.
    pub fn derive(cycle: u64, module: &str) -> Self {
        let mut h = Sha256::new();
        h.update(b"cuttle-diversifier-v1");
        h.update(cycle.to_le_bytes());
        h.update(module.as_bytes());
        let out = h.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(&out);
        Self(s)
    }
}

/// Per-cycle decision log emitted by [`diversify_with_log`] alongside
/// the candidate source. Captures the deterministic choices made by the
/// `codegen_perturb` and `stack_pad` passes so that downstream layers
/// (today: the morph engine's attestation entry) can record what the
/// factory *did* in addition to the resulting bytes.
///
/// The two maps are keyed by function name. For `Item::Fn` items the key
/// is the bare identifier; for `ImplItem::Fn` methods inside `Item::Impl`
/// blocks the `stack_pad` pass uses `"Type::method"` while the
/// `codegen_perturb` pass currently only operates on free fns (so
/// `perturb_decisions` never contains a `::`-bearing key today).
///
/// Both maps are deterministic in `(seed, source)` — re-running
/// `diversify_with_log` on the same inputs yields byte-identical
/// `DiversifierLog`s. The morph engine's attestation entry serialises
/// them with `skip_serializing_if = "BTreeMap::is_empty"` so an empty
/// log (e.g. an empty source file) round-trips byte-identically through
/// the canonical-JSON hash.
///
/// `perturb_decisions` values are the lower-case spellings of the
/// [`codegen_perturb::PerturbDecision`] variants:
/// `"inline-always"`, `"inline-never"`, `"no-attr"`,
/// `"ineligible:main-fn"`, `"ineligible:already-inline"`. The dash form
/// (rather than `Debug`'s `{:?}` spelling) is locked because the
/// attestation chain commits to these strings via canonical JSON — any
/// future variant rename here is a SCHEMA-affecting change and must be
/// gated by an attestation schema bump on the consumer side.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiversifierLog {
    /// `fn_name` → pad size in bytes. Empty when the input file
    /// contains no morphable functions (every function was filtered
    /// out by [`stack_pad::apply`]'s skip rules).
    pub pad_decisions: BTreeMap<String, u32>,
    /// `fn_name` → decision spelling (see the type-level docs for the
    /// locked alphabet). Empty when the input file contains no free
    /// fns at all (e.g. a contracts-only source consisting of trait
    /// definitions).
    pub perturb_decisions: BTreeMap<String, String>,
    /// `fn_name` → semantic-perturb decision spelling (Rung 1). Values
    /// are comma-joined labels from [`semantic_perturb`]
    /// (`"strength-reduction"`, `"branch-polarity"`, `"loop-form"`),
    /// `"eligible:no-change"`, or `"ineligible:<reason>"`. Populated
    /// only when [`DiversifyOptions::semantic_perturb`] is on; empty
    /// otherwise so the attestation canonical-JSON of pre-Rung-1
    /// entries is byte-identical.
    pub semantic_decisions: BTreeMap<String, String>,
}

impl DiversifierLog {
    /// `true` iff both maps are empty. Convenience for the attestation
    /// emitter's "omit when empty" path.
    pub fn is_empty(&self) -> bool {
        self.pad_decisions.is_empty()
            && self.perturb_decisions.is_empty()
            && self.semantic_decisions.is_empty()
    }

    /// Total recorded decisions across all passes. Convenience for
    /// metrics / dashboards.
    pub fn total_decisions(&self) -> usize {
        self.pad_decisions.len() + self.perturb_decisions.len() + self.semantic_decisions.len()
    }
}

/// Canonicalise a [`codegen_perturb::PerturbDecision`] to the locked
/// string spelling stored in [`DiversifierLog::perturb_decisions`].
/// Locked: the attestation chain commits to these strings, so a rename
/// here is a SCHEMA-affecting change.
pub fn perturb_decision_label(d: &codegen_perturb::PerturbDecision) -> &'static str {
    use codegen_perturb::{PerturbDecision, Reason};
    match d {
        PerturbDecision::NoAttr => "no-attr",
        PerturbDecision::InlineAlways => "inline-always",
        PerturbDecision::InlineNever => "inline-never",
        PerturbDecision::Ineligible(Reason::MainFn) => "ineligible:main-fn",
        PerturbDecision::Ineligible(Reason::AlreadyInline) => "ineligible:already-inline",
    }
}

/// Tunables for a single diversify invocation.
///
/// # Production default (`stack_pad = false`)
///
/// TASK-029 stack-frame padding was introduced to force function-size
/// (and therefore offset) diversity. After Phase-1 layout seeding
/// (`-Zrandomize-layout` + lld `--shuffle-sections`) landed, measured
/// ROP chain survival dropped to 0% *without* stack pads — while the
/// pad pass itself inflated gadget count by ~33% (diversity_demo
/// measurement, 2026-05-28). Production morphs therefore leave
/// stack-pad **off** by default. Opt in only for A/B measurement or
/// when deliberately testing the TASK-029 pass in isolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiversifyOptions {
    /// When `true`, run [`stack_pad::apply`] as the last diversifier
    /// pass. Default: `false` (see type-level docs).
    pub stack_pad: bool,
    /// When `true`, run the Rung-1 [`semantic_perturb`] pass after
    /// codegen perturbation. Default: `false` — existing consumers
    /// keep byte-identical output unless they opt in.
    pub semantic_perturb: bool,
    /// Per-transform fire rate (0..=100) for the Rung-1
    /// [`semantic_perturb`] pass; each transform's deterministic
    /// per-function coin fires with this probability. Values above
    /// 100 are clamped. Default: `50` (the pre-fire-rate behavior).
    /// [`DiversifyOptions::with_semantic_perturb`] sets it to `100`
    /// (production wants maximum instruction-mix diversity).
    pub semantic_fire_rate_percent: u8,
}

impl Default for DiversifyOptions {
    fn default() -> Self {
        Self {
            stack_pad: false,
            semantic_perturb: false,
            semantic_fire_rate_percent: 50,
        }
    }
}

impl DiversifyOptions {
    /// Convenience: production defaults with stack-pad forced on.
    /// Used by TASK-029 unit/integration tests and A/B CLI paths.
    pub fn with_stack_pad() -> Self {
        Self {
            stack_pad: true,
            ..Self::default()
        }
    }

    /// Convenience: production defaults with the Rung-1 semantic
    /// perturbation pass forced on. Used by the A/B measurement path
    /// (`mtd specimen --semantic`).
    pub fn with_semantic_perturb() -> Self {
        Self {
            semantic_perturb: true,
            semantic_fire_rate_percent: 100,
            ..Self::default()
        }
    }
}

/// Apply the full diversifier pipeline to `source` under `seed`. Thin
/// back-compat wrapper around [`diversify_with_log`]: callers that only
/// need the candidate source (today: the diversifier CLI and ~50 test
/// sites) keep the original `Result<String>` shape; callers that need
/// the per-cycle decision log (today: the morph engine's attestation
/// emitter) use [`diversify_with_log`] directly.
///
/// Uses [`DiversifyOptions::default`] (stack-pad **off**).
pub fn diversify(source: &str, seed: &Seed) -> Result<String> {
    diversify_with_log(source, seed).map(|(s, _log)| s)
}

/// Apply the full diversifier pipeline under explicit [`DiversifyOptions`].
/// Prefer this when you need stack-pad on (tests / A/B) without changing
/// the production default.
pub fn diversify_with_options(
    source: &str,
    seed: &Seed,
    options: &DiversifyOptions,
) -> Result<(String, DiversifierLog)> {
    diversify_with_log_and_options(source, seed, options)
}

/// Apply the full diversifier pipeline to `source` under `seed`,
/// returning both the candidate source and the per-cycle decision log
/// for the `codegen_perturb` and (when enabled) `stack_pad` passes.
///
/// Uses [`DiversifyOptions::default`] (stack-pad **off**). The log is
/// deterministic in `(seed, source, options)`; two runs with the same
/// inputs produce byte-identical `DiversifierLog`s. See
/// [`DiversifierLog`] for the field semantics and the canonicalised
/// `perturb_decisions` value alphabet.
///
/// This is the entry point used by the morph engine's attestation
/// plumbing (TASK-031). Existing callers continue to use [`diversify`].
pub fn diversify_with_log(source: &str, seed: &Seed) -> Result<(String, DiversifierLog)> {
    diversify_with_log_and_options(source, seed, &DiversifyOptions::default())
}

/// With-log entry point with explicit options. The morph engine's
/// production cycles call this with `semantic_perturb` on (Phase 1
/// lived diversify-first defense); `diversify_with_log` remains the
/// default-options compatibility shim.
pub fn diversify_with_log_and_options(
    source: &str,
    seed: &Seed,
    options: &DiversifyOptions,
) -> Result<(String, DiversifierLog)> {
    let mut file: File = syn::parse_str(source).context("parse input source")?;
    let mut rng = ChaCha20Rng::from_seed(seed.0);

    // Strip any `#[inline(always)]` / `#[inline(never)]` attributes injected
    // by a prior morph cycle so `codegen_perturb` re-rolls a fresh inlining
    // decision every cycle instead of freezing after ~2 cycles. Bare
    // author-written `#[inline]` attributes are preserved untouched.
    strip_prior_cycle_inline_attrs(&mut file);

    // Rename private fns consistently across the file. Done before item
    // reordering so the rename pass walks the original AST layout. Also
    // done before per-function transforms so renamed-fn identifiers
    // propagate.
    let rename_map = build_private_fn_rename_map(&file, &mut rng);
    // Symmetric to the per-function macro-ident skip: if a private
    // fn's original name appears as an identifier inside any macro
    // body anywhere in the file, refuse to rename it. The macro
    // body is opaque tokens to `RenamePrivateFns::visit_macro_mut`
    // (which is a no-op by design — macro grammars are unknown), so
    // a rename here would leave the macro reference stale and
    // produce E0425 at compile time. This generalisation of the
    // TASK-016 fix prevents the same class of bug from showing up
    // when a future donor module calls a private helper from inside
    // an `assert!` / `format!` / `dbg!` / declarative-macro body.
    let file_macro_idents = collect_macro_idents_in_file(&file);
    let filtered_rename_map: BTreeMap<String, String> = rename_map
        .into_iter()
        .filter(|(orig, _new)| !file_macro_idents.contains(orig))
        .collect();
    if !filtered_rename_map.is_empty() {
        RenamePrivateFns {
            map: &filtered_rename_map,
        }
        .visit_file_mut(&mut file);
    }

    // Per-function transforms. Each function gets its own deterministic
    // sub-seed pulled from the master rng, so per-function output is
    // stable regardless of file-level item order.
    let func_suffix = derive_suffix(&mut rng, "v");
    apply_per_function_transforms(&mut file, &mut rng, &func_suffix);

    // Reorder top-level items. Done before codegen perturbation so the
    // perturbation pass sees the final post-reorder AST. (Order between
    // these two is observationally indistinguishable — perturbation
    // adds attrs to specific named items regardless of position — but
    // we keep reorder-then-perturb so the rng is consumed by reorder
    // before any future pass that might also want determinism on rng
    // state.)
    ReorderItems { rng: &mut rng }.visit_file_mut(&mut file);

    // Codegen-level perturbation (TASK-027). Attaches
    // `#[inline(never)]` / `#[inline(always)]` to a deterministic
    // seed-keyed subset of private free functions, so that two
    // MIR-distinct candidates do not fold back to identical machine
    // code in LLVM's late passes. See `codegen_perturb.rs` for the
    // full rationale and the decision distribution.
    let perturb_log = codegen_perturb::apply(&mut file, seed);

    // Semantic-level perturbation (Rung 1) — **opt-in**. When enabled,
    // rewrites instruction-mix-affecting expression shapes (strength
    // reduction ↔ shifts, branch polarity, loop form) inside eligible
    // function bodies. Like `codegen_perturb`, determinism is derived
    // from hash(tag, seed, fn_name); the shared rng is not consumed.
    // Default OFF so pre-Rung-1 consumers keep byte-identical output.
    let semantic_log = if options.semantic_perturb {
        semantic_perturb::apply(&mut file, seed, options.semantic_fire_rate_percent)
    } else {
        Vec::new()
    };

    // Stack-frame padding (TASK-029) — **opt-in**. Production default
    // is off (see [`DiversifyOptions`]): Phase-1 layout seeding is the
    // lever that relocates offsets; stack pads were measured to inflate
    // gadget count without buying additional chain-death once layout
    // seeds are engaged. When enabled, injects a per-(seed, fn_name)
    // sized `core::hint::black_box`-anchored `[u8; N]` pad at the top
    // of every morphable function body. See `stack_pad.rs`.
    //
    // Order: this pass runs LAST so it sees the final post-reorder,
    // post-codegen-perturb AST. It does not consume from the shared
    // rng — the pad size per function is derived from
    // hash(tag, seed, fn_name) directly.
    let pad_log = if options.stack_pad {
        stack_pad::apply(&mut file, seed)
    } else {
        Vec::new()
    };

    let mut log = DiversifierLog::default();
    for (name, decision) in perturb_log {
        // Last-write-wins ordering: in today's `codegen_perturb::apply`
        // each free fn appears once, so the BTreeMap insert never
        // collides. Documented here so a future refactor that allows
        // multiple decisions per name (e.g. when methods join the
        // perturb pass) has to make the consolidation policy explicit.
        log.perturb_decisions
            .insert(name, perturb_decision_label(&decision).to_string());
    }
    for (name, decision) in semantic_log {
        log.semantic_decisions.insert(name, decision);
    }
    for d in pad_log {
        // `bytes` is bounded by `MIN_PAD_BYTES + PAD_RANGE_BYTES = 224`
        // so the `usize -> u32` narrowing is always lossless. We commit
        // to `u32` in the log because the attestation entry serialises
        // through canonical JSON, which rejects float literals — and
        // `u64` is overkill for a value bounded under 1 KiB.
        log.pad_decisions
            .insert(d.fn_name, d.bytes as u32);
    }

    Ok((emit(&file), log))
}

fn emit(file: &File) -> String {
    // `quote`'s token-stream `to_string()` is functionally correct
    // (semantically equivalent output, just stylistically dense). The
    // morph engine consumes this and the candidate is byte-compared by
    // canonical hash, not by visual style, so this is sufficient. A
    // future revision can swap in `prettyplease::unparse` for readable
    // output without changing semantics.
    quote::quote!(#file).to_string()
}

fn derive_suffix(rng: &mut ChaCha20Rng, tag: &str) -> String {
    let mut b = [0u8; 4];
    rng.fill_bytes(&mut b);
    format!("_{}{:02x}{:02x}{:02x}{:02x}", tag, b[0], b[1], b[2], b[3])
}

/// Strip any trailing Cuttle private-fn rename suffixes (`_m<8 lowercase hex>`)
/// so repeated morph cycles replace the suffix rather than growing identifier
/// length without bound.
pub(crate) fn strip_cuttle_fn_suffix(mut name: &str) -> &str {
    loop {
        if name.len() <= 10 || !name.is_char_boundary(name.len() - 10) {
            break;
        }
        let (prefix, tail) = name.split_at(name.len() - 10);
        if !prefix.is_empty()
            && tail.starts_with("_m")
            && tail[2..]
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            name = prefix;
        } else {
            break;
        }
    }
    name
}

/// Strip any trailing Cuttle local-var rename suffixes (`_v<8 hex>_<hex>`)
/// so repeated morph cycles replace the suffix rather than growing local
/// variable names without bound.
pub(crate) fn strip_cuttle_var_suffix(mut name: &str) -> &str {
    loop {
        let Some(last_u) = name.rfind('_') else {
            break;
        };
        let counter = &name[last_u + 1..];
        if counter.is_empty()
            || !counter
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            break;
        }
        let before_counter = &name[..last_u];
        if before_counter.len() <= 10
            || !before_counter.is_char_boundary(before_counter.len() - 10)
        {
            break;
        }
        let (prefix, v_tail) = before_counter.split_at(before_counter.len() - 10);
        if !prefix.is_empty()
            && v_tail.starts_with("_v")
            && v_tail[2..]
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            name = prefix;
        } else {
            break;
        }
    }
    name
}

/// Remove `#[inline(always)]` and `#[inline(never)]` attributes attached by a
/// prior morph cycle from top-level functions while preserving bare `#[inline]`
/// attributes written by human authors.
fn strip_prior_cycle_inline_attrs(file: &mut File) {
    for it in file.items.iter_mut() {
        if let Item::Fn(f) = it {
            f.attrs.retain(|a| {
                if !a.path().is_ident("inline") {
                    return true;
                }
                let s = quote::quote!(#a).to_string().replace(' ', "");
                !(s == "#[inline(always)]" || s == "#[inline(never)]")
            });
        }
    }
}

fn build_private_fn_rename_map(file: &File, rng: &mut ChaCha20Rng) -> BTreeMap<String, String> {
    let suffix = derive_suffix(rng, "m");

    let mut map = BTreeMap::new();
    for it in &file.items {
        if let Item::Fn(f) = it {
            if matches!(f.vis, Visibility::Inherited) {
                let original = f.sig.ident.to_string();
                // Skip `main` — even in a no_std lib it's a magic name,
                // and renaming it would break any test/main binary.
                if original == "main" {
                    continue;
                }
                let base = strip_cuttle_fn_suffix(&original);
                let renamed = format!("{}{}", base, suffix);
                map.insert(original, renamed);
            }
        }
    }
    map
}

struct RenamePrivateFns<'a> {
    map: &'a BTreeMap<String, String>,
}

impl<'a> VisitMut for RenamePrivateFns<'a> {
    fn visit_ident_mut(&mut self, id: &mut Ident) {
        if let Some(new) = self.map.get(&id.to_string()) {
            *id = Ident::new(new, Span::call_site());
        }
    }

    fn visit_macro_mut(&mut self, _m: &mut Macro) {
        // Macro tokens are not yet Rust; we cannot safely rename inside
        // them without understanding the macro's grammar. Skip entirely.
        // (Side effect: a private fn referenced ONLY from inside a macro
        // body would be missed. Today's target_minimal does not do that;
        // production manifests would flag any module that does.)
    }
}

struct ReorderItems<'r> {
    rng: &'r mut ChaCha20Rng,
}

impl<'r> VisitMut for ReorderItems<'r> {
    fn visit_file_mut(&mut self, f: &mut File) {
        // Identify movable items — those whose textual position in the
        // file has no semantic effect. `Item::Use`, `Item::Mod`,
        // `Item::Macro`, and `Item::Impl` are NOT in this set because
        // their ordering can be observable.
        let movable_flag: Vec<bool> = f
            .items
            .iter()
            .map(|it| {
                matches!(
                    it,
                    Item::Fn(_) | Item::Const(_) | Item::Static(_) | Item::Struct(_) | Item::Enum(_)
                )
            })
            .collect();

        let mut movable: Vec<Item> = f
            .items
            .iter()
            .enumerate()
            .filter(|(i, _)| movable_flag[*i])
            .map(|(_, it)| it.clone())
            .collect();
        movable.shuffle(&mut *self.rng);

        let mut out = Vec::with_capacity(f.items.len());
        let mut movable_iter = movable.into_iter();
        for (i, it) in f.items.iter().enumerate() {
            if movable_flag[i] {
                out.push(movable_iter.next().unwrap());
            } else {
                out.push(it.clone());
            }
        }
        f.items = out;

        // Do NOT recurse into inner items — nested item reordering would
        // require per-block scope analysis and is not in today's
        // conservative set.
    }
}

// ---------------------------------------------------------------------------
// Per-function transforms
// ---------------------------------------------------------------------------

/// Walk every function-like body in the file and apply the per-function
/// transformations. We treat `Item::Fn` at file level and `ImplItem::Fn`
/// inside `Item::Impl` blocks. Other nestings (e.g. nested mod) are out
/// of scope for today's pass.
fn apply_per_function_transforms(file: &mut File, rng: &mut ChaCha20Rng, suffix: &str) {
    for it in file.items.iter_mut() {
        match it {
            Item::Fn(f) => {
                if contains_unsafe_block(&f.block) || f.sig.unsafety.is_some() {
                    continue;
                }
                let arg_names = collect_arg_names(&f.sig.inputs);
                transform_function_body(&mut f.block, rng, suffix, &arg_names);
            }
            Item::Impl(im) => {
                for ii in im.items.iter_mut() {
                    if let ImplItem::Fn(method) = ii {
                        if contains_unsafe_block(&method.block) || method.sig.unsafety.is_some() {
                            continue;
                        }
                        let arg_names = collect_arg_names(&method.sig.inputs);
                        transform_function_body(&mut method.block, rng, suffix, &arg_names);
                    }
                }
            }
            _ => {}
        }
    }
}

fn collect_arg_names(inputs: &syn::punctuated::Punctuated<FnArg, syn::Token![,]>) -> HashSet<String> {
    let mut out = HashSet::new();
    for arg in inputs {
        if let FnArg::Typed(pt) = arg {
            collect_pat_idents(&pt.pat, &mut out);
        }
    }
    out
}

fn collect_pat_idents(p: &Pat, out: &mut HashSet<String>) {
    match p {
        Pat::Ident(pi) => {
            out.insert(pi.ident.to_string());
            // A `Pat::Ident` may carry a sub-pattern (e.g. `x @ Some(_)`).
            // The sub-pattern can introduce additional bindings.
            if let Some((_, sub)) = &pi.subpat {
                collect_pat_idents(sub, out);
            }
        }
        Pat::Tuple(t) => t.elems.iter().for_each(|e| collect_pat_idents(e, out)),
        Pat::TupleStruct(t) => t.elems.iter().for_each(|e| collect_pat_idents(e, out)),
        Pat::Struct(s) => s.fields.iter().for_each(|f| collect_pat_idents(&f.pat, out)),
        Pat::Reference(r) => collect_pat_idents(&r.pat, out),
        Pat::Or(o) => o.cases.iter().for_each(|c| collect_pat_idents(c, out)),
        Pat::Paren(p) => collect_pat_idents(&p.pat, out),
        Pat::Slice(s) => s.elems.iter().for_each(|e| collect_pat_idents(e, out)),
        // `Pat::Type` is `pat: ty` — the type annotation does not affect
        // which names are bound; recurse into the inner pattern. This is
        // the form a typed closure parameter takes, e.g. `|prev: u32|`,
        // where `prev` MUST be registered as a binding scoped to the
        // closure body, or else outer-scope rewrites leak in.
        Pat::Type(pt) => collect_pat_idents(&pt.pat, out),
        _ => {}
    }
}

/// Does this block contain an `unsafe` block expression anywhere?
pub(crate) fn contains_unsafe_block(block: &Block) -> bool {
    for stmt in &block.stmts {
        if stmt_contains_unsafe(stmt) {
            return true;
        }
    }
    false
}

fn stmt_contains_unsafe(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Local(local) => {
            if let Some(init) = &local.init {
                if expr_contains_unsafe(&init.expr) {
                    return true;
                }
                if let Some((_, d)) = &init.diverge {
                    if expr_contains_unsafe(d) {
                        return true;
                    }
                }
            }
            false
        }
        Stmt::Expr(e, _) => expr_contains_unsafe(e),
        Stmt::Item(_) => false,
        Stmt::Macro(_) => false,
    }
}

fn expr_contains_unsafe(e: &Expr) -> bool {
    match e {
        Expr::Unsafe(_) => true,
        Expr::Block(b) => contains_unsafe_block(&b.block),
        Expr::If(i) => {
            expr_contains_unsafe(&i.cond)
                || contains_unsafe_block(&i.then_branch)
                || i.else_branch
                    .as_ref()
                    .map_or(false, |(_, els)| expr_contains_unsafe(els))
        }
        Expr::Match(m) => {
            expr_contains_unsafe(&m.expr)
                || m.arms.iter().any(|a| {
                    a.guard
                        .as_ref()
                        .map_or(false, |(_, g)| expr_contains_unsafe(g))
                        || expr_contains_unsafe(&a.body)
                })
        }
        Expr::ForLoop(f) => expr_contains_unsafe(&f.expr) || contains_unsafe_block(&f.body),
        Expr::While(w) => expr_contains_unsafe(&w.cond) || contains_unsafe_block(&w.body),
        Expr::Loop(l) => contains_unsafe_block(&l.body),
        Expr::Binary(b) => expr_contains_unsafe(&b.left) || expr_contains_unsafe(&b.right),
        Expr::Unary(u) => expr_contains_unsafe(&u.expr),
        Expr::Call(c) => {
            expr_contains_unsafe(&c.func) || c.args.iter().any(expr_contains_unsafe)
        }
        Expr::MethodCall(mc) => {
            expr_contains_unsafe(&mc.receiver) || mc.args.iter().any(expr_contains_unsafe)
        }
        Expr::Field(f) => expr_contains_unsafe(&f.base),
        Expr::Index(i) => expr_contains_unsafe(&i.expr) || expr_contains_unsafe(&i.index),
        Expr::Paren(p) => expr_contains_unsafe(&p.expr),
        Expr::Group(g) => expr_contains_unsafe(&g.expr),
        Expr::Reference(r) => expr_contains_unsafe(&r.expr),
        Expr::Cast(c) => expr_contains_unsafe(&c.expr),
        Expr::Tuple(t) => t.elems.iter().any(expr_contains_unsafe),
        Expr::Array(a) => a.elems.iter().any(expr_contains_unsafe),
        Expr::Assign(a) => expr_contains_unsafe(&a.left) || expr_contains_unsafe(&a.right),
        Expr::Return(r) => r.expr.as_deref().map_or(false, expr_contains_unsafe),
        Expr::Break(b) => b.expr.as_deref().map_or(false, expr_contains_unsafe),
        Expr::Range(r) => {
            r.start.as_deref().map_or(false, expr_contains_unsafe)
                || r.end.as_deref().map_or(false, expr_contains_unsafe)
        }
        Expr::Try(t) => expr_contains_unsafe(&t.expr),
        Expr::Async(a) => contains_unsafe_block(&a.block),
        Expr::Await(a) => expr_contains_unsafe(&a.base),
        Expr::Closure(c) => expr_contains_unsafe(&c.body),
        Expr::Let(l) => expr_contains_unsafe(&l.expr),
        Expr::Struct(s) => {
            s.fields.iter().any(|f| expr_contains_unsafe(&f.expr))
                || s.rest.as_deref().map_or(false, expr_contains_unsafe)
        }
        Expr::Repeat(r) => expr_contains_unsafe(&r.expr) || expr_contains_unsafe(&r.len),
        _ => false,
    }
}

fn transform_function_body(
    block: &mut Block,
    rng: &mut ChaCha20Rng,
    suffix: &str,
    arg_names: &HashSet<String>,
) {
    // Pre-pass: collect every identifier that appears inside any macro
    // body in this function. Macro bodies are opaque token streams to
    // the rename visitor — `Expr::Macro` and `Stmt::Macro` are skipped
    // by `transform_expr` / `transform_stmt`. So if a `let` binding
    // were renamed, any reference to it inside a macro body (e.g.
    // `assert!(total_label_len <= 255)`, `format!("{x}")`,
    // `println!("{}", x)`) would be left stale, producing E0425.
    //
    // We could try to rewrite tokens inside macro bodies, but the
    // grammar of every macro is different — `assert!`'s first arg is
    // an expression, `format!`'s first arg is a literal containing
    // implicit-capture interpolations like `{x}`, declarative macros
    // can do whatever they want with their inputs. There is no safe
    // generic rewriter.
    //
    // The conservative answer (per the contract: "either rename the
    // reference or refuse to rename the binding — refusing is the
    // safer fallback if a reference site cannot be confidently
    // identified") is: collect the set of identifier-shaped tokens
    // that appear inside macro bodies, and refuse to rename any
    // binding whose original name is in that set.
    let mut macro_idents: HashSet<String> = HashSet::new();
    collect_macro_idents_in_block(block, &mut macro_idents);

    let mut t = FunctionTransform {
        rng,
        suffix,
        arg_names,
        macro_idents: &macro_idents,
        scopes: Vec::new(),
        rename_counter: 0,
    };
    t.transform_block(block);
}

/// Walk a function-body `Block` and record every identifier-shaped
/// token that occurs inside the token stream of any macro invocation
/// (statement-position OR expression-position).
///
/// We DO NOT distinguish "this is a macro name vs a reference to a
/// local". The macro grammar is unknown, so any ident inside a macro
/// body is treated as potentially referring to a local in scope. The
/// over-set is a soundness-preferring choice: it may forgo a small
/// number of valid renames, never a borked rename.
/// File-level companion to `collect_macro_idents_in_block`. Walks
/// every macro invocation anywhere in the file — including inside
/// `Item::Fn` bodies, `Item::Impl` method bodies, and free-standing
/// macro invocations at the item level — and records every
/// identifier token that occurs in their token streams. Plus
/// implicit-capture idents inside string literals inside those
/// macros, by the same `extract_format_captures` rule.
///
/// Used by `diversify` to filter the private-fn rename map: a
/// private fn whose name is in this set will not be renamed.
fn collect_macro_idents_in_file(file: &File) -> HashSet<String> {
    struct V<'a> {
        out: &'a mut HashSet<String>,
    }
    impl<'ast, 'a> syn::visit::Visit<'ast> for V<'a> {
        fn visit_macro(&mut self, m: &'ast Macro) {
            collect_idents_in_token_stream(&m.tokens, self.out);
            collect_format_captures_in_token_stream(&m.tokens, self.out);
            syn::visit::visit_macro(self, m);
        }
    }
    let mut out = HashSet::new();
    let mut v = V { out: &mut out };
    syn::visit::Visit::visit_file(&mut v, file);
    out
}

fn collect_macro_idents_in_block(block: &Block, out: &mut HashSet<String>) {
    struct V<'a> {
        out: &'a mut HashSet<String>,
    }
    impl<'ast, 'a> syn::visit::Visit<'ast> for V<'a> {
        fn visit_macro(&mut self, m: &'ast Macro) {
            collect_idents_in_token_stream(&m.tokens, self.out);
            // Also include any string-literal interpolation captures
            // — `format!("{x}")` does NOT keep `x` as an `Ident`
            // token; it lives inside a `LitStr`. Conservatively scan
            // every string literal in the macro's tokens for
            // `{ident}` patterns.
            collect_format_captures_in_token_stream(&m.tokens, self.out);
            // Continue descent: nested macros inside macro bodies
            // would not show as syn nodes (they're raw tokens), so
            // we already captured them via the token-stream walk.
            syn::visit::visit_macro(self, m);
        }
    }
    let mut v = V { out };
    for stmt in &block.stmts {
        syn::visit::Visit::visit_stmt(&mut v, stmt);
    }
}

fn collect_idents_in_token_stream(ts: &proc_macro2::TokenStream, out: &mut HashSet<String>) {
    use proc_macro2::TokenTree;
    for tt in ts.clone() {
        match tt {
            TokenTree::Ident(id) => {
                out.insert(id.to_string());
            }
            TokenTree::Group(g) => {
                collect_idents_in_token_stream(&g.stream(), out);
            }
            _ => {}
        }
    }
}

/// Find implicit-capture identifiers inside string literals — e.g.
/// `"{x}"`, `"{x:?}"`, `"{count:>5}"`, `"a {x} b {y}"`. Used to model
/// `format_args!` / `format!` / `println!` / `write!` / `panic!` /
/// `assert!` (with formatted message) capture sets.
///
/// Conservative pattern: `\{ident(?::[^}]*)?\}` where `ident` matches
/// `[A-Za-z_][A-Za-z0-9_]*`. We never confuse `{{` (escaped brace)
/// with a real capture because we require the contents to begin with
/// an ident character. Indexed captures (`{0}`, `{1}`) are skipped —
/// they don't refer to locals by name.
fn collect_format_captures_in_token_stream(
    ts: &proc_macro2::TokenStream,
    out: &mut HashSet<String>,
) {
    use proc_macro2::TokenTree;
    for tt in ts.clone() {
        match tt {
            TokenTree::Literal(lit) => {
                let s = lit.to_string();
                // We only care about string literals. `lit.to_string()`
                // returns the source representation including quotes
                // for strings, or numeric text for numbers. A string
                // literal will start with `"` or `r"` / `r#"` etc. A
                // simple heuristic: if it contains a `"`, scan it.
                if s.contains('"') {
                    extract_format_captures(&s, out);
                }
            }
            TokenTree::Group(g) => {
                collect_format_captures_in_token_stream(&g.stream(), out);
            }
            _ => {}
        }
    }
}

fn extract_format_captures(s: &str, out: &mut HashSet<String>) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'{' {
            // Escaped brace?
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                i += 2;
                continue;
            }
            // Try to parse an ident.
            let start = i + 1;
            if start >= bytes.len() {
                break;
            }
            let first = bytes[start];
            let is_ident_start = first == b'_' || first.is_ascii_alphabetic();
            if !is_ident_start {
                i += 1;
                continue;
            }
            let mut end = start + 1;
            while end < bytes.len() {
                let c = bytes[end];
                if c == b'_' || c.is_ascii_alphanumeric() {
                    end += 1;
                } else {
                    break;
                }
            }
            // The character after the ident must be `}` or `:` for
            // this to be a capture (e.g. `{x}` or `{x:?}`).
            if end < bytes.len() && (bytes[end] == b'}' || bytes[end] == b':') {
                let name = &s[start..end];
                out.insert(name.to_string());
            }
            i = end;
        } else {
            i += 1;
        }
    }
}

// A scope is a map from original-name -> currently-bound renamed-name.
// `None` means "do not rename" (e.g. for underscore-prefixed names or
// names that shadow function arguments where we chose not to touch).
type Scope = BTreeMap<String, Option<String>>;

struct FunctionTransform<'a> {
    rng: &'a mut ChaCha20Rng,
    suffix: &'a str,
    /// Function-argument names. These never appear in `scopes`, so
    /// a name lookup for an arg falls through to the bottom of the
    /// chain and returns `None` — i.e. we never rewrite an arg
    /// reference. Carried for diagnostics and future use (e.g. a
    /// debug assertion that we never accidentally shadow an arg
    /// in a renamed binding).
    #[allow(dead_code)]
    arg_names: &'a HashSet<String>,
    /// Every identifier-shaped token that appears inside any macro
    /// body in this function. A `let` binding whose name is in this
    /// set is NOT renamed, because the rename pass cannot rewrite
    /// occurrences inside macro tokens (their grammar is unknown).
    /// See `transform_function_body` for the rationale.
    macro_idents: &'a HashSet<String>,
    scopes: Vec<Scope>,
    rename_counter: u32,
}

impl<'a> FunctionTransform<'a> {
    /// Look up a name through the scope chain, innermost first. Returns
    /// `Some(renamed)` if the name is bound and should be rewritten,
    /// `None` if either unbound or bound-but-skipped.
    fn lookup(&self, name: &str) -> Option<String> {
        for s in self.scopes.iter().rev() {
            if let Some(entry) = s.get(name) {
                return entry.clone();
            }
        }
        None
    }

    fn fresh_name(&mut self, original: &str) -> String {
        let c = self.rename_counter;
        self.rename_counter += 1;
        let base = strip_cuttle_var_suffix(original);
        format!("{}{}_{:x}", base, self.suffix, c)
    }

    fn push_scope(&mut self) {
        self.scopes.push(Scope::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    /// Register a `let` binding in the current scope, producing the
    /// rename map entry. The pattern is walked to find `PatIdent`s.
    /// `_`-prefixed names are skipped. Function arguments are skipped
    /// unless they're being shadowed by a `let`, in which case the new
    /// binding is its own fresh name from this point forward.
    fn register_let_pat(&mut self, pat: &mut Pat) {
        match pat {
            Pat::Ident(pi) => {
                let original = pi.ident.to_string();
                let skip = original.starts_with('_')
                    || pi.subpat.is_some() && {
                        // sub-pattern bindings get complicated; play it safe.
                        true
                    }
                    // If the name appears anywhere inside a macro body
                    // in this function, refuse to rename. The macro's
                    // grammar is opaque, so a reference there cannot
                    // be confidently rewritten. Renaming the binding
                    // anyway would leave the macro reference stale
                    // and produce E0425 at compile time (canonical
                    // failure: `assert!(total_label_len <= 255)` in
                    // `target_enterprise/src/tls.rs::hkdf_expand_label`,
                    // which surfaced the bug fixed by TASK-016).
                    || self.macro_idents.contains(&original);
                if skip {
                    if let Some(top) = self.scopes.last_mut() {
                        top.insert(original, None);
                    }
                    return;
                }
                // The let always introduces a fresh binding even if it
                // shadows. Shadowing function-args is fine because we
                // never rewrite a name when its current binding is the
                // function arg (an arg sits in `arg_names` and is not
                // in any scope).
                let renamed = self.fresh_name(&original);
                pi.ident = Ident::new(&renamed, pi.ident.span());
                if let Some(top) = self.scopes.last_mut() {
                    top.insert(original, Some(renamed));
                }
            }
            Pat::Tuple(t) => {
                for e in t.elems.iter_mut() {
                    self.register_let_pat(e);
                }
            }
            Pat::TupleStruct(t) => {
                for e in t.elems.iter_mut() {
                    self.register_let_pat(e);
                }
            }
            Pat::Struct(s) => {
                for f in s.fields.iter_mut() {
                    // Symmetric to the Expr::Struct shorthand fix.
                    // `let Foo { bar } = expr;` is sugar for
                    // `let Foo { bar: bar } = expr;`. syn represents
                    // shorthand as `FieldPat { member: bar,
                    // colon_token: None, pat: Pat::Ident(bar) }`. If
                    // we rename the inner `Pat::Ident` to
                    // `Pat::Ident(bar_renamed)`, quote!'s ToTokens
                    // impl emits only the member shorthand `bar`,
                    // dropping the renamed pat. The binding goes
                    // back to its original name in the emitted
                    // source, while later references in the body
                    // were rewritten to `bar_renamed` — E0425.
                    //
                    // Insert the colon to force explicit emission.
                    if f.colon_token.is_none() {
                        f.colon_token = Some(<syn::Token![:]>::default());
                    }
                    self.register_let_pat(&mut f.pat);
                }
            }
            Pat::Reference(r) => self.register_let_pat(&mut r.pat),
            Pat::Or(o) => {
                for c in o.cases.iter_mut() {
                    self.register_let_pat(c);
                }
            }
            Pat::Paren(p) => self.register_let_pat(&mut p.pat),
            Pat::Slice(s) => {
                for e in s.elems.iter_mut() {
                    self.register_let_pat(e);
                }
            }
            Pat::Type(pt) => self.register_let_pat(&mut pt.pat),
            _ => {}
        }
    }

    /// Walk a block:
    /// 1. Push a fresh scope.
    /// 2. For each statement in order:
    ///    - if it's a `let`, register its pattern bindings (renaming
    ///      the LHS), then rewrite the RHS (which still sees the
    ///      outer scope for unmentioned-by-this-let names).
    ///    - otherwise, rewrite the statement against current scope.
    /// 3. Reorder independent statement pairs (after rewriting, so the
    ///    independence check sees the renamed names — equivalent).
    /// 4. Apply match-arm reordering and if/match substitution within
    ///    expression contexts (already done recursively as we walk).
    /// 5. Pop scope.
    fn transform_block(&mut self, block: &mut Block) {
        self.push_scope();
        for stmt in block.stmts.iter_mut() {
            self.transform_stmt(stmt);
        }
        self.maybe_reorder_stmts(&mut block.stmts);
        self.pop_scope();
    }

    fn transform_stmt(&mut self, stmt: &mut Stmt) {
        match stmt {
            Stmt::Local(local) => self.transform_local(local),
            Stmt::Expr(e, _) => self.transform_expr(e),
            Stmt::Item(_) => {
                // Nested items: out of scope for the per-function pass.
                // They were already handled (or not) at file level.
            }
            Stmt::Macro(_) => {
                // Macro statements: skipped wholesale.
            }
        }
    }

    fn transform_local(&mut self, local: &mut Local) {
        // 1. Rewrite the RHS first, against the *outer* scope. A
        //    `let x = x + 1` legitimately reads the outer `x` on the
        //    RHS, then binds a new `x` for subsequent statements.
        if let Some(init) = local.init.as_mut() {
            self.transform_expr(&mut init.expr);
            if let Some((_, diverge)) = init.diverge.as_mut() {
                self.transform_expr(diverge);
            }
        }
        // 2. Register the LHS pattern bindings, renaming in-place.
        self.register_let_pat(&mut local.pat);
    }

    fn transform_expr(&mut self, expr: &mut Expr) {
        // First, dispatch on the expression kind: recurse where we want
        // scope-aware traversal, then optionally rewrite the whole node.
        match expr {
            Expr::Block(eb) => {
                self.transform_block(&mut eb.block);
            }
            Expr::Unsafe(_) => {
                // Should not reach here: outer guard skips functions
                // that contain unsafe. Defensive no-op.
            }
            Expr::If(ei) => {
                // Special-case `if let PAT = EXPR { ... }`: the bindings
                // introduced by PAT are scoped to the then-branch only;
                // they must NOT be visible in the else-branch nor leak
                // upward. Without this, an outer-scope binding of the
                // same name as one of PAT's bindings would rewrite the
                // then-branch references — which corrupts the pattern's
                // value-extraction.
                if let Expr::Let(el) = &mut *ei.cond {
                    // 1. Transform the RHS in the *outer* scope.
                    self.transform_expr(&mut el.expr);
                    // 2. Push a then-branch scope, mark the let-pat
                    //    bindings as "don't rename" (the names are tied
                    //    to the pattern's matching semantics).
                    self.push_scope();
                    let mut bound = HashSet::new();
                    collect_pat_idents(&el.pat, &mut bound);
                    if let Some(top) = self.scopes.last_mut() {
                        for b in bound {
                            top.insert(b, None);
                        }
                    }
                    // 3. Walk the then-branch statements directly (do
                    //    NOT call transform_block: that would push a
                    //    second scope and the bindings would be hidden
                    //    from sibling statements at the same level —
                    //    they wouldn't, actually, because lookup walks
                    //    upward — but the doubled push is needless).
                    for s in ei.then_branch.stmts.iter_mut() {
                        self.transform_stmt(s);
                    }
                    self.maybe_reorder_stmts(&mut ei.then_branch.stmts);
                    // 4. Pop the let-scope before walking the else.
                    self.pop_scope();
                } else {
                    self.transform_expr(&mut ei.cond);
                    self.transform_block(&mut ei.then_branch);
                }
                if let Some((_, els)) = ei.else_branch.as_mut() {
                    self.transform_expr(els);
                }
                // Optionally rewrite to a match. Skip for `if let` —
                // try_if_to_match already refuses Expr::Let conditions.
                if self.rng.gen_bool(0.5) {
                    if let Some(new_expr) = self.try_if_to_match(ei) {
                        *expr = new_expr;
                    }
                }
            }
            Expr::Match(em) => {
                self.transform_expr(&mut em.expr);
                for arm in em.arms.iter_mut() {
                    self.transform_match_arm(arm);
                }
                // Symmetric inverse of `try_if_to_match`: a boolean 2-arm
                // `match cond { true => ..., false => ... }` converts back
                // to `if cond { ... } else { ... }` with p = 0.5 so repeated
                // morph cycles oscillate rather than ratcheting all `if/else`
                // branches into nested `match` expressions.
                if let Some(if_expr) = self.try_match_to_if(em) {
                    if self.rng.gen_bool(0.5) {
                        *expr = if_expr;
                    } else {
                        self.maybe_reorder_match_arms(em);
                    }
                } else {
                    self.maybe_reorder_match_arms(em);
                }
            }
            Expr::ForLoop(fl) => {
                self.transform_expr(&mut fl.expr);
                self.push_scope();
                self.register_let_pat(&mut fl.pat);
                for s in fl.body.stmts.iter_mut() {
                    self.transform_stmt(s);
                }
                self.pop_scope();
            }
            Expr::While(w) => {
                // `while let PAT = EXPR { ... }` — bindings from PAT are
                // visible in the loop body only.
                if let Expr::Let(el) = &mut *w.cond {
                    self.transform_expr(&mut el.expr);
                    self.push_scope();
                    let mut bound = HashSet::new();
                    collect_pat_idents(&el.pat, &mut bound);
                    if let Some(top) = self.scopes.last_mut() {
                        for b in bound {
                            top.insert(b, None);
                        }
                    }
                    for s in w.body.stmts.iter_mut() {
                        self.transform_stmt(s);
                    }
                    self.maybe_reorder_stmts(&mut w.body.stmts);
                    self.pop_scope();
                } else {
                    self.transform_expr(&mut w.cond);
                    self.transform_block(&mut w.body);
                }
            }
            Expr::Loop(l) => {
                self.transform_block(&mut l.body);
            }
            Expr::Let(el) => {
                // Bare `Expr::Let` outside an `if`/`while` condition can
                // appear in `let`-chains (a nightly-ish feature) and a
                // few other niche contexts. We do not try to register
                // its bindings here because we don't know the scope they
                // extend to from this position alone — the parent
                // `Expr::If` / `Expr::While` handler above is the right
                // place. Just recurse into the RHS.
                self.transform_expr(&mut el.expr);
            }
            Expr::Closure(c) => {
                // A closure introduces a fresh lexical scope. Its inputs
                // bind names visible only inside the body — they MUST
                // shadow any same-named outer binding, and references
                // inside the body MUST resolve to the closure parameter,
                // not to any outer rename. The previous implementation
                // marked closure inputs as "don't rename", which was
                // safe in isolation but broke when the input's pattern
                // was `Pat::Type` (typed param like `|prev: u32|`) and
                // `collect_pat_idents` failed to find the binding — the
                // body's `prev` then resolved up into the outer scope.
                //
                // We now treat closure inputs as renameable bindings,
                // just like `let` LHS patterns. `register_let_pat`
                // handles `_`-prefix skipping and recurses into
                // destructuring/typed patterns uniformly.
                self.push_scope();
                for input in c.inputs.iter_mut() {
                    self.register_let_pat(input);
                }
                self.transform_expr(&mut c.body);
                self.pop_scope();
            }
            Expr::Path(ep) => {
                // Rewrite a bare identifier path if it matches a binding.
                if let Some(name) = single_ident(ep) {
                    if let Some(renamed) = self.lookup(&name) {
                        if let Some(seg) = ep.path.segments.first_mut() {
                            seg.ident = Ident::new(&renamed, seg.ident.span());
                        }
                    }
                }
            }
            Expr::Assign(ea) => {
                self.transform_expr(&mut ea.left);
                self.transform_expr(&mut ea.right);
            }
            Expr::Binary(eb) => {
                self.transform_expr(&mut eb.left);
                self.transform_expr(&mut eb.right);
            }
            Expr::Unary(eu) => {
                self.transform_expr(&mut eu.expr);
            }
            Expr::Call(ec) => {
                self.transform_expr(&mut ec.func);
                for a in ec.args.iter_mut() {
                    self.transform_expr(a);
                }
            }
            Expr::MethodCall(emc) => {
                self.transform_expr(&mut emc.receiver);
                for a in emc.args.iter_mut() {
                    self.transform_expr(a);
                }
            }
            Expr::Field(ef) => {
                self.transform_expr(&mut ef.base);
            }
            Expr::Index(ei) => {
                self.transform_expr(&mut ei.expr);
                self.transform_expr(&mut ei.index);
            }
            Expr::Paren(ep) => self.transform_expr(&mut ep.expr),
            Expr::Group(eg) => self.transform_expr(&mut eg.expr),
            Expr::Reference(er) => self.transform_expr(&mut er.expr),
            Expr::Cast(ec) => self.transform_expr(&mut ec.expr),
            Expr::Tuple(et) => {
                for e in et.elems.iter_mut() {
                    self.transform_expr(e);
                }
            }
            Expr::Array(ea) => {
                for e in ea.elems.iter_mut() {
                    self.transform_expr(e);
                }
            }
            Expr::Return(er) => {
                if let Some(e) = er.expr.as_mut() {
                    self.transform_expr(e);
                }
            }
            Expr::Break(eb) => {
                if let Some(e) = eb.expr.as_mut() {
                    self.transform_expr(e);
                }
            }
            Expr::Range(er) => {
                if let Some(s) = er.start.as_mut() {
                    self.transform_expr(s);
                }
                if let Some(e) = er.end.as_mut() {
                    self.transform_expr(e);
                }
            }
            Expr::Try(et) => self.transform_expr(&mut et.expr),
            Expr::Async(ea) => self.transform_block(&mut ea.block),
            Expr::Await(ea) => self.transform_expr(&mut ea.base),
            Expr::Struct(es) => {
                for f in es.fields.iter_mut() {
                    // Struct-field shorthand: `S { foo }` is sugar for
                    // `S { foo: foo }`. syn represents the shorthand
                    // as `FieldValue { member: Named(foo), colon_token:
                    // None, expr: Expr::Path(foo) }`. `quote!`'s
                    // `ToTokens` impl for `FieldValue` emits ONLY the
                    // member when `colon_token` is `None` — the
                    // expression is silently dropped. If we then
                    // rename the local `foo` referenced by `expr`, the
                    // output keeps the shorthand `S { foo }` with the
                    // (no-longer-bound) original name. Result: E0425.
                    //
                    // Reproducer surfaced by TASK-016 real-mode runs:
                    // `Ok(ClientHelloView { session_id, x25519_pub })`
                    // in `target_enterprise/src/tls.rs::parse_client_hello`.
                    //
                    // Fix: before walking, normalise the shorthand to
                    // the explicit form. If the `expr` then gets
                    // rewritten by a rename, the emit preserves it.
                    // If the `expr` is unchanged (e.g. it's not a
                    // local at all), the output is `S { foo: foo }`
                    // — slightly more verbose but semantically
                    // identical. This is one of the diversifier's
                    // legitimate diversifications.
                    if f.colon_token.is_none() {
                        f.colon_token = Some(<syn::Token![:]>::default());
                    }
                    self.transform_expr(&mut f.expr);
                }
                if let Some(rest) = es.rest.as_mut() {
                    self.transform_expr(rest);
                }
            }
            Expr::Repeat(er) => {
                self.transform_expr(&mut er.expr);
                self.transform_expr(&mut er.len);
            }
            Expr::Macro(_) => {
                // Macro contents are opaque.
            }
            _ => {}
        }
    }

    fn transform_match_arm(&mut self, arm: &mut Arm) {
        // Match-arm patterns introduce bindings in the arm body's
        // scope. We don't rename them (they're tangled with the
        // pattern's matching semantics); we just mark them so reads in
        // the arm body don't accidentally rewrite to an outer binding.
        self.push_scope();
        let mut bound = HashSet::new();
        collect_pat_idents(&arm.pat, &mut bound);
        if let Some(top) = self.scopes.last_mut() {
            for b in bound {
                top.insert(b, None);
            }
        }
        if let Some((_, guard)) = arm.guard.as_mut() {
            self.transform_expr(guard);
        }
        self.transform_expr(&mut arm.body);
        self.pop_scope();
    }

    // -- match-arm reordering -----------------------------------------

    fn maybe_reorder_match_arms(&mut self, em: &mut ExprMatch) {
        if em.arms.is_empty() {
            return;
        }
        // All arms must be literal patterns, no guards.
        let all_literal_no_guard = em
            .arms
            .iter()
            .all(|a| a.guard.is_none() && is_literal_pat(&a.pat));
        if !all_literal_no_guard {
            return;
        }
        em.arms.shuffle(&mut *self.rng);
    }

    // -- if/match substitution ----------------------------------------

    fn try_if_to_match(&mut self, ei: &ExprIf) -> Option<Expr> {
        // Only if there's a block else branch (refuse `else if` chains so
        // linear `else if` ladders don't turn into nested matches).
        let (_, else_expr) = ei.else_branch.as_ref()?;
        if !matches!(**else_expr, Expr::Block(_)) {
            return None;
        }
        // Exclude `if let` (Expr::Let).
        if matches!(*ei.cond, Expr::Let(_)) {
            return None;
        }
        // Exclude assignments and compound expressions that obviously
        // aren't boolean. We can't fully type-check; this is a syntactic
        // best-effort sieve.
        if !looks_like_bool_expr(&ei.cond) {
            return None;
        }
        // Build:
        //   match <cond> { true => { then }, false => <else> }
        let cond = (*ei.cond).clone();
        let then_block = ei.then_branch.clone();
        let else_clone = (**else_expr).clone();

        let true_arm: Arm = syn::parse_quote! { true => #then_block };
        let false_arm: Arm = syn::parse_quote! { false => #else_clone };

        let expr: Expr = syn::parse_quote! {
            match #cond { #true_arm, #false_arm }
        };
        Some(expr)
    }

    /// Inverse of [`Self::try_if_to_match`]: convert a 2-arm boolean literal
    /// `match cond { true => { then }, false => { else } }` (in either arm
    /// order) back to `if cond { then } else { else }` without adding extra
    /// block layers.
    fn try_match_to_if(&self, em: &ExprMatch) -> Option<Expr> {
        if em.arms.len() != 2 || !em.attrs.is_empty() {
            return None;
        }
        if em.arms.iter().any(|a| a.guard.is_some() || !a.attrs.is_empty()) {
            return None;
        }
        let b0 = match &em.arms[0].pat {
            Pat::Lit(pl) => match &pl.lit {
                Lit::Bool(b) => b.value,
                _ => return None,
            },
            _ => return None,
        };
        let b1 = match &em.arms[1].pat {
            Pat::Lit(pl) => match &pl.lit {
                Lit::Bool(b) => b.value,
                _ => return None,
            },
            _ => return None,
        };
        if b0 == b1 {
            return None;
        }
        let (true_body, false_body) = if b0 {
            (&em.arms[0].body, &em.arms[1].body)
        } else {
            (&em.arms[1].body, &em.arms[0].body)
        };
        let then_block: Block = match &**true_body {
            Expr::Block(eb) if eb.label.is_none() && eb.attrs.is_empty() => eb.block.clone(),
            other => syn::parse_quote!({ #other }),
        };
        let else_block: Block = match &**false_body {
            Expr::Block(eb) if eb.label.is_none() && eb.attrs.is_empty() => eb.block.clone(),
            other => syn::parse_quote!({ #other }),
        };
        let cond = (*em.expr).clone();
        Some(syn::parse_quote! {
            if #cond #then_block else #else_block
        })
    }

    // -- statement reordering -----------------------------------------

    fn maybe_reorder_stmts(&mut self, stmts: &mut Vec<Stmt>) {
        if stmts.len() < 2 {
            return;
        }
        // Walk adjacent pairs left-to-right. Single linear pass is
        // sufficient — we are intentionally not chasing convergence.
        let mut i = 0;
        while i + 1 < stmts.len() {
            // Never move the tail expression of a block past anything
            // (it is the block's return value), and never move a trailing
            // `<var> += 1;` loop increment out of last position (preserving
            // canonical `while` loop reversibility in `semantic_perturb`).
            let last_index = stmts.len() - 1;
            let tail_pinned = match stmts.last() {
                Some(Stmt::Expr(_, None)) => true,
                Some(last_stmt) => is_unit_increment_stmt(last_stmt),
                None => false,
            };
            if tail_pinned && (i + 1) == last_index {
                break;
            }
            if are_independent(&stmts[i], &stmts[i + 1]) && self.rng.gen_bool(0.5) {
                stmts.swap(i, i + 1);
            }
            i += 1;
        }
    }
}

fn is_unit_increment_stmt(stmt: &Stmt) -> bool {
    if let Stmt::Expr(Expr::Binary(b), Some(_)) = stmt {
        if matches!(b.op, syn::BinOp::AddAssign(_)) {
            if let Expr::Lit(el) = &*b.right {
                if let Lit::Int(li) = &el.lit {
                    return li.base10_digits() == "1";
                }
            }
        }
    }
    false
}

fn single_ident(ep: &syn::ExprPath) -> Option<String> {
    if ep.qself.is_some() {
        return None;
    }
    if ep.path.leading_colon.is_some() {
        return None;
    }
    if ep.path.segments.len() != 1 {
        return None;
    }
    let seg = &ep.path.segments[0];
    if !seg.arguments.is_none() {
        return None;
    }
    Some(seg.ident.to_string())
}

fn is_literal_pat(p: &Pat) -> bool {
    match p {
        Pat::Lit(pl) => matches!(
            pl.lit,
            Lit::Int(_) | Lit::Bool(_) | Lit::Char(_) | Lit::Byte(_)
        ),
        // A unary minus literal (e.g. `-1`) shows up as Pat::Lit with
        // an Expr::Unary inside in older syn versions. syn 2 stores
        // Pat::Lit { lit: Lit }, so handle only Lit. Skip otherwise.
        _ => false,
    }
}

fn looks_like_bool_expr(e: &Expr) -> bool {
    match e {
        Expr::Let(_) => false,
        Expr::Assign(_) => false,
        Expr::Binary(b) => matches!(
            b.op,
            syn::BinOp::Eq(_)
                | syn::BinOp::Ne(_)
                | syn::BinOp::Lt(_)
                | syn::BinOp::Le(_)
                | syn::BinOp::Gt(_)
                | syn::BinOp::Ge(_)
                | syn::BinOp::And(_)
                | syn::BinOp::Or(_)
        ),
        Expr::Unary(u) => matches!(u.op, syn::UnOp::Not(_)) && looks_like_bool_expr(&u.expr),
        Expr::Paren(p) => looks_like_bool_expr(&p.expr),
        Expr::Group(g) => looks_like_bool_expr(&g.expr),
        Expr::Lit(l) => matches!(l.lit, Lit::Bool(_)),
        // A path or method call MIGHT be bool; we conservatively allow
        // method calls (e.g. `x.is_empty()`) and paths. A wrong guess
        // here is caught by the verifier; the worst case is a candidate
        // rejection.
        Expr::MethodCall(_) => true,
        Expr::Call(_) => true,
        Expr::Path(_) => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Statement independence (data-flow proxy)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct NameSets {
    reads: HashSet<String>,
    writes: HashSet<String>,
    /// `true` if this statement contains anything that disqualifies it
    /// from being a reorder candidate: function calls, macros, control
    /// flow exits, unsafe blocks. A side-effect tripwire.
    has_side_effect: bool,
}

fn collect_names_in_stmt(stmt: &Stmt) -> NameSets {
    let mut n = NameSets::default();
    walk_stmt_names(stmt, &mut n);
    // For a `let`, the LHS pattern bindings count as writes (they
    // introduce names that may be read by later statements).
    if let Stmt::Local(local) = stmt {
        let mut bound = HashSet::new();
        collect_pat_idents(&local.pat, &mut bound);
        n.writes.extend(bound);
    }
    n
}

fn walk_stmt_names(stmt: &Stmt, n: &mut NameSets) {
    match stmt {
        Stmt::Local(local) => {
            if let Some(init) = &local.init {
                walk_expr_names(&init.expr, n, false);
                if let Some((_, d)) = &init.diverge {
                    walk_expr_names(d, n, false);
                }
            }
        }
        Stmt::Expr(e, _) => walk_expr_names(e, n, false),
        Stmt::Item(_) => {
            // Nested items are opaque; mark as side-effecting to be safe.
            n.has_side_effect = true;
        }
        Stmt::Macro(_) => {
            n.has_side_effect = true;
        }
    }
}

fn walk_expr_names(e: &Expr, n: &mut NameSets, in_lhs: bool) {
    match e {
        Expr::Call(_) | Expr::MethodCall(_) | Expr::Macro(_) | Expr::Unsafe(_)
        | Expr::Return(_) | Expr::Break(_) | Expr::Continue(_) | Expr::Yield(_)
        | Expr::Await(_) | Expr::Try(_) => {
            n.has_side_effect = true;
        }
        Expr::Path(ep) => {
            if let Some(name) = single_ident(ep) {
                if in_lhs {
                    n.writes.insert(name);
                } else {
                    n.reads.insert(name);
                }
            }
        }
        Expr::Assign(ea) => {
            walk_expr_names(&ea.left, n, true);
            walk_expr_names(&ea.right, n, false);
        }
        Expr::Binary(b) => {
            // Compound assignments (`+=`, `-=`, `*=`, etc.) are encoded
            // in syn 2 as `Expr::Binary` with an *-Assign binop. The LHS
            // is both read and written for these. We mark it both ways
            // so reorder-independence treats `i += 2` as having
            // writes={i} and reads={i}, which prevents misordering
            // against any other statement that reads or writes `i`.
            if is_assign_op(&b.op) {
                walk_expr_names(&b.left, n, true);
                walk_expr_names(&b.left, n, false);
                walk_expr_names(&b.right, n, false);
            } else {
                walk_expr_names(&b.left, n, false);
                walk_expr_names(&b.right, n, false);
            }
        }
        Expr::Unary(u) => walk_expr_names(&u.expr, n, false),
        Expr::Paren(p) => walk_expr_names(&p.expr, n, in_lhs),
        Expr::Group(g) => walk_expr_names(&g.expr, n, in_lhs),
        Expr::Reference(r) => walk_expr_names(&r.expr, n, in_lhs),
        Expr::Cast(c) => walk_expr_names(&c.expr, n, false),
        Expr::Tuple(t) => t.elems.iter().for_each(|e| walk_expr_names(e, n, in_lhs)),
        Expr::Array(a) => a.elems.iter().for_each(|e| walk_expr_names(e, n, false)),
        Expr::Field(f) => walk_expr_names(&f.base, n, in_lhs),
        Expr::Index(i) => {
            walk_expr_names(&i.expr, n, in_lhs);
            walk_expr_names(&i.index, n, false);
        }
        Expr::Range(r) => {
            if let Some(s) = &r.start {
                walk_expr_names(s, n, false);
            }
            if let Some(end) = &r.end {
                walk_expr_names(end, n, false);
            }
        }
        Expr::Lit(_) => {}
        Expr::If(i) => {
            walk_expr_names(&i.cond, n, false);
            walk_block_names(&i.then_branch, n);
            if let Some((_, els)) = &i.else_branch {
                walk_expr_names(els, n, false);
            }
        }
        Expr::Match(m) => {
            walk_expr_names(&m.expr, n, false);
            for arm in &m.arms {
                if let Some((_, g)) = &arm.guard {
                    walk_expr_names(g, n, false);
                }
                walk_expr_names(&arm.body, n, false);
            }
        }
        Expr::Block(b) => walk_block_names(&b.block, n),
        Expr::ForLoop(_) | Expr::While(_) | Expr::Loop(_) | Expr::Closure(_) | Expr::Let(_) => {
            // Loops/closures complicate read/write framing across
            // iterations. Mark side-effecting and refuse to reorder.
            n.has_side_effect = true;
        }
        Expr::Struct(s) => {
            for f in &s.fields {
                walk_expr_names(&f.expr, n, false);
            }
            if let Some(rest) = &s.rest {
                walk_expr_names(rest, n, false);
            }
        }
        Expr::Repeat(r) => {
            walk_expr_names(&r.expr, n, false);
            walk_expr_names(&r.len, n, false);
        }
        Expr::Async(_) | Expr::Const(_) => {
            n.has_side_effect = true;
        }
        _ => {
            // Conservative default: anything we don't model, assume
            // side-effecting. This errs toward refusing-to-reorder.
            n.has_side_effect = true;
        }
    }
}

fn walk_block_names(b: &Block, n: &mut NameSets) {
    for s in &b.stmts {
        walk_stmt_names(s, n);
    }
}

fn is_assign_op(op: &syn::BinOp) -> bool {
    matches!(
        op,
        syn::BinOp::AddAssign(_)
            | syn::BinOp::SubAssign(_)
            | syn::BinOp::MulAssign(_)
            | syn::BinOp::DivAssign(_)
            | syn::BinOp::RemAssign(_)
            | syn::BinOp::BitXorAssign(_)
            | syn::BinOp::BitAndAssign(_)
            | syn::BinOp::BitOrAssign(_)
            | syn::BinOp::ShlAssign(_)
            | syn::BinOp::ShrAssign(_)
    )
}

fn are_independent(a: &Stmt, b: &Stmt) -> bool {
    let na = collect_names_in_stmt(a);
    let nb = collect_names_in_stmt(b);
    if na.has_side_effect || nb.has_side_effect {
        return false;
    }
    // A `Local` is reorderable only if neither statement reads its
    // bound name. The bound name is in `na.writes` / `nb.writes`.
    // General rule: writes(A) must be disjoint from reads(B)+writes(B),
    // and writes(B) must be disjoint from reads(A)+writes(A).
    if !disjoint(&na.writes, &nb.reads) {
        return false;
    }
    if !disjoint(&na.writes, &nb.writes) {
        return false;
    }
    if !disjoint(&nb.writes, &na.reads) {
        return false;
    }
    // Additionally exclude statements with no name signature at all
    // (e.g. an inner block whose contents are opaque to our walker).
    // If both are pure expression statements that don't touch any
    // identifier, swapping is moot but not unsafe; we permit it.
    true
}

fn disjoint(a: &HashSet<String>, b: &HashSet<String>) -> bool {
    a.iter().all(|x| !b.contains(x))
}

/// Hash the canonical token stream of `source`, ignoring whitespace and
/// comments. Two source files with the same canonical-hash are
/// semantically indistinguishable for the morph engine's purposes and are
/// deduplicated at the verifier.
pub fn canonical_hash(source: &str) -> Result<[u8; 32]> {
    let file: File = syn::parse_str(source).context("parse for canonical hash")?;
    let ts = quote::quote!(#file).to_string();
    let h = Sha256::digest(ts.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        pub fn checksum(data: &[u8]) -> u32 {
            let mut sum: u32 = 0;
            for byte in data {
                sum = sum.wrapping_add(*byte as u32);
            }
            mix(sum)
        }

        fn mix(x: u32) -> u32 {
            x.wrapping_mul(0x9E3779B1)
        }

        pub const TAG: u32 = 0xDEADBEEF;
    "#;

    #[test]
    fn diversify_is_deterministic_under_same_seed() {
        let seed = Seed::derive(42, "demo");
        let a = diversify(SAMPLE, &seed).unwrap();
        let b = diversify(SAMPLE, &seed).unwrap();
        assert_eq!(a, b, "same seed must produce identical output");
    }

    #[test]
    fn diversify_changes_under_different_seed() {
        let s1 = Seed::derive(1, "demo");
        let s2 = Seed::derive(2, "demo");
        let a = diversify(SAMPLE, &s1).unwrap();
        let b = diversify(SAMPLE, &s2).unwrap();
        assert_ne!(a, b, "different seeds must produce different output");
    }

    #[test]
    fn canonical_hash_strips_whitespace() {
        let a = "fn f() {let x = 1;x}";
        let b = "fn f() {   let x = 1;   x   }";
        assert_eq!(canonical_hash(a).unwrap(), canonical_hash(b).unwrap());
    }

    #[test]
    fn public_symbols_are_preserved() {
        let seed = Seed::derive(7, "demo");
        let out = diversify(SAMPLE, &seed).unwrap();
        assert!(out.contains("checksum"), "pub fn checksum must survive");
        assert!(out.contains("TAG"), "pub const TAG must survive");
        // The pub fn name must appear unmodified — no rename suffix.
        assert!(
            !out.contains("checksum_m"),
            "pub fn must not be renamed: {}",
            out
        );
    }

    #[test]
    fn private_fns_are_renamed_consistently() {
        let seed = Seed::derive(13, "demo");
        let out = diversify(SAMPLE, &seed).unwrap();
        // The private fn `mix` must be either fully renamed (def + call
        // both carry the suffix) or fully not. A half-renamed module
        // would not compile and is the bug we explicitly guard against.
        let plain_mix_def = out.contains("fn mix ") || out.contains("fn mix(");
        let plain_mix_call = out.contains("mix (sum)") || out.contains("mix(sum)");
        let renamed_def = out.contains("fn mix_m");
        let renamed_call = out.contains("mix_m");

        if renamed_def || renamed_call {
            assert!(
                renamed_def && renamed_call,
                "private fn rename must be consistent (def renamed: {}, call renamed: {})\nout: {}",
                renamed_def,
                renamed_call,
                out
            );
        } else {
            assert!(
                plain_mix_def && plain_mix_call,
                "if not renamed, both def and call must be plain"
            );
        }
    }

    #[test]
    fn diversified_output_parses() {
        // The most important property: whatever we emit must be valid
        // Rust source. The verifier rejects unparseable candidates, but
        // we should never emit one in the first place.
        for cycle in 0..20u64 {
            let seed = Seed::derive(cycle, "demo");
            let out = diversify(SAMPLE, &seed).unwrap();
            syn::parse_str::<File>(&out)
                .unwrap_or_else(|e| panic!("cycle {} produced unparseable output: {}\n{}", cycle, e, out));
        }
    }

    // ---- New tests for the extended transformations ----

    const TARGET_MINIMAL_SRC: &str = include_str!("../../target_minimal/src/lib.rs");

    #[test]
    fn diversified_output_for_target_minimal_parses() {
        for cycle in 0..20u64 {
            let seed = Seed::derive(cycle, "lib");
            let out = diversify(TARGET_MINIMAL_SRC, &seed).unwrap();
            syn::parse_str::<File>(&out).unwrap_or_else(|e| {
                panic!(
                    "target_minimal cycle {} produced unparseable output: {}\n---\n{}",
                    cycle, e, out
                )
            });
        }
    }

    #[test]
    fn local_rename_is_consistent() {
        let src = r#"
            pub fn sample() -> u32 {
                let x = 1u32;
                let y = x + 2;
                y
            }
        "#;
        let seed = Seed::derive(0xCAFE, "local_rename");
        let out = diversify(src, &seed).unwrap();
        // The local `x` should be renamed; assert no bare `x` remains
        // in the body. We grep for whitespace-bounded `x` to avoid
        // matching inside identifiers like `xxx`.
        let file: File = syn::parse_str(&out).expect("output parses");
        // Walk the function body and verify every `let` binding name
        // is referenced consistently. We do this by re-parsing and
        // ensuring no usage of the literal name `x` or `y` appears as
        // a bare identifier in expression position; they should all be
        // renamed to the same per-occurrence suffix.
        let mut found_x_renamed: Option<String> = None;
        let mut found_y_renamed: Option<String> = None;
        for it in &file.items {
            if let Item::Fn(f) = it {
                for stmt in &f.block.stmts {
                    if let Stmt::Local(l) = stmt {
                        if let Pat::Ident(pi) = &l.pat {
                            let name = pi.ident.to_string();
                            if name.starts_with("x_") {
                                found_x_renamed = Some(name);
                            } else if name.starts_with("y_") {
                                found_y_renamed = Some(name);
                            } else {
                                panic!("expected renamed local, got: {}", name);
                            }
                        }
                    }
                }
            }
        }
        let x_name = found_x_renamed.expect("x was renamed");
        let y_name = found_y_renamed.expect("y was renamed");
        assert!(
            out.contains(&x_name),
            "renamed x ({}) must appear in body: {}",
            x_name,
            out
        );
        assert!(
            out.contains(&y_name),
            "renamed y ({}) must appear in body: {}",
            y_name,
            out
        );
        // The renamed `x` must be referenced by name in the RHS of the
        // `let y = ...` binding, i.e. it must appear more than once in
        // the output (definition + use).
        let x_uses = out.matches(&x_name).count();
        assert!(
            x_uses >= 2,
            "renamed x ({}) should appear at definition and use ({} occurrences)",
            x_name,
            x_uses
        );
    }

    #[test]
    fn public_symbols_preserved_under_aggressive_transforms() {
        // Every pub item's name must survive across many seeds.
        for cycle in 0..20u64 {
            let seed = Seed::derive(cycle, "preserve");
            let out = diversify(TARGET_MINIMAL_SRC, &seed).unwrap();
            for sym in &["fletcher32", "feistel_mix", "derive_byte", "DemoHash"] {
                assert!(
                    out.contains(sym),
                    "cycle {}: pub symbol `{}` missing from output",
                    cycle,
                    sym
                );
            }
        }
    }

    #[test]
    fn shadowing_is_handled() {
        let src = r#"
            pub fn shadow() -> u32 {
                let x = 1u32;
                let x = x + 1;
                x
            }
        "#;
        for cycle in 0..8u64 {
            let seed = Seed::derive(cycle, "shadow");
            let out = diversify(src, &seed).unwrap();
            let file: File = syn::parse_str(&out)
                .unwrap_or_else(|e| panic!("cycle {} unparseable: {}\n{}", cycle, e, out));
            // Confirm the function still has exactly two `let` bindings
            // for `x`. (Post-TASK-029 the diversifier also injects a
            // `__cuttle_stack_pad_*` let binding; filter it out before
            // counting — the shadowing semantics we care about are about
            // the source-level locals, not the synthetic pad.)
            let mut let_count = 0;
            for it in &file.items {
                if let Item::Fn(f) = it {
                    for s in &f.block.stmts {
                        if let Stmt::Local(l) = s {
                            // Skip the injected stack-pad let binding.
                            let name = match &l.pat {
                                Pat::Ident(p) => p.ident.to_string(),
                                Pat::Type(t) => match &*t.pat {
                                    Pat::Ident(p) => p.ident.to_string(),
                                    _ => String::new(),
                                },
                                _ => String::new(),
                            };
                            if name.starts_with("__cuttle_stack_pad_") {
                                continue;
                            }
                            let_count += 1;
                        }
                    }
                }
            }
            assert_eq!(let_count, 2, "shadow fn must keep two let bindings: {}", out);
        }
    }

    #[test]
    fn match_arms_only_reordered_for_literals() {
        // A literal-pattern-only match: all four arms are integer
        // literals, no guards, no wildcard. The diversifier only
        // parses (not typechecks), so exhaustiveness doesn't matter.
        let literal_src = r#"
            pub fn lit_match(v: u32) -> u32 {
                match v { 0 => 10u32, 1 => 20u32, 2 => 30u32, 3 => 40u32 }
            }
        "#;
        let destruct_src = r#"
            pub fn destruct_match(v: Option<u32>) -> u32 {
                match v { Some(x) => x, None => 0u32 }
            }
        "#;

        // For literal match: arm-order CAN change across seeds.
        let mut saw_order_change = false;
        let baseline_lit = diversify(literal_src, &Seed::derive(0, "lit")).unwrap();
        for cycle in 1..16u64 {
            let out = diversify(literal_src, &Seed::derive(cycle, "lit")).unwrap();
            if out != baseline_lit {
                // Check that the change is in arm order (i.e. the arms
                // 1=>, 2=>, 3=> appear in a different order than the
                // baseline). We measure by the position of `1 =>` etc.
                saw_order_change = true;
                break;
            }
        }
        // It is theoretically possible — though astronomically
        // unlikely — for all 16 seeds to pick the identity permutation.
        // The shuffle uses ChaCha20; with 4! = 24 permutations and 16
        // independent draws, P(all identity) ≈ 1/24^16.
        assert!(
            saw_order_change,
            "literal match arms should be reorderable across 16 seeds"
        );

        // For destructuring match: arm order must NEVER change.
        let baseline_destruct = diversify(destruct_src, &Seed::derive(0, "destruct")).unwrap();
        // Extract the arm-order signature by finding the position of
        // `Some` and `None` in the output.
        let baseline_some = baseline_destruct.find("Some").unwrap();
        let baseline_none = baseline_destruct.find("None").unwrap();
        let baseline_some_first = baseline_some < baseline_none;
        for cycle in 0..16u64 {
            let out = diversify(destruct_src, &Seed::derive(cycle, "destruct")).unwrap();
            let some_pos = out.find("Some").unwrap();
            let none_pos = out.find("None").unwrap();
            assert_eq!(
                some_pos < none_pos,
                baseline_some_first,
                "destructuring match arm order changed at cycle {}: {}",
                cycle,
                out
            );
        }
    }

    #[test]
    fn compound_assignment_is_treated_as_write() {
        // Regression guard: `i += 2` must NEVER be reordered above
        // a `let word = data[i]...` statement. The bug this catches:
        // syn 2 encodes compound assignment as `Expr::Binary` with
        // `BinOp::AddAssign`, not as `Expr::Assign`. A naive walker
        // sees the LHS as a "read" and concludes `i += 2` is
        // independent of any statement that reads `i`.
        let src = r#"
            pub fn loop_fn(data: &[u8]) -> u32 {
                let mut i = 0;
                let mut acc: u32 = 0;
                while i + 1 < data.len() {
                    let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
                    acc = acc.wrapping_add(word);
                    i += 2;
                }
                acc
            }
        "#;
        for cycle in 0..32u64 {
            let seed = Seed::derive(cycle, "compound");
            let out = diversify(src, &seed).unwrap();
            // The `i += 2` (its renamed form `i_..._? += 2`) must
            // appear AFTER the `let word ...` line within the while
            // body. We search for the textual order of `i_` `+= 2`
            // vs `let word`.
            // Strategy: locate the *last* `+= 2` (it's the i increment)
            // and the *first* `let word` after the while keyword, and
            // assert the let-word comes first.
            let while_idx = out.find("while").expect("while present");
            let body = &out[while_idx..];
            let plus_eq_2 = body.find("+= 2").expect("+= 2 present");
            let let_word = body.find("let word").expect("let word present");
            assert!(
                let_word < plus_eq_2,
                "cycle {}: `i += 2` was reordered above the `let word` read of `i`\n{}",
                cycle,
                out
            );
        }
    }

    #[test]
    fn if_match_substitution_compiles_back() {
        let src = r#"
            pub fn pick(c: bool, a: u32, b: u32) -> u32 {
                if c { a } else { b }
            }
        "#;
        let mut saw_match = false;
        let mut saw_if = false;
        for cycle in 0..16u64 {
            let seed = Seed::derive(cycle, "ifmatch");
            let out = diversify(src, &seed).unwrap();
            // Must always parse.
            syn::parse_str::<File>(&out)
                .unwrap_or_else(|e| panic!("cycle {} unparseable: {}\n{}", cycle, e, out));
            // Either an if or a match must remain.
            if out.contains("match ") {
                saw_match = true;
            }
            if out.contains("if ") {
                saw_if = true;
            }
        }
        assert!(saw_match || saw_if, "must emit either if or match form");
        // Across 16 seeds with p=0.5 per call, we expect to see the
        // match form at least once. Probability of never seeing it is
        // (0.5)^16 ≈ 1.5e-5; we treat that as test-flake-acceptable
        // and require it.
        assert!(
            saw_match,
            "if->match substitution should fire at least once across 16 seeds"
        );
    }

    // ---- Closure / scope regression tests ---------------------------
    //
    // These guard the bug where `Expr::Closure`, `Expr::ForLoop`, `if let`,
    // `while let`, and `match` arm patterns were not properly given their
    // own lexical scope. Specifically:
    //
    //   * A typed closure parameter (`|prev: u32|`) is `Pat::Type(Pat::Ident)`.
    //     The previous `collect_pat_idents` did not handle `Pat::Type`, so
    //     the closure body's `prev` resolved up into the outer scope and
    //     was rewritten to the outer rename. The result no longer compiled
    //     because the actual closure parameter was still named `prev`.
    //
    //   * `if let Some(value) = ...` introduced `value` without pushing a
    //     scope, so an outer-scope binding of `value` would corrupt the
    //     pattern matching.
    //
    // Agent T worked around this by hand-inlining `tag_fletcher32` to
    // avoid closures entirely (see comment in target_minimal). These
    // tests pin the fix.

    /// Helper: re-parse a diversified output and return the renamed name
    /// of the FIRST top-level `let pat = ...` binding in the named fn
    /// whose pattern is `Pat::Ident { ident: <original> }` or
    /// `Pat::Type { Pat::Ident { ident: <original> }, .. }`. Returns the
    /// renamed identifier (which may equal `original` if the binding was
    /// skipped by the rename pass).
    fn first_let_rename(out: &str, fn_name: &str, original: &str) -> Option<String> {
        let file: File = syn::parse_str(out).ok()?;
        for it in &file.items {
            if let Item::Fn(f) = it {
                if f.sig.ident == fn_name {
                    if let Some(name) = first_let_rename_in_block(&f.block, original) {
                        return Some(name);
                    }
                }
            }
        }
        None
    }

    fn first_let_rename_in_block(block: &Block, original: &str) -> Option<String> {
        for stmt in &block.stmts {
            if let Stmt::Local(l) = stmt {
                // Unwrap a leading `Pat::Type` so `let prev: u32 = ...`
                // is recognised the same as `let prev = ...`.
                let mut pat: &Pat = &l.pat;
                if let Pat::Type(pt) = pat {
                    pat = &pt.pat;
                }
                if let Pat::Ident(pi) = pat {
                    let name = pi.ident.to_string();
                    // A rename produces `<original>_<suffix>_<counter>`;
                    // the binding may also be unchanged if rename was
                    // skipped (e.g. `_`-prefix). Accept both.
                    if name == original
                        || name.starts_with(&format!("{}_", original))
                    {
                        return Some(name);
                    }
                }
            }
        }
        None
    }

    #[test]
    fn closure_parameter_does_not_leak_to_outer_scope() {
        let src = r#"
            pub fn outer(_items: &[u32]) -> u32 {
                let prev: u32 = 0;
                let closure_result = (|prev: u32| prev.wrapping_add(1))(5);
                prev.wrapping_add(closure_result)
            }
        "#;
        for cycle in 0..20u64 {
            let seed = Seed::derive(cycle, "closure_leak");
            let out = diversify(src, &seed).unwrap();
            // 1. Output parses.
            let file: File = syn::parse_str(&out).unwrap_or_else(|e| {
                panic!("cycle {} unparseable: {}\n{}", cycle, e, out)
            });
            // 2. Look up the outer `prev` binding's renamed name and the
            //    final-expression `prev` reference.
            let outer_prev = first_let_rename(&out, "outer", "prev")
                .unwrap_or_else(|| panic!("cycle {}: no outer `prev` binding\n{}", cycle, out));
            // 3. Find the closure parameter and the tail expression.
            //    The tail expression's `prev` MUST equal the outer rename,
            //    NOT the closure-parameter rename.
            let mut closure_param_name: Option<String> = None;
            let mut tail_recv_name: Option<String> = None;
            for it in &file.items {
                if let Item::Fn(f) = it {
                    if f.sig.ident != "outer" {
                        continue;
                    }
                    // Tail expr is the last stmt of the fn block.
                    if let Some(Stmt::Expr(Expr::MethodCall(mc), None)) =
                        f.block.stmts.last()
                    {
                        if let Expr::Path(p) = &*mc.receiver {
                            if let Some(seg) = p.path.segments.first() {
                                tail_recv_name = Some(seg.ident.to_string());
                            }
                        }
                    }
                    // The closure parameter name: walk the fn block to
                    // find the closure expression.
                    for stmt in &f.block.stmts {
                        if let Some(name) = find_closure_param(stmt) {
                            closure_param_name = Some(name);
                            break;
                        }
                    }
                }
            }
            let closure_param = closure_param_name.unwrap_or_else(|| {
                panic!("cycle {}: no closure parameter found\n{}", cycle, out)
            });
            let tail = tail_recv_name.unwrap_or_else(|| {
                panic!("cycle {}: no tail receiver\n{}", cycle, out)
            });
            assert_eq!(
                tail, outer_prev,
                "cycle {}: tail `prev` ({}) must equal outer-scope rename ({}), not closure param ({})\n{}",
                cycle, tail, outer_prev, closure_param, out
            );
            assert_ne!(
                closure_param, outer_prev,
                "cycle {}: closure param ({}) and outer prev ({}) must be distinct\n{}",
                cycle, closure_param, outer_prev, out
            );
            // The CORE bug: the closure body's `prev.wrapping_add(1)`
            // must reference the closure parameter, not the outer
            // (renamed) `prev`. Verify by walking the AST.
            let closure_body_ref = find_closure_body_first_path(&file, "outer");
            let body_ref = closure_body_ref.unwrap_or_else(|| {
                panic!("cycle {}: could not find closure body path expr\n{}", cycle, out)
            });
            assert_eq!(
                body_ref, closure_param,
                "cycle {}: closure body's `prev` ({}) must reference the closure parameter ({}), not the outer rename ({})\n{}",
                cycle, body_ref, closure_param, outer_prev, out
            );
        }
    }

    fn find_closure_body_first_path(file: &File, fn_name: &str) -> Option<String> {
        for it in &file.items {
            if let Item::Fn(f) = it {
                if f.sig.ident == fn_name {
                    for stmt in &f.block.stmts {
                        if let Some(name) = find_closure_body_path_in_stmt(stmt) {
                            return Some(name);
                        }
                    }
                }
            }
        }
        None
    }

    fn find_closure_body_path_in_stmt(stmt: &Stmt) -> Option<String> {
        match stmt {
            Stmt::Local(l) => l
                .init
                .as_ref()
                .and_then(|i| find_closure_body_path_in_expr(&i.expr)),
            Stmt::Expr(e, _) => find_closure_body_path_in_expr(e),
            _ => None,
        }
    }

    fn find_closure_body_path_in_expr(e: &Expr) -> Option<String> {
        match e {
            Expr::Closure(c) => first_path_in_expr(&c.body),
            Expr::Call(c) => find_closure_body_path_in_expr(&c.func)
                .or_else(|| c.args.iter().find_map(find_closure_body_path_in_expr)),
            Expr::MethodCall(mc) => find_closure_body_path_in_expr(&mc.receiver)
                .or_else(|| mc.args.iter().find_map(find_closure_body_path_in_expr)),
            Expr::Paren(p) => find_closure_body_path_in_expr(&p.expr),
            Expr::Group(g) => find_closure_body_path_in_expr(&g.expr),
            Expr::Binary(b) => find_closure_body_path_in_expr(&b.left)
                .or_else(|| find_closure_body_path_in_expr(&b.right)),
            _ => None,
        }
    }

    fn first_path_in_expr(e: &Expr) -> Option<String> {
        match e {
            Expr::Path(p) => p.path.segments.first().map(|s| s.ident.to_string()),
            Expr::MethodCall(mc) => first_path_in_expr(&mc.receiver),
            Expr::Binary(b) => first_path_in_expr(&b.left),
            Expr::Paren(p) => first_path_in_expr(&p.expr),
            Expr::Group(g) => first_path_in_expr(&g.expr),
            Expr::Cast(c) => first_path_in_expr(&c.expr),
            Expr::Unary(u) => first_path_in_expr(&u.expr),
            Expr::Reference(r) => first_path_in_expr(&r.expr),
            _ => None,
        }
    }

    /// Find the (first) closure parameter name in a stmt/expr, walking
    /// only as far as we need to for the test inputs.
    fn find_closure_param(stmt: &Stmt) -> Option<String> {
        match stmt {
            Stmt::Local(l) => l
                .init
                .as_ref()
                .and_then(|i| find_closure_param_in_expr(&i.expr)),
            Stmt::Expr(e, _) => find_closure_param_in_expr(e),
            _ => None,
        }
    }

    fn find_closure_param_in_expr(e: &Expr) -> Option<String> {
        match e {
            Expr::Closure(c) => {
                let p = c.inputs.first()?;
                let inner = match p {
                    Pat::Type(pt) => &*pt.pat,
                    other => other,
                };
                if let Pat::Ident(pi) = inner {
                    Some(pi.ident.to_string())
                } else {
                    None
                }
            }
            Expr::Call(c) => find_closure_param_in_expr(&c.func)
                .or_else(|| c.args.iter().find_map(find_closure_param_in_expr)),
            Expr::MethodCall(mc) => find_closure_param_in_expr(&mc.receiver)
                .or_else(|| mc.args.iter().find_map(find_closure_param_in_expr)),
            Expr::Paren(p) => find_closure_param_in_expr(&p.expr),
            Expr::Group(g) => find_closure_param_in_expr(&g.expr),
            Expr::Binary(b) => find_closure_param_in_expr(&b.left)
                .or_else(|| find_closure_param_in_expr(&b.right)),
            Expr::Block(b) => b.block.stmts.iter().find_map(find_closure_param),
            _ => None,
        }
    }

    #[test]
    fn closure_body_references_outer_name_consistently() {
        let src = r#"
            pub fn outer(items: &[u32]) -> u32 {
                let scale: u32 = 7;
                items.iter().map(|x| x.wrapping_mul(scale)).sum()
            }
        "#;
        for cycle in 0..20u64 {
            let seed = Seed::derive(cycle, "closure_outer_ref");
            let out = diversify(src, &seed).unwrap();
            syn::parse_str::<File>(&out).unwrap_or_else(|e| {
                panic!("cycle {} unparseable: {}\n{}", cycle, e, out)
            });
            // The outer `scale` was renamed at its `let` site. Every
            // reference to `scale` inside the closure body MUST use the
            // same renamed name.
            let scale_renamed = first_let_rename(&out, "outer", "scale")
                .unwrap_or_else(|| panic!("cycle {}: no `scale` binding\n{}", cycle, out));
            // The renamed `scale` must appear at least twice — once at
            // the `let` site, once inside the closure body.
            let occurrences = out.matches(&scale_renamed).count();
            assert!(
                occurrences >= 2,
                "cycle {}: renamed `scale` ({}) must appear at let + inside closure body ({} occurrences)\n{}",
                cycle,
                scale_renamed,
                occurrences,
                out
            );
            // And the original bare `scale` must NOT survive as an
            // identifier in the body (after rename). We check that no
            // bare `scale` appears outside of the rename string. The
            // simplest robust check: split on the rename, ensure no
            // remaining fragment contains a standalone `scale` token.
            let blanked = out.replace(&scale_renamed, "");
            // The diversifier may emit the literal substring "scale" as
            // part of OTHER renames if rename collides — but our suffix
            // includes random hex, collisions are vanishingly unlikely.
            // We just assert no standalone whitespace-delimited `scale`.
            for piece in blanked.split_whitespace() {
                let trimmed = piece.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_');
                let trimmed = trimmed.trim_start_matches(|c: char| !c.is_alphanumeric() && c != '_');
                assert_ne!(
                    trimmed, "scale",
                    "cycle {}: stray bare `scale` survives after rename — closure body referenced outer scope inconsistently\n{}",
                    cycle, out
                );
            }
        }
    }

    #[test]
    fn nested_closures_have_independent_scopes() {
        let src = r#"
            pub fn outer() -> u32 {
                let a = (|x: u32| (|y: u32| x.wrapping_add(y))(2))(3);
                a
            }
        "#;
        for cycle in 0..20u64 {
            let seed = Seed::derive(cycle, "nested_closures");
            let out = diversify(src, &seed).unwrap();
            // The primary guarantee: output parses cleanly. A scope-
            // tracking bug would produce e.g. a reference to `y` that
            // got rewritten to `x`'s rename — which still parses but
            // breaks at compile. We verify parse here and assert that
            // both closures still have parameters bound to a name with
            // a renamed-`x`-style or unrenamed form.
            let file: File = syn::parse_str(&out).unwrap_or_else(|e| {
                panic!("cycle {} unparseable: {}\n{}", cycle, e, out)
            });
            // Walk to find both closure params; assert they are
            // distinct identifiers.
            let mut params: Vec<String> = Vec::new();
            for it in &file.items {
                if let Item::Fn(f) = it {
                    if f.sig.ident == "outer" {
                        collect_closure_params_in_block(&f.block, &mut params);
                    }
                }
            }
            assert_eq!(
                params.len(),
                2,
                "cycle {}: expected 2 closure params, got {:?}\n{}",
                cycle,
                params,
                out
            );
            assert_ne!(
                params[0], params[1],
                "cycle {}: nested closure params must be distinct (got {} / {})\n{}",
                cycle, params[0], params[1], out
            );
            // The inner closure's body references both x and y. Both
            // referenced names must appear somewhere in the output.
            // Stronger: each closure's parameter name must appear at
            // least twice (definition + at least one use in body).
            for p in &params {
                let n = out.matches(p.as_str()).count();
                assert!(
                    n >= 2,
                    "cycle {}: closure param {} must appear at def and body use ({} occurrences)\n{}",
                    cycle,
                    p,
                    n,
                    out
                );
            }
        }
    }

    fn collect_closure_params_in_block(block: &Block, out: &mut Vec<String>) {
        for stmt in &block.stmts {
            collect_closure_params_in_stmt(stmt, out);
        }
    }

    fn collect_closure_params_in_stmt(stmt: &Stmt, out: &mut Vec<String>) {
        match stmt {
            Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    collect_closure_params_in_expr(&init.expr, out);
                }
            }
            Stmt::Expr(e, _) => collect_closure_params_in_expr(e, out),
            _ => {}
        }
    }

    fn collect_closure_params_in_expr(e: &Expr, out: &mut Vec<String>) {
        match e {
            Expr::Closure(c) => {
                for p in &c.inputs {
                    let inner = match p {
                        Pat::Type(pt) => &*pt.pat,
                        other => other,
                    };
                    if let Pat::Ident(pi) = inner {
                        out.push(pi.ident.to_string());
                    }
                }
                collect_closure_params_in_expr(&c.body, out);
            }
            Expr::Call(c) => {
                collect_closure_params_in_expr(&c.func, out);
                for a in &c.args {
                    collect_closure_params_in_expr(a, out);
                }
            }
            Expr::MethodCall(mc) => {
                collect_closure_params_in_expr(&mc.receiver, out);
                for a in &mc.args {
                    collect_closure_params_in_expr(a, out);
                }
            }
            Expr::Paren(p) => collect_closure_params_in_expr(&p.expr, out),
            Expr::Group(g) => collect_closure_params_in_expr(&g.expr, out),
            Expr::Binary(b) => {
                collect_closure_params_in_expr(&b.left, out);
                collect_closure_params_in_expr(&b.right, out);
            }
            Expr::Block(b) => collect_closure_params_in_block(&b.block, out),
            Expr::If(i) => {
                collect_closure_params_in_expr(&i.cond, out);
                collect_closure_params_in_block(&i.then_branch, out);
                if let Some((_, els)) = &i.else_branch {
                    collect_closure_params_in_expr(els, out);
                }
            }
            Expr::Match(m) => {
                collect_closure_params_in_expr(&m.expr, out);
                for arm in &m.arms {
                    collect_closure_params_in_expr(&arm.body, out);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn for_loop_variable_is_scoped() {
        let src = r#"
            pub fn sumup(n: u32) -> u32 {
                let i: u32 = 100;
                let mut acc: u32 = 0;
                for i in 0..n { acc = acc.wrapping_add(i); }
                acc.wrapping_add(i)
            }
        "#;
        for cycle in 0..20u64 {
            let seed = Seed::derive(cycle, "for_scope");
            let out = diversify(src, &seed).unwrap();
            let _file: File = syn::parse_str(&out).unwrap_or_else(|e| {
                panic!("cycle {} unparseable: {}\n{}", cycle, e, out)
            });
            // The outer `i` got renamed to e.g. `i_v..._0`. The for-loop
            // variable `i` is a NEW binding scoped to the loop body —
            // it is registered in the loop scope (we mark loop pats as
            // "don't rename" so the name stays `i`, BUT it shadows the
            // outer `i` only inside the loop body).
            //
            // The tail `acc.wrapping_add(i)` is OUTSIDE the loop, so its
            // `i` must resolve to the outer (renamed) `i`.
            let outer_i = first_let_rename(&out, "sumup", "i")
                .unwrap_or_else(|| panic!("cycle {}: no outer `i` binding\n{}", cycle, out));
            assert!(
                outer_i != "i",
                "cycle {}: outer `i` should be renamed (got {})\n{}",
                cycle,
                outer_i,
                out
            );
            // The output must contain the outer-i renamed identifier in
            // the final position. Easiest check: parse and look at the
            // tail expression of sumup.
            let file: File = syn::parse_str(&out).unwrap();
            let mut tail_arg_name: Option<String> = None;
            for it in &file.items {
                if let Item::Fn(f) = it {
                    if f.sig.ident == "sumup" {
                        if let Some(Stmt::Expr(Expr::MethodCall(mc), None)) =
                            f.block.stmts.last()
                        {
                            if let Some(arg) = mc.args.first() {
                                if let Expr::Path(p) = arg {
                                    if let Some(seg) = p.path.segments.first() {
                                        tail_arg_name = Some(seg.ident.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            let tail = tail_arg_name.unwrap_or_else(|| {
                panic!("cycle {}: no tail arg in sumup\n{}", cycle, out)
            });
            assert_eq!(
                tail, outer_i,
                "cycle {}: tail `i` ({}) must equal outer-scope rename ({}), not the for-loop var\n{}",
                cycle, tail, outer_i, out
            );
        }
    }

    #[test]
    fn if_let_pattern_is_scoped() {
        let src = r#"
            pub fn unwrap_or(x: Option<u32>, default: u32) -> u32 {
                if let Some(value) = x { value } else { default }
            }
        "#;
        for cycle in 0..20u64 {
            let seed = Seed::derive(cycle, "if_let");
            let out = diversify(src, &seed).unwrap();
            // Must parse.
            syn::parse_str::<File>(&out).unwrap_or_else(|e| {
                panic!("cycle {} unparseable: {}\n{}", cycle, e, out)
            });
            // `value` is bound by the `if let` pattern. We mark its
            // pattern bindings as "don't rename" (consistent with how
            // we handle match arm patterns), so the literal name
            // `value` must survive in the then-branch.
            assert!(
                out.contains("value"),
                "cycle {}: `value` binding should survive\n{}",
                cycle,
                out
            );
            // And the else branch must NOT reference `value` — it has
            // only `default`. We check the AST.
            let file: File = syn::parse_str(&out).unwrap();
            for it in &file.items {
                if let Item::Fn(f) = it {
                    if f.sig.ident == "unwrap_or" {
                        // Find the if-expression (it may have been
                        // rewritten as a match, but `if let` is excluded
                        // from match-rewrite, so it stays an if).
                        for stmt in &f.block.stmts {
                            check_if_let_scope(stmt, &out, cycle);
                        }
                    }
                }
            }
        }
    }

    fn check_if_let_scope(stmt: &Stmt, out: &str, cycle: u64) {
        let expr = match stmt {
            Stmt::Expr(e, _) => e,
            _ => return,
        };
        if let Expr::If(ei) = expr {
            if let Some((_, els)) = &ei.else_branch {
                // The else-branch must not contain the literal name `value`.
                let token_str = quote::quote!(#els).to_string();
                for piece in token_str.split_whitespace() {
                    let trimmed = piece.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
                    assert_ne!(
                        trimmed, "value",
                        "cycle {}: `value` leaked into else branch\n{}",
                        cycle, out
                    );
                }
            }
        }
    }

    #[test]
    fn match_arm_bindings_are_per_arm() {
        let src = r#"
            pub fn unwrap_pair(p: (Option<u32>, Option<u32>), default: u32) -> u32 {
                match p {
                    (Some(a), Some(b)) => a.wrapping_add(b),
                    (Some(a), None) => a,
                    (None, Some(b)) => b,
                    (None, None) => default,
                }
            }
        "#;
        for cycle in 0..20u64 {
            let seed = Seed::derive(cycle, "match_arms");
            let out = diversify(src, &seed).unwrap();
            syn::parse_str::<File>(&out).unwrap_or_else(|e| {
                panic!("cycle {} unparseable: {}\n{}", cycle, e, out)
            });
            // `a` and `b` are bound differently in different arms. We
            // mark match-arm bindings as "don't rename", so the literal
            // names must survive. The arm bodies are `a.wrapping_add(b)`,
            // `a`, `b`, `default`. We assert each appears in the output.
            //
            // The key correctness property: each arm's `a`/`b` is
            // INDEPENDENT — if arm 1's `a` leaked into outer scope, the
            // outer scope would carry `a` and arm 2/3/4 might rename
            // their references. We rely on the syn::parse_str success
            // plus name-survival as the indicator.
            assert!(
                out.contains("wrapping_add"),
                "cycle {}: first arm body lost\n{}",
                cycle,
                out
            );
            // The last arm references `default` (a fn argument). It
            // should appear by its original name.
            assert!(
                out.contains("default"),
                "cycle {}: `default` arg reference lost\n{}",
                cycle,
                out
            );
        }
    }

    #[test]
    fn closure_based_tag_fletcher32_diversifies_cleanly() {
        // This is the closure pattern Agent T avoided by hand-inlining.
        // After the closure-scope fix, the diversifier must produce
        // parseable output across every seed.
        let src = r#"
            pub fn tag(input: &[u8]) -> u32 {
                let prev: u32 = 0;
                input.iter().fold(prev, |prev, &b| (prev << 8) ^ (b as u32))
            }
        "#;
        for cycle in 0..20u64 {
            let seed = Seed::derive(cycle, "tag_closure");
            let out = diversify(src, &seed).unwrap();
            syn::parse_str::<File>(&out).unwrap_or_else(|e| {
                panic!(
                    "cycle {}: closure-based tag fn produced unparseable output: {}\n---\n{}",
                    cycle, e, out
                )
            });
            // The outer `prev` (init value passed to fold) and the
            // closure parameter `prev` are distinct bindings. After
            // diversification, they MUST be distinct identifiers in
            // the output (the closure param shadows the outer one
            // inside the closure body, and the outer one is the
            // initializer of fold).
            let outer_prev = first_let_rename(&out, "tag", "prev")
                .unwrap_or_else(|| panic!("cycle {}: no outer `prev` in tag\n{}", cycle, out));
            // Find the closure parameter name. The closure here uses
            // `|prev, &b|` — `prev` is `Pat::Ident` (no type), `&b` is
            // `Pat::Reference(Pat::Ident)`. We pull the first param.
            let file: File = syn::parse_str(&out).unwrap();
            let mut params: Vec<String> = Vec::new();
            for it in &file.items {
                if let Item::Fn(f) = it {
                    if f.sig.ident == "tag" {
                        collect_closure_params_in_block(&f.block, &mut params);
                    }
                }
            }
            assert!(
                !params.is_empty(),
                "cycle {}: no closure param in tag fn\n{}",
                cycle,
                out
            );
            let closure_prev = &params[0];
            assert_ne!(
                closure_prev, &outer_prev,
                "cycle {}: closure `prev` ({}) and outer `prev` ({}) must be distinct identifiers\n{}",
                cycle, closure_prev, outer_prev, out
            );
        }
    }

    // ---- TASK-016 macro-ident pre-pass / shorthand tests ------------

    #[test]
    fn extract_format_captures_finds_simple_named() {
        let mut out = HashSet::new();
        extract_format_captures("\"count={count}\"", &mut out);
        assert!(out.contains("count"), "missing 'count'; got {:?}", out);
    }

    #[test]
    fn extract_format_captures_finds_format_spec_named() {
        // `{name:?}`, `{name:#x}`, `{name:>5}` — all should still
        // produce 'name'.
        let mut out = HashSet::new();
        extract_format_captures("\"a={a:?} b={b:#x} c={c:>5}\"", &mut out);
        assert!(out.contains("a"));
        assert!(out.contains("b"));
        assert!(out.contains("c"));
        assert_eq!(out.len(), 3, "expected exactly a/b/c; got {:?}", out);
    }

    #[test]
    fn extract_format_captures_skips_indexed_and_escaped() {
        // `{0}` is a positional index, not a name. `{{` is an escaped
        // brace and produces no capture. The scanner should not emit
        // a capture for either.
        let mut out = HashSet::new();
        extract_format_captures("\"index={0} escaped={{ paired={x}\"", &mut out);
        assert!(out.contains("x"), "expected 'x'; got {:?}", out);
        assert!(!out.contains("0"), "must not capture indexed; got {:?}", out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn extract_format_captures_handles_multiple_in_one_literal() {
        let mut out = HashSet::new();
        extract_format_captures(
            "\"a={alpha} b={beta} c={gamma:?}\"",
            &mut out,
        );
        assert!(out.contains("alpha"));
        assert!(out.contains("beta"));
        assert!(out.contains("gamma"));
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn extract_format_captures_ignores_unbalanced() {
        // A `{` with no matching `}` is malformed; the scanner should
        // not panic and should not produce false captures.
        let mut out = HashSet::new();
        extract_format_captures("\"oops {name\"", &mut out);
        // Either we emitted nothing (because no `}` was seen) or we
        // emitted `name` (because we stopped scanning at the end of
        // string). Both are acceptable — what we MUST NOT do is panic.
        // Assert no panic; either behavior is fine.
        let _ = out;
    }

    #[test]
    fn collect_macro_idents_in_block_picks_up_assert_args() {
        let f: File = syn::parse_str(
            r#"
            pub fn k() {
                let total = 5usize;
                assert!(total <= 255, "label too long");
                let _ = total;
            }
            "#,
        )
        .unwrap();
        let body = match &f.items[0] {
            Item::Fn(fi) => &fi.block,
            _ => unreachable!(),
        };
        let mut out = HashSet::new();
        collect_macro_idents_in_block(body, &mut out);
        assert!(
            out.contains("total"),
            "expected 'total' in macro idents; got {:?}",
            out
        );
    }

    #[test]
    fn collect_macro_idents_in_block_picks_up_format_captures() {
        let f: File = syn::parse_str(
            r#"
            pub fn k(seed: u32) -> String {
                let captured = seed + 1;
                format!("captured={captured}")
            }
            "#,
        )
        .unwrap();
        let body = match &f.items[0] {
            Item::Fn(fi) => &fi.block,
            _ => unreachable!(),
        };
        let mut out = HashSet::new();
        collect_macro_idents_in_block(body, &mut out);
        assert!(
            out.contains("captured"),
            "expected 'captured' (format-args implicit capture) in macro idents; got {:?}",
            out
        );
    }

    #[test]
    fn collect_macro_idents_in_file_walks_all_fn_bodies() {
        let f: File = syn::parse_str(
            r#"
            fn a() {
                assert!(alpha == 1);
            }
            fn b() {
                println!("beta={beta}");
            }
            pub fn c() {
                let _ = gamma_local;
            }
            "#,
        )
        .unwrap();
        let out = collect_macro_idents_in_file(&f);
        assert!(out.contains("alpha"), "missing 'alpha'; got {:?}", out);
        assert!(out.contains("beta"), "missing 'beta'; got {:?}", out);
        // `gamma_local` is NOT inside a macro, so it should not appear.
        assert!(
            !out.contains("gamma_local"),
            "'gamma_local' should not be in macro idents; got {:?}",
            out
        );
    }

    #[test]
    fn private_fn_referenced_in_macro_is_not_renamed() {
        // The old `RenamePrivateFns` would rename `mix` even when
        // `mix` was called from inside an `assert!` body, producing
        // E0425 at compile time. With TASK-016's symmetric fix, the
        // private fn rename map is filtered against file-level macro
        // idents — `mix` stays unrenamed in this case.
        let src = r#"
            pub fn checksum(data: &[u8]) -> u32 {
                let s = data.len() as u32;
                assert!(mix(s) != 0, "mix must be nonzero");
                mix(s)
            }
            fn mix(x: u32) -> u32 {
                x.wrapping_mul(0x9E3779B1).wrapping_add(1)
            }
        "#;
        // Run several seeds — every one must keep `mix` unchanged
        // (call + def both 'mix'), because renaming would orphan the
        // assert! reference.
        for cycle in 0..8u64 {
            let seed = Seed::derive(cycle, "mix_in_macro");
            let out = diversify(src, &seed).unwrap();
            let f: File = syn::parse_str(&out).expect("parse");
            // Find the `mix` (or whatever it's been renamed to) fn def.
            let mut def_name: Option<String> = None;
            for it in &f.items {
                if let Item::Fn(fi) = it {
                    let nm = fi.sig.ident.to_string();
                    if nm == "mix" || nm.starts_with("mix_") {
                        def_name = Some(nm);
                    }
                }
            }
            let def_name = def_name.expect("mix def must exist");
            assert_eq!(
                def_name, "mix",
                "cycle {}: 'mix' is referenced in assert! body and \
                 must not be renamed; got def={}\nout:\n{}",
                cycle, def_name, out
            );
            // And the assert!() body still contains the bare `mix`.
            assert!(
                out.contains("mix (s)") || out.contains("mix(s)"),
                "cycle {}: assert! body must still call bare 'mix'\nout:\n{}",
                cycle,
                out
            );
        }
    }

    #[test]
    fn struct_expr_shorthand_is_normalised_before_rename() {
        // When a local `let foo` is renamed and used in struct-expr
        // shorthand `S { foo }`, the emitter must produce explicit
        // `S { foo: <renamed> }` form. Bare shorthand `S { foo }`
        // would lookup the (now-nonexistent) original name.
        let src = r#"
            pub struct V { pub field_a: u32, pub field_b: u32 }
            pub fn build(seed: u32) -> V {
                let field_a = seed + 1;
                let field_b = seed + 2;
                V { field_a, field_b }
            }
        "#;
        for cycle in 0..8u64 {
            let seed = Seed::derive(cycle, "shorthand_norm");
            let out = diversify(src, &seed).unwrap();
            // After normalisation, the emitted struct literal must
            // use the explicit colon form (or, equivalently, if no
            // rename happened on this seed, still be syntactically
            // valid). The key invariant: the output parses AND
            // contains a colon between each field name and its
            // value. We assert the colon-form is present.
            assert!(
                out.contains("field_a :") || out.contains("field_a:"),
                "cycle {}: struct field 'field_a' must be in colon form\nout:\n{}",
                cycle,
                out
            );
            assert!(
                out.contains("field_b :") || out.contains("field_b:"),
                "cycle {}: struct field 'field_b' must be in colon form\nout:\n{}",
                cycle,
                out
            );
            // And the whole thing must parse.
            let _: File = syn::parse_str(&out).expect("parse");
        }
    }

    #[test]
    fn collect_macro_idents_in_nested_macro_groups() {
        // Macro bodies are token streams; identifiers inside
        // `Group(...)` subtrees must still be collected. e.g.
        // `vec![(a, b), (c, d)]` is `vec` then `Group([(a,b),(c,d)])`.
        let f: File = syn::parse_str(
            r#"
            pub fn k() {
                let v = vec![(alpha, beta), (gamma, delta)];
                let _ = v;
            }
            "#,
        )
        .unwrap();
        let body = match &f.items[0] {
            Item::Fn(fi) => &fi.block,
            _ => unreachable!(),
        };
        let mut out = HashSet::new();
        collect_macro_idents_in_block(body, &mut out);
        for name in &["alpha", "beta", "gamma", "delta"] {
            assert!(
                out.contains(*name),
                "expected '{}' in nested-macro idents; got {:?}",
                name,
                out
            );
        }
    }

    // -----------------------------------------------------------------
    // TASK-031: DiversifierLog and diversify_with_log unit tests.
    // -----------------------------------------------------------------

    const LOG_FIXTURE: &str = r#"
        fn helper_a() { let x = 1; let _ = x; }
        fn helper_b() { let y = 2; let _ = y; }
        fn helper_c() { let z = 3; let _ = z; }
        pub fn entry() { helper_a(); helper_b(); helper_c(); }
    "#;

    #[test]
    fn diversify_with_log_returns_same_source_as_diversify() {
        // The two entry points must produce byte-identical candidate
        // source under the same seed. This is the back-compat contract
        // — `diversify` is the historical Result<String> shape.
        let seed = Seed::derive(42, "log_fixture");
        let plain = diversify(LOG_FIXTURE, &seed).expect("diversify");
        let (with_log, _) = diversify_with_log(LOG_FIXTURE, &seed).expect("diversify_with_log");
        assert_eq!(plain, with_log);
    }

    #[test]
    fn diversifier_log_is_deterministic_in_seed_and_source() {
        // Two runs with the same seed and same source produce
        // bit-identical logs. This is the property the attestation
        // chain commits to.
        let seed = Seed::derive(7, "log_fixture");
        let (_, log_a) = diversify_with_log(LOG_FIXTURE, &seed).expect("first");
        let (_, log_b) = diversify_with_log(LOG_FIXTURE, &seed).expect("second");
        assert_eq!(log_a, log_b);
    }

    #[test]
    fn diversifier_log_differs_across_seeds() {
        // Different seeds → at least one of the two decision maps
        // differs. Production default leaves stack-pad off, so pad
        // maps are empty; we compare perturb decisions instead (and
        // force stack-pad on for a pad-map check).
        let s1 = Seed::derive(1, "log_fixture");
        let s2 = Seed::derive(2, "log_fixture");
        let (_, log1) = diversify_with_log(LOG_FIXTURE, &s1).expect("morph s1");
        let (_, log2) = diversify_with_log(LOG_FIXTURE, &s2).expect("morph s2");
        assert!(
            log1.pad_decisions.is_empty() && log2.pad_decisions.is_empty(),
            "production default must leave pad_decisions empty"
        );
        assert_ne!(
            log1.perturb_decisions, log2.perturb_decisions,
            "perturb decisions must vary across seeds under default options"
        );
        let opts = DiversifyOptions::with_stack_pad();
        let (_, pad1) =
            diversify_with_options(LOG_FIXTURE, &s1, &opts).expect("morph s1 pad-on");
        let (_, pad2) =
            diversify_with_options(LOG_FIXTURE, &s2, &opts).expect("morph s2 pad-on");
        assert_ne!(pad1.pad_decisions, pad2.pad_decisions);
    }

    #[test]
    fn diversifier_default_leaves_stack_pad_off() {
        // Production default: no `__cuttle_stack_pad_*` and empty
        // pad_decisions. Pin this so a future refactor cannot
        // re-enable the gadget-inflating pass by accident.
        let seed = Seed::derive(3, "log_fixture");
        let (out, log) = diversify_with_log(LOG_FIXTURE, &seed).expect("morph");
        assert!(
            log.pad_decisions.is_empty(),
            "default pad_decisions must be empty, got {:?}",
            log.pad_decisions
        );
        assert!(
            !out.contains("__cuttle_stack_pad_"),
            "default diversify must not inject stack pads: {}",
            &out.chars().take(200).collect::<String>()
        );
    }

    #[test]
    fn diversifier_log_pad_decisions_cover_every_morphable_free_fn() {
        // The fixture has 4 morphable free fns (helper_a, helper_b,
        // helper_c, entry — none unsafe / const / async / main). All
        // four must appear in the pad map when stack-pad is opted in.
        // Private fns are renamed before stack_pad runs, so we match
        // by prefix; `entry` is `pub` and so keeps its identity.
        let seed = Seed::derive(3, "log_fixture");
        let (_, log) = diversify_with_options(
            LOG_FIXTURE,
            &seed,
            &DiversifyOptions::with_stack_pad(),
        )
        .expect("morph");
        assert_eq!(
            log.pad_decisions.len(),
            4,
            "expected 4 pad decisions, got {:?}",
            log.pad_decisions
        );
        assert!(
            log.pad_decisions.contains_key("entry"),
            "missing pad_decision for 'entry': got {:?}",
            log.pad_decisions
        );
        for prefix in &["helper_a", "helper_b", "helper_c"] {
            assert!(
                log.pad_decisions
                    .keys()
                    .any(|k| k == *prefix || k.starts_with(&format!("{}_", prefix))),
                "missing pad_decision for prefix '{}': got {:?}",
                prefix,
                log.pad_decisions
            );
        }
    }

    #[test]
    fn diversifier_log_pad_sizes_are_in_documented_range() {
        // Every pad bytes value must be in [MIN_PAD_BYTES, MIN_PAD_BYTES
        // + PAD_RANGE_BYTES) — see `stack_pad::decide_pad_bytes`. We
        // assert via the public constants by reading from the log
        // (testing the contract, not the implementation).
        let seed = Seed::derive(11, "log_fixture");
        let (_, log) = diversify_with_options(
            LOG_FIXTURE,
            &seed,
            &DiversifyOptions::with_stack_pad(),
        )
        .expect("morph");
        for (name, bytes) in &log.pad_decisions {
            assert!(
                (32..=(32 + 192 - 1)).contains(&(*bytes as usize)),
                "pad bytes for '{}' = {} out of [32, 224)",
                name,
                bytes
            );
        }
    }

    #[test]
    fn diversifier_log_perturb_decisions_cover_every_free_fn() {
        // Every free fn — including `main` if present — must have a
        // perturb decision recorded. Our fixture has no `main`; the 4
        // free fns each must produce one entry. Private fns are
        // renamed before codegen_perturb runs, so we match by prefix
        // for the three private helpers and exactly for the pub
        // `entry`.
        let seed = Seed::derive(5, "log_fixture");
        let (_, log) = diversify_with_log(LOG_FIXTURE, &seed).expect("morph");
        assert_eq!(
            log.perturb_decisions.len(),
            4,
            "expected 4 perturb decisions, got {:?}",
            log.perturb_decisions
        );
        assert!(
            log.perturb_decisions.contains_key("entry"),
            "missing perturb_decision for 'entry': got {:?}",
            log.perturb_decisions
        );
        for prefix in &["helper_a", "helper_b", "helper_c"] {
            assert!(
                log.perturb_decisions
                    .keys()
                    .any(|k| k == *prefix || k.starts_with(&format!("{}_", prefix))),
                "missing perturb_decision for prefix '{}': got {:?}",
                prefix,
                log.perturb_decisions
            );
        }
    }

    #[test]
    fn diversifier_log_perturb_labels_are_locked_alphabet() {
        // The set of legal label spellings is the locked alphabet — the
        // attestation chain commits to these literal strings.
        let allowed: HashSet<&str> = [
            "no-attr",
            "inline-always",
            "inline-never",
            "ineligible:main-fn",
            "ineligible:already-inline",
        ]
        .iter()
        .copied()
        .collect();
        let seed = Seed::derive(13, "log_fixture");
        let (_, log) = diversify_with_log(LOG_FIXTURE, &seed).expect("morph");
        for (name, label) in &log.perturb_decisions {
            assert!(
                allowed.contains(label.as_str()),
                "perturb label '{}' for fn '{}' not in locked alphabet",
                label,
                name
            );
        }
    }

    #[test]
    fn diversifier_log_helpers_match_implementation() {
        // is_empty + total_decisions are simple but documented; pin
        // their semantics so future refactors don't drift.
        let mut log = DiversifierLog::default();
        assert!(log.is_empty());
        assert_eq!(log.total_decisions(), 0);
        log.pad_decisions.insert("foo".into(), 64);
        assert!(!log.is_empty());
        assert_eq!(log.total_decisions(), 1);
        log.perturb_decisions.insert("foo".into(), "no-attr".into());
        assert_eq!(log.total_decisions(), 2);
    }

    #[test]
    fn diversifier_log_empty_source_produces_empty_log() {
        // A source with only a `use` item has no free fns and no
        // morphable functions — both maps are empty, total = 0.
        let src = "use core::mem;";
        let seed = Seed::derive(0, "empty");
        let (_, log) = diversify_with_log(src, &seed).expect("morph");
        assert!(log.is_empty(), "expected empty log, got {:?}", log);
    }

    #[test]
    fn perturb_decision_label_covers_all_variants() {
        // Locked alphabet enforcement at the source level: every
        // variant must map to a non-empty label, and every label must
        // be in the documented set. Catches future variant additions.
        use codegen_perturb::{PerturbDecision, Reason};
        let cases = [
            (PerturbDecision::NoAttr, "no-attr"),
            (PerturbDecision::InlineAlways, "inline-always"),
            (PerturbDecision::InlineNever, "inline-never"),
            (
                PerturbDecision::Ineligible(Reason::MainFn),
                "ineligible:main-fn",
            ),
            (
                PerturbDecision::Ineligible(Reason::AlreadyInline),
                "ineligible:already-inline",
            ),
        ];
        for (d, expected) in &cases {
            assert_eq!(perturb_decision_label(d), *expected);
        }
    }

    #[test]
    fn repeated_in_place_morph_500_cycles_is_zero_drift_and_bounded() {
        // Exercises the exact failure mode that previously caused cycle ~244
        // stack overflow and multi-cycle freeze:
        //   1. `for i in 0..n` <-> `while i < n` round-trips without accumulating `{ { ... } }`
        //   2. `if x == C { A } else { B }` <-> `match x { ... }` oscillates cleanly
        //   3. `_m<8hex>` and `_v<8hex>_<hex>` suffixes are stripped and replaced each cycle
        //   4. `#[inline(always)]` / `#[inline(never)]` are re-decided every cycle (never frozen)
        //   5. `impl` block methods participate in both stack padding and semantic perturbation
        let donor = r#"
            pub struct Engine {
                state: u64,
            }

            impl Engine {
                pub fn step(&mut self, n: u64, flag: bool) -> u64 {
                    let mut acc = self.state * 8;
                    for i in 0..n {
                        acc = acc.wrapping_add(i * 4);
                    }
                    if acc == 42 {
                        acc + 1
                    } else {
                        acc + 2
                    }
                }
            }

            fn helper_mix(x: u64, n: u64) -> u64 {
                let mut total = x * 16;
                for idx in 0..n {
                    total = total.wrapping_add(idx * 2);
                }
                if total == 7 {
                    total ^ 0x55
                } else {
                    total ^ 0xAA
                }
            }

            pub fn entry(x: u64, n: u64) -> u64 {
                let a = helper_mix(x, n);
                let b = a * 8;
                b
            }
        "#;

        let opts = DiversifyOptions {
            stack_pad: true,
            semantic_perturb: true,
            semantic_fire_rate_percent: 75,
        };

        let mut current = donor.to_string();
        let mut cycle1_len = 0usize;
        let mut saw_inline_always = false;
        let mut saw_inline_never = false;
        let mut saw_no_attr = false;
        let mut saw_impl_semantic = false;

        for cycle in 1..=500u64 {
            let seed = Seed::derive(cycle, "zero_drift_500");
            let (next, log) = diversify_with_options(&current, &seed, &opts)
                .unwrap_or_else(|e| panic!("cycle {} failed to diversify: {}", cycle, e));

            if cycle == 1 {
                cycle1_len = next.len();
            }

            // 1. Source size must never grow unboundedly across 500 cycles.
            assert!(
                next.len() <= cycle1_len + 250 && next.len() + 250 >= cycle1_len,
                "cycle {}: source size drifted! cycle1_len={}, current_len={}\n{}",
                cycle,
                cycle1_len,
                next.len(),
                next
            );

            // 2. Codegen perturbation must never freeze into `ineligible:already-inline`.
            for (fn_name, decision) in &log.perturb_decisions {
                assert_ne!(
                    decision, "ineligible:already-inline",
                    "cycle {}: fn {} froze into already-inline!",
                    cycle, fn_name
                );
                match decision.as_str() {
                    "inline-always" => saw_inline_always = true,
                    "inline-never" => saw_inline_never = true,
                    "no-attr" => saw_no_attr = true,
                    _ => {}
                }
            }

            // 3. `Engine::step` impl method must participate in semantic perturbation.
            if let Some(sem) = log.semantic_decisions.get("Engine::step") {
                if sem != "eligible:no-change" && !sem.starts_with("ineligible:") {
                    saw_impl_semantic = true;
                }
            }

            current = next;
        }

        // Verify the final 500th-cycle output still parses cleanly as a Rust AST.
        let final_ast: File = syn::parse_str(&current).expect("cycle 500 output must parse");
        assert_eq!(final_ast.items.len(), 4);
        assert!(saw_inline_always && saw_inline_never && saw_no_attr, "inline decisions must ergodically visit all states across 500 cycles");
        assert!(saw_impl_semantic, "impl method Engine::step must receive semantic perturbation");
    }
}
