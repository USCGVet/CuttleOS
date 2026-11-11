//! Seed-keyed expression and control-flow semantic perturbation pass.
//!
//! Applies three reversible, value-preserving AST rewrites to induce distinct
//! LLVM instruction selection and basic-block layout per seed:
//! 1. **Strength-reduction inversion**: `x * {2,4,8,16}` ↔ `x << {1,2,3,4}`.
//! 2. **Branch polarity inversion**: `if c { A } else { B }` ↔ `if !c { B } else { A }`
//!    for side-effect-free comparisons, boolean literals, and identifiers.
//! 3. **Loop-form rewrite**: `for i in 0..n { body }` ↔
//!    `{ let mut i = 0; while i < n { body; i += 1; } }` when unlabelled and
//!    free of `break`/`continue`.
//!
//! Skips `main`, `#[test]` / `#[cfg(test)]` functions, `extern` functions, and
//! expressions inside `unsafe { ... }` blocks. Decisions are derived
//! deterministically from `SHA-256(HASH_TAG, seed, fn_name)`.

use proc_macro2::Span;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use syn::visit_mut::VisitMut;
use syn::{BinOp, Block, Expr, ExprBinary, ExprIf, File, Item, Lit, Pat, Stmt, UnOp};

use crate::Seed;

/// Domain-separation tag for the semantic-perturb decision hash.
/// Bumping this string is the contract-versioning lever, same policy
/// as `codegen_perturb::HASH_TAG`.
const HASH_TAG: &[u8] = b"cuttle-semantic-perturb-v1";

/// Log label for the strength-reduction transform.
pub const LABEL_STRENGTH: &str = "strength-reduction";
/// Log label for the branch-polarity transform.
pub const LABEL_POLARITY: &str = "branch-polarity";
/// Log label for the loop-form transform.
pub const LABEL_LOOP: &str = "loop-form";

/// Per-function decision bits derived from the seed hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
struct Flips {
    strength: bool,
    polarity: bool,
    loopform: bool,
}

/// One coin: fires when `byte < rate*256/100`. `rate` is clamped to
/// 100, so rate 100 fires for every byte value and rate 0 for none.
fn coin_fires(byte: u8, rate_percent: u8) -> bool {
    let rate = rate_percent.min(100) as u32;
    (byte as u32) < rate * 256 / 100
}

/// Deterministic coin flips for one function. Pure. Three independent
/// hash bytes gate the three transforms; each fires with probability
/// `fire_rate_percent`%.
fn flips_for(seed: &Seed, fn_name: &str, fire_rate_percent: u8) -> Flips {
    let base_name = crate::strip_cuttle_fn_suffix(fn_name);
    let mut h = Sha256::new();
    h.update(HASH_TAG);
    h.update(seed.0);
    h.update(base_name.as_bytes());
    let out = h.finalize();
    Flips {
        strength: coin_fires(out[0], fire_rate_percent),
        polarity: coin_fires(out[1], fire_rate_percent),
        loopform: coin_fires(out[2], fire_rate_percent),
    }
}

/// Why a function or method signature was ruled ineligible. Rendered into
/// the log value as `"ineligible:<reason>"`.
fn ineligibility_sig(sig: &syn::Signature, attrs: &[syn::Attribute]) -> Option<&'static str> {
    if sig.ident == "main" {
        return Some("main-fn");
    }
    if sig.constness.is_some() {
        return Some("const-fn");
    }
    if sig.abi.is_some() || attrs.iter().any(is_abi_or_naked_attr) {
        return Some("extern-fn");
    }
    if attrs
        .iter()
        .any(|a| a.path().is_ident("test") || (a.path().is_ident("cfg") && attr_mentions_test(a)))
    {
        return Some("test-fn");
    }
    None
}

fn is_abi_or_naked_attr(a: &syn::Attribute) -> bool {
    if a.path().is_ident("no_mangle")
        || a.path().is_ident("export_name")
        || a.path().is_ident("link_name")
        || a.path().is_ident("naked")
    {
        return true;
    }
    if a.path().is_ident("unsafe") {
        let s = quote::quote!(#a).to_string();
        return s.contains("no_mangle")
            || s.contains("export_name")
            || s.contains("link_name")
            || s.contains("naked");
    }
    false
}

fn attr_mentions_test(a: &syn::Attribute) -> bool {
    quote::quote!(#a).to_string().contains("test")
}

fn perturb_block(
    name: String,
    sig: &syn::Signature,
    attrs: &[syn::Attribute],
    block: &mut Block,
    seed: &Seed,
    fire_rate_percent: u8,
    log: &mut Vec<(String, String)>,
) {
    if let Some(reason) = ineligibility_sig(sig, attrs) {
        log.push((name, format!("ineligible:{}", reason)));
        return;
    }
    let flips = flips_for(seed, &name, fire_rate_percent);
    let mut v = SemanticVisitor {
        flips,
        applied: HashSet::new(),
    };
    v.visit_block_mut(block);
    let value = if v.applied.is_empty() {
        "eligible:no-change".to_string()
    } else {
        // Stable order for determinism of the log string.
        let mut labels: Vec<&str> = Vec::new();
        for l in [LABEL_STRENGTH, LABEL_POLARITY, LABEL_LOOP] {
            if v.applied.contains(l) {
                labels.push(l);
            }
        }
        labels.join(",")
    };
    log.push((name, value));
}

/// Apply the semantic-perturb pass to `file` under `seed`.
///
/// Walks both top-level `Item::Fn` functions and `Item::Impl` methods
/// (`ImplItem::Fn`). Returns a per-function log: `fn_name` → comma-joined
/// applied transform labels, `"eligible:no-change"` when the coins said no
/// (or no pattern matched), or `"ineligible:<reason>"`.
///
/// `fire_rate_percent` (0..=100) gates each transform's per-function
/// coin; values above 100 are clamped. 100 fires on every eligible
/// function, 0 never fires.
pub fn apply(file: &mut File, seed: &Seed, fire_rate_percent: u8) -> Vec<(String, String)> {
    let mut log = Vec::new();
    for item in file.items.iter_mut() {
        match item {
            Item::Fn(f) => {
                let name = f.sig.ident.to_string();
                perturb_block(
                    name,
                    &f.sig,
                    &f.attrs,
                    &mut f.block,
                    seed,
                    fire_rate_percent,
                    &mut log,
                );
            }
            Item::Impl(imp) => {
                let self_ty = &imp.self_ty;
                let parent = quote::quote!(#self_ty).to_string().replace(' ', "");
                for impl_item in imp.items.iter_mut() {
                    if let syn::ImplItem::Fn(m) = impl_item {
                        let name = format!("{}::{}", parent, m.sig.ident);
                        perturb_block(
                            name,
                            &m.sig,
                            &m.attrs,
                            &mut m.block,
                            seed,
                            fire_rate_percent,
                            &mut log,
                        );
                    }
                }
            }
            _ => {}
        }
    }
    log
}

// ---------------------------------------------------------------------------
// Visitor
// ---------------------------------------------------------------------------

struct SemanticVisitor {
    flips: Flips,
    applied: HashSet<&'static str>,
}

impl VisitMut for SemanticVisitor {
    fn visit_expr_mut(&mut self, e: &mut Expr) {
        // Position-level eligibility: never rewrite inside an
        // `unsafe { }` or `const { }` block. Recurse with all
        // coins suppressed, then restore.
        if matches!(e, Expr::Unsafe(_) | Expr::Const(_)) {
            let saved = self.flips;
            self.flips = Flips::default();
            syn::visit_mut::visit_expr_mut(self, e);
            self.flips = saved;
            return;
        }
        // Recurse first so inner nodes are already rewritten; then
        // attempt node-level rewrites on this expression.
        syn::visit_mut::visit_expr_mut(self, e);

        // If `for_to_while` in an earlier cycle wrapped `{ let mut i = 0; while ... }`
        // in an `Expr::Block`, and `visit_block_mut` just converted that inner block
        // back to a single `for` loop (`{ for i in 0..n { ... } }`), unwrap the
        // redundant outer block and return immediately so we never accumulate
        // `{ { { ... } } }` wrapper braces across cycles or re-convert it in this pass.
        if let Expr::Block(eb) = e {
            if eb.label.is_none() && eb.attrs.is_empty() && eb.block.stmts.len() == 1 {
                if matches!(eb.block.stmts.first(), Some(Stmt::Expr(Expr::ForLoop(_), None))) {
                    if let Some(Stmt::Expr(inner_for, None)) = eb.block.stmts.pop() {
                        *e = inner_for;
                        return;
                    }
                }
            }
        }

        if self.flips.strength {
            if let Expr::Binary(b) = e {
                if let Some(new_expr) = strength_reduce(b) {
                    *e = new_expr;
                    self.applied.insert(LABEL_STRENGTH);
                }
            }
        }

        // Collapse nested `((expr))` parentheses produced across alternating
        // strength-reduction cycles (`x * 8` -> `(x << 3)` -> `(x * 8)` -> `(x << 3)`)
        // so source size remains strictly bounded across arbitrary cycle counts.
        if let Expr::Paren(outer) = e {
            if outer.attrs.is_empty() {
                if let Expr::Paren(inner) = &*outer.expr {
                    if inner.attrs.is_empty() {
                        *e = (*outer.expr).clone();
                    }
                }
            }
        }

        if self.flips.polarity {
            if let Expr::If(ei) = e {
                if invert_branch_polarity(ei) {
                    self.applied.insert(LABEL_POLARITY);
                }
            }
        }

        if self.flips.loopform {
            if let Expr::ForLoop(fl) = e {
                if let Some(new_expr) = for_to_while(fl) {
                    *e = new_expr;
                    self.applied.insert(LABEL_LOOP);
                }
            }
        }
    }

    fn visit_block_mut(&mut self, block: &mut Block) {
        // Recurse into nested structure first.
        syn::visit_mut::visit_block_mut(self, block);
        if self.flips.loopform {
            if while_to_for_in_stmts(&mut block.stmts) {
                self.applied.insert(LABEL_LOOP);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// (a) strength-reduction inversion
// ---------------------------------------------------------------------------

/// Unsuffixed small integer literal value, or None.
fn unsuffixed_int(e: &Expr) -> Option<u64> {
    if let Expr::Lit(el) = e {
        if let Lit::Int(li) = &el.lit {
            if li.suffix().is_empty() {
                return li.base10_parse::<u64>().ok();
            }
        }
    }
    None
}

fn is_tight_for_mul(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Path(_)
            | Expr::Lit(_)
            | Expr::Paren(_)
            | Expr::Call(_)
            | Expr::MethodCall(_)
            | Expr::Field(_)
            | Expr::Index(_)
            | Expr::Array(_)
            | Expr::Tuple(_)
    )
}

fn strength_reduce(b: &ExprBinary) -> Option<Expr> {
    let left = &b.left;
    match b.op {
        // x * C  ->  (x << log2(C)), for C in {2,4,8,16}
        BinOp::Mul(_) => {
            let c = unsuffixed_int(&b.right)?;
            let k = match c {
                2 => 1u64,
                4 => 2,
                8 => 3,
                16 => 4,
                _ => return None,
            };
            let lit = syn::LitInt::new(&k.to_string(), Span::call_site());
            Some(syn::parse_quote!((#left << #lit)))
        }
        // x << k  ->  x * (1 << k) (or (x) * (1 << k) when `x` has lower precedence than `*`)
        BinOp::Shl(_) => {
            let k = unsuffixed_int(&b.right)?;
            if !(1..=4).contains(&k) {
                return None;
            }
            let lit = syn::LitInt::new(&(1u64 << k).to_string(), Span::call_site());
            if is_tight_for_mul(left) {
                Some(syn::parse_quote!(#left * #lit))
            } else {
                Some(syn::parse_quote!((#left) * #lit))
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// (b) branch polarity inversion
// ---------------------------------------------------------------------------

/// True when `e` is syntactically an integer, byte, or char literal (optionally
/// parenthesized or negated), proving in Rust (which has no implicit int-to-float
/// coercion) that a comparison with `e` cannot involve `f32`/`f64` `NaN`.
fn is_non_float_literal(e: &Expr) -> bool {
    match e {
        Expr::Lit(el) => matches!(el.lit, Lit::Int(_) | Lit::Byte(_) | Lit::Char(_)),
        Expr::Paren(p) => is_non_float_literal(&p.expr),
        Expr::Group(g) => is_non_float_literal(&g.expr),
        Expr::Unary(u) if matches!(u.op, UnOp::Neg(_)) => is_non_float_literal(&u.expr),
        _ => false,
    }
}

/// Swap a comparison operator for its inverse when total-order / IEEE-754 safe.
/// Returns `None` for non-comparison operators and for ordered `<, <=, >, >=`
/// comparisons whose operands might be floating-point (`!(NaN < x) != (NaN >= x)`).
fn invert_binop(b: &ExprBinary) -> Option<BinOp> {
    let ordered_safe = is_non_float_literal(&b.left) || is_non_float_literal(&b.right);
    Some(match b.op {
        BinOp::Eq(_) => BinOp::Ne(Default::default()),
        BinOp::Ne(_) => BinOp::Eq(Default::default()),
        BinOp::Lt(_) if ordered_safe => BinOp::Ge(Default::default()),
        BinOp::Le(_) if ordered_safe => BinOp::Gt(Default::default()),
        BinOp::Gt(_) if ordered_safe => BinOp::Le(Default::default()),
        BinOp::Ge(_) if ordered_safe => BinOp::Lt(Default::default()),
        _ => return None,
    })
}

/// Is `e` a plain single-identifier path (e.g. `flag`)?
fn simple_ident(e: &Expr) -> Option<syn::Ident> {
    if let Expr::Path(ep) = e {
        if ep.path.segments.len() == 1 && ep.qself.is_none() {
            let seg = &ep.path.segments[0];
            if seg.arguments.is_empty() {
                return Some(seg.ident.clone());
            }
        }
    }
    None
}

/// Negate a condition that is invertible without side effects.
/// Conservative: only comparisons, plain idents, `!ident`, and bool
/// literals.
fn negate_condition(cond: &Expr) -> Option<Expr> {
    match cond {
        Expr::Binary(b) => {
            let new_op = invert_binop(b)?;
            let l = &b.left;
            let r = &b.right;
            let mut out: Expr = syn::parse_quote!(#l #new_op #r);
            // Preserve parenthesisation needs: comparison results are
            // always fine unparenthesised in if-condition position.
            if let Expr::Binary(nb) = &mut out {
                nb.attrs = b.attrs.clone();
            }
            Some(out)
        }
        Expr::Unary(u) if matches!(u.op, UnOp::Not(_)) => {
            // `!ident` -> `ident` (only for a simple ident operand;
            // anything else might be `!(!x)` chains we don't want to
            // reason about).
            simple_ident(&u.expr).map(|id| syn::parse_quote!(#id))
        }
        Expr::Path(_) => {
            let id = simple_ident(cond)?;
            Some(syn::parse_quote!( ! #id))
        }
        Expr::Lit(el) => match &el.lit {
            Lit::Bool(lb) => {
                let flipped = !lb.value;
                Some(syn::parse_quote!(#flipped))
            }
            _ => None,
        },
        _ => None,
    }
}

/// `if c { A } else { B }` -> `if !c { B } else { A }`.
/// Only fires with a block `else` branch (no `else if` chains) and an
/// invertible condition. Returns true when the rewrite happened.
fn invert_branch_polarity(ei: &mut ExprIf) -> bool {
    let (_, else_expr) = match ei.else_branch.as_mut() {
        Some(pair) => pair,
        None => return false,
    };
    // Refuse else-if chains: polarity inversion of a chain requires
    // restructuring we don't want to reason about.
    let else_block = match &mut **else_expr {
        Expr::Block(eb) => eb.block.clone(),
        _ => return false,
    };
    let new_cond = match negate_condition(&ei.cond) {
        Some(c) => c,
        None => return false,
    };
    let then_block = ei.then_branch.clone();
    let attrs = ei.attrs.clone();
    let new_if: Expr = syn::parse_quote!(
        if #new_cond #else_block else #then_block
    );
    if let Expr::If(mut ni) = new_if {
        ni.attrs.clone_from(&attrs);
        *ei = ni;
    }
    true
}

// ---------------------------------------------------------------------------
// (c) loop-form rewrite
// ---------------------------------------------------------------------------

/// Does this block contain a `break` or `continue`?
/// Conservative: any occurrence anywhere (including inside a nested
/// loop, where it would be legal) disqualifies the rewrite.
fn block_contains_break_or_continue(b: &Block) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'ast> syn::visit::Visit<'ast> for Finder {
        fn visit_expr_break(&mut self, _: &'ast syn::ExprBreak) {
            self.found = true;
        }
        fn visit_expr_continue(&mut self, _: &'ast syn::ExprContinue) {
            self.found = true;
        }
    }
    let mut f = Finder { found: false };
    syn::visit::Visit::visit_block(&mut f, b);
    f.found
}

fn expr_mentions_ident(e: &Expr, target: &str) -> bool {
    quote::quote!(#e).to_string().split(|c: char| !c.is_alphanumeric() && c != '_').any(|tok| tok == target)
}

/// True if `target` is shadowed/rebound in a pattern, assigned/compound-assigned,
/// `&mut`-borrowed, or referenced inside an opaque macro anywhere in `stmts`.
fn ident_is_mutated_or_rebound_in_stmts(stmts: &[Stmt], target: &str) -> bool {
    struct HazardFinder<'a> {
        target: &'a str,
        found: bool,
    }
    impl<'ast, 'a> syn::visit::Visit<'ast> for HazardFinder<'a> {
        fn visit_pat_ident(&mut self, pi: &'ast syn::PatIdent) {
            if pi.ident == self.target {
                self.found = true;
            }
            syn::visit::visit_pat_ident(self, pi);
        }
        fn visit_expr_assign(&mut self, ea: &'ast syn::ExprAssign) {
            if expr_mentions_ident(&ea.left, self.target) {
                self.found = true;
            }
            syn::visit::visit_expr_assign(self, ea);
        }
        fn visit_expr_binary(&mut self, b: &'ast ExprBinary) {
            if crate::is_assign_op(&b.op) && expr_mentions_ident(&b.left, self.target) {
                self.found = true;
            }
            syn::visit::visit_expr_binary(self, b);
        }
        fn visit_expr_reference(&mut self, r: &'ast syn::ExprReference) {
            if r.mutability.is_some() && expr_mentions_ident(&r.expr, self.target) {
                self.found = true;
            }
            syn::visit::visit_expr_reference(self, r);
        }
        fn visit_macro(&mut self, m: &'ast syn::Macro) {
            let s = m.tokens.to_string();
            if s.split(|c: char| !c.is_alphanumeric() && c != '_').any(|tok| tok == self.target) {
                self.found = true;
            }
        }
    }
    let mut f = HazardFinder {
        target,
        found: false,
    };
    for s in stmts {
        syn::visit::Visit::visit_stmt(&mut f, s);
    }
    f.found
}

fn is_pure_invariant_loop_bound(end: &Expr, body_stmts: &[Stmt]) -> bool {
    match end {
        Expr::Lit(el) => matches!(el.lit, Lit::Int(_)),
        _ => match simple_ident(end) {
            Some(id) => !ident_is_mutated_or_rebound_in_stmts(body_stmts, &id.to_string()),
            None => false,
        },
    }
}

/// `for i in 0..n { body }` -> `{ let mut i = 0; while i < n { body; i += 1; } }`.
fn for_to_while(fl: &syn::ExprForLoop) -> Option<Expr> {
    if fl.label.is_some() {
        return None;
    }
    // Pattern must be a plain identifier binding.
    let var = match &*fl.pat {
        Pat::Ident(pi)
            if pi.by_ref.is_none() && pi.mutability.is_none() && pi.subpat.is_none() =>
        {
            pi.ident.clone()
        }
        _ => return None,
    };
    // Range must be exactly `0..END` (half-open, literal zero start).
    let range = match &*fl.expr {
        Expr::Range(r) => r,
        _ => return None,
    };
    let start = range.start.as_deref()?;
    if unsuffixed_int(start) != Some(0) {
        return None;
    }
    let end = range.end.as_deref()?;
    if !matches!(range.limits, syn::RangeLimits::HalfOpen(_)) {
        return None;
    }
    if block_contains_break_or_continue(&fl.body) {
        return None;
    }
    if !is_pure_invariant_loop_bound(end, &fl.body.stmts) {
        return None;
    }
    if ident_is_mutated_or_rebound_in_stmts(&fl.body.stmts, &var.to_string()) {
        return None;
    }
    let stmts: Vec<Stmt> = fl.body.stmts.clone();
    let out: Expr = syn::parse_quote!({
        let mut #var = 0;
        while #var < #end {
            #(#stmts)*
            #var += 1;
        }
    });
    Some(out)
}

/// Is `stmt` a `let mut <ident> = 0;` local? Returns the ident.
fn match_let_mut_zero(stmt: &Stmt) -> Option<syn::Ident> {
    let Stmt::Local(local) = stmt else { return None };
    let init = local.init.as_ref()?;
    if unsuffixed_int(&init.expr) != Some(0) || init.diverge.is_some() {
        return None;
    }
    match &local.pat {
        Pat::Ident(pi)
            if pi.by_ref.is_none() && pi.mutability.is_some() && pi.subpat.is_none() =>
        {
            Some(pi.ident.clone())
        }
        _ => None,
    }
}

/// Is `stmt` the expression-statement `<ident> += 1;`?
fn match_incr_one(stmt: &Stmt, var: &syn::Ident) -> bool {
    // syn 2 represents `i += 1;` as `Expr::Assign` with the compound
    // operator folded into the token stream of the assignment. Rather
    // than depend on the exact node shape, compare the normalized
    // token spelling.
    let spelling = quote::quote!(#stmt).to_string().replace(' ', "");
    spelling == format!("{}+=1;", var)
}

/// Does any expression in `stmts` reference the identifier `name`?
fn stmts_reference_ident(stmts: &[Stmt], name: &str) -> bool {
    struct Finder<'a> {
        name: &'a str,
        found: bool,
    }
    impl<'ast, 'a> syn::visit::Visit<'ast> for Finder<'a> {
        fn visit_ident(&mut self, id: &'ast proc_macro2::Ident) {
            if *id == self.name {
                self.found = true;
            }
        }
    }
    let mut f = Finder { name, found: false };
    for s in stmts {
        syn::visit::Visit::visit_stmt(&mut f, s);
    }
    f.found
}

/// Try the reverse direction at block-statement level:
///   `let mut i = 0; while i < n { body; i += 1; }`
/// →  `for i in 0..n { body }`
/// Only when `i` is not referenced after the loop. Returns true when
/// any rewrite happened.
fn while_to_for_in_stmts(stmts: &mut Vec<Stmt>) -> bool {
    let mut changed = false;
    let mut i = 0;
    while i + 1 < stmts.len() {
        let rewrite: Option<(syn::Ident, Expr)> = (|| {
            let var = match_let_mut_zero(&stmts[i])?;
            let Stmt::Expr(Expr::While(w), _) = &stmts[i + 1] else {
                return None;
            };
            if w.label.is_some() {
                return None;
            }
            // Condition must be exactly `i < END`.
            let Expr::Binary(cond) = &*w.cond else {
                return None;
            };
            if !matches!(cond.op, BinOp::Lt(_)) {
                return None;
            }
            if simple_ident(&cond.left).as_ref() != Some(&var) {
                return None;
            }
            let end = (*cond.right).clone();
            // Body must end with `i += 1;` and contain no break/continue.
            if w.body.stmts.is_empty() {
                return None;
            }
            let (last, body_prefix) = w.body.stmts.split_last().unwrap();
            if !match_incr_one(last, &var) {
                return None;
            }
            if block_contains_break_or_continue(&w.body) {
                return None;
            }
            if !is_pure_invariant_loop_bound(&end, body_prefix) {
                return None;
            }
            if ident_is_mutated_or_rebound_in_stmts(body_prefix, &var.to_string()) {
                return None;
            }
            // The induction variable must not be read after the loop —
            // after `while` it equals `n`; after `for` it is out of
            // scope. Only rewrite when nothing later references it.
            if stmts_reference_ident(&stmts[i + 2..], &var.to_string()) {
                return None;
            }
            let body_stmts: Vec<Stmt> = body_prefix.to_vec();
            let for_loop: Expr = syn::parse_quote!(
                for #var in 0..#end {
                    #(#body_stmts)*
                }
            );
            Some((var, for_loop))
        })();
        if let Some((_var, for_loop)) = rewrite {
            stmts.drain(i..=i + 1);
            stmts.insert(i, Stmt::Expr(for_loop, None));
            changed = true;
            // Do not advance i: a following pair could chain.
        } else {
            i += 1;
        }
    }
    changed
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file(src: &str) -> File {
        syn::parse_str(src).expect("fixture must parse")
    }

    fn seed_with_flips(fn_name: &str, want: Flips) -> Seed {
        for cycle in 0..4096u64 {
            let s = Seed::derive(cycle, "semantic-test");
            if flips_for(&s, fn_name, 50) == want {
                return s;
            }
        }
        panic!("no seed found for {:?} on {}", want, fn_name);
    }

    fn emitted(file: &File) -> String {
        quote::quote!(#file).to_string()
    }

    const SR_SRC: &str = r#"
        fn scaled(x: u64) -> u64 {
            let a = x * 8;
            let b = a << 2;
            b * 4
        }
    "#;

    #[test]
    fn strength_reduction_fires_when_coin_yes() {
        let seed = seed_with_flips(
            "scaled",
            Flips {
                strength: true,
                polarity: false,
                loopform: false,
            },
        );
        let mut file = make_file(SR_SRC);
        let log = apply(&mut file, &seed, 50);
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].1, LABEL_STRENGTH);
        let out = emitted(&file);
        // `x * 8` became `x << 3`; `a << 2` became `a * 4`; `b * 4` became `b << 2`.
        assert!(out.contains("x << 3"), "out: {}", out);
        assert!(out.contains("a * 4"), "out: {}", out);
        assert!(out.contains("b << 2"), "out: {}", out);
        assert!(!out.contains("x * 8"), "out: {}", out);
        // Reparses cleanly.
        let _: File = syn::parse_str(&out).expect("output must reparse");
    }

    #[test]
    fn strength_reduction_silent_when_coin_no() {
        let seed = seed_with_flips(
            "scaled",
            Flips {
                strength: false,
                polarity: false,
                loopform: false,
            },
        );
        let mut file = make_file(SR_SRC);
        let log = apply(&mut file, &seed, 50);
        assert_eq!(log[0].1, "eligible:no-change");
        assert!(emitted(&file).contains("x * 8"));
    }

    const BP_SRC: &str = r#"
        fn branchy(x: u64, flag: bool) -> u64 {
            if x == 7 {
                111
            } else {
                222
            }
        }
        fn branchy_ident(flag: bool) -> u64 {
            if flag {
                1
            } else {
                0
            }
        }
    "#;

    #[test]
    fn branch_polarity_swaps_arms_and_negates_condition() {
        let seed = seed_with_flips(
            "branchy",
            Flips {
                strength: false,
                polarity: true,
                loopform: false,
            },
        );
        let mut file = make_file(BP_SRC);
        let log = apply(&mut file, &seed, 50);
        let entry = log.iter().find(|(n, _)| n == "branchy").unwrap();
        assert_eq!(entry.1, LABEL_POLARITY);
        let out = emitted(&file);
        // `x == 7` inverted to `x != 7`, arms swapped: 222 arm first.
        assert!(out.contains("x != 7"), "out: {}", out);
        let ne_pos = out.find("x != 7").unwrap();
        let first_arm = out[ne_pos..].find("222").unwrap();
        let second_arm = out[ne_pos..].find("111").unwrap();
        assert!(first_arm < second_arm, "arms must be swapped: {}", out);
        let _: File = syn::parse_str(&out).expect("output must reparse");
    }

    #[test]
    fn branch_polarity_negates_plain_ident_condition() {
        let seed = seed_with_flips(
            "branchy_ident",
            Flips {
                strength: false,
                polarity: true,
                loopform: false,
            },
        );
        let mut file = make_file(BP_SRC);
        let log = apply(&mut file, &seed, 50);
        let entry = log.iter().find(|(n, _)| n == "branchy_ident").unwrap();
        assert_eq!(entry.1, LABEL_POLARITY);
        let out = emitted(&file);
        assert!(out.contains("if ! flag"), "out: {}", out);
    }

    #[test]
    fn branch_polarity_refuses_else_if_and_missing_else() {
        let src = r#"
            fn chained(x: u64) -> u64 {
                if x < 3 { 1 } else if x < 9 { 2 } else { 3 }
            }
            fn lonely(x: u64) -> u64 {
                if x > 1 { 9 } else { 8 }
            }
        "#;
        let seed = seed_with_flips(
            "chained",
            Flips {
                strength: false,
                polarity: true,
                loopform: false,
            },
        );
        let mut file = make_file(src);
        let log = apply(&mut file, &seed, 50);
        // The outer `else if` chain head is NOT invertible (else is an
        // if, not a block), so the chain structure is preserved. The
        // innermost `if x < 9 {2} else {3}` IS a plain if/else and may
        // invert — that's fine and semantics-preserving. Pin both
        // facts: chain structure survives, and no arm was dropped.
        let entry = log.iter().find(|(n, _)| n == "chained").unwrap();
        assert!(
            entry.1 == LABEL_POLARITY || entry.1 == "eligible:no-change",
            "unexpected decision: {}",
            entry.1
        );
        let out = emitted(&file);
        assert!(out.contains("else if"), "chain must survive: {}", out);
        assert!(out.contains("x < 3"), "outer cond untouched: {}", out);
        let _: File = syn::parse_str(&out).expect("output must reparse");
    }

    const LOOP_SRC: &str = r#"
        fn total(n: u64) -> u64 {
            let mut acc = 0u64;
            for i in 0..n {
                acc = acc.wrapping_add(i * 2);
            }
            acc
        }
    "#;

    #[test]
    fn loop_form_rewrites_for_to_while_when_coin_yes() {
        let seed = seed_with_flips(
            "total",
            Flips {
                strength: false,
                polarity: false,
                loopform: true,
            },
        );
        let mut file = make_file(LOOP_SRC);
        let log = apply(&mut file, &seed, 50);
        assert_eq!(log[0].1, LABEL_LOOP);
        let out = emitted(&file);
        assert!(out.contains("while i < n"), "out: {}", out);
        assert!(out.contains("let mut i = 0"), "out: {}", out);
        assert!(out.contains("i += 1"), "out: {}", out);
        assert!(!out.contains("for i in"), "out: {}", out);
        let _: File = syn::parse_str(&out).expect("output must reparse");
    }

    #[test]
    fn loop_form_rewrites_canonical_while_back_to_for() {
        let src = r#"
            fn total2(n: u64) -> u64 {
                let mut acc = 0u64;
                let mut i = 0;
                while i < n {
                    acc = acc.wrapping_add(i);
                    i += 1;
                }
                acc
            }
        "#;
        let seed = seed_with_flips(
            "total2",
            Flips {
                strength: false,
                polarity: false,
                loopform: true,
            },
        );
        let mut file = make_file(src);
        let log = apply(&mut file, &seed, 50);
        assert_eq!(log[0].1, LABEL_LOOP);
        let out = emitted(&file);
        assert!(out.contains("for i in 0 .. n"), "out: {}", out);
        assert!(!out.contains("while i < n"), "out: {}", out);
        let _: File = syn::parse_str(&out).expect("output must reparse");
    }

    #[test]
    fn loop_form_refuses_break_continue_and_induction_var_reuse() {
        let src = r#"
            fn with_break(n: u64) -> u64 {
                for i in 0..n {
                    if i == 5 { break; }
                }
                n
            }
            fn reused(n: u64) -> u64 {
                let mut i = 0;
                while i < n {
                    i += 1;
                }
                i
            }
        "#;
        let seed = seed_with_flips(
            "with_break",
            Flips {
                strength: false,
                polarity: false,
                loopform: true,
            },
        );
        let mut file = make_file(src);
        let log = apply(&mut file, &seed, 50);
        assert_eq!(log[0].1, "eligible:no-change");
        let reused = log.iter().find(|(n, _)| n == "reused").unwrap();
        assert_eq!(reused.1, "eligible:no-change");
        let out = emitted(&file);
        assert!(out.contains("for i in 0 .. n"));
        assert!(out.contains("while i < n"));
    }

    #[test]
    fn main_test_and_extern_fns_are_ineligible() {
        let src = r#"
            fn main() {}
            #[test]
            fn a_test() {}
            pub extern "C" fn exported(x: u64) -> u64 { x * 8 }
        "#;
        let seed = Seed::derive(0, "semantic-test");
        let mut file = make_file(src);
        let log = apply(&mut file, &seed, 50);
        let get = |n: &str| log.iter().find(|(name, _)| name == n).unwrap().1.clone();
        assert_eq!(get("main"), "ineligible:main-fn");
        assert_eq!(get("a_test"), "ineligible:test-fn");
        assert_eq!(get("exported"), "ineligible:extern-fn");
    }

    #[test]
    fn unsafe_fn_safe_statements_are_rewritten() {
        // Eligibility v2: an `unsafe fn` is eligible; its SAFE
        // statements are rewritten. Fire rate 100 forces the coin.
        let src = r#"
            unsafe fn uns(x: u64) -> u64 { x * 8 }
        "#;
        let seed = Seed::derive(0, "semantic-test");
        let mut file = make_file(src);
        let log = apply(&mut file, &seed, 100);
        assert_eq!(log[0].1, LABEL_STRENGTH);
        let out = emitted(&file);
        assert!(out.contains("x << 3"), "out: {}", out);
        assert!(!out.contains("x * 8"), "out: {}", out);
        let _: File = syn::parse_str(&out).expect("output must reparse");
    }

    #[test]
    fn unsafe_block_contents_are_never_rewritten() {
        // Statements inside `unsafe { }` keep their shape even at fire
        // rate 100; safe siblings in the same function ARE rewritten.
        let src = r#"
            fn mixed(x: u64, p: *const u8) -> u64 {
                let inside = unsafe { x * 8 + (*p as u64) * 4 };
                let outside = x * 16;
                inside + outside
            }
        "#;
        let seed = Seed::derive(0, "semantic-test");
        let mut file = make_file(src);
        let log = apply(&mut file, &seed, 100);
        assert!(log[0].1.contains(LABEL_STRENGTH), "log: {:?}", log);
        let out = emitted(&file);
        // Inside the unsafe block: untouched.
        assert!(out.contains("x * 8"), "out: {}", out);
        assert!(out.contains("* p as u64) * 4"), "out: {}", out);
        // Safe sibling: rewritten.
        assert!(out.contains("x << 4"), "out: {}", out);
        let _: File = syn::parse_str(&out).expect("output must reparse");
    }

    #[test]
    fn macro_operands_are_never_rewritten() {
        // Macro bodies are opaque token streams; even at fire rate 100
        // nothing inside them is touched.
        let src = r#"
            fn mac(x: u64) -> u64 {
                let v = donor_macro!(x * 8);
                v * 8
            }
        "#;
        let seed = Seed::derive(0, "semantic-test");
        let mut file = make_file(src);
        apply(&mut file, &seed, 100);
        let out = emitted(&file);
        assert!(out.contains("donor_macro ! (x * 8)"), "out: {}", out);
        assert!(out.contains("v << 3"), "out: {}", out);
        let _: File = syn::parse_str(&out).expect("output must reparse");
    }

    #[test]
    fn fire_rate_100_fires_on_every_eligible_fn() {
        let src = format!("{}\n{}\n{}", SR_SRC, BP_SRC, LOOP_SRC);
        let seed = Seed::derive(7, "semantic-test");
        let mut file = make_file(&src);
        let log = apply(&mut file, &seed, 100);
        for (name, decision) in &log {
            assert_ne!(
                decision, "eligible:no-change",
                "{} must fire at rate 100",
                name
            );
        }
        assert!(log.iter().any(|(_, d)| d.contains(LABEL_STRENGTH)));
        assert!(log.iter().any(|(_, d)| d.contains(LABEL_POLARITY)));
        assert!(log.iter().any(|(_, d)| d.contains(LABEL_LOOP)));
        let _: File = syn::parse_str(&emitted(&file)).expect("output must reparse");
    }

    #[test]
    fn fire_rate_0_never_fires() {
        let src = format!("{}\n{}\n{}", SR_SRC, BP_SRC, LOOP_SRC);
        let seed = Seed::derive(7, "semantic-test");
        let mut file = make_file(&src);
        let before = emitted(&file);
        let log = apply(&mut file, &seed, 0);
        for (_, decision) in &log {
            assert_eq!(decision, "eligible:no-change");
        }
        assert_eq!(emitted(&file), before);
    }

    #[test]
    fn apply_is_deterministic_under_same_seed() {
        let seed = seed_with_flips(
            "total",
            Flips {
                strength: true,
                polarity: true,
                loopform: true,
            },
        );
        let src = format!("{}\n{}\n{}", SR_SRC, BP_SRC, LOOP_SRC);
        let mut a = make_file(&src);
        let mut b = make_file(&src);
        let la = apply(&mut a, &seed, 50);
        let lb = apply(&mut b, &seed, 50);
        assert_eq!(la, lb);
        assert_eq!(emitted(&a), emitted(&b));
    }

    #[test]
    fn flips_vary_across_seeds() {
        let mut seen = HashSet::new();
        for c in 0..64u64 {
            seen.insert(flips_for(&Seed::derive(c, "semantic-test"), "scaled", 50));
        }
        assert!(seen.len() >= 4, "flips collapsed: {:?}", seen);
    }

    #[test]
    fn semantics_spot_check_while_loop_equivalence_shape() {
        // Structural check: the for->while rewrite preserves the body
        // statements verbatim between the decl and the increment.
        let seed = seed_with_flips(
            "total",
            Flips {
                strength: false,
                polarity: false,
                loopform: true,
            },
        );
        let mut file = make_file(LOOP_SRC);
        apply(&mut file, &seed, 50);
        let out = emitted(&file);
        let body_pos = out.find("acc = acc . wrapping_add (i * 2)").unwrap();
        let incr_pos = out.find("i += 1").unwrap();
        assert!(body_pos < incr_pos);
    }

    #[test]
    fn strength_reduce_preserves_precedence_in_additive_and_bitwise_exprs() {
        // 1) `a + b * 8` means `a + (b * 8)`. Without parens around the shift result,
        //    emitting `a + b << 3` parses in Rust as `(a + b) << 3`!
        // 2) `b * 8 * 3` means `(b * 8) * 3`. Without parens around the shift result,
        //    emitting `b << 3 * 3` parses in Rust as `b << 9`!
        // 3) `a + c << 2` means `(a + c) << 2`. Without parens around `#left`,
        //    emitting `a + c * 4` parses in Rust as `a + (c * 4)`!
        let src = r#"
            fn calc(a: u64, b: u64, c: u64) -> u64 {
                let x = a + b * 8;
                let z = b * 8 * 3;
                let y = a + c << 2;
                x ^ y ^ z
            }
        "#;
        let mut file = make_file(src);
        let log = apply(&mut file, &Seed::derive(1, "semantic-test"), 100);
        assert_eq!(log[0].1, LABEL_STRENGTH);
        let out = emitted(&file);
        assert!(
            out.contains("a + (b << 3)"),
            "expected parenthesized `a + (b << 3)`, got: {out}"
        );
        assert!(
            out.contains("(b << 3) * 3"),
            "expected parenthesized `(b << 3) * 3`, got: {out}"
        );
        assert!(
            out.contains("(a + c) * 4"),
            "expected parenthesized `(a + c) * 4`, got: {out}"
        );
        let _: File = syn::parse_str(&out).expect("output must reparse");
    }

    #[test]
    fn for_to_while_refuses_shadowed_induction_var_and_mutated_or_impure_bound() {
        let src = r#"
            fn shadowed(n: usize) -> usize {
                let mut acc = 0usize;
                for i in 0..n {
                    let mut i = 10usize;
                    i += 1;
                    acc += i;
                }
                acc
            }
            fn mutated_end(mut n: usize) -> usize {
                let mut acc = 0usize;
                for i in 0..n {
                    n = n.saturating_sub(1);
                    acc += i;
                }
                acc
            }
            fn impure_end(v: &[u8]) -> usize {
                let mut acc = 0usize;
                for i in 0..v.len() {
                    acc += i;
                }
                acc
            }
        "#;
        let mut file = make_file(src);
        let seed = Seed::derive(1, "semantic-test");
        apply(&mut file, &seed, 100);
        let out = emitted(&file);
        assert!(
            !out.contains("while i <"),
            "unsafe for->while rewrite fired on shadowed/mutated/impure loop: {out}"
        );
    }

    #[test]
    fn branch_polarity_refuses_ordered_comparison_on_potential_floats() {
        let src = r#"
            fn fcmp_vars(a: f64, b: f64) -> u64 {
                if a < b { 1 } else { 2 }
            }
            fn fcmp_lit(a: f64) -> u64 {
                if a < 0.0 { 1 } else { 2 }
            }
        "#;
        let mut file = make_file(src);
        let seed = Seed::derive(1, "semantic-test");
        apply(&mut file, &seed, 100);
        let out = emitted(&file);
        assert!(
            !out.contains(">="),
            "NaN-unsafe `<` -> `>=` inversion fired on potential float comparison: {out}"
        );
    }

    #[test]
    fn skips_const_fn_abi_export_attrs_and_const_blocks() {
        let src = r#"
            pub const fn compile_time_calc(x: u64) -> u64 {
                if x == 0 { 1 } else { x * 8 }
            }
            #[no_mangle]
            pub fn exported_entry(x: u64) -> u64 {
                if x == 0 { 1 } else { x * 8 }
            }
            #[export_name = "_cuttle_abi_sym"]
            pub fn custom_export(x: u64) -> u64 {
                if x == 0 { 1 } else { x * 8 }
            }
            #[unsafe(no_mangle)]
            pub fn edition2024_export(x: u64) -> u64 {
                if x == 0 { 1 } else { x * 8 }
            }
            pub fn has_const_block(y: u64) -> u64 {
                let k = const { if 1 == 0 { 2 } else { 3 * 8 } };
                k + y
            }
        "#;
        let mut file = make_file(src);
        let seed = Seed::derive(1, "semantic-const-abi-test");
        let log = apply(&mut file, &seed, 100);
        let map: std::collections::HashMap<_, _> = log.into_iter().collect();
        assert_eq!(
            map.get("compile_time_calc").map(String::as_str),
            Some("ineligible:const-fn")
        );
        assert_eq!(
            map.get("exported_entry").map(String::as_str),
            Some("ineligible:extern-fn")
        );
        assert_eq!(
            map.get("custom_export").map(String::as_str),
            Some("ineligible:extern-fn")
        );
        assert_eq!(
            map.get("edition2024_export").map(String::as_str),
            Some("ineligible:extern-fn")
        );
        let out = emitted(&file);
        assert!(
            !out.contains("<<"),
            "const fn, ABI-exported fn, or const {{ }} block was rewritten: {out}"
        );
    }
}
