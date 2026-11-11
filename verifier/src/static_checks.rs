//! Static (pre-compile) verifier stages.
//!
//! These checks run *before* the scratch-workspace cargo build. They are
//! cheap, pure, and form the first half of the poison corpus: every
//! adversarial candidate in this class must reject without spending a
//! rustc cycle.
//!
//! Stages, in order:
//!
//! 1. **Parse** — `syn` must accept the candidate as a Rust file.
//! 2. **Manifest pubs** — every name in the module manifest must appear
//!    as a top-level `pub` item.
//! 3. **Previous-surface** — no `pub` item present in the previous cycle
//!    may be removed (anti-regression).
//! 4. **Canonical dedup** — candidate must not be AST-canonical-equal to
//!    the previous cycle (no diversity ⇒ reject).
//!
//! The load-bearing *semantic* battery (golden / KAT / property tests)
//! lives in the compile-and-test stage and is covered by the on-disk
//! fixtures under `tests/fixtures/` (e.g. `broken_fletcher32.rs`).

use std::collections::BTreeSet;

use syn::{File, Item, Visibility};

/// Why a static check rejected a candidate. Stable string tags for
/// corpus tests and stderr matching — do not rename without bumping
/// consumers that assert on the label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaticRejectReason {
    /// `syn` could not parse the candidate.
    ParseFailed { message: String },
    /// One or more names from the manifest are absent as top-level pubs.
    MissingManifestSymbols { missing: Vec<String> },
    /// A public symbol from the previous cycle was dropped.
    RemovedPreviousSymbol { name: String },
    /// Canonical AST hash matches the previous cycle (zero diversity).
    CanonicalDuplicate,
}

impl StaticRejectReason {
    /// Short stable tag used in tests and log greps.
    pub fn tag(&self) -> &'static str {
        match self {
            StaticRejectReason::ParseFailed { .. } => "parse_failed",
            StaticRejectReason::MissingManifestSymbols { .. } => "missing_manifest_symbols",
            StaticRejectReason::RemovedPreviousSymbol { .. } => "removed_previous_symbol",
            StaticRejectReason::CanonicalDuplicate => "canonical_duplicate",
        }
    }

    /// Human-readable line matching the historical `verify:` stderr style.
    pub fn stderr_line(&self) -> String {
        match self {
            StaticRejectReason::ParseFailed { message } => {
                format!("verify: parse failed: {}", message)
            }
            StaticRejectReason::MissingManifestSymbols { missing } => {
                format!(
                    "verify: candidate is missing required public symbols: {:?}",
                    missing
                )
            }
            StaticRejectReason::RemovedPreviousSymbol { name } => {
                format!(
                    "verify: candidate removed public symbol present in previous cycle: {}",
                    name
                )
            }
            StaticRejectReason::CanonicalDuplicate => {
                "verify: candidate is canonical-equivalent to previous cycle (no diversity)"
                    .to_string()
            }
        }
    }
}

/// Outcome of [`evaluate_static`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaticCheckOutcome {
    /// All static stages passed; proceed to compile-and-test.
    Accept,
    /// Rejected at a static stage. `reason` is non-empty and tagged.
    Reject { reason: StaticRejectReason },
}

impl StaticCheckOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, StaticCheckOutcome::Accept)
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }

    pub fn reject_tag(&self) -> Option<&'static str> {
        match self {
            StaticCheckOutcome::Accept => None,
            StaticCheckOutcome::Reject { reason } => Some(reason.tag()),
        }
    }
}

/// Inputs to the static pipeline for a single-module candidate.
#[derive(Debug, Clone)]
pub struct StaticCheckInput<'a> {
    /// Candidate source text.
    pub candidate: &'a str,
    /// Previous-cycle source, if any.
    pub previous: Option<&'a str>,
    /// Required public symbol names (from `manifest.txt`). Empty = no
    /// manifest enforcement.
    pub required_pub: &'a BTreeSet<String>,
}

/// Run the static pipeline. Pure: no IO, no cargo.
///
/// Order matches the production verifier binary so corpus tags align
/// with live `verify:` stderr lines.
pub fn evaluate_static(input: &StaticCheckInput<'_>) -> StaticCheckOutcome {
    // 1. Parse.
    let cand: File = match syn::parse_str(input.candidate) {
        Ok(f) => f,
        Err(e) => {
            return StaticCheckOutcome::Reject {
                reason: StaticRejectReason::ParseFailed {
                    message: e.to_string(),
                },
            };
        }
    };
    let cand_pub = collect_pub_idents(&cand);

    // 2. Manifest pubs.
    let mut missing = Vec::new();
    for name in input.required_pub {
        if !cand_pub.contains(name) {
            missing.push(name.clone());
        }
    }
    if !missing.is_empty() {
        missing.sort();
        return StaticCheckOutcome::Reject {
            reason: StaticRejectReason::MissingManifestSymbols { missing },
        };
    }

    // 3. Previous-surface anti-regression.
    if let Some(prev_src) = input.previous {
        let prev: File = match syn::parse_str(prev_src) {
            Ok(f) => f,
            Err(e) => {
                // A previous that does not parse is an infrastructure
                // problem for the morph engine, not a candidate accept.
                // Treat as parse failure of the *input pair*.
                return StaticCheckOutcome::Reject {
                    reason: StaticRejectReason::ParseFailed {
                        message: format!("previous source: {}", e),
                    },
                };
            }
        };
        let prev_pub = collect_pub_idents(&prev);
        for s in &prev_pub {
            if !cand_pub.contains(s) {
                return StaticCheckOutcome::Reject {
                    reason: StaticRejectReason::RemovedPreviousSymbol { name: s.clone() },
                };
            }
        }

        // 4. Canonical-hash dedup.
        match (
            cuttle_diversifier::canonical_hash(input.candidate),
            cuttle_diversifier::canonical_hash(prev_src),
        ) {
            (Ok(cand_h), Ok(prev_h)) if cand_h == prev_h => {
                return StaticCheckOutcome::Reject {
                    reason: StaticRejectReason::CanonicalDuplicate,
                };
            }
            (Ok(_), Ok(_)) => {}
            // Hash infrastructure failure: do not reject the candidate
            // as "bad code" — the binary treats diversifier errors as
            // ERROR (exit 2). Surface that by accepting static here
            // and letting the caller decide; in practice
            // canonical_hash only fails on unparseable input, which
            // we already handled above.
            (Err(_), _) | (_, Err(_)) => {}
        }
    }

    StaticCheckOutcome::Accept
}

/// Per-member input for bundle-mode static verification.
#[derive(Debug, Clone)]
pub struct BundleMemberInput<'a> {
    pub module: &'a str,
    pub candidate: &'a str,
    pub previous: Option<&'a str>,
}

/// Run static checks across an atomic multi-module bundle:
/// 1. Every member must parse cleanly.
/// 2. If `required_pub` is non-empty, every required symbol must appear as a
///    top-level `pub` item in at least one bundle member.
/// 3. For each member with `previous: Some(prev_src)`, no `pub` item present in
///    `prev_src` may be dropped from `candidate` (`RemovedPreviousSymbol`).
/// 4. If at least one member has `previous: Some(prev_src)`, at least ONE member
///    in the bundle must actually change its canonical AST (`CanonicalDuplicate`
///    if the entire bundle is AST-identical to the previous cycle).
pub fn evaluate_bundle_static(
    members: &[BundleMemberInput<'_>],
    required_pub: &BTreeSet<String>,
) -> StaticCheckOutcome {
    let mut union_pub = BTreeSet::new();
    let mut saw_any_previous = false;
    let mut any_member_diversified = false;

    for m in members {
        let cand: File = match syn::parse_str(m.candidate) {
            Ok(f) => f,
            Err(e) => {
                return StaticCheckOutcome::Reject {
                    reason: StaticRejectReason::ParseFailed {
                        message: format!("module {}: {}", m.module, e),
                    },
                };
            }
        };
        let cand_pub = collect_pub_idents(&cand);
        union_pub.extend(cand_pub.iter().cloned());

        if let Some(prev_src) = m.previous {
            saw_any_previous = true;
            let prev: File = match syn::parse_str(prev_src) {
                Ok(f) => f,
                Err(e) => {
                    return StaticCheckOutcome::Reject {
                        reason: StaticRejectReason::ParseFailed {
                            message: format!("previous source ({}): {}", m.module, e),
                        },
                    };
                }
            };
            let prev_pub = collect_pub_idents(&prev);
            for s in &prev_pub {
                if !cand_pub.contains(s) {
                    return StaticCheckOutcome::Reject {
                        reason: StaticRejectReason::RemovedPreviousSymbol {
                            name: format!("{}::{}", m.module, s),
                        },
                    };
                }
            }
            match (
                cuttle_diversifier::canonical_hash(m.candidate),
                cuttle_diversifier::canonical_hash(prev_src),
            ) {
                (Ok(cand_h), Ok(prev_h)) if cand_h != prev_h => {
                    any_member_diversified = true;
                }
                _ => {}
            }
        }
    }

    if !required_pub.is_empty() {
        let mut missing: Vec<String> = required_pub
            .iter()
            .filter(|name| !union_pub.contains(*name))
            .cloned()
            .collect();
        if !missing.is_empty() {
            missing.sort();
            return StaticCheckOutcome::Reject {
                reason: StaticRejectReason::MissingManifestSymbols { missing },
            };
        }
    }

    if saw_any_previous && !any_member_diversified {
        return StaticCheckOutcome::Reject {
            reason: StaticRejectReason::CanonicalDuplicate,
        };
    }

    StaticCheckOutcome::Accept
}

/// Collect top-level public item names from a parsed file.
///
/// Matches the historical verifier surface: `pub fn` / `struct` /
/// `enum` / `const` / `static` / `trait` / `type` / `mod`.
pub fn collect_pub_idents(file: &File) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let is_pub = |v: &Visibility| matches!(v, Visibility::Public(_));
    for it in &file.items {
        match it {
            Item::Fn(f) if is_pub(&f.vis) => {
                out.insert(f.sig.ident.to_string());
            }
            Item::Struct(s) if is_pub(&s.vis) => {
                out.insert(s.ident.to_string());
            }
            Item::Enum(e) if is_pub(&e.vis) => {
                out.insert(e.ident.to_string());
            }
            Item::Const(c) if is_pub(&c.vis) => {
                out.insert(c.ident.to_string());
            }
            Item::Static(s) if is_pub(&s.vis) => {
                out.insert(s.ident.to_string());
            }
            Item::Trait(t) if is_pub(&t.vis) => {
                out.insert(t.ident.to_string());
            }
            Item::Type(t) if is_pub(&t.vis) => {
                out.insert(t.ident.to_string());
            }
            Item::Mod(m) if is_pub(&m.vis) => {
                out.insert(m.ident.to_string());
            }
            _ => {}
        }
    }
    out
}

/// Parse a `manifest.txt`-shaped body into a required-pub set.
pub fn parse_manifest_str(body: &str) -> BTreeSet<String> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_req() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn accepts_minimal_good_source() {
        let src = r#"
            #![no_std]
            pub fn fletcher32(_d: &[u8]) -> u32 { 0 }
            pub struct DemoHash;
        "#;
        let mut req = BTreeSet::new();
        req.insert("fletcher32".into());
        req.insert("DemoHash".into());
        let out = evaluate_static(&StaticCheckInput {
            candidate: src,
            previous: None,
            required_pub: &req,
        });
        assert!(out.is_accept(), "{:?}", out);
    }

    #[test]
    fn rejects_syntax_error() {
        let out = evaluate_static(&StaticCheckInput {
            candidate: "fn broken( {",
            previous: None,
            required_pub: &empty_req(),
        });
        assert_eq!(out.reject_tag(), Some("parse_failed"));
    }

    #[test]
    fn rejects_missing_manifest_symbol() {
        let src = "pub fn feistel_mix(s: u64) -> u64 { s }";
        let mut req = BTreeSet::new();
        req.insert("fletcher32".into());
        req.insert("feistel_mix".into());
        let out = evaluate_static(&StaticCheckInput {
            candidate: src,
            previous: None,
            required_pub: &req,
        });
        match out {
            StaticCheckOutcome::Reject {
                reason: StaticRejectReason::MissingManifestSymbols { missing },
            } => {
                assert_eq!(missing, vec!["fletcher32".to_string()]);
            }
            other => panic!("expected missing_manifest_symbols, got {:?}", other),
        }
    }

    #[test]
    fn rejects_removed_previous_symbol() {
        let prev = "pub fn a() {} pub fn b() {}";
        let cand = "pub fn a() {}";
        let out = evaluate_static(&StaticCheckInput {
            candidate: cand,
            previous: Some(prev),
            required_pub: &empty_req(),
        });
        match out {
            StaticCheckOutcome::Reject {
                reason: StaticRejectReason::RemovedPreviousSymbol { name },
            } => assert_eq!(name, "b"),
            other => panic!("expected removed_previous_symbol, got {:?}", other),
        }
    }

    #[test]
    fn rejects_canonical_duplicate() {
        // Same AST, different whitespace → same canonical hash.
        let prev = "pub fn a ( ) { }";
        let cand = "pub fn a() {}";
        let out = evaluate_static(&StaticCheckInput {
            candidate: cand,
            previous: Some(prev),
            required_pub: &empty_req(),
        });
        assert_eq!(out.reject_tag(), Some("canonical_duplicate"));
    }

    #[test]
    fn accepts_when_candidate_diversifies_previous() {
        let prev = "pub fn a() { let x = 1; x }";
        let cand = "pub fn a() { let y = 2; y }";
        let out = evaluate_static(&StaticCheckInput {
            candidate: cand,
            previous: Some(prev),
            required_pub: &empty_req(),
        });
        assert!(out.is_accept(), "{:?}", out);
    }

    #[test]
    fn evaluate_bundle_static_rejects_removed_symbol_and_accepts_partial_diversification() {
        let dropped = [BundleMemberInput {
            module: "tls",
            candidate: "pub fn handshake() {}",
            previous: Some("pub fn handshake() {} pub fn record_open() {}"),
        }];
        let out_drop = evaluate_bundle_static(&dropped, &empty_req());
        assert_eq!(out_drop.reject_tag(), Some("removed_previous_symbol"));

        // One small unchanged module + one diversified module -> bundle accepts.
        let partial = [
            BundleMemberInput {
                module: "tiny",
                candidate: "pub const VERSION: u32 = 1;",
                previous: Some("pub const VERSION: u32 = 1;"),
            },
            BundleMemberInput {
                module: "wal",
                candidate: "pub fn append() -> u32 { let y = 2; y }",
                previous: Some("pub fn append() -> u32 { let x = 1; x }"),
            },
        ];
        let out_ok = evaluate_bundle_static(&partial, &empty_req());
        assert!(out_ok.is_accept(), "{out_ok:?}");
    }
}
