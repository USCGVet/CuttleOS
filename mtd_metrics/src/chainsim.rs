//! ROP/JOP chain exploit simulator — the red-team instrument for the
//! core Proteus thesis.
//!
//! The thesis under test: *a layout-dependent exploit built against
//! morph cycle N fails against cycle N+1.* The churn metrics in
//! [`crate`] measure gadget *survival rates*; this module measures the
//! quantity an attacker actually cares about — **chain viability**. A
//! chain is a sequence of gadgets that must ALL land for the exploit to
//! work, so survival compounds: 5% per-gadget positional survival means
//! a 10-gadget chain survives at ~0.05^10 ≈ 1e-13. Rates can look
//! modest while viability is annihilated — or the reverse. This module
//! settles which.
//!
//! # Attacker models
//!
//! * **A — Static chain (stockpiled exploit).** The attacker developed
//!   a chain against the base image (hardcoded gadget offsets, as every
//!   real ROP payload does) and fires it unchanged at a morphed
//!   instance. A chain step survives iff the variant has *the identical
//!   gadget text at the identical `.text` offset*. Chain viability =
//!   all steps survive.
//!
//! * **B — Leak-and-rebase (weaponized, per-target).** The attacker has
//!   a runtime disclosure and re-derives gadget addresses against the
//!   *current* image. Modeled as: for each base gadget, does a gadget
//!   with the same address-independent (normalized) semantics exist
//!   *anywhere* in the variant? If yes at every step, the chain is
//!   rebuildable. This attacker is NOT defeated by layout churn alone —
//!   measuring rebuild rate honestly shows the limit of what morphing
//!   buys without cadence.
//!
//! * **C — Cadence-bounded re-derivation.** Attacker B's re-derivation
//!   takes wall-clock time (disclosure, scan, chain assembly, delivery).
//!   [`cadence_break_even`] computes the probability that no morph
//!   occurs inside the attack window as a function of window/period —
//!   the curve that shows when morphing starts to beat even attacker B.
//!
//! # Byte-level note (binmorph honesty)
//!
//! [`ChainReport`] also reports *byte-exact* positional survival: the
//! fraction of chain steps where the variant's raw `.text` bytes at the
//! step offset equal the base's. Post-link rewriters like `binmorph`
//! re-encode instructions (MOV 89↔8B) without moving addresses or
//! changing disassembly — so they drive byte-exact survival down while
//! leaving attacker-A viability at 100%. That is the empirical proof
//! that byte-level morphing alone does NOT break ROP: execution, not
//! bytes, is what the chain depends on.

use anyhow::{Context, Result};
use serde::Serialize;

use crate::{
    canonicalize_registers_gadget, extract_gadgets, normalize_gadget, read_text_section, GadgetSet,
    DEFAULT_MAX_INSTRS,
};

/// A synthesized exploit chain: offsets of gadgets (within `.text`,
/// section-relative — exactly what a hardcoded payload commits to after
/// the attacker learns the load base).
#[derive(Debug, Clone)]
pub struct Chain {
    pub gadget_offsets: Vec<u64>,
}

impl Chain {
    pub fn len(&self) -> usize {
        self.gadget_offsets.len()
    }
}

/// Splitmix64 — small deterministic PRNG for reproducible chain sampling.
pub struct Prng(u64);

impl Prng {
    pub fn new(seed: u64) -> Self {
        Prng(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
}

/// Synthesize a chain of `len` gadgets drawn uniformly (without
/// replacement) from the base gadget set. Any gadget in the set is
/// eligible — real chain construction is constrained by register
/// clobbers, but attacker A's viability question ("does my developed
/// chain still land?") is orthogonal to which gadgets were chosen, and
/// uniform sampling makes the viability estimate unbiased over the
/// whole gadget population.
pub fn synthesize_chain(base: &GadgetSet, len: usize, rng: &mut Prng) -> Result<Chain> {
    let offsets: Vec<u64> = base.by_offset.keys().copied().collect();
    if offsets.len() < len {
        anyhow::bail!(
            "base gadget set has {} gadgets, cannot build a {}-gadget chain",
            offsets.len(),
            len
        );
    }
    let mut picked: Vec<u64> = Vec::with_capacity(len);
    let mut pool = offsets;
    for _ in 0..len {
        let i = rng.below(pool.len() as u64) as usize;
        picked.push(pool.swap_remove(i));
    }
    Ok(Chain {
        gadget_offsets: picked,
    })
}

/// Per-step outcome of one chain fired at one variant.
#[derive(Debug, Clone, Default)]
pub struct ChainOutcome {
    /// Steps where the identical gadget text sits at the identical
    /// offset in the variant (attacker A's per-step survival).
    pub positional_hits: usize,
    /// Steps where the variant's raw bytes at the offset equal the
    /// base's bytes at that offset for the gadget's span (byte-exact;
    /// binmorph-sensitive).
    pub byte_hits: usize,
    /// Steps whose normalized gadget kind exists *somewhere* in the
    /// variant (attacker B's exact-register per-step rebuild success).
    pub semantic_hits: usize,
    /// Steps whose register-canonicalized gadget kind exists *somewhere*
    /// in the variant (attacker B_reg's register-adapting per-step
    /// rebuild success).
    pub reg_adapted_hits: usize,
}

impl ChainOutcome {
    /// Attacker A: the developed chain executes correctly against the
    /// morphed image. ALL steps must land — one broken step crashes or
    /// misdirects the chain.
    pub fn viable_static(&self, chain_len: usize) -> bool {
        self.positional_hits == chain_len
    }
    /// Attacker B (exact-register): the chain can be re-derived against
    /// the morphed image without changing its register assignment.
    pub fn rebuildable(&self, chain_len: usize) -> bool {
        self.semantic_hits == chain_len
    }
    /// Attacker B_reg (register-adapting): the chain can be re-derived
    /// against the morphed image when the attacker also adapts to
    /// swapped general-purpose registers (e.g. `pop r13; ret` for
    /// `pop r12; ret`). Fails only when the opcode/mnemonic class of a
    /// required gadget no longer exists in the variant.
    pub fn rebuildable_reg_adapted(&self, chain_len: usize) -> bool {
        self.reg_adapted_hits == chain_len
    }
}

/// Evaluate one chain against one variant. `base_text`/`variant_text`
/// are the raw `.text` bytes for the byte-exact check.
pub fn evaluate_chain(
    chain: &Chain,
    base: &GadgetSet,
    variant: &GadgetSet,
    base_text: &[u8],
    variant_text: &[u8],
) -> ChainOutcome {
    let variant_kinds: std::collections::HashSet<String> = variant.distinct_normalized();
    let variant_reg_kinds: std::collections::HashSet<String> = variant.distinct_reg_canonicalized();
    evaluate_chain_with_kinds(
        chain,
        base,
        variant,
        &variant_kinds,
        &variant_reg_kinds,
        base_text,
        variant_text,
    )
}

fn evaluate_chain_with_kinds(
    chain: &Chain,
    base: &GadgetSet,
    variant: &GadgetSet,
    variant_kinds: &std::collections::HashSet<String>,
    variant_reg_kinds: &std::collections::HashSet<String>,
    base_text: &[u8],
    variant_text: &[u8],
) -> ChainOutcome {
    let mut out = ChainOutcome::default();
    for off in &chain.gadget_offsets {
        let gadget_text = match base.by_offset.get(off) {
            Some(t) => t,
            None => continue, // not a base gadget — shouldn't happen
        };
        // Attacker A step: same text at same offset.
        if variant.by_offset.get(off) == Some(gadget_text) {
            out.positional_hits += 1;
        }
        // Byte-exact step: the gadget's byte span is unchanged.
        let start = *off as usize;
        // Gadget byte length: re-derive from the base image by decoding
        // is overkill; use the span to the next known base gadget offset
        // or a fixed 15-byte max-instruction window clipped to .text.
        let end = (start + 15).min(base_text.len());
        if start < base_text.len() && start < variant_text.len() {
            let b = &base_text[start..end.min(base_text.len())];
            let v_end = (start + b.len()).min(variant_text.len());
            if v_end == start + b.len() && &variant_text[start..v_end] == b {
                out.byte_hits += 1;
            }
        }
        // Attacker B step: same normalized kind exists anywhere.
        if variant_kinds.contains(&normalize_gadget(gadget_text)) {
            out.semantic_hits += 1;
        }
        // Attacker B_reg step: same register-canonicalized kind exists anywhere.
        if variant_reg_kinds.contains(&canonicalize_registers_gadget(gadget_text)) {
            out.reg_adapted_hits += 1;
        }
    }
    out
}

/// Aggregate result of firing `chains` synthesized chains at one variant.
#[derive(Debug, Clone, Serialize)]
pub struct ChainReport {
    pub variant_label: String,
    pub chains: usize,
    pub chain_len: usize,
    /// Attacker A: fraction of chains still fully viable unchanged.
    pub static_viable: usize,
    pub static_viable_rate: f64,
    /// Mean per-step positional survival across all chains (sanity vs
    /// the population-level churn metric).
    pub mean_step_positional_survival: f64,
    /// Byte-exact per-step survival (binmorph-sensitivity probe).
    pub mean_step_byte_survival: f64,
    /// Attacker B (exact-register): fraction of chains rebuildable via
    /// semantic re-scan with fixed register assignments.
    pub rebuildable: usize,
    pub rebuildable_rate: f64,
    pub mean_step_semantic_survival: f64,
    /// Attacker B_reg (register-adapting): fraction of chains rebuildable
    /// when the attacker also adapts to swapped general-purpose registers.
    pub rebuildable_reg_adapted: usize,
    pub rebuildable_reg_adapted_rate: f64,
    pub mean_step_reg_adapted_survival: f64,
}

/// Run the two-attacker experiment: sample `n_chains` chains of
/// `chain_len` from the base image and evaluate each against the variant.
pub fn run_experiment(
    variant_label: &str,
    base_text: &[u8],
    base_ip: u64,
    variant_text: &[u8],
    variant_ip: u64,
    n_chains: usize,
    chain_len: usize,
    seed: u64,
    max_instrs: usize,
) -> Result<ChainReport> {
    let base = extract_gadgets(base_text, base_ip, max_instrs);
    let variant = extract_gadgets(variant_text, variant_ip, max_instrs);
    if base.len() < chain_len {
        anyhow::bail!(
            "base image has only {} gadgets (need >= {} for chain sampling)",
            base.len(),
            chain_len
        );
    }
    let variant_kinds = variant.distinct_normalized();
    let variant_reg_kinds = variant.distinct_reg_canonicalized();
    let mut rng = Prng::new(seed);
    let mut rep = ChainReport {
        variant_label: variant_label.to_string(),
        chains: n_chains,
        chain_len,
        static_viable: 0,
        static_viable_rate: 0.0,
        mean_step_positional_survival: 0.0,
        mean_step_byte_survival: 0.0,
        rebuildable: 0,
        rebuildable_rate: 0.0,
        mean_step_semantic_survival: 0.0,
        rebuildable_reg_adapted: 0,
        rebuildable_reg_adapted_rate: 0.0,
        mean_step_reg_adapted_survival: 0.0,
    };
    for _ in 0..n_chains {
        let chain = synthesize_chain(&base, chain_len, &mut rng)?;
        let oc = evaluate_chain_with_kinds(
            &chain,
            &base,
            &variant,
            &variant_kinds,
            &variant_reg_kinds,
            base_text,
            variant_text,
        );
        if oc.viable_static(chain_len) {
            rep.static_viable += 1;
        }
        if oc.rebuildable(chain_len) {
            rep.rebuildable += 1;
        }
        if oc.rebuildable_reg_adapted(chain_len) {
            rep.rebuildable_reg_adapted += 1;
        }
        rep.mean_step_positional_survival += oc.positional_hits as f64 / chain_len as f64;
        rep.mean_step_byte_survival += oc.byte_hits as f64 / chain_len as f64;
        rep.mean_step_semantic_survival += oc.semantic_hits as f64 / chain_len as f64;
        rep.mean_step_reg_adapted_survival += oc.reg_adapted_hits as f64 / chain_len as f64;
    }
    let n = n_chains as f64;
    rep.static_viable_rate = rep.static_viable as f64 / n;
    rep.rebuildable_rate = rep.rebuildable as f64 / n;
    rep.rebuildable_reg_adapted_rate = rep.rebuildable_reg_adapted as f64 / n;
    rep.mean_step_positional_survival /= n;
    rep.mean_step_byte_survival /= n;
    rep.mean_step_semantic_survival /= n;
    rep.mean_step_reg_adapted_survival /= n;
    Ok(rep)
}

/// Load an ELF and run the experiment in one call (CLI convenience).
pub fn run_experiment_on_elves(
    variant_label: &str,
    base_elf: &std::path::Path,
    variant_elf: &std::path::Path,
    n_chains: usize,
    chain_len: usize,
    seed: u64,
) -> Result<ChainReport> {
    let (bt, bip) = read_text_section(base_elf)
        .with_context(|| format!("read .text of {}", base_elf.display()))?;
    let (vt, vip) = read_text_section(variant_elf)
        .with_context(|| format!("read .text of {}", variant_elf.display()))?;
    run_experiment(
        variant_label,
        &bt,
        bip,
        &vt,
        vip,
        n_chains,
        chain_len,
        seed,
        DEFAULT_MAX_INSTRS,
    )
}

/// Cadence break-even (attacker C). Closed form: if the attack window
/// (disclosure → chain assembly → delivery) is `window_secs` and morphs
/// occur every `period_secs`, the attack succeeds only if the whole
/// window fits inside one morph period AND starts early enough in it.
/// With uniformly random phase, P(success) = max(0, 1 - window/period).
/// (Periodic morph, uniformly random attack start — the standard MTD
/// scheduling model. A periodic morph at exactly the window boundary
/// still kills the exploit because the re-derived offsets describe the
/// pre-morph image.)
///
/// Returns P(attack succeeds) in [0, 1].
pub fn cadence_break_even(window_secs: f64, period_secs: f64) -> f64 {
    if period_secs <= 0.0 {
        return 0.0; // continuous morph — no stable layout to hit
    }
    if window_secs <= 0.0 {
        return 1.0;
    }
    (1.0 - window_secs / period_secs).max(0.0)
}

/// Sweep the break-even curve over a grid of window/period ratios.
pub fn cadence_curve(ratios: &[f64]) -> Vec<(f64, f64)> {
    ratios
        .iter()
        .map(|&r| (r, cadence_break_even(r, 1.0)))
        .collect()
}
