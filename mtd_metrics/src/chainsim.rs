//! Multi-step ROP/JOP chain exploit simulator.
//!
//! Evaluates multi-gadget chain survival across two compiled ELF binaries
//! under four attacker models:
//!
//! * **Attacker A — Static chain**: Stockpiled exploit with hardcoded `.text`
//!   offsets from the base build fired unchanged at the variant build. A chain
//!   survives iff every step lands on the identical gadget at the identical
//!   offset.
//! * **Attacker B — Exact-register relocation**: Attacker with a full `.text`
//!   disclosure of the variant who relocates each step to any offset containing
//!   an address-normalized gadget with the same registers.
//! * **Attacker B_reg — Register-adapting relocation**: Attacker with a full
//!   `.text` disclosure of the variant who can both relocate gadgets and
//!   substitute any general-purpose register of the same width (`r64`/`r32`/
//!   `r16`/`r8`) at each step.
//! * **Attacker C — Cadence-bounded re-derivation**: Models the probability
//!   that a morph cycle completes before an attacker's disclosure-and-assembly
//!   window finishes ([`cadence_break_even`]).

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

/// Map an x86-64 general-purpose register name (in NASM lowercase format) to its
/// canonical architectural index `0..16`:
/// `0=rax, 1=rcx, 2=rdx, 3=rbx, 4=rsp, 5=rbp, 6=rsi, 7=rdi, 8..15=r8..r15`.
pub fn gpr_name_to_index(tok: &str) -> Option<u8> {
    Some(match tok.trim() {
        "rax" | "eax" | "ax" | "al" | "ah" => 0,
        "rcx" | "ecx" | "cx" | "cl" | "ch" => 1,
        "rdx" | "edx" | "dx" | "dl" | "dh" => 2,
        "rbx" | "ebx" | "bx" | "bl" | "bh" => 3,
        "rsp" | "esp" | "sp" | "spl" => 4,
        "rbp" | "ebp" | "bp" | "bpl" => 5,
        "rsi" | "esi" | "si" | "sil" => 6,
        "rdi" | "edi" | "di" | "dil" => 7,
        "r8" | "r8d" | "r8w" | "r8b" => 8,
        "r9" | "r9d" | "r9w" | "r9b" => 9,
        "r10" | "r10d" | "r10w" | "r10b" => 10,
        "r11" | "r11d" | "r11w" | "r11b" => 11,
        "r12" | "r12d" | "r12w" | "r12b" => 12,
        "r13" | "r13d" | "r13w" | "r13b" => 13,
        "r14" | "r14d" | "r14w" | "r14b" => 14,
        "r15" | "r15d" | "r15w" | "r15b" => 15,
        _ => return None,
    })
}

/// Analyze a formatted gadget (`"pop rdi; xor eax,eax; ret"`) and return:
/// `(defs_mask, clobbers_rsp_arbitrarily)` where:
/// - `defs_mask` has bit `r` (`0..16`) set for every GP register defined by the gadget
///   (excluding normal constant stack adjustments on `rsp`),
/// - `clobbers_rsp_arbitrarily` is `true` if any instruction overwrites `rsp` with a
///   non-constant stack pivot (`pop rsp`, `mov rsp, ...`, `xchg rsp, ...`, `lea rsp, ...`)
///   or if a `call` or `jmp` appears before the gadget's final terminator instruction.
///
/// Note: `defs_mask` tracks all GP register definitions (`pop`, `mov`, `lea`, ALU writes)
/// so [`DataflowChain`] measures ordered non-clobbering register-definition survival; use
/// [`analyze_stack_controlled_gadget_dataflow`] when restricting strictly to stack-fed
/// (`pop <reg>` or `[rsp + ...]`) payload loads.
pub fn analyze_gadget_dataflow(gadget_text: &str) -> (u16, bool) {
    let mut defs_mask = 0u16;
    let mut clobbers_rsp = false;

    let stmts: Vec<&str> = gadget_text
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    for (idx, &stmt) in stmts.iter().enumerate() {
        let is_last = idx + 1 == stmts.len();
        let (mnem, rest) = match stmt.split_once(' ') {
            Some((m, r)) => (m.trim(), r.trim()),
            None => (stmt, ""),
        };
        match mnem {
            "ret" | "retn" | "nop" | "cmp" | "test" => {}
            "leave" => {
                clobbers_rsp = true;
                defs_mask |= 1 << 5; // rbp
            }
            "pop" => {
                if let Some(reg_idx) = gpr_name_to_index(rest) {
                    if reg_idx == 4 {
                        clobbers_rsp = true;
                    } else {
                        defs_mask |= 1 << reg_idx;
                    }
                }
            }
            "push" => {}
            "call" | "jmp" => {
                if !is_last {
                    clobbers_rsp = true;
                }
            }
            "xchg" => {
                for op in rest.split(',') {
                    if let Some(reg_idx) = gpr_name_to_index(op) {
                        if reg_idx == 4 {
                            clobbers_rsp = true;
                        } else {
                            defs_mask |= 1 << reg_idx;
                        }
                    }
                }
            }
            "cdq" | "cqo" => {
                defs_mask |= 1 << 2; // rdx
            }
            "mul" | "imul" if !rest.contains(',') => {
                defs_mask |= (1 << 0) | (1 << 2); // rax, rdx
            }
            _ => {
                let dst = rest.split(',').next().unwrap_or("").trim();
                if let Some(reg_idx) = gpr_name_to_index(dst) {
                    if reg_idx == 4 {
                        let is_const_adj = (mnem == "add" || mnem == "sub")
                            && rest
                                .split(',')
                                .nth(1)
                                .map(|rhs| gpr_name_to_index(rhs).is_none() && !rhs.contains('['))
                                .unwrap_or(false);
                        if !is_const_adj {
                            clobbers_rsp = true;
                        }
                    } else {
                        defs_mask |= 1 << reg_idx;
                    }
                }
            }
        }
    }
    (defs_mask, clobbers_rsp)
}

/// Analyze a formatted gadget for stack-controlled register loads (`pop <reg>` or
/// `mov <reg>, [rsp...]` without subsequent overwrite by a non-stack instruction).
/// Returns `(stack_loads_mask, all_defs_mask, clobbers_rsp_arbitrarily)`.
pub fn analyze_stack_controlled_gadget_dataflow(gadget_text: &str) -> (u16, u16, bool) {
    let (all_defs, mut clobbers_rsp) = analyze_gadget_dataflow(gadget_text);
    let mut stack_loads = 0u16;
    let stmts: Vec<&str> = gadget_text
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    for (idx, &stmt) in stmts.iter().enumerate() {
        let is_last = idx + 1 == stmts.len();
        let (mnem, rest) = match stmt.split_once(' ') {
            Some((m, r)) => (m.trim(), r.trim()),
            None => (stmt, ""),
        };
        match mnem {
            "pop" => {
                if let Some(reg_idx) = gpr_name_to_index(rest) {
                    if reg_idx != 4 {
                        stack_loads |= 1 << reg_idx;
                    }
                }
            }
            "mov" | "movzx" | "movsx" | "movsxd" => {
                let mut parts = rest.split(',');
                let dst = parts.next().unwrap_or("").trim();
                let src = parts.next().unwrap_or("").trim();
                if let Some(reg_idx) = gpr_name_to_index(dst) {
                    if reg_idx != 4 {
                        if src.contains("[rsp") || src.contains("[esp") {
                            stack_loads |= 1 << reg_idx;
                        } else {
                            stack_loads &= !(1 << reg_idx);
                        }
                    }
                }
            }
            "call" | "jmp" => {
                if !is_last {
                    clobbers_rsp = true;
                }
            }
            _ => {
                let dst = rest.split(',').next().unwrap_or("").trim();
                if let Some(reg_idx) = gpr_name_to_index(dst) {
                    if reg_idx != 4 {
                        stack_loads &= !(1 << reg_idx);
                    }
                }
            }
        }
    }
    (stack_loads, all_defs, clobbers_rsp)
}

/// One step in a register-dataflow-constrained ROP chain.
#[derive(Debug, Clone, Serialize)]
pub struct DataflowStep {
    /// Offset of the chosen gadget within the base `.text` section.
    pub offset: u64,
    /// Target architectural register index (`0..16`) this step is responsible for setting.
    pub goal_reg: u8,
    /// Bitmask of all GP registers defined by this gadget in the base binary.
    pub defs_mask: u16,
}

/// An ordered register-dataflow-constrained ROP chain where each step $i$ defines
/// `goal_regs[i]` without clobbering `RSP` or any register already defined by steps $0..i$.
#[derive(Debug, Clone, Serialize)]
pub struct DataflowChain {
    pub steps: Vec<DataflowStep>,
}

/// Synthesize a register-dataflow-constrained ROP chain for the ordered `goal_regs`
/// sequence (`0..16`, e.g. `[7, 6, 2, 0]` for System V `rdi, rsi, rdx, rax`).
pub fn synthesize_dataflow_chain(
    base: &GadgetSet,
    goal_regs: &[u8],
    rng: &mut Prng,
) -> Result<DataflowChain> {
    let analyzed: Vec<(u64, u16, bool)> = base
        .by_offset
        .iter()
        .map(|(&off, text)| {
            let (defs, clobbers_rsp) = analyze_gadget_dataflow(text);
            (off, defs, clobbers_rsp)
        })
        .collect();

    let mut established_mask = 0u16;
    let mut steps = Vec::with_capacity(goal_regs.len());
    for &goal_reg in goal_regs {
        let goal_bit = 1u16 << goal_reg;
        let candidates: Vec<(u64, u16)> = analyzed
            .iter()
            .filter(|&&(_off, defs, clobbers_rsp)| {
                !clobbers_rsp && (defs & goal_bit) != 0 && (defs & established_mask) == 0
            })
            .map(|&(off, defs, _)| (off, defs))
            .collect();
        if candidates.is_empty() {
            anyhow::bail!(
                "no non-clobbering gadget found for goal_reg={} with established_mask=0x{:04x}",
                goal_reg,
                established_mask
            );
        }
        let idx = rng.below(candidates.len() as u64) as usize;
        let (offset, defs_mask) = candidates[idx];
        steps.push(DataflowStep {
            offset,
            goal_reg,
            defs_mask,
        });
        established_mask |= goal_bit;
    }
    Ok(DataflowChain { steps })
}

/// Aggregate result of evaluating register-dataflow-constrained ROP chains against a morphed variant.
#[derive(Debug, Clone, Serialize)]
pub struct DataflowChainReport {
    pub chains: usize,
    pub chain_len: usize,
    pub static_dataflow_viable: usize,
    pub static_dataflow_viable_rate: f64,
    pub mean_step_dataflow_survival: f64,
    pub relocated_pool_satisfiable: bool,
}

/// Evaluate `n_chains` register-dataflow-constrained chains for `goal_regs` against `variant`.
pub fn evaluate_dataflow_chains(
    base: &GadgetSet,
    variant: &GadgetSet,
    goal_regs: &[u8],
    n_chains: usize,
    seed: u64,
) -> Result<DataflowChainReport> {
    let mut rng = Prng::new(seed);
    let mut static_viable = 0usize;
    let mut total_step_hits = 0usize;

    for _ in 0..n_chains {
        let chain = synthesize_dataflow_chain(base, goal_regs, &mut rng)?;
        let mut established_mask = 0u16;
        let mut chain_ok = true;
        for step in &chain.steps {
            let goal_bit = 1u16 << step.goal_reg;
            let base_text = base.by_offset.get(&step.offset);
            let step_ok = match (base_text, variant.by_offset.get(&step.offset)) {
                (Some(b_text), Some(v_text)) if b_text == v_text => {
                    let (v_defs, v_clobbers_rsp) = analyze_gadget_dataflow(v_text);
                    !v_clobbers_rsp && (v_defs & goal_bit) != 0 && (v_defs & established_mask) == 0
                }
                _ => false,
            };
            if step_ok {
                total_step_hits += 1;
            } else {
                chain_ok = false;
            }
            established_mask |= goal_bit;
        }
        if chain_ok {
            static_viable += 1;
        }
    }

    let mut check_rng = Prng::new(seed ^ 0xA5A5_5A5A);
    let relocated_pool_satisfiable =
        synthesize_dataflow_chain(variant, goal_regs, &mut check_rng).is_ok();

    let total_steps = (n_chains * goal_regs.len()).max(1) as f64;
    Ok(DataflowChainReport {
        chains: n_chains,
        chain_len: goal_regs.len(),
        static_dataflow_viable: static_viable,
        static_dataflow_viable_rate: static_viable as f64 / (n_chains.max(1) as f64),
        mean_step_dataflow_survival: total_step_hits as f64 / total_steps,
        relocated_pool_satisfiable,
    })
}

#[cfg(test)]
mod dataflow_tests {
    use super::*;
    use crate::{extract_gadgets, DEFAULT_MAX_INSTRS};

    #[test]
    fn analyze_gadget_dataflow_tracks_defs_and_rsp_clobbers() {
        let (defs1, rsp1) = analyze_gadget_dataflow("pop rdi; pop rsi; ret");
        assert_eq!(defs1, (1 << 7) | (1 << 6));
        assert!(!rsp1);

        let (defs2, rsp2) = analyze_gadget_dataflow("mov eax, 1; add rsp, 18h; ret");
        assert_eq!(defs2, 1 << 0);
        assert!(!rsp2, "constant add rsp, imm must not be flagged as arbitrary rsp clobber");

        let (_defs3, rsp3) = analyze_gadget_dataflow("pop rsp; ret");
        assert!(rsp3, "pop rsp is a stack pivot and must be flagged");

        let (_defs4, rsp4) = analyze_gadget_dataflow("pop rdi; call rax; ret");
        assert!(rsp4, "interior call before final instruction must be flagged");

        let (stack_defs, all_defs, _) =
            analyze_stack_controlled_gadget_dataflow("mov rdi, rbx; pop rsi; ret");
        assert_eq!(all_defs, (1 << 7) | (1 << 6));
        assert_eq!(
            stack_defs,
            1 << 6,
            "register-to-register mov without stack source must not count as stack-controlled"
        );
    }

    #[test]
    fn dataflow_chain_synthesis_enforces_non_clobbering_order_and_detects_morph_disruption() {
        let base_bytes = [0x5F, 0xC3, 0x5E, 0xC3, 0x5A, 0xC3, 0x89, 0xC8, 0xC3];
        let morph_bytes = [0x41, 0x5C, 0xC3, 0x41, 0x5D, 0xC3, 0x31, 0xC0, 0xC3];

        let base_gs = extract_gadgets(&base_bytes, 0x1000, DEFAULT_MAX_INSTRS);
        let morph_gs = extract_gadgets(&morph_bytes, 0x1000, DEFAULT_MAX_INSTRS);
        let goals = [7u8, 6, 2, 0];

        let self_rep = evaluate_dataflow_chains(&base_gs, &base_gs, &goals, 16, 42).unwrap();
        assert_eq!(self_rep.static_dataflow_viable, 16);
        assert_eq!(self_rep.static_dataflow_viable_rate, 1.0);

        let morph_rep = evaluate_dataflow_chains(&base_gs, &morph_gs, &goals, 16, 42).unwrap();
        assert_eq!(morph_rep.static_dataflow_viable, 0);
        assert!(morph_rep.mean_step_dataflow_survival < 0.5);
        assert!(!morph_rep.relocated_pool_satisfiable);
    }
}

