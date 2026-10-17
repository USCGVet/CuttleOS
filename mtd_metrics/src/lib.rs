//! Moving-target-defense measurement core (Phase 0 — the chronograph).
//!
//! The Proteus thesis is that morphing a kernel's internals destroys the
//! layout assumptions a memory-corruption / ROP exploit depends on. That
//! claim has, until now, been *asserted* — there was no number attached
//! to it. This module produces the number.
//!
//! # What it measures
//!
//! Given the compiled `.text` of two morph cycles (call them *base* and
//! *variant*), we enumerate the **gadget set** of each — every short
//! linear instruction sequence ending in a `ret`, indirect `jmp`, or
//! indirect `call` (the raw material of ROP / JOP / COP chains) — and
//! report two distinct survival rates:
//!
//! * **Positional survival** — the fraction of base gadgets that appear
//!   in the variant *at the same offset with identical semantics*. This
//!   is the number that matters most: it is exactly "does an exploit that
//!   hardcoded gadget addresses against the base cycle still work against
//!   the variant?" A strong diversifier drives this toward **0**.
//!
//! * **Semantic survival** — the fraction of base gadget *kinds* (ignoring
//!   address) still present *somewhere* in the variant. This models a
//!   stronger attacker who re-scans for gadgets each cycle. Driving this
//!   down requires changing *which* gadgets exist (instruction selection,
//!   register allocation), not merely *where* they sit. It is the harder
//!   bar and is not expected to move under offset-only diversification.
//!
//! The gap between the two is itself diagnostic: a diversifier that only
//! shifts code (e.g. stack padding) collapses positional survival while
//! leaving semantic survival near 1.0; one that rewrites code lowers both.
//!
//! # Scope of v0
//!
//! Gadgets are scanned with the standard unaligned-x86 method (try a
//! decode starting at every byte offset). The gadget identity is its
//! NASM-formatted instruction text, so `pop rax; ret` and `pop rbx; ret`
//! are correctly distinct. We do not yet model gadget *usefulness*
//! (Turing-complete gadget catalogues, register-class coverage) — that is
//! a Phase-0.2 refinement. Positional survival is meaningful on its own:
//! it is a direct, conservative proxy for "fraction of a fixed ROP chain
//! that still lands."

use std::collections::{BTreeMap, HashSet};

pub mod chainsim;

use anyhow::{Context, Result};
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter};
use object::{Object, ObjectSection, SectionKind};

/// Default cap on instructions per gadget. Real ROP gadgets are short;
/// 6 instructions before the terminator covers the overwhelming majority
/// of useful gadgets while keeping the scan cheap.
pub const DEFAULT_MAX_INSTRS: usize = 6;

/// A set of gadgets discovered in one `.text` image, keyed by their
/// **offset within `.text`** (the address an attacker would hardcode,
/// relative to the section base). The value is the gadget's normalized
/// instruction text — its semantic identity.
#[derive(Debug, Clone, Default)]
pub struct GadgetSet {
    pub by_offset: BTreeMap<u64, String>,
}

impl GadgetSet {
    pub fn len(&self) -> usize {
        self.by_offset.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_offset.is_empty()
    }
    /// Distinct gadget kinds (semantics, ignoring offset).
    pub fn distinct(&self) -> HashSet<&str> {
        self.by_offset.values().map(String::as_str).collect()
    }

    /// Distinct gadget kinds with numeric operands (immediates, absolute
    /// and rip-relative addresses, branch targets) masked out. This is the
    /// address-independent notion of "the same gadget": `call [rel 2E620h]`
    /// and `call [rel 3F100h]` collapse to one kind. Without this masking,
    /// pure relocation (every address shifting because code moved) masquerades
    /// as instruction-mix diversity and inflates the apparent churn.
    pub fn distinct_normalized(&self) -> HashSet<String> {
        self.by_offset.values().map(|g| normalize_gadget(g)).collect()
    }

    /// Distinct gadget kinds with both numeric operands AND general-purpose
    /// register names canonicalized to their width class (`r64`, `r32`,
    /// `r16`, `r8`), while keeping architectural stack/instruction pointers
    /// (`rsp`/`esp`/`sp`/`spl`, `rip`) distinct.
    ///
    /// This models **Attacker B_reg** (a leak-and-rebase attacker who also
    /// adapts to register permutations such as `pop r13; ret` substituting
    /// for `pop r12; ret`). Driving this metric down requires changing
    /// instruction mnemonics / opcode classes (`mov`↔`lea`, `xor`↔`sub`,
    /// `add`↔`lea`, `test`↔`or`↔`and`), not merely renaming registers.
    pub fn distinct_reg_canonicalized(&self) -> HashSet<String> {
        self.by_offset
            .values()
            .map(|g| canonicalize_registers_gadget(g))
            .collect()
    }
}

/// Mask numeric operands in a formatted gadget so two gadgets that differ
/// only by an address / immediate compare equal. A "number" is a run that
/// starts with a decimal digit (NASM renders hex as `2E620h`, `0FFh`, and
/// decimals bare), optionally with a `0x` prefix and a trailing `h`.
/// Register names (`rax`, `r13`, `xmm0`) start with a letter and are left
/// intact, so the masked form still distinguishes `pop rax` from `pop rbx`.
pub fn normalize_gadget(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    // A digit only starts a numeric *literal* if it is not preceded by an
    // identifier character — otherwise it is part of a register or symbol
    // name (`r13`, `xmm0`, `cr3`) and must be preserved.
    let mut prev_ident = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_digit() && !prev_ident {
            // Consume an optional 0x / 0X prefix.
            if c == '0' && i + 1 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
                i += 2;
            }
            while i < bytes.len() && (bytes[i] as char).is_ascii_hexdigit() {
                i += 1;
            }
            // Consume a trailing NASM hex marker.
            if i < bytes.len() && (bytes[i] == b'h' || bytes[i] == b'H') {
                i += 1;
            }
            out.push('N');
            prev_ident = true;
        } else {
            out.push(c);
            prev_ident = c.is_ascii_alphanumeric() || c == '_';
            i += 1;
        }
    }
    out
}

/// Canonicalize both numeric operands (`N`) and interchangeable general-purpose
/// registers (`r64`, `r32`, `r16`, `r8`) in a formatted gadget string.
///
/// Architectural stack pointers (`rsp`, `esp`, `sp`, `spl`) and instruction
/// pointers (`rip`, `eip`) are intentionally preserved because a stack-pivot
/// gadget (`pop rsp; ret`) cannot be replaced by a general-purpose register
/// pop (`pop r13; ret`).
pub fn canonicalize_registers_gadget(s: &str) -> String {
    let norm = normalize_gadget(s);
    let bytes = norm.as_bytes();
    let mut out = String::with_capacity(norm.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            i += 1;
            while i < bytes.len() {
                let ch = bytes[i] as char;
                if ch.is_ascii_alphanumeric() || ch == '_' {
                    i += 1;
                } else {
                    break;
                }
            }
            let tok = &norm[start..i];
            let replacement = match tok {
                "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "r8" | "r9" | "r10"
                | "r11" | "r12" | "r13" | "r14" | "r15" => "r64",
                "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "r8d" | "r9d" | "r10d"
                | "r11d" | "r12d" | "r13d" | "r14d" | "r15d" => "r32",
                "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "r8w" | "r9w" | "r10w"
                | "r11w" | "r12w" | "r13w" | "r14w" | "r15w" => "r16",
                "al" | "bl" | "cl" | "dl" | "ah" | "bh" | "ch" | "dh" | "sil" | "dil" | "bpl"
                | "r8b" | "r9b" | "r10b" | "r11b" | "r12b" | "r13b" | "r14b" | "r15b" => "r8",
                _ => tok,
            };
            out.push_str(replacement);
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Enumerate gadgets in `text`. `base_ip` is the virtual address the
/// section is loaded at (used only for rendering absolute targets in the
/// gadget text; offsets in the returned map are always relative to the
/// start of `text`). A gadget is a run of at most `max_instrs`
/// straight-line instructions terminated by a return or indirect branch /
/// call, containing no other control-flow transfer.
pub fn extract_gadgets(text: &[u8], base_ip: u64, max_instrs: usize) -> GadgetSet {
    let mut by_offset = BTreeMap::new();
    let mut formatter = NasmFormatter::new();
    let mut instr = Instruction::default();
    let mut rendered = String::new();

    for start in 0..text.len() {
        let mut decoder = Decoder::with_ip(
            64,
            &text[start..],
            base_ip + start as u64,
            DecoderOptions::NONE,
        );
        let mut seq: Vec<String> = Vec::with_capacity(max_instrs);
        let mut terminated = false;

        for _ in 0..max_instrs {
            if !decoder.can_decode() {
                break;
            }
            decoder.decode_out(&mut instr);
            if instr.code() == Code::INVALID {
                break;
            }
            rendered.clear();
            formatter.format(&instr, &mut rendered);
            match instr.flow_control() {
                FlowControl::Next => seq.push(rendered.clone()),
                FlowControl::Return | FlowControl::IndirectBranch | FlowControl::IndirectCall => {
                    seq.push(rendered.clone());
                    terminated = true;
                    break;
                }
                // A direct call/branch, interrupt, or exception in the
                // middle of the run means this is not a clean gadget.
                _ => break,
            }
        }

        if terminated && !seq.is_empty() {
            by_offset.insert(start as u64, seq.join("; "));
        }
    }

    GadgetSet { by_offset }
}

/// The headline measurement: how much of `base`'s attack surface survived
/// the morph into `variant`.
#[derive(Debug, Clone)]
pub struct ChurnReport {
    pub base_gadgets: usize,
    pub variant_gadgets: usize,
    pub base_distinct: usize,
    pub variant_distinct: usize,
    /// Gadgets present at the same offset with identical semantics.
    pub positional_survivors: usize,
    /// Distinct base gadget kinds (exact text, addresses included) still
    /// present anywhere in the variant.
    pub semantic_survivors: usize,
    /// Distinct base gadget kinds still present anywhere in the variant
    /// after masking numeric operands. This is the address-independent
    /// measure of real instruction-mix diversity — the number that is NOT
    /// inflated by pure relocation.
    pub base_distinct_normalized: usize,
    pub semantic_survivors_normalized: usize,
    /// Distinct base gadget kinds still present anywhere in the variant
    /// after masking BOTH numeric operands and interchangeable GP register
    /// names (`r64`/`r32`/`r16`/`r8`). Models an attacker who adapts to
    /// register permutations (`Attacker B_reg`).
    pub base_distinct_reg_canonicalized: usize,
    pub semantic_survivors_reg_canonicalized: usize,
}

impl ChurnReport {
    /// Fraction of base gadgets an offset-hardcoded chain would still find
    /// intact. Lower is better diversity. `0.0` when there are no base
    /// gadgets (nothing to survive).
    pub fn positional_survival(&self) -> f64 {
        if self.base_gadgets == 0 {
            0.0
        } else {
            self.positional_survivors as f64 / self.base_gadgets as f64
        }
    }
    /// Fraction of base gadget kinds (exact text) still available to a
    /// re-scanning attacker. Deflated by relocation — use
    /// [`Self::semantic_survival_normalized`] for the address-independent
    /// figure.
    pub fn semantic_survival(&self) -> f64 {
        if self.base_distinct == 0 {
            0.0
        } else {
            self.semantic_survivors as f64 / self.base_distinct as f64
        }
    }
    /// Fraction of base gadget *kinds* (numeric operands masked) still
    /// available anywhere in the variant. This isolates genuine
    /// instruction-mix diversity from mere code relocation: a high value
    /// means the morph moved gadgets around without changing which gadgets
    /// exist — the signature of weak (offset-only) diversity.
    pub fn semantic_survival_normalized(&self) -> f64 {
        if self.base_distinct_normalized == 0 {
            0.0
        } else {
            self.semantic_survivors_normalized as f64 / self.base_distinct_normalized as f64
        }
    }
    /// Fraction of base gadget *kinds* (numeric operands AND interchangeable
    /// GP registers canonicalized) still available anywhere in the variant.
    /// Isolates mnemonic/opcode-class diversity against an attacker who adapts
    /// to swapped registers (`Attacker B_reg`).
    pub fn semantic_survival_reg_canonicalized(&self) -> f64 {
        if self.base_distinct_reg_canonicalized == 0 {
            0.0
        } else {
            self.semantic_survivors_reg_canonicalized as f64
                / self.base_distinct_reg_canonicalized as f64
        }
    }
}

/// Compare two gadget sets. Positional survival counts offsets that hold
/// the *same* gadget in both images; semantic survival counts base gadget
/// kinds that reappear anywhere in the variant.
pub fn churn(base: &GadgetSet, variant: &GadgetSet) -> ChurnReport {
    let positional_survivors = base
        .by_offset
        .iter()
        .filter(|(off, g)| variant.by_offset.get(*off).map(String::as_str) == Some(g.as_str()))
        .count();

    let base_distinct = base.distinct();
    let variant_distinct = variant.distinct();
    let semantic_survivors = base_distinct
        .iter()
        .filter(|g| variant_distinct.contains(*g))
        .count();

    let base_distinct_norm = base.distinct_normalized();
    let variant_distinct_norm = variant.distinct_normalized();
    let semantic_survivors_normalized = base_distinct_norm
        .iter()
        .filter(|g| variant_distinct_norm.contains(*g))
        .count();

    let base_distinct_reg = base.distinct_reg_canonicalized();
    let variant_distinct_reg = variant.distinct_reg_canonicalized();
    let semantic_survivors_reg_canonicalized = base_distinct_reg
        .iter()
        .filter(|g| variant_distinct_reg.contains(*g))
        .count();

    ChurnReport {
        base_gadgets: base.len(),
        variant_gadgets: variant.len(),
        base_distinct: base_distinct.len(),
        variant_distinct: variant_distinct.len(),
        positional_survivors,
        semantic_survivors,
        base_distinct_normalized: base_distinct_norm.len(),
        semantic_survivors_normalized,
        base_distinct_reg_canonicalized: base_distinct_reg.len(),
        semantic_survivors_reg_canonicalized,
    }
}

impl std::fmt::Display for ChurnReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "gadgets: base={} variant={} (distinct: base={} variant={})",
            self.base_gadgets, self.variant_gadgets, self.base_distinct, self.variant_distinct
        )?;
        writeln!(
            f,
            "positional survival: {}/{} = {:.1}%   (lower = better — fraction of a fixed ROP chain that still lands)",
            self.positional_survivors,
            self.base_gadgets,
            self.positional_survival() * 100.0
        )?;
        writeln!(
            f,
            "semantic   survival: {}/{} = {:.1}%   (raw text — deflated by relocation)",
            self.semantic_survivors,
            self.base_distinct,
            self.semantic_survival() * 100.0
        )?;
        writeln!(
            f,
            "semantic   survival: {}/{} = {:.1}%   (address-masked — Attacker B exact-register survival)",
            self.semantic_survivors_normalized,
            self.base_distinct_normalized,
            self.semantic_survival_normalized() * 100.0
        )?;
        write!(
            f,
            "semantic   survival: {}/{} = {:.1}%   (reg-canonicalized — Attacker B_reg opcode-class survival)",
            self.semantic_survivors_reg_canonicalized,
            self.base_distinct_reg_canonicalized,
            self.semantic_survival_reg_canonicalized() * 100.0
        )
    }
}

/// One slice of the `.text` offset range, with how many base gadgets fell
/// in it and how many survived positionally. Used to visualize whether
/// gadget survival is uniform (real per-gadget diversity) or concentrated
/// in the low offsets (pure global shift — everything before the first
/// size change stays put, everything after moves).
#[derive(Debug, Clone)]
pub struct OffsetBucket {
    pub lo: u64,
    pub hi: u64,
    pub total: usize,
    pub survived: usize,
}

/// Bucket base gadgets by offset and report positional survival per bucket.
pub fn survivor_offset_buckets(
    base: &GadgetSet,
    variant: &GadgetSet,
    nbuckets: usize,
) -> Vec<OffsetBucket> {
    let nbuckets = nbuckets.max(1);
    let span = base.by_offset.keys().last().copied().unwrap_or(0) + 1;
    let width = span.div_ceil(nbuckets as u64).max(1);
    let mut buckets: Vec<OffsetBucket> = (0..nbuckets)
        .map(|i| OffsetBucket {
            lo: i as u64 * width,
            hi: ((i as u64 + 1) * width).min(span),
            total: 0,
            survived: 0,
        })
        .collect();
    for (off, g) in &base.by_offset {
        let bi = ((off / width) as usize).min(nbuckets - 1);
        buckets[bi].total += 1;
        if variant.by_offset.get(off).map(String::as_str) == Some(g.as_str()) {
            buckets[bi].survived += 1;
        }
    }
    buckets
}

/// Read the executable code of a compiled artifact (ELF, COFF/PE, or
/// Mach-O) and return `(bytes, base_address)`.
///
/// A linked ELF kernel has a single `.text`; an MSVC relocatable object
/// (what `rustc --emit obj` produces on Windows) scatters each function
/// into its own `.text$...` COMDAT section. We therefore aggregate **all**
/// `Text`-kind sections rather than the one literally named `.text`, in a
/// deterministic order (by address, then name) so the concatenated image
/// is comparable across morph variants. For a relocatable object this
/// image is the pure morphed code with no linked runtime diluting the
/// signal — exactly what we want to measure.
pub fn read_text_section(path: &std::path::Path) -> Result<(Vec<u8>, u64)> {
    let data = std::fs::read(path).with_context(|| format!("read artifact {}", path.display()))?;
    let file = object::File::parse(&*data)
        .with_context(|| format!("parse object file {}", path.display()))?;

    let mut texts: Vec<(u64, String, Vec<u8>)> = Vec::new();
    for sec in file.sections() {
        if sec.kind() != SectionKind::Text {
            continue;
        }
        if let Ok(bytes) = sec.data() {
            if !bytes.is_empty() {
                let name = sec.name().unwrap_or("").to_string();
                texts.push((sec.address(), name, bytes.to_vec()));
            }
        }
    }
    if texts.is_empty() {
        anyhow::bail!("no executable (.text) sections found in {}", path.display());
    }
    // Deterministic concatenation order. Linked images sort cleanly by
    // address; relocatable objects (all addresses 0) fall back to name,
    // which is stable across variants because the exported function names
    // do not morph.
    texts.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let base = texts[0].0;
    let mut out = Vec::new();
    for (_, _, bytes) in &texts {
        out.extend_from_slice(bytes);
    }
    Ok((out, base))
}

#[cfg(test)]
mod tests {
    use super::*;

    // pop rax (0x58) ; ret (0xc3)
    const POP_RAX_RET: &[u8] = &[0x58, 0xC3];

    #[test]
    fn extracts_pop_ret_gadget() {
        let g = extract_gadgets(POP_RAX_RET, 0, DEFAULT_MAX_INSTRS);
        // offset 0: "pop rax; ret", offset 1: "ret"
        assert_eq!(g.by_offset.get(&0).map(String::as_str), Some("pop rax; ret"));
        assert_eq!(g.by_offset.get(&1).map(String::as_str), Some("ret"));
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn identical_images_survive_fully() {
        let g = extract_gadgets(POP_RAX_RET, 0, DEFAULT_MAX_INSTRS);
        let r = churn(&g, &g);
        assert_eq!(r.positional_survival(), 1.0);
        assert_eq!(r.semantic_survival(), 1.0);
    }

    #[test]
    fn a_pure_shift_destroys_positional_but_not_semantic_survival() {
        // Prepending a nop (0x90) shifts every subsequent gadget by one
        // byte. An offset-hardcoded chain breaks completely, but every
        // gadget *kind* is still present — the signature of offset-only
        // diversity (e.g. stack padding).
        let base = extract_gadgets(POP_RAX_RET, 0, DEFAULT_MAX_INSTRS);
        let shifted_bytes = [&[0x90u8][..], POP_RAX_RET].concat();
        let variant = extract_gadgets(&shifted_bytes, 0, DEFAULT_MAX_INSTRS);

        let r = churn(&base, &variant);
        assert_eq!(r.positional_survivors, 0, "shift must break every fixed offset");
        assert_eq!(r.positional_survival(), 0.0);
        // "pop rax; ret" and "ret" both still exist in the variant.
        assert_eq!(r.semantic_survival(), 1.0);
    }

    #[test]
    fn disjoint_gadget_kinds_have_zero_semantic_survival() {
        // base: pop rax; ret    variant: pop rbx (0x5b); ret
        let base = extract_gadgets(&[0x58, 0xC3], 0, DEFAULT_MAX_INSTRS);
        let variant = extract_gadgets(&[0x5B, 0xC3], 0, DEFAULT_MAX_INSTRS);
        let r = churn(&base, &variant);
        // "ret" is shared; "pop rax; ret" is not present in the variant.
        assert!(r.semantic_survival() > 0.0 && r.semantic_survival() < 1.0);
        // Under register-canonicalized survival (Attacker B_reg), "pop rax; ret"
        // and "pop rbx; ret" both canonicalize to "pop r64; ret", so survival is 1.0!
        assert_eq!(r.semantic_survival_reg_canonicalized(), 1.0);
        // The bare "ret" at offset 1 is positionally identical.
        assert_eq!(r.positional_survivors, 1);
    }

    #[test]
    fn no_gadgets_in_pure_nops() {
        // 0x90 nop, no terminator: no gadgets at all.
        let g = extract_gadgets(&[0x90, 0x90, 0x90, 0x90], 0, DEFAULT_MAX_INSTRS);
        assert!(g.is_empty());
    }

    #[test]
    fn max_instrs_bounds_gadget_length() {
        // Five pops then a ret. With max_instrs=2 the gadget starting at
        // offset 0 cannot reach the ret, so it is not recorded; only the
        // tail (within 2 instrs of the ret) yields gadgets.
        let bytes = [0x58, 0x58, 0x58, 0x58, 0x58, 0xC3]; // pop rax x5 ; ret
        let g2 = extract_gadgets(&bytes, 0, 2);
        // offset 4 ("pop rax; ret") and offset 5 ("ret") only.
        assert_eq!(g2.by_offset.get(&4).map(String::as_str), Some("pop rax; ret"));
        assert_eq!(g2.by_offset.get(&5).map(String::as_str), Some("ret"));
        assert!(g2.by_offset.get(&0).is_none());
        // With a generous cap the full-length gadget is found.
        let g6 = extract_gadgets(&bytes, 0, 6);
        assert!(g6.by_offset.contains_key(&0));
    }

    #[test]
    fn normalize_masks_addresses_not_registers() {
        assert_eq!(normalize_gadget("call qword [rel 2E620h]"), "call qword [rel N]");
        assert_eq!(normalize_gadget("mov esi,8"), "mov esi,N");
        assert_eq!(normalize_gadget("mov r13,rdx"), "mov r13,rdx");
        assert_eq!(normalize_gadget("pop rax; ret"), "pop rax; ret");
        // Two gadgets differing only by address collapse to one kind...
        let a = normalize_gadget("jmp 1234h");
        let b = normalize_gadget("jmp 9ABCh");
        assert_eq!(a, b);
        // ...but differing registers stay distinct.
        assert_ne!(normalize_gadget("pop rax"), normalize_gadget("pop rbx"));
    }

    #[test]
    fn canonicalize_registers_collapses_gp_regs_and_preserves_rsp_and_mnemonics() {
        assert_eq!(
            canonicalize_registers_gadget("pop r12; ret"),
            canonicalize_registers_gadget("pop r13; ret")
        );
        assert_eq!(
            canonicalize_registers_gadget("mov eax,r14d; ret"),
            "mov r32,r32; ret"
        );
        // Stack pointer rsp/esp must NOT collapse to r64/r32 (stack pivot vs GP load).
        assert_ne!(
            canonicalize_registers_gadget("pop rsp; ret"),
            canonicalize_registers_gadget("pop r13; ret")
        );
        assert_eq!(canonicalize_registers_gadget("add rsp,28h; ret"), "add rsp,N; ret");
        // Different mnemonics stay distinct even after register canonicalization.
        assert_ne!(
            canonicalize_registers_gadget("mov rax,rcx; ret"),
            canonicalize_registers_gadget("lea rax,[rcx]; ret")
        );
    }

    #[test]
    fn indirect_call_terminates_a_gadget() {
        // pop rax (0x58) ; call rax (0xff 0xd0)
        let g = extract_gadgets(&[0x58, 0xFF, 0xD0], 0, DEFAULT_MAX_INSTRS);
        assert_eq!(g.by_offset.get(&0).map(String::as_str), Some("pop rax; call rax"));
    }
}
