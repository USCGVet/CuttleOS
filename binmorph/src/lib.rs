//! Post-link size-preserving x86-64 binary rewriter (`proteus-binmorph`).
//!
//! Rewrites compiled ELF `.text` functions in place using a deterministic
//! seed while preserving exact instruction-window byte lengths and execution
//! semantics. Because no byte offsets shift, all relative branches, calls,
//! RIP-relative displacements, and symbol table boundaries remain valid
//! without re-linking.
//!
//! # Rewriting Pipeline (`rewrite_function`)
//!
//! 1. **Callee-saved register permutation**: Permutes `{R12, R13, R14, R15}`
//!    (`r64`/`r32`/`r16`/`r8`) across the function body when matching
//!    prologue `push` and epilogue `pop` pairs are verified.
//! 2. **Leaf caller-saved scratch permutation**: Permutes `{R8, R9, R10, R11}`
//!    across leaf functions.
//! 3. **Return-block & tail-call scratch renaming**: Permutes caller-saved
//!    scratch registers (`{R8..R11}` and `{RCX, RSI, RDI}`) inside return
//!    basic blocks and before external tail jumps.
//! 4. **Prologue/epilogue stack-slot permutation**: Permutes adjacent
//!    callee-saved `push` order in the prologue and applies the exact reverse
//!    `pop` order in every epilogue.
//! 5. **Basic-block instruction commutation**: Applies seeded Fisher-Yates
//!    permutation over windows of up to 6 independent instructions, adjusting
//!    `[rip + disp32]` displacements when RIP-relative instructions move.
//! 6. **Opcode-class, multi-instruction & encoding morphing**: Rewrites
//!    instructions into equal-length semantic equivalents (`mov` ↔ `or`/`and`/`lea`/`xchg`,
//!    `add`/`sub` ↔ `lea`, `cmp`/`sub` ↔ `test`, cross-branch `CF/AF`-dead
//!    `add ↔ sub (-imm)`, 2-instruction small-immediate load decomposition,
//!    and ModR/M direction swaps) while scrubbing unintended `ret`
//!    (`0xC3/0xC2/0xCB/0xCA/0xCF`) and indirect `call/jmp` (`0xFF /2..5`)
//!    bytes from immediate and displacement fields.

use iced_x86::{Code, Decoder, DecoderOptions, Encoder, Instruction, Mnemonic, OpKind};

/// Deterministic seeded PRNG (splitmix64). Reproducible from the recorded
/// seed; that reproducibility is what lets the attestation chain replay a
/// diversified binary.
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
    /// `true` with ~50% probability.
    pub fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Functions whose code was scanned.
    pub functions: usize,
    /// Instructions decoded.
    pub instrs: usize,
    /// Reg-reg movs eligible for the encoding swap.
    pub candidates: usize,
    /// Candidates actually re-encoded into the alternate form.
    pub swapped: usize,
    /// Functions whose r14<->r15 callee-saved pair was swapped.
    pub reg_swapped_fns: usize,
    /// Instructions rewritten by the r14<->r15 swap.
    pub reg_remapped_instrs: usize,
}

/// Map any reg-reg `r/m, r` <-> `r, r/m` opcode (`MOV`, `ADD`, `OR`, `ADC`,
/// `SBB`, `AND`, `SUB`, `XOR`, `CMP`) to its opposite-direction encoding, or
/// `None` if this is not a swappable reg-reg instruction.
fn alternate_dir_code(code: Code) -> Option<Code> {
    Some(match code {
        // MOV
        Code::Mov_rm8_r8 => Code::Mov_r8_rm8,
        Code::Mov_r8_rm8 => Code::Mov_rm8_r8,
        Code::Mov_rm16_r16 => Code::Mov_r16_rm16,
        Code::Mov_r16_rm16 => Code::Mov_rm16_r16,
        Code::Mov_rm32_r32 => Code::Mov_r32_rm32,
        Code::Mov_r32_rm32 => Code::Mov_rm32_r32,
        Code::Mov_rm64_r64 => Code::Mov_r64_rm64,
        Code::Mov_r64_rm64 => Code::Mov_rm64_r64,
        // ADD
        Code::Add_rm8_r8 => Code::Add_r8_rm8,
        Code::Add_r8_rm8 => Code::Add_rm8_r8,
        Code::Add_rm16_r16 => Code::Add_r16_rm16,
        Code::Add_r16_rm16 => Code::Add_rm16_r16,
        Code::Add_rm32_r32 => Code::Add_r32_rm32,
        Code::Add_r32_rm32 => Code::Add_rm32_r32,
        Code::Add_rm64_r64 => Code::Add_r64_rm64,
        Code::Add_r64_rm64 => Code::Add_rm64_r64,
        // OR
        Code::Or_rm8_r8 => Code::Or_r8_rm8,
        Code::Or_r8_rm8 => Code::Or_rm8_r8,
        Code::Or_rm16_r16 => Code::Or_r16_rm16,
        Code::Or_r16_rm16 => Code::Or_rm16_r16,
        Code::Or_rm32_r32 => Code::Or_r32_rm32,
        Code::Or_r32_rm32 => Code::Or_rm32_r32,
        Code::Or_rm64_r64 => Code::Or_r64_rm64,
        Code::Or_r64_rm64 => Code::Or_rm64_r64,
        // ADC
        Code::Adc_rm8_r8 => Code::Adc_r8_rm8,
        Code::Adc_r8_rm8 => Code::Adc_rm8_r8,
        Code::Adc_rm16_r16 => Code::Adc_r16_rm16,
        Code::Adc_r16_rm16 => Code::Adc_rm16_r16,
        Code::Adc_rm32_r32 => Code::Adc_r32_rm32,
        Code::Adc_r32_rm32 => Code::Adc_rm32_r32,
        Code::Adc_rm64_r64 => Code::Adc_r64_rm64,
        Code::Adc_r64_rm64 => Code::Adc_rm64_r64,
        // SBB
        Code::Sbb_rm8_r8 => Code::Sbb_r8_rm8,
        Code::Sbb_r8_rm8 => Code::Sbb_rm8_r8,
        Code::Sbb_rm16_r16 => Code::Sbb_r16_rm16,
        Code::Sbb_r16_rm16 => Code::Sbb_rm16_r16,
        Code::Sbb_rm32_r32 => Code::Sbb_r32_rm32,
        Code::Sbb_r32_rm32 => Code::Sbb_rm32_r32,
        Code::Sbb_rm64_r64 => Code::Sbb_r64_rm64,
        Code::Sbb_r64_rm64 => Code::Sbb_rm64_r64,
        // AND
        Code::And_rm8_r8 => Code::And_r8_rm8,
        Code::And_r8_rm8 => Code::And_rm8_r8,
        Code::And_rm16_r16 => Code::And_r16_rm16,
        Code::And_r16_rm16 => Code::And_rm16_r16,
        Code::And_rm32_r32 => Code::And_r32_rm32,
        Code::And_r32_rm32 => Code::And_rm32_r32,
        Code::And_rm64_r64 => Code::And_r64_rm64,
        Code::And_r64_rm64 => Code::And_rm64_r64,
        // SUB
        Code::Sub_rm8_r8 => Code::Sub_r8_rm8,
        Code::Sub_r8_rm8 => Code::Sub_rm8_r8,
        Code::Sub_rm16_r16 => Code::Sub_r16_rm16,
        Code::Sub_r16_rm16 => Code::Sub_rm16_r16,
        Code::Sub_rm32_r32 => Code::Sub_r32_rm32,
        Code::Sub_r32_rm32 => Code::Sub_rm32_r32,
        Code::Sub_rm64_r64 => Code::Sub_r64_rm64,
        Code::Sub_r64_rm64 => Code::Sub_rm64_r64,
        // XOR
        Code::Xor_rm8_r8 => Code::Xor_r8_rm8,
        Code::Xor_r8_rm8 => Code::Xor_rm8_r8,
        Code::Xor_rm16_r16 => Code::Xor_r16_rm16,
        Code::Xor_r16_rm16 => Code::Xor_rm16_r16,
        Code::Xor_rm32_r32 => Code::Xor_r32_rm32,
        Code::Xor_r32_rm32 => Code::Xor_rm32_r32,
        Code::Xor_rm64_r64 => Code::Xor_r64_rm64,
        Code::Xor_r64_rm64 => Code::Xor_rm64_r64,
        // CMP
        Code::Cmp_rm8_r8 => Code::Cmp_r8_rm8,
        Code::Cmp_r8_rm8 => Code::Cmp_rm8_r8,
        Code::Cmp_rm16_r16 => Code::Cmp_r16_rm16,
        Code::Cmp_r16_rm16 => Code::Cmp_rm16_r16,
        Code::Cmp_rm32_r32 => Code::Cmp_r32_rm32,
        Code::Cmp_r32_rm32 => Code::Cmp_rm32_r32,
        Code::Cmp_rm64_r64 => Code::Cmp_r64_rm64,
        Code::Cmp_r64_rm64 => Code::Cmp_rm64_r64,
        _ => return None,
    })
}

/// If `instr` is a register-to-register `MOV`, return the equivalent
/// instruction in the opposite encoding direction. iced normalizes operand
/// order to (dst, src) for both directions, so the operands carry over
/// unchanged. Returns `None` for memory operands or any non-`MOV`.
pub fn swapped_reg_reg_mov(instr: &Instruction) -> Option<Instruction> {
    if instr.mnemonic() != Mnemonic::Mov || instr.op_count() != 2 {
        return None;
    }
    if instr.op0_kind() != OpKind::Register || instr.op1_kind() != OpKind::Register {
        return None;
    }
    let alt = alternate_dir_code(instr.code())?;
    Instruction::with2(alt, instr.op0_register(), instr.op1_register()).ok()
}

/// Map a 32-bit or 64-bit GP register to its 64-bit base register for `LEA`,
/// excluding `RSP`/`R12` (which require a SIB byte) and `RBP`/`R13` (which
/// require a displacement byte) so `[base64]` encodes in `mod=00` with zero
/// extra bytes.
fn lea_compatible_base64(reg: iced_x86::Register) -> Option<iced_x86::Register> {
    use iced_x86::Register::*;
    Some(match reg {
        RAX | EAX => RAX,
        RCX | ECX => RCX,
        RDX | EDX => RDX,
        RBX | EBX => RBX,
        RSI | ESI => RSI,
        RDI | EDI => RDI,
        R8 | R8D => R8,
        R9 | R9D => R9,
        R10 | R10D => R10,
        R11 | R11D => R11,
        R14 | R14D => R14,
        R15 | R15D => R15,
        _ => return Option::None,
    })
}

/// Map a 64-bit base register back to its 32-bit sub-register.
fn base64_to_reg32(reg: iced_x86::Register) -> Option<iced_x86::Register> {
    use iced_x86::Register::*;
    Some(match reg {
        RAX => EAX,
        RCX => ECX,
        RDX => EDX,
        RBX => EBX,
        RSI => ESI,
        RDI => EDI,
        R8 => R8D,
        R9 => R9D,
        R10 => R10D,
        R11 => R11D,
        R14 => R14D,
        R15 => R15D,
        _ => return Option::None,
    })
}

/// Morph any eligible instruction (`MOV`, `LEA`, `ADD`, `OR`, `ADC`, `SBB`,
/// `AND`, `SUB`, `XOR`, `CMP`, `TEST`) into a flag- and register-identical
/// alternative encoding (and where applicable, an equivalent mnemonic or
/// swapped commutative operand order).
///
/// * **`mov r32/64, r32/64` <-> `lea r32/64, [r64]`**: `LEA` is pure address
///   calculation (no memory access, no page faults, no flags touched) and
///   truncates/zero-extends 32-bit destinations identically to `MOV`. For any
///   source register other than `RSP/R12/RBP/R13`, `lea dst, [src64]` has the
///   exact same byte length as `mov dst, src` while changing the decoded
///   mnemonic (`mov` <-> `lea`).
/// * **Self-zeroing (`xor r, r` <-> `sub r, r`)**: when `op0 == op1`, both
///   zero the destination and set `CF=0, OF=0, ZF=1, SF=0, PF=1`. Can flip
///   mnemonic (`XOR` <-> `SUB`), encoding direction (`r/m,r` <-> `r,r/m`),
///   or both.
/// * **8/16/64-bit self-test (`test r, r` <-> `or r, r` <-> `and r, r`)**:
///   when `op0 == op1` on an 8-, 16-, or 64-bit GP register, all three leave
///   all 64 bits of the register unchanged and set identical `CF=0, OF=0,
///   SF, ZF, PF` flags. (32-bit `or/and` zero-extends upper 32 bits whereas
///   `test` does not, so 32-bit `test` is excluded.)
/// * **Distinct-register `test r1, r2` -> `test r2, r1`**: `TEST` is
///   commutative and writes no register; swapping distinct operands flips
///   both the ModR/M byte (`reg` <-> `rm`, `REX.R` <-> `REX.B`) and the
///   decoded operand order.
/// * **All 9 reg-reg direction-bit families**: swaps `r/m, r` <-> `r, r/m`.
pub fn morph_reg_reg_instr(instr: &Instruction, choice: u64) -> Option<Instruction> {
    // Special case A: `lea dst32/64, [base64]` (zero displacement, no index,
    // no segment override) -> `mov dst32/64, src32/64`.
    if instr.mnemonic() == Mnemonic::Lea
        && instr.op_count() == 2
        && instr.op0_kind() == OpKind::Register
        && instr.op1_kind() == OpKind::Memory
        && !instr.is_ip_rel_memory_operand()
        && instr.memory_index() == iced_x86::Register::None
        && instr.memory_displacement64() == 0
        && instr.segment_prefix() == iced_x86::Register::None
    {
        let dst = instr.op0_register();
        let base = instr.memory_base();
        let _ = lea_compatible_base64(base)?;
        match instr.code() {
            Code::Lea_r64_m => {
                let mov_code = if choice & 1 == 0 {
                    Code::Mov_rm64_r64
                } else {
                    Code::Mov_r64_rm64
                };
                return Instruction::with2(mov_code, dst, base).ok();
            }
            Code::Lea_r32_m => {
                let src32 = base64_to_reg32(base)?;
                let mov_code = if choice & 1 == 0 {
                    Code::Mov_rm32_r32
                } else {
                    Code::Mov_r32_rm32
                };
                return Instruction::with2(mov_code, dst, src32).ok();
            }
            _ => return None,
        }
    }

    // Special case B: `shl reg, 1` -> `add reg, reg`.
    // In x86-64, shifting a GP register left by 1 (`D0 /4` or `D1 /4`) is
    // 100% identical in result, byte length, and CF/OF/SF/ZF/PF flags to
    // adding the register to itself (`add reg, reg`).
    if instr.op0_kind() == OpKind::Register {
        let r0 = instr.op0_register();
        let add_code = match (instr.code(), choice & 1) {
            (Code::Shl_rm8_1, 0) => Some(Code::Add_rm8_r8),
            (Code::Shl_rm8_1, _) => Some(Code::Add_r8_rm8),
            (Code::Shl_rm16_1, 0) => Some(Code::Add_rm16_r16),
            (Code::Shl_rm16_1, _) => Some(Code::Add_r16_rm16),
            (Code::Shl_rm32_1, 0) => Some(Code::Add_rm32_r32),
            (Code::Shl_rm32_1, _) => Some(Code::Add_r32_rm32),
            (Code::Shl_rm64_1, 0) => Some(Code::Add_rm64_r64),
            (Code::Shl_rm64_1, _) => Some(Code::Add_r64_rm64),
            _ => None,
        };
        if let Some(ac) = add_code {
            return Instruction::with2(ac, r0, r0).ok();
        }
    }

    // Special case C: Commutative SIB `[base + index*1 + disp]` <->
    // `[index + base*1 + disp]` when both `base` and `index` are distinct
    // non-RSP/R12/RBP/R13 64-bit GP registers and `scale == 1`.
    if (0..instr.op_count()).any(|i| instr.op_kind(i) == OpKind::Memory)
        && !instr.is_ip_rel_memory_operand()
        && instr.memory_index_scale() == 1
    {
        let base = instr.memory_base();
        let index = instr.memory_index();
        if base != iced_x86::Register::None
            && index != iced_x86::Register::None
            && base != index
            && lea_compatible_base64(base) == Some(base)
            && lea_compatible_base64(index) == Some(index)
        {
            let mut ni = *instr;
            ni.set_memory_base(index);
            ni.set_memory_index(base);
            return Some(ni);
        }
    }

    if instr.op_count() != 2
        || instr.op0_kind() != OpKind::Register
        || instr.op1_kind() != OpKind::Register
    {
        return None;
    }
    let r0 = instr.op0_register();
    let r1 = instr.op1_register();

    // 0. `mov r32/64, r32/64` -> `lea r32/64, [r64]` (for choices 0, 1, 2 when
    //    `r1` is LEA-base-compatible) or opposite-direction `mov` (choice 3).
    //    `lea dst, [base64]` changes both the bytes and the disassembled
    //    mnemonic, and its ModR/M byte (`0x00..=0x3F`) can never be `0xC3`.
    if instr.mnemonic() == Mnemonic::Mov {
        if (choice & 0b11) != 3 {
            if let Some(base64) = lea_compatible_base64(r1) {
                let lea_code = match instr.code() {
                    Code::Mov_rm64_r64 | Code::Mov_r64_rm64 => Some(Code::Lea_r64_m),
                    Code::Mov_rm32_r32 | Code::Mov_r32_rm32 => Some(Code::Lea_r32_m),
                    _ => None,
                };
                if let Some(lc) = lea_code {
                    let mem = iced_x86::MemoryOperand::with_base(base64);
                    if let Ok(lea_instr) = Instruction::with2(lc, r0, mem) {
                        return Some(lea_instr);
                    }
                }
            }
        }
        let alt = alternate_dir_code(instr.code())?;
        return Instruction::with2(alt, r0, r1).ok();
    }

    // 0b. Self-addition `add r, r` <-> `shl r, 1` (or opposite-dir `add r, r`).
    if r0 == r1 && instr.mnemonic() == Mnemonic::Add {
        if (choice & 0b11) != 3 {
            let shl_code = match instr.code() {
                Code::Add_rm8_r8 | Code::Add_r8_rm8 => Some(Code::Shl_rm8_1),
                Code::Add_rm16_r16 | Code::Add_r16_rm16 => Some(Code::Shl_rm16_1),
                Code::Add_rm32_r32 | Code::Add_r32_rm32 => Some(Code::Shl_rm32_1),
                Code::Add_rm64_r64 | Code::Add_r64_rm64 => Some(Code::Shl_rm64_1),
                _ => None,
            };
            if let Some(sc) = shl_code {
                if let Ok(shl_instr) = Instruction::with2(sc, r0, 1u32) {
                    return Some(shl_instr);
                }
            }
        }
        let alt = alternate_dir_code(instr.code())?;
        return Instruction::with2(alt, r0, r1).ok();
    }

    // 0c. Commutative `xchg r1, r2` -> `xchg r2, r1` when `r1 != r2`.
    if instr.mnemonic() == Mnemonic::Xchg && r0 != r1 {
        return Instruction::with2(instr.code(), r1, r0).ok();
    }

    // 1. Self-zeroing: `xor r, r` <-> `sub r, r` (4 encodings total).
    if r0 == r1 && matches!(instr.mnemonic(), Mnemonic::Xor | Mnemonic::Sub) {
        let is_xor = instr.mnemonic() == Mnemonic::Xor;
        let code = match (instr.code(), choice & 0b11) {
            (Code::Xor_rm8_r8 | Code::Xor_r8_rm8 | Code::Sub_rm8_r8 | Code::Sub_r8_rm8, 0) => {
                if is_xor { Code::Sub_rm8_r8 } else { Code::Xor_rm8_r8 }
            }
            (Code::Xor_rm8_r8 | Code::Xor_r8_rm8 | Code::Sub_rm8_r8 | Code::Sub_r8_rm8, 1) => {
                if is_xor { Code::Sub_r8_rm8 } else { Code::Xor_r8_rm8 }
            }
            (Code::Xor_rm8_r8 | Code::Xor_r8_rm8 | Code::Sub_rm8_r8 | Code::Sub_r8_rm8, _) => {
                alternate_dir_code(instr.code())?
            }
            (
                Code::Xor_rm16_r16 | Code::Xor_r16_rm16 | Code::Sub_rm16_r16 | Code::Sub_r16_rm16,
                0,
            ) => {
                if is_xor { Code::Sub_rm16_r16 } else { Code::Xor_rm16_r16 }
            }
            (
                Code::Xor_rm16_r16 | Code::Xor_r16_rm16 | Code::Sub_rm16_r16 | Code::Sub_r16_rm16,
                1,
            ) => {
                if is_xor { Code::Sub_r16_rm16 } else { Code::Xor_r16_rm16 }
            }
            (
                Code::Xor_rm16_r16 | Code::Xor_r16_rm16 | Code::Sub_rm16_r16 | Code::Sub_r16_rm16,
                _,
            ) => alternate_dir_code(instr.code())?,
            (
                Code::Xor_rm32_r32 | Code::Xor_r32_rm32 | Code::Sub_rm32_r32 | Code::Sub_r32_rm32,
                c,
            ) => {
                // For upper registers `R8D..R15D`, both 32-bit (`0x45` REX) and
                // 64-bit (`0x4D` REX) self-zeroing are 3 bytes, zero all 64 bits
                // of `R8..R15`, and set identical flags (`CF=0, OF=0, ZF=1, SF=0, PF=1`).
                if let Some(fam) = upper_reg_family(r0) {
                    let (op_code, reg) = match c % 7 {
                        0 => (if is_xor { Code::Sub_rm32_r32 } else { Code::Xor_rm32_r32 }, fam.r32),
                        1 => (if is_xor { Code::Sub_r32_rm32 } else { Code::Xor_r32_rm32 }, fam.r32),
                        2 => (alternate_dir_code(instr.code())?, fam.r32),
                        3 => (Code::Xor_rm64_r64, fam.r64),
                        4 => (Code::Xor_r64_rm64, fam.r64),
                        5 => (Code::Sub_rm64_r64, fam.r64),
                        _ => (Code::Sub_r64_rm64, fam.r64),
                    };
                    if op_code != instr.code() {
                        return Instruction::with2(op_code, reg, reg).ok();
                    }
                }
                match c & 0b11 {
                    0 => if is_xor { Code::Sub_rm32_r32 } else { Code::Xor_rm32_r32 },
                    1 => if is_xor { Code::Sub_r32_rm32 } else { Code::Xor_r32_rm32 },
                    _ => alternate_dir_code(instr.code())?,
                }
            }
            (
                Code::Xor_rm64_r64 | Code::Xor_r64_rm64 | Code::Sub_rm64_r64 | Code::Sub_r64_rm64,
                c,
            ) => {
                if let Some(fam) = upper_reg_family(r0) {
                    let (op_code, reg) = match c % 7 {
                        0 => (if is_xor { Code::Sub_rm64_r64 } else { Code::Xor_rm64_r64 }, fam.r64),
                        1 => (if is_xor { Code::Sub_r64_rm64 } else { Code::Xor_r64_rm64 }, fam.r64),
                        2 => (alternate_dir_code(instr.code())?, fam.r64),
                        3 => (Code::Xor_rm32_r32, fam.r32),
                        4 => (Code::Xor_r32_rm32, fam.r32),
                        5 => (Code::Sub_rm32_r32, fam.r32),
                        _ => (Code::Sub_r32_rm32, fam.r32),
                    };
                    if op_code != instr.code() {
                        return Instruction::with2(op_code, reg, reg).ok();
                    }
                }
                match c & 0b11 {
                    0 => if is_xor { Code::Sub_rm64_r64 } else { Code::Xor_rm64_r64 },
                    1 => if is_xor { Code::Sub_r64_rm64 } else { Code::Xor_r64_rm64 },
                    _ => alternate_dir_code(instr.code())?,
                }
            }
            _ => return None,
        };
        if code != instr.code() {
            return Instruction::with2(code, r0, r1).ok();
        }
    }

    // 2. 8/16/64-bit self-test: `test r, r` <-> `or r, r` <-> `and r, r`.
    //    (32-bit is excluded in the context-free helper because `or/and r32, r32`
    //    zero-extends upper 32 bits of the 64-bit register whereas `test r32, r32`
    //    does not; see `morph_instr_with_context` when `upper32_zero` is proven.)
    if r0 == r1 {
        let code = match (instr.code(), choice & 0b11) {
            // 8-bit
            (Code::Test_rm8_r8, 0) => Some(Code::Or_rm8_r8),
            (Code::Test_rm8_r8, 1) => Some(Code::Or_r8_rm8),
            (Code::Test_rm8_r8, 2) => Some(Code::And_rm8_r8),
            (Code::Test_rm8_r8, _) => Some(Code::And_r8_rm8),
            (Code::Or_rm8_r8 | Code::Or_r8_rm8, 0) => Some(Code::Test_rm8_r8),
            (Code::Or_rm8_r8 | Code::Or_r8_rm8, 1) => Some(Code::And_rm8_r8),
            (Code::Or_rm8_r8 | Code::Or_r8_rm8, _) => alternate_dir_code(instr.code()),
            (Code::And_rm8_r8 | Code::And_r8_rm8, 0) => Some(Code::Test_rm8_r8),
            (Code::And_rm8_r8 | Code::And_r8_rm8, 1) => Some(Code::Or_rm8_r8),
            (Code::And_rm8_r8 | Code::And_r8_rm8, _) => alternate_dir_code(instr.code()),
            // 16-bit
            (Code::Test_rm16_r16, 0) => Some(Code::Or_rm16_r16),
            (Code::Test_rm16_r16, 1) => Some(Code::Or_r16_rm16),
            (Code::Test_rm16_r16, 2) => Some(Code::And_rm16_r16),
            (Code::Test_rm16_r16, _) => Some(Code::And_r16_rm16),
            (Code::Or_rm16_r16 | Code::Or_r16_rm16, 0) => Some(Code::Test_rm16_r16),
            (Code::Or_rm16_r16 | Code::Or_r16_rm16, 1) => Some(Code::And_rm16_r16),
            (Code::Or_rm16_r16 | Code::Or_r16_rm16, _) => alternate_dir_code(instr.code()),
            (Code::And_rm16_r16 | Code::And_r16_rm16, 0) => Some(Code::Test_rm16_r16),
            (Code::And_rm16_r16 | Code::And_r16_rm16, 1) => Some(Code::Or_rm16_r16),
            (Code::And_rm16_r16 | Code::And_r16_rm16, _) => alternate_dir_code(instr.code()),
            // 64-bit
            (Code::Test_rm64_r64, 0) => Some(Code::Or_rm64_r64),
            (Code::Test_rm64_r64, 1) => Some(Code::Or_r64_rm64),
            (Code::Test_rm64_r64, 2) => Some(Code::And_rm64_r64),
            (Code::Test_rm64_r64, _) => Some(Code::And_r64_rm64),
            (Code::Or_rm64_r64 | Code::Or_r64_rm64, 0) => Some(Code::Test_rm64_r64),
            (Code::Or_rm64_r64 | Code::Or_r64_rm64, 1) => Some(Code::And_rm64_r64),
            (Code::Or_rm64_r64 | Code::Or_r64_rm64, _) => alternate_dir_code(instr.code()),
            (Code::And_rm64_r64 | Code::And_r64_rm64, 0) => Some(Code::Test_rm64_r64),
            (Code::And_rm64_r64 | Code::And_r64_rm64, 1) => Some(Code::Or_rm64_r64),
            (Code::And_rm64_r64 | Code::And_r64_rm64, _) => alternate_dir_code(instr.code()),
            _ => None,
        };
        if let Some(c) = code {
            return Instruction::with2(c, r0, r1).ok();
        }
    }

    // 3. Commutative `test r1, r2` -> `test r2, r1` when `r1 != r2`.
    if instr.mnemonic() == Mnemonic::Test && r0 != r1 {
        return Instruction::with2(instr.code(), r1, r0).ok();
    }

    // 4. General opposite-direction encoding swap (`MOV`, `ADD`, `OR`, `ADC`,
    //    `SBB`, `AND`, `SUB`, `XOR`, `CMP`).
    let alt = alternate_dir_code(instr.code())?;
    Instruction::with2(alt, r0, r1).ok()
}

/// Context-sensitive instruction morphing: unlocks additional size- and
/// semantics-preserving transformations when intra-block liveness proves:
/// - `dead_flags`: all 6 arithmetic flags (`CF, OF, SF, ZF, PF, AF`) are
///   overwritten before any flag read or reached `ret`.
/// - `upper32_zero`: the upper 32 bits of `op0`'s 64-bit register were already
///   zeroed by the immediately preceding instruction in the same basic block.
fn morph_instr_with_context(
    instr: &Instruction,
    choice: u64,
    dead_flags: bool,
    cf_af_dead: bool,
    upper32_zero: bool,
    src_reg_dead: bool,
) -> Option<Instruction> {
    // 0. Dead-source register `mov/lea dst, src <-> xchg dst, src / xchg src, dst`:
    //    When `src` is provably dead after `instr` (overwritten in the same basic
    //    block before any read, or caller-saved non-return `{RCX, RSI, RDI, R8..R11}`
    //    at `ret`), `xchg dst, src` writes `old_src` into `dst`, leaves `RFLAGS`
    //    untouched, and changes the mnemonic to `xchg` (even for `RBP/R13/R12`!).
    if src_reg_dead && matches!(choice & 0b111, 4 | 5) {
        if instr.mnemonic() == Mnemonic::Mov
            && instr.op_count() == 2
            && instr.op0_kind() == OpKind::Register
            && instr.op1_kind() == OpKind::Register
        {
            let dst = instr.op0_register();
            let src = instr.op1_register();
            if dst != src
                && gp_reg_index(dst) != Some(4)
                && gp_reg_index(src) != Some(4)
            {
                let xchg_code = match instr.code() {
                    Code::Mov_rm64_r64 | Code::Mov_r64_rm64 => Some(Code::Xchg_rm64_r64),
                    Code::Mov_rm32_r32 | Code::Mov_r32_rm32 => Some(Code::Xchg_rm32_r32),
                    _ => None,
                };
                if let Some(xc) = xchg_code {
                    let (a, b) = if (choice & 1) == 0 { (dst, src) } else { (src, dst) };
                    if let Ok(xi) = Instruction::with2(xc, a, b) {
                        return Some(xi);
                    }
                }
            }
        } else if instr.mnemonic() == Mnemonic::Lea
            && instr.op_count() == 2
            && instr.op0_kind() == OpKind::Register
            && instr.op1_kind() == OpKind::Memory
            && !instr.is_ip_rel_memory_operand()
            && instr.memory_index() == iced_x86::Register::None
            && instr.memory_displacement64() == 0
            && instr.segment_prefix() == iced_x86::Register::None
        {
            let dst = instr.op0_register();
            let base = instr.memory_base();
            if gp_reg_index(dst) != gp_reg_index(base)
                && gp_reg_index(dst) != Some(4)
                && gp_reg_index(base) != Some(4)
            {
                match instr.code() {
                    Code::Lea_r64_m => {
                        let (a, b) = if (choice & 1) == 0 { (dst, base) } else { (base, dst) };
                        if let Ok(xi) = Instruction::with2(Code::Xchg_rm64_r64, a, b) {
                            return Some(xi);
                        }
                    }
                    Code::Lea_r32_m => {
                        if let Some(src32) = base64_to_reg32(base) {
                            let (a, b) = if (choice & 1) == 0 { (dst, src32) } else { (src32, dst) };
                            if let Ok(xi) = Instruction::with2(Code::Xchg_rm32_r32, a, b) {
                                return Some(xi);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // 1. 32-bit self-test `test r32, r32 <-> or r32, r32 <-> and r32, r32` when
    //    `upper32_zero` is proven (so zero-extension of `or/and` is a no-op).
    if upper32_zero
        && instr.op_count() == 2
        && instr.op0_kind() == OpKind::Register
        && instr.op1_kind() == OpKind::Register
        && instr.op0_register() == instr.op1_register()
    {
        let r0 = instr.op0_register();
        let code = match (instr.code(), choice & 0b11) {
            (Code::Test_rm32_r32, 0) => Some(Code::Or_rm32_r32),
            (Code::Test_rm32_r32, 1) => Some(Code::Or_r32_rm32),
            (Code::Test_rm32_r32, 2) => Some(Code::And_rm32_r32),
            (Code::Test_rm32_r32, _) => Some(Code::And_r32_rm32),
            (Code::Or_rm32_r32 | Code::Or_r32_rm32, 0) => Some(Code::Test_rm32_r32),
            (Code::Or_rm32_r32 | Code::Or_r32_rm32, 1) => Some(Code::And_rm32_r32),
            (Code::Or_rm32_r32 | Code::Or_r32_rm32, _) => alternate_dir_code(instr.code()),
            (Code::And_rm32_r32 | Code::And_r32_rm32, 0) => Some(Code::Test_rm32_r32),
            (Code::And_rm32_r32 | Code::And_r32_rm32, 1) => Some(Code::Or_rm32_r32),
            (Code::And_rm32_r32 | Code::And_r32_rm32, _) => alternate_dir_code(instr.code()),
            _ => None,
        };
        if let Some(c) = code {
            return Instruction::with2(c, r0, r0).ok();
        }
    }

    // 2. Dead-flags / `CF,AF`-dead transformations (`add <-> sub -imm <-> lea [reg + disp]`):
    //    Note that `ADD r, k` and `SUB r, -k` (for `k != 0, k != MIN`) produce the
    //    exact same register result AND identical `ZF, SF, OF, PF` flags, differing
    //    only in `CF` and `AF`. Thus `add <-> sub -imm` is valid whenever `cf_af_dead`
    //    holds, while `add/sub <-> lea` requires `dead_flags` (all 6 flags dead).
    if dead_flags || cf_af_dead {
        if instr.op_count() == 2 && instr.op0_kind() == OpKind::Register {
            let r0 = instr.op0_register();
            match instr.code() {
                Code::Add_rm64_imm8 | Code::Sub_rm64_imm8 => {
                    let imm = instr.immediate8() as i8;
                    if imm != 0 && imm != i8::MIN {
                        let signed_disp = if instr.code() == Code::Add_rm64_imm8 {
                            imm as i64
                        } else {
                            -(imm as i64)
                        };
                        let neg_imm = (-imm) as i32;
                        if dead_flags && (choice & 1) == 0 {
                            if let Some(base64) = lea_disp_compatible_base64(r0) {
                                let mem = iced_x86::MemoryOperand::with_base_displ(base64, signed_disp);
                                if let Ok(lea) = Instruction::with2(Code::Lea_r64_m, r0, mem) {
                                    return Some(lea);
                                }
                            }
                        }
                        let opp = if instr.code() == Code::Add_rm64_imm8 {
                            Code::Sub_rm64_imm8
                        } else {
                            Code::Add_rm64_imm8
                        };
                        return Instruction::with2(opp, r0, neg_imm).ok();
                    }
                }
                Code::Add_rm32_imm8 | Code::Sub_rm32_imm8 => {
                    let imm = instr.immediate8() as i8;
                    if imm != 0 && imm != i8::MIN {
                        let signed_disp = if instr.code() == Code::Add_rm32_imm8 {
                            imm as i64
                        } else {
                            -(imm as i64)
                        };
                        let neg_imm = (-imm) as i32;
                        if dead_flags && (choice & 1) == 0 {
                            if let Some(base64) = lea_disp_compatible_base64(r0) {
                                let mem = iced_x86::MemoryOperand::with_base_displ(base64, signed_disp);
                                if let Ok(lea) = Instruction::with2(Code::Lea_r32_m, r0, mem) {
                                    return Some(lea);
                                }
                            }
                        }
                        let opp = if instr.code() == Code::Add_rm32_imm8 {
                            Code::Sub_rm32_imm8
                        } else {
                            Code::Add_rm32_imm8
                        };
                        return Instruction::with2(opp, r0, neg_imm).ok();
                    }
                }
                Code::Add_rm64_imm32 | Code::Sub_rm64_imm32 => {
                    let imm = instr.immediate32() as i32;
                    if imm != 0
                        && imm != i32::MIN
                        && !(-128..=127).contains(&imm)
                        && !(-128..=127).contains(&(-imm))
                    {
                        let signed_disp = if instr.code() == Code::Add_rm64_imm32 {
                            imm as i64
                        } else {
                            -(imm as i64)
                        };
                        if dead_flags && (choice & 1) == 0 {
                            if let Some(base64) = lea_disp_compatible_base64(r0) {
                                let mem =
                                    iced_x86::MemoryOperand::with_base_displ(base64, signed_disp);
                                if let Ok(lea) = Instruction::with2(Code::Lea_r64_m, r0, mem) {
                                    return Some(lea);
                                }
                            }
                        }
                        let opp = if instr.code() == Code::Add_rm64_imm32 {
                            Code::Sub_rm64_imm32
                        } else {
                            Code::Add_rm64_imm32
                        };
                        return Instruction::with2(opp, r0, -imm).ok();
                    }
                }
                Code::Add_rm32_imm32 | Code::Sub_rm32_imm32 => {
                    let imm = instr.immediate32() as i32;
                    if imm != 0
                        && imm != i32::MIN
                        && !(-128..=127).contains(&imm)
                        && !(-128..=127).contains(&(-imm))
                    {
                        let signed_disp = if instr.code() == Code::Add_rm32_imm32 {
                            imm as i64
                        } else {
                            -(imm as i64)
                        };
                        if dead_flags && (choice & 1) == 0 {
                            if let Some(base64) = lea_disp_compatible_base64(r0) {
                                let mem =
                                    iced_x86::MemoryOperand::with_base_displ(base64, signed_disp);
                                if let Ok(lea) = Instruction::with2(Code::Lea_r32_m, r0, mem) {
                                    return Some(lea);
                                }
                            }
                        }
                        let opp = if instr.code() == Code::Add_rm32_imm32 {
                            Code::Sub_rm32_imm32
                        } else {
                            Code::Add_rm32_imm32
                        };
                        return Instruction::with2(opp, r0, -imm).ok();
                    }
                }
                Code::Add_RAX_imm32 | Code::Sub_RAX_imm32 => {
                    let imm = instr.immediate32() as i32;
                    if imm != 0
                        && imm != i32::MIN
                        && !(-128..=127).contains(&imm)
                        && !(-128..=127).contains(&(-imm))
                    {
                        let opp = if instr.code() == Code::Add_RAX_imm32 {
                            Code::Sub_RAX_imm32
                        } else {
                            Code::Add_RAX_imm32
                        };
                        return Instruction::with2(opp, r0, -imm).ok();
                    }
                }
                Code::Add_EAX_imm32 | Code::Sub_EAX_imm32 => {
                    let imm = instr.immediate32() as i32;
                    if imm != 0
                        && imm != i32::MIN
                        && !(-128..=127).contains(&imm)
                        && !(-128..=127).contains(&(-imm))
                    {
                        let opp = if instr.code() == Code::Add_EAX_imm32 {
                            Code::Sub_EAX_imm32
                        } else {
                            Code::Add_EAX_imm32
                        };
                        return Instruction::with2(opp, r0, -imm).ok();
                    }
                }
                _ => {}
            }
        }
    }

    if dead_flags {
        // 2b. `lea r32/64, [base64 + disp8/disp32]` (where `dst == base` and
        //     `disp != 0`) -> `add/sub r32/64, imm8/imm32`.
        if instr.mnemonic() == Mnemonic::Lea
            && instr.op_count() == 2
            && instr.op0_kind() == OpKind::Register
            && instr.op1_kind() == OpKind::Memory
            && !instr.is_ip_rel_memory_operand()
            && instr.memory_index() == iced_x86::Register::None
            && instr.segment_prefix() == iced_x86::Register::None
        {
            let disp = instr.memory_displacement64() as i64;
            let dst = instr.op0_register();
            let base = instr.memory_base();
            if (-127..=127).contains(&disp) && disp != 0 {
                match instr.code() {
                    Code::Lea_r64_m if dst == base => {
                        let (op_code, imm) = if (choice & 1) == 0 {
                            (Code::Add_rm64_imm8, disp as i32)
                        } else {
                            (Code::Sub_rm64_imm8, (-disp) as i32)
                        };
                        return Instruction::with2(op_code, dst, imm).ok();
                    }
                    Code::Lea_r32_m if base64_to_reg32(base) == Some(dst) => {
                        let (op_code, imm) = if (choice & 1) == 0 {
                            (Code::Add_rm32_imm8, disp as i32)
                        } else {
                            (Code::Sub_rm32_imm8, (-disp) as i32)
                        };
                        return Instruction::with2(op_code, dst, imm).ok();
                    }
                    _ => {}
                }
            } else if disp >= (i32::MIN as i64) + 1
                && disp <= i32::MAX as i64
                && !(-128..=127).contains(&disp)
                && !(-128..=127).contains(&(-disp))
            {
                match instr.code() {
                    Code::Lea_r64_m if dst == base => {
                        let (op_code, imm) = if (choice & 1) == 0 {
                            (Code::Add_rm64_imm32, disp as i32)
                        } else {
                            (Code::Sub_rm64_imm32, (-disp) as i32)
                        };
                        return Instruction::with2(op_code, dst, imm).ok();
                    }
                    Code::Lea_r32_m if base64_to_reg32(base) == Some(dst) => {
                        let (op_code, imm) = if (choice & 1) == 0 {
                            (Code::Add_rm32_imm32, disp as i32)
                        } else {
                            (Code::Sub_rm32_imm32, (-disp) as i32)
                        };
                        return Instruction::with2(op_code, dst, imm).ok();
                    }
                    _ => {}
                }
            }
        }
    }

    // 3. Flag-independent 7-byte immediate load morph:
    //    `mov r64, imm32` (`48 C7 C0+r imm32`, 7 bytes, for `RAX..RDI` when `imm32 > 0`)
    //    <-> `lea r32, [disp32]` (`8D 04+8*r 25 disp32`, 7 bytes, zero-extends to `r64`
    //    without touching flags or accessing memory).
    if instr.code() == Code::Mov_rm64_imm32
        && instr.op0_kind() == OpKind::Register
        && (instr.immediate32() as i32) > 0
    {
        if let Some(dst32) = base64_to_reg32(instr.op0_register()) {
            let imm = instr.immediate32() as u32 as u64;
            let mem = iced_x86::MemoryOperand::with_displ(imm, 8);
            if let Ok(lea) = Instruction::with2(Code::Lea_r32_m, dst32, mem) {
                return Some(lea);
            }
        }
    }
    if instr.code() == Code::Lea_r32_m
        && instr.op0_kind() == OpKind::Register
        && instr.op1_kind() == OpKind::Memory
        && !instr.is_ip_rel_memory_operand()
        && instr.memory_base() == iced_x86::Register::None
        && instr.memory_index() == iced_x86::Register::None
        && instr.segment_prefix() == iced_x86::Register::None
    {
        let disp = instr.memory_displacement64() as i64;
        if disp > 0 && disp <= i32::MAX as i64 {
            if let Some(dst64) = reg32_to_base64_low8(instr.op0_register()) {
                if let Ok(mov) = Instruction::with2(Code::Mov_rm64_imm32, dst64, disp as i32) {
                    return Some(mov);
                }
            }
        }
    }

    morph_reg_reg_instr(instr, choice)
}

fn reg32_to_base64_low8(reg: iced_x86::Register) -> Option<iced_x86::Register> {
    use iced_x86::Register::*;
    Some(match reg {
        EAX => RAX,
        ECX => RCX,
        EDX => RDX,
        EBX => RBX,
        ESP => RSP,
        EBP => RBP,
        ESI => RSI,
        EDI => RDI,
        _ => return Option::None,
    })
}

/// Map a 32/64-bit register to its 64-bit base register for `lea dst, [base + disp8]`,
/// excluding `RSP` and `R12` (which require a SIB byte). Note that `RBP` and `R13`
/// DO NOT require a SIB byte when `disp8 != 0`.
fn lea_disp_compatible_base64(reg: iced_x86::Register) -> Option<iced_x86::Register> {
    use iced_x86::Register::*;
    Some(match reg {
        RAX | EAX => RAX,
        RCX | ECX => RCX,
        RDX | EDX => RDX,
        RBX | EBX => RBX,
        RBP | EBP => RBP,
        RSI | ESI => RSI,
        RDI | EDI => RDI,
        R8 | R8D => R8,
        R9 | R9D => R9,
        R10 | R10D => R10,
        R11 | R11D => R11,
        R13 | R13D => R13,
        R14 | R14D => R14,
        R15 | R15D => R15,
        _ => return Option::None,
    })
}

/// A 64-bit general-purpose register and its 32-, 16-, and 8-bit sub-registers.
///
/// Any valid per-function register rename on x86-64 MUST remap all four
/// widths simultaneously: LLVM routinely pushes the 64-bit register in the
/// prologue (`push r14`) and then operates on `r14d` (32-bit), `r14w`
/// (16-bit), or `r14b` (8-bit) in the function body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegFamily {
    pub r64: iced_x86::Register,
    pub r32: iced_x86::Register,
    pub r16: iced_x86::Register,
    pub r8: iced_x86::Register,
}

impl RegFamily {
    pub const fn new(
        r64: iced_x86::Register,
        r32: iced_x86::Register,
        r16: iced_x86::Register,
        r8: iced_x86::Register,
    ) -> Self {
        Self { r64, r32, r16, r8 }
    }

    #[inline]
    pub fn contains(&self, r: iced_x86::Register) -> bool {
        r == self.r64 || r == self.r32 || r == self.r16 || r == self.r8
    }
}

pub const FAM_RCX: RegFamily = RegFamily::new(
    iced_x86::Register::RCX,
    iced_x86::Register::ECX,
    iced_x86::Register::CX,
    iced_x86::Register::CL,
);
pub const FAM_RSI: RegFamily = RegFamily::new(
    iced_x86::Register::RSI,
    iced_x86::Register::ESI,
    iced_x86::Register::SI,
    iced_x86::Register::SIL,
);
pub const FAM_RDI: RegFamily = RegFamily::new(
    iced_x86::Register::RDI,
    iced_x86::Register::EDI,
    iced_x86::Register::DI,
    iced_x86::Register::DIL,
);
pub const FAM_R8: RegFamily = RegFamily::new(
    iced_x86::Register::R8,
    iced_x86::Register::R8D,
    iced_x86::Register::R8W,
    iced_x86::Register::R8L,
);
pub const FAM_R9: RegFamily = RegFamily::new(
    iced_x86::Register::R9,
    iced_x86::Register::R9D,
    iced_x86::Register::R9W,
    iced_x86::Register::R9L,
);
pub const FAM_R10: RegFamily = RegFamily::new(
    iced_x86::Register::R10,
    iced_x86::Register::R10D,
    iced_x86::Register::R10W,
    iced_x86::Register::R10L,
);
pub const FAM_R11: RegFamily = RegFamily::new(
    iced_x86::Register::R11,
    iced_x86::Register::R11D,
    iced_x86::Register::R11W,
    iced_x86::Register::R11L,
);
pub const FAM_R12: RegFamily = RegFamily::new(
    iced_x86::Register::R12,
    iced_x86::Register::R12D,
    iced_x86::Register::R12W,
    iced_x86::Register::R12L,
);
pub const FAM_R13: RegFamily = RegFamily::new(
    iced_x86::Register::R13,
    iced_x86::Register::R13D,
    iced_x86::Register::R13W,
    iced_x86::Register::R13L,
);
pub const FAM_R14: RegFamily = RegFamily::new(
    iced_x86::Register::R14,
    iced_x86::Register::R14D,
    iced_x86::Register::R14W,
    iced_x86::Register::R14L,
);
pub const FAM_R15: RegFamily = RegFamily::new(
    iced_x86::Register::R15,
    iced_x86::Register::R15D,
    iced_x86::Register::R15W,
    iced_x86::Register::R15L,
);

fn upper_reg_family(r: iced_x86::Register) -> Option<RegFamily> {
    for fam in [
        FAM_R8, FAM_R9, FAM_R10, FAM_R11, FAM_R12, FAM_R13, FAM_R14, FAM_R15,
    ] {
        if fam.contains(r) {
            return Some(fam);
        }
    }
    None
}

/// Swap occurrences of register family `a` and `b` across all 4 sub-register
/// widths (`64`, `32`, `16`, `8`-bit).
fn swap_family_reg(r: iced_x86::Register, a: &RegFamily, b: &RegFamily) -> iced_x86::Register {
    if r == a.r64 {
        b.r64
    } else if r == a.r32 {
        b.r32
    } else if r == a.r16 {
        b.r16
    } else if r == a.r8 {
        b.r8
    } else if r == b.r64 {
        a.r64
    } else if r == b.r32 {
        a.r32
    } else if r == b.r16 {
        a.r16
    } else if r == b.r8 {
        a.r8
    } else {
        r
    }
}

/// `true` if any operand register or memory base/index of `instr` belongs to `fam`.
fn touches_family(instr: &Instruction, fam: &RegFamily) -> bool {
    for i in 0..instr.op_count() {
        if instr.op_kind(i) == OpKind::Register && fam.contains(instr.op_register(i)) {
            return true;
        }
    }
    fam.contains(instr.memory_base()) || fam.contains(instr.memory_index())
}

/// Return a copy of `instr` with register families `a` and `b` swapped
/// everywhere (operand registers + memory base/index).
fn remap_family_pair(instr: &Instruction, a: &RegFamily, b: &RegFamily) -> Instruction {
    let mut ni = *instr;
    for i in 0..ni.op_count() {
        if ni.op_kind(i) == OpKind::Register {
            let r = swap_family_reg(ni.op_register(i), a, b);
            ni.set_op_register(i, r);
        }
    }
    let mb = ni.memory_base();
    if a.contains(mb) || b.contains(mb) {
        ni.set_memory_base(swap_family_reg(mb, a, b));
    }
    let mi = ni.memory_index();
    if a.contains(mi) || b.contains(mi) {
        ni.set_memory_index(swap_family_reg(mi, a, b));
    }
    ni
}

/// Swap occurrences of `a` and `b` in a register: `a`->`b`, `b`->`a`, else
/// unchanged.
fn swap_one(r: iced_x86::Register, a: iced_x86::Register, b: iced_x86::Register) -> iced_x86::Register {
    if r == a {
        b
    } else if r == b {
        a
    } else {
        r
    }
}

/// `true` if any operand register or memory base/index of `instr` is `a` or `b`.
fn touches_pair(instr: &Instruction, a: iced_x86::Register, b: iced_x86::Register) -> bool {
    for i in 0..instr.op_count() {
        if instr.op_kind(i) == OpKind::Register {
            let r = instr.op_register(i);
            if r == a || r == b {
                return true;
            }
        }
    }
    let mb = instr.memory_base();
    let mi = instr.memory_index();
    mb == a || mb == b || mi == a || mi == b
}

/// Return a copy of `instr` with registers `a` and `b` swapped everywhere
/// (operand registers + memory base/index).
fn remap_pair(instr: &Instruction, a: iced_x86::Register, b: iced_x86::Register) -> Instruction {
    let mut ni = *instr;
    for i in 0..ni.op_count() {
        if ni.op_kind(i) == OpKind::Register {
            let r = swap_one(ni.op_register(i), a, b);
            ni.set_op_register(i, r);
        }
    }
    let mb = ni.memory_base();
    if mb == a || mb == b {
        ni.set_memory_base(swap_one(mb, a, b));
    }
    let mi = ni.memory_index();
    if mi == a || mi == b {
        ni.set_memory_index(swap_one(mi, a, b));
    }
    ni
}

/// Verify that `fam` (one of `R12..R15`) obeys strict single-prologue `push`
/// and per-`ret` epilogue `pop` discipline inside `instrs`:
/// - If `fam` is not touched anywhere in `instrs`, returns `true`.
/// - If `fam` is touched:
///   1. Its very first touch in `instrs` must be `push fam.r64` in the entry
///      basic block (before any branch, call, `ret`, or internal branch target).
///   2. `push fam.r64` appears exactly once in the entire function.
///   3. Every `Return` (`ret`) instruction in `instrs` is preceded in its
///      straight-line epilogue (after the last branch, call, or branch target
///      before that `ret`) by `pop fam.r64`, with no touch of `fam` between
///      `pop fam.r64` and `ret`.
///   4. Total `pop fam.r64` in the function equals total `ret` instructions.
fn verify_family_push_pop_discipline(
    instrs: &[Instruction],
    branch_targets: &[u64],
    fam: &RegFamily,
) -> bool {
    use iced_x86::FlowControl;

    let any_touch = instrs.iter().any(|ins| touches_family(ins, fam));
    if !any_touch {
        return true;
    }

    let is_push_fam = |ins: &Instruction| -> bool {
        ins.mnemonic() == Mnemonic::Push
            && ins.op_count() == 1
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register() == fam.r64
    };
    let is_pop_fam = |ins: &Instruction| -> bool {
        ins.mnemonic() == Mnemonic::Pop
            && ins.op_count() == 1
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register() == fam.r64
    };

    let push_count = instrs.iter().filter(|i| is_push_fam(i)).count();
    let pop_count = instrs.iter().filter(|i| is_pop_fam(i)).count();
    let ret_count = instrs
        .iter()
        .filter(|i| i.flow_control() == FlowControl::Return)
        .count();

    if push_count != 1 || ret_count == 0 || pop_count != ret_count {
        return false;
    }

    // 1. Entry prologue check: the first instruction touching `fam` must be
    //    `push fam.r64`, and it must occur before any branch/call/ret or
    //    internal branch target (other than function entry `instrs[0].ip()`).
    let mut found_prologue_push = false;
    for (idx, ins) in instrs.iter().enumerate() {
        if idx > 0 && branch_targets.contains(&ins.ip()) {
            return false;
        }
        if touches_family(ins, fam) {
            if is_push_fam(ins) {
                found_prologue_push = true;
                break;
            } else {
                return false;
            }
        }
        if ins.flow_control() != FlowControl::Next {
            return false;
        }
    }
    if !found_prologue_push {
        return false;
    }

    // 2. Epilogue check: for every `Return` instruction, scan backward to find
    //    `pop fam.r64` before hitting any branch/call/ret or branch target, and
    //    ensure no instruction between `pop fam.r64` and `ret` touches `fam`.
    for (ret_idx, ins) in instrs.iter().enumerate() {
        if ins.flow_control() != FlowControl::Return {
            continue;
        }
        if ret_idx == 0 {
            return false;
        }
        let mut found_epilogue_pop = false;
        let mut cursor = ret_idx;
        while cursor > 0 {
            // The instruction at `cursor` must not be jumped over into the middle
            // of the epilogue after `pop fam.r64`.
            if branch_targets.contains(&instrs[cursor].ip()) {
                return false;
            }
            cursor -= 1;
            let prev = &instrs[cursor];
            if prev.flow_control() != FlowControl::Next {
                return false;
            }
            if touches_family(prev, fam) {
                if is_pop_fam(prev) {
                    found_epilogue_pop = true;
                    break;
                } else {
                    // Touched `fam` after `pop fam.r64` (or instead of `pop`)!
                    return false;
                }
            }
        }
        if !found_epilogue_pop {
            return false;
        }
    }

    true
}

/// Sound whole-function callee-saved register family swap (`fam_a <-> fam_b`,
/// covering `64/32/16/8`-bit sub-registers) with strict control-flow and
/// prologue/epilogue verification.
pub fn try_swap_callee_saved_family(
    code: &mut [u8],
    base_ip: u64,
    fam_a: &RegFamily,
    fam_b: &RegFamily,
    stats: &mut Stats,
) -> bool {
    use iced_x86::FlowControl;

    if code.is_empty() || fam_a == fam_b {
        return false;
    }
    let end_ip = base_ip.saturating_add(code.len() as u64);
    let original = code.to_vec();
    let mut decoder = Decoder::with_ip(64, &original, base_ip, DecoderOptions::NONE);
    let mut instrs: Vec<Instruction> = Vec::new();
    let mut positions: Vec<usize> = Vec::new();
    let mut branch_targets: Vec<u64> = Vec::new();

    while decoder.can_decode() {
        let pos = decoder.position();
        let instr = decoder.decode();
        if instr.code() == Code::INVALID {
            return false;
        }
        match instr.flow_control() {
            FlowControl::Next | FlowControl::Return | FlowControl::Call | FlowControl::IndirectCall => {}
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                match instr.op0_kind() {
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                        let target = instr.near_branch_target();
                        // Reject any function with a tail-call or hot/cold split branch
                        // that jumps outside `[base_ip, end_ip)`.
                        if target < base_ip || target >= end_ip {
                            return false;
                        }
                        branch_targets.push(target);
                    }
                    _ => return false,
                }
            }
            FlowControl::Exception if instr.mnemonic() == Mnemonic::Ud2 => {}
            // IndirectBranch (jump tables / register tail calls), Interrupt, etc.
            _ => return false,
        }
        positions.push(pos);
        instrs.push(instr);
    }

    let Some(last) = instrs.last() else {
        return false;
    };
    // Function must end with a non-fallthrough terminator (`ret`, in-bounds `jmp`,
    // `ud2`, or a trailing cold `noreturn` panic `call`).
    if !matches!(
        last.flow_control(),
        FlowControl::Return
            | FlowControl::UnconditionalBranch
            | FlowControl::Call
            | FlowControl::IndirectCall
    ) && last.mnemonic() != Mnemonic::Ud2
    {
        return false;
    }

    if !verify_family_push_pop_discipline(&instrs, &branch_targets, fam_a)
        || !verify_family_push_pop_discipline(&instrs, &branch_targets, fam_b)
    {
        return false;
    }

    let mut edits: Vec<(usize, Vec<u8>)> = Vec::new();
    for (pos, instr) in positions.into_iter().zip(instrs.iter()) {
        if !touches_family(instr, fam_a) && !touches_family(instr, fam_b) {
            continue;
        }
        let ni = remap_family_pair(instr, fam_a, fam_b);
        let mut enc = Encoder::new(64);
        match enc.encode(&ni, instr.ip()) {
            Ok(len) if len == instr.len() => edits.push((pos, enc.take_buffer())),
            _ => return false,
        }
    }

    if edits.is_empty() {
        return false;
    }
    for (pos, bytes) in &edits {
        code[*pos..*pos + bytes.len()].copy_from_slice(bytes);
    }
    stats.reg_remapped_instrs += edits.len();
    true
}

/// Low-level 64-bit-only `R14 <-> R15` swap helper retained for unit tests.
/// Production [`rewrite_function`] uses [`try_swap_callee_saved_family`] which
/// remaps all sub-register widths (`64/32/16/8`-bit) and verifies prologue/epilogue
/// and branch-target containment.
pub fn try_swap_r14_r15(code: &mut [u8], base_ip: u64, stats: &mut Stats) -> bool {
    use iced_x86::Register::{R14, R15};
    let original = code.to_vec();
    let mut decoder = Decoder::with_ip(64, &original, base_ip, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut edits: Vec<(usize, Vec<u8>)> = Vec::new();
    while decoder.can_decode() {
        let pos = decoder.position();
        decoder.decode_out(&mut instr);
        if instr.code() == Code::INVALID {
            return false; // can't reason about a function we can't fully decode
        }
        if !touches_pair(&instr, R14, R15) {
            continue;
        }
        let ni = remap_pair(&instr, R14, R15);
        let mut enc = Encoder::new(64);
        match enc.encode(&ni, instr.ip()) {
            Ok(len) if len == instr.len() => edits.push((pos, enc.take_buffer())),
            // Any surprise (encode error, or a length change we did not
            // expect) aborts the whole-function swap to preserve consistency.
            _ => return false,
        }
    }
    if edits.is_empty() {
        return false;
    }
    for (pos, bytes) in &edits {
        code[*pos..*pos + bytes.len()].copy_from_slice(bytes);
    }
    stats.reg_remapped_instrs += edits.len();
    true
}

/// Seeded per-function callee-saved register permutation across `{R12, R13, R14, R15}`.
///
/// Chooses a seeded sequence of transpositions across `{R12, R13, R14, R15}` and
/// automatically falls back to `(R14, R15)` / `(R12, R13)` if a cross-pair fails
/// length-preservation due to `[r12]` SIB or `[r13]` disp8 addressing.
fn pass_callee_saved_reg_swap(code: &mut [u8], base_ip: u64, prng: &mut Prng, stats: &mut Stats) {
    const PAIRINGS: [[(RegFamily, RegFamily); 2]; 3] = [
        [(FAM_R14, FAM_R15), (FAM_R12, FAM_R13)],
        [(FAM_R13, FAM_R15), (FAM_R12, FAM_R14)],
        [(FAM_R12, FAM_R15), (FAM_R13, FAM_R14)],
    ];
    let draw = prng.next_u64();
    let idx = (draw as usize) % 3;
    let pairing = &PAIRINGS[idx];
    let mut any_swapped = false;

    // Ensure at least one of the two transpositions in `pairing` is attempted on
    // 87.5% of seeds, and if a cross-pairing (idx 1 or 2) fails to encode due to
    // `[r12]` SIB or `[r13]` disp8 addressing, fall back to `(FAM_R14, FAM_R15)`.
    let try0 = (draw >> 8) & 1 == 1 || ((draw >> 8) & 0b11 == 0);
    let try1 = (draw >> 9) & 1 == 1;
    if try0 {
        if try_swap_callee_saved_family(code, base_ip, &pairing[0].0, &pairing[0].1, stats) {
            any_swapped = true;
        }
    }
    if try1 {
        if try_swap_callee_saved_family(code, base_ip, &pairing[1].0, &pairing[1].1, stats) {
            any_swapped = true;
        }
    }
    if !any_swapped && idx != 0 && ((draw >> 10) & 1 == 1) {
        if try_swap_callee_saved_family(code, base_ip, &FAM_R14, &FAM_R15, stats) {
            any_swapped = true;
        }
    }
    if any_swapped {
        stats.reg_swapped_fns += 1;
    }
}

/// `true` if `ins` unconditionally overwrites all 64 bits of `fam` (writing
/// `fam.r64` or zero-extending `fam.r32`) without reading any sub-register of `fam`.
fn is_unconditional_family_overwrite(ins: &Instruction, fam: &RegFamily) -> bool {
    if ins.op_count() != 2 || ins.op0_kind() != OpKind::Register {
        return false;
    }
    let dst = ins.op0_register();
    if dst != fam.r64 && dst != fam.r32 {
        return false;
    }
    // Case 1: self-zeroing `xor r, r` or `sub r, r`
    if matches!(ins.mnemonic(), Mnemonic::Xor | Mnemonic::Sub)
        && ins.op1_kind() == OpKind::Register
        && ins.op1_register() == dst
    {
        return true;
    }
    // Case 2: pure overwrite `mov`, `movzx`, `movsx`, `movsxd`, `lea`
    if matches!(
        ins.mnemonic(),
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd | Mnemonic::Lea
    ) {
        let op1_touches =
            ins.op1_kind() == OpKind::Register && fam.contains(ins.op1_register());
        let mem_touches =
            fam.contains(ins.memory_base()) || fam.contains(ins.memory_index());
        if !op1_touches && !mem_touches {
            return true;
        }
    }
    false
}

/// Verify that caller-saved register family `fam` (`R8..R11`) is strictly local
/// to a leaf function `instrs` (not a live-in function argument):
/// - Either `fam` is never touched in `instrs`, OR
/// - Its very first touch in `instrs` occurs in the entry basic block (before
///   any branch or internal branch target) and is a full 32/64-bit register
///   overwrite (`mov`/`movzx`/`movsx`/`movsxd`/`lea` whose source operands do
///   not touch `fam`, or self-zeroing `xor`/`sub`).
fn verify_leaf_scratch_family(
    instrs: &[Instruction],
    branch_targets: &[u64],
    fam: &RegFamily,
) -> bool {
    use iced_x86::FlowControl;

    let any_touch = instrs.iter().any(|ins| touches_family(ins, fam));
    if !any_touch {
        return true;
    }

    for (idx, ins) in instrs.iter().enumerate() {
        if idx > 0 && branch_targets.contains(&ins.ip()) {
            return false;
        }
        if touches_family(ins, fam) {
            return is_unconditional_family_overwrite(ins, fam);
        }
        if ins.flow_control() != FlowControl::Next {
            return false;
        }
    }
    false
}

/// Whole-function caller-saved scratch register permutation across `{R8, R9, R10, R11}`
/// in leaf functions (functions with no `Call` or `IndirectCall`).
fn pass_leaf_scratch_reg_swap(code: &mut [u8], base_ip: u64, prng: &mut Prng, stats: &mut Stats) {
    use iced_x86::FlowControl;

    if code.is_empty() {
        return;
    }
    let end_ip = base_ip.saturating_add(code.len() as u64);
    let original = code.to_vec();
    let mut decoder = Decoder::with_ip(64, &original, base_ip, DecoderOptions::NONE);
    let mut instrs: Vec<Instruction> = Vec::new();
    let mut positions: Vec<usize> = Vec::new();
    let mut branch_targets: Vec<u64> = Vec::new();

    while decoder.can_decode() {
        let pos = decoder.position();
        let instr = decoder.decode();
        if instr.code() == Code::INVALID {
            return;
        }
        match instr.flow_control() {
            FlowControl::Next | FlowControl::Return => {}
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                match instr.op0_kind() {
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                        let target = instr.near_branch_target();
                        if target < base_ip || target >= end_ip {
                            return;
                        }
                        branch_targets.push(target);
                    }
                    _ => return,
                }
            }
            FlowControl::Exception if instr.mnemonic() == Mnemonic::Ud2 => {}
            // Any Call, IndirectCall, IndirectBranch, or Interrupt disqualifies leaf scratch swap.
            _ => return,
        }
        positions.push(pos);
        instrs.push(instr);
    }

    let Some(last) = instrs.last() else {
        return;
    };
    if last.flow_control() != FlowControl::Return {
        return;
    }

    const SCRATCH_PAIRINGS: [[(RegFamily, RegFamily); 2]; 3] = [
        [(FAM_R10, FAM_R11), (FAM_R8, FAM_R9)],
        [(FAM_R9, FAM_R11), (FAM_R8, FAM_R10)],
        [(FAM_R8, FAM_R11), (FAM_R9, FAM_R10)],
    ];
    let draw = prng.next_u64();
    let pairing = &SCRATCH_PAIRINGS[(draw as usize) % 3];

    for (bit, (fam_a, fam_b)) in pairing.iter().enumerate() {
        if ((draw >> (8 + bit)) & 1 == 0) && ((draw >> 8) & 0b11 != 0) {
            continue;
        }
        if !verify_leaf_scratch_family(&instrs, &branch_targets, fam_a)
            || !verify_leaf_scratch_family(&instrs, &branch_targets, fam_b)
        {
            continue;
        }
        let mut edits: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut ok = true;
        for (pos, instr) in positions.iter().copied().zip(instrs.iter()) {
            if !touches_family(instr, fam_a) && !touches_family(instr, fam_b) {
                continue;
            }
            let ni = remap_family_pair(instr, fam_a, fam_b);
            let mut enc = Encoder::new(64);
            match enc.encode(&ni, instr.ip()) {
                Ok(len) if len == instr.len() => edits.push((pos, enc.take_buffer())),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && !edits.is_empty() {
            for (pos, bytes) in &edits {
                code[*pos..*pos + bytes.len()].copy_from_slice(bytes);
            }
            stats.reg_remapped_instrs += edits.len();
            // Re-decode `instrs` if a second pair is going to run.
            let mut dec2 = Decoder::with_ip(64, code, base_ip, DecoderOptions::NONE);
            instrs.clear();
            while dec2.can_decode() {
                instrs.push(dec2.decode());
            }
        }
    }
}

/// `true` if `ins` has only explicit register/memory operands and cannot
/// implicitly read or write caller-saved registers `RCX, RSI, RDI, R8..R11`
/// (e.g. rejects variable shifts by `CL`, string ops `rep/movs/stos`, `mul/div`, etc.).
fn is_explicit_reg_only_instr(ins: &Instruction) -> bool {
    match ins.mnemonic() {
        Mnemonic::Mov
        | Mnemonic::Movzx
        | Mnemonic::Movsx
        | Mnemonic::Movsxd
        | Mnemonic::Lea
        | Mnemonic::Add
        | Mnemonic::Sub
        | Mnemonic::Xor
        | Mnemonic::Or
        | Mnemonic::And
        | Mnemonic::Cmp
        | Mnemonic::Test
        | Mnemonic::Not
        | Mnemonic::Neg
        | Mnemonic::Bswap
        | Mnemonic::Xchg
        | Mnemonic::Push
        | Mnemonic::Pop
        | Mnemonic::Nop
        | Mnemonic::Sete
        | Mnemonic::Setne
        | Mnemonic::Setb
        | Mnemonic::Seta
        | Mnemonic::Setbe
        | Mnemonic::Setae
        | Mnemonic::Setl
        | Mnemonic::Setg
        | Mnemonic::Setle
        | Mnemonic::Setge
        | Mnemonic::Cmove
        | Mnemonic::Cmovne
        | Mnemonic::Cmovb
        | Mnemonic::Cmova
        | Mnemonic::Cmovbe
        | Mnemonic::Cmovae
        | Mnemonic::Cmovl
        | Mnemonic::Cmovg
        | Mnemonic::Cmovle
        | Mnemonic::Cmovge => true,
        Mnemonic::Imul => ins.op_count() >= 2,
        Mnemonic::Shl | Mnemonic::Shr | Mnemonic::Sar => {
            ins.op_count() == 2 && ins.op1_kind() != OpKind::Register
        }
        _ => false,
    }
}

/// Return-Basic-Block Caller-Saved Scratch Register Renaming:
///
/// At any `ret` instruction in x86-64, caller-saved registers `{R8, R9, R10, R11}`
/// and `{RCX, RSI, RDI}` are 100% dead by ABI (`RAX`/`RDX` are the only return
/// registers; `RBX, RBP, RSP, R12..R15` are callee-saved).
///
/// For each `ret` basic-block tail `instrs[bb_start..ret_idx]` (after the last
/// `call`, branch, or `branch_target`), if any scratch register family `fam_a`
/// is unconditionally full-register overwritten at `def_idx` (`bb_start <= def_idx < ret_idx`)
/// and a partner family `fam_b` in the same encoding class (`{R8..R11}` or
/// `{RCX, RSI, RDI}`) is either untouched in `instrs[def_idx..ret_idx]` or also
/// unconditionally overwritten before first read in `instrs[bb_start..ret_idx]`,
/// we can safely swap `fam_a <-> fam_b` across that return slice, directly
/// mutating registers inside `ret`-terminated ROP gadgets of non-leaf functions!
fn pass_return_block_scratch_swap(code: &mut [u8], base_ip: u64, prng: &mut Prng, stats: &mut Stats) {
    use iced_x86::FlowControl;

    if code.is_empty() {
        return;
    }
    let end_ip = base_ip.saturating_add(code.len() as u64);
    let original = code.to_vec();
    let mut decoder = Decoder::with_ip(64, &original, base_ip, DecoderOptions::NONE);
    let mut instrs: Vec<Instruction> = Vec::new();
    let mut positions: Vec<usize> = Vec::new();
    let mut branch_targets: Vec<u64> = Vec::new();

    while decoder.can_decode() {
        let pos = decoder.position();
        let instr = decoder.decode();
        if instr.code() == Code::INVALID {
            return;
        }
        match instr.flow_control() {
            FlowControl::Next | FlowControl::Return | FlowControl::Call | FlowControl::IndirectCall => {}
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                match instr.op0_kind() {
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                        let target = instr.near_branch_target();
                        if target >= base_ip && target < end_ip {
                            branch_targets.push(target);
                        } else if instr.flow_control() != FlowControl::UnconditionalBranch {
                            return;
                        }
                    }
                    _ => return,
                }
            }
            FlowControl::Exception if instr.mnemonic() == Mnemonic::Ud2 => {}
            _ => return,
        }
        positions.push(pos);
        instrs.push(instr);
    }

    // Find all `ret` instructions (`Mnemonic::Ret && op_count == 0`).
    let mut ret_indices: Vec<usize> = Vec::new();
    for (idx, ins) in instrs.iter().enumerate() {
        if ins.flow_control() == FlowControl::Return && ins.mnemonic() == Mnemonic::Ret && ins.op_count() == 0 {
            ret_indices.push(idx);
        }
    }
    if ret_indices.is_empty() {
        return;
    }

    const UPPER_FAMILIES: [RegFamily; 4] = [FAM_R8, FAM_R9, FAM_R10, FAM_R11];
    const LOWER_FAMILIES: [RegFamily; 3] = [FAM_RCX, FAM_RSI, FAM_RDI];

    for ret_idx in ret_indices {
        if ret_idx == 0 || branch_targets.contains(&instrs[ret_idx].ip()) {
            continue;
        }
        // Scan backward from `ret_idx` to find the start `bb_start` of the
        // straight-line basic block ending at `ret_idx`.
        let mut bb_start = ret_idx;
        while bb_start > 0 {
            let prev = &instrs[bb_start - 1];
            if prev.flow_control() != FlowControl::Next || !is_explicit_reg_only_instr(prev) {
                break;
            }
            bb_start -= 1;
            if branch_targets.contains(&instrs[bb_start].ip()) {
                break;
            }
        }
        if bb_start >= ret_idx {
            continue;
        }

        // Try renaming an overwritten scratch family `fam_a` in `instrs[def_idx..ret_idx]`
        // to an untouched partner family `fam_b` in `instrs[def_idx..ret_idx]`.
        let draw = prng.next_u64();
        let mut try_class = |families: &[RegFamily], seed_bits: u64| {
            for (a_i, fam_a) in families.iter().enumerate() {
                // Find the last unconditional overwrite `def_idx` of `fam_a` in `bb_start..ret_idx`
                // (or the first touch of `fam_a` in `bb_start..ret_idx` if it is an overwrite).
                let mut slice_start: Option<usize> = None;
                for idx in bb_start..ret_idx {
                    if touches_family(&instrs[idx], fam_a) {
                        if is_unconditional_family_overwrite(&instrs[idx], fam_a) {
                            slice_start = Some(idx);
                        }
                        break;
                    }
                }
                // Even if `fam_a` was read earlier in `bb_start..ret_idx`, if there is a LATER
                // unconditional overwrite `def_idx` of `fam_a` in `bb_start..ret_idx`, `fam_a` is
                // completely local in `def_idx..ret_idx`!
                if slice_start.is_none() {
                    for idx in (bb_start..ret_idx).rev() {
                        if is_unconditional_family_overwrite(&instrs[idx], fam_a) {
                            slice_start = Some(idx);
                            break;
                        }
                    }
                }
                let Some(start_idx) = slice_start else {
                    continue;
                };
                // Pick a partner `fam_b != fam_a` that is untouched in `start_idx..ret_idx`.
                let n = families.len();
                let offset = ((seed_bits as usize).wrapping_add(a_i)) % n;
                for step in 0..n {
                    let b_i = (offset + step) % n;
                    if b_i == a_i {
                        continue;
                    }
                    let fam_b = &families[b_i];
                    let b_touched = (start_idx..ret_idx).any(|k| touches_family(&instrs[k], fam_b));
                    if b_touched {
                        continue;
                    }
                    if (seed_bits.wrapping_shr(step as u32) & 0b11) == 0 {
                        continue;
                    }
                    let mut edits: Vec<(usize, Vec<u8>)> = Vec::new();
                    let mut ok = true;
                    for k in start_idx..ret_idx {
                        let ins = &instrs[k];
                        if !touches_family(ins, fam_a) {
                            continue;
                        }
                        let ni = remap_family_pair(ins, fam_a, fam_b);
                        let mut enc = Encoder::new(64);
                        match enc.encode(&ni, ins.ip()) {
                            Ok(len) if len == ins.len() => edits.push((positions[k], enc.take_buffer())),
                            _ => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if ok && !edits.is_empty() {
                        for (pos, bytes) in &edits {
                            code[*pos..*pos + bytes.len()].copy_from_slice(bytes);
                        }
                        stats.reg_remapped_instrs += edits.len();
                        // Re-decode the modified instructions in `start_idx..ret_idx`.
                        for k in start_idx..ret_idx {
                            let p = positions[k];
                            let l = instrs[k].len();
                            let mut d = Decoder::with_ip(64, &code[p..p + l], instrs[k].ip(), DecoderOptions::NONE);
                            instrs[k] = d.decode();
                        }
                        break;
                    }
                }
            }
        };

        try_class(&UPPER_FAMILIES, draw);
        try_class(&LOWER_FAMILIES, draw.rotate_right(17));
    }
}

/// Prologue `push` / Epilogue `pop` order permutation across `{RBX, RBP, R12, R13, R14, R15}`.
///
/// Permutes the contiguous entry `push` block into a seeded order $\pi$ and
/// every matching epilogue `pop` block into the exact reverse order $\pi^{-1}$.
/// Preserves the exact byte length of both blocks while permuting epilogue
/// `pop ...; ret` ROP gadgets and shifting internal 1-byte (`pop rbx/rbp`) vs
/// 2-byte (`pop r12..r15`) instruction boundaries.
fn pass_prologue_epilogue_perm(code: &mut [u8], base_ip: u64, prng: &mut Prng, stats: &mut Stats) {
    use iced_x86::{FlowControl, Register};

    if code.is_empty() {
        return;
    }
    let end_ip = base_ip.saturating_add(code.len() as u64);
    let original = code.to_vec();
    let mut decoder = Decoder::with_ip(64, &original, base_ip, DecoderOptions::NONE);
    let mut instrs: Vec<Instruction> = Vec::new();
    let mut positions: Vec<usize> = Vec::new();
    let mut branch_targets: Vec<u64> = Vec::new();

    while decoder.can_decode() {
        let pos = decoder.position();
        let instr = decoder.decode();
        if instr.code() == Code::INVALID {
            return;
        }
        // Reject if any instruction uses RBP as a memory base or index (frame pointer).
        if instr.memory_base() == Register::RBP || instr.memory_index() == Register::RBP {
            return;
        }
        match instr.flow_control() {
            FlowControl::Next | FlowControl::Return | FlowControl::Call | FlowControl::IndirectCall => {}
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                match instr.op0_kind() {
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                        let target = instr.near_branch_target();
                        if target < base_ip || target >= end_ip {
                            return;
                        }
                        branch_targets.push(target);
                    }
                    _ => return,
                }
            }
            FlowControl::Exception if instr.mnemonic() == Mnemonic::Ud2 => {}
            _ => return,
        }
        positions.push(pos);
        instrs.push(instr);
    }

    let Some(last) = instrs.last() else {
        return;
    };
    if !matches!(
        last.flow_control(),
        FlowControl::Return
            | FlowControl::UnconditionalBranch
            | FlowControl::Call
            | FlowControl::IndirectCall
    ) && last.mnemonic() != Mnemonic::Ud2
    {
        return;
    }

    let is_callee_saved_reg = |r: Register| -> bool {
        matches!(
            r,
            Register::RBX
                | Register::RBP
                | Register::R12
                | Register::R13
                | Register::R14
                | Register::R15
        )
    };

    // Collect contiguous entry `push <callee_saved>` instructions starting at index 0.
    let mut push_regs: Vec<Register> = Vec::new();
    let mut p_end = 0usize;
    for (idx, ins) in instrs.iter().enumerate() {
        if idx > 0 && branch_targets.contains(&ins.ip()) {
            break;
        }
        if ins.mnemonic() == Mnemonic::Push
            && ins.op_count() == 1
            && ins.op0_kind() == OpKind::Register
            && is_callee_saved_reg(ins.op0_register())
            && !push_regs.contains(&ins.op0_register())
        {
            push_regs.push(ins.op0_register());
            p_end = idx + 1;
        } else {
            break;
        }
    }

    let k = push_regs.len();
    if k < 2 || p_end >= instrs.len() {
        return;
    }
    // No branch may target the instruction immediately after a partial prefix of pushes.
    for idx in 1..p_end {
        if branch_targets.contains(&instrs[idx].ip()) {
            return;
        }
    }

    // Determine local stack frame size if `instrs[p_end]` is `sub rsp, frame_size`
    // OR 1-byte `push rax` (LLVM's 8-byte stack alignment slot).
    let is_push_rax_alloc = instrs[p_end].mnemonic() == Mnemonic::Push
        && instrs[p_end].op_count() == 1
        && instrs[p_end].op0_kind() == OpKind::Register
        && instrs[p_end].op0_register() == Register::RAX;

    let frame_size: i64 = if is_push_rax_alloc {
        8
    } else if matches!(instrs[p_end].code(), Code::Sub_rm64_imm8 | Code::Sub_rm64_imm32)
        && instrs[p_end].op0_kind() == OpKind::Register
        && instrs[p_end].op0_register() == Register::RSP
    {
        let imm = if instrs[p_end].code() == Code::Sub_rm64_imm8 {
            (instrs[p_end].immediate8() as i8) as i64
        } else {
            (instrs[p_end].immediate32() as i32) as i64
        };
        if imm < 0 {
            return;
        }
        imm
    } else {
        0
    };

    // Collect all `Return` (`ret`) indices and verify each is preceded by the exact
    // reverse contiguous sequence of `k` `pop` instructions.
    let mut ret_indices: Vec<usize> = Vec::new();
    for (idx, ins) in instrs.iter().enumerate() {
        if ins.flow_control() == FlowControl::Return {
            if ins.mnemonic() != Mnemonic::Ret || ins.op_count() != 0 || idx < p_end + k {
                return;
            }
            let q_start = idx - k;
            for j in 0..k {
                let pop_ins = &instrs[q_start + j];
                let expected_reg = push_regs[k - 1 - j];
                if pop_ins.mnemonic() != Mnemonic::Pop
                    || pop_ins.op_count() != 1
                    || pop_ins.op0_kind() != OpKind::Register
                    || pop_ins.op0_register() != expected_reg
                {
                    return;
                }
            }
            // No branch target may land strictly inside `(q_start ..= idx]`.
            for inner in (q_start + 1)..=idx {
                if branch_targets.contains(&instrs[inner].ip()) {
                    return;
                }
            }
            ret_indices.push(idx);
        }
    }
    let Some(&last_ret_idx) = ret_indices.last() else {
        return;
    };

    // Check if the trailing region after `last_ret_idx` is a pure cold `noreturn` sink
    // (no branch in `last_ret_idx + 1 ..` jumps back to `<= instrs[last_ret_idx].ip()`,
    // and no instruction in `last_ret_idx + 1 ..` executes `pop` or indexes `[rsp + ...]`).
    let trailing_is_cold_sink = instrs[last_ret_idx + 1..].iter().all(|ins| {
        if matches!(
            ins.flow_control(),
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
        ) {
            if ins.near_branch_target() <= instrs[last_ret_idx].ip() {
                return false;
            }
        }
        ins.mnemonic() != Mnemonic::Pop
            && ins.memory_base() != Register::RSP
            && ins.memory_index() != Register::RSP
    });

    // Verify no instruction outside `[0..p_end)` and the epilogue `[q_start..ret_idx)` blocks:
    // 1. Executes `push` or `pop` (except `push rax` at `p_end` or stack alignment in a trailing cold sink).
    // 2. Accesses `[rsp + disp]` outside `[0 .. frame_size)` (so the pushed register
    //    save area `[frame_size .. frame_size + 8*k)` is never indexed by `[rsp + disp]`).
    let in_epilogue_pops = |idx: usize| -> bool {
        ret_indices.iter().any(|&r| idx >= r - k && idx < r)
    };
    let is_epilogue_rsp_dealloc = |idx: usize| -> bool {
        ret_indices.iter().any(|&r| idx + k + 1 == r)
            && matches!(
                instrs[idx].code(),
                Code::Add_rm64_imm8 | Code::Add_rm64_imm32 | Code::Sub_rm64_imm8 | Code::Sub_rm64_imm32
            )
            && instrs[idx].op0_kind() == OpKind::Register
            && instrs[idx].op0_register() == Register::RSP
    };

    for (idx, ins) in instrs.iter().enumerate() {
        if idx < p_end || in_epilogue_pops(idx) {
            continue;
        }
        if idx > last_ret_idx && trailing_is_cold_sink {
            continue;
        }
        if (idx == p_end && frame_size > 0) || is_epilogue_rsp_dealloc(idx) {
            continue;
        }
        if ins.mnemonic() == Mnemonic::Push || ins.mnemonic() == Mnemonic::Pop {
            return;
        }
        // Reject if RSP is modified by any other instruction in the body.
        for op_i in 0..ins.op_count() {
            if ins.op_kind(op_i) == OpKind::Register && ins.op_register(op_i) == Register::RSP {
                return;
            }
        }
        if ins.memory_index() == Register::RSP {
            return;
        }
        if ins.memory_base() == Register::RSP {
            let disp = ins.memory_displacement64() as i64;
            if disp < 0 || disp + 8 > frame_size {
                return;
            }
        }
    }

    // Seeded Fisher-Yates shuffle of `push_regs`.
    let mut perm_regs = push_regs.clone();
    for i in (1..k).rev() {
        let j = (prng.next_u64() as usize) % (i + 1);
        perm_regs.swap(i, j);
    }
    if perm_regs == push_regs {
        return;
    }

    // Encode new prologue `push` block.
    let push_span_len = positions[p_end] - positions[0];
    let mut new_push_bytes: Vec<u8> = Vec::with_capacity(push_span_len);
    let mut cur_ip = base_ip + positions[0] as u64;
    for &reg in &perm_regs {
        let Ok(pi) = Instruction::with1(Code::Push_r64, reg) else {
            return;
        };
        let mut enc = Encoder::new(64);
        let Ok(len) = enc.encode(&pi, cur_ip) else {
            return;
        };
        new_push_bytes.extend_from_slice(&enc.take_buffer());
        cur_ip += len as u64;
    }
    if new_push_bytes.len() != push_span_len {
        return;
    }

    // Encode each epilogue `pop` block in exact reverse order of `perm_regs`.
    let mut epilogue_edits: Vec<(usize, Vec<u8>)> = Vec::with_capacity(ret_indices.len());
    for &ret_idx in &ret_indices {
        let q_start = ret_idx - k;
        let pop_pos = positions[q_start];
        let pop_span_len = positions[ret_idx] - pop_pos;
        let mut new_pop_bytes: Vec<u8> = Vec::with_capacity(pop_span_len);
        let mut pop_ip = base_ip + pop_pos as u64;
        for &reg in perm_regs.iter().rev() {
            let Ok(qi) = Instruction::with1(Code::Pop_r64, reg) else {
                return;
            };
            let mut enc = Encoder::new(64);
            let Ok(len) = enc.encode(&qi, pop_ip) else {
                return;
            };
            new_pop_bytes.extend_from_slice(&enc.take_buffer());
            pop_ip += len as u64;
        }
        if new_pop_bytes.len() != pop_span_len {
            return;
        }
        epilogue_edits.push((pop_pos, new_pop_bytes));
    }

    code[positions[0]..positions[0] + push_span_len].copy_from_slice(&new_push_bytes);
    for (pop_pos, bytes) in epilogue_edits {
        code[pop_pos..pop_pos + bytes.len()].copy_from_slice(&bytes);
    }
    stats.swapped += 1 + ret_indices.len();
}

/// Map any x86-64 GP register (`8/16/32/64`-bit) to a canonical index `0..16`,
/// or `None` if `r` is not a general-purpose register.
fn gp_reg_index(r: iced_x86::Register) -> Option<u8> {
    use iced_x86::Register::*;
    Some(match r {
        RAX | EAX | AX | AL | AH => 0,
        RCX | ECX | CX | CL | CH => 1,
        RDX | EDX | DX | DL | DH => 2,
        RBX | EBX | BX | BL | BH => 3,
        RSP | ESP | SP | SPL => 4,
        RBP | EBP | BP | BPL => 5,
        RSI | ESI | SI | SIL => 6,
        RDI | EDI | DI | DIL => 7,
        R8 | R8D | R8W | R8L => 8,
        R9 | R9D | R9W | R9L => 9,
        R10 | R10D | R10W | R10L => 10,
        R11 | R11D | R11W | R11L => 11,
        R12 | R12D | R12W | R12L => 12,
        R13 | R13D | R13W | R13L => 13,
        R14 | R14D | R14W | R14L => 14,
        R15 | R15D | R15W | R15L => 15,
        _ => return Option::None,
    })
}

/// Extract `(write_mask, read_mask, reads_memory)` for a flag-neutral
/// register-destination instruction (`Mov`, `Movzx`, `Movsx`, `Movsxd`, `Lea`),
/// including RIP-relative `[rip + disp32]` addressing (whose `disp32` is
/// automatically recomputed by `iced-x86::Encoder` at the new IP).
fn schedule_reg_masks(ins: &Instruction) -> Option<(u16, u16, bool)> {
    use iced_x86::{FlowControl, Register};

    if ins.flow_control() != FlowControl::Next
        || ins.segment_prefix() != Register::None
        || ins.op_count() != 2
        || ins.op0_kind() != OpKind::Register
    {
        return None;
    }
    if !matches!(
        ins.mnemonic(),
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd | Mnemonic::Lea
    ) {
        return None;
    }

    let dst_idx = gp_reg_index(ins.op0_register())?;
    let w_mask: u16 = 1u16 << dst_idx;
    let mut r_mask: u16 = 0;

    match ins.op1_kind() {
        OpKind::Register => {
            let src_idx = gp_reg_index(ins.op1_register())?;
            r_mask |= 1u16 << src_idx;
            Some((w_mask, r_mask, false))
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Some((w_mask, r_mask, false)),
        OpKind::Memory => {
            let mb = ins.memory_base();
            if mb != Register::None && mb != Register::RIP {
                let b_idx = gp_reg_index(mb)?;
                r_mask |= 1u16 << b_idx;
            }
            let mi = ins.memory_index();
            if mi != Register::None {
                let i_idx = gp_reg_index(mi)?;
                r_mask |= 1u16 << i_idx;
            }
            let reads_mem = ins.mnemonic() != Mnemonic::Lea;
            Some((w_mask, r_mask, reads_mem))
        }
        _ => None,
    }
}

/// Intra-block independent instruction window scheduling pass: finds maximal
/// contiguous windows (up to 6 instructions) of mutually data-, flag-, and
/// memory-independent instructions and applies a seeded Fisher-Yates permutation,
/// shifting internal instruction boundaries, recomputing RIP-relative `disp32`
/// offsets, and breaking multi-instruction gadget sequences.
fn pass_schedule_commute(code: &mut [u8], base_ip: u64, prng: &mut Prng, stats: &mut Stats) {
    use iced_x86::FlowControl;

    if code.is_empty() {
        return;
    }
    let end_ip = base_ip.saturating_add(code.len() as u64);
    let original = code.to_vec();
    let mut decoder = Decoder::with_ip(64, &original, base_ip, DecoderOptions::NONE);
    let mut instrs: Vec<Instruction> = Vec::new();
    let mut positions: Vec<usize> = Vec::new();
    let mut branch_targets: Vec<u64> = Vec::new();

    while decoder.can_decode() {
        let pos = decoder.position();
        let instr = decoder.decode();
        if instr.code() == Code::INVALID {
            return;
        }
        match instr.flow_control() {
            FlowControl::Next | FlowControl::Return | FlowControl::Call | FlowControl::IndirectCall => {}
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                match instr.op0_kind() {
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                        let target = instr.near_branch_target();
                        if target >= base_ip && target < end_ip {
                            branch_targets.push(target);
                        } else if instr.flow_control() != FlowControl::UnconditionalBranch {
                            return;
                        }
                    }
                    _ => return,
                }
            }
            FlowControl::Exception if instr.mnemonic() == Mnemonic::Ud2 => {}
            _ => return,
        }
        positions.push(pos);
        instrs.push(instr);
    }

    let mut i = 0usize;
    while i + 1 < instrs.len() {
        let Some(m0) = schedule_reg_masks(&instrs[i]) else {
            i += 1;
            continue;
        };
        let mut window_masks: Vec<(u16, u16, bool)> = vec![m0];
        let mut end = i + 1;
        while end < instrs.len() && window_masks.len() < 6 {
            if branch_targets.contains(&instrs[end].ip()) {
                break;
            }
            let Some((w_new, r_new, mem_new)) = schedule_reg_masks(&instrs[end]) else {
                break;
            };
            let independent = window_masks.iter().all(|&(w_old, r_old, mem_old)| {
                (w_old & w_new) == 0
                    && (w_old & r_new) == 0
                    && (r_old & w_new) == 0
                    && !(mem_old && mem_new)
            });
            if !independent {
                break;
            }
            window_masks.push((w_new, r_new, mem_new));
            end += 1;
        }

        let win_len = end - i;
        if win_len >= 2 {
            let mut order: Vec<usize> = (0..win_len).collect();
            if win_len == 2 {
                if prng.coin() {
                    order.swap(0, 1);
                }
            } else {
                for k in (1..win_len).rev() {
                    let j = (prng.next_u64() as usize) % (k + 1);
                    order.swap(k, j);
                }
            }
            if order.iter().enumerate().any(|(idx, &ord)| idx != ord) {
                let start_pos = positions[i];
                let total_bytes: usize = (i..end).map(|k| instrs[k].len()).sum();
                let mut cur_ip = instrs[i].ip();
                let mut encoded_window: Vec<u8> = Vec::with_capacity(total_bytes);
                let mut ok = true;
                for &ord in &order {
                    let ins = &instrs[i + ord];
                    let mut enc = Encoder::new(64);
                    match enc.encode(ins, cur_ip) {
                        Ok(l) if l == ins.len() => {
                            encoded_window.extend_from_slice(&enc.take_buffer());
                            cur_ip += l as u64;
                        }
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok && encoded_window.len() == total_bytes {
                    code[start_pos..start_pos + total_bytes].copy_from_slice(&encoded_window);
                    stats.swapped += 1;
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
}

/// Encode a candidate replacement instruction if its byte length matches
/// `instr.len()`.
fn try_encode_same_len(alt: &Instruction, instr: &Instruction) -> Option<Vec<u8>> {
    let mut enc = Encoder::new(64);
    let len = enc.encode(alt, instr.ip()).ok()?;
    if len == instr.len() {
        Some(enc.take_buffer())
    } else {
        None
    }
}

#[inline]
fn is_flag_killer_instr(ins: &Instruction, branch_targets: &[u64]) -> bool {
    use iced_x86::FlowControl;
    if matches!(
        ins.flow_control(),
        FlowControl::Return | FlowControl::Call | FlowControl::IndirectCall
    ) || ins.mnemonic() == Mnemonic::Ud2
        || (ins.flow_control() == FlowControl::UnconditionalBranch
            && matches!(
                ins.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
            && !branch_targets.contains(&ins.near_branch_target()))
    {
        return true;
    }
    ins.flow_control() == FlowControl::Next
        && matches!(
            ins.mnemonic(),
            Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::Cmp
                | Mnemonic::And
                | Mnemonic::Or
                | Mnemonic::Xor
                | Mnemonic::Test
                | Mnemonic::Neg
        )
}

#[inline]
fn is_flag_neutral_instr(ins: &Instruction) -> bool {
    ins.flow_control() == iced_x86::FlowControl::Next
        && matches!(
            ins.mnemonic(),
            Mnemonic::Mov
                | Mnemonic::Movzx
                | Mnemonic::Movsx
                | Mnemonic::Movsxd
                | Mnemonic::Lea
                | Mnemonic::Push
                | Mnemonic::Pop
                | Mnemonic::Xchg
                | Mnemonic::Nop
                | Mnemonic::Bswap
        )
}

/// `true` if all 6 arithmetic flags (`CF, OF, SF, ZF, PF, AF`) after `instrs[idx]`
/// are provably overwritten (or killed by `ret`, `call`, tail-call, or `ud2`) before
/// any flag read or branch target.
fn flags_are_dead(instrs: &[Instruction], branch_targets: &[u64], idx: usize) -> bool {
    for ins in &instrs[idx + 1..] {
        if branch_targets.contains(&ins.ip()) {
            return false;
        }
        if is_flag_killer_instr(ins, branch_targets) {
            return true;
        }
        if is_flag_neutral_instr(ins) {
            continue;
        }
        return false;
    }
    false
}

/// `true` if all 6 arithmetic flags entering `instrs[start_idx]` are provably
/// overwritten before any flag read.
fn flags_are_dead_at_entry(
    instrs: &[Instruction],
    branch_targets: &[u64],
    start_idx: usize,
) -> bool {
    for (j, ins) in instrs[start_idx..].iter().enumerate() {
        if j > 0 && branch_targets.contains(&ins.ip()) {
            return false;
        }
        if is_flag_killer_instr(ins, branch_targets) {
            return true;
        }
        if is_flag_neutral_instr(ins) {
            continue;
        }
        return false;
    }
    false
}

/// `true` if `CF` and `AF` are provably dead after `instrs[idx]`, even if
/// `{ZF, SF, OF, PF}` are read by `Setcc`/`Cmovcc` or a conditional branch
/// (`Je/Jne/Js/Jns/Jo/Jno/Jp/Jnp/Jl/Jge/Jle/Jg`) whose fallthrough and target
/// paths both overwrite all flags before reading `CF` or `AF`.
fn cf_af_are_dead(instrs: &[Instruction], branch_targets: &[u64], idx: usize) -> bool {
    use iced_x86::FlowControl;

    for (offset, ins) in instrs[idx + 1..].iter().enumerate() {
        let cur_idx = idx + 1 + offset;
        if branch_targets.contains(&ins.ip()) {
            return false;
        }
        if is_flag_killer_instr(ins, branch_targets) {
            return true;
        }
        if is_flag_neutral_instr(ins) {
            continue;
        }
        if ins.flow_control() == FlowControl::Next
            && matches!(
                ins.mnemonic(),
                Mnemonic::Sete
                    | Mnemonic::Setne
                    | Mnemonic::Sets
                    | Mnemonic::Setns
                    | Mnemonic::Seto
                    | Mnemonic::Setno
                    | Mnemonic::Setp
                    | Mnemonic::Setnp
                    | Mnemonic::Setl
                    | Mnemonic::Setge
                    | Mnemonic::Setle
                    | Mnemonic::Setg
                    | Mnemonic::Cmove
                    | Mnemonic::Cmovne
                    | Mnemonic::Cmovs
                    | Mnemonic::Cmovns
                    | Mnemonic::Cmovo
                    | Mnemonic::Cmovno
                    | Mnemonic::Cmovp
                    | Mnemonic::Cmovnp
                    | Mnemonic::Cmovl
                    | Mnemonic::Cmovge
                    | Mnemonic::Cmovle
                    | Mnemonic::Cmovg
            )
        {
            continue;
        }
        if ins.flow_control() == FlowControl::ConditionalBranch
            && matches!(
                ins.mnemonic(),
                Mnemonic::Je
                    | Mnemonic::Jne
                    | Mnemonic::Js
                    | Mnemonic::Jns
                    | Mnemonic::Jo
                    | Mnemonic::Jno
                    | Mnemonic::Jp
                    | Mnemonic::Jnp
                    | Mnemonic::Jl
                    | Mnemonic::Jge
                    | Mnemonic::Jle
                    | Mnemonic::Jg
            )
            && matches!(
                ins.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        {
            let target_ip = ins.near_branch_target();
            let Some(target_idx) = instrs.iter().position(|t| t.ip() == target_ip) else {
                return false;
            };
            return flags_are_dead(instrs, branch_targets, cur_idx)
                && flags_are_dead_at_entry(instrs, branch_targets, target_idx);
        }
        return false;
    }
    false
}

/// `true` if the source GP register of `instrs[idx]` (`mov dst, src` or `lea dst, [src]`)
/// is provably dead after `instrs[idx]` (unconditionally full-register overwritten in the
/// same basic block before any read, or caller-saved non-return `{RCX, RSI, RDI, R8..R11}`
/// reaching `ret` without being read).
fn src_reg_is_dead_after(
    instrs: &[Instruction],
    branch_targets: &[u64],
    idx: usize,
) -> bool {
    use iced_x86::{FlowControl, Register};

    let cur = &instrs[idx];
    let (dst_reg, src_reg) = if cur.mnemonic() == Mnemonic::Mov
        && cur.op_count() == 2
        && cur.op0_kind() == OpKind::Register
        && cur.op1_kind() == OpKind::Register
    {
        (cur.op0_register(), cur.op1_register())
    } else if cur.mnemonic() == Mnemonic::Lea
        && cur.op_count() == 2
        && cur.op0_kind() == OpKind::Register
        && cur.op1_kind() == OpKind::Memory
        && !cur.is_ip_rel_memory_operand()
        && cur.memory_index() == Register::None
        && cur.memory_displacement64() == 0
        && cur.segment_prefix() == Register::None
    {
        (cur.op0_register(), cur.memory_base())
    } else {
        return false;
    };

    let (Some(dst_gp), Some(src_gp)) = (gp_reg_index(dst_reg), gp_reg_index(src_reg)) else {
        return false;
    };
    if dst_gp == src_gp || dst_gp == 4 || src_gp == 4 {
        return false;
    }

    for ins in &instrs[idx + 1..] {
        if branch_targets.contains(&ins.ip()) {
            return false;
        }
        if ins.flow_control() == FlowControl::Return
            && ins.mnemonic() == Mnemonic::Ret
            && ins.op_count() == 0
        {
            return matches!(src_gp, 1 | 6 | 7 | 8 | 9 | 10 | 11);
        }
        if ins.flow_control() != FlowControl::Next || !is_explicit_reg_only_instr(ins) {
            return false;
        }
        if gp_reg_index(ins.memory_base()) == Some(src_gp)
            || gp_reg_index(ins.memory_index()) == Some(src_gp)
        {
            return false;
        }
        if ins.mnemonic() == Mnemonic::Pop
            && ins.op_count() == 1
            && ins.op0_kind() == OpKind::Register
        {
            if gp_reg_index(ins.op0_register()) == Some(src_gp) {
                return true;
            }
            continue;
        }
        if ins.op_count() == 2
            && ins.op0_kind() == OpKind::Register
            && ins.op1_kind() == OpKind::Register
            && ins.op0_register() == ins.op1_register()
            && matches!(
                ins.code(),
                Code::Xor_rm32_r32
                    | Code::Xor_r32_rm32
                    | Code::Xor_rm64_r64
                    | Code::Xor_r64_rm64
                    | Code::Sub_rm32_r32
                    | Code::Sub_r32_rm32
                    | Code::Sub_rm64_r64
                    | Code::Sub_r64_rm64
            )
        {
            if gp_reg_index(ins.op0_register()) == Some(src_gp) {
                return true;
            }
            continue;
        }
        if matches!(
            ins.mnemonic(),
            Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd | Mnemonic::Lea
        ) && ins.op_count() == 2
            && ins.op0_kind() == OpKind::Register
        {
            if ins.op1_kind() == OpKind::Register
                && gp_reg_index(ins.op1_register()) == Some(src_gp)
            {
                return false;
            }
            if gp_reg_index(ins.op0_register()) == Some(src_gp) {
                // Only treat non-reg-reg moves (immediates, memory loads, non-zero disp LEA)
                // as unconditional sinks so chained reg-reg moves never interact.
                let is_reg_copy = (ins.mnemonic() == Mnemonic::Mov
                    && ins.op1_kind() == OpKind::Register)
                    || (ins.mnemonic() == Mnemonic::Lea
                        && !ins.is_ip_rel_memory_operand()
                        && ins.memory_index() == Register::None
                        && ins.memory_displacement64() == 0);
                if is_reg_copy {
                    return false;
                }
                let r0 = ins.op0_register();
                let is_32_or_64 = reg32_to_base64_low8(r0).is_some()
                    || upper_reg_family(r0).map_or(false, |f| r0 == f.r64 || r0 == f.r32)
                    || matches!(
                        r0,
                        Register::RAX
                            | Register::RCX
                            | Register::RDX
                            | Register::RBX
                            | Register::RBP
                            | Register::RSI
                            | Register::RDI
                    );
                return is_32_or_64;
            }
            continue;
        }
        for op_i in 0..ins.op_count() {
            if ins.op_kind(op_i) == OpKind::Register
                && gp_reg_index(ins.op_register(op_i)) == Some(src_gp)
            {
                return false;
            }
        }
    }
    false
}

/// Generate exact-same-length 2-instruction byte sequences for `5`-byte
/// `mov eax..edi, imm32` (`B8+r imm32`) and `7`-byte `mov r64, imm32`
/// (`48/49 C7 C0+r imm32`) when `dead_flags == true` and `imm32 as i32` is in
/// `-127..=127` (`!= 0`), combining `{xor | sub}` self-zeroing with
/// `{lea | add | sub | or | xor}` `imm8`/`disp8`.
fn multi_instr_imm_load_alts(instr: &Instruction, dead_flags: bool) -> Vec<Vec<u8>> {
    use iced_x86::Register;

    let mut out = Vec::new();
    if !dead_flags || instr.op0_kind() != OpKind::Register {
        return out;
    }

    if instr.code() == Code::Mov_r32_imm32 && instr.len() == 5 {
        let r32 = instr.op0_register();
        if r32 == Register::ESP {
            return out;
        }
        let Some(r64) = reg32_to_base64_low8(r32) else {
            return out;
        };
        let imm = instr.immediate32() as i32;
        if !(-127..=127).contains(&imm) || imm == 0 {
            return out;
        }
        let zeros = [
            Instruction::with2(Code::Xor_rm32_r32, r32, r32).ok(),
            Instruction::with2(Code::Sub_rm32_r32, r32, r32).ok(),
        ];
        let mem = iced_x86::MemoryOperand::with_base_displ(r64, imm as i64);
        let ops = [
            Instruction::with2(Code::Lea_r32_m, r32, mem).ok(),
            Instruction::with2(Code::Add_rm32_imm8, r32, imm).ok(),
            Instruction::with2(Code::Sub_rm32_imm8, r32, -imm).ok(),
            Instruction::with2(Code::Or_rm32_imm8, r32, imm).ok(),
            Instruction::with2(Code::Xor_rm32_imm8, r32, imm).ok(),
        ];
        for z in zeros.iter().flatten() {
            let mut enc1 = Encoder::new(64);
            let Ok(l1) = enc1.encode(z, instr.ip()) else {
                continue;
            };
            let b1 = enc1.take_buffer();
            for op in ops.iter().flatten() {
                let mut enc2 = Encoder::new(64);
                let Ok(l2) = enc2.encode(op, instr.ip() + l1 as u64) else {
                    continue;
                };
                if l1 + l2 == 5 {
                    let mut combined = Vec::with_capacity(5);
                    combined.extend_from_slice(&b1);
                    combined.extend_from_slice(&enc2.take_buffer());
                    out.push(combined);
                }
            }
        }
    } else if instr.code() == Code::Mov_rm64_imm32 && instr.len() == 7 {
        let r64 = instr.op0_register();
        if r64 == Register::RSP || gp_reg_index(r64).is_none() {
            return out;
        }
        let imm = instr.immediate32() as i32;
        if !(-127..=127).contains(&imm) || imm == 0 {
            return out;
        }
        let zeros = [
            Instruction::with2(Code::Xor_rm64_r64, r64, r64).ok(),
            Instruction::with2(Code::Sub_rm64_r64, r64, r64).ok(),
        ];
        let lea_opt = if r64 != Register::R12 {
            let mem = iced_x86::MemoryOperand::with_base_displ(r64, imm as i64);
            Instruction::with2(Code::Lea_r64_m, r64, mem).ok()
        } else {
            None
        };
        let ops = [
            lea_opt,
            Instruction::with2(Code::Add_rm64_imm8, r64, imm).ok(),
            Instruction::with2(Code::Sub_rm64_imm8, r64, -imm).ok(),
            Instruction::with2(Code::Or_rm64_imm8, r64, imm).ok(),
            Instruction::with2(Code::Xor_rm64_imm8, r64, imm).ok(),
        ];
        for z in zeros.iter().flatten() {
            let mut enc1 = Encoder::new(64);
            let Ok(l1) = enc1.encode(z, instr.ip()) else {
                continue;
            };
            let b1 = enc1.take_buffer();
            for op in ops.iter().flatten() {
                let mut enc2 = Encoder::new(64);
                let Ok(l2) = enc2.encode(op, instr.ip() + l1 as u64) else {
                    continue;
                };
                if l1 + l2 == 7 {
                    let mut combined = Vec::with_capacity(7);
                    combined.extend_from_slice(&b1);
                    combined.extend_from_slice(&enc2.take_buffer());
                    out.push(combined);
                }
            }
        }
    }
    out
}

/// `true` if `instrs[idx]` is a 32-bit self-test (`test/or/and r32, r32`) and
/// an earlier instruction in the same basic block wrote to that exact `r32`
/// (guaranteeing bits 63..32 of the 64-bit register are already zero) with no
/// intervening write to that register family.
fn prev_instr_zeroed_upper32(
    instrs: &[Instruction],
    branch_targets: &[u64],
    idx: usize,
) -> bool {
    use iced_x86::FlowControl;

    if idx == 0 {
        return false;
    }
    let cur = &instrs[idx];
    if cur.op_count() != 2 || cur.op0_kind() != OpKind::Register {
        return false;
    }
    let r32 = cur.op0_register();
    let Some(target_gp) = gp_reg_index(r32) else {
        return false;
    };

    let mut cursor = idx;
    let mut steps = 0usize;
    while cursor > 0 && steps < 8 {
        if branch_targets.contains(&instrs[cursor].ip()) {
            return false;
        }
        cursor -= 1;
        steps += 1;
        let prev = &instrs[cursor];
        if prev.flow_control() != FlowControl::Next {
            return false;
        }
        if prev.op_count() >= 1
            && prev.op0_kind() == OpKind::Register
            && prev.op0_register() == r32
            && matches!(
                prev.mnemonic(),
                Mnemonic::Mov
                    | Mnemonic::Movzx
                    | Mnemonic::Lea
                    | Mnemonic::Add
                    | Mnemonic::Sub
                    | Mnemonic::And
                    | Mnemonic::Or
                    | Mnemonic::Xor
                    | Mnemonic::Shl
                    | Mnemonic::Shr
            )
        {
            return true;
        }
        // Only skip over explicit-register instructions that do not write `target_gp`.
        if !matches!(
            prev.mnemonic(),
            Mnemonic::Mov
                | Mnemonic::Movzx
                | Mnemonic::Movsx
                | Mnemonic::Movsxd
                | Mnemonic::Lea
                | Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::And
                | Mnemonic::Or
                | Mnemonic::Xor
                | Mnemonic::Cmp
                | Mnemonic::Test
                | Mnemonic::Shl
                | Mnemonic::Shr
                | Mnemonic::Sar
                | Mnemonic::Push
        ) {
            return false;
        }
        if prev.op_count() >= 1 && prev.op0_kind() == OpKind::Register {
            if gp_reg_index(prev.op0_register()) == Some(target_gp)
                && !matches!(prev.mnemonic(), Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Push)
            {
                return false;
            }
        }
    }
    false
}

#[inline]
fn has_ret_opcode_byte(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .any(|&b| b == 0xC3 || b == 0xC2 || b == 0xCB || b == 0xCA || b == 0xCF)
        || bytes
            .windows(2)
            .any(|w| w[0] == 0xFF && matches!((w[1] >> 3) & 0b111, 2..=5))
}

/// Per-instruction flag- and register-safe morph pass (`MOV<->LEA<->XCHG`,
/// `MOV/ALU/CMP` opposite-direction encoding swaps, self-zeroing `xor<->sub`,
/// 8/16/32/64-bit self-test `test<->or<->and`, dead-flags `add<->sub<->lea`,
/// `CF/AF`-dead `add<->sub`, 2-instruction small-immediate load morphs,
/// commutative distinct-reg `test`/`xchg`, SIB `scale=1` swap, and active
/// unintended return/indirect-branch (`0xC3/0xC2/0xCB/0xCA/0xCF`, `0xFF /2../5`)
/// gadget terminator scrubbing).
fn pass_reg_reg_morph(code: &mut [u8], base_ip: u64, prng: &mut Prng, stats: &mut Stats) {
    use iced_x86::FlowControl;

    let original = code.to_vec();
    let end_ip = base_ip.saturating_add(original.len() as u64);
    let mut decoder = Decoder::with_ip(64, &original, base_ip, DecoderOptions::NONE);
    let mut instrs: Vec<Instruction> = Vec::new();
    let mut positions: Vec<usize> = Vec::new();
    let mut branch_targets: Vec<u64> = Vec::new();
    let mut allow_liveness = true;

    while decoder.can_decode() {
        let pos = decoder.position();
        let instr = decoder.decode();
        if instr.code() == Code::INVALID {
            break;
        }
        match instr.flow_control() {
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                match instr.op0_kind() {
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                        let t = instr.near_branch_target();
                        if t >= base_ip && t < end_ip {
                            branch_targets.push(t);
                        } else if instr.flow_control() != FlowControl::UnconditionalBranch {
                            allow_liveness = false;
                        }
                    }
                    _ => allow_liveness = false,
                }
            }
            FlowControl::IndirectBranch => allow_liveness = false,
            _ => {}
        }
        positions.push(pos);
        instrs.push(instr);
    }

    for (idx, instr) in instrs.iter().enumerate() {
        let pos = positions[idx];
        stats.instrs += 1;
        let ilen = instr.len();
        let dead_flags = allow_liveness && flags_are_dead(&instrs, &branch_targets, idx);
        let cf_af_dead =
            allow_liveness && (dead_flags || cf_af_are_dead(&instrs, &branch_targets, idx));
        let upper32_zero = allow_liveness && prev_instr_zeroed_upper32(&instrs, &branch_targets, idx);
        let src_reg_dead = allow_liveness && src_reg_is_dead_after(&instrs, &branch_targets, idx);

        let orig_bytes = &original[pos..pos + ilen];
        let mut alts: Vec<(Vec<u8>, bool)> = Vec::new();
        for c in 0..8u64 {
            if let Some(alt) = morph_instr_with_context(
                instr,
                c,
                dead_flags,
                cf_af_dead,
                upper32_zero,
                src_reg_dead,
            ) {
                if let Some(bytes) = try_encode_same_len(&alt, instr) {
                    if bytes != orig_bytes && !alts.iter().any(|(b, _)| b == &bytes) {
                        let sem_changed = alt.mnemonic() != instr.mnemonic()
                            || alt.op0_register() != instr.op0_register()
                            || alt.memory_base() != instr.memory_base();
                        alts.push((bytes, sem_changed));
                    }
                }
            }
        }
        for pair_bytes in multi_instr_imm_load_alts(instr, dead_flags) {
            if pair_bytes != orig_bytes && !alts.iter().any(|(b, _)| b == &pair_bytes) {
                alts.push((pair_bytes, true));
            }
        }
        if alts.is_empty() {
            continue;
        }
        stats.candidates += 1;
        let orig_has_ret = has_ret_opcode_byte(orig_bytes);
        let draw = prng.next_u64();

        // Unintended `0xC3/0xC2/0xCB/0xCA/0xCF` (`ret`/`iret`) and `0xFF /2../5`
        // (`call/jmp r/m64`) bytes are free ROP/JOP gadgets: always scrub them
        // (100% probability); otherwise flip on the seeded coin.
        if !orig_has_ret && (draw & 1 == 0) {
            continue;
        }

        // Prefer encodings that:
        // 1. Do NOT contain any embedded return or indirect call/jmp byte, AND
        // 2. Change the disassembled mnemonic or operand order (`mov`↔`lea`↔`xchg`,
        //    `xor`↔`sub`, `test`↔`or`↔`and`, `add`↔`shl`, `add`↔`sub`↔`lea`,
        //    `mov imm32`↔`xor/sub+lea/add/sub/or/xor`, `r32`↔`r64`, SIB swap)
        //    rather than merely flipping the direction bit (`89`↔`8B`).
        let sem_clean_count = alts
            .iter()
            .filter(|(b, sem)| *sem && !has_ret_opcode_byte(b))
            .count();
        let clean_count = alts
            .iter()
            .filter(|(b, _)| !has_ret_opcode_byte(b))
            .count();
        let pick_idx = (draw >> 1) as usize;
        let chosen = if sem_clean_count > 0 {
            let mut k = pick_idx % sem_clean_count;
            alts.into_iter()
                .find_map(|(b, sem)| {
                    if sem && !has_ret_opcode_byte(&b) {
                        if k == 0 {
                            return Some(b);
                        }
                        k -= 1;
                    }
                    None
                })
                .unwrap()
        } else if clean_count > 0 {
            let mut k = pick_idx % clean_count;
            alts.into_iter()
                .find_map(|(b, _)| {
                    if !has_ret_opcode_byte(&b) {
                        if k == 0 {
                            return Some(b);
                        }
                        k -= 1;
                    }
                    None
                })
                .unwrap()
        } else {
            alts.swap_remove(pick_idx % alts.len()).0
        };

        code[pos..pos + ilen].copy_from_slice(&chosen);
        stats.swapped += 1;
    }
}

/// Rewrite one function's code in place. Every edit is size-preserving, so
/// the buffer length and all external addresses are preserved.
///
/// Runs 6 passes:
/// 1. [`pass_callee_saved_reg_swap`] — whole-function callee-saved register
///    family permutation across `{R12, R13, R14, R15}` (`64/32/16/8`-bit).
/// 2. [`pass_leaf_scratch_reg_swap`] — whole-function caller-saved scratch
///    register family permutation across `{R8, R9, R10, R11}` in leaf functions.
/// 3. [`pass_return_block_scratch_swap`] — return-basic-block caller-saved
///    scratch register family renaming across `{R8..R11}` and `{RCX, RSI, RDI}`.
/// 4. [`pass_prologue_epilogue_perm`] — prologue `push` / epilogue `pop` order
///    permutation across `{RBX, RBP, R12, R13, R14, R15}`.
/// 5. [`pass_schedule_commute`] — intra-block independent instruction window permutation.
/// 6. [`pass_reg_reg_morph`] — liveness-guided instruction morphing (`MOV<->LEA`,
///    dead-flags `ADD<->SUB<->LEA`, 8/16/32/64-bit `TEST<->OR<->AND`, upper-reg
///    32/64-bit zeroing, SIB `scale=1` swap, and return-byte gadget scrubbing).
pub fn rewrite_function(code: &mut [u8], base_ip: u64, prng: &mut Prng, stats: &mut Stats) {
    stats.functions += 1;
    pass_callee_saved_reg_swap(code, base_ip, prng, stats);
    pass_leaf_scratch_reg_swap(code, base_ip, prng, stats);
    pass_return_block_scratch_swap(code, base_ip, prng, stats);
    pass_prologue_epilogue_perm(code, base_ip, prng, stats);
    pass_schedule_commute(code, base_ip, prng, stats);
    pass_reg_reg_morph(code, base_ip, prng, stats);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_one(bytes: &[u8]) -> Instruction {
        let mut d = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        d.decode()
    }

    #[test]
    fn swaps_reg_reg_mov_to_equivalent_encoding() {
        // mov rax, rbx  ==  48 89 D8  (MOV r/m,r)
        let instr = decode_one(&[0x48, 0x89, 0xD8]);
        assert_eq!(instr.mnemonic(), Mnemonic::Mov);
        let alt = swapped_reg_reg_mov(&instr).expect("should be swappable");
        let mut enc = Encoder::new(64);
        let len = enc.encode(&alt, 0x1000).unwrap();
        let out = enc.take_buffer();
        // Expect the opposite encoding: 48 8B C3 (MOV r,r/m), same length.
        assert_eq!(len, 3);
        assert_eq!(out, vec![0x48, 0x8B, 0xC3]);
        // And it must still mean `mov rax, rbx`.
        let back = decode_one(&out);
        assert_eq!(back.op0_register(), instr.op0_register());
        assert_eq!(back.op1_register(), instr.op1_register());
        assert_eq!(back.mnemonic(), Mnemonic::Mov);
    }

    #[test]
    fn swap_is_an_involution() {
        // Swapping twice returns the original encoding.
        let a = decode_one(&[0x48, 0x89, 0xD8]);
        let b = swapped_reg_reg_mov(&a).unwrap();
        let c = swapped_reg_reg_mov(&b).unwrap();
        let mut enc = Encoder::new(64);
        enc.encode(&c, 0).unwrap();
        assert_eq!(enc.take_buffer(), vec![0x48, 0x89, 0xD8]);
    }

    #[test]
    fn does_not_touch_memory_movs() {
        // mov rax, [rbx]  = 48 8B 03  — op1 is memory, not swappable.
        let instr = decode_one(&[0x48, 0x8B, 0x03]);
        assert_eq!(instr.mnemonic(), Mnemonic::Mov);
        assert!(swapped_reg_reg_mov(&instr).is_none());
        assert!(morph_reg_reg_instr(&instr, 0).is_none());
    }

    #[test]
    fn does_not_touch_non_movs() {
        let instr = decode_one(&[0x48, 0x01, 0xD8]); // add rax, rbx
        assert!(swapped_reg_reg_mov(&instr).is_none());
    }

    #[test]
    fn morphs_alu_and_cmp_reg_reg_directions() {
        // add rax, rbx = 48 01 D8 (r/m, r) <-> 48 03 C3 (r, r/m)
        let add = decode_one(&[0x48, 0x01, 0xD8]);
        let alt = morph_reg_reg_instr(&add, 0).expect("add reg,reg should morph");
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&alt, 0x1000).unwrap(), 3);
        assert_eq!(enc.take_buffer(), vec![0x48, 0x03, 0xC3]);

        // cmp rcx, rdx = 48 39 D1 (r/m, r) <-> 48 3B CA (r, r/m)
        let cmp = decode_one(&[0x48, 0x39, 0xD1]);
        let alt_cmp = morph_reg_reg_instr(&cmp, 0).expect("cmp reg,reg should morph");
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&alt_cmp, 0x1000).unwrap(), 3);
        assert_eq!(enc.take_buffer(), vec![0x48, 0x3B, 0xCA]);
    }

    #[test]
    fn morphs_self_zeroing_xor_to_sub_and_alt_dir() {
        // xor eax, eax = 31 C0 (2 bytes)
        let xor_eax = decode_one(&[0x31, 0xC0]);
        // choice 0 -> sub eax, eax (29 C0)
        let as_sub = morph_reg_reg_instr(&xor_eax, 0).unwrap();
        assert_eq!(as_sub.mnemonic(), Mnemonic::Sub);
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&as_sub, 0x1000).unwrap(), 2);
        assert_eq!(enc.take_buffer(), vec![0x29, 0xC0]);

        // choice 2 -> xor eax, eax opposite dir (33 C0)
        let as_xor_alt = morph_reg_reg_instr(&xor_eax, 2).unwrap();
        assert_eq!(as_xor_alt.mnemonic(), Mnemonic::Xor);
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&as_xor_alt, 0x1000).unwrap(), 2);
        assert_eq!(enc.take_buffer(), vec![0x33, 0xC0]);
    }

    #[test]
    fn morphs_self_test_to_or_and_and_for_8_16_64_only() {
        // test rax, rax = 48 85 C0 (3 bytes)
        let test64 = decode_one(&[0x48, 0x85, 0xC0]);
        let as_or = morph_reg_reg_instr(&test64, 0).unwrap();
        assert_eq!(as_or.mnemonic(), Mnemonic::Or);
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&as_or, 0x1000).unwrap(), 3);
        assert_eq!(enc.take_buffer(), vec![0x48, 0x09, 0xC0]);

        let as_and = morph_reg_reg_instr(&test64, 2).unwrap();
        assert_eq!(as_and.mnemonic(), Mnemonic::And);
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&as_and, 0x1000).unwrap(), 3);
        assert_eq!(enc.take_buffer(), vec![0x48, 0x21, 0xC0]);

        // 8-bit `test al, al` = 84 C0 (2 bytes) -> `or al, al` (08 C0)
        let test8 = decode_one(&[0x84, 0xC0]);
        let as_or8 = morph_reg_reg_instr(&test8, 0).unwrap();
        assert_eq!(as_or8.mnemonic(), Mnemonic::Or);
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&as_or8, 0x1000).unwrap(), 2);
        assert_eq!(enc.take_buffer(), vec![0x08, 0xC0]);

        // 32-bit `test eax, eax` (85 C0) must NOT morph to `or/and` because
        // 32-bit `or/and` zero-extends upper 32 bits of RAX whereas `test`
        // does not.
        let test32 = decode_one(&[0x85, 0xC0]);
        assert!(morph_reg_reg_instr(&test32, 0).is_none());
    }

    #[test]
    fn morphs_mov_to_lea_and_back() {
        // mov rax, rbx = 48 89 D8 (3 bytes) -> choice 0 is `lea rax, [rbx]` = 48 8D 03 (3 bytes)
        let mov64 = decode_one(&[0x48, 0x89, 0xD8]);
        let lea64 = morph_reg_reg_instr(&mov64, 0).expect("mov rax, rbx -> lea rax, [rbx]");
        assert_eq!(lea64.mnemonic(), Mnemonic::Lea);
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&lea64, 0x1000).unwrap(), 3);
        let lea_bytes = enc.take_buffer();
        assert_eq!(lea_bytes, vec![0x48, 0x8D, 0x03]);

        // And `lea rax, [rbx]` morphs back to `mov rax, rbx`
        let decoded_lea = decode_one(&lea_bytes);
        let back_mov = morph_reg_reg_instr(&decoded_lea, 0).expect("lea rax, [rbx] -> mov rax, rbx");
        assert_eq!(back_mov.mnemonic(), Mnemonic::Mov);

        // `mov rax, rsp` (48 89 E0) must NOT morph to `lea rax, [rsp]` because
        // `[rsp]` requires a SIB byte (4 bytes vs 3 bytes), only opposite-dir `mov` is valid.
        let mov_rsp = decode_one(&[0x48, 0x89, 0xE0]);
        let alt_rsp = morph_reg_reg_instr(&mov_rsp, 0).unwrap();
        assert_eq!(alt_rsp.mnemonic(), Mnemonic::Mov);
    }

    #[test]
    fn scrubs_unintended_c3_modrm_bytes() {
        // `mov rbx, rax` = 48 89 C3 — contains an embedded `0xC3` (`ret`) byte!
        // `rewrite_function` must always scrub it (100% probability across seeds)
        // to an equivalent non-0xC3 encoding (`48 8B D8` or `48 8D 18`).
        for seed in 0..16u64 {
            let mut code = vec![0x48, 0x89, 0xC3, 0xC3];
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            rewrite_function(&mut code, 0x1000, &mut prng, &mut stats);
            assert_eq!(stats.swapped, 1, "embedded 0xC3 must always be scrubbed");
            assert!(
                !code[0..3].contains(&0xC3),
                "rewritten instruction must not contain 0xC3: {:02x?}",
                &code[0..3]
            );
            assert_eq!(code[3], 0xC3, "actual ret instruction must remain untouched");
        }
    }

    #[test]
    fn morphs_commutative_distinct_reg_test() {
        // test eax, ecx = 85 C8 -> test ecx, eax = 85 C1
        let t = decode_one(&[0x85, 0xC8]);
        let alt = morph_reg_reg_instr(&t, 0).unwrap();
        assert_eq!(alt.mnemonic(), Mnemonic::Test);
        assert_eq!(alt.op0_register(), t.op1_register());
        assert_eq!(alt.op1_register(), t.op0_register());
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&alt, 0x1000).unwrap(), 2);
        assert_eq!(enc.take_buffer(), vec![0x85, 0xC1]);
    }

    #[test]
    fn morphs_shl_by_1_to_self_add_and_back() {
        // shl rax, 1 = 48 D1 E0 (3 bytes) -> add rax, rax = 48 01 C0 (3 bytes)
        let shl64 = decode_one(&[0x48, 0xD1, 0xE0]);
        assert_eq!(shl64.mnemonic(), Mnemonic::Shl);
        let add64 = morph_reg_reg_instr(&shl64, 0).expect("shl rax, 1 -> add rax, rax");
        assert_eq!(add64.mnemonic(), Mnemonic::Add);
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&add64, 0x1000).unwrap(), 3);
        let add_bytes = enc.take_buffer();
        assert_eq!(add_bytes, vec![0x48, 0x01, 0xC0]);

        // And `add rax, rax` morphs back to `shl rax, 1` (for choices 0..=2)
        let decoded_add = decode_one(&add_bytes);
        let back_shl = morph_reg_reg_instr(&decoded_add, 0).expect("add rax, rax -> shl rax, 1");
        assert_eq!(back_shl.mnemonic(), Mnemonic::Shl);
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&back_shl, 0x1000).unwrap(), 3);
        assert_eq!(enc.take_buffer(), vec![0x48, 0xD1, 0xE0]);
    }

    #[test]
    fn morphs_sib_scale1_base_and_index() {
        // mov rax, [rcx + rdx] = 48 8B 04 11 (4 bytes)
        // -> mov rax, [rdx + rcx] = 48 8B 04 0A (4 bytes)
        let load = decode_one(&[0x48, 0x8B, 0x04, 0x11]);
        let swapped = morph_reg_reg_instr(&load, 0).expect("scale=1 SIB should swap base<->index");
        assert_eq!(swapped.memory_base(), load.memory_index());
        assert_eq!(swapped.memory_index(), load.memory_base());
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&swapped, 0x1000).unwrap(), 4);
        assert_eq!(enc.take_buffer(), vec![0x48, 0x8B, 0x04, 0x0A]);
    }

    #[test]
    fn morphs_commutative_xchg() {
        // xchg ecx, edx = 87 D1 (2 bytes) -> xchg edx, ecx = 87 CA (2 bytes)
        let x = decode_one(&[0x87, 0xD1]);
        let alt = morph_reg_reg_instr(&x, 0).expect("xchg r1, r2 should commute");
        assert_eq!(alt.mnemonic(), Mnemonic::Xchg);
        assert_eq!(alt.op0_register(), x.op1_register());
        assert_eq!(alt.op1_register(), x.op0_register());
        let mut enc = Encoder::new(64);
        assert_eq!(enc.encode(&alt, 0x1000).unwrap(), 2);
        assert_eq!(enc.take_buffer(), vec![0x87, 0xCA]);
    }

    #[test]
    fn rewrite_preserves_length_and_only_edits_reg_reg_candidates() {
        // mov rax,[rbx] (48 8B 03, memory -> non-candidate) ; mov rax,rbx (48 89 D8) ; ret (C3)
        let mut code = vec![0x48, 0x8B, 0x03, 0x48, 0x89, 0xD8, 0xC3];
        let original_len = code.len();
        let mut prng = Prng::new(12345);
        let mut stats = Stats::default();
        rewrite_function(&mut code, 0x2000, &mut prng, &mut stats);
        assert_eq!(code.len(), original_len, "rewrite must be size-preserving");
        assert_eq!(stats.candidates, 1, "exactly one reg-reg candidate");
        // The memory-mov and ret bytes are never touched.
        assert_eq!(&code[0..3], &[0x48, 0x8B, 0x03]);
        assert_eq!(code[6], 0xC3);
        // The mov is either untouched, the opposite-dir mov, or `lea rax, [rbx]`.
        let mov = &code[3..6];
        assert!(
            mov == [0x48, 0x89, 0xD8] || mov == [0x48, 0x8B, 0xC3] || mov == [0x48, 0x8D, 0x03],
            "mov must remain itself or its equivalent encoding, got {:02x?}",
            mov
        );
    }

    #[test]
    fn remap_r14_to_r15_register_operand() {
        use iced_x86::Register::{R14, R15};
        // mov r14, rcx = 49 89 CE
        let instr = decode_one(&[0x49, 0x89, 0xCE]);
        let ni = remap_pair(&instr, R14, R15);
        let mut enc = Encoder::new(64);
        let len = enc.encode(&ni, 0x1000).unwrap();
        assert_eq!(len, 3, "r14<->r15 must be length-preserving");
        // mov r15, rcx = 49 89 CF
        assert_eq!(enc.take_buffer(), vec![0x49, 0x89, 0xCF]);
    }

    #[test]
    fn remap_r14_to_r15_memory_base() {
        use iced_x86::Register::{R14, R15};
        // mov rax, [r14] = 49 8B 06
        let instr = decode_one(&[0x49, 0x8B, 0x06]);
        let ni = remap_pair(&instr, R14, R15);
        let mut enc = Encoder::new(64);
        let len = enc.encode(&ni, 0x1000).unwrap();
        assert_eq!(len, 3);
        // mov rax, [r15] = 49 8B 07
        assert_eq!(enc.take_buffer(), vec![0x49, 0x8B, 0x07]);
    }

    #[test]
    fn try_swap_r14_r15_applies_consistently() {
        // mov r14, rcx (49 89 CE) ; ret (C3)
        let mut code = vec![0x49, 0x89, 0xCE, 0xC3];
        let mut stats = Stats::default();
        let applied = try_swap_r14_r15(&mut code, 0x1000, &mut stats);
        assert!(applied, "function uses r14 → swap should apply");
        assert_eq!(stats.reg_remapped_instrs, 1);
        // mov r15, rcx (49 89 CF) ; ret unchanged
        assert_eq!(code, vec![0x49, 0x89, 0xCF, 0xC3]);
    }

    #[test]
    fn try_swap_r14_r15_noop_when_absent() {
        // add rax, rbx ; ret — no r14/r15
        let mut code = vec![0x48, 0x01, 0xD8, 0xC3];
        let before = code.clone();
        let mut stats = Stats::default();
        let applied = try_swap_r14_r15(&mut code, 0x1000, &mut stats);
        assert!(!applied, "no r14/r15 → nothing to swap");
        assert_eq!(code, before, "code must be untouched");
    }

    #[test]
    fn rewrite_eventually_swaps_across_seeds() {
        // Over many seeds, at least one must flip the candidate — proves the
        // swap path is reachable, not just the skip path.
        let mut any = false;
        for seed in 0..32u64 {
            let mut code = vec![0x48, 0x89, 0xD8, 0xC3];
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            rewrite_function(&mut code, 0, &mut prng, &mut stats);
            if stats.swapped == 1 {
                // Prefers non-0xC3 `lea rax, [rbx]` (`48 8D 03`) over `48 8B C3`.
                assert_eq!(&code[0..3], &[0x48, 0x8D, 0x03]);
                any = true;
                break;
            }
        }
        assert!(any, "no seed in 0..32 triggered a swap");
    }

    #[test]
    fn prologue_epilogue_permutes_push_and_reverse_pop_blocks() {
        // push r15 (41 57) ; push rbx (53) ; xor eax, eax (31 C0) ; pop rbx (5B) ; pop r15 (41 5F) ; ret (C3)
        let orig = vec![0x41, 0x57, 0x53, 0x31, 0xC0, 0x5B, 0x41, 0x5F, 0xC3];
        let mut saw_permuted = false;
        for seed in 0..32u64 {
            let mut code = orig.clone();
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            pass_prologue_epilogue_perm(&mut code, 0x1000, &mut prng, &mut stats);
            assert_eq!(code.len(), orig.len());
            if &code[0..3] != &orig[0..3] {
                // Prologue became `push rbx (53) ; push r15 (41 57)`
                assert_eq!(&code[0..3], &[0x53, 0x41, 0x57]);
                // Epilogue became `pop r15 (41 5F) ; pop rbx (5B)`
                assert_eq!(&code[5..8], &[0x41, 0x5F, 0x5B]);
                assert_eq!(code[8], 0xC3);
                saw_permuted = true;
            }
        }
        assert!(saw_permuted, "prologue/epilogue push-pop order must permute");
    }

    #[test]
    fn leaf_scratch_reg_swap_permutes_overwritten_r8_r11() {
        // mov r10d, 1 (41 BA 01 00 00 00) ; mov eax, r10d (44 89 D0) ; ret (C3)
        let orig = vec![0x41, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x44, 0x89, 0xD0, 0xC3];
        let mut saw_swapped = false;
        for seed in 0..32u64 {
            let mut code = orig.clone();
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            pass_leaf_scratch_reg_swap(&mut code, 0x1000, &mut prng, &mut stats);
            assert_eq!(code.len(), orig.len());
            if code != orig {
                saw_swapped = true;
                break;
            }
        }
        assert!(saw_swapped, "leaf scratch R8..R11 must permute when overwritten at entry");
    }

    #[test]
    fn schedule_commute_swaps_independent_moves() {
        // mov eax, 1 (B8 01 00 00 00) ; mov ecx, 2 (B9 02 00 00 00) ; ret (C3)
        let orig = vec![
            0xB8, 0x01, 0x00, 0x00, 0x00, 0xB9, 0x02, 0x00, 0x00, 0x00, 0xC3,
        ];
        let mut saw_commuted = false;
        for seed in 0..32u64 {
            let mut code = orig.clone();
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            pass_schedule_commute(&mut code, 0x1000, &mut prng, &mut stats);
            if &code[0..5] == &[0xB9, 0x02, 0x00, 0x00, 0x00] {
                assert_eq!(&code[5..10], &[0xB8, 0x01, 0x00, 0x00, 0x00]);
                saw_commuted = true;
                break;
            }
        }
        assert!(saw_commuted, "independent adjacent moves must commute");
    }

    #[test]
    fn dead_flags_morphs_add_rsp_and_32bit_test() {
        // add rsp, 0x28 (48 83 C4 28) ; ret (C3) -> sub rsp, -0x28 (48 83 EC D8) ; ret (C3)
        let orig_rsp = vec![0x48, 0x83, 0xC4, 0x28, 0xC3];
        let mut saw_sub_rsp = false;
        for seed in 0..32u64 {
            let mut code = orig_rsp.clone();
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            pass_reg_reg_morph(&mut code, 0x1000, &mut prng, &mut stats);
            if &code[0..4] == &[0x48, 0x83, 0xEC, 0xD8] {
                saw_sub_rsp = true;
                break;
            }
        }
        assert!(saw_sub_rsp, "epilogue add rsp, imm8 must morph to sub rsp, -imm8");

        // mov eax, edi (89 F8) ; test eax, eax (85 C0) ; ret (C3)
        // Because `mov eax, edi` zeroes bits 63..32 of RAX, `test eax, eax` can
        // safely morph to `or eax, eax` (09 C0 / 0B C0) or `and eax, eax` (21 C0 / 23 C0).
        let orig_test = vec![0x89, 0xF8, 0x85, 0xC0, 0xC3];
        let mut saw_test32_morph = false;
        for seed in 0..32u64 {
            let mut code = orig_test.clone();
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            pass_reg_reg_morph(&mut code, 0x1000, &mut prng, &mut stats);
            if &code[2..4] != &[0x85, 0xC0] {
                saw_test32_morph = true;
                break;
            }
        }
        assert!(saw_test32_morph, "32-bit test after 32-bit write must morph to or/and");
    }

    #[test]
    fn prologue_epilogue_permutes_with_push_rax_and_cold_panic_call() {
        // push r15 (41 57) ; push r14 (41 56) ; push rax (50) ; add rsp, 8 (48 83 C4 08) ;
        // pop r14 (41 5E) ; pop r15 (41 5F) ; ret (C3) ; call +0 (E8 00 00 00 00)
        let orig = vec![
            0x41, 0x57, 0x41, 0x56, 0x50, 0x48, 0x83, 0xC4, 0x08, 0x41, 0x5E, 0x41, 0x5F, 0xC3,
            0xE8, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut saw_perm = false;
        for seed in 0..32u64 {
            let mut code = orig.clone();
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            pass_prologue_epilogue_perm(&mut code, 0x1000, &mut prng, &mut stats);
            if &code[0..4] != &orig[0..4] {
                assert_eq!(&code[0..4], &[0x41, 0x56, 0x41, 0x57]);
                assert_eq!(code[4], 0x50, "push rax alignment slot must remain intact");
                assert_eq!(&code[9..13], &[0x41, 0x5F, 0x41, 0x5E]);
                saw_perm = true;
                break;
            }
        }
        assert!(
            saw_perm,
            "prologue/epilogue must permute across push rax alignment and trailing cold call"
        );
    }

    #[test]
    fn return_block_scratch_swap_renames_overwritten_caller_saved_before_ret() {
        // Non-leaf function:
        // call +0 (E8 00 00 00 00) ; mov r8d, 7 (41 B8 07 00 00 00) ; add eax, r8d (44 01 C0) ; ret (C3)
        let orig = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, 0x41, 0xB8, 0x07, 0x00, 0x00, 0x00, 0x44, 0x01, 0xC0,
            0xC3,
        ];
        let mut saw_renamed = false;
        for seed in 0..32u64 {
            let mut code = orig.clone();
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            pass_return_block_scratch_swap(&mut code, 0x1000, &mut prng, &mut stats);
            if code != orig {
                assert_eq!(code.len(), orig.len());
                assert_eq!(&code[0..5], &orig[0..5], "call must not be modified");
                assert_eq!(code[14], 0xC3, "ret must not be modified");
                saw_renamed = true;
                break;
            }
        }
        assert!(
            saw_renamed,
            "return basic block scratch R8 must rename in non-leaf function before ret"
        );
    }

    #[test]
    fn schedule_commute_permutes_window_and_recomputes_rip_relative_lea() {
        // lea rdi, [rip + 0x100] (48 8D 3D 00 01 00 00, len=7, target=0x1107)
        // mov esi, 42 (BE 2A 00 00 00, len=5)
        // ret (C3)
        let orig = vec![
            0x48, 0x8D, 0x3D, 0x00, 0x01, 0x00, 0x00, 0xBE, 0x2A, 0x00, 0x00, 0x00, 0xC3,
        ];
        let mut saw_commuted = false;
        for seed in 0..32u64 {
            let mut code = orig.clone();
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            pass_schedule_commute(&mut code, 0x1000, &mut prng, &mut stats);
            if &code[0..5] == &[0xBE, 0x2A, 0x00, 0x00, 0x00] {
                // `lea rdi, [rip + disp32]` moved from 0x1000 to 0x1005 (+5 bytes),
                // so disp32 must decrease by 5 (`0x100 - 5 = 0xFB`).
                assert_eq!(&code[5..12], &[0x48, 0x8D, 0x3D, 0xFB, 0x00, 0x00, 0x00]);
                saw_commuted = true;
                break;
            }
        }
        assert!(
            saw_commuted,
            "RIP-relative lea must commute and recompute disp32"
        );
    }

    #[test]
    fn scrubs_unintended_cf_iret_modrm_bytes() {
        // mov rdi, rcx = 48 89 CF (contains 0xCF `iretd` gadget byte!) ; ret (C3)
        for seed in 0..16u64 {
            let mut code = vec![0x48, 0x89, 0xCF, 0xC3];
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            rewrite_function(&mut code, 0x1000, &mut prng, &mut stats);
            assert!(
                !code[0..3].contains(&0xCF),
                "embedded 0xCF must always be scrubbed: {:02x?}",
                &code[0..3]
            );
        }
    }

    #[test]
    fn morphs_7byte_mov_r64_imm32_to_lea_r32_abs_disp32_and_back() {
        // mov rcx, 0x1000 = 48 C7 C1 00 10 00 00 (7 bytes)
        let mov = decode_one(&[0x48, 0xC7, 0xC1, 0x00, 0x10, 0x00, 0x00]);
        assert_eq!(mov.code(), Code::Mov_rm64_imm32);
        let lea = morph_instr_with_context(&mov, 0, false, false, false, false)
            .expect("mov rcx, 0x1000 should morph to lea ecx, [0x1000]");
        assert_eq!(lea.code(), Code::Lea_r32_m);
        let lea_bytes = try_encode_same_len(&lea, &mov).expect("both must be 7 bytes");
        assert_eq!(lea_bytes, vec![0x8D, 0x0C, 0x25, 0x00, 0x10, 0x00, 0x00]);

        let decoded_lea = decode_one(&lea_bytes);
        let back_mov = morph_instr_with_context(&decoded_lea, 0, false, false, false, false)
            .expect("lea ecx, [0x1000] should morph back to mov rcx, 0x1000");
        assert_eq!(back_mov.code(), Code::Mov_rm64_imm32);
        let mov_bytes = try_encode_same_len(&back_mov, &decoded_lea).expect("both must be 7 bytes");
        assert_eq!(mov_bytes, vec![0x48, 0xC7, 0xC1, 0x00, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn morphs_dead_flags_add_imm32_to_lea_disp32_and_sub_imm32() {
        // add rcx, 0x1000 = 48 81 C1 00 10 00 00 (7 bytes)
        let add = decode_one(&[0x48, 0x81, 0xC1, 0x00, 0x10, 0x00, 0x00]);
        let lea = morph_instr_with_context(&add, 0, true, true, false, false)
            .expect("dead-flags add rcx, 0x1000 should morph to lea rcx, [rcx + 0x1000]");
        assert_eq!(lea.code(), Code::Lea_r64_m);
        let lea_bytes = try_encode_same_len(&lea, &add).expect("both must be 7 bytes");
        assert_eq!(lea_bytes, vec![0x48, 0x8D, 0x89, 0x00, 0x10, 0x00, 0x00]);

        let sub = morph_instr_with_context(&add, 1, true, true, false, false)
            .expect("dead-flags add rcx, 0x1000 should morph to sub rcx, -0x1000");
        assert_eq!(sub.code(), Code::Sub_rm64_imm32);
        let sub_bytes = try_encode_same_len(&sub, &add).expect("both must be 7 bytes");
        assert_eq!(sub_bytes, vec![0x48, 0x81, 0xE9, 0x00, 0xF0, 0xFF, 0xFF]);

        let decoded_lea = decode_one(&lea_bytes);
        let back_add = morph_instr_with_context(&decoded_lea, 0, true, true, false, false)
            .expect("dead-flags lea rcx, [rcx + 0x1000] should morph back to add rcx, 0x1000");
        assert_eq!(back_add.code(), Code::Add_rm64_imm32);
    }

    #[test]
    fn morphs_dead_src_reg_mov_to_xchg() {
        // mov r14, rsi (49 89 F6) ; mov esi, 8 (BE 08 00 00 00) ; ret (C3)
        // Because `rsi` is overwritten by `mov esi, 8`, `mov r14, rsi` can morph to `xchg r14, rsi`.
        let orig = vec![0x49, 0x89, 0xF6, 0xBE, 0x08, 0x00, 0x00, 0x00, 0xC3];
        let mut saw_xchg = false;
        for seed in 0..64u64 {
            let mut code = orig.clone();
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            pass_reg_reg_morph(&mut code, 0x1000, &mut prng, &mut stats);
            let first = decode_one(&code[0..3]);
            if first.mnemonic() == Mnemonic::Xchg {
                saw_xchg = true;
                break;
            }
        }
        assert!(saw_xchg, "dead-source mov r14, rsi must morph to xchg");
    }

    #[test]
    fn morphs_5byte_and_7byte_small_imm_loads_to_multi_instr_pairs() {
        // mov esi, 0x39 (BE 39 00 00 00, 5 bytes)
        let mov32 = decode_one(&[0xBE, 0x39, 0x00, 0x00, 0x00]);
        let alts32 = multi_instr_imm_load_alts(&mov32, true);
        assert!(
            alts32.len() >= 8,
            "expected >= 8 2-instruction 5-byte alternatives for mov esi, 0x39, got {}",
            alts32.len()
        );
        for bytes in &alts32 {
            assert_eq!(bytes.len(), 5);
            let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
            let i1 = dec.decode();
            let i2 = dec.decode();
            assert!(!dec.can_decode());
            assert!(matches!(i1.mnemonic(), Mnemonic::Xor | Mnemonic::Sub));
            assert!(matches!(
                i2.mnemonic(),
                Mnemonic::Lea | Mnemonic::Add | Mnemonic::Sub | Mnemonic::Or | Mnemonic::Xor
            ));
        }

        // mov r8, -1 (49 C7 C0 FF FF FF FF, 7 bytes)
        let mov64 = decode_one(&[0x49, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF]);
        let alts64 = multi_instr_imm_load_alts(&mov64, true);
        assert!(
            alts64.len() >= 8,
            "expected >= 8 2-instruction 7-byte alternatives for mov r8, -1, got {}",
            alts64.len()
        );
        for bytes in &alts64 {
            assert_eq!(bytes.len(), 7);
        }
    }

    #[test]
    fn morphs_cf_af_dead_loop_counter_across_jne() {
        // .Lloop (0x1000):
        //   xor eax, eax    (31 C0, 2 bytes — kills flags at loop entry)
        //   sub rcx, 1      (48 83 E9 01, 4 bytes)
        //   jne .Lloop      (75 F8, 2 bytes -> target 0x1000)
        //   ret             (C3, 1 byte — kills flags on fallthrough)
        let orig = vec![0x31, 0xC0, 0x48, 0x83, 0xE9, 0x01, 0x75, 0xF8, 0xC3];
        let mut saw_add_neg1 = false;
        for seed in 0..32u64 {
            let mut code = orig.clone();
            let mut prng = Prng::new(seed);
            let mut stats = Stats::default();
            pass_reg_reg_morph(&mut code, 0x1000, &mut prng, &mut stats);
            if &code[2..6] == &[0x48, 0x83, 0xC1, 0xFF] {
                saw_add_neg1 = true;
                break;
            }
        }
        assert!(
            saw_add_neg1,
            "sub rcx, 1 followed by jne (where both paths kill CF/AF) must morph to add rcx, -1"
        );
    }
}
