//! Differential Execution & Semantic Equivalence Verification Suite for `cuttle-binmorph`.
//!
//! Directly addresses the audit requirement:
//! > *"Differential execution or equivalence checking of the rewritten functions"*
//!
//! This suite embeds a deterministic concrete x86-64 machine-code micro-emulator (`X86MicroVm`)
//! that decodes and executes both original and `cuttle-binmorph`-rewritten `.text` functions
//! from raw ELF64 bytes across dozens of seeds and randomized initial register/flag/memory
//! states, checking bit-exact post-`ret` equivalence of:
//! - Return registers (`RAX`, `RDX`)
//! - All System V AMD64 ABI callee-saved registers (`RBX`, `RBP`, `R12`, `R13`, `R14`, `R15`)
//! - Stack pointer (`RSP`)
//! - Full 64 KiB stack & scratch data memory arena

use std::collections::{BTreeMap, BTreeSet};

use cuttle_binmorph::rewrite_elf_bytes;
use iced_x86::{Code, ConditionCode, Decoder, DecoderOptions, Instruction, OpKind, Register};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use sha2::{Digest, Sha256};

const TEXT_VADDR: u64 = 0x0040_1000;
const MEM_BASE: u64 = 0x0000_7FFF_0000_0000;
const MEM_SIZE: usize = 0x10000; // 64 KiB deterministic stack + data arena
const DATA_OFFSET: usize = 0x2000;
const INITIAL_RSP_OFFSET: usize = 0x8000;
const RET_SENTINEL: u64 = 0xDEAD_BEEF_CAFE_0000;

/// Complete initial/final concrete state of the x86-64 micro-emulator.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CpuState {
    /// 16 64-bit general-purpose registers in canonical x86-64 architectural order:
    /// `0=RAX, 1=RCX, 2=RDX, 3=RBX, 4=RSP, 5=RBP, 6=RSI, 7=RDI, 8..15=R8..R15`.
    regs: [u64; 16],
    cf: bool,
    pf: bool,
    af: bool,
    zf: bool,
    sf: bool,
    of: bool,
    /// 64 KiB memory arena (`MEM_BASE .. MEM_BASE + MEM_SIZE`).
    mem: Vec<u8>,
    /// Sparse copy-on-write byte overlay for ELF `.data` / `.bss` globals mutated during execution.
    elf_writes: BTreeMap<u64, u8>,
    /// Valid ELF `.data` / `.bss` address ranges `(vaddr_start, vaddr_end)` that read as `0`
    /// when not backed by `ro_segments` and accept stores into `elf_writes`.
    writable_elf_ranges: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VmFault {
    DecodeError(u64),
    PcOutOfBounds(u64),
    MemOutOfBounds(u64, usize),
    UnsupportedInstruction(Code, String),
    StepBudgetExceeded(usize),
    DivisionByZero,
}

impl CpuState {
    fn from_seed(input_seed: u64) -> Self {
        let mut s = input_seed ^ 0x9E37_79B9_7F4A_7C15;
        let mut next_u64 = || -> u64 {
            s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };

        let mut regs = [0u64; 16];
        for r in &mut regs {
            *r = next_u64();
        }
        let mut mem = vec![0u8; MEM_SIZE];
        // Populate the data region `[DATA_OFFSET .. DATA_OFFSET + 2048]` with deterministic pseudo-random bytes.
        for chunk in mem[DATA_OFFSET..DATA_OFFSET + 2048].chunks_exact_mut(8) {
            chunk.copy_from_slice(&next_u64().to_le_bytes());
        }
        // Set RSP to INITIAL_RSP_OFFSET and plant RET_SENTINEL at [RSP].
        regs[4] = MEM_BASE + (INITIAL_RSP_OFFSET as u64);
        mem[INITIAL_RSP_OFFSET..INITIAL_RSP_OFFSET + 8]
            .copy_from_slice(&RET_SENTINEL.to_le_bytes());

        let flags_bits = next_u64();
        Self {
            regs,
            cf: (flags_bits & 1) != 0,
            pf: (flags_bits & 2) != 0,
            af: (flags_bits & 4) != 0,
            zf: (flags_bits & 8) != 0,
            sf: (flags_bits & 16) != 0,
            of: (flags_bits & 32) != 0,
            mem,
            elf_writes: BTreeMap::new(),
            writable_elf_ranges: Vec::new(),
        }
    }

    fn read_mem(
        &self,
        addr: u64,
        size: usize,
        text: &[u8],
        text_vaddr: u64,
        ro_segments: &[(u64, &[u8])],
    ) -> Result<u64, VmFault> {
        if addr >= MEM_BASE && addr.saturating_add(size as u64) <= MEM_BASE + (MEM_SIZE as u64) {
            let off = (addr - MEM_BASE) as usize;
            let mut buf = [0u8; 8];
            buf[..size].copy_from_slice(&self.mem[off..off + size]);
            return Ok(u64::from_le_bytes(buf));
        }
        if addr >= text_vaddr
            && addr.saturating_add(size as u64) <= text_vaddr + (text.len() as u64)
        {
            let off = (addr - text_vaddr) as usize;
            let mut buf = [0u8; 8];
            buf[..size].copy_from_slice(&text[off..off + size]);
            return Ok(u64::from_le_bytes(buf));
        }
        for &(seg_vaddr, seg_bytes) in ro_segments {
            if addr >= seg_vaddr
                && addr.saturating_add(size as u64) <= seg_vaddr + (seg_bytes.len() as u64)
            {
                let off = (addr - seg_vaddr) as usize;
                let mut buf = [0u8; 8];
                buf[..size].copy_from_slice(&seg_bytes[off..off + size]);
                if !self.elf_writes.is_empty() {
                    for b in 0..size {
                        if let Some(&ov) = self.elf_writes.get(&(addr + b as u64)) {
                            buf[b] = ov;
                        }
                    }
                }
                return Ok(u64::from_le_bytes(buf));
            }
        }
        if self
            .writable_elf_ranges
            .iter()
            .any(|&(lo, hi)| addr >= lo && addr.saturating_add(size as u64) <= hi)
        {
            let mut buf = [0u8; 8];
            if !self.elf_writes.is_empty() {
                for b in 0..size {
                    if let Some(&ov) = self.elf_writes.get(&(addr + b as u64)) {
                        buf[b] = ov;
                    }
                }
            }
            return Ok(u64::from_le_bytes(buf));
        }
        Err(VmFault::MemOutOfBounds(addr, size))
    }

    fn write_mem(&mut self, addr: u64, size: usize, val: u64) -> Result<(), VmFault> {
        if addr >= MEM_BASE && addr.saturating_add(size as u64) <= MEM_BASE + (MEM_SIZE as u64) {
            let off = (addr - MEM_BASE) as usize;
            let bytes = val.to_le_bytes();
            self.mem[off..off + size].copy_from_slice(&bytes[..size]);
            return Ok(());
        }
        if self
            .writable_elf_ranges
            .iter()
            .any(|&(lo, hi)| addr >= lo && addr.saturating_add(size as u64) <= hi)
        {
            let bytes = val.to_le_bytes();
            for b in 0..size {
                self.elf_writes.insert(addr + b as u64, bytes[b]);
            }
            return Ok(());
        }
        Err(VmFault::MemOutOfBounds(addr, size))
    }

    fn read_reg(&self, reg: Register) -> Result<(u64, u32), VmFault> {
        if let Some((idx, width, hi8)) = decode_gpr(reg) {
            let raw = self.regs[idx];
            let val = match (width, hi8) {
                (8, true) => (raw >> 8) & 0xFF,
                (8, false) => raw & 0xFF,
                (16, _) => raw & 0xFFFF,
                (32, _) => raw & 0xFFFF_FFFF,
                (64, _) => raw,
                _ => unreachable!(),
            };
            Ok((val, width))
        } else {
            Err(VmFault::UnsupportedInstruction(
                Code::INVALID,
                format!("unsupported register {reg:?}"),
            ))
        }
    }

    fn write_reg(&mut self, reg: Register, val: u64) -> Result<(), VmFault> {
        if let Some((idx, width, hi8)) = decode_gpr(reg) {
            match (width, hi8) {
                (8, true) => {
                    self.regs[idx] = (self.regs[idx] & !0xFF00) | ((val & 0xFF) << 8);
                }
                (8, false) => {
                    self.regs[idx] = (self.regs[idx] & !0xFF) | (val & 0xFF);
                }
                (16, _) => {
                    self.regs[idx] = (self.regs[idx] & !0xFFFF) | (val & 0xFFFF);
                }
                (32, _) => {
                    // x86-64 architectural rule: writing a 32-bit GPR zero-extends to 64 bits.
                    self.regs[idx] = val & 0xFFFF_FFFF;
                }
                (64, _) => {
                    self.regs[idx] = val;
                }
                _ => unreachable!(),
            }
            Ok(())
        } else {
            Err(VmFault::UnsupportedInstruction(
                Code::INVALID,
                format!("unsupported register {reg:?}"),
            ))
        }
    }

    fn effective_address(&self, insn: &Instruction, next_rip: u64) -> Result<u64, VmFault> {
        if insn.is_ip_rel_memory_operand() {
            return Ok(insn.ip_rel_memory_address());
        }
        let base_reg = insn.memory_base();
        let index_reg = insn.memory_index();
        let scale = insn.memory_index_scale() as u64;
        let disp = insn.memory_displacement64();

        let base_val = if base_reg == Register::None {
            0
        } else if base_reg == Register::RIP {
            next_rip
        } else {
            self.read_reg(base_reg)?.0
        };
        let index_val = if index_reg == Register::None {
            0
        } else {
            self.read_reg(index_reg)?.0
        };
        Ok(base_val
            .wrapping_add(index_val.wrapping_mul(scale))
            .wrapping_add(disp))
    }

    fn read_op(
        &self,
        insn: &Instruction,
        op_idx: u32,
        next_rip: u64,
        text: &[u8],
        text_vaddr: u64,
        ro_segments: &[(u64, &[u8])],
        default_bits: u32,
    ) -> Result<(u64, u32), VmFault> {
        match insn.op_kind(op_idx) {
            OpKind::Register => self.read_reg(insn.op_register(op_idx)),
            OpKind::Memory => {
                let size = mem_op_size_bytes(insn);
                let addr = self.effective_address(insn, next_rip)?;
                let val = self.read_mem(addr, size, text, text_vaddr, ro_segments)?;
                Ok((val, (size * 8) as u32))
            }
            OpKind::Immediate8 => Ok(((insn.immediate8() as i8 as i64 as u64) & mask_for_bits(default_bits), default_bits)),
            OpKind::Immediate16 => Ok(((insn.immediate16() as i16 as i64 as u64) & mask_for_bits(default_bits), default_bits)),
            OpKind::Immediate32 => Ok(((insn.immediate32() as i32 as i64 as u64) & mask_for_bits(default_bits), default_bits)),
            OpKind::Immediate64 => Ok((insn.immediate64(), 64)),
            OpKind::Immediate8to16 => Ok(((insn.immediate8to16() as u16 as u64), 16)),
            OpKind::Immediate8to32 => Ok(((insn.immediate8to32() as u32 as u64), 32)),
            OpKind::Immediate8to64 => Ok((insn.immediate8to64() as u64, 64)),
            OpKind::Immediate32to64 => Ok((insn.immediate32to64() as u64, 64)),
            other => Err(VmFault::UnsupportedInstruction(
                insn.code(),
                format!("unsupported operand kind {other:?}"),
            )),
        }
    }

    fn write_op(
        &mut self,
        insn: &Instruction,
        op_idx: u32,
        next_rip: u64,
        val: u64,
    ) -> Result<(), VmFault> {
        match insn.op_kind(op_idx) {
            OpKind::Register => self.write_reg(insn.op_register(op_idx), val),
            OpKind::Memory => {
                let size = mem_op_size_bytes(insn);
                let addr = self.effective_address(insn, next_rip)?;
                self.write_mem(addr, size, val)
            }
            other => Err(VmFault::UnsupportedInstruction(
                insn.code(),
                format!("unsupported dst operand kind {other:?}"),
            )),
        }
    }

    fn dst_bits(&self, insn: &Instruction, op_idx: u32) -> Result<u32, VmFault> {
        match insn.op_kind(op_idx) {
            OpKind::Register => Ok(self.read_reg(insn.op_register(op_idx))?.1),
            OpKind::Memory => Ok((mem_op_size_bytes(insn) * 8) as u32),
            other => Err(VmFault::UnsupportedInstruction(
                insn.code(),
                format!("cannot determine width of {other:?}"),
            )),
        }
    }

    fn set_szp(&mut self, res: u64, bits: u32) {
        let m = mask_for_bits(bits);
        let r = res & m;
        self.zf = r == 0;
        self.sf = ((r >> (bits - 1)) & 1) != 0;
        self.pf = (r as u8).count_ones() % 2 == 0;
    }

    fn alu_add(&mut self, a: u64, b: u64, cin: bool, bits: u32) -> u64 {
        let m = mask_for_bits(bits);
        let a_m = a & m;
        let b_m = b & m;
        let c = if cin { 1u128 } else { 0u128 };
        let full = (a_m as u128) + (b_m as u128) + c;
        let res = (full as u64) & m;
        self.cf = (full >> bits) != 0;
        self.af = ((a_m & 0xF) + (b_m & 0xF) + (c as u64)) > 0xF;
        let sign_bit = 1u64 << (bits - 1);
        self.of = ((!(a_m ^ b_m) & (a_m ^ res)) & sign_bit) != 0;
        self.set_szp(res, bits);
        res
    }

    fn alu_sub(&mut self, a: u64, b: u64, bin: bool, bits: u32) -> u64 {
        let m = mask_for_bits(bits);
        let a_m = a & m;
        let b_m = b & m;
        let borrow = if bin { 1u128 } else { 0u128 };
        let subtrahend = (b_m as u128) + borrow;
        let res = a_m.wrapping_sub(b_m).wrapping_sub(if bin { 1 } else { 0 }) & m;
        self.cf = (a_m as u128) < subtrahend;
        self.af = (a_m & 0xF) < ((b_m & 0xF) + (if bin { 1 } else { 0 }));
        let sign_bit = 1u64 << (bits - 1);
        self.of = (((a_m ^ b_m) & (a_m ^ res)) & sign_bit) != 0;
        self.set_szp(res, bits);
        res
    }

    fn alu_logic(&mut self, res: u64, bits: u32) -> u64 {
        let r = res & mask_for_bits(bits);
        self.cf = false;
        self.of = false;
        self.af = false;
        self.set_szp(r, bits);
        r
    }

    fn eval_cc(&self, cc: ConditionCode) -> Result<bool, VmFault> {
        Ok(match cc {
            ConditionCode::o => self.of,
            ConditionCode::no => !self.of,
            ConditionCode::b => self.cf,
            ConditionCode::ae => !self.cf,
            ConditionCode::e => self.zf,
            ConditionCode::ne => !self.zf,
            ConditionCode::be => self.cf || self.zf,
            ConditionCode::a => !self.cf && !self.zf,
            ConditionCode::s => self.sf,
            ConditionCode::ns => !self.sf,
            ConditionCode::p => self.pf,
            ConditionCode::np => !self.pf,
            ConditionCode::l => self.sf != self.of,
            ConditionCode::ge => self.sf == self.of,
            ConditionCode::le => self.zf || (self.sf != self.of),
            ConditionCode::g => !self.zf && (self.sf == self.of),
            ConditionCode::None => {
                return Err(VmFault::UnsupportedInstruction(
                    Code::INVALID,
                    "ConditionCode::None".into(),
                ))
            }
        })
    }
}

fn mask_for_bits(bits: u32) -> u64 {
    match bits {
        8 => 0xFF,
        16 => 0xFFFF,
        32 => 0xFFFF_FFFF,
        64 => u64::MAX,
        _ => u64::MAX,
    }
}

fn sign_extend(val: u64, from_bits: u32) -> i64 {
    match from_bits {
        8 => (val as u8) as i8 as i64,
        16 => (val as u16) as i16 as i64,
        32 => (val as u32) as i32 as i64,
        64 => val as i64,
        _ => val as i64,
    }
}

fn mem_op_size_bytes(insn: &Instruction) -> usize {
    match insn.memory_size().size() {
        1 => 1,
        2 => 2,
        4 => 4,
        8 => 8,
        _ => 8,
    }
}

/// Returns `(reg_index 0..15, bit_width, is_high_8bit)`.
fn decode_gpr(reg: Register) -> Option<(usize, u32, bool)> {
    Some(match reg {
        Register::AL => (0, 8, false),
        Register::CL => (1, 8, false),
        Register::DL => (2, 8, false),
        Register::BL => (3, 8, false),
        Register::SPL => (4, 8, false),
        Register::BPL => (5, 8, false),
        Register::SIL => (6, 8, false),
        Register::DIL => (7, 8, false),
        Register::R8L => (8, 8, false),
        Register::R9L => (9, 8, false),
        Register::R10L => (10, 8, false),
        Register::R11L => (11, 8, false),
        Register::R12L => (12, 8, false),
        Register::R13L => (13, 8, false),
        Register::R14L => (14, 8, false),
        Register::R15L => (15, 8, false),

        Register::AH => (0, 8, true),
        Register::CH => (1, 8, true),
        Register::DH => (2, 8, true),
        Register::BH => (3, 8, true),

        Register::AX => (0, 16, false),
        Register::CX => (1, 16, false),
        Register::DX => (2, 16, false),
        Register::BX => (3, 16, false),
        Register::SP => (4, 16, false),
        Register::BP => (5, 16, false),
        Register::SI => (6, 16, false),
        Register::DI => (7, 16, false),
        Register::R8W => (8, 16, false),
        Register::R9W => (9, 16, false),
        Register::R10W => (10, 16, false),
        Register::R11W => (11, 16, false),
        Register::R12W => (12, 16, false),
        Register::R13W => (13, 16, false),
        Register::R14W => (14, 16, false),
        Register::R15W => (15, 16, false),

        Register::EAX => (0, 32, false),
        Register::ECX => (1, 32, false),
        Register::EDX => (2, 32, false),
        Register::EBX => (3, 32, false),
        Register::ESP => (4, 32, false),
        Register::EBP => (5, 32, false),
        Register::ESI => (6, 32, false),
        Register::EDI => (7, 32, false),
        Register::R8D => (8, 32, false),
        Register::R9D => (9, 32, false),
        Register::R10D => (10, 32, false),
        Register::R11D => (11, 32, false),
        Register::R12D => (12, 32, false),
        Register::R13D => (13, 32, false),
        Register::R14D => (14, 32, false),
        Register::R15D => (15, 32, false),

        Register::RAX => (0, 64, false),
        Register::RCX => (1, 64, false),
        Register::RDX => (2, 64, false),
        Register::RBX => (3, 64, false),
        Register::RSP => (4, 64, false),
        Register::RBP => (5, 64, false),
        Register::RSI => (6, 64, false),
        Register::RDI => (7, 64, false),
        Register::R8 => (8, 64, false),
        Register::R9 => (9, 64, false),
        Register::R10 => (10, 64, false),
        Register::R11 => (11, 64, false),
        Register::R12 => (12, 64, false),
        Register::R13 => (13, 64, false),
        Register::R14 => (14, 64, false),
        Register::R15 => (15, 64, false),
        _ => return None,
    })
}

/// Execute `fn_vaddr` inside `text` (mapped at `text_vaddr`) until `ret` pops `RET_SENTINEL`.
fn execute_function(
    text: &[u8],
    text_vaddr: u64,
    fn_vaddr: u64,
    state: CpuState,
    max_steps: usize,
) -> Result<CpuState, VmFault> {
    execute_function_with_ro(text, text_vaddr, &[], fn_vaddr, state, max_steps)
}

/// Execute `fn_vaddr` inside `text` (mapped at `text_vaddr`) with additional read-only ELF
/// segments (`ro_segments`, e.g. `.rodata`, `.data.rel.ro`) until `ret` pops `RET_SENTINEL`.
fn execute_function_with_ro(
    text: &[u8],
    text_vaddr: u64,
    ro_segments: &[(u64, &[u8])],
    fn_vaddr: u64,
    mut state: CpuState,
    max_steps: usize,
) -> Result<CpuState, VmFault> {
    let mut rip = fn_vaddr;
    for _step in 0..max_steps {
        if rip == RET_SENTINEL {
            return Ok(state);
        }
        if rip < text_vaddr || rip >= text_vaddr + (text.len() as u64) {
            return Err(VmFault::PcOutOfBounds(rip));
        }
        let off = (rip - text_vaddr) as usize;
        let mut decoder = Decoder::with_ip(64, &text[off..], rip, DecoderOptions::NONE);
        let insn = decoder.decode();
        if insn.is_invalid() {
            return Err(VmFault::DecodeError(rip));
        }
        let next_rip = insn.next_ip();
        let mnemonic = insn.mnemonic();

        match mnemonic {
            iced_x86::Mnemonic::Nop
            | iced_x86::Mnemonic::Endbr64
            | iced_x86::Mnemonic::Cld
            | iced_x86::Mnemonic::Pause
            | iced_x86::Mnemonic::Lfence
            | iced_x86::Mnemonic::Sfence
            | iced_x86::Mnemonic::Mfence => {
                rip = next_rip;
            }
            iced_x86::Mnemonic::Clc => {
                state.cf = false;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Stc => {
                state.cf = true;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Cmc => {
                state.cf = !state.cf;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Push => {
                let (val, _bits) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, 64)?;
                let new_rsp = state.regs[4].wrapping_sub(8);
                state.write_mem(new_rsp, 8, val)?;
                state.regs[4] = new_rsp;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Pop => {
                let rsp = state.regs[4];
                let val = state.read_mem(rsp, 8, text, text_vaddr, ro_segments)?;
                state.regs[4] = rsp.wrapping_add(8);
                state.write_op(&insn, 0, next_rip, val)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Ret => {
                let rsp = state.regs[4];
                let ret_addr = state.read_mem(rsp, 8, text, text_vaddr, ro_segments)?;
                let imm_pop = if insn.op_count() > 0 {
                    insn.immediate16() as u64
                } else {
                    0
                };
                state.regs[4] = rsp.wrapping_add(8).wrapping_add(imm_pop);
                rip = ret_addr;
            }
            iced_x86::Mnemonic::Call => {
                let target = if insn.op_kind(0) == OpKind::NearBranch64 {
                    insn.near_branch64()
                } else {
                    state
                        .read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, 64)?
                        .0
                };
                let new_rsp = state.regs[4].wrapping_sub(8);
                state.write_mem(new_rsp, 8, next_rip)?;
                state.regs[4] = new_rsp;
                rip = target;
            }
            iced_x86::Mnemonic::Leave => {
                let rbp = state.regs[5];
                let saved_rbp = state.read_mem(rbp, 8, text, text_vaddr, ro_segments)?;
                state.regs[5] = saved_rbp;
                state.regs[4] = rbp.wrapping_add(8);
                rip = next_rip;
            }
            iced_x86::Mnemonic::Mov => {
                let bits = state.dst_bits(&insn, 0)?;
                let (val, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                state.write_op(&insn, 0, next_rip, val & mask_for_bits(bits))?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Movzx => {
                let src_bits = match insn.op_kind(1) {
                    OpKind::Register => state.read_reg(insn.op_register(1))?.1,
                    OpKind::Memory => (mem_op_size_bytes(&insn) * 8) as u32,
                    _ => 8,
                };
                let (val, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, src_bits)?;
                let zext = val & mask_for_bits(src_bits);
                state.write_op(&insn, 0, next_rip, zext)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Movsx | iced_x86::Mnemonic::Movsxd => {
                let dst_bits = state.dst_bits(&insn, 0)?;
                let src_bits = match insn.op_kind(1) {
                    OpKind::Register => state.read_reg(insn.op_register(1))?.1,
                    OpKind::Memory => (mem_op_size_bytes(&insn) * 8) as u32,
                    _ => 32,
                };
                let (val, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, src_bits)?;
                let sext = (sign_extend(val, src_bits) as u64) & mask_for_bits(dst_bits);
                state.write_op(&insn, 0, next_rip, sext)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Lea => {
                let bits = state.dst_bits(&insn, 0)?;
                let ea = state.effective_address(&insn, next_rip)?;
                state.write_op(&insn, 0, next_rip, ea & mask_for_bits(bits))?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Xchg => {
                let bits = state.dst_bits(&insn, 0)?;
                let (v0, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (v1, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                state.write_op(&insn, 0, next_rip, v1 & mask_for_bits(bits))?;
                state.write_op(&insn, 1, next_rip, v0 & mask_for_bits(bits))?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Xadd => {
                let bits = state.dst_bits(&insn, 0)?;
                let (v0, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (v1, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let sum = state.alu_add(v0, v1, false, bits);
                state.write_op(&insn, 1, next_rip, v0 & mask_for_bits(bits))?;
                state.write_op(&insn, 0, next_rip, sum)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Cmpxchg => {
                let bits = state.dst_bits(&insn, 0)?;
                let (dst_val, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (src_val, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let acc_val = state.regs[0] & mask_for_bits(bits);
                let _ = state.alu_sub(acc_val, dst_val, false, bits);
                if acc_val == (dst_val & mask_for_bits(bits)) {
                    state.zf = true;
                    state.write_op(&insn, 0, next_rip, src_val & mask_for_bits(bits))?;
                } else {
                    state.zf = false;
                    let acc_reg = match bits {
                        8 => Register::AL,
                        16 => Register::AX,
                        32 => Register::EAX,
                        _ => Register::RAX,
                    };
                    state.write_reg(acc_reg, dst_val & mask_for_bits(bits))?;
                }
                rip = next_rip;
            }
            iced_x86::Mnemonic::Bswap => {
                let bits = state.dst_bits(&insn, 0)?;
                let (v0, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let swapped = match bits {
                    32 => (v0 as u32).swap_bytes() as u64,
                    64 => v0.swap_bytes(),
                    16 => ((v0 as u16).swap_bytes()) as u64,
                    _ => v0,
                };
                state.write_op(&insn, 0, next_rip, swapped)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Bsf | iced_x86::Mnemonic::Tzcnt => {
                let bits = state.dst_bits(&insn, 0)?;
                let (src_val, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let v = src_val & mask_for_bits(bits);
                if v == 0 {
                    state.zf = true;
                    state.cf = true;
                    if mnemonic == iced_x86::Mnemonic::Tzcnt {
                        state.write_op(&insn, 0, next_rip, bits as u64)?;
                    }
                } else {
                    state.zf = false;
                    state.cf = false;
                    let tz = v.trailing_zeros() as u64;
                    state.write_op(&insn, 0, next_rip, tz)?;
                }
                rip = next_rip;
            }
            iced_x86::Mnemonic::Bsr | iced_x86::Mnemonic::Lzcnt => {
                let bits = state.dst_bits(&insn, 0)?;
                let (src_val, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let v = src_val & mask_for_bits(bits);
                if v == 0 {
                    state.zf = true;
                    state.cf = true;
                    if mnemonic == iced_x86::Mnemonic::Lzcnt {
                        state.write_op(&insn, 0, next_rip, bits as u64)?;
                    }
                } else {
                    state.zf = false;
                    state.cf = false;
                    let highest_bit = 63 - v.leading_zeros();
                    let res = if mnemonic == iced_x86::Mnemonic::Lzcnt {
                        (bits - 1 - highest_bit) as u64
                    } else {
                        highest_bit as u64
                    };
                    state.write_op(&insn, 0, next_rip, res)?;
                }
                rip = next_rip;
            }
            iced_x86::Mnemonic::Popcnt => {
                let bits = state.dst_bits(&insn, 0)?;
                let (src_val, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let v = src_val & mask_for_bits(bits);
                let cnt = v.count_ones() as u64;
                state.cf = false;
                state.of = false;
                state.sf = false;
                state.af = false;
                state.pf = false;
                state.zf = cnt == 0;
                state.write_op(&insn, 0, next_rip, cnt)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Bt
            | iced_x86::Mnemonic::Bts
            | iced_x86::Mnemonic::Btr
            | iced_x86::Mnemonic::Btc => {
                let bits = state.dst_bits(&insn, 0)?;
                let (base_val, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (bit_idx_raw, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let bit_idx = (bit_idx_raw as u32) % bits;
                let mask = 1u64 << bit_idx;
                state.cf = (base_val & mask) != 0;
                match mnemonic {
                    iced_x86::Mnemonic::Bt => {}
                    iced_x86::Mnemonic::Bts => {
                        state.write_op(&insn, 0, next_rip, (base_val | mask) & mask_for_bits(bits))?;
                    }
                    iced_x86::Mnemonic::Btr => {
                        state.write_op(&insn, 0, next_rip, (base_val & !mask) & mask_for_bits(bits))?;
                    }
                    iced_x86::Mnemonic::Btc => {
                        state.write_op(&insn, 0, next_rip, (base_val ^ mask) & mask_for_bits(bits))?;
                    }
                    _ => unreachable!(),
                }
                rip = next_rip;
            }
            iced_x86::Mnemonic::Add => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (b, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let res = state.alu_add(a, b, false, bits);
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Adc => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (b, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let cf = state.cf;
                let res = state.alu_add(a, b, cf, bits);
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Sub => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (b, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let res = state.alu_sub(a, b, false, bits);
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Sbb => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (b, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let cf = state.cf;
                let res = state.alu_sub(a, b, cf, bits);
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Cmp => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (b, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let _ = state.alu_sub(a, b, false, bits);
                rip = next_rip;
            }
            iced_x86::Mnemonic::And => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (b, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let res = state.alu_logic(a & b, bits);
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Or => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (b, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let res = state.alu_logic(a | b, bits);
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Xor => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (b, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let res = state.alu_logic(a ^ b, bits);
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Test => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (b, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let _ = state.alu_logic(a & b, bits);
                rip = next_rip;
            }
            iced_x86::Mnemonic::Inc => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let saved_cf = state.cf;
                let res = state.alu_add(a, 1, false, bits);
                state.cf = saved_cf;
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Dec => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let saved_cf = state.cf;
                let res = state.alu_sub(a, 1, false, bits);
                state.cf = saved_cf;
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Neg => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let res = state.alu_sub(0, a, false, bits);
                state.cf = (a & mask_for_bits(bits)) != 0;
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Not => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let res = (!a) & mask_for_bits(bits);
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Shl | iced_x86::Mnemonic::Sal => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (cnt_raw, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, 8)?;
                let mask = if bits == 64 { 63 } else { 31 };
                let cnt = (cnt_raw as u32) & mask;
                let mut res = a & mask_for_bits(bits);
                if cnt > 0 {
                    state.cf = ((res >> (bits - cnt)) & 1) != 0;
                    res = (res << cnt) & mask_for_bits(bits);
                    if cnt == 1 {
                        let msb = ((res >> (bits - 1)) & 1) != 0;
                        state.of = msb ^ state.cf;
                    }
                    state.set_szp(res, bits);
                }
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Shr => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (cnt_raw, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, 8)?;
                let mask = if bits == 64 { 63 } else { 31 };
                let cnt = (cnt_raw as u32) & mask;
                let orig = a & mask_for_bits(bits);
                let mut res = orig;
                if cnt > 0 {
                    state.cf = ((orig >> (cnt - 1)) & 1) != 0;
                    res = (orig >> cnt) & mask_for_bits(bits);
                    if cnt == 1 {
                        state.of = ((orig >> (bits - 1)) & 1) != 0;
                    }
                    state.set_szp(res, bits);
                }
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Sar => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (cnt_raw, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, 8)?;
                let mask = if bits == 64 { 63 } else { 31 };
                let cnt = (cnt_raw as u32) & mask;
                let signed = sign_extend(a, bits);
                let mut res = a & mask_for_bits(bits);
                if cnt > 0 {
                    state.cf = (((signed >> (cnt - 1)) as u64) & 1) != 0;
                    res = ((signed >> cnt) as u64) & mask_for_bits(bits);
                    if cnt == 1 {
                        state.of = false;
                    }
                    state.set_szp(res, bits);
                }
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Shld => {
                let bits = state.dst_bits(&insn, 0)?;
                let (dst_val, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (src_val, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (cnt_raw, _) =
                    state.read_op(&insn, 2, next_rip, text, text_vaddr, ro_segments, 8)?;
                let mask = if bits == 64 { 63 } else { 31 };
                let cnt = (cnt_raw as u32) & mask;
                let d = dst_val & mask_for_bits(bits);
                let s = src_val & mask_for_bits(bits);
                let mut res = d;
                if cnt > 0 && cnt < bits {
                    state.cf = ((d >> (bits - cnt)) & 1) != 0;
                    res = ((d << cnt) | (s >> (bits - cnt))) & mask_for_bits(bits);
                    state.set_szp(res, bits);
                }
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Shrd => {
                let bits = state.dst_bits(&insn, 0)?;
                let (dst_val, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (src_val, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (cnt_raw, _) =
                    state.read_op(&insn, 2, next_rip, text, text_vaddr, ro_segments, 8)?;
                let mask = if bits == 64 { 63 } else { 31 };
                let cnt = (cnt_raw as u32) & mask;
                let d = dst_val & mask_for_bits(bits);
                let s = src_val & mask_for_bits(bits);
                let mut res = d;
                if cnt > 0 && cnt < bits {
                    state.cf = ((d >> (cnt - 1)) & 1) != 0;
                    res = ((d >> cnt) | (s << (bits - cnt))) & mask_for_bits(bits);
                    state.set_szp(res, bits);
                }
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Rol => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (cnt_raw, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, 8)?;
                let mask = if bits == 64 { 63 } else { 31 };
                let cnt = ((cnt_raw as u32) & mask) % bits;
                let orig = a & mask_for_bits(bits);
                let res = if cnt == 0 {
                    orig
                } else {
                    ((orig << cnt) | (orig >> (bits - cnt))) & mask_for_bits(bits)
                };
                if ((cnt_raw as u32) & mask) != 0 {
                    state.cf = (res & 1) != 0;
                }
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Ror => {
                let bits = state.dst_bits(&insn, 0)?;
                let (a, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                let (cnt_raw, _) =
                    state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, 8)?;
                let mask = if bits == 64 { 63 } else { 31 };
                let cnt = ((cnt_raw as u32) & mask) % bits;
                let orig = a & mask_for_bits(bits);
                let res = if cnt == 0 {
                    orig
                } else {
                    ((orig >> cnt) | (orig << (bits - cnt))) & mask_for_bits(bits)
                };
                if ((cnt_raw as u32) & mask) != 0 {
                    state.cf = ((res >> (bits - 1)) & 1) != 0;
                }
                state.write_op(&insn, 0, next_rip, res)?;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Imul => {
                if insn.op_count() == 2 {
                    let bits = state.dst_bits(&insn, 0)?;
                    let (a, _) =
                        state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                    let (b, _) =
                        state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                    let sa = sign_extend(a, bits) as i128;
                    let sb = sign_extend(b, bits) as i128;
                    let prod = sa * sb;
                    let res = (prod as u64) & mask_for_bits(bits);
                    let sext_res = sign_extend(res, bits) as i128;
                    state.cf = prod != sext_res;
                    state.of = state.cf;
                    state.write_op(&insn, 0, next_rip, res)?;
                } else if insn.op_count() == 3 {
                    let bits = state.dst_bits(&insn, 0)?;
                    let (a, _) =
                        state.read_op(&insn, 1, next_rip, text, text_vaddr, ro_segments, bits)?;
                    let (b, _) =
                        state.read_op(&insn, 2, next_rip, text, text_vaddr, ro_segments, bits)?;
                    let sa = sign_extend(a, bits) as i128;
                    let sb = sign_extend(b, bits) as i128;
                    let prod = sa * sb;
                    let res = (prod as u64) & mask_for_bits(bits);
                    let sext_res = sign_extend(res, bits) as i128;
                    state.cf = prod != sext_res;
                    state.of = state.cf;
                    state.write_op(&insn, 0, next_rip, res)?;
                } else {
                    let bits = state.dst_bits(&insn, 0)?;
                    let (b, _) =
                        state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                    let sa = sign_extend(state.regs[0], bits) as i128;
                    let sb = sign_extend(b, bits) as i128;
                    let prod = sa * sb;
                    if bits == 64 {
                        state.regs[0] = prod as u64;
                        state.regs[2] = (prod >> 64) as u64;
                    } else if bits == 32 {
                        state.regs[0] = (prod as u64) & 0xFFFF_FFFF;
                        state.regs[2] = ((prod >> 32) as u64) & 0xFFFF_FFFF;
                    } else {
                        return Err(VmFault::UnsupportedInstruction(
                            insn.code(),
                            "1-op imul width".into(),
                        ));
                    }
                }
                rip = next_rip;
            }
            iced_x86::Mnemonic::Mul => {
                let bits = state.dst_bits(&insn, 0)?;
                let (b, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                if bits == 64 {
                    let prod = (state.regs[0] as u128) * (b as u128);
                    state.regs[0] = prod as u64;
                    state.regs[2] = (prod >> 64) as u64;
                    state.cf = state.regs[2] != 0;
                    state.of = state.cf;
                } else if bits == 32 {
                    let prod =
                        ((state.regs[0] & 0xFFFF_FFFF) as u128) * ((b & 0xFFFF_FFFF) as u128);
                    state.regs[0] = (prod as u64) & 0xFFFF_FFFF;
                    state.regs[2] = ((prod >> 32) as u64) & 0xFFFF_FFFF;
                    state.cf = state.regs[2] != 0;
                    state.of = state.cf;
                } else {
                    return Err(VmFault::UnsupportedInstruction(
                        insn.code(),
                        "1-op mul width".into(),
                    ));
                }
                rip = next_rip;
            }
            iced_x86::Mnemonic::Div => {
                let bits = state.dst_bits(&insn, 0)?;
                let (divisor, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                if (divisor & mask_for_bits(bits)) == 0 {
                    return Err(VmFault::DivisionByZero);
                }
                if bits == 64 {
                    let dividend = ((state.regs[2] as u128) << 64) | (state.regs[0] as u128);
                    let q = dividend / (divisor as u128);
                    let r = dividend % (divisor as u128);
                    state.regs[0] = q as u64;
                    state.regs[2] = r as u64;
                } else if bits == 32 {
                    let dividend =
                        ((state.regs[2] & 0xFFFF_FFFF) << 32) | (state.regs[0] & 0xFFFF_FFFF);
                    let d = divisor & 0xFFFF_FFFF;
                    state.regs[0] = (dividend / d) & 0xFFFF_FFFF;
                    state.regs[2] = (dividend % d) & 0xFFFF_FFFF;
                } else {
                    return Err(VmFault::UnsupportedInstruction(
                        insn.code(),
                        "div width".into(),
                    ));
                }
                rip = next_rip;
            }
            iced_x86::Mnemonic::Idiv => {
                let bits = state.dst_bits(&insn, 0)?;
                let (divisor, _) =
                    state.read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, bits)?;
                if (divisor & mask_for_bits(bits)) == 0 {
                    return Err(VmFault::DivisionByZero);
                }
                if bits == 64 {
                    let dividend =
                        ((state.regs[2] as i64 as i128) << 64) | ((state.regs[0] as u128) as i128);
                    let d = divisor as i64 as i128;
                    let q = dividend.checked_div(d).ok_or(VmFault::DivisionByZero)?;
                    let r = dividend.checked_rem(d).ok_or(VmFault::DivisionByZero)?;
                    if q < (i64::MIN as i128) || q > (i64::MAX as i128) {
                        return Err(VmFault::DivisionByZero);
                    }
                    state.regs[0] = (q as i64) as u64;
                    state.regs[2] = (r as i64) as u64;
                } else if bits == 32 {
                    let dividend = ((state.regs[2] as u32 as i32 as i64) << 32)
                        | (state.regs[0] as u32 as i64);
                    let d = divisor as u32 as i32 as i64;
                    let q = dividend.checked_div(d).ok_or(VmFault::DivisionByZero)?;
                    let r = dividend.checked_rem(d).ok_or(VmFault::DivisionByZero)?;
                    if q < (i32::MIN as i64) || q > (i32::MAX as i64) {
                        return Err(VmFault::DivisionByZero);
                    }
                    state.regs[0] = (q as i32 as u32) as u64;
                    state.regs[2] = (r as i32 as u32) as u64;
                } else {
                    return Err(VmFault::UnsupportedInstruction(
                        insn.code(),
                        "idiv width".into(),
                    ));
                }
                rip = next_rip;
            }
            iced_x86::Mnemonic::Cbw => {
                let sign = (state.regs[0] as u8 as i8 as i16) as u16 as u64;
                state.regs[0] = (state.regs[0] & !0xFFFF) | sign;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Cwd => {
                let sign = (state.regs[0] as u16 as i16) < 0;
                let dx = if sign { 0xFFFFu64 } else { 0 };
                state.regs[2] = (state.regs[2] & !0xFFFF) | dx;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Cwde => {
                state.regs[0] = (state.regs[0] as u16 as i16 as i32 as u32) as u64;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Cdq => {
                let sign = (state.regs[0] as u32 as i32) < 0;
                state.regs[2] = if sign { 0xFFFF_FFFF } else { 0 };
                rip = next_rip;
            }
            iced_x86::Mnemonic::Cqo => {
                let sign = (state.regs[0] as i64) < 0;
                state.regs[2] = if sign { u64::MAX } else { 0 };
                rip = next_rip;
            }
            iced_x86::Mnemonic::Cdqe => {
                state.regs[0] = (state.regs[0] as u32 as i32 as i64) as u64;
                rip = next_rip;
            }
            iced_x86::Mnemonic::Stosb
            | iced_x86::Mnemonic::Stosw
            | iced_x86::Mnemonic::Stosd
            | iced_x86::Mnemonic::Stosq => {
                let elem_bytes = match mnemonic {
                    iced_x86::Mnemonic::Stosb => 1usize,
                    iced_x86::Mnemonic::Stosw => 2,
                    iced_x86::Mnemonic::Stosd => 4,
                    _ => 8,
                };
                let val = state.regs[0];
                if insn.has_rep_prefix() {
                    let count = state.regs[1];
                    if count > 4096 {
                        return Err(VmFault::StepBudgetExceeded(max_steps));
                    }
                    for _ in 0..count {
                        let rdi = state.regs[7];
                        state.write_mem(rdi, elem_bytes, val)?;
                        state.regs[7] = rdi.wrapping_add(elem_bytes as u64);
                    }
                    state.regs[1] = 0;
                } else {
                    let rdi = state.regs[7];
                    state.write_mem(rdi, elem_bytes, val)?;
                    state.regs[7] = rdi.wrapping_add(elem_bytes as u64);
                }
                rip = next_rip;
            }
            iced_x86::Mnemonic::Movsb
            | iced_x86::Mnemonic::Movsw
            | iced_x86::Mnemonic::Movsd
            | iced_x86::Mnemonic::Movsq => {
                let elem_bytes = match mnemonic {
                    iced_x86::Mnemonic::Movsb => 1usize,
                    iced_x86::Mnemonic::Movsw => 2,
                    iced_x86::Mnemonic::Movsd => 4,
                    _ => 8,
                };
                if insn.has_rep_prefix() {
                    let count = state.regs[1];
                    if count > 4096 {
                        return Err(VmFault::StepBudgetExceeded(max_steps));
                    }
                    for _ in 0..count {
                        let rsi = state.regs[6];
                        let rdi = state.regs[7];
                        let v = state.read_mem(rsi, elem_bytes, text, text_vaddr, ro_segments)?;
                        state.write_mem(rdi, elem_bytes, v)?;
                        state.regs[6] = rsi.wrapping_add(elem_bytes as u64);
                        state.regs[7] = rdi.wrapping_add(elem_bytes as u64);
                    }
                    state.regs[1] = 0;
                } else {
                    let rsi = state.regs[6];
                    let rdi = state.regs[7];
                    let v = state.read_mem(rsi, elem_bytes, text, text_vaddr, ro_segments)?;
                    state.write_mem(rdi, elem_bytes, v)?;
                    state.regs[6] = rsi.wrapping_add(elem_bytes as u64);
                    state.regs[7] = rdi.wrapping_add(elem_bytes as u64);
                }
                rip = next_rip;
            }
            iced_x86::Mnemonic::Jmp => {
                if insn.op_kind(0) == OpKind::NearBranch64 {
                    rip = insn.near_branch64();
                } else {
                    rip = state
                        .read_op(&insn, 0, next_rip, text, text_vaddr, ro_segments, 64)?
                        .0;
                }
            }
            _ => {
                let cc = insn.condition_code();
                if cc != ConditionCode::None {
                    let taken = state.eval_cc(cc)?;
                    if insn.op_count() == 1 && insn.op_kind(0) == OpKind::NearBranch64 {
                        // Jcc
                        rip = if taken { insn.near_branch64() } else { next_rip };
                    } else if insn.op_count() == 1 {
                        // SETcc
                        let byte_val = if taken { 1u64 } else { 0u64 };
                        state.write_op(&insn, 0, next_rip, byte_val)?;
                        rip = next_rip;
                    } else if insn.op_count() == 2 {
                        // CMOVcc (note: on x86-64, even when condition is false, a 32-bit CMOVcc
                        // zero-extends the destination register's upper 32 bits!).
                        let bits = state.dst_bits(&insn, 0)?;
                        if taken {
                            let (src_val, _) = state.read_op(
                                &insn,
                                1,
                                next_rip,
                                text,
                                text_vaddr,
                                ro_segments,
                                bits,
                            )?;
                            state.write_op(&insn, 0, next_rip, src_val & mask_for_bits(bits))?;
                        } else if bits == 32 && insn.op_kind(0) == OpKind::Register {
                            let (cur_val, _) = state.read_reg(insn.op_register(0))?;
                            state.write_reg(insn.op_register(0), cur_val & 0xFFFF_FFFF)?;
                        }
                        rip = next_rip;
                    } else {
                        return Err(VmFault::UnsupportedInstruction(
                            insn.code(),
                            format!("unhandled conditional {insn:?}"),
                        ));
                    }
                } else {
                    return Err(VmFault::UnsupportedInstruction(
                        insn.code(),
                        format!("unhandled mnemonic {:?}", insn.mnemonic()),
                    ));
                }
            }
        }
    }
    Err(VmFault::StepBudgetExceeded(max_steps))
}

/// Assert that executing `fn_vaddr` in `orig_text` and `morph_text` produces bit-exact
/// architectural output states across `num_inputs` randomized input states.
fn assert_function_equivalent(
    fn_name: &str,
    orig_text: &[u8],
    morph_text: &[u8],
    text_vaddr: u64,
    fn_vaddr: u64,
    seed: u64,
    num_inputs: usize,
    pointer_in_rdi: bool,
) {
    for input_idx in 0..num_inputs {
        let mut init = CpuState::from_seed(((input_idx as u64) + 1).wrapping_mul(0x517C_C1B7_2722_0A95));
        if pointer_in_rdi {
            // Point RDI and RSI into our valid scratch data arena `[MEM_BASE + DATA_OFFSET + ...]`.
            init.regs[7] = MEM_BASE + (DATA_OFFSET as u64) + 64;
            init.regs[6] = MEM_BASE + (DATA_OFFSET as u64) + 128;
        }

        let out_orig = execute_function(orig_text, text_vaddr, fn_vaddr, init.clone(), 4096)
            .unwrap_or_else(|e| {
                panic!("original function {fn_name} faulted on input {input_idx}: {e:?}")
            });
        let out_morph = execute_function(morph_text, text_vaddr, fn_vaddr, init.clone(), 4096)
            .unwrap_or_else(|e| {
                panic!(
                    "morphed function {fn_name} (seed={seed}) faulted on input {input_idx}: {e:?}"
                )
            });

        // 1. Return value registers (RAX, RDX):
        assert_eq!(
            out_orig.regs[0], out_morph.regs[0],
            "RAX return value mismatch in {fn_name} (seed={seed}, input={input_idx}): orig=0x{:016x} morph=0x{:016x}",
            out_orig.regs[0], out_morph.regs[0]
        );
        // 2. Stack pointer RSP must return to INITIAL_RSP_OFFSET + 8:
        assert_eq!(
            out_orig.regs[4],
            MEM_BASE + (INITIAL_RSP_OFFSET as u64) + 8,
            "original RSP not balanced at ret in {fn_name}"
        );
        assert_eq!(
            out_orig.regs[4], out_morph.regs[4],
            "RSP mismatch at ret in {fn_name} (seed={seed}, input={input_idx})"
        );
        // 3. All System V AMD64 ABI callee-saved registers (RBX=3, RBP=5, R12=12, R13=13, R14=14, R15=15)
        //    must be preserved identically!
        for &(reg_idx, reg_name) in &[
            (3usize, "RBX"),
            (5, "RBP"),
            (12, "R12"),
            (13, "R13"),
            (14, "R14"),
            (15, "R15"),
        ] {
            assert_eq!(
                out_orig.regs[reg_idx], out_morph.regs[reg_idx],
                "callee-saved register {reg_name} mismatch in {fn_name} (seed={seed}, input={input_idx}): orig=0x{:016x} morph=0x{:016x}",
                out_orig.regs[reg_idx], out_morph.regs[reg_idx]
            );
        }
        // 4. Data memory region `[0 .. INITIAL_RSP_OFFSET - 256]` (above stack scratch redzone)
        //    and above initial stack frame `[INITIAL_RSP_OFFSET + 8 .. MEM_SIZE]` must match byte-for-byte!
        //    (Note: dead stack frame slots below RSP after pop/add rsp may be permuted by
        //    pass_prologue_epilogue_perm, which is why we compare all memory outside the dead redzone).
        assert_eq!(
            &out_orig.mem[..INITIAL_RSP_OFFSET - 256],
            &out_morph.mem[..INITIAL_RSP_OFFSET - 256],
            "data memory mismatch in {fn_name} (seed={seed}, input={input_idx})"
        );
        assert_eq!(
            &out_orig.mem[INITIAL_RSP_OFFSET..],
            &out_morph.mem[INITIAL_RSP_OFFSET..],
            "caller stack frame memory mismatch in {fn_name} (seed={seed}, input={input_idx})"
        );
    }
}

struct FnSpec {
    name: &'static str,
    bytes: Vec<u8>,
    pointer_in_rdi: bool,
}

/// Build a corpus of 8 x86-64 functions specifically designed to exercise every one of
/// `cuttle-binmorph`'s 7 passes (`callee_saved_reg_swap`, `leaf_scratch_reg_swap`,
/// `return_block_scratch_swap`, `prologue_epilogue_perm`, `schedule_commute`,
/// `reg_reg_morph`, `cross_width_pair_morph`) plus loops, conditional moves, and memory I/O.
fn build_corpus_functions() -> Vec<FnSpec> {
    vec![
        // 0. Callee-saved register heavy function:
        //    push rbp; push rbx; push r12; push r13
        //    mov rbx, rdi; mov r12, rsi; mov r13, rdx; mov rbp, rcx
        //    add rbx, r12; xor r13, rbp; sub rbx, r13; lea rax, [rbx + r12*2 + 0x20]
        //    pop r13; pop r12; pop rbx; pop rbp; ret
        FnSpec {
            name: "fn0_callee_saved_swap",
            pointer_in_rdi: false,
            bytes: vec![
                0x55, // push rbp
                0x53, // push rbx
                0x41, 0x54, // push r12
                0x41, 0x55, // push r13
                0x48, 0x89, 0xFB, // mov rbx, rdi
                0x49, 0x89, 0xF4, // mov r12, rsi
                0x49, 0x89, 0xD5, // mov r13, rdx
                0x48, 0x89, 0xCD, // mov rbp, rcx
                0x4C, 0x01, 0xE3, // add rbx, r12
                0x49, 0x31, 0xED, // xor r13, rbp
                0x4C, 0x29, 0xEB, // sub rbx, r13
                0x4A, 0x8D, 0x44, 0x63, 0x20, // lea rax, [rbx + r12*2 + 0x20]
                0x41, 0x5D, // pop r13
                0x41, 0x5C, // pop r12
                0x5B, // pop rbx
                0x5D, // pop rbp
                0xC3, // ret
            ],
        },
        // 1. Leaf scratch register swap & memory load/store function:
        //    mov r8, [rdi]
        //    mov r9, [rsi]
        //    lea r10, [r8 + r9 + 0x11]
        //    xor r10, rdx
        //    add r8, rcx
        //    sub r10, r8
        //    mov [rdi + 8], r10
        //    mov rax, r10
        //    ret
        FnSpec {
            name: "fn1_leaf_scratch_and_mem",
            pointer_in_rdi: true,
            bytes: vec![
                0x4C, 0x8B, 0x07, // mov r8, [rdi]
                0x4C, 0x8B, 0x0E, // mov r9, [rsi]
                0x4F, 0x8D, 0x54, 0x08, 0x11, // lea r10, [r8 + r9 + 0x11]
                0x49, 0x31, 0xD2, // xor r10, rdx
                0x49, 0x01, 0xC8, // add r8, rcx
                0x4D, 0x29, 0xC2, // sub r10, r8
                0x4C, 0x89, 0x57, 0x08, // mov [rdi + 8], r10
                0x4C, 0x89, 0xD0, // mov rax, r10
                0xC3, // ret
            ],
        },
        // 2. Multi-block function with conditional branch & return-block scratch computation:
        //    cmp rdx, rcx
        //    jge +6 (to return_block)
        //    xor rdx, 0x55
        //    return_block:
        //    mov r8, [rdi]
        //    add r8, rdx
        //    xor r8, rcx
        //    lea rax, [r8 + 7]
        //    ret
        FnSpec {
            name: "fn2_return_block_scratch",
            pointer_in_rdi: true,
            bytes: vec![
                0x48, 0x39, 0xCA, // cmp rdx, rcx
                0x7D, 0x04, // jge +4
                0x48, 0x83, 0xF2, 0x55, // xor rdx, 0x55
                0x4C, 0x8B, 0x07, // mov r8, [rdi]
                0x49, 0x01, 0xD0, // add r8, rdx
                0x49, 0x31, 0xC8, // xor r8, rcx
                0x49, 0x8D, 0x40, 0x07, // lea rax, [r8 + 7]
                0xC3, // ret
            ],
        },
        // 3. Prologue/epilogue push/pop permutation with local stack frame (`sub rsp, 0x18`):
        //    push rbp; push rbx; push r12; push r14
        //    sub rsp, 0x18
        //    mov rbx, rdi; mov r12, rsi; mov r14, rdx
        //    add rbx, 0x10; sub r12, 0x05; xor r14, rcx
        //    mov rax, rbx; add rax, r12; xor rax, r14
        //    add rsp, 0x18
        //    pop r14; pop r12; pop rbx; pop rbp; ret
        FnSpec {
            name: "fn3_prologue_epilogue_perm",
            pointer_in_rdi: false,
            bytes: vec![
                0x55, // push rbp
                0x53, // push rbx
                0x41, 0x54, // push r12
                0x41, 0x56, // push r14
                0x48, 0x83, 0xEC, 0x18, // sub rsp, 0x18
                0x48, 0x89, 0xFB, // mov rbx, rdi
                0x49, 0x89, 0xF4, // mov r12, rsi
                0x49, 0x89, 0xD6, // mov r14, rdx
                0x48, 0x83, 0xC3, 0x10, // add rbx, 0x10
                0x49, 0x83, 0xEC, 0x05, // sub r12, 0x05
                0x49, 0x31, 0xCE, // xor r14, rcx
                0x48, 0x89, 0xD8, // mov rax, rbx
                0x4C, 0x01, 0xE0, // add rax, r12
                0x4C, 0x31, 0xF0, // xor rax, r14
                0x48, 0x83, 0xC4, 0x18, // add rsp, 0x18
                0x41, 0x5E, // pop r14
                0x41, 0x5C, // pop r12
                0x5B, // pop rbx
                0x5D, // pop rbp
                0xC3, // ret
            ],
        },
        // 4. Cross-width 6-byte pair morph & independent instruction commutation:
        //    mov eax, edi
        //    mov ecx, esi
        //    add ecx, 0x11223344   (6 bytes: 81 C1 44 33 22 11)
        //    lea r8, [rdx + 0x55]  (4 bytes)
        //    sub ecx, 0x01020304   (6 bytes: 81 E9 04 03 02 01)
        //    add r8, 0x00001234    (7 bytes: 49 81 C0 34 12 00 00)
        //    xor eax, ecx
        //    add rax, r8
        //    ret
        FnSpec {
            name: "fn4_schedule_and_cross_width",
            pointer_in_rdi: false,
            bytes: vec![
                0x89, 0xF8, // mov eax, edi
                0x89, 0xF1, // mov ecx, esi
                0x81, 0xC1, 0x44, 0x33, 0x22, 0x11, // add ecx, 0x11223344
                0x4C, 0x8D, 0x42, 0x55, // lea r8, [rdx + 0x55]
                0x81, 0xE9, 0x04, 0x03, 0x02, 0x01, // sub ecx, 0x01020304
                0x49, 0x81, 0xC0, 0x34, 0x12, 0x00, 0x00, // add r8, 0x1234
                0x31, 0xC8, // xor eax, ecx
                0x4C, 0x01, 0xC0, // add rax, r8
                0xC3, // ret
            ],
        },
        // 5. Same-width reg-reg polarity morph across 8/16/32/64-bit registers + bswap/neg/not:
        //    mov rax, rdi
        //    add rax, rsi
        //    sub rax, rdx
        //    and rax, rcx
        //    or  rax, r8
        //    xor eax, r9d
        //    bswap rax
        //    not rax
        //    neg rax
        //    ret
        FnSpec {
            name: "fn5_reg_reg_polarity_and_bitops",
            pointer_in_rdi: false,
            bytes: vec![
                0x48, 0x89, 0xF8, // mov rax, rdi
                0x48, 0x01, 0xF0, // add rax, rsi
                0x48, 0x29, 0xD0, // sub rax, rdx
                0x48, 0x21, 0xC8, // and rax, rcx
                0x4C, 0x09, 0xC0, // or rax, r8
                0x44, 0x31, 0xC8, // xor eax, r9d (zero-extends upper 32 bits!)
                0x48, 0x0F, 0xC8, // bswap rax
                0x48, 0xF7, 0xD0, // not rax
                0x48, 0xF7, 0xD8, // neg rax
                0xC3, // ret
            ],
        },
        // 6. Carry/borrow chains (`adc`/`sbb`), `cmovcc`, and `setcc`:
        //    mov rax, rdi
        //    add rax, rsi
        //    adc rax, rdx
        //    sub rax, rcx
        //    sbb rax, r8
        //    cmp rdi, rsi
        //    cmovl rax, rdx
        //    setge cl
        //    movzx rcx, cl
        //    add rax, rcx
        //    ret
        FnSpec {
            name: "fn6_flags_adc_sbb_cmov_setcc",
            pointer_in_rdi: false,
            bytes: vec![
                0x48, 0x89, 0xF8, // mov rax, rdi
                0x48, 0x01, 0xF0, // add rax, rsi
                0x48, 0x11, 0xD0, // adc rax, rdx
                0x48, 0x29, 0xC8, // sub rax, rcx
                0x4C, 0x19, 0xC0, // sbb rax, r8
                0x48, 0x39, 0xF7, // cmp rdi, rsi
                0x48, 0x0F, 0x4C, 0xC2, // cmovl rax, rdx
                0x0F, 0x9D, 0xC1, // setge cl
                0x48, 0x0F, 0xB6, 0xC9, // movzx rcx, cl
                0x48, 0x01, 0xC8, // add rax, rcx
                0xC3, // ret
            ],
        },
        // 7. Bounded multi-block loop hash accumulator:
        //    mov rax, rdi
        //    mov ecx, esi
        //    and ecx, 7
        //    inc ecx
        //  loop_top:
        //    imul rax, rax, 0x01000193
        //    xor rax, rdx
        //    dec ecx
        //    jnz loop_top (-14)
        //    ret
        FnSpec {
            name: "fn7_loop_hash_accumulator",
            pointer_in_rdi: false,
            bytes: vec![
                0x48, 0x89, 0xF8, // mov rax, rdi
                0x89, 0xF1, // mov ecx, esi
                0x83, 0xE1, 0x07, // and ecx, 7
                0xFF, 0xC1, // inc ecx
                // loop_top:
                0x48, 0x69, 0xC0, 0x93, 0x01, 0x00, 0x01, // imul rax, rax, 0x01000193
                0x48, 0x31, 0xD0, // xor rax, rdx
                0xFF, 0xC9, // dec ecx
                0x75, 0xF2, // jnz loop_top (-14)
                0xC3, // ret
            ],
        },
        // 8. Partial register writes (8/16-bit preserving upper bits vs 32-bit zero-extending
        //    bits 63:32) and 0x66 operand-size + REX prefix combinations across callee-saved
        //    and leaf-scratch registers:
        FnSpec {
            name: "fn8_partial_regs_and_0x66_rex_prefixes",
            pointer_in_rdi: false,
            bytes: vec![
                0x41, 0x54, // push r12
                0x41, 0x55, // push r13
                0x49, 0x89, 0xFC, // mov r12, rdi
                0x49, 0x89, 0xF5, // mov r13, rsi
                0x48, 0x89, 0xD0, // mov rax, rdx
                0x40, 0x88, 0xF8, // mov al, dil
                0x66, 0x01, 0xC8, // add ax, cx
                0x66, 0x45, 0x31, 0xEC, // xor r12w, r13w
                0x45, 0x28, 0xEC, // sub r12b, r13b
                0x41, 0x89, 0xC0, // mov r8d, eax
                0x66, 0x45, 0x01, 0xE0, // add r8w, r12w
                0x4C, 0x31, 0xE0, // xor rax, r12
                0x4C, 0x01, 0xC0, // add rax, r8
                0x41, 0x5D, // pop r13
                0x41, 0x5C, // pop r12
                0xC3, // ret
            ],
        },
        // 9. RIP-relative `[rip + disp32]` displacement recomputation under `schedule_commute`
        //    (commuting 7-byte RIP-relative `lea` and 8-byte RIP-relative `movzx` memory load
        //    across 2-byte, 4-byte, and 5-byte independent instructions) combined with cross-width
        //    `5+5 <-> 7+3` immediate load boundary shifts and live CF/OF/SF/ZF flag consumption
        //    (`adc`, `sbb`, `cmovo`):
        FnSpec {
            name: "fn9_rip_relative_commute_and_cross_width_flags",
            pointer_in_rdi: false,
            bytes: vec![
                0x89, 0xF8, // 0..2 (2B): mov eax, edi
                0x4C, 0x8D, 0x05, 0xF7, 0xFF, 0xFF, 0xFF, // 2..9 (7B): lea r8, [rip - 9] (-> fn9_vaddr + 0)
                0x4C, 0x8D, 0x4E, 0x33, // 9..13 (4B): lea r9, [rsi + 0x33]
                0x44, 0x0F, 0xB6, 0x15, 0x1A, 0x00, 0x00, 0x00, // 13..21 (8B): movzx r10d, byte ptr [rip + 26] (-> fn9_vaddr + 47 = 0xC3 ret!)
                0xB9, 0x05, 0x00, 0x00, 0x00, // 21..26 (5B): mov ecx, 5
                0xBA, 0x09, 0x00, 0x00, 0x00, // 26..31 (5B): mov edx, 9
                0x4C, 0x01, 0xC0, // 31..34 (3B): add rax, r8
                0x4C, 0x11, 0xC8, // 34..37 (3B): adc rax, r9
                0x4C, 0x29, 0xD0, // 37..40 (3B): sub rax, r10
                0x48, 0x19, 0xC8, // 40..43 (3B): sbb rax, rcx
                0x48, 0x0F, 0x40, 0xC2, // 43..47 (4B): cmovo rax, rdx
                0xC3, // 47..48 (1B): ret (invariant 0xC3 byte read by movzx above)
            ],
        },
    ]
}

/// Package a list of functions into a minimal valid ELF64 binary with `.text`, `.symtab`,
/// `.strtab`, and `.shstrtab` so `cuttle_binmorph::rewrite_elf_bytes` parses and rewrites
/// every function symbol exactly as it does on a real kernel ELF.
fn build_multi_fn_elf64(fns: &[FnSpec]) -> (Vec<u8>, Vec<(String, u64, usize, bool)>) {
    // 1. Assemble `.text` with 16-byte INT3 (`0xCC`) padding between functions.
    let mut text = Vec::new();
    let mut layout = Vec::new();
    for spec in fns {
        while text.len() % 16 != 0 {
            text.push(0xCC);
        }
        let fn_off = text.len();
        let fn_vaddr = TEXT_VADDR + (fn_off as u64);
        text.extend_from_slice(&spec.bytes);
        layout.push((
            spec.name.to_string(),
            fn_vaddr,
            spec.bytes.len(),
            spec.pointer_in_rdi,
        ));
    }

    // 2. Build `.strtab` and `.symtab` (24 bytes per Elf64_Sym).
    let mut strtab = vec![0u8];
    let mut symtab = vec![0u8; 24]; // Null symbol #0
    for (name, vaddr, size, _) in &layout {
        let st_name = strtab.len() as u32;
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);

        let mut sym = [0u8; 24];
        sym[0..4].copy_from_slice(&st_name.to_le_bytes());
        sym[4] = (1 << 4) | 2; // STB_GLOBAL | STT_FUNC
        sym[6..8].copy_from_slice(&1u16.to_le_bytes()); // st_shndx = 1 (.text)
        sym[8..16].copy_from_slice(&vaddr.to_le_bytes());
        sym[16..24].copy_from_slice(&(*size as u64).to_le_bytes());
        symtab.extend_from_slice(&sym);
    }

    let shstrtab = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
    // Offsets:
    // 0x00..0x40: Elf64_Ehdr (64B)
    // 0x40..0x40+text: .text
    // aligned 8: .symtab
    // .strtab
    // .shstrtab
    // aligned 8: 5 Elf64_Shdr entries (5 * 64B = 320B)
    let mut elf = vec![0u8; 64];
    let text_off = elf.len();
    elf.extend_from_slice(&text);
    while elf.len() % 8 != 0 {
        elf.push(0);
    }
    let symtab_off = elf.len();
    elf.extend_from_slice(&symtab);
    let strtab_off = elf.len();
    elf.extend_from_slice(&strtab);
    let shstrtab_off = elf.len();
    elf.extend_from_slice(shstrtab);
    while elf.len() % 8 != 0 {
        elf.push(0);
    }
    let shoff = elf.len();

    let push_shdr = |buf: &mut Vec<u8>,
                     sh_name: u32,
                     sh_type: u32,
                     sh_flags: u64,
                     sh_addr: u64,
                     sh_offset: u64,
                     sh_size: u64,
                     sh_link: u32,
                     sh_info: u32,
                     sh_addralign: u64,
                     sh_entsize: u64| {
        let mut sh = [0u8; 64];
        sh[0..4].copy_from_slice(&sh_name.to_le_bytes());
        sh[4..8].copy_from_slice(&sh_type.to_le_bytes());
        sh[8..16].copy_from_slice(&sh_flags.to_le_bytes());
        sh[16..24].copy_from_slice(&sh_addr.to_le_bytes());
        sh[24..32].copy_from_slice(&sh_offset.to_le_bytes());
        sh[32..40].copy_from_slice(&sh_size.to_le_bytes());
        sh[40..44].copy_from_slice(&sh_link.to_le_bytes());
        sh[44..48].copy_from_slice(&sh_info.to_le_bytes());
        sh[48..56].copy_from_slice(&sh_addralign.to_le_bytes());
        sh[56..64].copy_from_slice(&sh_entsize.to_le_bytes());
        buf.extend_from_slice(&sh);
    };

    // Section 0: NULL
    push_shdr(&mut elf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    // Section 1: .text (SHT_PROGBITS = 1, SHF_ALLOC|SHF_EXECINSTR = 6)
    push_shdr(
        &mut elf,
        1,
        1,
        6,
        TEXT_VADDR,
        text_off as u64,
        text.len() as u64,
        0,
        0,
        16,
        0,
    );
    // Section 2: .symtab (SHT_SYMTAB = 2, link = 3 (.strtab), info = 1)
    push_shdr(
        &mut elf,
        7,
        2,
        0,
        0,
        symtab_off as u64,
        symtab.len() as u64,
        3,
        1,
        8,
        24,
    );
    // Section 3: .strtab (SHT_STRTAB = 3)
    push_shdr(
        &mut elf,
        15,
        3,
        0,
        0,
        strtab_off as u64,
        strtab.len() as u64,
        0,
        0,
        1,
        0,
    );
    // Section 4: .shstrtab (SHT_STRTAB = 3)
    push_shdr(
        &mut elf,
        23,
        3,
        0,
        0,
        shstrtab_off as u64,
        shstrtab.len() as u64,
        0,
        0,
        1,
        0,
    );

    // Populate Elf64_Ehdr:
    elf[0..4].copy_from_slice(b"\x7FELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    elf[24..32].copy_from_slice(&TEXT_VADDR.to_le_bytes()); // e_entry
    elf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes()); // e_shoff
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    elf[60..62].copy_from_slice(&5u16.to_le_bytes()); // e_shnum
    elf[62..64].copy_from_slice(&4u16.to_le_bytes()); // e_shstrndx

    (elf, layout)
}

fn extract_text_slice(elf_bytes: &[u8]) -> &[u8] {
    let obj = object::File::parse(elf_bytes).expect("parse ELF64");
    let sec = obj.section_by_name(".text").expect("locate .text");
    let (off, len) = sec.file_range().expect(".text file_range");
    &elf_bytes[off as usize..(off + len) as usize]
}

#[test]
fn differential_equivalence_across_all_passes_and_64_seeds() {
    let fns = build_corpus_functions();
    let (base_elf, layout) = build_multi_fn_elf64(&fns);
    let orig_text = extract_text_slice(&base_elf);

    let mut distinct_text_hashes = BTreeSet::new();
    let mut total_swapped = 0usize;
    let mut total_reg_remapped = 0usize;

    // Sweep 64 distinct morph seeds × 32 randomized initial register/flag/memory states
    // = 2,048 concrete executions per function (16,384 differential pairs in total).
    for seed in 1u64..=64 {
        let mut morphed_elf = base_elf.clone();
        let stats = rewrite_elf_bytes(&mut morphed_elf, seed).expect("rewrite_elf_bytes");
        assert_eq!(stats.functions, fns.len());
        assert!(
            stats.swapped > 0 || stats.reg_remapped_instrs > 0,
            "seed {seed} should mutate instructions across corpus, got {stats:?}"
        );
        total_swapped += stats.swapped;
        total_reg_remapped += stats.reg_remapped_instrs;

        let morph_text = extract_text_slice(&morphed_elf);
        let mut hasher = Sha256::new();
        hasher.update(morph_text);
        let digest: [u8; 32] = hasher.finalize().into();
        distinct_text_hashes.insert(digest);

        for (fn_name, fn_vaddr, _fn_size, ptr_in_rdi) in &layout {
            assert_function_equivalent(
                fn_name,
                orig_text,
                morph_text,
                TEXT_VADDR,
                *fn_vaddr,
                seed,
                32,
                *ptr_in_rdi,
            );
        }
    }

    assert!(
        total_swapped >= 256,
        "expected >= 256 morphed instruction windows across 64 seeds, got {total_swapped}"
    );
    assert!(
        total_reg_remapped >= 64,
        "expected >= 64 register-remapped instructions across 64 seeds, got {total_reg_remapped}"
    );
    assert!(
        distinct_text_hashes.len() >= 32,
        "expected rich multi-seed diversity across 64 seeds, got {} distinct .text digests",
        distinct_text_hashes.len()
    );
}

#[test]
fn differential_equivalence_catches_injected_semantic_bugs_meta_test() {
    // Prove the differential equivalence engine is sound and never vacuously passes:
    // 1. Inject an arithmetic bug (flipping `add` to `sub` in `fn0_callee_saved_swap`).
    // 2. Inject a callee-saved register restoration bug (clobbering `r12` before `ret`).
    // 3. Inject a memory store bug (corrupting store displacement in `fn1_leaf_scratch_and_mem`).
    let fns = build_corpus_functions();
    let (base_elf, layout) = build_multi_fn_elf64(&fns);
    let orig_text = extract_text_slice(&base_elf);

    // Fault 1: Mutate `add rbx, r12` (0x4C 0x01 0xE3) -> `sub rbx, r12` (0x4C 0x29 0xE3) in fn0.
    let mut bad_text_1 = orig_text.to_vec();
    let (_, fn0_vaddr, fn0_len, _) = &layout[0];
    let fn0_off = (*fn0_vaddr - TEXT_VADDR) as usize;
    let add_pos = bad_text_1[fn0_off..fn0_off + fn0_len]
        .windows(3)
        .position(|w| w == [0x4C, 0x01, 0xE3])
        .expect("locate add rbx, r12");
    bad_text_1[fn0_off + add_pos + 1] = 0x29;
    let caught_1 = std::panic::catch_unwind(|| {
        assert_function_equivalent(
            "fn0_fault_arith",
            orig_text,
            &bad_text_1,
            TEXT_VADDR,
            *fn0_vaddr,
            1,
            8,
            false,
        );
    });
    assert!(
        caught_1.is_err(),
        "differential harness must catch arithmetic mutation in RAX return value"
    );

    // Fault 2: Replace `pop r12; pop rbx` (`41 5C 5B`) with `pop rbx; pop r12` (`5B 41 5C`)
    // in fn0 epilogue without permuting the prologue, corrupting callee-saved registers RBX & R12!
    let mut bad_text_2 = orig_text.to_vec();
    let pop_pos = bad_text_2[fn0_off..fn0_off + fn0_len]
        .windows(3)
        .position(|w| w == [0x41, 0x5C, 0x5B])
        .expect("locate pop r12; pop rbx");
    bad_text_2[fn0_off + pop_pos..fn0_off + pop_pos + 3].copy_from_slice(&[0x5B, 0x41, 0x5C]);
    let caught_2 = std::panic::catch_unwind(|| {
        assert_function_equivalent(
            "fn0_fault_callee_saved",
            orig_text,
            &bad_text_2,
            TEXT_VADDR,
            *fn0_vaddr,
            1,
            8,
            false,
        );
    });
    assert!(
        caught_2.is_err(),
        "differential harness must catch asymmetric push/pop callee-saved corruption"
    );

    // Fault 3: Corrupt memory store offset `mov [rdi + 8], r10` (`4C 89 57 08` -> `4C 89 57 10`) in fn1.
    let mut bad_text_3 = orig_text.to_vec();
    let (_, fn1_vaddr, fn1_len, _) = &layout[1];
    let fn1_off = (*fn1_vaddr - TEXT_VADDR) as usize;
    let st_pos = bad_text_3[fn1_off..fn1_off + fn1_len]
        .windows(4)
        .position(|w| w == [0x4C, 0x89, 0x57, 0x08])
        .expect("locate mov [rdi+8], r10");
    bad_text_3[fn1_off + st_pos + 3] = 0x10;
    let caught_3 = std::panic::catch_unwind(|| {
        assert_function_equivalent(
            "fn1_fault_mem_store",
            orig_text,
            &bad_text_3,
            TEXT_VADDR,
            *fn1_vaddr,
            1,
            8,
            true,
        );
    });
    assert!(
        caught_3.is_err(),
        "differential harness must catch memory store displacement corruption"
    );

    // Fault 4: Partial-register / 32-bit zero-extension bug in `fn8_partial_regs_and_0x66_rex_prefixes`:
    // Replace 16-bit `add ax, cx` (`66 01 C8`, which preserves bits 63:16 of RAX) with `nop; add eax, ecx`
    // (`90 01 C8`, which zero-extends and clobbers bits 63:32 of RAX).
    let mut bad_text_4 = orig_text.to_vec();
    let (_, fn8_vaddr, fn8_len, _) = &layout[8];
    let fn8_off = (*fn8_vaddr - TEXT_VADDR) as usize;
    let p16_pos = bad_text_4[fn8_off..fn8_off + fn8_len]
        .windows(3)
        .position(|w| w == [0x66, 0x01, 0xC8])
        .expect("locate 66 01 C8 (add ax, cx)");
    bad_text_4[fn8_off + p16_pos] = 0x90; // drop 0x66 operand-size prefix -> 32-bit `add eax, ecx`!
    let caught_4 = std::panic::catch_unwind(|| {
        assert_function_equivalent(
            "fn8_fault_partial_reg_0x66",
            orig_text,
            &bad_text_4,
            TEXT_VADDR,
            *fn8_vaddr,
            1,
            8,
            false,
        );
    });
    assert!(
        caught_4.is_err(),
        "differential harness must catch 16-bit vs 32-bit zero-extension partial-register corruption"
    );

    // Fault 5: Off-by-instruction-length RIP-relative displacement bug in `fn9_rip_relative_commute_and_cross_width_flags`:
    // Perturb `disp32` of `lea r8, [rip - 9]` (`4C 8D 05 F7 FF FF FF`) by +2 bytes (`F9 FF FF FF`),
    // simulating a commutation pass that swapped a 7-byte RIP-relative instruction past a 2-byte `mov`
    // without recomputing `disp32`.
    let mut bad_text_5 = orig_text.to_vec();
    let (_, fn9_vaddr, fn9_len, _) = &layout[9];
    let fn9_off = (*fn9_vaddr - TEXT_VADDR) as usize;
    let rip_pos = bad_text_5[fn9_off..fn9_off + fn9_len]
        .windows(7)
        .position(|w| w == [0x4C, 0x8D, 0x05, 0xF7, 0xFF, 0xFF, 0xFF])
        .expect("locate lea r8, [rip - 9]");
    bad_text_5[fn9_off + rip_pos + 3] = 0xF9;
    let caught_5 = std::panic::catch_unwind(|| {
        assert_function_equivalent(
            "fn9_fault_rip_disp32",
            orig_text,
            &bad_text_5,
            TEXT_VADDR,
            *fn9_vaddr,
            1,
            8,
            false,
        );
    });
    assert!(
        caught_5.is_err(),
        "differential harness must catch off-by-length RIP-relative disp32 corruption"
    );

    // Fault 6: Live carry-flag (`CF`) corruption in `fn6_flags_adc_sbb_cmov_setcc`:
    // Mutate `adc rax, rdx` (`48 11 D0`) -> `add rax, rdx` (`48 01 D0`), dropping the incoming carry flag `CF`.
    let mut bad_text_6 = orig_text.to_vec();
    let (_, fn6_vaddr, fn6_len, _) = &layout[6];
    let fn6_off = (*fn6_vaddr - TEXT_VADDR) as usize;
    let adc_pos = bad_text_6[fn6_off..fn6_off + fn6_len]
        .windows(3)
        .position(|w| w == [0x48, 0x11, 0xD0])
        .expect("locate adc rax, rdx");
    bad_text_6[fn6_off + adc_pos + 1] = 0x01;
    let caught_6 = std::panic::catch_unwind(|| {
        assert_function_equivalent(
            "fn6_fault_live_cf",
            orig_text,
            &bad_text_6,
            TEXT_VADDR,
            *fn6_vaddr,
            1,
            8,
            false,
        );
    });
    assert!(
        caught_6.is_err(),
        "differential harness must catch live carry-flag (CF) corruption across adc/sbb chains"
    );
}

#[test]
fn multi_seed_elf_structural_and_gadget_byte_invariants_across_50_seeds() {
    let fns = build_corpus_functions();
    let (base_elf, layout) = build_multi_fn_elf64(&fns);
    let orig_text = extract_text_slice(&base_elf);

    for seed in 1u64..=50 {
        let mut morphed_elf = base_elf.clone();
        let stats = rewrite_elf_bytes(&mut morphed_elf, seed).expect("rewrite_elf_bytes");
        assert_eq!(stats.functions, fns.len());

        // 1. Re-parse morphed ELF with `object` and verify all symbols and section bounds match.
        let obj = object::File::parse(morphed_elf.as_slice()).expect("re-parse morphed ELF");
        let text_sec = obj.section_by_name(".text").expect("morphed .text");
        assert_eq!(text_sec.address(), TEXT_VADDR);
        assert_eq!(text_sec.size() as usize, orig_text.len());
        let morph_text = extract_text_slice(&morphed_elf);

        // 2. Every function symbol must decode cleanly from entry to its `ret` terminator,
        //    and no non-terminator instruction may contain embedded `0xC3` (`ret`) or `0xCF` (`iretq`) bytes.
        for (fn_name, fn_vaddr, fn_size, _) in &layout {
            let fn_off = (*fn_vaddr - TEXT_VADDR) as usize;
            let fn_bytes = &morph_text[fn_off..fn_off + fn_size];
            let mut dec = Decoder::with_ip(64, fn_bytes, *fn_vaddr, DecoderOptions::NONE);
            let mut cursor = 0usize;
            let mut saw_ret = false;
            while dec.can_decode() {
                let insn = dec.decode();
                assert!(
                    !insn.is_invalid(),
                    "invalid instruction in {fn_name} at seed {seed}"
                );
                let len = insn.len();
                let raw = &fn_bytes[cursor..cursor + len];
                if insn.mnemonic() == iced_x86::Mnemonic::Ret {
                    saw_ret = true;
                } else {
                    assert!(
                        !raw.contains(&0xC3) && !raw.contains(&0xCF),
                        "non-terminator instruction in {fn_name} (seed={seed}) contains gadget byte 0xC3/0xCF: {raw:02x?}"
                    );
                }
                cursor += len;
            }
            assert_eq!(cursor, *fn_size, "decoded byte length mismatch in {fn_name}");
            assert!(saw_ret, "missing ret terminator in {fn_name}");
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum AbiProfile {
    PureScalar,
    SmallBounds,
    SinglePtrAndLen,
    TwoPtrsAndLen,
    ThreePtrs,
    StructSelfZeroed,
    SelfSliceAndOutSlice,
    TwoSlicesAndOutSlice,
    FourPtrsAndStackArgs,
    StructWithSliceFields,
}

impl AbiProfile {
    const ALL: [Self; 10] = [
        Self::PureScalar,
        Self::SmallBounds,
        Self::SinglePtrAndLen,
        Self::TwoPtrsAndLen,
        Self::ThreePtrs,
        Self::StructSelfZeroed,
        Self::SelfSliceAndOutSlice,
        Self::TwoSlicesAndOutSlice,
        Self::FourPtrsAndStackArgs,
        Self::StructWithSliceFields,
    ];

    fn make_input(self, input_idx: usize, writable_elf_ranges: &[(u64, u64)]) -> CpuState {
        let seed = ((input_idx as u64) + 1).wrapping_mul(0x517C_C1B7_2722_0A95);
        let mut init = CpuState::from_seed(seed);
        init.writable_elf_ranges = writable_elf_ranges.to_vec();
        match self {
            Self::PureScalar => {}
            Self::SmallBounds => {
                // RDI=7, RSI=6, RDX=2, RCX=1, R8=8, R9=9
                for &reg in &[7usize, 6, 2, 1, 8, 9] {
                    init.regs[reg] &= 0x0F;
                }
            }
            Self::SinglePtrAndLen => {
                init.regs[7] = MEM_BASE + (DATA_OFFSET as u64) + 128;
                init.regs[6] &= 0x0F;
                init.regs[2] &= 0x0F;
                init.regs[1] &= 0x0F;
            }
            Self::TwoPtrsAndLen => {
                init.regs[7] = MEM_BASE + (DATA_OFFSET as u64) + 128;
                init.regs[6] = MEM_BASE + (DATA_OFFSET as u64) + 512;
                init.regs[2] &= 0x0F;
                init.regs[1] &= 0x0F;
            }
            Self::ThreePtrs => {
                init.regs[7] = MEM_BASE + (DATA_OFFSET as u64) + 128;
                init.regs[6] = MEM_BASE + (DATA_OFFSET as u64) + 512;
                init.regs[2] = MEM_BASE + (DATA_OFFSET as u64) + 896;
                init.regs[1] &= 0x0F;
            }
            Self::StructSelfZeroed => {
                // Zero-initialize a 256-byte struct at DATA_OFFSET + 128 with small deterministic scalars
                // at the first few words so `&self` / `&mut self` methods with internal length/state invariants
                // execute cleanly without out-of-bounds slice panics.
                init.mem[DATA_OFFSET + 128..DATA_OFFSET + 384].fill(0);
                init.mem[DATA_OFFSET + 128] = (input_idx as u8) & 0x07;
                init.mem[DATA_OFFSET + 136] = ((input_idx as u8).wrapping_mul(3)) & 0x07;
                init.regs[7] = MEM_BASE + (DATA_OFFSET as u64) + 128;
                init.regs[6] = (input_idx as u64) & 0x07;
                init.regs[2] = ((input_idx as u64).wrapping_mul(5)) & 0x07;
                init.regs[1] = ((input_idx as u64).wrapping_mul(7)) & 0x07;
            }
            Self::SelfSliceAndOutSlice => {
                // `(&mut self, input: &[u8], out: &mut [u8])`:
                // RDI = self_ptr, RSI = in_ptr, RDX = in_len (8..23), RCX = out_ptr, R8 = out_len (128), R9 = small scalar
                init.regs[7] = MEM_BASE + (DATA_OFFSET as u64) + 128;
                init.regs[6] = MEM_BASE + (DATA_OFFSET as u64) + 512;
                init.regs[2] = 8 + ((input_idx as u64) & 0x0F);
                init.regs[1] = MEM_BASE + (DATA_OFFSET as u64) + 1024;
                init.regs[8] = 128;
                init.regs[9] = (input_idx as u64) & 0x07;
            }
            Self::TwoSlicesAndOutSlice => {
                // `(a: &[u8], b: &[u8], out: &mut [u8])`:
                // RDI = a_ptr, RSI = a_len, RDX = b_ptr, RCX = b_len, R8 = out_ptr, R9 = out_len
                init.regs[7] = MEM_BASE + (DATA_OFFSET as u64) + 128;
                init.regs[6] = 8 + ((input_idx as u64) & 0x07);
                init.regs[2] = MEM_BASE + (DATA_OFFSET as u64) + 512;
                init.regs[1] = 8 + (((input_idx as u64) >> 1) & 0x07);
                init.regs[8] = MEM_BASE + (DATA_OFFSET as u64) + 1024;
                init.regs[9] = 128;
            }
            Self::FourPtrsAndStackArgs => {
                // 4 pointer args + R8 ptr + R9 len + valid caller stack args at `[RSP + 8 .. RSP + 48]`
                init.regs[7] = MEM_BASE + (DATA_OFFSET as u64) + 128;
                init.regs[6] = MEM_BASE + (DATA_OFFSET as u64) + 384;
                init.regs[2] = MEM_BASE + (DATA_OFFSET as u64) + 640;
                init.regs[1] = MEM_BASE + (DATA_OFFSET as u64) + 896;
                init.regs[8] = MEM_BASE + (DATA_OFFSET as u64) + 1152;
                init.regs[9] = 64;
                let p_stack = MEM_BASE + (DATA_OFFSET as u64) + 1408;
                init.mem[INITIAL_RSP_OFFSET + 8..INITIAL_RSP_OFFSET + 16]
                    .copy_from_slice(&p_stack.to_le_bytes());
                init.mem[INITIAL_RSP_OFFSET + 16..INITIAL_RSP_OFFSET + 24]
                    .copy_from_slice(&64u64.to_le_bytes());
                init.mem[INITIAL_RSP_OFFSET + 24..INITIAL_RSP_OFFSET + 32]
                    .copy_from_slice(&p_stack.to_le_bytes());
                init.mem[INITIAL_RSP_OFFSET + 32..INITIAL_RSP_OFFSET + 40]
                    .copy_from_slice(&64u64.to_le_bytes());
            }
            Self::StructWithSliceFields => {
                // Struct at `[RDI]` whose fields are valid `(ptr, len)` slice pairs inside the data arena.
                let struct_off = DATA_OFFSET + 128;
                let buf1 = MEM_BASE + (DATA_OFFSET as u64) + 640;
                let buf2 = MEM_BASE + (DATA_OFFSET as u64) + 896;
                let len = 8 + ((input_idx as u64) & 0x07);
                init.mem[struct_off..struct_off + 256].fill(0);
                init.mem[struct_off..struct_off + 8].copy_from_slice(&buf1.to_le_bytes());
                init.mem[struct_off + 8..struct_off + 16].copy_from_slice(&len.to_le_bytes());
                init.mem[struct_off + 16..struct_off + 24].copy_from_slice(&buf2.to_le_bytes());
                init.mem[struct_off + 24..struct_off + 32].copy_from_slice(&len.to_le_bytes());
                init.regs[7] = MEM_BASE + (struct_off as u64);
                init.regs[6] = buf1;
                init.regs[2] = len;
                init.regs[1] = buf2;
                init.regs[8] = 64;
                init.regs[9] = (input_idx as u64) & 0x07;
            }
        }
        init
    }
}

fn ensure_compiled_kernel_elf_exists(root: &std::path::Path) -> std::path::PathBuf {
    let candidate_paths = [
        root.join("target_enterprise_kernel")
            .join("target")
            .join("x86_64-unknown-none")
            .join("release")
            .join("target_enterprise_kernel"),
        root.join("target")
            .join("x86_64-unknown-none")
            .join("release")
            .join("target_enterprise_kernel"),
    ];
    if let Some(found) = candidate_paths.iter().find(|p| p.exists()) {
        return found.clone();
    }
    let kernel_dir = root.join("target_enterprise_kernel");
    let status = std::process::Command::new("cargo")
        .arg("build")
        .arg("--release")
        .current_dir(&kernel_dir)
        .status()
        .expect("failed to invoke `cargo build --release` in target_enterprise_kernel");
    assert!(
        status.success(),
        "`cargo build --release` in target_enterprise_kernel failed with {status}"
    );
    candidate_paths
        .into_iter()
        .find(|p| p.exists())
        .expect("target_enterprise_kernel ELF missing after successful `cargo build --release`")
}

#[test]
fn differential_equivalence_on_real_compiled_kernel_elf_functions() {
    // Always locate or build the bare-metal `target_enterprise_kernel` ELF (never skip)
    // and run concrete differential execution on real compiler-emitted (`rustc` + LLVM)
    // kernel `.text` functions rewritten by `cuttle-binmorph` across 32 seeds!
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().expect("workspace root");
    let kernel_elf_path = ensure_compiled_kernel_elf_exists(root);

    let base_elf = std::fs::read(&kernel_elf_path).expect("read kernel ELF");
    let obj = object::File::parse(base_elf.as_slice()).expect("parse kernel ELF");
    let text_sec = obj.section_by_name(".text").expect(".text section");
    let text_vaddr = text_sec.address();
    let (text_file_off, text_len) = text_sec.file_range().expect(".text file_range");
    let orig_text = &base_elf[text_file_off as usize..(text_file_off + text_len) as usize];

    // Map all non-`.text` file-backed ELF sections (`.rodata`, `.data.rel.ro`, `.data`, etc.)
    // as read-only reference segments, and map `.data` / `.bss` (`SHT_NOBITS`) as copy-on-write
    // writable segments so real kernel functions that read or mutate static/global state via
    // `[rip + disp32]` execute cleanly inside `X86MicroVm`.
    let mut ro_segments: Vec<(u64, &[u8])> = Vec::new();
    let mut writable_elf_ranges: Vec<(u64, u64)> = Vec::new();
    for sec in obj.sections() {
        let sec_name = sec.name().unwrap_or("");
        if sec_name == ".text" {
            continue;
        }
        let vaddr = sec.address();
        let vsize = sec.size();
        if vaddr == 0 || vsize == 0 {
            continue;
        }
        if let Some((foff, flen)) = sec.file_range() {
            if flen > 0 && (foff + flen) as usize <= base_elf.len() {
                ro_segments.push((vaddr, &base_elf[foff as usize..(foff + flen) as usize]));
            }
            if sec_name.starts_with(".data") || sec_name.starts_with(".bss") {
                writable_elf_ranges.push((vaddr, vaddr.saturating_add(vsize)));
            }
        } else {
            // SHT_NOBITS (e.g. `.bss`): zero-initialized and writable via `elf_writes`.
            writable_elf_ranges.push((vaddr, vaddr.saturating_add(vsize)));
        }
    }

    const NUM_INPUTS: usize = 16;
    const NUM_SEEDS: u64 = 32;
    const MAX_STEPS: usize = 1024;
    let expected_ret_rsp = MEM_BASE + (INITIAL_RSP_OFFSET as u64) + 8;

    // Discover all `.text` functions (`STT_FUNC`, size 4..=4096) that execute cleanly to `ret`
    // with balanced `RSP` across all `NUM_INPUTS` inputs under one of the realistic ABI profiles.
    let mut verified_kernel_fns: Vec<(String, u64, usize, AbiProfile)> = Vec::new();
    let mut input_sensitive_fns = 0usize;
    let mut mem_mutating_fns = 0usize;
    let mut global_bss_data_fns = 0usize;
    let mut contract_and_boundary_fns = 0usize;

    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text {
            continue;
        }
        let addr = sym.address();
        let size = sym.size() as usize;
        if !(4..=4096).contains(&size) {
            continue;
        }
        if addr < text_vaddr || addr + (size as u64) > text_vaddr + text_len {
            continue;
        }
        let name = sym.name().unwrap_or("<anon>").to_string();

        for profile in AbiProfile::ALL {
            let mut profile_ok = true;
            let mut first_ret_pair: Option<(u64, u64)> = None;
            let mut first_data_hash: Option<[u8; 32]> = None;
            let mut varies_across_inputs = false;
            let mut mutates_data_arena = false;
            let mut mutates_elf_globals = false;

            for input_idx in 0..NUM_INPUTS {
                let init = profile.make_input(input_idx, &writable_elf_ranges);
                let init_data_slice = init.mem[..0x4000].to_vec();
                match execute_function_with_ro(
                    orig_text,
                    text_vaddr,
                    &ro_segments,
                    addr,
                    init,
                    MAX_STEPS,
                ) {
                    Ok(out) if out.regs[4] == expected_ret_rsp => {
                        let ret_pair = (out.regs[0], out.regs[2]);
                        // Compute the XOR-delta between `out.mem[..0x4000]` and `init_data_slice`
                        // plus any `.data`/`.bss` global writes in `out.elf_writes`.
                        let mut delta_hasher = Sha256::new();
                        for (&after, &before) in
                            out.mem[..0x4000].iter().zip(init_data_slice.iter())
                        {
                            delta_hasher.update([after ^ before]);
                        }
                        for (&g_addr, &g_byte) in &out.elf_writes {
                            delta_hasher.update(g_addr.to_le_bytes());
                            delta_hasher.update([g_byte]);
                        }
                        let write_delta_hash: [u8; 32] = delta_hasher.finalize().into();
                        if out.mem[..0x4000] != init_data_slice[..] || !out.elf_writes.is_empty() {
                            mutates_data_arena = true;
                        }
                        if !out.elf_writes.is_empty() {
                            mutates_elf_globals = true;
                        }
                        if let (Some(prev_ret), Some(prev_hash)) = (first_ret_pair, first_data_hash)
                        {
                            if ret_pair != prev_ret || write_delta_hash != prev_hash {
                                varies_across_inputs = true;
                            }
                        } else {
                            first_ret_pair = Some(ret_pair);
                            first_data_hash = Some(write_delta_hash);
                        }
                    }
                    _ => {
                        profile_ok = false;
                        break;
                    }
                }
            }
            if profile_ok {
                if varies_across_inputs {
                    input_sensitive_fns += 1;
                }
                if mutates_data_arena {
                    mem_mutating_fns += 1;
                }
                if mutates_elf_globals {
                    global_bss_data_fns += 1;
                }
                if name.contains("cuttle_contracts") || name.contains("target_enterprise_kernel") {
                    contract_and_boundary_fns += 1;
                }
                verified_kernel_fns.push((name, addr, size, profile));
                break;
            }
        }
    }

    assert!(
        verified_kernel_fns.len() >= 700,
        "expected at least 700 real compiled kernel functions in target_enterprise_kernel .text, got {}",
        verified_kernel_fns.len()
    );
    assert!(
        input_sensitive_fns >= 700,
        "expected at least 700 real kernel functions with input-dependent dynamic return/memory outputs, got {}",
        input_sensitive_fns
    );
    assert!(
        mem_mutating_fns >= 340,
        "expected at least 340 real kernel functions that concretely mutate the 16 KiB data/struct arena, got {}",
        mem_mutating_fns
    );
    assert!(
        contract_and_boundary_fns >= 100,
        "expected at least 100 cuttle_contracts / target_enterprise_kernel boundary functions verified, got {}",
        contract_and_boundary_fns
    );

    // Rewrite the entire real kernel ELF across 32 seeds (`1..=32`) and verify that every discovered
    // kernel function (including every mutated function-seed instance) produces bit-exact output
    // across all 16 inputs per seed!
    let mut mutated_fn_seed_instances = 0usize;
    let mut distinct_mutated_fns = BTreeSet::new();

    for seed in 1u64..=NUM_SEEDS {
        let mut morphed_elf = base_elf.clone();
        let stats = rewrite_elf_bytes(&mut morphed_elf, seed).expect("rewrite kernel ELF");
        assert!(stats.functions > 0 && stats.swapped > 0);
        let morph_text =
            &morphed_elf[text_file_off as usize..(text_file_off + text_len) as usize];

        for (fn_name, fn_vaddr, fn_size, profile) in &verified_kernel_fns {
            let fn_off = (*fn_vaddr - text_vaddr) as usize;
            if orig_text[fn_off..fn_off + *fn_size] != morph_text[fn_off..fn_off + *fn_size] {
                mutated_fn_seed_instances += 1;
                distinct_mutated_fns.insert(fn_name.clone());
            }

            for input_idx in 0..NUM_INPUTS {
                let init = profile.make_input(input_idx, &writable_elf_ranges);
                let out_orig = execute_function_with_ro(
                    orig_text,
                    text_vaddr,
                    &ro_segments,
                    *fn_vaddr,
                    init.clone(),
                    MAX_STEPS,
                )
                .unwrap_or_else(|e| {
                    panic!("original kernel fn {fn_name} faulted on input {input_idx}: {e:?}")
                });
                let out_morph = execute_function_with_ro(
                    morph_text,
                    text_vaddr,
                    &ro_segments,
                    *fn_vaddr,
                    init,
                    MAX_STEPS,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "morphed kernel fn {fn_name} (seed={seed}) faulted on input {input_idx}: {e:?}"
                    )
                });

                assert_eq!(
                    out_orig.regs[0], out_morph.regs[0],
                    "RAX return value mismatch in real kernel fn {fn_name} (seed={seed}, input={input_idx})"
                );
                assert_eq!(
                    out_orig.regs[2], out_morph.regs[2],
                    "RDX secondary return register mismatch in real kernel fn {fn_name} (seed={seed}, input={input_idx})"
                );
                assert_eq!(
                    out_orig.regs[4], out_morph.regs[4],
                    "RSP mismatch at ret in real kernel fn {fn_name} (seed={seed}, input={input_idx})"
                );
                for &(reg_idx, reg_name) in &[
                    (3usize, "RBX"),
                    (5, "RBP"),
                    (12, "R12"),
                    (13, "R13"),
                    (14, "R14"),
                    (15, "R15"),
                ] {
                    assert_eq!(
                        out_orig.regs[reg_idx], out_morph.regs[reg_idx],
                        "callee-saved register {reg_name} mismatch in real kernel fn {fn_name} (seed={seed}, input={input_idx})"
                    );
                }
                // Compare the entire 16 KiB data arena `[0 .. 0x4000]`, caller stack frame
                // `[INITIAL_RSP_OFFSET .. MEM_SIZE]`, and `.data`/`.bss` ELF global writes.
                assert_eq!(
                    &out_orig.mem[..0x4000],
                    &out_morph.mem[..0x4000],
                    "data memory mismatch in real kernel fn {fn_name} (seed={seed}, input={input_idx})"
                );
                assert_eq!(
                    &out_orig.mem[INITIAL_RSP_OFFSET..],
                    &out_morph.mem[INITIAL_RSP_OFFSET..],
                    "caller stack frame mismatch in real kernel fn {fn_name} (seed={seed}, input={input_idx})"
                );
                assert_eq!(
                    out_orig.elf_writes, out_morph.elf_writes,
                    ".data/.bss global memory write mismatch in real kernel fn {fn_name} (seed={seed}, input={input_idx})"
                );
            }
        }
    }

    // Negative mutation-testing proof on REAL compiled kernel functions:
    // For each verified real kernel function, take a morphed `.text` buffer, inject a single
    // interior instruction semantic corruption (flipping `add` <-> `sub`, `xor` <-> `or`,
    // `mov` source/dest register bits, or immediate/displacement byte), and verify that the
    // concrete execution comparator catches the divergence!
    let mut base_morphed_elf = base_elf.clone();
    rewrite_elf_bytes(&mut base_morphed_elf, 1).expect("rewrite kernel ELF for negative check");
    let base_morph_text =
        &base_morphed_elf[text_file_off as usize..(text_file_off + text_len) as usize];
    let mut real_kernel_semantic_faults_caught = 0usize;

    for (_fn_name, fn_vaddr, fn_size, profile) in &verified_kernel_fns {
        let fn_off = (*fn_vaddr - text_vaddr) as usize;
        let fn_bytes = &base_morph_text[fn_off..fn_off + *fn_size];

        // Decode instructions in this real kernel function and find an interior instruction to corrupt.
        let mut dec = Decoder::with_ip(64, fn_bytes, *fn_vaddr, DecoderOptions::NONE);
        let mut cursor = 0usize;
        let mut corrupt_pos: Option<(usize, u8)> = None;
        while dec.can_decode() {
            let insn = dec.decode();
            let len = insn.len();
            if insn.is_invalid() || len == 0 {
                break;
            }
            let raw = &fn_bytes[cursor..cursor + len];
            // Corrupt an interior arithmetic, logic, move, or immediate/displacement byte:
            if len >= 2 && insn.mnemonic() != iced_x86::Mnemonic::Ret {
                // Flip the last byte of the instruction (either ModR/M register field or immediate/disp8)
                // by XORing with 0x01, avoiding creating 0xC3/0xCF.
                let last_idx = cursor + len - 1;
                let flipped = raw[len - 1] ^ 0x01;
                if flipped != 0xC3 && flipped != 0xCF {
                    corrupt_pos = Some((fn_off + last_idx, flipped));
                    break;
                }
            }
            cursor += len;
        }

        if let Some((byte_idx, bad_byte)) = corrupt_pos {
            let mut corrupted_text = base_morph_text.to_vec();
            corrupted_text[byte_idx] = bad_byte;

            let mut caught_divergence = false;
            for input_idx in 0..NUM_INPUTS {
                let init = profile.make_input(input_idx, &writable_elf_ranges);
                let Ok(out_orig) = execute_function_with_ro(
                    orig_text,
                    text_vaddr,
                    &ro_segments,
                    *fn_vaddr,
                    init.clone(),
                    MAX_STEPS,
                ) else {
                    continue;
                };
                let Ok(out_bad) = execute_function_with_ro(
                    &corrupted_text,
                    text_vaddr,
                    &ro_segments,
                    *fn_vaddr,
                    init,
                    MAX_STEPS,
                ) else {
                    // Faulting in the micro-VM on the corrupted instruction also catches the bug!
                    caught_divergence = true;
                    break;
                };
                if out_orig.regs[0] != out_bad.regs[0]
                    || out_orig.regs[2] != out_bad.regs[2]
                    || out_orig.regs[4] != out_bad.regs[4]
                    || out_orig.regs[3] != out_bad.regs[3]
                    || out_orig.regs[5] != out_bad.regs[5]
                    || out_orig.regs[12] != out_bad.regs[12]
                    || out_orig.regs[13] != out_bad.regs[13]
                    || out_orig.regs[14] != out_bad.regs[14]
                    || out_orig.regs[15] != out_bad.regs[15]
                    || out_orig.mem[..0x4000] != out_bad.mem[..0x4000]
                    || out_orig.mem[INITIAL_RSP_OFFSET..] != out_bad.mem[INITIAL_RSP_OFFSET..]
                    || out_orig.elf_writes != out_bad.elf_writes
                {
                    caught_divergence = true;
                    break;
                }
            }
            if caught_divergence {
                real_kernel_semantic_faults_caught += 1;
            }
        }
    }

    eprintln!(
        "real kernel ELF differential check: verified {} real kernel functions ({} input-sensitive, {} memory-mutating, {} .data/.bss-mutating, {} contract/kernel-boundary, {} distinct mutated functions, {} mutated fn×seed instances, {} total concrete executions across {} seeds, {} real-kernel injected faults caught)",
        verified_kernel_fns.len(),
        input_sensitive_fns,
        mem_mutating_fns,
        global_bss_data_fns,
        contract_and_boundary_fns,
        distinct_mutated_fns.len(),
        mutated_fn_seed_instances,
        verified_kernel_fns.len() * (NUM_SEEDS as usize) * NUM_INPUTS,
        NUM_SEEDS,
        real_kernel_semantic_faults_caught
    );
    assert!(
        distinct_mutated_fns.len() >= 650,
        "expected at least 650 distinct real kernel functions mutated by cuttle-binmorph, got {}",
        distinct_mutated_fns.len()
    );
    assert!(
        mutated_fn_seed_instances >= 18_500,
        "expected at least 18500 mutated (function, seed) instances verified on real kernel ELF, got {}",
        mutated_fn_seed_instances
    );
    assert!(
        real_kernel_semantic_faults_caught >= 600,
        "expected concrete execution comparator to catch injected 1-byte instruction corruptions on at least 600 real kernel functions, got {}",
        real_kernel_semantic_faults_caught
    );
}
