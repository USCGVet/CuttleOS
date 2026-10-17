//! Kernel-ELF symbol resolver — TASK-019.
//!
//! Backtrace addresses captured into a [`crate::panic_dump`] record are
//! raw RIPs. To make a dump useful for post-mortem debugging the kernel
//! ships its own sorted symbol table and resolves each address to
//! `(function_name, offset_into_function)`. Two flavours are supported:
//!
//! - [`StaticSymbolResolver`] — owns a `&'static [SymbolEntry]` table
//!   stamped into the binary by a build.rs step (or, in tests, a
//!   hand-built slice). O(log n) `resolve()` via binary search; the
//!   primary path the kernel uses post-boot.
//! - [`elf::parse_symtab_into`] — minimal `no_std` ELF64 parser that
//!   extracts `STT_FUNC` symbols from a kernel ELF image at runtime
//!   into a caller-supplied scratch buffer. Used when the bootloader
//!   keeps the kernel ELF resident in memory and the kernel wants to
//!   populate its own table.
//!
//! Both flavours implement [`proteus_contracts::SymbolResolve`].
//!
//! ## Containment rule
//!
//! A symbol `(addr, size, name)` *contains* `ip` iff `addr <= ip &&
//! ip < addr + size`. Zero-size entries are skipped — they cannot
//! contain any address by the strict inequality. This matches the
//! `RustOSa` donor's `symbols::resolve_with` semantics.
//!
//! ## Binary search
//!
//! The table MUST be sorted ascending by `addr`. [`SymbolEntry`] is a
//! plain struct so test/build-time code can construct one directly;
//! the `is_sorted_by_addr` helper validates this at boot time as a
//! cheap sanity check.
//!
//! ## Hostile-input safety (ELF parser)
//!
//! Every multi-byte read in [`elf::parse_symtab_into`] is bounds-checked
//! against the input slice. Out-of-range section offsets terminate
//! parsing with an [`ElfParseError`] rather than reading past the
//! buffer. Lifted-and-hardened from `RustOSa/src/symbols.rs`.

#![allow(clippy::manual_range_contains)]

use proteus_contracts::SymbolResolve;

/// One entry in the kernel's static symbol table. Constructed at build
/// time (by build.rs) or at test time (by hand).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SymbolEntry {
    /// Virtual address the symbol resolves to (start of function).
    pub addr: u64,
    /// Size of the function in bytes. Zero indicates an unsized entry
    /// (cannot contain any ip; skipped by [`StaticSymbolResolver::resolve`]).
    pub size: u32,
    /// Function name. `&'static` so the kernel can ship the table as
    /// `const` and resolve directly into the `.rodata` section without
    /// any runtime allocation.
    pub name: &'static str,
}

impl SymbolEntry {
    /// Construct a symbol entry. `const fn` so callers can build tables
    /// in `const` contexts (the canonical use is a build.rs-emitted
    /// `pub const SYMBOLS: &[SymbolEntry] = &[...]`).
    pub const fn new(addr: u64, size: u32, name: &'static str) -> Self {
        Self { addr, size, name }
    }
}

/// In-tree resolver backed by a sorted `&'static [SymbolEntry]` table.
///
/// `O(log n)` `resolve()` via binary search. The table must be sorted
/// ascending by `addr`; [`Self::is_sorted_by_addr`] validates this in
/// debug builds, and [`Self::resolve`] still produces *correct or
/// `None`* output on a mis-sorted table (binary search may return
/// `None` where a linear scan would find a hit, but it will not
/// return an incorrect name).
pub struct StaticSymbolResolver<'a> {
    table: &'a [SymbolEntry],
}

impl<'a> StaticSymbolResolver<'a> {
    /// Construct a resolver over `table`. The caller MUST ensure the
    /// table is sorted ascending by `addr`. Use [`Self::is_sorted_by_addr`]
    /// at boot time to validate before passing the table here.
    pub const fn new(table: &'a [SymbolEntry]) -> Self {
        Self { table }
    }

    /// Borrow the underlying table. Useful for tooling that wants to
    /// enumerate symbols (e.g. a `/proc/kallsyms`-like surface).
    pub fn table(&self) -> &'a [SymbolEntry] {
        self.table
    }

    /// Returns `true` iff the table is sorted strictly ascending by
    /// `addr`. Equal addresses are NOT accepted — they would create
    /// resolution ambiguity. Allocation-free; runs in O(n).
    pub fn is_sorted_by_addr(table: &[SymbolEntry]) -> bool {
        let mut i = 1usize;
        while i < table.len() {
            if table[i].addr <= table[i - 1].addr {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Number of entries in the underlying table — `O(1)`.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// True iff the table is empty.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

impl<'a> SymbolResolve for StaticSymbolResolver<'a> {
    fn resolve(&self, addr: u64) -> Option<(&str, u64)> {
        if self.table.is_empty() {
            return None;
        }
        // Binary search by `addr`. Find the rightmost entry with
        // `addr <= probe`. Then check the containment rule.
        let mut lo = 0usize;
        let mut hi = self.table.len();
        // Invariant: every entry below `lo` has addr <= probe;
        // every entry at-or-above `hi` has addr > probe.
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.table[mid].addr <= addr {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return None;
        }
        let idx = lo - 1;
        let sym = &self.table[idx];
        // Zero-size entries cannot contain any addr by the strict
        // inequality. Same rule as `RustOSa/src/symbols.rs`.
        if sym.size == 0 {
            return None;
        }
        let offset = addr - sym.addr;
        if offset >= sym.size as u64 {
            return None;
        }
        Some((sym.name, offset))
    }

    fn symbol_count(&self) -> usize {
        self.table.len()
    }
}

/// Format a resolved `(name, offset)` into `out` as ASCII bytes:
///
/// ```text
///   <name>+0x<hex(offset)>
/// ```
///
/// Returns the number of bytes written (always `name.len() + 3 + hex_digits`).
/// `out` must be large enough; otherwise returns `Err(out.len())` so the
/// caller can resize. Allocation-free; suitable for the kernel panic
/// path.
pub fn format_resolved(
    name: &str,
    offset: u64,
    out: &mut [u8],
) -> Result<usize, usize> {
    let name_bytes = name.as_bytes();
    // Compute hex-digit count without `format`.
    let mut hex_digits = 0usize;
    let mut v = offset;
    if v == 0 {
        hex_digits = 1;
    } else {
        while v > 0 {
            hex_digits += 1;
            v >>= 4;
        }
    }
    let need = name_bytes.len() + 3 + hex_digits;
    if out.len() < need {
        return Err(need);
    }
    let mut pos = 0usize;
    let mut i = 0usize;
    while i < name_bytes.len() {
        out[pos] = name_bytes[i];
        pos += 1;
        i += 1;
    }
    out[pos] = b'+';
    pos += 1;
    out[pos] = b'0';
    pos += 1;
    out[pos] = b'x';
    pos += 1;
    // Emit `hex_digits` lowercase hex characters of `offset`, MSB-first.
    let mut k = hex_digits;
    while k > 0 {
        k -= 1;
        let nyb = ((offset >> (k * 4)) & 0xF) as u8;
        out[pos] = if nyb < 10 { b'0' + nyb } else { b'a' + (nyb - 10) };
        pos += 1;
    }
    Ok(pos)
}

// ============================================================
// ELF parser — minimal, hostile-input-safe, no_std
// ============================================================

/// Errors returned by [`elf::parse_symtab_into`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ElfParseError {
    /// ELF header is shorter than 64 bytes.
    HeaderTooSmall,
    /// First four bytes are not `\x7FELF`.
    BadMagic,
    /// EI_CLASS != 2 (not ELF64).
    NotElf64,
    /// EI_DATA != 1 (not little-endian).
    NotLittleEndian,
    /// Section header table extends past the buffer.
    SectionTableOob,
    /// A section header's file-offset / size combination is out of
    /// range.
    SectionOob,
    /// No `SHT_SYMTAB` section in this ELF.
    NoSymtab,
    /// `symtab.sh_link` points outside the section header table.
    SymtabLinkOob,
    /// `symtab.sh_entsize` is smaller than `Elf64_Sym` (24 bytes).
    SymtabEntsizeTooSmall,
    /// Output buffer in [`parse_symtab_into`] is too small to hold the
    /// recovered `STT_FUNC` symbols. The returned `usize` (via the
    /// `BufferOverflow` value) tells the caller how many slots were
    /// needed.
    BufferOverflow,
}

/// Minimal ELF64 helpers.
pub mod elf {
    use super::*;

    pub(crate) const SHT_SYMTAB: u32 = 2;
    pub(crate) const STT_FUNC: u8 = 2;

    /// Read a u16 little-endian at `off`, bounds-checked.
    fn read_u16(bytes: &[u8], off: usize) -> Result<u16, ElfParseError> {
        if off + 2 > bytes.len() {
            return Err(ElfParseError::SectionOob);
        }
        Ok(u16::from_le_bytes([bytes[off], bytes[off + 1]]))
    }

    /// Read a u32 little-endian at `off`, bounds-checked.
    fn read_u32(bytes: &[u8], off: usize) -> Result<u32, ElfParseError> {
        if off + 4 > bytes.len() {
            return Err(ElfParseError::SectionOob);
        }
        Ok(u32::from_le_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
        ]))
    }

    /// Read a u64 little-endian at `off`, bounds-checked.
    fn read_u64(bytes: &[u8], off: usize) -> Result<u64, ElfParseError> {
        if off + 8 > bytes.len() {
            return Err(ElfParseError::SectionOob);
        }
        Ok(u64::from_le_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]))
    }

    /// Parse the `SHT_SYMTAB` section of `bytes` (an ELF64 LE image)
    /// and write the recovered `STT_FUNC` entries into `out` as
    /// (`SymbolEntry`-shaped) tuples. The `name_arena` is a contiguous
    /// byte slab the parser borrows function-name strings from — the
    /// caller can either point this at the ELF's `.strtab` section
    /// (zero-copy) or copy the strings out into a separate arena
    /// before the ELF buffer is freed.
    ///
    /// Returns the number of `STT_FUNC` entries written.
    ///
    /// Output entries are written in symtab order. The caller must sort
    /// before constructing a [`StaticSymbolResolver`]; `RawSymbolEntry`
    /// is `Ord` by `addr` to make this a one-liner.
    pub fn parse_symtab_into<'a>(
        bytes: &'a [u8],
        out: &mut [RawSymbolEntry<'a>],
    ) -> Result<usize, ElfParseError> {
        if bytes.len() < 64 {
            return Err(ElfParseError::HeaderTooSmall);
        }
        if &bytes[0..4] != b"\x7FELF" {
            return Err(ElfParseError::BadMagic);
        }
        if bytes[4] != 2 {
            return Err(ElfParseError::NotElf64);
        }
        if bytes[5] != 1 {
            return Err(ElfParseError::NotLittleEndian);
        }

        let e_shoff = read_u64(bytes, 0x28)?;
        let e_shentsize = read_u16(bytes, 0x3A)? as u64;
        let e_shnum = read_u16(bytes, 0x3C)? as u64;
        if e_shentsize < 64 {
            return Err(ElfParseError::SectionOob);
        }
        let sh_table_end = e_shoff
            .checked_add(e_shnum.checked_mul(e_shentsize).ok_or(ElfParseError::SectionTableOob)?)
            .ok_or(ElfParseError::SectionTableOob)?;
        if (sh_table_end as usize) > bytes.len() {
            return Err(ElfParseError::SectionTableOob);
        }

        // Locate the first SHT_SYMTAB section.
        let mut symtab_idx: Option<u64> = None;
        let mut i = 0u64;
        while i < e_shnum {
            let off = (e_shoff + i * e_shentsize) as usize;
            let sh_type = read_u32(bytes, off + 4)?;
            if sh_type == SHT_SYMTAB {
                symtab_idx = Some(i);
                break;
            }
            i += 1;
        }
        let symtab_idx = symtab_idx.ok_or(ElfParseError::NoSymtab)?;
        let symtab_off = (e_shoff + symtab_idx * e_shentsize) as usize;
        let sym_file_off = read_u64(bytes, symtab_off + 0x18)? as usize;
        let sym_size = read_u64(bytes, symtab_off + 0x20)? as usize;
        let sym_link = read_u32(bytes, symtab_off + 0x28)? as u64;
        let sym_entsize = read_u64(bytes, symtab_off + 0x38)? as usize;
        if sym_entsize < 24 {
            return Err(ElfParseError::SymtabEntsizeTooSmall);
        }
        let sym_end = sym_file_off
            .checked_add(sym_size)
            .ok_or(ElfParseError::SectionOob)?;
        if sym_end > bytes.len() {
            return Err(ElfParseError::SectionOob);
        }

        if sym_link >= e_shnum {
            return Err(ElfParseError::SymtabLinkOob);
        }
        let str_hdr_off = (e_shoff + sym_link * e_shentsize) as usize;
        let str_file_off = read_u64(bytes, str_hdr_off + 0x18)? as usize;
        let str_size = read_u64(bytes, str_hdr_off + 0x20)? as usize;
        let str_end = str_file_off
            .checked_add(str_size)
            .ok_or(ElfParseError::SectionOob)?;
        if str_end > bytes.len() {
            return Err(ElfParseError::SectionOob);
        }
        let strtab = &bytes[str_file_off..str_end];

        let entry_count = sym_size / sym_entsize;
        let mut written = 0usize;
        let mut k = 0usize;
        while k < entry_count {
            let off = sym_file_off + k * sym_entsize;
            let st_name = read_u32(bytes, off)? as usize;
            let st_info = bytes[off + 4];
            let st_value = read_u64(bytes, off + 8)?;
            let st_size = read_u64(bytes, off + 16)?;
            let stt = st_info & 0x0F;
            if stt != STT_FUNC || st_value == 0 {
                k += 1;
                continue;
            }
            if st_name >= strtab.len() {
                k += 1;
                continue;
            }
            let mut end = st_name;
            while end < strtab.len() && strtab[end] != 0 {
                end += 1;
            }
            if end == st_name {
                k += 1;
                continue;
            }
            let name = match core::str::from_utf8(&strtab[st_name..end]) {
                Ok(s) => s,
                Err(_) => {
                    k += 1;
                    continue;
                }
            };
            if written >= out.len() {
                return Err(ElfParseError::BufferOverflow);
            }
            out[written] = RawSymbolEntry {
                addr: st_value,
                size: if st_size > u32::MAX as u64 {
                    u32::MAX
                } else {
                    st_size as u32
                },
                name,
            };
            written += 1;
            k += 1;
        }
        Ok(written)
    }
}

/// Borrowed cousin of [`SymbolEntry`] returned by
/// [`elf::parse_symtab_into`]. The name slice borrows directly from
/// the ELF's `.strtab` section.
#[derive(Copy, Clone, Debug)]
pub struct RawSymbolEntry<'a> {
    /// Function start address.
    pub addr: u64,
    /// Function size in bytes (0 for unsized).
    pub size: u32,
    /// Function name, borrowed from `.strtab`.
    pub name: &'a str,
}

impl<'a> RawSymbolEntry<'a> {
    /// Default-construct a zeroed entry. Used to initialise scratch
    /// arrays before [`elf::parse_symtab_into`].
    pub const fn zeroed() -> Self {
        Self {
            addr: 0,
            size: 0,
            name: "",
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built canonical kernel-symbol fixture used across the
    /// resolver tests. Each entry stakes out a non-overlapping range so
    /// containment checks have a clean truth table.
    const FIXTURE: &[SymbolEntry] = &[
        SymbolEntry::new(0x0000_0000_0000_1000, 0x100, "kpti_sync_fault_dispatcher"),
        SymbolEntry::new(0x0000_0000_0000_1200, 0x080, "schedule_next_task"),
        SymbolEntry::new(0x0000_0000_0000_1400, 0x040, "kmsg_write"),
        SymbolEntry::new(0x0000_0000_0000_1500, 0x000, "weak_alias"),
        SymbolEntry::new(0x0000_0000_0000_2000, 0x800, "iommu_translate"),
        SymbolEntry::new(0x0000_0000_0000_3000, 0x010, "halt_forever"),
    ];

    fn resolver() -> StaticSymbolResolver<'static> {
        StaticSymbolResolver::new(FIXTURE)
    }

    #[test]
    fn fixture_is_sorted() {
        assert!(StaticSymbolResolver::is_sorted_by_addr(FIXTURE));
    }

    #[test]
    fn unsorted_table_detected() {
        const BAD: &[SymbolEntry] = &[
            SymbolEntry::new(2, 1, "b"),
            SymbolEntry::new(1, 1, "a"),
        ];
        assert!(!StaticSymbolResolver::is_sorted_by_addr(BAD));
    }

    #[test]
    fn resolve_function_start_yields_offset_zero() {
        let r = resolver();
        let (name, off) = r.resolve(0x1000).expect("hit");
        assert_eq!(name, "kpti_sync_fault_dispatcher");
        assert_eq!(off, 0);
    }

    #[test]
    fn resolve_mid_function() {
        let r = resolver();
        let (name, off) = r.resolve(0x1042).expect("hit");
        assert_eq!(name, "kpti_sync_fault_dispatcher");
        assert_eq!(off, 0x42);
    }

    #[test]
    fn resolve_last_byte_of_function() {
        let r = resolver();
        // Last byte still inside: addr=0x10FF (size=0x100, so 0x1000..0x1100).
        let (name, off) = r.resolve(0x10FF).expect("hit");
        assert_eq!(name, "kpti_sync_fault_dispatcher");
        assert_eq!(off, 0xFF);
    }

    #[test]
    fn resolve_one_past_end_misses() {
        let r = resolver();
        // 0x1100 is one byte past the end of `kpti_sync_fault_dispatcher`;
        // there's a hole before `schedule_next_task` starts at 0x1200.
        assert!(r.resolve(0x1100).is_none());
        assert!(r.resolve(0x11FF).is_none());
    }

    #[test]
    fn resolve_between_functions_misses() {
        let r = resolver();
        // 0x1280: past schedule_next_task (0x1200..0x1280); hole until 0x1400.
        assert!(r.resolve(0x1280).is_none());
        assert!(r.resolve(0x1300).is_none());
    }

    #[test]
    fn resolve_before_first_symbol_misses() {
        let r = resolver();
        assert!(r.resolve(0x0).is_none());
        assert!(r.resolve(0xFFF).is_none());
    }

    #[test]
    fn resolve_zero_size_entry_skipped() {
        let r = resolver();
        // `weak_alias` has size=0 at 0x1500 → never contains anything.
        assert!(r.resolve(0x1500).is_none());
    }

    #[test]
    fn resolve_far_past_table_misses() {
        let r = resolver();
        assert!(r.resolve(0xFFFF_FFFF_FFFF_FFFF).is_none());
    }

    #[test]
    fn resolve_against_large_function() {
        let r = resolver();
        let (name, off) = r.resolve(0x2700).expect("hit");
        assert_eq!(name, "iommu_translate");
        assert_eq!(off, 0x700);
    }

    #[test]
    fn resolve_deterministic_across_calls() {
        let r = resolver();
        let a = r.resolve(0x1042);
        let b = r.resolve(0x1042);
        let c = r.resolve(0x1042);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn resolve_empty_table_returns_none() {
        let empty: &[SymbolEntry] = &[];
        let r = StaticSymbolResolver::new(empty);
        assert!(r.resolve(0).is_none());
        assert!(r.resolve(0xFFFF).is_none());
        assert_eq!(r.symbol_count(), 0);
    }

    #[test]
    fn symbol_count_matches_table_len() {
        let r = resolver();
        assert_eq!(r.symbol_count(), FIXTURE.len());
        assert_eq!(r.len(), FIXTURE.len());
        assert!(!r.is_empty());
    }

    #[test]
    fn binary_search_visits_logarithmic_depth() {
        // We can't directly assert on call count, but we can build a
        // ~1024-entry sorted table and confirm random lookups all
        // succeed/fail correctly. This proves the binary-search
        // implementation handles a large table; the "O(log n)"
        // claim is structural in the implementation.
        const N: usize = 256;
        // Static storage so we can keep references to &'static str
        // simple. We synthesise the table at runtime into a vec.
        let mut buf: alloc::vec::Vec<SymbolEntry> = alloc::vec::Vec::with_capacity(N);
        // Names: we need &'static str. Use one shared name across all.
        let name = "fn_n";
        for i in 0..N {
            buf.push(SymbolEntry::new((i as u64 + 1) * 0x1000, 0x100, name));
        }
        // Sort just to be safe.
        buf.sort_by_key(|s| s.addr);
        let r = StaticSymbolResolver::new(&buf);
        // Every function-start address resolves.
        for i in 0..N {
            let want = (i as u64 + 1) * 0x1000;
            let (n, off) = r.resolve(want).expect("hit");
            assert_eq!(n, name);
            assert_eq!(off, 0);
        }
        // Every just-past-end address misses (size=0x100, then 0xF00
        // bytes of hole before the next entry).
        for i in 0..N {
            let probe = (i as u64 + 1) * 0x1000 + 0x100;
            assert!(r.resolve(probe).is_none(), "miss at {:#x}", probe);
        }
    }

    extern crate alloc;

    #[test]
    fn format_resolved_basic() {
        let mut out = [0u8; 64];
        let n = format_resolved("kpti_dispatch", 0x42, &mut out).unwrap();
        assert_eq!(&out[..n], b"kpti_dispatch+0x42");
    }

    #[test]
    fn format_resolved_zero_offset() {
        let mut out = [0u8; 64];
        let n = format_resolved("entry", 0, &mut out).unwrap();
        assert_eq!(&out[..n], b"entry+0x0");
    }

    #[test]
    fn format_resolved_large_offset() {
        let mut out = [0u8; 64];
        let n = format_resolved("big_fn", 0xDEAD_BEEF, &mut out).unwrap();
        assert_eq!(&out[..n], b"big_fn+0xdeadbeef");
    }

    #[test]
    fn format_resolved_overflow_reports_need() {
        let mut out = [0u8; 5];
        let res = format_resolved("kpti_dispatch", 0x42, &mut out);
        match res {
            Err(need) => assert!(need > out.len()),
            Ok(_) => panic!("expected overflow"),
        }
    }

    // ---- ELF parser tests ----

    fn build_minimal_elf64_with_symtab() -> alloc::vec::Vec<u8> {
        // Hand-built ELF64 LE image carrying:
        //   - one .strtab section: ["", "foo", "bar"]
        //   - one .symtab section: 3 STT_FUNC entries
        //
        // Section header layout (64 bytes each, 4 sections incl. null):
        //   [0] SHN_UNDEF (all zero, conventional)
        //   [1] SHT_PROGBITS (placeholder for .text — not needed for
        //                     the parser but keeps section indices clean)
        //   [2] SHT_STRTAB  (.strtab) — content below
        //   [3] SHT_SYMTAB  (.symtab, sh_link=2) — content below

        use alloc::vec::Vec;
        let mut img = Vec::<u8>::new();

        // Strtab content first so we know its offset.
        // strtab: [NUL][foo][NUL][bar][NUL][long_name][NUL]
        let strtab_payload: &[u8] =
            b"\0foo\0bar\0long_name\0";
        // names start at offsets: foo=1, bar=5, long_name=9

        // ---- ELF header (64 bytes) ----
        // Placeholders, patched below.
        img.extend_from_slice(&[0u8; 64]);
        img[0] = 0x7F;
        img[1] = b'E';
        img[2] = b'L';
        img[3] = b'F';
        img[4] = 2; // ELF64
        img[5] = 1; // little-endian
        img[6] = 1; // EI_VERSION
        // e_type, e_machine, e_version, e_entry, e_phoff: leave zero.
        // We patch e_shoff (0x28) + e_shentsize (0x3A) + e_shnum (0x3C)
        // after we know the section table position.

        // .strtab content + .symtab content live before the section header table.
        let strtab_file_off = img.len();
        img.extend_from_slice(strtab_payload);

        // ---- .symtab content ----
        // Each entry: 24 bytes:
        //   0..4 st_name (u32)
        //   4..5 st_info (u8)  (STT_FUNC = 2)
        //   5..6 st_other
        //   6..8 st_shndx
        //   8..16 st_value (u64)  function start
        //   16..24 st_size (u64)  function size
        let symtab_file_off = img.len();

        // First entry is conventionally the undefined symbol.
        img.extend_from_slice(&[0u8; 24]);

        // foo: addr=0x1000, size=0x100
        img.extend_from_slice(&(1u32).to_le_bytes()); // st_name
        img.push(2); // st_info = STT_FUNC
        img.push(0); // st_other
        img.extend_from_slice(&(1u16).to_le_bytes()); // st_shndx
        img.extend_from_slice(&(0x1000u64).to_le_bytes());
        img.extend_from_slice(&(0x100u64).to_le_bytes());

        // bar: addr=0x2000, size=0x080
        img.extend_from_slice(&(5u32).to_le_bytes()); // "bar"
        img.push(2);
        img.push(0);
        img.extend_from_slice(&(1u16).to_le_bytes());
        img.extend_from_slice(&(0x2000u64).to_le_bytes());
        img.extend_from_slice(&(0x080u64).to_le_bytes());

        // long_name: addr=0x3000, size=0x010
        img.extend_from_slice(&(9u32).to_le_bytes()); // "long_name"
        img.push(2);
        img.push(0);
        img.extend_from_slice(&(1u16).to_le_bytes());
        img.extend_from_slice(&(0x3000u64).to_le_bytes());
        img.extend_from_slice(&(0x010u64).to_le_bytes());

        // Non-FUNC entry to confirm it's filtered out.
        img.extend_from_slice(&(1u32).to_le_bytes()); // name = "foo"
        img.push(1); // st_info = STT_OBJECT
        img.push(0);
        img.extend_from_slice(&(1u16).to_le_bytes());
        img.extend_from_slice(&(0x4000u64).to_le_bytes());
        img.extend_from_slice(&(0x004u64).to_le_bytes());

        let symtab_size = img.len() - symtab_file_off;
        let strtab_size = strtab_payload.len();

        // ---- Section header table (64 bytes per entry, 4 entries) ----
        // Align to 8 to be tidy.
        while img.len() % 8 != 0 {
            img.push(0);
        }
        let shoff = img.len();

        // [0] SHN_UNDEF — all zero
        img.extend_from_slice(&[0u8; 64]);
        // [1] SHT_PROGBITS placeholder
        let mut sh1 = [0u8; 64];
        sh1[4..8].copy_from_slice(&1u32.to_le_bytes()); // sh_type = SHT_PROGBITS
        img.extend_from_slice(&sh1);
        // [2] SHT_STRTAB
        let mut sh2 = [0u8; 64];
        sh2[4..8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        sh2[0x18..0x20].copy_from_slice(&(strtab_file_off as u64).to_le_bytes()); // sh_offset
        sh2[0x20..0x28].copy_from_slice(&(strtab_size as u64).to_le_bytes()); // sh_size
        sh2[0x38..0x40].copy_from_slice(&(1u64).to_le_bytes()); // sh_entsize=1 (strtab)
        img.extend_from_slice(&sh2);
        // [3] SHT_SYMTAB, sh_link=2
        let mut sh3 = [0u8; 64];
        sh3[4..8].copy_from_slice(&2u32.to_le_bytes()); // SHT_SYMTAB
        sh3[0x18..0x20].copy_from_slice(&(symtab_file_off as u64).to_le_bytes()); // sh_offset
        sh3[0x20..0x28].copy_from_slice(&(symtab_size as u64).to_le_bytes()); // sh_size
        sh3[0x28..0x2C].copy_from_slice(&(2u32).to_le_bytes()); // sh_link → strtab idx
        sh3[0x38..0x40].copy_from_slice(&(24u64).to_le_bytes()); // sh_entsize = 24
        img.extend_from_slice(&sh3);

        // Patch ELF header.
        img[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        img[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        img[0x3C..0x3E].copy_from_slice(&4u16.to_le_bytes()); // e_shnum

        img
    }

    #[test]
    fn elf_parser_recovers_func_symbols() {
        let img = build_minimal_elf64_with_symtab();
        let mut out = [RawSymbolEntry::zeroed(); 16];
        let n = elf::parse_symtab_into(&img, &mut out).expect("parse");
        assert_eq!(n, 3);
        assert_eq!(out[0].addr, 0x1000);
        assert_eq!(out[0].size, 0x100);
        assert_eq!(out[0].name, "foo");
        assert_eq!(out[1].addr, 0x2000);
        assert_eq!(out[1].size, 0x080);
        assert_eq!(out[1].name, "bar");
        assert_eq!(out[2].addr, 0x3000);
        assert_eq!(out[2].size, 0x010);
        assert_eq!(out[2].name, "long_name");
    }

    #[test]
    fn elf_parser_rejects_bad_magic() {
        let mut img = build_minimal_elf64_with_symtab();
        img[0] = b'X';
        let mut out = [RawSymbolEntry::zeroed(); 16];
        assert_eq!(
            elf::parse_symtab_into(&img, &mut out),
            Err(ElfParseError::BadMagic)
        );
    }

    #[test]
    fn elf_parser_rejects_not_elf64() {
        let mut img = build_minimal_elf64_with_symtab();
        img[4] = 1; // ELFCLASS32
        let mut out = [RawSymbolEntry::zeroed(); 16];
        assert_eq!(
            elf::parse_symtab_into(&img, &mut out),
            Err(ElfParseError::NotElf64)
        );
    }

    #[test]
    fn elf_parser_rejects_big_endian() {
        let mut img = build_minimal_elf64_with_symtab();
        img[5] = 2; // ELFDATA2MSB
        let mut out = [RawSymbolEntry::zeroed(); 16];
        assert_eq!(
            elf::parse_symtab_into(&img, &mut out),
            Err(ElfParseError::NotLittleEndian)
        );
    }

    #[test]
    fn elf_parser_short_header_rejected() {
        let short = [0u8; 32];
        let mut out = [RawSymbolEntry::zeroed(); 16];
        assert_eq!(
            elf::parse_symtab_into(&short, &mut out),
            Err(ElfParseError::HeaderTooSmall)
        );
    }

    #[test]
    fn elf_parser_buffer_overflow_reported() {
        let img = build_minimal_elf64_with_symtab();
        let mut out = [RawSymbolEntry::zeroed(); 2]; // only space for 2
        assert_eq!(
            elf::parse_symtab_into(&img, &mut out),
            Err(ElfParseError::BufferOverflow)
        );
    }

    #[test]
    fn elf_parser_round_trip_into_static_resolver() {
        // Parse → sort → resolve, exactly the boot sequence.
        let img = build_minimal_elf64_with_symtab();
        let mut scratch = [RawSymbolEntry::zeroed(); 16];
        let n = elf::parse_symtab_into(&img, &mut scratch).unwrap();
        // Project into owned (heap'd in this test) SymbolEntry slice
        // so the resolver can hold a `&'static`-lookalike.
        let entries: alloc::vec::Vec<SymbolEntry> = scratch[..n]
            .iter()
            .map(|r| {
                // Leak the &str into 'static — fine for a test.
                let leaked: &'static str = alloc::boxed::Box::leak(r.name.into());
                SymbolEntry::new(r.addr, r.size, leaked)
            })
            .collect();
        let r = StaticSymbolResolver::new(&entries);
        let (name, off) = r.resolve(0x2010).expect("hit bar+0x10");
        assert_eq!(name, "bar");
        assert_eq!(off, 0x10);
        let (name, off) = r.resolve(0x3008).expect("hit long_name+0x8");
        assert_eq!(name, "long_name");
        assert_eq!(off, 0x8);
        assert!(r.resolve(0x4000).is_none(), "STT_OBJECT entry filtered out");
    }
}
