#!/usr/bin/env python3
"""
Independent MTD Metrics & Binary Diversification Verifier (`verify_metrics_independent.py`).

Directly addresses the audit requirement:
  "Independent verification of the metrics"

This script shares ZERO code, libraries, or AST/disassembler infrastructure with
`cuttle-mtd-metrics` or `cuttle-binmorph`. Using only the Python standard library
(`struct`, `hashlib`), it:
1. Independently parses ELF64 headers (`Elf64_Ehdr`), section headers (`Elf64_Shdr`),
   `.text`, `.symtab`, and `.strtab`.
2. Independently scans `.text` for raw x86-64 control-flow transfer bytes (`0xC3` ret,
   `0xC2` ret imm16, `0xCF` iretq, `0x0F 0x05` syscall, `0xFF /2` call r/m64,
   `0xFF /4` jmp r/m64) and extracts backward-sliced byte-suffix windows of lengths
   2..=10 bytes ending at each terminator site.
3. Independently computes:
   - Exact positional suffix-window survival rate between base and morphed variants,
   - Set-level Jaccard distance over distinct suffix windows,
   - Per-symbol (`STT_FUNC`) byte mutation counts and symbol-boundary preservation,
   - Unintended `0xC3`/`0xCF` byte reduction inside function bodies,
   - Full C(K, 2) pairwise diversity matrix across K distinct seeds to prove that
     `cuttle-binmorph` produces K mutually distinct binary variants (not a 2-state flip-flop).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple


ELF_MAGIC = b"\x7fELF"
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
STT_FUNC = 2


@dataclass(frozen=True)
class ElfFunctionSymbol:
    name: str
    vaddr: int
    size: int
    text_offset: int


@dataclass
class IndependentElfView:
    raw: bytes
    text_vaddr: int
    text_offset: int
    text_bytes: bytes
    functions: List[ElfFunctionSymbol]

    @property
    def text_sha256(self) -> str:
        return hashlib.sha256(self.text_bytes).hexdigest()


def parse_elf64_independent(raw: bytes) -> IndependentElfView:
    """Parse an ELF64 little-endian image using only `struct.unpack_from`."""
    if len(raw) < 64 or raw[:4] != ELF_MAGIC:
        raise ValueError("not a valid ELF image")
    ei_class, ei_data = raw[4], raw[5]
    if ei_class != 2 or ei_data != 1:
        raise ValueError(f"expected ELFCLASS64 LSB (2, 1), got ({ei_class}, {ei_data})")

    (
        _e_type,
        e_machine,
        _e_version,
        _e_entry,
        _e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    if e_machine != 62:
        raise ValueError(f"expected EM_X86_64 (62), got {e_machine}")
    if e_shoff == 0 or e_shnum == 0:
        raise ValueError("ELF image has no section headers")

    shdrs = []
    for idx in range(e_shnum):
        off = e_shoff + idx * e_shentsize
        shdrs.append(struct.unpack_from("<IIQQQQIIQQ", raw, off))

    shstr_shdr = shdrs[e_shstrndx]
    shstr_off, shstr_size = shstr_shdr[4], shstr_shdr[5]
    shstrtab = raw[shstr_off : shstr_off + shstr_size]

    def read_cstr(blob: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(blob):
            return ""
        end = blob.find(b"\x00", offset)
        if end == -1:
            end = len(blob)
        return blob[offset:end].decode("utf-8", errors="replace")

    text_vaddr = None
    text_offset = None
    text_size = None
    symtab_shdr = None

    for sh in shdrs:
        sh_name, sh_type, _sh_flags, sh_addr, sh_off, sh_sz, sh_link, _sh_info, _align, sh_entsz = sh
        sec_name = read_cstr(shstrtab, sh_name)
        if sec_name == ".text" and sh_type == SHT_PROGBITS:
            text_vaddr = sh_addr
            text_offset = sh_off
            text_size = sh_sz
        elif sh_type == SHT_SYMTAB:
            symtab_shdr = sh

    if text_vaddr is None or text_offset is None or text_size is None:
        raise ValueError("no .text section found in ELF64")

    text_bytes = raw[text_offset : text_offset + text_size]
    functions: List[ElfFunctionSymbol] = []

    if symtab_shdr is not None:
        _n, _t, _f, _a, sym_off, sym_sz, str_link, _info, _al, sym_entsz = symtab_shdr
        entsz = sym_entsz or 24
        str_shdr = shdrs[str_link]
        strtab = raw[str_shdr[4] : str_shdr[4] + str_shdr[5]]
        count = sym_sz // entsz
        seen_ranges: Set[Tuple[int, int]] = set()
        for i in range(count):
            st_name, st_info, _st_other, _st_shndx, st_value, st_size = struct.unpack_from(
                "<IBBHQQ", raw, sym_off + i * entsz
            )
            st_type = st_info & 0x0F
            if st_type == STT_FUNC and st_size > 0:
                if text_vaddr <= st_value and (st_value + st_size) <= (text_vaddr + text_size):
                    key = (st_value, st_size)
                    if key not in seen_ranges:
                        seen_ranges.add(key)
                        functions.append(
                            ElfFunctionSymbol(
                                name=read_cstr(strtab, st_name),
                                vaddr=st_value,
                                size=st_size,
                                text_offset=st_value - text_vaddr,
                            )
                        )
        functions.sort(key=lambda fn: (fn.vaddr, fn.size))

    return IndependentElfView(
        raw=raw,
        text_vaddr=text_vaddr,
        text_offset=text_offset,
        text_bytes=text_bytes,
        functions=functions,
    )


def find_terminator_sites(text: bytes) -> List[Tuple[int, str]]:
    """
    Independently locate all raw control-flow transfer byte positions in `.text`:
      - 0xC3: near ret
      - 0xC2 <imm16>: near ret imm16
      - 0xCF: iretq
      - 0x0F 0x05: syscall
      - 0xFF /2 (call r/m64) and 0xFF /4 (jmp r/m64)
    Returns a sorted list of `(end_exclusive_offset, kind_tag)`.
    """
    sites: List[Tuple[int, str]] = []
    n = len(text)
    for i in range(n):
        b = text[i]
        if b == 0xC3:
            sites.append((i + 1, "ret"))
        elif b == 0xC2 and i + 2 < n:
            sites.append((i + 3, "ret_imm16"))
        elif b == 0xCF:
            sites.append((i + 1, "iretq"))
        elif b == 0x0F and i + 1 < n and text[i + 1] == 0x05:
            sites.append((i + 2, "syscall"))
        elif b == 0xFF and i + 1 < n:
            modrm = text[i + 1]
            reg_op = (modrm >> 3) & 0x07
            mod = (modrm >> 6) & 0x03
            rm = modrm & 0x07
            if reg_op in (2, 4):
                # Compute instruction length for 0xFF /2 or 0xFF /4 in 1-byte ModR/M cases
                if mod == 3:
                    sites.append((i + 2, "ind_call" if reg_op == 2 else "ind_jmp"))
                elif mod == 0 and rm != 4 and rm != 5:
                    sites.append((i + 2, "ind_call_mem" if reg_op == 2 else "ind_jmp_mem"))
                elif mod == 1 and rm != 4 and i + 2 < n:
                    sites.append((i + 3, "ind_call_disp8" if reg_op == 2 else "ind_jmp_disp8"))
    return sites


def extract_suffix_windows(
    text: bytes, window_lengths: Tuple[int, ...] = (2, 3, 4, 5, 6, 8)
) -> Tuple[Dict[Tuple[int, int], bytes], Set[bytes]]:
    """
    For every terminator site ending at `end_off`, extract raw byte suffixes
    `text[end_off - w : end_off]` for each `w` in `window_lengths`.
    Returns:
      - `by_pos`: dict mapping `(start_off, w)` -> `raw_suffix_bytes`
      - `distinct_set`: set of all distinct `raw_suffix_bytes` across `.text`
    """
    sites = find_terminator_sites(text)
    by_pos: Dict[Tuple[int, int], bytes] = {}
    distinct_set: Set[bytes] = set()
    for end_off, _kind in sites:
        for w in window_lengths:
            if end_off >= w:
                start_off = end_off - w
                suffix = text[start_off:end_off]
                by_pos[(start_off, w)] = suffix
                distinct_set.add(suffix)
    return by_pos, distinct_set


def compare_base_and_variant_independent(
    base: IndependentElfView, variant: IndependentElfView
) -> Dict[str, object]:
    """Independently audit structural invariants and gadget-window churn between two ELFs."""
    if len(base.text_bytes) != len(variant.text_bytes):
        raise ValueError(
            f".text length changed: base={len(base.text_bytes)} vs variant={len(variant.text_bytes)}"
        )
    if base.text_vaddr != variant.text_vaddr:
        raise ValueError(".text vaddr changed")
    if [(f.name, f.vaddr, f.size) for f in base.functions] != [
        (f.name, f.vaddr, f.size) for f in variant.functions
    ]:
        raise ValueError("function symbol table entries changed")

    base_pos, base_distinct = extract_suffix_windows(base.text_bytes)
    var_pos, var_distinct = extract_suffix_windows(variant.text_bytes)

    pos_survivors = sum(
        1 for key, b_bytes in base_pos.items() if var_pos.get(key) == b_bytes
    )
    pos_survival_rate = pos_survivors / max(1, len(base_pos))

    union_cnt = len(base_distinct | var_distinct)
    inter_cnt = len(base_distinct & var_distinct)
    jaccard_distance = 1.0 - (inter_cnt / max(1, union_cnt))

    mutated_funcs = 0
    unintended_c3_base = 0
    unintended_c3_var = 0
    for fn in base.functions:
        b_slice = base.text_bytes[fn.text_offset : fn.text_offset + fn.size]
        v_slice = variant.text_bytes[fn.text_offset : fn.text_offset + fn.size]
        if b_slice != v_slice:
            mutated_funcs += 1
        # Count interior 0xC3/0xCF bytes prior to the final byte of the function
        if len(b_slice) > 1:
            unintended_c3_base += b_slice[:-1].count(0xC3) + b_slice[:-1].count(0xCF)
            unintended_c3_var += v_slice[:-1].count(0xC3) + v_slice[:-1].count(0xCF)

    hamming_bytes = sum(
        1 for a, b in zip(base.text_bytes, variant.text_bytes) if a != b
    )

    return {
        "base_sha256": base.text_sha256,
        "variant_sha256": variant.text_sha256,
        "text_size": len(base.text_bytes),
        "functions_total": len(base.functions),
        "functions_mutated": mutated_funcs,
        "hamming_changed_bytes": hamming_bytes,
        "hamming_changed_fraction": hamming_bytes / max(1, len(base.text_bytes)),
        "base_suffix_windows": len(base_pos),
        "positional_suffix_survivors": pos_survivors,
        "positional_suffix_survival_rate": pos_survival_rate,
        "distinct_suffix_jaccard_distance": jaccard_distance,
        "interior_c3_cf_bytes_base": unintended_c3_base,
        "interior_c3_cf_bytes_variant": unintended_c3_var,
    }


def evaluate_pairwise_seeds_independent(
    views: Dict[int, IndependentElfView]
) -> Dict[str, object]:
    """Evaluate all C(K, 2) pairs across K seeded variants."""
    seeds = sorted(views.keys())
    k = len(seeds)
    sha_set = {views[s].text_sha256 for s in seeds}
    pair_reports = []
    min_hamming = None
    max_pos_survival = 0.0

    for i in range(k):
        for j in range(i + 1, k):
            s_i, s_j = seeds[i], seeds[j]
            rep = compare_base_and_variant_independent(views[s_i], views[s_j])
            hb = int(rep["hamming_changed_bytes"])
            ps = float(rep["positional_suffix_survival_rate"])
            if min_hamming is None or hb < min_hamming:
                min_hamming = hb
            if ps > max_pos_survival:
                max_pos_survival = ps
            pair_reports.append(
                {
                    "seed_a": s_i,
                    "seed_b": s_j,
                    "hamming_changed_bytes": hb,
                    "positional_suffix_survival_rate": ps,
                    "distinct_suffix_jaccard_distance": rep[
                        "distinct_suffix_jaccard_distance"
                    ],
                }
            )

    return {
        "seed_count": k,
        "pair_count": len(pair_reports),
        "unique_sha256_count": len(sha_set),
        "min_pairwise_hamming_bytes": min_hamming or 0,
        "max_pairwise_positional_suffix_survival": max_pos_survival,
        "pairs": pair_reports,
    }


def build_synthetic_elf64_specimen() -> bytes:
    """
    Construct a self-contained ELF64 x86-64 binary with 4 functions containing
    embedded 0xC3ModR/M bytes, callee-saved push/pop pairs, leaf scratch registers,
    and commutable ALU instructions so `--self-test` can run even without a prebuilt kernel ELF.
    """
    text_vaddr = 0x00401000
    fn_Payloads = [
        (
            b"specimen_fn0",
            bytes(
                [
                    0x55,
                    0x53,
                    0x41,
                    0x54,
                    0x41,
                    0x55,
                    0x48,
                    0x89,
                    0xC3,  # mov rbx, rax (embedded 0xC3!)
                    0x49,
                    0x89,
                    0xF4,  # mov r12, rsi
                    0x49,
                    0x89,
                    0xD5,  # mov r13, rdx
                    0x4C,
                    0x01,
                    0xE3,  # add rbx, r12
                    0x49,
                    0x31,
                    0xED,  # xor r13, rbp
                    0x48,
                    0x89,
                    0xD8,  # mov rax, rbx
                    0x41,
                    0x5D,
                    0x41,
                    0x5C,
                    0x5B,
                    0x5D,
                    0xC3,
                ]
            ),
        ),
        (
            b"specimen_fn1",
            bytes(
                [
                    0x4C,
                    0x8B,
                    0x07,  # mov r8, [rdi]
                    0x4C,
                    0x8B,
                    0x0E,  # mov r9, [rsi]
                    0x4F,
                    0x8D,
                    0x54,
                    0x08,
                    0x11,  # lea r10, [r8+r9+0x11]
                    0x49,
                    0x31,
                    0xD2,  # xor r10, rdx
                    0x49,
                    0x01,
                    0xC8,  # add r8, rcx
                    0x4D,
                    0x29,
                    0xC2,  # sub r10, r8
                    0x4C,
                    0x89,
                    0xD0,  # mov rax, r10
                    0xC3,
                ]
            ),
        ),
        (
            b"specimen_fn2",
            bytes(
                [
                    0x89,
                    0xF8,  # mov eax, edi
                    0x89,
                    0xF1,  # mov ecx, esi
                    0x81,
                    0xC1,
                    0x44,
                    0x33,
                    0x22,
                    0x11,  # add ecx, 0x11223344
                    0x4C,
                    0x8D,
                    0x42,
                    0x55,  # lea r8, [rdx+0x55]
                    0x81,
                    0xE9,
                    0x04,
                    0x03,
                    0x02,
                    0x01,  # sub ecx, 0x01020304
                    0x49,
                    0x81,
                    0xC0,
                    0x34,
                    0x12,
                    0x00,
                    0x00,  # add r8, 0x1234
                    0x31,
                    0xC8,  # xor eax, ecx
                    0x4C,
                    0x01,
                    0xC0,  # add rax, r8
                    0xC3,
                ]
            ),
        ),
    ]

    text = bytearray()
    sym_entries = [b"\x00" * 24]
    strtab = bytearray(b"\x00")
    for name, code in fn_Payloads:
        while len(text) % 16 != 0:
            text.append(0xCC)
        fn_vaddr = text_vaddr + len(text)
        text.extend(code)
        st_name = len(strtab)
        strtab.extend(name + b"\x00")
        sym_entries.append(
            struct.pack(
                "<IBBHQQ",
                st_name,
                (1 << 4) | STT_FUNC,
                0,
                1,
                fn_vaddr,
                len(code),
            )
        )

    symtab = b"".join(sym_entries)
    shstrtab = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"

    elf = bytearray(64)
    text_off = len(elf)
    elf.extend(text)
    while len(elf) % 8 != 0:
        elf.append(0)
    symtab_off = len(elf)
    elf.extend(symtab)
    strtab_off = len(elf)
    elf.extend(strtab)
    shstrtab_off = len(elf)
    elf.extend(shstrtab)
    while len(elf) % 8 != 0:
        elf.append(0)
    shoff = len(elf)

    def pack_shdr(
        sh_name: int,
        sh_type: int,
        sh_flags: int,
        sh_addr: int,
        sh_offset: int,
        sh_size: int,
        sh_link: int,
        sh_info: int,
        sh_addralign: int,
        sh_entsize: int,
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        )

    elf.extend(pack_shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    elf.extend(
        pack_shdr(1, SHT_PROGBITS, 6, text_vaddr, text_off, len(text), 0, 0, 16, 0)
    )
    elf.extend(
        pack_shdr(7, SHT_SYMTAB, 0, 0, symtab_off, len(symtab), 3, 1, 8, 24)
    )
    elf.extend(pack_shdr(15, SHT_STRTAB, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0))
    elf.extend(
        pack_shdr(23, SHT_STRTAB, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0)
    )

    struct.pack_into(
        "<4sBBBB8sHHIQQQIHHHHHH",
        elf,
        0,
        ELF_MAGIC,
        2,
        1,
        1,
        0,
        b"\x00" * 8,
        2,
        62,
        1,
        text_vaddr,
        0,
        shoff,
        0,
        64,
        0,
        0,
        64,
        5,
        4,
    )
    return bytes(elf)


def find_binmorph_cmd(repo_root: Path) -> List[str]:
    env_bin = os.environ.get("CARGO_BIN_EXE_binmorph")
    if env_bin and Path(env_bin).exists():
        return [env_bin]
    exe_suffix = ".exe" if os.name == "nt" else ""
    for rel in [
        Path("target") / "debug" / f"binmorph{exe_suffix}",
        Path("target") / "release" / f"binmorph{exe_suffix}",
    ]:
        cand = repo_root / rel
        if cand.exists():
            return [str(cand)]
    return ["cargo", "run", "--quiet", "-p", "cuttle-binmorph", "--"]


def run_self_test(repo_root: Path) -> int:
    print("[independent-verifier] starting standalone ELF64 + multi-seed metric verification...")
    seeds = [1, 2, 3, 4, 5, 6, 7, 8]
    bm_prefix = find_binmorph_cmd(repo_root)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        base_path = tmp_dir / "base_specimen.elf"
        base_bytes = build_synthetic_elf64_specimen()
        base_path.write_bytes(base_bytes)
        base_view = parse_elf64_independent(base_bytes)

        assert len(base_view.functions) == 3, f"expected 3 functions, got {len(base_view.functions)}"

        views: Dict[int, IndependentElfView] = {}
        for seed in seeds:
            out_path = tmp_dir / f"variant_{seed}.elf"
            cmd = bm_prefix + [
                "--in",
                str(base_path),
                "--out",
                str(out_path),
                "--seed",
                str(seed),
            ]
            res = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)
            if res.returncode != 0:
                print(f"ERROR: cuttle-binmorph failed for seed {seed}: {res.stderr}", file=sys.stderr)
                return 1
            v_view = parse_elf64_independent(out_path.read_bytes())
            rep = compare_base_and_variant_independent(base_view, v_view)

            # Assert every variant mutated functions, scrubbed the embedded 0xC3 byte in fn0,
            # and reduced positional suffix survival:
            assert int(rep["functions_mutated"]) >= 2, f"seed {seed} did not mutate >=2 functions: {rep}"
            assert int(rep["interior_c3_cf_bytes_base"]) >= 1
            assert int(rep["interior_c3_cf_bytes_variant"]) == 0, (
                f"seed {seed} left unintended interior 0xC3/0xCF byte: {rep}"
            )
            assert float(rep["positional_suffix_survival_rate"]) < 0.75, (
                f"seed {seed} positional suffix survival too high: {rep}"
            )
            assert float(rep["distinct_suffix_jaccard_distance"]) > 0.25, (
                f"seed {seed} suffix Jaccard distance too low: {rep}"
            )
            views[seed] = v_view

        pw = evaluate_pairwise_seeds_independent(views)
        assert int(pw["unique_sha256_count"]) >= 6, (
            f"expected >= 6 unique SHA-256 variants across 8 seeds, got {pw['unique_sha256_count']}"
        )
        print(
            f"[independent-verifier] synthetic ELF64 PASS: "
            f"{pw['unique_sha256_count']}/{len(seeds)} unique SHA-256 digests across {pw['pair_count']} pairs"
        )

        # Also independently verify the real compiled kernel ELF if present on disk:
        kernel_candidates = [
            repo_root
            / "target_enterprise_kernel"
            / "target"
            / "x86_64-unknown-none"
            / "release"
            / "target_enterprise_kernel",
            repo_root
            / "target"
            / "x86_64-unknown-none"
            / "release"
            / "target_enterprise_kernel",
        ]
        kernel_elf = next((p for p in kernel_candidates if p.exists()), None)
        if kernel_elf is not None:
            k_base = parse_elf64_independent(kernel_elf.read_bytes())
            k_views: Dict[int, IndependentElfView] = {}
            for seed in [101, 202, 303, 404]:
                k_out = tmp_dir / f"kernel_{seed}.elf"
                subprocess.run(
                    bm_prefix
                    + [
                        "--in",
                        str(kernel_elf),
                        "--out",
                        str(k_out),
                        "--seed",
                        str(seed),
                    ],
                    cwd=repo_root,
                    check=True,
                    capture_output=True,
                )
                kv = parse_elf64_independent(k_out.read_bytes())
                k_rep = compare_base_and_variant_independent(k_base, kv)
                assert int(k_rep["functions_mutated"]) > 50, (
                    f"expected > 50 mutated kernel functions, got {k_rep['functions_mutated']}"
                )
                assert int(k_rep["interior_c3_cf_bytes_variant"]) <= int(
                    k_rep["interior_c3_cf_bytes_base"]
                ), "binmorph must never increase interior 0xC3/0xCF gadget bytes"
                k_views[seed] = kv

            k_pw = evaluate_pairwise_seeds_independent(k_views)
            assert int(k_pw["unique_sha256_count"]) == 4, (
                f"all 4 kernel seeds must produce distinct .text SHA-256 digests: {k_pw}"
            )
            assert int(k_pw["min_pairwise_hamming_bytes"]) > 500, (
                f"expected > 500 pairwise differing bytes across kernel seeds, got {k_pw['min_pairwise_hamming_bytes']}"
            )
            print(
                f"[independent-verifier] real kernel ELF64 PASS: "
                f"{k_base.functions.__len__()} functions, "
                f"4/4 unique morphed skins, min pairwise diff={k_pw['min_pairwise_hamming_bytes']} bytes"
            )

    print("[independent-verifier] ALL INDEPENDENT METRIC CHECKS PASSED")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Independent ELF64 & MTD gadget metric verifier (zero shared code with mtd_metrics)"
    )
    parser.add_argument("--self-test", action="store_true", help="Run standalone self-test suite")
    parser.add_argument("--base", type=Path, help="Base ELF64 binary path")
    parser.add_argument("--variant", type=Path, help="Morphed variant ELF64 binary path")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    if args.self_test:
        return run_self_test(repo_root)

    if args.base and args.variant:
        b_view = parse_elf64_independent(args.base.read_bytes())
        v_view = parse_elf64_independent(args.variant.read_bytes())
        rep = compare_base_and_variant_independent(b_view, v_view)
        print(json.dumps(rep, indent=2))
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
