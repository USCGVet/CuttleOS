#!/usr/bin/env python3
"""Generate THIRD_PARTY_NOTICES.md for the bootable CuttleOS image.

A CuttleOS disk image (built by `factory_builder`) contains:

  * the kernel ELF: `target_enterprise_kernel` and its runtime dependency
    closure for `x86_64-unknown-none`, plus the Rust `core`/`alloc`/
    `compiler_builtins` libraries compiled in by `build-std`;
  * the bootloader: the BIOS boot sector and stages 2-4 of the `bootloader`
    crate (and the UEFI loader when the image is built with `--uefi`). The
    bootloader compiles those stages with `cargo install --locked` from each
    stage crate's own Cargo.lock, so they never appear in any CuttleOS
    lockfile and `cargo deny` cannot see them.

This script resolves both, collects every third-party crate's license
expression and shipped license/notice files, and writes them to
THIRD_PARTY_NOTICES.md, which must accompany any distributed image (see
NOTICE). It also enforces the license policy from deny.toml on the
bootloader stages, failing on any license outside it apart from the
documented exceptions below.

    python tools/third_party_notices.py           # (re)write the file
    python tools/third_party_notices.py --check   # exit 1 if stale / policy fails

Needs `cargo` (and network access the first time, to download the stage
crates' dependencies into the cargo cache).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "THIRD_PARTY_NOTICES.md"
KERNEL_MANIFEST = ROOT / "target_enterprise_kernel" / "Cargo.toml"
PACKAGER_MANIFEST = ROOT / "factory_builder_pkg" / "Cargo.toml"
KERNEL_TARGET = "x86_64-unknown-none"

# (stage crate suffix, platform used to prune target-specific deps, where it ships)
STAGES = [
    ("bios-boot-sector", "x86_64-unknown-none", "BIOS bootloader"),
    ("bios-stage-2", "x86_64-unknown-none", "BIOS bootloader"),
    ("bios-stage-3", "x86_64-unknown-none", "BIOS bootloader"),
    ("bios-stage-4", "x86_64-unknown-none", "BIOS bootloader"),
    ("uefi", "x86_64-unknown-uefi", "UEFI bootloader (only images built with --uefi)"),
]

# Licenses outside deny.toml's allow list that are accepted for one crate,
# with the reason. Anything else outside the list fails the run.
EXCEPTIONS = {
    "ucs2": (
        "MPL-2.0",
        "Used only by the optional UEFI loader. MPL-2.0 is file-level copyleft: it "
        "covers ucs2's own source files only and does not require relicensing "
        "CuttleOS or software built on it, provided a distributed UEFI image informs "
        "recipients where the unmodified ucs2 source can be obtained (MPL-2.0 "
        "section 3.2): https://crates.io/crates/ucs2 and "
        "https://github.com/rust-osdev/ucs2-rs.",
    ),
}

# Content embedded in a crate that carries a license of its own.
EMBEDDED = {
    "noto-sans-mono-bitmap": (
        "Noto Sans Mono font data (rasterized glyphs)",
        "Copyright 2022 The Noto Project Authors "
        "(https://github.com/notofonts/latin-greek-cyrillic)\n\n"
        "This Font Software is licensed under the SIL Open Font License, Version 1.1.",
        ROOT / "licenses" / "OFL-1.1.txt",
    ),
}

LICENSE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|COPYRIGHT|NOTICE|UNLICENSE)", re.IGNORECASE)


def run(cmd: list[str], cwd: pathlib.Path | None = None) -> str:
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout


def metadata(manifest: pathlib.Path, platform: str) -> dict:
    return json.loads(
        run(
            [
                "cargo", "metadata", "--format-version", "1", "--locked",
                "--manifest-path", str(manifest), "--filter-platform", platform,
            ]
        )
    )


def runtime_closure(manifest: pathlib.Path, platform: str, include_root: bool = False) -> list[dict]:
    """Third-party packages linked into `manifest`'s binary for `platform`:
    `cargo tree` over normal edges (it applies the real feature resolution,
    which `cargo metadata` does not), skipping proc-macro crates and
    everything only they depend on. Package details come from metadata."""
    meta = metadata(manifest, platform)
    by_name_version = {(p["name"], p["version"]): p for p in meta["packages"]}
    tree = run(
        [
            "cargo", "tree", "--locked", "-e", "normal", "--target", platform,
            "--prefix", "depth", "--format", "{p}", "--no-dedupe",
            "--manifest-path", str(manifest),
        ]
    )
    found: dict[tuple[str, str], dict] = {}
    skip_below: int | None = None
    for line in tree.splitlines():
        m = re.match(r"^(\d+)(\S+) v(\S+)", line)
        if not m:
            continue
        depth, name, version = int(m.group(1)), m.group(2), m.group(3)
        if skip_below is not None:
            if depth > skip_below:
                continue
            skip_below = None
        pkg = by_name_version[(name, version)]
        if any("proc-macro" in t["kind"] for t in pkg["targets"]):
            skip_below = depth
            continue
        if pkg["source"] is not None or (include_root and depth == 0):
            found[(name, version)] = pkg
    return list(found.values())


def stage_closure(registry_src: pathlib.Path, stage: str, version: str, platform: str) -> list[dict]:
    """Resolve a bootloader stage crate (including the stage root package
    itself) from its shipped Cargo.lock. Works on a temporary copy so nothing
    is written into the cargo registry."""
    src = registry_src / f"bootloader-x86_64-{stage}-{version}"
    if not src.is_dir():
        sys.exit(f"{src} not found: build an image once (run.bat or factory_builder) first")
    stage_name = f"bootloader-x86_64-{stage}"
    with tempfile.TemporaryDirectory() as tmp:
        dst = pathlib.Path(tmp) / src.name
        shutil.copytree(src, dst)
        pkgs = runtime_closure(dst / "Cargo.toml", platform, include_root=True)
        for pkg in pkgs:
            if pkg["name"] == stage_name and pkg["source"] is None:
                pkg["manifest_path"] = str(src / "Cargo.toml")
        return pkgs


# --- SPDX expressions -------------------------------------------------------

class _SpdxSyntaxError(Exception):
    pass


def spdx_allowed(expr: str, allowed: set[str]) -> bool:
    """Evaluate a Cargo license expression ("A OR B", "A AND (B OR C)",
    "A WITH E", legacy "A/B") against the allow list. Rejects malformed or
    lowercase operators ("and", "or", "with"), unbalanced parentheses, and
    any trailing tokens."""
    tokens = re.findall(r"\(|\)|[^\s()]+", expr.replace("/", " OR "))
    if not tokens:
        return False
    pos = 0
    reserved = {"(", ")", "AND", "OR", "WITH", "and", "or", "with"}

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise _SpdxSyntaxError("unexpected end of SPDX expression")
        pos += 1
        return tokens[pos - 1]

    def factor() -> bool:
        tok = peek()
        if tok is None:
            raise _SpdxSyntaxError("missing factor")
        if tok == "(":
            take()
            value = disjunction()
            if peek() != ")":
                raise _SpdxSyntaxError("unclosed '('")
            take()
            return value
        if tok in reserved:
            raise _SpdxSyntaxError(f"unexpected operator {tok!r}")
        lic = take()
        if peek() == "WITH":
            take()
            exc = peek()
            if exc is None or exc in reserved:
                raise _SpdxSyntaxError("missing exception after WITH")
            lic = f"{lic} WITH {take()}"
        return lic in allowed

    def conjunction() -> bool:
        value = factor()
        while peek() == "AND":
            take()
            rhs = factor()
            value = value and rhs
        return value

    def disjunction() -> bool:
        value = conjunction()
        while peek() == "OR":
            take()
            rhs = conjunction()
            value = value or rhs
        return value

    try:
        result = disjunction()
    except _SpdxSyntaxError:
        return False
    if pos != len(tokens):
        return False
    return result


# --- License texts ----------------------------------------------------------

def normalize(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").strip().split("\n"))


def license_files(pkg: dict) -> list[tuple[str, str]]:
    pkg_dir = pathlib.Path(pkg["manifest_path"]).parent
    found = []
    for path in sorted(pkg_dir.iterdir()):
        if path.is_file() and LICENSE_FILE.match(path.name):
            found.append((path.name, normalize(path.read_text(encoding="utf-8", errors="replace"))))
    if pkg.get("license_file"):
        path = pkg_dir / pkg["license_file"]
        if path.is_file() and path.name not in {n for n, _ in found}:
            found.append((path.name, normalize(path.read_text(encoding="utf-8", errors="replace"))))
    return found


def fallback_text(pkg: dict) -> list[tuple[str, str]]:
    """For a crate that ships no license file: the license named in its
    metadata, with its authors as the copyright holders."""
    expr = pkg.get("license") or ""
    holders = ", ".join(pkg.get("authors") or []) or f"the {pkg['name']} authors"
    if "MIT" in expr:
        mit = normalize((ROOT / "licenses" / "MIT-template.txt").read_text(encoding="utf-8"))
        return [("MIT (from Cargo metadata)", mit.replace("<COPYRIGHT HOLDERS>", holders))]
    if "Apache-2.0" in expr:
        return [("Apache-2.0 (from Cargo metadata)", normalize((ROOT / "LICENSE").read_text(encoding="utf-8")))]
    sys.exit(f"{pkg['name']} {pkg['version']} ships no license file and has no usable license metadata")


def rust_std_entry() -> dict:
    kernel_dir = KERNEL_MANIFEST.parent
    sysroot = pathlib.Path(run(["rustc", "--print", "sysroot"], cwd=kernel_dir).strip())
    docs_apache = sysroot / "share" / "doc" / "rust" / "licenses" / "Apache-2.0.txt"
    src_apache = sysroot / "lib" / "rustlib" / "src" / "rust" / "LICENSE-APACHE"
    apache_path = docs_apache if docs_apache.is_file() else (src_apache if src_apache.is_file() else (ROOT / "LICENSE"))
    builtins = sysroot / "lib" / "rustlib" / "src" / "rust" / "library" / "compiler-builtins" / "LICENSE.txt"
    files = [
        (
            "LICENSE-MIT",
            normalize((ROOT / "licenses" / "MIT-template.txt").read_text(encoding="utf-8")).replace(
                "<COPYRIGHT HOLDERS>", "The Rust Project Contributors"
            ),
        ),
        ("LICENSE-APACHE", normalize(apache_path.read_text(encoding="utf-8"))),
        ("compiler-builtins/LICENSE.txt", normalize(builtins.read_text(encoding="utf-8"))),
    ]
    return {
        "name": "Rust standard library (core, alloc, compiler_builtins)",
        "version": "nightly (build-std)",
        "license": "MIT OR Apache-2.0; compiler_builtins: MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0)",
        "repository": "https://github.com/rust-lang/rust",
        "files": files,
    }


# --- Main -------------------------------------------------------------------

def collect() -> tuple[str, list[str]]:
    deny = tomllib.loads((ROOT / "deny.toml").read_text(encoding="utf-8"))
    allowed = set(deny["licenses"]["allow"])

    components: dict[tuple[str, str], dict] = {}

    def add(pkg: dict, where: str) -> None:
        key = (pkg["name"], pkg["version"])
        entry = components.setdefault(
            key,
            {
                "name": pkg["name"],
                "version": pkg["version"],
                "license": pkg.get("license") or "(see license file)",
                "repository": pkg.get("repository") or f"https://crates.io/crates/{pkg['name']}",
                "files": license_files(pkg) or fallback_text(pkg),
                "where": set(),
            },
        )
        entry["where"].add(where)

    for pkg in runtime_closure(KERNEL_MANIFEST, KERNEL_TARGET):
        add(pkg, "kernel")

    packager = metadata(PACKAGER_MANIFEST, "x86_64-pc-windows-msvc")
    bootloader = next(p for p in packager["packages"] if p["name"] == "bootloader")
    registry_src = pathlib.Path(bootloader["manifest_path"]).parent.parent
    for stage, platform, where in STAGES:
        for pkg in stage_closure(registry_src, stage, bootloader["version"], platform):
            add(pkg, where)

    problems = []
    for entry in components.values():
        if spdx_allowed(entry["license"], allowed):
            continue
        exception = EXCEPTIONS.get(entry["name"])
        if exception and exception[0] == entry["license"]:
            entry["exception"] = exception[1]
            continue
        problems.append(f"{entry['name']} {entry['version']}: {entry['license']} ({', '.join(sorted(entry['where']))})")

    std = rust_std_entry()
    std["where"] = {"kernel"}
    ordered = [std] + sorted(components.values(), key=lambda e: (e["name"].lower(), e["version"]))
    return render(ordered), problems


def render(entries: list[dict]) -> str:
    out = [
        "# Third-party notices",
        "",
        "CuttleOS is licensed under the Apache License 2.0 (see [LICENSE](LICENSE) and",
        "[NOTICE](NOTICE)). A CuttleOS disk image also contains the third-party",
        "components below, linked into the kernel or into the bootloader. Their",
        "licenses are permissive (MIT, Apache-2.0, BSD, ISC and similar) except",
        "where an entry says otherwise. This file must accompany any distributed",
        "image.",
        "",
        "Generated by `tools/third_party_notices.py`; do not edit by hand.",
        "",
        "## Components",
        "",
        "| Component | Version | License | Linked into |",
        "|---|---|---|---|",
    ]
    for e in entries:
        where = ", ".join(sorted(e["where"]))
        out.append(f"| [{e['name']}]({e['repository']}) | {e['version']} | {e['license']} | {where} |")

    notes = [e for e in entries if "exception" in e or e["name"] in EMBEDDED]
    if notes:
        out += ["", "## Notes", ""]
        for e in notes:
            if "exception" in e:
                out.append(f"- **{e['name']} {e['version']} ({e['license']}).** {e['exception']}")
            if e["name"] in EMBEDDED:
                title, _, _ = EMBEDDED[e["name"]]
                out.append(
                    f"- **{e['name']} {e['version']}** embeds {title}, which is under the "
                    "SIL Open Font License 1.1 (text below). The OFL permits bundling the "
                    "font with any software; it does not apply to that software."
                )

    # Each distinct license text once, with the components that ship it.
    texts: dict[str, dict] = {}
    for e in entries:
        files = list(e["files"])
        if e["name"] in EMBEDDED:
            title, notice, path = EMBEDDED[e["name"]]
            files.append((title, notice + "\n\n" + normalize(path.read_text(encoding="utf-8"))))
        for fname, text in files:
            digest = hashlib.sha256(text.encode()).hexdigest()
            slot = texts.setdefault(digest, {"text": text, "users": set()})
            slot["users"].add(f"{e['name']} {e['version']} ({fname})")

    out += ["", "## License and notice texts", ""]
    for i, slot in enumerate(sorted(texts.values(), key=lambda s: sorted(s["users"])[0].lower()), 1):
        users = ", ".join(sorted(slot["users"], key=str.lower))
        out += [f"### {i}. Used by: {users}", "", "~~~~text", slot["text"], "~~~~", ""]
    return "\n".join(out).rstrip() + "\n"


def run_self_test() -> int:
    allowed = {"MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-3-Clause"}
    assert spdx_allowed("MIT OR Apache-2.0", allowed)
    assert spdx_allowed("MIT/Apache-2.0", allowed)
    assert spdx_allowed("MIT AND (Apache-2.0 WITH LLVM-exception OR GPL-3.0)", allowed)
    assert not spdx_allowed("MIT and GPL-3.0", allowed), "lowercase 'and' must fail"
    assert not spdx_allowed("MIT or GPL-3.0", allowed), "lowercase 'or' must fail"
    assert not spdx_allowed("MIT GPL-3.0", allowed), "trailing token must fail"
    assert not spdx_allowed("(MIT OR Apache-2.0", allowed), "unclosed '(' must fail"
    assert not spdx_allowed("MIT OR Apache-2.0)", allowed), "trailing ')' must fail"
    assert not spdx_allowed("MIT WITH", allowed), "missing exception must fail"
    assert not spdx_allowed("", allowed), "empty expression must fail"

    text, problems = collect()
    assert not problems, f"unexpected license policy problems: {problems}"
    for stage, _, _ in STAGES:
        stage_pkg = f"[bootloader-x86_64-{stage}]"
        assert stage_pkg in text, f"missing bootloader stage root package {stage_pkg} in notices"
    assert "| [Rust standard library (core, alloc, compiler_builtins)](https://github.com/rust-lang/rust) | nightly (build-std) |" in text
    assert "does not require relicensing CuttleOS" in text
    print("third_party_notices self-test OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="fail if THIRD_PARTY_NOTICES.md is stale")
    parser.add_argument("--self-test", action="store_true", help="run unit and policy self-tests")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    text, problems = collect()
    if problems:
        print("License policy violations (not allowed by deny.toml, no exception):", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != text:
            print(f"{OUTPUT.name} is stale: run python tools/third_party_notices.py", file=sys.stderr)
            return 1
        print(f"{OUTPUT.name} is up to date")
        return 0
    OUTPUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
