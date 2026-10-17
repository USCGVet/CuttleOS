//! `factory_builder` — host-side packager that turns a verified kernel
//! ELF into a bootable disk image.
//!
//! The workspace-member library half exposes pure helpers (ELF-magic
//! validation, sha256-of-file, stdout formatting, kernel-build
//! shell-out) so the binary stays a thin argv-parser, and so the morph
//! engine can call `parse_image_line` to consume our stdout without
//! re-implementing the regex.
//!
//! ## Why packaging shells out
//!
//! The `bootloader = "0.11"` crate's build.rs spawns nested cargo
//! invocations with `-Z` flags that require nightly. The Proteus
//! workspace builds on stable, so we keep the heavy bootloader
//! dependency out of the workspace entirely: the sibling crate
//! `factory_builder_pkg/` (excluded from the workspace, pinned to
//! nightly via its own `rust-toolchain.toml`) owns that dep. This
//! workspace crate shells out to its binary when actual packaging is
//! requested.
//!
//! No silent fallbacks: every wrong input becomes an `anyhow::Error`
//! whose message names the failing path. The morph engine parses our
//! stdout success lines verbatim; the format is pinned by tests.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Magic bytes at offset 0 of every ELF file: 0x7F 'E' 'L' 'F'.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// stdout line prefix for the BIOS image record.
pub const STDOUT_BIOS_PREFIX: &str = "bios ";
/// stdout line prefix for the UEFI image record.
pub const STDOUT_UEFI_PREFIX: &str = "uefi ";

/// Name of the out-of-workspace sibling crate that owns the heavy
/// `bootloader = "0.11"` dependency. Resolved relative to this crate's
/// `CARGO_MANIFEST_DIR` (= `<workspace>/factory_builder/`) → goes one
/// directory up to `<workspace>/factory_builder_pkg/`.
pub const PKG_SIBLING_DIR: &str = "factory_builder_pkg";

/// Validate that `path` exists, is readable, and starts with the ELF
/// magic. Returns the path canonicalized to absolute form on success.
pub fn validate_elf(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        bail!("factory_builder: kernel ELF not found at {}", path.display());
    }
    let bytes = fs::read(path)
        .with_context(|| format!("factory_builder: read {}", path.display()))?;
    if bytes.len() < 4 || bytes[..4] != ELF_MAGIC {
        bail!(
            "factory_builder: {} is not an ELF file (magic mismatch)",
            path.display()
        );
    }
    let abs = fs::canonicalize(path)
        .with_context(|| format!("factory_builder: canonicalize {}", path.display()))?;
    Ok(abs)
}

/// Compute the SHA-256 of a file's bytes. Streams in 64 KiB chunks so we
/// don't materialize the whole image in RAM (BIOS images can be ~30 MiB).
pub fn sha256_of_file(path: &Path) -> Result<[u8; 32]> {
    let mut f = fs::File::open(path)
        .with_context(|| format!("factory_builder: open {} for sha256", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    use std::io::Read;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Lowercase-hex encoding of arbitrary bytes.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Format a single stdout success line: `<kind> <abs-path> <hex-sha256>`.
/// This is the format the morph engine parses. The function is exposed
/// (and tested) so the producer-consumer pair stays in sync.
pub fn format_image_line(kind: ImageKind, abs_path: &Path, sha256_hex: &str) -> String {
    let prefix = match kind {
        ImageKind::Bios => STDOUT_BIOS_PREFIX,
        ImageKind::Uefi => STDOUT_UEFI_PREFIX,
    };
    format!("{}{} {}", prefix, abs_path.display(), sha256_hex)
}

/// Parse a single stdout success line back into its three components.
/// Used by the morph engine's deploy-stage glue and by unit tests.
pub fn parse_image_line(line: &str) -> Result<(ImageKind, PathBuf, String)> {
    let (kind, rest) = if let Some(r) = line.strip_prefix(STDOUT_BIOS_PREFIX) {
        (ImageKind::Bios, r)
    } else if let Some(r) = line.strip_prefix(STDOUT_UEFI_PREFIX) {
        (ImageKind::Uefi, r)
    } else {
        bail!("factory_builder: stdout line has no bios/uefi prefix: {:?}", line);
    };
    // sha256 is the *last* space-separated token (path can contain
    // spaces on Windows like "C:\Program Files\...").
    let trimmed = rest.trim_end();
    let space = trimmed.rfind(' ').ok_or_else(|| {
        anyhow::anyhow!("factory_builder: stdout line missing sha256 token: {:?}", line)
    })?;
    let path = PathBuf::from(&trimmed[..space]);
    let sha = trimmed[space + 1..].to_string();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!(
            "factory_builder: stdout line sha256 token isn't 64 hex chars: {:?}",
            sha
        );
    }
    Ok((kind, path, sha))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Bios,
    Uefi,
}

impl ImageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ImageKind::Bios => "bios",
            ImageKind::Uefi => "uefi",
        }
    }
}

/// Locate the out-of-workspace `factory_builder_pkg/` crate directory.
/// Resolves it relative to the workspace root inferred from
/// `CARGO_MANIFEST_DIR` of this crate at compile time. Falls back to
/// `../factory_builder_pkg` relative to the current exe if that env var
/// is missing (e.g. when this lib is invoked from a release build).
pub fn locate_pkg_crate() -> Result<PathBuf> {
    // Compile-time discovery: `CARGO_MANIFEST_DIR` is set by Cargo for
    // *this* crate during `cargo build`, so it ends up baked into the
    // compiled lib. At runtime we use it as the anchor.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let parent = Path::new(manifest_dir)
        .parent()
        .context("CARGO_MANIFEST_DIR has no parent")?;
    let pkg = parent.join(PKG_SIBLING_DIR);
    if pkg.exists() {
        return Ok(pkg);
    }
    bail!(
        "factory_builder: out-of-workspace sibling crate not found at {}",
        pkg.display()
    );
}

/// Run `factory_builder_pkg`'s binary against the kernel ELF and capture
/// the produced image paths. This is the high-level packaging entry
/// point used by both the CLI and the morph engine.
///
/// `pkg_crate_dir` is the path to the out-of-workspace
/// `factory_builder_pkg/` crate. Pass `locate_pkg_crate()?` as the
/// default. Separated for testability.
pub fn package_kernel_via_pkg(
    pkg_crate_dir: &Path,
    kernel_elf: &Path,
    bios_out: &Path,
    uefi_out: Option<&Path>,
) -> Result<Vec<(ImageKind, PathBuf, String)>> {
    if let Some(parent) = bios_out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("factory_builder: create parent dir {}", parent.display())
            })?;
        }
    }
    let manifest = pkg_crate_dir.join("Cargo.toml");
    if !manifest.exists() {
        bail!(
            "factory_builder: factory_builder_pkg manifest missing at {} \
             (out-of-workspace crate not initialised?)",
            manifest.display()
        );
    }
    let mut cmd = Command::new("cargo");
    // Same rationale as in `build_kernel`: set CWD inside the pkg
    // crate so its `rust-toolchain.toml` (nightly) wins over the
    // parent process's toolchain selection.
    cmd.current_dir(pkg_crate_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO_TARGET_DIR")
        .arg("run")
        .arg("--release")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--")
        .arg("--candidate")
        .arg(kernel_elf)
        .arg("--out")
        .arg(bios_out);
    if let Some(u) = uefi_out {
        cmd.arg("--uefi").arg(u);
    }
    eprintln!(
        "factory_builder: invoking {} via cargo run --manifest-path {}",
        PKG_SIBLING_DIR,
        manifest.display()
    );
    let output = cmd
        .output()
        .with_context(|| format!("spawn cargo run for {}", manifest.display()))?;
    if !output.status.success() {
        bail!(
            "factory_builder: factory_builder_pkg failed (exit {:?})\n--- stderr ---\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // factory_builder_pkg prints exactly the same line format we use
    // ourselves: `<kind> <abs-path>` (one per image). It does NOT
    // compute sha256 — we do that here so the canonical hash is
    // computed in one place. Parsing accepts either the two-token form
    // (just kind + path) or the three-token form (kind + path + sha).
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (kind, path) = parse_pkg_output_line(line)?;
        let sha = hex(&sha256_of_file(&path)?);
        let abs = fs::canonicalize(&path)
            .with_context(|| format!("canonicalize {}", path.display()))?;
        out.push((kind, abs, sha));
    }
    if out.is_empty() {
        bail!("factory_builder: factory_builder_pkg produced no image lines on stdout");
    }
    Ok(out)
}

/// Parse a line emitted by `factory_builder_pkg`: `bios <path>` or
/// `uefi <path>`. The pkg crate's job is to produce the image only —
/// sha256 is computed by this crate so the canonical hash is computed
/// exactly once.
pub fn parse_pkg_output_line(line: &str) -> Result<(ImageKind, PathBuf)> {
    let (kind, rest) = if let Some(r) = line.strip_prefix(STDOUT_BIOS_PREFIX) {
        (ImageKind::Bios, r)
    } else if let Some(r) = line.strip_prefix(STDOUT_UEFI_PREFIX) {
        (ImageKind::Uefi, r)
    } else {
        bail!("factory_builder: pkg output line missing prefix: {:?}", line);
    };
    Ok((kind, PathBuf::from(rest.trim())))
}

/// Invoke `cargo build --release --manifest-path <kernel-crate>/Cargo.toml`
/// against an out-of-workspace kernel crate and return the absolute path
/// to the produced ELF.
///
/// The kernel crate is expected to be a `bin` crate whose package name is
/// `target_enterprise_kernel` and which builds for `x86_64-unknown-none`
/// (the `.cargo/config.toml` inside the crate pins the target). The ELF
/// lands under
/// `<kernel-crate>/target/x86_64-unknown-none/release/target_enterprise_kernel`.
pub fn build_kernel(kernel_crate_dir: &Path) -> Result<PathBuf> {
    build_kernel_with_layout_seed(kernel_crate_dir, None)
}

/// Compose the RUSTFLAGS for a layout-seeded kernel build.
///
/// Two cheap, surface-neutral codegen-diversity levers driven by the one
/// recorded seed: (1) `-Zrandomize-layout` reorders #[repr(Rust)] type
/// fields (perturbs some load/store encodings); (2) `-Zfunction-sections`
/// + LLD `--shuffle-sections` permute the order of functions in `.text`
/// (the glob form `.text*=<seed>` is required; the bare `=<seed>` form is
/// silently ignored by current rust-lld). Both leave gadget *count*
/// essentially unchanged; they are positional entropy. Intra-function
/// instruction-mix entropy is a separate (post-link) lever.
///
/// The shuffle seed is the layout seed truncated to 32 bits: rust-lld's
/// `--shuffle-sections` parser rejects values above `i64::MAX` with
/// "expected an integer" (observed on the pinned nightly's rust-lld with
/// the cycle-derived seed `14112513078648262138`), so passing the full
/// u64 makes roughly half of all derived seeds fail to link. 32 bits is
/// safely inside every signed parse width and loses nothing that matters
/// for a section-permutation seed. `-Zlayout-seed` keeps the full u64 —
/// rustc parses it unsigned.
pub fn kernel_diversity_rustflags(base: &str, seed: u64) -> String {
    let shuffle_seed = seed as u32;
    format!(
        "{base} -Zrandomize-layout=yes -Zlayout-seed={seed} \
         -Zfunction-sections=yes -Clink-arg=--shuffle-sections=.text*={shuffle_seed}"
    )
    .trim()
    .to_string()
}

/// Deterministic, seed-derived LLVM backend codegen perturbation flags
/// (`--inline-threshold`, `--unroll-threshold`, `--regalloc-csr-first-time-cost`,
/// `--x86-cmov-converter`).
///
/// Because `target_enterprise_kernel` compiles with `-Z build-std=core,compiler_builtins,alloc`,
/// these flags diversify register allocation, callee-saved register pressure
/// (`push`/`pop` epilogue gadget shapes), loop unrolling, and call-graph
/// inlining across 100% of `.text` (including `core` and `alloc`), while
/// remaining 100% reproducible from the recorded `seed`.
pub fn kernel_llvm_codegen_rustflags(seed: u64) -> String {
    const INLINE_THRESHOLDS: [u32; 8] = [50, 110, 175, 225, 285, 350, 425, 500];
    const UNROLL_THRESHOLDS: [u32; 6] = [40, 80, 150, 225, 300, 400];
    const CSR_COSTS: [u32; 8] = [0, 3, 7, 12, 18, 25, 35, 50];

    let mut hasher = Sha256::new();
    hasher.update(b"proteus-llvm-codegen-v1");
    hasher.update(seed.to_le_bytes());
    let d = hasher.finalize();

    let inline_thr = INLINE_THRESHOLDS[(d[0] as usize) % INLINE_THRESHOLDS.len()];
    let unroll_thr = UNROLL_THRESHOLDS[(d[1] as usize) % UNROLL_THRESHOLDS.len()];
    let csr_cost = CSR_COSTS[(d[2] as usize) % CSR_COSTS.len()];
    let cmov_conv = if d[3] & 1 == 0 { "true" } else { "false" };

    format!(
        "-Cllvm-args=--inline-threshold={inline_thr} \
         -Cllvm-args=--unroll-threshold={unroll_thr} \
         -Cllvm-args=--regalloc-csr-first-time-cost={csr_cost} \
         -Cllvm-args=--x86-cmov-converter={cmov_conv}"
    )
}

/// Like [`build_kernel`], but when `layout_seed` is `Some(n)` the kernel
/// (and its build-std dependencies) are compiled with
/// `-Zrandomize-layout=yes -Zlayout-seed=n` plus a `.text*` section
/// shuffle — see [`kernel_diversity_rustflags`] for the exact flags and
/// the 32-bit shuffle-seed truncation. This is the Phase-1 codegen
/// diversity lever: a per-cycle, *reproducible* (seed recorded in the
/// attestation) randomization that relocates functions and perturbs some
/// instruction encodings across the whole image, with no growth in gadget
/// count. `None` preserves the historical deterministic build exactly —
/// tests and the QEMU smoke path use that.
pub fn build_kernel_with_layout_seed(
    kernel_crate_dir: &Path,
    layout_seed: Option<u64>,
) -> Result<PathBuf> {
    build_kernel_with_layout_seed_and_prod(kernel_crate_dir, layout_seed, false)
}

/// Like [`build_kernel_with_layout_seed`], but `prod = true` appends
/// `--cfg proteus_prod` to RUSTFLAGS, compiling out the kernel's banner
/// self-proof suite and the planted red-team attack harness (see the
/// crate header in `target_enterprise_kernel/src/main.rs`). The kernel
/// crate's `[lints.rust] unexpected_cfgs` check-cfg entry already
/// whitelists the cfg, so no extra lint flags are needed here.
pub fn build_kernel_with_layout_seed_and_prod(
    kernel_crate_dir: &Path,
    layout_seed: Option<u64>,
    prod: bool,
) -> Result<PathBuf> {
    let manifest = kernel_crate_dir.join("Cargo.toml");
    if !manifest.exists() {
        bail!(
            "factory_builder: no Cargo.toml at {}",
            manifest.display()
        );
    }
    eprintln!(
        "factory_builder: building kernel crate at {}",
        manifest.display()
    );
    // CRITICAL: we set `current_dir` to the kernel crate before
    // invoking cargo. Cargo looks for `.cargo/config.toml` and
    // `rust-toolchain.toml` by walking up from the CWD, not from the
    // `--manifest-path` argument. Without this, the kernel's bare-
    // metal target (`x86_64-unknown-none`) and nightly-only build-std
    // flags would be silently dropped and cargo would try to link
    // against MSVC for the host target. We also clear `RUSTUP_TOOLCHAIN`
    // (set by the parent test runner) so rust-toolchain.toml wins.
    let mut cmd = Command::new("cargo");
    cmd.current_dir(kernel_crate_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO_TARGET_DIR")
        .arg("build")
        .arg("--release")
        .arg("--manifest-path")
        .arg(&manifest);
    // Compose RUSTFLAGS once from the inherited base: diversity levers
    // for a layout seed, then the prod cfg. Building the string in one
    // place avoids each lever clobbering the other's flags.
    let mut rustflags = std::env::var("RUSTFLAGS").unwrap_or_default();
    if let Some(seed) = layout_seed {
        // Append to any inherited RUSTFLAGS rather than clobber. The seed
        // must be explicit: `-Zrandomize-layout` without a fixed seed picks
        // a non-reproducible per-build value, which would make attestation
        // un-replayable.
        rustflags = kernel_diversity_rustflags(&rustflags, seed);
        let llvm_flags = kernel_llvm_codegen_rustflags(seed);
        rustflags = format!("{rustflags} {llvm_flags}").trim().to_string();
        cmd.env("PROTEUS_VARIANT_SEED", seed.to_string());
        eprintln!(
            "factory_builder: kernel codegen diversity enabled (seed={seed}: layout-randomize + function-shuffle + llvm-codegen [{llvm_flags}])"
        );
    }
    if prod {
        rustflags = format!("{rustflags} --cfg proteus_prod").trim().to_string();
        eprintln!("factory_builder: production kernel build (banner suite + attack harness stripped)");
    }
    if layout_seed.is_some() || prod {
        // Because `-Zlayout-seed=<seed>` changes `RUSTFLAGS` on every cycle,
        // Cargo computes a fresh crate metadata hash each cycle and would
        // otherwise accumulate hundreds of old `.rlib`/`.rmeta` copies in
        // `target/x86_64-unknown-none/release/deps/`. Wipe `deps/` and
        // `incremental/` before a seeded build so disk usage stays flat.
        let rel_dir = kernel_crate_dir
            .join("target")
            .join("x86_64-unknown-none")
            .join("release");
        let _ = fs::remove_dir_all(rel_dir.join("deps"));
        let _ = fs::remove_dir_all(rel_dir.join("incremental"));
        let _ = fs::remove_dir_all(rel_dir.join(".fingerprint"));
        cmd.env("RUSTFLAGS", rustflags);
    }
    let status = cmd
        .status()
        .with_context(|| format!("spawn cargo for kernel build at {}", manifest.display()))?;
    if !status.success() {
        bail!(
            "factory_builder: cargo build failed for kernel crate at {}",
            manifest.display()
        );
    }
    let elf = kernel_crate_dir
        .join("target")
        .join("x86_64-unknown-none")
        .join("release")
        .join("target_enterprise_kernel");
    if !elf.exists() {
        let alt = kernel_crate_dir
            .join("target")
            .join("release")
            .join("target_enterprise_kernel");
        if alt.exists() {
            return Ok(fs::canonicalize(alt)?);
        }
        bail!(
            "factory_builder: built kernel but ELF not found at {}",
            elf.display()
        );
    }
    Ok(fs::canonicalize(elf)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ---- kernel_diversity_rustflags ----

    #[test]
    fn diversity_rustflags_small_seed_full_width_everywhere() {
        let f = kernel_diversity_rustflags("", 7);
        assert_eq!(
            f,
            "-Zrandomize-layout=yes -Zlayout-seed=7 \
             -Zfunction-sections=yes -Clink-arg=--shuffle-sections=.text*=7"
        );
    }

    #[test]
    fn diversity_rustflags_preserves_base_flags() {
        let f = kernel_diversity_rustflags("-Cforce-frame-pointers=yes", 1);
        assert!(f.starts_with("-Cforce-frame-pointers=yes -Zrandomize-layout=yes"));
    }

    #[test]
    fn diversity_rustflags_truncates_shuffle_seed_above_i64_max() {
        // Regression for the cycle-derived seed that broke the link:
        // kernel_layout_seed(1) = 14112513078648262138 > i64::MAX, which
        // rust-lld's --shuffle-sections parser rejects ("expected an
        // integer"). -Zlayout-seed must keep the full value (rustc is
        // fine with it); the shuffle seed must be the low 32 bits.
        let seed: u64 = 14112513078648262138;
        let f = kernel_diversity_rustflags("", seed);
        assert!(
            f.contains("-Zlayout-seed=14112513078648262138"),
            "full-width layout seed must survive: {f}"
        );
        let expected_shuffle = seed as u32; // low 32 bits
        assert!(
            f.contains(&format!("--shuffle-sections=.text*={expected_shuffle}")),
            "shuffle seed must be truncated to u32 ({expected_shuffle}): {f}"
        );
        // And nowhere does the over-wide value reach the linker arg.
        assert!(
            !f.contains("--shuffle-sections=.text*=14112513078648262138"),
            "u64 shuffle seed would fail rust-lld: {f}"
        );
    }

    fn tmpdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "factory_builder_test_{}_{}",
            std::process::id(),
            rand_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn rand_nanos() -> u32 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    }

    #[test]
    fn elf_magic_constant_correct() {
        assert_eq!(&ELF_MAGIC, b"\x7FELF");
    }

    #[test]
    fn validate_elf_rejects_missing_file() {
        let bogus = PathBuf::from(
            "D:/RustProjects/Proteus/factory_builder/__definitely_missing_test_fixture__.elf",
        );
        let r = validate_elf(&bogus);
        assert!(r.is_err(), "expected missing-file error");
        let msg = format!("{:#}", r.unwrap_err());
        assert!(msg.contains("not found"), "msg was: {}", msg);
    }

    #[test]
    fn validate_elf_rejects_empty_file() {
        let dir = tmpdir();
        let p = dir.join("empty.bin");
        fs::write(&p, []).unwrap();
        let r = validate_elf(&p);
        assert!(r.is_err());
        let msg = format!("{:#}", r.unwrap_err());
        assert!(msg.contains("not an ELF"), "msg was: {}", msg);
    }

    #[test]
    fn validate_elf_rejects_random_bytes() {
        let dir = tmpdir();
        let p = dir.join("random.bin");
        fs::write(&p, b"MZ\x90\x00not-an-elf-at-all").unwrap();
        let r = validate_elf(&p);
        assert!(r.is_err());
        assert!(format!("{:#}", r.unwrap_err()).contains("magic mismatch"));
    }

    #[test]
    fn validate_elf_accepts_magic_prefix() {
        let dir = tmpdir();
        let p = dir.join("magic.bin");
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(&ELF_MAGIC).unwrap();
        f.write_all(&[0; 64]).unwrap();
        let r = validate_elf(&p);
        assert!(
            r.is_ok(),
            "validate_elf rejected a 4-byte-ELF-magic file: {:?}",
            r
        );
    }

    #[test]
    fn sha256_known_vector() {
        let dir = tmpdir();
        let p = dir.join("hello.txt");
        fs::write(&p, b"hello").unwrap();
        let h = sha256_of_file(&p).unwrap();
        assert_eq!(
            hex(&h),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn hex_round_trip() {
        let bytes: [u8; 4] = [0x00, 0x0f, 0xff, 0xab];
        assert_eq!(hex(&bytes), "000fffab");
    }

    #[test]
    fn format_and_parse_image_line_round_trip_bios() {
        let path = PathBuf::from("D:/img/proteus-bios.img");
        let sha = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let line = format_image_line(ImageKind::Bios, &path, sha);
        assert!(line.starts_with(STDOUT_BIOS_PREFIX));
        let (k, p, s) = parse_image_line(&line).expect("parse");
        assert_eq!(k, ImageKind::Bios);
        assert_eq!(p, path);
        assert_eq!(s, sha);
    }

    #[test]
    fn format_and_parse_image_line_round_trip_uefi_with_spaces() {
        let path = PathBuf::from("C:/Program Files/Proteus/uefi image.img");
        let sha = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let line = format_image_line(ImageKind::Uefi, &path, sha);
        let (k, p, s) = parse_image_line(&line).expect("parse");
        assert_eq!(k, ImageKind::Uefi);
        assert_eq!(p, path);
        assert_eq!(s, sha);
    }

    #[test]
    fn parse_image_line_rejects_bad_prefix() {
        let r = parse_image_line("oops C:/foo abcd");
        assert!(r.is_err());
    }

    #[test]
    fn parse_image_line_rejects_bad_sha() {
        let r = parse_image_line(
            "bios C:/foo NOT_VALID_HEX_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        );
        assert!(r.is_err());
    }

    #[test]
    fn parse_image_line_rejects_short_sha() {
        let r = parse_image_line("bios C:/foo deadbeef");
        assert!(r.is_err());
    }

    #[test]
    fn parseable_stdout_format_regex() {
        // Pinned format: `^(bios|uefi) .+ [0-9a-f]{64}$`.
        let path = PathBuf::from("D:/proteus/target/bios.img");
        let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let line = format_image_line(ImageKind::Bios, &path, sha);
        assert!(line.starts_with("bios ") || line.starts_with("uefi "));
        let tail = line.split_whitespace().last().unwrap();
        assert_eq!(tail.len(), 64);
        assert!(tail.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn parse_pkg_output_line_two_token() {
        let (k, p) = parse_pkg_output_line("bios D:/foo/bar.img").unwrap();
        assert_eq!(k, ImageKind::Bios);
        assert_eq!(p, PathBuf::from("D:/foo/bar.img"));
    }

    #[test]
    fn parse_pkg_output_line_uefi() {
        let (k, p) = parse_pkg_output_line("uefi D:/foo/bar.img").unwrap();
        assert_eq!(k, ImageKind::Uefi);
        assert_eq!(p, PathBuf::from("D:/foo/bar.img"));
    }

    #[test]
    fn parse_pkg_output_line_rejects_unknown_prefix() {
        let r = parse_pkg_output_line("disk D:/foo.img");
        assert!(r.is_err());
    }

    #[test]
    fn image_kind_as_str() {
        assert_eq!(ImageKind::Bios.as_str(), "bios");
        assert_eq!(ImageKind::Uefi.as_str(), "uefi");
    }
}
