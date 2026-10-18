//! TASK-124 — attestation schema v9: `diversity` evidence fields.
//!
//! Load-bearing properties:
//! 1. SCHEMA_VERSION >= 9
//! 2. write_attestation auto-fills diversity from diversifier_log
//! 3. explicit DiversityEvidence (incl. ELF metrics) survives round-trip
//! 4. verify_chain accepts diversity and rejects malformed bps/hex
//! 5. pre-v9 entries without diversity still verify (legacy)
//! 6. None is skip_serialized (pre-v9 hash stability)

use cuttle_morph_engine::attest::{
    self, compute_entry_sha256, load_entries, verify_chain, verify_chain_with_options,
    write_attestation, AttestEntry, AttestEntryFields, DiversityEvidence, DiversifierLog,
    VerifyOptions, ATTEST_DIR_ENV, READABLE_MIN_SCHEMA, SCHEMA_VERSION, ZERO_HEX,
};
use cuttle_morph_engine::{
    diversity_from_diversifier_log, diversity_from_elf_pair, diversity_merge, rate_to_bps,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn fresh_tempdir(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "cuttle_attest_v9_test_{}_{}_{}_{}",
        label,
        std::process::id(),
        nanos,
        n,
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    dir: PathBuf,
}

impl EnvGuard {
    fn new(label: &str) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = fresh_tempdir(label);
        unsafe {
            std::env::set_var(ATTEST_DIR_ENV, &dir);
        }
        Self { _lock: lock, dir }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var(ATTEST_DIR_ENV);
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn base_fields(cycle: u64) -> AttestEntryFields {
    AttestEntryFields {
        cycle,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
        sig_ed25519: "00".repeat(64),
        accepted: true,
        synthesizer: "passthrough".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: Vec::new(),
        federation_threshold: None,
        factory_binaries: BTreeMap::new(),
        bundle_name: None,
        modules: BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: None,
        diversity: None,
    durable_seals: std::collections::BTreeMap::new(),
    signing_key: None,
    }
}

#[test]
fn schema_v9_floor() {
    assert!(SCHEMA_VERSION >= 9);
    assert_eq!(READABLE_MIN_SCHEMA, 3);
}

#[test]
fn write_auto_fills_diversity_from_diversifier_log() {
    let _g = EnvGuard::new("autofill_div");
    let mut log = DiversifierLog::default();
    log.pad_decisions.insert("f".into(), 64);
    log.pad_decisions.insert("g".into(), 96);
    log.perturb_decisions
        .insert("f".into(), "inline-never".into());

    let mut f = base_fields(1);
    f.diversifier_log = Some(log);
    f.kernel_layout_seed = Some(0xdead_beef);
    write_attestation(f).unwrap();

    let entries = load_entries().unwrap();
    assert_eq!(entries.len(), 1);
    let d = entries[0]
        .diversity
        .as_ref()
        .expect("diversity auto-filled");
    assert_eq!(d.pad_decision_count, Some(2));
    assert_eq!(d.perturb_decision_count, Some(1));
    assert_eq!(d.layout_seed, Some(0xdead_beef));
    // No ELF metrics without emit path.
    assert!(d.base_text_sha256.is_none());
    assert!(d.positional_survival_bps.is_none());

    let rep = verify_chain().unwrap();
    assert_eq!(rep.entries_ok, 1);
}

#[test]
fn write_explicit_elf_diversity_and_verify() {
    let _g = EnvGuard::new("elf_div");
    let evidence = DiversityEvidence {
        base_text_sha256: Some("aa".repeat(32)),
        variant_text_sha256: Some("bb".repeat(32)),
        positional_survival_bps: Some(42),
        semantic_survival_norm_bps: Some(8750),
        layout_seed: Some(0x1234),
        pad_decision_count: Some(10),
        perturb_decision_count: Some(9),
    };
    assert!(evidence.has_elf_metrics());

    let mut f = base_fields(1);
    f.diversity = Some(evidence.clone());
    write_attestation(f).unwrap();

    let entries = load_entries().unwrap();
    let d = entries[0].diversity.as_ref().unwrap();
    assert_eq!(d, &evidence);
    assert_eq!(d.positional_survival_bps, Some(42));
    assert_eq!(d.variant_text_sha256.as_ref().unwrap().len(), 64);

    let rep = verify_chain_with_options(&VerifyOptions {
        require_ext_tlv: true,
        ..VerifyOptions::default()
    })
    .unwrap();
    assert_eq!(rep.entries_ok, 1);
}

#[test]
fn verify_rejects_malformed_diversity_bps() {
    let _g = EnvGuard::new("bad_bps");
    let mut e = AttestEntry {
        schema_version: 9, // pinned: v11+ entries require a real signature to verify
        cycle: 1,
        ts_unix: 1_700_000_000,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
        sig_ed25519: "00".repeat(64),
        accepted: true,
        synthesizer: "passthrough".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: Vec::new(),
        federation_threshold: None,
        factory_binaries: BTreeMap::new(),
        bundle_name: None,
        modules: BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: Some(
            cuttle_morph_engine::build_ext_tlv_b64(
                1,
                "lib",
                "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8",
            )
            .unwrap(),
        ),
        diversity: Some(DiversityEvidence {
            positional_survival_bps: Some(12_000), // invalid
            ..Default::default()
        }),
        durable_seals: BTreeMap::new(),
        prev_entry_sha256: ZERO_HEX.to_string(),
        entry_sha256: String::new(),
    };
    e.entry_sha256 = {
        let h = compute_entry_sha256(&e).unwrap();
        h.iter().map(|b| format!("{:02x}", b)).collect()
    };
    let path = _g.dir.join(attest::ATTEST_LOG);
    fs::write(&path, serde_json::to_string(&e).unwrap() + "\n").unwrap();

    let err = verify_chain().unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("diversity") || msg.contains("10000") || msg.contains("bps"),
        "unexpected err: {msg}"
    );
}

#[test]
fn legacy_without_diversity_still_verifies() {
    let _g = EnvGuard::new("legacy");
    // schema 8-style entry: no diversity field (skip_serializing).
    let mut e = AttestEntry {
        schema_version: 8,
        cycle: 1,
        ts_unix: 1_700_000_000,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
        sig_ed25519: "00".repeat(64),
        accepted: true,
        synthesizer: "passthrough".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: Vec::new(),
        federation_threshold: None,
        factory_binaries: BTreeMap::new(),
        bundle_name: None,
        modules: BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: Some(
            cuttle_morph_engine::build_ext_tlv_b64(
                1,
                "lib",
                "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8",
            )
            .unwrap(),
        ),
        diversity: None,
        durable_seals: std::collections::BTreeMap::new(),
        prev_entry_sha256: ZERO_HEX.to_string(),
        entry_sha256: String::new(),
    };
    e.entry_sha256 = {
        let h = compute_entry_sha256(&e).unwrap();
        h.iter().map(|b| format!("{:02x}", b)).collect()
    };
    let path = _g.dir.join(attest::ATTEST_LOG);
    fs::write(&path, serde_json::to_string(&e).unwrap() + "\n").unwrap();

    let rep = verify_chain().unwrap();
    assert_eq!(rep.entries_ok, 1);
}

#[test]
fn diversity_none_omitted_from_on_disk_json() {
    let e = AttestEntry {
        schema_version: SCHEMA_VERSION,
        cycle: 1,
        ts_unix: 1,
        module: "lib".into(),
        candidate_sha256: "aa".repeat(32),
        sig_ed25519: "00".repeat(64),
        accepted: true,
        synthesizer: "passthrough".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: Vec::new(),
        federation_threshold: None,
        factory_binaries: BTreeMap::new(),
        bundle_name: None,
        modules: BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: None,
        diversity: None,
        durable_seals: std::collections::BTreeMap::new(),
        prev_entry_sha256: ZERO_HEX.to_string(),
        entry_sha256: "bb".repeat(32),
    };
    let line = serde_json::to_string(&e).unwrap();
    assert!(
        !line.contains("\"diversity\""),
        "diversity:None must be omitted from JSON: {line}"
    );
    // Present when set.
    let mut e2 = e;
    e2.diversity = Some(DiversityEvidence {
        layout_seed: Some(1),
        ..Default::default()
    });
    let line2 = serde_json::to_string(&e2).unwrap();
    assert!(line2.contains("\"diversity\""), "expected diversity key");
    assert!(line2.contains("\"layout_seed\""));
}

#[test]
fn require_diversity_rejects_missing() {
    let _g = EnvGuard::new("req_div_missing");
    // Accepted entry without diversity (schema 8-style).
    let mut e = AttestEntry {
        schema_version: 8,
        cycle: 1,
        ts_unix: 1_700_000_000,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
        sig_ed25519: "00".repeat(64),
        accepted: true,
        synthesizer: "passthrough".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: Vec::new(),
        federation_threshold: None,
        factory_binaries: BTreeMap::new(),
        bundle_name: None,
        modules: BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: Some(
            cuttle_morph_engine::build_ext_tlv_b64(
                1,
                "lib",
                "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8",
            )
            .unwrap(),
        ),
        diversity: None,
        durable_seals: std::collections::BTreeMap::new(),
        prev_entry_sha256: ZERO_HEX.to_string(),
        entry_sha256: String::new(),
    };
    e.entry_sha256 = {
        let h = compute_entry_sha256(&e).unwrap();
        h.iter().map(|b| format!("{:02x}", b)).collect()
    };
    let path = _g.dir.join(attest::ATTEST_LOG);
    fs::write(&path, serde_json::to_string(&e).unwrap() + "\n").unwrap();

    // Default: no require_diversity → OK.
    verify_chain().unwrap();
    // Strict: must fail.
    let err = verify_chain_with_options(&VerifyOptions {
        require_diversity: true,
        ..VerifyOptions::default()
    })
    .unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("diversity") || msg.contains("require-diversity"),
        "unexpected: {msg}"
    );
}

#[test]
fn require_diversity_accepts_auto_filled() {
    let _g = EnvGuard::new("req_div_ok");
    let mut log = DiversifierLog::default();
    log.perturb_decisions
        .insert("f".into(), "inline-never".into());
    let mut f = base_fields(1);
    f.diversifier_log = Some(log);
    write_attestation(f).unwrap();
    let rep = verify_chain_with_options(&VerifyOptions {
        require_diversity: true,
        ..VerifyOptions::default()
    })
    .unwrap();
    assert_eq!(rep.entries_ok, 1);
}

#[test]
fn require_diversity_skips_rejected_entries() {
    let _g = EnvGuard::new("req_div_rej");
    // Rejected entry without diversity is OK under the gate.
    let mut e = AttestEntry {
        schema_version: 9, // pinned: v11+ entries require a real signature to verify
        cycle: 1,
        ts_unix: 1,
        module: "lib".into(),
        candidate_sha256: "aa".repeat(32),
        sig_ed25519: "00".repeat(64),
        accepted: false,
        synthesizer: "passthrough".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: Vec::new(),
        federation_threshold: None,
        factory_binaries: BTreeMap::new(),
        bundle_name: None,
        modules: BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: Some(
            cuttle_morph_engine::build_ext_tlv_b64(1, "lib", &"aa".repeat(32)).unwrap(),
        ),
        diversity: None,
        durable_seals: std::collections::BTreeMap::new(),
        prev_entry_sha256: ZERO_HEX.to_string(),
        entry_sha256: String::new(),
    };
    e.entry_sha256 = {
        let h = compute_entry_sha256(&e).unwrap();
        h.iter().map(|b| format!("{:02x}", b)).collect()
    };
    let path = _g.dir.join(attest::ATTEST_LOG);
    fs::write(&path, serde_json::to_string(&e).unwrap() + "\n").unwrap();
    verify_chain_with_options(&VerifyOptions {
        require_diversity: true,
        ..VerifyOptions::default()
    })
    .unwrap();
}

#[test]
fn helpers_rate_and_merge_smoke() {
    assert_eq!(rate_to_bps(0.05), 500);
    let a = diversity_from_diversifier_log(None, Some(9)).unwrap();
    assert_eq!(a.layout_seed, Some(9));
    let b = DiversityEvidence {
        positional_survival_bps: Some(1),
        ..Default::default()
    };
    let m = diversity_merge(a, b);
    assert_eq!(m.layout_seed, Some(9));
    assert_eq!(m.positional_survival_bps, Some(1));
}

#[test]
fn from_elf_pair_identical_files_full_survival() {
    // Tiny ELF64 with a few-byte .text (ret; nop; ret) — cheap to scan.
    let dir = fresh_tempdir("tiny_elf");
    let elf = dir.join("tiny.elf");
    fs::write(&elf, tiny_elf64_with_text(&[0xC3, 0x90, 0xC3])).expect("write elf");
    let d = diversity_from_elf_pair(&elf, &elf).expect("identical pair");
    assert!(d.has_elf_metrics());
    assert_eq!(d.base_text_sha256, d.variant_text_sha256);
    assert_eq!(d.positional_survival_bps, Some(10_000));
    assert_eq!(d.semantic_survival_norm_bps, Some(10_000));
    let _ = fs::remove_dir_all(&dir);
}

/// Minimal little-endian ELF64 with a single PROGBITS `.text` section.
fn tiny_elf64_with_text(text: &[u8]) -> Vec<u8> {
    // Layout: Ehdr (64) + Shdr[0] null (64) + Shdr[1] .text (64) + Shdr[2] .shstrtab (64)
    //         + shstrtab bytes + .text bytes
    const EH_SIZE: usize = 64;
    const SH_SIZE: usize = 64;
    let shoff = EH_SIZE;
    let shstrtab_off = EH_SIZE + 3 * SH_SIZE;
    let shstr = b"\0.text\0.shstrtab\0";
    let text_off = shstrtab_off + shstr.len();
    let mut out = vec![0u8; text_off + text.len()];

    // e_ident
    out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    out[4] = 2; // ELFCLASS64
    out[5] = 1; // ELFDATA2LSB
    out[6] = 1; // EV_CURRENT
    // e_type ET_REL
    out[16] = 1;
    // e_machine EM_X86_64
    out[18] = 62;
    // e_version
    out[20] = 1;
    // e_ehsize
    out[52] = EH_SIZE as u8;
    // e_shentsize
    out[58] = SH_SIZE as u8;
    // e_shnum = 3
    out[60] = 3;
    // e_shstrndx = 2
    out[62] = 2;
    // e_shoff
    out[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());

    // Shdr[1] .text — sh_name=1 (".text"), SHT_PROGBITS=1, SHF_EXECINSTR|ALLOC=6
    let sh1 = shoff + SH_SIZE;
    out[sh1..sh1 + 4].copy_from_slice(&1u32.to_le_bytes()); // name
    out[sh1 + 4..sh1 + 8].copy_from_slice(&1u32.to_le_bytes()); // type
    out[sh1 + 8..sh1 + 16].copy_from_slice(&6u64.to_le_bytes()); // flags
    out[sh1 + 24..sh1 + 32].copy_from_slice(&(text_off as u64).to_le_bytes()); // offset
    out[sh1 + 32..sh1 + 40].copy_from_slice(&(text.len() as u64).to_le_bytes()); // size

    // Shdr[2] .shstrtab — sh_name=7, SHT_STRTAB=3
    let sh2 = shoff + 2 * SH_SIZE;
    out[sh2..sh2 + 4].copy_from_slice(&7u32.to_le_bytes());
    out[sh2 + 4..sh2 + 8].copy_from_slice(&3u32.to_le_bytes());
    out[sh2 + 24..sh2 + 32].copy_from_slice(&(shstrtab_off as u64).to_le_bytes());
    out[sh2 + 32..sh2 + 40].copy_from_slice(&(shstr.len() as u64).to_le_bytes());

    out[shstrtab_off..shstrtab_off + shstr.len()].copy_from_slice(shstr);
    out[text_off..text_off + text.len()].copy_from_slice(text);
    out
}
