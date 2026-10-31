//! Attestation diversity evidence helpers (TASK-124 / schema v9).
//!
//! Builds [`DiversityEvidence`](crate::attest::DiversityEvidence) from:
//! 1. Source-side diversifier decision logs (always available on morph).
//! 2. Pairwise kernel ELF gadget churn via `cuttle_mtd_metrics` when
//!    base + variant binaries exist on disk.

use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::attest::{DiversityEvidence, DiversifierLog};

/// Convert a 0.0..=1.0 rate to basis points (0..=10_000), saturating.
pub fn rate_to_bps(rate: f64) -> u32 {
    if !rate.is_finite() {
        return 0;
    }
    let bps = (rate * 10_000.0).round();
    if bps <= 0.0 {
        0
    } else if bps >= 10_000.0 {
        10_000
    } else {
        bps as u32
    }
}

/// SHA-256 of the `.text` section of an ELF/PE/COFF at `path`.
pub fn text_sha256_of_elf(path: &Path) -> Result<String> {
    let (text, _ip) = cuttle_mtd_metrics::read_text_section(path)
        .with_context(|| format!("read .text from {}", path.display()))?;
    Ok(hex_sha256(&text))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Source-side evidence only: pad/perturb decision counts + optional
/// layout seed. Used for every morph cycle that has a diversifier log
/// even when no kernel ELF was built.
pub fn from_diversifier_log(
    log: Option<&DiversifierLog>,
    layout_seed: Option<u64>,
) -> Option<DiversityEvidence> {
    let (pad, perturb) = match log {
        Some(l) => (
            Some(l.pad_decisions.len() as u32),
            Some(l.perturb_decisions.len() as u32),
        ),
        None => (None, None),
    };
    let d = DiversityEvidence {
        base_text_sha256: None,
        variant_text_sha256: None,
        positional_survival_bps: None,
        semantic_survival_norm_bps: None,
        layout_seed,
        pad_decision_count: pad,
        perturb_decision_count: perturb,
        sbom_sha256: None,
    };
    if d.is_empty() {
        None
    } else {
        Some(d)
    }
}

/// Full gadget-churn measurement between two compiled artifacts.
///
/// Populates base/variant `.text` sha256 and positional / semantic
/// survival in basis points. Does not set diversifier counts or
/// layout_seed — callers merge with [`from_diversifier_log`].
pub fn from_elf_pair(base_elf: &Path, variant_elf: &Path) -> Result<DiversityEvidence> {
    let (base_text, base_ip) = cuttle_mtd_metrics::read_text_section(base_elf)
        .with_context(|| format!("read .text from base {}", base_elf.display()))?;
    let (var_text, var_ip) = cuttle_mtd_metrics::read_text_section(variant_elf)
        .with_context(|| format!("read .text from variant {}", variant_elf.display()))?;

    let base_text_sha256 = hex_sha256(&base_text);
    let variant_text_sha256 = hex_sha256(&var_text);

    let base_g = cuttle_mtd_metrics::extract_gadgets(
        &base_text,
        base_ip,
        cuttle_mtd_metrics::DEFAULT_MAX_INSTRS,
    );
    let var_g = cuttle_mtd_metrics::extract_gadgets(
        &var_text,
        var_ip,
        cuttle_mtd_metrics::DEFAULT_MAX_INSTRS,
    );
    let report = cuttle_mtd_metrics::churn(&base_g, &var_g);

    Ok(DiversityEvidence {
        base_text_sha256: Some(base_text_sha256),
        variant_text_sha256: Some(variant_text_sha256),
        positional_survival_bps: Some(rate_to_bps(report.positional_survival())),
        semantic_survival_norm_bps: Some(rate_to_bps(report.semantic_survival_normalized())),
        layout_seed: None,
        pad_decision_count: None,
        perturb_decision_count: None,
        sbom_sha256: None,
    })
}

/// Merge two evidence blobs: non-`None` fields in `overlay` win.
pub fn merge(base: DiversityEvidence, overlay: DiversityEvidence) -> DiversityEvidence {
    DiversityEvidence {
        base_text_sha256: overlay.base_text_sha256.or(base.base_text_sha256),
        variant_text_sha256: overlay
            .variant_text_sha256
            .or(base.variant_text_sha256),
        positional_survival_bps: overlay
            .positional_survival_bps
            .or(base.positional_survival_bps),
        semantic_survival_norm_bps: overlay
            .semantic_survival_norm_bps
            .or(base.semantic_survival_norm_bps),
        layout_seed: overlay.layout_seed.or(base.layout_seed),
        pad_decision_count: overlay.pad_decision_count.or(base.pad_decision_count),
        perturb_decision_count: overlay
            .perturb_decision_count
            .or(base.perturb_decision_count),
        sbom_sha256: overlay.sbom_sha256.or(base.sbom_sha256),
    }
}

/// Validate structural sanity of diversity fields (used by verify-attest).
/// Does not re-measure binaries — only checks hex lengths and bps range.
pub fn validate_evidence(d: &DiversityEvidence) -> Result<()> {
    for (name, v) in [
        ("base_text_sha256", &d.base_text_sha256),
        ("variant_text_sha256", &d.variant_text_sha256),
        ("sbom_sha256", &d.sbom_sha256),
    ] {
        if let Some(h) = v {
            if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                anyhow::bail!("diversity.{name}: expected 64-char hex, got len={}", h.len());
            }
        }
    }
    for (name, v) in [
        ("positional_survival_bps", d.positional_survival_bps),
        ("semantic_survival_norm_bps", d.semantic_survival_norm_bps),
    ] {
        if let Some(bps) = v {
            if bps > 10_000 {
                anyhow::bail!("diversity.{name}={bps} > 10000");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn rate_to_bps_edges() {
        assert_eq!(rate_to_bps(0.0), 0);
        assert_eq!(rate_to_bps(1.0), 10_000);
        assert_eq!(rate_to_bps(0.05), 500);
        assert_eq!(rate_to_bps(0.0523), 523);
        assert_eq!(rate_to_bps(f64::NAN), 0);
    }

    #[test]
    fn from_diversifier_counts() {
        let mut log = DiversifierLog::default();
        log.pad_decisions.insert("a".into(), 64);
        log.pad_decisions.insert("b".into(), 96);
        log.perturb_decisions
            .insert("a".into(), "inline-never".into());
        let d = from_diversifier_log(Some(&log), Some(0xabc)).unwrap();
        assert_eq!(d.pad_decision_count, Some(2));
        assert_eq!(d.perturb_decision_count, Some(1));
        assert_eq!(d.layout_seed, Some(0xabc));
        assert!(d.base_text_sha256.is_none());
    }

    #[test]
    fn from_empty_is_none() {
        assert!(from_diversifier_log(None, None).is_none());
        assert!(from_diversifier_log(Some(&DiversifierLog::default()), None).is_some());
        // empty maps still yield Some(0,0) counts — useful signal that
        // diversifier ran with zero decisions. But Default log is empty maps.
        let d = from_diversifier_log(Some(&DiversifierLog::default()), None).unwrap();
        assert_eq!(d.pad_decision_count, Some(0));
        assert_eq!(d.perturb_decision_count, Some(0));
    }

    #[test]
    fn merge_prefers_overlay() {
        let a = DiversityEvidence {
            layout_seed: Some(1),
            pad_decision_count: Some(3),
            ..Default::default()
        };
        let b = DiversityEvidence {
            layout_seed: Some(2),
            variant_text_sha256: Some("aa".repeat(32)),
            ..Default::default()
        };
        let m = merge(a, b);
        assert_eq!(m.layout_seed, Some(2));
        assert_eq!(m.pad_decision_count, Some(3));
        assert_eq!(m.variant_text_sha256.as_ref().map(|s| s.len()), Some(64));
    }

    #[test]
    fn validate_rejects_bad_hex() {
        let d = DiversityEvidence {
            base_text_sha256: Some("deadbeef".into()),
            ..Default::default()
        };
        assert!(validate_evidence(&d).is_err());
    }

    #[test]
    fn validate_rejects_bps_overflow() {
        let d = DiversityEvidence {
            positional_survival_bps: Some(10_001),
            ..Default::default()
        };
        assert!(validate_evidence(&d).is_err());
    }

    #[test]
    fn validate_ok_full() {
        let d = DiversityEvidence {
            base_text_sha256: Some("ab".repeat(32)),
            variant_text_sha256: Some("cd".repeat(32)),
            positional_survival_bps: Some(42),
            semantic_survival_norm_bps: Some(9000),
            layout_seed: Some(1),
            pad_decision_count: Some(10),
            perturb_decision_count: Some(10),
            sbom_sha256: Some("ef".repeat(32)),
        };
        validate_evidence(&d).unwrap();
        assert!(d.satisfies_require());
    }

    #[test]
    fn satisfies_require_layout_only() {
        let d = DiversityEvidence {
            layout_seed: Some(1),
            ..Default::default()
        };
        assert!(d.satisfies_require());
        assert!(!DiversityEvidence::default().satisfies_require());
    }

    #[test]
    fn identical_elf_pair_is_full_survival() {
        // Minimal COFF/PE or ELF isn't required: use two copies of a
        // tiny hand-built x86-64 .text blob via a temp object is heavy.
        // Instead unit-test churn rates through mtd_metrics gadget sets
        // and bps conversion consistency.
        use cuttle_mtd_metrics::GadgetSet;
        let mut g = GadgetSet::default();
        g.by_offset.insert(0, "pop rax ; ret".into());
        g.by_offset.insert(8, "pop rbx ; ret".into());
        let r = cuttle_mtd_metrics::churn(&g, &g);
        assert_eq!(rate_to_bps(r.positional_survival()), 10_000);
        let _ = BTreeMap::<String, u32>::new();
    }
}
