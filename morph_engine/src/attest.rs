//! Tamper-evident attestation log (schema v3).
//!
//! Every entry in `attest.log.jsonl` is hash-chained: it carries the
//! SHA-256 of its own canonical JSON (`entry_sha256`) and the
//! `entry_sha256` of the previous entry (`prev_entry_sha256`). Modifying
//! entry N invalidates the chain from N onward; inserting or reordering
//! entries breaks the `prev_entry_sha256` link.
//!
//! Every `ANCHOR_INTERVAL` (= 10) entries the writer emits a Merkle root
//! over those 10 entries' `entry_sha256` values to a separate
//! `merkle_anchors.jsonl` file. Anchors themselves chain via
//! `prev_anchor_merkle_root`. The motivating threat: an attacker with
//! filesystem write but without the factory signing key can rewrite the
//! attestation log; the Merkle anchor file (designed to be replicated to
//! external immutable storage) makes such rewrites detectable.
//!
//! ## Schema migration policy
//!
//! - Pre-v2 entries lack a `schema_version` field. On the first v3 write,
//!   if the existing `attest.log.jsonl` is present and its last entry does
//!   NOT have `schema_version`, we rename it to `attest.log.v1.jsonl.bak`
//!   and start a fresh log.
//! - v2 entries have `schema_version=2` but no `cosignatures` /
//!   `federation_threshold`. On the first v3 write, if the existing log's
//!   last entry has `schema_version=2`, we rename it to
//!   `attest.log.v2.jsonl.bak` and start a fresh v3 log. Same for
//!   `merkle_anchors.jsonl`.
//!
//! Old logs are preserved on disk but not chained into v3. This matches
//! the design decision in the brief: don't try to upgrade in place — keep
//! audit logic simple.
//!
//! ## Canonical JSON
//!
//! For `entry_sha256` and `merkle_root` to be reproducible, the JSON
//! over which they are hashed must be canonical. We hand-roll a
//! key-sorted, whitespace-free encoder rather than pull in a
//! canonicalization crate. The string encoder handles the JSON-mandated
//! escapes (`\\`, `\"`, control chars). Numeric values are emitted as
//! integers (`u64` / `i64`) or booleans only — we never put f64 in an
//! attestation entry, so we never have to worry about float
//! canonicalization.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::factory::{self, FactoryExpected};
use crate::federation::{self, Cosignature, FederationConfig};
use crate::merkle;

/// Every Nth entry, emit a Merkle anchor. Constant — changing this is a
/// schema-affecting change (anchors built under a different interval
/// won't verify).
pub const ANCHOR_INTERVAL: u64 = 10;

/// Current attestation entry schema version. v1 entries lacked this
/// field entirely; v2 introduced the hash chain + Merkle anchors; v3
/// added the federation cosignature set; v4 added the
/// `factory_binaries` map (per-component sha256 of the factory
/// executables that produced the entry). v5 added bundle support:
/// `bundle_name` names the multi-module bundle this entry covers when
/// the cycle ran a bundle, and `modules` records per-module artefacts
/// (each module's diversified-candidate sha256, plus optionally the
/// `.text` sha256 from the linked kernel ELF). Single-module entries
/// continue to use the existing top-level `module` + `candidate_sha256`
/// fields and leave the new fields absent.
///
/// **v6 adds the diversifier log** (TASK-031): the
/// [`DiversifierLog`] captured by `cuttle_diversifier::diversify_with_log`
/// rides alongside the existing codegen + bundle fields. Carries the
/// per-function pad sizes and codegen-perturb decisions for the cycle
/// so a future `morph verify-attest --replay-diversifier` invocation
/// can reconstruct the candidate from `(seed, pad_log, perturb_log)`
/// and prove the attestation entry is the deterministic result of the
/// recorded factory state. The new field is `Option<DiversifierLog>`
/// with `skip_serializing_if = "Option::is_none"` so v3 / v4 / v5
/// entries round-trip byte-identically through v6 code.
///
/// **Canonical-JSON compatibility**: every additive field since v3 is
/// `skip_serializing_if`, so older entries hash byte-identically under
/// v6 code. v3 / v4 / v5 chains continue to verify under a v6 binary;
/// see [`migrate_chain`] and the v6 round-trip tests in
/// `tests/attest_v6.rs`.
///
/// **v7 adds `kernel_layout_seed`** (Phase 1 codegen diversity): the
/// `-Zlayout-seed` used for the cycle's kernel image build, recorded so the
/// image is reproducible from `(source, layout_seed)`. Same additive,
/// `skip_serializing_if`-omitted treatment as every field since v3, so
/// v3–v6 chains continue to verify byte-identically under a v7 binary (see
/// the migrate range below and `tests/attest_v7.rs`).
///
/// **v8 adds `ext_tlv_b64`** (TASK-102): Base64 (RFC 4648) encoding of a
/// three-tag JSON-free TLV sequence (cycle / module / candidate-hash
/// seed prefix) built with the same `AttestTlv` + `Base64` contracts the
/// enterprise target morphs. Every new write populates it; verify
/// re-decodes and checks agreement with the JSON fields. Omitted on
/// pre-v8 entries (`skip_serializing_if`) so v3–v7 chains still hash
/// byte-identically under a v8 binary.
///
/// **v9 adds `diversity`** (TASK-124): optional [`DiversityEvidence`]
/// recording measured MTD metrics (`.text` shas, positional/semantic
/// survival in basis points, layout seed, diversifier decision counts).
/// Omitted when absent so v3–v8 entries continue to hash byte-identically.
///
/// **v10 adds `durable_seals`** (TASK-140): optional map of durable-blob
/// label → SHA-256 hex from [`crate::durable_seal::DurableSeal`]. Empty
/// map is omitted so v3–v9 entries hash byte-identically.
///
/// **v11 binds the signature to the entry** (security fix): pre-v11 the
/// primary signature covered only `candidate_sha256`, leaving `module`,
/// `accepted`, `diversity`, `image_sha256`, `durable_seals`, chain
/// position — everything else — forgeable by any filesystem attacker.
/// v11 entries are minted only via [`AttestEntryFields::signing_key`]:
/// `sig_ed25519` signs the *signable hash* (canonical JSON of the entry
/// minus `sig_ed25519` / `cosignatures` / `entry_sha256`), which commits
/// the signature to every other field including `prev_entry_sha256`.
/// `cosignatures` stays excluded from the preimage so `morph cosign` can
/// append federation signatures after minting without invalidating the
/// primary signature. v3–v10 chains still verify (hash-chain only);
/// v11 entries are **always** signature-verified — see
/// [`verify_chain_with_options`].
pub const SCHEMA_VERSION: u64 = 11;

/// Entries at or above this schema version carry a signature over the
/// signable entry hash (not just the candidate hash) and MUST have that
/// signature verified during chain verification.
pub const SIGNED_ENTRY_MIN_SCHEMA: u64 = 11;

/// Schema version minted when [`AttestEntryFields::signing_key`] is `None`
/// (legacy caller-supplied-signature path). Identical canonical shape to
/// v10; kept so existing tests/tooling mint pre-v11 entries explicitly.
pub const LEGACY_SCHEMA_VERSION: u64 = 10;

/// Lowest schema version that this binary will read without migrating
/// the log aside. v3 entries continue to verify under a v4 binary —
/// see [`migrate_chain`] and the matching test in
/// `tests/attest_v4.rs`.
pub const READABLE_MIN_SCHEMA: u64 = 3;

pub const ATTEST_LOG: &str = "attest.log.jsonl";
pub const ANCHOR_LOG: &str = "merkle_anchors.jsonl";
pub const ATTEST_LOG_V1_BAK: &str = "attest.log.v1.jsonl.bak";
pub const ANCHOR_LOG_V1_BAK: &str = "merkle_anchors.v1.jsonl.bak";
pub const ATTEST_LOG_V2_BAK: &str = "attest.log.v2.jsonl.bak";
pub const ANCHOR_LOG_V2_BAK: &str = "merkle_anchors.v2.jsonl.bak";

/// Rolling Merkle root over **every** committed attestation entry.
/// Re-written after each successful `write_attestation`. Distinct from
/// the chunked `merkle_anchors.jsonl` log, which commits to every 10
/// entries. The rolling root gives a single 32-byte fingerprint a
/// verifier can re-derive in O(N) without reading the anchor log.
///
/// Filename: `attest.merkle_root` (no extension — emphasises that this
/// is a single-fact sidecar rather than a JSONL chain).
pub const ATTEST_MERKLE_ROOT: &str = "attest.merkle_root";

/// Current schema version of the `attest.merkle_root` sidecar. Bumped
/// when the file format changes; not tied to [`SCHEMA_VERSION`] (which
/// versions the entry log itself). `v1` corresponds to TASK-013.
pub const MERKLE_ROOT_SCHEMA_VERSION: u64 = 1;

/// The 64-hex-zero string used for the genesis `prev_entry_sha256` and
/// the genesis `prev_anchor_merkle_root`.
pub const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Tests and operators can override the directory containing
/// `attest.log.jsonl` and `merkle_anchors.jsonl` via this env var. When
/// unset, paths are resolved relative to the process CWD (matches the
/// pre-existing behaviour of the inline emitter in cycle.rs).
pub const ATTEST_DIR_ENV: &str = "CUTTLE_ATTEST_DIR";

/// Per-cycle diversifier decision log embedded in v6+ attestation
/// entries. Mirrors `cuttle_diversifier::DiversifierLog` (which lives
/// in a dep-free crate; this is the serde-bearing copy). Captures the
/// `stack_pad::apply` and `codegen_perturb::apply` decisions made
/// during the cycle so a future `verify-attest --replay-diversifier`
/// can reconstruct the candidate from `(seed, pad_log, perturb_log)`
/// and prove the attestation entry is the deterministic result of the
/// recorded factory state.
///
/// **Canonical JSON**: both maps are `skip_serializing_if`-omitted
/// when empty, and the outer field on `AttestEntry` is itself
/// `Option`-omitted when `None`. This three-layer skip means:
///
/// - v3/v4/v5 entries (no field) hash byte-identically under v6.
/// - A v6 entry with `Some(DiversifierLog::default())` hashes the
///   field as `{}`, distinguishable from `None`.
/// - A v6 entry whose log has e.g. only `pad_decisions` set hashes
///   without a `perturb_decisions` key, identical to the v3 omission
///   pattern.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiversifierLog {
    /// Per-function pad size in bytes (canonical: `u32`, range
    /// `[32, 224)` — see `cuttle_diversifier::stack_pad`). Keyed by
    /// `fn_name` for free fns and `"Type::method"` for impl-block
    /// methods. `BTreeMap` so canonical-JSON serialisation sorts keys
    /// deterministically — the chain commits to these bytes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pad_decisions: BTreeMap<String, u32>,
    /// Per-function codegen-perturb decision (canonical label set:
    /// `"no-attr"`, `"inline-always"`, `"inline-never"`,
    /// `"ineligible:main-fn"`, `"ineligible:already-inline"`). Keys
    /// match those in `pad_decisions` where both passes considered the
    /// same function. The locked label alphabet is enforced at the
    /// diversifier source level; this struct holds whatever spelling
    /// the diversifier emitted.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub perturb_decisions: BTreeMap<String, String>,
    /// Per-function semantic-perturb decision (Rung 1): comma-joined
    /// labels `"strength-reduction"`, `"branch-polarity"`, `"loop-form"`,
    /// or `"eligible:no-change"` / `"ineligible:<reason>"`. Empty unless
    /// the cycle ran with `DiversifyOptions::semantic_perturb` on, so
    /// pre-Rung-1 entries hash byte-identically.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub semantic_decisions: BTreeMap<String, String>,
}

impl DiversifierLog {
    /// `true` iff both maps are empty. Use as a precondition for
    /// `skip_serializing_if` on the outer `Option<DiversifierLog>`
    /// when constructing an entry — an empty log is preserved
    /// in the canonical encoding as `Some({})` which is observably
    /// distinct from `None`. If a caller wants byte-identical-to-v5
    /// canonical bytes, it must pass `None`, not `Some(empty)`.
    pub fn is_empty(&self) -> bool {
        self.pad_decisions.is_empty()
            && self.perturb_decisions.is_empty()
            && self.semantic_decisions.is_empty()
    }
}

/// Build a serde-bearing [`DiversifierLog`] from the dep-free
/// `cuttle_diversifier::DiversifierLog`. Pure data marshalling — the
/// two types have identical field shapes.
pub fn diversifier_log_from(src: &cuttle_diversifier::DiversifierLog) -> DiversifierLog {
    DiversifierLog {
        pad_decisions: src.pad_decisions.clone(),
        perturb_decisions: src.perturb_decisions.clone(),
        semantic_decisions: src.semantic_decisions.clone(),
    }
}

/// Measured moving-target diversity for one accepted (or rejected)
/// morph cycle (TASK-124 / schema v9).
///
/// All fields are optional so a cycle can record *partial* evidence:
/// source-side diversifier counts always; ELF gadget churn only when
/// base+variant binaries exist; layout seed only when an image was
/// emitted. Canonical-JSON omits every `None` field.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiversityEvidence {
    /// `.text` SHA-256 of the baseline binary used for churn compare.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_text_sha256: Option<String>,
    /// `.text` SHA-256 of this cycle's diversified binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant_text_sha256: Option<String>,
    /// Positional gadget survival in basis points (0..=10_000).
    /// 0 = no gadgets land at the same offset; 10_000 = identical layout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub positional_survival_bps: Option<u32>,
    /// Semantic (address-normalized) gadget survival in basis points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_survival_norm_bps: Option<u32>,
    /// Master kernel diversity seed (`-Zlayout-seed` / binmorph seed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout_seed: Option<u64>,
    /// Number of stack-pad decisions recorded in `diversifier_log`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pad_decision_count: Option<u32>,
    /// Number of codegen-perturb decisions recorded in `diversifier_log`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perturb_decision_count: Option<u32>,
}

impl DiversityEvidence {
    /// `true` iff every field is `None` (no evidence recorded).
    pub fn is_empty(&self) -> bool {
        self.base_text_sha256.is_none()
            && self.variant_text_sha256.is_none()
            && self.positional_survival_bps.is_none()
            && self.semantic_survival_norm_bps.is_none()
            && self.layout_seed.is_none()
            && self.pad_decision_count.is_none()
            && self.perturb_decision_count.is_none()
    }

    /// At least one ELF-side metric is present (text sha or survival bps).
    pub fn has_elf_metrics(&self) -> bool {
        self.base_text_sha256.is_some()
            || self.variant_text_sha256.is_some()
            || self.positional_survival_bps.is_some()
            || self.semantic_survival_norm_bps.is_some()
    }

    /// Satisfies `verify-attest --require-diversity` (TASK-125):
    /// source-side diversifier counts and/or ELF metrics are present.
    /// Zero decision counts still qualify — they prove the diversifier
    /// ran and recorded an empty decision set.
    pub fn satisfies_require(&self) -> bool {
        self.pad_decision_count.is_some()
            || self.perturb_decision_count.is_some()
            || self.has_elf_metrics()
            || self.layout_seed.is_some()
    }
}

/// Per-module artefact recorded inside a bundle attestation entry.
/// One of these per declared module in the bundle. The driver of the
/// whole-kernel-scramble property: when N modules morph atomically per
/// cycle, the attestation log records N canonical hashes here, plus
/// optionally the ELF `.text` SHA-256 of the resulting kernel.
///
/// Canonical-JSON: `elf_text_sha256` is `Option<String>` with
/// `skip_serializing_if` so attestation entries written before the
/// kernel-build step ran continue to hash stably.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleArtifact {
    /// Canonical SHA-256 of this module's diversified candidate source.
    pub candidate_sha256: String,
    /// `.text` section SHA-256 of the kernel ELF built against the
    /// full bundle. Same value across every `ModuleArtifact` in the
    /// same entry (the kernel is built once per bundle), recorded
    /// per-module for query convenience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf_text_sha256: Option<String>,
}

/// Plain-old-data view of an attestation entry. Fields ordered for
/// readability; canonical serialization sorts them alphabetically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestEntry {
    pub schema_version: u64,
    pub cycle: u64,
    pub ts_unix: u64,
    pub module: String,
    pub candidate_sha256: String,
    pub sig_ed25519: String,
    pub accepted: bool,
    pub synthesizer: String,
    /// Present only when the prompt-only synthesizer wrote a prompt file.
    /// Absent for PassThrough. Canonical JSON omits absent fields entirely
    /// — this keeps backward-compat with the v1 emitter's behaviour and
    /// keeps the hash stable across PassThrough cycles.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub prompt_path: Option<String>,
    /// SHA-256 of the bootable image emitted by `factory_builder` during
    /// the deploy stage, when `--emit-image` was set on the cycle. Absent
    /// for non-bootable targets and for runs that didn't request image
    /// emission. Same canonical-JSON treatment as `prompt_path`: when
    /// `None`, the field is omitted entirely from the canonical encoding,
    /// so legacy entries continue to verify under v2.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub image_sha256: Option<String>,
    /// Federation cosignatures over `candidate_sha256`. Includes the
    /// primary signature (signer_id="primary"); the historical
    /// `sig_ed25519` field stays as a denormalized copy of the
    /// primary's signature for backward compat with v2 readers.
    ///
    /// Skipped from canonical JSON when empty so reserialization of any
    /// legacy zero-cosig entry is hash-stable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cosignatures: Vec<Cosignature>,
    /// The federation threshold (M) this entry was minted under. Used
    /// during `verify-attest --require-threshold` to detect entries
    /// minted under a relaxed policy. `None` for entries written before
    /// the federation config was active (e.g. `morph tick` on a host
    /// without `factory_keys.toml`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_threshold: Option<u32>,
    /// Per-component SHA-256 of the factory executables that produced
    /// this entry (TASK-022). Keys are short component names (`morph`,
    /// `verify`, `diversify`, `rustc`); values are 64-char lowercase
    /// hex. Empty for entries minted by a binary that didn't compute
    /// the fingerprint (legacy v3 entries, or v4 entries with hashing
    /// disabled).
    ///
    /// Canonical-JSON: `skip_serializing_if = "BTreeMap::is_empty"` so
    /// v3 entries (no map at all) and v4 entries with an empty map
    /// produce byte-identical canonical bytes and therefore identical
    /// `entry_sha256`. This is the same omission pattern as
    /// `image_sha256` / `cosignatures` / `federation_threshold`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub factory_binaries: BTreeMap<String, String>,
    /// Name of the morph **bundle** this entry covers, when the cycle
    /// ran a bundle rather than a single module. `None` for legacy
    /// single-module entries; populated (e.g. `Some("kernel")`) when
    /// `run_bundle` is the driving cycle.
    ///
    /// When this is `Some`, the top-level `module` field carries the
    /// bundle name (a denormalised copy so legacy single-module
    /// tooling can still read `entry.module`), `candidate_sha256` is
    /// the BUNDLE hash (deterministic sort + concat + sha256 of each
    /// member's canonical hash), and the [`modules`](Self::modules)
    /// map carries the per-member artefacts.
    ///
    /// Canonical-JSON: skipped when `None` so v3/v4 entries round-trip
    /// byte-identically through v5 code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_name: Option<String>,
    /// Per-module artefacts within a bundle entry. Empty (and
    /// `skip_serializing_if`-omitted) for legacy single-module entries.
    /// Keys are module names; values carry the per-module
    /// canonical-hash + optional ELF `.text` sha256. Bound is the
    /// bundle's declared `modules` list.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub modules: BTreeMap<String, ModuleArtifact>,
    /// Per-cycle diversifier decision log (TASK-031). `None` for v3 /
    /// v4 / v5 entries and for any v6 entry whose driving cycle didn't
    /// have a log to record (e.g. legacy passthrough paths). When
    /// `Some`, the inner maps record every `stack_pad::apply` and
    /// `codegen_perturb::apply` decision the diversifier made.
    ///
    /// Canonical-JSON: `skip_serializing_if = "Option::is_none"` so
    /// pre-v6 entries continue to hash byte-identically under v6
    /// code. See the type-level docs on [`DiversifierLog`] for the
    /// three-layer skip semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diversifier_log: Option<DiversifierLog>,
    /// `-Zlayout-seed` used for the kernel build that produced this entry's
    /// image (Phase 1 codegen diversity lever). `Some(n)` only when the
    /// deploy stage emitted a bootable image with layout randomization;
    /// `None` for cycles that didn't build an image (the default path) and
    /// for all pre-v7 entries. Recording it makes the morph's codegen
    /// layout reproducible from the attestation — a verifier can rebuild
    /// the exact image by replaying `(source, layout_seed)`.
    ///
    /// Canonical-JSON: `skip_serializing_if = "Option::is_none"`, so v3–v6
    /// entries (no field) hash byte-identically under v7 code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_layout_seed: Option<u64>,
    /// Base64 of a three-tag TLV extension blob (TASK-102 / v8). See
    /// [`crate::ext_tlv`]. `None` for pre-v8 entries; every write under
    /// v8+ fills this via [`crate::ext_tlv::build_ext_tlv_b64`] unless
    /// the caller supplies an explicit value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext_tlv_b64: Option<String>,
    /// Measured diversity evidence (TASK-124 / v9). `None` for pre-v9
    /// entries and for cycles that recorded no diversifier/ELF metrics.
    /// Canonical-JSON omits when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diversity: Option<DiversityEvidence>,
    /// Durable-blob seals bound to this entry (TASK-140 / v10). Keys are
    /// operator labels (`audit_snapshot`, `wal_head`, …); values are
    /// lowercase 64-char hex SHA-256 digests. Empty map omitted.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub durable_seals: BTreeMap<String, String>,
    pub prev_entry_sha256: String,
    /// Populated *after* canonical hashing. When computing the hash we
    /// omit this field entirely (see `compute_entry_sha256`).
    pub entry_sha256: String,
}

/// Caller-supplied fields. The writer fills in `prev_entry_sha256`,
/// `entry_sha256`, `schema_version`, and `ts_unix`.
#[derive(Debug, Clone)]
pub struct AttestEntryFields {
    pub cycle: u64,
    pub module: String,
    pub candidate_sha256: String,
    pub sig_ed25519: String,
    pub accepted: bool,
    pub synthesizer: String,
    pub prompt_path: Option<String>,
    /// SHA-256 of the bootable image (BIOS variant) emitted during the
    /// deploy stage. `None` if the deploy stage didn't run image
    /// emission (default for all targets today; opt-in via
    /// `--emit-image` on `morph run`).
    pub image_sha256: Option<String>,
    /// Cosignatures attached at write-time. The cycle code typically
    /// provides the primary cosignature only; `morph cosign` later
    /// appends additional cosignatures to satisfy the federation
    /// threshold.
    pub cosignatures: Vec<Cosignature>,
    /// The federation threshold (M) this entry was minted under.
    /// `None` is allowed for fallback paths where the federation TOML
    /// is absent.
    pub federation_threshold: Option<u32>,
    /// Per-component SHA-256 of the factory executables that produced
    /// this entry (TASK-022). Empty if hashing was disabled or the
    /// cycle could not locate a particular component (which is logged
    /// to stderr rather than silently dropped). Cycle code computes
    /// this once per process via [`crate::factory::fingerprint`] and
    /// reuses it for every entry written in the same session.
    pub factory_binaries: BTreeMap<String, String>,
    /// Bundle name when this entry covers a multi-module morph; `None`
    /// for single-module entries. See [`AttestEntry::bundle_name`] for
    /// the full semantics.
    pub bundle_name: Option<String>,
    /// Per-module artefacts within a bundle. Empty for single-module
    /// entries. The cycle code populates this in `run_bundle`.
    pub modules: BTreeMap<String, ModuleArtifact>,
    /// Per-cycle diversifier decision log captured by
    /// `cuttle_diversifier::diversify_with_log`. `None` when the
    /// caller path doesn't have a log to record (legacy paths, tests
    /// that don't exercise the diversifier). The morph engine's
    /// `cycle.rs` populates this for every accepted morph cycle in
    /// v6+ runs.
    pub diversifier_log: Option<DiversifierLog>,
    /// `-Zlayout-seed` for the kernel image this cycle built, or `None`
    /// when no image was emitted. See [`AttestEntry::kernel_layout_seed`].
    pub kernel_layout_seed: Option<u64>,
    /// Optional pre-built extension TLV (Base64). When `None`,
    /// [`write_attestation`] builds the default three-tag blob from
    /// `cycle` / `module` / `candidate_sha256`.
    pub ext_tlv_b64: Option<String>,
    /// Optional diversity evidence (TASK-124). When `None`,
    /// [`write_attestation`] derives source-side counts from
    /// `diversifier_log` + `kernel_layout_seed` when either is present.
    pub diversity: Option<DiversityEvidence>,
    /// Optional durable seals (TASK-140). Empty = omit from entry.
    /// Use [`crate::durable_seal::seals_map_from`] to build from
    /// [`crate::durable_seal::DurableSeal`] values.
    pub durable_seals: BTreeMap<String, String>,
    /// When `Some`, the entry is minted at schema v11 and
    /// [`AttestEntry::sig_ed25519`] is computed **at write time** as the
    /// signature over the signable entry hash ([`compute_signable_sha256`])
    /// — the caller's `sig_ed25519` field is ignored. This binds the
    /// signature to the full entry content, not just the candidate hash.
    /// When `None`, the entry is minted at legacy schema v10 with the
    /// caller-supplied `sig_ed25519` (kept for tests and tooling that
    /// pre-compute signatures; production cycle code MUST pass the key).
    pub signing_key: Option<ed25519_dalek::SigningKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorEntry {
    pub anchor_index: u64,
    pub first_entry: u64,
    pub last_entry: u64,
    pub first_entry_sha256: String,
    pub last_entry_sha256: String,
    pub merkle_root: String,
    pub prev_anchor_merkle_root: String,
    pub ts_unix: u64,
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub entries_ok: usize,
    pub anchors_ok: usize,
    /// Set by `verify_chain` when the rolling root sidecar exists and
    /// matches the recomputed root. `None` when the sidecar is absent
    /// (legacy logs from before TASK-013) and the caller did not pass
    /// `require_merkle_root=true`.
    pub merkle_root_verified: Option<MerkleRootStatus>,
    /// Number of entries whose `factory_binaries` map was checked
    /// against `factory_expected.toml` under
    /// `require_strict_factory`. `None` when the flag wasn't set.
    pub factory_verified: Option<usize>,
}

/// What `verify_chain` discovered about the rolling Merkle root sidecar
/// (`attest.merkle_root`). The `verify-attest` CLI prints a one-line
/// summary; the integration tests assert on this enum directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleRootStatus {
    /// Sidecar present, entry_count matched, recomputed root equals
    /// stored root.
    Ok,
    /// Sidecar absent and the verifier was not asked to require it.
    /// Legacy attestation logs hit this branch.
    Absent,
}

/// On-disk shape of `attest.merkle_root`. Persisted as canonical JSON
/// (key-sorted, no whitespace) so two host installs with the same log
/// produce byte-identical sidecars and operators can diff them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleRootFile {
    /// Schema version of the sidecar itself (not the entry log).
    pub schema_version: u64,
    /// Schema version of the entries the root was computed over. Stored
    /// so a verifier can detect "the entry log got migrated but the
    /// sidecar didn't" mismatches.
    pub entry_schema_version: u64,
    /// Number of entries in `attest.log.jsonl` when the root was last
    /// recomputed.
    pub entry_count: u64,
    /// Hex SHA-256 of `entries[entry_count - 1].entry_sha256`. Provides
    /// a quick "did the tail move" check for verifiers that don't want
    /// to rebuild the full tree.
    pub last_entry_sha256: String,
    /// Hex Merkle root over `entries[0..entry_count].entry_sha256`.
    /// When `entry_count == 0`, this is [`ZERO_HEX`].
    pub merkle_root: String,
    /// Unix seconds when the sidecar was last rewritten. Operational
    /// metadata only — never part of the canonical hash.
    pub computed_ts_unix: u64,
}

// ============================================================================
// Path resolution
// ============================================================================

fn attest_dir() -> PathBuf {
    match std::env::var(ATTEST_DIR_ENV) {
        Ok(s) if !s.is_empty() => PathBuf::from(s),
        _ => PathBuf::from("."),
    }
}

pub fn attest_log_path() -> PathBuf {
    attest_dir().join(ATTEST_LOG)
}
pub fn anchor_log_path() -> PathBuf {
    attest_dir().join(ANCHOR_LOG)
}
pub fn merkle_root_path() -> PathBuf {
    attest_dir().join(ATTEST_MERKLE_ROOT)
}
fn attest_log_v1_bak_path() -> PathBuf {
    attest_dir().join(ATTEST_LOG_V1_BAK)
}
fn anchor_log_v1_bak_path() -> PathBuf {
    attest_dir().join(ANCHOR_LOG_V1_BAK)
}
fn attest_log_v2_bak_path() -> PathBuf {
    attest_dir().join(ATTEST_LOG_V2_BAK)
}
fn anchor_log_v2_bak_path() -> PathBuf {
    attest_dir().join(ANCHOR_LOG_V2_BAK)
}

// ============================================================================
// Canonical JSON (hand-rolled, key-sorted, no whitespace)
// ============================================================================

/// Canonical-JSON-serialize a `serde_json::Value`. Object keys are sorted
/// lexicographically; arrays preserve order; numbers must be integer (we
/// reject floats — none of our attestation fields are floats and silently
/// canonicalizing floats is a footgun); strings get standard JSON escape.
pub fn canonical_json(v: &serde_json::Value) -> Result<String> {
    let mut out = String::new();
    write_value(&mut out, v)?;
    Ok(out)
}

fn write_value(out: &mut String, v: &serde_json::Value) -> Result<()> {
    use serde_json::Value;
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // Integer fast path; reject floats so we never silently
            // produce a hash that depends on `f64::to_string` rounding.
            if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else {
                bail!("canonical_json: floating-point numbers are not allowed in attestation entries");
            }
        }
        Value::String(s) => write_string(out, s),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sort keys lexicographically. BTreeMap re-collects to enforce
            // the ordering invariant — relying on `serde_json::Map`'s
            // preserved insertion order would silently produce a different
            // hash if fields were added in a different order at the call
            // site.
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            out.push('{');
            for (i, (k, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, val)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ============================================================================
// Hash computation
// ============================================================================

/// Hex-encode bytes (lowercase). Local copy so this module is self-contained
/// (the `signing::hex` symbol is `pub(crate)` and we want to keep it that way).
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Parse a 64-char hex string into a 32-byte array.
pub fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!("expected 64-hex string, got {} chars", s.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("invalid hex at offset {}", i * 2))?;
    }
    Ok(out)
}

/// Compute `entry_sha256`: SHA-256 over the canonical JSON of the entry
/// fields *excluding* `entry_sha256` itself (otherwise the field would be
/// self-referential).
pub fn compute_entry_sha256(entry: &AttestEntry) -> Result<[u8; 32]> {
    let v = serde_json::to_value(entry).context("serialize entry to JSON value")?;
    let mut obj = match v {
        serde_json::Value::Object(m) => m,
        _ => bail!("attestation entry did not serialize to a JSON object"),
    };
    obj.remove("entry_sha256");
    let canonical = canonical_json(&serde_json::Value::Object(obj))?;
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    Ok(h.finalize().into())
}

/// Compute the **signable hash** (schema v11+): SHA-256 over the canonical
/// JSON of the entry *excluding* `sig_ed25519`, `cosignatures`, and
/// `entry_sha256`. This is the message the primary factory key signs.
///
/// - `sig_ed25519` is excluded (self-reference).
/// - `cosignatures` is excluded so `morph cosign` can append federation
///   signatures post-mint without invalidating the primary signature.
/// - `entry_sha256` is excluded (it is derived, and `morph cosign`
///   legitimately re-derives it when re-linking the chain).
///
/// Everything else — `module`, `accepted`, `diversity`, `image_sha256`,
/// `durable_seals`, `prev_entry_sha256`, `cycle`, `ts_unix`, … — is
/// committed to by the signature. A filesystem attacker who cannot sign
/// can no longer relabel a signed candidate onto a different module,
/// fabricate diversity evidence, or move a signed entry to a different
/// chain position.
pub fn compute_signable_sha256(entry: &AttestEntry) -> Result<[u8; 32]> {
    let v = serde_json::to_value(entry).context("serialize entry to JSON value")?;
    let mut obj = match v {
        serde_json::Value::Object(m) => m,
        _ => bail!("attestation entry did not serialize to a JSON object"),
    };
    obj.remove("entry_sha256");
    obj.remove("sig_ed25519");
    obj.remove("cosignatures");
    let canonical = canonical_json(&serde_json::Value::Object(obj))?;
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    Ok(h.finalize().into())
}

/// Build a Merkle root over a slice of 32-byte leaves. Thin wrapper
/// around [`merkle::compute_root`] kept for backward-compatible API:
/// the chunked-anchor emitter and old integration tests still call
/// `compute_merkle_root`. Padding is Bitcoin-style (duplicate-last on
/// odd layers) — see [`crate::merkle`] for the full rationale and the
/// no-alloc verify counterpart.
///
/// Panics on an empty leaf set, matching the historical contract.
/// Verifier callers that need to tolerate empty inputs should consult
/// [`load_merkle_root`] instead, which uses the explicit
/// "entry_count == 0 → ZERO_HEX" convention.
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    merkle::compute_root(leaves).expect("compute_merkle_root: empty leaf set")
}

// ============================================================================
// Migration
// ============================================================================

/// Inspect the existing logs and migrate them aside if they predate the
/// current schema version. Handles v1→v3 and v2→v3 transitions; both
/// rename the existing log to a version-specific `.bak` and start fresh.
/// Idempotent: once the .bak file exists and the current log doesn't,
/// re-running is a no-op.
fn migrate_chain() -> Result<()> {
    let log = attest_log_path();
    if !log.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(&log).with_context(|| format!("read {}", log.display()))?;
    let last = match content.lines().rev().find(|l| !l.trim().is_empty()) {
        Some(s) => s,
        None => return Ok(()),
    };
    let v: serde_json::Value = match serde_json::from_str(last) {
        Ok(x) => x,
        // Malformed last line: treat as v1, migrate aside.
        Err(_) => {
            move_aside(&log, &attest_log_v1_bak_path())?;
            let anchor = anchor_log_path();
            if anchor.exists() {
                move_aside(&anchor, &anchor_log_v1_bak_path())?;
            }
            return Ok(());
        }
    };
    let existing_ver = v.get("schema_version").and_then(|x| x.as_u64());
    if existing_ver == Some(SCHEMA_VERSION) {
        // Already at the current schema.
        return Ok(());
    }
    // Every schema bump since v3 has added only
    // `skip_serializing_if`-omitted fields, so an older entry deserialises
    // to a newer struct whose canonical-JSON encoding matches the original
    // bytes exactly. Any version in [READABLE_MIN_SCHEMA, SCHEMA_VERSION)
    // therefore verifies in place; current-version entries are handled by
    // the equality check above. Leave older logs in place; new entries
    // chain forward from the existing tail. See `tests/attest_v{4,6,7}.rs`.
    if let Some(v) = existing_ver {
        if (READABLE_MIN_SCHEMA..SCHEMA_VERSION).contains(&v) {
            return Ok(());
        }
    }
    let (log_bak, anchor_bak, label) = match existing_ver {
        None => (
            attest_log_v1_bak_path(),
            anchor_log_v1_bak_path(),
            "pre-v2",
        ),
        Some(2) => (
            attest_log_v2_bak_path(),
            anchor_log_v2_bak_path(),
            "v2",
        ),
        Some(v) => bail!(
            "attest.log has unknown schema_version {} (this binary expects {} or {})",
            v,
            READABLE_MIN_SCHEMA,
            SCHEMA_VERSION
        ),
    };
    eprintln!(
        "morph: migrating {} attestation log aside to {}",
        label,
        log_bak.display()
    );
    move_aside(&log, &log_bak)?;
    let anchor = anchor_log_path();
    if anchor.exists() {
        move_aside(&anchor, &anchor_bak)?;
    }
    Ok(())
}

fn move_aside(from: &Path, to: &Path) -> Result<()> {
    // If `to` exists, append a numeric suffix so we never overwrite a prior
    // migration's backup.
    let mut target = to.to_path_buf();
    let mut n = 1u32;
    while target.exists() {
        target = to.with_extension(format!("bak.{}", n));
        n += 1;
        if n > 1000 {
            bail!(
                "too many existing backups at {}; refusing to migrate",
                to.display()
            );
        }
    }
    fs::rename(from, &target)
        .with_context(|| format!("rename {} -> {}", from.display(), target.display()))?;
    Ok(())
}

// ============================================================================
// Reading the current chain state
// ============================================================================

/// Load all v2 entries from the attestation log, in order. Returns an
/// empty vec if the log is missing or empty.
pub fn load_entries() -> Result<Vec<AttestEntry>> {
    let log = attest_log_path();
    if !log.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&log).with_context(|| format!("read {}", log.display()))?;
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let e: AttestEntry = serde_json::from_str(line)
            .with_context(|| format!("parse entry at line {}", i + 1))?;
        out.push(e);
    }
    Ok(out)
}

/// Load the rolling Merkle root sidecar. Returns `Ok(None)` when the
/// file is absent (a fresh log, or a log written before TASK-013
/// landed). Returns `Err` on parse failure — corruption of the sidecar
/// is a signal the verifier wants surfaced, not silently ignored.
pub fn load_merkle_root() -> Result<Option<MerkleRootFile>> {
    let path = merkle_root_path();
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let mut content = raw.trim().to_string();
    if content.is_empty() {
        return Ok(None);
    }
    // Strip a trailing newline if anyone hand-edited the file.
    while content.ends_with('\n') || content.ends_with('\r') {
        content.pop();
    }
    let f: MerkleRootFile = serde_json::from_str(&content)
        .with_context(|| format!("parse {}", path.display()))?;
    if f.schema_version != MERKLE_ROOT_SCHEMA_VERSION {
        bail!(
            "{}: unsupported schema_version {} (this binary expects {})",
            path.display(),
            f.schema_version,
            MERKLE_ROOT_SCHEMA_VERSION
        );
    }
    Ok(Some(f))
}

/// Compute the rolling root over the supplied entries and atomically
/// rewrite `attest.merkle_root`. Empty `entries` produces a sidecar
/// with `entry_count = 0` and `merkle_root = ZERO_HEX`, which acts as
/// an explicit "we know this log is empty" marker (vs the
/// indistinguishable "no sidecar" state, which is the legacy
/// pre-TASK-013 condition).
pub fn write_merkle_root(entries: &[AttestEntry]) -> Result<MerkleRootFile> {
    let entry_count = entries.len() as u64;
    let merkle_root = if entry_count == 0 {
        ZERO_HEX.to_string()
    } else {
        let leaves: Vec<[u8; 32]> = entries
            .iter()
            .map(|e| parse_hex32(&e.entry_sha256))
            .collect::<Result<Vec<_>>>()
            .context("rolling-root: parse entry_sha256")?;
        hex(&merkle::compute_root(&leaves).context("rolling-root: compute")?)
    };
    let last_entry_sha256 = entries
        .last()
        .map(|e| e.entry_sha256.clone())
        .unwrap_or_else(|| ZERO_HEX.to_string());
    let computed_ts_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let f = MerkleRootFile {
        schema_version: MERKLE_ROOT_SCHEMA_VERSION,
        entry_schema_version: SCHEMA_VERSION,
        entry_count,
        last_entry_sha256,
        merkle_root,
        computed_ts_unix,
    };
    // Canonical-JSON serialise so two replicas with the same log
    // produce byte-identical sidecars. We construct the value via
    // serde_json so the order of keys is canonicalised by the helper,
    // not by struct-field ordering above.
    let json = canonical_json(&serde_json::to_value(&f).context("serialize MerkleRootFile")?)?;
    let path = merkle_root_path();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).ok();
        }
    }
    let tmp = path.with_extension("tmp");
    {
        let mut g = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        g.write_all(json.as_bytes())?;
        g.write_all(b"\n")?;
    }
    // Windows rename refuses to overwrite; remove first.
    if path.exists() {
        fs::remove_file(&path).ok();
    }
    fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(f)
}

/// Re-derive the rolling root from the current on-disk attest log and
/// rewrite the sidecar. Convenience for `morph` subcommands that want
/// to repair a sidecar after manual log edits (typically: never).
pub fn recompute_merkle_root_from_disk() -> Result<MerkleRootFile> {
    let entries = load_entries()?;
    write_merkle_root(&entries)
}

pub fn load_anchors() -> Result<Vec<AnchorEntry>> {
    let log = anchor_log_path();
    if !log.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&log).with_context(|| format!("read {}", log.display()))?;
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let a: AnchorEntry = serde_json::from_str(line)
            .with_context(|| format!("parse anchor at line {}", i + 1))?;
        out.push(a);
    }
    Ok(out)
}

// ============================================================================
// Writing entries + anchors
// ============================================================================

/// Append a v2 attestation entry. Handles:
///
/// - v1→v2 migration on first invocation (renames pre-v2 log aside).
/// - `prev_entry_sha256` lookup from the last existing v2 entry (or
///   genesis zeros).
/// - `entry_sha256` computation.
/// - Anchor emission every `ANCHOR_INTERVAL` entries.
pub fn write_attestation(fields: AttestEntryFields) -> Result<()> {
    migrate_chain()?;

    let entries = load_entries()?;
    let prev_entry_sha256 = entries
        .last()
        .map(|e| e.entry_sha256.clone())
        .unwrap_or_else(|| ZERO_HEX.to_string());

    let ts_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // TASK-102: always embed the JSON-free extension TLV for new writes
    // unless the caller supplied an explicit blob (tests).
    let ext_tlv_b64 = match fields.ext_tlv_b64 {
        Some(s) => Some(s),
        None => Some(
            crate::ext_tlv::build_ext_tlv_b64(
                fields.cycle,
                &fields.module,
                &fields.candidate_sha256,
            )
            .context("build default ext_tlv_b64")?,
        ),
    };

    // TASK-124: diversity evidence — caller-supplied wins; else derive
    // source-side pad/perturb counts + layout seed from the same fields
    // already recorded on the entry. ELF churn (bps / text shas) is
    // only present when the cycle path measured binaries.
    let diversity = match fields.diversity {
        Some(d) if !d.is_empty() => Some(d),
        Some(_) => None,
        None => crate::diversity::from_diversifier_log(
            fields.diversifier_log.as_ref(),
            fields.kernel_layout_seed,
        ),
    };
    if let Some(ref d) = diversity {
        crate::diversity::validate_evidence(d)
            .context("write_attestation: diversity evidence invalid")?;
    }

    let durable_seals = fields.durable_seals;
    if !durable_seals.is_empty() {
        crate::durable_seal::validate_seals_map(&durable_seals)
            .context("write_attestation: durable_seals invalid")?;
    }

    let signing_key = fields.signing_key;
    let mut entry = AttestEntry {
        schema_version: if signing_key.is_some() {
            SCHEMA_VERSION
        } else {
            LEGACY_SCHEMA_VERSION
        },
        cycle: fields.cycle,
        ts_unix,
        module: fields.module,
        candidate_sha256: fields.candidate_sha256,
        sig_ed25519: fields.sig_ed25519,
        accepted: fields.accepted,
        synthesizer: fields.synthesizer,
        prompt_path: fields.prompt_path,
        image_sha256: fields.image_sha256,
        cosignatures: fields.cosignatures,
        federation_threshold: fields.federation_threshold,
        factory_binaries: fields.factory_binaries,
        bundle_name: fields.bundle_name,
        modules: fields.modules,
        diversifier_log: fields.diversifier_log,
        kernel_layout_seed: fields.kernel_layout_seed,
        ext_tlv_b64,
        diversity,
        durable_seals,
        prev_entry_sha256,
        entry_sha256: String::new(),
    };
    // v11: bind the signature to the full entry content. Sign the signable
    // hash *after* every derived field (ext_tlv, diversity, chain link) is
    // fixed, so the signature commits to all of them.
    if let Some(key) = signing_key {
        use ed25519_dalek::Signer;
        let signable = compute_signable_sha256(&entry)?;
        let sig = key.sign(&signable);
        entry.sig_ed25519 = hex(&sig.to_bytes());
    }
    let hash = compute_entry_sha256(&entry)?;
    entry.entry_sha256 = hex(&hash);

    // Append exactly one line. We use serde_json::to_string for the on-disk
    // representation (compact, well-formed); the *canonical* form is only
    // used for hashing. The on-disk line's ordering doesn't affect the
    // chain because verification re-derives the hash from canonical form.
    let line = serde_json::to_string(&entry).context("serialize entry to JSON")?;
    let log = attest_log_path();
    if let Some(parent) = log.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).ok();
        }
    }
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .with_context(|| format!("open {}", log.display()))?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
    }

    // Anchor emission: after appending the Nth entry where N is a
    // multiple of ANCHOR_INTERVAL. Indexing is 0-based: entries 0..=9
    // anchor at total_count=10, entries 10..=19 anchor at total_count=20.
    let total = entries.len() as u64 + 1;
    if total > 0 && total % ANCHOR_INTERVAL == 0 {
        emit_anchor(total)?;
    }

    // Rolling root: TASK-013 — recompute over the full log and rewrite
    // the sidecar so `verify-attest` can prove tamper-evidence in O(N).
    // Re-read from disk rather than splicing the in-memory `entry` onto
    // the already-loaded `entries`: this guarantees the sidecar always
    // commits to bytes that landed on disk, not bytes we *intended* to
    // write.
    let all_entries = load_entries()?;
    write_merkle_root(&all_entries)?;

    Ok(())
}

/// Emit a Merkle anchor over the last ANCHOR_INTERVAL entries.
/// `total` = total number of entries now in the log.
fn emit_anchor(total: u64) -> Result<()> {
    let entries = load_entries()?;
    if (entries.len() as u64) != total {
        bail!(
            "emit_anchor: expected {} entries, found {}",
            total,
            entries.len()
        );
    }
    let start = (total - ANCHOR_INTERVAL) as usize;
    let chunk = &entries[start..];
    let leaves: Vec<[u8; 32]> = chunk
        .iter()
        .map(|e| parse_hex32(&e.entry_sha256))
        .collect::<Result<Vec<_>>>()?;
    let root = compute_merkle_root(&leaves);

    let anchors = load_anchors()?;
    let prev_anchor_merkle_root = anchors
        .last()
        .map(|a| a.merkle_root.clone())
        .unwrap_or_else(|| ZERO_HEX.to_string());

    let anchor = AnchorEntry {
        anchor_index: (start as u64) / ANCHOR_INTERVAL,
        first_entry: start as u64,
        last_entry: (start as u64) + ANCHOR_INTERVAL - 1,
        first_entry_sha256: chunk.first().unwrap().entry_sha256.clone(),
        last_entry_sha256: chunk.last().unwrap().entry_sha256.clone(),
        merkle_root: hex(&root),
        prev_anchor_merkle_root,
        ts_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let line = serde_json::to_string(&anchor).context("serialize anchor")?;
    let path = anchor_log_path();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

// ============================================================================
// Verification
// ============================================================================

/// Options for `verify_chain_with_options`. When `require_threshold` is
/// `true`, the federation TOML at `federation_config` (or, if `None`,
/// `federation::resolve_federation_path()`) is loaded and every entry's
/// cosignature set is verified against it. The threshold check requires
/// each entry's `federation_threshold` to equal the loaded config's
/// threshold.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub require_threshold: bool,
    pub federation_config: Option<PathBuf>,
    /// When `true`, `verify_chain_with_options` returns an error if the
    /// `attest.merkle_root` sidecar is absent. Always returns an error
    /// when the sidecar exists and does not match the recomputed root
    /// (regardless of this flag). Legacy logs from before TASK-013 lack
    /// the sidecar; operators upgrading existing factory state should
    /// run `morph verify-attest` once *without* this flag, observe the
    /// "absent" notice, then call `recompute_merkle_root_from_disk()`
    /// (or simply trigger a fresh `morph run`) to materialise it.
    pub require_merkle_root: bool,
    /// When `true`, `verify_chain_with_options` loads
    /// `factory_expected.toml` (or the path in `factory_expected_path`)
    /// and rejects entries whose `factory_binaries` map references an
    /// unknown component, or a known component with a hash not listed
    /// in the expected set. v3 entries (which carry no
    /// `factory_binaries` field) are an automatic rejection under
    /// strict mode — they were minted by a factory that didn't record
    /// its own fingerprint, so the audit guarantee can't apply to
    /// them.
    pub require_strict_factory: bool,
    /// Override path for `factory_expected.toml`. `None` means
    /// `factory::resolve_factory_expected_path()` is used (env var or
    /// workspace-relative default).
    pub factory_expected_path: Option<PathBuf>,
    /// When `true` (the **default** as of TASK-106), every entry must
    /// carry a valid `ext_tlv_b64` that re-decodes to the entry's
    /// cycle/module/candidate_sha256 prefix. Pre-v8 chains without the
    /// field fail under the default — operators verifying historical
    /// logs pass `--allow-missing-ext-tlv` (CLI) or set this to
    /// `false` in-process. Corrupt blobs always fail regardless.
    pub require_ext_tlv: bool,
    /// When `true` (TASK-125), every **accepted** entry must carry
    /// non-empty [`DiversityEvidence`] that
    /// [`DiversityEvidence::satisfies_require`]. Default `false` so
    /// pre-v9 / non-morph logs still verify. North-star soak enables
    /// this. Corrupt/malformed diversity always fails regardless.
    pub require_diversity: bool,
    /// When `true` (TASK-144), every **accepted** entry must carry a
    /// non-empty `durable_seals` map. Default `false` — seals are
    /// operator-optional. Malformed digests always fail when present.
    pub require_durable_seals: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            require_threshold: false,
            federation_config: None,
            require_merkle_root: false,
            require_strict_factory: false,
            factory_expected_path: None,
            // TASK-106 cutover: v8 writes always emit ext_tlv_b64;
            // verify enforces presence by default.
            require_ext_tlv: true,
            // TASK-125: opt-in; north-star / scorecard enable it.
            require_diversity: false,
            // TASK-144: opt-in for fleets that always attach seals.
            require_durable_seals: false,
        }
    }
}

/// Walk attest.log + merkle_anchors.log and verify chain + Merkle
/// integrity. Returns Ok with a count summary on full integrity. Returns
/// Err naming the first offending entry/anchor on any failure.
pub fn verify_chain() -> Result<VerifyReport> {
    verify_chain_with_options(&VerifyOptions::default())
}

/// Resolve the trusted primary factory verifying key for v11 entry
/// signature checks. Sources, in order:
///
/// 1. The federation config (`--federation-config` override or the
///    default `factory_keys.toml`), signer id `"primary"`. This is the
///    strong path: the roster can be held/pinned outside the log's
///    blast radius.
/// 2. `factory_signing_key.bin` next to the attestation log (or CWD).
///    This detects the "filesystem write WITHOUT the signing key"
///    attacker — the classic tamper-evidence threat model. It does NOT
///    detect an attacker who also read the key; fleets with that threat
///    model must pin the federation config externally and use
///    `--require-threshold`.
///
/// Returns `Ok(None)` when no key source exists. Callers fail closed if
/// the chain actually contains v11 entries in that case.
fn resolve_primary_verifying_key(
    opts: &VerifyOptions,
) -> Result<Option<ed25519_dalek::VerifyingKey>> {
    let fed_path = opts
        .federation_config
        .clone()
        .unwrap_or_else(federation::resolve_federation_path);
    if fed_path.exists() {
        let cfg = federation::load_federation(&fed_path).with_context(|| {
            format!(
                "verify-attest: load federation config {} for primary key",
                fed_path.display()
            )
        })?;
        if let Some(signer) = cfg.signers.iter().find(|s| s.id == "primary") {
            let mut bytes = [0u8; 32];
            for i in 0..32 {
                bytes[i] = u8::from_str_radix(&signer.pubkey_hex[i * 2..i * 2 + 2], 16)
                    .with_context(|| "primary signer pubkey_hex malformed")?;
            }
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .context("primary signer pubkey is not a valid ed25519 key")?;
            return Ok(Some(vk));
        }
        // Config exists but has no "primary" signer — fall through to the
        // key file so single-signer hosts still authenticate.
    }
    for candidate in [
        crate::signing::resolve_signing_key_path(),
        attest_dir().join(crate::signing::SIGNING_KEY_FILE),
        PathBuf::from(crate::signing::SIGNING_KEY_FILE),
    ] {
        if candidate.exists() {
            let key = crate::signing::load_signing_key_from(&candidate)
                .with_context(|| format!("load primary key from {}", candidate.display()))?;
            return Ok(Some(key.verifying_key()));
        }
    }
    Ok(None)
}

/// Verify a v11+ entry's primary signature against `vk`. Fails closed on
/// malformed hex, wrong length, or signature mismatch.
fn verify_entry_signature(
    entry: &AttestEntry,
    vk: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    use ed25519_dalek::Verifier;
    if entry.sig_ed25519.len() != 128 {
        bail!(
            "v{} entry has sig_ed25519 of {} chars (expected 128)",
            entry.schema_version,
            entry.sig_ed25519.len()
        );
    }
    let mut sig_bytes = [0u8; 64];
    for i in 0..64 {
        sig_bytes[i] = u8::from_str_radix(&entry.sig_ed25519[i * 2..i * 2 + 2], 16)
            .with_context(|| "sig_ed25519 malformed hex")?;
    }
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let signable = compute_signable_sha256(entry)?;
    vk.verify(&signable, &sig)
        .context("primary signature over entry content does not verify")?;
    Ok(())
}

/// Like [`verify_chain`], but with additional cosignature/threshold
/// checks when `opts.require_threshold` is set. The federation config is
/// loaded lazily once and reused for every entry.
pub fn verify_chain_with_options(opts: &VerifyOptions) -> Result<VerifyReport> {
    let fed: Option<FederationConfig> = if opts.require_threshold {
        let p = opts
            .federation_config
            .clone()
            .unwrap_or_else(federation::resolve_federation_path);
        Some(federation::load_federation(&p)?)
    } else {
        None
    };
    let factory_expected: Option<FactoryExpected> = if opts.require_strict_factory {
        let p = opts
            .factory_expected_path
            .clone()
            .unwrap_or_else(factory::resolve_factory_expected_path);
        Some(factory::load_factory_expected(&p).with_context(|| {
            format!("verify-attest --strict-factory: load {}", p.display())
        })?)
    } else {
        None
    };
    let mut factory_verified: usize = 0;
    let entries = load_entries()?;

    // v11+ entries carry a signature over the full entry content; it is
    // ALWAYS verified (no opt-out). Resolve the trusted primary key once,
    // lazily, only if the chain actually contains signed-schema entries.
    let needs_sig_verify = entries
        .iter()
        .any(|e| e.schema_version >= SIGNED_ENTRY_MIN_SCHEMA);
    let primary_vk: Option<ed25519_dalek::VerifyingKey> = if needs_sig_verify {
        match resolve_primary_verifying_key(opts)? {
            Some(vk) => Some(vk),
            None => bail!(
                "verify-attest: chain contains v{}+ entries but no trusted primary key \
                 could be resolved (no usable factory_keys.toml signer 'primary' and no \
                 {}). Refusing to treat unauthenticated entries as verified.",
                SIGNED_ENTRY_MIN_SCHEMA,
                crate::signing::SIGNING_KEY_FILE
            ),
        }
    } else {
        None
    };

    // Entry-level checks: recompute each entry_sha256 and check the
    // prev_entry_sha256 chain link.
    let mut prev_hash = ZERO_HEX.to_string();
    for (i, e) in entries.iter().enumerate() {
        // Hash check.
        let mut e_copy = e.clone();
        let stored = e_copy.entry_sha256.clone();
        e_copy.entry_sha256 = String::new();
        let recomputed = compute_entry_sha256(&e_copy)?;
        let recomputed_hex = hex(&recomputed);
        if recomputed_hex != stored {
            bail!(
                "verify-attest: entry {} (cycle={}, module={}) has corrupted entry_sha256: \
                 stored={} recomputed={}",
                i,
                e.cycle,
                e.module,
                stored,
                recomputed_hex
            );
        }
        // Chain link check.
        if e.prev_entry_sha256 != prev_hash {
            bail!(
                "verify-attest: entry {} (cycle={}, module={}) chain break: \
                 prev_entry_sha256={} expected={}",
                i,
                e.cycle,
                e.module,
                e.prev_entry_sha256,
                prev_hash
            );
        }
        prev_hash = stored;
        // Schema version sanity. Accept any version between
        // READABLE_MIN_SCHEMA and SCHEMA_VERSION inclusive — older
        // entries are part of legitimate chain history, newer entries
        // signal "this binary is out of date" which is an operator
        // problem.
        if e.schema_version < READABLE_MIN_SCHEMA || e.schema_version > SCHEMA_VERSION {
            bail!(
                "verify-attest: entry {} has unexpected schema_version {} (expected {}..={})",
                i,
                e.schema_version,
                READABLE_MIN_SCHEMA,
                SCHEMA_VERSION
            );
        }
        // v11+: the primary signature commits to the full entry content
        // (module, accepted, diversity, seals, chain position, …). Always
        // verify it — this is what makes the log tamper-evident against a
        // filesystem attacker who does not hold the signing key.
        if e.schema_version >= SIGNED_ENTRY_MIN_SCHEMA {
            let vk = primary_vk
                .as_ref()
                .expect("primary key resolved when signed entries exist");
            verify_entry_signature(e, vk).with_context(|| {
                format!(
                    "verify-attest: entry {} (cycle={}, module={}) signature invalid",
                    i, e.cycle, e.module
                )
            })?;
        }
        // TASK-102: when ext_tlv_b64 is present, always re-decode and
        // check agreement with JSON fields. Corrupt blobs fail even
        // without --require-ext-tlv. Missing field only fails when the
        // strict flag is set (legacy v3–v7 chains stay readable).
        match &e.ext_tlv_b64 {
            Some(b64) => {
                crate::ext_tlv::verify_ext_tlv_b64(
                    b64,
                    e.cycle,
                    &e.module,
                    &e.candidate_sha256,
                )
                .with_context(|| {
                    format!(
                        "verify-attest: entry {} (cycle={}, module={}) ext_tlv_b64 invalid",
                        i, e.cycle, e.module
                    )
                })?;
            }
            None if opts.require_ext_tlv => {
                bail!(
                    "verify-attest: entry {} (cycle={}) missing ext_tlv_b64 under --require-ext-tlv",
                    i,
                    e.cycle
                );
            }
            None => {}
        }
        // TASK-140/144: validate digests when present; require non-empty
        // map on accepted entries when require_durable_seals.
        if !e.durable_seals.is_empty() {
            crate::durable_seal::validate_seals_map(&e.durable_seals).with_context(|| {
                format!(
                    "verify-attest: entry {} (cycle={}) durable_seals invalid",
                    i, e.cycle
                )
            })?;
        } else if opts.require_durable_seals && e.accepted {
            bail!(
                "verify-attest: entry {} (cycle={}, module={}) missing durable_seals \
                 under --require-durable-seals",
                i,
                e.cycle,
                e.module
            );
        }
        // TASK-124: when diversity is present, structural-validate it.
        // Missing diversity is always OK unless require_diversity (TASK-125).
        match &e.diversity {
            Some(d) => {
                crate::diversity::validate_evidence(d).with_context(|| {
                    format!(
                        "verify-attest: entry {} (cycle={}, module={}) diversity invalid",
                        i, e.cycle, e.module
                    )
                })?;
                if opts.require_diversity
                    && e.accepted
                    && !d.satisfies_require()
                {
                    bail!(
                        "verify-attest: entry {} (cycle={}, module={}) diversity present \
                         but empty under --require-diversity",
                        i,
                        e.cycle,
                        e.module
                    );
                }
            }
            None if opts.require_diversity && e.accepted => {
                bail!(
                    "verify-attest: entry {} (cycle={}, module={}) missing diversity \
                     under --require-diversity",
                    i,
                    e.cycle,
                    e.module
                );
            }
            None => {}
        }
        // Federation threshold enforcement (--require-threshold).
        if let Some(fed) = &fed {
            let entry_thr = e.federation_threshold.ok_or_else(|| {
                anyhow::anyhow!(
                    "verify-attest: entry {} (cycle={}) missing federation_threshold field; \
                     refusing under --require-threshold",
                    i,
                    e.cycle
                )
            })?;
            if entry_thr != fed.threshold {
                bail!(
                    "verify-attest: entry {} (cycle={}) declares federation_threshold={} \
                     but federation config has threshold={}",
                    i,
                    e.cycle,
                    entry_thr,
                    fed.threshold
                );
            }
            let cand = parse_hex32(&e.candidate_sha256).with_context(|| {
                format!("verify-attest: entry {} candidate_sha256 malformed", i)
            })?;
            federation::verify_cosignatures(&cand, &e.cosignatures, fed)
                .with_context(|| format!("verify-attest: entry {} (cycle={})", i, e.cycle))?;
        }
        // Factory-fingerprint enforcement (--strict-factory).
        if let Some(expected) = &factory_expected {
            factory::verify_entry_factory_subset(&e.factory_binaries, expected).with_context(
                || {
                    format!(
                        "verify-attest --strict-factory: entry {} (cycle={}, module={})",
                        i, e.cycle, e.module
                    )
                },
            )?;
            factory_verified += 1;
        }
    }

    // Anchor-level checks.
    let anchors = load_anchors()?;
    let mut prev_root = ZERO_HEX.to_string();
    for (i, a) in anchors.iter().enumerate() {
        if a.anchor_index != i as u64 {
            bail!(
                "verify-attest: anchor at position {} has anchor_index={} (expected {})",
                i,
                a.anchor_index,
                i
            );
        }
        if a.prev_anchor_merkle_root != prev_root {
            bail!(
                "verify-attest: anchor {} chain break: prev_anchor_merkle_root={} expected={}",
                i,
                a.prev_anchor_merkle_root,
                prev_root
            );
        }
        let start = a.first_entry as usize;
        let last = a.last_entry as usize;
        if last >= entries.len() {
            bail!(
                "verify-attest: anchor {} references entry {} but only {} entries exist",
                i,
                last,
                entries.len()
            );
        }
        if (last - start + 1) as u64 != ANCHOR_INTERVAL {
            bail!(
                "verify-attest: anchor {} spans {} entries (expected {})",
                i,
                last - start + 1,
                ANCHOR_INTERVAL
            );
        }
        let chunk = &entries[start..=last];
        if chunk.first().unwrap().entry_sha256 != a.first_entry_sha256 {
            bail!(
                "verify-attest: anchor {} first_entry_sha256 mismatch",
                i
            );
        }
        if chunk.last().unwrap().entry_sha256 != a.last_entry_sha256 {
            bail!(
                "verify-attest: anchor {} last_entry_sha256 mismatch",
                i
            );
        }
        let leaves: Vec<[u8; 32]> = chunk
            .iter()
            .map(|e| parse_hex32(&e.entry_sha256))
            .collect::<Result<Vec<_>>>()?;
        let root = hex(&compute_merkle_root(&leaves));
        if root != a.merkle_root {
            bail!(
                "verify-attest: anchor {} merkle_root mismatch: stored={} recomputed={}",
                i,
                a.merkle_root,
                root
            );
        }
        prev_root = a.merkle_root.clone();
    }

    // Rolling-root sidecar check (TASK-013). Three branches:
    //   - sidecar absent + caller didn't require it -> Absent status,
    //     verify still succeeds (legacy compat).
    //   - sidecar absent + caller required it       -> hard error.
    //   - sidecar present                            -> recompute root
    //     over the entries we just verified and compare. Any mismatch
    //     (entry_count, last_entry_sha256, merkle_root) is a tamper
    //     signal regardless of `require_merkle_root`.
    let merkle_status = match load_merkle_root()? {
        None => {
            if opts.require_merkle_root {
                bail!(
                    "verify-attest: {} is missing; run `morph` once or call \
                     attest::recompute_merkle_root_from_disk to materialise it",
                    merkle_root_path().display()
                );
            }
            MerkleRootStatus::Absent
        }
        Some(stored) => {
            // Accept any sidecar version in the supported range. A v3
            // sidecar from before TASK-022 commits to v3 entry hashes,
            // which still verify under v4 (canonical bytes unchanged).
            if stored.entry_schema_version < READABLE_MIN_SCHEMA
                || stored.entry_schema_version > SCHEMA_VERSION
            {
                bail!(
                    "verify-attest: rolling-root sidecar at {} records \
                     entry_schema_version={} but this binary expects {}..={}",
                    merkle_root_path().display(),
                    stored.entry_schema_version,
                    READABLE_MIN_SCHEMA,
                    SCHEMA_VERSION
                );
            }
            let expected_count = entries.len() as u64;
            if stored.entry_count != expected_count {
                bail!(
                    "verify-attest: rolling-root sidecar records entry_count={} \
                     but attest.log.jsonl has {} entries (tampered?)",
                    stored.entry_count,
                    expected_count
                );
            }
            let expected_last = entries
                .last()
                .map(|e| e.entry_sha256.clone())
                .unwrap_or_else(|| ZERO_HEX.to_string());
            if stored.last_entry_sha256 != expected_last {
                bail!(
                    "verify-attest: rolling-root sidecar last_entry_sha256={} \
                     but recomputed last={} (entry-tail tamper)",
                    stored.last_entry_sha256,
                    expected_last
                );
            }
            let recomputed = if entries.is_empty() {
                ZERO_HEX.to_string()
            } else {
                let leaves: Vec<[u8; 32]> = entries
                    .iter()
                    .map(|e| parse_hex32(&e.entry_sha256))
                    .collect::<Result<Vec<_>>>()?;
                // No-alloc path: reuse the leaves buffer in place. This
                // is the TASK-013 contract — the verify path goes
                // through merkle::compute_root_in_place rather than the
                // allocating wrapper.
                let mut buf = leaves.clone();
                let root = merkle::compute_root_in_place(&mut buf, leaves.len())
                    .context("verify-attest: recompute rolling root")?;
                hex(&root)
            };
            if recomputed != stored.merkle_root {
                bail!(
                    "verify-attest: rolling-root mismatch: stored={} recomputed={}",
                    stored.merkle_root,
                    recomputed
                );
            }
            MerkleRootStatus::Ok
        }
    };

    Ok(VerifyReport {
        entries_ok: entries.len(),
        anchors_ok: anchors.len(),
        merkle_root_verified: Some(merkle_status),
        factory_verified: if opts.require_strict_factory {
            Some(factory_verified)
        } else {
            None
        },
    })
}

// ============================================================================
// Chain rebuild for `morph cosign`
// ============================================================================

/// After modifying entries at and after `modified_from`, walk forward
/// recomputing `entry_sha256` and re-linking `prev_entry_sha256`. The
/// caller is responsible for updating the entries' content (e.g.
/// appending cosignatures) before invoking this.
pub fn rebuild_chain_after_cosign(entries: &mut [AttestEntry], modified_from: usize) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    if modified_from >= entries.len() {
        return Ok(());
    }
    // Establish prev_hash from the prior unmodified entry (or genesis).
    let mut prev_hash = if modified_from == 0 {
        ZERO_HEX.to_string()
    } else {
        entries[modified_from - 1].entry_sha256.clone()
    };
    for i in modified_from..entries.len() {
        entries[i].prev_entry_sha256 = prev_hash.clone();
        entries[i].entry_sha256 = String::new();
        let h = compute_entry_sha256(&entries[i])?;
        entries[i].entry_sha256 = hex(&h);
        prev_hash = entries[i].entry_sha256.clone();
    }
    Ok(())
}

/// Rebuild Merkle anchors whose entry range intersects
/// `[modified_from..len)`, then re-chain `prev_anchor_merkle_root` for
/// every anchor at or after the first affected one. Anchors outside the
/// affected range are left untouched.
pub fn rebuild_anchors_after_cosign(
    entries: &[AttestEntry],
    anchors: &mut [AnchorEntry],
    modified_from: usize,
) -> Result<()> {
    if anchors.is_empty() {
        return Ok(());
    }
    let first_affected = anchors.iter().position(|a| (a.last_entry as usize) >= modified_from);
    let Some(first) = first_affected else { return Ok(()) };
    let mut prev_root = if first == 0 {
        ZERO_HEX.to_string()
    } else {
        anchors[first - 1].merkle_root.clone()
    };
    for i in first..anchors.len() {
        let start = anchors[i].first_entry as usize;
        let last = anchors[i].last_entry as usize;
        if last >= entries.len() {
            bail!(
                "rebuild_anchors: anchor {} references entry {} but only {} entries exist",
                i,
                last,
                entries.len()
            );
        }
        let chunk = &entries[start..=last];
        let leaves: Vec<[u8; 32]> = chunk
            .iter()
            .map(|e| parse_hex32(&e.entry_sha256))
            .collect::<Result<Vec<_>>>()?;
        anchors[i].first_entry_sha256 = chunk.first().unwrap().entry_sha256.clone();
        anchors[i].last_entry_sha256 = chunk.last().unwrap().entry_sha256.clone();
        anchors[i].merkle_root = hex(&compute_merkle_root(&leaves));
        anchors[i].prev_anchor_merkle_root = prev_root.clone();
        prev_root = anchors[i].merkle_root.clone();
    }
    Ok(())
}

/// Atomically rewrite the attestation log and merkle anchor log from
/// the in-memory entries/anchors. Used by `morph cosign` after
/// `rebuild_chain_after_cosign` updates the chain hashes.
pub fn write_chain_atomic(entries: &[AttestEntry], anchors: &[AnchorEntry]) -> Result<()> {
    let log = attest_log_path();
    let log_tmp = log.with_extension("jsonl.tmp");
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&log_tmp)
            .with_context(|| format!("open {}", log_tmp.display()))?;
        for e in entries {
            let line = serde_json::to_string(e).context("serialize entry")?;
            f.write_all(line.as_bytes())?;
            f.write_all(b"\n")?;
        }
    }
    // Windows: rename fails if the destination exists. Remove first.
    if log.exists() {
        fs::remove_file(&log).ok();
    }
    fs::rename(&log_tmp, &log)
        .with_context(|| format!("rename {} -> {}", log_tmp.display(), log.display()))?;

    let anchor_log = anchor_log_path();
    if !anchors.is_empty() {
        let anchor_tmp = anchor_log.with_extension("jsonl.tmp");
        {
            let mut f = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&anchor_tmp)
                .with_context(|| format!("open {}", anchor_tmp.display()))?;
            for a in anchors {
                let line = serde_json::to_string(a).context("serialize anchor")?;
                f.write_all(line.as_bytes())?;
                f.write_all(b"\n")?;
            }
        }
        if anchor_log.exists() {
            fs::remove_file(&anchor_log).ok();
        }
        fs::rename(&anchor_tmp, &anchor_log)
            .with_context(|| format!("rename {} -> {}", anchor_tmp.display(), anchor_log.display()))?;
    }

    // Rolling-root sidecar mirrors the new chain. `morph cosign`
    // rebuilds the chain hashes; without this update the sidecar would
    // commit to the pre-cosign hashes and verify-attest would falsely
    // flag tamper after a legitimate cosign run.
    write_merkle_root(entries)?;

    Ok(())
}
