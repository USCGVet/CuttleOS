//! Library half of the `morph` factory orchestrator.
//!
//! The binary in `src/main.rs` is a thin CLI dispatcher; everything
//! re-usable lives here so tests and the new `tick` subcommand can call
//! the cycle logic without re-spawning a process.

pub mod attest;
pub mod cycle;
pub mod daemon;
pub mod diversity;
pub mod durable_seal;
pub mod ext_tlv;
pub mod factory;
pub mod federation;
pub mod merkle;
pub mod scheduler;
pub mod signing;
pub mod synth;
pub mod tui;

pub use ext_tlv::{build_ext_tlv_b64, verify_ext_tlv_b64, EXT_TLV_TAG_COUNT};

pub use attest::{
    load_merkle_root, recompute_merkle_root_from_disk, verify_chain, verify_chain_with_options,
    write_merkle_root, AnchorEntry, AttestEntry, AttestEntryFields, DiversityEvidence,
    MerkleRootFile, MerkleRootStatus, VerifyOptions, VerifyReport, ANCHOR_INTERVAL,
    ATTEST_DIR_ENV, ATTEST_MERKLE_ROOT, MERKLE_ROOT_SCHEMA_VERSION, READABLE_MIN_SCHEMA,
    SCHEMA_VERSION,
};
pub use diversity::{
    from_diversifier_log as diversity_from_diversifier_log,
    from_elf_pair as diversity_from_elf_pair, merge as diversity_merge, rate_to_bps,
    text_sha256_of_elf, validate_evidence as validate_diversity_evidence,
};
pub use durable_seal::{
    load_seals_dir as durable_load_seals_dir,
    resolve_durable_seals as durable_resolve_seals,
    seal_file as durable_seal_file, seals_map_from as durable_seals_map_from,
    validate_seals_map as durable_validate_seals_map, verify_file as durable_verify_file,
    DurableSeal, DURABLE_SEAL_SCHEMA, DURABLE_SEALS_DIR_ENV,
};
pub use factory::{
    fingerprint as fingerprint_factory, fingerprint_uncached as fingerprint_factory_uncached,
    hash_file as hash_factory_file, load_factory_expected, resolve_factory_expected_path,
    validate_factory_expected, verify_entry_factory_subset, FactoryExpected,
    COMPONENT_DIVERSIFY, COMPONENT_MORPH, COMPONENT_RUSTC, COMPONENT_VERIFY,
    FACTORY_BIN_DIR_ENV, FACTORY_EXPECTED_ENV, FACTORY_EXPECTED_PATH, FACTORY_OVERRIDE_ENV,
};
pub use federation::{
    load_federation, resolve_federation_path, verify_cosignatures, Cosignature, FederationConfig,
    Signer as FederationSigner, FEDERATION_CONFIG_ENV, FEDERATION_CONFIG_PATH,
};
pub use cycle::{
    attest_proposal, propose_cycle, run_bundle, run_cycle, BundleCycleArgs, CycleArgs, Proposal,
    SynthesizerKind, PROPOSAL_SCHEMA_VERSION,
};
pub use daemon::{
    run_daemon, run_daemon_with, Clock, DaemonArgs, DaemonEvent, DaemonReport, FakeClock,
    ProductionWorkRunner, SystemClock, WorkRunner, DAEMON_LOG, DEFAULT_HEARTBEAT_SECS,
    DEFAULT_MAX_CYCLE_SECS, DEFAULT_POLL_SECS,
};
pub use scheduler::{
    load_state, pick_next, pick_next_work, pick_next_work_at, record_success_bundle,
    record_success_bundle_at, save_state, BundleConfig, ModuleConfig, ModuleState,
    NextBundleChoice, NextChoice, NextWork, SchedulerConfig, SchedulerState, EX_NOINPUT,
    SCHEDULER_CONFIG, SCHEDULER_STATE,
};
pub use signing::{
    init_signing_key, load_signing_key, resolve_signing_key_path, SIGNING_KEY_ENV,
    SIGNING_KEY_FILE,
};
pub use synth::{
    parse_anthropic_response_text, AnthropicSynth, MutationBudget, PassThrough, PromptBuilder,
    PromptOnly, SynthRequest, SynthResponse, Synthesizer, ANTHROPIC_API_KEY_ENV,
    ANTHROPIC_API_VERSION, ANTHROPIC_DEFAULT_ENDPOINT, ANTHROPIC_DEFAULT_MAX_TOKENS,
    ANTHROPIC_DEFAULT_MODEL, ANTHROPIC_MODEL_ENV, SYNTHESIS_PROMPT_V1, SYNTH_BEGIN_FENCE,
    SYNTH_END_FENCE,
};
