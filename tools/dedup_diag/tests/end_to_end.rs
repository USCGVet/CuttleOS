//! End-to-end smoke test for `dedup_diag`.
//!
//! Builds a synthetic `cycles.jsonl` containing one genuine collision
//! cluster, runs `run_diagnosis` without the MIR pass (no candidate
//! files on disk → labels resolve to `Indeterminate`), and asserts the
//! Markdown output contains the expected cluster identifiers.

use std::fs;

use dedup_diag::{run_diagnosis, CollisionLabel};

#[test]
fn run_diagnosis_against_synthetic_cycles_jsonl_emits_expected_markdown() {
    let dir = std::env::temp_dir().join("dedup_diag_e2e");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cycles.jsonl");
    let body = "\
        {\"cycle\":0,\"accepted\":true,\"reject_reason\":null,\"candidate_sha256\":\"01aa\",\"elf_text_sha256\":\"deadbeef00000000000000000000000000000000000000000000000000000000\",\"elf_text_size\":1024,\"function_offsets\":{}}\n\
        {\"cycle\":1,\"accepted\":true,\"reject_reason\":null,\"candidate_sha256\":\"02bb\",\"elf_text_sha256\":\"feedface00000000000000000000000000000000000000000000000000000000\",\"elf_text_size\":1024,\"function_offsets\":{}}\n\
        {\"cycle\":2,\"accepted\":true,\"reject_reason\":null,\"candidate_sha256\":\"03cc\",\"elf_text_sha256\":\"deadbeef00000000000000000000000000000000000000000000000000000000\",\"elf_text_size\":1024,\"function_offsets\":{}}\n\
        {\"cycle\":3,\"accepted\":false,\"reject_reason\":\"verifier rejected\",\"candidate_sha256\":\"\",\"elf_text_sha256\":\"\",\"elf_text_size\":0,\"function_offsets\":{}}\n\
        {\"cycle\":4,\"accepted\":true,\"reject_reason\":null,\"candidate_sha256\":\"05ee\",\"elf_text_sha256\":\"feedface00000000000000000000000000000000000000000000000000000000\",\"elf_text_size\":1024,\"function_offsets\":{}}\n";
    fs::write(&path, body).unwrap();

    let summary = run_diagnosis(&path, None, None).expect("run_diagnosis");
    assert_eq!(summary.total_accepted_cycles, 4);
    assert_eq!(summary.distinct_elf_text_sha256, 2);
    assert_eq!(summary.cluster_count, 2);
    assert_eq!(summary.redundant_cycle_count, 2);
    assert_eq!(summary.ast_equivalent_pairs, 0);
    assert_eq!(summary.codegen_folded_pairs, 0);
    assert_eq!(summary.indeterminate_pairs, 2);
    assert!(summary.markdown.contains("Accepted cycles: 4"));
    assert!(summary.markdown.contains("Distinct `elf_text_sha256`: 2"));
    // Both clusters should be enumerated in the Markdown output.
    assert!(summary.markdown.contains("deadbeef"));
    assert!(summary.markdown.contains("feedface"));
    // With no candidates dir, every label is indeterminate citing
    // missing candidate sources.
    for diag in &summary.clusters {
        for lab in &diag.labels {
            assert!(matches!(lab, CollisionLabel::Indeterminate(_)));
        }
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn run_diagnosis_with_candidates_dir_computes_source_diffs() {
    let dir = std::env::temp_dir().join("dedup_diag_e2e_with_candidates");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cycles.jsonl");
    let body = "\
        {\"cycle\":0,\"accepted\":true,\"reject_reason\":null,\"candidate_sha256\":\"01aa\",\"elf_text_sha256\":\"colsha00000000000000000000000000000000000000000000000000000000\",\"elf_text_size\":1024,\"function_offsets\":{}}\n\
        {\"cycle\":1,\"accepted\":true,\"reject_reason\":null,\"candidate_sha256\":\"02bb\",\"elf_text_sha256\":\"colsha00000000000000000000000000000000000000000000000000000000\",\"elf_text_size\":1024,\"function_offsets\":{}}\n";
    fs::write(&path, body).unwrap();

    let cand_dir = dir.join("candidates");
    fs::create_dir_all(&cand_dir).unwrap();
    fs::write(
        cand_dir.join("cycle_00.rs"),
        "fn alpha() {\n    let x = 1;\n}\n",
    )
    .unwrap();
    fs::write(
        cand_dir.join("cycle_01.rs"),
        "fn alpha() {\n    let x = 2;\n}\n",
    )
    .unwrap();

    let summary = run_diagnosis(&path, Some(&cand_dir), None).expect("run_diagnosis");
    assert_eq!(summary.cluster_count, 1);
    let diag = &summary.clusters[0];
    assert!(diag.source_diffs[0].is_some());
    let d = diag.source_diffs[0].as_ref().unwrap();
    assert_eq!(d.differing_line_count, 1);
    // MIR pass disabled → label is Indeterminate citing that fact.
    if let CollisionLabel::Indeterminate(reason) = &diag.labels[0] {
        assert!(reason.contains("MIR pass disabled"));
    } else {
        panic!("expected Indeterminate; got {:?}", diag.labels[0]);
    }
    let _ = fs::remove_dir_all(&dir);
}
