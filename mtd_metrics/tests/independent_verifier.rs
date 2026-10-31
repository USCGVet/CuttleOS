//! Multi-seed Pairwise Diversity, Dataflow-Constrained Chain Simulation, and
//! Independent Python Verifier Cross-Check Suite for `cuttle-mtd-metrics`.

use std::process::Command;

use cuttle_binmorph::{rewrite_elf_bytes, rewrite_function, Prng, Stats};
use cuttle_mtd_metrics::chainsim::evaluate_dataflow_chains;
use cuttle_mtd_metrics::{
    churn, evaluate_pairwise_diversity, extract_gadgets, DEFAULT_MAX_INSTRS,
};

/// Build a multi-block x86-64 function buffer with rich register/instruction diversity
/// and non-clobbering ROP gadget suffixes for `[rdi=7, rsi=6, rdx=2, rax=0]`.
fn build_rich_function_code() -> Vec<u8> {
    vec![
        0x55, // push rbp
        0x53, // push rbx
        0x41, 0x54, // push r12
        0x41, 0x55, // push r13
        0x41, 0x56, // push r14
        0x41, 0x57, // push r15
        0x48, 0x83, 0xEC, 0x18, // sub rsp, 0x18
        0x48, 0x89, 0xFB, // mov rbx, rdi
        0x49, 0x89, 0xF4, // mov r12, rsi
        0x49, 0x89, 0xD5, // mov r13, rdx
        0x49, 0x89, 0xCE, // mov r14, rcx
        0x4D, 0x89, 0xC7, // mov r15, r8
        0x48, 0x89, 0xC3, // mov rbx, rax (embedded 0xC3!)
        0x4C, 0x01, 0xE3, // add rbx, r12
        0x4D, 0x31, 0xEE, // xor r14, r13
        0x4D, 0x29, 0xFE, // sub r14, r15
        0x81, 0xC3, 0x44, 0x33, 0x22, 0x11, // add ebx, 0x11223344
        0x49, 0x81, 0xF4, 0x01, 0x02, 0x03, 0x04, // xor r12, 0x04030201
        0x48, 0x89, 0xDF, // mov rdi, rbx
        0x4C, 0x89, 0xE6, // mov rsi, r12
        0x4C, 0x89, 0xEA, // mov rdx, r13
        0x4C, 0x89, 0xF0, // mov rax, r14
        0x48, 0x83, 0xC4, 0x18, // add rsp, 0x18
        0x41, 0x5F, // pop r15
        0x41, 0x5E, // pop r14
        0x41, 0x5D, // pop r13
        0x41, 0x5C, // pop r12
        0x5B, // pop rbx
        0x5D, // pop rbp
        0xC3, // ret
    ]
}

#[test]
fn multi_seed_binmorph_pairwise_diversity_and_dataflow_chain_disruption() {
    let base_fn = build_rich_function_code();
    let base_ip = 0x0040_1000u64;

    // Generate 12 morphed variants from seeds 1..=12:
    let mut variants_owned: Vec<(String, Vec<u8>)> = Vec::new();
    for seed in 1u64..=12 {
        let mut code = base_fn.clone();
        let mut prng = Prng::new(seed);
        let mut stats = Stats::default();
        rewrite_function(&mut code, base_ip, &mut prng, &mut stats);
        assert!(stats.swapped > 0 || stats.reg_remapped_instrs > 0);
        variants_owned.push((format!("seed_{seed}"), code));
    }

    let variant_refs: Vec<(&str, &[u8], u64)> = variants_owned
        .iter()
        .map(|(lbl, bytes)| (lbl.as_str(), bytes.as_slice(), base_ip))
        .collect();

    let pw = evaluate_pairwise_diversity(&variant_refs, DEFAULT_MAX_INSTRS);
    assert_eq!(pw.variant_count, 12);
    assert_eq!(pw.pair_count, 66); // C(12, 2) = 66
    assert_eq!(
        pw.unique_sha256_count, 12,
        "all 12 binmorph seeds must produce pairwise distinct .text variants (no 2-state flip-flop)"
    );
    assert!(
        pw.min_pairwise_byte_diff_fraction > 0.05,
        "every pair of distinct seeds must differ in .text bytes, got min={}",
        pw.min_pairwise_byte_diff_fraction
    );
    assert!(
        pw.mean_pairwise_positional_survival < 0.75,
        "expected mean pairwise positional gadget survival < 0.75 across seed pairs, got {}",
        pw.mean_pairwise_positional_survival
    );

    // Verify dataflow-constrained chain simulation on a base gadget pool with
    // non-clobbering chains for `[rbx=3, rbp=5]`:
    let base_gs = extract_gadgets(&base_fn, base_ip, DEFAULT_MAX_INSTRS);
    let var1_gs = extract_gadgets(&variants_owned[0].1, base_ip, DEFAULT_MAX_INSTRS);
    let df_self = evaluate_dataflow_chains(&base_gs, &base_gs, &[3, 5], 16, 99).unwrap();
    assert_eq!(df_self.static_dataflow_viable_rate, 1.0);

    let df_var = evaluate_dataflow_chains(&base_gs, &var1_gs, &[3, 5], 16, 99).unwrap();
    assert!(
        df_var.static_dataflow_viable_rate < 1.0
            || churn(&base_gs, &var1_gs).positional_survival() < 0.7,
        "morphed variant must disrupt static chain offsets or gadget kinds"
    );
}

#[test]
fn cross_check_mtd_metrics_against_independent_python_verifier() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().expect("workspace root");
    let script = root.join("tools").join("verify_metrics_independent.py");
    assert!(script.exists(), "missing {}", script.display());

    // Build a valid ELF64 binary with our rich function, rewrite it in-memory with
    // `cuttle_binmorph::rewrite_elf_bytes`, and pass `--base` and `--variant` to the
    // independent Python verifier so zero `cargo run` lock contention can occur.
    let fn_bytes = build_rich_function_code();
    let text_vaddr = 0x0040_1000u64;
    let mut strtab = vec![0u8];
    let st_name = strtab.len() as u32;
    strtab.extend_from_slice(b"rich_fn\0");
    let mut symtab = vec![0u8; 24];
    let mut sym = [0u8; 24];
    sym[0..4].copy_from_slice(&st_name.to_le_bytes());
    sym[4] = (1 << 4) | 2;
    sym[6..8].copy_from_slice(&1u16.to_le_bytes());
    sym[8..16].copy_from_slice(&text_vaddr.to_le_bytes());
    sym[16..24].copy_from_slice(&(fn_bytes.len() as u64).to_le_bytes());
    symtab.extend_from_slice(&sym);

    let shstrtab = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
    let mut base_elf = vec![0u8; 64];
    let text_off = base_elf.len();
    base_elf.extend_from_slice(&fn_bytes);
    while base_elf.len() % 8 != 0 {
        base_elf.push(0);
    }
    let symtab_off = base_elf.len();
    base_elf.extend_from_slice(&symtab);
    let strtab_off = base_elf.len();
    base_elf.extend_from_slice(&strtab);
    let shstrtab_off = base_elf.len();
    base_elf.extend_from_slice(shstrtab);
    while base_elf.len() % 8 != 0 {
        base_elf.push(0);
    }
    let shoff = base_elf.len();

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
    push_shdr(&mut base_elf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    push_shdr(
        &mut base_elf,
        1,
        1,
        6,
        text_vaddr,
        text_off as u64,
        fn_bytes.len() as u64,
        0,
        0,
        16,
        0,
    );
    push_shdr(
        &mut base_elf,
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
    push_shdr(
        &mut base_elf,
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
    push_shdr(
        &mut base_elf,
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
    base_elf[0..4].copy_from_slice(b"\x7FELF");
    base_elf[4] = 2;
    base_elf[5] = 1;
    base_elf[6] = 1;
    base_elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    base_elf[18..20].copy_from_slice(&62u16.to_le_bytes());
    base_elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    base_elf[24..32].copy_from_slice(&text_vaddr.to_le_bytes());
    base_elf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    base_elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    base_elf[58..60].copy_from_slice(&64u16.to_le_bytes());
    base_elf[60..62].copy_from_slice(&5u16.to_le_bytes());
    base_elf[62..64].copy_from_slice(&4u16.to_le_bytes());

    let mut variant_elf = base_elf.clone();
    let stats = rewrite_elf_bytes(&mut variant_elf, 42).expect("rewrite_elf_bytes");
    assert_eq!(stats.functions, 1);

    let tmp_dir = std::env::temp_dir().join(format!("cuttle_indep_verify_{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir");
    let base_path = tmp_dir.join("base.elf");
    let var_path = tmp_dir.join("variant.elf");
    std::fs::write(&base_path, &base_elf).expect("write base.elf");
    std::fs::write(&var_path, &variant_elf).expect("write variant.elf");

    let out = ["python", "python3"]
        .into_iter()
        .find_map(|bin| {
            Command::new(bin)
                .arg(&script)
                .arg("--base")
                .arg(&base_path)
                .arg("--variant")
                .arg(&var_path)
                .output()
                .ok()
                .filter(|o| o.status.success())
        })
        .expect("invoke python/python3 tools/verify_metrics_independent.py");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let json_val: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("parse independent verifier JSON");
    assert_eq!(json_val["functions_total"].as_u64(), Some(1));
    assert_eq!(json_val["functions_mutated"].as_u64(), Some(1));
    assert_eq!(
        json_val["interior_c3_cf_bytes_base"].as_u64(),
        Some(2),
        "base ELF had 2 embedded 0xC3 bytes (in mov rbx, rax and add ebx, imm32)"
    );
    assert_eq!(
        json_val["interior_c3_cf_bytes_variant"].as_u64(),
        Some(0),
        "independent verifier must confirm embedded 0xC3 was scrubbed by binmorph"
    );
    let pos_surv = json_val["positional_suffix_survival_rate"]
        .as_f64()
        .expect("positional_suffix_survival_rate");
    assert!(
        pos_surv < 0.5,
        "independent verifier positional suffix survival should be < 0.5, got {pos_surv}"
    );
}

#[test]
fn cross_check_real_compiled_kernel_elf_with_independent_python_verifier_and_dataflow_chains() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().expect("workspace root");
    let script = root.join("tools").join("verify_metrics_independent.py");
    assert!(script.exists(), "missing {}", script.display());

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
    let kernel_elf_path = if let Some(found) = candidate_paths.iter().find(|p| p.exists()) {
        found.clone()
    } else {
        let kernel_dir = root.join("target_enterprise_kernel");
        let status = Command::new("cargo")
            .arg("build")
            .arg("--release")
            .current_dir(&kernel_dir)
            .status()
            .expect("invoke cargo build --release in target_enterprise_kernel");
        assert!(status.success(), "target_enterprise_kernel build failed");
        candidate_paths
            .into_iter()
            .find(|p| p.exists())
            .expect("target_enterprise_kernel ELF missing after build")
    };

    let base_elf = std::fs::read(&kernel_elf_path).expect("read real kernel ELF");
    let mut variant_elf = base_elf.clone();
    let stats = rewrite_elf_bytes(&mut variant_elf, 42).expect("rewrite real kernel ELF");
    assert!(
        stats.functions >= 2000 && stats.swapped >= 25_000,
        "expected >= 2000 functions and >= 25000 instructions rewritten on real kernel ELF, got {stats:?}"
    );

    let tmp_dir = std::env::temp_dir().join(format!(
        "cuttle_real_kernel_indep_verify_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir");
    let base_path = tmp_dir.join("kernel_base.elf");
    let var_path = tmp_dir.join("kernel_seed42.elf");
    std::fs::write(&base_path, &base_elf).expect("write kernel_base.elf");
    std::fs::write(&var_path, &variant_elf).expect("write kernel_seed42.elf");

    let out = ["python", "python3"]
        .into_iter()
        .find_map(|bin| {
            Command::new(bin)
                .arg(&script)
                .arg("--base")
                .arg(&base_path)
                .arg("--variant")
                .arg(&var_path)
                .output()
                .ok()
                .filter(|o| o.status.success())
        })
        .expect("invoke python/python3 tools/verify_metrics_independent.py on real kernel ELF");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let json_val: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("parse independent verifier JSON on real kernel");
    let fns_total = json_val["functions_total"].as_u64().expect("functions_total");
    let fns_mutated = json_val["functions_mutated"]
        .as_u64()
        .expect("functions_mutated");
    let hamming_frac = json_val["hamming_changed_fraction"]
        .as_f64()
        .expect("hamming_changed_fraction");
    let c3_base = json_val["interior_c3_cf_bytes_base"]
        .as_u64()
        .expect("interior_c3_cf_bytes_base");
    let c3_var = json_val["interior_c3_cf_bytes_variant"]
        .as_u64()
        .expect("interior_c3_cf_bytes_variant");
    let pos_surv = json_val["positional_suffix_survival_rate"]
        .as_f64()
        .expect("positional_suffix_survival_rate");
    let jaccard_dist = json_val["distinct_suffix_jaccard_distance"]
        .as_f64()
        .expect("distinct_suffix_jaccard_distance");

    eprintln!(
        "real kernel ELF independent verification: functions={}/{} ({:.1}% mutated), hamming_diff={:.2}%, pos_survival={:.2}%, jaccard_dist={:.2}%, interior_c3_cf={} -> {} ({} scrubbed)",
        fns_mutated,
        fns_total,
        (fns_mutated as f64 / fns_total as f64) * 100.0,
        hamming_frac * 100.0,
        pos_surv * 100.0,
        jaccard_dist * 100.0,
        c3_base,
        c3_var,
        c3_base.saturating_sub(c3_var)
    );

    assert!(fns_total >= 2000, "expected >= 2000 kernel functions, got {fns_total}");
    assert!(
        fns_mutated >= 1800,
        "expected >= 1800 mutated kernel functions, got {fns_mutated}"
    );
    assert!(
        hamming_frac > 0.18,
        "expected > 18% .text byte Hamming difference on real kernel ELF, got {hamming_frac}"
    );
    assert!(
        c3_var < c3_base && c3_base - c3_var >= 500,
        "expected >= 500 interior 0xC3/0xCF gadget bytes scrubbed on real kernel ELF, got {c3_base} -> {c3_var}"
    );
    assert!(
        pos_surv < 0.55 && jaccard_dist > 0.50,
        "expected positional suffix survival < 0.55 and Jaccard distance > 0.50, got pos={pos_surv} jaccard={jaccard_dist}"
    );

    // Also evaluate 6-seed pairwise diversity and dataflow-constrained chain simulation on a
    // 64 KiB slice of the real kernel `.text`:
    let (base_text_bytes, base_text_vaddr) =
        cuttle_mtd_metrics::read_text_section(&kernel_elf_path)
            .expect("read_text_section on real kernel ELF");
    let text_file_pos = base_elf
        .windows(64)
        .position(|w| w == &base_text_bytes[..64])
        .expect("locate .text offset in real kernel ELF");
    let slice_len = base_text_bytes.len().min(65_536);
    let mut seed_variants: Vec<(String, Vec<u8>)> = Vec::new();
    for seed in 1u64..=6 {
        let mut elf_copy = base_elf.clone();
        rewrite_elf_bytes(&mut elf_copy, seed).expect("rewrite real kernel ELF seed");
        seed_variants.push((
            format!("kernel_seed_{seed}"),
            elf_copy[text_file_pos..text_file_pos + slice_len].to_vec(),
        ));
    }
    let refs: Vec<(&str, &[u8], u64)> = seed_variants
        .iter()
        .map(|(lbl, b)| (lbl.as_str(), b.as_slice(), base_text_vaddr))
        .collect();
    let pw = evaluate_pairwise_diversity(&refs, DEFAULT_MAX_INSTRS);
    assert_eq!(pw.variant_count, 6);
    assert_eq!(pw.pair_count, 15);
    assert_eq!(pw.unique_sha256_count, 6);
    assert!(
        pw.min_pairwise_byte_diff_fraction > 0.12,
        "expected min pairwise byte diff > 12% across 6 real kernel seeds, got {}",
        pw.min_pairwise_byte_diff_fraction
    );

    let base_gs = extract_gadgets(
        &base_text_bytes[..slice_len],
        base_text_vaddr,
        DEFAULT_MAX_INSTRS,
    );
    let var_gs = extract_gadgets(&seed_variants[0].1, base_text_vaddr, DEFAULT_MAX_INSTRS);
    let df_report =
        evaluate_dataflow_chains(&base_gs, &var_gs, &[7, 6, 2, 0], 500, 2026).expect("dataflow chains on real kernel");
    eprintln!(
        "real kernel 64KiB .text dataflow chains (n=500, [rdi,rsi,rdx,rax]): static_viable={:.2}%, mean_step_survival={:.2}%, relocated_pool_satisfiable={}",
        df_report.static_dataflow_viable_rate * 100.0,
        df_report.mean_step_dataflow_survival * 100.0,
        df_report.relocated_pool_satisfiable
    );
    assert!(
        df_report.static_dataflow_viable_rate < 0.12,
        "expected static 4-step dataflow chain survival < 12% under in-place binmorph alone on real kernel .text, got {}",
        df_report.static_dataflow_viable_rate
    );
}
