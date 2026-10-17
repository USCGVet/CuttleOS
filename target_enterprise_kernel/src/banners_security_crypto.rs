//! Cryptographic, KPTI, TPM, Audit, eBPF, X.509, and diagnostic boot banners.

pub(crate) use crate::*;


/// HASH: hash the locked fixture input through `HashImpl`, assert the
/// 32-byte digest matches the locked expected bytes, emit
/// `HASH OK digest_sha=<hex16>\n`.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_hash_digest() {
    let mut got = [0u8; 32];
    HashImpl::hash(kf::HASH_INPUT, &mut got);
    assert_eq_bytes(&got, &kf::HASH_EXPECTED, "HashImpl digest");

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"HASH OK digest_sha=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += hex_encode(&got, 8, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// KPTI: build a synthetic kernel L4 (kernel .text, heap, IDT, signing
// key, three KPTI trampoline pages, two user pages), call
// `KptiImpl::build_user_view` to produce a per-task user view that
// strips the four secret regions, then `validate_user_view` to assert
// the locked invariants hold. On success emit:
//   `KPTI build_user_view OK secrets=4\n`
//   `KPTI validate_user_view OK violations=0\n`
//
// The synthetic fixture mirrors the post-boot kernel L4 shape (kernel
// `.text` at canonical-high addresses, KPTI trampolines at the locked
// KPTI_*_VIRT slots, user code/stack at canonical-low addresses) so
// the validate path exercises a realistic separation, not a contrived
// minimum.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_kpti() {
    let mut kernel: PageTable<32> = PageTable::new();
    // Kernel secrets — these MUST be stripped from the user view.
    let secrets: [u64; 4] = [
        0xFFFF_FFFF_8000_0000, // kernel .text
        0xFFFF_FFFF_9000_0000, // kernel heap
        0xFFFF_FFFF_A000_0000, // IDT
        0xFFFF_FFFF_B000_0000, // Ed25519 private key page
    ];
    kernel.map(secrets[0], PTE_PRESENT).expect("kpti map .text");
    kernel
        .map(secrets[1], PTE_PRESENT | PTE_WRITABLE | PTE_NX)
        .expect("kpti map heap");
    kernel
        .map(secrets[2], PTE_PRESENT | PTE_NX)
        .expect("kpti map IDT");
    kernel
        .map(secrets[3], PTE_PRESENT | PTE_NX)
        .expect("kpti map signing-key");

    // KPTI trampolines — USER bit set so the build path retains them.
    kernel
        .map(KPTI_TRAMPOLINE_VIRT, PTE_PRESENT | PTE_USER)
        .expect("kpti map SYSCALL trampoline");
    kernel
        .map(KPTI_IRETQ_VIRT, PTE_PRESENT | PTE_USER)
        .expect("kpti map iretq trampoline");
    kernel
        .map(KPTI_IRQ_TIMER_VIRT, PTE_PRESENT | PTE_USER)
        .expect("kpti map timer trampoline");

    // User pages — USER bit set; build path keeps these.
    kernel
        .map(0x0000_0000_4000_0000, PTE_PRESENT | PTE_USER | PTE_NX)
        .expect("kpti map user code");
    kernel
        .map(
            0x0000_0000_5000_0000,
            PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX,
        )
        .expect("kpti map user stack");

    let user = KptiImpl::<32>::build_user_view(&kernel, &secrets);

    // Emit build banner: `KPTI build_user_view OK secrets=4\n`.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"KPTI build_user_view OK secrets=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(secrets.len() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Validate. Panic on any violation — the QEMU smoke test then
    // surfaces the missing banner as a failure.
    if let Err(violation) = KptiImpl::<32>::validate_user_view(&user, &kernel, &secrets) {
        // Touch `violation` to avoid `unused_variables`; emit a tag
        // before panicking so even a panic-handler-eaten message at
        // least surfaces the violation kind.
        serial_write_str("KPTI VALIDATE FAIL: ");
        match violation {
            proteus_contracts::KptiViolation::SecretLeaked { .. } => {
                serial_write_str("SecretLeaked\n")
            }
            proteus_contracts::KptiViolation::UserPageMissing { .. } => {
                serial_write_str("UserPageMissing\n")
            }
            proteus_contracts::KptiViolation::KernelBitsSetOnUserPage { .. } => {
                serial_write_str("KernelBitsSetOnUserPage\n")
            }
        }
        panic!("KPTI validate_user_view returned an invariant violation");
    }

    // Emit validate banner: `KPTI validate_user_view OK violations=0\n`.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"KPTI validate_user_view OK violations=0";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Stateless IPv4 packet-filter exercise.
///
/// Builds a four-entry [`FirewallTable`] mirroring the TASK-050 spec:
///
/// 1. Accept TCP/22 from `10/8`
/// 2. Accept UDP/53 from anywhere
/// 3. Reject ICMP from `192.168/16`
/// 4. (table empty otherwise → default Drop)
///
/// Evaluates three synthetic IPv4 packets through
/// [`FirewallImpl::evaluate`] AND through [`FirewallTable::evaluate`]
/// (which folds in the default-action), asserting both paths return
/// the locked verdict — Accept, Accept, Drop (the ICMP rule is
/// `Reject`, which the operator-facing banner reports as `drop` per
/// the task spec's verdict label, but the underlying `Verdict` is
/// `Reject`; we assert the underlying byte too).
///
/// After the per-packet checks, the function feeds a packet that no
/// rule matches (TCP/443 from a public IP) and asserts the default
/// fall-through is `Drop`.
///
/// A morph that perturbs the CIDR-mask arithmetic, the descending-
/// mask-score ordering invariant, the first-match-wins semantics, or
/// the proto-byte equality check panics inside `banner_firewall` and
/// the two banners never appear.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_firewall() {
    // ------------------------------------------------------------------
    // 1. Build the canonical 4-rule table (3 rules + default fallthrough).
    // ------------------------------------------------------------------
    let mut table: FirewallTable<8> = FirewallTable::new();

    // Rule 1: Accept TCP/22 from 10/8 (any source port, dst port 22).
    let r1 = FilterRule {
        src_ip: [10, 0, 0, 0],
        src_mask: 8,
        dst_ip: [0, 0, 0, 0],
        dst_mask: 0,
        proto: IP_PROTO_TCP,
        src_port_start: FW_PORT_ANY,
        src_port_end: FW_PORT_ANY,
        dst_port_start: 22,
        dst_port_end: 22,
        action: FilterAction::Accept,
    };
    // Rule 2: Accept UDP/53 from 0/0 (everywhere, any source port, dst 53).
    let r2 = FilterRule {
        src_ip: [0, 0, 0, 0],
        src_mask: 0,
        dst_ip: [0, 0, 0, 0],
        dst_mask: 0,
        proto: IP_PROTO_UDP,
        src_port_start: FW_PORT_ANY,
        src_port_end: FW_PORT_ANY,
        dst_port_start: 53,
        dst_port_end: 53,
        action: FilterAction::Accept,
    };
    // Rule 3: Reject ICMP from 192.168/16.
    let r3 = FilterRule {
        src_ip: [192, 168, 0, 0],
        src_mask: 16,
        dst_ip: [0, 0, 0, 0],
        dst_mask: 0,
        proto: IP_PROTO_ICMP,
        src_port_start: FW_PORT_ANY,
        src_port_end: FW_PORT_ANY,
        dst_port_start: FW_PORT_ANY,
        dst_port_end: FW_PORT_ANY,
        action: FilterAction::Reject,
    };

    if r1.validate().is_err() {
        panic!("firewall: r1 failed validate");
    }
    if r2.validate().is_err() {
        panic!("firewall: r2 failed validate");
    }
    if r3.validate().is_err() {
        panic!("firewall: r3 failed validate");
    }

    // Insert in operator-natural order; the table re-orders by
    // descending mask score so r3 (/16) winds up at slot 0, r1 (/8)
    // at slot 1, r2 (/0) at slot 2.
    if table.insert(r1).is_err() {
        panic!("firewall: insert r1 failed");
    }
    if table.insert(r2).is_err() {
        panic!("firewall: insert r2 failed");
    }
    if table.insert(r3).is_err() {
        panic!("firewall: insert r3 failed");
    }
    if table.len() != 3 {
        panic!("firewall: table len drift");
    }

    // Locked ordering: r3 (/16) > r1 (/8) > r2 (/0).
    let s = table.as_slice();
    if s[0].proto != IP_PROTO_ICMP {
        panic!("firewall: slot 0 not r3");
    }
    if s[1].proto != IP_PROTO_TCP {
        panic!("firewall: slot 1 not r1");
    }
    if s[2].proto != IP_PROTO_UDP {
        panic!("firewall: slot 2 not r2");
    }

    // ------------------------------------------------------------------
    // 2. Evaluate the three synthetic packets.
    // ------------------------------------------------------------------
    // Packet A: 10.0.0.5:40000 → 192.168.1.10:22 TCP → Accept.
    let pa = Ipv4PacketView {
        src_ip: [10, 0, 0, 5],
        dst_ip: [192, 168, 1, 10],
        protocol: IP_PROTO_TCP,
        src_port: 40000,
        dst_port: 22,
    };
    // Packet B: 8.8.8.8:12345 → 10.0.0.5:53 UDP → Accept.
    let pb = Ipv4PacketView {
        src_ip: [8, 8, 8, 8],
        dst_ip: [10, 0, 0, 5],
        protocol: IP_PROTO_UDP,
        src_port: 12345,
        dst_port: 53,
    };
    // Packet C: 192.168.1.42 → 10.0.0.5 ICMP → Reject (banner labels "drop").
    let pc = Ipv4PacketView {
        src_ip: [192, 168, 1, 42],
        dst_ip: [10, 0, 0, 5],
        protocol: IP_PROTO_ICMP,
        src_port: 0,
        dst_port: 0,
    };

    let va = FirewallImpl::evaluate(s, &pa);
    let vb = FirewallImpl::evaluate(s, &pb);
    let vc = FirewallImpl::evaluate(s, &pc);
    if va != Verdict::Accept {
        panic!("firewall: packet A verdict drift");
    }
    if vb != Verdict::Accept {
        panic!("firewall: packet B verdict drift");
    }
    if vc != Verdict::Reject {
        panic!("firewall: packet C verdict drift");
    }

    // Same packets through the table-with-default path: should match
    // the trait-level verdict because every packet has a matching
    // rule.
    if table.evaluate(&pa, FilterAction::Drop) != Verdict::Accept {
        panic!("firewall: pa via table drift");
    }
    if table.evaluate(&pb, FilterAction::Drop) != Verdict::Accept {
        panic!("firewall: pb via table drift");
    }
    if table.evaluate(&pc, FilterAction::Drop) != Verdict::Reject {
        panic!("firewall: pc via table drift");
    }

    // Emit the first banner.
    serial_write_str("FW eval OK rules=3 verdicts=accept,accept,drop\n");

    // ------------------------------------------------------------------
    // 3. Default-deny fall-through. A packet that matches no rule
    //    should surface as the supplied default action (Drop).
    // ------------------------------------------------------------------
    // Packet D: 1.1.1.1:50000 → 9.9.9.9:443 TCP. No rule matches
    // (10/8 source missing, dst port != 22, dst port != 53,
    // 192.168/16 source missing, ICMP missing).
    let pd = Ipv4PacketView {
        src_ip: [1, 1, 1, 1],
        dst_ip: [9, 9, 9, 9],
        protocol: IP_PROTO_TCP,
        src_port: 50000,
        dst_port: 443,
    };
    let raw = FirewallImpl::evaluate(s, &pd);
    if raw != Verdict::NoMatch {
        panic!("firewall: default-deny: raw verdict not NoMatch");
    }
    let folded = table.evaluate(&pd, FilterAction::Drop);
    if folded != Verdict::Drop {
        panic!("firewall: default-deny: folded verdict not Drop");
    }

    // Also assert that flipping the default to Accept changes the
    // folded verdict — proves the table doesn't ignore the default
    // policy parameter under a NoMatch.
    if table.evaluate(&pd, FilterAction::Accept) != Verdict::Accept {
        panic!("firewall: default policy parameter not honoured");
    }

    // Emit the second banner.
    serial_write_str("FW default OK action=Drop\n");
}

/// TPM 2.0 client-side wire codec banner (TASK-051).
///
/// Exercises every command builder in [`TpmImpl`] plus the response
/// parser against locked TCG-spec wire fixtures. The kernel asserts
/// byte-equality on:
///
/// * `TPM2_Startup(SU_CLEAR)` — 12-byte request golden,
/// * `TPM2_GetRandom(16)` — 12-byte request golden,
/// * `TPM2_PCR_Read(pcr=10)` — 20-byte request golden, bitmap byte 1
///    bit 2 set (PCR 10 = 8 + 2),
/// * `TPM2_PCR_Extend(pcr=8, SHA-256, [0x42; 32])` — 65-byte request
///   golden, sessions tag, PWAP session block.
///
/// It then hand-builds the canonical 28-byte `TPM2_GetRandom(16)`
/// success response and walks the parsed view: tag = 0x8001, size =
/// 28, response_code = TPM_RC_SUCCESS, body length = 18 (TPM2B_DIGEST
/// = 2 + 16), the inline 16 random bytes recover byte-for-byte. A
/// morph that perturbs any byte of the locked wire layout or any
/// constant (header endianness, command codes, the auth-session
/// constants, the PCR bitmap arithmetic, the response size-field
/// check) panics here and the two banners never appear.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_tpm() {
    // ------------------------------------------------------------------
    // 1. TPM2_Startup(SU_CLEAR) request — locked 12-byte frame.
    // ------------------------------------------------------------------
    let expected_startup: [u8; TPM_STARTUP_CMD_LEN] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    let mut startup_buf = [0u8; TPM_STARTUP_CMD_LEN];
    let startup_len = match TpmImpl::build_startup(&mut startup_buf, TPM_SU_CLEAR) {
        Ok(n) => n,
        Err(_) => panic!("tpm: build_startup failed"),
    };
    if startup_len != TPM_STARTUP_CMD_LEN {
        panic!("tpm: startup length drift");
    }
    assert_eq_bytes(&startup_buf, &expected_startup, "TPM startup wire");

    // ------------------------------------------------------------------
    // 2. TPM2_GetRandom(16) request — locked 12-byte frame.
    // ------------------------------------------------------------------
    let expected_get_random: [u8; TPM_GET_RANDOM_CMD_LEN] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0x00, 0x10,
    ];
    let mut get_random_buf = [0u8; TPM_GET_RANDOM_CMD_LEN];
    let get_random_len = match TpmImpl::build_get_random(&mut get_random_buf, 16) {
        Ok(n) => n,
        Err(_) => panic!("tpm: build_get_random failed"),
    };
    if get_random_len != TPM_GET_RANDOM_CMD_LEN {
        panic!("tpm: get_random length drift");
    }
    assert_eq_bytes(&get_random_buf, &expected_get_random, "TPM getrandom wire");

    // ------------------------------------------------------------------
    // 3. TPM2_PCR_Read(pcr=10) request — locked 20-byte frame.
    // ------------------------------------------------------------------
    let expected_pcr_read: [u8; TPM_PCR_READ_CMD_LEN] = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x14, // commandSize = 20
        0x00, 0x00, 0x01, 0x7E, // commandCode = PCR_Read
        0x00, 0x00, 0x00, 0x01, // count = 1
        0x00, 0x0B, // SHA-256
        0x03, // sizeOfSelect
        0x00, 0x04, 0x00, // bitmap: bit 2 of byte 1 = PCR 10
    ];
    let mut pcr_read_buf = [0u8; TPM_PCR_READ_CMD_LEN];
    let pcr_read_len = match TpmImpl::build_pcr_read(&mut pcr_read_buf, 10) {
        Ok(n) => n,
        Err(_) => panic!("tpm: build_pcr_read failed"),
    };
    if pcr_read_len != TPM_PCR_READ_CMD_LEN {
        panic!("tpm: pcr_read length drift");
    }
    assert_eq_bytes(&pcr_read_buf, &expected_pcr_read, "TPM pcr_read wire");

    // ------------------------------------------------------------------
    // 4. TPM2_PCR_Extend(pcr=8, SHA-256, [0x42; 32]) — locked 65-byte
    //    frame. Use the MaxTpmCommandBuf scratch wrapper so we exercise
    //    that surface too.
    // ------------------------------------------------------------------
    let extend_digest = [0x42u8; TPM_SHA256_DIGEST_LEN];
    let expected_pcr_extend: [u8; TPM_PCR_EXTEND_SHA256_CMD_LEN] = [
        0x80, 0x02, // sessions tag
        0x00, 0x00, 0x00, 0x41, // commandSize = 65
        0x00, 0x00, 0x01, 0x82, // commandCode = PCR_Extend
        0x00, 0x00, 0x00, 0x08, // pcrHandle = 8
        0x00, 0x00, 0x00, 0x09, // authorizationSize = 9
        0x40, 0x00, 0x00, 0x09, // session: handle = TPM_RS_PW
        0x00, 0x00, // nonceSize = 0
        0x00, // sessionAttributes = 0
        0x00, 0x00, // hmacSize = 0
        0x00, 0x00, 0x00, 0x01, // digests.count = 1
        0x00, 0x0B, // hashAlg = SHA-256
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42,
    ];
    let mut scratch = MaxTpmCommandBuf::new();
    let pcr_extend_len = match TpmImpl::build_pcr_extend(
        scratch.as_mut(),
        8,
        TPM_ALG_SHA256,
        &extend_digest,
    ) {
        Ok(n) => n,
        Err(_) => panic!("tpm: build_pcr_extend failed"),
    };
    if pcr_extend_len != TPM_PCR_EXTEND_SHA256_CMD_LEN {
        panic!("tpm: pcr_extend length drift");
    }
    assert_eq_bytes(
        scratch.prefix(pcr_extend_len),
        &expected_pcr_extend,
        "TPM pcr_extend wire",
    );

    // First banner: byte-exact request encoding for the two task-spec
    // fixtures (startup + getrandom). The format echoes the locked
    // header fields so a serial-log grep can confirm both at once.
    serial_write_str("TPM startup OK len=12 tag=8001\n");
    serial_write_str("TPM getrandom OK len=12 cc=0000017b\n");

    // ------------------------------------------------------------------
    // 5. Parse a hand-built TPM2_GetRandom(16) success response. Walk
    //    every field of the view and recover the random bytes.
    // ------------------------------------------------------------------
    // Wire layout: tag(2) + size(4) + rc(4) + TPM2B_DIGEST { size(2) + 16 bytes }.
    // Total: 10 + 2 + 16 = 28 bytes.
    let mut resp = [0u8; 28];
    resp[0] = 0x80;
    resp[1] = 0x01;
    resp[2] = 0x00;
    resp[3] = 0x00;
    resp[4] = 0x00;
    resp[5] = 28; // size
    resp[6] = 0x00;
    resp[7] = 0x00;
    resp[8] = 0x00;
    resp[9] = 0x00; // rc = success
    // body: TPM2B_DIGEST size = 16
    resp[10] = 0x00;
    resp[11] = 0x10;
    let mut i = 0usize;
    while i < 16 {
        resp[12 + i] = (0xC0 ^ i as u8).wrapping_add(1);
        i += 1;
    }

    let view: TpmResponseView<'_> = match TpmImpl::parse_response(&resp) {
        Ok(v) => v,
        Err(_) => panic!("tpm: parse_response failed"),
    };
    if view.tag != TPM_ST_NO_SESSIONS {
        panic!("tpm: response tag drift");
    }
    if view.size != 28 {
        panic!("tpm: response size drift");
    }
    if view.response_code != TPM_RC_SUCCESS {
        panic!("tpm: response rc not success");
    }
    if view.body.len() != 18 {
        panic!("tpm: response body length drift");
    }

    let random = match extract_get_random_bytes(view.body) {
        Ok(r) => r,
        Err(_) => panic!("tpm: extract_get_random_bytes failed"),
    };
    if random.len() != 16 {
        panic!("tpm: random buffer length drift");
    }
    // Verify a couple of recovered bytes byte-for-byte.
    if random[0] != ((0xC0u8) ^ 0).wrapping_add(1) {
        panic!("tpm: random[0] drift");
    }
    if random[15] != ((0xC0u8) ^ 15).wrapping_add(1) {
        panic!("tpm: random[15] drift");
    }

    // Negative path #1: malformed tag. Hand-build a 10-byte response
    // with tag = 0x8003 (unassigned) and verify parse rejects it.
    let mut bad_tag = [0u8; 10];
    bad_tag[0] = 0x80;
    bad_tag[1] = 0x03;
    bad_tag[5] = 10;
    if TpmImpl::parse_response(&bad_tag).is_ok() {
        panic!("tpm: parse_response accepted bad tag");
    }

    // Negative path #2: size-field mismatch. tag valid, size says 12
    // but buffer is 10. parse must reject.
    let mut bad_size = [0u8; 10];
    bad_size[0] = 0x80;
    bad_size[1] = 0x01;
    bad_size[5] = 12;
    if TpmImpl::parse_response(&bad_size).is_ok() {
        panic!("tpm: parse_response accepted size mismatch");
    }

    // Cover the sessions tag too — also build a PCR_Extend response.
    let mut extend_resp = [0u8; 19];
    extend_resp[0] = 0x80;
    extend_resp[1] = 0x02;
    extend_resp[5] = 19;
    let extend_view = match TpmImpl::parse_response(&extend_resp) {
        Ok(v) => v,
        Err(_) => panic!("tpm: parse_response rejected sessions tag"),
    };
    if extend_view.tag != TPM_ST_SESSIONS {
        panic!("tpm: sessions tag round-trip drift");
    }

    // Second banner: response parser proved healthy on both tags and
    // recovered the 16 random bytes. Includes the parsed RC for
    // operator visibility.
    serial_write_str("TPM parse OK rc=00000000 random_len=16\n");
    let _ = (TPM_CC_GET_RANDOM,); // suppress unused-import warning if any
}

/// Kernel audit-log subsystem banner (TASK-052).
///
/// Exercises the locked [`AuditLog`] surface: appends three events of
/// distinct verdicts (Allowed / Denied / Error), confirms the
/// monotonic-event-id contract, takes a `snapshot`, parses the header
/// + every record back via the offline-parser helpers, and asserts
/// byte-equality against the expected layout. A morph that perturbs
/// the ring head/len bookkeeping, the snapshot byte layout, the
/// verdict discriminants, or the high-watermark accounting panics
/// inside `banner_audit` and the two banners never appear.
///
/// Emits two banners:
/// - `AUDIT append OK events=3` — three appends, three monotonic ids
///   recovered from `iter()` byte-for-byte.
/// - `AUDIT snapshot OK bytes=<N>` — snapshot returns the locked
///   `AUDIT_SNAPSHOT_HEADER_LEN + 3 * AUDIT_EVENT_WIRE_LEN = 308`
///   bytes; offline-parser round-trips every record's verdict +
///   message; the recorded magic == 'AUDT' and high_watermark == 3.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_audit() {
    // Three locked events — one per verdict variant. The kernel uses
    // the audit log to record cap-table denials and IOMMU faults, so
    // the fixture covers every verdict the future syscall/IOMMU
    // surfaces will emit.
    let mut log: AuditLogImpl<16> = AuditLogImpl::new();

    let e0 = AuditEvent::new(
        0,
        0x1111_2222_3333_4444,
        0x0000_0000_0000_0001, // task_id 1 (init)
        0x0000_0001,           // sys_exit
        AuditVerdict::Allowed,
        b"sys_exit OK",
    );
    let e1 = AuditEvent::new(
        0,
        0x1111_2222_3333_4445,
        0x0000_0000_0000_0002, // task_id 2 (worker)
        0x0000_000A,           // sys_open
        AuditVerdict::Denied,
        b"cap_check EPERM",
    );
    let e2 = AuditEvent::new(
        0,
        0x1111_2222_3333_4446,
        0x0000_0000_0000_0003, // task_id 3 (driver)
        0x0000_0014,           // hypothetical IOMMU syscall
        AuditVerdict::Error,
        b"iommu_translate ENOENT",
    );

    let id0 = log.append(e0);
    let id1 = log.append(e1);
    let id2 = log.append(e2);
    if id0 != 0 || id1 != 1 || id2 != 2 {
        panic!("audit: append id drift");
    }
    if log.len() != 3 {
        panic!("audit: len drift after 3 appends");
    }
    if log.high_watermark() != 3 {
        panic!("audit: high_watermark drift");
    }
    if log.dropped() != 0 {
        panic!("audit: dropped drift");
    }

    // iter() must yield ids 0, 1, 2 in order, each preserving its
    // caller-supplied verdict + message + task_id.
    let expected_verdicts = [AuditVerdict::Allowed, AuditVerdict::Denied, AuditVerdict::Error];
    let expected_tasks = [1u64, 2, 3];
    let expected_msgs: [&[u8]; 3] = [b"sys_exit OK", b"cap_check EPERM", b"iommu_translate ENOENT"];
    let mut idx = 0usize;
    for ev in log.iter() {
        if ev.event_id != idx as u64 {
            panic!("audit: iter event_id drift");
        }
        if ev.verdict != expected_verdicts[idx] {
            panic!("audit: iter verdict drift");
        }
        if ev.task_id != expected_tasks[idx] {
            panic!("audit: iter task_id drift");
        }
        if ev.message_bytes() != expected_msgs[idx] {
            panic!("audit: iter message drift");
        }
        idx += 1;
    }
    if idx != 3 {
        panic!("audit: iter yielded wrong count");
    }

    // First banner — three appends survived the monotonic-id contract.
    serial_write_str("AUDIT append OK events=3\n");

    // ------------------------------------------------------------------
    // Snapshot: header + 3 records = 20 + 3*96 = 308 bytes locked.
    // ------------------------------------------------------------------
    const SNAP_LEN: usize = AUDIT_SNAPSHOT_HEADER_LEN + 3 * AUDIT_EVENT_WIRE_LEN;
    let mut snap_buf = [0u8; SNAP_LEN];
    let n = match log.snapshot(&mut snap_buf) {
        Ok(n) => n,
        Err(_) => panic!("audit: snapshot returned Err"),
    };
    if n != SNAP_LEN {
        panic!("audit: snapshot length drift");
    }

    // Header round-trip via offline parser.
    let header = match parse_audit_header(&snap_buf) {
        Some(h) => h,
        None => panic!("audit: parse_header returned None"),
    };
    if header.magic != AUDIT_SNAPSHOT_MAGIC {
        panic!("audit: snapshot magic drift");
    }
    if header.record_count != 3 {
        panic!("audit: snapshot record_count drift");
    }
    if header.record_size as usize != AUDIT_EVENT_WIRE_LEN {
        panic!("audit: snapshot record_size drift");
    }
    if header.high_watermark != 3 {
        panic!("audit: snapshot high_watermark drift");
    }

    // First three bytes of the magic must literally spell 'A', 'U',
    // 'D' so an operator browsing the snapshot file with a hex viewer
    // recognises it instantly.
    if snap_buf[0] != b'A' || snap_buf[1] != b'U' || snap_buf[2] != b'D' || snap_buf[3] != b'T' {
        panic!("audit: snapshot magic bytes drift");
    }

    // Each record round-trips byte-for-byte.
    let mut cursor = AUDIT_SNAPSHOT_HEADER_LEN;
    let mut rec_idx = 0usize;
    while rec_idx < 3 {
        let rec = match parse_audit_record(&snap_buf[cursor..cursor + AUDIT_EVENT_WIRE_LEN]) {
            Some(r) => r,
            None => panic!("audit: parse_record returned None"),
        };
        if rec.event_id != rec_idx as u64 {
            panic!("audit: record event_id drift");
        }
        if rec.verdict != expected_verdicts[rec_idx] {
            panic!("audit: record verdict drift");
        }
        if rec.task_id != expected_tasks[rec_idx] {
            panic!("audit: record task_id drift");
        }
        if rec.message_bytes() != expected_msgs[rec_idx] {
            panic!("audit: record message drift");
        }
        cursor += AUDIT_EVENT_WIRE_LEN;
        rec_idx += 1;
    }
    if cursor != n {
        panic!("audit: cursor did not reach n");
    }

    // Second banner — snapshot length is the locked invariant.
    {
        let mut line = [0u8; 64];
        let prefix = b"AUDIT snapshot OK bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// eBPF interpreter banner — TASK-055.
///
/// Builds the 6-instruction reference program (which computes
/// `1 - (ctx[0] & 1)`), runs it against three input bytes
/// `[0, 1, 2]`, asserts the verdicts equal the locked pattern
/// `[1, 0, 1]`, and emits two banners:
///
/// - `EBPF program OK insns=6 verdicts=1,0,1`
/// - `EBPF stack OK bytes=512`
///
/// A morph that perturbs the ALU64 sub-op dispatch, the MOV/SUB/AND
/// wire-encoding, the LDX byte-size routing, the ST imm planting,
/// or the EXIT terminator path panics inside `banner_ebpf` and the
/// banners never appear. The stack-size banner also fails if the
/// contract's [`BPF_STACK_SIZE`] constant drifts — surfacing a
/// schema-incompatible change before the trailing `PROTEUS-TE
/// HALT` line.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_ebpf() {
    // Run the reference program three times. The context is
    // re-used; the interpreter resets registers + stack on every
    // call by contract, so cross-run leakage is impossible.
    let mut ctx = BpfContext::new();
    const EXPECTED_VERDICTS: [u64; 3] = [1, 0, 1];
    let inputs: [u8; 3] = [0, 1, 2];

    let mut i = 0usize;
    while i < 3 {
        let verdict = match run_reference_program(inputs[i], &mut ctx) {
            Ok(v) => v,
            Err(_) => panic!("ebpf: run returned Err"),
        };
        if verdict != EXPECTED_VERDICTS[i] {
            panic!("ebpf: verdict drift");
        }
        i += 1;
    }

    // Also validate the trait-direct path against a 1-instruction
    // EXIT program — exercises `EBpfImpl::run` directly so a morph
    // that breaks the trait dispatch is caught here.
    let exit_only = [proteus_contracts::BpfInstr::new(
        proteus_contracts::bpf_op::BPF_OP_EXIT,
        0,
        0,
        0,
        0,
    )];
    match EBpfImpl::run(&exit_only, &mut ctx) {
        Ok(0) => {}
        _ => panic!("ebpf: trait-direct exit drift"),
    }

    // Emit banner 1: program OK with the locked verdict tuple.
    {
        let mut line = [0u8; 64];
        let prefix = b"EBPF program OK insns=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(REFERENCE_PROGRAM_INSNS as u64, &mut line[pos..]);
        let mid = b" verdicts=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        // Verdicts are 0/1 — fixed-width single decimal digit each.
        line[pos] = b'0' + (EXPECTED_VERDICTS[0] as u8);
        line[pos + 1] = b',';
        line[pos + 2] = b'0' + (EXPECTED_VERDICTS[1] as u8);
        line[pos + 3] = b',';
        line[pos + 4] = b'0' + (EXPECTED_VERDICTS[2] as u8);
        line[pos + 5] = b'\n';
        pos += 6;
        serial_write_bytes(&line[..pos]);
    }

    // Emit banner 2: stack-size invariant from the contract.
    {
        let mut line = [0u8; 64];
        let prefix = b"EBPF stack OK bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(BPF_STACK_SIZE as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-087 DRBG
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_drbg() {
    use proteus_contracts::HmacDrbg;
    use target_enterprise::hmac_drbg::{banner_out16, BANNER_LABEL, BANNER_SEED, HmacDrbgImpl};

    let mut o = [0u8; 16];
    HmacDrbgImpl::expand(&BANNER_SEED, BANNER_LABEL, &mut o);
    if o != banner_out16() {
        panic!("DRBG banner: kat");
    }
    serial_write_bytes(b"DRBG kat OK\n");
}

// TASK-091 Attest TLV
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_attest_tlv() {
    use proteus_contracts::AttestTlv;
    use target_enterprise::attest_tlv::{banner_three_tags, AttestTlvImpl};

    let mut b = [0u8; 64];
    let n = match banner_three_tags(&mut b) {
        Ok(n) => n,
        Err(_) => panic!("TLV banner: encode"),
    };
    match AttestTlvImpl::count_sequence(&b[..n]) {
        Ok(3) => {}
        _ => panic!("TLV banner: tags"),
    }
    serial_write_bytes(b"TLV parse OK tags=3\n");
}

// TASK-092 Base64
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_base64() {
    use target_enterprise::base64::banner_roundtrip;

    if !banner_roundtrip() {
        panic!("B64 banner: roundtrip");
    }
    serial_write_bytes(b"B64 roundtrip OK\n");
}

// TASK-080 CRC32C
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_crc32c() {
    use proteus_contracts::Crc32c;
    use target_enterprise::crc32c::Crc32cImpl;

    if Crc32cImpl::hash(b"123456789") != 0xE306_9283 {
        panic!("CRC32C banner: kat fail");
    }
    serial_write_bytes(b"CRC32C kat OK\n");
}

// TASK-078: sig kat
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_sigkat() {
    use proteus_contracts::{SigKat, SIGKAT_VECTOR_COUNT};
    use target_enterprise::sigkat::SigKatImpl;

    let s = SigKatImpl::run_all();
    if !s.all_ok() || s.total != SIGKAT_VECTOR_COUNT {
        panic!("SIGKAT banner: suite failed");
    }
    {
        let mut line = [0u8; 40];
        let mut pos = 0usize;
        let prefix = b"SIGKAT all OK vectors=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(s.passed as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-072: RNG KAT
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_rng() {
    use proteus_contracts::Random;
    use target_enterprise::random::{banner_expected_prefix8, BANNER_SEED, RandomImpl};

    let mut r = RandomImpl::new();
    if r.seed(&BANNER_SEED).is_err() {
        panic!("RNG banner: seed failed");
    }
    let mut out = [0u8; 8];
    if r.fill(&mut out).is_err() {
        panic!("RNG banner: fill failed");
    }
    let exp = banner_expected_prefix8();
    let mut i = 0usize;
    while i < 8 {
        if out[i] != exp[i] {
            panic!("RNG banner: KAT drift");
        }
        i += 1;
    }
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"RNG kat OK seed=0102 out=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        i = 0;
        while i < 4 {
            let b = out[i];
            let hi = b >> 4;
            let lo = b & 0x0F;
            line[pos] = if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) };
            pos += 1;
            line[pos] = if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) };
            pos += 1;
            i += 1;
        }
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-068: Stack canary mint + mismatch fingerprint.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_canary() {
    use proteus_contracts::StackCanary;
    use target_enterprise::stack_canary::{BANNER_SEED, StackCanaryImpl};

    let tok = match StackCanaryImpl::mint(&BANNER_SEED) {
        Ok(t) => t,
        Err(_) => panic!("CANARY banner: mint failed"),
    };
    if StackCanaryImpl::verify(&tok, &tok).is_err() {
        panic!("CANARY banner: self-verify failed");
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"CANARY mint OK tok=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // first 4 bytes as hex
        let mut i = 0usize;
        while i < 4 {
            let b = tok.bytes[i];
            let hi = b >> 4;
            let lo = b & 0x0F;
            line[pos] = if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) };
            pos += 1;
            line[pos] = if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) };
            pos += 1;
            i += 1;
        }
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    let mut bad = tok;
    bad.bytes[0] ^= 0x01;
    if StackCanaryImpl::verify(&tok, &bad).is_ok() {
        panic!("CANARY banner: mismatch not detected");
    }
    let fp = StackCanaryImpl::fail_fingerprint(&tok, &bad);
    if (fp & 0xFF) != 1 {
        panic!("CANARY banner: fingerprint drift");
    }
    serial_write_bytes(b"CANARY fail OK reason=mismatch\n");
}

// TASK-065: GDB RSP wire codec. Parses the locked `$g#67` frame
// (read-registers), classifies it, builds the 256-zero register
// reply, re-frames it, and asserts the checksum digits are `00`.
// Banner: `GDBSTUB parse OK cmd=g cksum=67`.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_gdbstub() {
    use proteus_contracts::{GdbCommand, GdbStub};
    use target_enterprise::gdbstub::GdbStubImpl;

    let frame = b"$g#67";
    let pkt = match GdbStubImpl::parse_frame(frame) {
        Ok(p) => p,
        Err(_) => panic!("GDBSTUB banner: parse failed"),
    };
    if pkt.body != b"g" {
        panic!("GDBSTUB banner: body drift");
    }
    if pkt.checksum != 0x67 {
        panic!("GDBSTUB banner: checksum drift");
    }
    let cmd = GdbStubImpl::classify(pkt.body);
    if cmd != GdbCommand::ReadRegisters {
        panic!("GDBSTUB banner: classify drift");
    }
    let mut body = [0u8; 256];
    let n = match GdbStubImpl::reply_body(&cmd, &mut body) {
        Ok(n) => n,
        Err(_) => panic!("GDBSTUB banner: reply failed"),
    };
    if n != 256 {
        panic!("GDBSTUB banner: reply length drift");
    }
    // Re-frame and verify checksum digits of the all-zero reply.
    let mut out_frame = [0u8; 512];
    let flen = match GdbStubImpl::build_frame(&body[..n], &mut out_frame) {
        Ok(n) => n,
        Err(_) => panic!("GDBSTUB banner: build_frame failed"),
    };
    // Last two bytes must be hex of checksum(256 × '0') = 0x00.
    if out_frame[flen - 2] != b'0' || out_frame[flen - 1] != b'0' {
        panic!("GDBSTUB banner: reply frame cksum drift");
    }
    // Round-trip parse.
    match GdbStubImpl::parse_frame(&out_frame[..flen]) {
        Ok(p) if p.body.len() == 256 && p.checksum == 0 => {}
        _ => panic!("GDBSTUB banner: reply reparse failed"),
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"GDBSTUB parse OK cmd=g cksum=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // Two hex digits of 0x67.
        let cs: u8 = 0x67;
        let hi = cs >> 4;
        let lo = cs & 0x0F;
        line[pos] = if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) };
        pos += 1;
        line[pos] = if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) };
        pos += 1;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-063: Crypto KAT harness. Runs the locked 9-vector suite
// (SHA-256 empty/abc/million-a, HMAC RFC 4231 cases 1-4, HKDF RFC
// 5869 cases 1-2) against the real TLS crypto primitives. Any
// digest drift panics; on full pass emits
// `KAT all OK vectors=9`. A morph that perturbs SHA-256, HMAC, or
// HKDF arithmetic panics inside `banner_kat` and the banner never
// appears.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_kat() {
    use proteus_contracts::{KatRunner, KAT_VECTOR_COUNT};
    use target_enterprise::kat::KatImpl;

    let suite = KatImpl::run_all();
    if suite.total != KAT_VECTOR_COUNT {
        panic!("KAT banner: suite cardinality drift");
    }
    if !suite.all_ok() {
        panic!("KAT banner: vector failure");
    }
    if suite.passed != KAT_VECTOR_COUNT {
        panic!("KAT banner: passed count drift");
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"KAT all OK vectors=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(suite.passed as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-060: X.509 v3 DER parser. The kernel parses the locked
// 257-byte Ed25519 self-signed fixture in
// `kernel_fixtures::X509_FIXTURE_DER`, asserts the recovered
// version / serial / validity window / pubkey / subject CN match
// the locked goldens byte-for-byte, then emits two banners. A
// morph that perturbs any byte position in the TLV walker, the
// SPKI BIT STRING decode, or the UTCTime arithmetic panics inside
// `banner_x509` and the banners never appear.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_x509() {
    use proteus_contracts::{X509PubKey, X509PubKeyAlg, X509Time, X509};
    use target_enterprise::x509::X509Impl;

    let cert = match X509Impl::parse(kf::X509_FIXTURE_DER) {
        Ok(c) => c,
        Err(_) => panic!("X509 banner: parse failed"),
    };
    if cert.version != 2 {
        panic!("X509 banner: version drift");
    }
    if cert.pubkey_alg != X509PubKeyAlg::Ed25519 {
        panic!("X509 banner: pubkey_alg drift");
    }
    if cert.serial.len() != 1 || cert.serial[0] != kf::X509_FIXTURE_SERIAL {
        panic!("X509 banner: serial drift");
    }
    if cert.not_before.unix != kf::X509_FIXTURE_NOT_BEFORE_UNIX {
        panic!("X509 banner: not_before drift");
    }
    if cert.not_after.unix != kf::X509_FIXTURE_NOT_AFTER_UNIX {
        panic!("X509 banner: not_after drift");
    }
    match cert.pubkey {
        X509PubKey::Ed25519 { key } => {
            if key != kf::X509_FIXTURE_PUBKEY {
                panic!("X509 banner: pubkey bytes drift");
            }
        }
        _ => panic!("X509 banner: pubkey variant drift"),
    }
    if !X509Impl::validity_contains(&cert, X509Time { unix: 1_700_000_000 }) {
        panic!("X509 banner: validity window drift");
    }
    if cert.issuer != cert.subject {
        panic!("X509 banner: self-signed DN drift");
    }
    if X509Impl::issuer_matches_subject(&cert, &cert).is_err() {
        panic!("X509 banner: issuer/subject match drift");
    }

    // Emit parse banner: byte length + serial.
    {
        let mut line = [0u8; 96];
        let mut pos = 0usize;
        let prefix = b"X509 parse OK len=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(kf::X509_FIXTURE_DER.len() as u64, &mut line[pos..]);
        let mid = b" serial=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(cert.serial[0] as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Recover the CN from the subject DN and assert byte-equality.
    let cn = match X509Impl::find_cn(cert.subject) {
        Some(c) => c,
        None => panic!("X509 banner: subject CN missing"),
    };
    if cn != kf::X509_FIXTURE_SUBJECT_CN {
        panic!("X509 banner: CN drift");
    }

    // Emit CN banner.
    {
        let mut line = [0u8; 96];
        let mut pos = 0usize;
        let prefix = b"X509 cn OK cn=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        line[pos..pos + cn.len()].copy_from_slice(cn);
        pos += cn.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// TASK-145: live guest durable seal of a fixed empty audit snapshot
/// header (magic-only / zero events). Proves `durable_seal` is linked
/// into the boot image. Does **not** claim implant immunity.
#[inline(never)]
pub(crate) fn banner_durable_seal() {
    use proteus_contracts::{AUDIT_SNAPSHOT_HEADER_LEN, AUDIT_SNAPSHOT_MAGIC};
    use target_enterprise::durable_seal::{
        seal_bytes, seal_bytes_keyed, seal_matches_keyed, DURABLE_DIGEST_LEN,
    };

    // Empty log snapshot = 20-byte header only (count=0).
    let mut snap = [0u8; AUDIT_SNAPSHOT_HEADER_LEN];
    let magic = AUDIT_SNAPSHOT_MAGIC.to_be_bytes();
    snap[0..4].copy_from_slice(&magic);
    // record_count = 0 already
    let rec_size = (96u32).to_be_bytes(); // AUDIT_EVENT_WIRE_LEN
    snap[8..12].copy_from_slice(&rec_size);
    // high_watermark = 0

    let mut dig = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes(&snap, &mut dig);

    // Also verify keyed HMAC-SHA256 tamper-proof sealing and confirm an unkeyed SHA-256 hash is rejected.
    let seal_key = derive_runtime_seal_key();
    let mut keyed_mac = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(&seal_key, &snap, &mut keyed_mac);
    if !seal_matches_keyed(&seal_key, &snap, &keyed_mac)
        || seal_matches_keyed(&seal_key, &snap, &dig)
    {
        panic!("DURABLE seal: keyed HMAC-SHA256 verification failed");
    }

    let mut line = [0u8; 80];
    let mut pos = 0usize;
    let prefix = b"DURABLE seal OK dig=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let mut hex = [0u8; 16]; // first 8 bytes of digest
    hex_encode(&dig, 8, &mut hex);
    line[pos..pos + 16].copy_from_slice(&hex);
    pos += 16;
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_panic_dump() {
    // Build the canonical CrashContext.
    let ctx = CrashContext {
        wall_unix: kf::CRASH_WALL_UNIX,
        tsc: kf::CRASH_TSC,
        panic_loc: kf::CRASH_PANIC_LOC,
        message: kf::CRASH_MESSAGE,
        registers: &kf::CRASH_REGISTERS,
        backtrace: &kf::CRASH_BACKTRACE,
        kmsg: kf::CRASH_KMSG,
    };

    let mut buf = [0u8; proteus_contracts::CRASH_DUMP_BYTES];
    let mut sink = MemorySectorSink::new();
    let (lba_start, lba_end) = match PanicDumpImpl::dump_to_sink(&ctx, &mut buf, &mut sink) {
        Ok(t) => t,
        Err(_) => panic!("PanicDumpImpl::dump_to_sink failed"),
    };
    if lba_start != DUMP_START_LBA {
        panic!("panic_dump: lba_start drift");
    }
    if lba_end - lba_start != proteus_contracts::CRASH_DUMP_SECTORS {
        panic!("panic_dump: lba range size drift");
    }

    // Body CRC must verify, AND the recorded CRC must equal the
    // locked expected fixture so a morph that perturbs the layout
    // panics here.
    if PanicDumpImpl::verify_crc(&buf).is_err() {
        panic!("panic_dump: verify_crc returned Err for own dump");
    }
    let header = match PanicDumpImpl::parse_header(&buf) {
        Ok(h) => h,
        Err(_) => panic!("panic_dump: parse_header rejected own dump"),
    };
    if header.body_crc32c != kf::CRASH_EXPECTED_CRC32C {
        panic!("panic_dump: CRC32-C drift");
    }
    if header.kmsg_len as usize != kf::CRASH_KMSG.len() {
        panic!("panic_dump: kmsg_len drift");
    }
    if header.backtrace_count as usize != kf::CRASH_BACKTRACE.len() {
        panic!("panic_dump: backtrace_count drift");
    }
    if header.register_count as usize != proteus_contracts::CRASH_REG_COUNT {
        panic!("panic_dump: register_count drift");
    }
    // Header strings must round-trip.
    if header.panic_loc.as_bytes() != kf::CRASH_PANIC_LOC.as_bytes() {
        panic!("panic_dump: panic_loc drift");
    }
    if header.message.as_bytes() != kf::CRASH_MESSAGE.as_bytes() {
        panic!("panic_dump: message drift");
    }

    // Sink must have received every sector in ascending LBA order.
    if sink.recorded != 32 {
        panic!("panic_dump: sink missed a sector");
    }
    let mut k = 1usize;
    while k < sink.recorded {
        if sink.recorded_lbas[k] <= sink.recorded_lbas[k - 1] {
            panic!("panic_dump: sector LBAs not strictly ascending");
        }
        k += 1;
    }

    // Disk bytes received by the sink must equal the build_dump output.
    let mut i = 0usize;
    while i < proteus_contracts::CRASH_DUMP_BYTES {
        if sink.disk[i] != buf[i] {
            panic!("panic_dump: sink/buf byte drift");
        }
        i += 1;
    }

    // Backtrace recovery must round-trip.
    let mut extracted_bt = [0u64; proteus_contracts::CRASH_BACKTRACE_MAX];
    let bt_n = match PanicDumpImpl::extract_backtrace(&buf, &mut extracted_bt) {
        Ok(n) => n,
        Err(_) => panic!("panic_dump: extract_backtrace failed"),
    };
    if bt_n != kf::CRASH_BACKTRACE.len() {
        panic!("panic_dump: extracted backtrace length drift");
    }
    let mut j = 0usize;
    while j < bt_n {
        if extracted_bt[j] != kf::CRASH_BACKTRACE[j] {
            panic!("panic_dump: backtrace frame drift");
        }
        j += 1;
    }

    // Emit the dump banner.
    {
        let mut line = [0u8; 96];
        let mut pos = 0usize;
        let prefix = b"CRASH_DUMP wrote 16384 bytes to lba=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(DUMP_START_LBA, &mut line[pos..]);
        let mid = b" crc=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let crc_be = header.body_crc32c.to_be_bytes();
        let mut crc_hex = [0u8; 8];
        hex_encode(&crc_be, 4, &mut crc_hex);
        line[pos..pos + 8].copy_from_slice(&crc_hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Hand-built kernel-symbol fixture matching CRASH_BACKTRACE.
    const SYMBOLS: &[SymbolEntry] = &[
        SymbolEntry::new(0xFFFF_FFFF_8010_0000, 0x100, "kernel_main"),
        SymbolEntry::new(0xFFFF_FFFF_8010_0500, 0x200, "schedule_next_task"),
        SymbolEntry::new(0xFFFF_FFFF_8010_0800, 0x100, "handle_irq_timer"),
        SymbolEntry::new(0xFFFF_FFFF_8010_0A00, 0x080, "halt_forever"),
    ];
    if !StaticSymbolResolver::is_sorted_by_addr(SYMBOLS) {
        panic!("panic_dump: kernel-symbol fixture is unsorted");
    }
    let resolver = StaticSymbolResolver::new(SYMBOLS);
    if resolver.symbol_count() != 4 {
        panic!("panic_dump: symbol_count drift");
    }

    // Resolve every recovered frame; assert the first matches the
    // locked expected name/offset.
    let (first_name, first_off) = match resolver.resolve(extracted_bt[0]) {
        Some(t) => t,
        None => panic!("panic_dump: first frame did not resolve"),
    };
    if first_name.as_bytes() != kf::CRASH_EXPECTED_RESOLVE_NAME.as_bytes() {
        panic!("panic_dump: resolved name drift");
    }
    if first_off != kf::CRASH_EXPECTED_RESOLVE_OFFSET {
        panic!("panic_dump: resolved offset drift");
    }
    let mut m = 0usize;
    while m < bt_n {
        if resolver.resolve(extracted_bt[m]).is_none() {
            panic!("panic_dump: a backtrace frame did not resolve");
        }
        m += 1;
    }

    // Emit the resolver banner.
    {
        let mut line = [0u8; 96];
        let mut pos = 0usize;
        let prefix = b"SYMBOL resolve OK ";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let nb = first_name.as_bytes();
        line[pos..pos + nb.len()].copy_from_slice(nb);
        pos += nb.len();
        let mid = b"+0x";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        // Lowercase hex of first_off, MSB-first, no leading zeros.
        let mut nyb = 16i32; // count leading non-zero nybbles
        while nyb > 0 {
            let shift = (nyb - 1) * 4;
            if ((first_off >> shift) & 0xF) != 0 {
                break;
            }
            nyb -= 1;
        }
        if nyb == 0 {
            line[pos] = b'0';
            pos += 1;
        } else {
            let mut nn = nyb;
            while nn > 0 {
                nn -= 1;
                let n = ((first_off >> (nn * 4)) & 0xF) as u8;
                line[pos] = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
                pos += 1;
            }
        }
        let mid2 = b" (";
        line[pos..pos + mid2.len()].copy_from_slice(mid2);
        pos += mid2.len();
        pos += dec_u64(bt_n as u64, &mut line[pos..]);
        let mid3 = b" frames)";
        line[pos..pos + mid3.len()].copy_from_slice(mid3);
        pos += mid3.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}
