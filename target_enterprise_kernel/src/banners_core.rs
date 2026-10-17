//! Kernel submodule.

pub(crate) use crate::*;

/// TLS: run HKDF-Extract + HKDF-Expand-Label against the locked
/// fixtures, assert byte-equality, emit
/// `TLS hkdf OK prk_sha=<hex16>\n`.
///
/// Returns the PRK so a follow-on banner could chain off it; the kernel
/// does not need it again here.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_tls_hkdf() {
    let mut prk = [0u8; 32];
    <Tls13ServerImpl as Tls13Server>::hkdf_extract(&kf::HKDF_SALT, &kf::HKDF_IKM, &mut prk);
    assert_eq_bytes(&prk, &kf::HKDF_EXPECTED_PRK, "TLS HKDF-Extract");

    // Also exercise the freestanding fn so the diversifier-renamed
    // local bindings in hkdf_extract (`total_label_len`, `sid_len`,
    // etc., per iteration 12) all show in the live call graph.
    let mut prk2 = [0u8; 32];
    hkdf_extract(&kf::HKDF_SALT, &kf::HKDF_IKM, &mut prk2);
    assert_eq_bytes(&prk2, &kf::HKDF_EXPECTED_PRK, "TLS HKDF-Extract(2)");

    let mut expanded = [0u8; kf::HKDF_EXPAND_OUT_LEN];
    hkdf_expand_label(&prk, kf::HKDF_EXPAND_LABEL, &kf::HKDF_INFO, &mut expanded);
    assert_eq_bytes(
        &expanded[..8],
        &kf::HKDF_EXPECTED_EXPAND_PREFIX8,
        "TLS HKDF-Expand-Label",
    );

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"TLS hkdf OK prk_sha=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += hex_encode(&prk, 8, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

/// TLS: build a ServerHello against the locked ClientHello fixture,
/// assert byte length and prefix, emit `TLS server_hello OK len=<N>\n`.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_tls_server_hello() {
    let mut out = [0u8; 256];
    let n = match build_server_hello(
        &kf::CLIENT_HELLO,
        &kf::SERVER_RANDOM,
        &kf::SERVER_PUBKEY,
        None,
        &mut out,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TLS build_server_hello returned Err"),
    };
    if n != kf::SERVER_HELLO_EXPECTED_LEN {
        panic!("TLS ServerHello length drift");
    }
    assert_eq_bytes(
        &out[..8],
        &kf::SERVER_HELLO_EXPECTED_PREFIX8,
        "TLS ServerHello prefix",
    );

    let mut line = [0u8; 48];
    let mut pos = 0usize;
    let prefix = b"TLS server_hello OK len=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += dec_u64(n as u64, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

/// TLS 1.3 client (TASK-049): build a ClientHello against the locked
/// fixtures, assert byte length + prefix; parse the locked
/// ServerHello fixture, assert the recovered server_pubkey matches;
/// run the RFC 8446 §7.1 key schedule against the locked shared
/// secret, assert all three secrets match the locked goldens; build
/// the client Finished verify_data against a synthetic transcript
/// hash, assert byte-equality.
///
/// Emits:
///   `TLS client_hello OK len=<dec>\n`
///   `TLS client handshake_keys OK prk=<hex16>\n`
///
/// A kernel that perturbs the ClientHello layout, the ServerHello
/// parser, the key-schedule label or chaining order, or the Finished
/// MAC construction panics here and the banners never appear.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_tls_client() {
    // 1) ClientHello build — length + prefix lock.
    let mut ch = [0u8; 256];
    let ch_len = match build_client_hello(
        &kf::TLS_CLIENT_RANDOM,
        &kf::TLS_CLIENT_PUBKEY,
        &mut ch,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TLS build_client_hello returned Err"),
    };
    if ch_len != kf::TLS_CLIENT_HELLO_EXPECTED_LEN {
        panic!("TLS ClientHello length drift");
    }
    assert_eq_bytes(
        &ch[..8],
        &kf::TLS_CLIENT_HELLO_EXPECTED_PREFIX8,
        "TLS ClientHello prefix",
    );

    // Also exercise the trait surface so the diversifier-renamed
    // helpers inside the impl all show in the live call graph.
    let mut ch2 = [0u8; 256];
    let ch2_len = match <Tls13ClientImpl as Tls13Client>::build_client_hello(
        &kf::TLS_CLIENT_RANDOM,
        &kf::TLS_CLIENT_PUBKEY,
        &mut ch2,
    ) {
        Ok(n) => n,
        Err(_) => panic!("Tls13Client::build_client_hello returned Err"),
    };
    if ch2_len != ch_len {
        panic!("TLS ClientHello length differs between free fn + trait");
    }
    assert_eq_bytes(&ch2[..ch2_len], &ch[..ch_len], "TLS ClientHello bytes");

    // Emit the first banner now that the ClientHello is locked.
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"TLS client_hello OK len=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(ch_len as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // 2) ServerHello parse — recover server_pubkey + assert.
    let parsed = match parse_server_hello(&kf::TLS_SERVER_HELLO_FIXTURE) {
        Ok(p) => p,
        Err(_) => panic!("TLS parse_server_hello returned Err"),
    };
    // Expect server_pubkey = 32 × 0x09.
    let mut i = 0usize;
    while i < 32 {
        if parsed.server_pubkey[i] != 0x09 {
            panic!("TLS parsed server_pubkey drift");
        }
        i += 1;
    }
    if parsed.cipher_suite != 0x1301 {
        panic!("TLS parsed cipher_suite drift");
    }

    // 3) Key schedule — derive + lock the three secrets.
    let mut keys = HandshakeKeys {
        handshake_secret: [0u8; 32],
        client_handshake_traffic_secret: [0u8; 32],
        server_handshake_traffic_secret: [0u8; 32],
    };
    derive_handshake_keys(
        &kf::TLS_SHARED_SECRET,
        &ch[..ch_len],
        &kf::TLS_SERVER_HELLO_FIXTURE,
        &mut keys,
    );
    assert_eq_bytes(
        &keys.handshake_secret,
        &kf::TLS_HANDSHAKE_SECRET_EXPECTED,
        "TLS handshake_secret",
    );
    assert_eq_bytes(
        &keys.client_handshake_traffic_secret,
        &kf::TLS_CLIENT_HS_TRAFFIC_EXPECTED,
        "TLS c_hs_traffic",
    );
    assert_eq_bytes(
        &keys.server_handshake_traffic_secret,
        &kf::TLS_SERVER_HS_TRAFFIC_EXPECTED,
        "TLS s_hs_traffic",
    );

    // 4) Client Finished MAC — lock verify_data bytes.
    let mut vd = [0u8; 32];
    build_client_finished(
        &keys.client_handshake_traffic_secret,
        &kf::TLS_FINISHED_TRANSCRIPT_HASH,
        &mut vd,
    );
    assert_eq_bytes(&vd, &kf::TLS_CLIENT_FINISHED_EXPECTED, "TLS client Finished");

    // Emit the second banner: `TLS client handshake_keys OK prk=<hex16>`.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TLS client handshake_keys OK prk=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += hex_encode(&keys.handshake_secret, 8, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// TLS 1.3 session resumption (RFC 8446 §4.6.1) — cross-morph session
/// continuity (Class B). Full chain: master secret → resumption master
/// secret → resumption PSK → sealed blob → [morph boundary] → open blob
/// → early secret from the RELOADED PSK. The banner proves the reloaded
/// early secret is byte-identical to the continuous-process one, and
/// that a corrupted durable PSK is rejected rather than silently
/// producing a wrong early secret. Emits
/// `TLS RESUME OK psk=<hex8>\n`.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_tls_resumption() {
    use target_enterprise::tls::{
        derive_resumption_master_secret, derive_resumption_psk, early_secret_from_psk,
        open_resumption_psk, seal_resumption_psk, RESUMPTION_BLOB_LEN,
    };

    // Fixture handshake output (a real deployment takes these from the
    // completed handshake; the banner exercises the derivation path).
    let master_secret = [0x42u8; 32];
    let transcript = b"proteus kernel resumption banner transcript";
    let ticket_nonce = [0xA5u8; 32];

    let mut rms = [0u8; 32];
    derive_resumption_master_secret(&master_secret, transcript, &mut rms);
    let mut psk = [0u8; 32];
    derive_resumption_psk(&rms, &ticket_nonce, &mut psk);
    let mut early_direct = [0u8; 32];
    early_secret_from_psk(&psk, &mut early_direct);

    // Sealed blob = the durable artifact that crosses a morph cycle.
    let mut blob = [0u8; RESUMPTION_BLOB_LEN];
    seal_resumption_psk(&psk, &ticket_nonce, &mut blob);

    // --- simulated morph boundary: parse back as the successor kernel ---
    let (nonce2, psk2) = match open_resumption_psk(&blob) {
        Ok(t) => t,
        Err(_) => panic!("TLS RESUME: sealed blob rejected own PSK"),
    };
    if nonce2 != ticket_nonce || psk2 != psk {
        panic!("TLS RESUME: blob round-trip drift");
    }
    let mut early_reloaded = [0u8; 32];
    early_secret_from_psk(&psk2, &mut early_reloaded);
    if early_reloaded != early_direct {
        panic!("TLS RESUME: early secret drift across boundary");
    }

    // Corrupt durable PSK must fail closed, not yield a wrong secret.
    let mut bad = blob;
    bad[50] ^= 0x80;
    if open_resumption_psk(&bad).is_ok() {
        panic!("TLS RESUME: corrupted blob accepted");
    }

    let mut line = [0u8; 48];
    let mut pos = 0usize;
    let prefix = b"TLS RESUME OK psk=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let be: [u8; 4] = [psk[0], psk[1], psk[2], psk[3]];
    let mut hx = [0u8; 8];
    hex_encode(&be, 4, &mut hx);
    line[pos..pos + 8].copy_from_slice(&hx);
    pos += 8;
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

/// WAL: instantiate a 4 KiB WalImpl, append 16 fixture frames, flush,/// replay, assert the frame count and final LSN match the fixture
/// constants, emit `WAL replay OK frames=16 lsn=<N>\n`.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_wal_replay() {
    let mut wal: WalImpl<{ kf::WAL_CAPACITY }> = WalImpl::new();
    let mut i = 0usize;
    while i < kf::WAL_FRAMES {
        let payload = [i as u8; kf::WAL_PAYLOAD_LEN];
        if wal.append(&payload).is_err() {
            panic!("WAL append failed");
        }
        i += 1;
    }
    // TASK-161: durable flush requires CapProof (DURABLE_WAL_WRITE).
    // Banner path is privileged init — self-grant the WAL durable bit.
    if wal
        .flush(target_enterprise::wal::durable_wal_proof_init())
        .is_err()
    {
        panic!("WAL flush failed");
    }
    if wal.next_lsn() != kf::WAL_EXPECTED_NEXT_LSN {
        panic!("WAL next_lsn drift");
    }
    // Walk the durable prefix; assert frame count and order.
    let mut seen: u64 = 0;
    let mut last_lsn: u64 = 0;
    wal.replay(&mut |lsn, payload| {
        seen += 1;
        if lsn != last_lsn + 1 {
            panic!("WAL replay LSN out of order");
        }
        last_lsn = lsn;
        if payload.len() != kf::WAL_PAYLOAD_LEN {
            panic!("WAL replay payload length drift");
        }
        let expected_byte = (lsn - 1) as u8;
        let mut j = 0usize;
        while j < payload.len() {
            if payload[j] != expected_byte {
                panic!("WAL replay payload content drift");
            }
            j += 1;
        }
    });
    if seen != kf::WAL_FRAMES as u64 {
        panic!("WAL replay frame count drift");
    }

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"WAL replay OK frames=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += dec_u64(seen, &mut line[pos..]);
    let mid = b" lsn=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += dec_u64(last_lsn, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

/// IOMMU: instantiate `IommuImpl<4, 8, 16>`, create a domain, bind one
/// device, map one page, translate, assert the host PA matches the
/// locked fixture, emit `IOMMU translate OK pa=<hex8>\n`.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_iommu_translate() {
    let mut iommu: IommuImpl<
        { kf::IOMMU_DOMAINS },
        { kf::IOMMU_DEVICES },
        { kf::IOMMU_ENTRIES_PER_DOMAIN },
    > = IommuImpl::new();

    let domain = match iommu.create_domain() {
        Ok(d) => d,
        Err(_) => panic!("IOMMU create_domain failed"),
    };
    let device = DeviceId::from_bdf(
        kf::IOMMU_DEVICE_SEGMENT,
        kf::IOMMU_DEVICE_BUS,
        kf::IOMMU_DEVICE_DEVICE,
        kf::IOMMU_DEVICE_FUNCTION,
    );
    if iommu.bind_device(device, domain).is_err() {
        panic!("IOMMU bind_device failed");
    }
    if iommu
        .map(domain, kf::IOMMU_DMA_ADDR, kf::IOMMU_HOST_PHYS, PagePerms::RW)
        .is_err()
    {
        panic!("IOMMU map failed");
    }
    let probe = kf::IOMMU_DMA_ADDR + kf::IOMMU_PAGE_OFFSET;
    let pa = match iommu.translate(device, probe, AccessKind::Read) {
        Ok(pa) => pa,
        Err(_) => panic!("IOMMU translate returned Err for mapped page"),
    };
    if pa != kf::IOMMU_EXPECTED_PA {
        panic!("IOMMU translate PA drift");
    }

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"IOMMU translate OK pa=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let mut hex8 = [0u8; 8];
    hex_u32((pa & 0xFFFF_FFFF) as u32, &mut hex8);
    line[pos..pos + 8].copy_from_slice(&hex8);
    pos += 8;
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

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

/// NET: build the canonical UDP/IPv4 datagram through
/// [`target_enterprise::net::build_udp_datagram`], assert the 38 emitted
/// bytes match the locked golden fixture in `kernel_fixtures`, parse
/// the datagram back through `parse_ipv4_header` + `parse_udp_datagram`
/// and assert the recovered src_ip / dst_ip / ttl / ident / port
/// fields, then emit
/// `NET build OK len=<dec> ip_cksum=<hex4> udp_cksum=<hex4>\n`.
///
/// The byte-equality check against `NET_EXPECTED_DATAGRAM` is the
/// load-bearing wire-equivalence proof inside the kernel: a morph
/// candidate that produces different bytes panics here rather than
/// reaching the trailing PROTEUS-TE HALT banner — the QEMU smoke test
/// then surfaces the missing banner as a failure.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_net_build() {
    let mut buf = [0u8; kf::NET_EXPECTED_LEN];
    let n = build_udp_datagram(
        kf::NET_SRC_IP,
        kf::NET_DST_IP,
        kf::NET_SRC_PORT,
        kf::NET_DST_PORT,
        kf::NET_PAYLOAD,
        kf::NET_TTL,
        kf::NET_IDENT,
        &mut buf,
    )
    .unwrap_or_else(|_| panic!("NET build_udp_datagram failed"));
    if n != kf::NET_EXPECTED_LEN {
        panic!("NET emitted length drift");
    }
    assert_eq_bytes(&buf[..n], &kf::NET_EXPECTED_DATAGRAM, "NET datagram");

    let ip = parse_ipv4_header(&buf[..n])
        .unwrap_or_else(|_| panic!("NET parse_ipv4_header rejected own output"));
    if ip.src_ip != kf::NET_SRC_IP
        || ip.dst_ip != kf::NET_DST_IP
        || ip.ttl != kf::NET_TTL
        || ip.identification != kf::NET_IDENT
        || ip.header_checksum != kf::NET_EXPECTED_IP_CHECKSUM
    {
        panic!("NET IPv4 parse drift");
    }

    let udp = parse_udp_datagram(kf::NET_SRC_IP, kf::NET_DST_IP, &buf[20..n])
        .unwrap_or_else(|_| panic!("NET parse_udp_datagram rejected own output"));
    if udp.src_port != kf::NET_SRC_PORT
        || udp.dst_port != kf::NET_DST_PORT
        || udp.checksum != kf::NET_EXPECTED_UDP_CHECKSUM
        || udp.payload_len != kf::NET_PAYLOAD.len()
    {
        panic!("NET UDP parse drift");
    }

    let mut line = [0u8; 96];
    let mut pos = 0usize;
    let prefix = b"NET build OK len=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += dec_u64(n as u64, &mut line[pos..]);
    let mid = b" ip_cksum=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    let mut hex_ip = [0u8; 8];
    hex_u32(kf::NET_EXPECTED_IP_CHECKSUM as u32, &mut hex_ip);
    // Take the low 4 chars (16-bit value).
    line[pos..pos + 4].copy_from_slice(&hex_ip[4..]);
    pos += 4;
    let mid2 = b" udp_cksum=";
    line[pos..pos + mid2.len()].copy_from_slice(mid2);
    pos += mid2.len();
    let mut hex_udp = [0u8; 8];
    hex_u32(kf::NET_EXPECTED_UDP_CHECKSUM as u32, &mut hex_udp);
    line[pos..pos + 4].copy_from_slice(&hex_udp[4..]);
    pos += 4;
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

// ============================================================
// TASK-014: DMA syscall path. Construct an `IommuImpl<4, 8, 16>`, bind
// a synthetic privileged device, build a `Task` pre-bound to that
// IOMMU domain, then call `dispatch_dma` twice: SYS_DMA_MAP +
// SYS_DMA_UNMAP. The dispatcher routes through `check_cap` (which
// mints a `CapProof`) and the handler consumes the proof by value
// before delegating to the IOMMU. Emits:
//   `DMA_MAP test OK\n`
//   `DMA_UNMAP test OK\n`
//
// A kernel that boots with the type-state cap check + the IOMMU +
// the per-task `iommu_domain` field is exercising every load-bearing
// piece TASK-014 wired together. If any of them is broken (proof not
// minted, domain not threaded, IOMMU state lost), one of the two
// banners is missing from the serial log and the QEMU smoke test
// surfaces it.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_dma() {
    use proteus_contracts::Iommu;
    use proteus_contracts::caps::NET_RAW;
    use target_enterprise::iommu::{DeviceId as IommuDeviceId, IommuImpl as DmaIommuImpl};
    use target_enterprise::scheduler::{Task, TaskId};
    use target_enterprise::syscall::{dispatch_dma, SYS_DMA_MAP, SYS_DMA_UNMAP};

    let mut iommu: DmaIommuImpl<4, 8, 16> = DmaIommuImpl::new();
    let domain = iommu.create_domain().expect("kpti-dma: create_domain");
    let device = IommuDeviceId::from_bdf(0, 0, 1, 0);
    iommu
        .bind_device(device, domain)
        .expect("kpti-dma: bind_device");
    let task = Task::new_ready_with_domain(7 as TaskId, 1, domain);

    // ---- SYS_DMA_MAP ----
    let dma_addr = 0x4000u64;
    let host_phys = 0xC000_0000u64;
    match dispatch_dma(
        &mut iommu,
        &task,
        NET_RAW,
        SYS_DMA_MAP,
        dma_addr,
        host_phys,
        0b11, // RW
    ) {
        Ok(0) => {}
        Ok(other) => panic!("DMA_MAP returned unexpected Ok({})", other),
        Err(_) => panic!("DMA_MAP failed unexpectedly"),
    }
    serial_write_str("DMA_MAP test OK\n");

    // ---- SYS_DMA_UNMAP ----
    match dispatch_dma(
        &mut iommu,
        &task,
        NET_RAW,
        SYS_DMA_UNMAP,
        dma_addr,
        0,
        0,
    ) {
        Ok(0) => {}
        Ok(other) => panic!("DMA_UNMAP returned unexpected Ok({})", other),
        Err(_) => panic!("DMA_UNMAP failed unexpectedly"),
    }
    serial_write_str("DMA_UNMAP test OK\n");
}

// ============================================================
// TASK-018: NVMe driver round-trip. Construct an in-kernel
// `MemNvmeController` emulator, drive an `NvmeImpl` through the
// spec-mandated bring-up + IO-queue creation + Identify Controller
// + write+read round-trip, emit:
//   `NVMe init OK ctrl=PROTEUS-NVME-EMU\n`
//   `NVMe read_lba(7) OK first_byte=A5\n`
//
// The emulator runs in-kernel because the QEMU smoke test boots
// without an actual NVMe device attached (factory_builder doesn't
// pass `-device nvme,drive=...`). Running the emulator in-kernel is
// the same pattern banner_iommu_translate / banner_kpti use — the
// algorithmic core is exercised against synthetic state, proving the
// driver pipeline is functionally correct without requiring real
// hardware.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_nvme() {
    use target_enterprise::nvme::{
        MemNvmeController, NvmeImpl, IDENTIFY_BUF_SIZE, NVME_BLOCK_SIZE,
    };

    // Construct the emulator + driver. Emulator's disk is 32 KiB (64
    // blocks) — small enough to live on the kernel stack.
    let mut drv = NvmeImpl::new(MemNvmeController::new());

    // Bring up the controller, create I/O queues.
    if drv.bring_up(0x1000, 0x2000).is_err() {
        panic!("NVMe bring_up failed");
    }
    if drv.create_io_queues(0x3000, 0x4000).is_err() {
        panic!("NVMe create_io_queues failed");
    }

    // Identify Controller — emulator stamps "PROTEUS-NVME-EMU" into
    // bytes [4..24] of the response. Confirm.
    let mut ident = [0u8; IDENTIFY_BUF_SIZE];
    if drv.identify_controller(0x5000, &mut ident).is_err() {
        panic!("NVMe identify_controller failed");
    }
    if &ident[4..20] != b"PROTEUS-NVME-EMU" {
        panic!("NVMe identify_controller SN mismatch");
    }

    // Emit init banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"NVMe init OK ctrl=PROTEUS-NVME-EMU";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Identify Namespace — populates disk_blocks (=64).
    let nsze = match drv.identify_namespace(0x5000) {
        Ok(n) => n,
        Err(_) => panic!("NVMe identify_namespace failed"),
    };
    if nsze != 64 {
        panic!("NVMe namespace block count drift");
    }

    // Write a fixture pattern to LBA 7, read it back, confirm.
    let mut write_buf = [0u8; NVME_BLOCK_SIZE];
    write_buf[0] = 0xA5; // First byte we'll surface in the banner.
    for i in 1..NVME_BLOCK_SIZE {
        write_buf[i] = ((i * 13) & 0xFF) as u8;
    }
    if drv.try_write_block(7, &write_buf, 0x6000).is_err() {
        panic!("NVMe try_write_block failed");
    }
    let mut read_buf = [0u8; NVME_BLOCK_SIZE];
    if drv.try_read_block(7, &mut read_buf, 0x6000).is_err() {
        panic!("NVMe try_read_block failed");
    }
    // Byte-equality check — load-bearing: if any byte differs, the
    // banner is suppressed and the QEMU smoke test fails.
    let mut i = 0usize;
    while i < NVME_BLOCK_SIZE {
        if read_buf[i] != write_buf[i] {
            panic!("NVMe read_back byte mismatch");
        }
        i += 1;
    }

    // Emit read_lba banner with the first byte (0xA5).
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"NVMe read_lba(7) OK first_byte=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 2];
        hex_encode(&read_buf[..1], 1, &mut hex);
        line[pos..pos + 2].copy_from_slice(&hex);
        pos += 2;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// TCP: drive a full 3-way handshake (LISTEN → SYN_RCVD → ESTABLISHED)
// then a clean teardown (FIN-from-peer → CLOSE_WAIT → close() → LAST_ACK
// → ACK → CLOSED). Every transition exercises real TCB state arithmetic
// AND a real wire-byte round-trip through `TcpImpl::build_segment` +
// `TcpImpl::parse_segment` (checksum-verified). Emits:
//   `TCP handshake OK state=ESTABLISHED seq=<hex8>\n`
//   `TCP teardown OK state=CLOSED snd_nxt=<hex8>\n`
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_tcp() {
    use proteus_contracts::{tcp_flags, Tcp};
    use target_enterprise::tcp::{close, process_segment, Tcb, TcpImpl, TcpState};

    let server_ip: [u8; 4] = [10, 0, 0, 2];
    let client_ip: [u8; 4] = [10, 0, 0, 1];
    let server_port: u16 = 8443;
    let client_port: u16 = 54321;
    let client_isn: u32 = 0x1000_0000;

    // Step 1: passive open.
    let mut tcb = Tcb::listen(server_ip, server_port, 65535);
    if tcb.state != TcpState::Listen {
        panic!("TCP listen did not produce Listen state");
    }

    // Step 2: client → server SYN.
    let mut buf = [0u8; 64];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn,
        0,
        tcp_flags::SYN,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TCP build SYN failed"),
    };
    let syn = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("TCP parse SYN failed (checksum?)"),
    };
    let (next_tcb, syn_ack_hint) = match process_segment(tcb, &syn, 0xCAFE) {
        Ok(t) => t,
        Err(_) => panic!("TCP process SYN failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::SynReceived {
        panic!("TCP SYN did not move TCB to SynReceived");
    }
    if !syn_ack_hint.present {
        panic!("TCP process SYN must produce a SYN+ACK reply hint");
    }
    let server_isn = syn_ack_hint.seq;

    // Step 3: client → server ACK of SYN+ACK.
    let mut buf = [0u8; 64];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        tcp_flags::ACK,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TCP build ACK-of-SYN failed"),
    };
    let ack = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("TCP parse ACK-of-SYN failed"),
    };
    let (next_tcb, _reply) = match process_segment(tcb, &ack, 0xCAFE) {
        Ok(t) => t,
        Err(_) => panic!("TCP process ACK-of-SYN failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::Established {
        panic!("TCP 3-way handshake did not reach Established");
    }
    let established_seq = tcb.snd_nxt;

    // Emit handshake banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TCP handshake OK state=ESTABLISHED seq=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let bytes = established_seq.to_be_bytes();
        let mut hex = [0u8; 8];
        hex_encode(&bytes, 4, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Step 4: client → server FIN (peer initiating close).
    let mut buf = [0u8; 64];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        tcp_flags::FIN | tcp_flags::ACK,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TCP build FIN failed"),
    };
    let fin = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("TCP parse FIN failed"),
    };
    let (next_tcb, _reply) = match process_segment(tcb, &fin, 0xCAFE) {
        Ok(t) => t,
        Err(_) => panic!("TCP process FIN failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::CloseWait {
        panic!("TCP FIN did not move TCB to CloseWait");
    }

    // Step 5: local close() → LastAck.
    let (next_tcb, fin_hint) = match close(tcb) {
        Ok(t) => t,
        Err(_) => panic!("TCP close() failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::LastAck {
        panic!("TCP close() did not produce LastAck");
    }
    if !fin_hint.present {
        panic!("TCP close() must produce FIN reply hint");
    }

    // Step 6: client → server ACK of our FIN.
    let mut buf = [0u8; 64];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(2),
        tcb.snd_nxt,
        tcp_flags::ACK,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TCP build ACK-of-our-FIN failed"),
    };
    let ack = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("TCP parse ACK-of-our-FIN failed"),
    };
    let (next_tcb, _reply) = match process_segment(tcb, &ack, 0xCAFE) {
        Ok(t) => t,
        Err(_) => panic!("TCP process ACK-of-our-FIN failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::Closed {
        panic!("TCP teardown did not reach Closed");
    }

    // Emit teardown banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TCP teardown OK state=CLOSED snd_nxt=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let bytes = tcb.snd_nxt.to_be_bytes();
        let mut hex = [0u8; 8];
        hex_encode(&bytes, 4, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// HTTP/1.1: parse a fixture `GET /healthz HTTP/1.1` request through
// `HttpImpl::parse_request`, then build a 200 OK response with
// `Content-Type: text/plain` and body "OK" through
// `HttpImpl::build_response`. Asserts the parsed method/path AND the
// byte-exact response prefix. Emits:
//   `HTTP parse OK method=GET path=/healthz\n`
//   `HTTP build OK status=200 bytes=<N>\n`
//
// A morph that perturbs the request-line tokenizer, the header-block
// scanner, or the response status-line emitter panics inside this
// banner and the trailing `PROTEUS-TE HALT` is suppressed.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_http() {
    use proteus_contracts::{Http, HttpMethod};
    use target_enterprise::http::HttpImpl;

    // --- parse ---
    let req: &[u8] = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nUser-Agent: probe\r\n\r\n";
    let view = match HttpImpl::parse_request(req) {
        Ok(v) => v,
        Err(_) => panic!("HTTP parse_request returned Err for healthz fixture"),
    };
    if view.method != HttpMethod::Get {
        panic!("HTTP parse: method drift");
    }
    if view.path != b"/healthz" {
        panic!("HTTP parse: path drift");
    }
    if view.version_minor != 1 {
        panic!("HTTP parse: version drift");
    }
    // Header lookup must find Host case-insensitively.
    match HttpImpl::find_header(view.headers_raw, b"host") {
        Some(v) if v == b"localhost" => {}
        Some(_) => panic!("HTTP find_header: host value drift"),
        None => panic!("HTTP find_header: missing Host"),
    }
    serial_write_str("HTTP parse OK method=GET path=/healthz\n");

    // --- build ---
    let mut out = [0u8; 96];
    let n = match HttpImpl::build_response(200, b"text/plain", b"OK", &mut out) {
        Ok(n) => n,
        Err(_) => panic!("HTTP build_response returned Err"),
    };
    // Byte-exact assert on the full response we expect from the locked
    // wire surface.
    let expected: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK";
    if n != expected.len() {
        panic!("HTTP build: length drift");
    }
    assert_eq_bytes(&out[..n], expected, "HTTP response");

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"HTTP build OK status=200 bytes=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += dec_u64(n as u64, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// DNS/RFC 1035: build an A-record query for `proteus.local`, parse it
// to recover the question name byte-for-byte, then build a response
// pointing to 10.0.0.42 and assert the resulting bytes match the
// locked golden encoding. Emits:
//   `DNS query OK id=<hex4> qname=proteus.local\n`
//   `DNS response OK id=<hex4> ans=10.0.0.42 bytes=<N>\n`
//
// A morph that perturbs name encoding, header byte order, or the
// answer-section assembly panics here and the trailing banners are
// suppressed.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_dns() {
    use proteus_contracts::{dns_class, dns_flags, Dns, DnsRecordType};
    use target_enterprise::dns::DnsImpl;

    let qid: u16 = 0xC0DE;

    // --- query build ---
    let mut qbuf = [0u8; 64];
    let qn = match DnsImpl::build_a_query(qid, b"proteus.local", &mut qbuf) {
        Ok(n) => n,
        Err(_) => panic!("DNS build_a_query returned Err"),
    };
    // Byte-exact assertion: known canonical encoding of "proteus.local"
    // as an A query with RD set.
    let qexpected: &[u8] = &[
        0xC0, 0xDE, // id
        0x01, 0x00, // flags (RD)
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // qd=1, an/ns/ar=0
        7, b'p', b'r', b'o', b't', b'e', b'u', b's',
        5, b'l', b'o', b'c', b'a', b'l', 0, // QNAME
        0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
    ];
    if qn != qexpected.len() {
        panic!("DNS query length drift");
    }
    assert_eq_bytes(&qbuf[..qn], qexpected, "DNS A query");

    // --- parse round-trip ---
    let qview = match DnsImpl::parse_message(&qbuf[..qn]) {
        Ok(v) => v,
        Err(_) => panic!("DNS parse_message rejected own query"),
    };
    if qview.header.id != qid {
        panic!("DNS parse: id drift");
    }
    if qview.header.qdcount != 1 {
        panic!("DNS parse: qdcount drift");
    }
    if qview.first_question_type != DnsRecordType::A as u16 {
        panic!("DNS parse: qtype drift");
    }
    if qview.first_question_class != dns_class::IN {
        panic!("DNS parse: qclass drift");
    }
    let qname_wire = match qview.first_question_name {
        Some(n) => n,
        None => panic!("DNS parse: missing first question name"),
    };

    let mut line = [0u8; 80];
    let mut pos = 0usize;
    let prefix = b"DNS query OK id=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let id_be = qid.to_be_bytes();
    let mut hex = [0u8; 4];
    hex_encode(&id_be, 2, &mut hex);
    line[pos..pos + 4].copy_from_slice(&hex);
    pos += 4;
    let mid = b" qname=proteus.local";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);

    // --- response build (echo of the parsed qname + 10.0.0.42 / TTL 60) ---
    let mut rbuf = [0u8; 96];
    let rn = match DnsImpl::build_a_response(qid, qname_wire, [10, 0, 0, 42], 60, &mut rbuf) {
        Ok(n) => n,
        Err(_) => panic!("DNS build_a_response returned Err"),
    };
    // Parse the response and verify the recovered fields.
    let rview = match DnsImpl::parse_message(&rbuf[..rn]) {
        Ok(v) => v,
        Err(_) => panic!("DNS parse_message rejected own response"),
    };
    if rview.header.id != qid {
        panic!("DNS response: id drift");
    }
    if rview.header.flags & dns_flags::QR_RESPONSE == 0 {
        panic!("DNS response: QR bit clear");
    }
    if rview.header.qdcount != 1 || rview.header.ancount != 1 {
        panic!("DNS response: section count drift");
    }
    // Confirm the rdata bytes 10.0.0.42 land at the locked offset.
    // header(12) + qname + 4 (qtype/qclass) + qname + 2 + 2 + 4 + 2
    let qn_len = qname_wire.len();
    let rdata_off = 12 + qn_len + 4 + qn_len + 2 + 2 + 4 + 2;
    if rbuf[rdata_off] != 10
        || rbuf[rdata_off + 1] != 0
        || rbuf[rdata_off + 2] != 0
        || rbuf[rdata_off + 3] != 42
    {
        panic!("DNS response: rdata drift");
    }

    let mut line = [0u8; 96];
    let mut pos = 0usize;
    let prefix = b"DNS response OK id=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let mut hex = [0u8; 4];
    hex_encode(&id_be, 2, &mut hex);
    line[pos..pos + 4].copy_from_slice(&hex);
    pos += 4;
    let mid = b" ans=10.0.0.42 bytes=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += dec_u64(rn as u64, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// ICMP/RFC 792: build an echo request (ping) with id=0x4242, seq=7,
// payload "proteus-ping", parse it (which verifies the RFC 1071
// checksum), then build the matching echo reply and confirm the
// reply parses with type=ECHO_REPLY and identical id/seq. Emits:
//   `ICMP echo_req OK id=4242 seq=7 cksum=<hex4>\n`
//   `ICMP echo_rep OK id=4242 seq=7\n`
//
// A morph that perturbs the checksum routine, the type-code byte, or
// the identifier/sequence byte order panics inside `banner_icmp` and
// these banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_icmp() {
    use proteus_contracts::{icmp_type, Icmp};
    use target_enterprise::icmp::IcmpImpl;

    let id: u16 = 0x4242;
    let seq: u16 = 7;
    let payload: &[u8] = b"proteus-ping";

    // --- build + parse echo request ---
    let mut qbuf = [0u8; 32];
    let qn = match IcmpImpl::build_echo_request(id, seq, payload, &mut qbuf) {
        Ok(n) => n,
        Err(_) => panic!("ICMP build_echo_request returned Err"),
    };
    let qview = match IcmpImpl::parse_echo(&qbuf[..qn]) {
        Ok(v) => v,
        Err(_) => panic!("ICMP parse_echo rejected own request (checksum?)"),
    };
    if qview.icmp_type != icmp_type::ECHO_REQUEST {
        panic!("ICMP echo request: type drift");
    }
    if qview.identifier != id || qview.sequence_number != seq {
        panic!("ICMP echo request: id/seq drift");
    }
    if qview.payload != payload {
        panic!("ICMP echo request: payload drift");
    }

    let mut line = [0u8; 80];
    let mut pos = 0usize;
    let prefix = b"ICMP echo_req OK id=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let id_be = id.to_be_bytes();
    let mut hex = [0u8; 4];
    hex_encode(&id_be, 2, &mut hex);
    line[pos..pos + 4].copy_from_slice(&hex);
    pos += 4;
    let mid = b" seq=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += dec_u64(seq as u64, &mut line[pos..]);
    let mid2 = b" cksum=";
    line[pos..pos + mid2.len()].copy_from_slice(mid2);
    pos += mid2.len();
    let cksum_be = qview.checksum.to_be_bytes();
    let mut cks_hex = [0u8; 4];
    hex_encode(&cksum_be, 2, &mut cks_hex);
    line[pos..pos + 4].copy_from_slice(&cks_hex);
    pos += 4;
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);

    // --- build + parse echo reply ---
    let mut rbuf = [0u8; 32];
    let rn = match IcmpImpl::build_echo_reply(id, seq, payload, &mut rbuf) {
        Ok(n) => n,
        Err(_) => panic!("ICMP build_echo_reply returned Err"),
    };
    let rview = match IcmpImpl::parse_echo(&rbuf[..rn]) {
        Ok(v) => v,
        Err(_) => panic!("ICMP parse_echo rejected own reply"),
    };
    if rview.icmp_type != icmp_type::ECHO_REPLY {
        panic!("ICMP echo reply: type drift");
    }
    if rview.identifier != id || rview.sequence_number != seq {
        panic!("ICMP echo reply: id/seq drift");
    }

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"ICMP echo_rep OK id=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let mut hex = [0u8; 4];
    hex_encode(&id_be, 2, &mut hex);
    line[pos..pos + 4].copy_from_slice(&hex);
    pos += 4;
    let mid = b" seq=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += dec_u64(seq as u64, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// Ethernet/IEEE 802.3: wrap the locked NET fixture (the
// 38-byte UDP/IPv4 datagram from kernel_fixtures) inside an Ethernet
// II frame, byte-exact assert against the locked golden bytes
// (header + payload), parse it back through `EthImpl::parse_frame`,
// confirm dst/src/EtherType/payload are recovered. Then build a
// VLAN-tagged version with PCP=3/VID=100 and round-trip it. Emits:
//   `ETH build OK len=52 ethertype=0800`
//   `ETH parse OK src=00aabbccddee dst=1234567890bc`
//   `ETH vlan OK tci=6064 vid=100 pcp=3`
//
// A morph that perturbs MAC byte order, EtherType big-endian
// encoding, VLAN TCI field packing, or the header byte layout
// panics in `banner_eth` and the banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_eth() {
    use proteus_contracts::{ether_type, Eth};
    use target_enterprise::ethernet::{
        is_broadcast, pack_vlan_tci, vlan_pcp, vlan_vid, EthImpl, ETH_HEADER_LEN,
    };
    use target_enterprise::net::build_udp_datagram;

    let dst: [u8; 6] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
    let src: [u8; 6] = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

    // Rebuild the canonical UDP/IPv4 datagram so we have a real wire
    // payload to wrap — not just synthetic bytes.
    let mut ipv4 = [0u8; kf::NET_EXPECTED_LEN];
    let ipv4_len = build_udp_datagram(
        kf::NET_SRC_IP,
        kf::NET_DST_IP,
        kf::NET_SRC_PORT,
        kf::NET_DST_PORT,
        kf::NET_PAYLOAD,
        kf::NET_TTL,
        kf::NET_IDENT,
        &mut ipv4,
    )
    .unwrap_or_else(|_| panic!("ETH banner: net build failed"));
    if ipv4_len != kf::NET_EXPECTED_LEN {
        panic!("ETH banner: net length drift");
    }

    // --- build untagged frame ---
    let mut frame = [0u8; 64];
    let n = match EthImpl::build_frame(dst, src, ether_type::IPV4, &ipv4[..ipv4_len], &mut frame)
    {
        Ok(n) => n,
        Err(_) => panic!("ETH build_frame returned Err"),
    };
    if n != ETH_HEADER_LEN + ipv4_len {
        panic!("ETH build_frame length drift");
    }
    // Header bytes byte-exact.
    let mut header_expected = [0u8; 14];
    header_expected[..6].copy_from_slice(&dst);
    header_expected[6..12].copy_from_slice(&src);
    header_expected[12] = 0x08;
    header_expected[13] = 0x00;
    assert_eq_bytes(&frame[..14], &header_expected, "ETH header");
    // Payload bytes byte-exact (against the locked NET fixture).
    assert_eq_bytes(&frame[14..n], &kf::NET_EXPECTED_DATAGRAM, "ETH payload");

    // Broadcast detection sanity — used by the eventual NIC driver to
    // short-circuit the unicast-filter path.
    let bcast = proteus_contracts::ETH_BROADCAST_MAC;
    if !is_broadcast(&bcast) {
        panic!("ETH is_broadcast(ETH_BROADCAST_MAC) returned false");
    }

    // Emit build banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"ETH build OK len=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        let mid = b" ethertype=0800";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- parse + recover ---
    let view = match EthImpl::parse_frame(&frame[..n]) {
        Ok(v) => v,
        Err(_) => panic!("ETH parse_frame rejected own output"),
    };
    if view.dst != dst {
        panic!("ETH parse: dst MAC drift");
    }
    if view.src != src {
        panic!("ETH parse: src MAC drift");
    }
    if view.ether_type != ether_type::IPV4 {
        panic!("ETH parse: ethertype drift");
    }
    if view.vlan_tci.is_some() {
        panic!("ETH parse: untagged frame claimed VLAN");
    }
    if view.payload.len() != ipv4_len {
        panic!("ETH parse: payload length drift");
    }
    if &view.payload[..] != &kf::NET_EXPECTED_DATAGRAM[..] {
        panic!("ETH parse: payload byte drift");
    }

    // Emit parse banner with src/dst MACs as hex12.
    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"ETH parse OK src=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 12];
        hex_encode(&src, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        let mid = b" dst=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        hex_encode(&dst, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- 802.1Q VLAN tagged round-trip ---
    let tci = pack_vlan_tci(3, false, 100); // PCP=3, DEI=0, VID=100
    if tci != 0x6064 {
        panic!("ETH pack_vlan_tci drift");
    }
    let mut vbuf = [0u8; 64];
    let vn = match EthImpl::build_frame_vlan(dst, src, tci, ether_type::IPV4, &[], &mut vbuf) {
        Ok(n) => n,
        Err(_) => panic!("ETH build_frame_vlan returned Err"),
    };
    let vview = match EthImpl::parse_frame(&vbuf[..vn]) {
        Ok(v) => v,
        Err(_) => panic!("ETH parse rejected own VLAN frame"),
    };
    match vview.vlan_tci {
        Some(t) if t == tci => {}
        Some(_) => panic!("ETH VLAN tci drift"),
        None => panic!("ETH parse missed VLAN tag"),
    }
    if vlan_pcp(tci) != 3 || vlan_vid(tci) != 100 {
        panic!("ETH VLAN field decode drift");
    }

    // Emit VLAN banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"ETH vlan OK tci=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let tci_be = tci.to_be_bytes();
        let mut hex = [0u8; 4];
        hex_encode(&tci_be, 2, &mut hex);
        line[pos..pos + 4].copy_from_slice(&hex);
        pos += 4;
        let mid = b" vid=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(vlan_vid(tci) as u64, &mut line[pos..]);
        let mid2 = b" pcp=";
        line[pos..pos + mid2.len()].copy_from_slice(mid2);
        pos += mid2.len();
        pos += dec_u64(vlan_pcp(tci) as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// TASK-046: ARP / RFC 826 over Ethernet. Build a REQUEST asking
// "who has 10.0.0.42? tell 10.0.0.1 / 00:AA:BB:CC:DD:EE", assert
// the wire bytes are byte-exact against the locked 28-byte
// expectation, parse them back through `ArpImpl::parse_packet`,
// confirm the round-trip recovers OPER/sender/target. Then build
// the matching REPLY (target_mac = 12:34:56:78:9A:BC) and add it
// to a 4-slot ArpCache; confirm lookup hits. Emits:
//   `ARP request OK target_ip=10.0.0.42 op=1`
//   `ARP cache OK entries=1`
//
// A morph that perturbs HTYPE/PTYPE big-endian encoding, the
// HLEN/PLEN constants, the 28-byte field layout, or the cache LRU /
// poison-defence routine panics inside `banner_arp` and the
// banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_arp() {
    use proteus_contracts::{arp_op, Arp};
    use target_enterprise::arp::{ArpCache, ArpImpl, PACKET_LEN};

    let sender_mac: [u8; 6] = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let sender_ip: [u8; 4] = [10, 0, 0, 1];
    let target_ip: [u8; 4] = [10, 0, 0, 42];
    let target_mac: [u8; 6] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];

    // --- build REQUEST ---
    let mut req = [0u8; 32];
    let qn = match ArpImpl::build_request(sender_mac, sender_ip, target_ip, &mut req) {
        Ok(n) => n,
        Err(_) => panic!("ARP build_request returned Err"),
    };
    if qn != PACKET_LEN {
        panic!("ARP build_request length drift");
    }
    let expected_req: [u8; 28] = [
        0x00, 0x01, // HTYPE = 1
        0x08, 0x00, // PTYPE = 0x0800
        0x06, 0x04, // HLEN=6, PLEN=4
        0x00, 0x01, // OPER = REQUEST
        0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // sender MAC
        10, 0, 0, 1, // sender IP
        0, 0, 0, 0, 0, 0, // target MAC zeros
        10, 0, 0, 42, // target IP
    ];
    assert_eq_bytes(&req[..qn], &expected_req, "ARP REQUEST bytes");

    // Parse + recover.
    let qview = match ArpImpl::parse_packet(&req[..qn]) {
        Ok(v) => v,
        Err(_) => panic!("ARP parse_packet rejected own REQUEST"),
    };
    if qview.oper != arp_op::REQUEST {
        panic!("ARP REQUEST: oper drift");
    }
    if qview.sender_mac != sender_mac {
        panic!("ARP REQUEST: sender_mac drift");
    }
    if qview.sender_ip != sender_ip {
        panic!("ARP REQUEST: sender_ip drift");
    }
    if qview.target_ip != target_ip {
        panic!("ARP REQUEST: target_ip drift");
    }
    if qview.target_mac != [0u8; 6] {
        panic!("ARP REQUEST: target_mac not all-zeros");
    }

    // Emit request banner.
    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"ARP request OK target_ip=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // Format the dotted-decimal IP in-line — keeps the banner
        // grep-friendly for the qemu_smoke required-banner check.
        let octets = [target_ip[0], target_ip[1], target_ip[2], target_ip[3]];
        for (i, oct) in octets.iter().enumerate() {
            pos += dec_u64(*oct as u64, &mut line[pos..]);
            if i < 3 {
                line[pos] = b'.';
                pos += 1;
            }
        }
        let mid = b" op=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(qview.oper as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- build matching REPLY + populate cache ---
    let mut rep = [0u8; 32];
    let rn = match ArpImpl::build_reply(target_mac, target_ip, sender_mac, sender_ip, &mut rep) {
        Ok(n) => n,
        Err(_) => panic!("ARP build_reply returned Err"),
    };
    let rview = match ArpImpl::parse_packet(&rep[..rn]) {
        Ok(v) => v,
        Err(_) => panic!("ARP parse_packet rejected own REPLY"),
    };
    if rview.oper != arp_op::REPLY {
        panic!("ARP REPLY: oper drift");
    }
    if rview.sender_mac != target_mac {
        panic!("ARP REPLY: sender_mac drift");
    }
    if rview.sender_ip != target_ip {
        panic!("ARP REPLY: sender_ip drift");
    }
    if rview.target_mac != sender_mac {
        panic!("ARP REPLY: target_mac drift");
    }

    let mut cache: ArpCache<4> = ArpCache::new();
    // Use the parsed REPLY's (sender_ip, sender_mac) — that's the
    // canonical "we now know IP X is at MAC Y" pattern.
    if cache
        .insert(rview.sender_ip, rview.sender_mac, 100)
        .is_err()
    {
        panic!("ARP cache insert failed");
    }
    if cache.len() != 1 {
        panic!("ARP cache: post-insert len drift");
    }
    match cache.lookup(&target_ip, 200) {
        Some(m) if m == target_mac => {}
        Some(_) => panic!("ARP cache: lookup returned wrong MAC"),
        None => panic!("ARP cache: lookup missed inserted entry"),
    }

    // Emit cache banner.
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"ARP cache OK entries=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(cache.len() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// TASK-047: DHCPv4 client (RFC 2131/2132). Drive a synthetic
// INIT → DISCOVER → (parse OFFER fixture) → REQUEST → (parse ACK
// fixture) → BOUND sequence. Asserts:
//   - DISCOVER bytes round-trip through parse_message (xid +
//     msg_type recovered).
//   - OFFER fixture is accepted: state -> Requesting, yiaddr +
//     server_id captured.
//   - ACK fixture binds the lease with the expected yiaddr.
//
// Emits:
//   `DHCP discover OK xid=<hex8>\n`
//   `DHCP bound OK yiaddr=10.0.0.42 lease=86400\n`
//
// A kernel that perturbs the BOOTP byte order, mishandles the
// magic-cookie offset, or breaks the option TLV scan panics here
// and the trailing banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_dhcp() {
    use proteus_contracts::{dhcp_msg_type, Dhcp, DhcpClientState, DHCP_FIXED_HEADER_LEN};
    use target_enterprise::dhcp::{DhcpClient, DhcpImpl, DHCP_MAX_MESSAGE_LEN};

    let mac: [u8; 6] = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let xid: u32 = 0xDEAD_BEEF;
    let offered_ip: [u8; 4] = [10, 0, 0, 42];
    let server_id: [u8; 4] = [10, 0, 0, 1];
    let subnet: [u8; 4] = [255, 255, 255, 0];
    let router: [u8; 4] = [10, 0, 0, 1];
    let dns: [u8; 4] = [10, 0, 0, 53];
    let lease_secs: u32 = 86_400;

    // --- Step 1: build a DISCOVER, parse it back, assert msg_type. ---
    let mut cli = DhcpClient::new(mac);
    let mut disc = [0u8; DHCP_MAX_MESSAGE_LEN];
    let n_disc = match cli.start_discover(xid, &mut disc) {
        Ok(n) => n,
        Err(_) => panic!("DHCP start_discover returned Err"),
    };
    if n_disc < DHCP_FIXED_HEADER_LEN {
        panic!("DHCP DISCOVER undersized");
    }
    let dview = match DhcpImpl::parse_message(&disc[..n_disc]) {
        Ok(v) => v,
        Err(_) => panic!("DHCP parse_message rejected own DISCOVER"),
    };
    if dview.msg_type != dhcp_msg_type::DISCOVER {
        panic!("DHCP DISCOVER msg_type drift");
    }
    if dview.xid != xid {
        panic!("DHCP DISCOVER xid drift");
    }
    if dview.chaddr != mac {
        panic!("DHCP DISCOVER chaddr drift");
    }
    if cli.state() != DhcpClientState::Selecting {
        panic!("DHCP client state != Selecting after DISCOVER");
    }

    // Emit discover banner with the xid in hex.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"DHCP discover OK xid=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 8];
        hex_u32(xid, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- Step 2: build an OFFER fixture by hand, feed it into the client. ---
    let mut offer = [0u8; DHCP_MAX_MESSAGE_LEN];
    let offer_len = build_dhcp_reply_fixture(
        &mut offer,
        dhcp_msg_type::OFFER,
        xid,
        mac,
        offered_ip,
        Some(server_id),
        Some(subnet),
        Some(router),
        Some(dns),
        Some(lease_secs),
    );
    let mut req = [0u8; DHCP_MAX_MESSAGE_LEN];
    let _n_req = match cli.on_offer(&offer[..offer_len], &mut req) {
        Ok(n) => n,
        Err(_) => panic!("DHCP on_offer rejected fixture"),
    };
    if cli.state() != DhcpClientState::Requesting {
        panic!("DHCP client state != Requesting after OFFER");
    }
    if cli.offered_ip() != offered_ip {
        panic!("DHCP captured offered_ip drift");
    }
    if cli.server_id() != server_id {
        panic!("DHCP captured server_id drift");
    }

    // --- Step 3: build an ACK fixture, bind. ---
    let mut ack = [0u8; DHCP_MAX_MESSAGE_LEN];
    let ack_len = build_dhcp_reply_fixture(
        &mut ack,
        dhcp_msg_type::ACK,
        xid,
        mac,
        offered_ip,
        Some(server_id),
        Some(subnet),
        Some(router),
        Some(dns),
        Some(lease_secs),
    );
    let lease = match cli.on_ack(&ack[..ack_len], 1_700_000_000) {
        Ok(l) => l,
        Err(_) => panic!("DHCP on_ack rejected fixture"),
    };
    if cli.state() != DhcpClientState::Bound {
        panic!("DHCP client state != Bound after ACK");
    }
    if lease.assigned_ip != offered_ip {
        panic!("DHCP lease.assigned_ip drift");
    }
    if lease.lease_secs != lease_secs {
        panic!("DHCP lease.lease_secs drift");
    }
    if lease.server_id != server_id {
        panic!("DHCP lease.server_id drift");
    }
    if lease.gateway != router {
        panic!("DHCP lease.gateway drift");
    }
    if lease.dns != dns {
        panic!("DHCP lease.dns drift");
    }

    // Emit bound banner: `DHCP bound OK yiaddr=10.0.0.42 lease=86400`
    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"DHCP bound OK yiaddr=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let octs = [
            lease.assigned_ip[0],
            lease.assigned_ip[1],
            lease.assigned_ip[2],
            lease.assigned_ip[3],
        ];
        for (i, o) in octs.iter().enumerate() {
            pos += dec_u64(*o as u64, &mut line[pos..]);
            if i < 3 {
                line[pos] = b'.';
                pos += 1;
            }
        }
        let mid = b" lease=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(lease.lease_secs as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Build a DHCP reply fixture in `buf`. Returns the byte length
/// written. Helper exists only for `banner_dhcp` — the per-option
/// matrix is hand-built so the banner doesn't depend on the impl's
/// reply-builder (the impl only emits client→server messages).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_dhcp_reply_fixture(
    buf: &mut [u8],
    msg_type: u8,
    xid: u32,
    mac: [u8; 6],
    yiaddr: [u8; 4],
    server_id: Option<[u8; 4]>,
    subnet_mask: Option<[u8; 4]>,
    router: Option<[u8; 4]>,
    dns: Option<[u8; 4]>,
    lease_secs: Option<u32>,
) -> usize {
    use proteus_contracts::{
        dhcp_option, DHCP_FIXED_HEADER_LEN, DHCP_HLEN_ETHERNET, DHCP_HTYPE_ETHERNET,
        DHCP_MAGIC_COOKIE, DHCP_OP_BOOTREPLY,
    };
    // Zero the fixed header span.
    for b in &mut buf[..DHCP_FIXED_HEADER_LEN] {
        *b = 0;
    }
    buf[0] = DHCP_OP_BOOTREPLY;
    buf[1] = DHCP_HTYPE_ETHERNET;
    buf[2] = DHCP_HLEN_ETHERNET;
    buf[4..8].copy_from_slice(&xid.to_be_bytes());
    buf[16..20].copy_from_slice(&yiaddr);
    buf[28..34].copy_from_slice(&mac);
    buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    let mut pos = DHCP_FIXED_HEADER_LEN;
    // opt53 msg_type
    buf[pos] = dhcp_option::MSG_TYPE;
    buf[pos + 1] = 1;
    buf[pos + 2] = msg_type;
    pos += 3;
    if let Some(sm) = subnet_mask {
        buf[pos] = dhcp_option::SUBNET_MASK;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&sm);
        pos += 6;
    }
    if let Some(rt) = router {
        buf[pos] = dhcp_option::ROUTER;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&rt);
        pos += 6;
    }
    if let Some(d) = dns {
        buf[pos] = dhcp_option::DNS;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&d);
        pos += 6;
    }
    if let Some(lt) = lease_secs {
        buf[pos] = dhcp_option::LEASE_TIME;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&lt.to_be_bytes());
        pos += 6;
    }
    if let Some(sid) = server_id {
        buf[pos] = dhcp_option::SERVER_ID;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&sid);
        pos += 6;
    }
    buf[pos] = dhcp_option::END;
    pos + 1
}

// ============================================================
// TASK-019: Panic-dump capture + symbol resolution. Build a
// deterministic CrashContext from the locked fixtures, package it
// via `PanicDumpImpl::dump_to_sink` into an in-kernel
// `MemorySectorSink`, verify the body CRC32-C matches
// `kf::CRASH_EXPECTED_CRC32C`, parse the header back, then resolve
// the first backtrace frame through a `StaticSymbolResolver` over a
// hand-built kernel-symbol fixture and assert (name, offset) match
// the locked expectations.
//
// Emits:
//   `CRASH_DUMP wrote 16384 bytes to lba=1024 crc=<hex8>\n`
//   `SYMBOL resolve OK kernel_main+0x42 (5 frames)\n`
//
// A kernel that perturbs the dump layout (sector offsets, CRC poly,
// header byte order) or the symbol-resolver binary search panics in
// this banner and the trailing `PROTEUS-TE HALT` is suppressed.
// ============================================================
// ============================================================
// TASK-048: VirtIO-net driver (VirtIO 1.0 §5.1). Drive a complete
// bring-up + roundtrip exercise against the in-process MemVirtioBus
// emulator:
//   - construct bus + driver, run init: asserts status sequence,
//     feature negotiation, MAC read, queue setup, RX pre-post.
//   - transmit a locked 60-byte fixture frame: asserts the captured
//     TX observation is byte-identical to the input.
//   - inject a synthetic incoming frame, deliver into the RX ring,
//     receive: asserts the returned bytes equal the injected frame
//     byte-for-byte and that the virtio_net header was stripped.
//
// Emits:
//   `VIRTIO_NET init OK mac=525400123456\n`
//   `VIRTIO_NET roundtrip OK tx=1 rx=1\n`
//
// A kernel that perturbs the descriptor wire layout, the bring-up
// status sequence, the feature-bit constants, or the TX/RX ring
// arithmetic panics here and these banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_virtio_net() {
    use proteus_contracts::NetDevice;
    use target_enterprise::virtio_net::{MemVirtioBus, VirtioNet, MAX_FRAME_LEN};

    // The MemVirtioBus carries a 64 KiB shadow + observation/pending
    // FIFOs (~85 KiB total). That's too large for the kernel-main
    // stack (the bootloader allocates a modest stack and we're
    // already deep into the banner sequence). Park it in static
    // storage guarded by a spin::Mutex.
    static BUS_STORAGE: spin::Mutex<MemVirtioBus> = spin::Mutex::new(MemVirtioBus::new());
    let mut bus_guard = BUS_STORAGE.lock();
    let bus: &mut MemVirtioBus = &mut *bus_guard;
    let mut drv = VirtioNet::new();

    if drv.init(bus).is_err() {
        panic!("virtio-net init failed");
    }
    let mac = drv.mac_address();
    if mac != [0x52, 0x54, 0x00, 0x12, 0x34, 0x56] {
        panic!("virtio-net MAC drift");
    }
    if !drv.link_up() {
        panic!("virtio-net link_up drift (expected true after init on default bus)");
    }

    // Emit init banner: `VIRTIO_NET init OK mac=525400123456`.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_NET init OK mac=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 12];
        hex_encode(&mac, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Build a locked 60-byte TX fixture: dst=broadcast, src=our MAC,
    // EtherType=0x0800, then a recognisable payload.
    let mut tx_frame = [0u8; 60];
    tx_frame[0] = 0xFF;
    tx_frame[1] = 0xFF;
    tx_frame[2] = 0xFF;
    tx_frame[3] = 0xFF;
    tx_frame[4] = 0xFF;
    tx_frame[5] = 0xFF;
    tx_frame[6] = mac[0];
    tx_frame[7] = mac[1];
    tx_frame[8] = mac[2];
    tx_frame[9] = mac[3];
    tx_frame[10] = mac[4];
    tx_frame[11] = mac[5];
    tx_frame[12] = 0x08; // EtherType high
    tx_frame[13] = 0x00; // EtherType low
    let mut i = 14;
    while i < 60 {
        tx_frame[i] = (i as u8).wrapping_mul(7).wrapping_add(11);
        i += 1;
    }

    if drv.transmit(bus, &tx_frame).is_err() {
        panic!("virtio-net transmit failed");
    }

    // Confirm the bus captured the TX frame byte-for-byte.
    let obs = bus.tx_observations();
    if obs.len() != 1 {
        panic!("virtio-net TX observation count drift");
    }
    if obs[0].len != 60 {
        panic!("virtio-net TX observation len drift");
    }
    let mut j = 0usize;
    while j < 60 {
        if obs[0].bytes[j] != tx_frame[j] {
            panic!("virtio-net TX byte drift");
        }
        j += 1;
    }

    // Inject an incoming frame. Use a different recognisable
    // payload so it cannot be confused with the TX bytes.
    let mut rx_inject = [0u8; 80];
    rx_inject[0] = mac[0];
    rx_inject[1] = mac[1];
    rx_inject[2] = mac[2];
    rx_inject[3] = mac[3];
    rx_inject[4] = mac[4];
    rx_inject[5] = mac[5];
    rx_inject[6] = 0xDE;
    rx_inject[7] = 0xAD;
    rx_inject[8] = 0xBE;
    rx_inject[9] = 0xEF;
    rx_inject[10] = 0xCA;
    rx_inject[11] = 0xFE;
    rx_inject[12] = 0x08;
    rx_inject[13] = 0x06; // EtherType = ARP — irrelevant to RX path.
    let mut k = 14usize;
    while k < 80 {
        rx_inject[k] = (k as u8) ^ 0x5A;
        k += 1;
    }

    if !bus.enqueue_rx(&rx_inject) {
        panic!("virtio-net RX enqueue refused");
    }
    if !bus.deliver_pending_rx() {
        panic!("virtio-net RX delivery refused");
    }

    let mut rx_out = [0u8; MAX_FRAME_LEN];
    let n = match drv.receive(bus, &mut rx_out) {
        Ok(n) => n,
        Err(_) => panic!("virtio-net receive failed"),
    };
    if n != 80 {
        panic!("virtio-net RX length drift");
    }
    let mut m = 0usize;
    while m < 80 {
        if rx_out[m] != rx_inject[m] {
            panic!("virtio-net RX byte drift");
        }
        m += 1;
    }

    // Emit roundtrip banner: `VIRTIO_NET roundtrip OK tx=1 rx=1`.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_NET roundtrip OK tx=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(drv.tx_count() as u64, &mut line[pos..]);
        let mid = b" rx=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(drv.rx_count() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

