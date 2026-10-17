//! Kernel submodule.

pub(crate) use crate::*;

// ============================================================
// TASK-061: VirtIO-blk driver bring-up + sector round-trip.
//
// Constructs a MemVirtioBlkBus + VirtioBlk in static storage,
// drives the VirtIO 1.0 RESET → ACK → DRIVER → FEATURES_OK →
// DRIVER_OK handshake against a virtio-blk device, reads the
// disk capacity from device-cfg (32 sectors — the bus default),
// writes a locked 512-byte pattern to sector 3, then reads it
// back and asserts byte-equality.
//
// Emits (in order):
//   `VIRTIO_BLK init OK capacity=32 blk_size=512\n`
//   `VIRTIO_BLK roundtrip OK reqs=2 sector=3 first_byte=a5\n`
//
// A kernel that perturbs the descriptor wire layout, the bring-up
// status sequence, the feature-bit constants, the request-header
// byte order, or the 3-descriptor chain shape panics here and
// these banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_virtio_blk() {
    use proteus_contracts::{BlockDeviceVirtio, VIRTIO_BLK_SECTOR_SIZE};
    use target_enterprise::virtio_blk::{MemVirtioBlkBus, VirtioBlk};

    // Same static-storage pattern as banner_virtio_net — the bus
    // carries a 64 KiB shadow + a 16 KiB backing disk + a handful
    // of observation buffers. Too large for the kernel-main stack
    // (the bootloader allocates a modest stack and the banner
    // sequence is already deep into it).
    static BUS_STORAGE: spin::Mutex<MemVirtioBlkBus> = spin::Mutex::new(MemVirtioBlkBus::new());
    let mut bus_guard = BUS_STORAGE.lock();
    let bus: &mut MemVirtioBlkBus = &mut *bus_guard;
    let mut drv = VirtioBlk::new();

    if drv.init(bus).is_err() {
        panic!("virtio-blk init failed");
    }
    if drv.capacity_sectors() != MemVirtioBlkBus::DISK_SECTORS {
        panic!("virtio-blk capacity drift");
    }
    if drv.preferred_block_size() != VIRTIO_BLK_SECTOR_SIZE as u32 {
        panic!("virtio-blk preferred_block_size drift");
    }
    if drv.read_only() {
        panic!("virtio-blk unexpected read-only flag");
    }

    // Emit init banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_BLK init OK capacity=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(drv.capacity_sectors(), &mut line[pos..]);
        let mid = b" blk_size=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(drv.preferred_block_size() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Build a locked 512-byte pattern. byte[i] = 0xA5 XOR i. The
    // first byte is therefore 0xA5 — the banner asserts that
    // specific value to make any byte-order drift obvious.
    let mut pattern = [0u8; VIRTIO_BLK_SECTOR_SIZE];
    let mut i = 0usize;
    while i < VIRTIO_BLK_SECTOR_SIZE {
        pattern[i] = 0xA5 ^ (i as u8);
        i += 1;
    }

    if drv.write_block(bus, 3, &pattern).is_err() {
        panic!("virtio-blk write_block failed");
    }

    let mut readback = [0u8; VIRTIO_BLK_SECTOR_SIZE];
    if drv.read_block(bus, 3, &mut readback).is_err() {
        panic!("virtio-blk read_block failed");
    }

    // Byte-equality check.
    let mut j = 0usize;
    while j < VIRTIO_BLK_SECTOR_SIZE {
        if readback[j] != pattern[j] {
            panic!("virtio-blk readback byte drift");
        }
        j += 1;
    }

    if drv.request_count() != 2 {
        panic!("virtio-blk request_count drift");
    }
    if drv.completion_count() != 2 {
        panic!("virtio-blk completion_count drift");
    }

    // Emit roundtrip banner with the first byte in hex so the log
    // line carries a non-trivial value derived from the actual
    // disk read (not just a counter).
    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_BLK roundtrip OK reqs=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(drv.request_count() as u64, &mut line[pos..]);
        let mid = b" sector=3 first_byte=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let mut hex = [0u8; 2];
        hex_encode(&[readback[0]], 1, &mut hex);
        line[pos..pos + 2].copy_from_slice(&hex);
        pos += 2;
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

/// Kernel SNTPv4 client banner (TASK-053).
///
/// Exercises the locked [`Sntp`] surface: builds a mode-3 client
/// request with `client_now = NTP_EPOCH + 100s`, asserts the wire
/// byte-0 carries (LI=0, VN=4, Mode=3) = 0x23, and asserts the
/// transmit-timestamp tail equals `100 << 32` in big-endian; then
/// parses a hand-built mode-4 reply with locked timestamps that yield
/// `offset_ns = 0`, `delay_ns = 1_000_000_000`, and asserts both
/// values byte-for-byte against the SNTP algorithm in RFC 4330 §5.
/// A morph that perturbs the bit-packing, the field offsets, or the
/// offset/delay arithmetic panics inside `banner_sntp` and the two
/// banners never appear.
///
/// Emits two banners:
/// - `SNTP request OK mode=3 vn=4 xmt=429496729600` — the transmit
///   timestamp raw value (decimal) recovered from the planted u64.
/// - `SNTP reply OK offset_ns=0 delay_ns=1000000000` — the locked
///   skew computed from the symmetric reply timestamps.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_sntp() {
    // ------------------------------------------------------------------
    // build_request — t1 = NTP_EPOCH + 100s -> raw = 100 << 32.
    // ------------------------------------------------------------------
    let t1 = NtpTimestamp::from_secs_frac(100, 0);
    let mut req = [0u8; SNTP_PACKET_LEN];
    let n = match <SntpImpl as Sntp>::build_request(t1, &mut req) {
        Ok(n) => n,
        Err(_) => panic!("sntp: build_request returned Err"),
    };
    if n != SNTP_PACKET_LEN {
        panic!("sntp: build_request length drift");
    }
    // Byte 0: LI=0, VN=4, Mode=3 -> 0x23.
    if req[0] != 0x23 {
        panic!("sntp: byte0 LI/VN/Mode drift");
    }
    // Bytes 1..40 must be zero in a stock client request.
    let mut k = 1usize;
    while k < 40 {
        if req[k] != 0 {
            panic!("sntp: non-zero filler byte");
        }
        k += 1;
    }
    // Bytes 40..48: big-endian of 100 << 32 = 0x0000_0064_0000_0000.
    let expected_xmt = [0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00];
    let mut j = 0usize;
    while j < 8 {
        if req[40 + j] != expected_xmt[j] {
            panic!("sntp: transmit timestamp wire drift");
        }
        j += 1;
    }

    // First banner: xmt raw is t1.raw = 100 << 32 = 429_496_729_600.
    {
        let mut line = [0u8; 96];
        let prefix = b"SNTP request OK mode=3 vn=4 xmt=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(t1.raw, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // ------------------------------------------------------------------
    // parse_reply + compute_offset_delay — symmetric goldens.
    //   t1 = 100s, t2 = 100.5s, t3 = 100.5s, t4 = 101s.
    //   offset = ((t2-t1) + (t3-t4)) / 2 = (500e6 + -500e6)/2 = 0.
    //   delay  = (t4-t1) - (t3-t2)       = 1e9 - 0 = 1_000_000_000.
    // ------------------------------------------------------------------
    let t2 = NtpTimestamp::from_secs_frac(100, 0x8000_0000); // 100.5s
    let t3 = NtpTimestamp::from_secs_frac(100, 0x8000_0000); // 100.5s
    let t4 = NtpTimestamp::from_secs_frac(101, 0);

    // Hand-build a mode-4 reply: byte 0 = LI=0, VN=4, Mode=4 = 0x24.
    let mut reply_buf = [0u8; SNTP_PACKET_LEN];
    reply_buf[0] = (0u8 << 6) | ((SNTP_VERSION & 0x7) << 3) | (SNTP_MODE_SERVER & 0x7);
    reply_buf[1] = 3; // stratum
    reply_buf[2] = 6; // poll
    reply_buf[3] = 0xEC; // precision = -20
    // Reference identifier "GPS\0" — stratum 1 primary-reference style.
    reply_buf[12] = b'G';
    reply_buf[13] = b'P';
    reply_buf[14] = b'S';
    reply_buf[15] = 0;
    // Reference + origin + receive + transmit timestamps (big-endian).
    let plant = |buf: &mut [u8; SNTP_PACKET_LEN], at: usize, v: u64| {
        buf[at] = (v >> 56) as u8;
        buf[at + 1] = (v >> 48) as u8;
        buf[at + 2] = (v >> 40) as u8;
        buf[at + 3] = (v >> 32) as u8;
        buf[at + 4] = (v >> 24) as u8;
        buf[at + 5] = (v >> 16) as u8;
        buf[at + 6] = (v >> 8) as u8;
        buf[at + 7] = v as u8;
    };
    plant(&mut reply_buf, 16, NtpTimestamp::from_secs_frac(99, 0).raw); // ref
    plant(&mut reply_buf, 24, t1.raw); // origin
    plant(&mut reply_buf, 32, t2.raw); // receive
    plant(&mut reply_buf, 40, t3.raw); // transmit

    let reply: NtpReply = match <SntpImpl as Sntp>::parse_reply(&reply_buf) {
        Ok(r) => r,
        Err(_) => panic!("sntp: parse_reply returned Err"),
    };
    if reply.stratum != 3 {
        panic!("sntp: reply stratum drift");
    }
    if reply.version != SNTP_VERSION {
        panic!("sntp: reply version drift");
    }
    if reply.leap_indicator != 0 {
        panic!("sntp: reply LI drift");
    }
    if reply.origin_timestamp != t1 {
        panic!("sntp: reply origin drift");
    }
    if reply.receive_timestamp != t2 {
        panic!("sntp: reply receive drift");
    }
    if reply.transmit_timestamp != t3 {
        panic!("sntp: reply transmit drift");
    }
    if reply.ref_id != [b'G', b'P', b'S', 0] {
        panic!("sntp: reply ref_id drift");
    }

    let skew = <SntpImpl as Sntp>::compute_offset_delay(&reply, t4);
    if skew.offset_ns != 0 {
        panic!("sntp: offset_ns drift");
    }
    if skew.delay_ns != 1_000_000_000 {
        panic!("sntp: delay_ns drift");
    }

    // Second banner — offset_ns is exactly zero, delay_ns is exactly
    // 1_000_000_000. dec_u64 handles the unsigned case; the offset is
    // nonneg here so no sign handling is needed.
    {
        let mut line = [0u8; 96];
        let prefix = b"SNTP reply OK offset_ns=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        let off = skew.offset_ns;
        if off < 0 {
            line[pos] = b'-';
            pos += 1;
            pos += dec_u64((-(off as i128)) as u64, &mut line[pos..]);
        } else {
            pos += dec_u64(off as u64, &mut line[pos..]);
        }
        let mid = b" delay_ns=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(skew.delay_ns as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Silence the import-unused warning in case the morph rewrites the
    // call site to avoid the constant.
    let _ = SNTP_MODE_CLIENT;
}

/// VFS banner — TASK-054.
///
/// Exercises the locked [`Vfs`] + [`Filesystem`] surfaces: instantiates a
/// `MemRamFs` in a static-mut arena, seeds `/etc/hostname` with the
/// locked byte fixture `b"proteus-te\n"`, mounts it at `/`, opens the
/// path through `VfsImpl`, reads the bytes back, and asserts the
/// recovered contents byte-for-byte against the locked expectation.
/// A morph that perturbs the mount-table dispatch, the path
/// normalisation, the handle packing, or the open-file table panics
/// inside `banner_vfs` and the two banners never appear.
///
/// Emits two banners:
/// - `VFS mount OK fs=ramfs root=/`
/// - `VFS read OK path=/etc/hostname bytes=11`
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_vfs() {
    // Locked fixture matching the kernel-banner expectation.
    const HOSTNAME_BYTES: &[u8] = b"proteus-te\n";
    const HOSTNAME_LEN: usize = 11;

    // Storage backing the ramfs lives in a static-mut arena. The
    // VFS holds a `'static mut` borrow for the lifetime of the
    // banner, so a heap allocator is not required.
    static RAMFS: spin::Mutex<VfsRamFsArena> = spin::Mutex::new(VfsRamFsArena::new());
    let fs_ref: &'static mut MemRamFs<8, 4096> = &mut spin::MutexGuard::leak(RAMFS.lock()).fs;

    // Seed `/etc/hostname` with the fixture.
    match fs_ref.seed_file(b"/etc/hostname", HOSTNAME_BYTES, HOSTNAME_LEN, 0) {
        Ok(_) => {}
        Err(_) => panic!("vfs: seed_file returned Err"),
    }

    // Build a fresh dispatcher and mount the ramfs at root.
    let mut vfs: VfsImpl<8> = VfsImpl::new();
    match vfs.mount(b"/", fs_ref as &mut dyn Filesystem) {
        Ok(()) => {}
        Err(_) => panic!("vfs: mount returned Err"),
    }
    if vfs.mount_count() != 1 {
        panic!("vfs: mount_count drift");
    }
    match vfs.mount_at(0) {
        Some(mp) if mp == b"/" => {}
        _ => panic!("vfs: mount_at(0) wire drift"),
    }

    // First banner.
    {
        let prefix = b"VFS mount OK fs=ramfs root=/\n";
        serial_write_bytes(prefix);
    }

    // Open + read + close round-trip.
    let h = match <VfsImpl<8> as Vfs>::open(&mut vfs, b"/etc/hostname", FS_O_RDONLY) {
        Ok(h) => h,
        Err(_) => panic!("vfs: open returned Err"),
    };
    let mut buf = [0u8; 32];
    let n = match <VfsImpl<8> as Vfs>::read(&mut vfs, h, 0, &mut buf) {
        Ok(n) => n,
        Err(_) => panic!("vfs: read returned Err"),
    };
    if n != HOSTNAME_LEN {
        panic!("vfs: read length drift");
    }
    // Byte-for-byte assertion against the locked fixture.
    let mut k = 0usize;
    while k < HOSTNAME_LEN {
        if buf[k] != HOSTNAME_BYTES[k] {
            panic!("vfs: read byte drift");
        }
        k += 1;
    }
    match <VfsImpl<8> as Vfs>::close(&mut vfs, h) {
        Ok(()) => {}
        Err(_) => panic!("vfs: close returned Err"),
    }

    // Second banner — bytes=11 is the locked length.
    {
        let mut line = [0u8; 64];
        let prefix = b"VFS read OK path=/etc/hostname bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Static-mut arena holding the kernel-banner ramfs. Sized at compile
/// time so the BSS slot is fixed; the morph engine can diversify the
/// pool / inode internal layout without changing the binary's symbol
/// table.
pub(crate) struct VfsRamFsArena {
    pub(crate) fs: MemRamFs<8, 4096>,
}

impl VfsRamFsArena {
    pub(crate) const fn new() -> Self {
        VfsRamFsArena {
            fs: MemRamFs::new(),
        }
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

/// Intel e1000 NIC driver banner — TASK-056.
///
/// Runs the locked round-trip:
///
/// 1. Construct a `MemMmioBus` pre-seeded with the locked
///    `BANNER_MAC` in EEPROM words 0/1/2 and STATUS bits encoding
///    `LU + FD + Up @ 1 Gbit`.
/// 2. Drive `E1000Impl::init` through the bring-up sequence (reset
///    → poll(!RST) → EEPROM MAC read → CTRL.SLU → program RX/TX
///    rings → RCTL.EN + TCTL.EN).
/// 3. Transmit a locked 64-byte Ethernet frame (broadcast dest,
///    `BANNER_MAC` source, EtherType=0x0800, deterministic payload).
///    The bus captures the frame from the TX descriptor on TDT
///    advance — byte-for-byte equality is asserted before continuing.
/// 4. Inject the same frame on the RX side and consume it via
///    `E1000Impl::receive`. Bytes recovered must equal the frame
///    bytes.
///
/// On any drift — descriptor byte packing, EEPROM word index order,
/// MAC read endianness, CTRL.RST poll path, link-state decode,
/// ring wrap modulus, RDT/TDT lag arithmetic — one of the asserts
/// inside `run_banner_round_trip` panics and the QEMU log emits a
/// PANIC line instead of the expected two `E1000 ...` banners.
///
/// A morph that perturbs these internals while leaving the
/// `EthernetController` contract methods, the `MmioRegBus` trait,
/// the descriptor STATUS/CMD constants, or the register-offset
/// constants intact will preserve the banner; a morph that perturbs
/// the wire surface will fail the in-order sweep on this banner.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_e1000() {
    // The driver embeds two 16-slot ring arrays of 1518-byte buffers
    // (~48 KiB) plus the `MemMmioBus` (128 KiB shadow + capture log
    // — ~180 KiB total) — well over the kernel-main stack budget.
    // Park BOTH in static storage initialised through `const fn`
    // constructors guarded by spin::Mutex so no large value ever lives on the stack.
    use target_enterprise::e1000::{build_banner_frame, E1000Impl, MemMmioBus};
    use proteus_contracts::{EthernetController, LinkState};

    static DRIVER_STORAGE: spin::Mutex<E1000Impl> = spin::Mutex::new(E1000Impl::new());
    static BUS_STORAGE: spin::Mutex<MemMmioBus> = spin::Mutex::new(MemMmioBus::zeroed());

    let mut driver_guard = DRIVER_STORAGE.lock();
    let driver: &mut E1000Impl = &mut *driver_guard;
    let mut bus_guard = BUS_STORAGE.lock();
    let bus: &mut MemMmioBus = &mut *bus_guard;

    // Seed the EEPROM with the locked banner MAC. STATUS was set by
    // `MemMmioBus::zeroed` to LU + FD + Up @ 1G.
    bus.set_eeprom_mac(BANNER_MAC);

    let mut mac = [0u8; 6];
    if driver.init(bus, &mut mac).is_err() {
        panic!("e1000: init failed");
    }
    if mac != BANNER_MAC {
        panic!("e1000: MAC drift");
    }
    if driver.link_state() != LinkState::Up1000 {
        panic!("e1000: link state drift (expected Up1000)");
    }

    // Transmit a 64-byte fixture frame; the bus drains the TX
    // descriptor on TDT advance and captures the bytes.
    let frame = build_banner_frame();
    if driver.transmit(bus, &frame).is_err() {
        panic!("e1000: transmit failed");
    }
    let caps = bus.tx_captures();
    if caps.len() != 1 || caps[0].len != 64 {
        panic!("e1000: TX capture count or length drift");
    }
    {
        let mut i = 0usize;
        while i < 64 {
            if caps[0].bytes[i] != frame[i] {
                panic!("e1000: TX capture byte drift");
            }
            i += 1;
        }
    }

    // Inject the same frame back on the RX side and round-trip it
    // through `receive`.
    if bus.inject_rx_frame(&frame).is_err() {
        panic!("e1000: RX inject failed");
    }
    let mut rx_buf = [0u8; 64];
    let rx_len = match driver.receive(bus, &mut rx_buf) {
        Ok(Some(n)) => n,
        _ => panic!("e1000: receive failed"),
    };
    if rx_len != 64 {
        panic!("e1000: RX length drift");
    }
    {
        let mut i = 0usize;
        while i < rx_len {
            if rx_buf[i] != frame[i] {
                panic!("e1000: RX byte drift");
            }
            i += 1;
        }
    }

    // Emit banner 1: init OK with the recovered MAC + link speed.
    {
        let mut line = [0u8; 80];
        let prefix = b"E1000 init OK mac=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        let mut hex = [0u8; 12];
        hex_encode(&mac, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        let mid = b" link=up_1000";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Emit banner 2: frame round-trip OK with byte counts.
    {
        let mut line = [0u8; 80];
        let prefix = b"E1000 frame OK tx_bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(64, &mut line[pos..]);
        let mid = b" rx_bytes=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(rx_len as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// TFTP / TASK-058: RFC 1350 client-side wire codec. The kernel
// builds an RRQ for `/proteus-boot.img` in octet mode, asserts
// the byte-exact request; parses a locked ACK(1) reply, recovers
// block=1; parses a locked DATA(2, "0123456789") packet, recovers
// block=2 + 10-byte payload byte-for-byte. Emits:
//   `TFTP rrq OK len=33 mode=octet\n`
//   `TFTP data OK block=2 bytes=10\n`
//
// A morph that perturbs the opcode big-endian encoding, the
// NUL-terminated string discipline, or the block-number byte
// order panics inside `banner_tftp` and these banners never
// appear.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_tftp() {
    use proteus_contracts::{Tftp, TftpMode, TftpPacket};
    use target_enterprise::tftp::TftpImpl;

    // --- build RRQ ---
    let mut rrq_buf = [0u8; 64];
    let rrq_n =
        match TftpImpl::build_rrq(b"/proteus-boot.img", TftpMode::Octet, &mut rrq_buf) {
            Ok(n) => n,
            Err(_) => panic!("TFTP banner: build_rrq failed"),
        };
    // Expected: opcode(0x0001) + "/proteus-boot.img"(17) + NUL +
    // "octet"(5) + NUL = 2 + 17 + 1 + 5 + 1 = 26.
    // Wait, /proteus-boot.img is 17 chars. So 2+17+1+5+1 = 26.
    // The banner text uses dec_u64 so we just need consistency.
    // Locked expected bytes:
    let expected_rrq: &[u8] = &[
        0x00, 0x01, // opcode = RRQ
        b'/', b'p', b'r', b'o', b't', b'e', b'u', b's', b'-', b'b', b'o', b'o', b't', b'.',
        b'i', b'm', b'g', // filename (17 bytes)
        0x00, // NUL
        b'o', b'c', b't', b'e', b't', // mode
        0x00, // NUL
    ];
    if rrq_n != expected_rrq.len() {
        panic!("TFTP banner: RRQ length drift");
    }
    assert_eq_bytes(&rrq_buf[..rrq_n], expected_rrq, "TFTP RRQ");

    // Emit RRQ banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TFTP rrq OK len=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(rrq_n as u64, &mut line[pos..]);
        let mid = b" mode=octet";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- parse locked ACK(1) reply ---
    let ack_bytes: &[u8] = &[0x00, 0x04, 0x00, 0x01];
    match TftpImpl::parse_packet(ack_bytes) {
        Ok(TftpPacket::Ack { block }) => {
            if block != 1 {
                panic!("TFTP banner: ACK block drift");
            }
        }
        Ok(_) => panic!("TFTP banner: ACK parsed as wrong variant"),
        Err(_) => panic!("TFTP banner: ACK parse failed"),
    }

    // --- parse locked DATA(2, "0123456789") packet ---
    let data_bytes: &[u8] = &[
        0x00, 0x03, // opcode = DATA
        0x00, 0x02, // block = 2
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
    ];
    let (rec_block, rec_payload_len) = match TftpImpl::parse_packet(data_bytes) {
        Ok(TftpPacket::Data { block, payload }) => {
            // Byte-equality on the payload.
            if payload.len() != 10 {
                panic!("TFTP banner: DATA payload length drift");
            }
            let expected_payload = b"0123456789";
            let mut i = 0usize;
            while i < payload.len() {
                if payload[i] != expected_payload[i] {
                    panic!("TFTP banner: DATA payload byte drift");
                }
                i += 1;
            }
            (block, payload.len())
        }
        _ => panic!("TFTP banner: DATA parse failed"),
    };
    if rec_block != 2 {
        panic!("TFTP banner: DATA block drift");
    }

    // Emit DATA banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TFTP data OK block=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(rec_block as u64, &mut line[pos..]);
        let mid = b" bytes=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(rec_payload_len as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// SMP / TASK-057: ACPI MADT parsing + INIT-SIPI-SIPI AP wake
// sequence. The kernel constructs a 4-CPU fixture MADT
// (BSP=0, APs=1/2/3, all ENABLED), runs `SmpImpl::discover`
// to recover the topology, asserts the 9-write ICR sequence
// emitted by `wake_aps` against a recording harness matches
// the locked golden (per Intel SDM Vol 3A §10.4.7.1):
// INIT, SIPI, SIPI per AP × 3 APs = 9 IPIs. Emits:
//   `SMP discover OK bsp=0 aps=3\n`
//   `SMP wake OK ipis=9 vec=0x08\n`
//
// This is wire-codec-shaped: no AP actually executes. The
// real-APIC kernel-side ApicWriter + AP-side real-mode
// trampoline + concurrent AP execution are TASK-057b. A
// morph that perturbs the ICR field encodings, the SIPI
// vector arithmetic, or the MADT entry-type walk panics
// inside `banner_smp` and the trailing banners are
// suppressed.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_smp() {
    use proteus_contracts::{smp_consts, ApicWriter, Smp};
    use target_enterprise::smp::{build_madt_fixture, SmpImpl};

    // 1. Build a 4-CPU MADT in a stack buffer + parse it.
    let mut madt_buf = [0u8; 128];
    let madt_len = match build_madt_fixture(4, &mut madt_buf) {
        Ok(n) => n,
        Err(_) => panic!("SMP banner: build_madt_fixture failed"),
    };
    let topo = match SmpImpl::discover(&madt_buf[..madt_len]) {
        Ok(t) => t,
        Err(_) => panic!("SMP banner: discover rejected fixture"),
    };
    if topo.bsp != 0 || topo.ap_count != 3 {
        panic!("SMP banner: topology drift");
    }
    if topo.ap_ids() != &[1u8, 2, 3] {
        panic!("SMP banner: AP order drift");
    }

    // Emit discover banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"SMP discover OK bsp=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(topo.bsp as u64, &mut line[pos..]);
        let mid = b" aps=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(topo.ap_count as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // 2. Wake APs through a recording harness — assert the 9-write
    //    golden + the vector arithmetic.
    struct RecordingApic {
        icr_low: [u32; 16],
        low_count: usize,
        icr_high: [u32; 16],
        high_count: usize,
    }
    impl ApicWriter for RecordingApic {
        fn write_icr_low(&mut self, val: u32) {
            if self.low_count < self.icr_low.len() {
                self.icr_low[self.low_count] = val;
                self.low_count += 1;
            }
        }
        fn write_icr_high(&mut self, val: u32) {
            if self.high_count < self.icr_high.len() {
                self.icr_high[self.high_count] = val;
                self.high_count += 1;
            }
        }
        fn read_icr_low(&mut self) -> u32 {
            0
        }
    }
    let mut apic = RecordingApic {
        icr_low: [0; 16],
        low_count: 0,
        icr_high: [0; 16],
        high_count: 0,
    };
    let mut delay_us_noop = |_us: u32| {};
    let ipi_count = match SmpImpl::wake_aps(
        &topo,
        0x8000,
        &mut apic,
        &mut delay_us_noop,
    ) {
        Ok(n) => n,
        Err(_) => panic!("SMP banner: wake_aps failed"),
    };
    if ipi_count != 9 {
        panic!("SMP banner: ipi count drift");
    }
    if apic.low_count != 9 || apic.high_count != 9 {
        panic!("SMP banner: ICR write count drift");
    }
    // Assert the SIPI vector encoded in the 2nd and 3rd ICR-low
    // writes (the SIPIs for AP 1) is 0x08.
    if apic.icr_low[1] & smp_consts::ICR_VECTOR_MASK != 0x08 {
        panic!("SMP banner: SIPI vector arithmetic drift");
    }
    if apic.icr_low[2] & smp_consts::ICR_VECTOR_MASK != 0x08 {
        panic!("SMP banner: SIPI redundancy vector drift");
    }
    // Assert the INIT IPI delivery-mode bits are set (first ICR-low
    // of each AP triple).
    let init_low = smp_consts::ICR_DELIVERY_INIT
        | smp_consts::ICR_LEVEL_ASSERT
        | smp_consts::ICR_TRIGGER_LEVEL;
    if apic.icr_low[0] != init_low
        || apic.icr_low[3] != init_low
        || apic.icr_low[6] != init_low
    {
        panic!("SMP banner: INIT encoding drift");
    }
    // Assert the target APIC IDs in ICR-high progress 1, 2, 3 (with
    // each one written 3 times for the 3-IPI sequence per AP).
    if apic.icr_high[0] != 1 << 24
        || apic.icr_high[3] != 2 << 24
        || apic.icr_high[6] != 3 << 24
    {
        panic!("SMP banner: ICR-high target drift");
    }

    // Emit wake banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"SMP wake OK ipis=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(ipi_count as u64, &mut line[pos..]);
        let mid = b" vec=0x08";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// PCI / TASK-059: legacy 0xCF8/0xCFC configuration-space wire codec.
// The kernel constructs an in-RAM `RecordingBus` populated with two
// QEMU-canonical devices (Intel 8086:100E e1000 at 00:03.0 + Intel
// 8086:5845 NVMe at 00:05.0). It runs `PciImpl::enumerate` and
// asserts both functions are surfaced with byte-exact
// (vendor, device, class, subclass). It then reads BAR0 on the e1000
// (port-I/O space at 0xC020) and asserts the decoded
// `PciBar::Io(0xC020)`. Emits:
//   `PCI scan OK devices=2 e1000=found nvme=found\n`
//   `PCI bar OK e1000_io=0xc020\n`
//
// Wire-codec-shaped: no real PCI cycle is issued — the recording bus
// scripts every dword. The real kernel-side 0xCF8/0xCFC port writer
// is plugged in at the `PciConfigBus` impl boundary, separately. A
// morph that perturbs the (bus, device, function, offset) encoding,
// the multi-function bit gating, the BAR low-bit decode, or the
// vendor-none sentinel panics inside `banner_pci` and these banners
// never appear.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_pci() {
    use proteus_contracts::{pci_class, Pci, PciAddress, PciBar};
    use target_enterprise::pci::{PciImpl, RecordingBus};

    // 1. Build the in-RAM bus with two QEMU-canonical devices +
    //    the e1000's BAR0 (port-I/O at 0xC020).
    let mut bus = RecordingBus::new();
    let e1000 = PciAddress {
        bus: 0,
        device: 3,
        function: 0,
    };
    let nvme = PciAddress {
        bus: 0,
        device: 5,
        function: 0,
    };
    // e1000: vendor=0x8086, device=0x100E, class=0x02 (Network),
    //        subclass=0x00 (Ethernet), prog_if=0, revision=0x03,
    //        header_type=0 (single-function).
    // Identification dword at 0x00: device_id<<16 | vendor_id.
    bus.set(e1000, 0x00, (0x100Eu32 << 16) | 0x8086);
    // Class dword at 0x08: class<<24 | subclass<<16 | prog_if<<8 | rev.
    bus.set(e1000, 0x08, (0x02u32 << 24) | (0x00 << 16) | (0x00 << 8) | 0x03);
    // Header dword at 0x0C: header_type in byte 2.
    bus.set(e1000, 0x0C, 0x0000_0000);
    // BAR0 at 0x10: port-I/O space at 0xC020 (low bit set).
    bus.set(e1000, 0x10, 0xC021);

    // nvme: vendor=0x8086, device=0x5845, class=0x01 (Mass Storage),
    //       subclass=0x08 (NVMe), prog_if=0x02, revision=0,
    //       header_type=0 (single-function).
    bus.set(nvme, 0x00, (0x5845u32 << 16) | 0x8086);
    bus.set(nvme, 0x08, (0x01u32 << 24) | (0x08 << 16) | (0x02 << 8));
    bus.set(nvme, 0x0C, 0x0000_0000);

    // 2. Enumerate and verify both devices are surfaced byte-exact.
    let mut e1000_found = false;
    let mut nvme_found = false;
    let mut count = 0usize;
    PciImpl::enumerate(&mut bus, &mut |d| {
        count += 1;
        if d.vendor_id == 0x8086
            && d.device_id == 0x100E
            && d.class == pci_class::CLASS_NETWORK
            && d.subclass == pci_class::SUBCLASS_ETHERNET
        {
            e1000_found = true;
        }
        if d.vendor_id == 0x8086
            && d.device_id == 0x5845
            && d.class == pci_class::CLASS_MASS_STORAGE
            && d.subclass == pci_class::SUBCLASS_NVME
        {
            nvme_found = true;
        }
    });
    if count != 2 {
        panic!("PCI banner: enumerate device count drift");
    }
    if !e1000_found {
        panic!("PCI banner: e1000 not surfaced");
    }
    if !nvme_found {
        panic!("PCI banner: NVMe not surfaced");
    }

    // 3. Emit the scan banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"PCI scan OK devices=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(count as u64, &mut line[pos..]);
        let mid = b" e1000=found nvme=found";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // 4. Read e1000 BAR0 and assert decoded value byte-exact.
    let bar = match PciImpl::read_bar(&mut bus, e1000, 0) {
        Ok(b) => b,
        Err(_) => panic!("PCI banner: BAR0 read failed"),
    };
    let io_port = match bar {
        PciBar::Io(p) => p,
        _ => panic!("PCI banner: BAR0 decoded as wrong variant"),
    };
    if io_port != 0xC020 {
        panic!("PCI banner: BAR0 address drift");
    }

    // 5. Emit the BAR banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"PCI bar OK e1000_io=0x";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // Lowercase hex of io_port (u32), MSB-first, no leading zeros.
        let mut nyb = 8i32;
        while nyb > 0 {
            let shift = (nyb - 1) * 4;
            if ((io_port >> shift) & 0xF) != 0 {
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
                let n = ((io_port >> (nn * 4)) & 0xF) as u8;
                line[pos] = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
                pos += 1;
            }
        }
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-062: PIT + CMOS RTC wire codec. The kernel programs the
// PIT for 1 kHz against a recording IoPort and asserts the exact
// three-byte sequence (cmd=0x36, divisor lo/hi for 1193), then
// reads a hardcoded BCD 24-hour RTC fixture (2026-03-15 12:34:56)
// and recovers the locked Unix epoch. A morph that perturbs the
// command byte, the divisor arithmetic, the CMOS index/data
// dance, BCD decode, or Gregorian conversion panics inside
// `banner_timer` and these banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_timer() {
    use proteus_contracts::{
        PicTimer, Rtc, PIT_CH0_PORT, PIT_CMD_CH0_LOHI_MODE3_BIN, PIT_CMD_PORT, RTC_REG_DAY,
        RTC_REG_HOURS, RTC_REG_MINUTES, RTC_REG_MONTH, RTC_REG_SECONDS, RTC_REG_STATUS_A,
        RTC_REG_STATUS_B, RTC_REG_YEAR, RTC_STATUS_B_24H,
    };
    use target_enterprise::timer::{PicTimerImpl, RecordingIoPort, RtcImpl};

    // ---- PIT 1 kHz program sequence ----
    let mut port = RecordingIoPort::new();
    let div = match PicTimerImpl::program_hz(&mut port, 1000) {
        Ok(d) => d,
        Err(_) => panic!("TIMER banner: program_hz failed"),
    };
    // 1_193_182 / 1000 = 1193 = 0x04A9
    if div != 1193 {
        panic!("TIMER banner: divisor drift");
    }
    if port.write_count() != 3 {
        panic!("TIMER banner: write count drift");
    }
    let w0 = match port.write_at(0) {
        Some(w) => w,
        None => panic!("TIMER banner: missing write 0"),
    };
    let w1 = match port.write_at(1) {
        Some(w) => w,
        None => panic!("TIMER banner: missing write 1"),
    };
    let w2 = match port.write_at(2) {
        Some(w) => w,
        None => panic!("TIMER banner: missing write 2"),
    };
    if w0.port != PIT_CMD_PORT || w0.value != PIT_CMD_CH0_LOHI_MODE3_BIN {
        panic!("TIMER banner: PIT cmd byte drift");
    }
    if w1.port != PIT_CH0_PORT || w1.value != 0xA9 {
        panic!("TIMER banner: PIT divisor lo drift");
    }
    if w2.port != PIT_CH0_PORT || w2.value != 0x04 {
        panic!("TIMER banner: PIT divisor hi drift");
    }

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"PIT program OK hz=1000 div=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(div as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // ---- RTC fixture read ----
    let mut rtc_port = RecordingIoPort::new();
    rtc_port.set_cmos(RTC_REG_STATUS_A, 0x00);
    rtc_port.set_cmos(RTC_REG_STATUS_B, RTC_STATUS_B_24H);
    rtc_port.set_cmos(RTC_REG_SECONDS, 0x56);
    rtc_port.set_cmos(RTC_REG_MINUTES, 0x34);
    rtc_port.set_cmos(RTC_REG_HOURS, 0x12);
    rtc_port.set_cmos(RTC_REG_DAY, 0x15);
    rtc_port.set_cmos(RTC_REG_MONTH, 0x03);
    rtc_port.set_cmos(RTC_REG_YEAR, 0x26);

    let t = match RtcImpl::read_time(&mut rtc_port) {
        Ok(v) => v,
        Err(_) => panic!("TIMER banner: RTC read failed"),
    };
    if t.year != 2026 || t.month != 3 || t.day != 15 {
        panic!("TIMER banner: RTC date drift");
    }
    if t.hour != 12 || t.minute != 34 || t.second != 56 {
        panic!("TIMER banner: RTC time drift");
    }
    // 2026-03-15 12:34:56 UTC
    if t.unix != 1_773_578_096 {
        panic!("TIMER banner: RTC unix drift");
    }

    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"RTC read OK unix=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(t.unix, &mut line[pos..]);
        let mid = b" date=2026-03-15";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-085 GPT
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_gpt() {
    use proteus_contracts::Gpt;
    use target_enterprise::gpt::{build_banner_fixture, GPT_FIXTURE_BYTES, GptImpl};

    let mut img = [0u8; GPT_FIXTURE_BYTES];
    build_banner_fixture(&mut img).unwrap();
    let h = GptImpl::parse_header(&img).unwrap();
    if h.num_parts != 1 {
        panic!("GPT banner: parts");
    }
    serial_write_bytes(b"GPT parse OK parts=1\n");
}

// TASK-086 DNS name
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_dns_name() {
    use proteus_contracts::{DnsName, DNS_MAX_LABELS};
    use target_enterprise::dns_name::DnsNameImpl;

    let mut wire = [0u8; 32];
    let n = DnsNameImpl::encode(&[b"a", b"b"], &mut wire).unwrap();
    let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
    let mut lens = [0usize; DNS_MAX_LABELS];
    let (c, _) = DnsNameImpl::decode(&wire[..n], 0, &mut labs, &mut lens).unwrap();
    if c != 2 {
        panic!("DNS name banner: labels");
    }
    serial_write_bytes(b"DNS name OK labels=2\n");
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

// TASK-088 AHCI Register H2D FIS
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_ahci_fis() {
    use proteus_contracts::{AhciFis, ATA_CMD_IDENTIFY, AHCI_FIS_H2D_LEN};
    use target_enterprise::ahci_fis::AhciFisImpl;

    let p = match AhciFisImpl::identify(0) {
        Ok(p) => p,
        Err(_) => panic!("AHCI banner: identify params"),
    };
    let mut fis = [0u8; AHCI_FIS_H2D_LEN];
    if AhciFisImpl::encode_h2d(&p, &mut fis).is_err() {
        panic!("AHCI banner: encode");
    }
    let d = match AhciFisImpl::decode_h2d(&fis) {
        Ok(d) => d,
        Err(_) => panic!("AHCI banner: decode"),
    };
    if d.command != ATA_CMD_IDENTIFY || fis[2] != ATA_CMD_IDENTIFY {
        panic!("AHCI banner: cmd drift");
    }
    serial_write_bytes(b"AHCI fis OK cmd=identify\n");
}

// TASK-089 xHCI No-Op TRB
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_xhci_trb() {
    use proteus_contracts::{XhciTrb, XHCI_TRB_TYPE_NOOP};
    use target_enterprise::xhci_trb::XhciTrbImpl;

    let w = XhciTrbImpl::encode_noop(true);
    if XhciTrbImpl::trb_type(w.d3) != XHCI_TRB_TYPE_NOOP {
        panic!("XHCI banner: type drift");
    }
    serial_write_bytes(b"XHCI trb OK type=noop\n");
}

// TASK-090 UEFI GOP mode
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_uefi_gop() {
    use proteus_contracts::UefiGop;
    use target_enterprise::uefi_gop::UefiGopImpl;

    let m = UefiGopImpl::mode_1280x720();
    let mut b = [0u8; 40];
    if UefiGopImpl::encode(&m, &mut b).is_err() {
        panic!("GOP banner: encode");
    }
    let d = match UefiGopImpl::decode(&b) {
        Ok(d) => d,
        Err(_) => panic!("GOP banner: decode"),
    };
    if d.horizontal != 1280 || d.vertical != 720 {
        panic!("GOP banner: res drift");
    }
    serial_write_bytes(b"GOP mode OK 1280x720\n");
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

// TASK-093 AHCI command header + PRDT
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_ahci_cmd() {
    use proteus_contracts::AhciCmd;
    use target_enterprise::ahci_cmd::AhciCmdImpl;

    let (h, p) = match AhciCmdImpl::identify_slot(0x1000, 0x2000) {
        Ok(v) => v,
        Err(_) => panic!("AHCI cmd banner: slot"),
    };
    if h.prdtl != 1 || p.byte_count != 512 {
        panic!("AHCI cmd banner: fields");
    }
    let mut hb = [0u8; 32];
    let mut pb = [0u8; 16];
    if AhciCmdImpl::encode_header(&h, &mut hb).is_err()
        || AhciCmdImpl::encode_prdt(&p, &mut pb).is_err()
    {
        panic!("AHCI cmd banner: encode");
    }
    serial_write_bytes(b"AHCI cmd OK prdtl=1\n");
}

