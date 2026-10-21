//! X.509 DER (RFC 5280), DRBG, KAT, SigKAT, Random, AttestTlv, Base64, and CRC32-C contracts.
//!
//! TLS 1.3 itself is not a contract here: HTTPS uses rustls (see
//! `target_enterprise::https`), whose wire behaviour is pinned by the
//! golden-transcript replay instead.

// ============================================================
// X.509 DER certificate parser (TASK-060)
//
// A *pure parser*: every field is a `&[u8]` view into the input
// DER buffer. No allocator, no signature verification, no chain
// walking — the caller is responsible for handing the parsed
// pieces to a verifier built atop the existing `SignatureVerify`
// surface.
//
// Locked invariants:
//
// 1. `X509::parse(der)` walks the RFC 5280 §4.1 outer SEQUENCE
//    exactly once, performs strict DER bounds checks (no
//    indefinite-length, no non-minimal length encoding, no
//    high-tag-number form), and rejects any blob longer than
//    [`X509_MAX_CERT_LEN`].
// 2. The recovered `X509Cert<'a>` borrows the TBSCertificate
//    sub-slice byte-exact — the slice MUST equal the byte range
//    the outer signatureAlgorithm/signatureValue covers, so a
//    caller can hash it for signature verification without
//    re-encoding.
// 3. Only three SPKI algorithm OIDs are accepted — rsaEncryption,
//    id-ecPublicKey (P-256), and id-Ed25519. Any other OID is
//    surfaced as [`X509Error::UnsupportedKeyAlg`] — refusing
//    unknown algorithms is how X.509 parsers stop being a CVE
//    factory (RFC 5280 §1 "any other" caveat).
// 4. Only three signatureAlgorithm OIDs are accepted —
//    sha256WithRSAEncryption, ecdsa-with-SHA256, and id-Ed25519.
// 5. The outer signatureAlgorithm field MUST equal the
//    TBSCertificate's `signature` field byte-for-byte (RFC 5280
//    §4.1.1.2). Drift surfaces as [`X509Error::SigAlgMismatch`].
// 6. Validity is decoded into Unix epoch seconds; UTCTime years
//    < 50 map to 20YY and ≥ 50 map to 19YY per RFC 5280 §4.1.2.5.1.
//    GeneralizedTime is also accepted for `notAfter` fields that
//    fall past 2049.
// ============================================================

/// ASN.1 / DER tag bytes the [`X509`] parser recognises. The set is
/// deliberately narrow — high-tag-number and indefinite-length forms
/// are rejected outright. (See RFC 5280 §4.1 for the cert structure
/// and X.690 §8.1 for the encoding rules.)
pub const X509_TAG_INTEGER: u8 = 0x02;
/// BIT STRING tag (0x03). The parser only accepts BIT STRINGs whose
/// first byte (the "unused bits" count) is zero — non-zero unused
/// bits would surface as a `MalformedBitString` error.
pub const X509_TAG_BIT_STRING: u8 = 0x03;
/// OCTET STRING tag (0x04). Used inside extensions; treated as opaque.
pub const X509_TAG_OCTET_STRING: u8 = 0x04;
/// NULL tag (0x05). Encodes the rsaEncryption SPKI parameters.
pub const X509_TAG_NULL: u8 = 0x05;
/// OBJECT IDENTIFIER tag (0x06).
pub const X509_TAG_OID: u8 = 0x06;
/// UTF8String tag (0x0C). Used inside RDN components.
pub const X509_TAG_UTF8_STRING: u8 = 0x0C;
/// PrintableString tag (0x13). Used inside RDN components.
pub const X509_TAG_PRINTABLE_STRING: u8 = 0x13;
/// IA5String tag (0x16). Used inside Subject Alternative Name extensions.
pub const X509_TAG_IA5_STRING: u8 = 0x16;
/// UTCTime tag (0x17). RFC 5280 form `YYMMDDhhmmssZ`.
pub const X509_TAG_UTC_TIME: u8 = 0x17;
/// GeneralizedTime tag (0x18). RFC 5280 form `YYYYMMDDhhmmssZ`.
pub const X509_TAG_GENERALIZED_TIME: u8 = 0x18;
/// SEQUENCE tag (0x30). Constructed.
pub const X509_TAG_SEQUENCE: u8 = 0x30;
/// SET tag (0x31). Constructed.
pub const X509_TAG_SET: u8 = 0x31;
/// Context-specific [0] EXPLICIT tag (0xA0). Wraps the TBS version field.
pub const X509_TAG_CTX_EXPLICIT_0: u8 = 0xA0;
/// Context-specific [3] EXPLICIT tag (0xA3). Wraps the TBS extensions
/// list.
pub const X509_TAG_CTX_EXPLICIT_3: u8 = 0xA3;

/// Hard cap on the total encoded length of a DER certificate the
/// parser will look at. 64 KiB is two orders of magnitude above any
/// real-world cert; anything larger is rejected before the first
/// tag is read. Bounded by definition, no allocator involved.
pub const X509_MAX_CERT_LEN: usize = 64 * 1024;

/// Hard cap on nested SEQUENCE/SET recursion. Walking a hostile blob
/// with arbitrary nesting depth is a stack-blow DoS; 16 is generous
/// for any real-world cert (real ones use ~5).
pub const X509_MAX_DEPTH: usize = 16;

/// OID encoding of `id-rsaEncryption` (1.2.840.113549.1.1.1).
pub const X509_OID_RSA_ENCRYPTION: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];
/// OID encoding of `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
pub const X509_OID_SHA256_WITH_RSA: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
];
/// OID encoding of `id-ecPublicKey` (1.2.840.10045.2.1).
pub const X509_OID_EC_PUBLIC_KEY: &[u8] = &[
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
];
/// OID encoding of `secp256r1` / `prime256v1` (1.2.840.10045.3.1.7).
pub const X509_OID_SECP256R1: &[u8] = &[
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
];
/// OID encoding of `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
pub const X509_OID_ECDSA_WITH_SHA256: &[u8] = &[
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
];
/// OID encoding of `id-Ed25519` (1.3.101.112) — RFC 8410.
pub const X509_OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
/// OID encoding of the X.500 commonName attribute (2.5.4.3). Used by
/// callers that want to extract the leaf CN from the parsed subject
/// DN without re-walking the SET-of-RDN structure.
pub const X509_OID_CN: &[u8] = &[0x55, 0x04, 0x03];

/// Required length of an Ed25519 public key (RFC 8410 §4 — the only
/// length the parser accepts).
pub const X509_ED25519_KEY_LEN: usize = 32;
/// Required length of a SEC1 uncompressed P-256 point: 0x04 || X || Y.
pub const X509_P256_POINT_LEN: usize = 65;

/// Algorithm identifier of a parsed public key. The locked variant
/// set is the three algorithms the kernel + TLS stack itself can
/// consume; any other SPKI algorithm is rejected at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509PubKeyAlg {
    /// RSA with PKCS#1 v1.5 encoding (the only RSA form X.509 uses).
    Rsa,
    /// ECDSA over the NIST P-256 curve (a.k.a. secp256r1 / prime256v1).
    EcdsaP256,
    /// Ed25519 per RFC 8410.
    Ed25519,
}

/// Algorithm identifier of the certificate's outer signature. Locked
/// variant set; see also [`X509PubKeyAlg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509SigAlg {
    /// RSASSA-PKCS1-v1_5 with SHA-256 — `sha256WithRSAEncryption`.
    RsaSha256,
    /// ECDSA-with-SHA-256 over P-256 — `ecdsa-with-SHA256`.
    EcdsaSha256,
    /// Pure Ed25519 — `id-Ed25519`.
    Ed25519,
}

/// View into a parsed public key. Every byte slice borrows from the
/// caller's input DER buffer — the parser allocates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509PubKey<'a> {
    /// RSA public key (RFC 3279 §2.3.1): the BIT STRING contents are
    /// an embedded SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
    /// `modulus` and `exponent` are the raw big-endian INTEGER bytes
    /// (any DER sign-bit guard 0x00 stripped).
    Rsa {
        /// Big-endian RSA modulus `n`. Leading 0x00 sign-bit byte
        /// stripped if present.
        modulus: &'a [u8],
        /// Big-endian RSA public exponent `e`. Almost always
        /// `&[0x01, 0x00, 0x01]` (65537).
        exponent: &'a [u8],
    },
    /// ECDSA P-256 public key encoded as SEC1 uncompressed point —
    /// `0x04 || X(32) || Y(32)`, exactly [`X509_P256_POINT_LEN`] bytes.
    EcdsaP256 {
        /// Uncompressed SEC1 point bytes. Always 65 bytes long.
        point: &'a [u8],
    },
    /// Ed25519 public key — exactly [`X509_ED25519_KEY_LEN`] bytes.
    Ed25519 {
        /// Raw 32-byte Edwards-curve compressed point.
        key: &'a [u8],
    },
}

/// Decoded calendar time, expressed as Unix epoch seconds. The parser
/// validates the month-day combination, leap-year handling, and the
/// 1970..=9999 range — values outside that range surface as a
/// [`X509Error::TimeOutOfRange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X509Time {
    /// Seconds since the Unix epoch (1970-01-01T00:00:00Z).
    pub unix: u64,
}

/// View of one parsed X.509 v3 certificate. Every slice borrows from
/// the caller's DER buffer; the structure carries no owned data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X509Cert<'a> {
    /// Decoded `version` field — always 2 (v3) after a successful parse.
    pub version: u8,
    /// Raw big-endian serial-number bytes (DER INTEGER value, minus
    /// any leading sign-bit guard 0x00).
    pub serial: &'a [u8],
    /// Issuer Name as the full DER `SEQUENCE OF RDN` blob — header
    /// byte and length included so the caller can compare against a
    /// parent cert's `subject` for chain-walking via byte equality
    /// (RFC 5280 §4.1.2.4 mandates a byte-exact match).
    pub issuer: &'a [u8],
    /// Subject Name as the full DER `SEQUENCE OF RDN` blob (same shape
    /// as `issuer`).
    pub subject: &'a [u8],
    /// Validity start.
    pub not_before: X509Time,
    /// Validity end.
    pub not_after: X509Time,
    /// Algorithm of the SubjectPublicKey.
    pub pubkey_alg: X509PubKeyAlg,
    /// Parsed SubjectPublicKey contents (algorithm-tagged view).
    pub pubkey: X509PubKey<'a>,
    /// Algorithm of the outer signatureValue.
    pub sig_alg: X509SigAlg,
    /// Raw signature bytes. For RSA: the PKCS#1 v1.5 encoded
    /// signature. For ECDSA: the DER-encoded `SEQUENCE { r, s }`
    /// pair as the BIT STRING contents specify (RFC 3279 §2.2.3).
    /// For Ed25519: 64 raw bytes.
    pub signature: &'a [u8],
    /// Byte-exact TBSCertificate sub-slice, *including* the
    /// outermost SEQUENCE header — what the signature algorithm
    /// covers. A caller computing `sha256(tbs)` and verifying
    /// against the parent's public key uses this slice directly,
    /// no re-encoding.
    pub tbs: &'a [u8],
}

/// Errors returned by [`X509::parse`]. Locked variant set; ordered
/// roughly by where they surface during the top-down walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509Error {
    /// Buffer empty or otherwise zero-length.
    Empty,
    /// Certificate length exceeds [`X509_MAX_CERT_LEN`].
    TooLarge,
    /// A TLV header runs off the end of the slice.
    TruncatedHeader,
    /// A TLV's claimed length runs off the end of the slice.
    TruncatedBody,
    /// X.690 indefinite-length form (illegal in DER).
    IndefiniteLength,
    /// Length field uses more octets than allowed (> 4).
    LengthTooLarge,
    /// Non-minimal length encoding (e.g. 0x81 0x05 instead of 0x05).
    NonMinimalLength,
    /// Tag was not in the recognised set, or did not match what the
    /// surrounding decode-context required.
    BadTag,
    /// High-tag-number form (low 5 bits of tag all set) — refused by
    /// policy.
    HighTagNumber,
    /// INTEGER body violates DER canonical form (leading 0x00 with
    /// next byte's high bit clear, or value too long for context).
    MalformedInteger,
    /// BIT STRING `unused bits` count was non-zero — refused.
    MalformedBitString,
    /// Trailing data found inside a SEQUENCE that was expected to be
    /// fully consumed (e.g. extra TLVs after `extensions`).
    TrailingData,
    /// Certificate `version` field is not v3 (encoded value 2).
    UnsupportedVersion,
    /// SPKI algorithm OID is not one of the three accepted.
    UnsupportedKeyAlg,
    /// SubjectPublicKey was structurally invalid for its algorithm
    /// (wrong length, missing/extra parameters, wrong inner tag).
    MalformedPubKey,
    /// `signatureAlgorithm` OID is not one of the three accepted.
    UnsupportedSigAlg,
    /// Outer `signatureAlgorithm` doesn't equal the TBS's `signature`
    /// AlgorithmIdentifier field (RFC 5280 §4.1.1.2 mismatch).
    SigAlgMismatch,
    /// AlgorithmIdentifier parameters were present where forbidden
    /// (or absent where required).
    BadAlgParams,
    /// UTCTime/GeneralizedTime field had the wrong length, missing
    /// trailing `Z`, non-digit bytes, or invalid calendar value.
    MalformedTime,
    /// Decoded time falls outside the 1970..=9999 window.
    TimeOutOfRange,
    /// `notAfter < notBefore` — the cert was never valid.
    ValidityWindowInverted,
    /// Nested SEQUENCE/SET depth exceeded [`X509_MAX_DEPTH`].
    DepthExceeded,
    /// `subject_der.is_empty()` (impossible in a valid v3 cert).
    EmptyName,
    /// Issuer DN of `child` did not equal subject DN of `parent`
    /// during a [`X509::issuer_matches_subject`] chain step.
    IssuerSubjectMismatch,
}

/// X.509 v3 DER certificate parser. Pure-parser: no signature
/// verification, no chain walking — see the trait-level documentation
/// for the locked invariants.
pub trait X509 {
    /// Parse one DER X.509 v3 certificate. The returned view borrows
    /// from `der` for its entire lifetime; the caller may not
    /// invalidate `der` while the view is live (Rust's lifetime
    /// system already enforces this — documented here for clarity).
    fn parse(der: &[u8]) -> Result<X509Cert<'_>, X509Error>;

    /// Check that `now.unix` falls inside `cert.not_before .. cert.not_after`
    /// inclusive of both endpoints. Returns `false` for any cert whose
    /// window is in the past or in the future.
    fn validity_contains(cert: &X509Cert<'_>, now: X509Time) -> bool;

    /// RFC 5280 §4.1.2.4 byte-exact DN check: the child's `issuer`
    /// DER blob must equal the parent's `subject` DER blob. Returns
    /// `Ok(())` on match; `Err(X509Error::IssuerSubjectMismatch)`
    /// otherwise. This is the *naming* half of a chain step — the
    /// caller still has to verify the signature.
    fn issuer_matches_subject(
        child: &X509Cert<'_>,
        parent: &X509Cert<'_>,
    ) -> Result<(), X509Error>;

    /// Locate the leaf `commonName` attribute value inside a DN blob.
    /// Returns the inner string bytes (without the tag/length header)
    /// of the FIRST `2.5.4.3` AttributeTypeAndValue encountered while
    /// walking the SEQUENCE of RDNs left-to-right. Returns `None` if
    /// the DN contains no CN component. Allocation-free.
    fn find_cn<'a>(dn: &'a [u8]) -> Option<&'a [u8]>;
}

/// Schema version of this contracts crate. Any breaking change to a trait
/// signature or to a `const` value in this crate MUST increment this and
/// trigger a coordinated fleet-wide upgrade — not a routine morph cycle.
///
/// Bumped to **2** by TASK-020: `SyscallCapTable::check` now returns
/// `Result<CapProof, CapError>` instead of `Result<(), CapError>`, and
/// the new required method [`SyscallCapTable::check_raw`] replaces the
/// old required `check` body. Every implementor crate (`target_minimal`,
/// `target_enterprise`) is updated in the same iteration that lands
/// this bump.
///
/// Bumped to **3** by TASK-011: introduces the [`NetStack`] trait and
/// the [`NetError`], [`Ipv4HeaderView`], [`UdpDatagramView`] types as
/// the locked wire surface for in-kernel UDP/IPv4. Pure addition — no
/// existing trait signature or const changes — but trait-set additions
/// are part of the schema because the morph engine enumerates the
/// trait list per cycle.
///
/// Bumped to **4** by TASK-017: introduces the [`Kpti`] trait and the
/// [`KptiViolation`] enum as the locked invariant boundary for per-task
/// page-table isolation. Pure addition — trait-set addition, same
/// rationale as the TASK-011 bump.
///
/// Bumped to **5** by the TCP port: introduces the [`Tcp`] trait,
/// [`TcpSegmentView`], [`TcpError`], and the [`tcp_flags`] module as
/// the locked wire surface for transmission control protocol header
/// emission + parsing. Pure addition — same trait-set-addition
/// rationale.
///
/// Bumped to **6** by the HTTP/1.1 port: introduces the [`Http`]
/// trait, [`HttpRequestView`], [`HttpError`], [`HttpMethod`], and
/// the [`http_status`] module as the locked wire surface for
/// application-protocol parsing + response emission. Pure addition.
///
/// Bumped to **7** by the DNS port: introduces the [`Dns`] trait,
/// [`DnsMessageView`], [`DnsHeader`], [`DnsError`], [`DnsRecordType`],
/// and the [`dns_flags`] + [`dns_class`] modules as the locked wire
/// surface for RFC 1035 query / response parsing + emission. Pure
/// addition — same trait-set-addition rationale.
///
/// Bumped to **8** by the ICMP port: introduces the [`Icmp`] trait,
/// [`IcmpEchoView`], [`IcmpError`], and the [`icmp_type`] module as
/// the locked wire surface for RFC 792 echo request / reply with
/// RFC 1071 checksum verification. Pure addition.
///
/// Bumped to **9** by the Ethernet/802.3 port: introduces the [`Eth`]
/// trait, [`EthFrameView`], [`EthError`], [`MacAddr`], and the
/// [`ether_type`] module as the locked wire surface for Ethernet II
/// frame emission + parsing including single 802.1Q VLAN tag
/// handling. Pure addition.
///
/// Bumped to **10** by TASK-019: introduces the [`CrashDump`] and
/// [`SymbolResolve`] traits along with [`CrashContext`],
/// [`CrashDumpHeader`], [`CrashDumpError`], [`CrashRegisters`], and
/// the [`crash_offsets`] module as the locked on-disk surface for
/// post-mortem panic dumps + kernel symbol resolution. Pure addition
/// — same trait-set-addition rationale as the prior bumps.
///
/// Bumped to **11** by TASK-046: introduces the [`Arp`] trait,
/// [`ArpPacketView`], [`ArpError`], the [`arp_op`] module, and the
/// `ARP_*` length constants as the locked wire surface for RFC 826
/// IPv4-over-Ethernet address resolution. Pure addition — same
/// trait-set-addition rationale.
///
/// Bumped to **12** by TASK-047: introduces the [`Dhcp`] trait,
/// [`DhcpMessageView`], [`DhcpError`], [`DhcpClientState`], the
/// [`dhcp_msg_type`] + [`dhcp_option`] modules, and the
/// `DHCP_*` constants (op codes, htype/hlen, magic cookie, fixed
/// header length, broadcast flag) as the locked wire surface for
/// RFC 2131 + RFC 2132 IPv4 DHCP boot-time IP acquisition. Pure
/// addition — same trait-set-addition rationale.
///
/// Bumped to **13** by TASK-048: introduces the [`NetDevice`] trait,
/// [`MmioBus`] trait, [`NetDeviceError`], [`VirtqDesc`],
/// [`VirtioNetHdr`], the [`virtio_net_feature`] + [`virtio_status`]
/// modules, and the `VIRTIO_*` constants as the locked surface for
/// a VirtIO 1.0 network-device driver. Pure addition — same
/// trait-set-addition rationale.
///
/// Bumped to **14** by TASK-049: introduces the `Tls13Client` trait
/// alongside the existing `Tls13Server`, plus the locked
/// `ParsedServerHello` + `HandshakeKeys` structs that carry the
/// trait's parse/derive outputs. Closes the symmetric gap left by the
/// server-only port from TASK-007 — the kernel can now build a
/// ClientHello, parse a ServerHello, run the RFC 8446 §7.1 key
/// schedule through the handshake-traffic secrets, and compute the
/// client Finished `verify_data`. Pure addition — same trait-set-
/// addition rationale; no existing surface byte changed.
///
/// Bumped to **15** by TASK-050: introduces the [`PacketFilter`] trait
/// and the locked surface around it — [`FilterRule`] (5-tuple +
/// action), [`Ipv4PacketView`] (5-tuple packet projection),
/// [`FilterAction`], [`Verdict`], [`FilterRuleError`], plus the
/// `IP_PROTO_TCP` / `IP_PROTO_ICMP` / `FW_PROTO_ANY` / `FW_PORT_ANY`
/// constants. Closes the security-policy gap left by the raw
/// [`NetStack`] (which currently accepts every parsed packet) by
/// giving the kernel a stateless first-match-wins filter that
/// composes with the existing IPv4 / TCP / UDP / ICMP wire codecs.
/// Pure addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **16** by TASK-051: introduces the [`Tpm`] trait — a
/// TPM 2.0 client-side wire codec covering `TPM2_Startup`,
/// `TPM2_GetRandom`, `TPM2_PCR_Read`, `TPM2_PCR_Extend`, and a
/// response-header parser — alongside [`TpmResponseView`],
/// [`TpmError`], and the TCG-assigned wire constants
/// (`TPM_HEADER_LEN`, `TPM_ST_NO_SESSIONS`, `TPM_ST_SESSIONS`,
/// `TPM_CC_STARTUP` / `_GET_RANDOM` / `_PCR_READ` / `_PCR_EXTEND`,
/// `TPM_SU_CLEAR` / `_STATE`, `TPM_ALG_SHA256` / `_SHA1`,
/// `TPM_RS_PW`, `TPM_RC_SUCCESS`, `TPM_SHA256_DIGEST_LEN` /
/// `_SHA1_DIGEST_LEN`, `TPM_MAX_PCR_INDEX`). Sets up the in-kernel
/// surface needed for measured boot + remote attestation; the wire
/// codec is transport-agnostic so a future CRB/TIS driver can plug
/// into the locked frame builders without re-implementing them.
/// Pure addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **17** by TASK-052: introduces the [`AuditLog`] trait —
/// a fixed-capacity in-kernel security-event ring with monotonic
/// `event_id`, append-order iteration, and a byte-exact `snapshot`
/// emission for offline log parsing — alongside [`AuditEvent`],
/// [`AuditVerdict`], [`AuditIter`], [`AuditError`], and the locked
/// wire constants (`AUDIT_MESSAGE_LEN`, `AUDIT_EVENT_WIRE_LEN`,
/// `AUDIT_SNAPSHOT_HEADER_LEN`, `AUDIT_SNAPSHOT_MAGIC`). Closes the
/// observability gap left by the existing cap-table / IOMMU / packet-
/// filter denial paths (which today refuse silently): every denial
/// becomes an [`AuditEvent`] the offline parser can correlate to a
/// task_id + syscall_nr. Pure addition — same trait-set-addition
/// rationale; no existing surface byte changed.
///
/// Bumped to **18** by TASK-053: introduces the [`Sntp`] trait — a
/// stateless RFC 4330 SNTPv4 client wire codec covering
/// `build_request`, `parse_reply`, and the `compute_offset_delay`
/// formula — alongside [`NtpTimestamp`], [`NtpReply`], [`NtpClockSkew`],
/// [`SntpError`], and the TCG-style locked wire constants
/// (`SNTP_PACKET_LEN`, `SNTP_VERSION`, `SNTP_MODE_CLIENT`,
/// `SNTP_MODE_SERVER`, `SNTP_LEAP_ALARM`, `SNTP_MAX_STRATUM`, plus
/// the four `SNTP_OFFSET_*` byte offsets and `SNTP_OFFSET_REF_ID`).
/// Closes the wall-clock-synchronisation gap left by the kernel
/// having no UDP-port-123 codec; composes with the existing
/// [`NetStack`] UDP path. Pure addition — same trait-set-addition
/// rationale; no existing surface byte changed.
///
/// Bumped to **19** by TASK-054: introduces the [`Filesystem`] +
/// [`Vfs`] traits along with [`FsHandle`], [`FsError`], [`FileStat`],
/// and the `FS_*` constant family (`FS_NAME_MAX`, `FS_PATH_MAX`,
/// `FS_MAX_MOUNTS`, `FS_O_RDONLY` / `_WRONLY` / `_RDWR` /
/// `_ACCMODE` / `_CREATE` / `_TRUNC` / `_EXCL`, `FS_MODE_FILE` /
/// `_DIR` / `_TYPE_MASK` / `_PERM_MASK`). Closes the no-filesystem
/// gap left by every prior iteration — the kernel had no in-memory
/// inode dispatch before this. The `Filesystem` trait is the
/// per-mount backing-fs surface; `Vfs` is the dispatcher that holds
/// a fixed-capacity mount table and routes by longest-prefix.
/// Pure addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **20** by TASK-055: introduces the [`EBpf`] trait —
/// a bounded 64-bit register-machine interpreter for upstream-
/// compatible eBPF bytecode (Linux `uapi/linux/bpf.h` subset) —
/// alongside [`BpfInstr`], [`BpfContext`], [`BpfError`], the
/// [`bpf_op`] constant module, and the `BPF_REG_COUNT` /
/// `BPF_STACK_SIZE` / `BPF_MAX_INSTRUCTIONS` /
/// `BPF_MAX_BRANCH_DEPTH` / `BPF_REG_FP` constants. Closes the
/// operator-probe gap left by the kernel having no programmable
/// observability surface: an operator can drop in a hand-built or
/// `clang -target bpf`-compiled program at a hookpoint, the
/// validator admits it, and the interpreter runs it with hard
/// instruction + memory caps. Pure addition — same trait-set-
/// addition rationale; no existing surface byte changed.
///
/// Bumped to **21** by TASK-056: introduces the
/// [`EthernetController`] + [`MmioRegBus`] traits, [`LinkState`],
/// [`E1000Error`], the Intel 82540EM (e1000) register-offset constant
/// family (`E1000_REG_CTRL` / `_STATUS` / `_EERD` / `_ICR` / `_IMS`
/// / `_IMC` / `_RCTL` / `_TCTL` / `_TIPG` / `_RDBAL` / `_RDBAH` /
/// `_RDLEN` / `_RDH` / `_RDT` / `_TDBAL` / `_TDBAH` / `_TDLEN` /
/// `_TDH` / `_TDT`), the CTRL/STATUS/EERD/RCTL/TCTL bit-flag
/// constants, the EEPROM word indices for the burned-in MAC
/// (`E1000_EEPROM_MAC_WORD0` / `_WORD1` / `_WORD2`), the legacy
/// descriptor STATUS / CMD bit family (`E1000_DESC_STA_DD`,
/// `_TXD_CMD_EOP` / `_IFCS` / `_RS`, `_RXD_STA_EOP`), and the
/// sizing constants (`E1000_TX_DESC_LEN` / `_RX_DESC_LEN` /
/// `_TX_RING_LEN` / `_RX_RING_LEN` / `_MAX_FRAME_LEN`). Closes
/// the no-real-NIC-driver gap left by the virtio-net surface — a
/// physical NIC driver was missing the contract treatment.
/// Pure addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **22** by TASK-057: introduces the [`Smp`] trait + the
/// [`ApicWriter`] trait + [`CpuTopology`], [`SmpError`], [`ApicId`],
/// [`PerCpu`] storage, the `smp_consts` module (ICR_*, SMP_*
/// constants), the `madt` module (SIG_APIC + entry type codes +
/// flag bits + header length), and the `MAX_CPUS = 64` constant.
/// Wire-codec-shaped infrastructure for multi-core bring-up: the
/// `discover(madt)` MADT parser + the `wake_aps(topology, ...)`
/// INIT-SIPI-SIPI ICR sequencer are testable through a recording
/// `ApicWriter` harness without actually running on AP cores. The
/// AP-side trampoline blob + real APIC MMIO wiring + actual
/// concurrent execution are explicit future surfaces. Pure
/// addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **23** by TASK-058: introduces the [`Tftp`] trait + the
/// locked surface around it — [`TftpMode`], [`TftpPacket`] view enum
/// (Data / Ack / Error / OAck), [`TftpError`], [`TftpErrorCode`],
/// the `tftp_op` module (RRQ / WRQ / DATA / ACK / ERROR / OACK
/// opcodes), and the `MAX_TFTP_FILENAME` / `MAX_TFTP_MODE` /
/// `TFTP_BLOCK_SIZE` / `TFTP_OPCODE_LEN` / `TFTP_BLOCK_LEN` /
/// `TFTP_MIN_DATA_LEN` / `TFTP_MIN_ACK_LEN` / `TFTP_MIN_ERROR_LEN`
/// constants. Closes the no-PXE-boot-fetcher gap left by every
/// prior iteration — the kernel had no UDP-port-69 boot-server
/// codec before this. Pure addition — same trait-set-addition
/// rationale; no existing surface byte changed.
///
/// Bumped to **24** by TASK-059: introduces the [`Pci`] trait + the
/// [`PciConfigBus`] trait + [`PciAddress`], [`PciDevice`], [`PciBar`],
/// [`PciMsixInfo`], [`PciError`], the [`pci_class`] discriminator
/// module, and the `PCI_*` constant family
/// (`PCI_CONFIG_ADDRESS_PORT` / `_DATA_PORT`, `PCI_VENDOR_NONE`,
/// `PCI_MAX_BUS` / `_DEVICE` / `_FUNCTION`,
/// `PCI_HEADER_MULTIFUNC_BIT`, `PCI_CAP_ID_MSI` / `_MSIX`,
/// `PCI_STATUS_CAPABILITIES_LIST`, `PCI_MAX_CAP_HOPS`, the seven
/// `PCI_CFG_OFFSET_*` offsets, `PCI_COMMAND_BUS_MASTER`, the four
/// `PCI_BAR_*` decode constants, `PCI_BAR_INT_LINE_NONE`,
/// `PCI_MAX_BAR_INDEX`, and the four `PCI_MSIX_*` field-mask /
/// enable-bit constants). Closes the no-PCI-discovery gap left
/// by every prior iteration — every existing driver (NVMe,
/// e1000, virtio-net) assumed static configuration-space
/// addresses before this. Wire-codec-shaped surface: the
/// `enumerate(bus)` walker + the BAR decoder + the MSI-X
/// capability parser are testable through a recording
/// `PciConfigBus` harness without actually issuing 0xCF8/0xCFC
/// port cycles. The kernel-side `PciConfigBus` impl wrapping
/// the real `in`/`out` opcodes is wired in `target_enterprise_kernel`.
/// Pure addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **25** by TASK-060: introduces the [`X509`] trait + the
/// locked surface around it — [`X509Cert`], [`X509Time`],
/// [`X509PubKey`], [`X509PubKeyAlg`], [`X509SigAlg`], [`X509Error`],
/// the `X509_TAG_*` family (INTEGER / BIT_STRING / OCTET_STRING /
/// NULL / OID / UTF8_STRING / PRINTABLE_STRING / IA5_STRING /
/// UTC_TIME / GENERALIZED_TIME / SEQUENCE / SET / CTX_EXPLICIT_0 /
/// CTX_EXPLICIT_3), the `X509_OID_*` family
/// (RSA_ENCRYPTION / SHA256_WITH_RSA / EC_PUBLIC_KEY / SECP256R1 /
/// ECDSA_WITH_SHA256 / ED25519 / CN), and the
/// `X509_MAX_CERT_LEN` / `X509_MAX_DEPTH` /
/// `X509_ED25519_KEY_LEN` / `X509_P256_POINT_LEN` constants.
/// Closes the no-cert-parsing gap left by every prior TLS / PKI
/// iteration: `cert.rs` could only *emit* the kernel's self-signed
/// boot cert, and `tls.rs` mTLS accepted a raw 32-byte Ed25519
/// pubkey as the entire `Certificate` payload (RFC 7250 style).
/// With [`X509::parse`] the kernel can now consume a real CA-
/// signed v3 certificate, extract the SPKI / validity / issuer /
/// subject / signature views, and hand them off to the existing
/// [`SignatureVerify`] surface for chain verification. Pure
/// addition — same trait-set-addition rationale; no existing
/// surface byte changed.
/// 25 → 26 (TASK-061 BlockDeviceVirtio trait + VirtBlkRequest +
/// VirtBlkError + virtio_blk_feature / virtio_blk_req_type /
/// virtio_blk_status_byte / virtio_blk_device_cfg modules +
/// VIRTIO_BLK_QUEUE_REQUESTQ / VIRTIO_BLK_HDR_LEN /
/// VIRTIO_BLK_SECTOR_SIZE / VIRTIO_BLK_STATUS_LEN constants).
/// Closes the no-paravirt-storage-driver gap left after NVMe
/// (TASK-018): NVMe is the bare-metal NVMe-over-PCIe path, virtio-
/// blk is the paravirtualised path every cloud hypervisor (KVM /
/// Hyper-V / Firecracker / Xen-VirtIO) exposes for guest disk.
/// Pure addition — same trait-set-addition rationale as TASK-060;
/// no existing surface byte changed. The MmioBus surface added in
/// TASK-048 is reused; only the device-cfg byte interpretation +
/// the request-header wire format are new.
///
/// Bumped to **27** by TASK-062: introduces the [`PicTimer`] +
/// [`Rtc`] traits + the [`IoPort`] recording surface +
/// [`RtcTimeView`] + [`TimerError`] + the locked I/O-port /
/// register / status-bit constant family (`PIT_CMD_PORT` /
/// `PIT_CH0_PORT` / `PIT_BASE_HZ` / `PIT_CMD_CH0_LOHI_MODE3_BIN`,
/// `CMOS_INDEX_PORT` / `CMOS_DATA_PORT`, `RTC_REG_*`,
/// `RTC_STATUS_A_UIP` / `RTC_STATUS_B_24H` / `RTC_STATUS_B_BINARY`
/// / `RTC_HOUR_PM`, `RTC_UIP_SPIN_BUDGET` / `RTC_CONSISTENCY_PASSES`).
/// Closes the no-monotonic-clock-primitive gap left by every prior
/// iteration: the scheduler tick + watchdog + `SYS_SLEEP_MS` /
/// `SYS_GETTIME_NS` paths had no wire-codec surface to pin against.
/// Pure addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **28** by TASK-063: introduces the [`KatRunner`] trait +
/// [`KatSuiteResult`] + [`KatResult`] + [`KatId`] +
/// [`KatPrimitive`] + the locked suite cardinality
/// [`KAT_VECTOR_COUNT`] and digest length [`KAT_DIGEST_LEN`].
/// Closes the "morph-cycle crypto drift is only noticed at next
/// boot's TLS handshake" gap: every SHA-256 / HMAC-SHA-256 / HKDF
/// primitive is forced through published FIPS 180-4 / RFC 4231 /
/// RFC 5869 known-answer vectors before the kernel declares itself
/// ready. Pure addition — same trait-set-addition rationale; no
/// existing surface byte changed.
///
/// Bumped to **29** by TASK-064: introduces the [`JournalFs`] trait +
/// [`JfsSuperblock`] + [`JfsInode`] + [`JfsDirEntry`] + [`JfsError`]
/// + the locked on-disk constant family (`JFS_MAGIC` /
/// `JFS_INODE_MAGIC` / `JFS_VERSION` / `JFS_SECTOR_SIZE` /
/// `JFS_SB_LEN` / `JFS_INODE_LEN` / `JFS_DIRENT_LEN` /
/// `JFS_DIRENT_MAX_NAME` / `JFS_INODES_PER_SECTOR` /
/// `JFS_ROOT_INODE` / `JFS_KIND_FILE` / `JFS_KIND_DIR` + the
/// `JFS_SB_OFF_*` / `JFS_INO_*` field offsets). Closes the
/// no-persistent-filesystem gap left after virtio-blk (TASK-061) +
/// MemRamFs (TASK-054): the kernel can now walk a hand-built or
/// on-disk JFS image (superblock → inode table → directory entries
/// → file body) without an allocator. Pure addition — same
/// trait-set-addition rationale; no existing surface byte changed.
///
/// Bumped to **30** by TASK-065: introduces the [`GdbStub`] trait +
/// [`GdbPacket`] + [`GdbCommand`] + [`GdbError`] + locked RSP
/// constants (`GDB_ACK` / `GDB_NACK` / `GDB_PACKET_START` /
/// `GDB_PACKET_END` / `GDB_INTERRUPT` / `GDB_MAX_BODY` /
/// `GDB_REG_HEX_LEN` / `GDB_MAX_MEM_READ` / `GDB_SIGTRAP`).
/// Closes the no-remote-debug-wire-codec gap: the kernel can parse
/// and frame GDB Remote Serial Protocol packets (checksum +
/// command classify + canned replies) without attaching a live
/// target. Pure addition — same trait-set-addition rationale; no
/// existing surface byte changed.
///
/// Bumped to **31** by TASK-066: introduces the [`Quota`] trait +
/// [`QuotaRecord`] + [`QuotaReject`] + [`QuotaError`] + locked
/// constants (`QUOTA_RECORD_LEN` / `QUOTA_MAX_RECORDS` /
/// `QUOTA_OFF_*` field offsets / `QUOTA_UNLIMITED`). Closes the
/// no-disk-quota-accounting gap the VFS needs to reject over-quota
/// writes: a fixed 32-byte per-uid record + scanner + check-on-write
/// predicate. Pure addition — same trait-set-addition rationale; no
/// existing surface byte changed.
///
/// Bumped to **32** by TASK-067: [`Hpet`] + [`HpetCaps`] +
/// [`HpetError`] + `HPET_REG_*` / `HPET_CFG_*` / `HPET_TN_*`.
///
/// Bumped to **33** by TASK-068: [`StackCanary`] + [`CanaryToken`] +
/// [`CanaryError`] + `STACK_CANARY_LEN`.
///
/// Bumped to **34** by TASK-069: [`Keyboard`] + [`KeyEvent`] +
/// [`KeyCode`] + [`KbError`] + set-1 make-code constants.
///
/// Bumped to **35** by TASK-070: [`Fat32`] + [`FatBpb`] +
/// [`FatDirent`] + [`FatError`] + `FAT_*` BPB/dirent constants.
///
/// Bumped to **36** by TASK-071: [`Watchdog`] + [`WatchdogError`] +
/// `WATCHDOG_DEFAULT_DEADLINE_TICKS`.
///
/// Bumped to **37** by TASK-072: [`Random`] + [`RandomError`] +
/// `RANDOM_SEED_LEN` / `RANDOM_BLOCK_LEN`.
///
/// Bumped to **38** by TASK-073: [`Power`] + [`Pm1Control`] +
/// `PM1_*` / `SLP_*` constants.
///
/// Bumped to **39** by TASK-074: [`Elf64`] + [`ElfHeader`] +
/// [`ElfPhdr`] + [`ElfError`] + `ELF_*` constants.
///
/// Bumped to **40** by TASK-075: [`Serial16550`] + COM port /
/// LSR / LCR constants.
///
/// Bumped to **41** by TASK-076: [`TickSource`] + [`TickKind`].
///
/// Bumped to **42** by TASK-077: [`VirtioPciCaps`] + cap IDs.
///
/// Bumped to **43** by TASK-078: [`SigKat`] + [`SigKatResult`] +
/// `SIGKAT_VECTOR_COUNT`.
///
/// Bumped to **44** by TASK-079: [`Multiboot2`] + tag types.
///
/// Bumped to **45** by TASK-080: [`Crc32c`] + poly constant.
///
/// Bumped to **46** by TASK-081: [`AcpiRsdp`] + signature/checksum.
///
/// Bumped to **47** by TASK-082: [`FrameBitmap`] + alloc/free.
///
/// Bumped to **48** by TASK-083: [`IoApic`] + redtable entry encode.
///
/// Bumped to **49** by TASK-084: [`LapicIcr`] + INIT/SIPI builders.
///
/// Bumped to **50** by TASK-085: [`Gpt`] + partition entry view.
///
/// Bumped to **51** by TASK-086: [`DnsName`] label codec.
///
/// Bumped to **52** by TASK-087: [`HmacDrbg`] + seed expand KAT.
///
/// Bumped to **53** by TASK-088: [`AhciFis`] + H2D Register FIS encode
/// for ATA IDENTIFY / READ DMA.
///
/// Bumped to **54** by TASK-089: [`XhciTrb`] + No-Op / Link TRB encode.
///
/// Bumped to **55** by TASK-090: [`UefiGop`] + GOP mode info view.
///
/// Bumped to **56** by TASK-091: [`AttestTlv`] + JSON-free TLV fields.
///
/// Bumped to **57** by TASK-092: [`Base64`] + RFC 4648 codec.
///
/// Bumped to **58** by TASK-093: [`AhciCmd`] + command header + PRDT.
///
/// Bumped to **59** when HTTPS moved to rustls: removes `Tls13Server`,
/// `Tls13Client`, `ParsedServerHello` and `HandshakeKeys`. They described the
/// hand-written TLS 1.3 handshake, which no longer exists; the rustls-based
/// server in `target_enterprise::https` is pinned by known-answer vectors and
/// a golden-transcript replay instead. A breaking removal, not an addition.
pub const CONTRACTS_SCHEMA_VERSION: u32 = 59;

// ============================================================
// HmacDrbg — one-step HMAC-SHA256 expand KAT (TASK-087)
// ============================================================

/// Seed / key length for the DRBG KAT.
pub const DRBG_SEED_LEN: usize = 32;
/// Output length for banner KAT.
pub const DRBG_OUT_LEN: usize = 16;

/// HMAC-DRBG-shaped expand (HMAC-SHA256 chain).
pub trait HmacDrbg {
    /// `out = HMAC-SHA256(seed, label || 0x01)` truncated/padded to out.len().
    fn expand(seed: &[u8; DRBG_SEED_LEN], label: &[u8], out: &mut [u8]);
}

// ============================================================
// AttestTlv — JSON-free type-length-value fields (TASK-091)
// ============================================================

/// TLV header size: u16 type + u16 length (little-endian).
pub const ATTEST_TLV_HDR_LEN: usize = 4;
/// Maximum value length accepted by the codec.
pub const ATTEST_TLV_MAX_VAL: usize = 256;
/// Max tags walked in one sequence parse.
pub const ATTEST_TLV_MAX_TAGS: usize = 32;
/// Example tag: morph cycle number.
pub const ATTEST_TLV_TAG_CYCLE: u16 = 1;
/// Example tag: layout seed.
pub const ATTEST_TLV_TAG_SEED: u16 = 2;
/// Example tag: module name bytes.
pub const ATTEST_TLV_TAG_MODULE: u16 = 3;

/// One decoded TLV record (value lives in the source buffer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestTlvRecord {
    /// Type tag.
    pub tag: u16,
    /// Byte offset of value within the input buffer.
    pub value_off: usize,
    /// Value length in bytes.
    pub value_len: usize,
}

/// Attestation TLV errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestTlvError {
    /// Truncated header or value.
    Truncated,
    /// Value length exceeds [`ATTEST_TLV_MAX_VAL`].
    ValueTooLong,
    /// Output buffer too small.
    BufferTooSmall,
    /// Too many tags in sequence.
    TooMany,
}

/// Minimal type-length-value codec for future attest v7 extension fields.
pub trait AttestTlv {
    /// Encode one TLV: `type(u16le) || len(u16le) || value`. Returns bytes written.
    fn encode(tag: u16, value: &[u8], out: &mut [u8]) -> Result<usize, AttestTlvError>;
    /// Decode the first TLV in `buf`.
    fn decode(buf: &[u8]) -> Result<AttestTlvRecord, AttestTlvError>;
    /// Count TLVs in a concatenated sequence (stops at end of `buf`).
    fn count_sequence(buf: &[u8]) -> Result<usize, AttestTlvError>;
}

// ============================================================
// Base64 — RFC 4648 standard alphabet (TASK-092)
// ============================================================

/// Base64 codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// Output buffer too small.
    BufferTooSmall,
    /// Invalid alphabet character or padding.
    InvalidInput,
    /// Input length not valid for decode (mod 4).
    BadLength,
}

/// RFC 4648 Base64 encode/decode without allocation.
pub trait Base64 {
    /// Encode `input` into `out` (standard alphabet + `=` padding).
    /// Returns bytes written.
    fn encode(input: &[u8], out: &mut [u8]) -> Result<usize, Base64Error>;
    /// Decode base64 `input` into `out`. Returns plaintext bytes written.
    fn decode(input: &[u8], out: &mut [u8]) -> Result<usize, Base64Error>;
    /// Exact encoded length for `n` input bytes (with padding).
    fn encoded_len(n: usize) -> usize;
}

// ============================================================
// Crc32c — Castagnoli (TASK-080)
// ============================================================

/// CRC32-C reversed polynomial (Castagnoli).
pub const CRC32C_POLY_REV: u32 = 0x82F6_3B78;

/// CRC32-C (Castagnoli) hash.
pub trait Crc32c {
    /// Compute CRC32-C over `data` (init 0xFFFFFFFF, final XOR same).
    fn hash(data: &[u8]) -> u32;
}

// ============================================================
// SigKat — Ed25519 RFC 8032 known-answer harness (TASK-078)
// ============================================================

/// Number of locked RFC 8032 vectors in the suite.
pub const SIGKAT_VECTOR_COUNT: u8 = 2;
/// Ed25519 public key length.
pub const SIGKAT_PK_LEN: usize = 32;
/// Ed25519 secret key length (seed).
pub const SIGKAT_SK_LEN: usize = 32;
/// Ed25519 signature length.
pub const SIGKAT_SIG_LEN: usize = 64;

/// One vector outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigKatResult {
    /// Vector id 0..SIGKAT_VECTOR_COUNT.
    pub id: u8,
    /// True if all checks passed.
    pub pass: bool,
}

/// Aggregate suite result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigKatSuite {
    /// Total vectors.
    pub total: u8,
    /// Passed count.
    pub passed: u8,
}

impl SigKatSuite {
    /// All vectors passed.
    pub const fn all_ok(self) -> bool {
        self.passed == self.total
    }
}

/// Ed25519 known-answer harness (fixture integrity + structural
/// verify against published RFC 8032 bytes).
pub trait SigKat {
    /// Run the full locked suite.
    fn run_all() -> SigKatSuite;
    /// Run one vector by id.
    fn run_one(id: u8) -> Option<SigKatResult>;
}

// ============================================================
// Random — deterministic seed mixer / counter DRBG (TASK-072)
// ============================================================

/// Seed length in bytes.
pub const RANDOM_SEED_LEN: usize = 32;
/// Default output block length for KAT.
pub const RANDOM_BLOCK_LEN: usize = 16;

/// RNG errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomError {
    /// Not seeded yet.
    NotSeeded,
    /// Output buffer empty.
    EmptyOutput,
    /// Seed all-zero rejected.
    WeakSeed,
}

/// Deterministic CSPRNG-shaped mixer (ChaCha-inspired quarter rounds
/// over a 32-byte state). Locked KAT for morph detection.
pub trait Random {
    /// Seed from 32 bytes (must not be all-zero).
    fn seed(&mut self, seed: &[u8; RANDOM_SEED_LEN]) -> Result<(), RandomError>;
    /// Fill `out` with next pseudorandom bytes.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError>;
    /// Next u64 (little-endian from 8 fill bytes).
    fn next_u64(&mut self) -> Result<u64, RandomError>;
}

// ============================================================
// KatRunner — Known-Answer Test harness (TASK-063)
// ============================================================

/// Output length of every digest / PRK the suite asserts against.
/// SHA-256 and HMAC-SHA-256 both produce 32 bytes.
pub const KAT_DIGEST_LEN: usize = 32;

/// Number of locked vectors in the boot suite. Every
/// [`KatRunner::run_all`] implementation MUST exercise exactly this
/// many vectors, in [`KatId`] discriminant order.
///
/// Composition (locked):
/// - 3 × SHA-256 (FIPS 180-4 / RFC 6234): empty, `"abc"`, million-`a`
/// - 4 × HMAC-SHA-256 (RFC 4231 §4.2–§4.5): test cases 1–4
/// - 2 × HKDF-SHA-256 (RFC 5869 §A.1–§A.2): cases 1–2 (PRK + OKM)
pub const KAT_VECTOR_COUNT: u8 = 9;

/// Which crypto primitive a vector exercises. Discriminants are part
/// of the locked surface so a morph cannot silently reclassify a
/// vector (e.g. claim a SHA failure as an HMAC failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KatPrimitive {
    /// SHA-256 (FIPS 180-4).
    Sha256 = 0,
    /// HMAC-SHA-256 (RFC 2104 / RFC 4231).
    HmacSha256 = 1,
    /// HKDF-Extract + Expand over SHA-256 (RFC 5869).
    HkdfSha256 = 2,
}

/// Stable identity of one vector in the locked suite. Discriminant
/// values 0..[`KAT_VECTOR_COUNT`] are part of the wire-observable
/// surface (the kernel banner prints the count; a failed vector's
/// id lands in [`KatSuiteResult::first_fail`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KatId {
    /// SHA-256 of the empty string.
    Sha256Empty = 0,
    /// SHA-256 of `"abc"`.
    Sha256Abc = 1,
    /// SHA-256 of one million ASCII `'a'` bytes.
    Sha256MillionA = 2,
    /// RFC 4231 test case 1.
    HmacRfc4231Case1 = 3,
    /// RFC 4231 test case 2.
    HmacRfc4231Case2 = 4,
    /// RFC 4231 test case 3.
    HmacRfc4231Case3 = 5,
    /// RFC 4231 test case 4.
    HmacRfc4231Case4 = 6,
    /// RFC 5869 test case 1 (PRK + OKM).
    HkdfRfc5869Case1 = 7,
    /// RFC 5869 test case 2 (PRK + OKM).
    HkdfRfc5869Case2 = 8,
}

impl KatId {
    /// Construct from the raw discriminant. Returns `None` if `raw`
    /// is outside `0..KAT_VECTOR_COUNT`.
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Sha256Empty),
            1 => Some(Self::Sha256Abc),
            2 => Some(Self::Sha256MillionA),
            3 => Some(Self::HmacRfc4231Case1),
            4 => Some(Self::HmacRfc4231Case2),
            5 => Some(Self::HmacRfc4231Case3),
            6 => Some(Self::HmacRfc4231Case4),
            7 => Some(Self::HkdfRfc5869Case1),
            8 => Some(Self::HkdfRfc5869Case2),
            _ => None,
        }
    }

    /// Primitive family this vector exercises.
    pub const fn primitive(self) -> KatPrimitive {
        match self {
            Self::Sha256Empty | Self::Sha256Abc | Self::Sha256MillionA => KatPrimitive::Sha256,
            Self::HmacRfc4231Case1
            | Self::HmacRfc4231Case2
            | Self::HmacRfc4231Case3
            | Self::HmacRfc4231Case4 => KatPrimitive::HmacSha256,
            Self::HkdfRfc5869Case1 | Self::HkdfRfc5869Case2 => KatPrimitive::HkdfSha256,
        }
    }

    /// Short stable name for serial banners / audit logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256Empty => "sha256_empty",
            Self::Sha256Abc => "sha256_abc",
            Self::Sha256MillionA => "sha256_million_a",
            Self::HmacRfc4231Case1 => "hmac_rfc4231_1",
            Self::HmacRfc4231Case2 => "hmac_rfc4231_2",
            Self::HmacRfc4231Case3 => "hmac_rfc4231_3",
            Self::HmacRfc4231Case4 => "hmac_rfc4231_4",
            Self::HkdfRfc5869Case1 => "hkdf_rfc5869_1",
            Self::HkdfRfc5869Case2 => "hkdf_rfc5869_2",
        }
    }

    /// Publication source citation.
    pub const fn source(self) -> &'static str {
        match self {
            Self::Sha256Empty | Self::Sha256Abc | Self::Sha256MillionA => "FIPS 180-4 / RFC 6234",
            Self::HmacRfc4231Case1
            | Self::HmacRfc4231Case2
            | Self::HmacRfc4231Case3
            | Self::HmacRfc4231Case4 => "RFC 4231",
            Self::HkdfRfc5869Case1 | Self::HkdfRfc5869Case2 => "RFC 5869",
        }
    }
}

/// One vector's outcome. Storage-only; no allocation. The expected
/// and actual digests are always [`KAT_DIGEST_LEN`] bytes for
/// SHA-256 / HMAC vectors; for HKDF vectors `expected`/`actual` hold
/// the PRK (32 bytes) and `okm_match` reports the expand step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KatResult {
    /// Vector identity.
    pub id: KatId,
    /// True iff every asserted output matched the published answer.
    pub pass: bool,
    /// Actual primary digest / PRK produced by the implementation.
    pub actual: [u8; KAT_DIGEST_LEN],
    /// Expected primary digest / PRK from the published standard.
    pub expected: [u8; KAT_DIGEST_LEN],
    /// For HKDF vectors: whether the OKM (expand output) matched.
    /// For non-HKDF vectors: always `true` (unused).
    pub okm_match: bool,
}

/// Aggregate outcome of [`KatRunner::run_all`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KatSuiteResult {
    /// Always equal to [`KAT_VECTOR_COUNT`] on a conforming impl.
    pub total: u8,
    /// Number of vectors that passed.
    pub passed: u8,
    /// First failing vector, if any. `None` means the suite is clean.
    pub first_fail: Option<KatId>,
}

impl KatSuiteResult {
    /// True iff every vector passed.
    pub const fn all_ok(self) -> bool {
        self.passed == self.total && self.first_fail.is_none()
    }
}

/// Known-answer test harness for the kernel crypto primitives.
///
/// # Locked invariants the verifier checks
///
/// 1. [`run_all`](KatRunner::run_all) exercises exactly
///    [`KAT_VECTOR_COUNT`] vectors in [`KatId`] order 0..N-1.
/// 2. On a clean suite, `passed == total`, `first_fail == None`, and
///    `all_ok()` is true.
/// 3. On the first failing vector, `first_fail` equals that vector's
///    id and `passed` equals the count of vectors before it that
///    passed (the suite may continue or short-circuit — either is
///    allowed; the seed continues so the banner can report `passed`).
/// 4. [`run_one`](KatRunner::run_one) for each [`KatId`] returns a
///    [`KatResult`] whose `expected` field is the published digest
///    for that vector (byte-exact against the standard).
///
/// The harness is pure computation over fixed inputs — no I/O, no
/// allocation, no global state. A morph that perturbs SHA-256,
/// HMAC, or HKDF arithmetic fails a published vector in the same
/// cycle the morph is deployed.
pub trait KatRunner {
    /// Run every locked vector. Returns the aggregate result.
    fn run_all() -> KatSuiteResult;

    /// Run a single vector by id.
    fn run_one(id: KatId) -> KatResult;
}

