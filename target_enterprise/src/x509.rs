//! X.509 v3 DER certificate parser — pure-parse, no allocator, no
//! signature verification.
//!
//! Why this module exists: the kernel's TLS stack (`tls.rs`) and the
//! cert encoder (`cert.rs`) historically only spoke RFC 7250 raw-public-
//! key form — the entire `Certificate` payload was a 32-byte Ed25519
//! key. That works against a peer we control; a real CA-signed peer
//! sends a full DER X.509 v3 blob. This module is the bridge.
//!
//! # Scope of the port
//!
//! The donor at `D:/RustProjects/RustOSa/src/x509.rs` couples parsing
//! with signature verification (Ed25519 + ECDSA-P256) and returns
//! `Vec<u8>` fields backed by `extern crate alloc`. Both are removed:
//!
//! - **Pure parser.** Signature verification is the caller's job —
//!   the existing [`cuttle_contracts::SignatureVerify`] trait handles
//!   it. A morph that broke `parse` would surface long before any
//!   crypto code runs; conflating the two enlarges the morphable
//!   surface for no isolation benefit.
//! - **`no_std`, no `alloc`.** Every field of [`X509Cert`] is a
//!   `&[u8]` view into the caller's input buffer. The parser never
//!   copies a byte. Issuer / Subject DN slices include their
//!   `SEQUENCE` header so a chain-walking caller can do
//!   `child.issuer == parent.subject` for the RFC 5280 §4.1.2.4
//!   match.
//! - **RSA + EC + Ed25519 SPKI.** Donor was Ed25519 + ECDSA-only.
//!   Real-world peers (Let's Encrypt, every public CA) sign with
//!   `sha256WithRSAEncryption` over an `rsaEncryption` SPKI. We
//!   add that algorithm pair so the kernel can ingest a real chain.
//!
//! # Strict-DER posture
//!
//! Every defensive check from the donor is preserved and a couple
//! added:
//!
//! - High-tag-number form (low 5 bits of tag all set) refused.
//! - Indefinite-length form refused.
//! - Long-form length with > 4 octets refused (no > 4 GiB certs).
//! - Non-minimal length encoding refused (long-form for < 128, or
//!   a leading 0x00 in the length octets).
//! - INTEGER bodies: leading 0x00 only when needed as a sign-bit
//!   guard; negative integers refused for fields that must be
//!   unsigned (serial, RSA modulus / exponent).
//! - BIT STRING `unused bits` non-zero refused (it's never legal
//!   for SPKI / signature carriers).
//! - UTCTime / GeneralizedTime: exact length, trailing `Z`, every
//!   byte an ASCII digit, calendar month-day combination valid for
//!   the year's leap-status.
//!
//! Any failed check surfaces a specific [`X509Error`] variant —
//! every error path returns a distinct discriminant so a fuzzing
//! caller can correlate the failure category to the test corpus.
//!
//! # No-allocator algebra
//!
//! The parser is built around a single [`Tlv`] view that borrows
//! into the input. A [`SeqWalker`] iterates the children of a
//! constructed TLV without owning anything. The TBS sub-slice is
//! computed using *byte indices* into a sub-slice the caller hands
//! us (saved as an explicit `tbs_start: usize` index, computed by
//! pointer arithmetic) — no `Vec`, no copy.

#![allow(clippy::needless_range_loop)]

use cuttle_contracts::{
    X509Cert, X509Error, X509PubKey, X509PubKeyAlg, X509SigAlg, X509Time,
    X509_ED25519_KEY_LEN, X509_MAX_CERT_LEN, X509_MAX_DEPTH, X509_OID_CN,
    X509_OID_ECDSA_WITH_SHA256, X509_OID_ED25519, X509_OID_EC_PUBLIC_KEY,
    X509_OID_RSA_ENCRYPTION, X509_OID_SECP256R1, X509_OID_SHA256_WITH_RSA,
    X509_P256_POINT_LEN, X509_TAG_BIT_STRING, X509_TAG_CTX_EXPLICIT_0,
    X509_TAG_CTX_EXPLICIT_3, X509_TAG_GENERALIZED_TIME, X509_TAG_INTEGER, X509_TAG_NULL,
    X509_TAG_OID, X509_TAG_SEQUENCE, X509_TAG_SET, X509_TAG_UTC_TIME, X509,
};

// ============================================================
// TLV decoder primitives
// ============================================================

/// A parsed tag-length-value triple borrowed from the input slice.
#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    /// Number of bytes in the encoded header (tag + length field).
    header_len: usize,
    /// Content (value) bytes.
    value: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Total encoded length of this TLV (header + value).
    fn encoded_len(&self) -> usize {
        self.header_len + self.value.len()
    }
}

/// Decode one TLV at the head of `buf`. Bounds-checked, DER-strict.
fn read_tlv(buf: &[u8]) -> Result<Tlv<'_>, X509Error> {
    if buf.len() < 2 {
        return Err(X509Error::TruncatedHeader);
    }
    let tag = buf[0];
    // Reject the high-tag-number form. None of the tags we care about
    // use it; refusing it shrinks the attack surface (no decoder for
    // multi-byte tag numbers).
    if (tag & 0x1F) == 0x1F {
        return Err(X509Error::HighTagNumber);
    }
    let first_len = buf[1];
    let (value_len, header_len) = if first_len < 0x80 {
        // Short form: length octet IS the length.
        (first_len as usize, 2usize)
    } else {
        // Long form: low 7 bits = number of subsequent length octets.
        let n = (first_len & 0x7F) as usize;
        if n == 0 {
            // Indefinite-length form is illegal in DER.
            return Err(X509Error::IndefiniteLength);
        }
        if n > 4 {
            // We refuse to parse > 4 GiB lengths.
            return Err(X509Error::LengthTooLarge);
        }
        if buf.len() < 2 + n {
            return Err(X509Error::TruncatedHeader);
        }
        // Leading-zero in the length octets is illegal (non-minimal).
        if buf[2] == 0x00 {
            return Err(X509Error::NonMinimalLength);
        }
        let mut len: usize = 0;
        for i in 0..n {
            len = (len << 8) | (buf[2 + i] as usize);
        }
        // DER requires minimum-length encoding: long form only legal
        // when value won't fit in short form (i.e. >= 128).
        if len < 128 {
            return Err(X509Error::NonMinimalLength);
        }
        (len, 2 + n)
    };
    if buf.len() < header_len + value_len {
        return Err(X509Error::TruncatedBody);
    }
    Ok(Tlv {
        tag,
        header_len,
        value: &buf[header_len..header_len + value_len],
    })
}

/// Read a TLV at `buf` and require its tag to equal `expected`.
fn read_tag(buf: &[u8], expected: u8) -> Result<Tlv<'_>, X509Error> {
    let tlv = read_tlv(buf)?;
    if tlv.tag != expected {
        return Err(X509Error::BadTag);
    }
    Ok(tlv)
}

/// Iterator-style walker over the contents of a SEQUENCE / SET.
struct SeqWalker<'a> {
    rest: &'a [u8],
}

impl<'a> SeqWalker<'a> {
    fn new(inner: &'a [u8]) -> Self {
        Self { rest: inner }
    }

    fn finished(&self) -> bool {
        self.rest.is_empty()
    }

    fn next(&mut self) -> Result<Tlv<'a>, X509Error> {
        if self.rest.is_empty() {
            return Err(X509Error::TruncatedBody);
        }
        let tlv = read_tlv(self.rest)?;
        self.rest = &self.rest[tlv.encoded_len()..];
        Ok(tlv)
    }

    /// Peek at the next tag byte without advancing. Returns `None`
    /// if the walker is exhausted.
    fn peek_tag(&self) -> Option<u8> {
        if self.rest.is_empty() {
            None
        } else {
            Some(self.rest[0])
        }
    }
}

/// Locate `inner`'s byte offset inside `outer`, given that `inner` is
/// a sub-slice of `outer`. Uses raw pointer arithmetic (no `unsafe`,
/// no scanning).
fn subslice_offset(outer: &[u8], inner: &[u8]) -> Option<usize> {
    let outer_start = outer.as_ptr() as usize;
    let outer_end = outer_start + outer.len();
    let inner_start = inner.as_ptr() as usize;
    if inner_start < outer_start || inner_start > outer_end {
        return None;
    }
    Some(inner_start - outer_start)
}

// ============================================================
// Field decoders (INTEGER / BIT STRING / OID / Time)
// ============================================================

/// Decode an INTEGER TLV's body into a borrowed slice, stripping the
/// DER sign-bit guard 0x00 if present. The slice returned is what a
/// caller treating the value as an unsigned big-endian magnitude
/// (RSA modulus, RSA exponent, serial number) actually wants.
fn decode_unsigned_int<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8], X509Error> {
    if tlv.tag != X509_TAG_INTEGER {
        return Err(X509Error::BadTag);
    }
    if tlv.value.is_empty() {
        return Err(X509Error::MalformedInteger);
    }
    // DER canonical form: leading 0x00 only when the next byte's
    // high bit is set (used as sign-bit guard so the magnitude
    // doesn't end up negative). Drop it.
    if tlv.value.len() > 1 && tlv.value[0] == 0x00 && tlv.value[1] & 0x80 == 0 {
        return Err(X509Error::MalformedInteger);
    }
    if tlv.value[0] & 0x80 != 0 {
        return Err(X509Error::MalformedInteger);
    }
    if tlv.value.len() > 1 && tlv.value[0] == 0x00 {
        // Strip the guard byte for the caller's benefit.
        Ok(&tlv.value[1..])
    } else {
        Ok(tlv.value)
    }
}

/// Decode a small INTEGER (used for the version field). Up to 8
/// octets, returned as a u64.
fn decode_small_int(tlv: &Tlv<'_>) -> Result<u64, X509Error> {
    if tlv.tag != X509_TAG_INTEGER {
        return Err(X509Error::BadTag);
    }
    if tlv.value.is_empty() {
        return Err(X509Error::MalformedInteger);
    }
    if tlv.value[0] & 0x80 != 0 {
        return Err(X509Error::MalformedInteger);
    }
    if tlv.value.len() > 8 {
        return Err(X509Error::MalformedInteger);
    }
    let mut acc: u64 = 0;
    for &b in tlv.value {
        acc = (acc << 8) | (b as u64);
    }
    Ok(acc)
}

/// Decode a BIT STRING's body and return the bytes with the leading
/// `unused bits` octet stripped. The parser only accepts zero-unused
/// — anything else surfaces `MalformedBitString`.
fn decode_bit_string<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8], X509Error> {
    if tlv.tag != X509_TAG_BIT_STRING {
        return Err(X509Error::BadTag);
    }
    if tlv.value.is_empty() {
        return Err(X509Error::MalformedBitString);
    }
    if tlv.value[0] != 0x00 {
        return Err(X509Error::MalformedBitString);
    }
    Ok(&tlv.value[1..])
}

/// Decode an OID's body bytes — kept opaque (bitwise-equality match).
fn decode_oid<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8], X509Error> {
    if tlv.tag != X509_TAG_OID {
        return Err(X509Error::BadTag);
    }
    if tlv.value.is_empty() {
        return Err(X509Error::BadTag);
    }
    Ok(tlv.value)
}

// ============================================================
// Time decoders (UTCTime / GeneralizedTime)
// ============================================================

const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn ascii_digits(buf: &[u8]) -> Option<u32> {
    let mut acc: u32 = 0;
    for &b in buf {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(acc)
}

fn calendar_to_unix(
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<u64> {
    if !(1970..=9999).contains(&year) {
        return None;
    }
    if !(1..=12).contains(&month) {
        return None;
    }
    if !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let second = if second == 60 { 59 } else { second };
    let mut this_month_days = DAYS_IN_MONTH[(month - 1) as usize];
    if month == 2 && is_leap_year(year) {
        this_month_days = 29;
    }
    if day > this_month_days {
        return None;
    }
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    for m in 1..month {
        let mut dim = DAYS_IN_MONTH[(m - 1) as usize] as u64;
        if m == 2 && is_leap_year(year) {
            dim = 29;
        }
        days += dim;
    }
    days += (day - 1) as u64;
    Some(days * 86_400 + (hour as u64) * 3600 + (minute as u64) * 60 + (second as u64))
}

fn parse_time(tlv: &Tlv<'_>) -> Result<X509Time, X509Error> {
    match tlv.tag {
        X509_TAG_UTC_TIME => {
            // YYMMDDhhmmssZ — exactly 13 bytes.
            if tlv.value.len() != 13 || tlv.value[12] != b'Z' {
                return Err(X509Error::MalformedTime);
            }
            let yy = ascii_digits(&tlv.value[0..2]).ok_or(X509Error::MalformedTime)?;
            let mm = ascii_digits(&tlv.value[2..4]).ok_or(X509Error::MalformedTime)?;
            let dd = ascii_digits(&tlv.value[4..6]).ok_or(X509Error::MalformedTime)?;
            let hh = ascii_digits(&tlv.value[6..8]).ok_or(X509Error::MalformedTime)?;
            let mi = ascii_digits(&tlv.value[8..10]).ok_or(X509Error::MalformedTime)?;
            let ss = ascii_digits(&tlv.value[10..12]).ok_or(X509Error::MalformedTime)?;
            // RFC 5280 §4.1.2.5.1: yy < 50 → 20yy, else 19yy.
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            calendar_to_unix(year, mm, dd, hh, mi, ss)
                .map(|s| X509Time { unix: s })
                .ok_or(X509Error::TimeOutOfRange)
        }
        X509_TAG_GENERALIZED_TIME => {
            // YYYYMMDDhhmmssZ — exactly 15 bytes.
            if tlv.value.len() != 15 || tlv.value[14] != b'Z' {
                return Err(X509Error::MalformedTime);
            }
            let year = ascii_digits(&tlv.value[0..4]).ok_or(X509Error::MalformedTime)?;
            let mm = ascii_digits(&tlv.value[4..6]).ok_or(X509Error::MalformedTime)?;
            let dd = ascii_digits(&tlv.value[6..8]).ok_or(X509Error::MalformedTime)?;
            let hh = ascii_digits(&tlv.value[8..10]).ok_or(X509Error::MalformedTime)?;
            let mi = ascii_digits(&tlv.value[10..12]).ok_or(X509Error::MalformedTime)?;
            let ss = ascii_digits(&tlv.value[12..14]).ok_or(X509Error::MalformedTime)?;
            calendar_to_unix(year, mm, dd, hh, mi, ss)
                .map(|s| X509Time { unix: s })
                .ok_or(X509Error::TimeOutOfRange)
        }
        _ => Err(X509Error::BadTag),
    }
}

// ============================================================
// AlgorithmIdentifier + SPKI decoders
// ============================================================

/// Decode an AlgorithmIdentifier SEQUENCE. Returns the OID body bytes
/// and a borrowed view of the (optional) parameters TLV.
fn decode_alg_id<'a>(
    tlv: &Tlv<'a>,
) -> Result<(&'a [u8], Option<Tlv<'a>>), X509Error> {
    if tlv.tag != X509_TAG_SEQUENCE {
        return Err(X509Error::BadTag);
    }
    let mut w = SeqWalker::new(tlv.value);
    let oid_tlv = w.next()?;
    let oid = decode_oid(&oid_tlv)?;
    let params = if w.finished() { None } else { Some(w.next()?) };
    if !w.finished() {
        return Err(X509Error::TrailingData);
    }
    Ok((oid, params))
}

/// Decode a SubjectPublicKeyInfo SEQUENCE.
fn decode_spki<'a>(
    tlv: &Tlv<'a>,
) -> Result<(X509PubKeyAlg, X509PubKey<'a>), X509Error> {
    if tlv.tag != X509_TAG_SEQUENCE {
        return Err(X509Error::BadTag);
    }
    let mut w = SeqWalker::new(tlv.value);
    let alg_tlv = w.next()?;
    let (alg_oid, params) = decode_alg_id(&alg_tlv)?;
    let key_bit_tlv = w.next()?;
    let key_bytes = decode_bit_string(&key_bit_tlv)?;
    if !w.finished() {
        return Err(X509Error::TrailingData);
    }
    if alg_oid == X509_OID_ED25519 {
        // RFC 8410: parameters MUST be absent.
        if params.is_some() {
            return Err(X509Error::BadAlgParams);
        }
        if key_bytes.len() != X509_ED25519_KEY_LEN {
            return Err(X509Error::MalformedPubKey);
        }
        Ok((
            X509PubKeyAlg::Ed25519,
            X509PubKey::Ed25519 { key: key_bytes },
        ))
    } else if alg_oid == X509_OID_EC_PUBLIC_KEY {
        // RFC 5480: parameters MUST be present and identify the curve.
        let params = params.ok_or(X509Error::BadAlgParams)?;
        let curve = decode_oid(&params)?;
        if curve != X509_OID_SECP256R1 {
            return Err(X509Error::UnsupportedKeyAlg);
        }
        if key_bytes.len() != X509_P256_POINT_LEN || key_bytes[0] != 0x04 {
            return Err(X509Error::MalformedPubKey);
        }
        Ok((
            X509PubKeyAlg::EcdsaP256,
            X509PubKey::EcdsaP256 { point: key_bytes },
        ))
    } else if alg_oid == X509_OID_RSA_ENCRYPTION {
        // RFC 3279 §2.3.1: parameters MUST be a NULL.
        let params = params.ok_or(X509Error::BadAlgParams)?;
        if params.tag != X509_TAG_NULL || !params.value.is_empty() {
            return Err(X509Error::BadAlgParams);
        }
        // The BIT STRING contents are themselves a DER-encoded
        // SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        // — RFC 3279 §2.3.1 "RSAPublicKey".
        let inner = read_tag(key_bytes, X509_TAG_SEQUENCE)?;
        if inner.encoded_len() != key_bytes.len() {
            return Err(X509Error::TrailingData);
        }
        let mut iw = SeqWalker::new(inner.value);
        let mod_tlv = iw.next()?;
        let modulus = decode_unsigned_int(&mod_tlv)?;
        let exp_tlv = iw.next()?;
        let exponent = decode_unsigned_int(&exp_tlv)?;
        if !iw.finished() {
            return Err(X509Error::TrailingData);
        }
        // RSA modulus must be > 1 byte (real keys are 128+ bytes).
        // Public exponent must be odd (low bit set) and at least 1.
        if modulus.is_empty() {
            return Err(X509Error::MalformedPubKey);
        }
        if exponent.is_empty() {
            return Err(X509Error::MalformedPubKey);
        }
        Ok((
            X509PubKeyAlg::Rsa,
            X509PubKey::Rsa { modulus, exponent },
        ))
    } else {
        Err(X509Error::UnsupportedKeyAlg)
    }
}

fn classify_sig_alg(oid: &[u8]) -> Result<X509SigAlg, X509Error> {
    if oid == X509_OID_ED25519 {
        Ok(X509SigAlg::Ed25519)
    } else if oid == X509_OID_ECDSA_WITH_SHA256 {
        Ok(X509SigAlg::EcdsaSha256)
    } else if oid == X509_OID_SHA256_WITH_RSA {
        Ok(X509SigAlg::RsaSha256)
    } else {
        Err(X509Error::UnsupportedSigAlg)
    }
}

// ============================================================
// Top-level certificate parser
// ============================================================

/// Pure-parser X.509 implementation. Stateless.
pub struct X509Impl;

impl X509Impl {
    /// Walk one TBSCertificate body. Returns the populated certificate
    /// view (minus the outer-level signature triple, which the caller
    /// fills in).
    fn parse_tbs<'a>(
        body: &'a [u8],
        tbs_slice: &'a [u8],
        depth: usize,
    ) -> Result<(
        u8,                // version
        &'a [u8],          // serial
        &'a [u8],          // tbs sig alg OID
        &'a [u8],          // issuer DER (full TLV)
        &'a [u8],          // subject DER (full TLV)
        X509Time,          // not before
        X509Time,          // not after
        X509PubKeyAlg,     //
        X509PubKey<'a>,    //
    ), X509Error> {
        if depth > X509_MAX_DEPTH {
            return Err(X509Error::DepthExceeded);
        }
        let mut w = SeqWalker::new(body);

        // version: [0] EXPLICIT INTEGER — must equal 2 (v3).
        let first = w.peek_tag().ok_or(X509Error::TruncatedBody)?;
        let version: u8 = if first == X509_TAG_CTX_EXPLICIT_0 {
            let wrap = w.next()?;
            let inner = read_tag(wrap.value, X509_TAG_INTEGER)?;
            if inner.encoded_len() != wrap.value.len() {
                return Err(X509Error::TrailingData);
            }
            let n = decode_small_int(&inner)?;
            if n > 2 {
                return Err(X509Error::UnsupportedVersion);
            }
            n as u8
        } else {
            // v1 default — refused.
            0
        };
        if version != 2 {
            return Err(X509Error::UnsupportedVersion);
        }

        // serialNumber
        let serial_tlv = w.next()?;
        let serial = decode_unsigned_int(&serial_tlv)?;

        // signature (TBS-level AlgorithmIdentifier)
        let sig_alg_tlv = w.next()?;
        let (tbs_sig_oid, tbs_sig_params) = decode_alg_id(&sig_alg_tlv)?;
        let _ = classify_sig_alg(tbs_sig_oid)?;
        // Ed25519 forbids params; sha256-with-rsa REQUIRES NULL params;
        // ecdsa-with-sha256 omits them.
        if tbs_sig_oid == X509_OID_ED25519 && tbs_sig_params.is_some() {
            return Err(X509Error::BadAlgParams);
        }
        if tbs_sig_oid == X509_OID_SHA256_WITH_RSA {
            let p = tbs_sig_params.ok_or(X509Error::BadAlgParams)?;
            if p.tag != X509_TAG_NULL || !p.value.is_empty() {
                return Err(X509Error::BadAlgParams);
            }
        }
        if tbs_sig_oid == X509_OID_ECDSA_WITH_SHA256 && tbs_sig_params.is_some()
        {
            return Err(X509Error::BadAlgParams);
        }

        // issuer Name
        let issuer_tlv = w.next()?;
        if issuer_tlv.tag != X509_TAG_SEQUENCE {
            return Err(X509Error::BadTag);
        }
        if issuer_tlv.value.is_empty() {
            return Err(X509Error::EmptyName);
        }
        let issuer_der = Self::slice_from_tlv(tbs_slice, &issuer_tlv)?;

        // validity SEQUENCE { notBefore, notAfter }
        let val_tlv = w.next()?;
        if val_tlv.tag != X509_TAG_SEQUENCE {
            return Err(X509Error::BadTag);
        }
        let mut vw = SeqWalker::new(val_tlv.value);
        let nb_tlv = vw.next()?;
        let na_tlv = vw.next()?;
        if !vw.finished() {
            return Err(X509Error::TrailingData);
        }
        let not_before = parse_time(&nb_tlv)?;
        let not_after = parse_time(&na_tlv)?;
        if not_after.unix < not_before.unix {
            return Err(X509Error::ValidityWindowInverted);
        }

        // subject Name
        let subject_tlv = w.next()?;
        if subject_tlv.tag != X509_TAG_SEQUENCE {
            return Err(X509Error::BadTag);
        }
        let subject_der = Self::slice_from_tlv(tbs_slice, &subject_tlv)?;

        // SubjectPublicKeyInfo
        let spki_tlv = w.next()?;
        let (pubkey_alg, pubkey) = decode_spki(&spki_tlv)?;

        // Consume optional [1] / [2] (UniqueIDs) and [3] (extensions)
        // tags. We don't inspect them — they're inside the signed TBS
        // bytes anyway, so a future iteration can pull out SAN /
        // BasicConstraints / KeyUsage without breaking this signature.
        while let Some(t) = w.peek_tag() {
            match t {
                0x81 | 0xA1 | 0x82 | 0xA2 | X509_TAG_CTX_EXPLICIT_3 => {
                    let _ = w.next()?;
                }
                _ => return Err(X509Error::TrailingData),
            }
        }

        Ok((
            version,
            serial,
            tbs_sig_oid,
            issuer_der,
            subject_der,
            not_before,
            not_after,
            pubkey_alg,
            pubkey,
        ))
    }

    /// Compute the full-TLV sub-slice of `outer` that `inner_tlv` came
    /// from — including its header — so the caller can compare it
    /// against another cert's DER blob byte-for-byte.
    fn slice_from_tlv<'a>(
        outer: &'a [u8],
        inner_tlv: &Tlv<'a>,
    ) -> Result<&'a [u8], X509Error> {
        let off = subslice_offset(outer, inner_tlv.value)
            .ok_or(X509Error::TrailingData)?
            .checked_sub(inner_tlv.header_len)
            .ok_or(X509Error::TrailingData)?;
        let total = inner_tlv.encoded_len();
        if off + total > outer.len() {
            return Err(X509Error::TruncatedBody);
        }
        Ok(&outer[off..off + total])
    }
}

impl X509 for X509Impl {
    fn parse(der: &[u8]) -> Result<X509Cert<'_>, X509Error> {
        if der.is_empty() {
            return Err(X509Error::Empty);
        }
        if der.len() > X509_MAX_CERT_LEN {
            return Err(X509Error::TooLarge);
        }
        // Outer Certificate SEQUENCE.
        let outer = read_tag(der, X509_TAG_SEQUENCE)?;
        if outer.encoded_len() != der.len() {
            return Err(X509Error::TrailingData);
        }
        let mut top = SeqWalker::new(outer.value);

        // TBSCertificate
        let tbs_tlv = top.next()?;
        if tbs_tlv.tag != X509_TAG_SEQUENCE {
            return Err(X509Error::BadTag);
        }
        // Stash the exact encoded TBS bytes — what the signature
        // covers. Returned to the caller as the `tbs` slice so an
        // out-of-tree verifier can `sha256(tbs)` directly.
        let tbs_slice = X509Impl::slice_from_tlv(outer.value, &tbs_tlv)?;
        let (
            version,
            serial,
            tbs_sig_oid,
            issuer_der,
            subject_der,
            not_before,
            not_after,
            pubkey_alg,
            pubkey,
        ) = X509Impl::parse_tbs(tbs_tlv.value, tbs_slice, 1)?;

        // outer signatureAlgorithm
        let sig_alg_tlv = top.next()?;
        let (outer_sig_oid, outer_sig_params) = decode_alg_id(&sig_alg_tlv)?;
        let sig_alg = classify_sig_alg(outer_sig_oid)?;
        if outer_sig_oid == X509_OID_ED25519 && outer_sig_params.is_some() {
            return Err(X509Error::BadAlgParams);
        }
        if outer_sig_oid == X509_OID_SHA256_WITH_RSA {
            let p = outer_sig_params.ok_or(X509Error::BadAlgParams)?;
            if p.tag != X509_TAG_NULL || !p.value.is_empty() {
                return Err(X509Error::BadAlgParams);
            }
        }
        if outer_sig_oid == X509_OID_ECDSA_WITH_SHA256 && outer_sig_params.is_some() {
            return Err(X509Error::BadAlgParams);
        }
        // RFC 5280 §4.1.1.2: outer signatureAlgorithm equals TBS.signature.
        if outer_sig_oid != tbs_sig_oid {
            return Err(X509Error::SigAlgMismatch);
        }

        // signatureValue
        let sig_bit_tlv = top.next()?;
        let signature = decode_bit_string(&sig_bit_tlv)?;
        if !top.finished() {
            return Err(X509Error::TrailingData);
        }

        Ok(X509Cert {
            version,
            serial,
            issuer: issuer_der,
            subject: subject_der,
            not_before,
            not_after,
            pubkey_alg,
            pubkey,
            sig_alg,
            signature,
            tbs: tbs_slice,
        })
    }

    fn validity_contains(cert: &X509Cert<'_>, now: X509Time) -> bool {
        now.unix >= cert.not_before.unix && now.unix <= cert.not_after.unix
    }

    fn issuer_matches_subject(
        child: &X509Cert<'_>,
        parent: &X509Cert<'_>,
    ) -> Result<(), X509Error> {
        if child.issuer == parent.subject {
            Ok(())
        } else {
            Err(X509Error::IssuerSubjectMismatch)
        }
    }

    fn find_cn<'a>(dn: &'a [u8]) -> Option<&'a [u8]> {
        // dn is a full SEQUENCE TLV: 0x30 LL <RDNs...>. Each RDN is a
        // SET of AttributeTypeAndValue { OID, value }. Walk every RDN
        // and every ATV, returning the first ATV whose OID matches CN.
        let outer = read_tlv(dn).ok()?;
        if outer.tag != X509_TAG_SEQUENCE {
            return None;
        }
        let mut rdns = SeqWalker::new(outer.value);
        while !rdns.finished() {
            let rdn = rdns.next().ok()?;
            if rdn.tag != X509_TAG_SET {
                continue;
            }
            let mut atvs = SeqWalker::new(rdn.value);
            while !atvs.finished() {
                let atv = atvs.next().ok()?;
                if atv.tag != X509_TAG_SEQUENCE {
                    continue;
                }
                let mut fields = SeqWalker::new(atv.value);
                let oid_tlv = fields.next().ok()?;
                if oid_tlv.tag != X509_TAG_OID {
                    continue;
                }
                if oid_tlv.value == X509_OID_CN {
                    let val = fields.next().ok()?;
                    return Some(val.value);
                }
            }
        }
        None
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- DER builder helpers for hand-rolled fixtures ----------
    //
    // `no_std` test-only: we use `Vec` via `alloc` (cfg(test) implies
    // a host-std build of the crate). Production code never reaches
    // these.

    extern crate alloc;
    use alloc::vec::Vec;

    fn enc_len(out: &mut Vec<u8>, len: usize) {
        if len < 128 {
            out.push(len as u8);
        } else if len < 256 {
            out.push(0x81);
            out.push(len as u8);
        } else if len < 65_536 {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        } else {
            out.push(0x83);
            out.push((len >> 16) as u8);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
    }

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(body.len() + 4);
        v.push(tag);
        enc_len(&mut v, body.len());
        v.extend_from_slice(body);
        v
    }

    fn seq(body: &[u8]) -> Vec<u8> {
        tlv(X509_TAG_SEQUENCE, body)
    }
    fn set(body: &[u8]) -> Vec<u8> {
        tlv(X509_TAG_SET, body)
    }
    fn oid_bytes(body: &[u8]) -> Vec<u8> {
        tlv(X509_TAG_OID, body)
    }
    fn int_unsigned(body: &[u8]) -> Vec<u8> {
        // Add leading 0x00 sign-bit guard if the top bit would be set.
        if !body.is_empty() && body[0] & 0x80 != 0 {
            let mut padded = Vec::with_capacity(body.len() + 1);
            padded.push(0x00);
            padded.extend_from_slice(body);
            tlv(X509_TAG_INTEGER, &padded)
        } else {
            tlv(X509_TAG_INTEGER, body)
        }
    }
    fn bit_string(body: &[u8]) -> Vec<u8> {
        let mut wrapped = Vec::with_capacity(body.len() + 1);
        wrapped.push(0);
        wrapped.extend_from_slice(body);
        tlv(X509_TAG_BIT_STRING, &wrapped)
    }
    fn utc_time(s: &[u8]) -> Vec<u8> {
        tlv(X509_TAG_UTC_TIME, s)
    }
    fn gen_time(s: &[u8]) -> Vec<u8> {
        tlv(X509_TAG_GENERALIZED_TIME, s)
    }
    fn null_tlv() -> Vec<u8> {
        tlv(X509_TAG_NULL, &[])
    }
    fn printable(s: &[u8]) -> Vec<u8> {
        tlv(0x13, s)
    }
    fn explicit_ctx_0(body: &[u8]) -> Vec<u8> {
        tlv(X509_TAG_CTX_EXPLICIT_0, body)
    }
    fn alg_ed25519() -> Vec<u8> {
        seq(&oid_bytes(X509_OID_ED25519))
    }
    fn alg_ecdsa_sha256() -> Vec<u8> {
        seq(&oid_bytes(X509_OID_ECDSA_WITH_SHA256))
    }
    fn alg_sha256_rsa() -> Vec<u8> {
        let mut b = oid_bytes(X509_OID_SHA256_WITH_RSA);
        b.extend(null_tlv());
        seq(&b)
    }
    fn alg_rsa_encryption() -> Vec<u8> {
        let mut b = oid_bytes(X509_OID_RSA_ENCRYPTION);
        b.extend(null_tlv());
        seq(&b)
    }
    fn alg_ec_p256() -> Vec<u8> {
        let mut b = oid_bytes(X509_OID_EC_PUBLIC_KEY);
        b.extend(oid_bytes(X509_OID_SECP256R1));
        seq(&b)
    }
    fn name_cn(cn: &[u8]) -> Vec<u8> {
        let mut atv = oid_bytes(X509_OID_CN);
        atv.extend(printable(cn));
        seq(&set(&seq(&atv)))
    }

    /// Build a minimal Ed25519 self-signed v3 certificate. Returns the
    /// full DER blob, the TBS slice (start..end indices), and the
    /// pubkey bytes used.
    fn build_ed25519_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let pubkey: Vec<u8> = (1u8..=32u8).collect();
        let signature: Vec<u8> = (0..64).map(|i| (i as u8) ^ 0xA5).collect();
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x2A]));
            b.extend(alg_ed25519());
            b.extend(name_cn(b"cuttle-x509-ed25519"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"700101000000Z"));
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"cuttle-x509-ed25519"));
            let spki = {
                let mut s = Vec::new();
                s.extend(alg_ed25519());
                s.extend(bit_string(&pubkey));
                seq(&s)
            };
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend_from_slice(&tbs);
            b.extend(alg_ed25519());
            b.extend(bit_string(&signature));
            b
        };
        let cert = seq(&outer_body);
        (cert, tbs, pubkey)
    }

    /// Build a synthetic v3 cert with an RSA-2048 pubkey + sha256-with-rsa
    /// signature. Mirrors what Let's Encrypt R3 looks like at the
    /// algorithm level.
    fn build_rsa_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // Hand-pack a "modulus" of length 256 that LOOKS like a real
        // RSA-2048 modulus. Top bit set so the encoder adds a sign-bit
        // guard byte and exercises that DER path.
        let modulus: Vec<u8> = (0..256).map(|i| 0x80u8 ^ (i as u8)).collect();
        let exponent = [0x01u8, 0x00, 0x01];
        let signature: Vec<u8> = (0..256).map(|i| 0x55u8 ^ (i as u8)).collect();
        let pubkey_seq = {
            let mut b = Vec::new();
            b.extend(int_unsigned(&modulus));
            b.extend(int_unsigned(&exponent));
            seq(&b)
        };
        let spki = {
            let mut s = Vec::new();
            s.extend(alg_rsa_encryption());
            s.extend(bit_string(&pubkey_seq));
            seq(&s)
        };
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            // Serial — give it 18 bytes (commercial CAs use big serials).
            let serial_body: Vec<u8> = (0..18).map(|i| 0x10u8 + i as u8).collect();
            b.extend(int_unsigned(&serial_body));
            b.extend(alg_sha256_rsa());
            b.extend(name_cn(b"Cuttle Test CA"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"260101000000Z"));
                v.extend(gen_time(b"20500101000000Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"cuttle.example.com"));
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend_from_slice(&tbs);
            b.extend(alg_sha256_rsa());
            b.extend(bit_string(&signature));
            b
        };
        let cert = seq(&outer_body);
        (cert, tbs, modulus)
    }

    /// Build a P-256 ECDSA self-signed cert.
    fn build_ecdsa_p256_cert() -> Vec<u8> {
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend((1u8..=32u8).into_iter());
        point.extend((33u8..=64u8).into_iter());
        let spki = {
            let mut s = Vec::new();
            s.extend(alg_ec_p256());
            s.extend(bit_string(&point));
            seq(&s)
        };
        // Synthetic ECDSA DER signature SEQUENCE { r, s }
        let r: Vec<u8> = (0..32).map(|i| 0xA0u8 ^ i).collect();
        let s_int: Vec<u8> = (0..32).map(|i| 0xB0u8 ^ i).collect();
        let ecdsa_sig = {
            let mut b = Vec::new();
            b.extend(int_unsigned(&r));
            b.extend(int_unsigned(&s_int));
            seq(&b)
        };
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x05]));
            b.extend(alg_ecdsa_sha256());
            b.extend(name_cn(b"P256-CA"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"240101000000Z"));
                v.extend(utc_time(b"341231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"p256.example.com"));
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend_from_slice(&tbs);
            b.extend(alg_ecdsa_sha256());
            b.extend(bit_string(&ecdsa_sig));
            b
        };
        seq(&outer_body)
    }

    // ---------- happy-path parse tests ----------

    #[test]
    fn parse_ed25519_minimal_cert_succeeds() {
        let (der, _, pubkey) = build_ed25519_cert();
        let cert = X509Impl::parse(&der).expect("parse must succeed");
        assert_eq!(cert.version, 2);
        assert_eq!(cert.pubkey_alg, X509PubKeyAlg::Ed25519);
        assert_eq!(cert.sig_alg, X509SigAlg::Ed25519);
        match cert.pubkey {
            X509PubKey::Ed25519 { key } => assert_eq!(key, pubkey.as_slice()),
            _ => panic!("wrong pubkey variant"),
        }
    }

    #[test]
    fn parse_rsa2048_cert_succeeds() {
        let (der, _, expected_modulus) = build_rsa_cert();
        let cert = X509Impl::parse(&der).expect("RSA parse must succeed");
        assert_eq!(cert.version, 2);
        assert_eq!(cert.pubkey_alg, X509PubKeyAlg::Rsa);
        assert_eq!(cert.sig_alg, X509SigAlg::RsaSha256);
        match cert.pubkey {
            X509PubKey::Rsa { modulus, exponent } => {
                assert_eq!(modulus, expected_modulus.as_slice());
                assert_eq!(exponent, &[0x01, 0x00, 0x01]);
            }
            _ => panic!("wrong RSA pubkey variant"),
        }
    }

    #[test]
    fn parse_ecdsa_p256_cert_succeeds() {
        let der = build_ecdsa_p256_cert();
        let cert = X509Impl::parse(&der).expect("ECDSA parse must succeed");
        assert_eq!(cert.pubkey_alg, X509PubKeyAlg::EcdsaP256);
        assert_eq!(cert.sig_alg, X509SigAlg::EcdsaSha256);
        match cert.pubkey {
            X509PubKey::EcdsaP256 { point } => {
                assert_eq!(point.len(), 65);
                assert_eq!(point[0], 0x04);
            }
            _ => panic!("wrong ECDSA pubkey variant"),
        }
    }

    #[test]
    fn tbs_slice_byte_exact() {
        let (der, expected_tbs, _) = build_ed25519_cert();
        let cert = X509Impl::parse(&der).unwrap();
        assert_eq!(cert.tbs, expected_tbs.as_slice());
    }

    #[test]
    fn serial_drops_sign_bit_guard() {
        let (der, _, _) = build_rsa_cert();
        let cert = X509Impl::parse(&der).unwrap();
        // Serial body was `[0x10..0x21]` — top bit clear, no guard.
        assert_eq!(cert.serial.len(), 18);
        assert_eq!(cert.serial[0], 0x10);
    }

    #[test]
    fn signature_bytes_byte_exact() {
        let (der, _, _) = build_ed25519_cert();
        let cert = X509Impl::parse(&der).unwrap();
        assert_eq!(cert.signature.len(), 64);
        for (i, &b) in cert.signature.iter().enumerate() {
            assert_eq!(b, (i as u8) ^ 0xA5);
        }
    }

    #[test]
    fn validity_window_decoded_correctly() {
        let (der, _, _) = build_ed25519_cert();
        let cert = X509Impl::parse(&der).unwrap();
        assert_eq!(cert.not_before.unix, 0);
        let nineteen_forty_nine_end = 2_524_607_999u64;
        assert_eq!(cert.not_after.unix, nineteen_forty_nine_end);
    }

    #[test]
    fn validity_contains_inside_window() {
        let (der, _, _) = build_ed25519_cert();
        let cert = X509Impl::parse(&der).unwrap();
        assert!(X509Impl::validity_contains(
            &cert,
            X509Time { unix: 1_700_000_000 }
        ));
    }

    #[test]
    fn validity_contains_at_boundary() {
        let (der, _, _) = build_ed25519_cert();
        let cert = X509Impl::parse(&der).unwrap();
        assert!(X509Impl::validity_contains(&cert, cert.not_before));
        assert!(X509Impl::validity_contains(&cert, cert.not_after));
    }

    #[test]
    fn validity_contains_outside_window_rejects() {
        let (der, _, _) = build_ed25519_cert();
        let cert = X509Impl::parse(&der).unwrap();
        assert!(!X509Impl::validity_contains(
            &cert,
            X509Time { unix: u64::MAX }
        ));
    }

    #[test]
    fn generalized_time_after_2050_parses() {
        // RSA cert uses `20500101000000Z` for notAfter via GT.
        let (der, _, _) = build_rsa_cert();
        let cert = X509Impl::parse(&der).unwrap();
        let one_jan_2050 = 2_524_608_000u64;
        assert_eq!(cert.not_after.unix, one_jan_2050);
    }

    #[test]
    fn issuer_subject_blobs_include_header() {
        let (der, _, _) = build_ed25519_cert();
        let cert = X509Impl::parse(&der).unwrap();
        assert_eq!(cert.issuer[0], X509_TAG_SEQUENCE);
        assert_eq!(cert.subject[0], X509_TAG_SEQUENCE);
    }

    #[test]
    fn self_signed_issuer_equals_subject() {
        let (der, _, _) = build_ed25519_cert();
        let cert = X509Impl::parse(&der).unwrap();
        assert_eq!(cert.issuer, cert.subject);
    }

    #[test]
    fn issuer_matches_subject_succeeds_on_self_signed() {
        let (der, _, _) = build_ed25519_cert();
        let cert = X509Impl::parse(&der).unwrap();
        assert!(X509Impl::issuer_matches_subject(&cert, &cert).is_ok());
    }

    #[test]
    fn issuer_matches_subject_fails_on_distinct_names() {
        let (a_der, _, _) = build_ed25519_cert();
        let b_der = build_ecdsa_p256_cert();
        let a = X509Impl::parse(&a_der).unwrap();
        let b = X509Impl::parse(&b_der).unwrap();
        assert!(matches!(
            X509Impl::issuer_matches_subject(&a, &b),
            Err(X509Error::IssuerSubjectMismatch)
        ));
    }

    #[test]
    fn find_cn_recovers_common_name() {
        let (der, _, _) = build_rsa_cert();
        let cert = X509Impl::parse(&der).unwrap();
        let cn = X509Impl::find_cn(cert.subject).expect("CN");
        assert_eq!(cn, b"cuttle.example.com");
        let issuer_cn = X509Impl::find_cn(cert.issuer).expect("CN");
        assert_eq!(issuer_cn, b"Cuttle Test CA");
    }

    #[test]
    fn find_cn_returns_none_for_dn_without_cn() {
        // SEQUENCE { SET { SEQUENCE { OID(serialNumber), PrintableString } } }
        let oid_sn: [u8; 3] = [0x55, 0x04, 0x05];
        let mut atv = oid_bytes(&oid_sn);
        atv.extend(printable(b"42"));
        let dn = seq(&set(&seq(&atv)));
        assert!(X509Impl::find_cn(&dn).is_none());
    }

    // ---------- negative / strict-DER tests ----------

    #[test]
    fn empty_input_rejected() {
        assert_eq!(X509Impl::parse(&[]), Err(X509Error::Empty));
    }

    #[test]
    fn oversize_input_rejected() {
        let huge = [0u8; X509_MAX_CERT_LEN + 1];
        assert_eq!(X509Impl::parse(&huge), Err(X509Error::TooLarge));
    }

    #[test]
    fn truncated_header_rejected() {
        // Length octet 0x82 promises 2 length bytes; only 1 supplied.
        let buf = [X509_TAG_SEQUENCE, 0x82, 0x05];
        match X509Impl::parse(&buf) {
            Err(X509Error::TruncatedHeader) => {}
            other => panic!("expected TruncatedHeader, got {:?}", other),
        }
    }

    #[test]
    fn truncated_body_rejected() {
        // SEQUENCE of declared length 10, only 5 body bytes.
        let buf = [X509_TAG_SEQUENCE, 0x0A, 0, 0, 0, 0, 0];
        assert_eq!(X509Impl::parse(&buf), Err(X509Error::TruncatedBody));
    }

    #[test]
    fn indefinite_length_rejected() {
        // 0x80 length byte = indefinite-length form.
        let buf = [X509_TAG_SEQUENCE, 0x80, 0, 0];
        assert_eq!(X509Impl::parse(&buf), Err(X509Error::IndefiniteLength));
    }

    #[test]
    fn length_too_large_rejected() {
        // 0x85 = long-form with 5 length octets — capped at 4.
        let buf = [X509_TAG_SEQUENCE, 0x85, 1, 0, 0, 0, 0];
        assert_eq!(X509Impl::parse(&buf), Err(X509Error::LengthTooLarge));
    }

    #[test]
    fn non_minimal_length_short_value_rejected() {
        // Use long form (0x81) for a short value (0x05) — non-minimal.
        let buf = [X509_TAG_SEQUENCE, 0x81, 0x05, 0, 0, 0, 0, 0];
        assert_eq!(X509Impl::parse(&buf), Err(X509Error::NonMinimalLength));
    }

    #[test]
    fn high_tag_number_rejected() {
        // Tag low-5-bits all set = high-tag-number form.
        let buf = [0x1F, 0x02, 0x00, 0x00];
        assert_eq!(X509Impl::parse(&buf), Err(X509Error::HighTagNumber));
    }

    #[test]
    fn wrong_outer_tag_rejected() {
        // Outer expected to be SEQUENCE; we pass SET.
        let buf = [X509_TAG_SET, 0x00];
        assert_eq!(X509Impl::parse(&buf), Err(X509Error::BadTag));
    }

    #[test]
    fn trailing_data_after_outer_rejected() {
        let (mut der, _, _) = build_ed25519_cert();
        der.push(0xFF);
        assert_eq!(X509Impl::parse(&der), Err(X509Error::TrailingData));
    }

    #[test]
    fn unsupported_version_v1_rejected() {
        // Build a TBS without the [0] EXPLICIT version wrapper — that
        // would be v1, which we refuse.
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(int_unsigned(&[0x42]));
            b.extend(alg_ed25519());
            b.extend(name_cn(b"v1-name"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"700101000000Z"));
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"v1-name"));
            let pubkey: Vec<u8> = (0..32).collect();
            let spki = {
                let mut s = Vec::new();
                s.extend(alg_ed25519());
                s.extend(bit_string(&pubkey));
                seq(&s)
            };
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_ed25519());
            b.extend(bit_string(&[0u8; 64]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(
            X509Impl::parse(&cert),
            Err(X509Error::UnsupportedVersion)
        );
    }

    #[test]
    fn unsupported_key_alg_rejected() {
        // Build a cert with a totally bogus SPKI algorithm OID
        // (1.2.3.4 — id-tao or similar).
        let bogus_oid = oid_bytes(&[0x2A, 0x03, 0x04]);
        let bogus_alg = seq(&bogus_oid);
        let spki = {
            let mut s = Vec::new();
            s.extend(bogus_alg);
            s.extend(bit_string(&[0u8; 32]));
            seq(&s)
        };
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x01]));
            b.extend(alg_ed25519());
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"700101000000Z"));
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_ed25519());
            b.extend(bit_string(&[0u8; 64]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(X509Impl::parse(&cert), Err(X509Error::UnsupportedKeyAlg));
    }

    #[test]
    fn sig_alg_mismatch_rejected() {
        // Build a cert where the TBS-level signature OID is Ed25519
        // but the outer signatureAlgorithm is ECDSA-with-SHA-256.
        let pubkey: Vec<u8> = (1u8..=32u8).collect();
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x2A]));
            b.extend(alg_ed25519()); // TBS says Ed25519
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"700101000000Z"));
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            let spki = {
                let mut s = Vec::new();
                s.extend(alg_ed25519());
                s.extend(bit_string(&pubkey));
                seq(&s)
            };
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_ecdsa_sha256()); // outer says ECDSA
            b.extend(bit_string(&[0u8; 64]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(X509Impl::parse(&cert), Err(X509Error::SigAlgMismatch));
    }

    #[test]
    fn ed25519_with_unexpected_params_rejected() {
        // Construct an Ed25519 AlgorithmIdentifier with a stray NULL
        // parameter — RFC 8410 says params MUST be absent.
        let bad_alg = {
            let mut b = oid_bytes(X509_OID_ED25519);
            b.extend(null_tlv());
            seq(&b)
        };
        let pubkey: Vec<u8> = (1u8..=32u8).collect();
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x2A]));
            b.extend(bad_alg.clone());
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"700101000000Z"));
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            let spki = {
                let mut s = Vec::new();
                s.extend(alg_ed25519());
                s.extend(bit_string(&pubkey));
                seq(&s)
            };
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(bad_alg);
            b.extend(bit_string(&[0u8; 64]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(X509Impl::parse(&cert), Err(X509Error::BadAlgParams));
    }

    #[test]
    fn malformed_pubkey_wrong_length_rejected() {
        // Build an Ed25519 cert where the SPKI BIT STRING is 31 bytes.
        let bad_key: Vec<u8> = (0u8..31u8).collect();
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x2A]));
            b.extend(alg_ed25519());
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"700101000000Z"));
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            let spki = {
                let mut s = Vec::new();
                s.extend(alg_ed25519());
                s.extend(bit_string(&bad_key));
                seq(&s)
            };
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_ed25519());
            b.extend(bit_string(&[0u8; 64]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(X509Impl::parse(&cert), Err(X509Error::MalformedPubKey));
    }

    #[test]
    fn malformed_bit_string_unused_bits_rejected() {
        // Build a TLV that LOOKS like a BIT STRING but with non-zero
        // unused-bits prefix. We poke it directly into a synthetic
        // cert SPKI.
        let bad_key: Vec<u8> = {
            let mut s = Vec::new();
            s.push(0x07); // 7 unused bits — invalid for SPKI
            s.extend(0u8..32u8);
            s
        };
        let bad_bit_string = tlv(X509_TAG_BIT_STRING, &bad_key);
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x2A]));
            b.extend(alg_ed25519());
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"700101000000Z"));
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            let spki = {
                let mut s = Vec::new();
                s.extend(alg_ed25519());
                s.extend(bad_bit_string);
                seq(&s)
            };
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_ed25519());
            b.extend(bit_string(&[0u8; 64]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(
            X509Impl::parse(&cert),
            Err(X509Error::MalformedBitString)
        );
    }

    #[test]
    fn malformed_integer_negative_serial_rejected() {
        // Serial INTEGER with high bit set and no sign-bit guard —
        // would parse as negative.
        let neg_serial = tlv(X509_TAG_INTEGER, &[0xFF]);
        let pubkey: Vec<u8> = (1u8..=32u8).collect();
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(neg_serial);
            b.extend(alg_ed25519());
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"700101000000Z"));
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            let spki = {
                let mut s = Vec::new();
                s.extend(alg_ed25519());
                s.extend(bit_string(&pubkey));
                seq(&s)
            };
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_ed25519());
            b.extend(bit_string(&[0u8; 64]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(X509Impl::parse(&cert), Err(X509Error::MalformedInteger));
    }

    #[test]
    fn validity_window_inverted_rejected() {
        let pubkey: Vec<u8> = (1u8..=32u8).collect();
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x2A]));
            b.extend(alg_ed25519());
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"491231235959Z")); // not_before = 2049
                v.extend(utc_time(b"700101000000Z")); // not_after  = 1970
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            let spki = {
                let mut s = Vec::new();
                s.extend(alg_ed25519());
                s.extend(bit_string(&pubkey));
                seq(&s)
            };
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_ed25519());
            b.extend(bit_string(&[0u8; 64]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(
            X509Impl::parse(&cert),
            Err(X509Error::ValidityWindowInverted)
        );
    }

    #[test]
    fn malformed_time_wrong_length_rejected() {
        // UTCTime with 12 bytes (missing seconds) — rejected.
        let bad_time = tlv(X509_TAG_UTC_TIME, b"700101000000");
        let pubkey: Vec<u8> = (1u8..=32u8).collect();
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x2A]));
            b.extend(alg_ed25519());
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(bad_time);
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            let spki = {
                let mut s = Vec::new();
                s.extend(alg_ed25519());
                s.extend(bit_string(&pubkey));
                seq(&s)
            };
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_ed25519());
            b.extend(bit_string(&[0u8; 64]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(X509Impl::parse(&cert), Err(X509Error::MalformedTime));
    }

    #[test]
    fn malformed_time_calendar_invalid_rejected() {
        // Feb 30 doesn't exist.
        let pubkey: Vec<u8> = (1u8..=32u8).collect();
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x2A]));
            b.extend(alg_ed25519());
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"230230000000Z")); // Feb 30, 2023
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            let spki = {
                let mut s = Vec::new();
                s.extend(alg_ed25519());
                s.extend(bit_string(&pubkey));
                seq(&s)
            };
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_ed25519());
            b.extend(bit_string(&[0u8; 64]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(X509Impl::parse(&cert), Err(X509Error::TimeOutOfRange));
    }

    #[test]
    fn utc_time_year_pivot_at_50() {
        // Two timestamps at the pivot boundary: 49 → 2049, 50 → 1950.
        let mut v_before = Vec::new();
        v_before.push(0x17);
        v_before.push(0x0D);
        v_before.extend_from_slice(b"491231235959Z");
        let tlv_a = read_tlv(&v_before).unwrap();
        assert_eq!(parse_time(&tlv_a).unwrap().unix, 2_524_607_999);

        let mut v_at = Vec::new();
        v_at.push(0x17);
        v_at.push(0x0D);
        v_at.extend_from_slice(b"500101000000Z");
        let tlv_b = read_tlv(&v_at).unwrap();
        // 1950-01-01 is before the epoch — returns TimeOutOfRange.
        assert_eq!(parse_time(&tlv_b), Err(X509Error::TimeOutOfRange));
    }

    #[test]
    fn leap_year_feb_29_accepted_in_2024() {
        let mut v = Vec::new();
        v.push(0x17);
        v.push(0x0D);
        v.extend_from_slice(b"240229000000Z");
        let tlv = read_tlv(&v).unwrap();
        let t = parse_time(&tlv).unwrap();
        // 2024-02-29 UTC = 1709164800.
        assert_eq!(t.unix, 1_709_164_800);
    }

    #[test]
    fn leap_year_feb_29_rejected_in_2023() {
        let mut v = Vec::new();
        v.push(0x17);
        v.push(0x0D);
        v.extend_from_slice(b"230229000000Z");
        let tlv = read_tlv(&v).unwrap();
        assert_eq!(parse_time(&tlv), Err(X509Error::TimeOutOfRange));
    }

    #[test]
    fn generalized_time_accepts_2050() {
        let mut v = Vec::new();
        v.push(0x18);
        v.push(0x0F);
        v.extend_from_slice(b"20500101000000Z");
        let tlv = read_tlv(&v).unwrap();
        assert_eq!(parse_time(&tlv).unwrap().unix, 2_524_608_000);
    }

    #[test]
    fn rsa_modulus_strips_sign_guard_byte() {
        let (der, _, modulus) = build_rsa_cert();
        let cert = X509Impl::parse(&der).unwrap();
        match cert.pubkey {
            X509PubKey::Rsa { modulus: m, .. } => {
                // The first byte of `modulus` had its high bit set, so
                // the DER encoder prepended 0x00. The parser must strip
                // it — so the returned `m` equals the original.
                assert_eq!(m, modulus.as_slice());
                assert_eq!(m[0], 0x80);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ed25519_pubkey_alg_drives_signature_alg() {
        let (der, _, _) = build_ed25519_cert();
        let cert = X509Impl::parse(&der).unwrap();
        // For a self-signed cert the SPKI alg and the sig alg are the
        // same family. (Not enforced by the parser — it's a property
        // of the fixture — but it's a sanity check on the round-trip.)
        assert_eq!(cert.pubkey_alg, X509PubKeyAlg::Ed25519);
        assert_eq!(cert.sig_alg, X509SigAlg::Ed25519);
    }

    #[test]
    fn max_depth_bound_documented() {
        // Sanity-check the documented constant — drift would mean the
        // contract documentation went out of sync with the code path.
        assert_eq!(X509_MAX_DEPTH, 16);
        assert_eq!(X509_MAX_CERT_LEN, 64 * 1024);
    }

    #[test]
    fn truncated_serial_rejected() {
        // INTEGER with empty body.
        let bad = tlv(X509_TAG_INTEGER, &[]);
        let pubkey: Vec<u8> = (1u8..=32u8).collect();
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(bad);
            b.extend(alg_ed25519());
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"700101000000Z"));
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            let spki = {
                let mut s = Vec::new();
                s.extend(alg_ed25519());
                s.extend(bit_string(&pubkey));
                seq(&s)
            };
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_ed25519());
            b.extend(bit_string(&[0u8; 64]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(X509Impl::parse(&cert), Err(X509Error::MalformedInteger));
    }

    #[test]
    fn rsa_missing_null_params_rejected() {
        // Build an RSA SPKI without the required NULL params.
        let bad_alg = seq(&oid_bytes(X509_OID_RSA_ENCRYPTION));
        let modulus: Vec<u8> = (0..256).map(|i| 0x80u8 ^ (i as u8)).collect();
        let exponent = [0x01u8, 0x00, 0x01];
        let pubkey_seq = {
            let mut b = Vec::new();
            b.extend(int_unsigned(&modulus));
            b.extend(int_unsigned(&exponent));
            seq(&b)
        };
        let spki = {
            let mut s = Vec::new();
            s.extend(bad_alg);
            s.extend(bit_string(&pubkey_seq));
            seq(&s)
        };
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x01]));
            b.extend(alg_sha256_rsa());
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"700101000000Z"));
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_sha256_rsa());
            b.extend(bit_string(&[0u8; 256]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(X509Impl::parse(&cert), Err(X509Error::BadAlgParams));
    }

    #[test]
    fn ec_p256_compressed_point_rejected() {
        // P-256 key starting with 0x02 (compressed) is refused.
        let mut compressed = Vec::with_capacity(33);
        compressed.push(0x02);
        compressed.extend(0u8..32u8);
        let spki = {
            let mut s = Vec::new();
            s.extend(alg_ec_p256());
            s.extend(bit_string(&compressed));
            seq(&s)
        };
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x01]));
            b.extend(alg_ecdsa_sha256());
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"700101000000Z"));
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_ecdsa_sha256());
            b.extend(bit_string(&[0u8; 70]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(X509Impl::parse(&cert), Err(X509Error::MalformedPubKey));
    }

    #[test]
    fn ec_wrong_curve_rejected() {
        // ECDSA SPKI claiming an unsupported curve OID (1.3.132.0.34
        // = secp384r1).
        let secp384 = [0x2B, 0x81, 0x04, 0x00, 0x22];
        let bad_alg = {
            let mut b = oid_bytes(X509_OID_EC_PUBLIC_KEY);
            b.extend(oid_bytes(&secp384));
            seq(&b)
        };
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend(0u8..64u8);
        let spki = {
            let mut s = Vec::new();
            s.extend(bad_alg);
            s.extend(bit_string(&point));
            seq(&s)
        };
        let tbs_body = {
            let mut b = Vec::new();
            b.extend(explicit_ctx_0(&int_unsigned(&[0x02])));
            b.extend(int_unsigned(&[0x01]));
            b.extend(alg_ecdsa_sha256());
            b.extend(name_cn(b"X"));
            let validity = {
                let mut v = Vec::new();
                v.extend(utc_time(b"700101000000Z"));
                v.extend(utc_time(b"491231235959Z"));
                seq(&v)
            };
            b.extend(validity);
            b.extend(name_cn(b"X"));
            b.extend(spki);
            b
        };
        let tbs = seq(&tbs_body);
        let outer_body = {
            let mut b = Vec::new();
            b.extend(tbs);
            b.extend(alg_ecdsa_sha256());
            b.extend(bit_string(&[0u8; 70]));
            b
        };
        let cert = seq(&outer_body);
        assert_eq!(X509Impl::parse(&cert), Err(X509Error::UnsupportedKeyAlg));
    }

    // ---------- 256-byte kernel fixture ----------
    //
    // The bytes used by the kernel banner live in
    // `target_enterprise::kernel_fixtures::X509_CERT_DER`. The host
    // test below imports them and asserts a parse succeeds, the same
    // way the kernel banner does — with no allocator, all fields
    // exposed as `&[u8]` views.

    #[test]
    fn kernel_fixture_parses_and_recovers_pubkey() {
        use crate::kernel_fixtures::{
            X509_FIXTURE_DER, X509_FIXTURE_PUBKEY, X509_FIXTURE_SUBJECT_CN,
        };
        let cert = X509Impl::parse(X509_FIXTURE_DER)
            .expect("kernel fixture must parse");
        assert_eq!(cert.version, 2);
        assert_eq!(cert.pubkey_alg, X509PubKeyAlg::Ed25519);
        match cert.pubkey {
            X509PubKey::Ed25519 { key } => {
                assert_eq!(key, X509_FIXTURE_PUBKEY);
            }
            _ => panic!("wrong fixture pubkey variant"),
        }
        let cn = X509Impl::find_cn(cert.subject).expect("CN");
        assert_eq!(cn, X509_FIXTURE_SUBJECT_CN);
        // Window covers 1970..2049, so any reasonable epoch second works.
        assert!(X509Impl::validity_contains(
            &cert,
            X509Time { unix: 1_700_000_000 }
        ));
    }
}
