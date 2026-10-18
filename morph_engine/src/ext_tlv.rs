//! Attestation extension fields as TLV + Base64 (TASK-102 / schema v8).
//!
//! Every new attestation entry carries `ext_tlv_b64`: a Base64 (RFC 4648)
//! encoding of a three-tag TLV sequence:
//!
//! | tag | value |
//! |-----|--------|
//! | [`ATTEST_TLV_TAG_CYCLE`] | cycle number as little-endian `u64` |
//! | [`ATTEST_TLV_TAG_MODULE`] | module / bundle name UTF-8 bytes |
//! | [`ATTEST_TLV_TAG_SEED`] | first 8 bytes of `candidate_sha256` (hex-decoded) |
//!
//! Built with the same `AttestTlv` / `Base64` impls as the enterprise
//! target, so the factory and the morph target share one extension
//! surface. `verify-attest` re-decodes and checks tag count + cycle +
//! module agreement with the entry's JSON fields.

use anyhow::{bail, Context, Result};
use cuttle_contracts::{
    AttestTlv, Base64, ATTEST_TLV_TAG_CYCLE, ATTEST_TLV_TAG_MODULE, ATTEST_TLV_TAG_SEED,
};
use target_enterprise::attest_tlv::AttestTlvImpl;
use target_enterprise::base64::Base64Impl;

/// Expected number of TLVs in a well-formed extension blob.
pub const EXT_TLV_TAG_COUNT: usize = 3;

/// Build the default three-tag extension blob for a cycle accept/reject.
pub fn build_ext_tlv_b64(cycle: u64, module: &str, candidate_sha256_hex: &str) -> Result<String> {
    let mut raw = [0u8; 256];
    let mut pos = 0usize;

    let cycle_le = cycle.to_le_bytes();
    pos += AttestTlvImpl::encode(ATTEST_TLV_TAG_CYCLE, &cycle_le, &mut raw[pos..])
        .map_err(|e| anyhow::anyhow!("encode cycle TLV: {:?}", e))?;

    let mod_bytes = module.as_bytes();
    pos += AttestTlvImpl::encode(ATTEST_TLV_TAG_MODULE, mod_bytes, &mut raw[pos..])
        .map_err(|e| anyhow::anyhow!("encode module TLV: {:?}", e))?;

    let seed8 = first8_from_hex(candidate_sha256_hex)?;
    pos += AttestTlvImpl::encode(ATTEST_TLV_TAG_SEED, &seed8, &mut raw[pos..])
        .map_err(|e| anyhow::anyhow!("encode seed TLV: {:?}", e))?;

    let mut b64 = [0u8; 512];
    let n = Base64Impl::encode(&raw[..pos], &mut b64)
        .map_err(|e| anyhow::anyhow!("base64 encode ext tlv: {:?}", e))?;
    Ok(std::str::from_utf8(&b64[..n])
        .context("base64 ascii")?
        .to_string())
}

/// Decode + validate `ext_tlv_b64` against the entry's JSON fields.
pub fn verify_ext_tlv_b64(
    b64: &str,
    cycle: u64,
    module: &str,
    candidate_sha256_hex: &str,
) -> Result<()> {
    let mut raw = [0u8; 512];
    let n = Base64Impl::decode(b64.as_bytes(), &mut raw)
        .map_err(|e| anyhow::anyhow!("ext_tlv_b64: base64 decode failed: {:?}", e))?;
    let buf = &raw[..n];

    let count = AttestTlvImpl::count_sequence(buf)
        .map_err(|e| anyhow::anyhow!("ext_tlv_b64: TLV sequence parse: {:?}", e))?;
    if count != EXT_TLV_TAG_COUNT {
        bail!(
            "ext_tlv_b64: expected {} tags, got {}",
            EXT_TLV_TAG_COUNT,
            count
        );
    }

    // Walk tags in order: cycle, module, seed.
    let mut off = 0usize;
    // cycle
    {
        let rec = AttestTlvImpl::decode(&buf[off..])
            .map_err(|e| anyhow::anyhow!("ext_tlv_b64: cycle TLV: {:?}", e))?;
        if rec.tag != ATTEST_TLV_TAG_CYCLE {
            bail!("ext_tlv_b64: first tag want CYCLE got {}", rec.tag);
        }
        if rec.value_len != 8 {
            bail!("ext_tlv_b64: cycle value len {}", rec.value_len);
        }
        let v = &buf[off + rec.value_off..off + rec.value_off + 8];
        let got = u64::from_le_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]]);
        if got != cycle {
            bail!("ext_tlv_b64: cycle {} != entry.cycle {}", got, cycle);
        }
        off += 4 + rec.value_len;
    }
    // module
    {
        let rec = AttestTlvImpl::decode(&buf[off..])
            .map_err(|e| anyhow::anyhow!("ext_tlv_b64: module TLV: {:?}", e))?;
        if rec.tag != ATTEST_TLV_TAG_MODULE {
            bail!("ext_tlv_b64: second tag want MODULE got {}", rec.tag);
        }
        let v = &buf[off + rec.value_off..off + rec.value_off + rec.value_len];
        if v != module.as_bytes() {
            bail!("ext_tlv_b64: module bytes mismatch entry.module");
        }
        off += 4 + rec.value_len;
    }
    // seed
    {
        let rec = AttestTlvImpl::decode(&buf[off..])
            .map_err(|e| anyhow::anyhow!("ext_tlv_b64: seed TLV: {:?}", e))?;
        if rec.tag != ATTEST_TLV_TAG_SEED {
            bail!("ext_tlv_b64: third tag want SEED got {}", rec.tag);
        }
        let expect = first8_from_hex(candidate_sha256_hex)?;
        let v = &buf[off + rec.value_off..off + rec.value_off + rec.value_len];
        if v != expect {
            bail!("ext_tlv_b64: seed prefix mismatch candidate_sha256");
        }
    }

    Ok(())
}

fn first8_from_hex(hex: &str) -> Result<[u8; 8]> {
    let h = hex.trim();
    if h.len() < 16 {
        bail!(
            "candidate_sha256 too short for 8-byte seed prefix (len={})",
            h.len()
        );
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        let s = &h[i * 2..i * 2 + 2];
        out[i] = u8::from_str_radix(s, 16)
            .with_context(|| format!("hex byte at offset {}", i))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ok() {
        let b64 = build_ext_tlv_b64(
            42,
            "kernel",
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8",
        )
        .unwrap();
        verify_ext_tlv_b64(
            &b64,
            42,
            "kernel",
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8",
        )
        .unwrap();
    }

    #[test]
    fn rejects_cycle_mismatch() {
        let b64 = build_ext_tlv_b64(
            1,
            "lib",
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8",
        )
        .unwrap();
        assert!(verify_ext_tlv_b64(
            &b64,
            2,
            "lib",
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8",
        )
        .is_err());
    }

    #[test]
    fn rejects_bad_b64() {
        assert!(verify_ext_tlv_b64(
            "!!!",
            1,
            "lib",
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8",
        )
        .is_err());
    }

    #[test]
    fn det() {
        let a = build_ext_tlv_b64(
            7,
            "m",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        let b = build_ext_tlv_b64(
            7,
            "m",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        assert_eq!(a, b);
    }
}
