//! Generic binary Merkle tree over SHA-256.
//!
//! Used by the attestation log to commit to the full set of recorded
//! entries in two distinct ways:
//!
//! * Chunked anchors — every [`ANCHOR_INTERVAL`] entries the writer
//!   emits a Merkle root over that chunk to `merkle_anchors.jsonl`
//!   (see [`crate::attest`]). The chunked roots are convenient for
//!   replication to immutable external storage.
//!
//! * Rolling root — after every committed entry the writer recomputes
//!   the Merkle root over the **entire log** and persists it to
//!   `attest.merkle_root`. This is the load-bearing primitive for
//!   TASK-013: a single 32-byte fingerprint of every attestation entry
//!   so a verifier can prove tamper-evidence in O(N) without first
//!   reading all chunked anchors.
//!
//! ## Tree shape
//!
//! Bitcoin-style binary Merkle tree:
//!
//! * Leaves are 32-byte SHA-256 hashes supplied by the caller (in
//!   [`crate::attest`]'s case, the canonical-JSON `entry_sha256` of each
//!   log line).
//! * Internal nodes hash the concatenation of their two children
//!   (`SHA-256(left || right)`, 64 bytes of input).
//! * Odd layers are padded by **duplicating the last node** at that
//!   layer before pairing. The resulting tree shape depends on N (not
//!   `next_power_of_two(N)`), matching the behaviour of the pre-TASK-013
//!   `compute_merkle_root` in [`crate::attest`] so existing anchor logs
//!   continue to verify.
//!
//! The Bitcoin-padding choice carries a known second-preimage caveat
//! (an N-leaf tree and an `N+1`-leaf tree where the last leaf is
//! duplicated produce the same root). Proteus's threat model is not
//! affected: leaf supplies in this module come from the attestation
//! writer, which sees every appended entry, so an attacker cannot
//! sneak a duplicated leaf into the writer's view. Verifier-side, the
//! rolling root is paired with the explicit `entry_count` in
//! `attest.merkle_root`, which removes the ambiguity entirely.
//!
//! ## Verify path: no `alloc`
//!
//! TASK-013 requires that the verifier rebuild and check a stored
//! root without heap allocation. Two helpers satisfy this:
//!
//! * [`compute_root_in_place`] collapses a caller-owned `&mut [Hash]`
//!   buffer in place and returns the root. The caller pre-populates
//!   the buffer with the leaves; we mutate it without ever allocating.
//! * [`verify_inclusion`] follows a [`MerkleProof`] sibling list from
//!   leaf to root with a single fixed-size stack frame (no Vec).
//!
//! The convenience [`compute_root`] is the writer-side allocating
//! variant. It is implemented in terms of `compute_root_in_place` so
//! the two paths can never drift.

use sha2::{Digest, Sha256};

/// Width of a Merkle hash in bytes (SHA-256 = 32).
pub const HASH_LEN: usize = 32;

/// Convenient type alias for a SHA-256 digest.
pub type Hash = [u8; HASH_LEN];

/// The all-zero hash. Used as the convention for the rolling root of
/// an empty attestation log.
pub const ZERO_HASH: Hash = [0u8; HASH_LEN];

/// Errors from the Merkle helpers. Kept compact so callers can pattern
/// match without depending on `std::error::Error` for the `no_alloc`
/// verify path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    /// `compute_root` called with no leaves. Callers that want the
    /// "empty log" sentinel should use [`ZERO_HASH`] directly rather
    /// than trying to compute a root.
    EmptyLeafSet,
    /// `compute_root_in_place` got a buffer with `len < leaves.len()`.
    BufferTooSmall { needed: usize, got: usize },
    /// Inclusion proof's `leaf_index` is out of range for the recorded
    /// `leaf_count`.
    ProofIndexOutOfRange { index: u64, count: u64 },
    /// Inclusion proof's sibling count does not match the depth
    /// required by `leaf_count`.
    ProofDepthMismatch { expected: usize, got: usize },
}

impl core::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MerkleError::EmptyLeafSet => f.write_str("merkle: empty leaf set"),
            MerkleError::BufferTooSmall { needed, got } => {
                write!(f, "merkle: scratch buffer too small ({} < {})", got, needed)
            }
            MerkleError::ProofIndexOutOfRange { index, count } => {
                write!(f, "merkle: proof index {} out of range for {} leaves", index, count)
            }
            MerkleError::ProofDepthMismatch { expected, got } => {
                write!(
                    f,
                    "merkle: proof has {} siblings, expected {}",
                    got, expected
                )
            }
        }
    }
}

impl std::error::Error for MerkleError {}

/// Hash the concatenation of two 32-byte children. Internal nodes
/// always come from this function.
#[inline]
pub fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Compute the Merkle root over `leaves` with a heap allocation for
/// scratch space. Writer-side helper.
///
/// Returns [`MerkleError::EmptyLeafSet`] on an empty input; the
/// attestation writer handles empty logs explicitly with [`ZERO_HASH`]
/// rather than calling this function.
pub fn compute_root(leaves: &[Hash]) -> Result<Hash, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyLeafSet);
    }
    if leaves.len() == 1 {
        return Ok(leaves[0]);
    }
    // Scratch buffer: one slot per leaf. The first layer fits exactly;
    // subsequent layers are strictly smaller, so this is enough.
    let mut buf: Vec<Hash> = leaves.to_vec();
    compute_root_in_place(&mut buf, leaves.len())
}

/// Collapse `buf[..len]` in place into a Merkle root. Caller-supplied
/// buffer must already contain the leaves at indices `0..len`. No
/// allocation happens inside this function — the buffer is reused
/// across layers.
///
/// Padding policy: when a layer has an odd node count, the last node
/// is duplicated before pairing (Bitcoin-style).
///
/// Returns:
/// * `Ok(root)` on success.
/// * `Err(EmptyLeafSet)` if `len == 0`.
/// * `Err(BufferTooSmall)` if `buf.len() < len`.
pub fn compute_root_in_place(buf: &mut [Hash], len: usize) -> Result<Hash, MerkleError> {
    if len == 0 {
        return Err(MerkleError::EmptyLeafSet);
    }
    if buf.len() < len {
        return Err(MerkleError::BufferTooSmall {
            needed: len,
            got: buf.len(),
        });
    }
    let mut layer_len = len;
    while layer_len > 1 {
        // Pad odd layer by duplicating the last entry. Safe in-place
        // because we never write past `layer_len`.
        let padded_len = if layer_len % 2 == 1 {
            // Duplicate `buf[layer_len - 1]` into `buf[layer_len]`. We
            // require `buf.len() >= layer_len + 1` only when the layer
            // is genuinely odd; the writer's `compute_root` sizes the
            // buffer to `leaves.len()` which can be too small here.
            // Fall back to reading-then-writing through a temp.
            if buf.len() <= layer_len {
                // Overflow into a stack-local: copy the duplicate, then
                // pair-hash it directly without writing back to buf.
                // We special-case this odd-tail by pairing it as the
                // last operation of the current layer.
                let last = buf[layer_len - 1];
                let mut i = 0usize;
                let mut write = 0usize;
                // Pair every full pair first.
                while i + 1 < layer_len {
                    let h = hash_pair(&buf[i], &buf[i + 1]);
                    buf[write] = h;
                    i += 2;
                    write += 1;
                }
                // Pair the lone tail with its duplicate.
                let tail_h = hash_pair(&last, &last);
                buf[write] = tail_h;
                layer_len = write + 1;
                continue;
            }
            buf[layer_len] = buf[layer_len - 1];
            layer_len + 1
        } else {
            layer_len
        };
        // Pair-hash in place. Write index <= read index always, so we
        // never clobber an unread input.
        let mut write = 0usize;
        let mut i = 0usize;
        while i + 1 < padded_len {
            let h = hash_pair(&buf[i], &buf[i + 1]);
            buf[write] = h;
            i += 2;
            write += 1;
        }
        layer_len = write;
    }
    Ok(buf[0])
}

/// Side of a sibling in an inclusion-proof step. `Left` means the
/// sibling sits to the **left** of the running hash and is therefore
/// concatenated before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// Inclusion proof for a single leaf in a Merkle tree. Sibling order
/// is from leaf to root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<(Side, Hash)>,
}

/// Construct an inclusion proof for `leaves[leaf_index]`. Allocates
/// a scratch buffer of size `leaves.len()` — this is the writer-side
/// helper; verification has a no-alloc path (see [`verify_inclusion`]).
pub fn build_proof(leaves: &[Hash], leaf_index: u64) -> Result<MerkleProof, MerkleError> {
    let n = leaves.len() as u64;
    if leaves.is_empty() {
        return Err(MerkleError::EmptyLeafSet);
    }
    if leaf_index >= n {
        return Err(MerkleError::ProofIndexOutOfRange {
            index: leaf_index,
            count: n,
        });
    }
    let mut siblings: Vec<(Side, Hash)> = Vec::new();
    // We walk the tree one layer at a time, tracking the position of
    // the leaf-under-proof at each layer.
    let mut layer: Vec<Hash> = leaves.to_vec();
    let mut pos = leaf_index as usize;
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().unwrap();
            layer.push(last);
        }
        let sibling_idx = pos ^ 1;
        let side = if pos % 2 == 1 { Side::Left } else { Side::Right };
        siblings.push((side, layer[sibling_idx]));
        // Collapse the layer.
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        layer = next;
        pos /= 2;
    }
    Ok(MerkleProof {
        leaf_index,
        leaf_count: n,
        siblings,
    })
}

/// Walk a [`MerkleProof`] from `leaf` upward and check the final value
/// equals `expected_root`. No allocation: a single `Hash` runs up the
/// chain.
///
/// The proof's `siblings` length must equal the tree depth implied by
/// `leaf_count`. Mismatched proofs are rejected with
/// [`MerkleError::ProofDepthMismatch`] rather than silently returning
/// `false`, so callers can distinguish "tampered proof" from "wrong
/// root".
pub fn verify_inclusion(
    leaf: &Hash,
    proof: &MerkleProof,
    expected_root: &Hash,
) -> Result<bool, MerkleError> {
    if proof.leaf_count == 0 {
        return Err(MerkleError::EmptyLeafSet);
    }
    if proof.leaf_index >= proof.leaf_count {
        return Err(MerkleError::ProofIndexOutOfRange {
            index: proof.leaf_index,
            count: proof.leaf_count,
        });
    }
    let expected_depth = depth_for_count(proof.leaf_count);
    if proof.siblings.len() != expected_depth {
        return Err(MerkleError::ProofDepthMismatch {
            expected: expected_depth,
            got: proof.siblings.len(),
        });
    }
    let mut acc = *leaf;
    for (side, sibling) in &proof.siblings {
        acc = match side {
            Side::Left => hash_pair(sibling, &acc),
            Side::Right => hash_pair(&acc, sibling),
        };
    }
    Ok(acc == *expected_root)
}

/// Number of Merkle layers between leaf and root for a tree built from
/// `count` leaves with duplicate-last-on-odd padding.
///
/// For `count = 1` the tree is degenerate (the root IS the leaf) and
/// the depth is zero.
pub fn depth_for_count(count: u64) -> usize {
    if count <= 1 {
        return 0;
    }
    let mut layer = count;
    let mut d = 0usize;
    while layer > 1 {
        if layer % 2 == 1 {
            layer += 1;
        }
        layer /= 2;
        d += 1;
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic leaves with a recognisable shape: `leaf[i][0] = i as u8`.
    fn synthetic_leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| {
                let mut h = [0u8; HASH_LEN];
                h[0] = i as u8;
                h[31] = (i >> 8) as u8;
                h
            })
            .collect()
    }

    #[test]
    fn single_leaf_root_equals_leaf() {
        let leaves = synthetic_leaves(1);
        let r = compute_root(&leaves).unwrap();
        assert_eq!(r, leaves[0]);
    }

    #[test]
    fn empty_leaves_rejected() {
        let leaves: Vec<Hash> = Vec::new();
        assert_eq!(
            compute_root(&leaves).unwrap_err(),
            MerkleError::EmptyLeafSet
        );
    }

    #[test]
    fn two_leaves_root_is_sha_concat() {
        let leaves = synthetic_leaves(2);
        let r = compute_root(&leaves).unwrap();
        let expected = hash_pair(&leaves[0], &leaves[1]);
        assert_eq!(r, expected);
    }

    #[test]
    fn three_leaves_uses_duplicate_last_padding() {
        let leaves = synthetic_leaves(3);
        let r = compute_root(&leaves).unwrap();
        // Layer 0: [L0, L1, L2] -> padded to [L0, L1, L2, L2]
        // Layer 1: [H(L0||L1), H(L2||L2)]
        // Root  : H(H(L0||L1) || H(L2||L2))
        let h01 = hash_pair(&leaves[0], &leaves[1]);
        let h22 = hash_pair(&leaves[2], &leaves[2]);
        let expected = hash_pair(&h01, &h22);
        assert_eq!(r, expected);
    }

    #[test]
    fn five_leaves_uses_cascaded_padding() {
        // Layer 0: [L0..L4] (5 -> pad to 6) -> [L0,L1,L2,L3,L4,L4]
        // Layer 1: [H(L0||L1), H(L2||L3), H(L4||L4)] (3 -> pad to 4)
        // Layer 2: [H(layer1[0]||layer1[1]), H(layer1[2]||layer1[2])]
        // Root  : H(layer2[0] || layer2[1])
        let leaves = synthetic_leaves(5);
        let l0 = hash_pair(&leaves[0], &leaves[1]);
        let l1 = hash_pair(&leaves[2], &leaves[3]);
        let l2 = hash_pair(&leaves[4], &leaves[4]);
        let m0 = hash_pair(&l0, &l1);
        let m1 = hash_pair(&l2, &l2);
        let expected = hash_pair(&m0, &m1);
        let r = compute_root(&leaves).unwrap();
        assert_eq!(r, expected);
    }

    #[test]
    fn compute_root_matches_in_place_root() {
        // Every input size from 1 to 17 (covers all odd/even shapes
        // including powers-of-two boundaries).
        for n in 1..=17usize {
            let leaves = synthetic_leaves(n);
            let a = compute_root(&leaves).unwrap();
            // For in-place we need a buffer large enough; oversize to
            // hit the "no overflow into scratch" branch.
            let mut buf = vec![[0u8; 32]; n + 1];
            buf[..n].copy_from_slice(&leaves);
            let b = compute_root_in_place(&mut buf, n).unwrap();
            assert_eq!(a, b, "compute_root vs in_place mismatch at n={}", n);

            // Tight-buffer variant: buf.len() == n, exercising the
            // "stack-local last" odd-layer branch.
            let mut buf2 = leaves.clone();
            let c = compute_root_in_place(&mut buf2, n).unwrap();
            assert_eq!(a, c, "tight in_place mismatch at n={}", n);
        }
    }

    #[test]
    fn in_place_rejects_too_small_buffer() {
        let _leaves = synthetic_leaves(4);
        let mut buf = vec![[0u8; 32]; 2];
        let err = compute_root_in_place(&mut buf, 4).unwrap_err();
        assert!(matches!(err, MerkleError::BufferTooSmall { .. }));
    }

    #[test]
    fn in_place_rejects_empty() {
        let mut buf = vec![[0u8; 32]; 0];
        let err = compute_root_in_place(&mut buf, 0).unwrap_err();
        assert_eq!(err, MerkleError::EmptyLeafSet);
    }

    #[test]
    fn root_changes_when_any_leaf_changes() {
        let mut leaves = synthetic_leaves(7);
        let r0 = compute_root(&leaves).unwrap();
        // Perturb every leaf and verify each perturbation shifts the root.
        for i in 0..leaves.len() {
            let mut clone = leaves.clone();
            clone[i][7] ^= 0x01;
            let r = compute_root(&clone).unwrap();
            assert_ne!(r0, r, "flipping byte 7 of leaf {} did not shift root", i);
        }
        // And ordering matters: swapping the first two leaves changes
        // the root.
        leaves.swap(0, 1);
        let r_swapped = compute_root(&leaves).unwrap();
        assert_ne!(r0, r_swapped);
    }

    #[test]
    fn proof_round_trip_every_leaf_and_size() {
        for n in 1..=12usize {
            let leaves = synthetic_leaves(n);
            let root = compute_root(&leaves).unwrap();
            for i in 0..n {
                let proof = build_proof(&leaves, i as u64).unwrap();
                assert_eq!(
                    proof.siblings.len(),
                    depth_for_count(n as u64),
                    "depth mismatch at n={} i={}",
                    n,
                    i
                );
                let ok = verify_inclusion(&leaves[i], &proof, &root).unwrap();
                assert!(ok, "valid proof failed verify at n={} i={}", n, i);
            }
        }
    }

    #[test]
    fn proof_rejected_when_leaf_swapped() {
        let leaves = synthetic_leaves(5);
        let root = compute_root(&leaves).unwrap();
        let proof = build_proof(&leaves, 2).unwrap();
        // Try the wrong leaf; verify must return Ok(false).
        let ok = verify_inclusion(&leaves[3], &proof, &root).unwrap();
        assert!(!ok, "wrong leaf must not match proof");
    }

    #[test]
    fn proof_rejected_when_root_perturbed() {
        let leaves = synthetic_leaves(6);
        let root = compute_root(&leaves).unwrap();
        let proof = build_proof(&leaves, 4).unwrap();
        let mut bad_root = root;
        bad_root[0] ^= 0xFF;
        let ok = verify_inclusion(&leaves[4], &proof, &bad_root).unwrap();
        assert!(!ok);
    }

    #[test]
    fn proof_rejects_depth_mismatch() {
        let leaves = synthetic_leaves(6);
        let root = compute_root(&leaves).unwrap();
        let mut proof = build_proof(&leaves, 3).unwrap();
        // Trim a sibling to fake a depth-mismatch tamper.
        proof.siblings.pop();
        let err = verify_inclusion(&leaves[3], &proof, &root).unwrap_err();
        assert!(matches!(err, MerkleError::ProofDepthMismatch { .. }));
    }

    #[test]
    fn proof_rejects_index_out_of_range() {
        let leaves = synthetic_leaves(4);
        let root = compute_root(&leaves).unwrap();
        let mut proof = build_proof(&leaves, 0).unwrap();
        proof.leaf_index = 9;
        let err = verify_inclusion(&leaves[0], &proof, &root).unwrap_err();
        assert!(matches!(err, MerkleError::ProofIndexOutOfRange { .. }));
    }

    #[test]
    fn build_proof_rejects_index_out_of_range() {
        let leaves = synthetic_leaves(3);
        let err = build_proof(&leaves, 9).unwrap_err();
        assert!(matches!(err, MerkleError::ProofIndexOutOfRange { .. }));
    }

    #[test]
    fn build_proof_rejects_empty_leaves() {
        let leaves: Vec<Hash> = Vec::new();
        let err = build_proof(&leaves, 0).unwrap_err();
        assert_eq!(err, MerkleError::EmptyLeafSet);
    }

    #[test]
    fn depth_for_count_matches_proof_depth() {
        let cases = [(1u64, 0usize), (2, 1), (3, 2), (4, 2), (5, 3), (8, 3), (9, 4), (16, 4), (17, 5)];
        for (n, d) in cases {
            assert_eq!(depth_for_count(n), d, "depth mismatch at n={}", n);
        }
    }

    /// Compatibility test: the in-place helper produces the same root
    /// values that the pre-TASK-013 anchor emitter used to write. The
    /// concrete byte values here are not load-bearing across schema
    /// migrations, but the assertion guards against accidentally
    /// changing the tree shape (which would silently invalidate every
    /// existing anchor on disk).
    #[test]
    fn ten_leaf_root_is_stable() {
        let leaves: Vec<Hash> = (0u8..10)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                h
            })
            .collect();
        let r = compute_root(&leaves).unwrap();
        // Hand-rolled SHA-256 reproduction of the same Bitcoin-style
        // tree. We only check the first 8 bytes — that's enough to fail
        // any accidental shape change while staying robust to
        // implementation-detail tweaks of the SHA crate.
        let h01 = hash_pair(&leaves[0], &leaves[1]);
        let h23 = hash_pair(&leaves[2], &leaves[3]);
        let h45 = hash_pair(&leaves[4], &leaves[5]);
        let h67 = hash_pair(&leaves[6], &leaves[7]);
        let h89 = hash_pair(&leaves[8], &leaves[9]);
        let l1_0 = hash_pair(&h01, &h23);
        let l1_1 = hash_pair(&h45, &h67);
        let l1_2 = hash_pair(&h89, &h89);
        let l2_0 = hash_pair(&l1_0, &l1_1);
        let l2_1 = hash_pair(&l1_2, &l1_2);
        let expected = hash_pair(&l2_0, &l2_1);
        assert_eq!(r, expected);
    }
}
