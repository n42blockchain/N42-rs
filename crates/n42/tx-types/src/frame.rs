// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Frames: the ingest's unit of transactions (500 at the bench tier), named
//! by a binary Merkle root over their transactions' hashes.
//!
//! `docs/BREAKTHROUGH_DESIGN.md` step 1. Every node receives the same frames
//! and computes each frame's root once, at admission; the root is the
//! frame's id. A frame-aligned block's transactions root is the same binary
//! Merkle construction over its frames' roots ([`frame_tree_root`]), so a
//! follower that holds the frames checks a 163,000-transaction body with a
//! ~326-leaf tree instead of a 163,000-leaf trie.
//!
//! The construction ([`binary_merkle_root`]):
//! - the empty list is `keccak256("")`;
//! - a single node is its own root;
//! - otherwise each level pairs neighbours as `keccak256(left || right)`,
//!   an odd last node paired with itself (`keccak256(last || last)`), until
//!   one node is left.

use alloy_primitives::{keccak256, B256};

/// The binary Merkle root over `leaves`, keccak256 throughout; see the
/// module documentation for the rule.
pub fn binary_merkle_root(leaves: &[B256]) -> B256 {
    match leaves {
        [] => keccak256([]),
        [only] => *only,
        _ => {
            let mut level: Vec<B256> = leaves.to_vec();
            let mut pair = [0u8; 64];
            while level.len() > 1 {
                let mut next = Vec::with_capacity(level.len().div_ceil(2));
                for chunk in level.chunks(2) {
                    let left = chunk[0];
                    let right = chunk.get(1).copied().unwrap_or(left);
                    pair[..32].copy_from_slice(left.as_slice());
                    pair[32..].copy_from_slice(right.as_slice());
                    next.push(keccak256(pair));
                }
                level = next;
            }
            level[0]
        }
    }
}

/// A frame's root, and so its id: the binary Merkle root over its
/// transactions' hashes in frame order.
///
/// A block whose last frame is truncated to a prefix roots that frame over
/// the prefix's hashes alone -- `frame_root(&hashes[..prefix])` -- which is
/// not the frame's id; the id still names the whole frame.
pub fn frame_root(tx_hashes: &[B256]) -> B256 {
    binary_merkle_root(tx_hashes)
}

/// A frame-aligned block's transactions root: the binary Merkle root over
/// its frames' roots, in block order (the last one over the prefix it
/// carries, see [`frame_root`]).
pub fn frame_tree_root(frame_roots: &[B256]) -> B256 {
    binary_merkle_root(frame_roots)
}

/// The frame tree over a body laid out as frames: `layout` is each frame's
/// length in the body, in order. `None` when the layout does not cover the
/// body exactly or names an empty frame, i.e. the body is not frame-aligned
/// by that layout.
pub fn frame_tree_root_of(tx_hashes: &[B256], layout: &[usize]) -> Option<B256> {
    if layout.iter().any(|len| *len == 0) || layout.iter().sum::<usize>() != tx_hashes.len() {
        return None;
    }
    let mut at = 0usize;
    let mut roots = Vec::with_capacity(layout.len());
    for len in layout {
        roots.push(frame_root(&tx_hashes[at..at + len]));
        at += len;
    }
    Some(frame_tree_root(&roots))
}

/// `N42_FRAME_BLOCKS=1`, read once: this node builds, describes and checks
/// frame-aligned blocks (phase B of step 1). Meaningful only on a chain whose
/// genesis sets `frameBlocks`; the execution layer refuses to start with it
/// on any other.
pub fn frame_blocks_requested() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FRAME_BLOCKS").is_ok_and(|v| v == "1"))
}

// ---------------------------------------------------------------------------
// Attested frames (`docs/BREAKTHROUGH_DESIGN.md` step 2): verification paid
// once, at the edge.
//
// The ingress that assembles a frame (a gateway; the flood on the bench)
// verifies its transactions' signatures once and signs the frame's root. A
// node that trusts at least `min` distinct configured gateways admits a frame
// carrying their valid attestations without verifying its transactions.
//
// SAFETY OF THE TRUST: an attested frame's transactions are taken to be
// validly signed on the gateways' word; nothing at the node checks them. The
// attestation covers the frame root, i.e. every transaction's hash (and so
// its signature bytes), in frame order -- not any sender a frame claims on
// the side, which stays a claim. With `min` = f+1 over a gateway set of which
// at most f are faulty, the f+1 signatures include an honest gateway's, and
// an honest gateway signs only frames whose signatures it verified: the same
// bound the consensus already assumes. With `min` = 1 (the bench: one
// gateway, the flood itself) the node trusts that one gateway entirely.
// A frame with fewer valid attestations is verified as any other, never
// dropped for it.
// ---------------------------------------------------------------------------

/// The domain an attestation's message starts with.
pub const FRAME_ATTEST_DOMAIN: &[u8] = b"n42-frame-attest";

/// Bytes one attestation takes on the wire: the gateway's 32-byte Ed25519
/// public key, then its 64-byte signature.
pub const FRAME_ATTESTATION_LEN: usize = 96;

/// Most attestations a frame may carry; bounds what a node reads.
pub const MAX_FRAME_ATTESTATIONS: usize = 16;

/// What a gateway signs for a frame:
/// `keccak256("n42-frame-attest" || chain_id as u64 big-endian || frame_root)`.
pub fn frame_attest_message(chain_id: u64, root: B256) -> B256 {
    let mut buf = [0u8; 16 + 8 + 32];
    buf[..16].copy_from_slice(FRAME_ATTEST_DOMAIN);
    buf[16..24].copy_from_slice(&chain_id.to_be_bytes());
    buf[24..].copy_from_slice(root.as_slice());
    keccak256(buf)
}

/// One gateway's attestation of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameAttestation {
    /// The gateway's Ed25519 public key.
    pub gateway: [u8; 32],
    /// Its Ed25519 signature over [`frame_attest_message`].
    pub signature: [u8; 64],
}

impl FrameAttestation {
    /// Signs the frame with root `root` on chain `chain_id` as `key`.
    pub fn sign(key: &ed25519_dalek::SigningKey, chain_id: u64, root: B256) -> Self {
        use ed25519_dalek::Signer;
        let message = frame_attest_message(chain_id, root);
        Self { gateway: key.verifying_key().to_bytes(), signature: key.sign(message.as_slice()).to_bytes() }
    }

    /// The wire bytes: gateway key, then signature.
    pub fn to_bytes(&self) -> [u8; FRAME_ATTESTATION_LEN] {
        let mut out = [0u8; FRAME_ATTESTATION_LEN];
        out[..32].copy_from_slice(&self.gateway);
        out[32..].copy_from_slice(&self.signature);
        out
    }

    /// From the wire bytes ([`Self::to_bytes`]).
    pub fn from_bytes(raw: &[u8; FRAME_ATTESTATION_LEN]) -> Self {
        let mut gateway = [0u8; 32];
        let mut signature = [0u8; 64];
        gateway.copy_from_slice(&raw[..32]);
        signature.copy_from_slice(&raw[32..]);
        Self { gateway, signature }
    }
}

/// What a frame's attestations came to at a node.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttestVerdict {
    /// Distinct configured gateways whose signature verified.
    pub valid: usize,
    /// Attestations by a configured gateway whose signature did not verify.
    pub bad: usize,
    /// Attestations by a key this node does not trust, or a repeat of a
    /// gateway already counted; not checked.
    pub ignored: usize,
    /// Whether `valid` reached the node's minimum: the frame is admitted
    /// without per-transaction verification.
    pub attested: bool,
}

/// The gateways a node trusts and how many of them a frame needs.
#[derive(Debug, Clone)]
pub struct FrameGateways {
    keys: Vec<ed25519_dalek::VerifyingKey>,
    min: usize,
}

impl FrameGateways {
    /// `keys` (duplicates removed) and a minimum of at least one.
    pub fn new(keys: Vec<ed25519_dalek::VerifyingKey>, min: usize) -> Self {
        let mut unique: Vec<ed25519_dalek::VerifyingKey> = Vec::with_capacity(keys.len());
        for key in keys {
            if !unique.contains(&key) {
                unique.push(key);
            }
        }
        Self { keys: unique, min: min.max(1) }
    }

    /// From a comma-separated list of hex public keys (`0x` optional) and a
    /// minimum. An empty list is `Ok(None)`: no gateway, every frame verified.
    pub fn parse(list: &str, min: usize) -> Result<Option<Self>, String> {
        let mut keys = Vec::new();
        for item in list.split(',').map(str::trim).filter(|item| !item.is_empty()) {
            let hex = item.strip_prefix("0x").unwrap_or(item);
            let raw = alloy_primitives::hex::decode(hex).map_err(|err| format!("gateway key {item}: {err}"))?;
            let raw: [u8; 32] = raw.try_into().map_err(|_| format!("gateway key {item}: not 32 bytes"))?;
            let key =
                ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(|err| format!("gateway key {item}: {err}"))?;
            keys.push(key);
        }
        let this = Self::new(keys, min);
        if this.keys.is_empty() {
            return Ok(None);
        }
        if this.min > this.keys.len() {
            return Err(format!(
                "N42_FRAME_ATTEST_MIN {} is more than the {} distinct gateways configured",
                this.min,
                this.keys.len()
            ));
        }
        Ok(Some(this))
    }

    /// `N42_FRAME_GATEWAYS` and `N42_FRAME_ATTEST_MIN` (default 1).
    pub fn from_env() -> Result<Option<Self>, String> {
        let Ok(list) = std::env::var("N42_FRAME_GATEWAYS") else { return Ok(None) };
        let min = match std::env::var("N42_FRAME_ATTEST_MIN") {
            Ok(value) => {
                value.trim().parse::<usize>().map_err(|err| format!("N42_FRAME_ATTEST_MIN {value}: {err}"))?
            }
            Err(_) => 1,
        };
        Self::parse(&list, min)
    }

    /// How many distinct gateways a frame needs.
    pub const fn min(&self) -> usize {
        self.min
    }

    /// The configured gateways.
    pub fn keys(&self) -> &[ed25519_dalek::VerifyingKey] {
        &self.keys
    }

    /// Checks `attestations` of the frame with root `root` on chain
    /// `chain_id`: one Ed25519 verification (strict) per attestation by a
    /// configured gateway not yet counted, stopping once the minimum is met.
    pub fn check(&self, chain_id: u64, root: B256, attestations: &[FrameAttestation]) -> AttestVerdict {
        let mut verdict = AttestVerdict::default();
        let mut counted: Vec<[u8; 32]> = Vec::with_capacity(self.min);
        let message = frame_attest_message(chain_id, root);
        for attestation in attestations {
            if verdict.valid >= self.min {
                break;
            }
            let Some(key) = self.keys.iter().find(|key| key.as_bytes() == &attestation.gateway) else {
                verdict.ignored += 1;
                continue;
            };
            if counted.contains(&attestation.gateway) {
                verdict.ignored += 1;
                continue;
            }
            let signature = ed25519_dalek::Signature::from_bytes(&attestation.signature);
            if key.verify_strict(message.as_slice(), &signature).is_ok() {
                counted.push(attestation.gateway);
                verdict.valid += 1;
            } else {
                verdict.bad += 1;
            }
        }
        verdict.attested = verdict.valid >= self.min;
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: u8) -> B256 {
        keccak256([i])
    }

    fn node(left: B256, right: B256) -> B256 {
        let mut pair = [0u8; 64];
        pair[..32].copy_from_slice(left.as_slice());
        pair[32..].copy_from_slice(right.as_slice());
        keccak256(pair)
    }

    #[test]
    fn the_frame_root_follows_the_rule() {
        assert_eq!(frame_root(&[]), keccak256([]));
        assert_eq!(frame_root(&[leaf(0)]), leaf(0));
        assert_eq!(frame_root(&[leaf(0), leaf(1)]), node(leaf(0), leaf(1)));
        // Three leaves: the odd last one is hashed with itself.
        let three = node(node(leaf(0), leaf(1)), node(leaf(2), leaf(2)));
        assert_eq!(frame_root(&[leaf(0), leaf(1), leaf(2)]), three);
        // Five: the odd node is paired with itself at every level it is odd.
        let five = node(
            node(node(leaf(0), leaf(1)), node(leaf(2), leaf(3))),
            node(node(leaf(4), leaf(4)), node(leaf(4), leaf(4))),
        );
        assert_eq!(frame_root(&(0..5).map(leaf).collect::<Vec<_>>()), five);
    }

    /// Pinned bytes, so a change of construction cannot pass as a refactor:
    /// leaves are `keccak256([i])` for i in 0..3.
    #[test]
    fn the_frame_root_vector() {
        let root = frame_root(&[leaf(0), leaf(1), leaf(2)]);
        assert_eq!(
            root.to_string(),
            "0xda965b3735d18da2dc9567c85f04f64c4df7e15e2f9cc1796aba0a583bf8d9aa"
        );
    }

    #[test]
    fn a_layout_must_cover_the_body() {
        let hashes: Vec<B256> = (0..7).map(leaf).collect();
        let expected = frame_tree_root(&[
            frame_root(&hashes[..3]),
            frame_root(&hashes[3..6]),
            frame_root(&hashes[6..]),
        ]);
        assert_eq!(frame_tree_root_of(&hashes, &[3, 3, 1]), Some(expected));
        assert_eq!(frame_tree_root_of(&hashes, &[3, 3]), None);
        assert_eq!(frame_tree_root_of(&hashes, &[3, 0, 3, 1]), None);
    }

    fn gateway(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn an_attestation_verifies_only_over_its_root_and_chain() {
        let root = leaf(7);
        let one = gateway(1);
        let gateways = FrameGateways::new(vec![one.verifying_key()], 1);
        let good = FrameAttestation::sign(&one, 94, root);
        assert_eq!(FrameAttestation::from_bytes(&good.to_bytes()), good);
        assert!(gateways.check(94, root, &[good]).attested);
        // Another root, another chain: bad, not attested.
        let other_root = gateways.check(94, leaf(8), &[good]);
        assert_eq!((other_root.attested, other_root.bad), (false, 1));
        assert_eq!(gateways.check(95, root, &[good]).bad, 1);
        // An unknown key is ignored, never verified.
        let stranger = FrameAttestation::sign(&gateway(2), 94, root);
        let verdict = gateways.check(94, root, &[stranger]);
        assert_eq!((verdict.attested, verdict.bad, verdict.ignored), (false, 0, 1));
        // A flipped signature bit is bad.
        let mut flipped = good;
        flipped.signature[3] ^= 1;
        assert_eq!(gateways.check(94, root, &[flipped]).bad, 1);
    }

    #[test]
    fn a_minimum_counts_distinct_gateways() {
        let root = leaf(3);
        let (one, two) = (gateway(1), gateway(2));
        let gateways = FrameGateways::new(vec![one.verifying_key(), two.verifying_key()], 2);
        let a = FrameAttestation::sign(&one, 1, root);
        let b = FrameAttestation::sign(&two, 1, root);
        assert!(!gateways.check(1, root, &[a]).attested);
        assert!(!gateways.check(1, root, &[a, a]).attested, "a repeat is one gateway");
        assert!(gateways.check(1, root, &[a, b]).attested);
    }

    #[test]
    fn gateways_parse_from_hex() {
        let key = gateway(9).verifying_key();
        let hex = alloy_primitives::hex::encode_prefixed(key.as_bytes());
        let parsed = FrameGateways::parse(&format!("{hex}, {hex}"), 1).expect("parses").expect("some");
        assert_eq!(parsed.keys(), &[key]);
        assert!(FrameGateways::parse("", 1).expect("parses").is_none());
        assert!(FrameGateways::parse(&hex, 2).is_err());
        assert!(FrameGateways::parse("0x1234", 1).is_err());
    }

    /// Pinned bytes of the attestation message, so the wire contract cannot
    /// drift as a refactor.
    #[test]
    fn the_attest_message_vector() {
        let expected = {
            let mut buf = Vec::new();
            buf.extend_from_slice(b"n42-frame-attest");
            buf.extend_from_slice(&94u64.to_be_bytes());
            buf.extend_from_slice(leaf(0).as_slice());
            keccak256(buf)
        };
        assert_eq!(frame_attest_message(94, leaf(0)), expected);
    }
}
