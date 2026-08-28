// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's simulated BLS committee pool, and the committee evidence every
//! header on a chain with one has to link to.
//!
//! On a chain whose genesis enables `hotstuff.committeePool`, gov5 stamps
//! `parentBeaconRoot` with `Blake3(parent's committee evidence)` and its
//! `VerifyHeader` refuses any other value (`hotstuff/adapter.go`). The
//! evidence is *deterministic*: a pool of `poolSize` BLS keys derived from a
//! seed, a committee of `committeeSize` drawn per block from
//! `(number, hash)`, and one aggregate signature over `(number, hash)` that,
//! since the simulator holds every key, is the signature of the summed
//! secret scalars (`internal/blspool`). Nothing has to be observed or
//! stored: any node with the genesis rebuilds the evidence of any block from
//! its header. This module is that computation, checked byte for byte
//! against gov5's (`testdata/gov5_committee_evidence.txt`, printed by
//! gov5's own `blspool`).
//!
//! What it does not do: the hand-over of pool slots to real mobile
//! validators (`consensus_registerCommitteeValidator`), after which the
//! replaced slots sign for themselves. Until a chain has registrations
//! this is the whole pool.

use alloy_primitives::{B256, U256};
use n42_h2_primitives::bls::{BlsPublicKey, BlsSecretKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// The order of BLS12-381's scalar field, `r`.
const BLS_SCALAR_ORDER: U256 = U256::from_be_bytes([
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
]);

/// The pool as the genesis configures it (`hotstuff.committeePool`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteePoolConfig {
    /// The master seed; slot `i`'s key is `keygen(sha256(seed ‖ i))`.
    pub seed: B256,
    /// Keys in the pool.
    pub pool_size: usize,
    /// Signers drawn per block.
    pub committee_size: usize,
    /// Blocks over which the active pool grows from `committee_size` to
    /// `pool_size`; zero means the whole pool from the start.
    pub ramp_blocks: u64,
}

/// Why the pool could not be built or used.
#[derive(Debug, thiserror::Error)]
pub enum CommitteePoolError {
    /// Sizes that gov5's `NewSimulatedPool` refuses.
    #[error("invalid pool/committee size: pool {pool_size}, committee {committee_size}")]
    InvalidSize {
        /// Keys in the pool.
        pool_size: usize,
        /// Signers per block.
        committee_size: usize,
    },
    /// A derived key was invalid.
    #[error("key derivation failed for slot {0}")]
    KeyDerivation(usize),
    /// The committee for a block was empty.
    #[error("no coverage for the committee at block {0}")]
    NoCoverage(u64),
    /// The summed scalar was not a usable key.
    #[error("summed committee scalar is not a valid secret key")]
    InvalidScalarSum,
}

/// The simulated pool: every slot's secret scalar, ready to be summed.
#[derive(Clone)]
pub struct SimulatedCommitteePool {
    config: CommitteePoolConfig,
    scalars: Vec<U256>,
}

impl std::fmt::Debug for SimulatedCommitteePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimulatedCommitteePool").field("config", &self.config).finish_non_exhaustive()
    }
}

/// The IKM slot `i`'s key is generated from: `sha256(seed ‖ i as u64 BE)`.
pub fn slot_ikm(seed: &B256, slot: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_slice());
    hasher.update((slot as u64).to_be_bytes());
    hasher.finalize().into()
}

/// Slots active at `block_number`, growing linearly over the ramp.
pub fn active_pool(block_number: u64, pool_size: usize, committee_size: usize, ramp_blocks: u64) -> usize {
    if ramp_blocks == 0 || block_number >= ramp_blocks {
        return pool_size;
    }
    let grow = (pool_size - committee_size) as u64 * block_number / ramp_blocks;
    (committee_size + grow as usize).min(pool_size)
}

/// The committee for `(view, block_hash)` out of `active` slots: a partial
/// Fisher–Yates over the slot indices, each step seeded by
/// `sha256(sha256(view LE ‖ hash) ‖ step LE)`.
pub fn committee(view: u64, block_hash: &B256, active: usize, committee_size: usize) -> Vec<usize> {
    let k = committee_size.min(active);
    let mut seed = [0u8; 40];
    seed[..8].copy_from_slice(&view.to_le_bytes());
    seed[8..].copy_from_slice(block_hash.as_slice());
    let base: [u8; 32] = Sha256::digest(seed).into();
    let mut swaps: HashMap<usize, usize> = HashMap::with_capacity(k * 2);
    let get = |swaps: &HashMap<usize, usize>, i: usize| swaps.get(&i).copied().unwrap_or(i);
    let mut out = Vec::with_capacity(k);
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(&base);
    for i in 0..k {
        buf[32..].copy_from_slice(&(i as u64).to_le_bytes());
        let h: [u8; 32] = Sha256::digest(buf).into();
        let rnd = u64::from_le_bytes(h[..8].try_into().expect("8 bytes"));
        let j = i + (rnd % (active - i) as u64) as usize;
        let vj = get(&swaps, j);
        out.push(vj);
        let vi = get(&swaps, i);
        swaps.insert(j, vi);
        swaps.insert(i, vj);
    }
    out
}

/// What a committee signs for a block: `view LE ‖ block hash`.
pub fn signing_message(view: u64, block_hash: &B256) -> [u8; 40] {
    let mut msg = [0u8; 40];
    msg[..8].copy_from_slice(&view.to_le_bytes());
    msg[8..].copy_from_slice(block_hash.as_slice());
    msg
}

impl SimulatedCommitteePool {
    /// Derives the pool's keys. Linear in `pool_size` (200k keys take a
    /// second or two), done once per process.
    pub fn new(config: CommitteePoolConfig) -> Result<Self, CommitteePoolError> {
        if config.pool_size == 0 || config.committee_size == 0 || config.committee_size > config.pool_size {
            return Err(CommitteePoolError::InvalidSize {
                pool_size: config.pool_size,
                committee_size: config.committee_size,
            });
        }
        let mut scalars = vec![U256::ZERO; config.pool_size];
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(config.pool_size);
        let chunk = config.pool_size.div_ceil(threads);
        let seed = config.seed;
        let failed = std::sync::Mutex::new(None);
        std::thread::scope(|scope| {
            for (index, part) in scalars.chunks_mut(chunk).enumerate() {
                let failed = &failed;
                scope.spawn(move || {
                    for (offset, scalar) in part.iter_mut().enumerate() {
                        let slot = index * chunk + offset;
                        match BlsSecretKey::key_gen(&slot_ikm(&seed, slot)) {
                            Ok(key) => *scalar = U256::from_be_bytes(key.to_bytes()),
                            Err(_) => {
                                *failed.lock().expect("lock") = Some(slot);
                                return;
                            }
                        }
                    }
                });
            }
        });
        if let Some(slot) = failed.into_inner().expect("lock") {
            return Err(CommitteePoolError::KeyDerivation(slot));
        }
        Ok(Self { config, scalars })
    }

    /// The configuration.
    pub const fn config(&self) -> &CommitteePoolConfig {
        &self.config
    }

    /// Slots active at `block_number`.
    pub fn active_size(&self, block_number: u64) -> usize {
        active_pool(block_number, self.config.pool_size, self.config.committee_size, self.config.ramp_blocks)
    }

    /// The committee drawn for a block.
    pub fn committee_at(&self, block_number: u64, block_hash: &B256) -> Vec<usize> {
        committee(block_number, block_hash, self.active_size(block_number), self.config.committee_size)
    }

    /// Slot `slot`'s secret key.
    pub fn secret_key(&self, slot: usize) -> Result<BlsSecretKey, CommitteePoolError> {
        let scalar = self.scalars.get(slot).ok_or(CommitteePoolError::KeyDerivation(slot))?;
        BlsSecretKey::from_bytes(&scalar.to_be_bytes::<32>()).map_err(|_| CommitteePoolError::KeyDerivation(slot))
    }

    /// Slot `slot`'s public key.
    pub fn public_key(&self, slot: usize) -> Result<BlsPublicKey, CommitteePoolError> {
        Ok(self.secret_key(slot)?.public_key())
    }

    /// The simulated committee evidence for a block, as gov5's
    /// `BuildSimulatedCE`: the committee's aggregate signature — the summed
    /// scalars' signature — over `(number, hash)`, every member present, and
    /// the same signature standing as the mobile attestation over the
    /// receipts root.
    pub fn build_evidence(
        &self,
        block_number: u64,
        block_hash: &B256,
        receipts_root: &B256,
    ) -> Result<ConsensusEvidence, CommitteePoolError> {
        let members = self.committee_at(block_number, block_hash);
        if members.is_empty() {
            return Err(CommitteePoolError::NoCoverage(block_number));
        }
        let mut sum = U256::ZERO;
        let mut bitmap = vec![0u8; members.len().div_ceil(8)];
        for (i, slot) in members.iter().enumerate() {
            sum = sum.add_mod(self.scalars[*slot], BLS_SCALAR_ORDER);
            bitmap[i / 8] |= 1 << (i % 8);
        }
        let key = BlsSecretKey::from_bytes(&sum.to_be_bytes::<32>())
            .map_err(|_| CommitteePoolError::InvalidScalarSum)?;
        let signature = key.sign_h2_v4(&signing_message(block_number, block_hash)).to_bytes();
        Ok(ConsensusEvidence {
            view: block_number,
            block_hash: *block_hash,
            aggregate_signature: signature,
            signer_count: members.len() as u16,
            signers_packed: bitmap.clone(),
            mobile: Some(MobileEvidence {
                receipts_root: *receipts_root,
                aggregate_signature: signature,
                participant_count: members.len() as u16,
                participants_packed: bitmap,
                created_at_ms: 0,
            }),
        })
    }

    /// The `parentBeaconRoot` a block whose parent is
    /// `(parent_number, parent_hash, parent_receipts_root)` must carry: the
    /// zero root when the parent is genesis, otherwise the Blake3 of the
    /// parent's evidence.
    pub fn parent_beacon_root(
        &self,
        parent_number: u64,
        parent_hash: &B256,
        parent_receipts_root: &B256,
    ) -> Result<B256, CommitteePoolError> {
        if parent_number == 0 {
            return Ok(B256::ZERO);
        }
        Ok(self.build_evidence(parent_number, parent_hash, parent_receipts_root)?.beacon_root())
    }
}

/// gov5's `rawdb.ConsensusEvidence`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusEvidence {
    /// The view (the block number, for simulated evidence).
    pub view: u64,
    /// The block signed.
    pub block_hash: B256,
    /// The committee's aggregate signature.
    pub aggregate_signature: [u8; 96],
    /// Committee members.
    pub signer_count: u16,
    /// Which members signed, one bit each, `⌈signer_count/8⌉` bytes.
    pub signers_packed: Vec<u8>,
    /// The mobile attestation, when present.
    pub mobile: Option<MobileEvidence>,
}

/// The mobile section of the evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MobileEvidence {
    /// The receipts root attested.
    pub receipts_root: B256,
    /// The attestation's aggregate signature.
    pub aggregate_signature: [u8; 96],
    /// Participants.
    pub participant_count: u16,
    /// Which participants signed, one bit each.
    pub participants_packed: Vec<u8>,
    /// When the attestation was made, milliseconds; zero when simulated.
    pub created_at_ms: u64,
}

impl ConsensusEvidence {
    /// gov5's `Marshal`: the fixed fields little-endian, the bitmaps as
    /// many bytes as their counts need, a mobile flag byte, and the mobile
    /// section when the flag is set.
    pub fn marshal(&self) -> Vec<u8> {
        let packed = (self.signer_count as usize).div_ceil(8);
        let mut out = Vec::with_capacity(8 + 32 + 96 + 2 + packed + 1 + 32 + 96 + 2 + 64 + 8);
        out.extend_from_slice(&self.view.to_le_bytes());
        out.extend_from_slice(self.block_hash.as_slice());
        out.extend_from_slice(&self.aggregate_signature);
        out.extend_from_slice(&self.signer_count.to_le_bytes());
        out.extend_from_slice(&padded(&self.signers_packed, packed));
        match &self.mobile {
            Some(mobile) => {
                out.push(1);
                out.extend_from_slice(mobile.receipts_root.as_slice());
                out.extend_from_slice(&mobile.aggregate_signature);
                out.extend_from_slice(&mobile.participant_count.to_le_bytes());
                let packed = (mobile.participant_count as usize).div_ceil(8);
                out.extend_from_slice(&padded(&mobile.participants_packed, packed));
                out.extend_from_slice(&mobile.created_at_ms.to_le_bytes());
            }
            None => out.push(0),
        }
        out
    }

    /// `Blake3(marshal)`: what a child header carries as `parentBeaconRoot`.
    pub fn beacon_root(&self) -> B256 {
        B256::from(*blake3::hash(&self.marshal()).as_bytes())
    }
}

fn padded(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = bytes.get(..len.min(bytes.len())).unwrap_or(&[]).to_vec();
    out.resize(len, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
    use std::collections::BTreeMap;

    /// `FIXTURE <case> <key>=<value>` lines, printed by gov5's `blspool`.
    fn fixtures() -> BTreeMap<String, BTreeMap<String, String>> {
        let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        for line in include_str!("../testdata/gov5_committee_evidence.txt").lines() {
            let mut parts = line.splitn(3, ' ');
            let (Some("FIXTURE"), Some(case), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
                continue;
            };
            // `k=v` pairs; a bracketed value keeps its spaces.
            let mut rest = rest;
            while let Some((k, after)) = rest.split_once('=') {
                let (v, tail) = if let Some(after) = after.strip_prefix('[') {
                    let (v, tail) = after.split_once(']').unwrap_or((after, ""));
                    (format!("[{v}]"), tail)
                } else {
                    after.split_once(' ').map_or((after.to_string(), ""), |(v, t)| (v.to_string(), t))
                };
                out.entry(case.to_string()).or_default().insert(k.trim().to_string(), v);
                rest = tail.trim_start();
            }
        }
        out
    }

    fn fixture_hashes() -> (B256, B256) {
        let mut hash = [0u8; 32];
        let mut receipts = [0u8; 32];
        for i in 0..32 {
            hash[i] = 0xA0 + (i % 16) as u8;
            receipts[i] = 0x50 + (i % 16) as u8;
        }
        (B256::from(hash), B256::from(receipts))
    }

    fn check_case(name: &str, seed: &str, pool_size: usize, committee_size: usize, ramp: u64, block: u64) {
        let fixture = &fixtures()[name];
        let pool = SimulatedCommitteePool::new(CommitteePoolConfig {
            seed: seed.parse().unwrap(),
            pool_size,
            committee_size,
            ramp_blocks: ramp,
        })
        .unwrap();
        let (hash, receipts) = fixture_hashes();
        let active: usize = fixture["active"].parse().unwrap();
        assert_eq!(pool.active_size(block), active, "{name}: active pool");
        assert_eq!(hex::encode(pool.secret_key(0).unwrap().to_bytes()), fixture["sk0"], "{name}: slot 0 key");
        assert_eq!(hex::encode(pool.public_key(0).unwrap().to_bytes()), fixture["pk0"], "{name}: slot 0 pubkey");
        let evidence = pool.build_evidence(block, &hash, &receipts).unwrap();
        assert_eq!(hex::encode(evidence.marshal()), fixture["ce"], "{name}: evidence bytes");
        assert_eq!(hex::encode(evidence.beacon_root()), fixture["root"], "{name}: beacon root");
        assert_eq!(pool.parent_beacon_root(block, &hash, &receipts).unwrap(), evidence.beacon_root());
        assert_eq!(pool.parent_beacon_root(0, &hash, &receipts).unwrap(), B256::ZERO);
    }

    #[test]
    fn a_small_pool_matches_gov5_byte_for_byte() {
        let fixture = &fixtures()["small"];
        let (hash, _) = fixture_hashes();
        // committee_head=[20 19 11 28 23 27 34 3]
        let head: Vec<usize> = fixture["committee_head"]
            .trim_matches(|c| c == '[' || c == ']')
            .split(' ')
            .map(|n| n.parse().unwrap())
            .collect();
        let active = active_pool(50, 64, 8, 100);
        assert_eq!(&committee(50, &hash, active, 8)[..8], head.as_slice());
        check_case("small", "0x0101010101010101010101010101010101010101010101010101010101010101", 64, 8, 100, 50);
    }

    #[test]
    fn chain_94s_pool_matches_gov5_byte_for_byte() {
        check_case(
            "chain94",
            "0x03c75de6b57f3563919956d11700f1d0c932e3c157506b23ed2c40d3ca47bb2f",
            200_000,
            512,
            1_000_000,
            13_013_133,
        );
    }

    #[test]
    fn the_scalar_sum_signs_like_the_aggregate() {
        let pool = SimulatedCommitteePool::new(CommitteePoolConfig {
            seed: B256::repeat_byte(7),
            pool_size: 16,
            committee_size: 4,
            ramp_blocks: 0,
        })
        .unwrap();
        let (hash, receipts) = fixture_hashes();
        let evidence = pool.build_evidence(9, &hash, &receipts).unwrap();
        let members = pool.committee_at(9, &hash);
        let signatures: Vec<_> = members
            .iter()
            .map(|slot| pool.secret_key(*slot).unwrap().sign_h2_v4(&signing_message(9, &hash)))
            .collect();
        let aggregate = n42_h2_primitives::bls::AggregateSignature::aggregate(&signatures.iter().collect::<Vec<_>>()).unwrap();
        assert_eq!(aggregate.to_bytes(), evidence.aggregate_signature);
    }
}
