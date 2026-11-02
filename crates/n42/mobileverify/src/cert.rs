// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The cohort certificate (`internal/mobileverify/cert.go`), the cross-node
//! merge and majority selection (`certmerge.go`) and the bounded store the
//! HTTP surface serves (`manager.go` `CertStore`).

use std::collections::{HashMap, HashSet, VecDeque};

use alloy_primitives::B256;
use blst::min_pk::Signature;
use parking_lot::RwLock;

use crate::bls::{self, SIGNATURE_LEN};
use crate::error::MobileVerifyError;
use crate::gojson::{self, Obj};
use crate::mask::{decode_mask, encode_mask};
use crate::receipt::signing_message;
use crate::registry::{MobileIndex, Registry, now_ms};

/// Blocks a [`CertStore`] retains by default (`cert_blocks`).
pub const DEFAULT_CERT_BLOCKS: usize = 512;

/// One `(block, receipts root)` cohort's aggregate attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileAttestationCert {
    /// The attested block's hash.
    pub block_hash: B256,
    /// The attested block's number.
    pub block_number: u64,
    /// The root this cohort attested to.
    pub receipts_root: B256,
    /// The G2 sum of the cohort's signatures.
    pub aggregate_sig: [u8; SIGNATURE_LEN],
    /// The sparse mask over registry indices.
    pub signer_mask: Vec<u8>,
    /// Unix ms the window closed; metadata, not signed.
    pub window_closed_at: u64,
}

impl MobileAttestationCert {
    /// Decodes the mask, sums the cohort's keys in G1 and verifies the
    /// aggregate over the 72-byte message (gov5 `Verify`). Returns the signers.
    pub fn verify(&self, reg: &Registry) -> Result<Vec<MobileIndex>, MobileVerifyError> {
        let indices = decode_mask(&self.signer_mask, reg.index_bound())?;
        if indices.is_empty() {
            return Err(MobileVerifyError::BadCertDetail("empty cohort".into()));
        }
        let pks = reg.public_keys(&indices)?;
        let sig = bls::decode_signature(&self.aggregate_sig)
            .map_err(|e| MobileVerifyError::BadCertDetail(format!("aggregate decode: {e}")))?;
        let refs: Vec<_> = pks.iter().collect();
        let agg = bls::aggregate_pubkeys(&refs).ok_or(MobileVerifyError::BadCert)?;
        if !bls::verify(&sig, &agg, &signing_message(self.block_hash, self.block_number, self.receipts_root)) {
            return Err(MobileVerifyError::BadCert);
        }
        Ok(indices)
    }

    /// Number of signers under `registry_bound`, 0 when the mask does not decode.
    pub fn signers(&self, registry_bound: usize) -> usize {
        decode_mask(&self.signer_mask, registry_bound).map_or(0, |v| v.len())
    }

    /// One element of `GET /mobileverify/cert/<hash>` (gov5 `certJSON`, fields
    /// in declaration order, no trailing newline).
    pub fn to_json(&self, registry_bound: usize) -> String {
        Obj::new()
            .str("blockHash", &gojson::hex0x(self.block_hash.as_slice()))
            .num("blockNumber", self.block_number)
            .str("receiptsRoot", &gojson::hex0x(self.receipts_root.as_slice()))
            .str("aggregateSig", &hex::encode(self.aggregate_sig))
            .str("signerMask", &hex::encode(&self.signer_mask))
            .num("signers", self.signers(registry_bound) as u64)
            .num("windowClosedAt", self.window_closed_at)
            .finish()
    }

    fn same_cohort(&self, other: &Self) -> bool {
        self.block_number == other.block_number &&
            self.block_hash == other.block_hash &&
            self.receipts_root == other.receipts_root
    }
}

/// The result of [`merge_certs`].
#[derive(Debug, Clone)]
pub struct Merged {
    /// The union certificate.
    pub cert: MobileAttestationCert,
    /// Authenticated inputs dropped for overlapping an accepted one.
    pub dropped_for_overlap: Vec<MobileAttestationCert>,
    /// Inputs that failed authentication.
    pub invalid: Vec<MobileAttestationCert>,
}

/// Combines certificates for one `(block, root)` into one over the union of
/// their (disjoint) signers (gov5 `MergeCerts`). Every input is verified
/// first; overlapping ones are dropped whole, largest first.
pub fn merge_certs(certs: &[MobileAttestationCert], reg: &Registry) -> Result<Merged, MobileVerifyError> {
    merge_certs_at(certs, reg, now_ms())
}

/// [`merge_certs`] with the merged certificate's `windowClosedAt` given.
pub fn merge_certs_at(
    certs: &[MobileAttestationCert],
    reg: &Registry,
    closed_at_ms: u64,
) -> Result<Merged, MobileVerifyError> {
    if certs.is_empty() {
        return Err(MobileVerifyError::EmptyCertSet);
    }
    let mut invalid = Vec::new();
    let mut ds: Vec<(&MobileAttestationCert, Vec<MobileIndex>, Signature)> = Vec::new();
    for c in certs {
        let Ok(indices) = c.verify(reg) else {
            invalid.push(c.clone());
            continue;
        };
        let Ok(sig) = bls::decode_signature(&c.aggregate_sig) else {
            invalid.push(c.clone());
            continue;
        };
        ds.push((c, indices, sig));
    }
    let Some(first) = ds.first().map(|d| d.0.clone()) else {
        return Err(MobileVerifyError::EmptyCertSet);
    };
    if ds.iter().skip(1).any(|d| !first.same_cohort(d.0)) {
        return Err(MobileVerifyError::CertMismatch);
    }
    if ds.len() == 1 {
        return Ok(Merged { cert: first, dropped_for_overlap: Vec::new(), invalid });
    }
    ds.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.aggregate_sig.cmp(&b.0.aggregate_sig)));
    let mut used = HashSet::new();
    let mut dropped = Vec::new();
    let mut idx = Vec::new();
    let mut sigs = Vec::new();
    for (c, indices, sig) in &ds {
        if indices.iter().any(|i| used.contains(i)) {
            dropped.push((*c).clone());
            continue;
        }
        used.extend(indices.iter().copied());
        idx.extend_from_slice(indices);
        sigs.push(sig);
    }
    if sigs.is_empty() {
        return Err(MobileVerifyError::AllCertsConflicted);
    }
    idx.sort_unstable();
    let mask = encode_mask(&idx)?;
    let agg = bls::aggregate_signatures(&sigs).ok_or(MobileVerifyError::AllCertsConflicted)?;
    Ok(Merged {
        cert: MobileAttestationCert {
            block_hash: first.block_hash,
            block_number: first.block_number,
            receipts_root: first.receipts_root,
            aggregate_sig: agg.compress(),
            signer_mask: mask,
            window_closed_at: closed_at_ms,
        },
        dropped_for_overlap: dropped,
        invalid,
    })
}

/// Picks the largest cohort among one block's per-root certificates; ties go
/// to the lexicographically smaller root (gov5 `SelectMajorityBucket`).
/// Returns `(winner, discarded)`.
pub fn select_majority_bucket(
    buckets: &[MobileAttestationCert],
    registry_bound: usize,
) -> Result<(MobileAttestationCert, Vec<MobileAttestationCert>), MobileVerifyError> {
    let Some(first) = buckets.first() else { return Err(MobileVerifyError::EmptyCertSet) };
    if buckets.len() == 1 {
        return Ok((first.clone(), Vec::new()));
    }
    let mut sizes = Vec::with_capacity(buckets.len());
    for b in buckets {
        let n = decode_mask(&b.signer_mask, registry_bound)
            .map_err(|e| MobileVerifyError::Other(format!("decode mask: {e}")))?
            .len();
        sizes.push(n);
    }
    let mut best = 0;
    for i in 1..buckets.len() {
        if sizes[i] > sizes[best] ||
            (sizes[i] == sizes[best] && buckets[i].receipts_root < buckets[best].receipts_root)
        {
            best = i;
        }
    }
    let discarded = buckets.iter().enumerate().filter(|(i, _)| *i != best).map(|(_, b)| b.clone()).collect();
    Ok((buckets[best].clone(), discarded))
}

#[derive(Debug, Default)]
struct StoreInner {
    by_hash: HashMap<B256, Vec<MobileAttestationCert>>,
    order: VecDeque<B256>,
}

/// The most recent blocks' certificates, insertion-order eviction.
#[derive(Debug)]
pub struct CertStore {
    max: usize,
    inner: RwLock<StoreInner>,
}

impl Default for CertStore {
    fn default() -> Self {
        Self::new(DEFAULT_CERT_BLOCKS)
    }
}

impl CertStore {
    /// A store retaining up to `max` blocks (0 means 512).
    pub fn new(max: usize) -> Self {
        let max = if max == 0 { DEFAULT_CERT_BLOCKS } else { max };
        Self { max, inner: RwLock::new(StoreInner::default()) }
    }

    /// Stores one block's certificates (they share a block hash), replacing
    /// what the block had.
    pub fn put(&self, certs: Vec<MobileAttestationCert>) {
        let Some(hash) = certs.first().map(|c| c.block_hash) else { return };
        let mut inner = self.inner.write();
        if !inner.by_hash.contains_key(&hash) {
            inner.order.push_back(hash);
            if inner.order.len() > self.max
                && let Some(oldest) = inner.order.pop_front()
            {
                inner.by_hash.remove(&oldest);
            }
        }
        inner.by_hash.insert(hash, certs);
    }

    /// A block's certificates (majority first); empty when none.
    pub fn get(&self, block_hash: &B256) -> Vec<MobileAttestationCert> {
        self.inner.read().by_hash.get(block_hash).cloned().unwrap_or_default()
    }

    /// Number of blocks with stored certificates.
    pub fn len(&self) -> usize {
        self.inner.read().by_hash.len()
    }

    /// Whether nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceKey;

    fn setup(n: u8) -> (Registry, Vec<DeviceKey>) {
        let reg = Registry::new();
        let keys: Vec<_> = (1..=n).map(|i| DeviceKey::from_ikm(&[i; 32]).unwrap()).collect();
        for k in &keys {
            reg.register(&k.pubkey(), &k.proof_of_possession()).unwrap();
        }
        reg.commit_epoch_at(1);
        (reg, keys)
    }

    fn cert_for(reg: &Registry, keys: &[&DeviceKey], hash: B256, root: B256) -> MobileAttestationCert {
        let mut pairs: Vec<_> = keys.iter().map(|k| (reg.lookup(&k.pubkey()).unwrap(), *k)).collect();
        pairs.sort_by_key(|p| p.0);
        let sigs: Vec<Signature> = pairs
            .iter()
            .map(|(_, k)| bls::decode_signature(&k.sign_receipt(hash, 10, root)).unwrap())
            .collect();
        let refs: Vec<_> = sigs.iter().collect();
        let idx: Vec<_> = pairs.iter().map(|p| p.0).collect();
        MobileAttestationCert {
            block_hash: hash,
            block_number: 10,
            receipts_root: root,
            aggregate_sig: bls::aggregate_signatures(&refs).unwrap().compress(),
            signer_mask: encode_mask(&idx).unwrap(),
            window_closed_at: 99,
        }
    }

    #[test]
    fn verify_and_merge() {
        let (reg, keys) = setup(4);
        let h = B256::repeat_byte(1);
        let r = B256::repeat_byte(2);
        let a = cert_for(&reg, &[&keys[0], &keys[1]], h, r);
        let b = cert_for(&reg, &[&keys[2]], h, r);
        assert_eq!(a.verify(&reg).unwrap().len(), 2);
        let m = merge_certs(&[a.clone(), b], &reg).unwrap();
        assert_eq!(m.cert.verify(&reg).unwrap().len(), 3);
        // Overlap drops the smaller cert whole.
        let c = cert_for(&reg, &[&keys[1]], h, r);
        let m = merge_certs(&[a.clone(), c], &reg).unwrap();
        assert_eq!(m.dropped_for_overlap.len(), 1);
        // A forged cert is rejected, the honest one survives as-is.
        let mut forged = a.clone();
        forged.signer_mask = encode_mask(&[3]).unwrap();
        let m = merge_certs(&[forged.clone(), a.clone()], &reg).unwrap();
        assert_eq!(m.invalid.len(), 1);
        assert_eq!(m.cert, a);
        assert_eq!(forged.verify(&reg).unwrap_err(), MobileVerifyError::BadCert);
    }

    #[test]
    fn majority_and_tie_break() {
        let (reg, keys) = setup(3);
        let h = B256::repeat_byte(1);
        let big = cert_for(&reg, &[&keys[0], &keys[1]], h, B256::repeat_byte(9));
        let small = cert_for(&reg, &[&keys[2]], h, B256::repeat_byte(1));
        let (w, d) = select_majority_bucket(&[small.clone(), big.clone()], 3).unwrap();
        assert_eq!(w, big);
        assert_eq!(d, vec![small]);
        let x = cert_for(&reg, &[&keys[0]], h, B256::repeat_byte(5));
        let y = cert_for(&reg, &[&keys[1]], h, B256::repeat_byte(4));
        let (w, _) = select_majority_bucket(&[x, y.clone()], 3).unwrap();
        assert_eq!(w, y);
    }

    #[test]
    fn json_shape() {
        let c = MobileAttestationCert {
            block_hash: B256::repeat_byte(0xab),
            block_number: 7,
            receipts_root: B256::repeat_byte(0x01),
            aggregate_sig: [0xcd; 96],
            signer_mask: vec![1, 0],
            window_closed_at: 1234,
        };
        let j = c.to_json(1);
        assert_eq!(
            j,
            format!(
                "{{\"blockHash\":\"0x{}\",\"blockNumber\":7,\"receiptsRoot\":\"0x{}\",\"aggregateSig\":\"{}\",\"signerMask\":\"0100\",\"signers\":1,\"windowClosedAt\":1234}}",
                "ab".repeat(32),
                "01".repeat(32),
                "cd".repeat(96)
            )
        );
        assert_eq!(c.signers(0), 0);
    }

    #[test]
    fn store_evicts_oldest() {
        let s = CertStore::new(2);
        for i in 1..=3u8 {
            s.put(vec![MobileAttestationCert {
                block_hash: B256::repeat_byte(i),
                block_number: 1,
                receipts_root: B256::ZERO,
                aggregate_sig: [0; 96],
                signer_mask: vec![],
                window_closed_at: 0,
            }]);
        }
        assert_eq!(s.len(), 2);
        assert!(s.get(&B256::repeat_byte(1)).is_empty());
        assert_eq!(s.get(&B256::repeat_byte(3)).len(), 1);
    }
}
