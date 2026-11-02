// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One block's receipt intake (`internal/mobileverify/collector.go`):
//! correct block, active committed key, valid signature, window open; one
//! receipt per device index, the latest wins; at close each receipts-root
//! bucket is aggregated into a certificate, largest first.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use alloy_primitives::B256;
use parking_lot::Mutex;

use crate::bls;
use crate::cert::MobileAttestationCert;
use crate::error::MobileVerifyError;
use crate::mask::encode_mask;
use crate::receipt::Receipt;
use crate::registry::{MobileIndex, Registry};

#[derive(Debug, Default)]
struct State {
    closed: bool,
    frozen: bool,
    by_index: HashMap<MobileIndex, Receipt>,
}

/// One block's collection window.
#[derive(Debug)]
pub struct Collector {
    block_hash: B256,
    block_number: u64,
    reg: Arc<Registry>,
    state: Mutex<State>,
}

impl Collector {
    /// Opens a window for one block.
    pub fn new(reg: Arc<Registry>, block_hash: B256, block_number: u64) -> Self {
        Self { block_hash, block_number, reg, state: Mutex::new(State::default()) }
    }

    /// Validates and admits one receipt; returns the device's index.
    pub fn add(&self, r: &Receipt) -> Result<MobileIndex, MobileVerifyError> {
        self.add_checked(r, false)
    }

    /// [`Self::add`], skipping the signature pairing when the caller has
    /// already verified this receipt's signature.
    pub(crate) fn add_checked(&self, r: &Receipt, signature_verified: bool) -> Result<MobileIndex, MobileVerifyError> {
        if r.block_hash != self.block_hash || r.block_number != self.block_number {
            return Err(MobileVerifyError::WrongBlock {
                got_number: r.block_number,
                got_hash8: hex::encode(&r.block_hash[..8]),
                want_number: self.block_number,
                want_hash8: hex::encode(&self.block_hash[..8]),
            });
        }
        let idx = self.reg.lookup(&r.verifier_pubkey).ok_or(MobileVerifyError::NotRegistered)?;
        if !signature_verified {
            r.verify_signature()?;
        }
        let mut st = self.state.lock();
        if st.closed || st.frozen {
            return Err(MobileVerifyError::WindowClosed);
        }
        st.by_index.insert(idx, r.clone());
        Ok(idx)
    }

    /// Seals intake without discarding what was admitted; returns the
    /// admitted indices, ascending.
    pub fn freeze(&self) -> Vec<MobileIndex> {
        let mut st = self.state.lock();
        st.frozen = true;
        let mut out: Vec<_> = st.by_index.keys().copied().collect();
        out.sort_unstable();
        out
    }

    /// Removes devices before close (cross-node reconciliation); returns how
    /// many were removed. No-op once closed.
    pub fn exclude(&self, banned: &[MobileIndex]) -> usize {
        let mut st = self.state.lock();
        if st.closed {
            return 0;
        }
        banned.iter().filter(|i| st.by_index.remove(i).is_some()).count()
    }

    /// Number of devices admitted.
    pub fn size(&self) -> usize {
        self.state.lock().by_index.len()
    }

    /// Ends the window and aggregates each root bucket: indices ascending,
    /// signatures summed in mask order; certificates largest cohort first,
    /// ties by the smaller root. A second close fails.
    pub fn close(&self, now_ms: u64) -> Result<Vec<MobileAttestationCert>, MobileVerifyError> {
        let by_index = {
            let mut st = self.state.lock();
            if st.closed {
                return Err(MobileVerifyError::WindowClosed);
            }
            st.closed = true;
            std::mem::take(&mut st.by_index)
        };
        let mut cohorts: BTreeMap<B256, Vec<(MobileIndex, blst::min_pk::Signature)>> = BTreeMap::new();
        for (idx, r) in by_index {
            let Ok(sig) = bls::decode_signature(&r.signature) else { continue };
            cohorts.entry(r.computed_receipts_root).or_default().push((idx, sig));
        }
        let mut certs = Vec::with_capacity(cohorts.len());
        let mut sizes = Vec::with_capacity(cohorts.len());
        for (root, mut members) in cohorts {
            members.sort_by_key(|m| m.0);
            let indices: Vec<_> = members.iter().map(|m| m.0).collect();
            let sigs: Vec<_> = members.iter().map(|m| &m.1).collect();
            let Some(agg) = bls::aggregate_signatures(&sigs) else { continue };
            sizes.push(indices.len());
            certs.push(MobileAttestationCert {
                block_hash: self.block_hash,
                block_number: self.block_number,
                receipts_root: root,
                aggregate_sig: agg.compress(),
                signer_mask: encode_mask(&indices)?,
                window_closed_at: now_ms,
            });
        }
        let mut order: Vec<usize> = (0..certs.len()).collect();
        order.sort_by(|a, b| sizes[*b].cmp(&sizes[*a]).then_with(|| certs[*a].receipts_root.cmp(&certs[*b].receipts_root)));
        Ok(order.into_iter().map(|i| certs[i].clone()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceKey;

    fn receipt(k: &DeviceKey, hash: B256, n: u64, root: B256) -> Receipt {
        Receipt {
            block_hash: hash,
            block_number: n,
            computed_receipts_root: root,
            verifier_pubkey: k.pubkey(),
            signature: k.sign_receipt(hash, n, root),
            timestamp_ms: 0,
        }
    }

    #[test]
    fn intake_rules_and_close() {
        let reg = Arc::new(Registry::new());
        let keys: Vec<_> = (1..=4u8).map(|i| DeviceKey::from_ikm(&[i; 32]).unwrap()).collect();
        for k in &keys[..3] {
            reg.register(&k.pubkey(), &k.proof_of_possession()).unwrap();
        }
        reg.commit_epoch_at(1);
        let h = B256::repeat_byte(0x11);
        let col = Collector::new(reg.clone(), h, 5);
        let r1 = B256::repeat_byte(1);
        let r2 = B256::repeat_byte(2);

        let err = col.add(&receipt(&keys[0], h, 6, r1)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "mobileverify: receipt is for a different block: got 6/1111111111111111 want 5/1111111111111111"
        );
        assert_eq!(col.add(&receipt(&keys[3], h, 5, r1)).unwrap_err(), MobileVerifyError::NotRegistered);
        let mut forged = receipt(&keys[0], h, 5, r1);
        forged.computed_receipts_root = r2;
        assert_eq!(col.add(&forged).unwrap_err(), MobileVerifyError::BadReceiptSignature);

        col.add(&receipt(&keys[0], h, 5, r1)).unwrap();
        col.add(&receipt(&keys[1], h, 5, r1)).unwrap();
        col.add(&receipt(&keys[2], h, 5, r1)).unwrap();
        // Latest wins: device 2 moves to the other bucket.
        col.add(&receipt(&keys[2], h, 5, r2)).unwrap();
        assert_eq!(col.size(), 3);
        col.freeze();
        assert_eq!(col.add(&receipt(&keys[0], h, 5, r1)).unwrap_err(), MobileVerifyError::WindowClosed);

        let certs = col.close(77).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].receipts_root, r1);
        assert_eq!(certs[0].verify(&reg).unwrap().len(), 2);
        assert_eq!(certs[1].verify(&reg).unwrap().len(), 1);
        assert_eq!(certs[0].window_closed_at, 77);
        assert_eq!(col.close(78).unwrap_err(), MobileVerifyError::WindowClosed);
    }

    #[test]
    fn close_order_ties_by_smaller_root() {
        let reg = Arc::new(Registry::new());
        let keys: Vec<_> = (1..=2u8).map(|i| DeviceKey::from_ikm(&[i; 32]).unwrap()).collect();
        for k in &keys {
            reg.register(&k.pubkey(), &k.proof_of_possession()).unwrap();
        }
        reg.commit_epoch_at(1);
        let h = B256::repeat_byte(0x22);
        let col = Collector::new(reg, h, 9);
        let (low, high) = (B256::repeat_byte(1), B256::repeat_byte(2));
        col.add(&receipt(&keys[0], h, 9, high)).unwrap();
        col.add(&receipt(&keys[1], h, 9, low)).unwrap();
        let roots: Vec<_> = col.close(0).unwrap().iter().map(|c| c.receipts_root).collect();
        assert_eq!(roots, vec![low, high]);
    }
}
