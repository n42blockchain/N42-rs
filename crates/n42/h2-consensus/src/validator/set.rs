use crate::error::{ConsensusError, ConsensusResult};
use alloy_primitives::Address;
use crate::ValidatorInfo;
use n42_h2_primitives::BlsPublicKey;

/// Manages the active validator set for consensus.
///
/// Validators are indexed by `ValidatorIndex` (u32), which is their position
/// in the ordered list. The set is fixed for an epoch; validator set changes
/// happen at epoch boundaries (not implemented in Phase 3).
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    /// Ordered list of validators.
    validators: Vec<ValidatorEntry>,
    /// Number of Byzantine faults tolerated: f = (n - 1) / 3
    fault_tolerance: u32,
}

/// Internal entry for a validator.
#[derive(Debug, Clone)]
struct ValidatorEntry {
    address: Address,
    public_key: BlsPublicKey,
    p2p_peer_id: Option<String>,
}

impl ValidatorSet {
    pub(crate) fn max_fault_tolerance_for_len(len: usize) -> u32 {
        (len as u32).saturating_sub(1) / 3
    }

    pub fn validate_params(validator_count: usize, fault_tolerance: u32) -> ConsensusResult<()> {
        let max_fault_tolerance = Self::max_fault_tolerance_for_len(validator_count);
        if fault_tolerance > max_fault_tolerance {
            return Err(ConsensusError::InvalidValidatorSetParams {
                validator_count: validator_count as u32,
                fault_tolerance,
                max_fault_tolerance,
            });
        }
        Ok(())
    }

    pub fn try_new(validators: &[ValidatorInfo], fault_tolerance: u32) -> ConsensusResult<Self> {
        Self::validate_params(validators.len(), fault_tolerance)?;

        // Validate every BLS public key once at construction time (subgroup +
        // non-infinity check). After this point all consensus signature
        // verifications can use `verify_prevalidated` and skip the per-call
        // subgroup check, saving ~10–20% of single-sig BLS verify cost on the
        // hot path. Aggregate verification (`fast_aggregate_verify`) already
        // assumes pre-validated keys per blst's contract.
        let mut entries = Vec::with_capacity(validators.len());
        for (index, v) in validators.iter().enumerate() {
            v.bls_public_key
                .validate()
                .map_err(|_| ConsensusError::InvalidValidatorPubkey {
                    index: index as u32,
                })?;
            entries.push(ValidatorEntry {
                address: v.address,
                public_key: v.bls_public_key.clone(),
                p2p_peer_id: v.p2p_peer_id.clone(),
            });
        }

        Ok(Self {
            validators: entries,
            fault_tolerance,
        })
    }

    /// Creates a new validator set from chain configuration.
    pub fn new(validators: &[ValidatorInfo], fault_tolerance: u32) -> Self {
        Self::try_new(validators, fault_tolerance)
            .unwrap_or_else(|error| panic!("invalid validator set parameters: {error}"))
    }

    /// Returns the total number of validators.
    pub fn len(&self) -> u32 {
        self.validators.len() as u32
    }

    /// Returns true if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Returns the authoritative consensus quorum size: `n - f`.
    ///
    /// Unlike `2f + 1`, this remains safe when a dynamic validator set has a
    /// valid size greater than `3f + 1`.
    pub fn quorum_size(&self) -> usize {
        self.validators
            .len()
            .saturating_sub(self.fault_tolerance as usize)
    }

    /// Returns the fault tolerance f.
    pub fn fault_tolerance(&self) -> u32 {
        self.fault_tolerance
    }

    /// Returns a clone of the validator infos backing this set.
    pub fn validator_infos(&self) -> Vec<ValidatorInfo> {
        self.validators
            .iter()
            .map(|entry| ValidatorInfo {
                address: entry.address,
                bls_public_key: entry.public_key.clone(),
                p2p_peer_id: entry.p2p_peer_id.clone(),
            })
            .collect()
    }

    /// Gets the BLS public key for a validator by index.
    pub fn get_public_key(&self, index: u32) -> ConsensusResult<&BlsPublicKey> {
        self.validators
            .get(index as usize)
            .map(|v| &v.public_key)
            .ok_or(ConsensusError::UnknownValidator {
                index,
                set_size: self.len(),
            })
    }

    /// Gets the address for a validator by index.
    pub fn get_address(&self, index: u32) -> ConsensusResult<&Address> {
        self.validators
            .get(index as usize)
            .map(|v| &v.address)
            .ok_or(ConsensusError::UnknownValidator {
                index,
                set_size: self.len(),
            })
    }

    /// Returns the validator index for the given BLS public key, if present.
    pub fn index_of_public_key(&self, public_key: &BlsPublicKey) -> Option<u32> {
        self.validators
            .iter()
            .position(|entry| entry.public_key.to_bytes() == public_key.to_bytes())
            .map(|index| index as u32)
    }

    /// Checks if a validator index is valid.
    pub fn contains(&self, index: u32) -> bool {
        (index as usize) < self.validators.len()
    }

    /// Returns true if the set contains a validator with the given address.
    pub fn contains_address(&self, addr: &Address) -> bool {
        self.validators.iter().any(|v| v.address == *addr)
    }

    /// Returns all public keys as references, in index order.
    /// Used for QC signature verification.
    pub fn all_public_keys(&self) -> Vec<&BlsPublicKey> {
        self.validators.iter().map(|v| &v.public_key).collect()
    }

    /// Returns public keys for specific indices (matching a signer bitmap).
    /// Used for verifying aggregated signatures against the signing subset.
    pub fn public_keys_for_signers(
        &self,
        signer_indices: &[u32],
    ) -> ConsensusResult<Vec<&BlsPublicKey>> {
        signer_indices
            .iter()
            .map(|&idx| self.get_public_key(idx))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n42_h2_primitives::BlsSecretKey;

    fn test_key(seed: u8) -> BlsSecretKey {
        BlsSecretKey::key_gen(&[seed; 32]).expect("deterministic test key should be valid")
    }

    /// Helper: create a ValidatorInfo with a deterministic BLS key and address.
    fn make_validator_info(index: u8) -> (BlsSecretKey, ValidatorInfo) {
        let sk = test_key(0x40 + index);
        let info = ValidatorInfo {
            address: Address::with_last_byte(index),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        };
        (sk, info)
    }

    #[test]
    fn test_validator_set_creation() {
        let infos: Vec<_> = (0..4u8).map(|i| make_validator_info(i).1).collect();
        let f = 1;
        let vs = ValidatorSet::new(&infos, f);

        assert_eq!(vs.len(), 4);
        assert_eq!(vs.fault_tolerance(), 1);
        assert_eq!(vs.quorum_size(), 3);
        assert!(!vs.is_empty());
    }

    #[test]
    fn test_quorum_size_uses_active_validator_count() {
        let test_cases = [(4, 3), (5, 4), (7, 5), (10, 7), (21, 15)];

        for (n, expected_quorum) in test_cases {
            let infos: Vec<_> = (0..n).map(|i| make_validator_info(i as u8).1).collect();
            let f = ValidatorSet::max_fault_tolerance_for_len(n);
            let vs = ValidatorSet::new(&infos, f);
            assert_eq!(vs.quorum_size(), expected_quorum, "n-f quorum for n={n}");
        }
    }

    #[test]
    fn test_get_public_key() {
        let items: Vec<_> = (0..4u8).map(make_validator_info).collect();
        let infos: Vec<_> = items.iter().map(|(_, info)| info.clone()).collect();
        let vs = ValidatorSet::new(&infos, 1);

        for (i, (_, info)) in items.iter().enumerate() {
            let pk = vs.get_public_key(i as u32).expect("valid index");
            assert_eq!(pk.to_bytes(), info.bls_public_key.to_bytes());
        }

        assert!(vs.get_public_key(4).is_err());
        assert!(vs.get_public_key(100).is_err());
    }

    #[test]
    fn test_contains() {
        let infos: Vec<_> = (0..4u8).map(|i| make_validator_info(i).1).collect();
        let vs = ValidatorSet::new(&infos, 1);

        assert!(vs.contains(0));
        assert!(vs.contains(1));
        assert!(vs.contains(2));
        assert!(vs.contains(3));
        assert!(!vs.contains(4));
        assert!(!vs.contains(100));
    }

    #[test]
    fn test_empty_set() {
        let vs = ValidatorSet::new(&[], 0);

        assert_eq!(vs.len(), 0);
        assert!(vs.is_empty());
        assert!(!vs.contains(0));
    }

    #[test]
    fn test_get_address() {
        let infos: Vec<_> = (0..3u8).map(|i| make_validator_info(i).1).collect();
        let vs = ValidatorSet::new(&infos, 0);

        for i in 0..3u8 {
            let addr = vs.get_address(i as u32).expect("valid index");
            assert_eq!(*addr, Address::with_last_byte(i));
        }

        assert!(vs.get_address(3).is_err());
    }

    #[test]
    fn test_all_public_keys() {
        let items: Vec<_> = (0..3u8).map(make_validator_info).collect();
        let infos: Vec<_> = items.iter().map(|(_, info)| info.clone()).collect();
        let vs = ValidatorSet::new(&infos, 0);

        let all_pks = vs.all_public_keys();
        assert_eq!(all_pks.len(), 3);
        for (i, pk) in all_pks.iter().enumerate() {
            assert_eq!(pk.to_bytes(), items[i].1.bls_public_key.to_bytes());
        }
    }

    #[test]
    fn test_index_of_public_key() {
        let items: Vec<_> = (0..4u8).map(make_validator_info).collect();
        let infos: Vec<_> = items.iter().map(|(_, info)| info.clone()).collect();
        let vs = ValidatorSet::new(&infos, 1);

        for (i, (_, info)) in items.iter().enumerate() {
            assert_eq!(vs.index_of_public_key(&info.bls_public_key), Some(i as u32));
        }

        let missing_key = test_key(0x7F).public_key();
        assert_eq!(vs.index_of_public_key(&missing_key), None);
    }

    #[test]
    fn test_public_keys_for_signers() {
        let items: Vec<_> = (0..4u8).map(make_validator_info).collect();
        let infos: Vec<_> = items.iter().map(|(_, info)| info.clone()).collect();
        let vs = ValidatorSet::new(&infos, 1);

        let pks = vs.public_keys_for_signers(&[0, 2]).expect("should succeed");
        assert_eq!(pks.len(), 2);
        assert_eq!(pks[0].to_bytes(), items[0].1.bls_public_key.to_bytes());
        assert_eq!(pks[1].to_bytes(), items[2].1.bls_public_key.to_bytes());

        assert!(vs.public_keys_for_signers(&[0, 10]).is_err());
    }

    #[test]
    fn test_try_new_rejects_invalid_fault_tolerance() {
        let infos: Vec<_> = (0..4u8).map(|i| make_validator_info(i).1).collect();
        let err = ValidatorSet::try_new(&infos, 2).unwrap_err();
        assert!(matches!(
            err,
            ConsensusError::InvalidValidatorSetParams {
                validator_count: 4,
                fault_tolerance: 2,
                max_fault_tolerance: 1,
            }
        ));
    }
}
