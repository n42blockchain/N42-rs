//! SBMT state-proof verification for mobile light clients.
//!
//! A phone can verify a single account/storage entry against a block's combined
//! state root **without re-executing the block or accessing any tree** — it only
//! runs blake3 over the proof. Built on the zero-dependency [`n42_bmt_core`]
//! crate, so this pulls no reth/mdbx storage stack into the mobile binary / FFI.

use alloy_primitives::{Address, B256, U256};

pub use n42_bmt_core::{
    BmtVerifyError, ShardedBmtProof, account_key, shard_index_for_key, storage_key,
};
pub use n42_twig_core::{ShardedTwigProof, TwigVerifyError};

/// Verify an SBMT account/storage proof against a block's combined state root,
/// **without** binding it to a queried key.
///
/// The proof carries the shard root + shard-tree path, the in-shard binary proof,
/// and the raw value; verification recomputes the combined root and checks the
/// value commitment. Returns `Ok(())` iff the proof is valid for `state_root`.
///
/// ⚠️ This only proves the proof is *internally consistent* — it does NOT prove
/// the proof answers the key you asked about. An untrusted server could return a
/// valid proof for an unrelated key. Prefer [`verify_account_proof`] /
/// [`verify_storage_proof`], which bind the proof to the queried account/slot.
pub fn verify_state_proof(proof: &ShardedBmtProof, state_root: B256) -> Result<(), BmtVerifyError> {
    proof.verify(&state_root.0)
}

/// Verify an SBMT account proof against `state_root`, bound to `address`.
///
/// Derives the canonical account key for `address` and rejects the proof unless
/// its leaf key and shard match — so a server cannot answer a query for one
/// account with another account's (or a wrong-shard non-membership) proof.
pub fn verify_account_proof(
    proof: &ShardedBmtProof,
    state_root: B256,
    address: Address,
) -> Result<(), BmtVerifyError> {
    let key = account_key(&address.into_array());
    proof.verify_for_key(&state_root.0, &key)
}

/// Verify an SBMT storage-slot proof against `state_root`, bound to
/// `(address, slot)`.
pub fn verify_storage_proof(
    proof: &ShardedBmtProof,
    state_root: B256,
    address: Address,
    slot: U256,
) -> Result<(), BmtVerifyError> {
    let key = storage_key(&address.into_array(), &slot.to_be_bytes::<32>());
    proof.verify_for_key(&state_root.0, &key)
}

/// Verify a twig account/storage proof against a block's combined twig state
/// root, **without** binding it to a queried key.
pub fn verify_twig_state_proof(
    proof: &ShardedTwigProof,
    state_root: B256,
) -> Result<(), TwigVerifyError> {
    proof.verify(&state_root.0)
}

/// Verify a twig account proof against `state_root`, bound to `address`.
pub fn verify_twig_account_proof(
    proof: &ShardedTwigProof,
    state_root: B256,
    address: Address,
) -> Result<(), TwigVerifyError> {
    let key = account_key(&address.into_array());
    proof.verify_for_key(&state_root.0, &key)
}

/// Verify a twig storage-slot proof against `state_root`, bound to
/// `(address, slot)`.
pub fn verify_twig_storage_proof(
    proof: &ShardedTwigProof,
    state_root: B256,
    address: Address,
    slot: U256,
) -> Result<(), TwigVerifyError> {
    let key = storage_key(&address.into_array(), &slot.to_be_bytes::<32>());
    proof.verify_for_key(&state_root.0, &key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use n42_bmt_core::{EMPTY_HASH, Sbmt, ShardedBmtProof, shard_tree_path, shard_tree_root};
    use n42_twig_core::ShardedTwig;

    /// Build a sharded proof by hand from the core primitives (mobile has no
    /// access to the `ShardedSbmt` builder, which lives in `n42-jmt`).
    fn build_single_shard_proof(key: [u8; 32], value: &[u8]) -> (ShardedBmtProof, B256) {
        let si = (key[0] >> 4) as usize;
        let mut shard = Sbmt::new();
        shard.insert(key, value);

        let mut roots = vec![EMPTY_HASH; 16];
        roots[si] = shard.root_hash();
        let combined = shard_tree_root(&roots);

        let proof = ShardedBmtProof {
            shard_index: si as u8,
            shard_root: roots[si],
            shard_path: shard_tree_path(&roots, si),
            inner: shard.prove(key),
            value: Some(value.to_vec()),
        };
        (proof, B256::from(combined))
    }

    fn build_twig_proof(key: [u8; 32], value: &[u8]) -> (ShardedTwigProof, B256) {
        let mut tree = ShardedTwig::new();
        tree.set(key, value);
        let root = B256::from(tree.root());
        let proof = tree.prove(&key).unwrap();
        (proof, root)
    }

    #[test]
    fn verifies_against_correct_root() {
        let (proof, root) = build_single_shard_proof([0x05; 32], b"account-value");
        assert!(verify_state_proof(&proof, root).is_ok());
    }

    #[test]
    fn rejects_wrong_root() {
        let (proof, _) = build_single_shard_proof([0x05; 32], b"account-value");
        let wrong = B256::from([0xFF; 32]);
        assert!(verify_state_proof(&proof, wrong).is_err());
    }

    #[test]
    fn rejects_tampered_value() {
        let (mut proof, root) = build_single_shard_proof([0x05; 32], b"account-value");
        proof.value = Some(b"forged-value".to_vec());
        assert!(verify_state_proof(&proof, root).is_err());
    }

    #[test]
    fn account_proof_binds_to_address() {
        let addr = Address::repeat_byte(0xAB);
        let key = account_key(&addr.into_array());
        let (proof, root) = build_single_shard_proof(key, b"account-value");

        // Bound verify against the right address passes.
        assert!(verify_account_proof(&proof, root, addr).is_ok());

        // A proof for `addr` must NOT verify as some other account's answer.
        let other = Address::repeat_byte(0xCD);
        assert_eq!(
            verify_account_proof(&proof, root, other),
            Err(BmtVerifyError::KeyMismatch),
        );
    }

    #[test]
    fn rejects_wrong_shard_for_key() {
        // Build a valid proof, then lie about the shard index. Unbound verify
        // would still need the root to match (it won't here), but the bound
        // check rejects on shard mismatch before that.
        let addr = Address::repeat_byte(0xAB);
        let key = account_key(&addr.into_array());
        let (mut proof, root) = build_single_shard_proof(key, b"account-value");
        let real_shard = shard_index_for_key(&key) as u8;
        proof.shard_index = real_shard ^ 0x01; // any other shard
        assert!(matches!(
            verify_account_proof(&proof, root, addr),
            Err(BmtVerifyError::WrongShardForKey { .. }),
        ));
    }

    #[test]
    fn twig_account_proof_binds_to_address() {
        let addr = Address::repeat_byte(0xAB);
        let key = account_key(&addr.into_array());
        let (proof, root) = build_twig_proof(key, b"twig-account-value");

        assert!(verify_twig_state_proof(&proof, root).is_ok());
        assert!(verify_twig_account_proof(&proof, root, addr).is_ok());

        let other = Address::repeat_byte(0xCD);
        assert_eq!(
            verify_twig_account_proof(&proof, root, other),
            Err(TwigVerifyError::KeyMismatch),
        );
    }

    #[test]
    fn twig_rejects_wrong_shard_for_key() {
        let addr = Address::repeat_byte(0xAB);
        let key = account_key(&addr.into_array());
        let (mut proof, root) = build_twig_proof(key, b"twig-account-value");
        let real_shard = shard_index_for_key(&key) as u8;
        proof.shard_index = real_shard ^ 0x01;
        assert!(matches!(
            verify_twig_account_proof(&proof, root, addr),
            Err(TwigVerifyError::WrongShardForKey { .. }),
        ));
    }

    #[test]
    fn twig_storage_proof_binds_to_address_and_slot() {
        let addr = Address::repeat_byte(0xEF);
        let slot = U256::from(42);
        let key = storage_key(&addr.into_array(), &slot.to_be_bytes::<32>());
        let (proof, root) = build_twig_proof(key, b"twig-storage-value");

        assert!(verify_twig_storage_proof(&proof, root, addr, slot).is_ok());
        assert_eq!(
            verify_twig_storage_proof(&proof, root, addr, U256::from(43)),
            Err(TwigVerifyError::KeyMismatch),
        );
    }
}
