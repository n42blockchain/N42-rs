use tree_hash::TreeHash;
use crate::beacon_state::{BeaconState, EthSpec};
use crate::chain_spec::ChainSpec;
use crate::crypto::{PublicKeyBytes, BlsPublicKey as PublicKey, BlsSignature as Signature};
use crate::error::{BlockOperationError, DepositInvalid};
use crate::{H256, Hash256};
use crate::safe_aitrh::SafeArith;
use crate::withdrawal::{Deposit, DepositData, SignedRoot};
use ethereum_hashing::{hash, hash32_concat};


type Result<T> = std::result::Result<T, BlockOperationError<DepositInvalid>>;
fn error(reason: DepositInvalid) -> BlockOperationError<DepositInvalid> {
    BlockOperationError::invalid(reason)
}

/// Verify that a deposit is included in the state's eth1 deposit root.
///
/// The deposit index is provided as a parameter so we can check proofs
/// before they're due to be processed, and in parallel.
///
/// Spec v0.12.1
pub fn verify_deposit_merkle_proof<E: EthSpec>(
    state: &BeaconState<E>,
    deposit: &Deposit,
    deposit_index: u64,
    spec: &ChainSpec,
) -> Result<()> {
    let leaf = deposit.data.tree_hash_root();

    verify!(
        verify_merkle_proof(
            leaf,
            &deposit.proof[..],
            spec.deposit_contract_tree_depth.safe_add(1)? as usize,
            deposit_index as usize,
            state.eth1_data().deposit_root,
        ),
        DepositInvalid::BadMerkleProof
    );

    Ok(())
}

/// Returns a `Some(validator index)` if a pubkey already exists in the `validators`,
/// otherwise returns `None`.
///
/// Builds the pubkey cache if it is not already built.
pub fn get_existing_validator_index<E: EthSpec>(
    state: &mut BeaconState<E>,
    pub_key: &PublicKeyBytes,
) -> Result<Option<u64>> {
    let validator_index = state.get_validator_index(pub_key)?;
    Ok(validator_index.map(|idx| idx as u64))
}

/// Verify a proof that `leaf` exists at `index` in a Merkle tree rooted at `root`.
///
/// The `branch` argument is the main component of the proof: it should be a list of internal
/// node hashes such that the root can be reconstructed (in bottom-up order).
pub fn verify_merkle_proof(
    leaf: H256,
    branch: &[H256],
    depth: usize,
    index: usize,
    root: H256,
) -> bool {
    if branch.len() == depth {
        merkle_root_from_branch(leaf, branch, depth, index) == root
    } else {
        false
    }
}

pub fn merkle_root_from_branch(leaf: H256, branch: &[H256], depth: usize, index: usize) -> H256 {
    assert_eq!(branch.len(), depth, "proof length should equal depth");

    let mut merkle_root = leaf.as_slice().to_vec();

    for (i, leaf) in branch.iter().enumerate().take(depth) {
        let ith_bit = (index >> i) & 0x01;
        if ith_bit == 1 {
            merkle_root = hash32_concat(leaf.as_slice(), &merkle_root)[..].to_vec();
        } else {
            let mut input = merkle_root;
            input.extend_from_slice(leaf.as_slice());
            merkle_root = hash(&input);
        }
    }

    H256::from_slice(&merkle_root)
}



/// Verify `Deposit.pubkey` signed `Deposit.signature`.
///
/// Spec v0.12.1
pub fn is_valid_deposit_signature(deposit_data: &DepositData, spec: &ChainSpec) -> Result<()> {
    let (public_key, signature, msg) = deposit_pubkey_signature_message(deposit_data, spec)
        .ok_or_else(|| error(DepositInvalid::BadBlsBytes))?;

    verify!(
        signature.verify(&public_key, msg),
        DepositInvalid::BadSignature
    );

    Ok(())
}

/// Returns the BLS values in a `Deposit`, if they're all valid. Otherwise, returns `None`.
pub fn deposit_pubkey_signature_message(
    deposit_data: &DepositData,
    spec: &ChainSpec,
) -> Option<(PublicKey, Signature, Hash256)> {
    let pubkey = deposit_data.pubkey.decompress().ok()?;
    let signature = deposit_data.signature.decompress().ok()?;
    let domain = spec.get_deposit_domain();
    let message = deposit_data.as_deposit_message().signing_root(domain);
    Some((pubkey, signature, message))
}