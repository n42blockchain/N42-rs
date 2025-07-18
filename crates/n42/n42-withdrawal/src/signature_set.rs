use std::borrow::Cow;
use tree_hash::{Hash256, TreeHash};
use crate::beacon_block_body::{BeaconBlockRef, SignedBeaconBlock};
use crate::beacon_state::{BeaconState, EthSpec, Error as BeaconStateError};
use crate::chain_spec::{ChainSpec, Domain};
use crate::crypto::{PublicKeyBytes, SignatureSet, BlsPublicKey as PublicKey, BlsAggregateSignature as AggregateSignature};
use crate::payload::AbstractExecPayload;
use crate::signature::{InconsistentFork, ProposerSlashing, SignedBeaconBlockHeader, SignedBlsToExecutionChange, SyncAggregate};
use crate::slashing::IndexedAttestationRef;
use crate::slot_epoch::Slot;
use crate::withdrawal::{Fork, SignedRoot, SignedVoluntaryExit, SigningData};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// Attempted to find the public key of a validator that does not exist. You cannot distinguish
    /// between an error and an invalid block in this case.
    ValidatorUnknown(u64),
    /// The `BeaconBlock` has a `proposer_index` that does not match the index we computed locally.
    /// The block is invalid.
    IncorrectBlockProposer { block: u64, local_shuffling: u64 },
    /// The block structure is not appropriate for the fork at `block.slot()`.
    InconsistentBlockFork(InconsistentFork),
    /// Pubkey decompression failed. The block is invalid.
    PublicKeyDecompressionFailed,
    /// There was an error attempting to read from a `BeaconState`. Block
    /// validity was not determined.
    BeaconStateError(crate::beacon_state::Error),
}
impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

/// Returns a signature set that is valid if the `SignedVoluntaryExit` was signed by the indicated
/// validator.
pub fn exit_signature_set<'a, E, F>(
    state: &'a BeaconState<E>,
    get_pubkey: F,
    signed_exit: &'a SignedVoluntaryExit,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>>
where
    E: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>>,
{
    let exit = &signed_exit.message;
    let proposer_index = exit.validator_index as usize;

    let domain = if state.fork_name_unchecked().electra_enabled() {
        // EIP-7044
        spec.compute_domain(
            Domain::VoluntaryExit,
            spec.capella_fork_version,
            state.genesis_validators_root(),
        )
    } else {
        spec.get_domain(
            exit.epoch,
            Domain::VoluntaryExit,
            &state.fork(),
            state.genesis_validators_root(),
        )
    };

    let message = exit.signing_root(domain);

    Ok(SignatureSet::single_pubkey(
        &signed_exit.signature,
        get_pubkey(proposer_index).ok_or(Error::ValidatorUnknown(proposer_index as u64))?,
        message,
    ))
}

/// A signature set that is valid if a block was signed by the expected block producer.
pub fn block_proposal_signature_set<'a, E, F, Payload: AbstractExecPayload<E>>(
    state: &'a BeaconState<E>,
    get_pubkey: F,
    signed_block: &'a SignedBeaconBlock<E, Payload>,
    block_root: Option<Hash256>,
    verified_proposer_index: Option<u64>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>>
where
    E: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>>,
{
    let block = signed_block.message();

    let proposer_index = if let Some(proposer_index) = verified_proposer_index {
        proposer_index
    } else {
        state.get_beacon_proposer_index(block.slot(), spec)? as u64
    };
    if proposer_index != block.proposer_index() {
        return Err(Error::IncorrectBlockProposer {
            block: block.proposer_index(),
            local_shuffling: proposer_index,
        });
    }

    block_proposal_signature_set_from_parts(
        signed_block,
        block_root,
        proposer_index,
        &state.fork(),
        state.genesis_validators_root(),
        get_pubkey,
        spec,
    )
}

/// A signature set that is valid if a block was signed by the expected block producer.
///
/// Unlike `block_proposal_signature_set` this does **not** check that the proposer index is
/// correct according to the shuffling. It should only be used if no suitable `BeaconState` is
/// available.
pub fn block_proposal_signature_set_from_parts<'a, E, F, Payload: AbstractExecPayload<E>>(
    signed_block: &'a SignedBeaconBlock<E, Payload>,
    block_root: Option<Hash256>,
    proposer_index: u64,
    fork: &Fork,
    genesis_validators_root: Hash256,
    get_pubkey: F,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>>
where
    E: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>>,
{
    // Verify that the `SignedBeaconBlock` instantiation matches the fork at `signed_block.slot()`.
    signed_block
        .fork_name(spec)
        .map_err(Error::InconsistentBlockFork)?;

    let block = signed_block.message();
    let domain = spec.get_domain(
        block.slot().epoch(E::slots_per_epoch()),
        Domain::BeaconProposer,
        fork,
        genesis_validators_root,
    );

    let message = if let Some(root) = block_root {
        SigningData {
            object_root: root,
            domain,
        }
            .tree_hash_root()
    } else {
        block.signing_root(domain)
    };

    Ok(SignatureSet::single_pubkey(
        signed_block.signature(),
        get_pubkey(proposer_index as usize).ok_or(Error::ValidatorUnknown(proposer_index))?,
        message,
    ))
}

/// A signature set that is valid if the block proposers randao reveal signature is correct.
pub fn randao_signature_set<'a, E, F, Payload: AbstractExecPayload<E>>(
    state: &'a BeaconState<E>,
    get_pubkey: F,
    block: BeaconBlockRef<'a, E, Payload>,
    verified_proposer_index: Option<u64>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>>
where
    E: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>>,
{
    let proposer_index = if let Some(proposer_index) = verified_proposer_index {
        proposer_index
    } else {
        state.get_beacon_proposer_index(block.slot(), spec)? as u64
    };

    let domain = spec.get_domain(
        block.slot().epoch(E::slots_per_epoch()),
        Domain::Randao,
        &state.fork(),
        state.genesis_validators_root(),
    );

    let message = block
        .slot()
        .epoch(E::slots_per_epoch())
        .signing_root(domain);

    Ok(SignatureSet::single_pubkey(
        block.body().randao_reveal(),
        get_pubkey(proposer_index as usize).ok_or(Error::ValidatorUnknown(proposer_index))?,
        message,
    ))
}

/// Returns two signature sets, one for each `BlockHeader` included in the `ProposerSlashing`.
pub fn proposer_slashing_signature_set<'a, E, F>(
    state: &'a BeaconState<E>,
    get_pubkey: F,
    proposer_slashing: &'a ProposerSlashing,
    spec: &'a ChainSpec,
) -> Result<(SignatureSet<'a>, SignatureSet<'a>)>
where
    E: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>>,
{
    let proposer_index = proposer_slashing.signed_header_1.message.proposer_index as usize;

    Ok((
        block_header_signature_set(
            state,
            &proposer_slashing.signed_header_1,
            get_pubkey(proposer_index).ok_or(Error::ValidatorUnknown(proposer_index as u64))?,
            spec,
        ),
        block_header_signature_set(
            state,
            &proposer_slashing.signed_header_2,
            get_pubkey(proposer_index).ok_or(Error::ValidatorUnknown(proposer_index as u64))?,
            spec,
        ),
    ))
}

/// Returns the signature set for the given `indexed_attestation`.
pub fn indexed_attestation_signature_set<'a, 'b, E, F>(
    state: &'a BeaconState<E>,
    get_pubkey: F,
    signature: &'a AggregateSignature,
    indexed_attestation: IndexedAttestationRef<'b, E>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>>
where
    E: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>>,
{
    let mut pubkeys = Vec::with_capacity(indexed_attestation.attesting_indices_len());
    for &validator_idx in indexed_attestation.attesting_indices_iter() {
        pubkeys.push(
            get_pubkey(validator_idx as usize).ok_or(Error::ValidatorUnknown(validator_idx))?,
        );
    }

    let domain = spec.get_domain(
        indexed_attestation.data().target.epoch,
        Domain::BeaconAttester,
        &state.fork(),
        state.genesis_validators_root(),
    );

    let message = indexed_attestation.data().signing_root(domain);

    Ok(SignatureSet::multiple_pubkeys(signature, pubkeys, message))
}

/// Signature set verifier for a block's `sync_aggregate` (Altair and later).
///
/// The `slot` should be the slot of the block that the sync aggregate is included in, which may be
/// different from `state.slot()`. The `block_root` should be the block root that the sync aggregate
/// signs over. It's passed in rather than extracted from the `state` because when verifying a batch
/// of blocks the `state` will not yet have had the blocks applied.
///
/// Returns `Ok(None)` in the case where `sync_aggregate` has 0 signatures. The spec
/// uses a separate function `eth2_fast_aggregate_verify` for this, but we can equivalently
/// check the exceptional case eagerly and do a `fast_aggregate_verify` in the case where the
/// check fails (by returning `Some(signature_set)`).
pub fn sync_aggregate_signature_set<'a, E, D>(
    decompressor: D,
    sync_aggregate: &'a SyncAggregate<E>,
    slot: Slot,
    block_root: Hash256,
    state: &'a BeaconState<E>,
    spec: &ChainSpec,
) -> Result<Option<SignatureSet<'a>>>
where
    E: EthSpec,
    D: Fn(&'a PublicKeyBytes) -> Option<Cow<'a, PublicKey>>,
{
    // Allow the point at infinity to count as a signature for 0 validators as per
    // `eth2_fast_aggregate_verify` from the spec.
    if sync_aggregate.sync_committee_bits.is_zero()
        && sync_aggregate.sync_committee_signature.is_infinity()
    {
        return Ok(None);
    }

    let committee_pubkeys = &state
        .get_built_sync_committee(slot.epoch(E::slots_per_epoch()), spec)?
        .pubkeys;

    let participant_pubkeys = committee_pubkeys
        .iter()
        .zip(sync_aggregate.sync_committee_bits.iter())
        .filter_map(|(pubkey, bit)| {
            if bit {
                Some(decompressor(pubkey))
            } else {
                None
            }
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::PublicKeyDecompressionFailed)?;

    let previous_slot = slot.saturating_sub(1u64);

    let domain = spec.get_domain(
        previous_slot.epoch(E::slots_per_epoch()),
        Domain::SyncCommittee,
        &state.fork(),
        state.genesis_validators_root(),
    );

    let message = SigningData {
        object_root: block_root,
        domain,
    }
        .tree_hash_root();

    Ok(Some(SignatureSet::multiple_pubkeys(
        &sync_aggregate.sync_committee_signature,
        participant_pubkeys,
        message,
    )))
}

pub fn bls_execution_change_signature_set<'a, E: EthSpec>(
    state: &'a BeaconState<E>,
    signed_address_change: &'a SignedBlsToExecutionChange,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let domain = spec.compute_domain(
        Domain::BlsToExecutionChange,
        spec.genesis_fork_version,
        state.genesis_validators_root(),
    );
    let message = signed_address_change.message.signing_root(domain);
    let signing_key = Cow::Owned(
        signed_address_change
            .message
            .from_bls_pubkey
            .decompress()
            .map_err(|_| Error::PublicKeyDecompressionFailed)?,
    );

    Ok(SignatureSet::single_pubkey(
        &signed_address_change.signature,
        signing_key,
        message,
    ))
}

/// Returns a signature set that is valid if the given `pubkey` signed the `header`.
fn block_header_signature_set<'a, E: EthSpec>(
    state: &'a BeaconState<E>,
    signed_header: &'a SignedBeaconBlockHeader,
    pubkey: Cow<'a,PublicKey>,
    spec: &'a ChainSpec,
) -> SignatureSet<'a> {
    let domain = spec.get_domain(
        signed_header.message.slot.epoch(E::slots_per_epoch()),
        Domain::BeaconProposer,
        &state.fork(),
        state.genesis_validators_root(),
    );

    let message = signed_header.message.signing_root(domain);

    SignatureSet::single_pubkey(&signed_header.signature, pubkey, message)
}