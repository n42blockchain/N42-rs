use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use derivative::Derivative;
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use serde::{Deserialize, Serialize};
use ssz_types::{BitVector};
use crate::beacon_block_body::{AttestationRef, SignedBeaconBlock};
use crate::beacon_state::{BeaconState, EthSpec, Error as BeaconStateError};
use crate::chain_spec::{ChainSpec};
use crate::withdrawal::{Checkpoint, SignedRoot};
use crate::crypto::{BlsPublicKey as PublicKey, PublicKeyBytes, BlsSignature as Signature, SignatureSet};
use crate::crypto::fake_crypto_implementations::AggregateSignature;
use crate::error::{AttestationInvalid, BlockOperationError};
use crate::fork_name::ForkName;
use crate::payload::AbstractExecPayload;
use crate::slot_epoch::{Epoch, Slot};
use crate::{CommitteeIndex, Hash256};
use crate::signature_set::{Error as SignatureSetError, *};
use crate::slashing::{AttesterSlashingRef, IndexedAttestation, IndexedAttestationRef};

pub type Result<T> = std::result::Result<T, Error>;


#[derive(Default, Clone, Debug, PartialEq)]
pub struct BeaconCommittee<'a> {
    pub slot: Slot,
    pub index: CommitteeIndex,
    pub committee: &'a [usize],
}

#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Eq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct SignedBlsToExecutionChange {
    pub message: BlsToExecutionChange,
    pub signature: Signature,
}

#[derive(
    arbitrary::Arbitrary, Debug, PartialEq,
    Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct BlsToExecutionChange {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub from_bls_pubkey: PublicKeyBytes,
    // #[serde(with = "serde_utils::address_hex")]
    // pub to_execution_address: Address,
}

impl SignedRoot for BlsToExecutionChange {}

#[derive(
    Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
pub struct SyncAggregate<E: EthSpec> {
    pub sync_committee_bits: BitVector<E::SyncCommitteeSize>,
    pub sync_committee_signature: AggregateSignature,
}

/// The data upon which an attestation is based.
#[derive(
    arbitrary::Arbitrary,
    Debug,
    Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Encode, Decode, TreeHash, Default,
)]
pub struct AttestationData {
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,

    // LMD GHOST vote
    pub beacon_block_root: Hash256,

    // FFG Vote
    pub source: Checkpoint,
    pub target: Checkpoint,
}

impl SignedRoot for AttestationData {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InconsistentFork {
    pub fork_at_slot: ForkName,
    pub object_fork: ForkName,
}

/// Two conflicting proposals from the same proposer (validator).
#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Eq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

/// A signed header of a `BeaconBlock`.
#[derive(
    arbitrary::Arbitrary, Debug, Clone, PartialEq, Eq, Hash,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: Signature,
}
/// A header of a `BeaconBlock`.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Eq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub body_root: Hash256,
}
impl SignedRoot for BeaconBlockHeader {}

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// All public keys were found but signature verification failed. The block is invalid.
    SignatureInvalid,
    /// Error related to the consensus context, likely the proposer index or block root calc.
    ContextError(ContextError),
    /// The `BeaconBlock` has a `proposer_index` that does not match the index we computed locally.
    /// The block is invalid.
    IncorrectBlockProposer { block: u64, local_shuffling: u64 },
    /// An attestation in the block was invalid. The block is invalid.
    AttestationValidationError(BlockOperationError<AttestationInvalid>),
    /// There was an error attempting to read from a `BeaconState`. Block
    /// validity was not determined.
    BeaconStateError(BeaconStateError),
    /// Failed to load a signature set. The block may be invalid or we failed to process it.
    SignatureSetError(SignatureSetError),
}
impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<ContextError> for Error {
    fn from(e: ContextError) -> Error {
        Error::ContextError(e)
    }
}

impl From<SignatureSetError> for Error {
    fn from(e: SignatureSetError) -> Error {
        match e {
            // Make a special distinction for `IncorrectBlockProposer` since it indicates an
            // invalid block, not an internal error.
            SignatureSetError::IncorrectBlockProposer {
                block,
                local_shuffling,
            } => Error::IncorrectBlockProposer {
                block,
                local_shuffling,
            },
            e => Error::SignatureSetError(e),
        }
    }
}

impl From<BlockOperationError<AttestationInvalid>> for Error {
    fn from(e: BlockOperationError<AttestationInvalid>) -> Error {
        Error::AttestationValidationError(e)
    }
}



#[derive(Debug, PartialEq, Clone)]
pub enum ContextError {
    BeaconState(BeaconStateError),
    SlotMismatch { slot: Slot, expected: Slot },
    EpochMismatch { epoch: Epoch, expected: Epoch },
}
impl From<BeaconStateError> for ContextError {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconState(e)
    }
}
#[derive(Debug, PartialEq, Clone)]
pub struct ConsensusContext<E: EthSpec> {
    /// Slot to act as an identifier/safeguard
    pub slot: Slot,
    /// Previous epoch of the `slot` precomputed for optimization purpose.
    pub previous_epoch: Epoch,
    /// Current epoch of the `slot` precomputed for optimization purpose.
    pub current_epoch: Epoch,
    /// Proposer index of the block at `slot`.
    pub proposer_index: Option<u64>,
    /// Block root of the block at `slot`.
    pub current_block_root: Option<Hash256>,
    /// Cache of indexed attestations constructed during block processing.
    pub indexed_attestations: HashMap<Hash256, IndexedAttestation<E>>,
}
impl<E: EthSpec> ConsensusContext<E> {
    pub fn get_current_block_root<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &SignedBeaconBlock<E, Payload>,
    ) -> std::result::Result<Hash256, ContextError> {
        self.check_slot(block.slot())?;

        if let Some(current_block_root) = self.current_block_root {
            return Ok(current_block_root);
        }

        let current_block_root = block.message().tree_hash_root();
        self.current_block_root = Some(current_block_root);
        Ok(current_block_root)
    }

    fn check_slot(&self, slot: Slot) -> std::result::Result<(), ContextError> {
        if slot == self.slot {
            Ok(())
        } else {
            Err(ContextError::SlotMismatch {
                slot,
                expected: self.slot,
            })
        }
    }
    /// More liberal method for fetching the proposer index.
    /// Fetches the proposer index for `self.slot` but does not require the state to be from an
    /// exactly matching slot (merely a matching epoch). This is useful in batch verification where
    /// we want to extract the proposer index from a single state for every slot in the epoch.
    pub fn get_proposer_index_from_epoch_state(
        &mut self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> std::result::Result<u64, ContextError> {
        self.check_epoch(state.current_epoch())?;
        self.get_proposer_index_no_checks(state, spec)
    }
    fn check_epoch(&self, epoch: Epoch) -> std::result::Result<(), ContextError> {
        let expected = self.slot.epoch(E::slots_per_epoch());
        if epoch == expected {
            Ok(())
        } else {
            Err(ContextError::EpochMismatch { epoch, expected })
        }
    }

    fn get_proposer_index_no_checks(
        &mut self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> std::result::Result<u64, ContextError> {
        if let Some(proposer_index) = self.proposer_index {
            return Ok(proposer_index);
        }

        let proposer_index = state.get_beacon_proposer_index(self.slot, spec)? as u64;
        self.proposer_index = Some(proposer_index);
        Ok(proposer_index)
    }

    #[allow(unknown_lints)]
    #[allow(elided_named_lifetimes)]
    pub fn get_indexed_attestation<'a>(
        &'a mut self,
        state: &BeaconState<E>,
        attestation: AttestationRef<'a, E>,
    ) -> std::result::Result<IndexedAttestationRef<E>, BlockOperationError<AttestationInvalid>> {
        let key = attestation.tree_hash_root();
        match attestation {
            AttestationRef::Electra(attn) => match self.indexed_attestations.entry(key) {
                Entry::Occupied(occupied) => Ok(occupied.into_mut()),
                Entry::Vacant(vacant) => {
                    let indexed_attestation =
                        attesting_indices_electra::get_indexed_attestation_from_state(state, attn)?;
                    Ok(vacant.insert(indexed_attestation))
                }
            },
        }
            .map(|indexed_attestation| (*indexed_attestation).to_ref())
    }
}

pub mod attesting_indices_electra {
    use std::collections::HashSet;
    use ssz_types::{BitList, BitVector, VariableList};
    use crate::beacon_block_body::AttestationElectra;
    use crate::beacon_state::{BeaconState, EthSpec, Error as BeaconStateError, Error};
    use crate::CommitteeIndex;
    use crate::error::BlockOperationError;
    use crate::signature::{BeaconCommittee, IndexedAttestation};
    use crate::error::AttestationInvalid as Invalid;
    use crate::safe_aitrh::SafeArith;
    use crate::slashing::IndexedAttestationElectra;

    pub fn get_indexed_attestation_from_state<E: EthSpec>(
        beacon_state: &BeaconState<E>,
        attestation: &AttestationElectra<E>,
    ) -> Result<IndexedAttestation<E>, BlockOperationError<Invalid>> {
        let committees = beacon_state.get_beacon_committees_at_slot(attestation.data.slot)?;
        get_indexed_attestation(&committees, attestation)
    }

    /// Compute an Electra IndexedAttestation given a list of committees.
    ///
    /// Committees must be sorted by ascending order 0..committees_per_slot
    pub fn get_indexed_attestation<E: EthSpec>(
        committees: &[BeaconCommittee],
        attestation: &AttestationElectra<E>,
    ) -> Result<IndexedAttestation<E>, BlockOperationError<Invalid>> {
        let attesting_indices = get_attesting_indices::<E>(
            committees,
            &attestation.aggregation_bits,
            &attestation.committee_bits,
        )?;

        Ok(IndexedAttestation::Electra(IndexedAttestationElectra {
            attesting_indices: VariableList::new(attesting_indices)?,
            data: attestation.data.clone(),
            signature: attestation.signature.clone(),
        }))
    }

    /// Returns validator indices which participated in the attestation, sorted by increasing index.
    ///
    /// Committees must be sorted by ascending order 0..committees_per_slot
    pub fn get_attesting_indices<E: EthSpec>(
        committees: &[BeaconCommittee],
        aggregation_bits: &BitList<E::MaxValidatorsPerSlot>,
        committee_bits: &BitVector<E::MaxCommitteesPerSlot>,
    ) -> Result<Vec<u64>, BeaconStateError> {
        let mut attesting_indices = vec![];

        let committee_indices = get_committee_indices::<E>(committee_bits);

        let mut committee_offset = 0;

        let committee_count_per_slot = committees.len() as u64;
        let mut participant_count = 0;
        for committee_index in committee_indices {
            let beacon_committee = committees
                .get(committee_index as usize)
                .ok_or(Error::NoCommitteeFound(committee_index))?;

            // This check is new to the spec's `process_attestation` in Electra.
            if committee_index >= committee_count_per_slot {
                return Err(BeaconStateError::InvalidCommitteeIndex(committee_index));
            }
            participant_count.safe_add_assign(beacon_committee.committee.len() as u64)?;
            let committee_attesters = beacon_committee
                .committee
                .iter()
                .enumerate()
                .filter_map(|(i, &index)| {
                    if let Ok(aggregation_bit_index) = committee_offset.safe_add(i) {
                        if aggregation_bits.get(aggregation_bit_index).unwrap_or(false) {
                            return Some(index as u64);
                        }
                    }
                    None
                })
                .collect::<HashSet<u64>>();

            // Require at least a single non-zero bit for each attesting committee bitfield.
            // This check is new to the spec's `process_attestation` in Electra.
            if committee_attesters.is_empty() {
                return Err(BeaconStateError::EmptyCommittee);
            }

            attesting_indices.extend(committee_attesters);
            committee_offset.safe_add_assign(beacon_committee.committee.len())?;
        }

        // This check is new to the spec's `process_attestation` in Electra.
        if participant_count as usize != aggregation_bits.len() {
            return Err(BeaconStateError::InvalidBitfield);
        }

        attesting_indices.sort_unstable();

        Ok(attesting_indices)
    }


    pub fn get_committee_indices<E: EthSpec>(
        committee_bits: &BitVector<E::MaxCommitteesPerSlot>,
    ) -> Vec<CommitteeIndex> {
        committee_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
            .collect()
    }
}

/// Reads the BLS signatures and keys from a `SignedBeaconBlock`, storing them as a `Vec<SignatureSet>`.
///
/// This allows for optimizations related to batch BLS operations (see the
/// `Self::verify_entire_block(..)` function).
pub struct BlockSignatureVerifier<'a, E, F, D>
where
    E: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>> + Clone,
    D: Fn(&'a PublicKeyBytes) -> Option<Cow<'a, PublicKey>>,
{
    get_pubkey: F,
    decompressor: D,
    state: &'a BeaconState<E>,
    spec: &'a ChainSpec,
    sets: ParallelSignatureSets<'a>,
}

#[derive(Default)]
pub struct ParallelSignatureSets<'a> {
    sets: Vec<SignatureSet<'a>>,
}
impl<'a> ParallelSignatureSets<'a> {
    pub fn push(&mut self, set: SignatureSet<'a>) {
        self.sets.push(set);
    }
    #[must_use]
    pub fn verify(self) -> bool {
        verify_signature_sets(self.sets.iter())
    }
}
pub fn verify_signature_sets<'a>(
    _signature_sets: impl ExactSizeIterator<Item = &'a SignatureSet<'a>>,
) -> bool {
    true
}

impl<'a, E, F, D> BlockSignatureVerifier<'a, E, F, D>
where
    E: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>> + Clone,
    D: Fn(&'a PublicKeyBytes) -> Option<Cow<'a, PublicKey>>,
{
    /// Verify all* the signatures in the given `SignedBeaconBlock`, returning `Ok(())` if the signatures
    /// are valid.
    ///
    /// * : _Does not verify any signatures in `block.body.deposits`. A block is still valid if it
    ///   contains invalid signatures on deposits._
    ///
    /// See `Self::verify` for more detail.
    pub fn verify_entire_block<Payload: AbstractExecPayload<E>>(
        state: &'a BeaconState<E>,
        get_pubkey: F,
        decompressor: D,
        block: &'a SignedBeaconBlock<E, Payload>,
        ctxt: &mut ConsensusContext<E>,
        spec: &'a ChainSpec,
    ) -> Result<()> {
        let mut verifier = Self::new(state, get_pubkey, decompressor, spec);
        verifier.include_all_signatures(block, ctxt)?;
        verifier.verify()
    }

    /// Create a new verifier without any included signatures. See the `include...` functions to
    /// add signatures, and the `verify`
    pub fn new(
        state: &'a BeaconState<E>,
        get_pubkey: F,
        decompressor: D,
        spec: &'a ChainSpec,
    ) -> Self {
        Self {
            get_pubkey,
            decompressor,
            state,
            spec,
            sets: ParallelSignatureSets::default(),
        }
    }

    /// Includes all signatures on the block (except the deposit signatures) for verification.
    pub fn include_all_signatures<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
        ctxt: &mut ConsensusContext<E>,
    ) -> Result<()> {
        let block_root = Some(ctxt.get_current_block_root(block)?);
        let verified_proposer_index =
            Some(ctxt.get_proposer_index_from_epoch_state(self.state, self.spec)?);

        self.include_block_proposal(block, block_root, verified_proposer_index)?;
        self.include_all_signatures_except_proposal(block, ctxt)?;

        Ok(())
    }

    /// Includes the block signature for `self.block` for verification.
    pub fn include_block_proposal<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
        block_root: Option<Hash256>,
        verified_proposer_index: Option<u64>,
    ) -> Result<()> {
        let set = block_proposal_signature_set(
            self.state,
            self.get_pubkey.clone(),
            block,
            block_root,
            verified_proposer_index,
            self.spec,
        )?;
        self.sets.push(set);
        Ok(())
    }

    /// Includes all signatures on the block (except the deposit signatures and the proposal
    /// signature) for verification.
    pub fn include_all_signatures_except_proposal<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
        ctxt: &mut ConsensusContext<E>,
    ) -> Result<()> {
        let verified_proposer_index =
            Some(ctxt.get_proposer_index_from_epoch_state(self.state, self.spec)?);
        self.include_randao_reveal(block, verified_proposer_index)?;
        self.include_proposer_slashings(block)?;
        self.include_attester_slashings(block)?;
        self.include_attestations(block, ctxt)?;
        // Deposits are not included because they can legally have invalid signatures.
        self.include_exits(block)?;
        self.include_sync_aggregate(block)?;
        self.include_bls_to_execution_changes(block)?;

        Ok(())
    }
    /// Includes the randao signature for `self.block` for verification.
    pub fn include_randao_reveal<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
        verified_proposer_index: Option<u64>,
    ) -> Result<()> {
        let set = randao_signature_set(
            self.state,
            self.get_pubkey.clone(),
            block.message(),
            verified_proposer_index,
            self.spec,
        )?;
        self.sets.push(set);
        Ok(())
    }
    /// Includes all signatures in `self.block.body.proposer_slashings` for verification.
    pub fn include_proposer_slashings<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
    ) -> Result<()> {
        self.sets
            .sets
            .reserve(block.message().body().proposer_slashings().len() * 2);

        block
            .message()
            .body()
            .proposer_slashings()
            .iter()
            .try_for_each(|proposer_slashing| {
                let (set_1, set_2) = proposer_slashing_signature_set(
                    self.state,
                    self.get_pubkey.clone(),
                    proposer_slashing,
                    self.spec,
                )?;

                self.sets.push(set_1);
                self.sets.push(set_2);

                Ok(())
            })
    }

    /// Includes all signatures in `self.block.body.attester_slashings` for verification.
    pub fn include_attester_slashings<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
    ) -> Result<()> {
        self.sets
            .sets
            .reserve(block.message().body().attester_slashings_len() * 2);

        block
            .message()
            .body()
            .attester_slashings()
            .try_for_each(|attester_slashing| {
                let (set_1, set_2) = attester_slashing_signature_sets(
                    self.state,
                    self.get_pubkey.clone(),
                    attester_slashing,
                    self.spec,
                )?;

                self.sets.push(set_1);
                self.sets.push(set_2);

                Ok(())
            })
    }

    /// Includes all signatures in `self.block.body.attestations` for verification.
    pub fn include_attestations<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
        ctxt: &mut ConsensusContext<E>,
    ) -> Result<()> {
        self.sets
            .sets
            .reserve(block.message().body().attestations_len());

        block
            .message()
            .body()
            .attestations()
            .try_for_each(|attestation| {
                let indexed_attestation = ctxt.get_indexed_attestation(self.state, attestation)?;

                self.sets.push(indexed_attestation_signature_set(
                    self.state,
                    self.get_pubkey.clone(),
                    attestation.signature(),
                    indexed_attestation,
                    self.spec,
                )?);
                Ok(())
            })
    }

    /// Includes all signatures in `self.block.body.voluntary_exits` for verification.
    pub fn include_exits<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
    ) -> Result<()> {
        self.sets
            .sets
            .reserve(block.message().body().voluntary_exits().len());

        block
            .message()
            .body()
            .voluntary_exits()
            .iter()
            .try_for_each(|exit| {
                let exit =
                    exit_signature_set(self.state, self.get_pubkey.clone(), exit, self.spec)?;

                self.sets.push(exit);

                Ok(())
            })
    }

    /// Include the signature of the block's sync aggregate (if it exists) for verification.
    pub fn include_sync_aggregate<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
    ) -> Result<()> {
        if let Ok(sync_aggregate) = block.message().body().sync_aggregate() {
            if let Some(signature_set) = sync_aggregate_signature_set(
                &self.decompressor,
                sync_aggregate,
                block.slot(),
                block.parent_root(),
                self.state,
                self.spec,
            )? {
                self.sets.push(signature_set);
            }
        }
        Ok(())
    }

    /// Include the signature of the block's BLS to execution changes for verification.
    pub fn include_bls_to_execution_changes<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
    ) -> Result<()> {
        // To improve performance we might want to decompress the withdrawal pubkeys in parallel.
        if let Ok(bls_to_execution_changes) = block.message().body().bls_to_execution_changes() {
            for bls_to_execution_change in bls_to_execution_changes {
                self.sets.push(bls_execution_change_signature_set(
                    self.state,
                    bls_to_execution_change,
                    self.spec,
                )?);
            }
        }
        Ok(())
    }

    /// Verify all the signatures that have been included in `self`, returning `true` if and only if
    /// all the signatures are valid.
    ///
    /// See `ParallelSignatureSets::verify` for more info.
    pub fn verify(self) -> Result<()> {
        if self.sets.verify() {
            Ok(())
        } else {
            Err(Error::SignatureInvalid)
        }
    }
}

/// Returns the signature set for the given `attester_slashing` and corresponding `pubkeys`.
pub fn attester_slashing_signature_sets<'a, E, F>(
    state: &'a BeaconState<E>,
    get_pubkey: F,
    attester_slashing: AttesterSlashingRef<'a, E>,
    spec: &'a ChainSpec,
) -> Result<(SignatureSet<'a>, SignatureSet<'a>)>
where
    E: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>> + Clone,
{
    Ok((
        indexed_attestation_signature_set(
            state,
            get_pubkey.clone(),
            attester_slashing.attestation_1().signature(),
            attester_slashing.attestation_1(),
            spec,
        )?,
        indexed_attestation_signature_set(
            state,
            get_pubkey,
            attester_slashing.attestation_2().signature(),
            attester_slashing.attestation_2(),
            spec,
        )?,
    ))
}





