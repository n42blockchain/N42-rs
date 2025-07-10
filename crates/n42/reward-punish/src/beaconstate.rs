use std::fmt;
use serde::{Deserialize, Serialize};
use std::hash::{Hash};
use std::sync::Arc;
use arbitrary;
use milhouse::{List,Vector};
use ssz_derive::{Decode, Encode};
use ssz::{ssz_encode, Decode, DecodeError, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use derivative::Derivative;
use crate::relative_epoch::RelativeEpoch;
use crate::beacon_committee::BeaconCommittee;
use crate::committee_cache::CommitteeCache;
use crate::pending_attestation::PendingAttestation;
use crate::relative_epoch::Error as RelativeEpochError;

// use tree_hash::TreeHash;

// pub type Hash256 = alloy_primitives::B256;
use crate::Hash256;
use crate::spec::{Spec, EthSpec,ForkName};
use crate::arith::{ArithError, SafeArith};
use crate::slot_epoch::{Slot,Epoch};
use superstruct::superstruct;
use metastruct::{metastruct, NumFields};
use typenum::Unsigned;

// pub type Validators<E> = List<Validator, <E as EthSpec>::ValidatorRegistryLimit>;
pub type CommitteeIndex = u64;
pub const CACHED_EPOCHS: usize = 3;


pub type Result<T, E = ArithError> = std::result::Result<T, E>;

#[derive(PartialEq, Clone)]
pub enum Error {
    /// A state for a different hard-fork was required -- a severe logic error.
    IncorrectStateVariant,
    EpochOutOfBounds,
    SlotOutOfBounds,
    UnknownValidator(usize),
    UnableToDetermineProducer,
    InvalidBitfield,
    EmptyCommittee,
    ValidatorIsWithdrawable,
    ValidatorIsInactive {
        val_index: usize,
    },
    UnableToShuffle,
    ShuffleIndexOutOfBounds(usize),
    IsAggregatorOutOfBounds,
    BlockRootsOutOfBounds(usize),
    StateRootsOutOfBounds(usize),
    SlashingsOutOfBounds(usize),
    BalancesOutOfBounds(usize),
    RandaoMixesOutOfBounds(usize),
    CommitteeCachesOutOfBounds(usize),
    ParticipationOutOfBounds(usize),
    InactivityScoresOutOfBounds(usize),
    TooManyValidators,
    InsufficientValidators,
    InsufficientRandaoMixes,
    InsufficientBlockRoots,
    InsufficientIndexRoots,
    InsufficientAttestations,
    InsufficientCommittees,
    InsufficientStateRoots,
    NoCommittee {
        slot: Slot,
        index: CommitteeIndex,
    },
    ZeroSlotsPerEpoch,
    PubkeyCacheInconsistent,
    PubkeyCacheIncomplete {
        cache_len: usize,
        registry_len: usize,
    },
    PreviousCommitteeCacheUninitialized,
    CurrentCommitteeCacheUninitialized,
    TotalActiveBalanceCacheUninitialized,
    TotalActiveBalanceCacheInconsistent {
        initialized_epoch: Epoch,
        current_epoch: Epoch,
    },
    RelativeEpochError(RelativeEpochError),
    ExitCacheUninitialized,
    ExitCacheInvalidEpoch {
        max_exit_epoch: Epoch,
        request_epoch: Epoch,
    },
    SlashingsCacheUninitialized {
        initialized_slot: Option<Slot>,
        latest_block_slot: Slot,
    },
    CommitteeCacheUninitialized(Option<RelativeEpoch>),
    SyncCommitteeCacheUninitialized,
    // BlsError(bls::Error),
    SszTypesError(ssz_types::Error),
    TreeHashCacheNotInitialized,
    NonLinearTreeHashCacheHistory,
    ProgressiveBalancesCacheNotInitialized,
    ProgressiveBalancesCacheInconsistent,
    TreeHashCacheSkippedSlot {
        cache: Slot,
        state: Slot,
    },
    TreeHashError(tree_hash::Error),
    InvalidValidatorPubkey(ssz::DecodeError),
    ValidatorRegistryShrunk,
    TreeHashCacheInconsistent,
    InvalidDepositState {
        deposit_count: u64,
        deposit_index: u64,
    },
    /// Attestation slipped through block processing with a non-matching source.
    IncorrectAttestationSource,
    /// An arithmetic operation occurred which would have overflowed or divided by 0.
    ///
    /// This represents a serious bug in either the spec or Lighthouse!
    ArithError(ArithError),
    // MissingBeaconBlock(SignedBeaconBlockHash),
    // MissingBeaconState(BeaconStateHash),
    PayloadConversionLogicFlaw,
    SyncCommitteeNotKnown {
        current_epoch: Epoch,
        epoch: Epoch,
    },
    MilhouseError(milhouse::Error),
    CommitteeCacheDiffInvalidEpoch {
        prev_current_epoch: Epoch,
        current_epoch: Epoch,
    },
    CommitteeCacheDiffUninitialized {
        expected_epoch: Epoch,
    },
    DiffAcrossFork {
        prev_fork: ForkName,
        current_fork: ForkName,
    },
    TotalActiveBalanceDiffUninitialized,
    GeneralizedIndexNotSupported(usize),
    IndexNotSupported(usize),
    InvalidFlagIndex(usize),
    // MerkleTreeError(merkle_proof::MerkleTreeError),
    PartialWithdrawalCountInvalid(usize),
    NonExecutionAddressWithdrawalCredential,
    NoCommitteeFound(CommitteeIndex),
    InvalidCommitteeIndex(CommitteeIndex),
    InvalidSelectionProof {
        aggregator_index: u64,
    },
    AggregatorNotInCommittee {
        aggregator_index: u64,
    },
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Error {
        Error::ArithError(e)
    }
}


// #[derive(PartialEq, Eq, Hash, Clone, Copy, arbitrary::Arbitrary)]
// pub struct BeaconStateHash(Hash256);
//
// impl fmt::Debug for BeaconStateHash {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "BeaconStateHash({:?})", self.0)
//     }
// }
//
// impl fmt::Display for BeaconStateHash {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "{}", self.0)
//     }
// }
//
// impl From<Hash256> for BeaconStateHash {
//     fn from(hash: Hash256) -> BeaconStateHash {
//         BeaconStateHash(hash)
//     }
// }
//
// impl From<BeaconStateHash> for Hash256 {
//     fn from(beacon_state_hash: BeaconStateHash) -> Hash256 {
//         beacon_state_hash.0
//     }
// }


#[superstruct(
    variants(Base, Altair, Bellatrix, Capella, Deneb, Electra, Fulu),
    variant_attributes(
        derive(
            Derivative,
            Debug,
            PartialEq,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            // arbitrary::Arbitrary,
        ),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        // arbitrary(bound = "E: EthSpec"),
        derivative(Clone),
    ),
    specific_variant_attributes(
        Base(metastruct(
            mappings(
                map_beacon_state_base_fields(),
                map_beacon_state_base_tree_list_fields(mutable, fallible, groups(tree_lists)),
                map_beacon_state_base_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_base_tree_list_fields(
                other_type = "BeaconStateBase",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        )),
        Altair(metastruct(
            mappings(
                map_beacon_state_altair_fields(),
                map_beacon_state_altair_tree_list_fields(mutable, fallible, groups(tree_lists)),
                map_beacon_state_altair_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_altair_tree_list_fields(
                other_type = "BeaconStateAltair",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        )),
        Bellatrix(metastruct(
            mappings(
                map_beacon_state_bellatrix_fields(),
                map_beacon_state_bellatrix_tree_list_fields(mutable, fallible, groups(tree_lists)),
                map_beacon_state_bellatrix_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_bellatrix_tree_list_fields(
                other_type = "BeaconStateBellatrix",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        )),
        Capella(metastruct(
            mappings(
                map_beacon_state_capella_fields(),
                map_beacon_state_capella_tree_list_fields(mutable, fallible, groups(tree_lists)),
                map_beacon_state_capella_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_capella_tree_list_fields(
                other_type = "BeaconStateCapella",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        )),
        Deneb(metastruct(
            mappings(
                map_beacon_state_deneb_fields(),
                map_beacon_state_deneb_tree_list_fields(mutable, fallible, groups(tree_lists)),
                map_beacon_state_deneb_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_deneb_tree_list_fields(
                other_type = "BeaconStateDeneb",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        )),
        Electra(metastruct(
            mappings(
                map_beacon_state_electra_fields(),
                map_beacon_state_electra_tree_list_fields(mutable, fallible, groups(tree_lists)),
                map_beacon_state_electra_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_electra_tree_list_fields(
                other_type = "BeaconStateElectra",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        )),
        Fulu(metastruct(
            mappings(
                map_beacon_state_fulu_fields(),
                map_beacon_state_fulu_tree_list_fields(mutable, fallible, groups(tree_lists)),
                map_beacon_state_fulu_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_fulu_tree_list_fields(
                other_type = "BeaconStateFulu",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        ))
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    map_ref_mut_into(BeaconStateRef)
)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode)]
#[serde(untagged)]
#[serde(bound = "E: EthSpec")]
// #[arbitrary(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
pub struct BeaconState<E>
where
    E: EthSpec,
{
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub slot: Slot,
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    pub balances: List<u64, E::ValidatorRegistryLimit>,

    // #[compare_fields(as_iter)]
    pub validators: List<Validator, E::ValidatorRegistryLimit>,
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub finalized_checkpoint: Checkpoint,
    // Slashings
    #[serde(with = "ssz_types::serde_utils::quoted_u64_fixed_vec")]
    pub slashings: Vector<u64, E::EpochsPerSlashingsVector>,


    // Attestations (genesis fork only)
    #[superstruct(only(Base))]
    // #[test_random(default)]
    pub previous_epoch_attestations: List<PendingAttestation<E>, E::MaxPendingAttestations>,
    #[superstruct(only(Base))]
    // #[test_random(default)]
    pub current_epoch_attestations: List<PendingAttestation<E>, E::MaxPendingAttestations>,


    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[metastruct(exclude)]
    pub committee_caches: [Arc<CommitteeCache>; CACHED_EPOCHS],

}

#[derive(
    arbitrary::Arbitrary,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
)]
pub struct Validator
{
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,

}
#[derive(
    arbitrary::Arbitrary,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Hash,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Hash256,
}


impl Validator {
    /// Returns `true` if the validator is considered active at some epoch.
    pub fn is_active_at(&self, epoch: Epoch) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    /// Returns `true` if the validator is slashable at some epoch.
    pub fn is_slashable_at(&self, epoch: Epoch) -> bool {
        !self.slashed && self.activation_epoch <= epoch && epoch < self.withdrawable_epoch
    }


    /// Returns `true` if the validator is able to withdraw at some epoch.
    pub fn is_withdrawable_at(&self, epoch: Epoch) -> bool {
        epoch >= self.withdrawable_epoch
    }

}



impl<E: EthSpec> BeaconState<E>
{

    /// The epoch corresponding to `self.slot()`.
    pub fn current_epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Does not check if `self` is consistent with the fork dictated by `self.slot()`.
    pub fn fork_name_unchecked(&self) -> ForkName {
        match self {
            BeaconState::Base { .. } => ForkName::Base,
            BeaconState::Altair { .. } => ForkName::Altair,
            BeaconState::Bellatrix { .. } => ForkName::Bellatrix,
            BeaconState::Capella { .. } => ForkName::Capella,
            BeaconState::Deneb { .. } => ForkName::Deneb,
            BeaconState::Electra { .. } => ForkName::Electra,
            BeaconState::Fulu { .. } => ForkName::Fulu,
        }
    }




    // /// Get a reference to the entire `slashings` vector.
    // pub fn get_all_slashings(&self) -> &Vector<u64, E::EpochsPerSlashingsVector> {
    //     self.slashings()
    // }

    /// Safely obtain the index for `slashings`, given some `epoch`.
    pub fn get_slashings_index(
        &self,
        epoch: Epoch,
        allow_next_epoch: AllowNextEpoch,
    ) -> std::result::Result<usize, Error> {
        // We allow the slashings vector to be accessed at any cached epoch at or before
        // the current epoch, or the next epoch if `AllowNextEpoch::True` is passed.
        let current_epoch = self.current_epoch();
        if current_epoch < epoch.safe_add(E::EpochsPerSlashingsVector::to_u64())?
            && epoch <= allow_next_epoch.upper_bound_of(current_epoch)?
        {
            Ok(epoch
                .as_usize()
                .safe_rem(E::EpochsPerSlashingsVector::to_usize())?)
        } else {
            Err(Error::EpochOutOfBounds)
        }
    }

    /// Get the total slashed balances for some epoch.
    pub fn get_slashings(&self, epoch: Epoch) -> Result<u64, Error> {
        let i = self.get_slashings_index(epoch, AllowNextEpoch::False)?;
        self.slashings()
            .get(i)
            .copied()
            .ok_or(Error::SlashingsOutOfBounds(i))
    }
    /// Get a reference to the entire `slashings` vector.
    pub fn get_all_slashings(&self) -> &Vector<u64, E::EpochsPerSlashingsVector> {
        self.slashings()
    }

    /// The epoch prior to `self.current_epoch()`.
    ///
    /// If the current epoch is the genesis epoch, the genesis_epoch is returned.
    pub fn previous_epoch(&self) -> Epoch {
        let current_epoch = self.current_epoch();
        if let Ok(prev_epoch) = current_epoch.safe_sub(1) {
            prev_epoch
        } else {
            current_epoch
        }
    }

    /// Passing `previous_epoch` to this function rather than computing it internally provides
    /// a tangible speed improvement in state processing.
    pub fn is_eligible_validator(
        &self,
        previous_epoch: Epoch,
        val: &Validator,
    ) -> std::result::Result<bool, Error> {
        Ok(val.is_active_at(previous_epoch)
            || (val.slashed && previous_epoch.safe_add(Epoch::new(1))? < val.withdrawable_epoch))
    }

    /// Get a mutable reference to the balance of a single validator.
    pub fn get_balance_mut(&mut self, validator_index: usize) -> std::result::Result<&mut u64, Error> {
        self.balances_mut()
            .get_mut(validator_index)
            .ok_or(Error::BalancesOutOfBounds(validator_index))
    }

    /// Get the Beacon committee at the given slot and index.
    ///
    /// Utilises the committee cache.
    ///
    /// Spec v0.12.1
    pub fn get_beacon_committee(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> std::result::Result<BeaconCommittee<'_>, Error> {
        let epoch = slot.epoch(E::slots_per_epoch());
        let relative_epoch = RelativeEpoch::from_epoch(self.current_epoch(), epoch)?;
        let cache = self.committee_cache(relative_epoch)?;

        cache
            .get_beacon_committee(slot, index)
            .ok_or(Error::NoCommittee { slot, index })
    }

    /// Returns the cache for some `RelativeEpoch`. Returns an error if the cache has not been
    /// initialized.
    pub fn committee_cache(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> std::result::Result<&Arc<CommitteeCache>, Error> {
        let i = Self::committee_cache_index(relative_epoch);
        let cache = self.committee_cache_at_index(i)?;

        if cache.is_initialized_at(relative_epoch.into_epoch(self.current_epoch())) {
            Ok(cache)
        } else {
            Err(Error::CommitteeCacheUninitialized(Some(relative_epoch)))
        }
    }

    /// Get the committee cache at a given index.
    fn committee_cache_at_index(&self, index: usize) -> std::result::Result<&Arc<CommitteeCache>, Error> {
        self.committee_caches()
            .get(index)
            .ok_or(Error::CommitteeCachesOutOfBounds(index))
    }

    pub(crate) fn committee_cache_index(relative_epoch: RelativeEpoch) -> usize {
        match relative_epoch {
            RelativeEpoch::Previous => 0,
            RelativeEpoch::Current => 1,
            RelativeEpoch::Next => 2,
        }
    }





}



/// Control whether an epoch-indexed field can be indexed at the next epoch or not.
#[derive(Debug, PartialEq, Clone, Copy)]
enum AllowNextEpoch {
    True,
    False,
}

impl AllowNextEpoch {
    fn upper_bound_of(self, current_epoch: Epoch) -> std::result::Result<Epoch, ArithError> {
        match self {
            AllowNextEpoch::True => Ok(current_epoch.safe_add(1)?),
            AllowNextEpoch::False => Ok(current_epoch),
        }
    }
}

impl From<RelativeEpochError> for Error {
    fn from(e: RelativeEpochError) -> Error {
        Error::RelativeEpochError(e)
    }
}

impl From<tree_hash::Error> for Error {
    fn from(e: tree_hash::Error) -> Error {
        Error::TreeHashError(e)
    }
}

impl From<ssz_types::Error> for Error {
    fn from(e: ssz_types::Error) -> Error {
        Error::SszTypesError(e)
    }
}