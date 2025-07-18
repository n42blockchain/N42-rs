
use serde::{Deserialize, Serialize};
use std::hash::{Hash};
use std::mem;
use std::sync::Arc;
use arbitrary;
use milhouse::{List,Vector};
use ssz_derive::{Decode, Encode};
use ssz::{ssz_encode, Decode, DecodeError, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use derivative::Derivative;
use ethereum_hashing::hash;
use crate::relative_epoch::RelativeEpoch;
use crate::beacon_committee::BeaconCommittee;
use crate::committee_cache::CommitteeCache;
use crate::pending_attestation::PendingAttestation;
use crate::relative_epoch::Error as RelativeEpochError;
use crate::spec::Domain;
use crate::{int_to_bytes4, int_to_bytes8};

use crate::Hash256;
use crate::spec::{Spec, EthSpec};
use crate::fork_name::ForkName;
use crate::arith::{ArithError, SafeArith};
use crate::slot_epoch::{Slot,Epoch};
use crate::fork_name::InconsistentFork;

use superstruct::superstruct;
use metastruct::{metastruct, NumFields};
use typenum::Unsigned;
// use n42_withdrawals::crypto::PublicKeyBytes;



use crate::common::participation_flags::ParticipationFlags;
use crate::common::progressive_balance_cache::ProgressiveBalancesCache;
use n42_withdrawals::exit_cache::{ExitCache};
use crate::common::epoch_cache::{EpochCache};
use crate::common::sync_committee::SyncCommittee;


pub type Validators<E> = List<Validator, <E as EthSpec>::ValidatorRegistryLimit>;
pub type Balances<E> = List<u64, <E as EthSpec>::ValidatorRegistryLimit>;
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


    // Randomness
    // #[test_random(default)]
    pub randao_mixes: Vector<Hash256, E::EpochsPerHistoricalVector>,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    // #[test_random(default)]
    #[metastruct(exclude)]
    pub total_active_balance: Option<(Epoch, u64)>,


    // Participation (Altair and later)
    // #[compare_fields(as_iter)]
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra, Fulu))]
    // #[test_random(default)]
    // #[compare_fields(as_iter)]
    pub previous_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra, Fulu))]
    // #[test_random(default)]
    pub current_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,


    // Inactivity
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra, Fulu))]
    // #[test_random(default)]
    pub inactivity_scores: List<u64, E::ValidatorRegistryLimit>,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    // #[test_random(default)]
    #[metastruct(exclude)]
    pub progressive_balances_cache: ProgressiveBalancesCache,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    // #[test_random(default)]
    #[metastruct(exclude)]
    pub exit_cache: ExitCache,

    /// Epoch cache of values that are useful for block processing that are static over an epoch.
    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    // #[test_random(default)]
    #[metastruct(exclude)]
    pub epoch_cache: EpochCache,


    // Light-client sync committees
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra, Fulu))]
    #[metastruct(exclude_from(tree_lists))]
    pub current_sync_committee: Arc<SyncCommittee<E>>,


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
    // pub pubkey: PublicKeyBytes,
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_epoch: Epoch,
    pub work_epoch: Epoch,
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

    pub fn get_work_epoch(&self) -> Epoch {
        self.work_epoch
    }

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



    // /// Sets the latest state root for slot.
    // pub fn set_state_root(&mut self, slot: Slot, state_root: Hash256) -> std::result::Result<(), Error> {
    //     let i = self.get_latest_state_roots_index(slot)?;
    //     *self
    //         .state_roots_mut()
    //         .get_mut(i)
    //         .ok_or(Error::StateRootsOutOfBounds(i))? = state_root;
    //     Ok(())
    // }
    /// Safely obtains the index for latest state roots, given some `slot`.
    ///
    /// Spec v0.12.1
    // fn get_latest_state_roots_index(&self, slot: Slot) -> std::result::Result<usize, Error> {
    //     if slot < self.slot() && self.slot() <= slot.safe_add(self.state_roots().len() as u64)? {
    //         Ok(slot.as_usize().safe_rem(self.state_roots().len())?)
    //     } else {
    //         Err(Error::SlotOutOfBounds)
    //     }
    // }

    /// Compute the tree hash root of the state using the tree hash cache.
    ///
    /// Initialize the tree hash cache if it isn't already initialized.
    // pub fn update_tree_hash_cache<'a>(&'a mut self) -> std::result::Result<Hash256, Error> {
    //     self.apply_pending_mutations()?;
    //     map_beacon_state_ref!(&'a _, self.to_ref(), |inner, cons| {
    //         let root = inner.tree_hash_root();
    //         cons(inner);
    //         Ok(root)
    //     })
    // }

    // #[allow(clippy::arithmetic_side_effects)]
    // pub fn apply_pending_mutations(&mut self) -> std::result::Result<(), Error> {
    //     match self {
    //         Self::Base(inner) => {
    //             map_beacon_state_base_tree_list_fields!(inner, |_, x| { x.apply_updates() })
    //         }
    //         Self::Altair(inner) => {
    //             map_beacon_state_altair_tree_list_fields!(inner, |_, x| { x.apply_updates() })
    //         }
    //         Self::Bellatrix(inner) => {
    //             map_beacon_state_bellatrix_tree_list_fields!(inner, |_, x| { x.apply_updates() })
    //         }
    //         Self::Capella(inner) => {
    //             map_beacon_state_capella_tree_list_fields!(inner, |_, x| { x.apply_updates() })
    //         }
    //         Self::Deneb(inner) => {
    //             map_beacon_state_deneb_tree_list_fields!(inner, |_, x| { x.apply_updates() })
    //         }
    //         Self::Electra(inner) => {
    //             map_beacon_state_electra_tree_list_fields!(inner, |_, x| { x.apply_updates() })
    //         }
    //         Self::Fulu(inner) => {
    //             map_beacon_state_fulu_tree_list_fields!(inner, |_, x| { x.apply_updates() })
    //         }
    //     }
    //     Ok(())
    // }


    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &Spec) -> std::result::Result<ForkName, InconsistentFork> {
        let fork_at_slot = spec.fork_name_at_epoch(self.current_epoch());
        let object_fork = self.fork_name_unchecked();

        if fork_at_slot == object_fork {
            Ok(object_fork)
        } else {
            Err(InconsistentFork {
                fork_at_slot,
                object_fork,
            })
        }
    }



    /// The epoch following `self.current_epoch()`.
    ///
    /// Spec v0.12.1
    pub fn next_epoch(&self) -> std::result::Result<Epoch, Error> {
        Ok(self.current_epoch().safe_add(1)?)
    }

    /// Passing `previous_epoch` to this function rather than computing it internally provides
    /// a tangible speed improvement in state processing.
    pub fn is_in_inactivity_leak(
        &self,
        previous_epoch: Epoch,
        spec: &Spec,
    ) -> std::result::Result<bool, ArithError> {
        Ok(
            (previous_epoch.safe_sub(self.finalized_checkpoint().epoch)?).as_u64()
                > spec.min_epochs_to_inactivity_penalty,
        )
    }



    /// Implementation of `get_total_active_balance`, matching the spec.
    ///
    /// Requires the total active balance cache to be initialised, which is initialised whenever
    /// the current committee cache is.
    ///
    /// Returns minimum `EFFECTIVE_BALANCE_INCREMENT`, to avoid div by 0.
    pub fn get_total_active_balance(&self) -> std::result::Result<u64, Error> {
        self.get_total_active_balance_at_epoch(self.current_epoch())
    }



    /// Return the churn limit for the current epoch (number of validators who can leave per epoch).
    ///
    /// Uses the current epoch committee cache, and will error if it isn't initialized.
    pub fn get_validator_churn_limit(&self, spec: &Spec) -> std::result::Result<u64, Error> {
        Ok(std::cmp::max(
            spec.min_per_epoch_churn_limit,
            (self
                .committee_cache(RelativeEpoch::Current)?
                .active_validator_count() as u64)
                .safe_div(spec.churn_limit_quotient)?,
        ))
    }

    #[allow(clippy::type_complexity)]
    pub fn mutable_validator_fields(
        &mut self,
    ) -> Result<
        (
            &mut Validators<E>,
            &mut Balances<E>,
            &List<ParticipationFlags, E::ValidatorRegistryLimit>,
            &List<ParticipationFlags, E::ValidatorRegistryLimit>,
            &mut List<u64, E::ValidatorRegistryLimit>,
            &mut ProgressiveBalancesCache,
            &mut ExitCache,
            &mut EpochCache,
        ),
        Error,
    > {

        match self {
            BeaconState::Base(_) => Err(Error::IncorrectStateVariant),
            BeaconState::Altair(state) => Ok((
                &mut state.validators,
                &mut state.balances,
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &mut state.inactivity_scores,
                &mut state.progressive_balances_cache,
                &mut state.exit_cache,
                &mut state.epoch_cache,
            )),
            BeaconState::Bellatrix(state) => Ok((
                &mut state.validators,
                &mut state.balances,
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &mut state.inactivity_scores,
                &mut state.progressive_balances_cache,
                &mut state.exit_cache,
                &mut state.epoch_cache,
            )),
            BeaconState::Capella(state) => Ok((
                &mut state.validators,
                &mut state.balances,
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &mut state.inactivity_scores,
                &mut state.progressive_balances_cache,
                &mut state.exit_cache,
                &mut state.epoch_cache,
            )),
            BeaconState::Deneb(state) => Ok((
                &mut state.validators,
                &mut state.balances,
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &mut state.inactivity_scores,
                &mut state.progressive_balances_cache,
                &mut state.exit_cache,
                &mut state.epoch_cache,
            )),
            BeaconState::Electra(state) => Ok((
                &mut state.validators,
                &mut state.balances,
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &mut state.inactivity_scores,
                &mut state.progressive_balances_cache,
                &mut state.exit_cache,
                &mut state.epoch_cache,
            )),
            BeaconState::Fulu(state) => Ok((
                &mut state.validators,
                &mut state.balances,
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &mut state.inactivity_scores,
                &mut state.progressive_balances_cache,
                &mut state.exit_cache,
                &mut state.epoch_cache,
            )),
        }

    }







    /// Build all caches (except the tree hash cache), if they need to be built.
    pub fn build_caches(&mut self, spec: &Spec) -> std::result::Result<(), Error> {
        self.build_all_committee_caches(spec)?;
        // self.update_pubkey_cache()?;
        // self.build_exit_cache(spec)?;
        // self.build_slashings_cache()?;

        Ok(())
    }

    /// Build all committee caches, if they need to be built.
    pub fn build_all_committee_caches(&mut self, spec: &Spec) -> std::result::Result<(), Error> {
        self.build_committee_cache(RelativeEpoch::Previous, spec)?;
        self.build_committee_cache(RelativeEpoch::Current, spec)?;
        self.build_committee_cache(RelativeEpoch::Next, spec)?;
        Ok(())
    }

    /// Build the exit cache, if it needs to be built.
    // pub fn build_exit_cache(&mut self, spec: &Spec) -> std::result::Result<(), Error> {
    //     if self.exit_cache().check_initialized().is_err() {
    //         *self.exit_cache_mut() = ExitCache::new(self.validators(), spec)?;
    //     }
    //     Ok(())
    // }
    // /// Updates the pubkey cache, if required.
    // ///
    // /// Adds all `pubkeys` from the `validators` which are not already in the cache. Will
    // /// never re-add a pubkey.
    // pub fn update_pubkey_cache(&mut self) -> std::result::Result<(), Error> {
    //     let mut pubkey_cache = mem::take(self.pubkey_cache_mut());
    //     let start_index = pubkey_cache.len();
    //
    //     for (i, validator) in self.validators().iter_from(start_index)?.enumerate() {
    //         let index = start_index.safe_add(i)?;
    //         let success = pubkey_cache.insert(validator.pubkey, index);
    //         if !success {
    //             return Err(Error::PubkeyCacheInconsistent);
    //         }
    //     }
    //     *self.pubkey_cache_mut() = pubkey_cache;
    //
    //     Ok(())
    // }

    // /// Build the slashings cache if it needs to be built.
    // pub fn build_slashings_cache(&mut self) -> std::result::Result<(), Error> {
    //     let latest_block_slot = self.latest_block_header().slot;
    //     if !self.slashings_cache().is_initialized(latest_block_slot) {
    //         *self.slashings_cache_mut() = SlashingsCache::new(latest_block_slot, self.validators());
    //     }
    //     Ok(())
    // }



    /// Build a committee cache, unless it is has already been built.
    pub fn build_committee_cache(
        &mut self,
        relative_epoch: RelativeEpoch,
        spec: &Spec,
    ) -> std::result::Result<(), Error> {
        let i = Self::committee_cache_index(relative_epoch);
        let is_initialized = self
            .committee_cache_at_index(i)?
            .is_initialized_at(relative_epoch.into_epoch(self.current_epoch()));

        if !is_initialized {
            self.force_build_committee_cache(relative_epoch, spec)?;
        }

        if self.total_active_balance().is_none() && relative_epoch == RelativeEpoch::Current {
            self.build_total_active_balance_cache(spec)?;
        }
        Ok(())
    }

    /// Build the total active balance cache for the current epoch if it is not already built.
    pub fn build_total_active_balance_cache(&mut self, spec: &Spec) -> std::result::Result<(), Error> {
        if self
            .get_total_active_balance_at_epoch(self.current_epoch())
            .is_err()
        {
            self.force_build_total_active_balance_cache(spec)?;
        }
        Ok(())
    }

    /// Get the cached total active balance while checking that it is for the correct `epoch`.
    pub fn get_total_active_balance_at_epoch(&self, epoch: Epoch) -> std::result::Result<u64, Error> {
        let (initialized_epoch, balance) = self
            .total_active_balance()
            .ok_or(Error::TotalActiveBalanceCacheUninitialized)?;

        if initialized_epoch == epoch {
            Ok(balance)
        } else {
            Err(Error::TotalActiveBalanceCacheInconsistent {
                initialized_epoch,
                current_epoch: epoch,
            })
        }
    }

    /// Build the total active balance cache, even if it is already built.
    pub fn force_build_total_active_balance_cache(
        &mut self,
        spec: &Spec,
    ) -> std::result::Result<(), Error> {
        let total_active_balance = self.compute_total_active_balance_slow(spec)?;
        *self.total_active_balance_mut() = Some((self.current_epoch(), total_active_balance));
        Ok(())
    }

    /// Compute the total active balance cache from scratch.
    ///
    /// This method should rarely be invoked because single-pass epoch processing keeps the total
    /// active balance cache up to date.
    pub fn compute_total_active_balance_slow(&self, spec: &Spec) -> std::result::Result<u64, Error> {
        let current_epoch = self.current_epoch();

        let mut total_active_balance = 0;

        for validator in self.validators() {
            if validator.is_active_at(current_epoch) {
                total_active_balance.safe_add_assign(validator.effective_balance)?;
            }
        }
        Ok(std::cmp::max(
            total_active_balance,
            spec.effective_balance_increment,
        ))
    }


    /// Compute the total  effective balance
    pub fn compute_total_effective_balance(&self) -> std::result::Result<u64, Error> {
        let mut total_effective_balance = 0;

        for validator in self.validators() {
            total_effective_balance.safe_add_assign(validator.effective_balance)?;
        }

        Ok(total_effective_balance)


    }




    /// Always builds the requested committee cache, even if it is already initialized.
    pub fn force_build_committee_cache(
        &mut self,
        relative_epoch: RelativeEpoch,
        spec: &Spec,
    ) -> std::result::Result<(), Error> {
        let epoch = relative_epoch.into_epoch(self.current_epoch());
        let i = Self::committee_cache_index(relative_epoch);

        *self.committee_cache_at_index_mut(i)? = self.initialize_committee_cache(epoch, spec)?;
        Ok(())
    }

    /// Get a mutable reference to the committee cache at a given index.
    fn committee_cache_at_index_mut(
        &mut self,
        index: usize,
    ) -> std::result::Result<&mut Arc<CommitteeCache>, Error> {
        self.committee_caches_mut()
            .get_mut(index)
            .ok_or(Error::CommitteeCachesOutOfBounds(index))
    }


    /// Initializes a new committee cache for the given `epoch`, regardless of whether one already
    /// exists. Returns the committee cache without attaching it to `self`.
    ///
    /// To build a cache and store it on `self`, use `Self::build_committee_cache`.
    pub fn initialize_committee_cache(
        &self,
        epoch: Epoch,
        spec: &Spec,
    ) -> std::result::Result<Arc<CommitteeCache>, Error> {
        CommitteeCache::initialized(self, epoch, spec)
    }

    /// The epoch corresponding to `self.slot()`.
    pub fn current_epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    // pub fn get_work_epoch(&self) -> Epoch {
    //     self.validators()
    //
    // }

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



    /// Get all of the Beacon committees at a given slot.
    ///
    /// Utilises the committee cache.
    ///
    /// Spec v0.12.1
    pub fn get_beacon_committees_at_slot(&self, slot: Slot) -> std::result::Result<Vec<BeaconCommittee<'_>>, Error> {
        let cache = self.committee_cache_at_slot(slot)?;
        cache.get_beacon_committees_at_slot(slot)
    }

    /// Get the committee cache for some `slot`.
    ///
    /// Return an error if the cache for the slot's epoch is not initialized.
    fn committee_cache_at_slot(&self, slot: Slot) -> std::result::Result<&Arc<CommitteeCache>, Error> {
        let epoch = slot.epoch(E::slots_per_epoch());
        let relative_epoch = RelativeEpoch::from_epoch(self.current_epoch(), epoch)?;
        self.committee_cache(relative_epoch)
    }



    /// Generate a seed for the given `epoch`.
    pub fn get_seed(
        &self,
        epoch: Epoch,
        domain_type: Domain,
        spec: &Spec,
    ) -> std::result::Result<Hash256, Error> {
        // Bypass the safe getter for RANDAO so we can gracefully handle the scenario where `epoch
        // == 0`.
        let mix = {
            let i = epoch
                .safe_add(E::EpochsPerHistoricalVector::to_u64())?
                .safe_sub(spec.min_seed_lookahead)?
                .safe_sub(1)?;
            let i_mod = i.as_usize().safe_rem(self.randao_mixes().len())?;
            self.randao_mixes()
                .get(i_mod)
                .ok_or(Error::RandaoMixesOutOfBounds(i_mod))?
        };
        let domain_bytes = int_to_bytes4(spec.get_domain_constant(domain_type));
        let epoch_bytes = int_to_bytes8(epoch.as_u64());

        const NUM_DOMAIN_BYTES: usize = 4;
        const NUM_EPOCH_BYTES: usize = 8;
        const MIX_OFFSET: usize = NUM_DOMAIN_BYTES + NUM_EPOCH_BYTES;
        const NUM_MIX_BYTES: usize = 32;

        let mut preimage = [0; NUM_DOMAIN_BYTES + NUM_EPOCH_BYTES + NUM_MIX_BYTES];
        preimage[0..NUM_DOMAIN_BYTES].copy_from_slice(&domain_bytes);
        preimage[NUM_DOMAIN_BYTES..MIX_OFFSET].copy_from_slice(&epoch_bytes);
        preimage[MIX_OFFSET..].copy_from_slice(mix.as_slice());

        Ok(Hash256::from_slice(&hash(&preimage)))
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

    /// Return the minimum epoch for which `get_randao_mix` will return a non-error value.
    pub fn min_randao_epoch(&self) -> Epoch {
        self.current_epoch()
            .saturating_add(1u64)
            .saturating_sub(E::EpochsPerHistoricalVector::to_u64())
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