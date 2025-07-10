use std::cmp::max;
use std::fmt::Debug;
use std::mem;
use std::sync::Arc;
use alloy_primitives::private::arbitrary;
use alloy_primitives::private::serde::{Deserialize, Serialize};
use milhouse::{List, Vector};
use superstruct::superstruct;
use crate::pending_partial_withdrawal::{PendingPartialWithdrawal, ParticipationFlags};
use derivative::Derivative;
use ethereum_hashing::{hash, Context, Sha256Context};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use metastruct::metastruct;
use ssz_types::typenum::Unsigned;
use crate::chain_spec::{ChainSpec, Domain};
use crate::crypto::PublicKeyBytes;
use crate::validators::Validator;
use crate::fork_name::ForkName;
use crate::slot_epoch::{Epoch, Slot};
use crate::exit_cache::{ExitCache, EpochCache, RelativeEpoch, CommitteeCache};
use crate::safe_aitrh::{ArithError, SafeArith};
use crate::exit_cache::{PubkeyCache, Error as RelativeEpochError};
use crate::withdrawal::{Checkpoint, Eth1Data, PendingDeposit, Fork, SyncCommittee};
use crate::{CommitteeIndex, Hash256};
use bytes::{BufMut, BytesMut};
use crate::signature::BeaconCommittee;

pub const CACHED_EPOCHS: usize = 3;
const MAX_RANDOM_VALUE: u64 = (1 << 16) - 1;
const MAX_RANDOM_BYTE: u64 = (1 << 8) - 1;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    IncorrectStateVariant,
    NonExecutionAddressWithdrawalCredential,
    BalancesOutOfBounds(usize),
    UnknownValidator(usize),
    ExitCacheUninitialized,
    ArithError(ArithError),
    TotalActiveBalanceCacheUninitialized,
    TotalActiveBalanceCacheInconsistent {
        initialized_epoch: Epoch,
        current_epoch: Epoch,
    },
    PubkeyCacheInconsistent,
    MilhouseError(milhouse::Error),
    CommitteeCacheUninitialized(Option<RelativeEpoch>),
    CommitteeCachesOutOfBounds(usize),
    SlotOutOfBounds,
    EpochOutOfBounds,
    InsufficientValidators,
    UnableToShuffle,
    ShuffleIndexOutOfBounds(usize),
    RandaoMixesOutOfBounds(usize),
    NoCommitteeFound(CommitteeIndex),
    InvalidCommitteeIndex(CommitteeIndex),
    EmptyCommittee,
    InvalidBitfield,
    NoCommittee {
        slot: Slot,
        index: CommitteeIndex,
    },
    RelativeEpochError(RelativeEpochError),
    SyncCommitteeNotKnown {
        current_epoch: Epoch,
        epoch: Epoch,
    },
}

#[superstruct(
    variants(Electra, Fulu),
    variant_attributes(
        derive(
            Derivative, Debug, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, arbitrary::Arbitrary,
        ),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
        derivative(Clone),
    ),
    specific_variant_attributes(
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
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, arbitrary::Arbitrary)]
#[serde(untagged)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
pub struct BeaconState<E>
where
    E: EthSpec,
{

    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub slot: Slot,
    pub validators: List<Validator, E::ValidatorRegistryLimit>,
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    pub balances: List<u64, E::ValidatorRegistryLimit>,

    #[superstruct(only(Fulu), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    #[metastruct(exclude_from(tree_lists))]
    pub next_withdrawal_index: u64,
    #[superstruct(only(Fulu), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    #[metastruct(exclude_from(tree_lists))]
    pub next_withdrawal_validator_index: u64,

    #[superstruct(only(Fulu), partial_getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_requests_start_index: u64,
    #[superstruct(only(Fulu))]
    pub pending_partial_withdrawals: List<PendingPartialWithdrawal, E::PendingPartialWithdrawalsLimit>,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[metastruct(exclude)]
    pub exit_cache: ExitCache,
    #[superstruct(only(Fulu), partial_getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub earliest_exit_epoch: Epoch,

    // Caching (not in the spec)
    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[metastruct(exclude)]
    pub total_active_balance: Option<(Epoch, u64)>,

    #[superstruct(only(Fulu), partial_getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub exit_balance_to_consume: u64,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[metastruct(exclude)]
    pub pubkey_cache: PubkeyCache,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[metastruct(exclude)]
    pub epoch_cache: EpochCache,

    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub finalized_checkpoint: Checkpoint,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[metastruct(exclude)]
    pub committee_caches: [Arc<CommitteeCache>; CACHED_EPOCHS],

    #[metastruct(exclude_from(tree_lists))]
    pub eth1_data: Eth1Data,
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub eth1_deposit_index: u64,

    #[superstruct(only(Fulu))]
    pub pending_deposits: List<PendingDeposit, E::PendingDepositsLimit>,

    #[superstruct(only(Fulu))]
    pub previous_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
    #[superstruct(only(Fulu))]
    pub current_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,

    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    #[superstruct(only(Fulu))]
    pub inactivity_scores: List<u64, E::ValidatorRegistryLimit>,

    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub genesis_validators_root: Hash256,

    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub fork: Fork,

    pub randao_mixes: Vector<Hash256, E::EpochsPerHistoricalVector>,

    #[superstruct(only(Fulu))]
    #[metastruct(exclude_from(tree_lists))]
    pub current_sync_committee: Arc<SyncCommittee<E>>,
    #[superstruct(only(Fulu))]
    #[metastruct(exclude_from(tree_lists))]
    pub next_sync_committee: Arc<SyncCommittee<E>>,
}

impl<E: EthSpec> BeaconState<E> {

    /// This method ensures the state's pubkey cache is fully up-to-date before checking if the validator
    /// exists in the registry. If a validator pubkey exists in the validator registry, returns `Some(i)`,
    /// otherwise returns `None`.
    pub fn get_validator_index(&mut self, pubkey: &PublicKeyBytes) -> Result<Option<usize>, Error> {
        self.update_pubkey_cache()?;
        Ok(self.pubkey_cache().get(pubkey))
    }
    /// The epoch corresponding to `self.slot()`.
    pub fn current_epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Does not check if `self` is consistent with the fork dictated by `self.slot()`.
    pub fn fork_name_unchecked(&self) -> ForkName {
        match self {
            BeaconState::Electra { .. } => ForkName::Electra,
            BeaconState::Fulu { .. } => ForkName::Fulu,
        }
    }

    /// Safe indexer for the `validators` list.
    pub fn get_validator(&self, validator_index: usize) -> Result<&Validator, Error> {
        self.validators()
            .get(validator_index)
            .ok_or(Error::UnknownValidator(validator_index))
    }

    /// Get the balance of a single validator.
    pub fn get_balance(&self, validator_index: usize) -> Result<u64, Error> {
        self.balances()
            .get(validator_index)
            .ok_or(Error::BalancesOutOfBounds(validator_index))
            .copied()
    }

    /// Get a mutable reference to the balance of a single validator.
    pub fn get_balance_mut(&mut self, validator_index: usize) -> Result<&mut u64, Error> {
        self.balances_mut()
            .get_mut(validator_index)
            .ok_or(Error::BalancesOutOfBounds(validator_index))
    }

    /// Safe copy-on-write accessor for the `validators` list.
    pub fn get_validator_cow(
        &mut self,
        validator_index: usize,
    ) -> Result<milhouse::Cow<Validator>, Error> {
        self.validators_mut()
            .get_cow(validator_index)
            .ok_or(Error::UnknownValidator(validator_index))
    }

    pub fn get_pending_balance_to_withdraw(&self, validator_index: usize) -> Result<u64, Error> {
        let mut pending_balance = 0;
        for withdrawal in self
            .pending_partial_withdrawals()?
            .iter()
            .filter(|withdrawal| withdrawal.validator_index as usize == validator_index)
        {
            pending_balance.safe_add_assign(withdrawal.amount)?;
        }
        Ok(pending_balance)
    }

    /// Updates the pubkey cache, if required.
    ///
    /// Adds all `pubkeys` from the `validators` which are not already in the cache. Will
    /// never re-add a pubkey.
    pub fn update_pubkey_cache(&mut self) -> Result<(), Error> {
        let mut pubkey_cache = mem::take(self.pubkey_cache_mut());
        let start_index = pubkey_cache.len();

        for (i, validator) in self.validators().iter_from(start_index)?.enumerate() {
            let index = start_index.safe_add(i)?;
            let success = pubkey_cache.insert(validator.pubkey, index);
            if !success {
                return Err(Error::PubkeyCacheInconsistent);
            }
        }
        *self.pubkey_cache_mut() = pubkey_cache;

        Ok(())
    }

    /// Build the exit cache, if it needs to be built.
    pub fn build_exit_cache(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        if self.exit_cache().check_initialized().is_err() { // 如果退出缓存没初始化
            *self.exit_cache_mut() = ExitCache::new(self.validators(), spec)?;
        }
        Ok(())
    }

    /// Return the effective balance for a validator with the given `validator_index`.
    pub fn get_effective_balance(&self, validator_index: usize) -> Result<u64, Error> {
        self.get_validator(validator_index)
            .map(|v| v.effective_balance)
    }

    /// Safe mutator for the `validators` list.
    pub fn get_validator_mut(&mut self, validator_index: usize) -> Result<&mut Validator, Error> {
        self.validators_mut()
            .get_mut(validator_index)
            .ok_or(Error::UnknownValidator(validator_index))
    }

    ///  Return the epoch at which an activation or exit triggered in ``epoch`` takes effect.
    ///
    ///  Spec v0.12.1
    pub fn compute_activation_exit_epoch(
        &self,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<Epoch, Error> {
        Ok(spec.compute_activation_exit_epoch(epoch)?)
    }

    /// Return the churn limit for the current epoch dedicated to activations and exits.
    pub fn get_activation_exit_churn_limit(&self, spec: &ChainSpec) -> Result<u64, Error> {
        Ok(std::cmp::min(
            spec.max_per_epoch_activation_exit_churn_limit,
            self.get_balance_churn_limit(spec)?,
        ))
    }

    /// Return the churn limit for the current epoch.
    pub fn get_balance_churn_limit(&self, spec: &ChainSpec) -> Result<u64, Error> {
        let total_active_balance = self.get_total_active_balance()?;
        let churn = std::cmp::max(
            spec.min_per_epoch_churn_limit_electra,
            total_active_balance.safe_div(spec.churn_limit_quotient)?,
        );

        Ok(churn.safe_sub(churn.safe_rem(spec.effective_balance_increment)?)?)
    }

    /// Implementation of `get_total_active_balance`, matching the spec.
    ///
    /// Requires the total active balance cache to be initialised, which is initialised whenever
    /// the current committee cache is.
    ///
    /// Returns minimum `EFFECTIVE_BALANCE_INCREMENT`, to avoid div by 0.
    pub fn get_total_active_balance(&self) -> Result<u64, Error> {
        self.get_total_active_balance_at_epoch(self.current_epoch())
    }

    /// Get the cached total active balance while checking that it is for the correct `epoch`.
    pub fn get_total_active_balance_at_epoch(&self, epoch: Epoch) -> Result<u64, Error> {
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

    /// Return the activation churn limit for the current epoch (number of validators who can enter per epoch).
    ///
    /// Uses the current epoch committee cache, and will error if it isn't initialized.
    pub fn get_activation_churn_limit(&self, spec: &ChainSpec) -> Result<u64, Error> {
        Ok(match self {
            BeaconState::Electra(_) | BeaconState::Fulu(_) => {
                std::cmp::min(
                    spec.max_per_epoch_activation_churn_limit,
                    self.get_validator_churn_limit(spec)?,
                )
            }
        })
    }

    /// Return the churn limit for the current epoch (number of validators who can leave per epoch).
    ///
    /// Uses the current epoch committee cache, and will error if it isn't initialized.
    pub fn get_validator_churn_limit(&self, spec: &ChainSpec) -> Result<u64, Error> {
        Ok(std::cmp::max(
            spec.min_per_epoch_churn_limit,
            (self
                .committee_cache(RelativeEpoch::Current)?
                .active_validator_count() as u64)
                .safe_div(spec.churn_limit_quotient)?,
        ))
    }

    /// Returns the cache for some `RelativeEpoch`. Returns an error if the cache has not been
    /// initialized.
    pub fn committee_cache(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> Result<&Arc<CommitteeCache>, Error> {
        let i = Self::committee_cache_index(relative_epoch);
        let cache = self.committee_cache_at_index(i)?;

        if cache.is_initialized_at(relative_epoch.into_epoch(self.current_epoch())) {
            Ok(cache)
        } else {
            Err(Error::CommitteeCacheUninitialized(Some(relative_epoch)))
        }
    }

    pub(crate) fn committee_cache_index(relative_epoch: RelativeEpoch) -> usize {
        match relative_epoch {
            RelativeEpoch::Previous => 0,
            RelativeEpoch::Current => 1,
            RelativeEpoch::Next => 2,
        }
    }

    /// Get the committee cache at a given index.
    fn committee_cache_at_index(&self, index: usize) -> Result<&Arc<CommitteeCache>, Error> {
        self.committee_caches()
            .get(index)
            .ok_or(Error::CommitteeCachesOutOfBounds(index))
    }



    pub fn compute_exit_epoch_and_update_churn(
        &mut self,
        exit_balance: u64,
        spec: &ChainSpec,
    ) -> Result<Epoch, Error> {
        let mut earliest_exit_epoch = std::cmp::max(
            self.earliest_exit_epoch()?,
            self.compute_activation_exit_epoch(self.current_epoch(), spec)?,
        );

        let per_epoch_churn = self.get_activation_exit_churn_limit(spec)?;
        // New epoch for exits
        let mut exit_balance_to_consume = if self.earliest_exit_epoch()? < earliest_exit_epoch {
            per_epoch_churn
        } else {
            self.exit_balance_to_consume()?
        };

        // Exit doesn't fit in the current earliest epoch
        if exit_balance > exit_balance_to_consume {
            let balance_to_process = exit_balance.safe_sub(exit_balance_to_consume)?;
            let additional_epochs = balance_to_process
                .safe_sub(1)?
                .safe_div(per_epoch_churn)?
                .safe_add(1)?;
            earliest_exit_epoch.safe_add_assign(additional_epochs)?;
            exit_balance_to_consume
                .safe_add_assign(additional_epochs.safe_mul(per_epoch_churn)?)?;
        }
        match self {
            BeaconState::Electra(_) | BeaconState::Fulu(_) => {
                // Consume the balance and update state variables
                *self.exit_balance_to_consume_mut()? =
                    exit_balance_to_consume.safe_sub(exit_balance)?;
                *self.earliest_exit_epoch_mut()? = earliest_exit_epoch;
                self.earliest_exit_epoch()
            }
        }
    }


    /// Add a validator to the registry and return the validator index that was allocated for it.
    pub fn add_validator_to_registry(
        &mut self,
        pubkey: PublicKeyBytes,
        withdrawal_credentials: Hash256,
        amount: u64,
        spec: &ChainSpec,
    ) -> Result<usize, Error> {
        let index = self.validators().len();
        let fork_name = self.fork_name_unchecked();
        self.validators_mut().push(Validator::from_deposit(
            pubkey,
            withdrawal_credentials,
            amount,
            fork_name,
            spec,
        ))?;
        self.balances_mut().push(amount)?;

        // Altair or later initializations.
        if let Ok(previous_epoch_participation) = self.previous_epoch_participation_mut() {
            previous_epoch_participation.push(ParticipationFlags::default())?;
        }
        if let Ok(current_epoch_participation) = self.current_epoch_participation_mut() {
            current_epoch_participation.push(ParticipationFlags::default())?;
        }
        if let Ok(inactivity_scores) = self.inactivity_scores_mut() {
            inactivity_scores.push(0)?;
        }

        // Keep the pubkey cache up to date if it was up to date prior to this call.
        //
        // Doing this here while we know the pubkey and index is marginally quicker than doing it in
        // a call to `update_pubkey_cache` later because we don't need to index into the validators
        // tree again.
        let pubkey_cache = self.pubkey_cache_mut();
        if pubkey_cache.len() == index {
            let success = pubkey_cache.insert(pubkey, index);
            if !success {
                return Err(Error::PubkeyCacheInconsistent);
            }
        }

        Ok(index)
    }

    /// Returns the beacon proposer index for the `slot` in `self.current_epoch()`.
    pub fn get_beacon_proposer_index(&self, slot: Slot, spec: &ChainSpec) -> Result<usize, Error> {
        // Proposer indices are only known for the current epoch, due to the dependence on the
        // effective balances of validators, which change at every epoch transition.
        let epoch = slot.epoch(E::slots_per_epoch());
        if epoch != self.current_epoch() {
            return Err(Error::SlotOutOfBounds);
        }

        let seed = self.get_beacon_proposer_seed(slot, spec)?;
        let indices = self.get_active_validator_indices(epoch, spec)?;

        self.compute_proposer_index(&indices, &seed, spec)
    }

    /// Compute the seed to use for the beacon proposer selection at the given `slot`.
    pub fn get_beacon_proposer_seed(&self, slot: Slot, spec: &ChainSpec) -> Result<Vec<u8>, Error> {
        let epoch = slot.epoch(E::slots_per_epoch());
        let mut preimage = self
            .get_seed(epoch, Domain::BeaconProposer, spec)?
            .as_slice()
            .to_vec();
        preimage.append(&mut int_to_bytes8(slot.as_u64()));
        Ok(hash(&preimage))
    }

    /// Returns the active validator indices for the given epoch.
    /// Does not utilize the cache, performs a full iteration over the validator registry.
    pub fn get_active_validator_indices(
        &self,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<Vec<usize>, Error> {
        if epoch >= self.compute_activation_exit_epoch(self.current_epoch(), spec)? {
            Err(Error::EpochOutOfBounds)
        } else {
            Ok(get_active_validator_indices(self.validators(), epoch))
        }
    }

    /// Compute the proposer (not necessarily for the Beacon chain) from a list of indices.
    pub fn compute_proposer_index(
        &self,
        indices: &[usize],
        seed: &[u8],
        spec: &ChainSpec,
    ) -> Result<usize, Error> {
        if indices.is_empty() {
            return Err(Error::InsufficientValidators);
        }

        let max_effective_balance = spec.max_effective_balance_for_fork(self.fork_name_unchecked());
        let max_random_value = if self.fork_name_unchecked().electra_enabled() {
            MAX_RANDOM_VALUE
        } else {
            MAX_RANDOM_BYTE
        };

        let mut i = 0;
        loop {
            let shuffled_index = compute_shuffled_index(
                i.safe_rem(indices.len())?,
                indices.len(),
                seed,
                spec.shuffle_round_count,
            )
                .ok_or(Error::UnableToShuffle)?;
            let candidate_index = *indices
                .get(shuffled_index)
                .ok_or(Error::ShuffleIndexOutOfBounds(shuffled_index))?;
            let random_value = self.shuffling_random_value(i, seed)?;
            let effective_balance = self.get_effective_balance(candidate_index)?;
            if effective_balance.safe_mul(max_random_value)?
                >= max_effective_balance.safe_mul(random_value)?
            {
                return Ok(candidate_index);
            }
            i.safe_add_assign(1)?;
        }
    }
    /// Fork-aware abstraction for the shuffling.
    ///
    /// In Electra and later, the random value is a 16-bit integer stored in a `u64`.
    ///
    /// Prior to Electra, the random value is an 8-bit integer stored in a `u64`.
    fn shuffling_random_value(&self, i: usize, seed: &[u8]) -> Result<u64, Error> {
        if self.fork_name_unchecked().electra_enabled() {
            Self::shuffling_random_u16_electra(i, seed).map(u64::from)
        } else {
            Self::shuffling_random_byte(i, seed).map(u64::from)
        }
    }
    /// Get two random bytes from the given `seed`.
    ///
    /// This is used in place of `shuffling_random_byte` from Electra onwards.
    fn shuffling_random_u16_electra(i: usize, seed: &[u8]) -> Result<u16, Error> {
        let mut preimage = seed.to_vec();
        preimage.append(&mut int_to_bytes8(i.safe_div(16)? as u64));
        let offset = i.safe_rem(16)?.safe_mul(2)?;
        hash(&preimage)
            .get(offset..offset.safe_add(2)?)
            .ok_or(Error::ShuffleIndexOutOfBounds(offset))?
            .try_into()
            .map(u16::from_le_bytes)
            .map_err(|_| Error::ShuffleIndexOutOfBounds(offset))
    }
    /// Get a random byte from the given `seed`.
    ///
    /// Used by the proposer & sync committee selection functions.
    fn shuffling_random_byte(i: usize, seed: &[u8]) -> Result<u8, Error> {
        let mut preimage = seed.to_vec();
        preimage.append(&mut int_to_bytes8(i.safe_div(32)? as u64));
        let index = i.safe_rem(32)?;
        hash(&preimage)
            .get(index)
            .copied()
            .ok_or(Error::ShuffleIndexOutOfBounds(index))
    }

    /// Generate a seed for the given `epoch`.
    pub fn get_seed(
        &self,
        epoch: Epoch,
        domain_type: Domain,
        spec: &ChainSpec,
    ) -> Result<Hash256, Error> {
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

    /// Get all of the Beacon committees at a given slot.
    /// Utilises the committee cache.
    pub fn get_beacon_committees_at_slot(&self, slot: Slot) -> Result<Vec<BeaconCommittee>, Error> {
        let cache = self.committee_cache_at_slot(slot)?;
        cache.get_beacon_committees_at_slot(slot)
    }
    /// Get the committee cache for some `slot`.
    ///
    /// Return an error if the cache for the slot's epoch is not initialized.
    fn committee_cache_at_slot(&self, slot: Slot) -> Result<&Arc<CommitteeCache>, Error> {
        let epoch = slot.epoch(E::slots_per_epoch());
        let relative_epoch = RelativeEpoch::from_epoch(self.current_epoch(), epoch)?;
        self.committee_cache(relative_epoch)
    }

    /// Get the already-built current or next sync committee from the state.
    pub fn get_built_sync_committee(
        &self,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<&Arc<SyncCommittee<E>>, Error> {
        let sync_committee_period = epoch.sync_committee_period(spec)?;
        let current_sync_committee_period = self.current_epoch().sync_committee_period(spec)?;
        let next_sync_committee_period = current_sync_committee_period.safe_add(1)?;

        if sync_committee_period == current_sync_committee_period {
            self.current_sync_committee()
        } else if sync_committee_period == next_sync_committee_period {
            self.next_sync_committee()
        } else {
            Err(Error::SyncCommitteeNotKnown {
                current_epoch: self.current_epoch(),
                epoch,
            })
        }
    }
}

impl From<RelativeEpochError> for Error {
    fn from(e: RelativeEpochError) -> Error {
        Error::RelativeEpochError(e)
    }
}
impl From<ArithError> for Error {
    fn from(e: ArithError) -> Error {
        Error::ArithError(e)
    }
}

impl From<milhouse::Error> for Error {
    fn from(e: milhouse::Error) -> Self {
        Self::MilhouseError(e)
    }
}

pub trait EthSpec:
'static + Default + Sync + Send + Clone + Debug + PartialEq + Eq + for<'a> arbitrary::Arbitrary<'a>
{
    type ValidatorRegistryLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type PendingPartialWithdrawalsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxWithdrawalsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type SlotsPerEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxDepositRequestsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxWithdrawalRequestsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxConsolidationRequestsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxDeposits: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxVoluntaryExits: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type PendingDepositsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type EpochsPerHistoricalVector: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type SyncCommitteeSize: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxProposerSlashings: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxAttesterSlashingsElectra: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxAttestationsElectra: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxValidatorsPerSlot: Unsigned + Clone + Sync + Send + Debug + PartialEq + Eq;
    type MaxCommitteesPerSlot: Unsigned + Clone + Sync + Send + Debug + PartialEq + Eq;
    type MaxBlsToExecutionChanges: Unsigned + Clone + Sync + Send + Debug + PartialEq;


    fn max_withdrawals_per_payload() -> usize {
        Self::MaxWithdrawalsPerPayload::to_usize()
    }

    /// Returns the `SLOTS_PER_EPOCH` constant for this specification.
    ///
    /// Spec v0.12.1
    fn slots_per_epoch() -> u64 {
        Self::SlotsPerEpoch::to_u64()
    }

    /// Returns the `PENDING_PARTIAL_WITHDRAWALS_LIMIT` constant for this specification.
    fn pending_partial_withdrawals_limit() -> usize {
        Self::PendingPartialWithdrawalsLimit::to_usize()
    }
}

/// Returns `int` as little-endian bytes with a length of 8.
pub fn int_to_bytes8(int: u64) -> Vec<u8> {
    let mut bytes = BytesMut::with_capacity(8);
    bytes.put_u64_le(int);
    bytes.to_vec()
}


/// Returns a list of all `validators` indices where the validator is active at the given

pub fn get_active_validator_indices<'a, V, I>(validators: V, epoch: Epoch) -> Vec<usize>
where
    V: IntoIterator<Item = &'a Validator, IntoIter = I>,
    I: ExactSizeIterator + Iterator<Item = &'a Validator>,
{
    let iter = validators.into_iter();

    let mut active = Vec::with_capacity(iter.len());

    for (index, validator) in iter.enumerate() {
        if validator.is_active_at(epoch) {
            active.push(index)
        }
    }

    active
}

pub fn compute_shuffled_index(
    index: usize,
    list_size: usize,
    seed: &[u8],
    shuffle_round_count: u8,
) -> Option<usize> {
    if list_size == 0
        || index >= list_size
        || list_size > usize::MAX / 2
        || list_size > 2_usize.pow(24)
    {
        return None;
    }

    let mut index = index;
    for round in 0..shuffle_round_count {
        let pivot = bytes_to_int64(&hash_with_round(seed, round)[..]) as usize % list_size;
        index = do_round(seed, index, pivot, round, list_size);
    }
    Some(index)
}

fn bytes_to_int64(slice: &[u8]) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&slice[0..8]);
    u64::from_le_bytes(bytes)
}
fn hash_with_round(seed: &[u8], round: u8) -> Hash256 {
    let mut context = Context::new();

    context.update(seed);
    context.update(&[round]);

    let digest = context.finalize();
    Hash256::from_slice(digest.as_ref())
}

fn do_round(seed: &[u8], index: usize, pivot: usize, round: u8, list_size: usize) -> usize {
    let flip = (pivot + (list_size - index)) % list_size;
    let position = max(index, flip);
    let source = hash_with_round_and_position(seed, round, position);
    let byte = source[(position % 256) / 8];
    let bit = (byte >> (position % 8)) % 2;
    if bit == 1 {
        flip
    } else {
        index
    }
}
fn hash_with_round_and_position(seed: &[u8], round: u8, position: usize) -> Hash256 {
    let mut context = Context::new();

    context.update(seed);
    context.update(&[round]);
    /*
     * Note: the specification has an implicit assertion in `int_to_bytes4` that `position / 256 <
     * 2**24`. For efficiency, we do not check for that here as it is checked in `compute_shuffled_index`.
     */
    context.update(&(position / 256).to_le_bytes()[0..4]);

    let digest = context.finalize();
    Hash256::from_slice(digest.as_ref())
}

/// Returns `int` as little-endian bytes with a length of 4.
pub fn int_to_bytes4(int: u32) -> [u8; 4] {
    int.to_le_bytes()
}