use std::fmt::Debug;
use std::mem;
use alloy_primitives::private::arbitrary;
use alloy_primitives::private::serde::{Deserialize, Serialize};
use milhouse::List;
use superstruct::superstruct;
use crate::pending_partial_withdrawal::PendingPartialWithdrawal;
use derivative::Derivative;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use metastruct::metastruct;
use ssz_types::typenum::Unsigned;
use crate::chain_spec::ChainSpec;
use crate::validators::Validator;
use crate::fork_name::ForkName;
use crate::slot_epoch::{Epoch, Slot};
use crate::exit_cache::ExitCache;
use crate::safe_aitrh::{ArithError, SafeArith};
use crate::exit_cache::PubkeyCache;

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

}

#[superstruct(
    variants(Electra, Fulu),
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
            arbitrary::Arbitrary,
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

    // Capella
    #[superstruct(only(Fulu), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    #[metastruct(exclude_from(tree_lists))]
    pub next_withdrawal_index: u64,
    #[superstruct(only(Fulu), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    #[metastruct(exclude_from(tree_lists))]
    pub next_withdrawal_validator_index: u64,

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
}

impl<E: EthSpec> BeaconState<E> {
    /// The epoch corresponding to `self.slot()`.
    pub fn current_epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Does not check if `self` is consistent with the fork dictated by `self.slot()`.
    pub fn fork_name_unchecked(&self) -> ForkName {
        match self {
            // BeaconState::Base { .. } => ForkName::Base,
            // BeaconState::Altair { .. } => ForkName::Altair,
            // BeaconState::Bellatrix { .. } => ForkName::Bellatrix,
            // BeaconState::Capella { .. } => ForkName::Capella,
            // BeaconState::Deneb { .. } => ForkName::Deneb,
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
            // BeaconState::Base(_)
            // | BeaconState::Altair(_)
            // | BeaconState::Bellatrix(_)
            // | BeaconState::Capella(_)
            // | BeaconState::Deneb(_) => Err(Error::IncorrectStateVariant),
            BeaconState::Electra(_) | BeaconState::Fulu(_) => {
                // Consume the balance and update state variables
                *self.exit_balance_to_consume_mut()? =
                    exit_balance_to_consume.safe_sub(exit_balance)?;
                *self.earliest_exit_epoch_mut()? = earliest_exit_epoch;
                self.earliest_exit_epoch()
            }
        }
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
