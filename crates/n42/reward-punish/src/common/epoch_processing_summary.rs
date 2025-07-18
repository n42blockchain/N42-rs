use std::sync::Arc;
use milhouse::List;
use crate::spec::EthSpec;
use crate::validator_statuses::{TotalBalances, ValidatorStatus};
use crate::common::progressive_balance_cache::ProgressiveBalancesCache;

use crate::beaconstate::Validator;
use crate::slot_epoch::Epoch;
use crate::common::participation_flags::ParticipationFlags;
use crate::common::sync_committee::SyncCommittee;







#[derive(PartialEq, Debug)]
pub enum EpochProcessingSummary<E: EthSpec> {
    Base {
        total_balances: TotalBalances,
        statuses: Vec<ValidatorStatus>,
    },
    Altair {
        progressive_balances: ProgressiveBalancesCache,
        current_epoch_total_active_balance: u64,
        participation: ParticipationEpochSummary<E>,
        sync_committee: Arc<SyncCommittee<E>>,
    },
}








#[derive(PartialEq, Debug)]
pub struct ParticipationEpochSummary<E: EthSpec> {
    /// Copy of the validator registry prior to mutation.
    validators: List<Validator, E::ValidatorRegistryLimit>,
    /// Copy of the participation flags for the previous epoch.
    previous_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
    /// Copy of the participation flags for the current epoch.
    current_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
    previous_epoch: Epoch,
    current_epoch: Epoch,
}

impl <E: EthSpec> ParticipationEpochSummary<E> {
    pub fn new(
        validators: List<Validator, E::ValidatorRegistryLimit>,
        previous_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
        current_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
        previous_epoch: Epoch,
        current_epoch: Epoch,
    ) -> Self {
        Self {
            validators,
            previous_epoch_participation,
            current_epoch_participation,
            previous_epoch,
            current_epoch,
        }
    }
}