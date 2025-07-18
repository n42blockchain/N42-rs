use arbitrary::Arbitrary;
use crate::slot_epoch::Epoch;
use crate::common::balance::Balance;
use crate::common::NUM_FLAG_INDICES;
use crate::beaconstate::Error as BeaconStateError;



#[derive(Default, Debug, PartialEq, Arbitrary, Clone)]
pub struct ProgressiveBalancesCache {
    inner: Option<Inner>,
}

impl ProgressiveBalancesCache {

    fn get_inner(&self) -> Result<&Inner, BeaconStateError> {
        self.inner
            .as_ref()
            .ok_or(BeaconStateError::ProgressiveBalancesCacheNotInitialized)
    }

    pub fn previous_epoch_flag_attesting_balance(
        &self,
        flag_index: usize,
    ) -> Result<u64, BeaconStateError> {
        self.get_inner()?
            .previous_epoch_cache
            .total_flag_balance(flag_index)
    }


}



#[derive(Debug, PartialEq, Arbitrary, Clone)]
struct Inner {
    pub current_epoch: Epoch,
    pub previous_epoch_cache: EpochTotalBalances,
    pub current_epoch_cache: EpochTotalBalances,
}




// Caches the participation values for one epoch (either the previous or current).
#[derive(PartialEq, Debug, Clone, Arbitrary)]
pub struct EpochTotalBalances {
    /// Stores the sum of the balances for all validators in `self.unslashed_participating_indices`
    /// for all flags in `NUM_FLAG_INDICES`.
    ///
    /// A flag balance is only incremented if a validator is in that flag set.
    pub total_flag_balances: [Balance; NUM_FLAG_INDICES],
}


impl EpochTotalBalances {
    /// Returns the total balance of attesters who have `flag_index` set.
    pub fn total_flag_balance(&self, flag_index: usize) -> Result<u64, BeaconStateError> {
        self.total_flag_balances
            .get(flag_index)
            .map(Balance::get)
            .ok_or(BeaconStateError::InvalidFlagIndex(flag_index))
    }
}
