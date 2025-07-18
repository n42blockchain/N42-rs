use std::collections::BTreeSet;
use std::sync::Arc;
use crate::slot_epoch::Epoch;
use crate::common::Hash256;
use crate::spec::Spec;
use crate::arith::SafeArith;
use crate::arith::ArithError;



#[derive(Debug, PartialEq, Clone)]
pub enum EpochCacheError {
    IncorrectEpoch { cache: Epoch, state: Epoch },
    IncorrectDecisionBlock { cache: Hash256, state: Hash256 },
    ValidatorIndexOutOfBounds { validator_index: usize },
    EffectiveBalanceOutOfBounds { effective_balance_eth: usize },
    // InvalidSlot { slot: Slot },
    Arith(ArithError),
    // BeaconState(BeaconStateError),
    CacheNotInitialized,
}

impl From<ArithError> for EpochCacheError {
    fn from(e: ArithError) -> Self {
        Self::Arith(e)
    }
}


#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct EpochCache {
    inner: Option<Arc<Inner>>,
}


#[derive(Debug, PartialEq, Eq, Clone)]
struct Inner {
    /// Unique identifier for this cache, which can be used to check its validity before use
    /// with any `BeaconState`.
    key: EpochCacheKey,
    /// Effective balance for every validator in this epoch.
    effective_balances: Vec<u64>,
    /// Base rewards for every effective balance increment (currently 0..32 ETH).
    ///
    /// Keyed by `effective_balance / effective_balance_increment`.
    base_rewards: Vec<u64>,
    /// Validator activation queue.
    activation_queue: ActivationQueue,
    /// Effective balance increment.
    effective_balance_increment: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct EpochCacheKey {
    pub epoch: Epoch,
    pub decision_block_root: Hash256,
}



#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct ActivationQueue {
    /// Validators represented by `(activation_eligibility_epoch, index)` in sorted order.
    ///
    /// These validators are not *necessarily* going to be activated. Their activation depends
    /// on how finalization is updated, and the `churn_limit`.
    queue: BTreeSet<(Epoch, usize)>,
}


impl EpochCache {
    pub fn new(
        key: EpochCacheKey,
        effective_balances: Vec<u64>,
        base_rewards: Vec<u64>,
        activation_queue: ActivationQueue,
        spec: &Spec,
    ) -> EpochCache {
        Self {
            inner: Some(Arc::new(Inner {
                key,
                effective_balances,
                base_rewards,
                activation_queue,
                effective_balance_increment: spec.effective_balance_increment,
            })),
        }
    }


    #[inline]
    pub fn get_effective_balance(&self, validator_index: usize) -> Result<u64, EpochCacheError> {
        self.inner
            .as_ref()
            .ok_or(EpochCacheError::CacheNotInitialized)?
            .effective_balances
            .get(validator_index)
            .copied()
            .ok_or(EpochCacheError::ValidatorIndexOutOfBounds { validator_index })
    }

    #[inline]
    pub fn get_base_reward(&self, validator_index: usize) -> Result<u64, EpochCacheError> {
        let inner = self
            .inner
            .as_ref()
            .ok_or(EpochCacheError::CacheNotInitialized)?;
        let effective_balance = self.get_effective_balance(validator_index)?;
        let effective_balance_eth =
                effective_balance as usize;
            // effective_balance.safe_div(inner.effective_balance_increment)? as usize;
        inner
            .base_rewards
            .get(effective_balance_eth)
            .copied()
            .ok_or(EpochCacheError::EffectiveBalanceOutOfBounds {
                effective_balance_eth,
            })
    }



}