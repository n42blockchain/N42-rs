use crate::arith::{ArithError, SafeArith};
use crate::spec::Spec;
use crate::beaconstate::BeaconState;
// use integer_sqrt::IntegerSquareRoot;
use crate::spec::EthSpec;


use crate::beaconstate::Error as BeaconStateError;
#[derive(Copy, Clone)]
pub struct SqrtTotalActiveBalance(u64);

impl SqrtTotalActiveBalance {
    pub fn new(total_active_balance: u64) -> Self {
        Self(total_active_balance.isqrt())
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Returns the base reward for some validator.
pub fn get_base_reward(
    validator_effective_balance: u64,
    sqrt_total_active_balance: SqrtTotalActiveBalance,
    spec: &Spec,
) -> Result<u64, ArithError> {
    validator_effective_balance
        .safe_mul(spec.base_reward_factor)?
        .safe_div(sqrt_total_active_balance.as_u64())?
        .safe_div(spec.base_rewards_per_epoch)
}



/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance<E: EthSpec>(
    state: &mut BeaconState<E>,
    index: usize,
    delta: u64,
) -> Result<(), BeaconStateError> {
    increase_balance_directly(state.get_balance_mut(index)?, delta)
}

/// Decrease the balance of a validator, saturating upon overflow, as per the spec.
pub fn decrease_balance<E: EthSpec>(
    state: &mut BeaconState<E>,
    index: usize,
    delta: u64,
) -> Result<(), BeaconStateError> {
    decrease_balance_directly(state.get_balance_mut(index)?, delta)
}

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance_directly(balance: &mut u64, delta: u64) -> Result<(), BeaconStateError> {
    let _  = balance.safe_add_assign(delta)?;
    Ok(())
}

/// Decrease the balance of a validator, saturating upon overflow, as per the spec.
pub fn decrease_balance_directly(balance: &mut u64, delta: u64) -> Result<(), BeaconStateError> {
    *balance = balance.saturating_sub(delta);
    Ok(())
}