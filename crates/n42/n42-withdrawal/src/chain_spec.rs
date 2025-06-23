use alloy_primitives::private::arbitrary;
use crate::slot_epoch::Epoch;

#[derive(arbitrary::Arbitrary, PartialEq, Debug, Clone)]
pub struct ChainSpec {
    pub max_pending_partials_per_withdrawals_sweep: u64,
    pub min_activation_balance: u64,
    pub far_future_epoch: Epoch,
    pub max_validators_per_withdrawals_sweep: u64,
    pub eth1_address_withdrawal_prefix_byte: u8,
    pub max_effective_balance_electra: u64,
    pub max_effective_balance: u64,
    pub compounding_withdrawal_prefix_byte: u8,

}