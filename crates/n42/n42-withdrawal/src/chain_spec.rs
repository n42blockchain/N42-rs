use alloy_primitives::private::arbitrary;
use crate::safe_aitrh::{ArithError, SafeArith};
use crate::slot_epoch::Epoch;

#[derive(arbitrary::Arbitrary, PartialEq, Debug, Clone)]
pub struct ChainSpec {
    /// 部分提现扫描时，一次最多从待提现部分队列的数量，如果一个区块有过多的待提现项，限制每块最多处理多少条
    pub max_pending_partials_per_withdrawals_sweep: u64,
    /// 验证者余额大于最小激活余额，才有资格全额提现
    pub min_activation_balance: u64,
    /// Epochs that never arrive, validators never exit
    pub far_future_epoch: Epoch,
    /// 对验证者扫描的最大数量，防止一次遍历过多
    pub max_validators_per_withdrawals_sweep: u64,
    /// eth1 withdrawal address prefix
    pub eth1_address_withdrawal_prefix_byte: u8,
    /// Electra 阶段下最大有效余额，在部分提现作为上限来确定可提现余额
    pub max_effective_balance_electra: u64,
    /// Maximum effective balance, 32eth
    pub max_effective_balance: u64,
    /// Compound withdrawal address prefix
    pub compounding_withdrawal_prefix_byte: u8,
    pub min_validator_withdrawability_delay: Epoch,

    pub max_seed_lookahead: Epoch,

    pub max_per_epoch_activation_exit_churn_limit: u64,
    pub min_per_epoch_churn_limit_electra: u64,
    pub churn_limit_quotient: u64,
    pub effective_balance_increment: u64,
    pub full_exit_request_amount: u64,
    pub shard_committee_period: u64,
    pub ejection_balance: u64,
    pub max_per_epoch_activation_churn_limit: u64,
    pub min_per_epoch_churn_limit: u64,

}

impl ChainSpec {
    /// Compute the epoch used for activations prior to Deneb, and for exits under all forks.
    ///
    /// Spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#compute_activation_exit_epoch
    pub fn compute_activation_exit_epoch(&self, epoch: Epoch) -> Result<Epoch, ArithError> {
        epoch.safe_add(1)?.safe_add(self.max_seed_lookahead)
    }

}