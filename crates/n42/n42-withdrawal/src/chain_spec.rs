use alloy_primitives::private::arbitrary;
use tree_hash::TreeHash;
use crate::beacon_state::EthSpec;
use crate::fork_name::{ForkData, ForkName};
use crate::safe_aitrh::{ArithError, SafeArith};
use crate::slot_epoch::{Epoch, Slot};
use crate::Hash256;
use crate::withdrawal::Fork;

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

    /// Compute activation and exit epochs
    pub max_seed_lookahead: Epoch,

    pub max_per_epoch_activation_exit_churn_limit: u64,
    pub min_per_epoch_churn_limit_electra: u64,
    /// Calculate the denominator of the activation number
    pub churn_limit_quotient: u64,
    pub effective_balance_increment: u64,
    pub full_exit_request_amount: u64,
    pub shard_committee_period: u64,
    /// if effective_balance < ejection_balance,Validator is forced to exit
    pub ejection_balance: u64,
    /// maximum number of activations
    pub max_per_epoch_activation_churn_limit: u64,
    /// minimum activation number
    pub min_per_epoch_churn_limit: u64,

    pub deposit_contract_tree_depth: u64,
    pub capella_fork_version: [u8; 4],
    pub genesis_slot: Slot,
    pub genesis_fork_version: [u8; 4],
    pub shuffle_round_count: u8,
    pub min_seed_lookahead: Epoch,
    pub fulu_fork_epoch: Option<Epoch>,
    pub electra_fork_epoch: Option<Epoch>,
    pub epochs_per_sync_committee_period: Epoch,

    pub(crate) domain_beacon_proposer: u32,
    pub(crate) domain_beacon_attester: u32,
    pub(crate) domain_randao: u32,
    pub(crate) domain_deposit: u32,
    pub(crate) domain_voluntary_exit: u32,
    pub(crate) domain_sync_committee: u32,
    pub(crate) domain_bls_to_execution_change: u32,

}

/// Each of the BLS signature domains.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Domain {
    VoluntaryExit,
    Deposit,
    BeaconProposer,
    Randao,
    BeaconAttester,
    SyncCommittee,
    BlsToExecutionChange,

}

impl ChainSpec {
    /// Compute the epoch used for activations prior to Deneb, and for exits under all forks.
    ///
    /// Spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#compute_activation_exit_epoch
    pub fn compute_activation_exit_epoch(&self, epoch: Epoch) -> Result<Epoch, ArithError> {
        epoch.safe_add(1)?.safe_add(self.max_seed_lookahead)
    }

    /// Compute a domain by applying the given `fork_version`.
    pub fn compute_domain(
        &self,
        domain: Domain,
        fork_version: [u8; 4],
        genesis_validators_root: Hash256,
    ) -> Hash256 {
        let domain_constant = self.get_domain_constant(domain);

        let mut domain = [0; 32];
        domain[0..4].copy_from_slice(&int_to_bytes4(domain_constant));
        domain[4..].copy_from_slice(
            Self::compute_fork_data_root(fork_version, genesis_validators_root)
                .as_slice()
                .get(..28)
                .expect("fork has is 32 bytes so first 28 bytes should exist"),
        );

        Hash256::from(domain)
    }

    /// Return the 32-byte fork data root for the `current_version` and `genesis_validators_root`.
    ///
    /// This is used primarily in signature domains to avoid collisions across forks/chains.
    ///
    /// Spec v0.12.1
    pub fn compute_fork_data_root(
        current_version: [u8; 4],
        genesis_validators_root: Hash256,
    ) -> Hash256 {
        ForkData {
            current_version,
            genesis_validators_root,
        }
            .tree_hash_root()
    }

    /// Get the domain number, unmodified by the fork.
    ///
    /// Spec v0.12.1
    pub fn get_domain_constant(&self, domain: Domain) -> u32 {
        match domain {
            Domain::BeaconProposer => self.domain_beacon_proposer,
            Domain::BeaconAttester => self.domain_beacon_attester,
            Domain::Randao => self.domain_randao,
            Domain::Deposit => self.domain_deposit,
            Domain::VoluntaryExit => self.domain_voluntary_exit,
            Domain::SyncCommittee => self.domain_sync_committee,
            Domain::BlsToExecutionChange => self.domain_bls_to_execution_change,
        }
    }
    /// Get the domain for a deposit signature.
    ///
    /// Deposits are valid across forks, thus the deposit domain is computed
    /// with the genesis fork version.
    pub fn get_deposit_domain(&self) -> Hash256 {
        self.compute_domain(Domain::Deposit, self.genesis_fork_version, Hash256::default())
    }

    /// Get the domain that represents the fork meta and signature domain.
    ///
    /// Spec v0.12.1
    pub fn get_domain(
        &self,
        epoch: Epoch,
        domain: Domain,
        fork: &Fork,
        genesis_validators_root: Hash256,
    ) -> Hash256 {
        let fork_version = fork.get_fork_version(epoch);
        self.compute_domain(domain, fork_version, genesis_validators_root)
    }

    pub fn max_effective_balance_for_fork(&self, fork_name: ForkName) -> u64 {
        if fork_name.electra_enabled() {
            self.max_effective_balance_electra
        } else {
            self.max_effective_balance
        }
    }

    /// Returns the name of the fork which is active at `slot`.
    pub fn fork_name_at_slot<E: EthSpec>(&self, slot: Slot) -> ForkName {
        self.fork_name_at_epoch(slot.epoch(E::slots_per_epoch()))
    }

    /// Returns the name of the fork which is active at `epoch`.
    pub fn fork_name_at_epoch(&self, epoch: Epoch) -> ForkName {
        if let Some(fork_epoch) = self.fulu_fork_epoch {
            if epoch >= fork_epoch {
                return ForkName::Fulu;
            }
        }
        ForkName::Electra
    }
}

/// Returns `int` as little-endian bytes with a length of 4.
pub fn int_to_bytes4(int: u32) -> [u8; 4] {
    int.to_le_bytes()
}