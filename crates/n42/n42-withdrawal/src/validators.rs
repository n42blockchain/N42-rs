use alloy_primitives::Address;
use alloy_primitives::private::arbitrary;
use alloy_primitives::private::serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use crate::chain_spec::ChainSpec;
use crate::crypto::PublicKeyBytes;
use crate::Hash256;
use crate::slot_epoch::Epoch;
use crate::fork_name::ForkName;

#[derive(
    arbitrary::Arbitrary, Debug, Clone, PartialEq, Eq,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct Validator {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

impl Validator {
    /// Get the execution withdrawal address if this validator has one initialized.
    pub fn get_execution_withdrawal_address(&self, spec: &ChainSpec) -> Option<Address> {
        self.has_execution_withdrawal_credential(spec)
            .then(|| {
                self.withdrawal_credentials
                    .as_slice()
                    .get(12..)
                    .map(Address::from_slice)
            })
            .flatten()
    }

    /// Returns `true` if the validator is fully withdrawable at some epoch.
    ///
    /// Calls the correct function depending on the provided `fork_name`.
    pub fn is_fully_withdrawable_validator(
        &self,
        balance: u64,
        epoch: Epoch,
        spec: &ChainSpec,
        current_fork: ForkName,
    ) -> bool {
        if current_fork.electra_enabled() {
            self.is_fully_withdrawable_validator_electra(balance, epoch, spec)
        } else {
            self.is_fully_withdrawable_validator_capella(balance, epoch, spec)
        }
    }

    /// Returns `true` if the validator is fully withdrawable at some epoch.
    ///
    /// Modified in electra as part of EIP 7251.
    fn is_fully_withdrawable_validator_electra(
        &self,
        balance: u64,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> bool {
        self.has_execution_withdrawal_credential(spec)
            && self.withdrawable_epoch <= epoch
            && balance > 0
    }

    /// Returns `true` if the validator has a 0x01 or 0x02 prefixed withdrawal credential.
    pub fn has_execution_withdrawal_credential(&self, spec: &ChainSpec) -> bool {
        self.has_compounding_withdrawal_credential(spec)
            || self.has_eth1_withdrawal_credential(spec)
    }

    /// Check if ``validator`` has an 0x02 prefixed "compounding" withdrawal credential.
    pub fn has_compounding_withdrawal_credential(&self, spec: &ChainSpec) -> bool {
        is_compounding_withdrawal_credential(self.withdrawal_credentials, spec)
    }

    /// Returns `true` if the validator is fully withdrawable at some epoch.
    fn is_fully_withdrawable_validator_capella(
        &self,
        balance: u64,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> bool {
        self.has_eth1_withdrawal_credential(spec) && self.withdrawable_epoch <= epoch && balance > 0
    }

    /// Returns `true` if the validator has eth1 withdrawal credential.
    pub fn has_eth1_withdrawal_credential(&self, spec: &ChainSpec) -> bool {
        self.withdrawal_credentials
            .as_slice()
            .first()
            .map(|byte| *byte == spec.eth1_address_withdrawal_prefix_byte)
            .unwrap_or(false)
    }

    /// Returns `true` if the validator is partially withdrawable.
    ///
    /// Calls the correct function depending on the provided `fork_name`.
    pub fn is_partially_withdrawable_validator(
        &self,
        balance: u64,
        spec: &ChainSpec,
        current_fork: ForkName,
    ) -> bool {
        if current_fork.electra_enabled() {
            self.is_partially_withdrawable_validator_electra(balance, spec, current_fork)
        } else {
            self.is_partially_withdrawable_validator_capella(balance, spec)
        }
    }

    /// Returns `true` if the validator is partially withdrawable.
    ///
    /// Modified in electra as part of EIP 7251.
    pub fn is_partially_withdrawable_validator_electra(
        &self,
        balance: u64,
        spec: &ChainSpec,
        current_fork: ForkName,
    ) -> bool {
        let max_effective_balance = self.get_max_effective_balance(spec, current_fork);
        let has_max_effective_balance = self.effective_balance == max_effective_balance;
        let has_excess_balance = balance > max_effective_balance;
        self.has_execution_withdrawal_credential(spec)
            && has_max_effective_balance
            && has_excess_balance
    }

    /// Returns `true` if the validator is partially withdrawable.
    fn is_partially_withdrawable_validator_capella(&self, balance: u64, spec: &ChainSpec) -> bool {
        self.has_eth1_withdrawal_credential(spec)
            && self.effective_balance == spec.max_effective_balance
            && balance > spec.max_effective_balance
    }

    /// Returns the max effective balance for a validator in gwei.
    pub fn get_max_effective_balance(&self, spec: &ChainSpec, current_fork: ForkName) -> u64 {
        if current_fork >= ForkName::Electra {
            if self.has_compounding_withdrawal_credential(spec) {
                spec.max_effective_balance_electra
            } else {
                spec.min_activation_balance
            }
        } else {
            spec.max_effective_balance
        }
    }
}

pub fn is_compounding_withdrawal_credential(
    withdrawal_credentials: Hash256,
    spec: &ChainSpec,
) -> bool {
    withdrawal_credentials
        .as_slice()
        .first()
        .map(|prefix_byte| *prefix_byte == spec.compounding_withdrawal_prefix_byte)
        .unwrap_or(false)
}