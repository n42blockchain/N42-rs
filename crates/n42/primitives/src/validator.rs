#![allow(missing_docs)]
use alloy_rlp::{Encodable, Decodable, RlpEncodable,  RlpDecodable};
use serde::{Deserialize, Serialize};
use alloy_primitives::{Address, BlockNumber, B256, Bytes};
use crate::{
    Epoch, BLSPubkey, Gwei,
    is_compounding_withdrawal_credential,
    far_future_epoch,
max_effective_balance,
effective_balance_increment,
eth1_address_withdrawal_prefix_byte,
};

#[derive(Serialize, Debug, Deserialize,PartialEq)]
pub struct  ValidatorBeforeTx{
    pub address: Address,
    pub info: Option<Validator>,
}
#[derive(Debug)]
pub struct ValidatorChangeset{
    pub validators: Vec<(Address,Option<Validator>)>,
}
#[derive(Debug)]
pub struct ValidatorRevert{
    pub validators: Vec<Vec<(Address, Option<Validator>)>>,
}

#[derive(Debug, Clone, Hash, Default, PartialEq, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
pub struct Validator {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: B256,  // Commitment to pubkey for withdrawals
    pub effective_balance: Gwei,  // Balance at stake
    pub slashed: bool,

    // Status epochs
    pub activation_eligibility_epoch: Epoch,  // When criteria for activation were met
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,  // When validator can withdraw funds
}

impl Validator {
    pub fn is_partially_withdrawable_validator(
        &self,
        balance: u64,
    ) -> bool {
        self.effective_balance == max_effective_balance
            && balance > max_effective_balance
    }

    pub fn is_fully_withdrawable_validator(
        &self,
        balance: u64,
        epoch: Epoch,
    ) -> bool {
        self.withdrawable_epoch <= epoch && balance > 0
    }

    pub fn get_execution_withdrawal_address(&self) -> Option<Address> {
        self.withdrawal_credentials
            .as_slice()
            .get(12..)
            .map(Address::from_slice)
    }

    /// Check if ``validator`` has an 0x02 prefixed "compounding" withdrawal credential.
    pub fn has_compounding_withdrawal_credential(&self) -> bool {
        is_compounding_withdrawal_credential(self.withdrawal_credentials)
    }

    pub fn has_execution_withdrawal_credential(&self) -> bool {
        self.has_compounding_withdrawal_credential()
            || self.has_eth1_withdrawal_credential()
    }

    /// Returns `true` if the validator has eth1 withdrawal credential.
    pub fn has_eth1_withdrawal_credential(&self) -> bool {
        self.withdrawal_credentials
            .as_slice()
            .first()
            .map(|byte| *byte == eth1_address_withdrawal_prefix_byte)
            .unwrap_or(false)
    }

    /// Returns `true` if the validator is considered active at some epoch.
    pub fn is_active_at(&self, epoch: Epoch) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    pub fn from_deposit(
        //pubkey: PublicKeyBytes,
        pubkey: Bytes,
        withdrawal_credentials: B256,
        amount: u64,
        //fork_name: ForkName,
        //spec: &ChainSpec,
    ) -> Self {
        let mut validator = Validator {
            pubkey,
            withdrawal_credentials,
            activation_eligibility_epoch: far_future_epoch,
            activation_epoch: far_future_epoch,
            exit_epoch: far_future_epoch,
            withdrawable_epoch: far_future_epoch,
            effective_balance: 0,
            slashed: false,
        };

        //let max_effective_balance = validator.get_max_effective_balance(spec, fork_name);
        // safe math is unnecessary here since the spec.effective_balance_increment is never <= 0
        validator.effective_balance = std::cmp::min(
            amount - (amount % effective_balance_increment),
            max_effective_balance,
        );

        validator
    }

    /// Returns `true` if the validator *could* be eligible for activation at `epoch`.
    ///
    /// Eligibility depends on finalization, so we assume best-possible finalization. This function
    /// returning true is a necessary but *not sufficient* condition for a validator to activate in
    /// the epoch transition at the end of `epoch`.
    pub fn could_be_eligible_for_activation_at(&self, epoch: Epoch) -> bool {
        // Has not yet been activated
        self.activation_epoch == far_future_epoch
        // Placement in queue could be finalized.
        //
        // NOTE: the epoch distance is 1 rather than 2 because we consider the activations that
        // occur at the *end* of `epoch`, after `process_justification_and_finalization` has already
        // updated the state's checkpoint.
        && self.activation_eligibility_epoch < epoch
    }

    /// Returns `true` if the validator is eligible to join the activation queue.
    ///
    /// Calls the correct function depending on the provided `fork_name`.
    pub fn is_eligible_for_activation_queue(
        &self,
    ) -> bool {
        self.is_eligible_for_activation_queue_base()
    }

    /// Returns `true` if the validator is eligible to join the activation queue.
    ///
    /// Spec v0.12.1
    fn is_eligible_for_activation_queue_base(&self) -> bool {
        self.activation_eligibility_epoch == far_future_epoch
            && self.effective_balance == max_effective_balance
    }

    /// Returns `true` if the validator is able to withdraw at some epoch.
    pub fn is_withdrawable_at(&self, epoch: Epoch) -> bool {
        epoch >= self.withdrawable_epoch
    }

    /// Returns `true` if the validator is considered exited at some epoch.
    pub fn is_exited_at(&self, epoch: Epoch) -> bool {
        self.exit_epoch <= epoch
    }

    pub fn is_exited_set(&self) -> bool {
        self.exit_epoch != far_future_epoch
    }

}

