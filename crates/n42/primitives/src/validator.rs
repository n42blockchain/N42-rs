// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

#![allow(missing_docs)]
use crate::{is_compounding_withdrawal_credential, BLSPubkey, ChainSpec, Epoch, Gwei};
use alloy_primitives::{Address, BlockNumber, Bytes, B256};
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(Serialize, Debug, Deserialize, PartialEq)]
pub struct ValidatorBeforeTx {
    pub address: Address,
    pub info: Option<Validator>,
}
#[derive(Debug)]
pub struct ValidatorChangeset {
    pub validators: Vec<(Address, Option<Validator>)>,
}
#[derive(Debug)]
pub struct ValidatorRevert {
    pub validators: Vec<Vec<(Address, Option<Validator>)>>,
}

#[derive(Debug, Clone, Hash, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct ValidatorInfo {
    pub activation_timestamp: u64,
    pub exit_timestamp: u64,
    pub balance_in_beacon: u64,
    pub effective_balance: u64,
    pub inactivity_score: u64,
}

#[derive(
    Debug, Clone, Hash, Default, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct Validator {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: B256, // Commitment to pubkey for withdrawals
    pub effective_balance: Gwei,      // Balance at stake
    pub slashed: bool,

    // Status epochs
    pub activation_eligibility_epoch: Epoch, // When criteria for activation were met
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch, // When validator can withdraw funds
}

impl Validator {
    pub fn is_partially_withdrawable_validator(&self, balance: u64, spec: &ChainSpec) -> bool {
        self.effective_balance == spec.max_effective_balance && balance > spec.max_effective_balance
    }

    pub fn is_fully_withdrawable_validator(&self, balance: u64, epoch: Epoch) -> bool {
        self.withdrawable_epoch <= epoch && balance > 0
    }

    pub fn get_execution_withdrawal_address(&self) -> Option<Address> {
        self.withdrawal_credentials
            .as_slice()
            .get(12..)
            .map(Address::from_slice)
    }

    /// Check if ``validator`` has an 0x02 prefixed "compounding" withdrawal credential.
    pub fn has_compounding_withdrawal_credential(&self, spec: &ChainSpec) -> bool {
        is_compounding_withdrawal_credential(self.withdrawal_credentials, spec)
    }

    pub fn has_execution_withdrawal_credential(&self, spec: &ChainSpec) -> bool {
        self.has_compounding_withdrawal_credential(spec)
            || self.has_eth1_withdrawal_credential(spec)
    }

    /// Returns `true` if the validator has eth1 withdrawal credential.
    pub fn has_eth1_withdrawal_credential(&self, spec: &ChainSpec) -> bool {
        self.withdrawal_credentials
            .as_slice()
            .first()
            .map(|byte| *byte == spec.eth1_address_withdrawal_prefix_byte)
            .unwrap_or(false)
    }

    /// Returns `true` if the validator is considered active at some epoch.
    pub fn is_active_at(&self, epoch: Epoch) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    pub fn from_deposit(
        //pubkey: PublicKeyBytes,
        pubkey: BLSPubkey,
        withdrawal_credentials: B256,
        amount: u64,
        //fork_name: ForkName,
        spec: &ChainSpec,
    ) -> Self {
        let mut validator = Validator {
            pubkey,
            withdrawal_credentials,
            activation_eligibility_epoch: spec.far_future_epoch,
            activation_epoch: spec.far_future_epoch,
            exit_epoch: spec.far_future_epoch,
            withdrawable_epoch: spec.far_future_epoch,
            effective_balance: 0,
            slashed: false,
        };

        //let max_effective_balance = validator.get_max_effective_balance(spec, fork_name);
        // safe math is unnecessary here since the spec.effective_balance_increment is never <= 0
        validator.effective_balance = std::cmp::min(
            amount - (amount % spec.effective_balance_increment),
            spec.max_effective_balance,
        );

        validator
    }

    /// Returns `true` if the validator *could* be eligible for activation at `epoch`.
    ///
    /// Eligibility depends on finalization, so we assume best-possible finalization. This function
    /// returning true is a necessary but *not sufficient* condition for a validator to activate in
    /// the epoch transition at the end of `epoch`.
    pub fn could_be_eligible_for_activation_at(&self, epoch: Epoch, spec: &ChainSpec) -> bool {
        // Has not yet been activated
        self.activation_epoch == spec.far_future_epoch
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
    pub fn is_eligible_for_activation_queue(&self, spec: &ChainSpec) -> bool {
        self.is_eligible_for_activation_queue_base(spec)
    }

    /// Returns `true` if the validator is eligible to join the activation queue.
    ///
    /// Spec v0.12.1
    fn is_eligible_for_activation_queue_base(&self, spec: &ChainSpec) -> bool {
        self.activation_eligibility_epoch == spec.far_future_epoch
            && self.effective_balance == spec.max_effective_balance
    }

    /// Returns `true` if the validator is able to withdraw at some epoch.
    pub fn is_withdrawable_at(&self, epoch: Epoch) -> bool {
        epoch >= self.withdrawable_epoch
    }

    /// Returns `true` if the validator is considered exited at some epoch.
    pub fn is_exited_at(&self, epoch: Epoch) -> bool {
        self.exit_epoch <= epoch
    }

    pub fn js_exited_set(&self, spec: &ChainSpec) -> bool {
        self.exit_epoch != spec.far_future_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    fn test_spec() -> ChainSpec {
        ChainSpec {
            max_effective_balance: 32_000_000_000,
            effective_balance_increment: 1_000_000_000,
            far_future_epoch: u64::MAX,
            eth1_address_withdrawal_prefix_byte: 0x01,
            compounding_withdrawal_prefix_byte: 0x02,
            ..Default::default()
        }
    }

    fn test_validator() -> Validator {
        Validator {
            pubkey: BLSPubkey::default(),
            withdrawal_credentials: B256::ZERO,
            effective_balance: 32_000_000_000,
            slashed: false,
            activation_eligibility_epoch: 0,
            activation_epoch: 10,
            exit_epoch: u64::MAX,
            withdrawable_epoch: u64::MAX,
        }
    }

    // ==================== ValidatorInfo Tests ====================

    #[test]
    fn test_validator_info_default() {
        let info = ValidatorInfo::default();
        assert_eq!(info.activation_timestamp, 0);
        assert_eq!(info.exit_timestamp, 0);
        assert_eq!(info.balance_in_beacon, 0);
        assert_eq!(info.effective_balance, 0);
        assert_eq!(info.inactivity_score, 0);
    }

    #[test]
    fn test_validator_info_creation() {
        let info = ValidatorInfo {
            activation_timestamp: 1000,
            exit_timestamp: 2000,
            balance_in_beacon: 32_000_000_000,
            effective_balance: 32_000_000_000,
            inactivity_score: 0,
        };
        assert_eq!(info.activation_timestamp, 1000);
        assert_eq!(info.exit_timestamp, 2000);
        assert_eq!(info.balance_in_beacon, 32_000_000_000);
    }

    // ==================== Validator Tests ====================

    #[test]
    fn test_validator_default() {
        let v = Validator::default();
        assert_eq!(v.effective_balance, 0);
        assert!(!v.slashed);
        assert_eq!(v.activation_epoch, 0);
        assert_eq!(v.exit_epoch, 0);
    }

    #[test]
    fn test_validator_is_active_at() {
        let v = test_validator();

        // Before activation
        assert!(!v.is_active_at(5));
        assert!(!v.is_active_at(9));

        // At and after activation (before exit)
        assert!(v.is_active_at(10));
        assert!(v.is_active_at(100));
        assert!(v.is_active_at(1000));
    }

    #[test]
    fn test_validator_is_active_at_with_exit() {
        let mut v = test_validator();
        v.exit_epoch = 100;

        // Active between activation and exit
        assert!(v.is_active_at(10));
        assert!(v.is_active_at(50));
        assert!(v.is_active_at(99));

        // Not active at or after exit
        assert!(!v.is_active_at(100));
        assert!(!v.is_active_at(101));
    }

    #[test]
    fn test_validator_is_exited_at() {
        let mut v = test_validator();
        v.exit_epoch = 100;

        assert!(!v.is_exited_at(99));
        assert!(v.is_exited_at(100));
        assert!(v.is_exited_at(101));
    }

    #[test]
    fn test_validator_is_withdrawable_at() {
        let mut v = test_validator();
        v.withdrawable_epoch = 200;

        assert!(!v.is_withdrawable_at(199));
        assert!(v.is_withdrawable_at(200));
        assert!(v.is_withdrawable_at(201));
    }

    #[test]
    fn test_validator_is_fully_withdrawable() {
        let mut v = test_validator();
        v.withdrawable_epoch = 100;

        // Not withdrawable before epoch
        assert!(!v.is_fully_withdrawable_validator(1000, 99));

        // Withdrawable at epoch with balance > 0
        assert!(v.is_fully_withdrawable_validator(1000, 100));
        assert!(v.is_fully_withdrawable_validator(1, 100));

        // Not withdrawable with 0 balance
        assert!(!v.is_fully_withdrawable_validator(0, 100));
    }

    #[test]
    fn test_validator_is_partially_withdrawable() {
        let spec = test_spec();
        let mut v = test_validator();
        v.effective_balance = spec.max_effective_balance;

        // Partially withdrawable when balance > max_effective_balance
        assert!(v.is_partially_withdrawable_validator(33_000_000_000, &spec));

        // Not partially withdrawable when balance <= max_effective_balance
        assert!(!v.is_partially_withdrawable_validator(32_000_000_000, &spec));
        assert!(!v.is_partially_withdrawable_validator(31_000_000_000, &spec));
    }

    #[test]
    fn test_validator_from_deposit() {
        let spec = test_spec();
        let pubkey = BLSPubkey::default();
        let withdrawal_credentials = B256::ZERO;
        let amount = 32_000_000_000u64;

        let v = Validator::from_deposit(pubkey, withdrawal_credentials, amount, &spec);

        assert_eq!(v.effective_balance, spec.max_effective_balance);
        assert!(!v.slashed);
        assert_eq!(v.activation_epoch, spec.far_future_epoch);
        assert_eq!(v.exit_epoch, spec.far_future_epoch);
    }

    #[test]
    fn test_validator_from_deposit_with_excess() {
        let spec = test_spec();
        let pubkey = BLSPubkey::default();
        let withdrawal_credentials = B256::ZERO;
        // Amount greater than max
        let amount = 64_000_000_000u64;

        let v = Validator::from_deposit(pubkey, withdrawal_credentials, amount, &spec);

        // Should be capped at max_effective_balance
        assert_eq!(v.effective_balance, spec.max_effective_balance);
    }

    #[test]
    fn test_validator_from_deposit_with_remainder() {
        let spec = test_spec();
        let pubkey = BLSPubkey::default();
        let withdrawal_credentials = B256::ZERO;
        // Amount with remainder after modulo
        let amount = 32_500_000_000u64;

        let v = Validator::from_deposit(pubkey, withdrawal_credentials, amount, &spec);

        // Should be rounded down to effective_balance_increment multiple
        assert_eq!(v.effective_balance, 32_000_000_000);
    }

    #[test]
    fn test_validator_has_eth1_withdrawal_credential() {
        let spec = test_spec();

        // With ETH1 prefix
        let mut credentials = [0u8; 32];
        credentials[0] = 0x01;
        let mut v = test_validator();
        v.withdrawal_credentials = B256::from_slice(&credentials);
        assert!(v.has_eth1_withdrawal_credential(&spec));

        // Without ETH1 prefix
        v.withdrawal_credentials = B256::ZERO;
        assert!(!v.has_eth1_withdrawal_credential(&spec));
    }

    #[test]
    fn test_validator_has_compounding_withdrawal_credential() {
        let spec = test_spec();

        // With compounding prefix
        let mut credentials = [0u8; 32];
        credentials[0] = 0x02;
        let mut v = test_validator();
        v.withdrawal_credentials = B256::from_slice(&credentials);
        assert!(v.has_compounding_withdrawal_credential(&spec));

        // Without compounding prefix
        v.withdrawal_credentials = B256::ZERO;
        assert!(!v.has_compounding_withdrawal_credential(&spec));
    }

    #[test]
    fn test_validator_get_execution_withdrawal_address() {
        let mut v = test_validator();

        // Set up withdrawal credentials with an address in bytes 12-32
        let mut credentials = [0u8; 32];
        credentials[0] = 0x01; // ETH1 prefix
        // Set address bytes (12-32)
        for i in 12..32 {
            credentials[i] = (i - 12) as u8;
        }
        v.withdrawal_credentials = B256::from_slice(&credentials);

        let addr = v.get_execution_withdrawal_address();
        assert!(addr.is_some());
    }

    #[test]
    fn test_validator_is_eligible_for_activation_queue() {
        let spec = test_spec();

        // Eligible: activation_eligibility_epoch == far_future and effective_balance == max
        let mut v = test_validator();
        v.activation_eligibility_epoch = spec.far_future_epoch;
        v.effective_balance = spec.max_effective_balance;
        assert!(v.is_eligible_for_activation_queue(&spec));

        // Not eligible: already has eligibility epoch set
        v.activation_eligibility_epoch = 10;
        assert!(!v.is_eligible_for_activation_queue(&spec));

        // Not eligible: insufficient balance
        v.activation_eligibility_epoch = spec.far_future_epoch;
        v.effective_balance = spec.max_effective_balance - 1;
        assert!(!v.is_eligible_for_activation_queue(&spec));
    }

    #[test]
    fn test_validator_could_be_eligible_for_activation() {
        let spec = test_spec();

        let mut v = test_validator();
        v.activation_epoch = spec.far_future_epoch;
        v.activation_eligibility_epoch = 5;

        // Could be eligible at epoch 7 (7 > 5)
        assert!(v.could_be_eligible_for_activation_at(7, &spec));

        // Not eligible at epoch 5 (5 is not > 5)
        assert!(!v.could_be_eligible_for_activation_at(5, &spec));

        // Not eligible if already activated
        v.activation_epoch = 10;
        assert!(!v.could_be_eligible_for_activation_at(20, &spec));
    }

    #[test]
    fn test_validator_js_exited_set() {
        let spec = test_spec();

        let mut v = test_validator();
        v.exit_epoch = spec.far_future_epoch;
        assert!(!v.js_exited_set(&spec));

        v.exit_epoch = 100;
        assert!(v.js_exited_set(&spec));
    }

    // ==================== ValidatorBeforeTx Tests ====================

    #[test]
    fn test_validator_before_tx() {
        let addr = Address::ZERO;
        let v = ValidatorBeforeTx {
            address: addr,
            info: Some(test_validator()),
        };
        assert_eq!(v.address, addr);
        assert!(v.info.is_some());
    }

    #[test]
    fn test_validator_before_tx_none() {
        let addr = Address::ZERO;
        let v = ValidatorBeforeTx {
            address: addr,
            info: None,
        };
        assert_eq!(v.address, addr);
        assert!(v.info.is_none());
    }
}
