// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42 Beacon chain table definitions
//!
//! This module defines the database table specifications for the N42 beacon chain.
//! These specifications are separate from the reth tables to maintain clean separation.
//!
//! # Table Schema
//!
//! ## BeaconStateRecord
//! | Key | Value |
//! |-----|-------|
//! | `BlockHash` | `BeaconState` |
//!
//! ## BeaconBlockRecord
//! | Key | Value |
//! |-----|-------|
//! | `BlockHash` | `BeaconBlock` |
//!
//! ## BeaconNum2Hash
//! | Key | Value |
//! |-----|-------|
//! | `BlockNumber` | `BlockHash` |
//!
//! ## PlainValidatorState
//! | Key | Value |
//! |-----|-------|
//! | `Address` | `Validator` |
//!
//! ## ValidatorsHistory
//! | Key | Value |
//! |-----|-------|
//! | `ShardedKey<Address>` | `BlockNumberList` |
//!
//! ## ValidatorChangeSets (DUPSORT)
//! | Key | SubKey | Value |
//! |-----|--------|-------|
//! | `BlockNumber` | `Address` | `ValidatorBeforeTx` |

/// Table names for N42 beacon chain storage
pub mod names {
    /// Beacon state table name
    pub const BEACON_STATE: &str = "BeaconStateRecord";
    /// Beacon block table name
    pub const BEACON_BLOCK: &str = "BeaconBlockRecord";
    /// Beacon num to hash table name
    pub const BEACON_NUM_TO_HASH: &str = "BeaconNum2Hash";
    /// Plain validator state table name
    pub const PLAIN_VALIDATOR_STATE: &str = "PlainValidatorState";
    /// Validators history table name
    pub const VALIDATORS_HISTORY: &str = "ValidatorsHistory";
    /// Validator change sets table name
    pub const VALIDATOR_CHANGE_SETS: &str = "ValidatorChangeSets";
}

/// All N42 beacon chain table names
pub const N42_TABLES: [&str; 6] = [
    names::BEACON_STATE,
    names::BEACON_BLOCK,
    names::BEACON_NUM_TO_HASH,
    names::PLAIN_VALIDATOR_STATE,
    names::VALIDATORS_HISTORY,
    names::VALIDATOR_CHANGE_SETS,
];

/// Table IDs for programmatic access
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum N42TableId {
    /// Beacon state table
    BeaconState = 0,
    /// Beacon block table
    BeaconBlock = 1,
    /// Beacon num to hash table
    BeaconNum2Hash = 2,
    /// Plain validator state table
    PlainValidatorState = 3,
    /// Validators history table
    ValidatorsHistory = 4,
    /// Validator change sets table
    ValidatorChangeSets = 5,
}

impl N42TableId {
    /// Get the table name
    pub const fn name(&self) -> &'static str {
        match self {
            Self::BeaconState => names::BEACON_STATE,
            Self::BeaconBlock => names::BEACON_BLOCK,
            Self::BeaconNum2Hash => names::BEACON_NUM_TO_HASH,
            Self::PlainValidatorState => names::PLAIN_VALIDATOR_STATE,
            Self::ValidatorsHistory => names::VALIDATORS_HISTORY,
            Self::ValidatorChangeSets => names::VALIDATOR_CHANGE_SETS,
        }
    }

    /// Get all table IDs
    pub const fn all() -> [Self; 6] {
        [
            Self::BeaconState,
            Self::BeaconBlock,
            Self::BeaconNum2Hash,
            Self::PlainValidatorState,
            Self::ValidatorsHistory,
            Self::ValidatorChangeSets,
        ]
    }
}

impl std::fmt::Display for N42TableId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}
