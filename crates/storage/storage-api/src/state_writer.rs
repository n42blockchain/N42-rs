// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::BlockNumber;
use reth_execution_types::{BlockExecutionOutput, ExecutionOutcome};
use reth_storage_errors::provider::ProviderResult;
use reth_trie_common::HashedPostStateSorted;
use revm_database::{
    states::{BundleState, PlainStateReverts, StateChangeset},
    OriginalValuesKnown,
};

/// A helper type used as input to [`StateWriter`] for writing execution outcome for one or many
/// blocks.
#[derive(Debug, Clone)]
pub enum WriteStateInput<'a, R> {
    /// Single block execution output with block number.
    Single {
        /// Execution output for a single block.
        outcome: &'a BlockExecutionOutput<R>,
        /// Block number for the execution output.
        block: BlockNumber,
    },
    /// Multiple blocks execution outcome.
    Multiple(&'a ExecutionOutcome<R>),
}

impl<'a, R> WriteStateInput<'a, R> {
    /// Returns the number of blocks in the input.
    pub fn len(&self) -> usize {
        match self {
            Self::Single { .. } => 1,
            Self::Multiple(outcome) => outcome.len(),
        }
    }

    /// Returns true if the input is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the first block number in the input.
    pub fn first_block(&self) -> BlockNumber {
        match self {
            Self::Single { block, .. } => *block,
            Self::Multiple(outcome) => outcome.first_block,
        }
    }

    /// Returns the last block number in the input.
    pub fn last_block(&self) -> BlockNumber {
        match self {
            Self::Single { block, .. } => *block,
            Self::Multiple(outcome) => outcome.first_block + outcome.len() as u64 - 1,
        }
    }

    /// Returns a reference to the bundle state.
    pub fn state(&self) -> &BundleState {
        match self {
            Self::Single { outcome, .. } => &outcome.state,
            Self::Multiple(outcome) => &outcome.bundle,
        }
    }

    /// Returns receipts for the blocks.
    pub fn receipts(&self) -> Vec<&[R]> {
        match self {
            Self::Single { outcome, .. } => {
                vec![outcome.result.receipts.as_slice()]
            }
            Self::Multiple(outcome) => outcome.receipts.iter().map(|r| r.as_slice()).collect(),
        }
    }
}

impl<'a, R> From<&'a ExecutionOutcome<R>> for WriteStateInput<'a, R> {
    fn from(outcome: &'a ExecutionOutcome<R>) -> Self {
        WriteStateInput::Multiple(outcome)
    }
}

/// Configuration for what to write when calling [`StateWriter::write_state`].
#[derive(Debug, Clone, Copy, Default)]
pub struct StateWriteConfig {
    /// Whether to write receipts to the database.
    pub write_receipts: bool,
    /// Whether to write account changesets to the database.
    pub write_account_changesets: bool,
}

impl StateWriteConfig {
    /// Creates a new config with all options enabled.
    pub fn full() -> Self {
        Self { write_receipts: true, write_account_changesets: true }
    }

    /// Creates a new config with receipts disabled.
    pub fn without_receipts() -> Self {
        Self { write_receipts: false, write_account_changesets: true }
    }

    /// Creates a new config with account changesets disabled.
    pub fn without_account_changesets() -> Self {
        Self { write_receipts: true, write_account_changesets: false }
    }
}

/// A trait specifically for writing state changes or reverts
pub trait StateWriter {
    /// Receipt type included into [`ExecutionOutcome`].
    type Receipt;

    /// Write the state and optionally receipts to the database.
    ///
    /// The `config` parameter allows skipping writing certain types of data if they are written
    /// elsewhere.
    fn write_state<'a>(
        &self,
        execution_outcome: impl Into<WriteStateInput<'a, Self::Receipt>>,
        is_value_known: OriginalValuesKnown,
        config: StateWriteConfig,
    ) -> ProviderResult<()>
    where
        Self::Receipt: 'a;

    /// Write state reverts to the database.
    ///
    /// NOTE: Reverts will delete all wiped storage from plain state.
    fn write_state_reverts(
        &self,
        reverts: PlainStateReverts,
        first_block: BlockNumber,
    ) -> ProviderResult<()>;

    /// Write state changes to the database.
    fn write_state_changes(&self, changes: StateChangeset) -> ProviderResult<()>;

    /// Writes the hashed state changes to the database
    fn write_hashed_state(&self, hashed_state: &HashedPostStateSorted) -> ProviderResult<()>;

    /// Remove the block range of state above the given block. The state of the passed block is not
    /// removed.
    fn remove_state_above(&self, block: BlockNumber) -> ProviderResult<()>;

    /// Take the block range of state, recreating the [`ExecutionOutcome`]. The state of the passed
    /// block is not removed.
    fn take_state_above(
        &self,
        block: BlockNumber,
    ) -> ProviderResult<ExecutionOutcome<Self::Receipt>>;
}
