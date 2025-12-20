// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Abstraction of an executable transaction.

use alloy_primitives::Address;

/// Loads transaction into execution environment.
pub trait FillTxEnv<TxEnv> {
    /// Fills `TxEnv` with an [`Address`] and transaction.
    fn fill_tx_env(&self, tx_env: &mut TxEnv, sender: Address);
}
