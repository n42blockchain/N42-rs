// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Re-execution of a recovery head on its parent's state.

use alloy_primitives::B256;
use reth_evm::{execute::Executor as _, ConfigureEvm, Database};
use reth_primitives_traits::RecoveredBlock;

/// Executes `block` once more on `db` (its parent's state) and returns its
/// EIP-7685 requests hash and its gas used. The gas used is the block figure
/// (the deferred header field), which under Amsterdam EIP-8037 is not the
/// receipts' cumulative gas.
pub fn reexecute_block<Evm, DB>(
    evm_config: &Evm,
    db: DB,
    block: &RecoveredBlock<n42_tx_types::Block>,
) -> Result<(B256, u64), reth_evm::execute::BlockExecutionError>
where
    Evm: ConfigureEvm<Primitives = n42_tx_types::N42Primitives>,
    DB: Database,
{
    let output = evm_config.executor(db).execute_one(block)?;
    Ok((output.requests.requests_hash(), output.gas_used))
}
