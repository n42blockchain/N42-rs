// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The block assembler the payload builder uses, with the roots it does not
//! need left out and the one it does computed in parallel.
//!
//! reth's assembler computes three things over the whole block before it can
//! hand a header back: the transactions root (a trie over every transaction's
//! encoding), the receipts root (a trie over every receipt) and the logs
//! bloom. Timed in the payload builder at the 163,000-transaction tier, that
//! step was 262-286 ms of a 650-780 ms build -- the largest single phase, ahead
//! of executing the transactions (184-273 ms).
//!
//! Two of the three are waste on a HotStuff chain. Its header profile is
//! gov5's, whose receipts root is a keccak over the receipts rather than a
//! trie, and the payload builder overwrites the field a moment after this
//! computes it; the bloom is kept. The transactions root is real, and half of
//! its cost is encoding 163,000 transactions one after another, which is what
//! the worker pool is for. The trie itself stays sequential.

use alloy_consensus::{proofs::calculate_receipt_root, Block, TxReceipt};
use alloy_eips::Encodable2718;
use alloy_primitives::B256;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_evm::{
    block::BlockExecutorFactory,
    eth::EthBlockExecutionCtx,
    execute::{BlockAssembler, BlockAssemblerInput, BlockExecutionError},
};
use reth_evm_ethereum::EthBlockAssembler;
use reth_primitives_traits::{logs_bloom, Receipt, SignedTransaction};
use std::sync::{Arc, Mutex};

/// The QMDB root, computed while the transactions trie is.
///
/// The root is over the execution's bundle, which the assembler is handed,
/// and it used to be computed by the payload builder *after* assembly: 63-113
/// ms at the 163,000-transaction tier, one after the other with a
/// transactions trie of about the same size. The two are independent, so the
/// assembler runs them side by side and leaves the result here for the
/// payload builder to collect.
pub struct QmdbRootJob {
    /// The forest to compute against.
    pub state: n42_qmdb_reth::QmdbNodeState,
    /// The block's parent, which the tree is computed on top of.
    pub parent: alloy_primitives::B256,
    /// Whether Prague is active at the block, which changes how the bundle is
    /// read.
    pub prague: bool,
    /// Where the result goes. `None` until the assembler has run.
    pub out: Arc<Mutex<Option<Result<n42_qmdb_reth::PreparedBlock, String>>>>,
}

impl std::fmt::Debug for QmdbRootJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QmdbRootJob").field("parent", &self.parent).field("prague", &self.prague).finish_non_exhaustive()
    }
}

/// [`EthBlockAssembler`], with the roots precomputed the way described in the
/// module documentation.
#[derive(Debug)]
pub struct N42BlockAssembler<ChainSpec> {
    inner: EthBlockAssembler<ChainSpec>,
    /// Whether the chain's header profile replaces the receipts root, so the
    /// trie need not be built.
    hotstuff: bool,
    /// The QMDB root to compute alongside, on a QMDB chain.
    qmdb: Option<QmdbRootJob>,
}

impl<ChainSpec> N42BlockAssembler<ChainSpec> {
    /// Wraps reth's assembler. `hotstuff` says the receipts root will be
    /// replaced by the payload builder and need not be computed.
    pub const fn new(inner: EthBlockAssembler<ChainSpec>, hotstuff: bool) -> Self {
        Self { inner, hotstuff, qmdb: None }
    }

    /// Computes the QMDB root during assembly as well. See [`QmdbRootJob`].
    pub fn with_qmdb_root(mut self, job: QmdbRootJob) -> Self {
        self.qmdb = Some(job);
        self
    }
}

/// The transactions root, with the encodings produced in parallel.
///
/// Identical to `alloy_consensus::proofs::calculate_transaction_root`: the
/// trie is over each transaction's EIP-2718 encoding, keyed by index, and
/// only the encoding step is spread over the worker pool.
pub fn parallel_transaction_root<T: Encodable2718 + Sync>(transactions: &[T]) -> B256 {
    use rayon::prelude::*;
    let encoded: Vec<Vec<u8>> = transactions.par_iter().map(|tx| tx.encoded_2718()).collect();
    alloy_trie::root::ordered_trie_root_with_encoder(&encoded, |item, buf| {
        buf.extend_from_slice(item)
    })
}

impl<F, ChainSpec> BlockAssembler<F> for N42BlockAssembler<ChainSpec>
where
    F: for<'a> BlockExecutorFactory<
        ExecutionCtx<'a> = EthBlockExecutionCtx<'a>,
        Transaction: SignedTransaction,
        Receipt: Receipt,
    >,
    ChainSpec: EthChainSpec + EthereumHardforks,
{
    type Block = Block<F::Transaction>;

    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, F>,
    ) -> Result<Self::Block, BlockExecutionError> {
        let receipts = &input.output.receipts;
        let hotstuff = self.hotstuff;
        let bundle = input.bundle_state;
        let (transactions_root, (receipts_root, bloom)) = rayon::join(
            || {
                rayon::join(
                    || parallel_transaction_root(&input.transactions),
                    || {
                        if let Some(job) = &self.qmdb {
                            let changes = n42_qmdb_reth::changes_from_execution(bundle, job.prague);
                            let prepared = job.state.compute(job.parent, &changes).map_err(|e| e.to_string());
                            *job.out.lock().unwrap_or_else(|p| p.into_inner()) = Some(prepared);
                        }
                    },
                )
                .0
            },
            || {
                let bloom = logs_bloom(receipts.iter().flat_map(|r| r.logs()));
                // Replaced by gov5's keccak-of-receipts in the payload builder;
                // a placeholder here is never seen by anyone.
                let root = if hotstuff {
                    B256::ZERO
                } else {
                    calculate_receipt_root(
                        &receipts.iter().map(|r| r.with_bloom_ref()).collect::<Vec<_>>(),
                    )
                };
                (root, bloom)
            },
        );
        self.inner.assemble_block(input, Some(transactions_root), Some(receipts_root), Some(bloom))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxEip1559, TxEnvelope, TxLegacy};
    use alloy_primitives::{Address, Signature, TxKind, U256};

    /// The parallel root is the sequential one, on typed and legacy
    /// transactions alike.
    #[test]
    fn parallel_root_matches_alloy() {
        let txs: Vec<TxEnvelope> = (0..500u64)
            .map(|n| {
                if n % 3 == 0 {
                    let tx = TxLegacy { chain_id: Some(1), nonce: n, gas_price: 10, gas_limit: 21_000, to: TxKind::Call(Address::repeat_byte(3)), value: U256::from(n), ..Default::default() };
                    TxEnvelope::Legacy(Signed::new_unchecked(tx, Signature::test_signature(), Default::default()))
                } else {
                    let tx = TxEip1559 { chain_id: 1, nonce: n, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(2)), value: U256::from(n), ..Default::default() };
                    TxEnvelope::Eip1559(Signed::new_unchecked(tx, Signature::test_signature(), Default::default()))
                }
            })
            .collect();
        assert_eq!(parallel_transaction_root(&txs), alloy_consensus::proofs::calculate_transaction_root(&txs));
        assert_eq!(parallel_transaction_root::<TxEnvelope>(&[]), alloy_consensus::proofs::calculate_transaction_root::<TxEnvelope>(&[]));
    }
}
