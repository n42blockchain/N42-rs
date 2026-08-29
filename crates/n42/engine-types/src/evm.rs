// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's EVM configuration: reth's Ethereum one, with every block
//! executor watched for the writes gov5 records and revm forgets.
//!
//! gov5 commits a block's state to QMDB by writing every dirty account and
//! storage slot of the block — dirty meaning written, not changed. A slot
//! that one transaction moves and a later one moves back is dirty with its
//! original value, and gov5 writes it (`BufferedPlainStateWriter`, which
//! refuses to short-circuit on `original == value`); QMDB appends a fresh
//! slot for the key and the root moves. revm's bundle, which is all reth
//! hands the state-root job, drops exactly that slot
//! (`TransitionAccount::update`). Every transaction's result passes
//! through here before it is committed, so the slots each one changes are
//! seen with their values at the start of that transaction; the first
//! sighting of a slot in a block is its value at the block's start, and
//! that is the value gov5 rewrites when the slot ends up back there. The
//! root job looks them up by parent hash and transaction hashes.
//!
//! Not covered: a slot changed and restored within one transaction — revm
//! reports the transaction's net effect, and gov5's journal would still
//! mark the slot dirty. It has not been seen on chain 94's traffic.

use std::{collections::HashMap, convert::Infallible, sync::Arc};

use alloy_consensus::{transaction::TxHashRef, Header};
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        ExecutableTx, ExecutableTxParts, GasOutput, StateDB, TxResult,
    },
    eth::EthBlockExecutionCtx,
    EvmFactory, RecoveredTx,
};
use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_engine::ExecutionData;
use n42_qmdb_reth::{record_restored_slots, restored_slots_key, RestoredSlot};
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::{Block, EthPrimitives};
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
    NextBlockEnvAttributes,
};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::{SealedBlock, SealedHeader, SignedTransaction};
use revm::Inspector;

/// reth's Ethereum EVM configuration with the tracking executor factory.
#[derive(Clone, Debug)]
pub struct N42EvmConfig {
    inner: EthEvmConfig,
    factory: TrackingBlockExecutorFactory<<EthEvmConfig as ConfigureEvm>::BlockExecutorFactory>,
}

impl N42EvmConfig {
    /// The configuration for `chain_spec`.
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        let inner = EthEvmConfig::new(chain_spec);
        let factory = TrackingBlockExecutorFactory { inner: inner.block_executor_factory().clone() };
        Self { inner, factory }
    }

    /// The chain.
    pub fn chain_spec(&self) -> &Arc<ChainSpec> {
        self.inner.chain_spec()
    }
}

impl ConfigureEvm for N42EvmConfig {
    type Primitives = EthPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory =
        TrackingBlockExecutorFactory<<EthEvmConfig as ConfigureEvm>::BlockExecutorFactory>;
    type BlockAssembler = <EthEvmConfig as ConfigureEvm>::BlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<Header>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<ExecutionCtxFor<'_, Self>, Self::Error> {
        self.inner.context_for_next_block(parent, attributes)
    }
}

impl ConfigureEngineEvm<ExecutionData> for N42EvmConfig {
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env_for_payload(payload)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        self.inner.context_for_payload(payload)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        self.inner.tx_iterator_for_payload(payload)
    }
}

/// A block executor factory whose executors record restored slots.
#[derive(Clone, Debug)]
pub struct TrackingBlockExecutorFactory<F> {
    inner: F,
}

impl<F> BlockExecutorFactory for TrackingBlockExecutorFactory<F>
where
    F: for<'a> BlockExecutorFactory<
        ExecutionCtx<'a> = EthBlockExecutionCtx<'a>,
        Transaction: SignedTransaction + TxHashRef,
    >,
{
    type EvmFactory = F::EvmFactory;
    type TxExecutionResult = F::TxExecutionResult;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = F::Transaction;
    type Receipt = F::Receipt;
    type Executor<'a, DB: StateDB, I: Inspector<<F::EvmFactory as EvmFactory>::Context<DB>>> =
        TrackingExecutor<F::Executor<'a, DB, I>>;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: <F::EvmFactory as EvmFactory>::Evm<DB, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I>
    where
        DB: StateDB,
        I: Inspector<<F::EvmFactory as EvmFactory>::Context<DB>>,
    {
        let parent_hash = ctx.parent_hash;
        TrackingExecutor {
            inner: self.inner.create_executor(evm, ctx),
            parent_hash,
            tx_hashes: Vec::new(),
            first_seen: HashMap::new(),
            pending: None,
        }
    }
}

/// A block executor that notes, for every slot a transaction changes, the
/// value the slot had when the block began, and files the block's list at
/// the end.
#[derive(Debug)]
pub struct TrackingExecutor<E> {
    inner: E,
    parent_hash: B256,
    /// The committed transactions, in order.
    tx_hashes: Vec<B256>,
    /// Each slot changed so far, with its value at the block's start.
    first_seen: HashMap<(Address, U256), U256>,
    /// The transaction executed but not yet committed: its hash and the
    /// slots it changed, with their values before it ran.
    pending: Option<(B256, Vec<RestoredSlot>)>,
}

impl<E> BlockExecutor for TrackingExecutor<E>
where
    E: BlockExecutor,
    E::Transaction: SignedTransaction + TxHashRef,
{
    type Transaction = E::Transaction;
    type Receipt = E::Receipt;
    type Evm = E::Evm;
    type Result = E::Result;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<Self::Result, BlockExecutionError> {
        let (tx_env, recovered) = tx.into_parts();
        let hash = *recovered.tx().tx_hash();
        let result = self.inner.execute_transaction_without_commit((tx_env, recovered))?;
        // Every slot this transaction changed, with the value it saw at its
        // start — the state it was loaded from, which is the block's start
        // for the first transaction to touch it.
        let mut changed = Vec::new();
        for (address, account) in &result.result().state {
            if account.is_selfdestructed() {
                continue;
            }
            for (slot, value) in &account.storage {
                if value.is_changed() {
                    changed.push((*address, *slot, value.original_value()));
                }
            }
        }
        self.pending = Some((hash, changed));
        Ok(result)
    }

    fn commit_transaction(&mut self, output: Self::Result) -> GasOutput {
        if let Some((hash, changed)) = self.pending.take() {
            self.tx_hashes.push(hash);
            for (address, slot, original) in changed {
                self.first_seen.entry((address, slot)).or_insert(original);
            }
        }
        self.inner.commit_transaction(output)
    }

    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        // Filed whole; the root job keeps the ones the bundle lost.
        let mut restored: Vec<RestoredSlot> = self
            .first_seen
            .into_iter()
            .map(|((address, slot), original)| (address, slot, original))
            .collect();
        restored.sort_unstable();
        record_restored_slots(restored_slots_key(self.parent_hash, self.tx_hashes.iter().copied()), restored);
        self.inner.finish()
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }

    fn receipts(&self) -> &[Self::Receipt] {
        self.inner.receipts()
    }
}
