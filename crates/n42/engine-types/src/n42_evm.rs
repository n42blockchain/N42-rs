// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's EVM configuration over [`N42Primitives`].
//!
//! reth's `EthEvmConfig` is pinned to the Ethereum envelope through its
//! receipt builder and its `Primitives`, and its executor factory to chain
//! specs whose header is alloy's. This is the same configuration (same block
//! environments, same evm2 execution through reth's [`EthBlockExecutor`],
//! same assembler) with [`N42TxEnvelope`] as the transaction and
//! [`N42Header`](Header) as the header, so a block may carry 0x50
//! transactions.
//!
//! reth v2.9.0 executes on evm2. A 0x50 transaction reaches evm2 as an
//! EIP-1559 transaction (`n42_tx_types::evm`); the revm-era fast transfer
//! path is behind the `legacy-revm-paths` feature
//! ([`crate::legacy_paths`]).

use alloy_consensus::BlockHeader as _;
use alloy_eips::{eip7840::BlobParams, Decodable2718};
use alloy_primitives::{Address, Bytes, U256};
use alloy_rpc_types_engine::ExecutionData;
use evm2::{env::BlockEnvExt, SpecId};
use n42_header::N42Header as Header;
use n42_tx_types::{AltSigSenderCache, N42Primitives, N42TxEnvelope, N42TxType, Receipt};
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks, Hardforks};
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor, NextBlockEnvAttributes,
    ReceiptBuilder, ReceiptBuilderCtx, SenderRecoveryCache,
};
use reth_evm_ethereum::{
    spec_id_by_timestamp_and_block_number, EthBlockExecutionCtx, EthBlockExecutor, EthEvmEnv, EvmFactory,
    RethEvmFactory,
};
use crate::assembler::N42HeaderAssembler;
use reth_primitives_traits::{SealedBlock, SealedHeader, SignedTransaction, TxTy};
use reth_storage_errors::any::AnyError;
use std::{borrow::Cow, convert::Infallible, fmt::Debug, sync::Arc};

/// Builds [`Receipt`]s (typed by [`N42TxType`]) from execution results.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct N42ReceiptBuilder;

impl ReceiptBuilder for N42ReceiptBuilder {
    type Transaction = N42TxEnvelope;
    type Receipt = Receipt;

    fn build_receipt<T: evm2::EvmTypes>(&self, ctx: ReceiptBuilderCtx<N42TxType, evm2::TxResult<T>>) -> Self::Receipt {
        let ReceiptBuilderCtx { tx_type, result, cumulative_gas_used } = ctx;
        Receipt { tx_type, success: result.status, cumulative_gas_used, logs: result.logs }
    }
}

/// reth's [`EthBlockExecutor`] with the parallel step's bundle half
/// (`docs/RETH_2_9_0_UPGRADE.md`, F5c): a merge of the batches handed over
/// with [`Self::set_pending_fold`] is folded into the bundle `finish` returns
/// ([`crate::graft_fold::fold_into`]), before anything downstream (the hashed
/// post-state, the QMDB root, the assembler) reads it. Without a pending
/// fold it is the inner executor, method for method; it derefs to it, so the
/// inner executor's fields (`receipts`, `cumulative_gas_used`, `evm`) read
/// as before.
#[allow(missing_debug_implementations)]
pub struct N42BlockExecutor<'a, T: evm2::EvmTypes<Tx: alloy_eips::eip2718::Typed2718, TxResultExt: Send + Sync>> {
    inner: EthBlockExecutor<'a, T, &'a N42ReceiptBuilder>,
    pending_fold: Option<crate::graft_fold::MergedBatches>,
}

impl<'a, T: evm2::EvmTypes<Tx: alloy_eips::eip2718::Typed2718, TxResultExt: Send + Sync>> N42BlockExecutor<'a, T> {
    /// Wraps `inner` with no pending fold.
    pub const fn new(inner: EthBlockExecutor<'a, T, &'a N42ReceiptBuilder>) -> Self {
        Self { inner, pending_fold: None }
    }

    /// Hands over the batches' merge for `finish` to fold into the block's
    /// bundle. The caller has written its accounts into the EVM's overlay
    /// (the cache half) and committed the batches' receipts.
    pub fn set_pending_fold(&mut self, merged: crate::graft_fold::MergedBatches) {
        self.pending_fold = Some(merged);
    }

    /// Whether a fold is pending.
    pub const fn has_pending_fold(&self) -> bool {
        self.pending_fold.is_some()
    }

    fn fold(
        pending: Option<crate::graft_fold::MergedBatches>,
        state: &mut reth_trie::bundle_state::BundleState,
    ) -> Result<(), reth_evm::BlockExecutionError> {
        if let Some(merged) = pending {
            crate::graft_fold::fold_into(state, merged).map_err(reth_evm::BlockExecutionError::other)?;
        }
        Ok(())
    }
}

impl<'a, T: evm2::EvmTypes<Tx: alloy_eips::eip2718::Typed2718, TxResultExt: Send + Sync>> std::ops::Deref
    for N42BlockExecutor<'a, T>
{
    type Target = EthBlockExecutor<'a, T, &'a N42ReceiptBuilder>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, T: evm2::EvmTypes<Tx: alloy_eips::eip2718::Typed2718, TxResultExt: Send + Sync>> std::ops::DerefMut
    for N42BlockExecutor<'a, T>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'a, T: evm2::EvmTypes<Tx: alloy_eips::eip2718::Typed2718, TxResultExt: Send + Sync>> reth_evm::execute::BlockExecutor
    for N42BlockExecutor<'a, T>
{
    type Transaction = <EthBlockExecutor<'a, T, &'a N42ReceiptBuilder> as reth_evm::execute::BlockExecutor>::Transaction;
    type Receipt = <EthBlockExecutor<'a, T, &'a N42ReceiptBuilder> as reth_evm::execute::BlockExecutor>::Receipt;
    type Evm = <EthBlockExecutor<'a, T, &'a N42ReceiptBuilder> as reth_evm::execute::BlockExecutor>::Evm;
    type TransactionResultWithState =
        <EthBlockExecutor<'a, T, &'a N42ReceiptBuilder> as reth_evm::execute::BlockExecutor>::TransactionResultWithState;
    type BlockAccessList = <EthBlockExecutor<'a, T, &'a N42ReceiptBuilder> as reth_evm::execute::BlockExecutor>::BlockAccessList;

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }
    fn set_state_hook(&mut self, hook: impl FnMut(reth_evm::StateUpdate) + Send + 'static) -> bool {
        self.inner.set_state_hook(hook)
    }
    fn convert_block_access_list(
        block_access_list: &alloy_eip7928::BlockAccessList,
    ) -> Result<Self::BlockAccessList, reth_evm::BlockExecutionError> {
        <EthBlockExecutor<'a, T, &'a N42ReceiptBuilder> as reth_evm::execute::BlockExecutor>::convert_block_access_list(
            block_access_list,
        )
    }
    fn set_block_access_list(&mut self, block_access_list: Arc<Self::BlockAccessList>) {
        self.inner.set_block_access_list(block_access_list)
    }
    fn set_block_access_index(&mut self, index: alloy_eip7928::BlockAccessIndex) {
        self.inner.set_block_access_index(index)
    }
    fn enable_block_access_list_builder(&mut self) {
        self.inner.enable_block_access_list_builder()
    }
    fn take_block_access_list(&mut self) -> Option<alloy_eip7928::BlockAccessList> {
        self.inner.take_block_access_list()
    }
    fn apply_pre_execution_changes(&mut self) -> Result<(), reth_evm::BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }
    fn into_state(self) -> reth_trie::bundle_state::BundleState {
        let mut state = self.inner.into_state();
        if let Some(merged) = self.pending_fold {
            // A refusal here leaves the serial part's state, as a caller of
            // `into_state` (a partial execution) gets it without the batches.
            let _ = crate::graft_fold::fold_into(&mut state, merged);
        }
        state
    }
    fn validate_transaction_gas_limit(&mut self, gas_limit: u64) -> Result<(), reth_evm::BlockExecutionError> {
        self.inner.validate_transaction_gas_limit(gas_limit)
    }
    fn execute_transaction_with_commit_condition(
        &mut self,
        transaction: impl reth_evm::execute::ExecutorTx<Self>,
        f: impl FnOnce(&evm2::TxResult<T>) -> reth_evm::CommitChanges,
    ) -> Result<Option<reth_evm::GasOutput>, reth_evm::BlockExecutionError> {
        // The inner executor's own path (it commits without detaching).
        self.inner.execute_transaction_with_commit_condition(transaction, f)
    }
    fn execute_transaction_without_commit(
        &mut self,
        transaction: impl reth_evm::execute::ExecutorTx<Self>,
    ) -> Result<Self::TransactionResultWithState, reth_evm::BlockExecutionError> {
        self.inner.execute_transaction_without_commit(transaction)
    }
    fn commit_transaction(
        &mut self,
        output: Self::TransactionResultWithState,
    ) -> Result<reth_evm::GasOutput, reth_evm::BlockExecutionError> {
        self.inner.commit_transaction(output)
    }
    fn receipts(&self) -> &[Self::Receipt] {
        self.inner.receipts()
    }
    fn finish_with_block_access_list(
        self,
    ) -> Result<
        (reth_evm::BlockExecutionOutput<Self::Receipt>, Option<alloy_eip7928::BlockAccessList>),
        reth_evm::BlockExecutionError,
    > {
        let (mut output, bal) = self.inner.finish_with_block_access_list()?;
        Self::fold(self.pending_fold, &mut output.state)?;
        Ok((output, bal))
    }
    fn finish_with_prepared_block_access_list(
        self,
    ) -> Result<(reth_evm::BlockExecutionOutput<Self::Receipt>, Option<evm2::evm::Bal>), reth_evm::BlockExecutionError>
    {
        let (mut output, bal) = self.inner.finish_with_prepared_block_access_list()?;
        Self::fold(self.pending_fold, &mut output.state)?;
        Ok((output, bal))
    }
}

/// The block executor factory of [`N42EvmConfig`]: reth's
/// `EthBlockExecutorFactory` without its `Header = alloy Header` bound on the
/// chain spec (the executor reads only hardforks and the deposit contract
/// from it), over [`N42ReceiptBuilder`].
#[derive(Debug)]
pub struct N42BlockExecutorFactory<C = ChainSpec, F = RethEvmFactory> {
    receipt_builder: N42ReceiptBuilder,
    chain_spec: Arc<C>,
    evm_factory: F,
}

impl<C, F: Clone> Clone for N42BlockExecutorFactory<C, F> {
    fn clone(&self) -> Self {
        Self { receipt_builder: self.receipt_builder, chain_spec: self.chain_spec.clone(), evm_factory: self.evm_factory.clone() }
    }
}

impl<C, F> N42BlockExecutorFactory<C, F> {
    /// The factory for `chain_spec` with `evm_factory`.
    pub const fn new(chain_spec: Arc<C>, evm_factory: F) -> Self {
        Self { receipt_builder: N42ReceiptBuilder, chain_spec, evm_factory }
    }

    /// The chain spec.
    pub const fn spec(&self) -> &Arc<C> {
        &self.chain_spec
    }

    /// The receipt builder.
    pub const fn receipt_builder(&self) -> &N42ReceiptBuilder {
        &self.receipt_builder
    }
}

impl<C, F> reth_evm::BlockExecutorFactory for N42BlockExecutorFactory<C, F>
where
    C: EthChainSpec + EthereumHardforks,
    F: EvmFactory,
    <F::Types as evm2::EvmTypesHost>::Tx: alloy_eips::eip2718::Typed2718,
{
    type EvmFactory = F;
    type EvmTypes = F::Types;
    type Transaction = N42TxEnvelope;
    type Receipt = Receipt;
    type Evm<'a> = evm2::Evm<'a, F::Types>;
    type EvmEnv = EthEvmEnv<F::Types>;
    type ExecutionCtx<'a>
        = EthBlockExecutionCtx<'a>
    where
        Self: 'a;
    type Executor<'a>
        = N42BlockExecutor<'a, F::Types>
    where
        Self: 'a;

    fn create_executor<'a>(&'a self, evm: Self::Evm<'a>, ctx: Self::ExecutionCtx<'a>) -> Self::Executor<'a>
    where
        Self: 'a,
    {
        N42BlockExecutor::new(EthBlockExecutor::new(evm, ctx, self.chain_spec.as_ref(), &self.receipt_builder))
    }

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn evm_with_env<'a, DB>(&self, db: DB, env: Self::EvmEnv) -> Self::Evm<'a>
    where
        DB: evm2::evm::DynDatabase + 'a,
    {
        // reth's `EthBlockExecutorFactory::build_evm`, which is crate-private.
        let spec = env.spec;
        let config = self.evm_factory.execution_config(spec, env.version);
        let registry = self.evm_factory.tx_registry(spec);
        let precompiles = self.evm_factory.precompiles(spec);
        let mut evm =
            evm2::Evm::<F::Types>::new_with_execution_config(config, spec, env.block, registry, db, precompiles);
        self.evm_factory.configure_evm(&mut evm);
        evm
    }
}

/// Ethereum's EVM configuration with [`N42TxEnvelope`] as the transaction.
#[derive(Debug, Clone)]
pub struct N42EvmConfig<C = ChainSpec, EvmF = RethEvmFactory> {
    /// The executor factory.
    pub executor_factory: N42BlockExecutorFactory<C, EvmF>,
    /// The block assembler.
    pub block_assembler: N42HeaderAssembler<C>,
    /// Cache of recovered senders, when the node keeps one.
    pub sender_recovery_cache: Option<SenderRecoveryCache>,
    /// Whether the chain is a HotStuff chain, read from its genesis once.
    hotstuff: std::sync::OnceLock<bool>,
    /// From when blocks execute under the Amsterdam rules on this native
    /// chain (gov5's `glamsterdamTime`), read from its genesis once; `None`
    /// on a chain that never does ([`glamsterdam_execution_time`]).
    glamsterdam_execution: std::sync::OnceLock<Option<u64>>,
}

impl<C> N42EvmConfig<C> {
    /// The configuration for `chain_spec` on reth's evm2 factory.
    pub fn new(chain_spec: Arc<C>) -> Self {
        crate::legacy_paths::warn_unavailable_once();
        Self::new_with_evm_factory(chain_spec, RethEvmFactory::default())
    }
}

impl<C, EvmF> N42EvmConfig<C, EvmF> {
    /// Creates the configuration for `chain_spec` with `evm_factory`.
    pub fn new_with_evm_factory(chain_spec: Arc<C>, evm_factory: EvmF) -> Self {
        Self {
            block_assembler: N42HeaderAssembler::new(chain_spec.clone()),
            sender_recovery_cache: None,
            executor_factory: N42BlockExecutorFactory::new(chain_spec, evm_factory),
            hotstuff: std::sync::OnceLock::new(),
            glamsterdam_execution: std::sync::OnceLock::new(),
        }
    }

    /// The chain spec.
    pub const fn chain_spec(&self) -> &Arc<C> {
        self.executor_factory.spec()
    }

    /// The beneficiary an executed block credits: on an APoS chain the signer
    /// recovered from the header's Clique seal, the account the payload
    /// builder credits (`payload.rs`, its coinbase); anywhere else, or when
    /// no seal recovers, the header's beneficiary. An APoS header's
    /// beneficiary is the target of a signer vote (zero, or the proposed
    /// signer), never the fee recipient: executing with it credited the
    /// block's fees to that address while the builder, whose execution the
    /// QMDB forest keeps, had credited them to the signer.
    fn block_beneficiary(&self, header: &Header) -> Address
    where
        C: EthChainSpec,
    {
        if self.is_hotstuff() {
            return header.beneficiary;
        }
        match n42_clique_utils::recover_address(header) {
            Ok(signer) => signer,
            Err(err) => {
                // No seal at all is an Ethereum header (this config also runs
                // the spec tests and non-N42 chains): its beneficiary is the
                // fee recipient. A seal-sized extra data whose seal does not
                // recover is an APoS header consensus should have refused;
                // `evm_env` cannot fail (`Error = Infallible`), so the
                // fallback stays, but it is no longer silent: the fees go to
                // the header's beneficiary, not the signer the builder
                // credited, and the state root will say so.
                if header.extra_data.len() >= n42_clique_utils::SIGNATURE_LENGTH {
                    tracing::warn!(
                        target: "n42::evm",
                        number = header.number,
                        %err,
                        "the APoS seal does not recover; crediting the header's beneficiary"
                    );
                }
                header.beneficiary
            }
        }
    }

    fn is_hotstuff(&self) -> bool
    where
        C: EthChainSpec,
    {
        *self
            .hotstuff
            .get_or_init(|| n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(self.chain_spec().genesis()).is_ok())
    }

    /// Whether blocks are credited to their signer (an APoS chain).
    fn credits_signer(&self) -> bool
    where
        C: EthChainSpec,
    {
        !self.is_hotstuff()
    }

    /// Whether a block at `timestamp` executes under the Amsterdam rules
    /// although the chain spec does not schedule reth's Amsterdam: an
    /// N42-native chain past gov5's `glamsterdamTime`
    /// ([`reth_chainspec::qmdb::glamsterdam_execution_active_at`]).
    pub fn glamsterdam_execution_active_at(&self, timestamp: u64) -> bool
    where
        C: EthChainSpec,
    {
        self.glamsterdam_execution
            .get_or_init(|| glamsterdam_execution_time(self.chain_spec().genesis()))
            .is_some_and(|at| timestamp >= at)
    }

    /// The spec a block at `timestamp` / `number` executes under: the chain
    /// spec's, raised to [`SpecId::AMSTERDAM`] (evm2's Amsterdam version:
    /// its gas table, EIP-8037, EIP-2780, EIP-7708 and EIP-8246) for a block
    /// that executes under gov5's Amsterdam rules.
    pub fn spec_at(&self, timestamp: u64, number: u64) -> SpecId
    where
        C: EthChainSpec + EthereumHardforks,
    {
        let spec = spec_id_by_timestamp_and_block_number(self.chain_spec().as_ref(), timestamp, number);
        if self.glamsterdam_execution_active_at(timestamp) && !spec.enables(SpecId::AMSTERDAM) {
            SpecId::AMSTERDAM
        } else {
            spec
        }
    }

    /// Uses `cache` for sender recovery on import.
    pub fn with_sender_recovery_cache(mut self, cache: SenderRecoveryCache) -> Self {
        self.sender_recovery_cache = Some(cache);
        self
    }

    /// The environment for `spec` over `block`, as reth's
    /// `EthEvmConfig::evm_env_from_base_spec` makes it.
    fn env_for(&self, spec: SpecId, block: evm2::env::BlockEnv, blob_params: Option<BlobParams>) -> EthEvmEnv<EvmF::Types>
    where
        C: EthChainSpec,
        EvmF: EvmFactory,
    {
        let factory = &self.executor_factory.evm_factory;
        let mut version = factory.version(spec, self.chain_spec().chain().id());
        if let Some(blob_params) = blob_params {
            version.max_blobs_per_tx = blob_params.max_blobs_per_tx as usize;
        }
        EthEvmEnv::new_with_version(factory.spec_id(spec), factory.block_env(block), version)
    }
}

/// The block environment of `header` (reth's `block_env_with_blob_params`),
/// crediting `beneficiary`.
fn block_env_of(header: &Header, beneficiary: Address, blob_params: Option<BlobParams>) -> evm2::env::BlockEnv {
    BlockEnvExt {
        number: U256::from(header.number()),
        beneficiary,
        timestamp: U256::from(header.timestamp()),
        gas_limit: U256::from(header.gas_limit()),
        basefee: U256::from(header.base_fee_per_gas().unwrap_or_default()),
        difficulty: header.difficulty(),
        prevrandao: header.mix_hash().map(|hash| U256::from_be_bytes(hash.0)).unwrap_or_default(),
        blob_basefee: blob_basefee(header.excess_blob_gas(), blob_params),
        slot_num: U256::from(header.slot_number().unwrap_or_default()),
        ext: (),
        _non_exhaustive: (),
    }
}

fn blob_basefee(excess_blob_gas: Option<u64>, blob_params: Option<BlobParams>) -> U256 {
    excess_blob_gas
        .zip(blob_params)
        .map(|(excess_blob_gas, params)| U256::from(params.calc_blob_fee(excess_blob_gas)))
        .unwrap_or_default()
}

impl<C, EvmF> ConfigureEvm for N42EvmConfig<C, EvmF>
where
    C: EthChainSpec + EthereumHardforks + Hardforks + 'static,
    EvmF: EvmFactory,
    <EvmF::Types as evm2::EvmTypesHost>::Tx: alloy_eips::eip2718::Typed2718
        + reth_evm::FromTxWithEncoded<N42TxEnvelope>
        + reth_evm::TransactionEnvMut,
{
    type Primitives = N42Primitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = N42BlockExecutorFactory<C, EvmF>;
    type BlockAssembler = N42HeaderAssembler<C>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnvFor<Self>, Self::Error> {
        let spec = self.spec_at(header.timestamp, header.number);
        let blob_params = self.chain_spec().blob_params_at_timestamp(header.timestamp);
        let block = block_env_of(header, self.block_beneficiary(header), blob_params);
        Ok(self.env_for(spec, block, blob_params))
    }

    fn next_evm_env(&self, parent: &Header, attributes: &NextBlockEnvAttributes) -> Result<EvmEnvFor<Self>, Self::Error> {
        let base_fee = parent
            .next_block_base_fee(self.chain_spec().base_fee_params_at_timestamp(attributes.timestamp))
            .unwrap_or_default();
        let blob_params = self.chain_spec().blob_params_at_timestamp(attributes.timestamp);
        let number = parent.number.saturating_add(1);
        // EIP-7843: on a native chain the header's slot number is its block
        // number (`docs/HEADER_FIELD_PARITY.md` section 4), stamped after the
        // build; SLOTNUM in the build reads the same value the header, and so
        // every importer, will carry.
        let slot_number = match attributes.slot_number {
            Some(slot) => Some(slot),
            None if self.glamsterdam_execution_active_at(attributes.timestamp) => Some(number),
            None => None,
        };
        let header = Header::from(alloy_consensus::Header {
            beneficiary: attributes.suggested_fee_recipient,
            timestamp: attributes.timestamp,
            number,
            gas_limit: attributes.gas_limit,
            base_fee_per_gas: Some(base_fee),
            mix_hash: attributes.prev_randao,
            slot_number,
            excess_blob_gas: parent
                .maybe_next_block_excess_blob_gas(blob_params)
                .or_else(|| blob_params.map(|_| 0)),
            ..Default::default()
        });
        let spec = self.spec_at(header.timestamp, header.number);
        let block = block_env_of(&header, attributes.suggested_fee_recipient, blob_params);
        Ok(self.env_for(spec, block, blob_params))
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<n42_tx_types::Block>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error>
    where
        Self: 'a,
    {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(block.transaction_count()),
            parent_hash: block.header().parent_hash,
            parent_beacon_block_root: block.header().parent_beacon_block_root,
            // Ethereum's ommer rewards read alloy headers; no N42 chain has
            // ommers (APoS has no uncles, HotStuff refuses them in the body
            // check), so none are paid.
            ommers: &[],
            withdrawals: block.body().withdrawals.as_ref().map(|w| Cow::Borrowed(w.as_slice())),
            extra_data: block.header().extra_data.clone(),
            slot_number: block.header().slot_number,
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<Header>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: None,
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            ommers: &[],
            withdrawals: attributes.withdrawals.map(|w| Cow::Owned(w.into_inner())),
            extra_data: attributes.extra_data,
            slot_number: attributes.slot_number,
        })
    }
}

impl<C, EvmF> ConfigureEngineEvm<ExecutionData> for N42EvmConfig<C, EvmF>
where
    C: EthChainSpec + EthereumHardforks + Hardforks + 'static,
    EvmF: EvmFactory,
    <EvmF::Types as evm2::EvmTypesHost>::Tx: alloy_eips::eip2718::Typed2718
        + reth_evm::FromTxWithEncoded<N42TxEnvelope>
        + reth_evm::FromRecoveredTx<N42TxEnvelope>
        + reth_evm::TransactionEnvMut,
{
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        let timestamp = payload.payload.timestamp();
        let block_number = payload.payload.block_number();
        let spec = self.spec_at(timestamp, block_number);
        let blob_params = self.chain_spec().blob_params_at_timestamp(timestamp);

        // On an APoS chain the payload's fee recipient is a vote target: the
        // block credits its signer, recovered from the seal over the header
        // the payload rebuilds (raw transactions, no decode).
        let beneficiary = if self.credits_signer() {
            payload
                .payload
                .clone()
                .into_block_with_sidecar_raw(&payload.sidecar)
                .ok()
                .and_then(|block| n42_clique_utils::recover_address(&block.header).ok())
                .unwrap_or_else(|| payload.payload.fee_recipient())
        } else {
            payload.payload.fee_recipient()
        };
        let block = BlockEnvExt {
            number: U256::from(block_number),
            beneficiary,
            timestamp: U256::from(timestamp),
            gas_limit: U256::from(payload.payload.gas_limit()),
            basefee: U256::from(payload.payload.saturated_base_fee_per_gas()),
            difficulty: if spec >= SpecId::MERGE {
                U256::ZERO
            } else {
                U256::from_be_bytes(payload.payload.as_v1().prev_randao.0)
            },
            prevrandao: U256::from_be_bytes(payload.payload.as_v1().prev_randao.0),
            blob_basefee: blob_basefee(payload.payload.excess_blob_gas(), blob_params),
            slot_num: U256::from(payload.payload.as_v4().map(|v4| v4.slot_number).unwrap_or_default()),
            ext: (),
            _non_exhaustive: (),
        };
        Ok(self.env_for(spec, block, blob_params))
    }

    fn context_for_payload<'a>(&self, payload: &'a ExecutionData) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(payload.payload.transactions().len()),
            parent_hash: payload.parent_hash(),
            parent_beacon_block_root: payload.sidecar.parent_beacon_block_root(),
            ommers: &[],
            withdrawals: payload.payload.withdrawals().map(|w| Cow::Borrowed(w.as_slice())),
            extra_data: payload.payload.as_v1().extra_data.clone(),
            slot_number: payload.payload.as_v4().map(|v4| v4.slot_number),
        })
    }

    fn tx_iterator_for_payload(&self, payload: &ExecutionData) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let txs = payload.payload.transactions().clone();
        let sender_recovery_cache = self.sender_recovery_cache.clone();
        let convert = move |tx: Bytes| {
            let tx = TxTy::<Self::Primitives>::decode_2718_exact(tx.as_ref()).map_err(AnyError::new)?;
            let signer = match &tx {
                // Verified in a batch by whoever admitted it; a miss verifies once here.
                N42TxEnvelope::AltSig(alt) => {
                    let cache = AltSigSenderCache::global();
                    match cache.get(alt.hash()) {
                        Some(sender) => Ok(sender),
                        None => tx.try_recover().inspect(|sender| cache.insert(*alt.hash(), *sender)),
                    }
                }
                N42TxEnvelope::Eth(_) => {
                    if let Some(cache) = &sender_recovery_cache { cache.recover(&tx) } else { tx.try_recover() }
                }
            }
            .map_err(AnyError::new)?;
            Ok::<_, AnyError>(tx.with_signer(signer))
        };
        Ok((txs, convert))
    }
}

/// From when a chain with `genesis` executes under gov5's Amsterdam rules:
/// its `glamsterdamTime` on an N42-native chain, `None` otherwise (the time
/// [`reth_chainspec::qmdb::glamsterdam_execution_active_at`] compares with).
/// A chain spec that schedules reth's own Amsterdam already selects
/// [`SpecId::AMSTERDAM`] and is left as it is.
pub fn glamsterdam_execution_time(genesis: &alloy_genesis::Genesis) -> Option<u64> {
    if !reth_chainspec::qmdb::is_n42_native(genesis) {
        return None;
    }
    reth_chainspec::qmdb::glamsterdam_time(genesis)
}

/// The evm2 version gov5's Amsterdam execution runs on a native chain:
/// evm2's [`SpecId::AMSTERDAM`] defaults (its gas table, EIP-8037, EIP-2780,
/// EIP-7708, EIP-8246; `docs/GLAMSTERDAM_EXECUTION_PARITY.md`) on `chain_id`.
pub fn glamsterdam_execution_version(chain_id: u64) -> evm2::Version {
    let mut version = evm2::Version::new(SpecId::AMSTERDAM);
    version.chain_id = chain_id;
    version
}

#[cfg(test)]
mod glamsterdam_execution_tests {
    //! gov5 runs its Amsterdam state transition on a native chain from
    //! `glamsterdamTime` (`docs/GLAMSTERDAM_EXECUTION_PARITY.md`); the EVM
    //! configuration selects evm2's Amsterdam there and nowhere else.
    use super::*;
    use alloy_consensus::Transaction as _;
    use alloy_primitives::B256;
    use evm2::{
        bytecode::Bytecode,
        evm::{
            CacheDB, EmptyDB,
            AccountInfo,
        },
        EvmFeatures,
    };
    use reth_evm::{execute::Executor as _, EvmEnv as _};
    use reth_primitives_traits::{constants::MAX_TX_GAS_LIMIT_OSAKA, RecoveredBlock, SealedBlock};

    type Config = N42EvmConfig<n42_header::N42ChainSpec>;

    fn config_for(json: &str) -> Config {
        let genesis: alloy_genesis::Genesis = serde_json::from_str(json).expect("genesis");
        let spec = n42_header::N42ChainSpec::from(reth_chainspec::ChainSpec::from_genesis(genesis));
        N42EvmConfig::new(Arc::new(spec))
    }

    /// A Prague/Osaka chain 1143 with `extra` in its config.
    fn config_with(extra: &str) -> Config {
        config_for(&format!(
            r#"{{"config":{{"chainId":1143,"homesteadBlock":0,"eip150Block":0,"eip155Block":0,"eip158Block":0,"byzantiumBlock":0,"constantinopleBlock":0,"petersburgBlock":0,"istanbulBlock":0,"berlinBlock":0,"londonBlock":0,"mergeNetsplitBlock":0,"terminalTotalDifficulty":0,"terminalTotalDifficultyPassed":true,"shanghaiTime":0,"cancunTime":0,"pragueTime":0,"osakaTime":0{extra}}},"alloc":{{}}}}"#
        ))
    }

    fn header_at(timestamp: u64) -> Header {
        Header::from(alloy_consensus::Header { number: 5, timestamp, gas_limit: 30_000_000, base_fee_per_gas: Some(7), ..Default::default() })
    }

    fn next_at(timestamp: u64) -> NextBlockEnvAttributes {
        NextBlockEnvAttributes {
            timestamp,
            suggested_fee_recipient: Address::repeat_byte(0xcb),
            prev_randao: B256::ZERO,
            gas_limit: 30_000_000,
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals: None,
            extra_data: Default::default(),
            slot_number: None,
        }
    }

    #[test]
    fn a_native_chain_executes_amsterdam_from_its_glamsterdam_time() {
        let c = config_with(r#","consensus":"hotstuff","glamsterdamTime":100"#);
        let before = c.evm_env(&header_at(99)).expect("env");
        assert_eq!(before.spec, SpecId::OSAKA);
        assert!(!before.version.feature(EvmFeatures::EIP8037));
        let after = c.evm_env(&header_at(100)).expect("env");
        assert_eq!(after.spec, SpecId::AMSTERDAM);
        assert!(after.version.feature(EvmFeatures::EIP8037) && after.version.feature(EvmFeatures::EIP2780));
        assert!(after.version.feature(EvmFeatures::EIP7708) && after.version.feature(EvmFeatures::EIP8246));
        assert_eq!(after.version.features, glamsterdam_execution_version(1143).features);
        assert_eq!(after.chain_id(), 1143);
        // The EIP-7825 cap stays: under EIP-8037 it bounds the regular gas only.
        assert_eq!(after.version.tx_gas_limit_cap, MAX_TX_GAS_LIMIT_OSAKA);
        // The builder's environment follows, with SLOTNUM at the block number.
        let parent = header_at(99);
        let next = c.next_evm_env(&parent, &next_at(100)).expect("env");
        assert_eq!(next.spec, SpecId::AMSTERDAM);
        assert_eq!(next.block.slot_num, U256::from(6));
        let next = c.next_evm_env(&parent, &next_at(99)).expect("env");
        assert_eq!(next.spec, SpecId::OSAKA);
        assert_eq!(next.block.slot_num, U256::ZERO);
        // reth's own Amsterdam is not scheduled: the header and payload rules
        // that hang off it stay off.
        assert!(!c.chain_spec().is_amsterdam_active_at_timestamp(u64::MAX));
    }

    #[test]
    fn other_chains_keep_their_spec() {
        // A native chain without the fork, and a non-native chain with it.
        for extra in [r#","consensus":"hotstuff""#, r#","glamsterdamTime":0"#, ""] {
            let c = config_with(extra);
            for ts in [0, 100, u64::MAX / 2] {
                assert_eq!(c.evm_env(&header_at(ts)).expect("env").spec, SpecId::OSAKA, "{extra} at {ts}");
                let next = c.next_evm_env(&header_at(ts), &next_at(ts + 1)).expect("env");
                assert_eq!(next.spec, SpecId::OSAKA);
                assert_eq!(next.block.slot_num, U256::ZERO);
            }
        }
    }

    /// The ungated devnet executes exactly as reth's Ethereum configuration
    /// does: the environment is the one `EthEvmConfig::evm_env` makes, field
    /// for field (but the beneficiary, which an APoS block credits to its
    /// signer).
    #[test]
    fn the_ungated_devnet_environment_is_unchanged() {
        let c = config_for(include_str!("../../../chainspec/res/genesis/n42_devnet.json"));
        for ts in [0, 1_000, 1_798_761_600, u64::MAX / 2] {
            let header = header_at(ts);
            let got = c.evm_env(&header).expect("env");
            let eth = reth_evm_ethereum::EthEvmConfig::new(c.chain_spec().inner().clone());
            let mut want = eth.evm_env(&alloy_consensus::Header::from(header.clone())).expect("env");
            want.block.beneficiary = got.block.beneficiary;
            assert_eq!(got.spec, want.spec);
            assert_eq!(got.version.features, want.version.features);
            assert_eq!(got.version.tx_gas_limit_cap, want.version.tx_gas_limit_cap);
            assert_eq!(got.version.max_blobs_per_tx, want.version.max_blobs_per_tx);
            assert_eq!(got.version.chain_id, want.version.chain_id);
            assert_eq!(got.block, want.block);
            assert_eq!(got.spec, SpecId::OSAKA);
        }
    }

    /// gov5's fixture (`internal/glamsterdam_native_fixture_test.go` on gov5
    /// branch `test/glamsterdam-native-fixtures`): one block of the native
    /// chain's transaction shapes on the gated devnet genesis, executed by
    /// gov5. Receipts, gas, logs, the receipts root and the touched accounts
    /// must be the same here, by value.
    #[test]
    fn the_gated_devnet_block_matches_gov5() {
        let fx: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/glamsterdam_native/block1.json")).expect("fixture");
        let c = config_for(include_str!("../../../chainspec/res/genesis/n42_devnet_mobileanchor.json"));
        let u = |v: &serde_json::Value| v.as_u64().expect("a number");
        let s = |v: &serde_json::Value| v.as_str().expect("a string").to_string();
        let addr = |v: &serde_json::Value| s(v).parse::<Address>().expect("an address");
        let bytes = |v: &serde_json::Value| s(v).parse::<alloy_primitives::Bytes>().expect("hex bytes");

        let mut db = CacheDB::new(EmptyDB::default());
        // The genesis system contracts, which the block's pre- and
        // post-execution calls read (gov5's fixture skips them; they touch
        // nothing the fixture compares).
        for (address, account) in &c.chain_spec().genesis().alloc {
            let code = account.code.clone().unwrap_or_default();
            if code.is_empty() {
                continue;
            }
            db.insert_account_info(
                address,
                AccountInfo { balance: account.balance, nonce: account.nonce.unwrap_or(0), ..Default::default() }
                    .with_code(Bytecode::new_raw(code)),
            );
        }
        for account in fx["pre"].as_array().expect("pre") {
            let code = bytes(&account["code"]);
            let mut info = AccountInfo {
                balance: s(&account["balance"]).parse().expect("balance"),
                nonce: u(&account["nonce"]),
                ..Default::default()
            };
            if !code.is_empty() {
                info = info.with_code(Bytecode::new_raw(code));
            }
            db.insert_account_info(&addr(&account["address"]), info);
        }

        let txs: Vec<N42TxEnvelope> = fx["transactions"]
            .as_array()
            .expect("txs")
            .iter()
            .map(|raw| N42TxEnvelope::decode_2718_exact(&bytes(raw)).expect("a transaction"))
            .collect();
        let senders: Vec<Address> = txs.iter().map(|tx| tx.try_recover().expect("signed")).collect();
        let header = Header::from(alloy_consensus::Header {
            number: u(&fx["number"]),
            timestamp: u(&fx["timestamp"]),
            gas_limit: u(&fx["gasLimit"]),
            base_fee_per_gas: Some(u(&fx["baseFee"])),
            beneficiary: addr(&fx["coinbase"]),
            slot_number: Some(u(&fx["slotNumber"])),
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            ..Default::default()
        });
        assert!(c.glamsterdam_execution_active_at(header.timestamp));
        let body = n42_tx_types::BlockBody { transactions: txs.clone(), ommers: Vec::new(), withdrawals: Some(Vec::new().into()) };
        let block = SealedBlock::seal_slow(n42_tx_types::Block { header, body });
        let block = RecoveredBlock::new_sealed(block, senders);
        let out = c.executor(db).execute(&block).expect("the block executes");

        let receipts = fx["receipts"].as_array().expect("receipts");
        assert_eq!(out.result.receipts.len(), receipts.len());
        let mut previous = 0;
        for (i, (got, want)) in out.result.receipts.iter().zip(receipts).enumerate() {
            assert_eq!(got.success, u(&want["status"]) == 1, "tx {i} status");
            assert_eq!(got.cumulative_gas_used, u(&want["cumulativeGasUsed"]), "tx {i} cumulative gas");
            assert_eq!(got.cumulative_gas_used - previous, u(&want["gasUsed"]), "tx {i} gas used");
            previous = got.cumulative_gas_used;
            let logs = want["logs"].as_array().expect("logs");
            assert_eq!(got.logs.len(), logs.len(), "tx {i} log count");
            for (j, (log, want)) in got.logs.iter().zip(logs).enumerate() {
                assert_eq!(log.address, addr(&want["address"]), "tx {i} log {j} emitter");
                let topics: Vec<B256> =
                    want["topics"].as_array().expect("topics").iter().map(|t| s(t).parse().expect("topic")).collect();
                assert_eq!(log.topics(), topics.as_slice(), "tx {i} log {j} topics");
                assert_eq!(log.data.data, bytes(&want["data"]), "tx {i} log {j} data");
            }
        }
        assert_eq!(previous, u(&fx["receiptsCumulativeGasUsed"]));
        assert_eq!(out.result.gas_used, u(&fx["gasUsed"]), "the header's gas used (EIP-8037)");
        let (root, _) = crate::hotstuff_consensus::gov5_receipt_root_bloom(&out.result.receipts);
        assert_eq!(root, s(&fx["receiptsRoot"]).parse::<B256>().expect("root"), "the receipts root");

        for account in fx["post"].as_array().expect("post") {
            let address = addr(&account["address"]);
            let got = out.state.account(&address).and_then(|a| a.info.clone());
            if s(&account["balance"]) == "absent" {
                assert!(got.as_ref().is_none_or(|info| info.is_empty()), "{address} must not exist: {got:?}");
                continue;
            }
            // An account the block left as it was is not in the bundle: its
            // post-state is its pre-state.
            let info = got.unwrap_or_else(|| {
                let pre = fx["pre"]
                    .as_array()
                    .expect("pre")
                    .iter()
                    .find(|pre| addr(&pre["address"]) == address)
                    .unwrap_or_else(|| panic!("{address} is in the pre- or post-state"));
                let code = bytes(&pre["code"]);
                AccountInfo {
                    balance: s(&pre["balance"]).parse().expect("balance"),
                    nonce: u(&pre["nonce"]),
                    ..Default::default()
                }
                .with_code(Bytecode::new_raw(code))
            });
            assert_eq!(info.balance, s(&account["balance"]).parse::<U256>().expect("balance"), "{address} balance");
            assert_eq!(info.nonce, u(&account["nonce"]), "{address} nonce");
            let code = bytes(&account["code"]);
            // evm2's bundle keeps an account's code by hash in its contracts
            // (the info carries it only when the block deployed it).
            let got_code = info
                .code
                .clone()
                .or_else(|| (!info.is_empty_code_hash()).then(|| out.state.bytecode(&info.code_hash)).flatten())
                .map(|c| c.original_bytes())
                .unwrap_or_else(|| {
                    // Code the block did not touch: the pre-state's, when
                    // the account's code hash still names it.
                    fx["pre"]
                        .as_array()
                        .and_then(|pre| pre.iter().find(|pre| addr(&pre["address"]) == address))
                        .map(|pre| bytes(&pre["code"]))
                        .filter(|pre_code| alloy_primitives::keccak256(pre_code) == info.code_hash)
                        .unwrap_or_default()
                });
            assert_eq!(got_code, code, "{address} code");
            let slot0 = out.state.account(&address).and_then(|a| a.storage.get(&U256::ZERO)).map(|slot| slot.present_value);
            let want = account
                .get("storage")
                .and_then(|storage| storage.as_object())
                .and_then(|storage| storage.values().next())
                .map(|v| s(v).parse::<U256>().expect("slot"));
            assert_eq!(slot0.filter(|v| !v.is_zero()), want, "{address} slot 0");
        }
        // Every transaction's gas limit stayed inside the block's.
        assert!(txs.iter().map(|tx| tx.gas_limit()).sum::<u64>() <= block.header().gas_limit);
    }
}
