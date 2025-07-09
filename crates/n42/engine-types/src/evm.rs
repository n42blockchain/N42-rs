use alloy_consensus::{proofs, Block, BlockBody, BlockHeader, Header, Transaction, TxReceipt, EMPTY_OMMER_ROOT_HASH};
use alloy_evm::{block::{
    BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
    BlockExecutorFor, ExecutableTx, OnStateHook,
}, precompiles::PrecompilesMap, Database, EthEvm, EthEvmFactory, Evm, EvmEnv};
use reth_evm::{execute::{BlockAssembler, BlockAssemblerInput}, ConfigureEvm, InspectorFor, NextBlockEnvAttributes};
use revm::{
    context::{result::ExecutionResult, TxEnv},
    database::State,
};
use std::sync::Arc;
use alloy_eips::merge::BEACON_NONCE;
use alloy_evm::eth::{EthBlockExecutionCtx, EthBlockExecutor};
use alloy_primitives::{logs_bloom, Bytes};
use reth_ethereum_primitives::{TransactionSigned, Receipt as EthReceipt, Receipt};
use reth_evm_ethereum::{EthBlockAssembler, EthEvmConfig, RethReceiptBuilder};
use reth_primitives::SealedBlock;
use reth_revm::primitives::hardfork::SpecId;
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks, N42};
use reth_primitives_traits::{SealedHeader, TxTy};
use crate::node::N42Primitives;

pub struct N42BlockExecutor<'a, Evm> {
    /// Inner Ethereum execution strategy.
    inner: EthBlockExecutor<'a, Evm, Arc<ChainSpec>, RethReceiptBuilder>,
}

impl<'db, DB, E> BlockExecutor for N42BlockExecutor<'_, E>
where
    DB: Database + 'db,
    E: Evm<DB = &'db mut State<DB>, Tx = TxEnv>,
{
    type Transaction = TransactionSigned;
    type Receipt = EthReceipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_with_result_closure(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>),
    ) -> Result<u64, BlockExecutionError> {
        self.inner.execute_transaction_with_result_closure(tx, f)
    }

    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<EthReceipt>), BlockExecutionError> {
        // Invoke inner finish method to apply Ethereum post-execution changes
        self.inner.finish()
    }

    fn set_state_hook(&mut self, _hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(_hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
}

// todo copy from EthBlockAssembler
#[derive(Clone, Debug)]
pub struct N42BlockAssembler<ChainSpec = reth_chainspec::ChainSpec> {
    /// The chainspec.
    pub chain_spec: Arc<ChainSpec>,
    /// Extra data to use for the blocks.
    pub extra_data: Bytes,
}

impl<ChainSpec> N42BlockAssembler<ChainSpec> {
    /// Creates a new [`N42BlockAssembler`].
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec, extra_data: Default::default() }
    }
}

impl<F, ChainSpec> BlockAssembler<F> for N42BlockAssembler<ChainSpec>
where
    F: for<'a> BlockExecutorFactory<
        ExecutionCtx<'a> = N42BlockExecutionCtx<'a, TxTy<N42Primitives>>,
        Transaction = TransactionSigned,
        Receipt =  EthReceipt,
    >,
    ChainSpec: EthChainSpec + EthereumHardforks,
{
    // TODO: use custom block here
    type Block = Block<TransactionSigned>;

    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, F>,
    ) -> Result<Self::Block, BlockExecutionError> {
        let BlockAssemblerInput {
            evm_env,
            execution_ctx: ctx,
            parent,
            transactions,
            output: BlockExecutionResult { receipts, requests, gas_used },
            state_root,
            ..
        } = input;

        let timestamp = evm_env.block_env.timestamp;

        let transactions_root = proofs::calculate_transaction_root(&transactions);
        let receipts_root = Receipt::calculate_receipt_root_no_memo(receipts);
        let logs_bloom = logs_bloom(receipts.iter().flat_map(|r| r.logs()));

        let withdrawals = self
            .chain_spec
            .is_shanghai_active_at_timestamp(timestamp)
            .then(|| ctx.inner.withdrawals.map(|w| w.into_owned()).unwrap_or_default());

        let withdrawals_root =
            withdrawals.as_deref().map(|w| proofs::calculate_withdrawals_root(w));
        let requests_hash = self
            .chain_spec
            .is_prague_active_at_timestamp(timestamp)
            .then(|| requests.requests_hash());

        let mut excess_blob_gas = None;
        let mut blob_gas_used = None;

        // only determine cancun fields when active
        if self.chain_spec.is_cancun_active_at_timestamp(timestamp) {
            blob_gas_used =
                Some(transactions.iter().map(|tx| tx.blob_gas_used().unwrap_or_default()).sum());
            excess_blob_gas = if self.chain_spec.is_cancun_active_at_timestamp(parent.timestamp) {
                parent.maybe_next_block_excess_blob_gas(
                    self.chain_spec.blob_params_at_timestamp(timestamp),
                )
            } else {
                // for the first post-fork block, both parent.blob_gas_used and
                // parent.excess_blob_gas are evaluated as 0
                Some(alloy_eips::eip7840::BlobParams::cancun().next_block_excess_blob_gas(0, 0))
            };
        }

        let header = Header {
            parent_hash: ctx.inner.parent_hash,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: evm_env.block_env.beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root,
            logs_bloom,
            timestamp,
            mix_hash: evm_env.block_env.prevrandao.unwrap_or_default(),
            nonce: BEACON_NONCE.into(),
            base_fee_per_gas: Some(evm_env.block_env.basefee),
            number: evm_env.block_env.number,
            gas_limit: evm_env.block_env.gas_limit,
            difficulty: evm_env.block_env.difficulty,
            gas_used: *gas_used,
            extra_data: self.extra_data.clone(),
            parent_beacon_block_root: ctx.inner.parent_beacon_block_root,
            blob_gas_used,
            excess_blob_gas,
            requests_hash,
        };

        Ok(Block {
            header,
            body: BlockBody { transactions, ommers: Default::default(), withdrawals },
        })
    }
}

#[derive(Debug, Clone)]
pub struct N42EvmConfig {
    inner: EthEvmConfig,
    block_assembler: N42BlockAssembler,
}

impl N42EvmConfig {
    /// Creates a new N42 EVM configuration with the given chain spec.
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self::n42(chain_spec)
    }

    /// Creates a new N42 EVM configuration.
    pub fn n42(chain_spec: Arc<ChainSpec>) -> Self {
        Self::new_with_evm_factory(chain_spec)
    }

    /// Sets the extra data for the block assembler.
    pub fn with_extra_data(mut self, extra_data: Bytes) -> Self {
        self.block_assembler.extra_data = extra_data;
        self
    }
}
impl N42EvmConfig {
    /// Creates a new n42 EVM configuration with the given chain spec and EVM factory.
    pub fn new_with_evm_factory(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            inner: EthEvmConfig::new(chain_spec.clone()),
            block_assembler: N42BlockAssembler::new(chain_spec.clone()),
        }
    }
}

impl BlockExecutorFactory for N42EvmConfig {
    type EvmFactory = EthEvmFactory;
    type ExecutionCtx<'a> = N42BlockExecutionCtx<'a, TxTy<N42Primitives>>;
    type Transaction = TransactionSigned;
    type Receipt = EthReceipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EthEvm<&'a mut State<DB>, I, PrecompilesMap>,
        ctx: N42BlockExecutionCtx<TxTy<N42Primitives>>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: InspectorFor<Self, &'a mut State<DB>> + 'a,
    {
        N42BlockExecutor {
            inner: EthBlockExecutor::new(
                evm,
                ctx.inner,
                self.inner.chain_spec().clone(),
                *self.inner.executor_factory.receipt_builder(),
            ),
        }
    }
}

impl ConfigureEvm for N42EvmConfig {
    type Primitives = N42Primitives;
    type Error = <EthEvmConfig as ConfigureEvm>::Error;
    type NextBlockEnvCtx = <EthEvmConfig as ConfigureEvm>::NextBlockEnvCtx;
    type BlockExecutorFactory = Self;
    type BlockAssembler = N42BlockAssembler<ChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> EvmEnv<SpecId> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv<SpecId>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block<'a>(&self, block: &'a SealedBlock) -> N42BlockExecutionCtx<'a, TxTy<N42Primitives>> {
        N42BlockExecutionCtx{inner: self.inner.context_for_block(block), txs: Some(block.body().clone().transactions)}
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> N42BlockExecutionCtx<TxTy<N42Primitives>> {
        N42BlockExecutionCtx{inner:  self.inner.context_for_next_block(parent, attributes), txs: None}
    }
}

#[derive(Debug, Clone)]
pub struct N42BlockExecutionCtx<'a, T> {
    /// Parent block hash.
    pub inner: EthBlockExecutionCtx<'a>,
    ///
    pub txs: Option<Vec<T>>,
}
