use alloy_consensus::{Block, Header};
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
use alloy_evm::eth::{EthBlockExecutionCtx, EthBlockExecutor};
use alloy_primitives::Bytes;
use reth_ethereum_primitives::{TransactionSigned, Receipt as EthReceipt};
use reth_evm_ethereum::{EthBlockAssembler, EthEvmConfig, RethReceiptBuilder};
use reth_primitives::SealedBlock;
use reth_revm::primitives::hardfork::SpecId;
use reth_chainspec::{ChainSpec, N42};
use reth_primitives_traits::SealedHeader;
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

#[derive(Clone, Debug)]
pub struct N42BlockAssembler {
    inner: EthBlockAssembler<ChainSpec>,
}

impl N42BlockAssembler {
    /// Creates a new [`N42BlockAssembler`].
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { inner: EthBlockAssembler::new(chain_spec) }
    }
}

impl<F> BlockAssembler<F> for N42BlockAssembler
where
    F: for<'a> BlockExecutorFactory<
        ExecutionCtx<'a> = EthBlockExecutionCtx<'a>,
        Transaction = TransactionSigned,
        Receipt =  EthReceipt,
    >,
{
    // TODO: use custom block here
    type Block = Block<TransactionSigned>;

    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, F>,
    ) -> Result<Self::Block, BlockExecutionError> {
        let block = self.inner.assemble_block(input)?;

        Ok(block)
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
        self.block_assembler.inner.extra_data = extra_data;
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
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = TransactionSigned;
    type Receipt = EthReceipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EthEvm<&'a mut State<DB>, I, PrecompilesMap>,
        ctx: EthBlockExecutionCtx,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: InspectorFor<Self, &'a mut State<DB>> + 'a,
    {
        N42BlockExecutor {
            inner: EthBlockExecutor::new(
                evm,
                ctx,
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
    type BlockAssembler = N42BlockAssembler;

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

    fn context_for_block<'a>(&self, block: &'a SealedBlock) -> EthBlockExecutionCtx<'a> {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> EthBlockExecutionCtx {
        self.inner.context_for_next_block(parent, attributes)
    }
}
