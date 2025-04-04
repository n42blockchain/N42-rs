#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use std::sync::Arc;
use alloy_primitives::U256;
use alloy_consensus::EMPTY_OMMER_ROOT_HASH;

use reth_consensus::Consensus;

use reth_primitives::{
    proofs::{self},
    revm_primitives::{BlockEnv, CfgEnvWithHandlerCfg},
    Block, BlockBody, EthereumHardforks, Header, Receipt, Verifiers, Rewards
};

use reth_revm::primitives::calc_excess_blob_gas;
use reth_revm::{
    db::{states::bundle_state::BundleRetention, State},
    primitives::{EVMError, EnvWithHandlerCfg, InvalidTransaction, ResultAndState},
    {database::StateProviderDatabase},
    DatabaseCommit,
};

use reth_evm::{system_calls::SystemCaller, ConfigureEvm, ConfigureEvmEnv, NextBlockEnvAttributes};
use reth_evm_ethereum::{eip6110::parse_deposits_from_receipts, EthEvmConfig};
use reth_execution_types::ExecutionOutcome;

use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, TransactionPool,
    ValidPoolTransaction,
};
use reth_trie::HashedPostState;

use reth_chain_state::{CanonStateSubscriptions, ExecutedBlock};
use reth_chainspec::{ChainSpec, ChainSpecProvider};
use reth_errors::RethError;
use reth_node_api::FullNodeTypes;

use reth_payload_builder::{
    EthBuiltPayload, PayloadBuilderError, PayloadBuilderHandle,
    PayloadBuilderService,
};
use tracing::{debug, warn, trace};
use alloy_eips::{eip4844::MAX_DATA_GAS_PER_BLOCK, eip7685::Requests};
use reth_payload_primitives::{PayloadBuilderAttributes, PayloadTypes};
use n42_engine_primitives::{N42PayloadAttributes, N42PayloadBuilderAttributes};
use reth_node_builder::components::PayloadServiceBuilder;
use reth_node_builder::{BuilderContext, NodeTypesWithEngine, PayloadBuilderConfig};
use reth_provider::{StateProviderFactory, StateRootProvider};
use crate::job::N42PayloadJobGeneratorConfig;
use crate::job_generator::{commit_withdrawals, is_better_payload, N42BuildArguments, BuildOutcome, N42PayloadJobGenerator, PayloadBuilder, PayloadConfig, WithdrawalsOutcome};

type BestTransactionsIter<Pool> = Box<
    dyn BestTransactions<Item = Arc<ValidPoolTransaction<<Pool as TransactionPool>::Transaction>>>,
>;

/// The type responsible for building custom payloads
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct N42PayloadBuilder<EvmConfig = EthEvmConfig> {
    /// The type responsible for creating the evm.
    evm_config: EvmConfig,
}

impl<EvmConfig> N42PayloadBuilder<EvmConfig> {
    /// `N42PayloadBuilder` constructor.
    pub const fn new(evm_config: EvmConfig) -> Self {
        Self { evm_config }
    }
}


impl<EvmConfig> N42PayloadBuilder<EvmConfig>
where
    EvmConfig: ConfigureEvm<Header = Header>,
{
    /// Returns the configured [`CfgEnvWithHandlerCfg`] and [`BlockEnv`] for the targeted payload
    /// (that has the `parent` as its parent).
    fn cfg_and_block_env(
        &self,
        config: &PayloadConfig<N42PayloadBuilderAttributes>,
        parent: &Header,
    ) -> Result<(CfgEnvWithHandlerCfg, BlockEnv), EvmConfig::Error> {
        let next_attributes = NextBlockEnvAttributes {
            timestamp: config.attributes.timestamp(),
            suggested_fee_recipient: config.attributes.suggested_fee_recipient(),
            prev_randao: config.attributes.prev_randao(),
        };
        self.evm_config.next_cfg_and_block_env(parent, next_attributes)
    }

}

impl<Pool, Client, Cons> PayloadBuilder<Pool, Client, Cons> for N42PayloadBuilder
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec>,
    Pool: TransactionPool,
    Cons: Consensus,
{
    type Attributes = N42PayloadBuilderAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: N42BuildArguments<Pool, Client, Cons, Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {

        let (cfg_env, block_env) = self
            .cfg_and_block_env(&args.config, &args.config.parent_header)
            .map_err(PayloadBuilderError::other)?;

        let pool = args.pool.clone();
        default_n42_payload(self.evm_config.clone(), args, cfg_env, block_env, |attributes| {
            pool.best_transactions_with_attributes(attributes)
        })
    }

    fn build_empty_payload(
        &self,
        args: N42BuildArguments<Pool, Client, Cons, Self::Attributes, Self::BuiltPayload>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {

        let (cfg_env, block_env) = self
            .cfg_and_block_env(&args.config, &args.config.parent_header)
            .map_err(PayloadBuilderError::other)?;

        let pool = args.pool.clone();


        default_n42_payload(self.evm_config.clone(), args, cfg_env, block_env, |attributes| {
            pool.best_transactions_with_attributes(attributes)
        })?
            .into_payload()
            .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}



/// A custom payload service builder that supports the custom engine types
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct N42PayloadServiceBuilder;

impl<Types, Node, Pool, Cons> PayloadServiceBuilder<Node, Pool, Cons> for N42PayloadServiceBuilder
where
    Types: NodeTypesWithEngine<ChainSpec = ChainSpec>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool + Unpin + 'static,
    Cons: Consensus + Unpin + Clone + 'static,
    Types::Engine: PayloadTypes<
        BuiltPayload = EthBuiltPayload,
        PayloadAttributes = N42PayloadAttributes,
        PayloadBuilderAttributes = N42PayloadBuilderAttributes,
    >,
{
    async fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        consensus: Cons,
    ) -> eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypesWithEngine>::Engine>> {
        let payload_builder = N42PayloadBuilder::new(
            EthEvmConfig::new(ctx.chain_spec()),
        );
        let conf = ctx.payload_builder_config();

        let payload_job_config = N42PayloadJobGeneratorConfig::default()
            .interval(conf.interval())
            .deadline(conf.deadline())
            .max_payload_tasks(conf.max_payload_tasks())
            .extradata(conf.extradata_bytes());

        let payload_generator = N42PayloadJobGenerator::with_builder(
            ctx.provider().clone(),
            pool,
            consensus,
            ctx.task_executor().clone(),
            payload_job_config,
            payload_builder,
        );
        let (payload_service, payload_builder) =
            PayloadBuilderService::new(payload_generator, ctx.provider().canonical_state_stream());

        ctx.task_executor().spawn_critical("payload builder service", Box::pin(payload_service));

        Ok(payload_builder)
    }
}



/// Constructs an N42 transaction payload using the best transactions from the pool.
///
/// Given build arguments including an Ethereum client, transaction pool,
/// and configuration, this function creates a transaction payload. Returns
/// a result indicating success with the payload or an error in case of failure.
#[inline]
pub fn default_n42_payload<EvmConfig, Pool, Cons, Client, F>(
    evm_config: EvmConfig,
    args: N42BuildArguments<Pool, Client, Cons, N42PayloadBuilderAttributes, EthBuiltPayload>,
    initialized_cfg: CfgEnvWithHandlerCfg,
    initialized_block_env: BlockEnv,
    best_txs: F,
) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError>
where
    EvmConfig: ConfigureEvm<Header = Header>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec>,
    Pool: TransactionPool,
    Cons: reth_consensus::Consensus,
    F: FnOnce(BestTransactionsAttributes) -> BestTransactionsIter<Pool>,
{
    let N42BuildArguments {
        client,
        pool,
        consensus,
        mut cached_reads,
        config,
        cancel,
        best_payload, ..
    } = args;

    let chain_spec = client.chain_spec();
    let state_provider = client.state_by_block_hash(config.parent_header.hash())?;
    let state = StateProviderDatabase::new(state_provider);
    let mut db =
        State::builder().with_database(cached_reads.as_db_mut(state)).with_bundle_update().build();
    let PayloadConfig { parent_header, extra_data, attributes } = config;

    debug!(target: "payload_builder", id=%attributes.0.id, parent_header = ?parent_header.hash(), parent_number = parent_header.number, "building new payload");
    let mut cumulative_gas_used = 0;
    let mut sum_blob_gas_used = 0;
    let block_gas_limit: u64 = initialized_block_env.gas_limit.to::<u64>();
    let base_fee = initialized_block_env.basefee.to::<u64>();

    let mut executed_txs = Vec::new();
    let mut executed_senders = Vec::new();

    let mut best_txs = best_txs(BestTransactionsAttributes::new(
        base_fee,
        initialized_block_env.get_blob_gasprice().map(|gasprice| gasprice as u64),
    ));
    let mut total_fees = U256::ZERO;

    let block_number = initialized_block_env.number.to::<u64>();

    let mut system_caller = SystemCaller::new(evm_config.clone(), chain_spec.clone());

    // let mut header = Header::default();
    // prepare
    let mut header = consensus.prepare(&parent_header).map_err(|err| PayloadBuilderError::Internal(err.into()))?;

    // apply eip-4788 pre block contract call
    system_caller
        .pre_block_beacon_root_contract_call(
            &mut db,
            &initialized_cfg,
            &initialized_block_env,
            attributes.0.parent_beacon_block_root,
        )
        .map_err(|err| {
            warn!(target: "payload_builder",
                parent_hash=%parent_header.hash(),
                %err,
                "failed to apply beacon root contract call for payload"
            );
            PayloadBuilderError::Internal(err.into())
        })?;

    // apply eip-2935 blockhashes update
    system_caller.pre_block_blockhashes_contract_call(
        &mut db,
        &initialized_cfg,
        &initialized_block_env,
        parent_header.hash(),
    )
        .map_err(|err| {
            warn!(target: "payload_builder", parent_hash=%parent_header.hash(), %err, "failed to update parent header blockhashes for payload");
            PayloadBuilderError::Internal(err.into())
        })?;

    let mut receipts = Vec::new();
    while let Some(pool_tx) = best_txs.next() {
        // ensure we still have capacity for this transaction
        if cumulative_gas_used + pool_tx.gas_limit() > block_gas_limit {
            // we can't fit this transaction into the block, so we need to mark it as invalid
            // which also removes all dependent transaction from the iterator before we can
            // continue
            best_txs.mark_invalid(&pool_tx);
            continue
        }

        // check if the job was cancelled, if so we can exit early
        if cancel.is_cancelled() {
            return Ok(BuildOutcome::Cancelled)
        }

        // convert tx to a signed transaction
        let tx = pool_tx.to_recovered_transaction();

        // There's only limited amount of blob space available per block, so we need to check if
        // the EIP-4844 can still fit in the block
        if let Some(blob_tx) = tx.transaction.as_eip4844() {
            let tx_blob_gas = blob_tx.blob_gas();
            if sum_blob_gas_used + tx_blob_gas > MAX_DATA_GAS_PER_BLOCK {
                // we can't fit this _blob_ transaction into the block, so we mark it as
                // invalid, which removes its dependent transactions from
                // the iterator. This is similar to the gas limit condition
                // for regular transactions above.
                trace!(target: "payload_builder", tx=?tx.hash, ?sum_blob_gas_used, ?tx_blob_gas, "skipping blob transaction because it would exceed the max data gas per block");
                best_txs.mark_invalid(&pool_tx);
                continue
            }
        }

        let env = EnvWithHandlerCfg::new_with_cfg_env(
            initialized_cfg.clone(),
            initialized_block_env.clone(),
            evm_config.tx_env(tx.as_signed(), tx.signer()),
        );

        // Configure the environment for the block.
        let mut evm = evm_config.evm_with_env(&mut db, env);

        let ResultAndState { result, state } = match evm.transact() {
            Ok(res) => res,
            Err(err) => {
                match err {
                    EVMError::Transaction(err) => {
                        if matches!(err, InvalidTransaction::NonceTooLow { .. }) {
                            // if the nonce is too low, we can skip this transaction
                            trace!(target: "payload_builder", %err, ?tx, "skipping nonce too low transaction");
                        } else {
                            // if the transaction is invalid, we can skip it and all of its
                            // descendants
                            trace!(target: "payload_builder", %err, ?tx, "skipping invalid transaction and its descendants");
                            best_txs.mark_invalid(&pool_tx);
                        }

                        continue
                    }
                    err => {
                        // this is an error that we should treat as fatal for this attempt
                        return Err(PayloadBuilderError::EvmExecutionError(err))
                    }
                }
            }
        };
        // drop evm so db is released.
        drop(evm);
        // commit changes
        db.commit(state);

        // add to the total blob gas used if the transaction successfully executed
        if let Some(blob_tx) = tx.transaction.as_eip4844() {
            let tx_blob_gas = blob_tx.blob_gas();
            sum_blob_gas_used += tx_blob_gas;

            // if we've reached the max data gas per block, we can skip blob txs entirely
            if sum_blob_gas_used == MAX_DATA_GAS_PER_BLOCK {
                best_txs.skip_blobs();
            }
        }

        let gas_used = result.gas_used();

        // add gas used by the transaction to cumulative gas used, before creating the receipt
        cumulative_gas_used += gas_used;

        // Push transaction changeset and calculate header bloom filter for receipt.
        #[allow(clippy::needless_update)] // side-effect of optimism fields
        receipts.push(Some(Receipt {
            tx_type: tx.tx_type(),
            success: result.is_success(),
            cumulative_gas_used,
            logs: result.into_logs().into_iter().map(Into::into).collect(),
            ..Default::default()
        }));

        // update add to total fees
        let miner_fee = tx
            .effective_tip_per_gas(Some(base_fee))
            .expect("fee is always valid; execution succeeded");
        total_fees += U256::from(miner_fee) * U256::from(gas_used);

        // append sender and transaction to the respective lists
        executed_senders.push(tx.signer());
        executed_txs.push(tx.into_signed());
    }

    // check if we have a better block
    if !is_better_payload(best_payload.as_ref(), total_fees) {
        // can skip building the block
        return Ok(BuildOutcome::Aborted { fees: total_fees, cached_reads })
    }

    // calculate the requests and the requests root
    let requests = if chain_spec.is_prague_active_at_timestamp(attributes.0.timestamp) {
        let deposit_requests = parse_deposits_from_receipts(&chain_spec, receipts.iter().flatten())
            .map_err(|err| PayloadBuilderError::Internal(RethError::Execution(err.into())))?;
        let withdrawal_requests = system_caller
            .post_block_withdrawal_requests_contract_call(
                &mut db,
                &initialized_cfg,
                &initialized_block_env,
            )
            .map_err(|err| PayloadBuilderError::Internal(err.into()))?;
        let consolidation_requests = system_caller
            .post_block_consolidation_requests_contract_call(
                &mut db,
                &initialized_cfg,
                &initialized_block_env,
            )
            .map_err(|err| PayloadBuilderError::Internal(err.into()))?;

        Some(Requests::new(vec![deposit_requests, withdrawal_requests, consolidation_requests]))
    } else {
        None
    };

    let WithdrawalsOutcome { withdrawals_root, withdrawals } =
        commit_withdrawals(&mut db, &chain_spec, attributes.0.timestamp, attributes.0.withdrawals)?;

    // merge all transitions into bundle state, this would apply the withdrawal balance changes
    // and 4788 contract call
    db.merge_transitions(BundleRetention::Reverts);

    let requests_hash = requests.as_ref().map(|requests| requests.requests_hash());
    let execution_outcome = ExecutionOutcome::new(
        db.take_bundle(),
        vec![receipts].into(),
        block_number,
        vec![requests.clone().unwrap_or_default()],
    );
    let receipts_root =
        execution_outcome.receipts_root_slow(block_number).expect("Number is in range");
    let logs_bloom = execution_outcome.block_logs_bloom(block_number).expect("Number is in range");

    // calculate the state root
    let hashed_state = HashedPostState::from_bundle_state(&execution_outcome.state().state);
    let (state_root, trie_output) = {
        db.database.inner().state_root_with_updates(hashed_state.clone()).inspect_err(|err| {
            warn!(target: "payload_builder",
                parent_hash=%parent_header.hash(),
                %err,
                "failed to calculate state root for payload"
            );
        })?
    };

    // create the block header
    let transactions_root = proofs::calculate_transaction_root(&executed_txs);

    // initialize empty blob sidecars at first. If cancun is active then this will
    let mut blob_sidecars = Vec::new();
    let mut excess_blob_gas = None;
    let mut blob_gas_used = None;

    // only determine cancun fields when active
    if chain_spec.is_cancun_active_at_timestamp(attributes.0.timestamp) {
        // grab the blob sidecars from the executed txs
        blob_sidecars = pool.get_all_blobs_exact(
            executed_txs.iter().filter(|tx| tx.is_eip4844()).map(|tx| tx.hash).collect(),
        )?;

        excess_blob_gas = if chain_spec.is_cancun_active_at_timestamp(parent_header.timestamp) {
            let parent_excess_blob_gas = parent_header.excess_blob_gas.unwrap_or_default();
            let parent_blob_gas_used = parent_header.blob_gas_used.unwrap_or_default();
            Some(calc_excess_blob_gas(parent_excess_blob_gas, parent_blob_gas_used))
        } else {
            // for the first post-fork block, both parent.blob_gas_used and
            // parent.excess_blob_gas are evaluated as 0
            Some(calc_excess_blob_gas(0, 0))
        };

        blob_gas_used = Some(sum_blob_gas_used);
    }

    header.parent_hash = parent_header.hash();
    header.ommers_hash = EMPTY_OMMER_ROOT_HASH;
    header.timestamp = attributes.0.timestamp;
    // header.beneficiary = initialized_block_env.coinbase;
    // header.number = parent_header.number + 1;
    header.gas_limit = block_gas_limit;
    // header.difficulty = U256::ZERO;
    // header.extra_data = extra_data;
    // roots
    header.state_root = state_root;
    header.transactions_root = transactions_root;
    header.receipts_root = receipts_root;
    header.withdrawals_root = withdrawals_root;
    header.logs_bloom = logs_bloom;
    header.requests_hash = requests_hash;
    // header.timestamp = attributes.0.timestamp;
    header.mix_hash = attributes.0.prev_randao;
    // header.nonce = BEACON_NONCE.into();
    header.base_fee_per_gas = Some(base_fee);
    //
    header.parent_beacon_block_root = attributes.0.parent_beacon_block_root;
    header.blob_gas_used = blob_gas_used.map(Into::into);
    header.excess_blob_gas = excess_blob_gas.map(Into::into);
    //

    // seal
    consensus.seal(&mut header).map_err(|err| PayloadBuilderError::Internal(err.into()))?;

    // ly Simple generation.
    let verifiers=Some(Verifiers::default());
    let rewards=Some(Rewards::default());
    // seal the block
    let block = Block {
        header,
        body: BlockBody { transactions: executed_txs, ommers: vec![], withdrawals, verifiers,rewards},
    };

    let sealed_block = block.seal_slow();
    debug!(target: "payload_builder", ?sealed_block, "sealed built block");

    // create the executed block data
    let executed = ExecutedBlock {
        block: Arc::new(sealed_block.clone()),
        senders: Arc::new(executed_senders),
        execution_output: Arc::new(execution_outcome),
        hashed_state: Arc::new(hashed_state),
        trie: Arc::new(trie_output),
    };

    let mut payload =
        EthBuiltPayload::new(attributes.0.id, sealed_block, total_fees, Some(executed), requests);

    // extend the payload with the blob sidecars from the executed txs
    payload.extend_sidecars(blob_sidecars.into_iter().map(Arc::unwrap_or_clone));

    Ok(BuildOutcome::Better { payload, cached_reads })
}
