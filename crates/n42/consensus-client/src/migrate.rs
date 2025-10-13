use alloy_eips::eip2718::Decodable2718;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::Block;
use alloy_rpc_types::BlockTransactionsKind;
use alloy_rpc_types::Transaction as RpcTransaction;
use alloy_rpc_types_engine::{CancunPayloadFields, ExecutionPayloadSidecar, ForkchoiceState};
use eyre::OptionExt;
use n42_engine_primitives::PayloadAttributesBuilderExt;
use reth_chainspec::EthereumHardforks;
use reth_engine_primitives::BeaconConsensusEngineHandle;
use reth_engine_primitives::EngineTypes;
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use reth_payload_primitives::{
    BuiltPayload, EngineApiMessageVersion, PayloadAttributesBuilder, PayloadKind, PayloadTypes,
};
use reth_primitives::{PooledTransaction, Recovered, SealedBlock, TransactionSigned};
use reth_primitives_traits::{AlloyBlockHeader, BlockBody, NodePrimitives, SignedTransaction};
use reth_provider::{
    BeaconProvider, BeaconProviderWriter, BlockIdReader, BlockReader, ChainSpecProvider,
};
use reth_transaction_pool::PoolTransaction;
use reth_transaction_pool::{TransactionOrigin, TransactionPool};
use sled::{Db, IVec};
use tokio::time::{interval_at, sleep, Instant, Interval};
use tracing::{debug, error, info, warn};

pub struct N42Migrate<T: PayloadTypes, Provider, B, Pool: TransactionPool> {
    provider: Provider,
    /// The payload attribute builder for the engine
    payload_attributes_builder: B,
    /// beacon engine handle
    beacon_engine_handle: BeaconConsensusEngineHandle<T>,
    /// The payload builder for the engine
    payload_builder: PayloadBuilderHandle<T>,
    pool: Pool,
    migrate_from_db_path: Option<String>,
    migrage_from_rpc: Option<String>,
}

impl<T, Provider, B, Pool> N42Migrate<T, Provider, B, Pool>
where
    T: PayloadTypes,
    <T::BuiltPayload as BuiltPayload>::Primitives:
        NodePrimitives<Block = reth_ethereum_primitives::Block>,
    Provider: BlockReader
        + BlockIdReader
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + BeaconProvider
        + BeaconProviderWriter
        + 'static
        + Clone,
    B: PayloadAttributesBuilderExt<<T as PayloadTypes>::PayloadAttributes>,
    Pool: TransactionPool + 'static,
    Recovered<<<Pool as TransactionPool>::Transaction as PoolTransaction>::Pooled>:
        From<Recovered<alloy_consensus::EthereumTxEnvelope<alloy_consensus::TxEip4844WithSidecar>>>,
{
    pub fn spawn_new(
        provider: Provider,
        payload_attributes_builder: B,
        beacon_engine_handle: BeaconConsensusEngineHandle<T>,
        payload_builder: PayloadBuilderHandle<T>,
        pool: Pool,
        migrate_from_db_path: Option<String>,
        migrage_from_rpc: Option<String>,
    ) {
        let migrate = Self {
            provider,
            payload_attributes_builder,
            beacon_engine_handle,
            payload_builder,
            pool,
            migrate_from_db_path,
            migrage_from_rpc,
        };
        tokio::spawn(migrate.run());
    }

    async fn run(mut self) -> eyre::Result<()> {
        match self.run_inner().await {
            Ok(v) => {
                info!(target: "consensus-client", ?v, "run ok");
            }
            Err(err) => {
                info!(target: "consensus-client", ?err, "run error");
            }
        }
        Ok(())
    }

    async fn run_inner(mut self) -> eyre::Result<()> {
        let db: Option<Db> = if self.migrate_from_db_path.is_some() {
            Some(sled::open(&self.migrate_from_db_path.clone().unwrap())?)
        } else {
            None
        };
        let rpc_provider = if self.migrage_from_rpc.is_some() {
            let rpc_url = self.migrage_from_rpc.clone().unwrap().parse()?;
            Some(ProviderBuilder::new().on_http(rpc_url))
        } else {
            None
        };

        let header = self
            .provider
            .sealed_header(self.provider.best_block_number().unwrap())
            .unwrap()
            .unwrap();
        let mut timestamp = header.timestamp();
        let mut block_number = self.provider.best_block_number().unwrap();
        let mut start = std::time::Instant::now();
        loop {
            if block_number % 100 == 0 {
                let duration = start.elapsed();
                debug!(target: "consensus-client", ?duration, "blocks generation time");
                start = std::time::Instant::now();
            }
            block_number += 1;
            debug!(target: "consensus-client", ?block_number, "before reading from database");
            let mut block = if db.is_some() {
                let value = db.as_ref().unwrap().get(block_number.to_be_bytes())?;
                if value.is_some() {
                    Some(serde_json::from_slice(&value.unwrap())?)
                } else {
                    None
                }
            } else {
                None
            };
            if block.is_none() {
                if rpc_provider.is_some() {
                    match rpc_provider
                        .as_ref()
                        .unwrap()
                        .get_block(block_number.into())
                        .await?
                    {
                        Some(v) => block = Some(v),
                        _ => {
                            eyre::bail!("block {:?} not found, stop", block_number);
                        }
                    }
                } else {
                    eyre::bail!("block {:?} not found, stop", block_number);
                }
            }
            let block = block.unwrap();
            if timestamp < block.header.timestamp {
                timestamp = block.header.timestamp;
            } else {
                timestamp += 8;
            }
            debug!(target: "consensus-client", ?block, "block of input");
            let transactions = block.transactions.into_transactions();
            let mut txs = transactions
                .into_iter()
                .map(|rpc_tx: RpcTransaction| {
                    debug!(target: "consensus-client", ?rpc_tx);

                    let tx_signed: TransactionSigned = rpc_tx.try_into().unwrap();
                    let pooled_transaction: PooledTransaction = tx_signed.try_into().unwrap();

                    let recovered = pooled_transaction.try_into_recovered().unwrap();
                    Pool::Transaction::from_pooled(recovered.try_into().unwrap())
                })
                .collect::<Vec<_>>();

            if block.header.number == 1131832 {
                let tx = {
                    let raw_tx = "0xf86e01843b9aca07825208940baefc7ff20fe19f8f3e822148f371c179d65fac890ad78ebc5ac620000080820910a05614f3d927ba547f5cc0c07da583d073f163dcfa5e3c17123ed1e10edba6cdc6a04a60889f37290f34a6284cffae0b54a89327878640e03846c0caf30d8bb52b63";
                    let raw_tx = raw_tx.strip_prefix("0x").unwrap();
                    let raw_bytes = hex::decode(raw_tx).unwrap();
                    let tx_signed: TransactionSigned =
                        TransactionSigned::fallback_decode(&mut &raw_bytes[..]).unwrap();

                    let pooled_transaction: PooledTransaction = tx_signed.try_into().unwrap();
                    let recovered = pooled_transaction.try_into_recovered().unwrap();
                    Pool::Transaction::from_pooled(recovered.into())
                };

                txs.push(tx);
            }

            let num_input_txs = txs.len();

            let results = self.pool.add_external_transactions(txs).await;
            debug!(target: "consensus-client", ?results, "add_external_transactions");
            if results.into_iter().any(|res| res.is_err()) {
                error!("add_external_transactions did not succeed for some transactions");
                eyre::bail!("add_external_transactions did not succeed for some transactions");
            }

            let pool_size = self.pool.pool_size();
            debug!(target: "consensus-client", ?pool_size, "add_external_transactions");

            debug!(target: "consensus-client", "before first fcu");
            let header = self
                .provider
                .sealed_header(self.provider.best_block_number().unwrap())
                .unwrap()
                .unwrap();
            let forkchoice_state = ForkchoiceState {
                head_block_hash: header.hash(),
                safe_block_hash: header.hash(),
                finalized_block_hash: header.hash(),
            };
            let res = self
                .beacon_engine_handle
                .fork_choice_updated(
                    forkchoice_state,
                    Some(self.payload_attributes_builder.build(timestamp)),
                    EngineApiMessageVersion::default(),
                )
                .await;
            debug!(target: "consensus-client", ?res, "after first fcu");
            let res = res?;
            if !res.payload_status.is_valid() {
                eyre::bail!("Error advancing the chain: fork_choice_updated with PayloadAttributes status is not valid: {:?}", res);
            }
            let payload_id = res.payload_id.ok_or_eyre("No payload id")?;
            info!(target: "consensus-client", ?payload_id);

            let payload = match self
                .payload_builder
                .resolve_kind(payload_id, PayloadKind::WaitForPending)
                .await
            {
                Some(Ok(payload)) => payload,
                Some(Err(err)) => {
                    eyre::bail!("Failed to resolve payload: {}", err);
                }
                None => {
                    eyre::bail!("No payload");
                }
            };
            debug!(target: "consensus-client", ?payload);
            let block = payload.block();
            if block.body().transactions.len() != num_input_txs {
                error!(target: "consensus-client", "new block transactions number does not match with old block transactions number at block {:?}, expected {:?}, got {:?}, stop", block.header().number, num_input_txs, block.body().transactions.len());
                eyre::bail!("new block transactions number does not match with old block transactions number at block {:?}, stop", block.header().number);
            }

            self.new_payload(block).await?;
            //sleep(std::time::Duration::from_millis(1)).await;

            debug!(target: "consensus-client", ?block, "payload block");
            let forkchoice_state = ForkchoiceState {
                head_block_hash: block.hash(),
                safe_block_hash: header.hash(),
                finalized_block_hash: header.hash(),
            };
            match self
                .beacon_engine_handle
                .fork_choice_updated(forkchoice_state, None, EngineApiMessageVersion::default())
                .await
            {
                Ok(v) => {
                    info!(target: "consensus-client", "forkchoice(block hash) status {:?}", v);
                }
                Err(e) => {
                    eyre::bail!("Error updating fork choice(block hash): {:?}", e);
                }
            };

            let pool_size = self.pool.pool_size();
            debug!(target: "consensus-client", ?pool_size, "after final fcu");
        }
    }

    async fn new_payload(
        &mut self,
        block: &SealedBlock<
            <<T::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
    ) -> eyre::Result<()> {
        debug!(target: "consensus-client", "new_block hash {:?}", block.header().hash_slow());

        let cancun_fields = self
            .provider
            .chain_spec()
            .is_cancun_active_at_timestamp(block.timestamp())
            .then(|| CancunPayloadFields {
                parent_beacon_block_root: block.parent_beacon_block_root().unwrap(),
                versioned_hashes: block.blob_versioned_hashes_iter().copied().collect(),
            });

        let execution_data = T::block_to_payload(block.clone());
        let res = self
            .beacon_engine_handle
            .new_payload(execution_data)
            .await?;
        debug!(target: "consensus-client", "new_payload res={:?}", res);
        if res.is_invalid() {
            eyre::bail!("new block is invalid: {}", res);
        }
        if res.is_syncing() {
            warn!(target: "consensus-client", "if all blocks are available, should not get syncing, new_payload res={:?}", res);
        }
        Ok(())
    }
}
