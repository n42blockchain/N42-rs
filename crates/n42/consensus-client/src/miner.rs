//! Contains the implementation of the mining mode for the local engine.

use alloy_eips::{
    eip7685::Requests,
};
use blst::min_pk::{AggregateSignature, Signature};
use blst::min_pk::PublicKey;
use alloy_primitives::FixedBytes;
use n42_clique::{BlockVerifyResult, UnverifiedBlock};
use reth_storage_errors::provider::ProviderResult;
use n42_engine_primitives::{PayloadAttributesBuilderExt};
use std::str::FromStr;
use alloy_consensus::TxReceipt;
use alloy_primitives::{Sealable, BlockNumber, Bytes};
use reth_network_api::{FullNetwork, BlockDownloaderProvider, BlockAnnounceProvider, NetworkEventListenerProvider};
use reth_ethereum_primitives::{EthPrimitives};
use reth_primitives::TransactionSigned;
use reth_primitives_traits::{AlloyBlockHeader, NodePrimitives, BlockBody};
use alloy_eips::{BlockHashOrNumber, BlockNumHash};
use alloy_primitives::{keccak256, Address, BlockHash, TxHash, B256, U128, U256};
use alloy_rpc_types_engine::{CancunPayloadFields, ExecutionPayloadSidecar, ForkchoiceState};
use eyre::OptionExt;
use futures_util::{stream::Fuse, StreamExt};
use itertools::Itertools;
use reth_engine_primitives::BeaconConsensusEngineHandle;
use reth_chainspec::EthereumHardforks;
use reth_chainspec::EthChainSpec;
use reth_consensus::{FullConsensus, ConsensusError};
use reth_payload_primitives::{EngineApiMessageVersion};
use reth_eth_wire_types::{NewBlock, NetworkPrimitives};
use reth_network_p2p::{
    bodies::client::BodiesClient, headers::client::HeadersClient, priority::Priority,
    BlockClient,
};
use reth_payload_builder::PayloadBuilderHandle;
use reth_payload_primitives::{
    BuiltPayload, PayloadAttributesBuilder, PayloadKind, PayloadTypes,
};
use reth_primitives::{Block, Header, SealedBlock};
use reth_primitives_traits::{Block as BlockTrait, header::clique_utils::{recover_address, recover_address_generic}};
use reth_provider::{BlockIdReader, BlockReader, ChainSpecProvider, BeaconProvider, BeaconProviderWriter};
use reth_transaction_pool::TransactionPool;
use std::collections::{HashMap};
use std::sync::Arc;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, UNIX_EPOCH},
};
use tokio::sync::{mpsc, broadcast};
use tokio::time::{interval_at, sleep, Instant, Interval};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{trace, debug, error, info, warn};

use crate::beacon::{Beacon};
use n42_primitives::{RelativeEpoch, Attestation, BeaconState, BeaconBlock, Deposit, VoluntaryExitWithSig, parse_deposit_log, BLSPubkey, BlockVerifyResultAggregate, agg_sig_to_fixed, fixed_to_agg_sig, SLOTS_PER_EPOCH, CommitteeIndex, AttestationData};
use crate::network::{fetch_beacon_block, broadcast_beacon_block};

/// A mining mode for the local dev engine.
#[derive(Debug)]
pub enum MiningMode {
    /// In this mode a block is built as soon as
    /// a valid transaction reaches the pool.
    Instant(Fuse<ReceiverStream<TxHash>>),
    /// In this mode a block is built at a fixed interval.
    Interval(Interval),
    /// In this mode no block is built by the node.
    NoMining,
}

impl MiningMode {
    /// Constructor for a [`MiningMode::Instant`]
    pub fn instant<Pool: TransactionPool>(pool: Pool) -> Self {
        let rx = pool.pending_transactions_listener();
        Self::Instant(ReceiverStream::new(rx).fuse())
    }

    /// Constructor for a [`MiningMode::Interval`]
    pub fn interval(duration: Duration) -> Self {
        let start = tokio::time::Instant::now() + duration;
        Self::Interval(tokio::time::interval_at(start, duration))
    }
}

impl Future for MiningMode {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this {
            Self::Instant(rx) => {
                // drain all transactions notifications
                if let Poll::Ready(Some(_)) = rx.poll_next_unpin(cx) {
                    return Poll::Ready(());
                }
                Poll::Pending
            }
            Self::Interval(interval) => {
                if interval.poll_tick(cx).is_ready() {
                    return Poll::Ready(());
                }
                Poll::Pending
            }
            Self::NoMining => Poll::Pending,
        }
    }
}

/// Local miner advancing the chain/
#[derive(Debug)]
pub struct N42Miner<T: PayloadTypes, Provider, B, Network> {
    /// Provider to read the current tip of the chain.
    provider: Provider,
    /// The payload attribute builder for the engine
    payload_attributes_builder: B,

    /// beacon engine handle
    beacon_engine_handle: BeaconConsensusEngineHandle<T>,
    /// The mining mode for the engine
    mode: MiningMode,
    /// The timer for preparing block
    interval_prepare_block: Interval,
    /// The payload builder for the engine
    payload_builder: PayloadBuilderHandle<T>,
    /// full network  for announce block
    network: Network,
    consensus: Arc<dyn FullConsensus<<T::BuiltPayload as BuiltPayload>::Primitives, Error = ConsensusError>>,
    recent_blocks: schnellru::LruMap<B256, SealedBlock<<<T::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block>>,
    recent_num_to_td: schnellru::LruMap<u64, U256>,
    new_block_tx: mpsc::Sender<(NewBlock, BlockHash)>,
    new_block_rx: mpsc::Receiver<(NewBlock, BlockHash)>,
    beacon: Beacon<Provider>,
    broadcast_unverified_block_tx: broadcast::Sender<(UnverifiedBlock, Arc<Vec<BLSPubkey>>)>,
    block_verify_result_rx: mpsc::Receiver<BlockVerifyResult>,
    pending_block_data: Option<PendingBlockData>,

    num_generated_blocks: u64,
    num_skipped_new_block: u64,
    num_should_skip_block_generation: u64,
    num_long_delayed_blocks: u64,
    num_fetched_blocks: u64,
    order_stats: HashMap<u64, bool>,
}

#[derive(Debug, Clone)]
struct PendingBlockData {
    block: SealedBlock,
    beacon_state_after_withdrawal: BeaconState,
    execution_requests: Option<Requests>,
    attestations: HashMap<CommitteeIndex, Attestation>,
}

const DEPOSIT_GAP: u64 = 6;
const INMEMORY_BLOCKS: u32 = 256;
const INMEMORY_BEACON_BLOCKS: u32 = 256;
const NUM_NUM_TO_TD: u32 = 256;
const WAIT_FOR_PEERS_INTERVAL_SECS: u64 = 5;
const WAIT_FOR_DOWNLOAD_INTERVAL_MS: u64 = 100;
const SYNC_DOWNLOAD_BLOCKS_UNIT: u64 = 512;
const DIFFICULTY_DELTA_CLAMP: u64 = 50;
const MAX_NUM_LOCAL_BLOCKS_TO_CHECK: u64 = 256;
const MIN_NO_BLOCK_TIMESTAMP_GAP: u64 = 300;

impl<T, Provider, B, Network> N42Miner<T, Provider, B, Network>
where
    T: PayloadTypes,
    <T::BuiltPayload as BuiltPayload>::Primitives: NodePrimitives,
    <T::BuiltPayload as BuiltPayload>::Primitives: NodePrimitives<Block = reth_ethereum_primitives::Block>,
    Provider: 
        BlockReader
        + BlockIdReader
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + BeaconProvider
        + BeaconProviderWriter
        + 'static + Clone,
    B: PayloadAttributesBuilderExt<<T as PayloadTypes>::PayloadAttributes>,
    Network: FullNetwork,
    Network: BlockAnnounceProvider<Block = Block<TransactionSigned>>,
    <<Network as BlockDownloaderProvider>::Client as BlockClient>::Block: reth_primitives_traits::Block<Header = reth_primitives_traits::Header>,
    <<<Network as BlockDownloaderProvider>::Client as BlockClient>::Block as reth_primitives_traits::Block>::Body: BlockBody< Transaction = TransactionSigned>,
    <<Network as NetworkEventListenerProvider>::Primitives as NetworkPrimitives>::Block: reth_primitives_traits::Block<Header = reth_primitives_traits::Header>,
    <<Network as NetworkEventListenerProvider>::Primitives as NetworkPrimitives>::BlockBody: reth_primitives_traits::BlockBody<OmmerHeader = reth_primitives_traits::Header>,
{
    /// Spawns a new [`N42Miner`] with the given parameters.
    pub fn spawn_new(
        provider: Provider,
        payload_attributes_builder: B,
        beacon_engine_handle: BeaconConsensusEngineHandle<T>,
        mode: MiningMode,
        payload_builder: PayloadBuilderHandle<T>,
        network: Network,
        consensus: Arc<dyn FullConsensus<<T::BuiltPayload as BuiltPayload>::Primitives, Error = ConsensusError>>,
        broadcast_unverified_block_tx: broadcast::Sender<(UnverifiedBlock, Arc<Vec<BLSPubkey>>)>,
        block_verify_result_rx: mpsc::Receiver<BlockVerifyResult>,
    ) {
        let (new_block_tx, new_block_rx) = mpsc::channel::<(NewBlock, BlockHash)>(128);
        let beacon = Beacon::new(provider.clone());

        let mode_interval = match mode {
            MiningMode::Instant(_) => {
                unimplemented!("Add a separate flow if needed");
            }
            MiningMode::Interval(ref v) => v,
            _ => return (),
        };
        let block_time = mode_interval.period().as_secs();

        let miner = Self {
            provider,
            payload_attributes_builder,
            beacon_engine_handle,
            mode,
            interval_prepare_block: tokio::time::interval(Duration::from_secs(block_time)),
            payload_builder,
            network,
            consensus,
            recent_blocks: schnellru::LruMap::new(schnellru::ByLength::new(INMEMORY_BLOCKS)),
            recent_num_to_td: schnellru::LruMap::new(schnellru::ByLength::new(NUM_NUM_TO_TD)),
            num_generated_blocks: 0,
            num_skipped_new_block: 0,
            num_should_skip_block_generation: 0,
            num_long_delayed_blocks: 0,
            num_fetched_blocks: 0,
            order_stats: HashMap::new(),
            new_block_tx,
            new_block_rx,
            beacon,
            broadcast_unverified_block_tx,
            block_verify_result_rx,
            pending_block_data: None,
        };

        // Spawn the miner
        tokio::spawn(miner.run());
    }

    /// Runs the [`N42Miner`] in a loop, polling the miner and building payloads.
    async fn run(mut self) -> eyre::Result<()> {
        self.provider.save_beacon_block_hash_by_eth1_hash(&self.provider.chain_spec().genesis_hash(), self.provider.chain_spec().genesis_hash())?;
        self.provider.save_beacon_state_by_hash(&self.provider.chain_spec().genesis_hash(), BeaconState::new())?;

        if !(self.get_best_block_num_signers()? == 1 && self.is_among_signers()?) {
            self.initial_sync().await;
        }

        let mut new_block_event_stream = self.network.subscribe_block();
        let mut network_event_stream = self.network.event_listener();

        loop {
            tokio::select! {
                Some(verification_result) = self.block_verify_result_rx.recv() => {
                    debug!(target: "consensus-client", ?verification_result, "verification_rx");
                    if let Err(e) = self.handle_verification_result(verification_result) {
                        error!(target: "consensus-client", "Error handling verification_result: {:?}", e);
                    }
                }
                Some((new_block, hash)) = self.new_block_rx.recv() => {
                    let insert_ok = self.recent_num_to_td.insert(new_block.block.number, U256::from(new_block.td));
                    debug!(target: "consensus-client", insert_ok, number=?new_block.block.number, "recent_num_to_td insert");
                    self.network.announce_block(new_block, hash);
                }
                _ = &mut self.mode => {
                    if let Err(e) = self.advance().await {
                        error!(target: "consensus-client", "Error advancing the chain: {:?}", e);
                    }
                }
                _ = self.interval_prepare_block.tick() => {
                    if let Err(e) = self.prepare_block().await {
                        error!(target: "consensus-client", "Error preparing the block: {:?}", e);
                    }
                }
                new_block_event = &mut new_block_event_stream.next() => {
                    debug!(target: "consensus-client", "new_block_event={:?}", new_block_event);
                    if let Some(new_block) = new_block_event {
                    if let Err(e) = self.handle_new_block(new_block).await {
                        error!(target: "consensus-client", "Error handling the new block: {:?}", e);
                    }
                    }
                }
                network_event = &mut network_event_stream.next() => {
                    debug!(target: "consensus-client", "network_event={:?}", network_event);
                }
            }
        }
    }

    async fn initial_sync(&mut self) {
        loop {
            let status_counts;
            loop {
                sleep(Duration::from_secs(WAIT_FOR_PEERS_INTERVAL_SECS)).await;

                if let Ok(all_peers) = self.network.get_all_peers().await {
                    debug!(target: "consensus-client", peers_count=all_peers.len());
                    if !all_peers.is_empty() {
                        status_counts = all_peers
                            .iter()
                            .map(|v| (v.status.total_difficulty, v.status.blockhash))
                            .counts();
                        break;
                    }
                }
            }
            let (&(peer_finalized_td, peer_finalized_td_hash), _) = {
                if status_counts.is_empty() {
                    break;
                }
                status_counts
                    .iter()
                    .max_by_key(|&(_, count)| count)
                    .unwrap()
            };

            let (max_td, max_td_hash) = self.max_td_and_hash();
            debug!(target: "consensus-client", ?peer_finalized_td, ?max_td, "Comparing peer_finalized_td with max_td");
            debug!(target: "consensus-client", ?peer_finalized_td_hash, ?max_td_hash,);
            if peer_finalized_td > max_td + U256::from(DIFFICULTY_DELTA_CLAMP) {
                match self
                    .initial_sync_to_hash(peer_finalized_td, peer_finalized_td_hash)
                    .await
                {
                    Ok(duration) => {
                        debug!(target: "consensus-client", ?peer_finalized_td, ?peer_finalized_td_hash, "finished one sync attempt");
                        if duration.as_secs() < (MIN_NO_BLOCK_TIMESTAMP_GAP / 2) {
                            break;
                        }
                    }
                    Err(err) => {
                        warn!(target: "consensus-client", ?err, "initial_sync_to_hash failed");
                    }
                }
            } else {
                info!(target: "consensus-client", "head td is close to peer finalized td, no need to sync");
                break;
            }
            if let Ok(all_peers) = self.network.get_all_peers().await {
                // workaround for obsolete peer status
                info!(target: "consensus-client", "disconnecting and removing peers to get the latest status");
                for peer in all_peers {
                    self.network.disconnect_peer(peer.remote_id);
                    self.network.remove_peer(peer.remote_id, peer.kind);
                    debug!(target: "consensus-client", "Disconnected peer {peer_id}", peer_id=peer.remote_id);
                }
            }
        }
    }

    fn long_time_no_block_generated(&self) -> eyre::Result<bool> {

        let best_block_number = self.provider.best_block_number()?;
        let latest_header = self.provider
            .sealed_header(best_block_number)?
.ok_or(eyre::eyre!("sealed_header not found, block_number={:?}", best_block_number))?;
        let now = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("cannot be earlier than UNIX_EPOCH");
        if now.as_secs() > latest_header.timestamp() + MIN_NO_BLOCK_TIMESTAMP_GAP {
            warn!(target: "consensus-client", latest_header_timestamp=?latest_header.timestamp(), ?now, "long_time_no_block_generated");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn exit_if_lagged_progress(&self, block: &SealedBlock) -> eyre::Result<()> {
        const MAX_PROGRESS_GAP: u64 = 100;

        let best_block_number = self.provider.best_block_number()?;
        debug!(target: "consensus-client", my_number=?best_block_number, received_number=?block.header().number,"exit_if_lagged_progress");
        if block.header().number > best_block_number + MAX_PROGRESS_GAP {
            let current_signers = self.get_best_block_signers()?;
            let signer = match recover_address(block.header()) {
                Ok(v) => v,
                Err(err) => {
                    eyre::bail!("Error in recover_address: {:?}", err);
                },
            };
            if current_signers.contains(&signer) && self.long_time_no_block_generated()? {
                warn!(target: "consensus-client", my_number=?best_block_number, received_number=?block.header().number, "exit for lagged progress");
                exit_by_sigint();
            }
        }

        Ok(())
    }

    async fn handle_new_block(&mut self, new_block: NewBlock<Network::Block>) -> eyre::Result<()> {
        trace!(target: "consensus-client", ?new_block);

        let mut parents = Vec::new();
        let block = new_block.clone().block.seal_slow();
        self.recent_blocks.insert(block.hash(), block.clone());
        let (max_td, _) = self.max_td_and_hash();
        if max_td >= U256::from(new_block.td) {
            return Ok(());
        }
        let _ = self.exit_if_lagged_progress(&block).await;

        let mut is_fork = false;
        let mut parent = block.hash();
        let mut parent_num = block.header().number;
        let mut difficulty;
        let safe_block_num_hash = self.get_safe_block_num_hash_from_provider();
        loop {
            debug!(target: "consensus-client", ?parent_num, ?parent, safe_number=?safe_block_num_hash.number, block_hash=?block.hash());
            if parent_num < safe_block_num_hash.number {
                break;
            }
            if parent == safe_block_num_hash.hash {
                is_fork = true;
                break;
            }
            if let Some(block) = self.recent_blocks.get(&parent) {
                parent = block.header().parent_hash();
                parent_num = block.header().number() - 1;
                difficulty = block.header().difficulty();
                debug!(target: "consensus-client", ?difficulty);
                parents.push(block.clone());
                continue;
            }
            match self.fetch_block(parent.into()).await {
                Ok(parent_block) => {
                    parent = parent_block.header().parent_hash();
                    parent_num = parent_block.header().number() - 1;
                    difficulty = parent_block.header().difficulty();
                    debug!(target: "consensus-client", ?difficulty);
                    let sealed_block = parent_block.seal_slow();
                    parents.push(sealed_block.clone());
                    self.recent_blocks.insert(sealed_block.hash(), sealed_block);
                }
                Err(e) => {
                    error!(target: "consensus-client", "Error getting the block: {:?}", e);
                    break;
                }
            }
        }
        let mut larger_td = max_td < U256::from(new_block.td);
        debug!(target: "consensus-client", is_fork, ?max_td, new_block_td=?U256::from(new_block.td));

        if let Some(&mut v) = self.recent_num_to_td.get(&new_block.block.number) {
            if v >= U256::from(new_block.td) {
                debug!(target: "consensus-client", number=new_block.block.number, td=?U256::from(new_block.td), old_td=?v, "skip new block");
                self.num_skipped_new_block += 1;
                larger_td = false;
            }
        }
        if is_fork && larger_td {
            let mut new_payload_ok = true;
            for parent in parents.iter().rev() {
                match self.new_payload(parent).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!(target: "consensus-client", "Error validating the block: {:?}", e);
                        new_payload_ok = false;
                        break;
                    }
                }

                //let new_beacon_block = fetch_beacon_block(parent.hash()).await?;
                // TODO
                let new_beacon_block: BeaconBlock = Default::default();
                let new_beacon_block_hash = new_beacon_block.hash_slow();

                //let deposits = self.get_deposits(parent.number.saturating_sub(DEPOSIT_GAP))?;
                let deposits: Vec<Deposit> = Default::default();
                if deposits != new_beacon_block.body.deposits {
                    return Err(eyre::eyre!("deposits mismatch between eth1 block and beacon block"));
                }

                let (_, beacon_state_after_withdrawal) = self.beacon.gen_withdrawals(parent.parent_hash)?;
                let new_beacon_state = self.beacon.state_transition(Some(beacon_state_after_withdrawal), &new_beacon_block)?;
                if new_beacon_state.hash_slow() != new_beacon_block.state_root {
                    return Err(eyre::eyre!("state root mismatch, new_beacon_state hash={:?}, new_beacon_block.state_root={:?}", new_beacon_state.hash_slow(), new_beacon_block.state_root));
                }

                self.provider.save_beacon_block_by_hash(&new_beacon_block_hash, new_beacon_block.clone())?;
                self.provider.save_beacon_block_hash_by_eth1_hash(&parent.hash(), new_beacon_block_hash)?;
            }

            if new_payload_ok {
                let forkchoice_state = self.forkchoice_state_with_head(block.hash())?;
                match self
                    .beacon_engine_handle
                    .fork_choice_updated(forkchoice_state, None, EngineApiMessageVersion::default())
                    .await
                {
                    Ok(v) => {
                        debug!(target: "consensus-client", "forkchoice(block hash) status {:?}", v);
                    }
                    Err(e) => {
                        error!(target: "consensus-client", "Error updating fork choice(block hash): {:?}", e);
                    }
                }
            }
        }
        Ok(())
    }

    fn get_best_block_signers(&self) -> eyre::Result<Vec<Address>> {
        let best_block_number = self.provider.best_block_number()?;
        let header = self
            .provider
            .sealed_header(best_block_number)?
            .ok_or(eyre::eyre!("sealed_header not found, block_number={:?}", best_block_number))?;
        let snapshot = self
            .consensus
            .snapshot(header.number(), header.hash_slow(), None)?;
        

        Ok(snapshot.signers)
    }

    fn get_best_block_num_signers(&self) -> eyre::Result<u64> {
        let num_signers: u64 = self.get_best_block_signers()?.len() as u64;

        Ok(num_signers)
    }

    fn get_safe_block_num_hash_from_provider(&mut self) -> BlockNumHash {
        let safe_block_number = self
            .provider
            .safe_block_number()
            .unwrap_or(Some(0))
            .unwrap_or(0);

        let safe_block_header = self
            .provider
            .sealed_header(safe_block_number)
            .unwrap()
            .unwrap();
        let safe_block_hash = safe_block_header.hash_slow();

        BlockNumHash {
            number: safe_block_header.number(),
            hash: safe_block_hash,
        }
    }

    fn determine_safe_block(&mut self) -> eyre::Result<BlockNumHash> {
        let mut safe_block_number = self
            .provider
            .safe_block_number()
            .unwrap_or(Some(0))
            .unwrap_or(0);

        let header = self
            .provider
            .sealed_header(self.provider.best_block_number().unwrap())
            .unwrap()
            .unwrap();

        const NUM_SAMPLE_ROUNDS: u64 = 2;
        const NUM_CONFIRM_ROUNDS: u64 = 1;

        let num_signers = self.get_best_block_num_signers()?;
        let best_block_number = self.provider.best_block_number().unwrap();
        let mut active_signers = (best_block_number.saturating_sub(NUM_SAMPLE_ROUNDS * num_signers)
            ..best_block_number)
            .filter(|&n| n != 0)
            .map(|n| {
                let sealed_header = self.provider.sealed_header(n).unwrap().unwrap();
                let signer = recover_address_generic(sealed_header.header()).unwrap();
                signer
            })
            .collect::<Vec<_>>();

        active_signers.sort();
        active_signers.dedup();
        let num_active_signers: u64 = active_signers.len() as u64;
        debug!(target: "consensus-client", num_signers, num_active_signers, "determine_safe_block");
        if num_active_signers == num_signers {
            // if in NUM_CONFIRM_ROUNDS rounds, all active signers have signed a 2-difficulty block, then it is considered finalized
            let order_in_round = (best_block_number.saturating_sub(NUM_CONFIRM_ROUNDS * num_signers)
                ..best_block_number)
                .filter(|&number| {
                    self.provider
                        .sealed_header(number)
                        .unwrap()
                        .unwrap()
                        .header()
                        .difficulty()
                        == U256::from(2)
                })
                .count() as u64
                == num_active_signers * NUM_CONFIRM_ROUNDS;
            if order_in_round {
                safe_block_number = safe_block_number.max(header
                    .number()
                    .saturating_sub(num_signers * NUM_CONFIRM_ROUNDS + 1));
            }
            self.order_stats.insert(header.number(), order_in_round);
            debug!(target: "consensus-client", number=?header.number(), num_active_signers, order_in_round);
        } else {
            safe_block_number = safe_block_number.max(header
                .number()
                .saturating_sub(num_active_signers * 2 + num_signers + 1));
        }
        let safe_block_header = self
            .provider
            .sealed_header(safe_block_number)
            .unwrap()
            .unwrap();
        let safe_block_hash = safe_block_header.hash_slow();

        Ok(BlockNumHash {
            number: safe_block_header.number(),
            hash: safe_block_hash,
        })
    }

    /// Returns current forkchoice state.
    fn forkchoice_state(&mut self) -> eyre::Result<ForkchoiceState> {
        let (_, max_td_hash) = self.max_td_and_hash();

        let safe_block_num_hash = self.determine_safe_block()?;
        let safe_block_hash = safe_block_num_hash.hash;
        Ok(ForkchoiceState {
            head_block_hash: max_td_hash,
            safe_block_hash,
            finalized_block_hash: safe_block_hash,
        })
    }

    fn get_order_stats(&self) -> (u64, u64, f64) {
        let in_order_count = self.order_stats.values().filter(|v| **v).count();
        let out_of_order_count = self.order_stats.len() - in_order_count;
        (
            in_order_count as u64,
            out_of_order_count as u64,
            in_order_count as f64 / self.order_stats.len() as f64,
        )
    }

    fn handle_verification_result(&mut self, verification_result: BlockVerifyResult) -> eyre::Result<()> {
        let mut pending_block_data = match &self.pending_block_data {
            Some(v) => v.clone(),
            None => {
                debug!(target: "consensus-client", "handle_verification_result: waiting for pending block data");
                return Ok(())
            },
        };
        let block = pending_block_data.block;

        let BlockVerifyResult {
            pubkey,
            signature,
            attestation_data,
            block_hash,
        } = verification_result.clone();

        if block.hash() != block_hash {
            return Err(eyre::eyre!("verification result block hash mismatch: block_hash={block_hash:?}, pending block hash={:?}", block.hash()));
        }

        let mut attestation = pending_block_data.attestations.get_mut(&attestation_data.committee_index)
.ok_or(eyre::eyre!("attestation not found, block_hash={block_hash:?}, committee index={:?}", attestation_data.committee_index))?;

        let signature = Signature::from_bytes(&hex::decode(signature)?).map_err(|e| eyre::eyre!("{e:?}"))?;

        let pubkey = PublicKey::from_bytes(&hex::decode(pubkey)?).map_err(|e| eyre::eyre!("{e:?}"))?;

        let validator_index = self.beacon.get_validator_index_from_beacon_state(block.parent_hash(), pubkey)?.ok_or(eyre::eyre!("validator not found, block_hash={block_hash:?}, pubkey={pubkey:?}"))?;

        if attestation_data.receipts_root != attestation.data.receipts_root {
            return Err(eyre::eyre!("mismatch receipts_root, expected={:?}, got={:?}", attestation.data.receipts_root, attestation_data.receipts_root));
        }

        let bytes: Vec<u8> = serde_json::to_vec(&attestation_data)?;
        let bytes_slice: &[u8] = &bytes;
        let err = signature.verify(true, bytes_slice, alloy_rpc_types_beacon::constants::BLS_DST_SIG, &[], &pubkey, true);
        if err != blst::BLST_ERROR::BLST_SUCCESS {
            return Err(eyre::eyre!("{verification_result:?}"));
        }
        debug!(target: "consensus-client", "sig verify result: {:?}", err);

        match attestation.block_aggregate_signature {
            Some(ref mut v) => {
                let mut sig = fixed_to_agg_sig(v);
                sig.add_signature(&signature, false).unwrap();
                *v = agg_sig_to_fixed(&sig);
            },
            None => {
                attestation.block_aggregate_signature = Some(agg_sig_to_fixed(&AggregateSignature::from_signature(&signature)));
            },
        }
        attestation.validator_indexes.insert(validator_index);
        self.pending_block_data.as_mut().map(|v| { *v.attestations.get_mut(&attestation_data.committee_index).unwrap() = attestation.clone(); });

        Ok(())
    }

    /// Generates a new beacon block, broadcast eth1 block to peers
    async fn advance(&mut self) -> eyre::Result<()> {
        let pending_block_data = match self.pending_block_data {
            Some(ref v) => v.clone(),
            None => {
                debug!(target: "consensus-client", "advance: waiting for pending block data");
                return Ok(())
            },
        };
        let PendingBlockData { block, beacon_state_after_withdrawal, execution_requests, attestations } = pending_block_data;
        let max_td = self.consensus.total_difficulty(block.hash());
        let num_signers = self.get_best_block_num_signers()?;
        let interval = match self.mode {
            MiningMode::Instant(_) => {
                unimplemented!("Add a separate flow if needed");
            }
            MiningMode::Interval(ref mut v) => v,
            _ => return Ok(()),
        };
        let block_time = interval.period().as_secs();
        debug!(target: "consensus-client", block_time, "advance");
        let now = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("cannot be earlier than UNIX_EPOCH");
        let expected_next_timestamp = Duration::from_secs(block.timestamp());
        if expected_next_timestamp > now {
            *interval = interval_at(
                Instant::now() + (expected_next_timestamp - now),
                interval.period(),
            );
            return Ok(());
        }

        let parent_beacon_block_hash = if block.number == 1 {
            self.provider.chain_spec().genesis_hash()
        } else {
            //fetch_beacon_block(block.header().parent_hash).unwrap().hash_slow()
            self.provider.get_beacon_block_hash_by_eth1_hash(&block.header().parent_hash)?.unwrap()
        };
        //let deposits = self.get_deposits(block.number.saturating_sub(DEPOSIT_GAP))?;
        let deposits: Vec<Deposit> = Default::default();
        let voluntary_exits: Vec<VoluntaryExitWithSig> = Default::default();
        let finalized_block_hash = self
            .provider
            .finalized_block_hash()
            .unwrap_or(Some(self.provider.chain_spec().genesis_hash()))
            .unwrap();
        let finalized_beacon_block_hash = self.provider.get_beacon_block_hash_by_eth1_hash(&finalized_block_hash)?.unwrap();
        let finalized_beacon_state = self.provider.get_beacon_state_by_hash(&finalized_beacon_block_hash)?.unwrap();
        let beacon_block = self.beacon.gen_beacon_block(Some(beacon_state_after_withdrawal), parent_beacon_block_hash, &deposits, &attestations.values().cloned().collect(), &voluntary_exits, &execution_requests, &block)?;
        let beacon_block_hash = beacon_block.hash_slow();
        self.provider.save_beacon_block_by_hash(&beacon_block_hash, beacon_block.clone())?;

        //
        self.provider.save_beacon_block_by_eth1_hash(&block.hash(), beacon_block.clone())?;

        self.provider.save_beacon_block_hash_by_eth1_hash(&block.hash(), beacon_block_hash)?;

        let new_beacon_state = self.provider.get_beacon_state_by_hash(&beacon_block_hash)?.unwrap();

        self.recent_blocks.insert(block.hash_slow(), block.clone());

        let wiggle = self.consensus.wiggle(
            block.header().number() - 1,
            block.header().parent_hash(),
            block.header().difficulty(),
        );
        debug!(target: "consensus::apos",
            "wiggle {:?}, timestamp {:?}, number {}",
            wiggle, block.timestamp(), block.number()
        );

        let new_block_tx = self.new_block_tx.clone();
        let block_clone = block.clone();
        let block_hash = block.hash_slow();
        self.provider.save_beacon_block_by_hash(&beacon_block.hash_slow(), beacon_block.clone()).unwrap();
        self.provider.save_beacon_block_by_eth1_hash(&block_hash, beacon_block.clone()).unwrap();
        self.provider.save_beacon_block_hash_by_eth1_hash(&block_hash, beacon_block.hash_slow()).unwrap();
        tokio::spawn(async move {
            sleep(wiggle).await;

            // TODO: broadcast beacon block
            //broadcast_beacon_block(block_hash, &beacon_block).unwrap();

            new_block_tx
                .send((
                    NewBlock {
                        block: block_clone.unseal(),
                        td: max_td.to::<U128>(),
                    },
                    block_hash,
                ))
                .await
                .unwrap();
        });

        self.num_generated_blocks += 1;
        if num_signers == 1 {
            self.new_payload(&block).await?;
            self.fcu_hash(block_hash).await?;
        }
        Ok(())
    }


    /// Generates a new block, broadcast it to validators
    async fn prepare_block(&mut self) -> eyre::Result<()> {
        let (in_order_count, out_of_order_count, order_ratio) = self.get_order_stats();
        let num_signers = self.get_best_block_num_signers()?;

        let block_time = self.interval_prepare_block.period().as_secs();
        info!(target: "consensus-client", num_generated_blocks=self.num_generated_blocks, num_skipped_new_block=self.num_skipped_new_block, num_should_skip_block_generation=self.num_should_skip_block_generation, num_long_delayed_blocks=self.num_long_delayed_blocks, num_fetched_blocks=self.num_fetched_blocks, in_order_count, out_of_order_count, order_ratio);
        let header = self
            .provider
            .sealed_header(self.provider.best_block_number().unwrap())
            .unwrap()
            .unwrap();
        debug!(target: "consensus-client", block_time, "prepare_block");
        let now = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("cannot be earlier than UNIX_EPOCH");
        let expected_next_timestamp = Duration::from_secs(header.header().timestamp() + block_time / 2);
        if expected_next_timestamp > now {
            self.interval_prepare_block = interval_at(
                Instant::now() + (expected_next_timestamp - now),
                self.interval_prepare_block.period(),
            );
            return Ok(());
        }

        if expected_next_timestamp + Duration::from_secs(block_time * num_signers) <= now {
            warn!(target: "consensus-client", number=header.number() + 1, ?expected_next_timestamp, ?now, "not seeing new blocks for a long time, try generating a block again");
            self.recent_num_to_td.remove(&(header.header().number() + 1));
            self.num_long_delayed_blocks += 1;
            self.interval_prepare_block = interval_at(
                Instant::now() + Duration::from_secs(block_time),
                self.interval_prepare_block.period(),
            );
        } else if self.recent_num_to_td.get(&(header.header().number() + 1)).is_some() {
            debug!(target: "consensus-client", number=header.header().number() + 1, "skip generating block");
            self.num_should_skip_block_generation += 1;
            return Ok(());
        }

        let timestamp = now + Duration::from_secs(block_time - block_time / 2);
        debug!(target: "consensus-client", ?timestamp, "prepare_block: PayloadAttributes timestamp");

        let (withdrawals, beacon_state_after_withdrawal) = self.beacon.gen_withdrawals(header.hash())?;
        debug!(target: "consensus-client", ?withdrawals, "prepare_block: PayloadAttributes withdrawals");

        let forkchoice_state = self.forkchoice_state()?;
        let payload_attributes = self.payload_attributes_builder.build_ext(timestamp.as_secs(), withdrawals);
        let res = self
            .beacon_engine_handle
            .fork_choice_updated(
                forkchoice_state,
                Some(payload_attributes),
                EngineApiMessageVersion::default(),
            )
            .await?;
        if !res.payload_status.is_valid() {
            eyre::bail!("Error advancing the chain: fork_choice_updated with PayloadAttributes status is not valid: {:?}", res);
        }
        let payload_id = res.payload_id.ok_or_eyre("No payload id")?;

        let payload = match self
            .payload_builder
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .await
        {
            Some(Ok(payload)) => payload,
            Some(Err(err)) => {
                if self.is_among_signers()? && self.long_time_no_block_generated()? {
                    exit_by_sigint();
                }
                eyre::bail!("Failed to resolve payload: {}", err);
            }
            None => {
                if self.is_among_signers()? && self.long_time_no_block_generated()? {
                    exit_by_sigint();
                }
                eyre::bail!("No payload");
            }
        };

        let execution_requests = payload.requests();
        let block = payload.block();

        let pending_block_data = PendingBlockData {
            block: payload.block().clone(),
            beacon_state_after_withdrawal: beacon_state_after_withdrawal.clone(),
            execution_requests: execution_requests.clone(),
            attestations: Default::default(),
        };
        self.pending_block_data.replace(pending_block_data);

        let max_td = self.consensus.total_difficulty(block.header().hash_slow());
        debug!(target: "consensus-client", ?max_td, "prepare_block: new_block hash {:?}", block.header().hash_slow());
        trace!(target: "consensus-client", ?block);

        let committee_cache = if block.number % SLOTS_PER_EPOCH == 0 {
            // committee_cache init requires non-empty validators
            if !beacon_state_after_withdrawal.has_active_validators(RelativeEpoch::Next) {
                return Ok(());
            }
            beacon_state_after_withdrawal.committee_cache(RelativeEpoch::Next)?
        } else {
            // committee_cache init requires non-empty validators
            if !beacon_state_after_withdrawal.has_active_validators(RelativeEpoch::Current) {
                return Ok(());
            }
            beacon_state_after_withdrawal.committee_cache(RelativeEpoch::Current)?
        };

        let beacon_committees = committee_cache.get_beacon_committees_at_slot(block.number)?;

        let cached_reads = self.consensus.get_cached_reads(block.hash())?.ok_or(eyre::eyre!("cached_reads not found, block_hash={:?}", block.hash()))?;
        let mut header = block.header().clone();
        header.receipts_root = Default::default();
        let body = block.body().clone();
        let sealed_block_modified = SealedBlock::from_parts_unhashed(header, body);
        trace!(target: "consensus-client", ?sealed_block_modified);
        let mut unverified_block = UnverifiedBlock::new(sealed_block_modified, cached_reads, max_td, 0);
        for beacon_committee in &beacon_committees {
            let attestation = Attestation {
                data: AttestationData {
                    slot: block.number,
                    committee_index: beacon_committee.index,
                    receipts_root: block.header().receipts_root,
                },
                ..Default::default()
            };
            self.pending_block_data.as_mut().ok_or(eyre::eyre!("pending_block_data not found, block_number={:?}", block.number))?.attestations.insert(beacon_committee.index, attestation);
            let mut target_committee_pubkeys = Vec::new();
            for validator_index in beacon_committee.committee {
                target_committee_pubkeys.push(beacon_state_after_withdrawal.get_validator(*validator_index)?.pubkey);
            }
            unverified_block.committee_index = beacon_committee.index;
            let _ = self.broadcast_unverified_block_tx.send((unverified_block.clone(), Arc::new(target_committee_pubkeys)));
        }
        Ok(())
    }

    fn forkchoice_state_with_head(&mut self, head_block_hash: B256) -> eyre::Result<ForkchoiceState> {
        let safe_block_num_hash = self.determine_safe_block()?;
        let safe_block_hash = safe_block_num_hash.hash;
        Ok(ForkchoiceState {
            head_block_hash,
            safe_block_hash,
            finalized_block_hash: safe_block_hash,
        })
    }

    async fn new_payload(&mut self, block: &SealedBlock<<<T::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block>) -> eyre::Result<()> {
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
            .new_payload(
                execution_data,
            )
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

    async fn fcu_hash(&mut self, block_hash: BlockHash) -> eyre::Result<()> {
        let forkchoice_state = self.forkchoice_state_with_head(block_hash)?;
        match self
            .beacon_engine_handle
            .fork_choice_updated(forkchoice_state, None, EngineApiMessageVersion::default())
            .await
        {
            Ok(v) => {
                debug!(target: "consensus-client", "forkchoice(block hash) status {:?}", v);
            }
            Err(e) => {
                eyre::bail!("Error updating fork choice(block hash): {:?}", e);
            }
        };

        Ok(())
    }

    async fn fcu_hash_finalized(
        &mut self,
        finalized_hash: BlockHash,
        block_hash: BlockHash,
    ) -> eyre::Result<()> {
        let head_block_hash = block_hash;
        let safe_block_hash = finalized_hash;
        let finalized_block_hash = finalized_hash;
        let forkchoice_state = ForkchoiceState {
            head_block_hash,
            safe_block_hash,
            finalized_block_hash,
        };
        match self
            .beacon_engine_handle
            .fork_choice_updated(forkchoice_state, None, EngineApiMessageVersion::default())
            .await
        {
            Ok(v) => {
                debug!(target: "consensus-client", "forkchoice(block hash) status {:?}", v);
            }
            Err(e) => {
                eyre::bail!("Error updating fork choice(block hash): {:?}", e);
            }
        };
        Ok(())
    }

    /// On node init, sync head to specified hash
    async fn initial_sync_to_hash(&mut self, _td: U256, block_hash: BlockHash) -> eyre::Result<Duration> {
        let start = Instant::now();
        info!(target: "consensus-client", "initial_sync_to_hash hash {:?}", block_hash);
        let finalized_block_number = self
            .provider
            .finalized_block_number()
            .unwrap_or(Some(0))
            .unwrap_or(0);
        let best_block_number = self.provider.best_block_number().unwrap_or(0);
        info!(target: "consensus-client", ?finalized_block_number, ?best_block_number, "initial_sync_to_hash");

        let num_blocks = best_block_number - finalized_block_number;
        let start_block_number = if num_blocks > MAX_NUM_LOCAL_BLOCKS_TO_CHECK {
            warn!(target: "consensus-client", ?finalized_block_number, ?best_block_number, MAX_NUM_LOCAL_BLOCKS_TO_CHECK=?MAX_NUM_LOCAL_BLOCKS_TO_CHECK,
                "some of the blocks from finalized block to best block are not checked to see they are same as the blocks on the chain",
            );
            best_block_number.saturating_sub(MAX_NUM_LOCAL_BLOCKS_TO_CHECK)
        } else {
            finalized_block_number
        };

        for number in (start_block_number..=best_block_number).skip(1) {
            let block = self.provider.block_by_number(number).unwrap().unwrap();
            let hash = block.header().hash_slow();
            debug!(target: "consensus-client", number, "initial_sync_to_hash, fetching header");
            let header_from_p2p = self.fetch_header(number.into()).await?;
            let header_hash_from_p2p = header_from_p2p.hash_slow();
            if hash != header_hash_from_p2p {
                warn!(target: "consensus-client", number, ?hash, ?header_hash_from_p2p, "found first different block");
                warn!(target: "consensus-client", "please execute 'n42 stage unwind to-block {}', then run n42 node again", number - 1);
                exit_by_sigint();
                sleep(Duration::from_secs(u64::MAX)).await;
            }
        }

        let finalized_block_from_p2p = self.fetch_block(block_hash.into()).await?.seal_slow();

        self.sync_to_hash_in_small_unit(
            finalized_block_from_p2p.header().parent_hash(),
            SYNC_DOWNLOAD_BLOCKS_UNIT,
        )
        .await?;
        self.new_payload(&finalized_block_from_p2p).await?;
        self.fcu_hash_finalized(block_hash, block_hash).await?;
        let duration = start.elapsed();
        info!(target: "consensus-client", ?duration, from=?best_block_number, to=?finalized_block_from_p2p.header().number(), "time spent in syncing");
        Ok(duration)
    }

    /// workaround for "stuck in downloading for large block ranges"
    async fn sync_to_hash_in_small_unit(
        &mut self,
        block_hash: BlockHash,
        unit_size: u64,
    ) -> eyre::Result<()> {
        let header_from_p2p = self.fetch_header(block_hash.into()).await?;

        loop {
            let best_block_number = self.provider.best_block_number().unwrap();
            if best_block_number == header_from_p2p.number {
                break;
            }

            let next_block_number =
                std::cmp::min(best_block_number + unit_size, header_from_p2p.number);

            let next_header_from_p2p = self.fetch_header(next_block_number.into()).await?;
            self.fcu_hash(next_header_from_p2p.hash_slow()).await?;
            loop {
                let block_number = self.provider.best_block_number().unwrap();
                if block_number < next_block_number {
                    sleep(Duration::from_millis(WAIT_FOR_DOWNLOAD_INTERVAL_MS)).await;
                } else {
                    info!(target: "consensus-client", ?block_number, "sync_to_hash_in_small_unit: synced to block");
                    break;
                }
            }
        }

        let header = self
            .provider
            .sealed_header(self.provider.best_block_number().unwrap())
            .unwrap()
            .unwrap();

        if header.hash() == block_hash {
            Ok(())
        } else {
            eyre::bail!(
                "number={:?}, expected block_hash={:?}, got hash={:?}",
                header.header().number(),
                block_hash,
                header.hash()
            );
        }
    }

    async fn fetch_header(&self, start: BlockHashOrNumber) -> eyre::Result<Header> {
        let fetch_client = match self.network.fetch_client().await {
            Ok(c) => c,
            Err(err) => {
                eyre::bail!("Failed to get fetch_client: {}, {:?}", err, start);
            }
        };
        let header = match fetch_client
            .get_header_with_priority(start, Priority::High)
            .await
        {
            Ok(h) => h.into_data(),
            Err(err) => {
                eyre::bail!("Failed to get header: {}, {:?}", err, start);
            }
        };
        if header.is_none() {
            eyre::bail!("Failed to get header: header is None, {:?}", start);
        }
        Ok(header.unwrap())
    }

    async fn fetch_block(&mut self, start: BlockHashOrNumber) -> eyre::Result<<<T::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block> {
        self.num_fetched_blocks += 1;
        let fetch_client = match self.network.fetch_client().await {
            Ok(c) => c,
            Err(err) => {
                eyre::bail!("Failed to get fetch_client: {}, {:?}", err, start);
            }
        };
        let header = match fetch_client
            .get_header_with_priority(start, Priority::High)
            .await
        {
            Ok(h) => h.into_data(),
            Err(err) => {
                eyre::bail!("Failed to get header: {}, {:?}", err, start);
            }
        };
        if header.is_none() {
            eyre::bail!("Failed to get header: header is None, {:?}", start);
        }
        let header = header.unwrap();
        let body = match fetch_client
            .get_block_body_with_priority(header.hash_slow(), Priority::High)
            .await
        {
            Ok(b) => b.into_data(),
            Err(err) => {
                eyre::bail!("Failed to get body: {}, {:?}", err, start);
            }
        };
        if body.is_none() {
            eyre::bail!("Failed to get body: body is None, {:?}", start);
        }
        let block = body.unwrap().into_ethereum_body().into_block(header);
        Ok(block)
    }

    fn max_td_and_hash(&self) -> (U256, B256) {
        let header = self
            .provider
            .sealed_header(self.provider.best_block_number().unwrap())
            .unwrap()
            .unwrap();
        let td = self.consensus.total_difficulty(header.hash_slow());
        let average_td = td.to::<u64>() as f64 / header.number() as f64;
        info!(hash=?header.hash(), ?td, header_number=header.number(), header_timestamp=header.timestamp(), average_td, "max_td_and_hash");
        (td, header.hash())
    }

    fn is_among_signers(&self) -> eyre::Result<bool> {
        if let Some(address) = self.consensus.get_eth_signer_address()? {
            Ok(self.get_best_block_signers()?.contains(&address))
        } else {
            Ok(false)
        }
    }

    fn get_deposits(&self, block_number: BlockNumber) -> eyre::Result<Vec<Deposit>> {
        let mut deposits = Vec::new();
        debug!(target: "consensus-client", ?block_number, "get_deposits");
        if let Some(receipts) = self.provider.receipts_by_block(block_number.into())? {
            for receipt in &receipts {
                for log in receipt.logs() {
                    debug!(target: "consensus-client", ?log);
                    if let Some(deposit_event) = parse_deposit_log(&log) {
                        debug!(target: "consensus-client", ?deposit_event);
                        let mut deposit: Deposit = Default::default();
                        deposit.data.amount = u64::from_le_bytes(deposit_event.amount.as_ref().try_into().unwrap());
                        deposit.data.withdrawal_credentials = B256::from_slice(&deposit_event.withdrawal_credentials);
                        let pubkey: BLSPubkey = deposit_event.pubkey.as_ref().try_into()?;
                        deposit.data.pubkey = pubkey;
                        //deposit.data.signature = deposit_event.signature.clone();
                        deposits.push(deposit);
                    }
                }
            }
        }
        Ok(deposits)
    }

}

fn exit_by_sigint() {
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::this(),
        nix::sys::signal::Signal::SIGINT,
    );
}
