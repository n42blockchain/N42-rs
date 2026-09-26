// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A loopback TCP channel that hands a built block to the validator as bytes.
//!
//! `n42Engine_getPayloadRaw` took the transactions out of the JSON but left
//! the block in it: a 12 MB RLP became a 24 MB hex string, serialised on this
//! side, parsed and decoded on the other. Measured at the 163,000-transaction
//! tier the validator saw a build take about 150 ms longer than the builder
//! spent on it, and this hop is most of that.
//!
//! This is the same block over a socket, length-prefixed, nothing encoded
//! twice. The RLP is produced with the transactions encoded in parallel, which
//! `alloy_rlp::encode` on a block does not do. The validator learns the address
//! from `n42Engine_payloadEndpoint` on the auth transport, so the channel needs
//! no flag on its side; on this side it is `N42_PAYLOAD_SERVE=<addr>`, loopback
//! only, because it is unauthenticated and answers with whatever this node has
//! built.
//!
//! # Wire
//!
//! ```text
//! request  := u8 kind (n42_h2_execution::raw_engine::request), then:
//!   GET_PAYLOAD: u64 payload id (the Engine API's 8 bytes, little-endian)
//!   reply    := u8 status            0 = unknown build, 1 = block follows, 2 = error (u32 len + message)
//!               u32 len, block RLP   [header, transactions, ommers, withdrawals]
//!               u8 has_requests, [u32 n, n x (u32 len, bytes)]
//!               u8 has_bal, [u32 len, bytes]
//!   NEW_PAYLOAD: u32 len, encoded ExecutionData (raw_engine::encode_execution_data)
//!   reply    := u8 status            1 = payload status follows, 2 = error (u32 len + message)
//!               u32 len, encoded PayloadStatus
//! ```
//!
//! `NEW_PAYLOAD` is the follower's half: the same `engine_newPayload`, handed
//! to the engine as the [`ExecutionData`] it wants without 39 MB of hex on the
//! way. Measured before it existed: ~285 ms between a body arriving at the
//! validator and its vote that the execution layer's own import (637 ms) did
//! not account for.

use std::net::SocketAddr;

use alloy_consensus::BlockHeader as _;
use alloy_primitives::B256;
use alloy_eips::Encodable2718;
use alloy_rlp::Encodable;
use n42_h2_execution::raw_engine::{self, request};
use reth_engine_primitives::ConsensusEngineHandle;
use n42_engine_types::N42BuiltPayload;
use reth_primitives_traits::transaction::TxHashRef as _;
use reth_payload_builder::PayloadBuilderHandle;
use reth_payload_primitives::{BuiltPayload, PayloadKind, PayloadTypes};
use reth_primitives_traits::{Block as _, BlockBody as _, SealedBlock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use n42_engine_types::engine_validator::CompactBodyError;
use tracing::{debug, info, warn};

/// The block's RLP, `[header, transactions, ommers, withdrawals]`, with the
/// transactions encoded on the worker pool.
///
/// Byte-identical to `alloy_rlp::encode(block)`: a typed transaction is an
/// RLP string wrapping its EIP-2718 bytes, a legacy one is its own RLP list.
pub fn encode_block_parallel<B>(block: &SealedBlock<B>) -> Vec<u8>
where
    B: reth_primitives_traits::Block,
    B::Body: reth_primitives_traits::BlockBody<Transaction: Encodable2718 + Sync>,
{
    encode_block_parallel_keeping_transactions(block).0
}

/// [`encode_block_parallel`], handing back the EIP-2718 encoding of each
/// transaction as well -- the bytes it makes on the way to the block's RLP and
/// used to drop. A payload lists transactions in exactly that form, so the
/// leader's own block is served from these instead of encoding its 163,000
/// transactions a second time a few milliseconds later (`request::OWN_BLOCK`).
pub fn encode_block_parallel_keeping_transactions<B>(block: &SealedBlock<B>) -> (Vec<u8>, Vec<alloy_primitives::Bytes>)
where
    B: reth_primitives_traits::Block,
    B::Body: reth_primitives_traits::BlockBody<Transaction: Encodable2718 + Sync>,
{
    use rayon::prelude::*;
    let header = alloy_rlp::encode(block.header());
    let (transactions, listed): (Vec<Vec<u8>>, Vec<alloy_primitives::Bytes>) = block
        .body()
        .transactions()
        .par_iter()
        .map(|tx| {
            let inner = tx.encoded_2718();
            let listed = alloy_primitives::Bytes::from(inner.clone());
            let encoded = if tx.type_flag().is_some() {
                let mut out = Vec::with_capacity(inner.len() + 4);
                alloy_rlp::Header { list: false, payload_length: inner.len() }.encode(&mut out);
                out.extend_from_slice(&inner);
                out
            } else {
                inner
            };
            (encoded, listed)
        })
        .unzip();
    let transactions_len: usize = transactions.iter().map(Vec::len).sum();
    let transactions_header = alloy_rlp::Header { list: true, payload_length: transactions_len };
    let ommers: &[u8] = &[0xc0];
    let withdrawals = block.body().withdrawals().map(|w| alloy_rlp::encode(w));
    let payload_length = header.len()
        + transactions_header.length_with_payload()
        + ommers.len()
        + withdrawals.as_ref().map_or(0, Vec::len);
    let mut out = Vec::with_capacity(payload_length + 8);
    alloy_rlp::Header { list: true, payload_length }.encode(&mut out);
    out.extend_from_slice(&header);
    transactions_header.encode(&mut out);
    for tx in &transactions {
        out.extend_from_slice(tx);
    }
    out.extend_from_slice(ommers);
    if let Some(withdrawals) = withdrawals {
        out.extend_from_slice(&withdrawals);
    }
    (out, listed)
}

/// Serves built blocks and imports on `addr` until the process ends.
/// What importing our own sealed block without re-executing it needs: the
/// validator that turns a payload into the sealed block, the QMDB state the
/// builder filed the block's root in (under the builder's hash), and the way
/// into the engine loop. See `n42_engine_types::built_executions`.
#[derive(Clone)]
pub struct OwnBlockReuse {
    /// Converts a payload into the sealed block, exactly as the engine would.
    pub validator: std::sync::Arc<n42_engine_types::engine_validator::N42EngineValidator<reth_chainspec::ChainSpec>>,
    /// The QMDB state, on a chain that declares one.
    pub qmdb: Option<n42_qmdb_reth::QmdbNodeState>,
    /// Into the engine loop.
    pub inserts: tokio::sync::mpsc::UnboundedSender<reth_node_builder::executed_inserts::ExecutedInsert>,
    /// Takes the block's transactions out of the pool the moment the block is
    /// in the tree, so the next build does not select them again. Opt-in.
    ///
    /// The pool learns of a canonical block through its maintenance task,
    /// asynchronously, and at 163,000 transactions a block that lags behind
    /// a leader that builds every view: a tenure leader's builder was
    /// measured pulling 327,000 transactions a build of which 163,000 were
    /// the previous block's, paying the pool iteration twice and an account
    /// read per stale transaction. Pruning here made `stale` zero and the
    /// round slower: reth removes transactions one at a time under the
    /// pool's write lock, 260-293 ms for a block's worth, and that is the
    /// same cost the maintenance pays later -- so on the import path it is
    /// on the critical path instead of beside it. The pool's per-transaction
    /// removal is the wall, not when it happens.
    pub prune_pool: Option<std::sync::Arc<dyn Fn(Vec<alloy_primitives::B256>) + Send + Sync>>,
    /// `N42_FOLLOWER_EXEC_PROBE=1`: after the engine has imported a block of
    /// another node's, execute it once more with the plain block executor on
    /// the parent's state and log how long that takes -- the time an import
    /// without the engine's payload-processor plumbing would cost. An
    /// instrument: it adds its own time to the import, and a leg run with it
    /// is not a measurement of the chain. Returns (ms, gas used, receipts).
    pub exec_probe: Option<
        std::sync::Arc<
            dyn Fn(reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>) -> Result<(u64, u64, usize), String>
                + Send
                + Sync,
        >,
    >,
    /// `N42_FOLLOWER_DIRECT_IMPORT=1`: another node's block is executed here
    /// with the plain block executor, checked against its header by the
    /// consensus rules and the QMDB root, and handed to the engine as
    /// executed -- the leader's own-block mechanism, for every block. The
    /// engine's `newPayload` still follows, finds the block in its tree and
    /// answers; it is the proof the insert landed and the fallback when it
    /// did not. Round 38 measured the plain executor at 121 ms a block
    /// against ~340 ms in the engine's payload-processor path.
    pub import_foreign: Option<std::sync::Arc<ForeignImport>>,
    /// The engine's canonical head, for the own block that forks from it.
    ///
    /// reth's tree drops an executed insert whose number is not above its
    /// canonical block number ("outdated block"): a sibling the leader
    /// re-proposes after a TC, at the height of the own block it already
    /// made canonical, was skipped, and the header-only `newPayload` that
    /// followed executed the sibling on the fork path -- on QMDB, against
    /// the wrong state (loop147-152: every header after it rejected). The
    /// head is moved to the sibling's parent first, so the insert extends it.
    pub canonical_head: Option<std::sync::Arc<dyn Fn() -> Option<B256> + Send + Sync>>,
}

/// Executes and checks another node's block; see [`OwnBlockReuse::import_foreign`].
/// Returns the executed block for the engine and the phase timings in
/// milliseconds: header checks, senders, execution, post-execution checks,
/// state root, hashed state, then the senders served from the cache, the
/// parent-state lookup, the carry, the wait for the parent to be canonical in
/// the engine, the wait for the execution gate, and the wait for the parent's
/// own QMDB root.
pub type ForeignImport = dyn Fn(
        SealedBlock<n42_tx_types::Block>,
        // The senders, when the caller already has them: the compact body
        // road assembles the block out of this node's own queue, which holds
        // each transaction with the sender its ingest recovered.
        Option<Vec<alloy_primitives::Address>>,
        Option<tokio::sync::oneshot::Sender<()>>,
        crate::follower_import::VoteRoad,
    ) -> Result<
        (Box<reth_payload_primitives::BuiltPayloadExecutedBlock<n42_tx_types::N42Primitives>>, [u64; 12]),
        String,
    > + Send
    + Sync;

impl std::fmt::Debug for OwnBlockReuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnBlockReuse").field("qmdb", &self.qmdb.is_some()).finish_non_exhaustive()
    }
}

/// Imports a payload that is one of our own builds under consensus's seal by
/// handing the engine the build's execution, so `newPayload` for it finds
/// the block already in the tree.
///
/// Returns `Some(built hash)` when the block went in that way. `None` means
/// the payload is not a build this node kept, or the sealed header did not
/// hash to the payload's hash, or the engine refused it -- and the caller
/// imports it the ordinary way, so nothing here can make a block invalid,
/// only slow.
async fn reuse_own_build<T>(
    reuse: &OwnBlockReuse,
    data: &alloy_rpc_types_engine::ExecutionData,
) -> Option<B256>
where
    T: PayloadTypes<ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    use reth_engine_primitives::PayloadValidator as _;
    let v1 = data.payload.as_v1();
    let (parent_hash, number, state_root, receipts_root, gas_used) =
        (v1.parent_hash, v1.block_number, v1.state_root, v1.receipts_root, v1.gas_used);
    // On a thread: a build sealed before its finish is waited for.
    let (built_hash, built) = tokio::task::spawn_blocking(move || {
        n42_engine_types::built_executions::take(parent_hash, number, state_root, receipts_root, gas_used, None)
    })
    .await
    .ok()??;
    let started = std::time::Instant::now();
    let expected_hash = data.payload.block_hash();
    // The sealed header, first from the fields alone: the payload carries
    // everything the seal may have changed, the build carries everything it
    // cannot, and the hash says whether the pairing is right. That is a
    // few microseconds; the full conversion below decodes 163,000
    // transactions to reach the same header, 50-100 ms, and is kept for the
    // day a profile changes a field this does not expect.
    let sealed_header = match sealed_header_from_fields(data, built.block.header()) {
        Some(header) if header.hash() == expected_hash => header,
        _ => {
            let sealed = match <n42_engine_types::engine_validator::N42EngineValidator<reth_chainspec::ChainSpec> as reth_engine_primitives::PayloadValidator<T>>::convert_payload_to_block(&reuse.validator, data.clone()) {
                Ok(sealed) => sealed,
                Err(err) => {
                    debug!(target: "n42.payload_serve", %err, "own build's payload did not convert; importing it the ordinary way");
                    return None;
                }
            };
            if sealed.hash() != expected_hash
                || sealed.header().transactions_root != built.block.header().transactions_root
                || sealed.body().transactions.len() != built.block.body().transactions.len()
            {
                return None;
            }
            sealed.split_sealed_header_body().0
        }
    };
    let converted = started.elapsed();
    if v1.transactions.len() != built.block.body().transactions.len() {
        return None;
    }
    let payload_withdrawals = data.payload.as_v2().map(|v2| v2.withdrawals.as_slice());
    if !build_executes_as_sealed(built.block.header(), built.block.body().withdrawals.as_ref().map(|w| w.as_slice()), &sealed_header, payload_withdrawals) {
        debug!(target: "n42.payload_serve", number, "a build on the same parent is not this block; importing it the ordinary way");
        return None;
    }
    hand_off_own_build::<T>(reuse, built_hash, built, sealed_header, converted).await
}

/// The transactions of the last blocks this node served, in the form a payload
/// lists them, kept from the encoding the service already did for the block's
/// RLP. Two entries: the own-block import follows its `getPayload` by a few
/// milliseconds, and a build ahead may put one more block in between.
static LISTED_TRANSACTIONS: std::sync::Mutex<Vec<(alloy_primitives::B256, std::sync::Arc<Vec<alloy_primitives::Bytes>>)>> =
    std::sync::Mutex::new(Vec::new());

/// Keeps `listed` for `block`, dropping all but the last two.
fn remember_listed(block: alloy_primitives::B256, listed: Vec<alloy_primitives::Bytes>) {
    let mut kept = LISTED_TRANSACTIONS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    kept.retain(|(held, _)| *held != block);
    kept.push((block, std::sync::Arc::new(listed)));
    if kept.len() > 2 {
        kept.remove(0);
    }
}

/// What [`remember_listed`] kept for `block`, if it is still held.
fn listed_for(block: alloy_primitives::B256) -> Option<std::sync::Arc<Vec<alloy_primitives::Bytes>>> {
    let kept = LISTED_TRANSACTIONS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    kept.iter().find(|(held, _)| *held == block).map(|(_, listed)| std::sync::Arc::clone(listed))
}

/// A block's transactions in their EIP-2718 encoding, as a payload lists them,
/// encoded on the worker pool.
fn encoded_transactions(block: &reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>) -> Vec<alloy_primitives::Bytes> {
    use rayon::prelude::*;
    block
        .body()
        .transactions
        .par_iter()
        .map(|tx| alloy_primitives::Bytes::from(alloy_eips::eip2718::Encodable2718::encoded_2718(tx)))
        .collect()
}

/// Whether a build this node kept executes as the sealed block does. The
/// build is found by its parent, number and -- under deferred execution --
/// the parent's result, all of which a sibling on the same parent shares,
/// and the sealed header takes the payload's beneficiary, timestamp, randao,
/// gas limit and base fee; so two blocks of equal transactions (two empty
/// ones, typically after a view change) matched, and the build's execution
/// was filed under the other block's hash (loop157 W: node4 filed its own
/// empty block 183's state root under node2's, and refused block 184). The
/// seal changes none of these fields -- only the view in the extra data --
/// so a block of ours always passes, and a block whose fields differ from the
/// build's is never executed as the build.
fn build_executes_as_sealed(
    built: &alloy_consensus::Header,
    built_withdrawals: Option<&[alloy_eips::eip4895::Withdrawal]>,
    sealed: &alloy_consensus::Header,
    payload_withdrawals: Option<&[alloy_eips::eip4895::Withdrawal]>,
) -> bool {
    built.beneficiary == sealed.beneficiary
        && built.timestamp == sealed.timestamp
        && built.mix_hash == sealed.mix_hash
        && built.gas_limit == sealed.gas_limit
        && built.base_fee_per_gas == sealed.base_fee_per_gas
        && built.parent_beacon_block_root == sealed.parent_beacon_block_root
        && built.transactions_root == sealed.transactions_root
        && built_withdrawals.unwrap_or_default() == payload_withdrawals.unwrap_or_default()
}

/// The hand-off of a build this node kept, under the sealed header consensus
/// gave it: the sealed block registered for the engine's own conversion, the
/// build's execution inserted as executed, the QMDB root filed under the
/// sealed hash, the queue told, the pool pruned. Shared by the payload path
/// (`reuse_own_build`) and the header-only path (`request::OWN_BLOCK`).
async fn hand_off_own_build<T>(
    reuse: &OwnBlockReuse,
    built_hash: B256,
    built: n42_engine_types::built_executions::BuiltExecution,
    sealed_header: reth_primitives_traits::SealedHeader,
    converted: std::time::Duration,
) -> Option<B256>
where
    T: PayloadTypes<ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    let started = std::time::Instant::now();
    let block_number = sealed_header.number;
    let sealed_hash = sealed_header.hash();
    // The build's block is moved out when this is its last holder (the
    // registry gave it up in `take`): one clone of the 163,000-transaction
    // body for the engine's copy instead of two.
    let (body, senders) = match std::sync::Arc::try_unwrap(built.block) {
        Ok(block) => {
            let (sealed, senders) = block.split_sealed();
            (sealed.split_sealed_header_body().1, senders)
        }
        Err(shared) => (shared.body().clone(), shared.senders().to_vec()),
    };
    // For the engine's newPayload of this block, which follows the hand-off:
    // its conversion finds the block here instead of decoding the payload.
    n42_engine_types::built_executions::remember_sealed(
        sealed_hash,
        SealedBlock::from_sealed_parts(sealed_header.clone(), body.clone()),
    );
    let recovered: reth_primitives_traits::RecoveredBlock<n42_tx_types::Block> = reth_primitives_traits::RecoveredBlock::new_sealed(
        SealedBlock::from_sealed_parts(sealed_header, body),
        senders,
    );
    // For the pool prune below, taken now: the block moves into the engine's
    // insert.
    let pool_prune_hashes: Option<Vec<B256>> = reuse
        .prune_pool
        .is_some()
        .then(|| recovered.body().transactions().map(|tx| *tx.tx_hash()).collect::<Vec<B256>>());
    if let Some(qmdb) = &reuse.qmdb {
        if let Err(err) = n42_engine_types::chain_alias::rename(qmdb, built_hash, sealed_hash) {
            warn!(target: "n42.payload_serve", %err, %built_hash, %sealed_hash, "could not file the build's QMDB root under the sealed hash; importing the ordinary way");
            return None;
        }
    }
    // The build's own execution result, recorded by the builder under the
    // build's hash: under deferred execution the next block's header is
    // checked against it under the sealed hash.
    if built_hash != sealed_hash {
        if let Some(fields) = n42_engine_types::executed_fields::get(&built_hash) {
            n42_engine_types::executed_fields::remember(sealed_hash, fields);
        }
    }
    let executed = reth_payload_primitives::BuiltPayloadExecutedBlock::<n42_tx_types::N42Primitives> {
        recovered_block: std::sync::Arc::new(recovered),
        execution_output: built.execution_output,
        hashed_state: built.hashed_state,
        trie_updates: built.trie_updates,
    };
    // The block's transactions leave the queue before this returns, as a
    // foreign block's do: the build ahead starts on the return, and a queue
    // that still lists this build as the last one gives its 163,000
    // transactions back to the lanes at the next build's start (57 ms of a
    // full block's build, under the lock) for the canonical pruner to take
    // out again 100 ms later (78 ms, waiting on the same lock).
    //
    // Not by removing them from the lanes (`remove_mined_batch`: 39-51 ms
    // here, most of it freeing the 163,000 transactions its retain drops)
    // but by forgetting the mined part of the build's taken list, with the
    // drop on a blocking thread. Forgetting the *whole* list lost the
    // puller's batches in flight when the block filled -- a few thousand
    // transactions across every sender -- and every sender's lane then
    // started above the chain's nonce (loop29E400a: 7% occupancy).
    let queue_prune_ms = n42_tx_queue::global::<n42_engine_types::N42PooledTransaction>().map(|queue| {
        let at = std::time::Instant::now();
        let mined = executed
            .recovered_block
            .transactions_with_sender()
            .map(|(sender, tx)| (*sender, alloy_consensus::Transaction::nonce(tx)));
        let dropped = queue.forget_mined(executed.recovered_block.header().parent_hash, mined);
        debug!(target: "n42.payload_serve", forgotten = dropped.len(), "own block's transactions forgotten by the queue");
        // Held, not dropped, until the chain settles this height: a block
        // consensus never commits gives them back (round 43).
        queue.hold_own_block(executed.recovered_block.number(), executed.recovered_block.hash(), dropped);
        at.elapsed().as_millis() as u64
    });
    let (done, handed) = tokio::sync::oneshot::channel();
    if reuse
        .inserts
        .send(reth_node_builder::executed_inserts::ExecutedInsert { block: Box::new(executed), done })
        .is_err()
    {
        return None;
    }
    let handed = tokio::time::timeout(std::time::Duration::from_secs(2), handed).await;
    match handed {
        Ok(Ok(true)) => {
            crate::follower_import::note_import_landed();
            if let (Some(prune), Some(hashes)) = (reuse.prune_pool.clone(), pool_prune_hashes) {
                let count = hashes.len();
                let pruned_at = std::time::Instant::now();
                // Synchronous, on a blocking thread: the removal holds the
                // pool's write lock, and it has to be done before this returns
                // so the next build, armed by this import, starts on a pool
                // without them.
                let _ = tokio::task::spawn_blocking(move || prune(hashes)).await;
                info!(
                    target: "n42.payload_serve",
                    count,
                    prune_ms = pruned_at.elapsed().as_millis() as u64,
                    "own block's transactions taken out of the pool"
                );
            }
            info!(
                target: "n42.payload_serve",
                number = block_number,
                convert_ms = converted.as_millis() as u64,
                queue_prune_ms,
                total_ms = started.elapsed().as_millis() as u64,
                "own block handed to the engine as executed"
            );
            Some(built_hash)
        }
        other => {
            warn!(target: "n42.payload_serve", ?other, "the engine did not take our executed block; importing the ordinary way");
            None
        }
    }
}

/// A block this node built, imported by its sealed header alone
/// (`request::OWN_BLOCK`): the build is found by the header's parent, number
/// and roots, handed to the engine as executed under the sealed hash, and
/// the engine's `newPayload` then runs on a payload assembled here from the
/// build's own transactions -- 19 MB that no longer cross the wire twice.
/// Returns the status, the block number, and the hand-off and payload
/// assembly times in milliseconds; an `Err` is the message to send back
/// (`unknown build`), on which the caller sends the payload the old way.
async fn own_block_by_header<T>(
    reuse: Option<&OwnBlockReuse>,
    engine: &ConsensusEngineHandle<T>,
    frame: &[u8],
) -> Result<(alloy_rpc_types_engine::PayloadStatus, u64, u64, u64), String>
where
    T: PayloadTypes<BuiltPayload = N42BuiltPayload, ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    use alloy_rlp::Decodable;
    let reuse = reuse.ok_or("no own-block reuse on this node")?;
    let header = alloy_consensus::Header::decode(&mut &frame[..]).map_err(|e| format!("header: {e}"))?;
    if header.block_access_list_hash.is_some() {
        // The build registry does not keep the access list the payload
        // carries; the payload path does.
        return Err("unknown build: block access list".to_owned());
    }
    // Taken out of the registry, so the hand-off can move the body instead
    // of cloning it -- unless the validator builds on seal: then a
    // `BUILD_ON_OWN` for this same block is on another connection at this
    // very moment and must still find it (loop110 S1: taking it here won
    // the race on 383 of 384 blocks, every build on seal was refused, and the
    // leader fell back to building on its critical path). Left in place, the
    // registry's own bound (two builds) retires it two blocks later; the
    // hand-off clones the body once (~10 ms, beside the leader's chain now).
    // On a thread: a build that sealed before its finish is waited for
    // (docs/PHASE_D_DEFERRED_EXECUTION.md section 13), and that wait must
    // not hold a runtime worker.
    let (parent_hash, number, state_root, receipts_root, gas_used, transactions_root) =
        (header.parent_hash, header.number, header.state_root, header.receipts_root, header.gas_used, Some(header.transactions_root));
    let stage = crate::follower_import::HandoffStage(number);
    stage.at(1);
    let (built_hash, built) = tokio::task::spawn_blocking(move || {
        if build_on_seal() {
            n42_engine_types::built_executions::find(parent_hash, number, state_root, receipts_root, gas_used, transactions_root)
        } else {
            n42_engine_types::built_executions::take(parent_hash, number, state_root, receipts_root, gas_used, transactions_root)
        }
    })
    .await
    .map_err(|err| format!("build lookup: {err}"))?
    .ok_or("unknown build")?;
    let sealed_hash = header.hash_slow();
    let sealed_header = reth_primitives_traits::SealedHeader::new(header.clone(), sealed_hash);
    let withdrawals = built.block.body().withdrawals.clone().map(|w| w.to_vec()).unwrap_or_default();
    // The transactions travel with the `newPayload` below. reth executes a
    // payload for as many transactions as the payload itself lists, whatever
    // block its conversion returns, and it executes this one whenever the
    // executed insert did not land first -- dropped as outdated when a sibling
    // was made canonical a moment before, which no check of the head here can
    // rule out. An empty list then executed a full block as empty: no receipts,
    // none of its state changes in the tree, and every block this node built
    // on it carried nonces the chain had mined (loop157 V3/C4/V4, loop158 V5).
    // Encoded on the worker pool, a few milliseconds at 163,000.
    let raw_transactions = match listed_for(built_hash) {
        // Kept from the `getPayload` that served this very block a few
        // milliseconds ago: the same 163,000 encodings, and the leader's
        // worker pool is wanted by the next build by now.
        Some(listed) => listed.as_ref().clone(),
        None => {
            let block = std::sync::Arc::clone(&built.block);
            tokio::task::spawn_blocking(move || encoded_transactions(&block))
                .await
                .map_err(|err| format!("encoding the transactions: {err}"))?
        }
    };
    // A block that forks from the engine's head (a sibling re-proposed
    // after a TC): the head goes back to the parent first, or the tree
    // drops the executed insert as outdated and executes the payload
    // itself, on the fork path. See `OwnBlockReuse::canonical_head`.
    if let Some(head) = reuse.canonical_head.as_ref().and_then(|current| current()) {
        if head != header.parent_hash {
            let moved_at = std::time::Instant::now();
            let state = alloy_rpc_types_engine::ForkchoiceState {
                head_block_hash: header.parent_hash,
                safe_block_hash: header.parent_hash,
                finalized_block_hash: header.parent_hash,
            };
            match engine.fork_choice_updated(state, None).await {
                Ok(updated) => info!(
                    target: "n42.payload_serve",
                    number, parent = ?header.parent_hash, engine_head = ?head, status = ?updated.payload_status.status,
                    moved_ms = moved_at.elapsed().as_millis() as u64,
                    "own block forks from the engine's head; the head was moved to its parent first"
                ),
                Err(err) => warn!(
                    target: "n42.payload_serve",
                    number, parent = ?header.parent_hash, engine_head = ?head, %err,
                    "own block forks from the engine's head and the head could not be moved to its parent"
                ),
            }
        }
    }
    let handoff_at = std::time::Instant::now();
    stage.at(2);
    hand_off_own_build::<T>(reuse, built_hash, built, sealed_header, std::time::Duration::ZERO)
        .await
        .ok_or("the engine did not take the executed block")?;
    let handoff_ms = handoff_at.elapsed().as_millis() as u64;
    // The payload for the engine's `newPayload`: its conversion takes the
    // sealed block registered above by the payload's block hash before it
    // looks at anything else, so nothing is decoded; the transactions are
    // there for the execution that follows a dropped insert (see above). If
    // the engine ever answered other than Valid, the validator's fallback
    // sends the whole payload and the engine converts it the ordinary way.
    let payload_at = std::time::Instant::now();
    stage.at(3);
    let data = n42_h2_consensus::execution_data_from_raw_parts(sealed_hash, &header, raw_transactions, withdrawals, None);
    let payload_ms = payload_at.elapsed().as_millis() as u64;
    stage.at(4);
    let status = engine.new_payload(data).await.map_err(|e| format!("engine: {e}"))?;
    drop(stage);
    if !status.status.is_valid() {
        return Err(format!("engine answered {:?} to the header-only payload", status.status));
    }
    Ok((status, header.number, handoff_ms, payload_ms))
}

/// Where a build on an own block spent its time, for the log line.
///
/// `decode_ms` .. `spawn_ms` are the road from the request landing to the
/// builder actually starting, which loop190/191 measured at 33-42 ms without
/// naming it: `queue_ms` was the only piece with a name and the rest was read
/// off the difference between two other lines. With `frame_ms` (added in the
/// serving arm, from the request's first byte) they sum to exactly that road,
/// so a leg can say where it went instead of inferring it.
#[derive(Debug, Default, Clone, Copy)]
struct BuildOnOwnTimes {
    decode_ms: u64,
    find_ms: u64,
    queue_ms: u64,
    rename_ms: u64,
    spawn_ms: u64,
    build_ms: u64,
    /// Built at the parent's seal (`N42_BUILD_ON_OUTPUT`): `queue_ms` ran
    /// beside the build then, not ahead of it.
    on_output: bool,
    /// `queue_ms` split: the fold of the block's nonces, the lock waits, the
    /// partition under the lock (`TxQueue::forget_mined_timed`).
    queue_fold_us: u64,
    queue_lock_us: u64,
    queue_partition_us: u64,
}

/// The next block, built on a block this node built and consensus has just
/// sealed (`request::BUILD_ON_OWN`) -- before the engine has imported that
/// block, and without the forkchoice and the payload service that used to
/// stand between the seal and the build (own import 62 ms + forkchoice 72 +
/// service ~35 on the leader's chain, loop108; `docs/FLEET7_PLAN_V2.md`).
///
/// The parent is found in the build registry by the sealed header's parent,
/// number, roots and gas, exactly as the header-only import finds it, and is
/// *not* taken out: that import follows and takes it. What this does first is
/// what the import's hand-off would otherwise do before the next build could
/// start: the queue forgets the parent's mined transactions (or the build
/// would select them again), and the QMDB tree moves to the sealed hash (the
/// hand-off's later rename finds it there and is content). Then the builder
/// runs on a blocking thread with the parent's bundle laid over the chain's
/// state. An `Err` is the message sent back, on which the validator builds
/// ahead the ordinary way.
async fn build_on_own_block(
    reuse: Option<&OwnBlockReuse>,
    frame: &[u8],
) -> Result<(N42BuiltPayload, BuildOnOwnTimes, Option<raw_engine::ChainHint>, bool), String> {
    let decode_at = std::time::Instant::now();
    let reuse = reuse.ok_or("no own-block reuse on this node")?;
    let builder = n42_engine_types::direct_build::get().ok_or("no direct builder")?;
    let (header, attributes, chain, want_hashes) = raw_engine::decode_build_on_own(frame)?;
    if header.block_access_list_hash.is_some() {
        return Err("unknown build: block access list".to_owned());
    }
    let mut times = BuildOnOwnTimes { decode_ms: decode_at.elapsed().as_millis() as u64, ..Default::default() };
    // A parent this node did not build -- the previous leader's last block,
    // at a tenure's first build -- is not in the build registry; with the
    // flag it is built on the output this node's follower execution of it
    // published, instead of the request being refused and the leader going
    // through the forkchoice and the payload job.
    if tenure_first_on_output()
        && n42_engine_types::built_executions::find_kept_sealed(
            header.parent_hash,
            header.number,
            header.state_root,
            header.receipts_root,
            header.gas_used,
            Some(header.transactions_root),
        )
        .is_none()
    {
        return build_on_published_output(builder, header, attributes, chain, want_hashes, times).await;
    }
    if build_on_output() {
        return build_on_sealed_output(reuse, builder, header, attributes, chain, want_hashes, times).await;
    }
    let at = std::time::Instant::now();
    // The parent's post-state is what the build needs (`StateReady`); a
    // parent sealed before its finish is waited for, on a thread.
    let (parent_hash, number, state_root, receipts_root, gas_used) =
        (header.parent_hash, header.number, header.state_root, header.receipts_root, header.gas_used);
    let transactions_root = Some(header.transactions_root);
    let (built_hash, built) = tokio::task::spawn_blocking(move || {
        n42_engine_types::built_executions::find_kept_at(
            parent_hash,
            number,
            state_root,
            receipts_root,
            gas_used,
            transactions_root,
            n42_engine_types::built_executions::Stage::StateReady,
        )
    })
    .await
    .map_err(|err| format!("build lookup: {err}"))?
    .ok_or("unknown build")?;
    times.find_ms = at.elapsed().as_millis() as u64;
    let sealed_hash = header.hash_slow();
    let parent = reth_primitives_traits::SealedHeader::new(header, sealed_hash);
    // The parent's transactions leave the build's taken list now, held until
    // the chain settles the height -- the same bookkeeping as the hand-off,
    // which finds nothing left to forget when it runs.
    if let Some(queue) = n42_tx_queue::global::<n42_engine_types::N42PooledTransaction>() {
        let at = std::time::Instant::now();
        let txs = built.block.body().transactions().count();
        let (dropped, forget) = if build_start_async() {
            let (body, senders): (&[_], &[_]) = (&built.block.body().transactions, built.block.senders());
            queue.forget_mined_parallel(built.block.header().parent_hash, body.len().min(senders.len()), |i| {
                (senders[i], alloy_consensus::Transaction::nonce(&body[i]))
            })
        } else {
            let mined = built
                .block
                .transactions_with_sender()
                .map(|(sender, tx)| (*sender, alloy_consensus::Transaction::nonce(tx)));
            queue.forget_mined_timed(built.block.header().parent_hash, mined)
        };
        (times.queue_fold_us, times.queue_lock_us, times.queue_partition_us) =
            (forget.fold_us, forget.lock_us, forget.partition_us);
        // At info: `forgotten` far below `txs` is the shape of the queue
        // defect this pairs with -- the build's take was already given back
        // to the lanes by a second build on the same parent, so there is
        // nothing left here to forget and nothing to hold (round 44).
        info!(
            target: "n42.payload_serve",
            number = built.block.number(),
            txs,
            forgotten = dropped.len(),
            parent = ?built.block.header().parent_hash,
            "own block's transactions forgotten by the queue ahead of the build"
        );
        queue.hold_own_block(built.block.number(), sealed_hash, dropped);
        times.queue_ms = at.elapsed().as_millis() as u64;
    }
    if let Some(qmdb) = &reuse.qmdb {
        let at = std::time::Instant::now();
        // A parent still finishing behind its seal has no tree yet; the
        // build renames it under the sealed hash when it needs it.
        // A parent still behind its seal is computing its root under the
        // forest's lock right now, and has filed nothing yet: asking would
        // wait out that computation for an answer of `None`.
        use n42_engine_types::built_executions::{stage_of, Stage};
        let finishing = matches!(stage_of(built_hash), Some(Stage::Sealed | Stage::StateReady));
        if !finishing && qmdb.root_of(&built_hash).is_some() {
            n42_engine_types::chain_alias::rename(qmdb, built_hash, sealed_hash)
                .map_err(|err| format!("qmdb rename: {err}"))?;
        }
        times.rename_ms = at.elapsed().as_millis() as u64;
    }
    let at = std::time::Instant::now();
    let request = n42_engine_types::direct_build::BuildOnOwnRequest {
        parent,
        parent_execution: n42_engine_types::direct_build::ParentExecution::Ready(built),
        attributes,
        before_pull: None,
    };
    // `spawn_ms` is the hop onto the blocking pool. Named because it was the
    // last unnamed piece of the request-to-start road, and because a blocking
    // pool with every thread busy is somewhere a leader's build can wait with
    // nothing saying so.
    let handle = tokio::task::spawn_blocking(move || builder.build_on_own(request));
    times.spawn_ms = at.elapsed().as_millis() as u64;
    let payload = handle.await.map_err(|err| format!("build task: {err}"))??;
    times.build_ms = at.elapsed().as_millis() as u64;
    Ok((payload, times, chain, want_hashes))
}

/// `N42_BUILD_START_ASYNC=1` (plan v6, the seal gap's first term): the
/// queue's hand-off of an own block -- the fold of its nonces and the
/// partition of the build's taken list -- runs on the queue's own pool
/// (`TxQueue::forget_mined_parallel`) instead of on one thread. A chained
/// build's first pull waits for that hand-off, and it was all of the
/// 19-21 ms before the build's parallel step (loop239: `queue_ms` 19-21
/// against `par_start_ms` 19-21; `start_handoff_ms` on the build's line
/// now says so directly). Off by default.
fn build_start_async() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BUILD_START_ASYNC").is_ok_and(|v| v == "1"))
}

/// `N42_BUILD_ON_OUTPUT=1`: a build on an own block starts at the parent's
/// seal instead of at its `StateReady` (plan v6 attempt J). Off by default.
fn build_on_output() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BUILD_ON_OUTPUT").is_ok_and(|v| v == "1"))
}

/// `N42_TENURE_FIRST_ON_OUTPUT=1` (defect 18b, `docs/FLEET7_PLAN_V4.md`
/// 7.13): a build request on a sealed parent this node did not build is served
/// on the parent's published follower output ([`build_on_published_output`])
/// instead of being refused. The validator sends such a request for the first
/// build of its tenure. Off by default.
fn tenure_first_on_output() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_TENURE_FIRST_ON_OUTPUT").is_ok_and(|v| v == "1"))
}

/// How long the first build of a tenure waits for this node's follower
/// execution of the parent to publish its output. The execution runs beside
/// the vote and ends ~80-160 ms after it on a full block; a parent not
/// executed by then is refused, and the leader builds the ordinary way.
const PUBLISHED_OUTPUT_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

/// The first build of a tenure: the next block on a peer's block this node
/// executed as a follower (`N42_TENURE_FIRST_ON_OUTPUT`).
///
/// The new leader's engine may not hold the parent yet -- a follower's
/// import runs behind its votes -- and the forkchoice the ordinary path
/// starts its build with is answered SYNCING until it does (loop251: 5.3-9.1 s
/// at every tenure handover, the view timing out). This node has already
/// executed the parent, though: its import published the output for the
/// child's check (`follower_import::publish_parent_output`). The build reads
/// that output (and any unimported ancestors' outputs) laid over the chain's
/// state at the nearest ancestor below them -- the follower's own overlay --
/// and the header's parent fields come from the follower's filed execution
/// fields under the parent's sealed hash, as for any parent.
///
/// The queue learns of the parent's transactions from its bundle: every
/// account in it whose nonce moved has its lane cut below its post-state
/// nonce (the follower's own hand-off, which follows, finds nothing left),
/// and the cut transactions are held until the chain settles the height.
async fn build_on_published_output(
    builder: std::sync::Arc<dyn n42_engine_types::direct_build::DirectBuilder>,
    header: alloy_consensus::Header,
    attributes: alloy_rpc_types_engine::PayloadAttributes,
    chain: Option<raw_engine::ChainHint>,
    want_hashes: bool,
    mut times: BuildOnOwnTimes,
) -> Result<(N42BuiltPayload, BuildOnOwnTimes, Option<raw_engine::ChainHint>, bool), String> {
    times.on_output = true;
    let at = std::time::Instant::now();
    let sealed_hash = header.hash_slow();
    let number = header.number;
    let ancestry = tokio::task::spawn_blocking(move || {
        crate::follower_import::published_ancestry(sealed_hash, PUBLISHED_OUTPUT_WAIT)
    })
    .await
    .map_err(|err| format!("published output lookup: {err}"))?
    .map_err(|why| {
        info!(target: "n42.payload_serve", number, parent = ?sealed_hash, why, "first build of the tenure not on the parent's published output");
        format!("unknown build: no published output for the parent ({why})")
    })?;
    times.find_ms = at.elapsed().as_millis() as u64;
    info!(
        target: "n42.payload_serve",
        number,
        parent = ?sealed_hash,
        waited_ms = ancestry.waited.as_millis() as u64,
        depth = ancestry.executed.len(),
        anchor = ?ancestry.anchor,
        "first build of the tenure on the parent's published output"
    );
    let (hand_off, before_pull) = match n42_tx_queue::global::<n42_engine_types::N42PooledTransaction>() {
        Some(queue) => {
            let (done, handed) = std::sync::mpsc::sync_channel::<()>(1);
            let output = std::sync::Arc::clone(&ancestry.output);
            let task = tokio::task::spawn_blocking(move || {
                let at = std::time::Instant::now();
                let mined = output.state.state.iter().filter_map(|(sender, account)| {
                    account.info.as_ref().filter(|info| info.nonce > 0).map(|info| (*sender, info.nonce - 1))
                });
                let removed = queue.remove_mined_batch_collecting(mined);
                let forgotten = removed.len();
                queue.hold_own_block(number, sealed_hash, removed);
                let _ = done.send(());
                info!(
                    target: "n42.payload_serve",
                    number,
                    forgotten,
                    queue_ms = at.elapsed().as_millis() as u64,
                    "the parent's transactions taken out of the queue from its published bundle"
                );
                at.elapsed().as_millis() as u64
            });
            (Some(task), Some(handed))
        }
        None => (None, None),
    };
    let parent = reth_primitives_traits::SealedHeader::new(header, sealed_hash);
    let at = std::time::Instant::now();
    let request = n42_engine_types::direct_build::BuildOnOwnRequest {
        parent,
        parent_execution: n42_engine_types::direct_build::ParentExecution::Published {
            parent_hash: sealed_hash,
            executed: ancestry.executed,
            anchor: ancestry.anchor,
        },
        attributes,
        before_pull,
    };
    let handle = tokio::task::spawn_blocking(move || builder.build_on_own(request));
    times.spawn_ms = at.elapsed().as_millis() as u64;
    let payload = handle.await.map_err(|err| format!("build task: {err}"));
    times.build_ms = at.elapsed().as_millis() as u64;
    if let Some(task) = hand_off
        && let Ok(queue_ms) = task.await
    {
        times.queue_ms = queue_ms;
    }
    Ok((payload??, times, chain, want_hashes))
}

/// [`build_on_own_block`] started at the parent's seal (`N42_BUILD_ON_OUTPUT`).
///
/// The chained request arrives a few ms after the parent's early seal, and
/// the parent's finish then still has 15-19 ms to go before its post-state
/// is filed (`state_ready_ms`, the ~147,000 reverts appended), which the
/// ordinary path waited out (`find_ms` 15-20 on chained builds, loop223)
/// before the queue's hand-off (`queue_ms` 13-16) and only then the build.
/// Here the parent is found at its seal without waiting, the hand-off runs
/// on a thread of its own, and the build starts at once: it waits for the
/// parent's output where it opens its state (`opener_on_sealed_parent`, the
/// same overlay on the same output) and for the hand-off before its first
/// pull, so the queue's order is the ordinary path's. The build's root
/// still stands on the parent's installed tree: its finish waits for that
/// behind its own seal, as before.
async fn build_on_sealed_output(
    reuse: &OwnBlockReuse,
    builder: std::sync::Arc<dyn n42_engine_types::direct_build::DirectBuilder>,
    header: alloy_consensus::Header,
    attributes: alloy_rpc_types_engine::PayloadAttributes,
    chain: Option<raw_engine::ChainHint>,
    want_hashes: bool,
    mut times: BuildOnOwnTimes,
) -> Result<(N42BuiltPayload, BuildOnOwnTimes, Option<raw_engine::ChainHint>, bool), String> {
    use n42_engine_types::built_executions::{find_kept_sealed, stage_of, Stage};
    times.on_output = true;
    let at = std::time::Instant::now();
    let (built_hash, block, _) = find_kept_sealed(
        header.parent_hash,
        header.number,
        header.state_root,
        header.receipts_root,
        header.gas_used,
        Some(header.transactions_root),
    )
    .ok_or("unknown build")?;
    times.find_ms = at.elapsed().as_millis() as u64;
    let sealed_hash = header.hash_slow();
    let parent = reth_primitives_traits::SealedHeader::new(header, sealed_hash);
    // The parent's transactions leave the build's taken list, held until the
    // chain settles the height -- the ordinary path's bookkeeping, beside the
    // build rather than ahead of it; the build's pull waits for `handed`.
    let (hand_off, before_pull) = match n42_tx_queue::global::<n42_engine_types::N42PooledTransaction>() {
        Some(queue) => {
            let (done, handed) = std::sync::mpsc::sync_channel::<()>(1);
            let task = tokio::task::spawn_blocking(move || {
                let at = std::time::Instant::now();
                let txs = block.body().transactions().count();
                let (dropped, forget) = if build_start_async() {
                    let (body, senders): (&[_], &[_]) = (&block.body().transactions, block.senders());
                    queue.forget_mined_parallel(block.header().parent_hash, body.len().min(senders.len()), |i| {
                        (senders[i], alloy_consensus::Transaction::nonce(&body[i]))
                    })
                } else {
                    let mined = block
                        .transactions_with_sender()
                        .map(|(sender, tx)| (*sender, alloy_consensus::Transaction::nonce(tx)));
                    queue.forget_mined_timed(block.header().parent_hash, mined)
                };
                info!(
                    target: "n42.payload_serve",
                    number = block.number(),
                    txs,
                    forgotten = dropped.len(),
                    parent = ?block.header().parent_hash,
                    "own block's transactions forgotten by the queue beside the build"
                );
                queue.hold_own_block(block.number(), sealed_hash, dropped);
                let _ = done.send(());
                (at.elapsed().as_millis() as u64, forget)
            });
            (Some(task), Some(handed))
        }
        None => (None, None),
    };
    if let Some(qmdb) = &reuse.qmdb {
        let at = std::time::Instant::now();
        // As the ordinary path: a parent still behind its seal has filed no
        // tree yet, and its successor's finish renames it when it needs it.
        let finishing = matches!(stage_of(built_hash), Some(Stage::Sealed | Stage::StateReady));
        if !finishing && qmdb.root_of(&built_hash).is_some() {
            n42_engine_types::chain_alias::rename(qmdb, built_hash, sealed_hash)
                .map_err(|err| format!("qmdb rename: {err}"))?;
        }
        times.rename_ms = at.elapsed().as_millis() as u64;
    }
    let at = std::time::Instant::now();
    let request = n42_engine_types::direct_build::BuildOnOwnRequest {
        parent,
        parent_execution: n42_engine_types::direct_build::ParentExecution::Sealed { built_hash },
        attributes,
        before_pull,
    };
    let handle = tokio::task::spawn_blocking(move || builder.build_on_own(request));
    times.spawn_ms = at.elapsed().as_millis() as u64;
    let payload = handle.await.map_err(|err| format!("build task: {err}"));
    times.build_ms = at.elapsed().as_millis() as u64;
    // The hand-off ended before the build pulled; its times are for the line.
    if let Some(task) = hand_off
        && let Ok((queue_ms, forget)) = task.await
    {
        times.queue_ms = queue_ms;
        times.queue_fold_us = forget.fold_us;
        times.queue_lock_us = forget.lock_us;
        times.queue_partition_us = forget.partition_us;
    }
    Ok((payload??, times, chain, want_hashes))
}

/// Writes a built payload in the channel's answer shape (status 1, the
/// block's RLP, the requests, the access list); returns the block's size and
/// how long the encoding took.
/// [`push_built_payload`] with the block's transaction hashes appended, for
/// a caller that will build a compact body out of them
/// (`request::GET_PAYLOAD_HASHED`, `BUILD_ON_OWN`'s hash tail).
///
/// The hashes are the ones already cached on the transactions the builder
/// selected -- `tx_hash()` is a read, not a keccak -- so this is 32 bytes a
/// transaction copied, against a keccak over the block's 26 MB if the
/// caller had to find them for itself on its proposal path.
fn push_built_payload_hashed(
    out: &mut Vec<u8>,
    payload: &N42BuiltPayload,
    with_hashes: bool,
) -> (usize, std::time::Duration) {
    let answer = push_built_payload(out, payload);
    if with_hashes {
        use alloy_consensus::transaction::TxHashRef as _;
        let transactions = &payload.block().body().transactions;
        // A block built from whole frames (`N42_FRAME_BLOCKS=1`): marker 2,
        // the hashes as ever and the frame layout after them, for the frame
        // description (`n42_h2_consensus::encode_compact_frame_body`).
        let layout = n42_engine_types::frame_blocks::active()
            .then(|| n42_engine_types::frame_blocks::layout_by_root(&payload.block().header().transactions_root))
            .flatten()
            .filter(|layout| !layout.is_empty());
        out.push(if layout.is_some() { 2 } else { 1 });
        out.extend_from_slice(&(transactions.len() as u32).to_le_bytes());
        for tx in transactions {
            out.extend_from_slice(tx.tx_hash().as_slice());
        }
        if let Some(layout) = layout {
            out.extend_from_slice(&(layout.len() as u32).to_le_bytes());
            for (id, count) in &layout {
                out.extend_from_slice(id.as_slice());
                out.extend_from_slice(&count.to_le_bytes());
            }
        }
    }
    answer
}

fn push_built_payload(out: &mut Vec<u8>, payload: &N42BuiltPayload) -> (usize, std::time::Duration) {
    let encode_at = std::time::Instant::now();
    let (block, listed) = encode_block_parallel_keeping_transactions(payload.block());
    remember_listed(payload.block().hash(), listed);
    let encoded = encode_at.elapsed();
    out.reserve(block.len() + 64);
    out.push(1);
    out.extend_from_slice(&(block.len() as u32).to_le_bytes());
    out.extend_from_slice(&block);
    match payload.requests() {
        Some(requests) => {
            let requests = requests.take();
            out.push(1);
            out.extend_from_slice(&(requests.len() as u32).to_le_bytes());
            for request in &requests {
                out.extend_from_slice(&(request.len() as u32).to_le_bytes());
                out.extend_from_slice(request);
            }
        }
        None => out.push(0),
    }
    match payload.block_access_list() {
        Some(bal) => {
            out.push(1);
            out.extend_from_slice(&(bal.len() as u32).to_le_bytes());
            out.extend_from_slice(bal);
        }
        None => out.push(0),
    }
    (block.len(), encoded)
}

/// The sealed header a payload describes, given the build it came from: the
/// payload's fields where the seal may have touched them, the build's where it
/// cannot. `None` if the shapes disagree; the caller checks the hash.
fn sealed_header_from_fields(
    data: &alloy_rpc_types_engine::ExecutionData,
    built: &alloy_consensus::Header,
) -> Option<reth_primitives_traits::SealedHeader> {
    let v1 = data.payload.as_v1();
    if v1.block_number != built.number || v1.parent_hash != built.parent_hash {
        return None;
    }
    let mut header = built.clone();
    header.beneficiary = v1.fee_recipient;
    header.state_root = v1.state_root;
    header.receipts_root = v1.receipts_root;
    header.logs_bloom = v1.logs_bloom;
    header.mix_hash = v1.prev_randao;
    header.gas_limit = v1.gas_limit;
    header.gas_used = v1.gas_used;
    header.timestamp = v1.timestamp;
    header.extra_data = v1.extra_data.clone();
    header.base_fee_per_gas = Some(v1.base_fee_per_gas.try_into().ok()?);
    // The fields gov5's profile is free to leave in either of two shapes --
    // the same candidates the engine's own conversion tries, a few dozen
    // header hashes at most.
    let expected = data.payload.block_hash();
    let withdrawals_roots: Vec<Option<B256>> = match (built.withdrawals_root, data.payload.as_v2()) {
        (Some(root), Some(v2)) => {
            let rewards = n42_h2_consensus::withdrawals_to_rewards(v2.withdrawals.as_slice());
            vec![Some(root), Some(n42_h2_consensus::gov5_rewards_root(rewards))]
        }
        (root, _) => vec![root],
    };
    let requests_hashes: Vec<Option<B256>> = match built.requests_hash {
        Some(hash) => vec![
            Some(hash),
            Some(n42_h2_consensus::GOV5_EMPTY_REQUESTS_HASH),
            Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
        ],
        None => vec![None],
    };
    for ommers_hash in [built.ommers_hash, B256::ZERO, alloy_consensus::EMPTY_OMMER_ROOT_HASH] {
        for difficulty in [built.difficulty, alloy_primitives::U256::ZERO, alloy_primitives::U256::from(1)] {
            for withdrawals_root in &withdrawals_roots {
                for requests_hash in &requests_hashes {
                    header.ommers_hash = ommers_hash;
                    header.difficulty = difficulty;
                    header.withdrawals_root = *withdrawals_root;
                    header.requests_hash = *requests_hash;
                    if header.hash_slow() == expected {
                        return Some(reth_primitives_traits::SealedHeader::new(header, expected));
                    }
                }
            }
        }
    }
    None
}

/// Whether the validators build on seal (`N42_BUILD_ON_SEAL`, the same
/// variable the validator reads; the fleet launcher sets it for both). It
/// decides whether the header-only import may take the build out of the
/// registry or must leave it for the `BUILD_ON_OWN` racing it.
fn build_on_seal() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BUILD_ON_SEAL").is_ok_and(|v| v != "0"))
}

/// `N42_RAW_SHARED_DECODE`, read once.
fn raw_shared_decode() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_RAW_SHARED_DECODE").is_ok_and(|v| v == "1"))
}

/// What a compact body's assembly refused with: the assembler's own verdict,
/// or something this side said before it ever got there.
enum CompactRefusal {
    Refused(CompactBodyError),
    Said(String),
}

impl std::fmt::Display for CompactRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(err) => write!(f, "{err}"),
            Self::Said(message) => f.write_str(message),
        }
    }
}

/// The largest miss worth asking for, as one part in `N42_COMPACT_BODY_FILL`
/// of the block: 2 by default, so up to half a block is fetched by index.
///
/// Above it the fill approaches the whole body's size and no longer pays for
/// a round trip and a second assembly; below it a fill is tens of kilobytes
/// against 26 megabytes (loop195: a median miss of 448 transactions of
/// 163,000, a p90 of ~7,000).
fn fill_share() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("N42_COMPACT_BODY_FILL")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|n: &usize| *n > 0)
            .unwrap_or(2)
    })
}

/// How long a compact body waits for this node's ingest to land a
/// transaction it named and the queue did not have: `N42_COMPACT_BODY_WAIT`
/// in milliseconds, 20 by default.
///
/// The ingest runs a few milliseconds behind the leader's block at worst --
/// the flood sends every transaction to every node -- so the wait is there
/// for that gap and not for a transaction that was never sent here. Waiting
/// longer than a view is worse than falling back: the fallback costs the
/// ordinary road, the wait costs the vote.
fn miss_wait() -> std::time::Duration {
    static WAIT: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();
    *WAIT.get_or_init(|| {
        std::time::Duration::from_millis(
            std::env::var("N42_COMPACT_BODY_WAIT").ok().and_then(|v| v.parse().ok()).unwrap_or(20),
        )
    })
}

/// `N42_PAYLOAD_SERVE_FRESH_BUFFERS`, read once.
fn fresh_buffers() -> bool {
    static FRESH: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FRESH.get_or_init(|| std::env::var("N42_PAYLOAD_SERVE_FRESH_BUFFERS").is_ok())
}

/// Puts the block by description's transaction list into its payload, once
/// the copy running beside the import has finished; nothing to do on every
/// other road. A copy that failed leaves the list empty, and the engine's
/// own pass then refuses the payload rather than executing an empty block
/// under the header: logged, because the direct import has already answered.
async fn complete_listing(
    data: &mut alloy_rpc_types_engine::ExecutionData,
    raw_transactions: &mut Vec<alloy_primitives::Bytes>,
    listing: &mut Option<tokio::task::JoinHandle<Vec<alloy_primitives::Bytes>>>,
    number: u64,
    // Whether anything reads `raw_transactions` after this: not once the
    // direct import has landed, which has the block's hashes already. The
    // copy is 163,000 `Bytes` clones (each an allocation, the first time a
    // `Vec`-backed one is shared) and as many releases when both are freed.
    keep_raw: bool,
) {
    let Some(pending) = listing.take() else { return };
    let waited_at = std::time::Instant::now();
    match pending.await {
        Ok(list) => {
            if keep_raw {
                raw_transactions.clone_from(&list);
            }
            data.payload.as_v1_mut().transactions = list;
        }
        Err(err) => warn!(target: "n42.payload_serve", number, %err, "the described block's payload list was not copied out"),
    }
    let waited_ms = waited_at.elapsed().as_millis() as u64;
    if waited_ms > 0 {
        debug!(target: "n42.payload_serve", number, waited_ms, "waited for the described block's payload list");
    }
}

/// Imports one block the validator handed over, whatever request carried it.
///
/// `data` is the payload the engine's own pass takes; `converted` is the
/// block itself when the caller already has it -- which the foreign-body
/// request does, because it decoded the body straight into one and there is
/// nothing left for `convert_payload_to_block` to do. Everything after that
/// point is the same for both: the direct import, the check answered ahead
/// of the execution, the queue and pool bookkeeping, and the engine's pass.
///
/// Writes the answer on `stream` itself, since under deferred execution the
/// check goes out before the verdict does.
#[allow(clippy::too_many_arguments)]
async fn import_for_validator<T>(
    stream: &mut TcpStream,
    out: &mut Vec<u8>,
    engine: &ConsensusEngineHandle<T>,
    reuse: Option<&OwnBlockReuse>,
    data: alloy_rpc_types_engine::ExecutionData,
    pre_converted: Option<SealedBlock<n42_tx_types::Block>>,
    // The senders the caller already has: the compact body road's, out of
    // this node's queue. `None` and the import recovers them as it always
    // did.
    pre_senders: Option<Vec<alloy_primitives::Address>>,
    // The block by description's payload list (`N42_BLOCK_BY_DESCRIPTION`):
    // `data` then lists no transactions, and they are copied out of the
    // encoded chunks beside the import and put back before the engine's own
    // pass -- the only reader of the list.
    payload_list: Option<n42_engine_types::engine_validator::PayloadList>,
    started: std::time::Instant,
    decoded: std::time::Duration,
    mut road: crate::follower_import::VoteRoad,
) -> std::io::Result<()>
where
    T: PayloadTypes<BuiltPayload = N42BuiltPayload, ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    let mut data = data;
    let number = data.payload.block_number();
    let txs = match (&payload_list, &pre_converted) {
        (Some(_), Some(block)) => block.body().transactions.len(),
        _ => data.payload.as_v1().transactions.len(),
    };
    // Copied on the blocking pool while the import runs; joined where the
    // list is first read.
    let mut listing = payload_list.map(|list| tokio::task::spawn_blocking(move || list.copy_out()));
    // One of ours, sealed: hand the engine the build's execution
    // first, and the newPayload below finds the block known.
    //
    // Timed on its own (`reuse_ms`): a foreign block pays this check too, and
    // it is a round trip to the blocking pool before the vote road's own
    // hand-off has even been made.
    let reuse_at = std::time::Instant::now();
    // Not on the described road: its payload has no list yet, and a
    // compact body is never one of this node's own builds (those arrive as
    // `request::OWN_BLOCK`).
    let reused = match reuse.filter(|_| listing.is_none()) {
        Some(reuse) => reuse_own_build::<T>(reuse, &data).await.is_some(),
        None => false,
    };
    road.reuse_us = reuse_at.elapsed().as_micros() as u64;
    // Everything copied between that check and the hand-off below is
    // `prepare_ms` in the vote road's line.
    let prepare_at = std::time::Instant::now();
    // The transactions' bytes, kept for the prune below; the
    // payload itself goes to the engine.
    let mut raw_transactions = data.payload.as_v1().transactions.clone();
    let probe = reuse.and_then(|r| r.exec_probe.clone()).filter(|_| !reused && txs > 10_000 && listing.is_none());
    let probe_data = probe.as_ref().map(|_| data.clone());
    // Another node's block: executed here and handed to the
    // engine as executed, when configured. Any failure logs
    // and leaves the block to the engine's own path.
    let mut direct_ms: Option<[u64; 16]> = None;
    // The block's transaction hashes, known once the direct
    // import converted the payload: the prune below then
    // needs no keccak over the raw bytes.
    let mut mined_hashes: Option<Vec<B256>> = None;
    // The sealed block being copied for the engine's own conversion, on a
    // worker thread; awaited before the pass that reads it.
    let mut remembering: Option<tokio::task::JoinHandle<()>> = None;
    if let Some(reuse) = reuse.filter(|r| !reused && r.import_foreign.is_some()) {
        let import = reuse.import_foreign.clone().expect("checked");
        let validator = reuse.validator.clone();
        let inserts = reuse.inserts.clone();
        // The block, when the caller decoded it from a body
        // (`request::FOREIGN_BODY`); otherwise the payload, converted on the
        // worker thread as before.
        let pre = pre_converted;
        let pre_senders = pre.is_some().then_some(pre_senders).flatten();
        let payload = pre.is_none().then(|| data.clone());
        let started = std::time::Instant::now();
        // Under deferred execution the import says when the
        // block is checked, and the validator hears it on a
        // CHECKED frame before the import's answer.
        let (checked_tx, checked_rx) = tokio::sync::oneshot::channel::<()>();
        road.prepare_us = prepare_at.elapsed().as_micros() as u64;
        // The hand-off itself: what the blocking pool costs before the import
        // runs is `dispatch_ms`, and nothing on the road can shorten it from
        // this side.
        let spawned = std::time::Instant::now();
        let handed = tokio::task::spawn_blocking(move || {
            let mut road = road;
            road.dispatch_us = spawned.elapsed().as_micros() as u64;
            let convert_at = std::time::Instant::now();
            let sealed = match (pre, payload) {
                (Some(sealed), _) => sealed,
                (None, Some(payload)) => <n42_engine_types::engine_validator::N42EngineValidator<reth_chainspec::ChainSpec> as reth_engine_primitives::PayloadValidator<T>>::convert_payload_to_block(&validator, payload)
                    .map_err(|err| format!("conversion: {err}"))?,
                (None, None) => return Err("no block and no payload to import".to_string()),
            };
            road.convert_us = convert_at.elapsed().as_micros() as u64;
            // The hand-off and the conversion together, so this stays the
            // `convert_ms` the direct-import line has always reported; the
            // vote road's line names the two apart.
            let converted = (road.dispatch_us + road.convert_us) / 1000;
            // The block the engine's own conversion takes instead of decoding
            // 163,000 transactions again is filed below, from the executed
            // block's `Arc` on a worker thread -- not here, where the clone
            // was on the vote road itself.
            let (executed, phases) = import(sealed, pre_senders, Some(checked_tx), road)?;
            Ok::<_, String>((executed, phases, converted))
        });
        tokio::pin!(handed);
        let mut finished = None;
        tokio::select! {
            checked = checked_rx => {
                if checked.is_ok() {
                    let status = alloy_rpc_types_engine::PayloadStatus::from_status(
                        alloy_rpc_types_engine::PayloadStatusEnum::Valid,
                    )
                    .with_latest_valid_hash(data.payload.block_hash());
                    let encoded = raw_engine::encode_payload_status(&status);
                    let mut frame = Vec::with_capacity(encoded.len() + 5);
                    frame.push(raw_engine::reply::CHECKED);
                    frame.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
                    frame.extend_from_slice(&encoded);
                    stream.write_all(&frame).await?;
                    info!(
                        target: "n42.payload_serve",
                        number,
                        txs,
                        checked_ms = started.elapsed().as_millis() as u64,
                        // The vote road's `total_ms` ends where the import
                        // released the check; this ends where the frame is on
                        // the wire, so the two together name the wake-up and
                        // the write as well.
                        released_ms = road.started.elapsed().as_millis() as u64,
                        "checked: answered before the execution"
                    );
                }
            }
            done = &mut handed => finished = Some(done),
        }
        let handed = match finished {
            Some(done) => done,
            None => handed.await,
        }
        .map_err(|err| err.to_string())
        .and_then(|r| r);
        match handed {
            Ok((executed, phases, converted)) => {
                // The block the engine's own pass takes instead of decoding
                // the payload again, copied from the executed block on a
                // worker thread and awaited just before that pass. It used to
                // be cloned ahead of the import, on the vote road: 14 ms to
                // copy a 163,000-transaction block and 3 more to free the one
                // `remember_sealed` evicts, of a road whose whole median was
                // 186-200 ms (`bench_vote_road_copies`, loop190). Nothing
                // reads it before the pass below, which is an insert and the
                // queue's bookkeeping away; the fast answer has taken the
                // block from this same `Arc` since b14304a73.
                let block = std::sync::Arc::clone(&executed.recovered_block);
                remembering = Some(tokio::task::spawn_blocking(move || {
                    n42_engine_types::built_executions::remember_sealed(block.hash(), block.sealed_block().clone());
                }));
                let handed_at = std::time::Instant::now();
                // The block's transactions leave the queue now, not
                // when the canonical pruner gets to them: a build
                // ahead starts the moment this import returns and
                // would otherwise take them again (87,800 stale
                // transactions in one build, round 38).
                // `N42_QUEUE_WORK_OFFLOAD=1`: the queue's and the
                // pool's bookkeeping goes to a worker thread holding
                // the block, because the two walks of a 163,000-
                // transaction block (one for the mined senders and
                // nonces, one for the hashes) sit on the vote's path
                // and nothing reads their result before the answer.
                // Off by default: it also delays the queue's removal
                // by those walks, and a build ahead that starts before
                // the removal takes the mined transactions again
                // (87,800 stale ones in one build, round 38).
                let queue_offloaded = queue_work_offload();
                if let Some(queue) = n42_tx_queue::global::<n42_engine_types::N42PooledTransaction>() {
                    if queue_offloaded {
                        let block = std::sync::Arc::clone(&executed.recovered_block);
                        let prune = reuse.prune_pool.clone();
                        tokio::task::spawn_blocking(move || {
                            let at = std::time::Instant::now();
                            let mined: Vec<(alloy_primitives::Address, u64)> = block
                                .transactions_with_sender()
                                .map(|(sender, tx)| (*sender, alloy_consensus::Transaction::nonce(tx)))
                                .collect();
                            let (number, hash) = (block.number(), block.hash());
                            let removed = queue.remove_mined_batch_collecting(mined);
                            // Held until the chain settles the height (round 43).
                            queue.hold_own_block(number, hash, removed);
                            let count = block.body().transactions().count();
                            if let Some(prune) = prune {
                                prune(block.body().transactions().map(|tx| *tx.tx_hash()).collect());
                            }
                            if count > 10_000 {
                                info!(
                                    target: "n42.payload_serve",
                                    number,
                                    count,
                                    queue_ms = at.elapsed().as_millis() as u64,
                                    "imported block's transactions taken out of the queue and the pool"
                                );
                            }
                        });
                    } else {
                        let mined: Vec<(alloy_primitives::Address, u64)> = executed
                            .recovered_block
                            .transactions_with_sender()
                            .map(|(sender, tx)| (*sender, alloy_consensus::Transaction::nonce(tx)))
                            .collect();
                        let (number, hash) =
                            (executed.recovered_block.number(), executed.recovered_block.hash());
                        mined_hashes = Some(
                            executed.recovered_block.body().transactions().map(|tx| *tx.tx_hash()).collect(),
                        );
                        tokio::task::spawn_blocking(move || {
                            let removed = queue.remove_mined_batch_collecting(mined);
                            queue.hold_own_block(number, hash, removed);
                        });
                    }
                }
                // The mined-transaction bookkeeping above walks the
                // block twice; time it and the engine's acknowledgement
                // apart, because together they were most of the ~78 ms
                // of a 438 ms import that no phase accounted for.
                let mined_ms = handed_at.elapsed().as_millis() as u64;
                let insert_at = std::time::Instant::now();
                let (done, handed) = tokio::sync::oneshot::channel();
                let sent = inserts
                    .send(reth_node_builder::executed_inserts::ExecutedInsert { block: executed, done })
                    .is_ok();
                let landed = sent
                    && matches!(tokio::time::timeout(std::time::Duration::from_secs(2), handed).await, Ok(Ok(true)));
                if landed {
                    crate::follower_import::note_import_landed();
                    direct_ms = Some([
                        converted,
                        phases[0],
                        phases[1],
                        phases[2],
                        phases[3],
                        phases[4],
                        phases[5],
                        started.elapsed().as_millis() as u64,
                        phases[6],
                        phases[7],
                        phases[8],
                        mined_ms,
                        insert_at.elapsed().as_millis() as u64,
                        phases[9],
                        phases[10],
                        phases[11],
                    ]);
                } else {
                    warn!(target: "n42.payload_serve", number, "direct import: the engine did not take the executed block; importing the ordinary way");
                }
            }
            Err(err) => warn!(target: "n42.payload_serve", number, %err, "direct import failed; importing the ordinary way"),
        }
    }
    // The fast answer (`N42_DIRECT_FAST_ANSWER=1`): this node
    // executed the block and the engine holds it as executed, so
    // the validator's vote does not wait for the engine's own
    // pass. Everything the pass would check has been checked here
    // -- the header against its parent, the transactions root, the
    // receipts root, the gas, and the QMDB state root -- so it is
    // bookkeeping; it runs below, after the answer is on the wire,
    // and a verdict other than VALID is logged loudly.
    if direct_ms.is_some() && direct_fast_answer() {
        let hash = data.payload.block_hash();
        let status = alloy_rpc_types_engine::PayloadStatus::from_status(
            alloy_rpc_types_engine::PayloadStatusEnum::Valid,
        )
        .with_latest_valid_hash(hash);
        let encoded = raw_engine::encode_payload_status(&status);
        out.push(1);
        out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        out.extend_from_slice(&encoded);
        stream.write_all(&out).await?;
        let answered = started.elapsed().saturating_sub(decoded).as_millis() as u64;
        if let Some(ms) = direct_ms {
            info!(
                target: "n42.payload_serve",
                number,
                txs,
                convert_ms = ms[0],
                header_ms = ms[1],
                senders_ms = ms[2],
                exec_ms = ms[3],
                checks_ms = ms[4],
                root_ms = ms[5],
                hashed_ms = ms[6],
                total_ms = ms[7],
                senders_cached = ms[8],
                state_ms = ms[9],
                carry_ms = ms[10],
                mined_ms = ms[11],
                insert_ms = ms[12],
                parent_engine_wait_ms = ms[13],
                gate_ms = ms[14],
                root_wait_ms = ms[15],
                answered_ms = answered,
                "direct import: answered before the engine's own pass"
            );
        }
        // The engine's pass would otherwise decode the payload's
        // 163,000 transactions again (round 43, loop100: its pass
        // went 35 -> 102 ms without the remembered block). The
        // clone started when the import returned, off the answered
        // path; this is where it has to be finished.
        if let Some(remembering) = remembering.take()
            && let Err(err) = remembering.await
        {
            warn!(target: "n42.payload_serve", number, %err, "remembering the sealed block failed; the engine will decode it again");
        }
        complete_listing(&mut data, &mut raw_transactions, &mut listing, number, false).await;
        let engine_at = std::time::Instant::now();
        match engine.new_payload(data).await {
            Ok(status) if !status.status.is_valid() => warn!(
                target: "n42.payload_serve", number, status = ?status.status,
                "the engine disagreed with a block this node executed and answered VALID for"
            ),
            Err(err) => warn!(target: "n42.payload_serve", number, %err, "the engine's own pass failed after the fast answer"),
            _ => {}
        }
        // Only when the walks stayed on this path; the worker thread
        // above prunes for itself otherwise.
        if let (Some(prune), Some(hashes)) = (reuse.and_then(|r| r.prune_pool.clone()), mined_hashes.take()) {
            let count = hashes.len();
            let pruned_at = std::time::Instant::now();
            let _ = tokio::task::spawn_blocking(move || {
                prune(hashes);
                if count > 10_000 {
                    info!(
                        target: "n42.payload_serve",
                        number,
                        count,
                        prune_ms = pruned_at.elapsed().as_millis() as u64,
                        "imported block's transactions taken out of the pool"
                    );
                }
            });
        }
        if txs > 10_000 {
            info!(
                target: "n42.payload_serve",
                number,
                txs,
                engine_after_ms = engine_at.elapsed().as_millis() as u64,
                "the engine's own pass, behind the answer"
            );
        }
        return Ok(());
    }
    // Without the fast answer the engine's pass is what the validator's
    // payload answer waits for, and it is the only reader of the block the
    // import started copying when it returned. Awaited here rather than
    // before the import, which is where it was on the vote road.
    //
    // The three steps of the direct import's `engine_ms` are timed apart
    // (`engine_remember_ms`, `engine_listing_ms`, `engine_new_payload_ms`):
    // at 163,000 transactions it was 46 ms with no name (loop234).
    let remember_at = std::time::Instant::now();
    if let Some(remembering) = remembering.take()
        && let Err(err) = remembering.await
    {
        warn!(target: "n42.payload_serve", number, %err, "remembering the sealed block failed; the engine will decode it again");
    }
    let remember_ms = remember_at.elapsed().as_millis() as u64;
    let listing_at = std::time::Instant::now();
    complete_listing(&mut data, &mut raw_transactions, &mut listing, number, direct_ms.is_none()).await;
    let listing_ms = listing_at.elapsed().as_millis() as u64;
    let new_payload_at = std::time::Instant::now();
    let new_payload = engine.new_payload(data).await;
    let new_payload_ms = new_payload_at.elapsed().as_millis() as u64;
    match new_payload {
        Ok(status) => {
            if let (Some(probe), Some(probe_data)) = (probe, probe_data) {
                let validator = reuse.map(|r| r.validator.clone());
                if let Some(validator) = validator {
                    let _ = tokio::task::spawn_blocking(move || {
                        let converted = match <n42_engine_types::engine_validator::N42EngineValidator<reth_chainspec::ChainSpec> as reth_engine_primitives::PayloadValidator<T>>::convert_payload_to_block(&validator, probe_data) {
                            Ok(block) => block,
                            Err(err) => { warn!(target: "n42.payload_serve", %err, "exec probe: conversion failed"); return; }
                        };
                        let recovered = match converted.try_recover() {
                            Ok(block) => block,
                            Err(_) => { warn!(target: "n42.payload_serve", "exec probe: sender recovery failed"); return; }
                        };
                        let header_gas = recovered.gas_used;
                        match probe(recovered) {
                            Ok((exec_ms, gas, receipts)) => info!(
                                target: "n42.payload_serve",
                                number, txs, exec_ms, gas, header_gas, receipts,
                                "follower exec probe: the block executed again with the plain executor"
                            ),
                            Err(err) => warn!(target: "n42.payload_serve", %err, "exec probe failed"),
                        }
                    })
                    .await;
                }
            }
            // A block this node now holds: its transactions
            // leave the pool at once rather than when the
            // pool's maintenance gets to them. On a follower
            // that is what keeps `pending` honest -- the
            // ingest gate reads it, and a block's 163,000
            // still counted as pending after the block was
            // imported is what stalled the whole fleet's
            // supply for the length of one node's maintenance.
            if status.status == alloy_rpc_types_engine::PayloadStatusEnum::Valid
                && !reused
                && (mined_hashes.is_some() || direct_ms.is_none())
                && let Some(prune) = reuse.and_then(|r| r.prune_pool.clone())
            {
                let pruned_at = std::time::Instant::now();
                // The mined hashes' count when the direct import has them:
                // the raw list is then not copied out of the payload.
                let count = mined_hashes.as_ref().map_or(raw_transactions.len(), Vec::len);
                // Not awaited: the answer to this payload is
                // what the validator's vote waits for, and the
                // prune of a full block was 66 ms of it (round
                // 43, loop94). The pool is a few tens of
                // milliseconds behind the chain instead of the
                // length of its maintenance, which is what the
                // `pending` the ingest gate reads needed.
                let mined_hashes = mined_hashes.take();
                let pruning = tokio::task::spawn_blocking(move || {
                    let hashes: Vec<B256> = mined_hashes.unwrap_or_else(|| {
                        use rayon::prelude::*;
                        raw_transactions.par_iter().map(|tx| alloy_primitives::keccak256(tx)).collect()
                    });
                    prune(hashes);
                    if count > 10_000 {
                        info!(
                            target: "n42.payload_serve",
                            number,
                            count,
                            prune_ms = pruned_at.elapsed().as_millis() as u64,
                            "imported block's transactions taken out of the pool"
                        );
                    }
                });
                // `N42_PRUNE_ASYNC=0`: the answer waits for the prune, as before round 43's loop98.
                if !prune_async() {
                    let _ = pruning.await;
                }
            }
            if let Some(ms) = direct_ms {
                info!(
                    target: "n42.payload_serve",
                    number,
                    txs,
                    convert_ms = ms[0],
                    header_ms = ms[1],
                    senders_ms = ms[2],
                    exec_ms = ms[3],
                    checks_ms = ms[4],
                    root_ms = ms[5],
                    hashed_ms = ms[6],
                    total_ms = ms[7],
                    senders_cached = ms[8],
                    state_ms = ms[9],
                    carry_ms = ms[10],
                    mined_ms = ms[11],
                    insert_ms = ms[12],
                    parent_engine_wait_ms = ms[13],
                    gate_ms = ms[14],
                    root_wait_ms = ms[15],
                    engine_ms = (started.elapsed().saturating_sub(decoded).as_millis() as u64).saturating_sub(ms[7]),
                    engine_remember_ms = remember_ms,
                    engine_listing_ms = listing_ms,
                    engine_new_payload_ms = new_payload_ms,
                    status = ?status.status,
                    "direct import: executed here, handed to the engine as executed"
                );
            }
            if txs > 10_000 {
                info!(
                    target: "n42.payload_serve",
                    number,
                    txs,
                    decode_ms = decoded.as_millis() as u64,
                    engine_ms = started.elapsed().saturating_sub(decoded).as_millis() as u64,
                    status = ?status.status,
                    reused,
                    "raw newPayload"
                );
            }
            let encoded = raw_engine::encode_payload_status(&status);
            out.push(1);
            out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            out.extend_from_slice(&encoded);
        }
        Err(err) => {
            let message = err.to_string();
            out.push(2);
            out.extend_from_slice(&(message.len() as u32).to_le_bytes());
            out.extend_from_slice(message.as_bytes());
        }
    }
    stream.write_all(out).await?;
    Ok(())
}

pub async fn serve<T>(
    addr: SocketAddr,
    payloads: PayloadBuilderHandle<T>,
    engine: ConsensusEngineHandle<T>,
    reuse: Option<OwnBlockReuse>,
) -> std::io::Result<()>
where
    T: PayloadTypes<BuiltPayload = N42BuiltPayload, ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    // `N42_ROAD_RUNTIME=1`: the accept loop and every connection it serves on
    // the road's own runtime, so their tasks, `spawn_blocking` calls and
    // `block_in_place` hand-offs use that runtime's workers and blocking pool
    // and not the ones the ingest saturates (`road_runtime`).
    if let Some(road) = crate::road_runtime::handle() {
        return match road.spawn(serve_here(addr, payloads, engine, reuse)).await {
            Ok(served) => served,
            Err(err) => Err(std::io::Error::other(format!("the road runtime's accept loop: {err}"))),
        };
    }
    serve_here(addr, payloads, engine, reuse).await
}

/// The channel's accept loop on the runtime it is polled on.
async fn serve_here<T>(
    addr: SocketAddr,
    payloads: PayloadBuilderHandle<T>,
    engine: ConsensusEngineHandle<T>,
    reuse: Option<OwnBlockReuse>,
) -> std::io::Result<()>
where
    T: PayloadTypes<BuiltPayload = N42BuiltPayload, ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    let listener = TcpListener::bind(addr).await?;
    // Said at start-up so a round can grep that its switch reached this
    // process: a variable that is set but never arrived measures nothing.
    info!(
        target: "n42.payload_serve",
        %addr,
        fresh_buffers = fresh_buffers(),
        own_block_reuse = reuse.is_some(),
        road_runtime = crate::road_runtime::enabled(),
        dispatch_wait = crate::road_runtime::measure_dispatch_wait(),
        "raw payload channel listening"
    );
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(target: "n42.payload_serve", %err, "accept failed");
                continue;
            }
        };
        let payloads = payloads.clone();
        let engine = engine.clone();
        let reuse = reuse.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_connection(stream, payloads, engine, reuse).await {
                debug!(target: "n42.payload_serve", %peer, %err, "raw payload connection ended");
            }
        });
    }
}

async fn serve_connection<T>(
    mut stream: TcpStream,
    payloads: PayloadBuilderHandle<T>,
    engine: ConsensusEngineHandle<T>,
    reuse: Option<OwnBlockReuse>,
) -> std::io::Result<()>
where
    T: PayloadTypes<BuiltPayload = N42BuiltPayload, ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    stream.set_nodelay(true)?;
    // Measured only when asked: the socket's receive timestamps, read with
    // the request's first byte. A socket that refuses them serves as before.
    let mut stamped = crate::road_runtime::measure_dispatch_wait();
    if stamped {
        if let Err(err) = crate::road_runtime::enable_receive_timestamps(&stream) {
            warn!(target: "n42.payload_serve", %err, "no receive timestamps; dispatch_wait_ms reads 0");
            stamped = false;
        }
    }
    // Buffers retained across frames. A newPayload frame is ~19 MB at the
    // bench tier and a served payload the same; allocated fresh per block
    // they are fresh pages first-touched on every block on every node --
    // measured as the followers' page-fault rate doubling in a round and
    // their runtime threads' time going to the kernel. Grown once, reused.
    let mut frame: Vec<u8> = Vec::new();
    let mut out: Vec<u8> = Vec::new();
    loop {
        let read = if stamped {
            crate::road_runtime::read_kind_timed(&stream).await
        } else {
            stream.read_u8().await.map(|kind| (kind, None))
        };
        let (kind, dispatch_wait) = match read {
            Ok(read) => read,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        // When the request's first byte landed: what follows it is ~25 MB
        // over the loopback socket, and the vote road starts here.
        let started_at = std::time::Instant::now();
        // Before it: the byte in the socket, waiting for this task to run.
        let dispatch_wait_us = dispatch_wait.map_or(0, |waited| waited.as_micros() as u64);
        if kind == request::OWN_BLOCK {
            let len = stream.read_u32_le().await? as usize;
            if len > 1 << 20 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "header frame too large"));
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            out.clear();
            let started = std::time::Instant::now();
            let reply = own_block_by_header::<T>(reuse.as_ref(), &engine, &buf).await;
            match reply {
                Ok((status, number, handoff_ms, payload_ms)) => {
                    info!(
                        target: "n42.payload_serve",
                        number,
                        handoff_ms,
                        payload_ms,
                        total_ms = started.elapsed().as_millis() as u64,
                        status = ?status.status,
                        "own block imported by header"
                    );
                    let encoded = raw_engine::encode_payload_status(&status);
                    out.push(1);
                    out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
                    out.extend_from_slice(&encoded);
                }
                Err(message) => {
                    debug!(target: "n42.payload_serve", %message, "own block by header refused");
                    out.push(2);
                    out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                    out.extend_from_slice(message.as_bytes());
                }
            }
            stream.write_all(&out).await?;
            continue;
        }
        if kind == request::BUILD_ON_OWN {
            let len = stream.read_u32_le().await? as usize;
            if len > 1 << 20 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "build request frame too large"));
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            out.clear();
            let frame_ms = started_at.elapsed().as_millis() as u64;
            let started = std::time::Instant::now();
            match build_on_own_block(reuse.as_ref(), &buf).await {
                Ok((payload, times, chain, want_hashes)) => {
                    // The builder answers on its early seal, so the block's
                    // header exists here and the block does not have to be
                    // encoded for it to travel. A caller that asked to chain
                    // (`request::BUILD_ON_OWN`'s hint) gets the header on its
                    // own frame first: it stamps and seals it for the view it
                    // will propose under and sends the next build's request
                    // at once, instead of waiting for this block's ~30 ms
                    // encode, its ~26 MB over the socket, and the proposal
                    // that follows -- 68-84 ms of a 360 ms cycle with the
                    // builder idle (loop190/191).
                    if chain.is_some() {
                        let rlp = alloy_rlp::encode(payload.block().header());
                        let mut frame = Vec::with_capacity(rlp.len() + 5);
                        frame.push(raw_engine::reply::CHAIN_HEADER);
                        frame.extend_from_slice(&(rlp.len() as u32).to_le_bytes());
                        frame.extend_from_slice(&rlp);
                        stream.write_all(&frame).await?;
                    }
                    let (bytes, encoded) = push_built_payload_hashed(&mut out, &payload, want_hashes);
                    info!(
                        target: "n42.payload_serve",
                        number = payload.block().number(),
                        txs = payload.block().body().transactions.len(),
                        bytes,
                        hashed = want_hashes,
                        chained = chain.is_some_and(|hint| hint.chained),
                        chain_ahead = chain.is_some(),
                        frame_ms,
                        decode_ms = times.decode_ms,
                        find_ms = times.find_ms,
                        queue_ms = times.queue_ms,
                        queue_fold_us = times.queue_fold_us,
                        queue_lock_us = times.queue_lock_us,
                        queue_partition_us = times.queue_partition_us,
                        on_output = times.on_output,
                        rename_ms = times.rename_ms,
                        spawn_ms = times.spawn_ms,
                        build_ms = times.build_ms,
                        encode_ms = encoded.as_millis() as u64,
                        total_ms = started.elapsed().as_millis() as u64,
                        "built ahead on the sealed own block"
                    );
                }
                Err(message) => {
                    info!(target: "n42.payload_serve", %message, "build on own block refused");
                    out.push(2);
                    out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                    out.extend_from_slice(message.as_bytes());
                }
            }
            stream.write_all(&out).await?;
            continue;
        }
        if kind == request::COMPACT_BODY {
            let len = stream.read_u32_le().await? as usize;
            if len > 256 << 20 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "compact body frame too large"));
            }
            frame.clear();
            frame.resize(len, 0);
            stream.read_exact(&mut frame[..]).await?;
            let recv = started_at.elapsed();
            let started = std::time::Instant::now();
            out.clear();
            // Only with the direct import configured, as the body road: the
            // point of assembling the block here is to put it straight into
            // that import.
            let validator = reuse
                .as_ref()
                .filter(|reuse| reuse.import_foreign.is_some())
                .map(|reuse| std::sync::Arc::clone(&reuse.validator));
            // `block_in_place` for the same reason the body road uses it:
            // this borrows the connection's frame buffer and is tens of
            // milliseconds of rayon work a runtime worker must not sit on.
            let assembled = tokio::task::block_in_place(|| {
                let (announced, profile, body) = raw_engine::decode_foreign_body(&frame)
                    .map_err(|err| CompactRefusal::Said(format!("compact body frame: {err}")))?;
                let validator = validator.ok_or_else(|| {
                    CompactRefusal::Said("no direct import; send the payload".to_owned())
                })?;
                let queue = n42_tx_queue::global::<n42_engine_types::N42PooledTransaction>()
                    .ok_or_else(|| {
                        CompactRefusal::Said("no transaction queue; send the whole body".to_owned())
                    })?;
                if !n42_tx_queue::block_by_description() {
                    return validator
                        .convert_compact_body_to_block(announced, profile, body, &queue, miss_wait())
                        .map(|assembled| (assembled, None))
                        .map_err(CompactRefusal::Refused);
                }
                // `N42_BLOCK_BY_DESCRIPTION`: the list checked against the
                // header with the queue's transactions held by reference,
                // then the one copy reth's block type forces.
                let mut described = validator
                    .describe_compact_body(announced, profile, body, &queue, miss_wait())
                    .map_err(CompactRefusal::Refused)?;
                let make_at = std::time::Instant::now();
                // The payload travels with an empty list until the import
                // has answered; the list is copied out of the encoded
                // transactions beside it (`import_for_validator`).
                let payload = described.header_payload();
                let list = described.take_payload_list();
                let made = described.maker(&payload).make(&validator).map_err(CompactRefusal::Refused)?;
                let senders = std::mem::take(&mut described.senders);
                let make_us = make_at.elapsed().as_micros() as u64;
                let (frames, frames_missing) = (described.frames, described.frames_missing);
                let (describe_us, root_us, miss_wait_us, misses, fill_us, filled, described_us) = (
                    described.describe_us,
                    described.root_us,
                    described.miss_wait_us,
                    described.misses,
                    described.fill_us,
                    described.filled,
                    described.total_us,
                );
                // 163,000 references released, ~4 ms: not on the road.
                rayon::spawn(move || drop(described));
                Ok((
                    n42_engine_types::engine_validator::AssembledBlock {
                        block: made.block,
                        payload,
                        senders,
                        assemble_us: describe_us.saturating_sub(root_us),
                        root_us,
                        miss_wait_us,
                        misses,
                        fill_us,
                        filled,
                        total_us: described_us + make_us,
                    },
                    Some((made.copy_us, list, frames, frames_missing)),
                ))
            });
            // A miss small enough to be worth asking for: the positions go
            // back on their own frame and the validator fetches just those
            // (`reply::NEED_TXNS`). Beyond the threshold the saving over the
            // whole body no longer pays for a round trip and a second
            // assembly, and a node missing that much of a block is behind in
            // a way one fill will not fix.
            let assembled = match assembled {
                Err(CompactRefusal::Refused(CompactBodyError::Missing { indices, total, sample, waited }))
                    if !indices.is_empty() && indices.len() <= total / fill_share() =>
                {
                    let number = raw_engine::decode_foreign_body(&frame)
                        .ok()
                        .and_then(|(_, profile, body)| {
                            n42_h2_consensus::decode_compact_body_header(body, profile).ok()
                        })
                        .map_or(0, |(_, header)| header.number);
                    info!(
                        target: "n42.payload_serve",
                        number,
                        wanted = indices.len(),
                        total,
                        first = ?indices.first(),
                        last = ?indices.last(),
                        ?sample,
                        waited_ms = waited.as_millis() as u64,
                        "compact body: asking for the transactions this node does not hold"
                    );
                    // Defect 17: the missing transactions are, at depth,
                    // the ones this node's own ingest gate is holding, and
                    // only this block's commit would reopen it. Open it for
                    // as long as the road keeps missing (`n42_tx_ingest`).
                    n42_tx_ingest::open_gate_for_block(indices.len());
                    let encoded = raw_engine::encode_need_txns(
                        &indices.iter().map(|&i| i as u32).collect::<Vec<_>>(),
                    );
                    out.push(raw_engine::reply::NEED_TXNS);
                    out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
                    out.extend_from_slice(&encoded);
                    stream.write_all(&out).await?;
                    continue;
                }
                Ok(assembled) => assembled,
                Err(refusal) => {
                    let message = refusal.to_string();
                    // "Not this way". A miss too large to be worth asking
                    // for, and a body that is not the block it claims to be,
                    // both end here, and both leave the validator to ask its
                    // peers for the whole body. Said at info level with the
                    // reason, because a leg where this happens often is a leg
                    // whose compact bodies are not doing their job.
                    // The block number costs one header decode on a path
                    // that is about to pay a whole-body road: a leg's logs
                    // are unreadable without it, which is what loop195's
                    // refusal lines showed.
                    let number = raw_engine::decode_foreign_body(&frame)
                        .ok()
                        .and_then(|(_, profile, body)| {
                            n42_h2_consensus::decode_compact_body_header(body, profile).ok()
                        })
                        .map_or(0, |(_, header)| header.number);
                    info!(target: "n42.payload_serve", number, %message, "compact body refused");
                    out.push(2);
                    out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                    out.extend_from_slice(message.as_bytes());
                    stream.write_all(&out).await?;
                    continue;
                }
            };
            let (assembled, described) = assembled;
            let (copied, payload_list, frames, frames_missing) = match described {
                Some((copy_us, list, frames, frames_missing)) => (Some(copy_us), Some(list), frames, frames_missing),
                None => (None, None, 0, 0),
            };
            let n42_engine_types::engine_validator::AssembledBlock {
                block: sealed,
                payload: data,
                senders,
                assemble_us,
                root_us,
                miss_wait_us,
                misses,
                fill_us,
                filled,
                total_us,
            } = assembled;
            info!(
                target: "n42.payload_serve",
                by_description = copied.is_some(),
                copy_ms = copied.unwrap_or(0) / 1000,
                number = sealed.number,
                txs = sealed.body().transactions.len(),
                bytes = len,
                recv_ms = recv.as_millis() as u64,
                assemble_ms = assemble_us / 1000,
                root_ms = root_us / 1000,
                miss_wait_ms = miss_wait_us / 1000,
                misses,
                fill_ms = fill_us / 1000,
                filled,
                decode_ms = started.elapsed().as_millis() as u64,
                "compact body assembled from the queue"
            );
            let decoded_in = started.elapsed();
            let road = crate::follower_import::VoteRoad {
                request: if copied.is_some() { "block_by_description" } else { "compact_body" },
                recv_us: recv.as_micros() as u64,
                // What the assembly cost that the named parts below do not:
                // the compact frame's decode, the seal, and reth's fork
                // checks.
                decode_us: total_us
                    .saturating_sub(assemble_us + root_us + miss_wait_us + fill_us + copied.unwrap_or(0)),
                copy_us: copied.unwrap_or(0),
                reuse_us: 0,
                prepare_us: 0,
                dispatch_us: 0,
                convert_us: 0,
                remember_us: 0,
                assemble_us,
                root_us,
                miss_wait_us,
                misses: misses as u64,
                fill_us,
                filled: filled as u64,
                frames: frames as u64,
                frames_missing: frames_missing as u64,
                dispatch_wait_us,
                started: started_at,
            };
            import_for_validator::<T>(
                &mut stream,
                &mut out,
                &engine,
                reuse.as_ref(),
                data,
                Some(sealed),
                Some(senders),
                payload_list,
                started,
                decoded_in,
                road,
            )
            .await?;
            continue;
        }
        if kind == request::FOREIGN_BODY {
            let len = stream.read_u32_le().await? as usize;
            if len > 256 << 20 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "body frame too large"));
            }
            frame.clear();
            frame.resize(len, 0);
            stream.read_exact(&mut frame[..]).await?;
            let recv = started_at.elapsed();
            let started = std::time::Instant::now();
            out.clear();
            // Only with the direct import configured: the body path exists to
            // put the block straight into it, and without it the engine's own
            // pass would convert a payload again anyway.
            let validator = reuse
                .as_ref()
                .filter(|reuse| reuse.import_foreign.is_some())
                .map(|reuse| std::sync::Arc::clone(&reuse.validator));
            // Read where it landed: the frame buffer is the one this
            // connection reuses for every block, the body is a slice of it,
            // and every transaction is a slice of that. Nothing that leaves
            // this block borrows it -- `convert_body_to_block` copies what it
            // keeps -- so the buffer is reused rather than a body's worth of
            // fresh pages being faulted in per block.
            //
            // `block_in_place`, not `spawn_blocking`: the conversion borrows
            // the frame, and it is tens of milliseconds of rayon work that a
            // runtime worker must not sit on.
            let decoded = tokio::task::block_in_place(|| {
                let (announced, profile, body) = raw_engine::decode_foreign_body(&frame)
                    .map_err(|err| format!("foreign body frame: {err}"))?;
                let validator = validator.ok_or_else(|| "no direct import; send the payload".to_string())?;
                validator
                    .convert_body_to_block(announced, profile, body)
                    .map_err(|err| format!("body: {err}"))
            });
            let decoded = match decoded {
                Ok(decoded) => decoded,
                Err(message) => {
                    // "Not this way": the validator sends the same block as a
                    // NEW_PAYLOAD payload. A body that does not decode is
                    // refused here rather than voted on; the validator's
                    // fallback decodes it too, fails the same way, and asks
                    // its peers for the block again.
                    debug!(target: "n42.payload_serve", %message, "foreign body refused");
                    out.push(2);
                    out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                    out.extend_from_slice(message.as_bytes());
                    stream.write_all(&out).await?;
                    continue;
                }
            };
            let (sealed, data) = decoded;
            info!(
                target: "n42.payload_serve",
                number = sealed.number,
                txs = sealed.body().transactions.len(),
                bytes = len,
                recv_ms = recv.as_millis() as u64,
                decode_ms = started.elapsed().as_millis() as u64,
                "foreign body decoded once"
            );
            let decoded_in = started.elapsed();
            let road = crate::follower_import::VoteRoad {
                request: "foreign_body",
                recv_us: recv.as_micros() as u64,
                // The frame's decode and the body's conversion to a block
                // both: this road arrives converted, so its `convert_ms` is 0.
                decode_us: decoded_in.as_micros() as u64,
                reuse_us: 0,
                prepare_us: 0,
                dispatch_us: 0,
                convert_us: 0,
                remember_us: 0,
                assemble_us: 0,
                root_us: 0,
                miss_wait_us: 0,
                misses: 0,
                fill_us: 0,
                copy_us: 0,
                filled: 0,
                frames: 0,
                frames_missing: 0,
                dispatch_wait_us,
                started: started_at,
            };
            import_for_validator::<T>(&mut stream, &mut out, &engine, reuse.as_ref(), data, Some(sealed), None, None, started, decoded_in, road).await?;
            continue;
        }
        if kind == request::NEW_PAYLOAD {
            let len = stream.read_u32_le().await? as usize;
            if len > 256 << 20 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "payload frame too large"));
            }
            // N42_PAYLOAD_SERVE_FRESH_BUFFERS=1 restores a fresh allocation per
            // frame, for the A-B-A that separates buffer reuse from the box.
            if fresh_buffers() {
                frame = Vec::new();
                out = Vec::new();
            }
            frame.clear();
            frame.resize(len, 0);
            stream.read_exact(&mut frame[..]).await?;
            let recv = started_at.elapsed();
            let started = std::time::Instant::now();
            out.clear();
            // Decoded with a copy per transaction, deliberately: decoding the
            // payload as slices of one shared 19 MB buffer (loop60N1) grew the
            // execution layer by ~19 MB a block -- something downstream keeps
            // a few of a payload's transaction bytes per block, and a slice
            // keeps the whole buffer alive with them. 4.2 -> 8.5 GB in two
            // minutes, then the fault storm.
            // `N42_RAW_SHARED_DECODE=1` decodes as slices of one shared copy of
            // the frame instead -- the variant that grew the execution layer,
            // kept for finding what holds the bytes.
            let shared_frame = raw_shared_decode().then(|| alloy_primitives::Bytes::copy_from_slice(&frame[..]));
            let decoded_data = match &shared_frame {
                Some(shared) => raw_engine::decode_execution_data_shared(shared),
                None => raw_engine::decode_execution_data(&frame),
            };
            match decoded_data {
                Err(err) => {
                    out.push(2);
                    out.extend_from_slice(&(err.len() as u32).to_le_bytes());
                    out.extend_from_slice(err.as_bytes());
                }
                Ok(data) => {
                    import_for_validator::<T>(
                        &mut stream,
                        &mut out,
                        &engine,
                        reuse.as_ref(),
                        data,
                        None,
                        None,
                        None,
                        started,
                        started.elapsed(),
                        crate::follower_import::VoteRoad {
                            request: "new_payload",
                            recv_us: recv.as_micros() as u64,
                            decode_us: started.elapsed().as_micros() as u64,
                            reuse_us: 0,
                            prepare_us: 0,
                            dispatch_us: 0,
                            convert_us: 0,
                            remember_us: 0,
                            assemble_us: 0,
                            root_us: 0,
                            miss_wait_us: 0,
                            misses: 0,
                            fill_us: 0,
                            copy_us: 0,
                            filled: 0,
                            frames: 0,
                            frames_missing: 0,
                            dispatch_wait_us,
                            started: started_at,
                        },
                    )
                    .await?;
                    continue;
                }
            }
            stream.write_all(&out).await?;
            continue;
        }
        if kind != request::GET_PAYLOAD && kind != request::GET_PAYLOAD_HASHED {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("request kind {kind}")));
        }
        let with_hashes = kind == request::GET_PAYLOAD_HASHED;
        let id = stream.read_u64_le().await?;
        let id = alloy_rpc_types_engine::PayloadId::new(id.to_le_bytes());
        let started = std::time::Instant::now();
        let resolved = payloads.resolve_kind(id, PayloadKind::WaitForPending).await;
        let waited = started.elapsed();
        out.clear();
        match resolved {
            None => out.push(0),
            Some(Err(err)) => {
                let message = err.to_string();
                out.push(2);
                out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                out.extend_from_slice(message.as_bytes());
            }
            Some(Ok(payload)) => {
                let (bytes, encoded) = push_built_payload_hashed(&mut out, &payload, with_hashes);
                if bytes > 1_000_000 {
                    info!(
                        target: "n42.payload_serve",
                        number = payload.block().number(),
                        bytes,
                        waited_ms = waited.as_millis() as u64,
                        encode_ms = encoded.as_millis() as u64,
                        "raw payload served"
                    );
                }
            }
        }
        stream.write_all(&out).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Block, BlockBody, Header, Signed, TxEip1559, TxLegacy};
    use alloy_primitives::{Address, Signature, TxKind, U256};
    use reth_ethereum_primitives::TransactionSigned;

    /// The parallel encoding is alloy's, byte for byte.
    #[test]
    fn parallel_block_rlp_is_alloys() {
        let txs: Vec<TransactionSigned> = (0..40u64)
            .map(|n| {
                if n % 3 == 0 {
                    let tx = TxLegacy { chain_id: Some(1), nonce: n, gas_price: 10, gas_limit: 21_000, to: TxKind::Call(Address::repeat_byte(3)), value: U256::from(n), ..Default::default() };
                    Signed::new_unchecked(tx, Signature::test_signature(), Default::default()).into()
                } else {
                    let tx = TxEip1559 { chain_id: 1, nonce: n, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(2)), value: U256::from(n), ..Default::default() };
                    Signed::new_unchecked(tx, Signature::test_signature(), Default::default()).into()
                }
            })
            .collect();
        let header = Header { number: 9, base_fee_per_gas: Some(7), withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH), ..Default::default() };
        let withdrawals = alloy_eips::eip4895::Withdrawals(vec![alloy_eips::eip4895::Withdrawal { index: 1, validator_index: 2, address: Address::repeat_byte(7), amount: 3 }]);
        let block = Block { header, body: BlockBody { transactions: txs, ommers: Vec::new(), withdrawals: Some(withdrawals) } };
        let sealed = SealedBlock::seal_slow(block);
        assert_eq!(encode_block_parallel(&sealed), alloy_rlp::encode(&sealed));
    }

    /// The encodings the service keeps when it answers `getPayload` are the
    /// ones the own-block import would have made for itself, byte for byte --
    /// a payload lists transactions in their EIP-2718 form, which is what the
    /// block's RLP is built from.
    #[test]
    fn the_kept_encodings_are_the_ones_a_payload_lists() {
        let txs: Vec<TransactionSigned> = (0..12u64)
            .map(|n| {
                if n % 4 == 0 {
                    let tx = TxLegacy { chain_id: Some(1), nonce: n, gas_price: 10, gas_limit: 21_000, to: TxKind::Call(Address::repeat_byte(3)), value: U256::from(n), ..Default::default() };
                    Signed::new_unchecked(tx, Signature::test_signature(), Default::default()).into()
                } else {
                    let tx = TxEip1559 { chain_id: 1, nonce: n, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(2)), value: U256::from(n), ..Default::default() };
                    Signed::new_unchecked(tx, Signature::test_signature(), Default::default()).into()
                }
            })
            .collect();
        let header = Header { number: 11, base_fee_per_gas: Some(7), ..Default::default() };
        let block = Block { header, body: BlockBody { transactions: txs.clone(), ommers: Vec::new(), withdrawals: None } };
        let sealed = SealedBlock::seal_slow(block);
        let (rlp, listed) = encode_block_parallel_keeping_transactions(&sealed);
        assert_eq!(rlp, alloy_rlp::encode(&sealed), "the block's RLP is unchanged");

        let n42: Vec<n42_tx_types::N42TxEnvelope> = txs.iter().cloned().map(n42_tx_types::N42TxEnvelope::from).collect();
        let n42_block = n42_tx_types::Block {
            header: sealed.header().clone(),
            body: n42_tx_types::BlockBody { transactions: n42, ommers: Vec::new(), withdrawals: None },
        };
        let recovered = reth_primitives_traits::RecoveredBlock::new_sealed(
            SealedBlock::seal_slow(n42_block),
            vec![Address::repeat_byte(1); txs.len()],
        );
        assert_eq!(listed, encoded_transactions(&recovered), "the same bytes the import used to encode for itself");

        let hash = sealed.hash();
        remember_listed(hash, listed.clone());
        assert_eq!(listed_for(hash).as_deref(), Some(&listed), "kept for the import that follows");
        // Two blocks later it is gone, and the import encodes for itself again.
        remember_listed(alloy_primitives::B256::repeat_byte(1), Vec::new());
        remember_listed(alloy_primitives::B256::repeat_byte(2), Vec::new());
        assert!(listed_for(hash).is_none(), "only the last two are kept");
    }

    /// A sibling on the same parent -- another leader's empty block after a
    /// view change -- is not executed as this node's build: its beneficiary,
    /// timestamp or rewards differ; this node's own block, which differs only
    /// in the view the extra data carries, is (loop157 W).
    #[test]
    fn a_sibling_on_the_same_parent_is_not_executed_as_the_build() {
        use alloy_eips::eip4895::Withdrawal;
        let built = Header {
            number: 183,
            beneficiary: Address::repeat_byte(4),
            timestamp: 1_000,
            gas_limit: 3_423_000_000,
            base_fee_per_gas: Some(7),
            extra_data: vec![0xAA].into(),
            ..Default::default()
        };
        let rewards = [Withdrawal { index: 0, validator_index: 0, address: Address::repeat_byte(4), amount: 1 }];
        let mut ours = built.clone();
        ours.extra_data = vec![0xBB].into();
        assert!(build_executes_as_sealed(&built, Some(&rewards), &ours, Some(&rewards)));

        let mut sibling = built.clone();
        sibling.beneficiary = Address::repeat_byte(2);
        assert!(!build_executes_as_sealed(&built, Some(&rewards), &sibling, Some(&rewards)));
        let mut later = built.clone();
        later.timestamp += 1;
        assert!(!build_executes_as_sealed(&built, Some(&rewards), &later, Some(&rewards)));
        let theirs = [Withdrawal { index: 0, validator_index: 0, address: Address::repeat_byte(2), amount: 1 }];
        assert!(!build_executes_as_sealed(&built, Some(&rewards), &ours, Some(&theirs)));
        assert!(build_executes_as_sealed(&built, None, &ours, Some(&[])));
    }

    /// The header-only own-block payload lists the block's transactions, so an
    /// engine that executes it runs all of them: they decode back to the block's.
    #[test]
    fn an_own_blocks_transactions_are_listed_for_its_payload() {
        let transactions: Vec<n42_tx_types::N42TxEnvelope> = (0..5u64)
            .map(|n| {
                let tx = TxEip1559 { chain_id: 1, nonce: n, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(2)), value: U256::from(n), ..Default::default() };
                n42_tx_types::N42TxEnvelope::from(TransactionSigned::from(Signed::new_unchecked(tx, Signature::test_signature(), alloy_primitives::B256::with_last_byte(n as u8))))
            })
            .collect();
        let block = n42_tx_types::Block {
            header: Header { number: 129, ..Default::default() },
            body: n42_tx_types::BlockBody { transactions: transactions.clone(), ommers: Vec::new(), withdrawals: None },
        };
        let recovered = reth_primitives_traits::RecoveredBlock::new_sealed(SealedBlock::seal_slow(block), vec![Address::repeat_byte(1); 5]);
        let listed = encoded_transactions(&recovered);
        assert_eq!(listed.len(), transactions.len());
        for (bytes, tx) in listed.iter().zip(&transactions) {
            // Compared as encodings: an envelope also caches its hash, and the
            // test's transactions carry a made-up one.
            assert_eq!(bytes.as_ref(), alloy_eips::eip2718::Encodable2718::encoded_2718(tx).as_slice());
            let decoded = <n42_tx_types::N42TxEnvelope as alloy_eips::Decodable2718>::decode_2718_exact(bytes.as_ref()).expect("decodes");
            assert_eq!(alloy_eips::eip2718::Encodable2718::encoded_2718(&decoded).as_slice(), bytes.as_ref());
        }
    }
}

/// Whether the queue's and the pool's bookkeeping for an imported block runs
/// on a worker thread (`N42_QUEUE_WORK_OFFLOAD=1`) instead of on this path.
/// Inline it walks the block twice -- once for the mined senders and nonces,
/// once for the hashes -- while the validator waits for the answer. Off until
/// a round shows the walks cost more than the delayed queue removal does
/// (round 38: a build ahead that starts first takes the mined transactions
/// again).
fn queue_work_offload() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_QUEUE_WORK_OFFLOAD").is_ok_and(|v| v == "1"))
}

/// Whether a block the direct import executed is answered VALID at once, with
/// the engine's own `newPayload` run behind the answer (`N42_DIRECT_FAST_ANSWER=1`,
/// off by default). The block was validated here; the engine's pass is
/// bookkeeping. Round 43: the engine's pass was 35 ms of a 533 ms import
/// barrier. The deep clone of the block's 163,000 transactions that
/// remembering it cost is no longer part of this choice -- both answers copy
/// it from the executed block after the import, off the vote road.
fn direct_fast_answer() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_DIRECT_FAST_ANSWER").is_ok_and(|v| v == "1"))
}

/// Whether an imported block's pool prune runs off the payload answer's path
/// (default; `N42_PRUNE_ASYNC=0` makes the answer wait for it, the behaviour
/// before round 43's loop98).
fn prune_async() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_PRUNE_ASYNC").map_or(true, |v| v != "0"))
}
