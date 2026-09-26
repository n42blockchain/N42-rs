// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A block described by its transactions' hashes and checked against this
//! node's own queue by reference (`N42_BLOCK_BY_DESCRIPTION`).
//!
//! The compact body (`N42_COMPACT_BODY`) proved a follower can put a block
//! together from the transactions its ingest already decoded and recovered;
//! what it cost was the copy: 163,000 transactions cloned out of the queue
//! before anything was checked, and the root then computed over the copies
//! in a second pass (loop201: assembly 65-75 ms on the fleet). Here the road
//! to the vote keeps the queue's `Arc`s instead:
//!
//! - the look-up and the encoding the transactions root needs happen in one
//!   pass on the worker that found each transaction, into one buffer per
//!   chunk -- no transaction copied and no allocation per transaction;
//! - the root over those bytes is compared with the header's, which binds
//!   the list the hashes named to the block consensus voted on, exactly as
//!   on the compact road: a reordered, duplicated, substituted or missing
//!   hash produces a different root and the block is refused;
//! - the senders are the queue's, as they were.
//!
//! What is left is the owned block reth's execution and its engine tree take:
//! `RecoveredBlock<Block>` holds a `SealedBlock<Block>` whose body is
//! `alloy_consensus::BlockBody { transactions: Vec<N42TxEnvelope> }`, owned,
//! and the parallel executor and `BuiltPayloadExecutedBlock` both take that
//! type. [`DescribedBlock::into_block`] makes that copy; the follower's import
//! runs it beside the rest of its vote road rather than ahead of it.

use super::*;
use alloy_eips::eip4895::{Withdrawal, Withdrawals};
use alloy_primitives::{Address, Bytes};
use reth_transaction_pool::ValidPoolTransaction;

/// A transaction of this node's queue, held by reference.
pub type Queued = Arc<ValidPoolTransaction<crate::N42PooledTransaction>>;

/// One position of a described block.
#[derive(Debug)]
pub enum DescribedTx {
    /// The queue's own transaction, by reference.
    Queued(Queued),
    /// A transaction a peer supplied for a position this node could not
    /// fill; decoded, checked against its hash and recovered on arrival.
    Supplied(Box<TransactionSigned>),
}

impl DescribedTx {
    /// The transaction.
    pub fn transaction(&self) -> &TransactionSigned {
        match self {
            Self::Queued(queued) => queued.transaction.transaction.inner(),
            Self::Supplied(tx) => tx,
        }
    }
}

/// One chunk of the block's transactions, encoded end to end: what the
/// transactions root is computed over, and what the payload's list is copied
/// from when the block is made.
#[derive(Debug, Default)]
struct EncodedChunk {
    bytes: Vec<u8>,
    ends: Vec<usize>,
    /// The blob versioned hashes of the chunk's EIP-4844 transactions, in
    /// order: what the payload's sidecar lists, read while the transaction
    /// is being encoded rather than in a pass of its own.
    versioned: Vec<B256>,
}

impl EncodedChunk {
    fn with_capacity(transactions: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(transactions * 200),
            ends: Vec::with_capacity(transactions),
            versioned: Vec::new(),
        }
    }

    fn push(&mut self, tx: &TransactionSigned) {
        alloy_eips::Encodable2718::encode_2718(tx, &mut self.bytes);
        self.ends.push(self.bytes.len());
        if let Some(hashes) = alloy_consensus::Transaction::blob_versioned_hashes(tx) {
            self.versioned.extend_from_slice(hashes);
        }
    }

    fn slices(&self) -> impl Iterator<Item = &[u8]> + '_ {
        let mut start = 0;
        self.ends.iter().map(move |&end| {
            let slice = &self.bytes[start..end];
            start = end;
            slice
        })
    }
}

/// A position the look-up filled, with the sender this node recorded.
type Found = Option<(Queued, Address)>;

/// How many transactions one worker encodes at a time: 163,000 of them in
/// ~160 chunks, enough for sixteen workers to balance.
const CHUNK: usize = 1024;

/// A block's description, checked: every transaction held (by reference
/// where this node's queue had it), their root equal to the header's, the
/// senders this node recorded. Not yet a block -- see [`Self::into_block`].
#[derive(Debug)]
pub struct DescribedBlock {
    /// The hash consensus voted on, the keccak of the header as it arrived.
    pub hash: B256,
    /// The header.
    pub header: alloy_consensus::Header,
    /// The transactions, in block order.
    pub transactions: Arc<Vec<DescribedTx>>,
    /// Their senders, in the same order.
    pub senders: Vec<Address>,
    withdrawals: Vec<Withdrawal>,
    bal: Option<Bytes>,
    encoded: Vec<EncodedChunk>,
    /// Finding the transactions in the queue, encoding them and building the
    /// trie, in the one pass (plus a second over any chunk a miss or a fill
    /// touched).
    pub describe_us: u64,
    /// Of `describe_us`: the trie over the encoded transactions.
    pub root_us: u64,
    /// Waiting for the ingest to catch up on a first-pass miss.
    pub miss_wait_us: u64,
    /// How many of the hashes the first pass did not find.
    pub misses: usize,
    /// Checking, decoding and recovering the transactions the frame supplied.
    pub fill_us: u64,
    /// How many positions the frame supplied.
    pub filled: usize,
    /// The whole call.
    pub total_us: u64,
    /// A frame description's frames (0 for a body that lists hashes).
    pub frames: usize,
    /// Of those, how many the first look-up did not find whole.
    pub frames_missing: usize,
    /// Of the frame tree's leaves, how many were the frame's id from this
    /// node's index (taken whole, computed at ingest).
    pub frame_roots_indexed: usize,
    /// And how many were hashed here: a filled frame, the cut last frame.
    pub frame_roots_hashed: usize,
}

/// The owned block a [`DescribedBlock`] becomes, with what that cost.
#[derive(Debug)]
pub struct DescribedInto {
    /// The block, sealed, checked against the voted hash and by reth's
    /// well-formedness checks.
    pub block: SealedBlock<EthBlock>,
    /// The payload the engine's own pass takes.
    pub payload: ExecutionData,
    /// The senders, in block order.
    pub senders: Vec<Address>,
    /// The copy of the transactions out of the queue.
    pub copy_us: u64,
    /// The payload's transaction list, copied out of the encoded chunks.
    pub payload_us: u64,
    /// Sealing and reth's checks.
    pub checks_us: u64,
}

impl<ChainSpec> N42EngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
{
    /// The block a compact body describes, checked against this node's
    /// queue by reference (`N42_BLOCK_BY_DESCRIPTION`).
    ///
    /// The checks the compact road makes before its block is voted on, on the
    /// same values: the header profile and the rewards against the
    /// withdrawals root (`decode_compact_body`), the voted hash against the
    /// header's keccak, every supplied transaction against the hash of its
    /// position, and **the transactions root recomputed over the list held
    /// here and compared with the header's** -- the whole binding between the
    /// hashes the body named and the block consensus voted on. The seal and
    /// reth's well-formedness checks follow in [`DescribedBlock::into_block`].
    ///
    /// Misses are handled as on the compact road: the inbox drained and the
    /// look-up repeated for `miss_wait`, then [`CompactBodyError::Missing`]
    /// with the positions, for the caller to ask the proposer for.
    pub fn describe_compact_body(
        &self,
        announced: B256,
        profile: N42HeaderProfile,
        compact: &[u8],
        queue: &n42_tx_queue::TxQueue<crate::N42PooledTransaction>,
        miss_wait: std::time::Duration,
    ) -> Result<DescribedBlock, CompactBodyError> {
        use rayon::prelude::*;
        let other = |message: String| CompactBodyError::Invalid(NewPayloadError::Other(message.into()));
        if profile != self.profile {
            return Err(other(format!(
                "body read under the {profile:?} header profile, this chain is {:?}",
                self.profile
            )));
        }
        let started = std::time::Instant::now();
        let body = n42_h2_consensus::decode_compact_body(compact, profile).map_err(|err| other(err.to_string()))?;
        if body.block_hash != announced {
            return Err(other(format!("body is block {} and not the announced {announced}", body.block_hash)));
        }

        let filled_at = std::time::Instant::now();
        let supplied = super::supplied_from_fill(&body)?;
        let fill_us = filled_at.elapsed().as_micros() as u64;
        if body.frames.is_some() {
            return self.describe_frames(body, queue, miss_wait, started, supplied, fill_us);
        }
        // Under `N42_FRAME_BLOCKS=1` a block described by hashes is one whose
        // body is not a run of frames: it carries the MPT root, checked below
        // exactly as without the flag.
        let covered: std::collections::HashSet<usize> = supplied.iter().map(|(index, _, _)| *index).collect();

        // The look-up and the encoding in one pass, a chunk per worker. A
        // chunk whose every position the queue held is encoded as it is
        // found; one with a miss or a supplied position is encoded again
        // below, once every position is held.
        let describe_at = std::time::Instant::now();
        // With the sender read while the transaction is in the worker's
        // cache: a serial walk for it afterwards is 163,000 random reads.
        let passes: Vec<(Vec<Found>, Option<EncodedChunk>)> = body
            .hashes
            .par_chunks(CHUNK)
            .enumerate()
            .map(|(nth, hashes)| {
                let base = nth * CHUNK;
                let mut found = Vec::with_capacity(hashes.len());
                let mut encoded = Some(EncodedChunk::with_capacity(hashes.len()));
                for (offset, hash) in hashes.iter().enumerate() {
                    let held = if !covered.is_empty() && covered.contains(&(base + offset)) {
                        None
                    } else {
                        queue.get_by_hash(hash).map(|queued| {
                            let sender = queued.transaction.transaction.signer();
                            (queued, sender)
                        })
                    };
                    match (&held, encoded.as_mut()) {
                        (Some((queued, _)), Some(chunk)) => chunk.push(queued.transaction.transaction.inner()),
                        (None, _) => encoded = None,
                        _ => {}
                    }
                    found.push(held);
                }
                (found, encoded)
            })
            .collect();
        let (mut held, mut encoded): (Vec<Found>, Vec<Option<EncodedChunk>>) = {
            let mut held = Vec::with_capacity(body.hashes.len());
            let mut encoded = Vec::with_capacity(passes.len());
            for (found, chunk) in passes {
                held.extend(found);
                encoded.push(chunk);
            }
            (held, encoded)
        };
        let first_pass = describe_at.elapsed();

        let mut misses: Vec<usize> =
            held.iter().enumerate().filter(|(i, tx)| tx.is_none() && !covered.contains(i)).map(|(i, _)| i).collect();
        let first_misses = misses.len();
        let waited_at = std::time::Instant::now();
        while !misses.is_empty() && waited_at.elapsed() < miss_wait {
            queue.drain_now();
            let mut still = Vec::new();
            for slot in misses {
                match queue.get_by_hash(&body.hashes[slot]) {
                    Some(tx) => {
                        let sender = tx.transaction.transaction.signer();
                        held[slot] = Some((tx, sender));
                    }
                    None => still.push(slot),
                }
            }
            misses = still;
            if misses.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let miss_wait_us = if first_misses == 0 { 0 } else { waited_at.elapsed().as_micros() as u64 };
        if !misses.is_empty() {
            return Err(CompactBodyError::Missing {
                sample: misses.iter().take(4).map(|&i| body.hashes[i]).collect(),
                total: body.hashes.len(),
                indices: misses,
                waited: waited_at.elapsed(),
            });
        }

        // Every position held: the list in block order, the senders beside it.
        let second_at = std::time::Instant::now();
        let mut supplied_at: std::collections::HashMap<usize, (Address, TransactionSigned)> =
            supplied.into_iter().map(|(index, sender, tx)| (index, (sender, tx))).collect();
        let mut transactions = Vec::with_capacity(held.len());
        let mut senders = Vec::with_capacity(held.len());
        for (index, slot) in held.drain(..).enumerate() {
            let supplied = if supplied_at.is_empty() { None } else { supplied_at.remove(&index) };
            match (slot, supplied) {
                (_, Some((sender, tx))) => {
                    senders.push(sender);
                    transactions.push(DescribedTx::Supplied(Box::new(tx)));
                }
                (Some((queued, sender)), None) => {
                    senders.push(sender);
                    transactions.push(DescribedTx::Queued(queued));
                }
                (None, None) => {
                    // Unreachable: the loop above returned on any miss.
                    // Checked rather than assumed, because the alternative
                    // is an unwrap on the vote road.
                    return Err(CompactBodyError::Missing {
                        indices: vec![index],
                        total: body.hashes.len(),
                        sample: vec![body.hashes[index]],
                        waited: waited_at.elapsed(),
                    });
                }
            }
        }
        // The chunks a miss or a fill interrupted, encoded now.
        encoded
            .par_iter_mut()
            .enumerate()
            .filter(|(_, chunk)| chunk.is_none())
            .for_each(|(nth, chunk)| {
                let range = nth * CHUNK..((nth + 1) * CHUNK).min(transactions.len());
                let mut fresh = EncodedChunk::with_capacity(range.len());
                for tx in &transactions[range] {
                    fresh.push(tx.transaction());
                }
                *chunk = Some(fresh);
            });
        let encoded: Vec<EncodedChunk> = encoded.into_iter().map(Option::unwrap_or_default).collect();

        // What binds the list to the header.
        let root_at = std::time::Instant::now();
        let slices: Vec<&[u8]> = encoded.iter().flat_map(EncodedChunk::slices).collect();
        if slices.len() != transactions.len() {
            return Err(other(format!(
                "{} transactions encoded for a list of {}",
                slices.len(),
                transactions.len()
            )));
        }
        let transactions_root = crate::assembler::parallel_ordered_trie_root(&slices);
        drop(slices);
        let root_us = root_at.elapsed().as_micros() as u64;
        if transactions_root != body.header.transactions_root {
            return Err(CompactBodyError::Invalid(
                PayloadError::BlockHash { execution: transactions_root, consensus: body.header.transactions_root }
                    .into(),
            ));
        }
        let describe_us = (first_pass + second_at.elapsed()).as_micros() as u64;
        Ok(DescribedBlock {
            hash: body.block_hash,
            header: body.header,
            transactions: Arc::new(transactions),
            senders,
            withdrawals: body.withdrawals,
            bal: body.bal.map(Bytes::copy_from_slice),
            encoded,
            describe_us,
            root_us,
            miss_wait_us,
            misses: first_misses,
            fill_us,
            filled: body.fill.len(),
            total_us: started.elapsed().as_micros() as u64,
            frames: 0,
            frames_missing: 0,
            frame_roots_indexed: 0,
            frame_roots_hashed: 0,
        })
    }

    /// [`Self::describe_compact_body`] for a frame description
    /// (`N42_FRAME_BLOCKS=1`): the block assembled by reference from the
    /// frames this node's queue indexed, one look-up per frame
    /// ([`n42_tx_queue::TxQueue::take_frames`]), the last one cut to the
    /// prefix the description names; its transactions root is the frame tree
    /// over that layout (~326 leaves for a full block, not a 163,000-leaf
    /// trie), compared with the header's.
    ///
    /// A frame this node does not hold whole is a miss: its positions --
    /// the description carries every frame's count, so they are known --
    /// go back to the caller as [`CompactBodyError::Missing`] after
    /// `miss_wait`, exactly as the hash road's, and the proposer's fill
    /// supplies them. A supplied transaction is not checked against a hash
    /// here (a missing frame's hashes are not known); the root over what
    /// was assembled binds it to the header all the same.
    ///
    /// The encoding the payload's list needs is still made, one pass on the
    /// worker pool; what this road does not do is the 163,000 look-ups by
    /// hash and the trie.
    fn describe_frames(
        &self,
        body: n42_h2_consensus::CompactBlockBody<'_>,
        queue: &n42_tx_queue::TxQueue<crate::N42PooledTransaction>,
        miss_wait: std::time::Duration,
        started: std::time::Instant,
        supplied: Vec<(usize, Address, TransactionSigned)>,
        fill_us: u64,
    ) -> Result<DescribedBlock, CompactBodyError> {
        use rayon::prelude::*;
        let other = |message: String| CompactBodyError::Invalid(NewPayloadError::Other(message.into()));
        if !crate::frame_blocks::active() {
            return Err(other("a frame description on a node without N42_FRAME_BLOCKS=1".to_owned()));
        }
        let frames: Vec<(B256, usize)> =
            body.frames.as_deref().unwrap_or_default().iter().map(|(id, count)| (*id, *count as usize)).collect();
        let total = body.len();
        let mut starts = Vec::with_capacity(frames.len());
        let mut at = 0usize;
        for (_, count) in &frames {
            starts.push(at);
            at += count;
        }
        let last = frames.len().saturating_sub(1);
        let covered: std::collections::HashSet<usize> = supplied.iter().map(|(index, _, _)| *index).collect();

        let describe_at = std::time::Instant::now();
        let mut held: Vec<Found> = Vec::with_capacity(total);
        held.resize_with(total, || None);
        let mut pending: Vec<usize> = (0..frames.len()).collect();
        let mut frames_missing: Option<usize> = None;
        // Frame k's root when this node took it whole out of its index: the
        // id the ingest computed over exactly the hashes `take_frames`
        // fetched by, so the frame tree reads it instead of rehashing.
        let mut known: Vec<Option<B256>> = vec![None; frames.len()];
        let mut first_pass = std::time::Duration::ZERO;
        let waited_at = loop {
            let ids: Vec<B256> = pending.iter().map(|&k| frames[k].0).collect();
            let found = queue.take_frames(&ids);
            let mut still = Vec::new();
            for (k, found) in pending.iter().copied().zip(found) {
                let (id, count) = frames[k];
                match found {
                    // Whole, or the last frame's prefix.
                    Some(txs) if txs.len() == count || (k == last && txs.len() > count) => {
                        if txs.len() == count {
                            known[k] = Some(id);
                        }
                        for (offset, queued) in txs.into_iter().take(count).enumerate() {
                            let sender = queued.transaction.transaction.signer();
                            held[starts[k] + offset] = Some((queued, sender));
                        }
                    }
                    Some(txs) => {
                        return Err(other(format!(
                            "frame {id} holds {} transactions, the description names {count} of it",
                            txs.len()
                        )));
                    }
                    None => still.push(k),
                }
            }
            pending = still;
            if frames_missing.is_none() {
                frames_missing = Some(pending.len());
                first_pass = describe_at.elapsed();
            }
            // Frames whose every position the fill covers are not missing.
            pending.retain(|&k| (starts[k]..starts[k] + frames[k].1).any(|index| !covered.contains(&index)));
            if pending.is_empty() || describe_at.elapsed() >= miss_wait + first_pass {
                break std::time::Instant::now();
            }
            queue.drain_now();
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        let frames_missing = frames_missing.unwrap_or(0);
        let miss_wait_us = if frames_missing == 0 {
            0
        } else {
            waited_at.duration_since(describe_at).saturating_sub(first_pass).as_micros() as u64
        };
        if !pending.is_empty() {
            let indices: Vec<usize> = pending
                .iter()
                .flat_map(|&k| starts[k]..starts[k] + frames[k].1)
                .filter(|index| !covered.contains(index))
                .collect();
            return Err(CompactBodyError::Missing {
                sample: pending.iter().take(4).map(|&k| frames[k].0).collect(),
                total,
                indices,
                waited: waited_at.duration_since(describe_at),
            });
        }
        let misses = (0..total).filter(|index| held[*index].is_none() && !covered.contains(index)).count();

        // Every position held: the list in block order, the senders beside it.
        let second_at = std::time::Instant::now();
        let mut supplied_at: std::collections::HashMap<usize, (Address, TransactionSigned)> =
            supplied.into_iter().map(|(index, sender, tx)| (index, (sender, tx))).collect();
        let mut transactions = Vec::with_capacity(total);
        let mut senders = Vec::with_capacity(total);
        for (index, slot) in held.into_iter().enumerate() {
            let supplied = if supplied_at.is_empty() { None } else { supplied_at.remove(&index) };
            match (slot, supplied) {
                (_, Some((sender, tx))) => {
                    senders.push(sender);
                    transactions.push(DescribedTx::Supplied(Box::new(tx)));
                }
                (Some((queued, sender)), None) => {
                    senders.push(sender);
                    transactions.push(DescribedTx::Queued(queued));
                }
                (None, None) => {
                    return Err(CompactBodyError::Missing {
                        indices: vec![index],
                        total,
                        sample: Vec::new(),
                        waited: waited_at.elapsed(),
                    });
                }
            }
        }
        // The payload's list: every chunk encoded, on the worker pool.
        let encoded: Vec<EncodedChunk> = transactions
            .par_chunks(CHUNK)
            .map(|chunk| {
                let mut fresh = EncodedChunk::with_capacity(chunk.len());
                for tx in chunk {
                    fresh.push(tx.transaction());
                }
                fresh
            })
            .collect();

        // What binds the list to the header: the frame tree.
        let root_at = std::time::Instant::now();
        // A frame any of whose positions the fill supplied is hashed: its
        // transactions are not (all) the indexed ones.
        if !covered.is_empty() {
            for (k, leaf) in known.iter_mut().enumerate() {
                if leaf.is_some() && (starts[k]..starts[k] + frames[k].1).any(|index| covered.contains(&index)) {
                    *leaf = None;
                }
            }
        }
        let counts: Vec<usize> = frames.iter().map(|(_, count)| *count).collect();
        let tree = {
            use alloy_consensus::transaction::TxHashRef as _;
            crate::frame_blocks::frame_tree_root_known(&counts, &known, transactions.len(), |index| {
                *transactions[index].transaction().tx_hash()
            })
        }
        .ok_or_else(|| other("the frame layout does not cover the assembled body".to_owned()))?;
        let transactions_root = tree.root;
        let root_us = root_at.elapsed().as_micros() as u64;
        if transactions_root != body.header.transactions_root {
            return Err(CompactBodyError::Invalid(
                PayloadError::BlockHash { execution: transactions_root, consensus: body.header.transactions_root }
                    .into(),
            ));
        }
        // Verified from the layout and the body's own hashes, whatever this
        // node's frame index holds (a supplied frame's transactions included):
        // kept so a later whole-body check of the block verifies it the same way.
        crate::frame_blocks::remember_verified(body.block_hash, transactions_root, body.frames.as_deref().unwrap_or_default());
        let describe_us = (first_pass + second_at.elapsed()).as_micros() as u64;
        Ok(DescribedBlock {
            hash: body.block_hash,
            header: body.header,
            transactions: Arc::new(transactions),
            senders,
            withdrawals: body.withdrawals,
            bal: body.bal.map(Bytes::copy_from_slice),
            encoded,
            describe_us,
            root_us,
            miss_wait_us,
            misses,
            fill_us,
            filled: body.fill.len(),
            total_us: started.elapsed().as_micros() as u64,
            frames: frames.len(),
            frames_missing,
            frame_roots_indexed: tree.indexed,
            frame_roots_hashed: tree.hashed,
        })
    }
}

impl DescribedBlock {
    /// The number of transactions.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Whether the block has none.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// The payload the engine's own pass takes, its transaction list copied
    /// out of the encoded chunks -- contiguous memory, one allocation per
    /// transaction. Copies rather than slices: a slice of a chunk would keep
    /// the chunk alive for as long as anything downstream held one
    /// transaction's bytes (the loop60N1 growth).
    pub fn payload(&self) -> ExecutionData {
        let mut payload = self.header_payload();
        payload.payload.as_v1_mut().transactions = copy_out(&self.encoded);
        payload
    }

    /// The payload with an empty transaction list and everything else in
    /// place -- the sidecar's blob versioned hashes included, read during the
    /// encoding. What the road carries until [`PayloadList::copy_out`] has
    /// filled the list in, off the road, before the engine's own pass.
    pub fn header_payload(&self) -> ExecutionData {
        let mut payload = n42_h2_consensus::execution_data_from_raw_parts(
            self.hash,
            &self.header,
            Vec::new(),
            self.withdrawals.clone(),
            self.bal.clone(),
        );
        let versioned: Vec<B256> = self.encoded.iter().flat_map(|chunk| chunk.versioned.iter().copied()).collect();
        if let Some(cancun) = payload.sidecar.cancun().cloned() {
            let cancun = alloy_rpc_types_engine::CancunPayloadFields { versioned_hashes: versioned, ..cancun };
            payload.sidecar = match payload.sidecar.into_prague() {
                Some(prague) => alloy_rpc_types_engine::ExecutionPayloadSidecar::v4(cancun, prague),
                None => alloy_rpc_types_engine::ExecutionPayloadSidecar::v3(cancun),
            };
        }
        payload
    }

    /// The encoded transactions, taken out for the payload's list. After
    /// this, [`Self::payload`] lists none.
    pub fn take_payload_list(&mut self) -> PayloadList {
        PayloadList(std::mem::take(&mut self.encoded))
    }

    /// What makes the owned block, apart from this description: it shares
    /// the transactions by reference, so the caller can go on checking the
    /// description while the block is made on another thread.
    pub fn maker(&self, payload: &ExecutionData) -> BlockMaker {
        BlockMaker {
            hash: self.hash,
            header: self.header.clone(),
            withdrawals: self.withdrawals.clone(),
            transactions: Arc::clone(&self.transactions),
            sidecar: payload.sidecar.clone(),
        }
    }

    /// The owned block, sealed and checked, and the payload: both halves of
    /// [`Self::payload`] and [`BlockMaker::make`] one after the other.
    pub fn into_block<ChainSpec>(
        self,
        validator: &N42EngineValidator<ChainSpec>,
    ) -> Result<DescribedInto, CompactBodyError>
    where
        ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    {
        let payload_at = std::time::Instant::now();
        let payload = self.payload();
        let payload_us = payload_at.elapsed().as_micros() as u64;
        let made = self.maker(&payload).make(validator)?;
        Ok(DescribedInto {
            block: made.block,
            payload,
            senders: self.senders,
            copy_us: made.copy_us,
            payload_us,
            checks_us: made.checks_us,
        })
    }
}

/// The payload's transaction list, one allocation per transaction copied out
/// of the chunks the root was computed over.
fn copy_out(chunks: &[EncodedChunk]) -> Vec<Bytes> {
    use rayon::prelude::*;
    let lists: Vec<Vec<Bytes>> =
        chunks.par_iter().map(|chunk| chunk.slices().map(Bytes::copy_from_slice).collect()).collect();
    lists.into_iter().flatten().collect()
}

/// A described block's transactions as the payload lists them, encoded and
/// not yet copied out.
#[derive(Debug, Default)]
pub struct PayloadList(Vec<EncodedChunk>);

impl PayloadList {
    /// The payload's transaction list: 163,000 allocations and a contiguous
    /// read, ~10 ms on the worker pool -- work for after the vote.
    pub fn copy_out(&self) -> Vec<Bytes> {
        copy_out(&self.0)
    }
}

/// The owned block of a [`DescribedBlock`], still to be made.
#[derive(Debug)]
pub struct BlockMaker {
    hash: B256,
    header: alloy_consensus::Header,
    withdrawals: Vec<Withdrawal>,
    transactions: Arc<Vec<DescribedTx>>,
    sidecar: alloy_rpc_types_engine::ExecutionPayloadSidecar,
}

/// A block a [`BlockMaker`] made.
#[derive(Debug)]
pub struct MadeBlock {
    /// The block, sealed, checked against the voted hash and by reth's
    /// well-formedness checks.
    pub block: SealedBlock<EthBlock>,
    /// The copy of the transactions out of the queue.
    pub copy_us: u64,
    /// Sealing and reth's checks.
    pub checks_us: u64,
}

impl BlockMaker {
    /// The owned block: the transactions copied out of the queue on the
    /// worker pool, the seal against the voted hash, reth's well-formedness
    /// checks on it and the payload's sidecar. The only per-transaction copy
    /// on this road, and the one reth's block type forces (see the module
    /// docs).
    pub fn make<ChainSpec>(self, validator: &N42EngineValidator<ChainSpec>) -> Result<MadeBlock, CompactBodyError>
    where
        ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    {
        use rayon::prelude::*;
        let Self { hash, header, withdrawals, transactions, sidecar } = self;
        let copy_at = std::time::Instant::now();
        let owned: Vec<TransactionSigned> =
            transactions.par_iter().map(|tx| tx.transaction().clone()).collect();
        let copy_us = copy_at.elapsed().as_micros() as u64;
        let checks_at = std::time::Instant::now();
        let withdrawals = header.withdrawals_root.map(|_| Withdrawals(withdrawals));
        let block = alloy_consensus::Block {
            header,
            body: alloy_consensus::BlockBody { transactions: owned, ommers: Vec::new(), withdrawals },
        };
        let block = validator.seal_and_check(block, hash, &sidecar)?;
        Ok(MadeBlock { block, copy_us, checks_us: checks_at.elapsed().as_micros() as u64 })
    }
}
