// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turning an Engine API payload back into the block that was hashed.
//!
//! An execution payload carries no `ommers_hash` and no `difficulty`; reth
//! fills in the post-merge values (the empty-list hash, zero) and checks that
//! the result hashes to the payload's block hash. A gov5 HotStuff header has
//! a zero ommers hash, so under that rule every block a Go member produces —
//! and every block this node's own validator process seals — is "block hash
//! mismatch". This validator knows the chain's header profile and, on a
//! HotStuff chain, reconstructs gov5's shape instead, letting the hash pick
//! between the variants gov5 has produced over time. Nothing is guessed: a
//! payload whose header hashes to none of them is refused exactly as before.
//!
//! Everything else reth checks about a payload — versioned hashes, fork
//! fields, the blob schedule — still runs, on the payload with its hash
//! adjusted to the Ethereum-shaped header so reth's own hash check passes.

use alloy_primitives::B256;
use alloy_rpc_types_engine::{ExecutionData, PayloadAttributes as EthPayloadAttributes, PayloadError};
use n42_h2_consensus::header_profile::N42HeaderProfile;
use n42_h2_consensus::reconstruct_gov5_h2_block_from;
use n42_qmdb_reth::HotStuffGenesisConfig;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_engine_primitives::{EngineApiValidator, EngineTypes, PayloadValidator};
use n42_tx_types::{Block as EthBlock, N42Primitives as EthPrimitives, N42TxEnvelope as TransactionSigned};
use reth_node_api::{AddOnsContext, FullNodeComponents, NodeTypes};
use reth_node_builder::rpc::PayloadValidatorBuilder;
use reth_node_ethereum::node::EthereumEngineValidator;
use reth_payload_primitives::{
    EngineApiMessageVersion, EngineObjectValidationError, NewPayloadError, PayloadOrAttributes,
    PayloadTypes,
};
use reth_primitives_traits::SealedBlock;
use std::sync::Arc;

mod by_description;
pub use by_description::{BlockMaker, DescribedBlock, DescribedInto, DescribedTx, MadeBlock, PayloadList, Queued};

/// The header profile a chain uses, read from its genesis.
///
/// A genesis that names a `hotstuff` validator set is driven by HotStuff-2
/// and its blocks are gov5-shaped; anything else is Ethereum-shaped.
pub fn header_profile_for<ChainSpec: EthChainSpec>(chain_spec: &ChainSpec) -> N42HeaderProfile {
    if HotStuffGenesisConfig::from_genesis(chain_spec.genesis()).is_ok() {
        N42HeaderProfile::Gov5H2
    } else {
        N42HeaderProfile::Ethereum
    }
}

/// reth's Ethereum payload validator, plus the chain's header profile.
#[derive(Clone, Debug)]
pub struct N42EngineValidator<ChainSpec> {
    inner: EthereumEngineValidator<ChainSpec>,
    /// The same chain spec `inner` holds, for the fork checks this validator
    /// runs itself.
    chain_spec: Arc<ChainSpec>,
    profile: N42HeaderProfile,
}

impl<ChainSpec> N42EngineValidator<ChainSpec> {
    /// A validator for `chain_spec` under `profile`.
    pub fn new(chain_spec: Arc<ChainSpec>, profile: N42HeaderProfile) -> Self {
        Self {
            inner: EthereumEngineValidator::new(chain_spec.clone()),
            chain_spec,
            profile,
        }
    }

    /// The profile in force.
    pub const fn profile(&self) -> N42HeaderProfile {
        self.profile
    }
}

impl<ChainSpec> N42EngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
{
    /// The block a gossip body describes, decoded once
    /// (`request::FOREIGN_BODY`).
    ///
    /// The twin of [`PayloadValidator::convert_payload_to_block`] for the
    /// bytes a follower actually received: `[header, transactions,
    /// verifiers, rewards]` as the producer put them on the wire. It ends
    /// where the payload conversion ends -- the same [`SealedBlock`] the
    /// import takes -- and hands back the [`ExecutionData`] beside it,
    /// because the engine's own pass still wants a payload and building one
    /// from parts already decoded costs a copy of the transaction bytes
    /// rather than a second parse.
    ///
    /// Every check the payload path runs is here, against the same values:
    ///
    /// - the header profile, and the rewards against the header's
    ///   withdrawals root (`decode_raw_block_body`);
    /// - the block hash the consensus layer voted on, twice: once against
    ///   the keccak of the header bytes as they arrived, before anything
    ///   expensive, and once against the sealed header, which also rejects a
    ///   header whose RLP is not canonical;
    /// - the transactions root. On the payload path the root is *computed*
    ///   and written into the reconstructed header, so the block hash binds
    ///   it; here the header arrives with its own root and the computed one
    ///   is compared against it, which binds the transactions to the block
    ///   the same way;
    /// - reth's well-formedness checks for Shanghai, Cancun and Prague, on
    ///   the same block and the same sidecar.
    ///
    /// What it does *not* do is reconstruct gov5's header by trying the
    /// variants against the hash: the body carries the header the producer
    /// sealed, ommers hash and difficulty included.
    ///
    /// `rlp` is borrowed, never kept: the transactions are decoded from
    /// slices of it and their bytes copied for the payload in the same
    /// parallel pass, and the access list is copied too. The copies are
    /// deliberate. A slice would keep the whole ~25 MB body alive for as
    /// long as anything downstream held one transaction's bytes, which grew
    /// this process by ~19 MB a block when the payload frame was decoded
    /// that way (loop60N1) -- and borrowing lets the caller keep one buffer
    /// and reuse it for every block instead of allocating a body's worth
    /// per block.
    pub fn convert_body_to_block(
        &self,
        announced: B256,
        profile: N42HeaderProfile,
        rlp: &[u8],
    ) -> Result<(SealedBlock<EthBlock>, ExecutionData), NewPayloadError> {
        use alloy_eips::eip4895::Withdrawals;
        let other = |message: String| NewPayloadError::Other(message.into());
        if profile != self.profile {
            return Err(other(format!(
                "body read under the {profile:?} header profile, this chain is {:?}",
                self.profile
            )));
        }
        let started = std::time::Instant::now();
        // One walk of the body: the header, the transactions as slices of
        // it, the rewards as withdrawals, the access list.
        let body = n42_h2_consensus::decode_raw_block_body_ref(rlp, profile)
            .map_err(|err| other(err.to_string()))?;
        if body.block_hash != announced {
            return Err(other(format!(
                "body is block {} and not the announced {announced}",
                body.block_hash
            )));
        }
        let walked = started.elapsed();
        let tx_count = body.transactions.len();

        // The root and the transactions, together, as the payload
        // conversion does it -- and the owned copies of the bytes in the
        // same pass, since it is already touching them.
        let (transactions_root, decoded) = rayon::join(
            || crate::assembler::parallel_ordered_trie_root(&body.transactions),
            || {
                use rayon::prelude::*;
                // Into a `Vec<Result>`, which rayon writes in place;
                // collecting straight into a `Result<Vec>` takes its
                // short-circuiting path and cost three times as much at
                // 163,000 items (round 43, `bench_convert_payload`).
                body.transactions
                    .par_iter()
                    .map(|tx| {
                        let decoded = <TransactionSigned as alloy_eips::Decodable2718>::decode_2718_exact(tx)
                            .map_err(alloy_rlp::Error::from)
                            .map_err(PayloadError::from)?;
                        Ok::<_, PayloadError>((decoded, alloy_primitives::Bytes::copy_from_slice(tx)))
                    })
                    .collect::<Vec<Result<_, _>>>()
            },
        );
        let joined = started.elapsed();
        let (transactions, raw_transactions): (Vec<_>, Vec<_>) =
            decoded.into_iter().collect::<Result<Vec<_>, _>>()?.into_iter().unzip();
        if transactions_root != body.header.transactions_root {
            return Err(PayloadError::BlockHash {
                execution: transactions_root,
                consensus: body.header.transactions_root,
            }
            .into());
        }

        // The payload the engine's own pass will take, built from the same
        // parts rather than parsed again. The access list is copied for the
        // same reason the transactions are: it is a slice of the body, and a
        // payload that outlives this call must not pin 25 MB behind one
        // field of it.
        let payload = n42_h2_consensus::execution_data_from_raw_parts(
            body.block_hash,
            &body.header,
            raw_transactions,
            body.withdrawals.clone(),
            body.bal.map(alloy_primitives::Bytes::copy_from_slice),
        );

        let withdrawals = body.header.withdrawals_root.map(|_| Withdrawals(body.withdrawals));
        let block = alloy_consensus::Block {
            header: body.header,
            body: alloy_consensus::BlockBody { transactions, ommers: Vec::new(), withdrawals },
        };
        let sealed = SealedBlock::seal_slow(block);
        if sealed.hash() != announced {
            return Err(PayloadError::BlockHash { execution: sealed.hash(), consensus: announced }.into());
        }
        let sealed_at = started.elapsed();

        // reth's checks on the block and its sidecar, the same three the
        // payload conversion runs.
        let timestamp = sealed.timestamp;
        reth_payload_validator::shanghai::ensure_well_formed_fields(
            sealed.body(),
            self.chain_spec.is_shanghai_active_at_timestamp(timestamp),
        )?;
        reth_payload_validator::cancun::ensure_well_formed_fields(
            &sealed,
            payload.sidecar.cancun(),
            self.chain_spec.is_cancun_active_at_timestamp(timestamp),
        )?;
        reth_payload_validator::prague::ensure_well_formed_fields(
            sealed.body(),
            payload.sidecar.prague(),
            self.chain_spec.is_prague_active_at_timestamp(timestamp),
        )?;
        if tx_count >= 10_000 {
            tracing::info!(
                target: "n42::engine_validator",
                number = sealed.number,
                txs = tx_count,
                walk_ms = walked.as_millis() as u64,
                join_ms = joined.saturating_sub(walked).as_millis() as u64,
                seal_ms = sealed_at.saturating_sub(joined).as_millis() as u64,
                checks_ms = started.elapsed().saturating_sub(sealed_at).as_millis() as u64,
                total_ms = started.elapsed().as_millis() as u64,
                "body converted"
            );
        }
        Ok((sealed, payload))
    }
}

/// The sender of a transaction that never reached this node's ingest, so
/// nothing recorded one for it: recovered here, the way the foreign-body
/// road recovers every sender it does not find cached.
fn sender_of(tx: &TransactionSigned) -> Result<alloy_primitives::Address, String> {
    use reth_primitives_traits::SignerRecoverable;
    match tx {
        TransactionSigned::AltSig(alt) => {
            let cache = n42_tx_types::AltSigSenderCache::global();
            if let Some(sender) = cache.get(alt.hash()) {
                return Ok(sender);
            }
            let sender = n42_tx_types::verify_batch(&[alt])
                .into_iter()
                .next()
                .unwrap_or(Err(n42_tx_types::AltSigError::UnknownAlgorithm(0)))
                .map_err(|err| err.to_string())?;
            cache.insert(*alt.hash(), sender);
            Ok(sender)
        }
        TransactionSigned::Eth(_) => tx.recover_signer().map_err(|err| err.to_string()),
    }
}

/// Why a compact body did not become a block.
#[derive(Debug)]
pub enum CompactBodyError {
    /// This node does not hold every transaction the body names, even after
    /// waiting for its ingest. Not a fault of the block: the caller asks for
    /// what is missing and, failing that, for the whole body.
    ///
    /// It carries enough for a leg's logs to say *which* transactions they
    /// are without another instrument: how many of how many, where they sit
    /// in the block, and a few hashes to look up in the flood's own record.
    /// loop195 wanted exactly this and had only a count.
    Missing {
        /// The block's positions this node cannot fill, in block order.
        indices: Vec<usize>,
        /// How many transactions the block has.
        total: usize,
        /// The first few missing hashes, for the log line.
        sample: Vec<B256>,
        /// How long the wait for the ingest lasted.
        waited: std::time::Duration,
    },
    /// The body is not the block it says it is. The caller must not vote on
    /// it and must not go looking for a better copy of the same thing.
    Invalid(NewPayloadError),
}

impl std::fmt::Display for CompactBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing { indices, total, sample, waited } => {
                write!(
                    f,
                    "compact body: {} of {total} transactions not held here, at {}, first",
                    indices.len(),
                    match (indices.first(), indices.last()) {
                        (Some(first), Some(last)) if first == last => format!("index {first}"),
                        (Some(first), Some(last)) => format!("indices {first}..{last}"),
                        _ => "no index".to_owned(),
                    },
                )?;
                for hash in sample {
                    write!(f, " {hash}")?;
                }
                write!(f, ", waited {} ms", waited.as_millis())
            }
            Self::Invalid(err) => write!(f, "compact body: {err}"),
        }
    }
}

/// A block assembled from a compact body, with what the assembly cost.
#[derive(Debug)]
pub struct AssembledBlock {
    /// The block, sealed and checked against the hash consensus voted on.
    pub block: SealedBlock<EthBlock>,
    /// The payload the engine's own pass takes, from the same parts.
    pub payload: ExecutionData,
    /// Every transaction's sender, as this node recorded it when it ingested
    /// the transaction -- so the import does not look them up again.
    pub senders: Vec<alloy_primitives::Address>,
    /// Finding the transactions in the queue and unpacking them, without
    /// the wait: the four timings are disjoint and sum to `total_us`.
    pub assemble_us: u64,
    /// The whole call, so a caller's line can name what the parts leave
    /// over instead of hiding it.
    pub total_us: u64,
    /// Encoding them and building the transactions trie.
    pub root_us: u64,
    /// Waiting for the ingest to catch up on a first-pass miss.
    pub miss_wait_us: u64,
    /// Checking, decoding and recovering the transactions the frame
    /// supplied for positions this node could not fill (the second attempt
    /// at a block whose first one missed); 0 on a frame with no fill.
    pub fill_us: u64,
    /// How many positions the frame supplied.
    pub filled: usize,
    /// How many of the hashes the first pass did not find.
    pub misses: usize,
}

impl<ChainSpec> N42EngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
{
    /// The block a *compact* body describes, assembled from this node's own
    /// transaction queue (`N42_COMPACT_BODY`).
    ///
    /// The twin of [`Self::convert_body_to_block`] for a body that names its
    /// transactions instead of carrying them. On a fleet where every node
    /// ingests every transaction the follower has already decoded each of
    /// them, verified its signature and recorded its sender before the block
    /// exists; this finds them by hash and puts the block together, which is
    /// what takes the 26 MB transfer, the 163,000-transaction decode and the
    /// sender look-ups off the vote road (43 + 82 + 38 ms of a 240 ms
    /// binding term, loop194 X2b).
    ///
    /// The checks are the ones the body road makes, against the same values:
    ///
    /// - the header profile, and the rewards against the header's
    ///   withdrawals root (`decode_compact_body`);
    /// - the block hash consensus voted on, against the keccak of the header
    ///   bytes as they arrived and again against the sealed header;
    /// - **the transactions root, recomputed over the list assembled here
    ///   and compared with the header's.** On this road that is the whole
    ///   binding between the hashes the body named and the block that was
    ///   voted on: a reordered, duplicated or substituted list produces a
    ///   different root and is refused here. It is not optional and it is not
    ///   implied by anything else;
    /// - reth's well-formedness checks for Shanghai, Cancun and Prague.
    ///
    /// A hash this node does not hold is not a fault: `miss_wait` is spent
    /// letting the ingest land (it is a few milliseconds behind the leader's
    /// block at most, and the queue's inbox is drained here rather than
    /// waited for), and after it the caller is told to ask for the whole
    /// body. Nothing is ever voted on that was not fully assembled and
    /// root-checked.
    pub fn convert_compact_body_to_block(
        &self,
        announced: B256,
        profile: N42HeaderProfile,
        compact: &[u8],
        queue: &n42_tx_queue::TxQueue<crate::N42PooledTransaction>,
        miss_wait: std::time::Duration,
    ) -> Result<AssembledBlock, CompactBodyError> {
        let other = |message: String| CompactBodyError::Invalid(NewPayloadError::Other(message.into()));
        if profile != self.profile {
            return Err(other(format!(
                "body read under the {profile:?} header profile, this chain is {:?}",
                self.profile
            )));
        }
        let started = std::time::Instant::now();
        let body = n42_h2_consensus::decode_compact_body(compact, profile)
            .map_err(|err| other(err.to_string()))?;
        if body.block_hash != announced {
            return Err(other(format!(
                "body is block {} and not the announced {announced}",
                body.block_hash
            )));
        }

        let filled_at = std::time::Instant::now();
        let supplied = supplied_from_fill(&body)?;
        let fill_us = filled_at.elapsed().as_micros() as u64;

        // The rest, out of this node's queue by the hashes the body names.
        // Nothing is removed: the canonical prune is still what takes a
        // block's transactions out of the queue, exactly as on the body road.
        // One pass: the look-up and the copy the block needs, on the worker
        // that did the look-up. See `TxQueue::recovered_by_hashes`.
        let lookup_at = std::time::Instant::now();
        let mut held = queue.recovered_by_hashes(&body.hashes);
        let first_pass = lookup_at.elapsed();
        let covered: std::collections::HashSet<usize> =
            supplied.iter().map(|(index, _, _)| *index).collect();
        let mut misses: Vec<usize> = held
            .iter()
            .enumerate()
            .filter(|(i, tx)| tx.is_none() && !covered.contains(i))
            .map(|(i, _)| i)
            .collect();
        let first_misses = misses.len();
        let waited_at = std::time::Instant::now();
        // A miss is usually this node's ingest being a few milliseconds
        // behind the leader's block, so the inbox is drained and the misses
        // asked for again rather than waited out.
        while !misses.is_empty() && waited_at.elapsed() < miss_wait {
            queue.drain_now();
            let again: Vec<B256> = misses.iter().map(|&i| body.hashes[i]).collect();
            let found = queue.recovered_by_hashes(&again);
            let mut still = Vec::new();
            for (slot, found) in misses.iter().copied().zip(found) {
                match found {
                    Some(tx) => held[slot] = Some(tx),
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
        self.finish_assembly(body, announced, held, supplied, started, first_pass, first_misses, miss_wait_us, fill_us)
    }

    /// The rest of [`Self::convert_compact_body_to_block`], once every
    /// position is held: the owned block, its root against the header's, the
    /// payload and reth's checks.
    #[allow(clippy::too_many_arguments)]
    fn finish_assembly(
        &self,
        body: n42_h2_consensus::CompactBlockBody<'_>,
        announced: B256,
        mut held: Vec<Option<(TransactionSigned, alloy_primitives::Address)>>,
        supplied: Vec<(usize, alloy_primitives::Address, TransactionSigned)>,
        started: std::time::Instant,
        first_pass: std::time::Duration,
        first_misses: usize,
        miss_wait_us: u64,
        fill_us: u64,
    ) -> Result<AssembledBlock, CompactBodyError> {
        use alloy_eips::eip4895::Withdrawals;
        use rayon::prelude::*;
        let unzip_at = std::time::Instant::now();
        // The supplied ones take their own positions, and the two vectors
        // the block and its import want come out in parallel: a serial
        // `unzip` moves 163,000 transactions a second time, ~45 MB, on one
        // core.
        for (index, sender, tx) in supplied {
            if let Some(slot) = held.get_mut(index) {
                *slot = Some((tx, sender));
            }
        }
        let (transactions, senders): (Vec<TransactionSigned>, Vec<alloy_primitives::Address>) =
            held.into_par_iter().flatten().unzip();
        if transactions.len() != body.hashes.len() {
            // Unreachable: the caller returned on any miss. Checked rather
            // than assumed, because the alternative to a check here is an
            // unwrap on the vote road.
            return Err(CompactBodyError::Missing {
                indices: (transactions.len()..body.hashes.len()).collect(),
                total: body.hashes.len(),
                sample: body.hashes.get(transactions.len()).copied().into_iter().collect(),
                waited: std::time::Duration::ZERO,
            });
        }
        let assemble_us = (first_pass + unzip_at.elapsed()).as_micros() as u64;

        // What binds the assembled list to the header: the trie over the
        // transactions' EIP-2718 encodings, against the root the producer
        // sealed. The encodings are kept, because the payload the engine's
        // own pass takes lists transactions in exactly that form.
        let root_at = std::time::Instant::now();
        let encoded: Vec<alloy_primitives::Bytes> = transactions
            .par_iter()
            .map(|tx| alloy_primitives::Bytes::from(alloy_eips::Encodable2718::encoded_2718(tx)))
            .collect();
        let transactions_root = crate::assembler::parallel_ordered_trie_root(&encoded);
        let root_us = root_at.elapsed().as_micros() as u64;
        if transactions_root != body.header.transactions_root {
            return Err(CompactBodyError::Invalid(
                PayloadError::BlockHash {
                    execution: transactions_root,
                    consensus: body.header.transactions_root,
                }
                .into(),
            ));
        }

        let payload = n42_h2_consensus::execution_data_from_raw_parts(
            body.block_hash,
            &body.header,
            encoded,
            body.withdrawals.clone(),
            body.bal.map(alloy_primitives::Bytes::copy_from_slice),
        );
        let withdrawals = body.header.withdrawals_root.map(|_| Withdrawals(body.withdrawals.clone()));
        let block = alloy_consensus::Block {
            header: body.header.clone(),
            body: alloy_consensus::BlockBody { transactions, ommers: Vec::new(), withdrawals },
        };
        let sealed = self.seal_and_check(block, announced, &payload.sidecar)?;
        Ok(AssembledBlock {
            block: sealed,
            payload,
            senders,
            assemble_us,
            root_us,
            miss_wait_us,
            misses: first_misses,
            fill_us,
            filled: body.fill.len(),
            total_us: started.elapsed().as_micros() as u64,
        })
    }

    /// Seals a block put together from a compact body, checks it is the one
    /// consensus voted on, and runs reth's well-formedness checks on it and
    /// its payload's sidecar -- the same three the payload conversion runs.
    fn seal_and_check(
        &self,
        block: EthBlock,
        announced: B256,
        sidecar: &alloy_rpc_types_engine::ExecutionPayloadSidecar,
    ) -> Result<SealedBlock<EthBlock>, CompactBodyError> {
        let sealed = SealedBlock::seal_slow(block);
        if sealed.hash() != announced {
            return Err(CompactBodyError::Invalid(
                PayloadError::BlockHash { execution: sealed.hash(), consensus: announced }.into(),
            ));
        }
        let timestamp = sealed.timestamp;
        let checks = |err: PayloadError| CompactBodyError::Invalid(err.into());
        reth_payload_validator::shanghai::ensure_well_formed_fields(
            sealed.body(),
            self.chain_spec.is_shanghai_active_at_timestamp(timestamp),
        )
        .map_err(checks)?;
        reth_payload_validator::cancun::ensure_well_formed_fields(
            &sealed,
            sidecar.cancun(),
            self.chain_spec.is_cancun_active_at_timestamp(timestamp),
        )
        .map_err(checks)?;
        reth_payload_validator::prague::ensure_well_formed_fields(
            sealed.body(),
            sidecar.prague(),
            self.chain_spec.is_prague_active_at_timestamp(timestamp),
        )
        .map_err(checks)?;
        Ok(sealed)
    }
}

/// The transactions supplied with a compact frame, for the positions a first
/// attempt could not fill from the queue (see `compact_body::with_fill`),
/// with their senders.
///
/// Each is checked against the hash the body names for its position before
/// it is used: a peer that answers a request for index 7 with something else
/// is refused here, by name, rather than left to the transactions root to
/// catch as a mismatch. The senders are recovered here: these transactions
/// never reached this node's ingest, so nothing recorded one for them.
fn supplied_from_fill(
    body: &n42_h2_consensus::CompactBlockBody<'_>,
) -> Result<Vec<(usize, alloy_primitives::Address, TransactionSigned)>, CompactBodyError> {
    let other = |message: String| CompactBodyError::Invalid(NewPayloadError::Other(message.into()));
    {
        let supplied: Vec<(usize, TransactionSigned)> = {
            use rayon::prelude::*;
            let checked: Vec<Result<(usize, TransactionSigned), String>> = body
                .fill
                .par_iter()
                .map(|(index, bytes)| {
                    let want = body.hashes.get(*index).copied().ok_or_else(|| {
                        format!("the fill names index {index}, which the body does not have")
                    })?;
                    if alloy_primitives::keccak256(bytes) != want {
                        return Err(format!(
                            "the transaction supplied for index {index} is not {want}"
                        ));
                    }
                    <TransactionSigned as alloy_eips::Decodable2718>::decode_2718_exact(bytes)
                        .map(|tx| (*index, tx))
                        .map_err(|err| format!("the transaction supplied for index {index}: {err}"))
                })
                .collect();
            checked.into_iter().collect::<Result<Vec<_>, String>>().map_err(other)?
        };
        // Their senders, recovered here: they never reached this node's
        // ingest, so nothing recorded one for them.
        let supplied: Vec<(usize, alloy_primitives::Address, TransactionSigned)> = {
            use rayon::prelude::*;
            let recovered: Vec<Result<_, String>> = supplied
                .into_par_iter()
                .map(|(index, tx)| {
                    let sender = sender_of(&tx)
                        .map_err(|err| format!("the sender of the transaction at index {index}: {err}"))?;
                    Ok((index, sender, tx))
                })
                .collect();
            recovered.into_iter().collect::<Result<Vec<_>, String>>().map_err(other)?
        };
        Ok(supplied)
    }
}

impl<ChainSpec, Types> PayloadValidator<Types> for N42EngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<ExecutionData = ExecutionData>,
{
    type Block = EthBlock;

    fn convert_payload_to_block(
        &self,
        payload: ExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        if self.profile == N42HeaderProfile::Ethereum {
            // reth's own conversion is pinned to its Ethereum envelope; this is
            // the same decode over the node's, checked against the announced hash.
            let expected_hash = payload.block_hash();
            let block = payload.try_into_block::<TransactionSigned>()?;
            let sealed = SealedBlock::seal_slow(block);
            if sealed.hash() != expected_hash {
                return Err(PayloadError::BlockHash { execution: sealed.hash(), consensus: expected_hash }.into());
            }
            return Ok(sealed);
        }

        let expected_hash = payload.block_hash();
        // A block this node built and has just handed to the engine as
        // executed: the payload is its own, and the block is already made.
        if let Some(block) = crate::built_executions::find_sealed(expected_hash) {
            let payload_transactions = payload.payload.as_v1().transactions.len();
            if payload_transactions == 0 || payload_transactions != block.body().transactions.len() {
                tracing::info!(
                    target: "n42::engine_validator",
                    number = block.number, block = ?expected_hash, sealed_transactions = block.body().transactions.len(), payload_transactions,
                    "payload converted from the sealed block kept for it"
                );
            }
            return Ok(block);
        }
        let started = std::time::Instant::now();
        let tx_count = payload.payload.as_v1().transactions.len();
        // The header-only own-block payload carries no transactions at all;
        // its body is the sealed block above. Without it there is nothing to
        // execute -- decoding the empty list made a block with an empty body
        // under the announced header, and the engine executed it (loop147:
        // receipts root empty, gas 0 recorded for the block, every header
        // after it rejected). The validator's fallback sends the full payload.
        if tx_count == 0 && crate::built_executions::sealed_here_with_transactions(expected_hash) {
            return Err(NewPayloadError::Other(
                format!("header-only own-block payload {expected_hash}: the sealed block is no longer kept; send the full payload").into(),
            ));
        }

        // Decoded once. This used to be three full conversions of the same
        // payload -- the reconstruction, a second to learn the Ethereum-shaped
        // hash, and a third inside reth's well-formedness check -- each of
        // them 163,000 transaction decodes, a hash per transaction and the
        // transactions trie, on the follower's critical path before the block
        // was even handed to the engine. A CPU profile of a follower showed
        // the conversion thread as busy as the execution thread.
        // The transactions root and the transaction decodes are independent,
        // and both are over the same bytes: the root goes on the header, the
        // decodes into the body. Sequentially that was 160-200 ms of a
        // follower's import at the 163,000-transaction tier; here the root is
        // computed while the decodes run on the worker pool.
        let raw_transactions = payload.payload.as_v1().transactions.clone();
        let (transactions_root, decoded_transactions) = rayon::join(
            || crate::assembler::parallel_ordered_trie_root(&raw_transactions),
            || {
                use rayon::prelude::*;
                // Into a `Vec<Result>`, which rayon writes in place; collecting
                // a parallel iterator straight into a `Result<Vec>` goes through
                // its short-circuiting path -- a linked list of pieces
                // concatenated afterwards -- and cost 33 ms against 11 for the
                // same 163,000 decodes (round 43, `bench_convert_payload`).
                raw_transactions
                    .par_iter()
                    .map(|tx| {
                        <TransactionSigned as alloy_eips::Decodable2718>::decode_2718_exact(tx.as_ref())
                            .map_err(alloy_rlp::Error::from)
                            .map_err(PayloadError::from)
                    })
                    .collect::<Vec<Result<_, _>>>()
            },
        );
        let joined = started.elapsed();
        let decoded_transactions = decoded_transactions.into_iter().collect::<Result<Vec<_>, _>>()?;
        let raw_block = payload
            .payload
            .clone()
            .into_block_with_sidecar_raw_with_transactions_root(&payload.sidecar, transactions_root)?;
        let ethereum_shaped = alloy_consensus::Block {
            header: raw_block.header,
            body: alloy_consensus::BlockBody {
                transactions: decoded_transactions,
                ommers: raw_block.body.ommers,
                withdrawals: raw_block.body.withdrawals,
            },
        };
        let raw_built = started.elapsed();
        let ethereum_shaped = SealedBlock::seal_slow(ethereum_shaped);
        let decoded = started.elapsed();

        // reth's checks on the Ethereum-shaped block, the same ones its own
        // validator runs after converting: fork fields and sidecar shape. Its
        // verdict on those is the one that counts; the hash comparison is
        // this validator's, against gov5's header, below.
        let timestamp = ethereum_shaped.timestamp;
        reth_payload_validator::shanghai::ensure_well_formed_fields(
            ethereum_shaped.body(),
            self.chain_spec.is_shanghai_active_at_timestamp(timestamp),
        )?;
        reth_payload_validator::cancun::ensure_well_formed_fields(
            &ethereum_shaped,
            payload.sidecar.cancun(),
            self.chain_spec.is_cancun_active_at_timestamp(timestamp),
        )?;
        reth_payload_validator::prague::ensure_well_formed_fields(
            ethereum_shaped.body(),
            payload.sidecar.prague(),
            self.chain_spec.is_prague_active_at_timestamp(timestamp),
        )?;

        // The block gov5 hashed: header profile checked, ommers hash and
        // difficulty restored, hash confirmed -- header arithmetic on the
        // block already decoded.
        let checked = started.elapsed();
        let block = reconstruct_gov5_h2_block_from(ethereum_shaped.into_block(), &payload)
            .map_err(|err| NewPayloadError::Other(err.into()))?;

        let sealed = SealedBlock::seal_slow(block);
        if tx_count >= 10_000 {
            tracing::info!(
                target: "n42::engine_validator",
                number = sealed.number,
                txs = tx_count,
                decode_ms = decoded.as_millis() as u64,
                join_ms = joined.as_millis() as u64,
                raw_block_ms = raw_built.saturating_sub(joined).as_millis() as u64,
                seal_ms = decoded.saturating_sub(raw_built).as_millis() as u64,
                checks_ms = checked.saturating_sub(decoded).as_millis() as u64,
                reconstruct_ms = started.elapsed().saturating_sub(checked).as_millis() as u64,
                "payload converted"
            );
        }
        if sealed.hash() != expected_hash {
            // Cannot happen after reconstruction confirmed the hash; kept
            // so a future change to either side fails loudly.
            return Err(PayloadError::BlockHash {
                execution: sealed.hash(),
                consensus: expected_hash,
            }
            .into());
        }
        Ok(sealed)
    }
}

impl<ChainSpec, Types> EngineApiValidator<Types> for N42EngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<PayloadAttributes = EthPayloadAttributes, ExecutionData = ExecutionData>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, ExecutionData, EthPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        <EthereumEngineValidator<ChainSpec> as EngineApiValidator<Types>>::validate_version_specific_fields(
            &self.inner,
            version,
            payload_or_attrs,
        )
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &EthPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        <EthereumEngineValidator<ChainSpec> as EngineApiValidator<Types>>::ensure_well_formed_attributes(
            &self.inner,
            version,
            attributes,
        )
    }
}

/// Builds [`N42EngineValidator`] for the node, reading the profile from the
/// chain it is launched on.
#[derive(Clone, Copy, Debug, Default)]
pub struct N42EngineValidatorBuilder;

impl<Node, Types> PayloadValidatorBuilder<Node> for N42EngineValidatorBuilder
where
    Types: NodeTypes<
        ChainSpec: EthChainSpec + EthereumHardforks + Clone + 'static,
        Payload: EngineTypes<ExecutionData = ExecutionData>
                     + PayloadTypes<PayloadAttributes = EthPayloadAttributes>,
        Primitives = EthPrimitives,
    >,
    Node: FullNodeComponents<Types = Types>,
{
    type Validator = N42EngineValidator<Types::ChainSpec>;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        let chain_spec = ctx.config.chain.clone();
        let profile = header_profile_for(chain_spec.as_ref());
        Ok(N42EngineValidator::new(chain_spec, profile))
    }
}

/// Convenience for tests and callers holding a hash: is this the value
/// gov5's producer leaves in `ommers_hash`?
pub fn is_gov5_ommers_hash(hash: B256) -> bool {
    hash == B256::ZERO
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, EMPTY_OMMER_ROOT_HASH, EMPTY_ROOT_HASH};
    use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
    use alloy_primitives::{Bytes, U256};
    use n42_h2_consensus::{block_for_header, execution_data_for_block, HeaderExtra, GOV5_NIL_HASH};
    use reth_chainspec::{ChainSpec, MAINNET};
    use crate::engine_types::N42EngineTypes as EthEngineTypes;

    fn gov5_header(ommers_hash: B256, difficulty: U256) -> Header {
        Header {
            parent_hash: B256::repeat_byte(1),
            ommers_hash,
            state_root: B256::repeat_byte(2),
            transactions_root: EMPTY_ROOT_HASH,
            receipts_root: GOV5_NIL_HASH,
            difficulty,
            number: 7,
            gas_limit: 30_000_000,
            // Post-Prague on mainnet, so reth's fork checks want every field.
            timestamp: 1_800_000_000,
            extra_data: HeaderExtra::for_view(7).encode(),
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: Some(EMPTY_REQUESTS_HASH),
            ..Default::default()
        }
    }

    fn payload_for(header: Header) -> ExecutionData {
        let block = block_for_header(header, vec![]);
        execution_data_for_block(block.header.hash_slow(), &block)
    }

    fn validator(profile: N42HeaderProfile) -> N42EngineValidator<ChainSpec> {
        N42EngineValidator::new(MAINNET.clone(), profile)
    }

    fn convert(
        validator: &N42EngineValidator<ChainSpec>,
        payload: ExecutionData,
    ) -> Result<SealedBlock<EthBlock>, NewPayloadError> {
        <N42EngineValidator<ChainSpec> as PayloadValidator<EthEngineTypes>>::convert_payload_to_block(
            validator, payload,
        )
    }

    /// Where a full block's conversion goes: 163,000 transfers through
    /// `convert_payload_to_block`. `cargo test --release -p n42-engine-types
    /// --lib bench_convert_payload -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing"]
    fn bench_convert_payload() {
        use alloy_consensus::{Signed, TxEip1559, TxEnvelope};
        use alloy_primitives::{Address, Signature, TxKind};
        let n: u64 = std::env::var("BENCH_TXS").ok().and_then(|v| v.parse().ok()).unwrap_or(163_000);
        let txs: Vec<TxEnvelope> = (0..n)
            .map(|i| {
                let inner = TxEip1559 {
                    chain_id: 1,
                    nonce: i % 400,
                    gas_limit: 21_000,
                    max_fee_per_gas: 10_000_000_000,
                    max_priority_fee_per_gas: 1_000_000_000,
                    to: TxKind::Call(Address::from_slice(&[[0u8; 12].as_slice(), &(i * 7919).to_be_bytes()].concat())),
                    value: U256::from(1_000 + i),
                    ..Default::default()
                };
                TxEnvelope::Eip1559(Signed::new_unchecked(inner, Signature::test_signature(), B256::random()))
            })
            .collect();
        let mut header = gov5_header(B256::ZERO, U256::ZERO);
        header.gas_limit = 10_000_000_000;
        header.gas_used = 21_000 * n;
        header.transactions_root = alloy_consensus::proofs::calculate_transaction_root(&txs);
        let block = block_for_header(header, txs);
        let payload = execution_data_for_block(block.header.hash_slow(), &block);
        let bytes: usize = payload.payload.as_v1().transactions.iter().map(|t| t.len()).sum();
        println!("payload: {n} transactions, {:.1} MB", bytes as f64 / 1e6);
        let _ = tracing_subscriber::fmt().with_env_filter("n42::engine_validator=info").without_time().try_init();
        let v = validator(N42HeaderProfile::Gov5H2);
        for round in 0..3 {
            let at = std::time::Instant::now();
            let sealed = convert(&v, payload.clone()).expect("converts");
            println!("round {round}: {} ms (hash {})", at.elapsed().as_millis(), sealed.hash());
        }
        // The pieces, each alone.
        for _ in 0..2 {
            let raw = payload.payload.as_v1().transactions.clone();
            let at = std::time::Instant::now();
            let root = crate::assembler::parallel_ordered_trie_root(&raw);
            let t_root = at.elapsed();
            let at = std::time::Instant::now();
            let (_root2, decoded2) = rayon::join(
                || crate::assembler::parallel_ordered_trie_root(&raw),
                || {
                    use rayon::prelude::*;
                    raw.par_iter()
                        .map(|tx| <TransactionSigned as alloy_eips::Decodable2718>::decode_2718_exact(tx.as_ref()).unwrap())
                        .collect::<Vec<_>>()
                },
            );
            let t_join = at.elapsed();
            let at = std::time::Instant::now();
            drop(decoded2);
            let t_drop2 = at.elapsed();
            let at = std::time::Instant::now();
            let decoded: Vec<TransactionSigned> = {
                use rayon::prelude::*;
                raw.par_iter()
                    .map(|tx| <TransactionSigned as alloy_eips::Decodable2718>::decode_2718_exact(tx.as_ref()).unwrap())
                    .collect()
            };
            let t_decode = at.elapsed();
            let at = std::time::Instant::now();
            let decoded_serial: Vec<TransactionSigned> = raw
                .iter()
                .map(|tx| <TransactionSigned as alloy_eips::Decodable2718>::decode_2718_exact(tx.as_ref()).unwrap())
                .collect();
            let t_decode_serial = at.elapsed();
            let at = std::time::Instant::now();
            let raw_block = payload
                .payload
                .clone()
                .into_block_with_sidecar_raw_with_transactions_root(&payload.sidecar, root)
                .unwrap();
            let t_raw_block = at.elapsed();
            let at = std::time::Instant::now();
            let sealed = SealedBlock::seal_slow(alloy_consensus::Block {
                header: raw_block.header,
                body: alloy_consensus::BlockBody { transactions: decoded, ommers: raw_block.body.ommers, withdrawals: raw_block.body.withdrawals },
            });
            let t_seal = at.elapsed();
            let at = std::time::Instant::now();
            drop(sealed);
            drop(decoded_serial);
            let t_drop = at.elapsed();
            println!(
                "pieces: join(root, decode) {} ms (drop of its decodes {} ms); root {} ms, decode par {} ms (serial {} ms), raw block {} ms, seal {} ms, drop {} ms",
                t_join.as_millis(),
                t_drop2.as_millis(),
                t_root.as_millis(),
                t_decode.as_millis(),
                t_decode_serial.as_millis(),
                t_raw_block.as_millis(),
                t_seal.as_millis(),
                t_drop.as_millis()
            );
        }
    }

    /// An Amsterdam block as the raw payload path seals it -- the header's
    /// access-list hash is EIP-7928's, its slot number set -- converts back
    /// to the same hash through the parallel conversion. Round ams4k refused
    /// every Amsterdam block at number 1 with "no gov5 header variant".

    /// The wire form of a block whose payload is `payload`, as a producer
    /// puts it on gov5's block topic: `[header, txs, verifiers, rewards]`.
    fn body_for(payload: &ExecutionData, header: &Header) -> Bytes {
        let rewards = n42_h2_consensus::withdrawals_to_rewards(
            payload.payload.as_v2().map_or(&[][..], |v2| v2.withdrawals.as_slice()),
        );
        let bal = match &payload.payload {
            alloy_rpc_types_engine::ExecutionPayload::V4(v4) => Some(v4.block_access_list.clone()),
            _ => None,
        };
        Bytes::from(n42_h2_consensus::encode_block_rlp_raw(
            header,
            &payload.payload.as_v1().transactions,
            &rewards,
            bal.as_ref(),
        ))
    }

    /// Transactions of every type this chain carries, so the body path and
    /// the payload path are compared on all three decoders: legacy,
    /// EIP-1559, and N42's 0x50 (AltSig).
    fn mixed_transactions() -> Vec<TransactionSigned> {
        use alloy_consensus::{Signed, TxEip1559, TxLegacy};
        use alloy_primitives::{Address, Signature, TxKind};
        let legacy = TxLegacy {
            chain_id: Some(1),
            nonce: 1,
            gas_price: 10_000_000_000,
            gas_limit: 21_000,
            to: TxKind::Call(Address::repeat_byte(0x11)),
            value: U256::from(1),
            input: Bytes::new(),
        };
        let eip1559 = TxEip1559 {
            chain_id: 1,
            nonce: 2,
            gas_limit: 21_000,
            max_fee_per_gas: 10_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(Address::repeat_byte(0x22)),
            value: U256::from(2),
            ..Default::default()
        };
        // The signature is never checked by a decode; what is under test is
        // that the body path and the payload path read the same bytes the
        // same way.
        let alt = n42_tx_types::AltSigTx::new(
            n42_tx_types::TxAltSig {
                chain_id: 1,
                nonce: 3,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 10_000_000_000,
                gas_limit: 21_000,
                to: Address::repeat_byte(0x66),
                value: U256::from(3),
                input: Bytes::new(),
                access_list: Default::default(),
                alg_type: n42_tx_types::ALG_ED25519,
                pubkey: Bytes::from(vec![7u8; 32]),
            },
            Bytes::from(vec![8u8; 64]),
        );
        vec![
            TransactionSigned::Eth(alloy_consensus::TxEnvelope::Legacy(Signed::new_unchecked(
                legacy,
                Signature::test_signature(),
                B256::repeat_byte(0x33),
            )).into()),
            TransactionSigned::Eth(alloy_consensus::TxEnvelope::Eip1559(Signed::new_unchecked(
                eip1559,
                Signature::test_signature(),
                B256::repeat_byte(0x44),
            )).into()),
            TransactionSigned::AltSig(alt),
        ]
    }

    /// The whole point: a block decoded from the bytes the gossip delivered
    /// is the block the payload conversion produces from the same block --
    /// same hash, same transactions, same withdrawals -- for every
    /// transaction type this chain carries.
    #[test]
    fn a_body_converts_to_the_block_the_payload_conversion_produces() {
        use alloy_eips::Encodable2718;
        let transactions = mixed_transactions();
        let raw: Vec<Bytes> = transactions.iter().map(|tx| Bytes::from(tx.encoded_2718())).collect();
        let mut header = gov5_header(B256::ZERO, U256::ZERO);
        header.transactions_root = alloy_consensus::proofs::calculate_transaction_root(&transactions);
        header.gas_used = 63_000;
        let withdrawals = vec![alloy_eips::eip4895::Withdrawal {
            index: 0,
            validator_index: 0,
            address: alloy_primitives::Address::repeat_byte(0x55),
            amount: 1_000_000_000,
        }];
        header.withdrawals_root =
            Some(n42_h2_consensus::gov5_rewards_root(n42_h2_consensus::withdrawals_to_rewards(&withdrawals)));
        let payload = n42_h2_consensus::execution_data_from_raw_parts(
            B256::ZERO,
            &header,
            raw,
            withdrawals,
            None,
        );
        let hash = header.hash_slow();
        let mut payload = payload;
        payload.payload.as_v1_mut().block_hash = hash;
        let body = body_for(&payload, &header);

        let validator = validator(N42HeaderProfile::Gov5H2);
        let from_payload = convert(&validator, payload.clone()).expect("the payload converts");
        let (from_body, rebuilt) = validator
            .convert_body_to_block(hash, N42HeaderProfile::Gov5H2, &body)
            .expect("the body converts");

        assert_eq!(from_body.hash(), from_payload.hash());
        assert_eq!(from_body.hash(), hash);
        assert_eq!(from_body.header(), from_payload.header());
        assert_eq!(from_body.body().transactions, from_payload.body().transactions);
        assert_eq!(from_body.body().withdrawals, from_payload.body().withdrawals);
        // And the payload it hands back is the one the validator would have
        // sent, so the engine's own pass sees no difference.
        assert_eq!(format!("{rebuilt:?}"), format!("{payload:?}"));
    }

    /// A queue holding `transactions` under the senders given, the way a
    /// node's ingest leaves them: this is what the compact body road
    /// assembles a block out of.
    fn queue_holding(
        transactions: &[TransactionSigned],
        senders: &[alloy_primitives::Address],
    ) -> n42_tx_queue::TxQueue<crate::N42PooledTransaction> {
        use alloy_eips::Encodable2718;
        let queue = n42_tx_queue::TxQueue::<crate::N42PooledTransaction>::with_run_length(1)
            .with_hash_index(1024);
        queue.push(transactions.iter().zip(senders).map(|(tx, sender)| {
            crate::N42PooledTransaction::new(
                reth_primitives_traits::Recovered::new_unchecked(tx.clone(), *sender),
                tx.encoded_2718().len(),
            )
        }));
        queue.drain_now();
        queue
    }

    /// The senders the queue is filled with: one per transaction, distinct,
    /// so a block assembled out of the queue can be checked to carry the
    /// queue's senders rather than anything the body claimed.
    fn senders_for(transactions: &[TransactionSigned]) -> Vec<alloy_primitives::Address> {
        (0..transactions.len()).map(|i| alloy_primitives::Address::repeat_byte(0x90 + i as u8)).collect()
    }

    /// A transaction of this chain that is not in the block under test.
    fn other_transaction() -> TransactionSigned {
        use alloy_consensus::{Signed, TxEip1559};
        use alloy_primitives::{Address, Signature, TxKind};
        let tx = TxEip1559 {
            chain_id: 1,
            nonce: 9,
            gas_limit: 21_000,
            max_fee_per_gas: 10_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(Address::repeat_byte(0x77)),
            value: U256::from(9),
            ..Default::default()
        };
        TransactionSigned::Eth(
            alloy_consensus::TxEnvelope::Eip1559(Signed::new_unchecked(
                tx,
                Signature::test_signature(),
                B256::repeat_byte(0x99),
            ))
            .into(),
        )
    }

    /// A transaction as this node's ingest holds it: decoded from the bytes
    /// it arrived in, so its hash is the hash of those bytes. The fixtures
    /// above are built with a made-up cached hash, which is fine for a
    /// decode-against-decode comparison and not for a road that finds a
    /// transaction *by* its hash.
    fn as_ingested(tx: &TransactionSigned) -> TransactionSigned {
        use alloy_eips::{Decodable2718, Encodable2718};
        TransactionSigned::decode_2718_exact(&tx.encoded_2718()).expect("its own encoding decodes")
    }

    /// A block, its hash, the gov5 body and the payload, as
    /// `a_body_converts_to_the_block_the_payload_conversion_produces`
    /// builds them.
    fn mixed_block() -> (Header, B256, Bytes, ExecutionData, Vec<TransactionSigned>) {
        use alloy_eips::Encodable2718;
        let transactions: Vec<TransactionSigned> = mixed_transactions().iter().map(as_ingested).collect();
        let raw: Vec<Bytes> = transactions.iter().map(|tx| Bytes::from(tx.encoded_2718())).collect();
        let mut header = gov5_header(B256::ZERO, U256::ZERO);
        header.transactions_root = alloy_consensus::proofs::calculate_transaction_root(&transactions);
        header.gas_used = 63_000;
        let withdrawals = vec![alloy_eips::eip4895::Withdrawal {
            index: 0,
            validator_index: 0,
            address: alloy_primitives::Address::repeat_byte(0x55),
            amount: 1_000_000_000,
        }];
        header.withdrawals_root =
            Some(n42_h2_consensus::gov5_rewards_root(n42_h2_consensus::withdrawals_to_rewards(&withdrawals)));
        let mut payload =
            n42_h2_consensus::execution_data_from_raw_parts(B256::ZERO, &header, raw, withdrawals, None);
        let hash = header.hash_slow();
        payload.payload.as_v1_mut().block_hash = hash;
        let body = body_for(&payload, &header);
        (header, hash, body, payload, transactions)
    }

    fn hashes_of(transactions: &[TransactionSigned]) -> Vec<B256> {
        use alloy_consensus::transaction::TxHashRef;
        transactions.iter().map(|tx| *tx.tx_hash()).collect()
    }

    /// Long enough that a test never trips over a scheduling hiccup, short
    /// enough that the missing-transaction tests stay instant.
    const SHORT_WAIT: std::time::Duration = std::time::Duration::from_millis(5);

    /// The whole point of the compact body: a block assembled out of this
    /// node's queue from the hashes the body named is the block the
    /// foreign-body road decodes from the same block's bytes -- same hash,
    /// same header, same transactions -- for every transaction type this
    /// chain carries, and its senders are the queue's.
    #[test]
    fn a_compact_body_assembles_the_block_the_body_road_decodes() {
        let (_, hash, body, payload, transactions) = mixed_block();
        let senders = senders_for(&transactions);
        let queue = queue_holding(&transactions, &senders);
        let compact = n42_h2_consensus::encode_compact_body(
            &body,
            &hashes_of(&transactions),
            N42HeaderProfile::Gov5H2,
        )
        .expect("encodes");

        let validator = validator(N42HeaderProfile::Gov5H2);
        let (from_body, body_payload) = validator
            .convert_body_to_block(hash, N42HeaderProfile::Gov5H2, &body)
            .expect("the body converts");
        let assembled = validator
            .convert_compact_body_to_block(hash, N42HeaderProfile::Gov5H2, &compact, &queue, SHORT_WAIT)
            .expect("the compact body assembles");

        assert_eq!(assembled.block.hash(), from_body.hash());
        assert_eq!(assembled.block.hash(), hash);
        assert_eq!(assembled.block.header(), from_body.header());
        assert_eq!(assembled.block.body().transactions, from_body.body().transactions);
        assert_eq!(assembled.block.body().withdrawals, from_body.body().withdrawals);
        assert_eq!(assembled.senders, senders);
        assert_eq!(assembled.misses, 0);
        // And the payload both roads hand the engine is the same one.
        assert_eq!(format!("{:?}", assembled.payload), format!("{body_payload:?}"));
        assert_eq!(format!("{:?}", assembled.payload), format!("{payload:?}"));
    }

    /// A hash list that is not the block's is refused by the transactions
    /// root, which is the only thing binding the list to the header.
    #[test]
    fn a_hash_list_that_is_not_the_blocks_is_refused_by_the_root() {
        let (_, hash, body, _, transactions) = mixed_block();
        let senders = senders_for(&transactions);
        // A fourth transaction the queue holds and the block does not, so
        // "a hash the assembler can resolve" and "a hash of this block" are
        // told apart.
        let mut held = transactions.clone();
        held.push(as_ingested(&other_transaction()));
        let mut held_senders = senders.clone();
        held_senders.push(alloy_primitives::Address::repeat_byte(0xC1));
        let queue = queue_holding(&held, &held_senders);
        let validator = validator(N42HeaderProfile::Gov5H2);
        let hashes = hashes_of(&transactions);
        let outsider = hashes_of(&held)[3];

        let mut reordered = hashes.clone();
        reordered.swap(0, 1);
        let mut duplicated = hashes.clone();
        duplicated[2] = duplicated[0];
        let mut substituted = hashes.clone();
        substituted[1] = outsider;
        for (what, list) in
            [("reordered", reordered), ("duplicated", duplicated), ("substituted", substituted)]
        {
            let compact = n42_h2_consensus::encode_compact_body(&body, &list, N42HeaderProfile::Gov5H2)
                .expect("encodes");
            let refused = validator
                .convert_compact_body_to_block(hash, N42HeaderProfile::Gov5H2, &compact, &queue, SHORT_WAIT)
                .expect_err(what);
            assert!(
                matches!(refused, CompactBodyError::Invalid(_)),
                "a {what} list is the block being wrong, not a miss: {refused}"
            );
        }
    }

    /// A hash this node does not hold is a miss, not a fault: the caller is
    /// told how many and asks for the whole body.
    #[test]
    fn a_hash_the_queue_does_not_hold_is_a_miss() {
        let (_, hash, body, _, transactions) = mixed_block();
        let senders = senders_for(&transactions);
        // Everything but the last transaction.
        let queue = queue_holding(&transactions[..2], &senders[..2]);
        let compact = n42_h2_consensus::encode_compact_body(
            &body,
            &hashes_of(&transactions),
            N42HeaderProfile::Gov5H2,
        )
        .expect("encodes");
        let validator = validator(N42HeaderProfile::Gov5H2);
        match validator
            .convert_compact_body_to_block(hash, N42HeaderProfile::Gov5H2, &compact, &queue, SHORT_WAIT)
            .expect_err("one transaction is not held here")
        {
            CompactBodyError::Missing { indices, total, sample, .. } => {
                assert_eq!(indices, vec![2], "the last transaction is the one missing");
                assert_eq!(total, 3);
                assert_eq!(sample, vec![hashes_of(&transactions)[2]]);
            }
            other => panic!("a miss, not {other}"),
        }
        // A queue that keeps no index at all is every hash missing, never a
        // wrong block.
        let blind = n42_tx_queue::TxQueue::<crate::N42PooledTransaction>::with_run_length(1);
        assert!(matches!(
            validator
                .convert_compact_body_to_block(hash, N42HeaderProfile::Gov5H2, &compact, &blind, SHORT_WAIT)
                .expect_err("nothing is held"),
            CompactBodyError::Missing { total: 3, .. }
        ));
    }

    /// The second attempt at a block whose first one missed: the peer
    /// supplies the transactions for the positions this node could not fill,
    /// and the block assembles from the queue and the fill together.
    #[test]
    fn a_fill_completes_a_block_the_queue_could_not() {
        use alloy_eips::Encodable2718;
        let (_, hash, body, _, transactions) = mixed_block();
        let senders = senders_for(&transactions);
        // This node holds all but one, which is what the ingest gate leaves
        // behind on the fleet (loop195: a median of 448 of 163,000, sitting
        // in frames the gate has not admitted). The one it misses is an
        // Ethereum transaction, because a supplied transaction's sender is
        // recovered here and these fixtures' 0x50 signature is a
        // placeholder -- the test below pins what happens to one of those.
        let held = vec![transactions[0].clone(), transactions[2].clone()];
        let held_senders = vec![senders[0], senders[2]];
        let queue = queue_holding(&held, &held_senders);
        let hashes = hashes_of(&transactions);
        let frame = n42_h2_consensus::encode_compact_body(&body, &hashes, N42HeaderProfile::Gov5H2)
            .expect("encodes");
        let validator = validator(N42HeaderProfile::Gov5H2);

        // Without the fill: a miss that names the position to ask for.
        let indices = match validator
            .convert_compact_body_to_block(hash, N42HeaderProfile::Gov5H2, &frame, &queue, SHORT_WAIT)
            .expect_err("one transaction is not held here")
        {
            CompactBodyError::Missing { indices, .. } => indices,
            other => panic!("a miss, not {other}"),
        };
        assert_eq!(indices, vec![1]);

        // With it: the same block the body road decodes, and the supplied
        // transaction's sender is recovered here rather than taken on trust.
        let fill: Vec<(usize, Bytes)> = indices
            .iter()
            .map(|&i| (i, Bytes::from(transactions[i].encoded_2718())))
            .collect();
        let filled = n42_h2_consensus::with_fill(&frame, &fill);
        let assembled = validator
            .convert_compact_body_to_block(hash, N42HeaderProfile::Gov5H2, &filled, &queue, SHORT_WAIT)
            .expect("the fill completes it");
        let (from_body, _) = validator
            .convert_body_to_block(hash, N42HeaderProfile::Gov5H2, &body)
            .expect("the body converts");
        assert_eq!(assembled.block.hash(), from_body.hash());
        assert_eq!(assembled.block.body().transactions, from_body.body().transactions);
        assert_eq!(assembled.filled, 1);
        assert_eq!(assembled.senders[0], senders[0], "the queue's senders are used as they are");
        assert_eq!(assembled.senders[2], senders[2]);
    }

    /// A peer that answers a request for one position with a different
    /// transaction is refused by name, before the transactions root ever
    /// sees it.
    #[test]
    fn a_fill_that_is_not_the_transaction_asked_for_is_refused() {
        use alloy_eips::Encodable2718;
        let (_, hash, body, _, transactions) = mixed_block();
        let senders = senders_for(&transactions);
        let queue = queue_holding(&transactions[..2], &senders[..2]);
        let frame = n42_h2_consensus::encode_compact_body(
            &body,
            &hashes_of(&transactions),
            N42HeaderProfile::Gov5H2,
        )
        .expect("encodes");
        let validator = validator(N42HeaderProfile::Gov5H2);

        // The right shape, the wrong transaction.
        let wrong = Bytes::from(as_ingested(&other_transaction()).encoded_2718());
        let filled = n42_h2_consensus::with_fill(&frame, &[(2, wrong)]);
        let refused = validator
            .convert_compact_body_to_block(hash, N42HeaderProfile::Gov5H2, &filled, &queue, SHORT_WAIT)
            .expect_err("that is not the transaction that was asked for");
        assert!(
            matches!(refused, CompactBodyError::Invalid(_)),
            "a wrong fill is the peer being wrong, not a miss: {refused}"
        );

        // And bytes that are not a transaction at all.
        let filled = n42_h2_consensus::with_fill(&frame, &[(2, Bytes::from_static(&[0x99, 0x01]))]);
        assert!(validator
            .convert_compact_body_to_block(hash, N42HeaderProfile::Gov5H2, &filled, &queue, SHORT_WAIT)
            .is_err());

        // A supplied 0x50 transaction whose sender cannot be recovered is
        // refused too: a transaction that never reached this node's ingest
        // has no recorded sender, so the fill path recovers it and a
        // signature that does not verify ends here rather than in the block.
        let alt = Bytes::from(transactions[2].encoded_2718());
        let filled = n42_h2_consensus::with_fill(&frame, &[(2, alt)]);
        let refused = validator
            .convert_compact_body_to_block(hash, N42HeaderProfile::Gov5H2, &filled, &queue, SHORT_WAIT)
            .expect_err("its signature does not verify");
        assert!(
            refused.to_string().contains("sender"),
            "the refusal says which transaction and why: {refused}"
        );
    }

    /// The announced hash and the header profile are checked before
    /// anything is looked up, exactly as on the body road.
    #[test]
    fn a_compact_body_that_is_not_the_announced_block_is_refused() {
        let (_, hash, body, _, transactions) = mixed_block();
        let senders = senders_for(&transactions);
        let queue = queue_holding(&transactions, &senders);
        let compact = n42_h2_consensus::encode_compact_body(
            &body,
            &hashes_of(&transactions),
            N42HeaderProfile::Gov5H2,
        )
        .expect("encodes");
        let validator = validator(N42HeaderProfile::Gov5H2);
        assert!(validator
            .convert_compact_body_to_block(
                B256::repeat_byte(0xEE),
                N42HeaderProfile::Gov5H2,
                &compact,
                &queue,
                SHORT_WAIT,
            )
            .is_err());
        assert!(validator
            .convert_compact_body_to_block(hash, N42HeaderProfile::Ethereum, &compact, &queue, SHORT_WAIT)
            .is_err());
        // And a full gov5 body is not a compact one.
        assert!(validator
            .convert_compact_body_to_block(hash, N42HeaderProfile::Gov5H2, &body, &queue, SHORT_WAIT)
            .is_err());
    }

    #[test]
    fn a_body_that_is_not_the_announced_block_is_refused() {
        let header = gov5_header(B256::ZERO, U256::ZERO);
        let payload = payload_for(header.clone());
        let body = body_for(&payload, &header);
        let validator = validator(N42HeaderProfile::Gov5H2);
        assert!(validator
            .convert_body_to_block(B256::repeat_byte(0xEE), N42HeaderProfile::Gov5H2, &body)
            .is_err());
        // And the right hash still converts, so the refusal is the hash and
        // nothing else.
        assert!(validator
            .convert_body_to_block(header.hash_slow(), N42HeaderProfile::Gov5H2, &body)
            .is_ok());
    }

    #[test]
    fn a_corrupted_body_is_refused_rather_than_decoded_into_something_else() {
        use alloy_eips::Encodable2718;
        let transactions = mixed_transactions();
        let raw: Vec<Bytes> = transactions.iter().map(|tx| Bytes::from(tx.encoded_2718())).collect();
        let mut header = gov5_header(B256::ZERO, U256::ZERO);
        header.transactions_root = alloy_consensus::proofs::calculate_transaction_root(&transactions);
        header.gas_used = 63_000;
        let payload = n42_h2_consensus::execution_data_from_raw_parts(
            B256::ZERO,
            &header,
            raw,
            Vec::new(),
            None,
        );
        let hash = header.hash_slow();
        let body = body_for(&payload, &header);
        let validator = validator(N42HeaderProfile::Gov5H2);
        assert!(validator.convert_body_to_block(hash, N42HeaderProfile::Gov5H2, &body).is_ok());

        // Truncated, padded, and a byte flipped inside the transactions: none
        // of these may produce a block.
        let mut truncated = body.to_vec();
        truncated.pop();
        assert!(validator
            .convert_body_to_block(hash, N42HeaderProfile::Gov5H2, &Bytes::from(truncated))
            .is_err());
        let mut padded = body.to_vec();
        padded.push(0);
        assert!(validator
            .convert_body_to_block(hash, N42HeaderProfile::Gov5H2, &Bytes::from(padded))
            .is_err());
        let mut flipped = body.to_vec();
        let last = flipped.len() - 8;
        flipped[last] ^= 0xff;
        assert!(validator
            .convert_body_to_block(hash, N42HeaderProfile::Gov5H2, &Bytes::from(flipped))
            .is_err());
    }

    /// A body whose transactions are not the ones the header commits to --
    /// the check the payload path gets for free, because there the root is
    /// computed into the header the hash is taken over.
    #[test]
    fn transactions_that_do_not_hash_to_the_headers_root_are_refused() {
        use alloy_eips::Encodable2718;
        let transactions = mixed_transactions();
        let raw: Vec<Bytes> = transactions.iter().map(|tx| Bytes::from(tx.encoded_2718())).collect();
        let mut header = gov5_header(B256::ZERO, U256::ZERO);
        // The root of a *different* list, sealed into the header.
        header.transactions_root =
            alloy_consensus::proofs::calculate_transaction_root(&transactions[..1]);
        header.gas_used = 63_000;
        let rewards: Vec<(alloy_primitives::Address, U256)> = Vec::new();
        let body = Bytes::from(n42_h2_consensus::encode_block_rlp_raw(&header, &raw, &rewards, None));
        let hash = header.hash_slow();
        assert!(validator(N42HeaderProfile::Gov5H2)
            .convert_body_to_block(hash, N42HeaderProfile::Gov5H2, &body)
            .is_err());
    }

    #[test]
    fn a_body_read_under_the_wrong_profile_is_refused() {
        let header = gov5_header(B256::ZERO, U256::ZERO);
        let payload = payload_for(header.clone());
        let body = body_for(&payload, &header);
        assert!(validator(N42HeaderProfile::Gov5H2)
            .convert_body_to_block(header.hash_slow(), N42HeaderProfile::Ethereum, &body)
            .is_err());
    }
    #[test]
    fn an_amsterdam_block_converts_through_the_parallel_path() {
        let bal = Bytes::from(alloy_rlp::encode(&alloy_eip7928::BlockAccessList::default()));
        let decoded = <alloy_eip7928::BlockAccessList as alloy_rlp::Decodable>::decode(&mut bal.as_ref()).unwrap();
        let mut header = gov5_header(B256::ZERO, U256::ZERO);
        header.block_access_list_hash = Some(alloy_eip7928::compute_block_access_list_hash(decoded.as_slice()));
        header.slot_number = Some(7);
        let block = block_for_header(header, vec![]);
        let payload = n42_h2_consensus::execution_data_for_block_with_bal(block.header.hash_slow(), &block, Some(bal));
        let expected = payload.block_hash();
        let sealed = convert(&validator(N42HeaderProfile::Gov5H2), payload).unwrap();
        assert_eq!(sealed.hash(), expected);
    }

    #[test]
    fn a_gov5_block_reconstructs_with_its_zero_ommers_hash() {
        let payload = payload_for(gov5_header(B256::ZERO, U256::ZERO));
        let expected = payload.block_hash();
        let sealed = convert(&validator(N42HeaderProfile::Gov5H2), payload).unwrap();
        assert_eq!(sealed.hash(), expected);
        assert_eq!(sealed.header().ommers_hash, B256::ZERO);
        assert!(is_gov5_ommers_hash(sealed.header().ommers_hash));
    }

    #[test]
    fn the_legacy_difficulty_one_range_still_reconstructs() {
        let payload = payload_for(gov5_header(B256::ZERO, U256::from(1)));
        let expected = payload.block_hash();
        let sealed = convert(&validator(N42HeaderProfile::Gov5H2), payload).unwrap();
        assert_eq!(sealed.hash(), expected);
        assert_eq!(sealed.header().difficulty, U256::from(1));
    }

    #[test]
    fn the_ethereum_profile_refuses_what_it_always_refused() {
        // Under reth's rules a zero-ommers header cannot be reconstructed
        // and the payload is a hash mismatch. Installing the gov5 profile on
        // an Ethereum chain would change that, which is why it is read from
        // the genesis and not configured.
        let payload = payload_for(gov5_header(B256::ZERO, U256::ZERO));
        assert!(convert(&validator(N42HeaderProfile::Ethereum), payload).is_err());

        let ethereum = payload_for(gov5_header(EMPTY_OMMER_ROOT_HASH, U256::ZERO));
        let expected = ethereum.block_hash();
        assert_eq!(convert(&validator(N42HeaderProfile::Ethereum), ethereum).unwrap().hash(), expected);
    }

    #[test]
    fn a_tampered_hash_is_refused_under_both_profiles() {
        let mut payload = payload_for(gov5_header(B256::ZERO, U256::ZERO));
        payload.payload.as_v1_mut().block_hash = B256::repeat_byte(0xEE);
        assert!(convert(&validator(N42HeaderProfile::Gov5H2), payload.clone()).is_err());
        assert!(convert(&validator(N42HeaderProfile::Ethereum), payload).is_err());
    }

    #[test]
    fn a_header_without_the_magic_is_not_a_gov5_block() {
        let mut header = gov5_header(B256::ZERO, U256::ZERO);
        header.extra_data = Bytes::from_static(b"not-n42h-but-long-enough-for-the-check");
        let payload = payload_for(header);
        assert!(convert(&validator(N42HeaderProfile::Gov5H2), payload).is_err());
    }

    /// The described road's block, made: what the import executes and the
    /// payload the engine's own pass takes.
    fn describe_and_make(
        validator: &N42EngineValidator<ChainSpec>,
        hash: B256,
        frame: &[u8],
        queue: &n42_tx_queue::TxQueue<crate::N42PooledTransaction>,
    ) -> Result<DescribedInto, CompactBodyError> {
        validator
            .describe_compact_body(hash, N42HeaderProfile::Gov5H2, frame, queue, SHORT_WAIT)?
            .into_block(validator)
    }

    /// The block by description is the block the body road decodes and the
    /// compact road assembles -- same hash, header, transactions (legacy,
    /// EIP-1559 and 0x50), withdrawals and payload -- with the queue's
    /// senders, and the transactions it checked were the queue's own objects,
    /// not copies.
    #[test]
    fn a_described_block_is_the_block_the_body_road_decodes() {
        let (_, hash, body, payload, transactions) = mixed_block();
        let senders = senders_for(&transactions);
        let queue = queue_holding(&transactions, &senders);
        let compact =
            n42_h2_consensus::encode_compact_body(&body, &hashes_of(&transactions), N42HeaderProfile::Gov5H2)
                .expect("encodes");
        let validator = validator(N42HeaderProfile::Gov5H2);
        let (from_body, body_payload) =
            validator.convert_body_to_block(hash, N42HeaderProfile::Gov5H2, &body).expect("the body converts");
        let assembled = validator
            .convert_compact_body_to_block(hash, N42HeaderProfile::Gov5H2, &compact, &queue, SHORT_WAIT)
            .expect("the compact body assembles");

        let described = validator
            .describe_compact_body(hash, N42HeaderProfile::Gov5H2, &compact, &queue, SHORT_WAIT)
            .expect("the description checks");
        assert_eq!(described.hash, hash);
        assert_eq!(described.senders, senders);
        assert_eq!(described.misses, 0);
        for (at, tx) in described.transactions.iter().enumerate() {
            match tx {
                DescribedTx::Queued(queued) => {
                    let held = queue.get_by_hash(&hashes_of(&transactions)[at]).expect("held");
                    assert!(Arc::ptr_eq(queued, &held), "position {at} is the queue's own transaction");
                }
                DescribedTx::Supplied(_) => panic!("nothing was supplied"),
            }
        }
        let made = described.into_block(&validator).expect("the described block is made");
        for block in [&made.block, &assembled.block] {
            assert_eq!(block.hash(), from_body.hash());
            assert_eq!(block.header(), from_body.header());
            assert_eq!(block.body().transactions, from_body.body().transactions);
            assert_eq!(block.body().withdrawals, from_body.body().withdrawals);
        }
        assert_eq!(made.senders, senders);
        assert_eq!(format!("{:?}", made.payload), format!("{body_payload:?}"));
        assert_eq!(format!("{:?}", made.payload), format!("{payload:?}"));
    }

    /// A list that is not the block's -- reordered, a duplicate, a
    /// transaction of another block, one position short, one extra -- is
    /// refused by the transactions root on the described road, as on the
    /// compact one: that root is the only thing binding the list to the header.
    #[test]
    fn a_described_list_that_is_not_the_blocks_is_refused_by_the_root() {
        let (_, hash, body, _, transactions) = mixed_block();
        let senders = senders_for(&transactions);
        let mut held = transactions.clone();
        held.push(as_ingested(&other_transaction()));
        let mut held_senders = senders.clone();
        held_senders.push(alloy_primitives::Address::repeat_byte(0xC1));
        let queue = queue_holding(&held, &held_senders);
        let validator = validator(N42HeaderProfile::Gov5H2);
        let hashes = hashes_of(&transactions);
        let outsider = hashes_of(&held)[3];

        let mut reordered = hashes.clone();
        reordered.swap(0, 1);
        let mut duplicated = hashes.clone();
        duplicated[2] = duplicated[0];
        let mut substituted = hashes.clone();
        substituted[1] = outsider;
        let short = hashes[..2].to_vec();
        let mut long = hashes.clone();
        long.push(outsider);
        for (what, list) in [
            ("reordered", reordered),
            ("duplicated", duplicated),
            ("substituted", substituted),
            ("short", short),
            ("long", long),
        ] {
            let compact =
                n42_h2_consensus::encode_compact_body(&body, &list, N42HeaderProfile::Gov5H2).expect("encodes");
            let refused = validator
                .describe_compact_body(hash, N42HeaderProfile::Gov5H2, &compact, &queue, SHORT_WAIT)
                .expect_err(what);
            assert!(
                matches!(refused, CompactBodyError::Invalid(_)),
                "a {what} list is the block being wrong, not a miss: {refused}"
            );
        }
    }

    /// A hash this node does not hold is a miss on the described road too,
    /// named by position; the fill for it completes the block, its supplied
    /// transaction decoded and recovered here; a fill that is not the
    /// transaction asked for is refused by name.
    #[test]
    fn a_described_miss_is_named_and_a_fill_completes_it() {
        use alloy_eips::Encodable2718;
        let (_, hash, body, _, transactions) = mixed_block();
        let senders = senders_for(&transactions);
        let queue =
            queue_holding(&[transactions[0].clone(), transactions[2].clone()], &[senders[0], senders[2]]);
        let frame =
            n42_h2_consensus::encode_compact_body(&body, &hashes_of(&transactions), N42HeaderProfile::Gov5H2)
                .expect("encodes");
        let validator = validator(N42HeaderProfile::Gov5H2);
        let indices = match describe_and_make(&validator, hash, &frame, &queue).expect_err("one is not held") {
            CompactBodyError::Missing { indices, total, .. } => {
                assert_eq!(total, 3);
                indices
            }
            other => panic!("a miss, not {other}"),
        };
        assert_eq!(indices, vec![1]);

        let fill: Vec<(usize, Bytes)> =
            indices.iter().map(|&i| (i, Bytes::from(transactions[i].encoded_2718()))).collect();
        let filled = n42_h2_consensus::with_fill(&frame, &fill);
        let described = validator
            .describe_compact_body(hash, N42HeaderProfile::Gov5H2, &filled, &queue, SHORT_WAIT)
            .expect("the fill completes it");
        assert_eq!(described.filled, 1);
        assert!(matches!(described.transactions[1], DescribedTx::Supplied(_)));
        let made = described.into_block(&validator).expect("made");
        let (from_body, _) =
            validator.convert_body_to_block(hash, N42HeaderProfile::Gov5H2, &body).expect("the body converts");
        assert_eq!(made.block.hash(), from_body.hash());
        assert_eq!(made.block.body().transactions, from_body.body().transactions);
        assert_eq!(made.senders[0], senders[0]);
        assert_eq!(made.senders[2], senders[2]);

        let wrong = Bytes::from(as_ingested(&other_transaction()).encoded_2718());
        let filled = n42_h2_consensus::with_fill(&frame, &[(1, wrong)]);
        assert!(matches!(
            validator
                .describe_compact_body(hash, N42HeaderProfile::Gov5H2, &filled, &queue, SHORT_WAIT)
                .expect_err("not the transaction asked for"),
            CompactBodyError::Invalid(_)
        ));
    }

    /// A block of several encoding chunks with misses filled in the middle of
    /// one and at a chunk's edge: the chunks encoded during the look-up and
    /// the ones encoded after the fill join into the header's root, and the
    /// made block is the one the body road decodes.
    #[test]
    fn a_described_block_of_many_chunks_with_fills_is_the_decoded_block() {
        use alloy_consensus::{Signed, TxEip1559};
        use alloy_eips::Encodable2718;
        use alloy_primitives::{Address, Signature, TxKind};
        let transactions: Vec<TransactionSigned> = (0..2_600u64)
            .map(|i| {
                let tx = TxEip1559 {
                    chain_id: 1,
                    nonce: i,
                    gas_limit: 21_000,
                    max_fee_per_gas: 10_000_000_000,
                    max_priority_fee_per_gas: 1_000_000_000,
                    to: TxKind::Call(Address::with_last_byte((i % 200) as u8)),
                    value: U256::from(i),
                    ..Default::default()
                };
                as_ingested(&TransactionSigned::Eth(
                    alloy_consensus::TxEnvelope::Eip1559(Signed::new_unchecked(
                        tx,
                        Signature::test_signature(),
                        B256::ZERO,
                    ))
                    .into(),
                ))
            })
            .collect();
        let senders: Vec<Address> = (0..transactions.len()).map(|i| Address::with_last_byte((i % 250) as u8)).collect();
        let raw: Vec<Bytes> = transactions.iter().map(|tx| Bytes::from(tx.encoded_2718())).collect();
        let mut header = gov5_header(B256::ZERO, U256::ZERO);
        header.transactions_root = alloy_consensus::proofs::calculate_transaction_root(&transactions);
        header.withdrawals_root = Some(n42_h2_consensus::gov5_rewards_root(Vec::new()));
        let mut payload =
            n42_h2_consensus::execution_data_from_raw_parts(B256::ZERO, &header, raw, Vec::new(), None);
        let hash = header.hash_slow();
        payload.payload.as_v1_mut().block_hash = hash;
        let body = body_for(&payload, &header);
        let missing = [1_500usize, 2_047, 2_048];
        let queue =
            n42_tx_queue::TxQueue::<crate::N42PooledTransaction>::with_run_length(1).with_hash_index(1 << 14);
        queue.push(
            transactions
                .iter()
                .zip(&senders)
                .enumerate()
                .filter(|(i, _)| !missing.contains(i))
                .map(|(_, (tx, sender))| {
                    crate::N42PooledTransaction::new(
                        reth_primitives_traits::Recovered::new_unchecked(tx.clone(), *sender),
                        tx.encoded_2718().len(),
                    )
                }),
        );
        queue.drain_now();
        let frame =
            n42_h2_consensus::encode_compact_body(&body, &hashes_of(&transactions), N42HeaderProfile::Gov5H2)
                .expect("encodes");
        let validator = validator(N42HeaderProfile::Gov5H2);
        let indices = match describe_and_make(&validator, hash, &frame, &queue).expect_err("three are not held") {
            CompactBodyError::Missing { indices, .. } => indices,
            other => panic!("a miss, not {other}"),
        };
        assert_eq!(indices, missing.to_vec());
        let fill: Vec<(usize, Bytes)> =
            indices.iter().map(|&i| (i, Bytes::from(transactions[i].encoded_2718()))).collect();
        let made = describe_and_make(&validator, hash, &n42_h2_consensus::with_fill(&frame, &fill), &queue)
            .expect("the fill completes it");
        let (from_body, body_payload) =
            validator.convert_body_to_block(hash, N42HeaderProfile::Gov5H2, &body).expect("the body converts");
        assert_eq!(made.block.hash(), from_body.hash());
        assert_eq!(made.block.body().transactions, from_body.body().transactions);
        assert_eq!(format!("{:?}", made.payload), format!("{body_payload:?}"));
        for (at, sender) in made.senders.iter().enumerate() {
            if !missing.contains(&at) {
                assert_eq!(*sender, senders[at], "the queue's sender at {at}");
            }
        }
    }
}
