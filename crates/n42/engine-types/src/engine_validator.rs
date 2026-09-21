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
    /// The transactions are decoded from slices of `rlp` and their bytes
    /// copied for the payload in the same parallel pass. The copy is
    /// deliberate: a slice keeps the whole ~25 MB body alive for as long as
    /// anything downstream holds one transaction's bytes, which grew this
    /// process by ~19 MB a block when the payload frame was decoded that way
    /// (loop60N1). The body itself is dropped when this returns.
    pub fn convert_body_to_block(
        &self,
        announced: B256,
        profile: N42HeaderProfile,
        rlp: &alloy_primitives::Bytes,
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
        let body = n42_h2_consensus::decode_raw_block_body(rlp, Some(rlp), profile)
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
                        let decoded = <TransactionSigned as alloy_eips::Decodable2718>::decode_2718_exact(
                            tx.as_ref(),
                        )
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
        // parts rather than parsed again.
        let payload = n42_h2_consensus::execution_data_from_raw_parts(
            body.block_hash,
            &body.header,
            raw_transactions,
            body.withdrawals.clone(),
            body.bal.clone(),
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
}
