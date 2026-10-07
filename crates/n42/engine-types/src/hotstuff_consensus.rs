// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block validation for a chain driven by HotStuff-2 — gov5's rules, so a
//! block accepted here is a block a Go member accepts, and the other way
//! round.
//!
//! What this checks that reth's Ethereum consensus does not: the header extra
//! layout (`N42H ‖ view ‖ [QC] ‖ seal`), and a receipts root computed gov5's
//! way (`hash.DeriveSha`: keccak over concatenated receipt encodings). What it
//! deliberately does not check that reth's does: the 32-byte extra-data bound
//! (gov5 headers carry at least 108 bytes), and the empty-list ommers hash
//! (gov5's producer leaves it zero). Everything fork-dependent — withdrawals,
//! blob gas, requests, base fee, gas limit ramp, timestamp ordering — is
//! Ethereum's and is checked as Ethereum checks it.
//!
//! The seal is not verified here, matching gov5's `VerifyHeader`. Whether a
//! block is *the* block is consensus's decision, made on the hash; the seal
//! is available to anyone who wants to attribute it — see
//! [`n42_h2_consensus::verify_seal`].
//!
//! This engine also plays the payload builder's consensus role: [`prepare`]
//! lays out the header a leader's block starts from, and [`seal`] leaves it
//! alone — the view and the seal are stamped by the validator process, which
//! is the only one that knows them.
//!
//! [`prepare`]: reth_consensus::Consensus::prepare
//! [`seal`]: reth_consensus::Consensus::seal

use alloy_consensus::{BlockHeader as _, Header, TxReceipt};
use alloy_primitives::{logs_bloom, Address, B256, U256};
use n42_consensus_traits::{AposError, AposResult, SignerManager};
use n42_h2_consensus::{
    gov5_receipts_root, gov5_rewards_root, is_empty_requests_hash, validate_gov5_h2_header,
    withdrawals_to_rewards,
    HeaderExtra, ReceiptView, SimulatedCommitteePool, GOV5_EMPTY_REQUESTS_HASH,
};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator, ReceiptRootBloom};
use reth_consensus_common::validation::{
    validate_4844_header_standalone, validate_cancun_gas, validate_header_base_fee,
    validate_header_gas,
};
use reth_ethereum_consensus::EthBeaconConsensus;
use n42_tx_types::{Block as EthBlock, BlockBody as EthBlockBody, N42Primitives as EthPrimitives, Receipt};
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{BlockBody as _, GotExpected, RecoveredBlock, SealedBlock, SealedHeader};
use std::sync::{Arc, RwLock};

/// gov5's HotStuff-2 block rules, for reth.
thread_local! {
    /// A transactions root already computed and checked for the block being
    /// validated on this thread, so the body check does not compute it again
    /// (163,000 encodings and a trie at the bench tier). Set only for the
    /// span of `validate_block_pre_execution_with_tx_root`.
    static KNOWN_TX_ROOT: std::cell::Cell<Option<B256>> = const { std::cell::Cell::new(None) };
}

#[derive(Debug)]
pub struct HotStuffConsensus<ChainSpec> {
    chain_spec: Arc<ChainSpec>,
    /// The Ethereum rules this shares: everything about a header that is not
    /// HotStuff's business.
    ethereum: EthBeaconConsensus<ChainSpec>,
    /// The signer address the operator configured, if any. Kept for the
    /// operator's information; on a HotStuff chain the block's beneficiary is
    /// the fee recipient the leader names, not a local key.
    signer: RwLock<Option<Address>>,
    /// The chain's committee pool, when its genesis enables one: every
    /// header's parent beacon root must be the Blake3 of the parent's
    /// committee evidence, which the pool rebuilds from the parent header.
    committee: Option<SimulatedCommitteePool>,
}

/// A header whose parent beacon root is not the parent's committee evidence.
#[derive(Debug, thiserror::Error)]
#[error("parent beacon root {got} is not the parent's committee evidence {expected}")]
pub struct CommitteeLinkError {
    /// What the header carries.
    pub got: B256,
    /// The Blake3 of the parent's evidence.
    pub expected: B256,
}

impl<ChainSpec: EthChainSpec + EthereumHardforks> HotStuffConsensus<ChainSpec> {
    /// Rules for `chain_spec`.
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        let committee = match n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(chain_spec.genesis()) {
            Ok(config) => match config.committee_pool() {
                Ok(pool) => pool,
                Err(err) => {
                    tracing::warn!(target: "n42::consensus", %err, "committee pool in the genesis could not be built; headers will not be checked against it");
                    None
                }
            },
            Err(_) => None,
        };
        Self {
            ethereum: EthBeaconConsensus::new(chain_spec.clone()),
            chain_spec,
            signer: RwLock::new(None),
            committee,
        }
    }

    /// The committee pool the chain runs, if any.
    pub const fn committee_pool(&self) -> Option<&SimulatedCommitteePool> {
        self.committee.as_ref()
    }

    /// The chain.
    pub const fn chain_spec(&self) -> &Arc<ChainSpec> {
        &self.chain_spec
    }
}

/// gov5's receipts root and the logs bloom, from what execution produced.
/// Why a header failed the deferred-execution check.
#[derive(Debug, thiserror::Error)]
pub enum DeferredExecutionError {
    /// The parent's execution result is not known here: it was not executed
    /// on this node and the chain holds no receipts for it yet.
    #[error("deferred execution: the parent {0}'s execution result is not known here")]
    ParentUnknown(B256),
    /// The header's execution fields are not the parent's result.
    #[error("deferred execution: header carries {got:?} for parent {parent}, this node executed {expected:?}")]
    Mismatch {
        /// The parent.
        parent: B256,
        /// What the header says.
        got: Box<crate::executed_fields::ExecutedFields>,
        /// What this node executed.
        expected: Box<crate::executed_fields::ExecutedFields>,
    },
}

/// The execution result a header past the fork must carry for `parent`:
/// the parent's own header if the parent is before the fork (its header
/// carries its own execution), the registry otherwise.
pub fn parent_executed_fields(genesis: &alloy_genesis::Genesis, parent: &SealedHeader) -> Option<crate::executed_fields::ExecutedFields> {
    ancestor_executed_fields(genesis, parent, 1)
}

/// The hash of the block whose execution result a child of `parent` carries
/// at `depth` (`docs/DEFERRED_DEPTH_2_DESIGN.md` section 1.1): the parent at
/// depth 1, the parent's parent at depth 2. By hash on the child's own chain,
/// never by number.
pub fn ancestor_hash(parent: &SealedHeader, depth: u64) -> B256 {
    if depth <= 1 {
        parent.hash()
    } else {
        parent.parent_hash
    }
}

/// The execution result a header past the fork must carry when its parent
/// is `parent` and the chain's deferred-execution depth is `depth`: the
/// result of the ancestor at that distance on the child's own chain.
///
/// Depth 1 is [`parent_executed_fields`]: the parent's own header before the
/// fork or at genesis, the registry under the parent's hash otherwise.
pub fn ancestor_executed_fields(
    genesis: &alloy_genesis::Genesis,
    parent: &SealedHeader,
    depth: u64,
) -> Option<crate::executed_fields::ExecutedFields> {
    if depth != 1 {
        // Depth 2 is filled in with the consensus rule; until then no other
        // depth has a result.
        return None;
    }
    // The genesis header carries the genesis state by definition, whatever
    // the fork time says; so does every header before the fork.
    if parent.number == 0 || !reth_chainspec::qmdb::deferred_execution_active_at(genesis, parent.timestamp) {
        return Some(crate::executed_fields::fields_from_child_header(parent.header()));
    }
    crate::executed_fields::get(&parent.hash())
}

/// How long [`parent_executed_fields_or_built`] waits for a parent that is
/// still finishing behind its own seal. Generous: it is a stall guard, not a
/// budget, and the parent's finish is ~65 ms at the bench tier.
pub const PARENT_FIELDS_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// [`parent_executed_fields`], falling back to the hash the *builder* gave
/// the parent and waiting for it.
///
/// A block's execution is filed under the builder's hash the moment its build
/// ends (`payload.rs`, both finishes) and copied to the hash consensus sealed
/// only when the own-block hand-off runs -- which is after the leader has
/// proposed the block. Anything that builds on that block earlier than the
/// hand-off therefore asks under a hash nothing has filed yet, and the build
/// chain (`N42_BUILD_CHAIN`) does exactly that: it starts the next build at
/// the parent's early seal, ~275 ms before the hand-off.
///
/// Measured on loop193 W1b: 289 of 347 refused chained builds were this, all
/// of them blocks the parallel step left empty -- an empty block skips the
/// early seal, and the ordinary finish was the one path that looked only
/// under the sealed hash. The refusal came 0.4-1.3 ms after the request,
/// which is how it was told apart from a wait that timed out.
///
/// The found fields are filed under the sealed hash as well, so the next
/// caller on that parent needs no fallback.
pub fn parent_executed_fields_or_built(
    genesis: &alloy_genesis::Genesis,
    parent: &SealedHeader,
    parent_built: Option<B256>,
    timeout: std::time::Duration,
) -> Option<crate::executed_fields::ExecutedFields> {
    ancestor_executed_fields_or_built(genesis, parent, parent_built, 1, timeout)
}

/// [`ancestor_executed_fields`], falling back to the hash the builder gave
/// the ancestor (`ancestor_built`) and waiting for it there; the found fields
/// are filed under the ancestor's sealed hash as well. At depth 1 this is
/// [`parent_executed_fields_or_built`].
pub fn ancestor_executed_fields_or_built(
    genesis: &alloy_genesis::Genesis,
    parent: &SealedHeader,
    ancestor_built: Option<B256>,
    depth: u64,
    timeout: std::time::Duration,
) -> Option<crate::executed_fields::ExecutedFields> {
    if let Some(fields) = ancestor_executed_fields(genesis, parent, depth) {
        return Some(fields);
    }
    let built = ancestor_built?;
    let fields = crate::executed_fields::wait_for(&built, timeout)?;
    crate::executed_fields::remember(ancestor_hash(parent, depth), fields);
    Some(fields)
}

pub fn gov5_receipt_root_bloom(receipts: &[Receipt]) -> ReceiptRootBloom {
    let root = gov5_receipts_root(receipts.iter().map(|receipt| ReceiptView {
        success: receipt.success,
        cumulative_gas_used: receipt.cumulative_gas_used,
        logs: &receipt.logs,
    }));
    let bloom = logs_bloom(receipts.iter().flat_map(|receipt| receipt.logs().iter()));
    (root, bloom)
}

/// The header a leader's block starts from, before the builder fills in
/// execution outputs: HotStuff's fixed fields, and a view-0 extra layout the
/// validator process overwrites with the real view and seal.
pub fn prepare_hotstuff_header(parent: &SealedHeader) -> Header {
    Header {
        parent_hash: parent.hash(),
        number: parent.number + 1,
        ommers_hash: B256::ZERO,
        difficulty: U256::ZERO,
        nonce: Default::default(),
        extra_data: HeaderExtra::for_view(0).encode(),
        ..Default::default()
    }
}

impl<ChainSpec> HeaderValidator for HotStuffConsensus<ChainSpec>
where
    ChainSpec: EthChainSpec<Header = Header> + EthereumHardforks + core::fmt::Debug + Send + Sync,
{
    fn validate_header(&self, header: &SealedHeader) -> Result<(), ConsensusError> {
        let header = header.header();
        if header.number == 0 {
            // Genesis carries no consensus fields, in gov5 as here.
            return Ok(());
        }
        validate_gov5_h2_header(header).map_err(|err| ConsensusError::Other(Arc::new(err)))?;

        validate_header_gas(header)?;
        validate_header_base_fee(header, &self.chain_spec)?;

        let timestamp = header.timestamp;
        if self.chain_spec.is_shanghai_active_at_timestamp(timestamp) {
            if header.withdrawals_root.is_none() {
                return Err(ConsensusError::WithdrawalsRootMissing);
            }
        } else if header.withdrawals_root.is_some() {
            return Err(ConsensusError::WithdrawalsRootUnexpected);
        }

        if self.chain_spec.is_cancun_active_at_timestamp(timestamp) {
            validate_4844_header_standalone(
                header,
                self.chain_spec
                    .blob_params_at_timestamp(timestamp)
                    .unwrap_or_else(alloy_eips::eip7840::BlobParams::cancun),
            )?;
        } else if header.blob_gas_used.is_some() {
            return Err(ConsensusError::BlobGasUsedUnexpected);
        } else if header.excess_blob_gas.is_some() {
            return Err(ConsensusError::ExcessBlobGasUnexpected);
        } else if header.parent_beacon_block_root.is_some() {
            return Err(ConsensusError::ParentBeaconBlockRootUnexpected);
        }

        if self.chain_spec.is_prague_active_at_timestamp(timestamp) {
            if header.requests_hash.is_none() {
                return Err(ConsensusError::RequestsHashMissing);
            }
        } else if header.requests_hash.is_some() {
            return Err(ConsensusError::RequestsHashUnexpected);
        }

        Ok(())
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader,
        parent: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        // Hash and number linkage, timestamp strictly after the parent, gas
        // limit ramp, base fee, blob gas: gov5 checks the first two and
        // relies on every producer deriving the rest the same way, which is
        // what checking them here guarantees for blocks this node accepts.
        self.ethereum.validate_header_against_parent(header, parent)?;
        // Deferred execution: the header's execution fields are the parent's
        // result, which this node executed (or, before the fork, which the
        // parent's own header carries). The first header past the fork
        // therefore repeats its parent's fields, the invariant at the switch.
        if reth_chainspec::qmdb::deferred_execution_active_at(self.chain_spec.genesis(), header.timestamp) {
            let depth = 1;
            let ancestor = ancestor_hash(parent, depth);
            let expected = ancestor_executed_fields(self.chain_spec.genesis(), parent, depth)
                .ok_or_else(|| ConsensusError::Other(Arc::new(DeferredExecutionError::ParentUnknown(ancestor))))?;
            let got = crate::executed_fields::fields_from_child_header(header);
            if got != expected {
                return Err(ConsensusError::Other(Arc::new(DeferredExecutionError::Mismatch {
                    parent: ancestor,
                    got: Box::new(got),
                    expected: Box::new(expected),
                })));
            }
        }
        // The committee-evidence link, exactly as gov5's `VerifyHeader`
        // checks it: the parent beacon root is the Blake3 of the parent's
        // evidence, zero when the parent is genesis.
        if let Some(pool) = &self.committee {
            let expected = pool
                .parent_beacon_root(parent.number, &parent.hash(), &parent.receipts_root)
                .map_err(|err| ConsensusError::Other(Arc::new(err)))?;
            let got = header.parent_beacon_block_root.unwrap_or_default();
            if got != expected {
                return Err(ConsensusError::Other(Arc::new(CommitteeLinkError { got, expected })));
            }
        }
        Ok(())
    }
}

impl<ChainSpec> Consensus<EthBlock> for HotStuffConsensus<ChainSpec>
where
    ChainSpec: EthChainSpec<Header = Header> + EthereumHardforks + core::fmt::Debug + Send + Sync,
{
    fn validate_body_against_header(
        &self,
        body: &EthBlockBody,
        header: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        // gov5's producer leaves the ommers hash zero; its genesis, and this
        // node's Ethereum-profile history, carry the empty-list hash. A body
        // never has ommers on this chain, so either value is "none".
        let ommers_hash = body.calculate_ommers_root();
        if header.ommers_hash == B256::ZERO && !body.ommers.is_empty() {
            // Zero says "none"; a body that brings ommers under it is lying.
            return Err(ConsensusError::BodyOmmersHashDiff(
                GotExpected {
                    got: ommers_hash,
                    expected: header.ommers_hash,
                }
                .into(),
            ));
        }
        if header.ommers_hash != B256::ZERO && header.ommers_hash != ommers_hash {
            return Err(ConsensusError::BodyOmmersHashDiff(
                GotExpected {
                    got: ommers_hash,
                    expected: header.ommers_hash,
                }
                .into(),
            ));
        }

        let tx_root = match KNOWN_TX_ROOT.with(|known| known.get()) {
            // A root the caller has already computed and matched against the
            // sealed hash (the payload's conversion did): not computed twice.
            Some(root) => root,
            // `N42_FRAME_BLOCKS=1`: the frame tree when a layout this node
            // can check covers the body (one it verified or built for that
            // root, or its frame index's), the MPT root otherwise -- aligned
            // or not is each block's own property.
            None if crate::frame_blocks::active() => {
                use alloy_consensus::transaction::TxHashRef as _;
                let hashes: Vec<B256> = body.transactions.iter().map(|tx| *tx.tx_hash()).collect();
                crate::frame_blocks::root_for_body(Some(header.transactions_root), &hashes, || body.calculate_tx_root()).0
            }
            None => body.calculate_tx_root(),
        };
        if header.transactions_root != tx_root {
            return Err(ConsensusError::BodyTransactionRootDiff(
                GotExpected {
                    got: tx_root,
                    expected: header.transactions_root,
                }
                .into(),
            ));
        }

        // gov5 fills `withdrawalsRoot` with its rewards commitment — keccak
        // of the block's rewards, of nothing when none were paid — while
        // Ethereum's is the withdrawals trie root. The block's withdrawals
        // are its rewards (`rewards_to_withdrawals`); either spelling of the
        // same list is accepted, a header claiming another list is refused.
        match (header.withdrawals_root, body.withdrawals.as_ref()) {
            (Some(header_root), Some(withdrawals)) => {
                let trie_root = body.calculate_withdrawals_root().unwrap_or_default();
                let gov5_root = Some(gov5_rewards_root(withdrawals_to_rewards(withdrawals.as_slice())));
                if header_root != trie_root && Some(header_root) != gov5_root {
                    return Err(ConsensusError::BodyWithdrawalsRootDiff(
                        GotExpected {
                            got: trie_root,
                            expected: header_root,
                        }
                        .into(),
                    ));
                }
            }
            (Some(_), None) => return Err(ConsensusError::BodyWithdrawalsMissing),
            (None, Some(_)) => return Err(ConsensusError::WithdrawalsRootUnexpected),
            (None, None) => {}
        }
        Ok(())
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<EthBlock>) -> Result<(), ConsensusError> {
        self.validate_body_against_header(block.body(), block.sealed_header())?;
        if self.chain_spec.is_shanghai_active_at_timestamp(block.timestamp())
            && block.body().withdrawals.is_none()
        {
            return Err(ConsensusError::BodyWithdrawalsMissing);
        }
        if self.chain_spec.is_cancun_active_at_timestamp(block.timestamp()) {
            validate_cancun_gas(block)?;
        }
        Ok(())
    }

    fn validate_block_pre_execution_with_tx_root(
        &self,
        block: &SealedBlock<EthBlock>,
        transaction_root: Option<B256>,
    ) -> Result<(), ConsensusError> {
        KNOWN_TX_ROOT.with(|known| known.set(transaction_root));
        let result = self.validate_block_pre_execution(block);
        KNOWN_TX_ROOT.with(|known| known.set(None));
        result
    }

    fn prepare(&self, parent_header: &SealedHeader) -> Result<Header, ConsensusError> {
        Ok(prepare_hotstuff_header(parent_header))
    }

    fn seal(&self, _header: &mut Header) -> Result<(), ConsensusError> {
        // The validator process stamps the view and signs the seal; the
        // execution layer has neither.
        Ok(())
    }

    fn set_eth_signer_by_key(&self, eth_signer_key: Option<String>) -> Result<(), ConsensusError> {
        self.set_signer_key(eth_signer_key)
            .map_err(|err| ConsensusError::Other(Arc::new(err)))
    }

    fn get_eth_signer_address(&self) -> Result<Option<Address>, ConsensusError> {
        Ok(*self
            .signer
            .read()
            .map_err(|_| ConsensusError::Other(Arc::new(AposError::Other("signer lock poisoned".into()))))?)
    }
}

impl<ChainSpec> FullConsensus<EthPrimitives> for HotStuffConsensus<ChainSpec>
where
    ChainSpec: EthChainSpec<Header = Header> + EthereumHardforks + core::fmt::Debug + Send + Sync,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<EthBlock>,
        result: &BlockExecutionResult<Receipt>,
        _receipt_root_bloom: Option<ReceiptRootBloom>,
        block_access_list_hash: Option<B256>,
    ) -> Result<(), ConsensusError> {
        let _ = block_access_list_hash;
        let header = block.header();
        if reth_chainspec::qmdb::deferred_execution_active_at(self.chain_spec.genesis(), header.timestamp) {
            // The header describes the parent; this block's own result is
            // what its child's header will be checked against. The requests
            // hash is not deferred (section 9 of the proposal): it is this
            // block's own and is held to the EIP here as before the fork.
            // An execution that did not cover the block has nothing to say
            // about it: recording its partial receipts (empty, gas 0) over the
            // build's put every header the leader made afterwards on the
            // followers' reject list (loop151). The cause was not an abort: a
            // header-only own-block payload, executed when its executed insert
            // had been dropped as outdated, was executed for the zero
            // transactions it listed (reth counts the payload's transactions,
            // not the kept block's); the payload now lists them
            // (`payload_serve`, loop158). An incomplete result here means
            // something else is wrong, and its state went into the tree:
            // reported loudly.
            let transactions = block.body().transactions.len();
            if result.receipts.len() != transactions {
                tracing::error!(
                    target: "n42::hotstuff",
                    number = header.number, block = ?block.hash(), transactions, receipts = result.receipts.len(), gas_used = result.gas_used,
                    "an incomplete execution result under deferred execution; its receipts are not recorded"
                );
                return self.validate_requests_hash(header, result);
            }
            let (receipts_root, logs_bloom) = gov5_receipt_root_bloom(&result.receipts);
            crate::executed_fields::remember_receipts(block.hash(), receipts_root, logs_bloom, result.gas_used);
            return self.validate_requests_hash(header, result);
        }
        if header.gas_used != result.gas_used {
            return Err(ConsensusError::BlockGasUsed {
                gas: GotExpected {
                    got: result.gas_used,
                    expected: header.gas_used,
                },
                gas_spent_by_tx: block
                    .body()
                    .transactions
                    .iter()
                    .zip(&result.receipts)
                    .enumerate()
                    .map(|(i, (_, receipt))| (i as u64, receipt.cumulative_gas_used))
                    .collect(),
            });
        }

        // The caller's precomputed root is the Merkle-Patricia one; this
        // chain commits to gov5's. Recomputed here, cheaply: it is a keccak
        // over the receipts, not a trie.
        let (receipts_root, logs_bloom) = gov5_receipt_root_bloom(&result.receipts);
        if header.receipts_root != receipts_root {
            return Err(ConsensusError::BodyReceiptRootDiff(
                GotExpected {
                    got: receipts_root,
                    expected: header.receipts_root,
                }
                .into(),
            ));
        }
        if header.logs_bloom != logs_bloom {
            return Err(ConsensusError::BodyBloomLogDiff(
                GotExpected {
                    got: logs_bloom,
                    expected: header.logs_bloom,
                }
                .into(),
            ));
        }

        self.validate_requests_hash(header, result)?;
        Ok(())
    }
}

impl<ChainSpec> HotStuffConsensus<ChainSpec>
where
    ChainSpec: EthChainSpec<Header = Header> + EthereumHardforks + core::fmt::Debug + Send + Sync,
{
    /// The block's EIP-7685 requests hash against the execution's requests.
    fn validate_requests_hash(&self, header: &Header, result: &BlockExecutionResult<Receipt>) -> Result<(), ConsensusError> {
        // Requests: gov5 spells "none" as the empty trie root where EIP-7685
        // says sha256 of nothing; both are accepted for a block that made no
        // requests, and a block that did is held to the EIP.
        if self.chain_spec.is_prague_active_at_timestamp(header.timestamp) {
            let Some(header_hash) = header.requests_hash else {
                return Err(ConsensusError::RequestsHashMissing);
            };
            let matches = if result.requests.is_empty() {
                is_empty_requests_hash(header_hash)
            } else {
                header_hash == result.requests.requests_hash()
            };
            if !matches {
                let expected = if result.requests.is_empty() {
                    GOV5_EMPTY_REQUESTS_HASH
                } else {
                    result.requests.requests_hash()
                };
                return Err(ConsensusError::BodyRequestsHashDiff(
                    GotExpected {
                        got: expected,
                        expected: header_hash,
                    }
                    .into(),
                ));
            }
        }
        Ok(())
    }
}

impl<ChainSpec: Send + Sync> SignerManager for HotStuffConsensus<ChainSpec> {
    fn set_signer_key(&self, key: Option<String>) -> AposResult<()> {
        let address = match key {
            None => None,
            Some(key) => {
                let signer = key
                    .parse::<alloy_signer_local::PrivateKeySigner>()
                    .map_err(|e| AposError::InvalidSignerKey(e.to_string()))?;
                Some(signer.address())
            }
        };
        *self
            .signer
            .write()
            .map_err(|_| AposError::Other("signer lock poisoned".into()))? = address;
        Ok(())
    }

    /// Always `None`: the beneficiary of a HotStuff block is the fee recipient
    /// the leader named in its payload attributes, which is what gov5's
    /// `Prepare` sets `Coinbase` to. A local key must not override it, or two
    /// execution layers would build different blocks from the same request.
    fn get_signer_address(&self) -> AposResult<Option<Address>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::EMPTY_OMMER_ROOT_HASH;
    use alloy_primitives::Log;
    use n42_h2_consensus::GOV5_NIL_HASH;

    /// A genesis on which every header carries its parent's execution.
    fn deferred_genesis() -> alloy_genesis::Genesis {
        let mut genesis = alloy_genesis::Genesis::default();
        genesis.config.extra_fields.insert(
            reth_chainspec::qmdb::DEFERRED_EXECUTION_TIME_KEY.to_owned(),
            serde_json::json!(0),
        );
        genesis
    }

    fn fields(byte: u8) -> crate::executed_fields::ExecutedFields {
        crate::executed_fields::ExecutedFields {
            state_root: B256::repeat_byte(byte),
            receipts_root: B256::repeat_byte(byte + 1),
            logs_bloom: Default::default(),
            gas_used: 21_000,
        }
    }

    /// The build chain's refusal, in one test: a parent this node built and
    /// has not yet handed to the engine has its execution filed under the
    /// hash the *builder* gave it and under no other, and a build that asks
    /// only under the hash consensus sealed gets nothing.
    ///
    /// This is what 289 of 347 refused chained builds on loop193 W1b were.
    /// The header a chain builds on is sealed ~275 ms before the own-block
    /// hand-off copies the fields across, so the fallback is not an
    /// optimisation -- without it the ordinary finish cannot build on a
    /// parent of this node's own making at all.
    #[test]
    fn a_parent_filed_under_the_builders_hash_is_found_through_the_fallback() {
        let genesis = deferred_genesis();
        // Distinct per test: the registry is process-wide.
        let built_hash = B256::repeat_byte(0x71);
        let sealed = SealedHeader::new(
            Header { number: 41, timestamp: 1_700_000_000, ..Default::default() },
            B256::repeat_byte(0x72),
        );
        let wait = std::time::Duration::from_millis(50);

        // Nothing filed anywhere: the build must fail, not hang.
        let at = std::time::Instant::now();
        assert_eq!(parent_executed_fields_or_built(&genesis, &sealed, Some(built_hash), wait), None);
        assert!(at.elapsed() >= wait, "a parent that never arrives is waited for, then refused");

        // As the builder leaves it: under the hash it gave the block.
        crate::executed_fields::remember(built_hash, fields(0xA0));
        assert_eq!(
            parent_executed_fields(&genesis, &sealed),
            None,
            "the sealed hash is what the hand-off files, and it has not run"
        );
        assert_eq!(
            parent_executed_fields_or_built(&genesis, &sealed, Some(built_hash), wait),
            Some(fields(0xA0))
        );
        // And filed under the sealed hash on the way out, so the next build
        // on this parent -- and the header check -- need no fallback.
        assert_eq!(parent_executed_fields(&genesis, &sealed), Some(fields(0xA0)));

        // Without a builder hash there is nothing to fall back to.
        let other = SealedHeader::new(
            Header { number: 42, timestamp: 1_700_000_001, ..Default::default() },
            B256::repeat_byte(0x73),
        );
        assert_eq!(parent_executed_fields_or_built(&genesis, &other, None, wait), None);
    }

    /// Depth as a parameter: at depth 1 the general form is the parent's
    /// result exactly, on a genesis parent, a pre-fork parent, a recorded
    /// parent and an unknown one (docs/DEFERRED_DEPTH_2_DESIGN.md step 0).
    #[test]
    fn at_depth_one_the_ancestor_is_the_parent() {
        let mut late_fork = alloy_genesis::Genesis::default();
        late_fork.config.extra_fields.insert(
            reth_chainspec::qmdb::DEFERRED_EXECUTION_TIME_KEY.to_owned(),
            serde_json::json!(1_000u64),
        );
        let recorded = SealedHeader::new(
            Header { number: 7, timestamp: 2_000, parent_hash: B256::repeat_byte(0x5e), ..Default::default() },
            B256::repeat_byte(0x5f),
        );
        crate::executed_fields::remember(recorded.hash(), fields(0x50));
        let carried = Header { state_root: B256::repeat_byte(0x52), gas_used: 9, ..Default::default() };
        let parents = [
            SealedHeader::new(Header { number: 0, ..carried.clone() }, B256::repeat_byte(0x53)),
            SealedHeader::new(Header { number: 3, timestamp: 10, ..carried.clone() }, B256::repeat_byte(0x54)),
            recorded,
            SealedHeader::new(Header { number: 8, timestamp: 2_001, ..carried }, B256::repeat_byte(0x55)),
        ];
        for genesis in [deferred_genesis(), late_fork] {
            for parent in &parents {
                assert_eq!(ancestor_executed_fields(&genesis, parent, 1), parent_executed_fields(&genesis, parent));
                assert_eq!(ancestor_hash(parent, 1), parent.hash());
                assert_eq!(
                    ancestor_executed_fields_or_built(&genesis, parent, None, 1, std::time::Duration::ZERO),
                    parent_executed_fields_or_built(&genesis, parent, None, std::time::Duration::ZERO),
                );
            }
        }
    }

    /// A block before the fork carries its own execution, so neither the
    /// registry nor the fallback is consulted.
    #[test]
    fn a_parent_before_the_fork_answers_from_its_own_header() {
        let mut genesis = alloy_genesis::Genesis::default();
        genesis.config.extra_fields.insert(
            reth_chainspec::qmdb::DEFERRED_EXECUTION_TIME_KEY.to_owned(),
            serde_json::json!(9_000_000_000u64),
        );
        let header = Header {
            number: 41,
            timestamp: 1_700_000_000,
            state_root: B256::repeat_byte(0xC1),
            receipts_root: B256::repeat_byte(0xC2),
            gas_used: 42_000,
            ..Default::default()
        };
        let sealed = SealedHeader::new(header, B256::repeat_byte(0xC9));
        let found = parent_executed_fields_or_built(&genesis, &sealed, None, std::time::Duration::ZERO)
            .expect("its own header is the answer");
        assert_eq!(found.state_root, B256::repeat_byte(0xC1));
        assert_eq!(found.gas_used, 42_000);
    }

    #[test]
    fn an_empty_block_commits_to_gov5s_nil_hash_and_an_empty_bloom() {
        let (root, bloom) = gov5_receipt_root_bloom(&[]);
        assert_eq!(root, GOV5_NIL_HASH);
        assert!(bloom.is_zero());
    }

    #[test]
    fn the_bloom_still_covers_every_log() {
        let receipt: Receipt = Receipt {
            success: true,
            cumulative_gas_used: 21_000,
            logs: vec![Log::new_unchecked(
                Address::repeat_byte(1),
                vec![B256::repeat_byte(2)],
                alloy_primitives::Bytes::new(),
            )],
            ..Default::default()
        };
        let (root, bloom) = gov5_receipt_root_bloom(std::slice::from_ref(&receipt));
        assert_ne!(root, GOV5_NIL_HASH);
        assert!(bloom.contains_input(alloy_primitives::BloomInput::Raw(Address::repeat_byte(1).as_slice())));
    }

    #[test]
    fn a_prepared_header_is_a_gov5_header_for_view_zero() {
        let parent = SealedHeader::seal_slow(Header {
            number: 4,
            ..Default::default()
        });
        let header = prepare_hotstuff_header(&parent);
        assert_eq!(header.number, 5);
        assert_eq!(header.parent_hash, parent.hash());
        assert_eq!(header.ommers_hash, B256::ZERO);
        assert_ne!(header.ommers_hash, EMPTY_OMMER_ROOT_HASH);
        assert_eq!(validate_gov5_h2_header(&header).unwrap().view, 0);
    }

    // ---- validation-rule tests ----

    use alloy_consensus::EMPTY_ROOT_HASH;
    use alloy_eips::eip4895::{Withdrawal, Withdrawals};
    use reth_chainspec::{ChainSpec, ChainSpecBuilder, MAINNET};

    // Mainnet fork times: Shanghai 1681338455, Cancun 1710338135, Prague 1746612311.
    const TS_LONDON: u64 = 1_600_000_000;
    const TS_SHANGHAI: u64 = 1_700_000_000;
    const TS_CANCUN: u64 = 1_720_000_000;
    const TS_PRAGUE: u64 = 1_800_000_000;

    fn consensus() -> HotStuffConsensus<ChainSpec> {
        HotStuffConsensus::new(MAINNET.clone())
    }

    /// A header the profile and Ethereum's standalone rules accept at `ts`.
    fn good_header(number: u64, ts: u64) -> Header {
        let mut header = Header {
            number,
            timestamp: ts,
            gas_limit: 30_000_000,
            gas_used: 0,
            base_fee_per_gas: Some(1_000),
            ommers_hash: B256::ZERO,
            transactions_root: EMPTY_ROOT_HASH,
            extra_data: HeaderExtra::for_view(number).encode(),
            ..Default::default()
        };
        if ts >= TS_SHANGHAI {
            header.withdrawals_root = Some(EMPTY_ROOT_HASH);
        }
        if ts >= TS_CANCUN {
            header.blob_gas_used = Some(0);
            header.excess_blob_gas = Some(0);
            header.parent_beacon_block_root = Some(B256::ZERO);
        }
        if ts >= TS_PRAGUE {
            header.requests_hash = Some(GOV5_EMPTY_REQUESTS_HASH);
        }
        header
    }

    fn sealed(header: Header) -> SealedHeader {
        SealedHeader::seal_slow(header)
    }

    fn other_err<T: std::error::Error + 'static>(err: &ConsensusError) -> Option<&T> {
        match err {
            ConsensusError::Other(inner) => inner.downcast_ref::<T>(),
            _ => None,
        }
    }

    #[test]
    fn genesis_header_is_accepted_without_consensus_fields() {
        let c = consensus();
        // No extra data, nonzero difficulty: genesis is exempt from every rule.
        let genesis = Header { number: 0, difficulty: U256::from(9), ..Default::default() };
        assert!(c.validate_header(&sealed(genesis)).is_ok());
    }

    #[test]
    fn a_well_formed_header_is_accepted_at_every_fork() {
        let c = consensus();
        for ts in [TS_LONDON, TS_SHANGHAI, TS_CANCUN, TS_PRAGUE] {
            c.validate_header(&sealed(good_header(5, ts))).unwrap_or_else(|e| panic!("ts {ts}: {e}"));
        }
        // gov5 spells the empty ommers list either way.
        let mut header = good_header(5, TS_SHANGHAI);
        header.ommers_hash = EMPTY_OMMER_ROOT_HASH;
        assert!(c.validate_header(&sealed(header)).is_ok());
        // Difficulty one is allowed as well as zero.
        let mut header = good_header(5, TS_SHANGHAI);
        header.difficulty = U256::from(1);
        assert!(c.validate_header(&sealed(header)).is_ok());
    }

    #[test]
    fn profile_violations_are_refused_as_other_errors() {
        use n42_h2_consensus::HeaderProfileError;
        let c = consensus();
        let cases: Vec<(&str, Header)> = vec![
            ("empty extra", Header { extra_data: Default::default(), ..good_header(5, TS_SHANGHAI) }),
            ("difficulty", Header { difficulty: U256::from(2), ..good_header(5, TS_SHANGHAI) }),
            ("nonce", Header { nonce: 7u64.into(), ..good_header(5, TS_SHANGHAI) }),
            ("ommers", Header { ommers_hash: B256::repeat_byte(3), ..good_header(5, TS_SHANGHAI) }),
        ];
        for (name, header) in cases {
            let err = c.validate_header(&sealed(header)).expect_err(name);
            assert!(other_err::<HeaderProfileError>(&err).is_some(), "{name}: {err:?}");
        }
        let err = c
            .validate_header(&sealed(Header { difficulty: U256::from(2), ..good_header(5, TS_SHANGHAI) }))
            .unwrap_err();
        assert!(matches!(other_err::<HeaderProfileError>(&err), Some(HeaderProfileError::Difficulty(_))));
    }

    #[test]
    fn ethereum_standalone_header_rules_still_apply() {
        let c = consensus();
        let mut header = good_header(5, TS_SHANGHAI);
        header.gas_used = header.gas_limit + 1;
        assert!(matches!(
            c.validate_header(&sealed(header)),
            Err(ConsensusError::HeaderGasUsedExceedsGasLimit { .. })
        ));
        // London is a block-number fork on mainnet: the base fee is demanded from 12,965,000.
        let mut header = good_header(13_000_000, TS_SHANGHAI);
        header.base_fee_per_gas = None;
        assert!(matches!(c.validate_header(&sealed(header)), Err(ConsensusError::BaseFeeMissing)));
    }

    #[test]
    fn withdrawals_root_presence_follows_shanghai() {
        let c = consensus();
        let mut header = good_header(5, TS_SHANGHAI);
        header.withdrawals_root = None;
        assert!(matches!(c.validate_header(&sealed(header)), Err(ConsensusError::WithdrawalsRootMissing)));
        let mut header = good_header(5, TS_LONDON);
        header.withdrawals_root = Some(EMPTY_ROOT_HASH);
        assert!(matches!(c.validate_header(&sealed(header)), Err(ConsensusError::WithdrawalsRootUnexpected)));
    }

    #[test]
    fn blob_fields_follow_cancun() {
        let c = consensus();
        let mut header = good_header(5, TS_SHANGHAI);
        header.blob_gas_used = Some(0);
        assert!(matches!(c.validate_header(&sealed(header)), Err(ConsensusError::BlobGasUsedUnexpected)));
        let mut header = good_header(5, TS_SHANGHAI);
        header.excess_blob_gas = Some(0);
        assert!(matches!(c.validate_header(&sealed(header)), Err(ConsensusError::ExcessBlobGasUnexpected)));
        let mut header = good_header(5, TS_SHANGHAI);
        header.parent_beacon_block_root = Some(B256::ZERO);
        assert!(matches!(
            c.validate_header(&sealed(header)),
            Err(ConsensusError::ParentBeaconBlockRootUnexpected)
        ));
        // Past Cancun the standalone 4844 check demands the blob fields.
        let mut header = good_header(5, TS_CANCUN);
        header.blob_gas_used = None;
        assert!(c.validate_header(&sealed(header)).is_err());
    }

    #[test]
    fn requests_hash_presence_follows_prague() {
        let c = consensus();
        let mut header = good_header(5, TS_PRAGUE);
        header.requests_hash = None;
        assert!(matches!(c.validate_header(&sealed(header)), Err(ConsensusError::RequestsHashMissing)));
        let mut header = good_header(5, TS_CANCUN);
        header.requests_hash = Some(GOV5_EMPTY_REQUESTS_HASH);
        assert!(matches!(c.validate_header(&sealed(header)), Err(ConsensusError::RequestsHashUnexpected)));
    }

    fn parent_and_child() -> (SealedHeader, Header) {
        let parent = sealed(good_header(5, TS_SHANGHAI));
        let mut child = good_header(6, TS_SHANGHAI + 3);
        child.parent_hash = parent.hash();
        // The parent used none of its gas, so the base fee falls by 1/8.
        child.base_fee_per_gas = Some(875);
        (parent, child)
    }

    #[test]
    fn a_child_that_follows_its_parent_is_accepted() {
        let (parent, child) = parent_and_child();
        assert!(consensus().validate_header_against_parent(&sealed(child), &parent).is_ok());
    }

    #[test]
    fn linkage_errors_are_the_ethereum_ones() {
        let c = consensus();
        let (parent, child) = parent_and_child();
        let mut bad = child.clone();
        bad.parent_hash = B256::repeat_byte(9);
        assert!(matches!(
            c.validate_header_against_parent(&sealed(bad), &parent),
            Err(ConsensusError::ParentHashMismatch(_))
        ));
        let mut bad = child.clone();
        bad.number = 9;
        assert!(matches!(
            c.validate_header_against_parent(&sealed(bad), &parent),
            Err(ConsensusError::ParentBlockNumberMismatch { .. })
        ));
        let mut bad = child.clone();
        bad.timestamp = parent.timestamp;
        assert!(matches!(
            c.validate_header_against_parent(&sealed(bad), &parent),
            Err(ConsensusError::TimestampIsInPast { .. })
        ));
        let mut bad = child;
        bad.gas_limit = parent.gas_limit * 2;
        assert!(matches!(
            c.validate_header_against_parent(&sealed(bad), &parent),
            Err(ConsensusError::GasLimitInvalidIncrease { .. })
        ));
    }

    fn deferred_consensus() -> HotStuffConsensus<ChainSpec> {
        HotStuffConsensus::new(Arc::new(ChainSpecBuilder::mainnet().genesis(deferred_genesis()).build()))
    }

    #[test]
    fn deferred_execution_demands_the_parents_result() {
        let c = deferred_consensus();
        let mut parent_header = good_header(500, TS_SHANGHAI);
        parent_header.state_root = B256::repeat_byte(0xD1);
        let parent = sealed(parent_header);
        let mut child = good_header(501, TS_SHANGHAI + 3);
        child.parent_hash = parent.hash();
        child.base_fee_per_gas = Some(875);

        // Parent's execution is not known here yet.
        let err = c.validate_header_against_parent(&sealed(child.clone()), &parent).unwrap_err();
        assert!(matches!(
            other_err::<DeferredExecutionError>(&err),
            Some(DeferredExecutionError::ParentUnknown(h)) if *h == parent.hash()
        ));

        // Known, header carries something else.
        crate::executed_fields::remember(parent.hash(), fields(0x40));
        let err = c.validate_header_against_parent(&sealed(child.clone()), &parent).unwrap_err();
        assert!(matches!(other_err::<DeferredExecutionError>(&err), Some(DeferredExecutionError::Mismatch { .. })));

        // Header repeats the parent's result.
        let expected = fields(0x40);
        child.state_root = expected.state_root;
        child.receipts_root = expected.receipts_root;
        child.gas_used = expected.gas_used;
        assert!(c.validate_header_against_parent(&sealed(child), &parent).is_ok());
    }

    #[test]
    fn deferred_execution_after_genesis_parent_repeats_its_header() {
        let c = deferred_consensus();
        let parent = sealed(Header {
            number: 0,
            timestamp: TS_SHANGHAI,
            gas_limit: 30_000_000,
            state_root: B256::repeat_byte(0xE1),
            base_fee_per_gas: Some(1_000),
            ..Default::default()
        });
        let mut child = good_header(1, TS_SHANGHAI + 3);
        child.parent_hash = parent.hash();
        child.base_fee_per_gas = Some(875);
        // The child's state root is not the genesis state root.
        assert!(c.validate_header_against_parent(&sealed(child.clone()), &parent).is_err());
        child.state_root = parent.state_root;
        assert!(c.validate_header_against_parent(&sealed(child), &parent).is_ok());
    }

    #[test]
    fn a_committee_chain_links_the_parent_beacon_root_to_the_parents_evidence() {
        let genesis: alloy_genesis::Genesis =
            serde_json::from_str(include_str!("../../../chainspec/res/genesis/n42_devnet.json")).unwrap();
        let c = HotStuffConsensus::new(Arc::new(ChainSpec::from(genesis)));
        let pool = c.committee_pool().expect("the devnet genesis names a committee pool");

        let mut parent_header = good_header(7, 1_000);
        parent_header.receipts_root = B256::repeat_byte(0x55);
        let parent = sealed(parent_header);
        let expected = pool.parent_beacon_root(parent.number, &parent.hash(), &parent.receipts_root).unwrap();
        assert_ne!(expected, B256::ZERO);

        let mut child = good_header(8, 1_003);
        child.parent_hash = parent.hash();
        child.base_fee_per_gas = Some(875);
        child.blob_gas_used = Some(0);
        child.excess_blob_gas = Some(0);
        child.requests_hash = Some(GOV5_EMPTY_REQUESTS_HASH);
        child.withdrawals_root = Some(EMPTY_ROOT_HASH);
        child.parent_beacon_block_root = Some(expected);
        c.validate_header_against_parent(&sealed(child.clone()), &parent).unwrap();

        child.parent_beacon_block_root = Some(B256::repeat_byte(0x66));
        let err = c.validate_header_against_parent(&sealed(child.clone()), &parent).unwrap_err();
        let link = other_err::<CommitteeLinkError>(&err).expect("a committee link error");
        assert_eq!(link.expected, expected);
        assert_eq!(link.got, B256::repeat_byte(0x66));

        // A missing root reads as zero, which is not the evidence either.
        child.parent_beacon_block_root = None;
        let err = c.validate_header_against_parent(&sealed(child), &parent).unwrap_err();
        assert_eq!(other_err::<CommitteeLinkError>(&err).unwrap().got, B256::ZERO);
    }

    fn block_of(header: Header, body: EthBlockBody) -> SealedBlock<EthBlock> {
        SealedBlock::seal_slow(EthBlock { header, body })
    }

    fn empty_body() -> EthBlockBody {
        EthBlockBody { transactions: vec![], ommers: vec![], withdrawals: None }
    }

    #[test]
    fn body_ommers_are_checked_against_either_spelling_of_none() {
        let c = consensus();
        let body = empty_body();
        let mut header = good_header(5, TS_LONDON);
        // Zero and the empty-list hash both mean "none".
        assert!(c.validate_body_against_header(&body, &sealed(header.clone())).is_ok());
        header.ommers_hash = EMPTY_OMMER_ROOT_HASH;
        assert!(c.validate_body_against_header(&body, &sealed(header.clone())).is_ok());
        // Any other claim is refused.
        header.ommers_hash = B256::repeat_byte(4);
        assert!(matches!(
            c.validate_body_against_header(&body, &sealed(header.clone())),
            Err(ConsensusError::BodyOmmersHashDiff(_))
        ));
        // A body that brings ommers under a zero hash is lying.
        header.ommers_hash = B256::ZERO;
        let with_ommers = EthBlockBody { ommers: vec![Header::default()], ..empty_body() };
        assert!(matches!(
            c.validate_body_against_header(&with_ommers, &sealed(header)),
            Err(ConsensusError::BodyOmmersHashDiff(_))
        ));
    }

    #[test]
    fn body_transactions_root_must_match() {
        let c = consensus();
        let mut header = good_header(5, TS_LONDON);
        header.transactions_root = B256::repeat_byte(8);
        assert!(matches!(
            c.validate_body_against_header(&empty_body(), &sealed(header)),
            Err(ConsensusError::BodyTransactionRootDiff(_))
        ));
    }

    fn withdrawal(index: u64, amount: u64) -> Withdrawal {
        Withdrawal { index, validator_index: 0, address: Address::repeat_byte(index as u8 + 1), amount }
    }

    #[test]
    fn body_withdrawals_accept_the_trie_root_or_gov5s_rewards_root() {
        let c = consensus();
        let list = vec![withdrawal(0, 5), withdrawal(1, 7)];
        let body = EthBlockBody { withdrawals: Some(Withdrawals::new(list.clone())), ..empty_body() };
        let trie_root = body.calculate_withdrawals_root().unwrap();
        let gov5_root = gov5_rewards_root(withdrawals_to_rewards(&list));
        assert_ne!(trie_root, gov5_root);

        let mut header = good_header(5, TS_SHANGHAI);
        header.withdrawals_root = Some(trie_root);
        assert!(c.validate_body_against_header(&body, &sealed(header.clone())).is_ok());
        header.withdrawals_root = Some(gov5_root);
        assert!(c.validate_body_against_header(&body, &sealed(header.clone())).is_ok());
        header.withdrawals_root = Some(B256::repeat_byte(0x99));
        assert!(matches!(
            c.validate_body_against_header(&body, &sealed(header)),
            Err(ConsensusError::BodyWithdrawalsRootDiff(_))
        ));
    }

    #[test]
    fn body_withdrawals_presence_must_agree_with_the_header() {
        let c = consensus();
        let header = good_header(5, TS_SHANGHAI);
        assert!(matches!(
            c.validate_body_against_header(&empty_body(), &sealed(header)),
            Err(ConsensusError::BodyWithdrawalsMissing)
        ));
        let mut header = good_header(5, TS_LONDON);
        header.withdrawals_root = None;
        let body = EthBlockBody { withdrawals: Some(Withdrawals::new(vec![])), ..empty_body() };
        assert!(matches!(
            c.validate_body_against_header(&body, &sealed(header)),
            Err(ConsensusError::WithdrawalsRootUnexpected)
        ));
    }

    #[test]
    fn pre_execution_requires_withdrawals_after_shanghai_and_checks_cancun_gas() {
        let c = consensus();
        let good_body = EthBlockBody { withdrawals: Some(Withdrawals::new(vec![])), ..empty_body() };
        // Withdrawals root None, body None: the body check passes, Shanghai's rule fires.
        let mut header = good_header(5, TS_SHANGHAI);
        header.withdrawals_root = None;
        assert!(matches!(
            c.validate_block_pre_execution(&block_of(header, empty_body())),
            Err(ConsensusError::BodyWithdrawalsMissing)
        ));
        assert!(c.validate_block_pre_execution(&block_of(good_header(5, TS_SHANGHAI), good_body.clone())).is_ok());
        assert!(c.validate_block_pre_execution(&block_of(good_header(5, TS_CANCUN), good_body.clone())).is_ok());
        // Cancun: the header's blob gas must be what the (empty) body consumes.
        let mut header = good_header(5, TS_CANCUN);
        header.blob_gas_used = Some(131_072);
        assert!(c.validate_block_pre_execution(&block_of(header, good_body)).is_err());
    }

    #[test]
    fn a_known_transaction_root_replaces_the_computed_one_for_one_call_only() {
        let c = consensus();
        let known = B256::repeat_byte(0x2A);
        let mut header = good_header(5, TS_LONDON);
        header.transactions_root = known;
        let block = block_of(header, empty_body());
        // The empty body's real root is the empty trie; only the passed root matches.
        assert!(c.validate_block_pre_execution_with_tx_root(&block, Some(known)).is_ok());
        // The thread-local is cleared afterwards.
        assert!(matches!(
            c.validate_block_pre_execution(&block),
            Err(ConsensusError::BodyTransactionRootDiff(_))
        ));
        // A passed root that disagrees with the header is refused.
        assert!(matches!(
            c.validate_block_pre_execution_with_tx_root(&block, Some(B256::repeat_byte(1))),
            Err(ConsensusError::BodyTransactionRootDiff(_))
        ));
        // None falls back to computing it.
        assert!(c.validate_block_pre_execution_with_tx_root(&block, None).is_err());
    }

    #[test]
    fn prepare_and_seal_leave_the_view_and_seal_to_the_validator() {
        let c = consensus();
        let parent = sealed(good_header(9, TS_SHANGHAI));
        let mut header = c.prepare(&parent).unwrap();
        assert_eq!(header.number, 10);
        let before = header.clone();
        c.seal(&mut header).unwrap();
        assert_eq!(header, before);
    }

    #[test]
    fn the_signer_key_is_kept_for_information_and_never_the_beneficiary() {
        let c = consensus();
        assert_eq!(c.get_eth_signer_address().unwrap(), None);
        let key = format!("0x{}", "01".repeat(32));
        c.set_eth_signer_by_key(Some(key.clone())).unwrap();
        let address = c.get_eth_signer_address().unwrap().expect("configured");
        let expected = key.parse::<alloy_signer_local::PrivateKeySigner>().unwrap().address();
        assert_eq!(address, expected);
        // The block's beneficiary never comes from the local key.
        assert_eq!(c.get_signer_address().unwrap(), None);
        c.set_eth_signer_by_key(None).unwrap();
        assert_eq!(c.get_eth_signer_address().unwrap(), None);
    }

    #[test]
    fn a_malformed_signer_key_is_refused_and_leaves_the_old_one() {
        let c = consensus();
        c.set_signer_key(Some(format!("0x{}", "02".repeat(32)))).unwrap();
        let before = c.get_eth_signer_address().unwrap();
        assert!(before.is_some());
        assert!(matches!(c.set_signer_key(Some("nonsense".into())), Err(AposError::InvalidSignerKey(_))));
        let err = c.set_eth_signer_by_key(Some("nonsense".into())).unwrap_err();
        assert!(other_err::<AposError>(&err).is_some());
        assert_eq!(c.get_eth_signer_address().unwrap(), before);
    }

    // ---- post-execution ----

    use alloy_eips::eip7685::Requests;

    fn recovered(header: Header) -> RecoveredBlock<EthBlock> {
        RecoveredBlock::new_unhashed(EthBlock { header, body: empty_body() }, vec![])
    }

    fn result_of(receipts: Vec<Receipt>, gas_used: u64) -> BlockExecutionResult<Receipt> {
        BlockExecutionResult { receipts, requests: Requests::default(), gas_used, blob_gas_used: 0 }
    }

    fn log_receipt(gas: u64) -> Receipt {
        Receipt {
            success: true,
            cumulative_gas_used: gas,
            logs: vec![Log::new_unchecked(Address::repeat_byte(7), vec![B256::repeat_byte(1)], Default::default())],
            ..Default::default()
        }
    }

    /// A header whose execution fields match `receipts`.
    fn header_for(receipts: &[Receipt], number: u64, ts: u64) -> Header {
        let (root, bloom) = gov5_receipt_root_bloom(receipts);
        let gas = receipts.last().map_or(0, |r| r.cumulative_gas_used);
        Header { receipts_root: root, logs_bloom: bloom, gas_used: gas, ..good_header(number, ts) }
    }

    #[test]
    fn post_execution_accepts_a_matching_result() {
        let c = consensus();
        let receipts = vec![log_receipt(21_000)];
        let block = recovered(header_for(&receipts, 5, TS_SHANGHAI));
        assert!(c.validate_block_post_execution(&block, &result_of(receipts, 21_000), None, None).is_ok());
        // An empty block commits to gov5's nil hash.
        let block = recovered(header_for(&[], 5, TS_SHANGHAI));
        assert!(c.validate_block_post_execution(&block, &result_of(vec![], 0), None, None).is_ok());
    }

    #[test]
    fn post_execution_refuses_each_mismatch_with_its_own_error() {
        let c = consensus();
        let receipts = vec![log_receipt(21_000)];
        let good = header_for(&receipts, 5, TS_SHANGHAI);

        let block = recovered(good.clone());
        assert!(matches!(
            c.validate_block_post_execution(&block, &result_of(receipts.clone(), 22_000), None, None),
            Err(ConsensusError::BlockGasUsed { .. })
        ));
        let block = recovered(Header { receipts_root: B256::repeat_byte(1), ..good.clone() });
        assert!(matches!(
            c.validate_block_post_execution(&block, &result_of(receipts.clone(), 21_000), None, None),
            Err(ConsensusError::BodyReceiptRootDiff(_))
        ));
        let block = recovered(Header { logs_bloom: Default::default(), ..good });
        assert!(matches!(
            c.validate_block_post_execution(&block, &result_of(receipts, 21_000), None, None),
            Err(ConsensusError::BodyBloomLogDiff(_))
        ));
    }

    #[test]
    fn post_execution_holds_requests_to_the_eip_after_prague() {
        let c = consensus();
        let empty = result_of(vec![], 0);
        let mut header = header_for(&[], 5, TS_PRAGUE);
        // Both spellings of "no requests" are accepted.
        assert!(c.validate_block_post_execution(&recovered(header.clone()), &empty, None, None).is_ok());
        header.requests_hash = Some(Requests::default().requests_hash());
        assert!(c.validate_block_post_execution(&recovered(header.clone()), &empty, None, None).is_ok());
        // Missing.
        header.requests_hash = None;
        assert!(matches!(
            c.validate_block_post_execution(&recovered(header.clone()), &empty, None, None),
            Err(ConsensusError::RequestsHashMissing)
        ));
        // Something else for an empty list.
        header.requests_hash = Some(B256::repeat_byte(5));
        assert!(matches!(
            c.validate_block_post_execution(&recovered(header.clone()), &empty, None, None),
            Err(ConsensusError::BodyRequestsHashDiff(_))
        ));
        // A block that made requests is held to the EIP's hash, not gov5's empty one.
        let mut requests = Requests::default();
        requests.push_request_with_type(0x01, [1u8, 2, 3]);
        let mut with_requests = result_of(vec![], 0);
        with_requests.requests = requests.clone();
        header.requests_hash = Some(requests.requests_hash());
        assert!(c.validate_block_post_execution(&recovered(header.clone()), &with_requests, None, None).is_ok());
        header.requests_hash = Some(GOV5_EMPTY_REQUESTS_HASH);
        assert!(matches!(
            c.validate_block_post_execution(&recovered(header), &with_requests, None, None),
            Err(ConsensusError::BodyRequestsHashDiff(_))
        ));
    }

    #[test]
    fn under_deferred_execution_post_execution_records_the_blocks_receipts() {
        let c = deferred_consensus();
        // Under deferral the header describes the parent, so its fields are not compared.
        let header = Header { receipts_root: B256::repeat_byte(0xAB), ..good_header(600, TS_SHANGHAI) };
        let block = recovered(header);
        let hash = block.hash();
        crate::executed_fields::remember_state_root(hash, B256::repeat_byte(0x77));
        // A result that does not cover the block (1 receipt, 0 transactions) is not recorded.
        let partial = result_of(vec![log_receipt(21_000)], 21_000);
        assert!(c.validate_block_post_execution(&block, &partial, None, None).is_ok());
        assert_eq!(crate::executed_fields::get(&hash), None);
        // A complete one (no transactions, no receipts) is.
        assert!(c.validate_block_post_execution(&block, &result_of(vec![], 0), None, None).is_ok());
        let recorded = crate::executed_fields::get(&hash).expect("recorded");
        assert_eq!(recorded.state_root, B256::repeat_byte(0x77));
        assert_eq!(recorded.receipts_root, GOV5_NIL_HASH);
        assert_eq!(recorded.gas_used, 0);
    }

    #[test]
    fn under_deferred_execution_the_requests_hash_is_still_checked() {
        let c = deferred_consensus();
        let mut header = good_header(601, TS_PRAGUE);
        header.requests_hash = Some(B256::repeat_byte(5));
        assert!(matches!(
            c.validate_block_post_execution(&recovered(header), &result_of(vec![], 0), None, None),
            Err(ConsensusError::BodyRequestsHashDiff(_))
        ));
    }
}
