// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A frame's includability facts, summed once at ingest
//! (`N42_FOLLOWER_FRAME_SCAN=1`, `docs/BREAKTHROUGH_DESIGN.md` section 1).
//!
//! The follower's includability check (`check_includable` in `bin/n42`)
//! scanned every transaction of a block on the vote road: its chain id, fee
//! cap, priority fee, authorization list, intrinsic gas, the nonces chaining
//! within a sender's run and the run's cost -- 163,000 transactions on the
//! check pool beside the execution's batches. All of that but the fee cap
//! against the block's base fee is a fact about the transaction alone, so it
//! is summed here per frame when the ingest admits the frame, in frame
//! order: the gas total, the smallest fee cap, the chain id the frame's
//! transactions carry, and the sender runs with their nonces and costs. The
//! check then reads ~326 summaries and their runs instead of the
//! transactions.
//!
//! Only a *clean* frame is summed: one in which no transaction is refused on
//! its own terms (under [`SUMMARY_SPEC`]) and every run's nonces are
//! contiguous. Anything else -- a frame with a flaw, a cut last frame, a
//! frame the proposer's fill supplied, a block under another fork -- is
//! scanned transaction by transaction exactly as before, so a verdict and its
//! message never depend on whether a summary existed.

use alloy_primitives::{map::B256HashMap, Address, B256, U256};
use reth_revm::primitives::hardfork::SpecId;
use std::sync::{Arc, Mutex};

use crate::N42PooledTransaction;
use n42_tx_types::N42TxEnvelope as TransactionSigned;

/// The fork the summaries' intrinsic gas is computed under; a block under any
/// other is scanned per transaction.
pub const SUMMARY_SPEC: SpecId = SpecId::OSAKA;

/// How many summaries are kept; the oldest leave first. Twice the queue's
/// frame index bound: a frame is read once, by the block that carries it.
const MAX_SUMMARIES: usize = 32_768;

/// One sender's consecutive transactions within a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRun {
    /// The sender.
    pub sender: Address,
    /// The run's first position within the frame.
    pub offset: u32,
    /// The first transaction's nonce; the run's nonces follow it one by one.
    pub first_nonce: u64,
    /// How many transactions.
    pub len: u64,
    /// The run's cost ([`tx_cost`] summed, saturating).
    pub cost: U256,
}

/// A clean frame's includability facts ([`summarize`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameScan {
    /// How many transactions the frame holds.
    pub len: usize,
    /// The chain id every transaction that carries one carries; `None` when
    /// none does.
    pub chain_id: Option<u64>,
    /// The smallest fee cap: the frame passes a block's base fee when this does.
    pub min_fee_cap: u128,
    /// The sum of the gas limits, saturating.
    pub gas_total: u64,
    /// The sender runs, in frame order.
    pub runs: Vec<FrameRun>,
}

impl FrameScan {
    /// Whether this summary answers for a block under `spec`, of chain
    /// `chain_id`, at `base_fee`: anything else and the frame is scanned.
    pub fn usable(&self, chain_id: u64, spec: SpecId, base_fee: u128) -> bool {
        spec == SUMMARY_SPEC && self.chain_id.is_none_or(|id| id == chain_id) && self.min_fee_cap >= base_fee
    }
}

/// The intrinsic gas -- the transaction's kind, calldata, access list and
/// authorizations under this fork -- that its gas limit does not cover, or
/// `None` if it does. The one definition the check and the summaries share.
pub fn intrinsic_gas_shortfall(tx: &TransactionSigned, spec: SpecId) -> Option<u64> {
    use alloy_consensus::Transaction as _;

    let (al_accounts, al_storages) = tx
        .access_list()
        .map(|list| (list.len() as u64, list.iter().map(|item| item.storage_keys.len() as u64).sum::<u64>()))
        .unwrap_or((0, 0));
    let intrinsic = reth_revm::context_interface::cfg::gas::calculate_initial_tx_gas(
        spec,
        tx.input(),
        tx.kind().is_create(),
        al_accounts,
        al_storages,
        tx.authorization_list().map_or(0, |list| list.len() as u64),
        None,
    );
    let needed = (intrinsic.initial_regular_gas + intrinsic.initial_state_gas).max(intrinsic.floor_gas);
    (tx.gas_limit() < needed).then_some(needed)
}

/// The per-run cost of one transaction: value plus gas at the fee cap plus
/// blob gas at its cap, saturating. The one definition the check and the
/// summaries share.
pub fn tx_cost(tx: &TransactionSigned) -> U256 {
    use alloy_consensus::Transaction as _;
    let gas = U256::from(tx.gas_limit()) * U256::from(tx.max_fee_per_gas());
    let blobs = U256::from(tx.blob_gas_used().unwrap_or(0)) * U256::from(tx.max_fee_per_blob_gas().unwrap_or(0));
    tx.value().saturating_add(gas).saturating_add(blobs)
}

/// A frame's summary from its transactions and senders in frame order, or
/// `None` when any of them would make the check say something other than
/// "includable" on its own terms (see the module docs).
pub fn summarize<'a>(txs: impl IntoIterator<Item = (&'a TransactionSigned, Address)>) -> Option<FrameScan> {
    use alloy_consensus::Transaction as _;
    let mut scan = FrameScan { len: 0, chain_id: None, min_fee_cap: u128::MAX, gas_total: 0, runs: Vec::new() };
    for (offset, (tx, sender)) in txs.into_iter().enumerate() {
        if let Some(id) = tx.chain_id() {
            match scan.chain_id {
                Some(held) if held != id => return None,
                _ => scan.chain_id = Some(id),
            }
        }
        let cap = tx.max_fee_per_gas();
        if tx.max_priority_fee_per_gas().is_some_and(|tip| tip > cap) {
            return None;
        }
        if tx.authorization_list().is_some_and(|list| list.is_empty()) {
            return None;
        }
        if intrinsic_gas_shortfall(tx, SUMMARY_SPEC).is_some() {
            return None;
        }
        scan.min_fee_cap = scan.min_fee_cap.min(cap);
        scan.gas_total = scan.gas_total.saturating_add(tx.gas_limit());
        match scan.runs.last_mut() {
            Some(run) if run.sender == sender => {
                if tx.nonce() != run.first_nonce.saturating_add(run.len) {
                    return None;
                }
                run.len += 1;
                run.cost = run.cost.saturating_add(tx_cost(tx));
            }
            _ => scan.runs.push(FrameRun {
                sender,
                offset: u32::try_from(offset).ok()?,
                first_nonce: tx.nonce(),
                len: 1,
                cost: tx_cost(tx),
            }),
        }
        scan.len += 1;
    }
    Some(scan)
}

#[derive(Debug, Default)]
struct Store {
    by_id: B256HashMap<Arc<FrameScan>>,
    order: std::collections::VecDeque<B256>,
}

fn store() -> &'static Mutex<Store> {
    static STORE: std::sync::OnceLock<Mutex<Store>> = std::sync::OnceLock::new();
    STORE.get_or_init(Mutex::default)
}

/// `N42_FOLLOWER_FRAME_SCAN=1`, read once: the ingest sums its frames and the
/// check reads the sums.
pub fn enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_FRAME_SCAN").is_ok_and(|v| v == "1"))
}

/// Files a frame's summary under its id.
pub fn remember(id: B256, scan: FrameScan) {
    let mut store = store().lock().unwrap_or_else(|p| p.into_inner());
    if store.by_id.insert(id, Arc::new(scan)).is_none() {
        store.order.push_back(id);
    }
    while store.order.len() > MAX_SUMMARIES {
        if let Some(old) = store.order.pop_front() {
            store.by_id.remove(&old);
        }
    }
}

/// The summaries of `ids`, one lock for all of them.
pub fn lookup(ids: impl IntoIterator<Item = B256>) -> Vec<Option<Arc<FrameScan>>> {
    let store = store().lock().unwrap_or_else(|p| p.into_inner());
    ids.into_iter().map(|id| store.by_id.get(&id).cloned()).collect()
}

/// A checked block's frame layout, filed by the frame road
/// ([`crate::engine_validator`]'s `describe_frames`) for its includability
/// check: each frame's id, its count in the block, and whether the block's
/// transactions there are the frame's own, taken whole from this node's index
/// (only then may the frame's summary stand for them).
pub type Layout = Vec<(B256, usize, bool)>;

fn layouts() -> &'static Mutex<std::collections::VecDeque<(B256, Arc<Layout>)>> {
    static LAYOUTS: std::sync::OnceLock<Mutex<std::collections::VecDeque<(B256, Arc<Layout>)>>> =
        std::sync::OnceLock::new();
    LAYOUTS.get_or_init(Mutex::default)
}

/// Files `block`'s layout for its check (a few blocks are kept).
pub fn remember_layout(block: B256, layout: Layout) {
    if !enabled() {
        return;
    }
    let mut held = layouts().lock().unwrap_or_else(|p| p.into_inner());
    held.retain(|(hash, _)| *hash != block);
    held.push_back((block, Arc::new(layout)));
    while held.len() > 16 {
        held.pop_front();
    }
}

/// `block`'s layout, when its frame road filed one.
pub fn layout_of(block: &B256) -> Option<Arc<Layout>> {
    if !enabled() {
        return None;
    }
    let held = layouts().lock().unwrap_or_else(|p| p.into_inner());
    held.iter().rev().find(|(hash, _)| hash == block).map(|(_, layout)| Arc::clone(layout))
}

/// The ingest's hook: a frame admitted whole, its transactions as decoded
/// (in any order) and its hashes in frame order. Sums it when the flag is on,
/// the transactions are this node's pooled type and they are exactly the
/// frame's; otherwise does nothing.
#[allow(clippy::ptr_arg)] // a `Vec`, because an unsized slice cannot be downcast
pub fn note_admitted<T: 'static>(id: B256, hashes: &[B256], decoded: &Vec<T>) {
    use reth_transaction_pool::PoolTransaction as _;
    if !enabled() || hashes.len() != decoded.len() {
        return;
    }
    let Some(decoded) = (decoded as &dyn std::any::Any).downcast_ref::<Vec<N42PooledTransaction>>().map(Vec::as_slice)
    else {
        return;
    };
    let in_order = decoded.iter().zip(hashes).all(|(tx, hash)| tx.hash() == hash);
    let ordered: Vec<&N42PooledTransaction> = if in_order {
        decoded.iter().collect()
    } else {
        let at: B256HashMap<&N42PooledTransaction> = decoded.iter().map(|tx| (*tx.hash(), tx)).collect();
        match hashes.iter().map(|hash| at.get(hash).copied()).collect::<Option<Vec<_>>>() {
            Some(ordered) => ordered,
            None => return,
        }
    };
    if let Some(scan) = summarize(ordered.iter().map(|tx| (tx.transaction().inner(), tx.transaction().signer()))) {
        remember(id, scan);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxEip1559};
    use alloy_primitives::{Signature, TxKind};

    fn transfer(nonce: u64, gas_limit: u64, fee: u128) -> TransactionSigned {
        let tx = TxEip1559 {
            chain_id: 7,
            nonce,
            gas_limit,
            max_fee_per_gas: fee,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(Address::repeat_byte(9)),
            value: U256::from(5),
            ..Default::default()
        };
        let signed = Signed::new_unchecked(tx, Signature::test_signature(), B256::random());
        TransactionSigned::from(reth_ethereum_primitives::TransactionSigned::from(signed))
    }

    #[test]
    fn a_clean_frame_sums_its_runs() {
        let (a, b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        let txs = [(transfer(3, 21_000, 10), a), (transfer(4, 21_000, 12), a), (transfer(0, 21_000, 11), b)];
        let scan = summarize(txs.iter().map(|(tx, s)| (tx, *s))).expect("clean");
        assert_eq!(scan.len, 3);
        assert_eq!(scan.chain_id, Some(7));
        assert_eq!(scan.min_fee_cap, 10);
        assert_eq!(scan.gas_total, 63_000);
        assert_eq!(scan.runs.len(), 2);
        assert_eq!((scan.runs[0].offset, scan.runs[0].first_nonce, scan.runs[0].len), (0, 3, 2));
        assert_eq!(scan.runs[0].cost, tx_cost(&txs[0].0) + tx_cost(&txs[1].0));
        assert_eq!((scan.runs[1].offset, scan.runs[1].len), (2, 1));
        assert!(scan.usable(7, SUMMARY_SPEC, 10));
        assert!(!scan.usable(7, SUMMARY_SPEC, 11));
        assert!(!scan.usable(8, SUMMARY_SPEC, 1));
        assert!(!scan.usable(7, SpecId::PRAGUE, 1));
    }

    #[test]
    fn a_flawed_frame_is_not_summed() {
        let a = Address::repeat_byte(1);
        let gap = [(transfer(3, 21_000, 10), a), (transfer(5, 21_000, 10), a)];
        assert!(summarize(gap.iter().map(|(tx, s)| (tx, *s))).is_none());
        let short = [(transfer(0, 20_000, 10), a)];
        assert!(summarize(short.iter().map(|(tx, s)| (tx, *s))).is_none());
    }
}
