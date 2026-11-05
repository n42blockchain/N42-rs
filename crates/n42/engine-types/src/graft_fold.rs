// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bundle half of the graft on reth v2.9.0 (`docs/RETH_2_9_0_UPGRADE.md`,
//! "F5 design").
//!
//! revm's `State` let the parallel paths graft the batches' bundles into the
//! block's live bundle mid-block. reth v2.9.0's executor has no such bundle:
//! its accumulator is private and becomes a bundle only at the end of
//! `finish`. So the graft is two halves:
//!
//! 1. **Cache half** (the caller's): before the serial tail and `finish`,
//!    every account the batches changed that anything after them may read
//!    is written into the executor's accepted overlay at its post-batch
//!    value ([`MergedBatches::accounts`]), so the serial transactions, the
//!    withdrawals and the post-execution calls read what a sequential
//!    execution would have left there.
//! 2. **Bundle half** ([`fold_into`]): after `finish`, the batches' accounts
//!    are folded into the finished bundle. An account only the batches
//!    touched goes in as they left it. An account the serial part touched
//!    too keeps the serial part's final info, which already includes the
//!    batches' effect, and takes the batches' original (the parent's); its
//!    status and its revert are recomputed from that pair, and the serial
//!    part's revert to the post-batch value is dropped. The batches'
//!    reverts go into the bundle's revert set for the block, sorted by
//!    address, as the revm-era graft left them, so a revert by index still
//!    rebuilds the parent's state.
//!
//! The fold is defensive: before it changes anything it checks every
//! invariant the rule relies on and refuses the block with a [`FoldRefused`]
//! (one warn line, [`refused_count`] up) so the caller can fall back to the
//! serial path, as the parallel paths refuse a block today:
//! - a batch account carries no storage, no code and no selfdestruct;
//! - every batch built against the same parent (an account two batches
//!   changed has one original), and at most one of them debited it (a
//!   sender's balance and nonce move in one batch; the others only credit,
//!   so the credits commute);
//! - an account the serial part touched too was read by it at its
//!   post-batch value: its serial original equals the batches' final info.
//!   This is what the cache half guarantees, and what catches a withdrawal
//!   recipient or a beneficiary the cache half missed.

use alloy_primitives::{
    map::{AddressMap, Entry},
    Address, U256,
};
use evm2::evm::AccountInfo;
use reth_trie::bundle_state::{AccountRevert, AccountStatus, BundleAccount, BundleState, TransitionAccount};
use std::sync::atomic::{AtomicU64, Ordering};

/// Why the bundle half refused a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoldRefused {
    /// A batch changed an account's storage.
    Storage(Address),
    /// A batch account has code, or a batch deployed code.
    Code(Address),
    /// A batch destroyed an account, or left it absent.
    Destroyed(Address),
    /// Two batches loaded an account with different originals.
    Originals(Address),
    /// Two batches debited the same account.
    TwoDebits(Address),
    /// The serial part read an account the batches changed at a value other
    /// than their result: the cache half did not hold it.
    Stale(Address),
    /// The serial part changed the storage of an account the batches changed.
    SerialStorage(Address),
}

impl std::fmt::Display for FoldRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(a) => write!(f, "batch account {a} has storage changes"),
            Self::Code(a) => write!(f, "batch account {a} has code"),
            Self::Destroyed(a) => write!(f, "batch account {a} was destroyed"),
            Self::Originals(a) => write!(f, "batches loaded {a} with different originals"),
            Self::TwoDebits(a) => write!(f, "two batches debited {a}"),
            Self::Stale(a) => write!(f, "the serial part read {a} at a value other than the batches' result"),
            Self::SerialStorage(a) => write!(f, "the serial part changed the storage of batch account {a}"),
        }
    }
}

impl std::error::Error for FoldRefused {}

static REFUSED: AtomicU64 = AtomicU64::new(0);

/// How many blocks the bundle half has refused in this process.
pub fn refused_count() -> u64 {
    REFUSED.load(Ordering::Relaxed)
}

fn refuse<T>(err: FoldRefused) -> Result<T, FoldRefused> {
    REFUSED.fetch_add(1, Ordering::Relaxed);
    tracing::warn!(target: "n42::graft", reason = %err, "parallel graft refused, the block goes to the serial path");
    Err(err)
}

/// One account across the batches.
#[derive(Debug)]
struct Merged {
    /// The parent's account, as every batch loaded it.
    original: Option<AccountInfo>,
    /// The account after all the batches.
    info: AccountInfo,
    /// Whether a batch debited it (balance down or nonce up).
    debited: bool,
    /// The batch's own account and revert while only one batch changed it.
    single: Option<(BundleAccount, Option<AccountRevert>)>,
}

/// The batches' bundles merged and checked: what the cache half writes and
/// the bundle half folds.
#[derive(Debug, Default)]
pub struct MergedBatches {
    accounts: AddressMap<Merged>,
}

fn debits(original: Option<&AccountInfo>, info: &AccountInfo) -> bool {
    let (balance, nonce) = original.map_or((U256::ZERO, 0), |o| (o.balance, o.nonce));
    info.balance < balance || info.nonce != nonce
}

/// Merges the batches' bundles, each built against the same parent with
/// [`crate::batch_state::BatchState`], refusing anything the fold cannot
/// model. An account two batches changed gets every batch's change added
/// together.
pub fn merge_batches(batches: Vec<BundleState>) -> Result<MergedBatches, FoldRefused> {
    let mut merged = MergedBatches {
        accounts: AddressMap::with_capacity_and_hasher(batches.iter().map(|b| b.state.len()).sum(), Default::default()),
    };
    for mut bundle in batches {
        if let Some(hash) = bundle.contracts.keys().next() {
            // A batch never deploys code; name an account if one carries it.
            let holder = bundle
                .state
                .iter()
                .find(|(_, a)| a.info.as_ref().is_some_and(|i| i.code_hash == *hash))
                .map_or(Address::ZERO, |(a, _)| *a);
            return refuse(FoldRefused::Code(holder));
        }
        let mut reverts: AddressMap<AccountRevert> = std::mem::take(&mut *bundle.reverts)
            .into_iter()
            .flatten()
            .collect();
        for (address, account) in bundle.state {
            if !account.storage.is_empty() {
                return refuse(FoldRefused::Storage(address));
            }
            if account.status.was_destroyed() {
                return refuse(FoldRefused::Destroyed(address));
            }
            let Some(info) = account.info.clone() else { return refuse(FoldRefused::Destroyed(address)) };
            if !info.is_empty_code_hash() || account.original_info.as_ref().is_some_and(|o| !o.is_empty_code_hash()) {
                return refuse(FoldRefused::Code(address));
            }
            let debited = debits(account.original_info.as_ref(), &info);
            let revert = reverts.remove(&address);
            match merged.accounts.entry(address) {
                Entry::Vacant(entry) => {
                    entry.insert(Merged {
                        original: account.original_info.clone(),
                        info,
                        debited,
                        single: Some((account, revert)),
                    });
                }
                Entry::Occupied(mut entry) => {
                    let m = entry.get_mut();
                    if m.original != account.original_info {
                        return refuse(FoldRefused::Originals(address));
                    }
                    if m.debited && debited {
                        return refuse(FoldRefused::TwoDebits(address));
                    }
                    let (balance, nonce) = m.original.as_ref().map_or((U256::ZERO, 0), |o| (o.balance, o.nonce));
                    // `info` = original + this batch's change, added onto
                    // what the earlier batches made of it.
                    m.info.balance = m.info.balance + info.balance - balance;
                    m.info.nonce += info.nonce - nonce;
                    m.debited |= debited;
                    m.single = None;
                }
            }
        }
    }
    Ok(merged)
}

impl MergedBatches {
    /// Accounts the batches changed.
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Whether the batches changed nothing.
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// An account's value after the batches, if they changed it.
    pub fn get(&self, address: &Address) -> Option<&AccountInfo> {
        self.accounts.get(address).map(|m| &m.info)
    }

    /// Every account the batches changed at its post-batch value: what the
    /// cache half writes into the executor's overlay.
    pub fn accounts(&self) -> impl Iterator<Item = (&Address, &AccountInfo)> {
        self.accounts.iter().map(|(address, m)| (address, &m.info))
    }
}

/// The status reth's accumulator gives an account loaded as `original`.
fn loaded_status(original: Option<&AccountInfo>) -> AccountStatus {
    match original {
        None => AccountStatus::LoadedNotExisting,
        Some(info) if info.is_empty() => AccountStatus::LoadedEmptyEIP161,
        Some(_) => AccountStatus::Loaded,
    }
}

/// The bundle account and revert of one transition from `original` (the
/// parent's) to `info`, as reth's accumulator makes them: the status from
/// the pair, never copied from either side.
fn transition(original: Option<AccountInfo>, info: AccountInfo) -> (BundleAccount, Option<AccountRevert>) {
    let previous_status = loaded_status(original.as_ref());
    let had_no_nonce_and_code = original.as_ref().is_none_or(|o| o.nonce == 0 && o.is_empty_code_hash());
    let t = TransitionAccount {
        info: Some(info),
        status: previous_status.on_changed(had_no_nonce_and_code),
        previous_info: original,
        previous_status,
        storage: Default::default(),
        storage_was_destroyed: false,
    };
    (t.present_bundle_account(), t.create_revert())
}

/// What [`fold_into`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FoldStats {
    /// Accounts folded in.
    pub accounts: usize,
    /// Of those, accounts the serial part had touched too.
    pub overlapped: usize,
}

/// Folds the merged batches into `block`, the bundle the serial part's
/// `finish` returned, after checking every account the two share (see the
/// module docs). Nothing is changed when it refuses.
pub fn fold_into(block: &mut BundleState, merged: MergedBatches) -> Result<FoldStats, FoldRefused> {
    // Checks first: the block is left as it was on a refusal.
    for (address, m) in &merged.accounts {
        if let Some(serial) = block.state.get(address) {
            if !serial.storage.is_empty() || serial.status.was_destroyed() {
                return refuse(FoldRefused::SerialStorage(*address));
            }
            if serial.original_info.as_ref() != Some(&m.info) {
                return refuse(FoldRefused::Stale(*address));
            }
        }
    }
    let mut stats = FoldStats { accounts: merged.accounts.len(), overlapped: 0 };
    let mut reverts = Vec::with_capacity(merged.accounts.len());
    // Accounts the block ended at the parent's value: out of the bundle, and
    // the serial part's revert to the post-batch value with them.
    let mut unchanged = Vec::new();
    block.state.reserve(merged.accounts.len());
    for (address, m) in merged.accounts {
        let (account, revert) = match (block.state.remove(&address), m.single) {
            (Some(serial), _) => {
                stats.overlapped += 1;
                block.state_size -= serial.size_hint();
                match serial.info {
                    Some(info) => transition(m.original, info),
                    // The serial part removed it (an empty account touched):
                    // nothing of it is left to fold.
                    None => {
                        block.state_size += serial.size_hint();
                        block.state.insert(address, serial);
                        continue;
                    }
                }
            }
            (None, Some(single)) => single,
            (None, None) => transition(m.original, m.info),
        };
        match revert {
            Some(revert) => {
                block.state_size += account.size_hint();
                block.state.insert(address, account);
                reverts.push((address, revert));
            }
            // reth's accumulator leaves an account whose block-level
            // transition has nothing to revert out of the bundle
            // (`apply_transitions_and_create_reverts`, `AccountRevert::is_empty`):
            // changed and changed back is not a change.
            None => unchanged.push(address),
        }
    }
    if !unchanged.is_empty() {
        unchanged.sort_unstable();
        if let Some(last) = block.reverts.last_mut() {
            last.retain(|(address, _)| unchanged.binary_search(address).is_err());
        }
        block.reverts_size = block.reverts.iter().map(Vec::len).sum();
    }
    crate::parallel_common::append_reverts(block, reverts);
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{batch_state::BatchState, n42_evm::N42EvmConfig};
    use alloy_consensus::{Signed, TxEip1559};
    use alloy_primitives::{Bytes, Signature, TxKind, B256};
    use evm2::evm::{CacheDB, EmptyDB};
    use n42_tx_types::N42TxEnvelope;
    use reth_evm::ConfigureEvm as _;
    use reth_execution_types::BlockState;
    use reth_primitives_traits::Recovered;
    use reth_trie::bundle_state::{AccountInfoRevert, StorageSlot};
    use std::sync::Arc;

    type Config = N42EvmConfig<n42_header::N42ChainSpec>;

    fn config() -> Config {
        let genesis: alloy_genesis::Genesis =
            serde_json::from_str(include_str!("../../../chainspec/res/genesis/n42_devnet.json")).expect("genesis");
        N42EvmConfig::new(Arc::new(n42_header::N42ChainSpec::from(reth_chainspec::ChainSpec::from_genesis(genesis))))
    }

    fn addr(i: u64) -> Address {
        Address::left_padding_from(&i.to_be_bytes())
    }

    const BENEFICIARY: u64 = 0xbe;
    const FUND: u64 = 1_000_000_000_000_000_000;

    fn parent() -> CacheDB<EmptyDB> {
        let mut db = CacheDB::new(EmptyDB::default());
        for i in 1..=40 {
            db.insert_account_info(&addr(i), AccountInfo { balance: U256::from(FUND), ..Default::default() });
        }
        db.insert_account_info(&addr(BENEFICIARY), AccountInfo { balance: U256::from(1u64), ..Default::default() });
        db
    }

    fn parent_info(address: &Address) -> Option<AccountInfo> {
        parent().cache.accounts.get(address).cloned().flatten()
    }

    fn tx(from: u64, nonce: u64, to: Address, value: u64) -> Recovered<N42TxEnvelope> {
        let tx = TxEip1559 {
            chain_id: 1143,
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 3,
            to: TxKind::Call(to),
            value: U256::from(value),
            input: Bytes::new(),
            ..Default::default()
        };
        let signed = Signed::new_unchecked(tx, Signature::test_signature(), B256::left_padding_from(&(from * 1000 + nonce).to_be_bytes()));
        Recovered::new_unchecked(N42TxEnvelope::from(reth_ethereum_primitives::TransactionSigned::from(signed)), addr(from))
    }

    fn env() -> reth_evm::EvmEnvFor<Config> {
        let header = n42_header::N42Header::from(alloy_consensus::Header {
            number: 5,
            timestamp: 1_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(7),
            beneficiary: addr(BENEFICIARY),
            ..Default::default()
        });
        config().evm_env(&header).expect("env")
    }

    /// Executes `txs` in order on one EVM over the parent, with `cache`
    /// written into its overlay first; the block accumulator's bundle and,
    /// if every change is modelled, a batch state's.
    fn execute(txs: &[Recovered<N42TxEnvelope>], cache: &[(Address, AccountInfo)]) -> (BundleState, BundleState) {
        let c = config();
        let mut evm = c.evm_with_env(parent(), env());
        for (address, info) in cache {
            evm.overlay_db_mut().insert_account_info(address, info.clone());
        }
        let (mut block, mut batch) = (BlockState::new(), BatchState::with_capacity(8));
        for t in txs {
            let t = t.clone().map(evm2::ethereum::TxEnvelope::from);
            let executed = evm.transact(&t).expect("the transaction executes").detach();
            for changes in executed.pending_state.account_changes() {
                block.commit_account_changes(changes, None);
            }
            batch.commit(&executed.pending_state).expect("a transfer");
            evm.state_mut().set_pending_state(executed.pending_state);
            evm.state_mut().commit_transaction();
        }
        (block.into_bundle(), batch.take_bundle())
    }

    fn sorted_reverts(bundle: &BundleState) -> Vec<Vec<(Address, String)>> {
        bundle
            .reverts
            .iter()
            .map(|block| {
                let mut v: Vec<_> = block.iter().map(|(a, r)| (*a, format!("{r:?}"))).collect();
                v.sort_by_key(|(a, _)| *a);
                v
            })
            .collect()
    }

    fn assert_same(ours: &BundleState, theirs: &BundleState) {
        assert_eq!(ours.state, theirs.state, "state");
        assert_eq!(sorted_reverts(ours), sorted_reverts(theirs), "reverts");
        assert_eq!(ours.state_size, theirs.state_size, "state size");
    }

    /// Two batches sharing a recipient and the beneficiary, then a serial
    /// tail spending from that recipient and from a batch sender, run over
    /// the cache half: the folded bundle is the sequential execution's, and
    /// reverting it by index gives back the parent.
    #[test]
    fn the_fold_equals_the_sequential_execution_and_reverts_to_the_parent() {
        let fresh = addr(0xf00d);
        let a = vec![tx(1, 0, addr(2), 100), tx(3, 0, fresh, 100_000_000_000_000_000)];
        let b = vec![tx(5, 0, addr(2), 300), tx(6, 0, addr(7), 400)];
        let tail = vec![tx(2, 0, addr(9), 50), tx(1, 1, addr(10), 60), tx(0xf00d, 0, addr(11), 10)];

        let sequential: Vec<_> = a.iter().chain(&b).chain(&tail).cloned().collect();
        let (reference, _) = execute(&sequential, &[]);

        let (_, bundle_a) = execute(&a, &[]);
        let (_, bundle_b) = execute(&b, &[]);
        let merged = merge_batches(vec![bundle_a, bundle_b]).expect("mergeable");
        let cache: Vec<_> = merged.accounts().map(|(a, i)| (*a, i.clone())).collect();
        let (mut serial, _) = execute(&tail, &cache);
        let stats = fold_into(&mut serial, merged).expect("foldable");
        assert!(stats.overlapped >= 3, "{stats:?}");
        assert_same(&serial, &reference);

        // Reverting the folded bundle by index gives back the parent.
        let touched: Vec<Address> = serial.state.keys().copied().collect();
        let mut reverted = serial;
        assert!(reverted.revert_latest());
        for address in touched {
            let now = reverted.state.get(&address).and_then(|a| a.info.clone());
            let want = parent_info(&address);
            assert!(
                now == want || (now.is_none() && reverted.state.get(&address).is_none()),
                "{address}: {now:?} after the revert, {want:?} in the parent"
            );
        }
    }

    fn info(balance: u64, nonce: u64) -> AccountInfo {
        AccountInfo { balance: U256::from(balance), nonce, ..Default::default() }
    }

    fn one_account_bundle(address: Address, original: Option<AccountInfo>, now: AccountInfo, status: AccountStatus) -> BundleState {
        let account = BundleAccount { info: Some(now), original_info: original.clone(), storage: Default::default(), status };
        let revert = AccountRevert {
            account: match original {
                Some(o) => AccountInfoRevert::RevertTo(o),
                None => AccountInfoRevert::DeleteIt,
            },
            storage: Default::default(),
            previous_status: loaded_status(None),
            wipe_storage: false,
        };
        let mut bundle = BundleState::default();
        bundle.state_size = account.size_hint();
        bundle.state.insert(address, account);
        bundle.reverts.push(vec![(address, revert)]);
        bundle
    }

    /// A batch created the account; the serial part changed it again, which
    /// on its own reads as `Changed` over an existing account. Folded, the
    /// status is recomputed from the parent's absence: created in memory,
    /// with a revert that deletes it.
    #[test]
    fn a_serial_change_over_a_batch_created_account_reads_as_created() {
        let x = addr(0xc4);
        let batch = one_account_bundle(x, None, info(500, 0), AccountStatus::InMemoryChange);
        let merged = merge_batches(vec![batch]).expect("mergeable");
        let mut serial = one_account_bundle(x, Some(info(500, 0)), info(300, 1), AccountStatus::Changed);
        fold_into(&mut serial, merged).expect("foldable");
        let account = &serial.state[&x];
        assert_eq!(account.status, AccountStatus::InMemoryChange);
        assert_eq!(account.original_info, None);
        assert_eq!(account.info, Some(info(300, 1)));
        assert_eq!(serial.reverts.len(), 1);
        let (address, revert) = &serial.reverts[0][0];
        assert_eq!((*address, &revert.account), (x, &AccountInfoRevert::DeleteIt));
        assert_eq!(serial.reverts[0].len(), 1, "the serial revert to the post-batch value is dropped");
    }

    /// The batches credited the account, the serial part took exactly that
    /// back: its final info is the parent's. reth's accumulator makes nothing
    /// of a block-level transition with nothing to revert (an account changed
    /// and changed back is left out of the bundle, with no revert), so the
    /// fold must do the same, and must drop the serial part's revert to the
    /// post-batch value rather than keep a revert that would "restore" 1,500.
    #[test]
    fn a_serial_change_back_to_the_parent_value_folds_as_reths_accumulator_does() {
        let x = addr(0xc5);
        let y = addr(0xc8);
        let mut batch = one_account_bundle(x, Some(info(1_000, 3)), info(1_500, 3), AccountStatus::Changed);
        // A second account the batches changed and nothing else touched.
        let other = one_account_bundle(y, Some(info(10, 0)), info(20, 0), AccountStatus::Changed);
        batch.state.extend(other.state);
        batch.reverts[0].extend(other.reverts[0].clone());
        let merged = merge_batches(vec![batch]).expect("mergeable");
        let mut serial = one_account_bundle(x, Some(info(1_500, 3)), info(1_000, 3), AccountStatus::Changed);
        fold_into(&mut serial, merged).expect("foldable");
        assert!(!serial.state.contains_key(&x), "back at the parent's value: not in the bundle");
        assert!(serial.reverts.iter().flatten().all(|(a, _)| *a != x), "and no revert for it");
        assert_eq!(serial.reverts[0].len(), 1);
        assert_eq!(serial.reverts[0][0].0, y);
        // The pair's own transition says the same: nothing to revert.
        assert!(transition(Some(info(1_000, 3)), info(1_000, 3)).1.is_none());
        // Changed back only in balance but not in nonce is a change.
        assert!(transition(Some(info(1_000, 3)), info(1_000, 4)).1.is_some());
    }

    /// The serial part read a batch account at the parent's value -- a
    /// withdrawal recipient the cache half missed: refused, the block left
    /// as it was, the counter up.
    #[test]
    fn an_account_the_cache_half_missed_is_refused() {
        let x = addr(0xc6);
        let batch = one_account_bundle(x, Some(info(1_000, 0)), info(1_200, 0), AccountStatus::Changed);
        let merged = merge_batches(vec![batch]).expect("mergeable");
        let mut serial = one_account_bundle(x, Some(info(1_000, 0)), info(1_100, 0), AccountStatus::Changed);
        let before = serial.clone();
        let count = refused_count();
        assert_eq!(fold_into(&mut serial, merged), Err(FoldRefused::Stale(x)));
        assert_eq!(serial, before);
        assert!(refused_count() > count);
    }

    /// The merge's own refusals: storage, two debits, different originals.
    #[test]
    fn the_merge_refuses_what_it_cannot_model() {
        let x = addr(0xc7);
        let mut with_storage = one_account_bundle(x, Some(info(1, 0)), info(2, 0), AccountStatus::Changed);
        with_storage.state.get_mut(&x).expect("x").storage.insert(U256::from(1), StorageSlot::new_changed(U256::ZERO, U256::from(1)));
        assert_eq!(merge_batches(vec![with_storage]).unwrap_err(), FoldRefused::Storage(x));

        let debit = || one_account_bundle(x, Some(info(10, 0)), info(5, 1), AccountStatus::Changed);
        assert_eq!(merge_batches(vec![debit(), debit()]).unwrap_err(), FoldRefused::TwoDebits(x));

        let a = one_account_bundle(x, Some(info(10, 0)), info(12, 0), AccountStatus::Changed);
        let b = one_account_bundle(x, Some(info(11, 0)), info(13, 0), AccountStatus::Changed);
        assert_eq!(merge_batches(vec![a, b]).unwrap_err(), FoldRefused::Originals(x));

        // A debit and a credit merge, the credit added onto the debit.
        let a = one_account_bundle(x, Some(info(10, 0)), info(5, 1), AccountStatus::Changed);
        let b = one_account_bundle(x, Some(info(10, 0)), info(17, 0), AccountStatus::Changed);
        let merged = merge_batches(vec![a, b]).expect("mergeable");
        assert_eq!(merged.get(&x), Some(&info(12, 1)));
    }
}
