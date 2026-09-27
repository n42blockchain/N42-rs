// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `N42_OUTPUT_SHARDS` (`n42_engine_types::output_shards`): the block's output
//! kept in address-range shards, with the executor's own changes laid over it
//! and merged behind the seal, equals the bundle the graft leaves -- through
//! the crate's public surface only, as the builder uses it.
#![allow(missing_docs, unreachable_pub, unused_crate_dependencies)]

use alloy_primitives::{Address, U256};
use n42_engine_types::output_shards::{any_destroyed, hashed_post_state_of, output_shards, FrozenShards, OutputShards};
use n42_engine_types::parallel_transfer::{append_reverts, graft_bundles_folded, install_staged, GraftFold, StagedGraft};
use reth_revm::db::State;
use revm::database::BundleState;
use revm::state::{AccountStatus, EvmState};
use revm::Database as _;
use revm::database::{states::bundle_state::BundleRetention, CacheDB, EmptyDB};
use revm::state::AccountInfo;

const BATCHES: u64 = 16;
const PER_BATCH: u64 = 500;
/// Shared recipients every batch pays (the repeated accounts).
const SHARED: u64 = 64;

/// An address whose top bytes spread over every shard.
fn addr(i: u64) -> Address {
    let hash = alloy_primitives::keccak256(i.to_be_bytes());
    Address::from_slice(&hash[12..])
}

fn beneficiary() -> Address {
    addr(1)
}
/// A pre-execution system call's account, also paid by a batch.
fn system() -> Address {
    addr(2)
}
/// A withdrawal's recipient the batches also touched, and one they did not.
fn withdrawn() -> (Address, Address) {
    (addr(1_000_000), addr(3))
}

fn parent() -> CacheDB<EmptyDB> {
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(beneficiary(), AccountInfo { balance: U256::from(7), ..Default::default() });
    db.insert_account_info(system(), AccountInfo { balance: U256::from(11), ..Default::default() });
    for b in 0..BATCHES {
        for k in 0..PER_BATCH / 2 {
            let sender = addr(1_000_000 + b * PER_BATCH + k);
            db.insert_account_info(sender, AccountInfo { balance: U256::from(10u128.pow(21)), nonce: 3, ..Default::default() });
        }
    }
    db
}

/// Sixteen batches of 500 accounts executed against the parent: 250
/// senders each paying a fresh recipient or one of the shared ones, the
/// beneficiary credited by every batch, and batch 3 paying the system
/// account too.
fn batch_bundles(db: &CacheDB<EmptyDB>) -> Vec<BundleState> {
    (0..BATCHES)
        .map(|b| {
            let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
            for k in 0..PER_BATCH / 2 {
                let sender = addr(1_000_000 + b * PER_BATCH + k);
                let to = if k % 4 == 0 { addr(5_000_000 + k % SHARED) } else { addr(9_000_000 + b * PER_BATCH + k) };
                let value = U256::from(1_000 + k);
                let mut changes: EvmState = Default::default();
                for (address, delta, nonce) in [(sender, None, 1u64), (to, Some(value), 0), (beneficiary(), Some(U256::from(21)), 0)] {
                    let loaded = state.basic(address).expect("an in-memory database");
                    let existed = loaded.is_some();
                    let mut info = loaded.unwrap_or_default();
                    match delta {
                        Some(add) => info.balance += add,
                        None => info.balance -= value,
                    }
                    info.nonce += nonce;
                    let mut account = revm::state::Account::from(info);
                    account.status = AccountStatus::Touched;
                    if !existed {
                        account.status |= AccountStatus::Created;
                    }
                    changes.insert(address, account);
                }
                revm::DatabaseCommit::commit(&mut state, changes);
            }
            if b == 3 {
                let mut info = state.basic(system()).expect("an in-memory database").unwrap_or_default();
                info.balance += U256::from(5);
                let mut account = revm::state::Account::from(info);
                account.status = AccountStatus::Touched;
                revm::DatabaseCommit::commit(&mut state, EvmState::from_iter([(system(), account)]));
            }
            state.merge_transitions(BundleRetention::Reverts);
            state.take_bundle()
        })
        .collect()
}

/// The block's state as the builder opens it: a pre-execution system
/// call's change already in its cache.
fn block_state(db: &CacheDB<EmptyDB>) -> State<CacheDB<EmptyDB>> {
    let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
    let mut info = state.basic(system()).expect("an in-memory database").unwrap_or_default();
    info.nonce += 1;
    let mut account = revm::state::Account::from(info);
    account.status = AccountStatus::Touched;
    revm::DatabaseCommit::commit(&mut state, EvmState::from_iter([(system(), account)]));
    state
}

/// What the builder does after the graft: the withdrawal recipients put
/// back into the cache (`keep_cache` off), the fee credit, the
/// withdrawals, then the merge and the take.
fn finish(
    state: &mut State<CacheDB<EmptyDB>>,
    fees: U256,
    keep_cache: bool,
    grafted: impl Fn(&State<CacheDB<EmptyDB>>, &Address) -> Option<AccountInfo>,
) -> BundleState {
    let (w1, w2) = withdrawn();
    finish_paying(state, fees, keep_cache, grafted, &[(w1, 5), (w2, 3)])
}

/// [`finish`] with the block's withdrawals paying `withdrawals`.
fn finish_paying(
    state: &mut State<CacheDB<EmptyDB>>,
    fees: U256,
    keep_cache: bool,
    grafted: impl Fn(&State<CacheDB<EmptyDB>>, &Address) -> Option<AccountInfo>,
    withdrawals: &[(Address, u64)],
) -> BundleState {
    if !keep_cache {
        for &(address, _) in withdrawals {
            if let Some(info) = grafted(state, &address) {
                state.insert_account(address, info);
            }
        }
    }
    let current = state.basic(beneficiary()).expect("an in-memory database");
    let existed = current.is_some();
    let mut info = current.unwrap_or_default();
    info.balance = info.balance.saturating_add(fees);
    let mut account = revm::state::Account::from(info);
    account.status = AccountStatus::Touched;
    if !existed {
        account.status |= AccountStatus::Created;
    }
    revm::DatabaseCommit::commit(state, EvmState::from_iter([(beneficiary(), account)]));
    // The withdrawals' credit, as the executor's finish makes it: each
    // recipient read through the block's state and committed.
    for &(address, amount) in withdrawals {
        let current = state.basic(address).expect("an in-memory database");
        let existed = current.is_some();
        let mut info = current.unwrap_or_default();
        info.balance += U256::from(amount);
        let mut account = revm::state::Account::from(info);
        account.status = AccountStatus::Touched;
        if !existed {
            account.status |= AccountStatus::Created;
        }
        revm::DatabaseCommit::commit(state, EvmState::from_iter([(address, account)]));
    }
    state.merge_transitions(BundleRetention::Reverts);
    state.take_bundle()
}

fn from_bundle(state: &State<CacheDB<EmptyDB>>, address: &Address) -> Option<AccountInfo> {
    state.bundle_state.state.get(address).and_then(|account| account.info.clone())
}

/// The direct graft (the default fold), then the builder's finish.
fn direct(db: &CacheDB<EmptyDB>, bundles: Vec<BundleState>, keep_cache: bool) -> (BundleState, State<CacheDB<EmptyDB>>) {
    let mut state = block_state(db);
    let graft = graft_bundles_folded(&mut state, bundles, beneficiary(), keep_cache, GraftFold::Direct, None)
        .expect("an in-memory database");
    let mut bundle = finish(&mut state, graft.beneficiary_delta, keep_cache, from_bundle);
    append_reverts(&mut bundle, graft.reverts);
    (bundle, state)
}

/// Both modes: the v4 shard maps and the index over the batches' maps
/// (`N42_OUTPUT_INDEX`).
const MODES: [bool; 2] = [false, true];

fn shards_of(bundles: Vec<BundleState>, count: usize, index: bool) -> FrozenShards {
    let shards = OutputShards::with_index(beneficiary(), (BATCHES * PER_BATCH) as usize, count, index);
    for bundle in bundles {
        shards.add(bundle);
    }
    shards.freeze()
}

/// The sharded path the builder takes when it seals early: no graft, the
/// cached accounts as deltas, the finish on the block's own state; the
/// shards and the executor's residual, before any merge.
fn sharded_parts(db: &CacheDB<EmptyDB>, mut shards: FrozenShards) -> (FrozenShards, BundleState) {
    let mut state = block_state(db);
    assert!(state.bundle_state.state.is_empty());
    shards.take_cached(&mut state);
    let fees = shards.beneficiary_delta();
    let residual = finish(&mut state, fees, false, |_, address| shards.get(address).and_then(|a| a.info.clone()));
    (shards, residual)
}

/// [`sharded_parts`] and the merge behind the seal.
fn sharded(db: &CacheDB<EmptyDB>, shards: FrozenShards) -> BundleState {
    let (shards, residual) = sharded_parts(db, shards);
    shards.merged_with(residual)
}

fn assert_same(label: &str, left: &BundleState, right: &BundleState) {
    assert_eq!(left.state.len(), right.state.len(), "{label}: accounts");
    for (address, account) in &left.state {
        assert_eq!(Some(account), right.state.get(address), "{label}: account {address}");
    }
    assert_eq!(left.contracts, right.contracts, "{label}: contracts");
    assert_eq!(left.reverts, right.reverts, "{label}: reverts");
    assert_eq!(left.state_size, right.state_size, "{label}: state size");
    assert_eq!(left.reverts_size, right.reverts_size, "{label}: reverts size");
}

#[test]
fn the_sharded_output_equals_the_direct_graft() {
    let db = parent();
    let bundles = batch_bundles(&db);
    let (expected, _) = direct(&db, bundles.clone(), false);
    // Accounts several batches touched really are in the block.
    assert!(expected.state.contains_key(&addr(5_000_000)));
    assert!(expected.state.contains_key(&system()));
    for count in [1, 16, 64] {
        for index in MODES {
            let got = sharded(&db, shards_of(bundles.clone(), count, index));
            assert_same(&format!("{count} shards, index {index}"), &expected, &got);
        }
    }
}

#[test]
fn the_sharded_output_equals_the_staged_graft() {
    let db = parent();
    let bundles = batch_bundles(&db);
    let mut state = block_state(&db);
    let mut staged = StagedGraft::new(beneficiary(), (BATCHES * PER_BATCH) as usize);
    for bundle in bundles.clone() {
        staged.add(bundle);
    }
    let graft = install_staged(&mut state, staged, false).expect("an in-memory database");
    let mut expected = finish(&mut state, graft.beneficiary_delta, false, from_bundle);
    append_reverts(&mut expected, graft.reverts);
    for index in MODES {
        let got = sharded(&db, shards_of(bundles.clone(), 16, index));
        assert_same(&format!("staged, index {index}"), &expected, &got);
    }
}

#[test]
fn batches_writing_at_once_give_the_same_output() {
    let db = parent();
    let bundles = batch_bundles(&db);
    let expected = sharded(&db, shards_of(bundles.clone(), 16, false));
    for index in MODES {
        let shards = OutputShards::with_index(beneficiary(), (BATCHES * PER_BATCH) as usize, 16, index);
        std::thread::scope(|scope| {
            for bundle in bundles.clone() {
                let shards = &shards;
                scope.spawn(move || shards.add(bundle));
            }
        });
        let got = sharded(&db, shards.freeze());
        assert_same(&format!("concurrent, index {index}"), &expected, &got);
    }
}

#[test]
fn the_fallback_with_the_cache_kept_equals_the_direct_graft() {
    let db = parent();
    let bundles = batch_bundles(&db);
    let (expected, expected_state) = direct(&db, bundles.clone(), true);
    for index in MODES {
        let mut state = block_state(&db);
        let staged = shards_of(bundles.clone(), 16, index).into_staged();
        let graft = install_staged(&mut state, staged, true).expect("an in-memory database");
        let mut got = finish(&mut state, graft.beneficiary_delta, true, from_bundle);
        append_reverts(&mut got, graft.reverts);
        assert_same(&format!("fallback, index {index}"), &expected, &got);
        assert_eq!(expected_state.cache.accounts.len(), state.cache.accounts.len());
        for (address, account) in &expected_state.cache.accounts {
            assert_eq!(Some(&account.account), state.cache.accounts.get(address).map(|a| &a.account), "cache {address}");
        }
    }
}

#[test]
fn a_read_probes_the_owning_shard() {
    let db = parent();
    let bundles = batch_bundles(&db);
    let (expected, _) = direct(&db, bundles.clone(), false);
    for index in MODES {
        let shards = shards_of(bundles.clone(), 64, index);
        let (w1, _) = withdrawn();
        for (address, account) in &expected.state {
            if *address == beneficiary() || *address == system() || *address == w1 || *address == withdrawn().1 {
                continue;
            }
            assert_eq!(shards.get(address).map(|a| &a.info), Some(&account.info), "{address}, index {index}");
        }
        assert!(shards.get(&beneficiary()).is_none());
        assert!(shards.get(&addr(77_777_777)).is_none());
    }
    assert_eq!(output_shards_off_by_default(), 0);
}

fn output_shards_off_by_default() -> usize {
    if std::env::var("N42_OUTPUT_SHARDS").is_ok() {
        0
    } else {
        output_shards()
    }
}

#[test]
fn the_fold_does_not_depend_on_the_order_the_batches_end() {
    let db = parent();
    let bundles = batch_bundles(&db);
    let (expected, _) = direct(&db, bundles.clone(), false);
    for count in [1, 16, 64] {
        for index in MODES {
            let mut reversed = bundles.clone();
            reversed.reverse();
            let got = sharded(&db, shards_of(reversed, count, index));
            assert_same(&format!("{count} shards, reversed, index {index}"), &expected, &got);
        }
    }
}

#[test]
fn the_roots_from_the_shards_equal_the_roots_from_the_merged_bundle() {
    use reth_trie::{HashedPostState, KeccakKeyHasher};
    let db = parent();
    let bundles = batch_bundles(&db);
    let (expected, _) = direct(&db, bundles.clone(), false);
    for (count, index) in [1, 16, 64].into_iter().flat_map(|count| MODES.map(|index| (count, index))) {
        let (shards, residual) = sharded_parts(&db, shards_of(bundles.clone(), count, index));
        let merged = shards.merged(&residual);
        assert_same(&format!("{count} shards, merged"), &expected, &merged);
        // The withdrawal to an account the batches also paid.
        let overlaps = shards.overlaps(&residual);
        assert!(overlaps.iter().any(|(address, _)| *address == withdrawn().0), "{count} shards: an overlap");
        let view = shards.view(&residual, &overlaps);
        assert_eq!(view.len(), merged.state.len(), "{count} shards: one entry an account");
        for (address, account) in &view {
            assert_eq!(merged.state.get(*address), Some(*account), "{count} shards: {address}");
        }
        assert!(!any_destroyed(&view));
        for prague in [false, true] {
            assert_eq!(
                n42_qmdb_reth::sorted_operations_from_accounts(&view, prague),
                n42_qmdb_reth::sorted_operations_from_execution(&merged, prague),
                "{count} shards: QMDB operations, prague {prague}"
            );
        }
        let from_merged = HashedPostState::from_bundle_state::<KeccakKeyHasher>(merged.state.iter());
        assert_eq!(hashed_post_state_of(&view), from_merged, "{count} shards: hashed post-state");
    }
}

/// Index mode against the direct graft and the v4 shards, with conflicts
/// present (recipients every batch pays), a cached pre-execution account
/// (taken out as a delta), the withdrawals and the beneficiary: every read,
/// written or not, the roots' inputs, the hashed post-state and the merged
/// bundle.
#[test]
fn the_index_reads_roots_and_merge_equal_the_graft() {
    use reth_trie::{HashedPostState, KeccakKeyHasher};
    let db = parent();
    let bundles = batch_bundles(&db);
    let (expected, _) = direct(&db, bundles.clone(), false);
    for count in [1, 16, 64] {
        let v4 = shards_of(bundles.clone(), count, false);
        let indexed = shards_of(bundles.clone(), count, true);
        assert!(indexed.is_indexed() && !v4.is_indexed());
        assert_eq!(indexed.shard_count(), v4.shard_count());
        // The 16 shared recipients every batch pays (the system account is
        // paid by one batch only).
        assert_eq!(indexed.index_conflicts(), 16, "{count} shards: conflicts");
        assert_eq!(indexed.accounts(), v4.accounts(), "{count} shards: accounts");
        assert_eq!(indexed.beneficiary_delta(), v4.beneficiary_delta());
        // Every address the batches wrote, then a set they did not.
        let none = BundleState::default();
        let written: Vec<Address> = v4.view(&none, &[]).into_iter().map(|(address, _)| *address).collect();
        assert_eq!(written.len(), v4.accounts());
        for address in &written {
            assert_eq!(indexed.get(address), v4.get(address), "{count} shards: read {address}");
        }
        for i in 0..2_000u64 {
            let address = addr(70_000_000 + i);
            assert!(indexed.get(&address).is_none() && v4.get(&address).is_none());
        }
        assert!(indexed.get(&beneficiary()).is_none());
        let (v4, v4_residual) = sharded_parts(&db, v4);
        let (indexed, residual) = sharded_parts(&db, indexed);
        assert_eq!(residual, v4_residual, "{count} shards: residual");
        assert!(indexed.get(&system()).is_none(), "{count} shards: the cached account taken out");
        for address in &written {
            assert_eq!(indexed.get(address), v4.get(address), "{count} shards: read {address} after the cache");
        }
        let merged = indexed.merged(&residual);
        assert_same(&format!("{count} shards, index merged"), &expected, &merged);
        let overlaps = indexed.overlaps(&residual);
        let view = indexed.view(&residual, &overlaps);
        assert_eq!(view.len(), merged.state.len());
        let v4_overlaps = v4.overlaps(&residual);
        let v4_view = v4.view(&residual, &v4_overlaps);
        for prague in [false, true] {
            let ops = n42_qmdb_reth::sorted_operations_from_accounts(&view, prague);
            assert_eq!(ops, n42_qmdb_reth::sorted_operations_from_execution(&merged, prague), "{count}: ops");
            assert_eq!(ops, n42_qmdb_reth::sorted_operations_from_accounts(&v4_view, prague), "{count}: v4 ops");
        }
        let from_merged = HashedPostState::from_bundle_state::<KeccakKeyHasher>(merged.state.iter());
        assert_eq!(hashed_post_state_of(&view), from_merged, "{count} shards: hashed post-state");
    }
}

/// The paths the builder takes on one block, with the withdrawals paying the
/// accounts the index handles apart: a conflict (a recipient every batch
/// paid, summed out of the batches' maps), the beneficiary (moved out of the
/// batches in `add`), an account one batch wrote, the pre-execution cached
/// account, and one nobody touched. The early seal (`take_cached`, the
/// finish on the block's own state), the fallback with the cache dropped
/// and with it kept (`into_staged` + `install_staged`, the tenure's first
/// build and any build that did not seal early), and a chained child's read
/// of the result (the residual over the shards, as `opener_on_sealed_parent`
/// lays them) all equal the direct graft, in both modes.
#[test]
fn every_path_with_withdrawals_to_conflicts_and_the_beneficiary_equals_the_direct_graft() {
    let db = parent();
    let bundles = batch_bundles(&db);
    let paid = [(addr(5_000_000), 5u64), (beneficiary(), 3), (addr(9_000_001), 2), (system(), 1), (addr(88_000_000), 4)];
    let direct_paying = |keep_cache: bool| {
        let mut state = block_state(&db);
        let graft = graft_bundles_folded(&mut state, bundles.clone(), beneficiary(), keep_cache, GraftFold::Direct, None)
            .expect("an in-memory database");
        let mut bundle = finish_paying(&mut state, graft.beneficiary_delta, keep_cache, from_bundle, &paid);
        append_reverts(&mut bundle, graft.reverts);
        bundle
    };
    let expected = direct_paying(false);
    assert!(expected.state.contains_key(&addr(9_000_001)) && expected.state.contains_key(&addr(88_000_000)));
    assert_same("direct, cache kept", &expected, &direct_paying(true));
    for index in MODES {
        if index {
            assert!(shards_of(bundles.clone(), 16, index).index_conflicts() > 0, "the shared recipients are conflicts");
        }
        // The early seal.
        let mut state = block_state(&db);
        let mut early = shards_of(bundles.clone(), 16, index);
        early.take_cached(&mut state);
        let fees = early.beneficiary_delta();
        let residual =
            finish_paying(&mut state, fees, false, |_, address| early.get(address).and_then(|a| a.info.clone()), &paid);
        // A chained child's reads: the residual first, then the shards.
        for (address, account) in &expected.state {
            let read = match residual.state.get(address) {
                Some(account) => account.info.clone(),
                None => early.get(address).and_then(|a| a.info.clone()),
            };
            assert_eq!(read, account.info, "index {index}: a child's read of {address}");
        }
        assert_same(&format!("early seal, index {index}"), &expected, &early.merged(&residual));
        // The fallback, the cache dropped and kept.
        for keep_cache in [false, true] {
            let mut state = block_state(&db);
            let staged = shards_of(bundles.clone(), 16, index).into_staged();
            let graft = install_staged(&mut state, staged, keep_cache).expect("an in-memory database");
            let mut got = finish_paying(&mut state, graft.beneficiary_delta, keep_cache, from_bundle, &paid);
            append_reverts(&mut got, graft.reverts);
            assert_same(&format!("fallback, index {index}, cache kept {keep_cache}"), &expected, &got);
        }
    }
}
