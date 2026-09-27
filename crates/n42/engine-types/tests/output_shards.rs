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
    if !keep_cache {
        for address in [w1, w2] {
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
    for (address, amount) in [(w1, 5u64), (w2, 3u64)] {
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

fn shards_of(bundles: Vec<BundleState>, count: usize) -> FrozenShards {
    let shards = OutputShards::new(beneficiary(), (BATCHES * PER_BATCH) as usize, count);
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
        let got = sharded(&db, shards_of(bundles.clone(), count));
        assert_same(&format!("{count} shards"), &expected, &got);
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
    let got = sharded(&db, shards_of(bundles, 16));
    assert_same("staged", &expected, &got);
}

#[test]
fn batches_writing_at_once_give_the_same_output() {
    let db = parent();
    let bundles = batch_bundles(&db);
    let expected = sharded(&db, shards_of(bundles.clone(), 16));
    let shards = OutputShards::new(beneficiary(), (BATCHES * PER_BATCH) as usize, 16);
    std::thread::scope(|scope| {
        for bundle in bundles {
            let shards = &shards;
            scope.spawn(move || shards.add(bundle));
        }
    });
    let got = sharded(&db, shards.freeze());
    assert_same("concurrent", &expected, &got);
}

#[test]
fn the_fallback_with_the_cache_kept_equals_the_direct_graft() {
    let db = parent();
    let bundles = batch_bundles(&db);
    let (expected, expected_state) = direct(&db, bundles.clone(), true);
    let mut state = block_state(&db);
    let graft = install_staged(&mut state, shards_of(bundles, 16).into_staged(), true).expect("an in-memory database");
    let mut got = finish(&mut state, graft.beneficiary_delta, true, from_bundle);
    append_reverts(&mut got, graft.reverts);
    assert_same("fallback", &expected, &got);
    assert_eq!(expected_state.cache.accounts.len(), state.cache.accounts.len());
    for (address, account) in &expected_state.cache.accounts {
        assert_eq!(Some(&account.account), state.cache.accounts.get(address).map(|a| &a.account), "cache {address}");
    }
}

#[test]
fn a_read_probes_the_owning_shard() {
    let db = parent();
    let bundles = batch_bundles(&db);
    let (expected, _) = direct(&db, bundles.clone(), false);
    let shards = shards_of(bundles, 64);
    let (w1, _) = withdrawn();
    for (address, account) in &expected.state {
        if *address == beneficiary() || *address == system() || *address == w1 || *address == withdrawn().1 {
            continue;
        }
        assert_eq!(shards.get(address).map(|a| &a.info), Some(&account.info), "{address}");
    }
    assert!(shards.get(&beneficiary()).is_none());
    assert!(shards.get(&addr(77_777_777)).is_none());
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
        let mut reversed = bundles.clone();
        reversed.reverse();
        let got = sharded(&db, shards_of(reversed, count));
        assert_same(&format!("{count} shards, reversed"), &expected, &got);
    }
}

#[test]
fn the_roots_from_the_shards_equal_the_roots_from_the_merged_bundle() {
    use reth_trie::{HashedPostState, KeccakKeyHasher};
    let db = parent();
    let bundles = batch_bundles(&db);
    let (expected, _) = direct(&db, bundles.clone(), false);
    for count in [1, 16, 64] {
        let (shards, residual) = sharded_parts(&db, shards_of(bundles.clone(), count));
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
