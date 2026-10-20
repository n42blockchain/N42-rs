// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An own block's post-state handed out without its merged account map
//! (`N42_MERGE_ELIDE=1`, `docs/MERGE_ELISION_DESIGN.md`).
//!
//! The leader's merger thread used to clone every account of the frozen output
//! shards (~147,000 a block, ~75 ms on one background thread) into the one
//! `BundleState` the block's execution output carries. With elision the output
//! carries a thin bundle instead: the residual's accounts (the executor's own
//! changes, each laid over the shard's account at its address exactly as the
//! merge lays it), every contract, the block's own reverts (the rest are owed
//! through `n42_deferred_reverts`) and the merged map's `state_size`. The
//! shards are registered here under the output's address, and every point
//! reader of the output's accounts asks [`account`] with the output's entry
//! ([`shards_of`]): the thin bundle first, then the shards -- what the merged
//! map holds at that key.
//!
//! An entry holds its output weakly: it lives as long as anyone else holds the
//! output (the tree's in-memory block, the build store, the kept layers), so it
//! leaves with the block. A dead entry is never answered (an address can be
//! reused once its output is freed) and is dropped by the next [`sweep`],
//! outside the lock: the last holder of the shards frees them there.

use std::any::Any;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

use alloy_primitives::Address;
use revm_database::{BundleAccount, BundleState};

/// A block's frozen output shards, as the registry reads them: the accounts
/// the batches wrote, before the residual is laid over them.
pub trait ShardedState: Send + Sync + 'static {
    /// The account the shards hold at `address`.
    fn shard_account(&self, address: &Address) -> Option<&BundleAccount>;
    /// The accounts the shards hold.
    fn shard_accounts(&self) -> usize;
    /// Every account the shards hold, each address once.
    fn for_each_shard_account(&self, f: &mut dyn FnMut(&Address, &BundleAccount));
}

/// A registered shard set.
pub type Shards = Arc<dyn ShardedState>;

struct Entry {
    key: usize,
    owner: Weak<dyn Any + Send + Sync>,
    shards: Shards,
}

impl Entry {
    fn answers(&self, key: usize) -> bool {
        self.key == key && self.owner.strong_count() > 0
    }
}

static ENTRIES: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
/// The registry's length, so the readers of an unregistered output (every
/// read with the switch off) skip the lock.
static LEN: AtomicUsize = AtomicUsize::new(0);

fn key_of<T>(output: *const T) -> usize {
    output.cast::<()>() as usize
}

/// Registers `shards` as the post-state under `output`'s thin bundle. Done
/// before the output is handed to anyone.
pub fn register<T: Send + Sync + 'static>(output: &Arc<T>, shards: Shards) {
    let owner: Arc<dyn Any + Send + Sync> = output.clone();
    let entry = Entry { key: key_of(Arc::as_ptr(output)), owner: Arc::downgrade(&owner), shards };
    drop(owner);
    let mut entries = ENTRIES.lock().unwrap_or_else(PoisonError::into_inner);
    entries.push(entry);
    LEN.store(entries.len(), Ordering::Relaxed);
}

/// The shards under `output`'s bundle, when it was handed out elided.
#[inline]
pub fn shards_of<T>(output: &T) -> Option<Shards> {
    if LEN.load(Ordering::Relaxed) == 0 {
        return None;
    }
    let key = key_of(std::ptr::from_ref(output));
    let entries = ENTRIES.lock().unwrap_or_else(PoisonError::into_inner);
    entries.iter().rev().find(|entry| entry.answers(key)).map(|entry| Arc::clone(&entry.shards))
}

/// Whether `output` was handed out elided.
pub fn is_elided<T>(output: &T) -> bool {
    shards_of(output).is_some()
}

/// Drops the entries whose output nobody holds any more (their shards freed
/// here, outside the lock) and returns how many remain.
pub fn sweep() -> usize {
    let dead: Vec<Entry> = {
        let mut entries = ENTRIES.lock().unwrap_or_else(PoisonError::into_inner);
        let dead = entries.extract_if(.., |entry| entry.owner.strong_count() == 0).collect();
        LEN.store(entries.len(), Ordering::Relaxed);
        dead
    };
    drop(dead);
    LEN.load(Ordering::Relaxed)
}

/// The entries the registry holds now (dead ones until the next [`sweep`]).
pub fn entries() -> usize {
    LEN.load(Ordering::Relaxed)
}

/// The account at `address` in a block's post-state: its thin bundle's, else
/// its shards' -- what the merged map holds at that key. With no shards it is
/// the bundle's lookup.
#[inline]
pub fn account<'a>(shards: Option<&'a dyn ShardedState>, thin: &'a BundleState, address: &Address) -> Option<&'a BundleAccount> {
    match thin.state.get(address) {
        Some(account) => Some(account),
        None => shards?.shard_account(address),
    }
}

/// The accounts of a block's post-state: the merged map's length.
pub fn accounts(shards: Option<&dyn ShardedState>, thin: &BundleState) -> usize {
    let Some(shards) = shards else { return thin.state.len() };
    let overlaps = thin.state.keys().filter(|address| shards.shard_account(address).is_some()).count();
    shards.shard_accounts() + thin.state.len() - overlaps
}

/// Every account of a block's post-state, each address once: the thin
/// bundle's, then the shards' it does not hold.
pub fn for_each_account(
    shards: Option<&dyn ShardedState>,
    thin: &BundleState,
    f: &mut dyn FnMut(&Address, &BundleAccount),
) {
    for (address, account) in &thin.state {
        f(address, account);
    }
    if let Some(shards) = shards {
        shards.for_each_shard_account(&mut |address, account| {
            if !thin.state.contains_key(address) {
                f(address, account);
            }
        });
    }
}

/// `bundle` -- a copy of an elided output's thin bundle -- with the shards'
/// accounts put in: the merged bundle's account map (its size, contracts and
/// reverts are the thin bundle's already). For the whole-map readers, which
/// the switch refuses to run beside, should one run anyway.
pub fn materialize(shards: &dyn ShardedState, bundle: &mut BundleState) {
    bundle.state.reserve(shards.shard_accounts());
    let state = &mut bundle.state;
    shards.for_each_shard_account(&mut |address, account| {
        if !state.contains_key(address) {
            state.insert(*address, account.clone());
        }
    });
}

/// `output`'s bundle with its shards' accounts put in, when it was handed out
/// elided; `None` when its bundle is whole as it stands. Also refuses
/// elision from now on ([`refuse`], with `reader` as the reason): the caller
/// is a reader of the whole map, and every such copy costs the merge.
pub fn materialized<T>(output: &T, thin: &BundleState, reader: &'static str) -> Option<BundleState> {
    let shards = shards_of(output)?;
    refuse(reader);
    let mut bundle = thin.clone();
    materialize(&*shards, &mut bundle);
    Some(bundle)
}

static REFUSED: OnceLock<&'static str> = OnceLock::new();

/// Refuses elision from now on: a reader of the whole merged map is running
/// (`reason` names it). Said once at WARN.
pub fn refuse(reason: &'static str) {
    if REFUSED.set(reason).is_ok() {
        tracing::warn!(target: "n42.sharded_output", reason, "N42_MERGE_ELIDE refused from now on: a reader of the whole merged bundle runs");
    }
}

/// Why elision was refused at run time ([`refuse`]), if it was.
pub fn refused() -> Option<&'static str> {
    REFUSED.get().copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::map::AddressHashMap;
    use revm_database::AccountStatus;

    #[derive(Default)]
    struct Map(AddressHashMap<BundleAccount>);

    impl ShardedState for Map {
        fn shard_account(&self, address: &Address) -> Option<&BundleAccount> {
            self.0.get(address)
        }
        fn shard_accounts(&self) -> usize {
            self.0.len()
        }
        fn for_each_shard_account(&self, f: &mut dyn FnMut(&Address, &BundleAccount)) {
            for (address, account) in &self.0 {
                f(address, account);
            }
        }
    }

    fn account(nonce: u64) -> BundleAccount {
        BundleAccount {
            info: Some(revm_database::state::AccountInfo { nonce, ..Default::default() }),
            original_info: None,
            storage: Default::default(),
            status: AccountStatus::Changed,
        }
    }

    #[test]
    fn an_entry_answers_while_its_output_lives_and_a_sweep_drops_it_after() {
        let mut shards = Map::default();
        shards.0.insert(Address::with_last_byte(1), account(1));
        shards.0.insert(Address::with_last_byte(2), account(2));
        let mut thin = BundleState::default();
        thin.state.insert(Address::with_last_byte(2), account(20));
        thin.state.insert(Address::with_last_byte(3), account(3));
        let output = Arc::new(thin);
        let other = Arc::new(BundleState::default());
        register(&output, Arc::new(shards));
        let found = shards_of(&*output).expect("registered");
        assert!(shards_of(&*other).is_none(), "another output is whole");
        let nonce = |address: u8| {
            super::account(Some(&*found), &output, &Address::with_last_byte(address))
                .and_then(|account| account.info.as_ref().map(|info| info.nonce))
        };
        assert_eq!((nonce(1), nonce(2), nonce(3), nonce(4)), (Some(1), Some(20), Some(3), None));
        assert_eq!(accounts(Some(&*found), &output), 3);
        let mut seen = Vec::new();
        for_each_account(Some(&*found), &output, &mut |address, _| seen.push(*address));
        seen.sort();
        assert_eq!(seen, (1..=3).map(Address::with_last_byte).collect::<Vec<_>>());
        let whole = materialized(&*output, &output, "test").expect("elided");
        assert_eq!(whole.state.len(), 3);
        assert_eq!(whole.state[&Address::with_last_byte(2)].info.as_ref().map(|info| info.nonce), Some(20));
        drop(found);
        let key = key_of(Arc::as_ptr(&output));
        drop(output);
        sweep();
        let entries = ENTRIES.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(entries.iter().all(|entry| entry.key != key), "the dead entry is swept");
    }
}
