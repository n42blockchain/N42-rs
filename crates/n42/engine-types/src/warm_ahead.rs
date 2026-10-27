// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: Apache-2.0

//! The warm read ahead of the build (`N42_PLAN_AHEAD_WARM=<threads>`,
//! `docs/BREAKTHROUGH_DESIGN.md` 10.122).
//!
//! `N42_BUILD_PREFETCH=1` read every account of the block into a
//! [`FrozenWarm`] layer the build's batches consult first, and halved the
//! execution, but on the build's own pool and on its critical path. Here the
//! same layer is filled while the plan for the next block is prepared, on a
//! pool of its own placed on the background set.
//!
//! The plan for block N+1 is made at block N's selection, while N is still
//! being built: N+1's parent state (N's post-state) does not exist yet. So
//! the read is made at the state build N itself reads -- N's parent P, by the
//! opener build N published at its start ([`note_base`]) -- and every
//! account block N can change is left out of it: the senders and recipients
//! of the plan N built (its plan's touched set, kept by that plan's own job),
//! N's beneficiary and withdrawal recipients and the system contracts
//! ([`note_built`]). For any other account N's post-state equals P's, so the
//! layer answers N+1's reads exactly; what it does not hold falls through to
//! the chain as before.
//!
//! The layer is used by build N+1 only when everything lines up
//! ([`usable`]): N sealed at its execution's end on exactly the plan whose
//! touched set was excluded (no serial transaction, no topped-up take), N+1's
//! parent is that block (the builder's hash N sealed equals the
//! `parent_built` N+1 was asked to build on), and the read was made at N's
//! parent (`base`), which is N+1's grandparent. Any mismatch -- a peer's block
//! at that height, a view change, a plan discarded and made again, a build
//! that fell back to the serial loop -- and the layer is dropped unread.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, OnceLock, PoisonError,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

use alloy_primitives::{
    Address, B256,
    map::{AddressHashMap, AddressHashSet},
};
use revm::Database;

use crate::parallel_transfer::{FrozenWarm, WARM_SHARDS, WarmInfo, warm_shard};

/// The pool's thread count (`N42_PLAN_AHEAD_WARM=<threads>`); 0 (unset) is
/// off. Read once.
pub fn threads() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| n42_env::parse::<usize>("N42_PLAN_AHEAD_WARM", 0).min(64))
}

/// The warm read's pool: [`threads`] threads (`n42-warm-*`), each placed on
/// the core layout's background set, never the build's.
fn pool() -> Option<&'static rayon::ThreadPool> {
    static POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads().max(1))
            .thread_name(|i| format!("n42-warm-{i}"))
            .start_handler(|_| n42_core_layout::enter(n42_core_layout::Set::Background))
            .build()
            .inspect_err(|err| tracing::warn!(target: "payload_builder", %err, "no pool for the warm read ahead; it is off"))
            .ok()
    })
    .as_ref()
}

/// The accounts no block of transfers changes through its transactions but
/// the block's own pre- and post-execution system calls touch: never served
/// from the layer.
const SYSTEM: [Address; 5] = [
    alloy_eips::eip4788::SYSTEM_ADDRESS,
    alloy_eips::eip4788::BEACON_ROOTS_ADDRESS,
    alloy_eips::eip2935::HISTORY_STORAGE_ADDRESS,
    alloy_eips::eip7002::WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
    alloy_eips::eip7251::CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
];

/// The state a running build reads: its parent's hash and its opener.
struct Base {
    parent: B256,
    open: crate::direct_build::ParentStateOpener,
}

static BASE: Mutex<Option<Base>> = Mutex::new(None);

/// The plan the running build took (its warm id, 0 for none) and its parent.
static SELECTED: Mutex<(u64, B256)> = Mutex::new((0, B256::ZERO));

/// The last build that sealed exactly its plan ([`note_built`]).
static BUILT: Mutex<Option<Built>> = Mutex::new(None);

/// The latest warm reads, newest last.
static RECENT: Mutex<VecDeque<Arc<WarmAhead>>> = Mutex::new(VecDeque::new());

/// The identity of a take of whole frames: each segment's frame (its
/// allocation), its length taken and the hashes of its first and last
/// transaction taken, folded; 0 when a segment does not start at its
/// frame's start or none is given. The plan hook and the build compute it
/// from the same segments, so a build that takes a plan whole names that
/// plan's read; the hashes keep a reused allocation from naming an older one.
pub fn segments_ident<'a, T: reth_transaction_pool::PoolTransaction + 'a>(
    segments: impl Iterator<Item = (&'a n42_tx_queue::FrameTxs<T>, usize, usize)>,
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut any = false;
    for (txs, from, to) in segments {
        if from != 0 || to == 0 || to > txs.len() {
            return 0;
        }
        any = true;
        (Arc::as_ptr(txs) as *const () as usize).hash(&mut hasher);
        to.hash(&mut hasher);
        txs[0].hash().hash(&mut hasher);
        txs[to - 1].hash().hash(&mut hasher);
    }
    if !any {
        return 0;
    }
    hasher.finish().max(1)
}

/// Build start: the state this build reads (`parent`, by `open`) is what the
/// next plan's warm read reads.
pub fn note_base(parent: B256, open: crate::direct_build::ParentStateOpener) {
    *BASE.lock().unwrap_or_else(PoisonError::into_inner) = Some(Base { parent, open });
}

/// Build start, for a build that reads the client's state at its parent
/// (no opener to share): the next plan reads nothing.
pub fn clear_base() {
    *BASE.lock().unwrap_or_else(PoisonError::into_inner) = None;
}

/// Build start: the build on `parent` took the plan whose warm id is `id`
/// (0: no prepared plan). The next plan's read leaves out that plan's
/// touched set.
pub fn note_selected(id: u64, parent: B256) {
    *SELECTED.lock().unwrap_or_else(PoisonError::into_inner) = (id, parent);
}

/// A build that sealed at its execution's end with exactly the transactions
/// of the plan `plan` and nothing serial: its block changed no account
/// outside that plan's senders and recipients and `extra`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    /// The plan's warm id.
    pub plan: u64,
    /// The build's parent (the state it read).
    pub base: B256,
    /// The hash the builder sealed the block under.
    pub built: B256,
    /// The beneficiary and the withdrawal recipients.
    pub extra: Vec<Address>,
}

/// Records [`Built`] for the block just sealed.
pub fn note_built(built: Built) {
    *BUILT.lock().unwrap_or_else(PoisonError::into_inner) = Some(built);
}

/// One plan's warm read.
#[derive(Debug)]
pub struct WarmAhead {
    /// The plan's warm id.
    pub id: u64,
    /// The state the read was made at.
    pub base: B256,
    /// The plan whose touched set was left out (0 when none could be).
    prev: OnceLock<u64>,
    /// This plan's senders and recipients, by shard: the next plan's
    /// exclusion.
    touched: Vec<OnceLock<AddressHashSet>>,
    /// What was read, by shard, put whole once the shard is read.
    maps: Vec<Mutex<Option<AddressHashMap<WarmInfo>>>>,
    /// Shards read.
    done: AtomicUsize,
    /// The exclusion was not known: nothing was read.
    failed: AtomicBool,
    /// A build took (or dropped) the layer: stop reading.
    cancelled: AtomicBool,
    started: std::time::Instant,
    /// The read's own wall, set when its last shard is done.
    wall_us: AtomicU64,
}

impl WarmAhead {
    /// An empty read with id `id` at `base`.
    pub fn new(id: u64, base: B256) -> Self {
        Self {
            id,
            base,
            prev: OnceLock::new(),
            touched: (0..WARM_SHARDS).map(|_| OnceLock::new()).collect(),
            maps: (0..WARM_SHARDS).map(|_| Mutex::new(None)).collect(),
            done: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            started: std::time::Instant::now(),
            wall_us: AtomicU64::new(0),
        }
    }

    /// The plan whose touched set was left out, once the read knows it.
    pub fn prev(&self) -> Option<u64> {
        self.prev.get().copied()
    }

    /// Whether every shard is read.
    pub fn complete(&self) -> bool {
        !self.failed.load(Ordering::Acquire) && self.done.load(Ordering::Acquire) == WARM_SHARDS
    }

    /// Stops the read at its next check.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// The read's wall so far (to its end once it ended), in ms.
    pub fn wall_ms(&self) -> u64 {
        match self.wall_us.load(Ordering::Acquire) {
            0 => self.started.elapsed().as_millis() as u64,
            us => us / 1000,
        }
    }

    /// The read, on the current rayon pool with `threads` groups: this
    /// plan's touched set by shard (`keys`, each transfer's sender and
    /// recipient), then -- once `prev` names the plan the running build
    /// took -- every one of them outside that plan's set read from a db
    /// `open` makes (one a group), shard by shard. A read that fails is left
    /// out (the build meets it on the chain). Never reads anything when the
    /// previous plan is unknown.
    pub fn run<G: Database>(
        &self,
        keys: &[(Address, Address)],
        prev: impl FnOnce() -> Option<Arc<Self>>,
        open: &(dyn Fn() -> Option<G> + Sync),
        threads: usize,
    ) {
        use rayon::prelude::*;
        let buckets: Vec<Vec<Vec<Address>>> = keys
            .par_chunks(16_384)
            .map(|chunk| {
                let mut by_shard = vec![Vec::new(); WARM_SHARDS];
                for (sender, recipient) in chunk {
                    by_shard[warm_shard(sender)].push(*sender);
                    by_shard[warm_shard(recipient)].push(*recipient);
                }
                by_shard
            })
            .collect();
        (0..WARM_SHARDS).into_par_iter().for_each(|s| {
            let mut set = AddressHashSet::default();
            set.reserve(buckets.iter().map(|b| b[s].len()).sum::<usize>() / 2);
            for bucket in &buckets {
                set.extend(bucket[s].iter().copied());
            }
            let _ = self.touched[s].set(set);
        });
        drop(buckets);
        let prev = prev();
        let _ = self.prev.set(prev.as_ref().map_or(0, |p| p.id));
        let Some(prev) = prev else {
            self.failed.store(true, Ordering::Release);
            self.wall_us.store(self.started.elapsed().as_micros().max(1) as u64, Ordering::Release);
            return;
        };
        let groups = threads.clamp(1, WARM_SHARDS);
        (0..groups).into_par_iter().for_each(|g| {
            let Some(mut db) = open() else { return };
            for s in (g..WARM_SHARDS).step_by(groups) {
                if self.cancelled.load(Ordering::Acquire) {
                    return;
                }
                let (Some(mine), Some(theirs)) = (self.touched[s].get(), prev.touched[s].get()) else { continue };
                let mut map = AddressHashMap::default();
                map.reserve(mine.len());
                for (n, address) in mine.iter().enumerate() {
                    if n % 256 == 255 && self.cancelled.load(Ordering::Acquire) {
                        return;
                    }
                    if theirs.contains(address) {
                        continue;
                    }
                    if let Ok(info) = db.basic(*address) {
                        map.insert(*address, info);
                    }
                }
                *self.maps[s].lock().unwrap_or_else(PoisonError::into_inner) = Some(map);
                if self.done.fetch_add(1, Ordering::AcqRel) + 1 == WARM_SHARDS {
                    self.wall_us.store(self.started.elapsed().as_micros().max(1) as u64, Ordering::Release);
                }
            }
        });
    }

    /// The layer as it stands, for the build that may use it: the shards
    /// read so far (the rest empty, so their reads fall through), with
    /// `extra` and the system contracts removed; the read is stopped. Also
    /// returns whether it was complete and how many accounts it holds.
    pub fn take(&self, extra: &[Address]) -> (FrozenWarm, bool) {
        let ready = self.complete();
        self.cancel();
        let mut shards: Vec<AddressHashMap<WarmInfo>> =
            self.maps.iter().map(|m| m.lock().unwrap_or_else(PoisonError::into_inner).take().unwrap_or_default()).collect();
        for address in extra.iter().chain(SYSTEM.iter()) {
            shards[warm_shard(address)].remove(address);
        }
        (FrozenWarm::from_shards(shards), ready)
    }
}

/// Whether a read made at `base` leaving out plan `prev` answers a build
/// whose parent's parent is `grandparent` and whose parent the builder sealed
/// as `parent_built`, given the record of the last build that sealed its
/// plan whole.
pub fn usable(base: B256, prev: Option<u64>, built: Option<&Built>, grandparent: B256, parent_built: Option<B256>) -> bool {
    let (Some(prev), Some(built), Some(parent_built)) = (prev, built, parent_built) else { return false };
    prev != 0 && prev == built.plan && base == built.base && grandparent == built.base && parent_built == built.built
}

/// The plan hook (`N42_PLAN_AHEAD_BODY=1` with `N42_PLAN_AHEAD_WARM`): the
/// read of the plan whose take is `id` ([`segments_ident`]) started on the
/// warm pool at the running build's state; `keys` (each transfer's sender
/// and recipient, `None` when one is not a plain transfer) is made there.
/// Nothing when off, when `id` is 0 or when no build has published its
/// state.
pub fn start(id: u64, keys: impl FnOnce() -> Option<Vec<(Address, Address)>> + Send + 'static) {
    if threads() == 0 || id == 0 {
        return;
    }
    let Some(pool) = pool() else { return };
    let Some((base, open)) =
        BASE.lock().unwrap_or_else(PoisonError::into_inner).as_ref().map(|b| (b.parent, Arc::clone(&b.open)))
    else {
        return;
    };
    let warm = Arc::new(WarmAhead::new(id, base));
    {
        let mut recent = RECENT.lock().unwrap_or_else(PoisonError::into_inner);
        // A plan made again for the same build supersedes the older one; a
        // read at another base is the running build's own and stays. (One
        // with this very take is superseded too: the newest is found first.)
        for older in recent.iter().filter(|older| older.base == base) {
            older.cancel();
        }
        while recent.len() >= 4 {
            recent.pop_front();
        }
        recent.push_back(Arc::clone(&warm));
    }
    let groups = threads();
    pool.spawn(move || {
        // The plan the running build took: the build on `base` notes it
        // right after its selection, which is what started this plan; a
        // short wait covers the race between the two threads.
        let prev = || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(10);
            loop {
                let (selected, parent) = *SELECTED.lock().unwrap_or_else(PoisonError::into_inner);
                if parent == base {
                    if selected == 0 {
                        return None;
                    }
                    return RECENT.lock().unwrap_or_else(PoisonError::into_inner).iter().rev().find(|w| w.id == selected).cloned();
                }
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        };
        let open_db = || {
            open().ok().map(|state| {
                reth_revm::database::StateProviderDatabase::new(reth_storage_api::StateProvider::into_evm_state_provider(
                    state,
                ))
            })
        };
        match keys() {
            Some(keys) => warm.run(&keys, prev, &open_db, groups),
            None => {
                // Not every transaction a plain transfer: its touched set is
                // unknown, so neither this read nor the next plan's is used.
                let _ = warm.prev.set(0);
                warm.failed.store(true, Ordering::Release);
            }
        }
    });
}

/// What a build found of the warm read ([`take_for`]).
#[derive(Debug, Default)]
pub struct Taken {
    /// The layer (empty when unusable).
    pub warm: FrozenWarm,
    /// Accounts in it.
    pub accounts: usize,
    /// The read's own wall time, ms.
    pub ms: u64,
    /// Whether it was complete when the build took it.
    pub ready: bool,
}

/// Build start (before its batches run): the newest warm read, if it answers
/// a build whose parent's parent is `grandparent` and whose parent the
/// builder sealed as `parent_built` ([`usable`]). Any read found is stopped;
/// a read that does not fit is dropped.
pub fn take_for(grandparent: B256, parent_built: Option<B256>) -> Option<Taken> {
    if threads() == 0 {
        return None;
    }
    let built = BUILT.lock().unwrap_or_else(PoisonError::into_inner).clone();
    // The newest read made at this build's grandparent: the next plan's read
    // (made at this build's parent) may already have started beside it.
    let warm = {
        let recent = RECENT.lock().unwrap_or_else(PoisonError::into_inner);
        let at_base: Vec<&Arc<WarmAhead>> = recent.iter().rev().filter(|w| w.base == grandparent).collect();
        let found = at_base.first().map(|w| Arc::clone(w));
        for older in at_base.iter().skip(1) {
            older.cancel();
        }
        found?
    };
    if !usable(warm.base, warm.prev(), built.as_ref(), grandparent, parent_built) {
        warm.cancel();
        return None;
    }
    let extra = built.map(|b| b.extra).unwrap_or_default();
    let (layer, ready) = warm.take(&extra);
    Some(Taken { accounts: layer.len(), ms: warm.wall_ms(), ready, warm: layer })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A read is used only by the build it was made for: on the block sealed
    /// from the plan it left out, at that block's parent.
    #[test]
    fn a_warm_read_for_another_parent_is_not_used() {
        let (p, n, other) = (B256::with_last_byte(1), B256::with_last_byte(2), B256::with_last_byte(3));
        let built = Built { plan: 7, base: p, built: n, extra: vec![] };
        assert!(usable(p, Some(7), Some(&built), p, Some(n)), "the build it was made for");
        assert!(!usable(p, Some(7), Some(&built), p, Some(other)), "another block at the parent's height");
        assert!(!usable(p, Some(7), Some(&built), p, None), "a parent this node did not build");
        assert!(!usable(p, Some(7), Some(&built), other, Some(n)), "a build on another grandparent");
        assert!(!usable(other, Some(7), Some(&built), other, Some(n)), "a read at another state");
        assert!(!usable(p, Some(6), Some(&built), p, Some(n)), "the parent built another plan than the one left out");
        assert!(!usable(p, Some(0), Some(&built), p, Some(n)), "nothing left out");
        assert!(!usable(p, None, Some(&built), p, Some(n)), "the exclusion not yet known");
        assert!(!usable(p, Some(7), None, p, Some(n)), "no block sealed its plan whole");
    }

    /// The flood's recipients (a slot under 2^20 big-endian in the first
    /// four bytes, 0x42 in the fifth) spread over every shard: by the first
    /// byte alone they all landed in shard 0 (loop351 stage ay).
    #[test]
    fn the_floods_recipients_spread_over_the_shards() {
        let mut per = vec![0usize; WARM_SHARDS];
        for i in 0..100_000u32 {
            let slot = i.wrapping_mul(2_654_435_761) % 900_000;
            let mut bytes = [0u8; 20];
            bytes[..4].copy_from_slice(&slot.to_be_bytes());
            bytes[4] = 0x42;
            per[warm_shard(&Address::new(bytes))] += 1;
        }
        let (min, max) = (per.iter().min().copied().unwrap(), per.iter().max().copied().unwrap());
        assert!(min > 1_200 && max < 1_950, "{min}..{max}");
    }

    /// `take` leaves out the parent's beneficiary, its withdrawal
    /// recipients and the system contracts, and stops the read.
    #[test]
    fn the_taken_layer_leaves_out_the_extra_accounts() {
        let mut db = revm::database::CacheDB::new(revm::database::EmptyDB::default());
        let (a, b, beneficiary) = (Address::with_last_byte(10), Address::with_last_byte(11), Address::with_last_byte(12));
        for address in [a, b, beneficiary, SYSTEM[1]] {
            db.insert_account_info(address, revm::state::AccountInfo { nonce: 3, ..Default::default() });
        }
        let prev = Arc::new(WarmAhead::new(1, B256::ZERO));
        prev.run(&[], || None, &|| Some(db.clone()), 2);
        let warm = WarmAhead::new(2, B256::ZERO);
        warm.run(&[(a, b), (beneficiary, SYSTEM[1])], || Some(Arc::clone(&prev)), &|| Some(db.clone()), 2);
        assert!(warm.complete());
        let (layer, ready) = warm.take(&[beneficiary]);
        assert!(ready);
        assert_eq!(layer.len(), 2);
        assert!(layer.get(&a).is_some() && layer.get(&b).is_some());
        assert!(layer.get(&beneficiary).is_none() && layer.get(&SYSTEM[1]).is_none());
        assert!(warm.cancelled.load(Ordering::Acquire));
    }
}
