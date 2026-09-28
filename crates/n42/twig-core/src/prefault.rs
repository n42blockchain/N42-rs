// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Page faults paid ahead, on a thread of their own, instead of on the
//! thread that computes a QMDB root.
//!
//! A block's apply runs under the lock the node's tree lives behind, and
//! every page it touches for the first time is a fault on that thread: the
//! ~80 fresh 128 KiB twig trees a 163,000-operation block opens, the entry
//! file's append buffer, the slot offsets' growth. On the fleet those faults
//! were 276 a root when they were cheap and ~1,900 when they were not (the
//! reclaim storm, 4 KiB fallbacks), and the slow roots were the cycle's tail
//! (BREAKTHROUGH_DESIGN 10.48). This module keeps what the apply takes
//! already faulted in:
//!
//! - a shared pool of twig trees, initialised to a fresh twig's nodes and
//!   written through, kept at a floor (`N42_TWIG_POOL_FLOOR`, default 512
//!   trees, 64 MiB; `0` turns the pool off and the tree keeps its own pool
//!   of evicted trees as before). Evicted trees come back through
//!   [`recycle_twig_nodes`] and are cleaned here, not under the lock;
//! - the entry file's append buffer (anonymous heap memory), populated
//!   writable (`MADV_POPULATE_WRITE`) ahead of the cursor on a thread of its
//!   own, `n42-qmdb-append-populate`: a window of
//!   `N42_QMDB_APPEND_AHEAD_MB` (default 64; `0` off) from the cursor
//!   whenever less than half of it is left or the cursor has moved an
//!   eighth of it, and from the buffer's start right after a chunk is
//!   sealed. The window is re-walked from the cursor every time, so pages
//!   the kernel took back since (the fleet's host swaps) are faulted in
//!   again off the root's thread;
//! - the slot offsets' next segments, allocated and written through ahead
//!   (`N42_QMDB_OFFSET_SEGMENTS_AHEAD`, default 2 segments of 8 MiB; `0`
//!   off);
//! - the undo record's two lists (the retired slots, the appended keys:
//!   ~6.5 MiB a 163,000-operation block), handed back when a head move
//!   releases the block's record and reused by the next block's record
//!   (`N42_QMDB_UNDO_POOL` sets, default 64; `0` off), with a few written
//!   through ahead when the pool runs dry between two releases. The records
//!   are released a persistence batch at a time, seconds apart, and the
//!   allocator had returned their pages to the kernel by the time the next
//!   block asked for as much again.
//!
//! Nothing here changes a byte of a tree: a pooled twig tree holds exactly
//! what a freshly allocated one is initialised to, and a populate leaves the
//! memory's content as it is.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    mpsc::Sender,
    Mutex, OnceLock,
};

use crate::{qmdb_compat::TwigNodes, Hash};

/// Slots per offsets segment: 8 MiB of `u64`s.
pub(crate) const OFFSET_SEGMENT_BITS: u32 = 20;
/// See [`OFFSET_SEGMENT_BITS`].
pub(crate) const OFFSET_SEGMENT_SLOTS: usize = 1 << OFFSET_SEGMENT_BITS;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

/// The shared twig pool's floor (`N42_TWIG_POOL_FLOOR`), 0 when off.
pub fn twig_pool_floor() -> usize {
    static FLOOR: OnceLock<usize> = OnceLock::new();
    *FLOOR.get_or_init(|| env_usize("N42_TWIG_POOL_FLOOR", 512))
}

/// Trees the shared pool holds at most, clean and awaiting cleaning
/// together: four times the floor, so a persistence batch's evictions are
/// reused rather than freed and allocated again.
fn twig_pool_cap() -> usize {
    twig_pool_floor().saturating_mul(4)
}

/// Bytes of the append buffer populated ahead of the cursor
/// (`N42_QMDB_APPEND_AHEAD_MB`), 0 when off.
pub(crate) fn append_ahead_bytes() -> usize {
    static AHEAD: OnceLock<usize> = OnceLock::new();
    *AHEAD.get_or_init(|| env_usize("N42_QMDB_APPEND_AHEAD_MB", 64).saturating_mul(1 << 20))
}

/// Undo list sets the pool keeps at most (`N42_QMDB_UNDO_POOL`), 0 when off.
fn undo_pool_cap() -> usize {
    static CAP: OnceLock<usize> = OnceLock::new();
    *CAP.get_or_init(|| env_usize("N42_QMDB_UNDO_POOL", 64))
}

/// Undo list sets written through ahead when the pool has fewer.
const UNDO_POOL_FLOOR: usize = 8;

/// The largest undo list a block asked for, which the sets written through
/// ahead are sized to.
static UNDO_OPS: AtomicU64 = AtomicU64::new(0);

/// Offsets segments kept allocated ahead (`N42_QMDB_OFFSET_SEGMENTS_AHEAD`).
fn offset_segments_ahead() -> usize {
    static AHEAD: OnceLock<usize> = OnceLock::new();
    *AHEAD.get_or_init(|| env_usize("N42_QMDB_OFFSET_SEGMENTS_AHEAD", 2))
}

#[derive(Default)]
struct Pools {
    /// Trees holding a fresh twig's nodes, every page written.
    clean: Vec<TwigNodes>,
    /// Evicted trees, to be cleaned on the worker.
    dirty: Vec<TwigNodes>,
    /// Offsets segments, every page written.
    segments: Vec<Box<[u64]>>,
    /// Empty undo slot lists with their capacity, every page written.
    undo_slots: Vec<Vec<u64>>,
    /// Empty undo key lists with their capacity, every page written.
    undo_keys: Vec<Vec<Hash>>,
}

static POOLS: Mutex<Pools> = Mutex::new(Pools {
    clean: Vec::new(),
    dirty: Vec::new(),
    segments: Vec::new(),
    undo_slots: Vec::new(),
    undo_keys: Vec::new(),
});
/// Fresh twig trees the worker allocated.
static TWIG_REFILLS: AtomicU64 = AtomicU64::new(0);
/// A top-up is queued and not yet started.
static TOP_UP_QUEUED: AtomicBool = AtomicBool::new(false);
/// `MADV_POPULATE_WRITE` failed once (an old kernel): not asked again.
static POPULATE_OFF: AtomicBool = AtomicBool::new(false);

fn pools() -> std::sync::MutexGuard<'static, Pools> {
    POOLS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// How many fresh twig trees the prefault thread has allocated in this
/// process (the shared pool's refills).
pub fn twig_pool_refills() -> u64 {
    TWIG_REFILLS.load(Ordering::Relaxed)
}

enum Job {
    TopUp,
}

/// One window of the append buffer to populate: `[base + from, base + to)`
/// of a live heap buffer, for the append epoch `epoch`.
struct PopulateJob {
    epoch: u64,
    base: usize,
    from: usize,
    to: usize,
}

/// The prefault thread, spawned on first use; `None` if it could not be.
fn worker() -> Option<&'static Sender<Job>> {
    static WORKER: OnceLock<Option<Sender<Job>>> = OnceLock::new();
    WORKER
        .get_or_init(|| {
            let (sender, receiver) = std::sync::mpsc::channel::<Job>();
            std::thread::Builder::new()
                .name("n42-qmdb-prefault".into())
                .spawn(move || {
                    for job in receiver {
                        match job {
                            Job::TopUp => top_up(),
                        }
                    }
                })
                .ok()
                .map(|_| sender)
        })
        .as_ref()
}

fn request_top_up() {
    if TOP_UP_QUEUED.swap(true, Ordering::AcqRel) {
        return;
    }
    let sent = worker().is_some_and(|worker| worker.send(Job::TopUp).is_ok());
    if !sent {
        TOP_UP_QUEUED.store(false, Ordering::Release);
    }
}

/// Writes one word per 4 KiB page of `bytes` bytes at `ptr` so the kernel
/// backs every page now: a store the optimiser cannot drop even where the
/// memory came zeroed from the allocator and the value written is zero.
fn touch_pages<T: Copy>(items: &mut [T]) {
    let stride = (4096 / std::mem::size_of::<T>().max(1)).max(1);
    for index in (0..items.len()).step_by(stride) {
        let item = &mut items[index];
        let value = *item;
        // SAFETY: `item` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(item, value) };
    }
}

/// A fresh twig tree: initialised to a new twig's nodes, every page written.
fn fresh_twig_nodes() -> TwigNodes {
    let mut nodes: TwigNodes = Box::new([crate::NULL_HASH; 2 * crate::TWIG_SIZE]);
    crate::qmdb_compat::init_twig_nodes(&mut nodes);
    touch_pages(&mut nodes[..]);
    nodes
}

/// Cleans evicted trees, then tops the clean pool up to the floor and the
/// offsets segments up to theirs. Allocation and cleaning happen outside the
/// pools' lock, a batch at a time.
fn top_up() {
    TOP_UP_QUEUED.store(false, Ordering::Release);
    const BATCH: usize = 32;
    // The undo lists first: a block without one faults ~6.5 MiB on the
    // root's thread, a twig tree short of the floor costs nothing yet.
    let ops = UNDO_OPS.load(Ordering::Relaxed) as usize;
    if undo_pool_cap() > 0 && ops > 0 {
        while pools().undo_keys.len() < UNDO_POOL_FLOOR {
            pools().undo_keys.push(touched_list(ops, [0u8; 32]));
        }
        while pools().undo_slots.len() < UNDO_POOL_FLOOR {
            pools().undo_slots.push(touched_list(ops, 0u64));
        }
    }
    let floor = twig_pool_floor();
    loop {
        let mut dirty: Vec<TwigNodes> = {
            let mut pools = pools();
            let from = pools.dirty.len().saturating_sub(BATCH);
            pools.dirty.split_off(from)
        };
        if dirty.is_empty() {
            break;
        }
        for nodes in &mut dirty {
            crate::qmdb_compat::init_twig_nodes(nodes);
        }
        pools().clean.append(&mut dirty);
    }
    loop {
        let missing = floor.saturating_sub(pools().clean.len()).min(BATCH);
        if missing == 0 {
            break;
        }
        let mut fresh: Vec<TwigNodes> = (0..missing).map(|_| fresh_twig_nodes()).collect();
        TWIG_REFILLS.fetch_add(missing as u64, Ordering::Relaxed);
        pools().clean.append(&mut fresh);
    }
    let ahead = offset_segments_ahead();
    while pools().segments.len() < ahead {
        let mut segment = vec![0u64; OFFSET_SEGMENT_SLOTS].into_boxed_slice();
        touch_pages(&mut segment);
        pools().segments.push(segment);
    }
}

/// An empty list with room for `capacity` items, every page of the room
/// written.
fn touched_list<T: Copy>(capacity: usize, fill: T) -> Vec<T> {
    let mut list = vec![fill; capacity];
    touch_pages(&mut list);
    list.clear();
    list
}

/// An empty list with room for at least `capacity` items from `pool`, the
/// smallest that fits; `None` when none does.
fn take_list<T>(pool: &mut Vec<Vec<T>>, capacity: usize) -> Option<Vec<T>> {
    let best = pool
        .iter()
        .enumerate()
        .filter(|(_, list)| list.capacity() >= capacity)
        .min_by_key(|(_, list)| list.capacity())
        .map(|(index, _)| index)?;
    Some(pool.swap_remove(best))
}

/// Empty undo lists for a block of `ops` operations -- the retired slots and
/// the appended keys -- with room for all of them and their pages faulted
/// in, when the pool has them; `None` for either list it has not (the pool
/// is off, or dry and not yet topped up).
pub(crate) fn take_undo_lists(ops: usize) -> (Option<Vec<u64>>, Option<Vec<Hash>>) {
    if undo_pool_cap() == 0 || ops == 0 {
        return (None, None);
    }
    UNDO_OPS.fetch_max(ops as u64, Ordering::Relaxed);
    let (slots, keys, low) = {
        let mut pools = pools();
        let slots = take_list(&mut pools.undo_slots, ops);
        let keys = take_list(&mut pools.undo_keys, ops);
        let low = pools.undo_slots.len() < UNDO_POOL_FLOOR || pools.undo_keys.len() < UNDO_POOL_FLOOR;
        (slots, keys, low)
    };
    if low {
        request_top_up();
    }
    (slots, keys)
}

/// Hands a released undo record's lists back for the next blocks' records,
/// up to the pool's cap; freed otherwise. A no-op with the pool off.
pub fn recycle_undo_lists(mut slots: Vec<u64>, mut keys: Vec<Hash>) {
    let cap = undo_pool_cap();
    if cap == 0 {
        return;
    }
    slots.clear();
    keys.clear();
    let mut pools = pools();
    if slots.capacity() > 0 && pools.undo_slots.len() < cap {
        pools.undo_slots.push(slots);
    }
    if keys.capacity() > 0 && pools.undo_keys.len() < cap {
        pools.undo_keys.push(keys);
    }
}

/// A twig tree holding a fresh twig's nodes, from the shared pool, or `None`
/// when the pool is off or empty. Asks for a top-up when the pool is under
/// its floor.
pub(crate) fn take_clean_twig_nodes() -> Option<TwigNodes> {
    let floor = twig_pool_floor();
    if floor == 0 {
        return None;
    }
    let (nodes, low) = {
        let mut pools = pools();
        let nodes = pools.clean.pop();
        (nodes, pools.clean.len() < floor)
    };
    if low {
        request_top_up();
    }
    nodes
}

/// Whether evicted twig trees go to the shared pool (through
/// [`recycle_twig_nodes`]) rather than to the tree's own.
pub(crate) fn shared_twig_pool() -> bool {
    twig_pool_floor() > 0
}

/// Hands evicted twig trees to the shared pool, up to its cap; what does not
/// fit stays in `nodes` for the caller to free. The trees are cleaned on the
/// prefault thread. A no-op with the pool off.
pub fn recycle_twig_nodes(nodes: &mut Vec<TwigNodes>) {
    if !shared_twig_pool() || nodes.is_empty() {
        return;
    }
    {
        let mut pools = pools();
        let room = twig_pool_cap().saturating_sub(pools.clean.len() + pools.dirty.len());
        let from = nodes.len().saturating_sub(room);
        pools.dirty.extend(nodes.drain(from..));
    }
    request_top_up();
}

/// An offsets segment of [`OFFSET_SEGMENT_SLOTS`] slots, every page written
/// ahead (its content is not meaningful), or a fresh one when none is ready.
pub(crate) fn take_offset_segment() -> Box<[u64]> {
    if offset_segments_ahead() == 0 {
        return vec![0u64; OFFSET_SEGMENT_SLOTS].into_boxed_slice();
    }
    let segment = pools().segments.pop();
    request_top_up();
    segment.unwrap_or_else(|| vec![0u64; OFFSET_SEGMENT_SLOTS].into_boxed_slice())
}

/// The append populate's progress: the epoch of the last piece it
/// finished, and the buffer offset that piece reached (its edge only grows
/// within an epoch).
static DONE_EPOCH: AtomicU64 = AtomicU64::new(0);
static DONE_TO: AtomicUsize = AtomicUsize::new(0);
/// The window the appender last asked for, as epoch and offset.
static ASKED_EPOCH: AtomicU64 = AtomicU64::new(0);
static ASKED_TO: AtomicUsize = AtomicUsize::new(0);
/// Records appended past the populate's finished edge.
static APPEND_BEHIND: AtomicU64 = AtomicU64::new(0);
/// Epochs handed out to appenders (one per buffer and seal).
static EPOCHS: AtomicU64 = AtomicU64::new(0);

/// A new append epoch: a fresh buffer, or the buffer restarted by a seal.
pub(crate) fn next_append_epoch() -> u64 {
    EPOCHS.fetch_add(1, Ordering::Relaxed) + 1
}

/// Whether the append window is also re-walked every eighth of a window
/// (`N42_QMDB_APPEND_REWALK=1`), not only when half of it is left.
pub(crate) fn append_rewalk() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| env_usize("N42_QMDB_APPEND_REWALK", 0) == 1)
}

/// Pieces a window is populated in, so the progress moves before the whole
/// window is done.
const POPULATE_PIECE: usize = 4 << 20;

/// The append populate's own thread: queued on the pool thread, a populate
/// waited behind the top-ups (thousands of twig trees cleaned after a
/// persistence batch).
fn append_populator() -> Option<&'static Sender<PopulateJob>> {
    static WORKER: OnceLock<Option<Sender<PopulateJob>>> = OnceLock::new();
    WORKER
        .get_or_init(|| {
            let (sender, receiver) = std::sync::mpsc::channel::<PopulateJob>();
            std::thread::Builder::new()
                .name("n42-qmdb-append-populate".into())
                .spawn(move || {
                    for job in receiver {
                        let mut at = job.from;
                        while at < job.to {
                            let end = (at + POPULATE_PIECE).min(job.to);
                            populate_write_now(job.base + at, end - at);
                            if DONE_EPOCH.load(Ordering::Acquire) == job.epoch {
                                DONE_TO.fetch_max(end, Ordering::AcqRel);
                            } else {
                                DONE_TO.store(end, Ordering::Release);
                                DONE_EPOCH.store(job.epoch, Ordering::Release);
                            }
                            at = end;
                        }
                    }
                })
                .ok()
                .map(|_| sender)
        })
        .as_ref()
}

/// Populates `[base + from, base + to)` writable on the append populate
/// thread, for append epoch `epoch`. The range is a live heap buffer's
/// spare capacity; should the buffer be reallocated before the thread gets
/// to it, the populate lands on memory that is free or someone else's,
/// which a populate cannot harm: it faults pages in and changes no byte.
pub(crate) fn populate_append(epoch: u64, base: usize, from: usize, to: usize) {
    if to <= from || POPULATE_OFF.load(Ordering::Relaxed) {
        return;
    }
    ASKED_TO.store(to, Ordering::Relaxed);
    ASKED_EPOCH.store(epoch, Ordering::Relaxed);
    if let Some(worker) = append_populator() {
        let _ = worker.send(PopulateJob { epoch, base, from, to });
    }
}

/// Notes an append reaching buffer offset `end` in epoch `epoch`: counted
/// as behind when the populate has not finished that far.
#[inline]
pub(crate) fn note_append(epoch: u64, end: usize) {
    let done = if DONE_EPOCH.load(Ordering::Acquire) == epoch { DONE_TO.load(Ordering::Acquire) } else { 0 };
    if end > done {
        APPEND_BEHIND.fetch_add(1, Ordering::Relaxed);
    }
}

/// Records appended in this process into pages the populate had not
/// reached, and how far the populate is behind the window last asked for,
/// in bytes (0 when it has caught up).
pub fn append_populate_stats() -> (u64, usize) {
    let behind = APPEND_BEHIND.load(Ordering::Relaxed);
    let asked_epoch = ASKED_EPOCH.load(Ordering::Relaxed);
    let asked = ASKED_TO.load(Ordering::Relaxed);
    let done = if DONE_EPOCH.load(Ordering::Acquire) == asked_epoch { DONE_TO.load(Ordering::Acquire) } else { 0 };
    (behind, asked.saturating_sub(done))
}

/// `MADV_POPULATE_WRITE` (Linux 5.14); the libc crate's constant is recent.
#[cfg(target_os = "linux")]
const MADV_POPULATE_WRITE: libc::c_int = 23;

fn populate_write_now(addr: usize, len: usize) {
    #[cfg(target_os = "linux")]
    {
        const PAGE: usize = 4096;
        // Whole pages inside the range only.
        let start = addr.div_ceil(PAGE) * PAGE;
        let end = (addr + len) / PAGE * PAGE;
        if end <= start {
            return;
        }
        // SAFETY: `madvise` with MADV_POPULATE_WRITE only faults the range's
        // pages in, writable, and changes no byte of them; no Rust reference
        // is made to the range. An unmapped range fails with ENOMEM.
        let result = unsafe { libc::madvise(start as *mut libc::c_void, end - start, MADV_POPULATE_WRITE) };
        if result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            POPULATE_OFF.store(true, Ordering::Relaxed);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (addr, len);
}

/// This thread's page faults (minor and major) so far; 0 off Linux.
pub fn thread_faults() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `getrusage` writes one `rusage` into the zeroed struct it is given.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { libc::getrusage(libc::RUSAGE_THREAD, &raw mut usage) } != 0 {
            return 0;
        }
        (usage.ru_minflt.max(0) + usage.ru_majflt.max(0)) as u64
    }
    #[cfg(not(target_os = "linux"))]
    0
}
