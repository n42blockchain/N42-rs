// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! What a block's execution produced, by block hash, for deferred execution.
//!
//! Under deferred execution (`docs/PHASE_D_DEFERRED_EXECUTION.md`, the
//! genesis `deferredExecutionTime`) a header carries the execution of its
//! *parent*: `stateRoot`, `receiptsRoot`, `logsBloom` and `gasUsed` are the
//! parent's after execution (at `deferredExecutionDepth` 2, the parent's
//! parent's: `docs/DEFERRED_DEPTH_2_DESIGN.md`; "parent" below reads as "the
//! ancestor at the chain's depth"). So a builder needs the parent's result to
//! assemble a header, and a validator needs it to check one. Both come from
//! here: every path that executes a block -- the builder, the follower's
//! direct import, the engine's validator -- records the block's fields under
//! its hash, and the header of the child is assembled from or checked
//! against them. A registry rather than a database read because the parent
//! was executed milliseconds ago on this node and its receipts may not be
//! persisted yet; the database is the fallback a restart needs (`seed`).
//!
//! The state root and the receipt side arrive separately (the QMDB root from
//! the forest, the receipts from the post-execution check), so an entry is
//! complete only once both are in.

use alloy_primitives::{Bloom, B256};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// A block's execution result, as its child's header carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutedFields {
    /// The state root after the block (the QMDB root on this chain).
    pub state_root: B256,
    /// gov5's receipts root of the block's receipts.
    pub receipts_root: B256,
    /// The logs bloom of the block's receipts.
    pub logs_bloom: Bloom,
    /// Gas used by the block.
    pub gas_used: u64,
}

#[derive(Debug, Default, Clone, Copy)]
struct Partial {
    state_root: Option<B256>,
    receipts: Option<(B256, Bloom, u64)>,
}

impl Partial {
    fn complete(&self) -> Option<ExecutedFields> {
        let (receipts_root, logs_bloom, gas_used) = self.receipts?;
        Some(ExecutedFields { state_root: self.state_root?, receipts_root, logs_bloom, gas_used })
    }
}

/// Blocks kept; a validator needs the parent, a builder the parent, a
/// restart the persisted head -- a few views' worth, generously.
const KEEP: usize = 256;

/// Sealed-to-built aliases kept ([`note_built`]): a depth-2 build needs its
/// grandparent's, noted one block earlier; a few views of re-seals besides.
const ALIASES_KEPT: usize = 16;

struct Registry {
    by_hash: HashMap<B256, Partial>,
    order: VecDeque<B256>,
    /// `(sealed, built)`, oldest first: a leader's own block is filed under
    /// the hash its builder gave it and is known to its descendants by the
    /// hash consensus sealed.
    aliases: VecDeque<(B256, B256)>,
}

impl Registry {
    /// The complete entry under `hash`, or under the builder hash `hash` is
    /// an alias of.
    fn complete(&self, hash: &B256) -> Option<ExecutedFields> {
        self.by_hash.get(hash).and_then(Partial::complete).or_else(|| {
            let built = self.aliases.iter().rev().find(|(sealed, _)| sealed == hash)?.1;
            self.by_hash.get(&built).and_then(Partial::complete)
        })
    }
}

static REGISTRY: Mutex<Option<Registry>> = Mutex::new(None);
/// Signalled on every access, for [`wait_for`].
static WRITTEN: std::sync::Condvar = std::sync::Condvar::new();

fn with_registry<T>(f: impl FnOnce(&mut Registry) -> T) -> T {
    let mut guard = REGISTRY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let registry = guard.get_or_insert_with(|| Registry { by_hash: HashMap::new(), order: VecDeque::new(), aliases: VecDeque::new() });
    let out = f(registry);
    drop(guard);
    WRITTEN.notify_all();
    out
}

fn entry_mut(registry: &mut Registry, hash: B256) -> &mut Partial {
    if !registry.by_hash.contains_key(&hash) {
        registry.order.push_back(hash);
        while registry.order.len() > KEEP {
            if let Some(old) = registry.order.pop_front() {
                registry.by_hash.remove(&old);
            }
        }
    }
    registry.by_hash.entry(hash).or_default()
}

/// Records the state root a block's execution produced.
pub fn remember_state_root(block_hash: B256, state_root: B256) {
    with_registry(|registry| entry_mut(registry, block_hash).state_root = Some(state_root));
}

/// Records the receipt side of a block's execution.
pub fn remember_receipts(block_hash: B256, receipts_root: B256, logs_bloom: Bloom, gas_used: u64) {
    with_registry(|registry| entry_mut(registry, block_hash).receipts = Some((receipts_root, logs_bloom, gas_used)));
}

/// Records a block's whole result at once.
pub fn remember(block_hash: B256, fields: ExecutedFields) {
    with_registry(|registry| {
        let entry = entry_mut(registry, block_hash);
        entry.state_root = Some(fields.state_root);
        entry.receipts = Some((fields.receipts_root, fields.logs_bloom, fields.gas_used));
    });
}

/// A block's execution result, once both halves are in: under `block_hash`,
/// or under the builder hash `block_hash` was noted as an alias of
/// ([`note_built`]).
pub fn get(block_hash: &B256) -> Option<ExecutedFields> {
    with_registry(|registry| registry.complete(block_hash))
}

/// Notes that the block consensus sealed as `sealed` is the one this node's
/// builder filed as `built` (`docs/DEFERRED_DEPTH_2_DESIGN.md` item 5).
///
/// A leader's own block has two hashes: its result is filed under the
/// builder's the moment its build ends, and copied to the sealed one only at
/// the own-block hand-off, about two cycles after the seal. At depth 1 the
/// child's seal finds the parent through the builder hash it is handed; at
/// depth 2 the child needs its *grandparent's* result, named only by the
/// parent header's `parent_hash` (a sealed hash), before that hand-off has
/// run. Noted where a build on the block is requested -- one block before it
/// becomes a grandparent; a block re-sealed after a view change gets its new
/// sealed hash noted the same way. [`get`] and [`wait_for`] follow it.
pub fn note_built(sealed: B256, built: B256) {
    if sealed == built {
        return;
    }
    with_registry(|registry| {
        registry.aliases.retain(|(known, _)| *known != sealed);
        registry.aliases.push_back((sealed, built));
        while registry.aliases.len() > ALIASES_KEPT {
            registry.aliases.pop_front();
        }
    });
}

/// The builder hash `sealed` was noted as, if any.
pub fn built_of(sealed: &B256) -> Option<B256> {
    with_registry(|registry| registry.aliases.iter().rev().find(|(known, _)| known == sealed).map(|(_, built)| *built))
}

/// [`get`], waiting up to `timeout` for the fields to be recorded: a parent
/// sealed before its finish (docs/PHASE_D_DEFERRED_EXECUTION.md section 13)
/// records them a moment after its child's build has started.
pub fn wait_for(block_hash: &B256, timeout: std::time::Duration) -> Option<ExecutedFields> {
    let deadline = std::time::Instant::now() + timeout;
    let mut guard = REGISTRY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        if let Some(found) = guard.as_ref().and_then(|registry| registry.complete(block_hash)) {
            return Some(found);
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return None;
        }
        let (g, _) = WRITTEN.wait_timeout(guard, deadline - now).unwrap_or_else(std::sync::PoisonError::into_inner);
        guard = g;
    }
}

/// Seeds the registry with a block whose execution the chain already holds
/// -- at startup, the persisted head, so the first header after a restart
/// can be assembled and checked. Before the fork every header carries its
/// own execution, so a pre-fork block's fields are its header's.
pub fn seed_from_header(block_hash: B256, header: &alloy_consensus::Header) {
    remember(
        block_hash,
        ExecutedFields {
            state_root: header.state_root,
            receipts_root: header.receipts_root,
            logs_bloom: header.logs_bloom,
            gas_used: header.gas_used,
        },
    );
}

/// The execution fields a header at or past the fork carries, read from that
/// header. The name is historical: the fields are those of the header's
/// depth-D ancestor (`deferredExecutionDepth`, `docs/DEFERRED_DEPTH_2_DESIGN.md`),
/// the parent at depth 1 and the parent's parent at depth 2.
pub fn fields_from_child_header(child: &alloy_consensus::Header) -> ExecutedFields {
    ExecutedFields {
        state_root: child.state_root,
        receipts_root: child.receipts_root,
        logs_bloom: child.logs_bloom,
        gas_used: child.gas_used,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_complete_only_with_both_halves_and_old_ones_fall_out() {
        let h = |b: u8| B256::repeat_byte(b);
        remember_state_root(h(1), h(0xA1));
        assert_eq!(get(&h(1)), None);
        remember_receipts(h(1), h(0xB1), Bloom::default(), 21_000);
        assert_eq!(
            get(&h(1)),
            Some(ExecutedFields { state_root: h(0xA1), receipts_root: h(0xB1), logs_bloom: Bloom::default(), gas_used: 21_000 })
        );
        for i in 0..(KEEP as u32 + 8) {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&(i + 100).to_le_bytes());
            remember(B256::from(bytes), ExecutedFields { state_root: h(2), receipts_root: h(3), logs_bloom: Bloom::default(), gas_used: 1 });
        }
        assert_eq!(get(&h(1)), None, "the oldest entries are evicted");
    }

    #[test]
    fn a_sealed_hash_noted_as_an_alias_finds_the_builders_entry() {
        let h = |b: u8| B256::repeat_byte(b);
        let fields = ExecutedFields { state_root: h(0xC1), receipts_root: h(0xC2), logs_bloom: Bloom::default(), gas_used: 7 };
        // Filed under the builder's hash only, as a leader's own block is.
        remember(h(0x31), fields);
        assert_eq!(get(&h(0x32)), None, "nothing under the sealed hash yet");
        note_built(h(0x32), h(0x31));
        assert_eq!(built_of(&h(0x32)), Some(h(0x31)));
        assert_eq!(get(&h(0x32)), Some(fields));
        // A waiter on the sealed hash is woken by the builder's entry.
        let waiter = std::thread::spawn(move || wait_for(&h(0x34), std::time::Duration::from_secs(2)));
        note_built(h(0x34), h(0x33));
        std::thread::sleep(std::time::Duration::from_millis(30));
        remember(h(0x33), fields);
        assert_eq!(waiter.join().expect("the waiter"), Some(fields));
        // Re-sealed after a view change: the new sealed hash follows too, and
        // re-noting a sealed hash replaces its builder hash.
        note_built(h(0x35), h(0x31));
        assert_eq!(get(&h(0x35)), Some(fields));
        note_built(h(0x35), h(0x36));
        assert_eq!(get(&h(0x35)), None, "the newer note wins");
        // A self-alias is never noted; old aliases fall out.
        note_built(h(0x37), h(0x37));
        assert_eq!(built_of(&h(0x37)), None);
        for i in 0..(ALIASES_KEPT as u8 + 2) {
            note_built(h(0x40 + i), h(0x31));
        }
        assert_eq!(built_of(&h(0x32)), None, "the oldest aliases are evicted");
    }
}
