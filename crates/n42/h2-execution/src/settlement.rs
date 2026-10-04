// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The forkchoice's `safe` and `finalized` hashes under HotStuff-2
//! (`docs/PHASE_D_DEFERRED_EXECUTION.md` section 17).
//!
//! | Tag | Meaning (`split`, the default) |
//! |---|---|
//! | `latest` (head) | committed by consensus |
//! | `safe` | execution certified: the block's execution fields are in a committed child's header (deferred execution), or the block itself was committed by import-gated votes (before the fork) |
//! | `finalized` | certified **and** at or below this node's last persisted block |
//!
//! `finalized` trails `safe`, which trails the head, and neither ever moves
//! backwards. `N42_SETTLEMENT_TAGS=legacy` sends head = safe = finalized =
//! the committed block, as every release before this one did.
//!
//! All of this is node-local Engine API state: nothing here changes what a
//! validator signs, sends or checks.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use alloy_primitives::B256;
use tracing::{debug, warn};

/// The environment variable that picks the [`SettlementTags`] mode.
pub const SETTLEMENT_TAGS_ENV: &str = "N42_SETTLEMENT_TAGS";

/// What the forkchoice's `safe` and `finalized` hashes mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SettlementTags {
    /// `safe` = certified, `finalized` = certified and persisted here.
    #[default]
    Split,
    /// head = safe = finalized = the committed block (the behaviour before
    /// the split), for A/B legs.
    Legacy,
}

/// Parses an [`SETTLEMENT_TAGS_ENV`] value; unset or empty is the default.
pub fn parse_settlement_tags(value: Option<&str>) -> Result<SettlementTags, String> {
    match value.map(str::trim) {
        None | Some("") | Some("split") => Ok(SettlementTags::Split),
        Some("legacy") => Ok(SettlementTags::Legacy),
        Some(other) => Err(format!("{SETTLEMENT_TAGS_ENV}={other}: expected split or legacy")),
    }
}

/// [`SETTLEMENT_TAGS_ENV`], read once. A value that does not parse is
/// reported and the default is used.
pub fn settlement_tags() -> SettlementTags {
    static MODE: std::sync::OnceLock<SettlementTags> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| {
        let raw = std::env::var(SETTLEMENT_TAGS_ENV).ok();
        parse_settlement_tags(raw.as_deref()).unwrap_or_else(|err| {
            warn!(target: "n42.h2.el", %err, "using the default settlement tags (split)");
            SettlementTags::Split
        })
    })
}

/// This node's last persisted block, as its execution layer reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistedHeight {
    /// The block number of the last persisted canonical block.
    Known(u64),
    /// Not known right now (no reading yet, or the last one failed):
    /// `finalized` holds where it is.
    Unknown,
    /// The execution layer does not report it at all (an execution layer
    /// without the method): `finalized` follows `safe`, and the node says so
    /// once.
    NotReported,
}

/// Reads [`PersistedHeight`]; called on the consensus loop, so it must not
/// block (the node's is an atomic a poller fills).
pub type PersistedSource = Arc<dyn Fn() -> PersistedHeight + Send + Sync>;

/// A block on the committed chain, by number and hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    /// Block number.
    pub number: u64,
    /// Block hash.
    pub hash: B256,
}

/// What the driver knows about a block's place in the chain.
#[derive(Debug, Clone, Copy)]
struct Link {
    number: u64,
    parent: B256,
    timestamp: u64,
}

/// Number, parent and timestamp of the blocks the driver has seen, bounded,
/// so a tag can be checked against a head and walked down to a height
/// without asking the execution layer.
#[derive(Debug)]
struct Lineage {
    links: HashMap<B256, Link>,
    order: VecDeque<B256>,
}

impl Lineage {
    /// Enough for reth's persistence backpressure bound on the fleet
    /// (1024 unpersisted blocks) with room for side blocks.
    const CAP: usize = 4096;

    fn new() -> Self {
        Self { links: HashMap::new(), order: VecDeque::new() }
    }

    fn note(&mut self, hash: B256, link: Link) {
        if self.links.insert(hash, link).is_none() {
            self.order.push_back(hash);
            while self.order.len() > Self::CAP {
                if let Some(oldest) = self.order.pop_front() {
                    self.links.remove(&oldest);
                }
            }
        }
    }

    fn get(&self, hash: &B256) -> Option<Link> {
        self.links.get(hash).copied()
    }

    /// The ancestor of `hash` (or `hash` itself) at `number`, if every link
    /// between them is known.
    fn ancestor_at(&self, hash: B256, number: u64) -> Option<B256> {
        let mut current = hash;
        loop {
            let link = self.get(&current)?;
            if link.number == number {
                return Some(current);
            }
            if link.number < number {
                return None;
            }
            if link.number - 1 == number {
                return Some(link.parent);
            }
            current = link.parent;
        }
    }
}

/// The driver's settlement state: the mode, the two tags, and what they are
/// derived from.
pub(crate) struct Settlement {
    mode: SettlementTags,
    safe: Option<Tag>,
    finalized: Option<Tag>,
    lineage: Lineage,
    persisted: Option<PersistedSource>,
    said_not_reported: bool,
}

impl std::fmt::Debug for Settlement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settlement")
            .field("mode", &self.mode)
            .field("safe", &self.safe)
            .field("finalized", &self.finalized)
            .field("lineage", &self.lineage.links.len())
            .field("persisted", &self.persisted.is_some())
            .finish()
    }
}

impl Settlement {
    pub(crate) fn new(mode: SettlementTags) -> Self {
        Self { mode, safe: None, finalized: None, lineage: Lineage::new(), persisted: None, said_not_reported: false }
    }

    pub(crate) const fn mode(&self) -> SettlementTags {
        self.mode
    }

    pub(crate) fn set_mode(&mut self, mode: SettlementTags) {
        self.mode = mode;
    }

    pub(crate) fn set_persisted(&mut self, source: PersistedSource) {
        self.persisted = Some(source);
    }

    /// Both tags start at `genesis` (block 0): a fresh chain, where genesis
    /// is certified and persisted by definition. A restarted node sets no
    /// floor: until the first commit moves them, its forkchoices carry zero
    /// tags, which the engine reads as "unchanged", so the tags it restored
    /// from disk stay as they are rather than being sent back to genesis.
    pub(crate) fn set_floor(&mut self, genesis: B256) {
        let floor = Tag { number: 0, hash: genesis };
        if self.safe.is_none() {
            self.safe = Some(floor);
        }
        if self.finalized.is_none() {
            self.finalized = Some(floor);
        }
    }

    pub(crate) const fn safe(&self) -> Option<Tag> {
        self.safe
    }

    pub(crate) const fn finalized(&self) -> Option<Tag> {
        self.finalized
    }

    /// Records a block's number, parent and timestamp.
    pub(crate) fn note(&mut self, hash: B256, number: u64, parent: B256, timestamp: u64) {
        self.lineage.note(hash, Link { number, parent, timestamp });
    }

    /// Whether the driver already knows `hash`'s place in the chain.
    pub(crate) fn knows(&self, hash: &B256) -> bool {
        self.lineage.links.contains_key(hash)
    }

    /// `committed` was committed by consensus: moves `safe` to the newest
    /// block whose execution that commit certifies and `finalized` to the
    /// newest certified block at or below the persisted height. Both only
    /// move forward; a commit for a block the driver has no lineage for
    /// moves nothing.
    ///
    /// `deferred` says whether a block with this timestamp is under deferred
    /// execution: its header carries its parent's execution fields, so its
    /// commit (a quorum on it, each voter having checked those fields against
    /// its own result) certifies the parent. Before the fork every vote is
    /// import-gated, so a commit certifies the block itself.
    pub(crate) fn advance(&mut self, committed: B256, deferred: impl Fn(u64) -> bool) {
        if self.mode == SettlementTags::Legacy {
            return;
        }
        let Some(link) = self.lineage.get(&committed) else {
            debug!(target: "n42.h2.el", block = ?committed, "a commit with no known lineage; settlement tags stay");
            return;
        };
        let certified = if deferred(link.timestamp) {
            link.number.checked_sub(1).map(|number| Tag { number, hash: link.parent })
        } else {
            Some(Tag { number: link.number, hash: committed })
        };
        if let Some(certified) = certified
            && self.safe.is_none_or(|safe| certified.number > safe.number)
        {
            self.safe = Some(certified);
        }
        let Some(safe) = self.safe else { return };
        let ceiling = match self.persisted.as_ref().map_or(PersistedHeight::NotReported, |read| read()) {
            PersistedHeight::Known(persisted) => safe.number.min(persisted),
            PersistedHeight::Unknown => return,
            PersistedHeight::NotReported => {
                if !self.said_not_reported {
                    self.said_not_reported = true;
                    warn!(target: "n42.h2.el", "the execution layer does not report its persisted block; finalized follows safe");
                }
                safe.number
            }
        };
        if self.finalized.is_some_and(|finalized| ceiling <= finalized.number) {
            return;
        }
        let hash = if ceiling == safe.number {
            Some(safe.hash)
        } else {
            self.lineage.ancestor_at(safe.hash, ceiling).or_else(|| self.lineage.ancestor_at(committed, ceiling))
        };
        if let Some(hash) = hash {
            self.finalized = Some(Tag { number: ceiling, hash });
        }
    }

    /// The `(safe, finalized)` hashes a forkchoice to `head` carries. A tag
    /// that is not provably an ancestor of `head` (or `head` itself) goes as
    /// zero, which the engine reads as "unchanged": a forkchoice whose safe
    /// or finalized block is off the head's chain is refused outright.
    pub(crate) fn tags_for(&self, head: B256) -> (B256, B256) {
        let on_chain = |tag: Option<Tag>| match tag {
            Some(tag) if self.is_ancestor(tag, head) => tag.hash,
            _ => B256::ZERO,
        };
        (on_chain(self.safe), on_chain(self.finalized))
    }

    fn is_ancestor(&self, tag: Tag, head: B256) -> bool {
        // Height 0 is only ever the floor: genesis, beneath every head.
        tag.number == 0 || tag.hash == head || self.lineage.ancestor_at(head, tag.number) == Some(tag.hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> B256 {
        B256::repeat_byte(n)
    }

    /// A chain 1..=n on genesis h(0), block i hashed h(i), timestamp i.
    fn chain(settlement: &mut Settlement, n: u8) {
        for i in 1..=n {
            settlement.note(h(i), u64::from(i), h(i - 1), u64::from(i));
        }
    }

    fn persisted(at: u64) -> PersistedSource {
        Arc::new(move || PersistedHeight::Known(at))
    }

    #[test]
    fn the_mode_parses() {
        assert_eq!(parse_settlement_tags(None), Ok(SettlementTags::Split));
        assert_eq!(parse_settlement_tags(Some("")), Ok(SettlementTags::Split));
        assert_eq!(parse_settlement_tags(Some("split")), Ok(SettlementTags::Split));
        assert_eq!(parse_settlement_tags(Some("legacy")), Ok(SettlementTags::Legacy));
        assert!(parse_settlement_tags(Some("finalized")).is_err());
    }

    #[test]
    fn under_deferred_execution_safe_is_the_parent_and_finalized_is_capped_by_persistence() {
        let mut s = Settlement::new(SettlementTags::Split);
        s.set_floor(h(0));
        s.set_persisted(persisted(3));
        chain(&mut s, 8);
        s.advance(h(8), |_| true);
        assert_eq!(s.safe(), Some(Tag { number: 7, hash: h(7) }));
        assert_eq!(s.finalized(), Some(Tag { number: 3, hash: h(3) }));
        assert_eq!(s.tags_for(h(8)), (h(7), h(3)));
    }

    #[test]
    fn before_the_fork_a_commit_certifies_the_block_itself() {
        let mut s = Settlement::new(SettlementTags::Split);
        s.set_persisted(persisted(100));
        chain(&mut s, 4);
        s.advance(h(4), |_| false);
        assert_eq!(s.safe(), Some(Tag { number: 4, hash: h(4) }));
        assert_eq!(s.finalized(), Some(Tag { number: 4, hash: h(4) }));
    }

    #[test]
    fn neither_tag_moves_backwards() {
        let mut s = Settlement::new(SettlementTags::Split);
        s.set_persisted(persisted(100));
        chain(&mut s, 6);
        s.advance(h(6), |_| true);
        s.advance(h(3), |_| true);
        assert_eq!(s.safe().map(|t| t.number), Some(5));
        assert_eq!(s.finalized().map(|t| t.number), Some(5));
    }

    #[test]
    fn an_unknown_persisted_height_holds_finalized_and_an_unreported_one_follows_safe() {
        let mut s = Settlement::new(SettlementTags::Split);
        s.set_persisted(Arc::new(|| PersistedHeight::Unknown));
        chain(&mut s, 3);
        s.advance(h(3), |_| true);
        assert_eq!(s.safe().map(|t| t.number), Some(2));
        assert_eq!(s.finalized(), None);
        s.set_persisted(Arc::new(|| PersistedHeight::NotReported));
        s.advance(h(3), |_| true);
        assert_eq!(s.finalized(), Some(Tag { number: 2, hash: h(2) }));
    }

    #[test]
    fn a_commit_without_lineage_moves_nothing_and_legacy_never_moves() {
        let mut s = Settlement::new(SettlementTags::Split);
        s.advance(h(9), |_| true);
        assert_eq!((s.safe(), s.finalized()), (None, None));
        let mut legacy = Settlement::new(SettlementTags::Legacy);
        chain(&mut legacy, 3);
        legacy.advance(h(3), |_| true);
        assert_eq!((legacy.safe(), legacy.finalized()), (None, None));
    }

    #[test]
    fn a_tag_off_the_heads_chain_goes_as_zero() {
        let mut s = Settlement::new(SettlementTags::Split);
        s.set_persisted(persisted(100));
        chain(&mut s, 5);
        s.advance(h(5), |_| true);
        // A head below the tags, and a head on a branch the driver knows
        // nothing about: neither may carry them.
        assert_eq!(s.tags_for(h(2)), (B256::ZERO, B256::ZERO));
        assert_eq!(s.tags_for(h(0xee)), (B256::ZERO, B256::ZERO));
        // A sibling of block 5 on block 4 carries both.
        s.note(h(0x55), 5, h(4), 5);
        assert_eq!(s.tags_for(h(0x55)), (h(4), h(4)));
        // The genesis floor is beneath every head.
        let mut fresh = Settlement::new(SettlementTags::Split);
        fresh.set_floor(h(0));
        assert_eq!(fresh.tags_for(h(0xee)), (h(0), h(0)));
    }
}
