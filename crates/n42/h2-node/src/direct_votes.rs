// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Votes sent straight to the view's leader (`N42_VOTE_TRANSPORT`).
//!
//! `gossip` (the default) is the v4 behaviour: a vote is published to the
//! mesh like everything else. `direct` sends it to the leader over
//! `n42_h2_net::VOTE_PROTOCOL` when the leader's peer id is known, and by
//! gossip otherwise; `both` does both. The leader's peer id is learnt from
//! the hello each member sends on connect (signed by its consensus key, so a
//! peer cannot claim another validator's votes). A node announces itself only
//! when it runs `direct` or `both`, so the default sends nothing new. The
//! gossip path is byte-identical in every mode; a member that does not speak
//! the protocol (any gov5 node) is reached by gossip, so a mixed fleet runs
//! `gossip` or `both`.
//!
//! A leader may receive one vote by both paths. Duplicates are dropped before
//! the engine, keyed by (round, view, voter, signature): a real vote's two
//! copies are the same bytes, and a forged vote for the same (view, voter)
//! cannot shadow the real one because its signature differs.

use std::collections::{HashMap, HashSet, VecDeque};

use n42_h2_net::PeerId;
use n42_h2_primitives::consensus::ConsensusMessage;

/// How votes travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VoteTransport {
    /// Published to the mesh only (v4, gov5).
    #[default]
    Gossip,
    /// Straight to the leader; by gossip when its peer id is unknown.
    Direct,
    /// Both.
    Both,
}

impl VoteTransport {
    /// `N42_VOTE_TRANSPORT=direct|both|gossip`; anything else is `gossip`.
    pub fn from_env() -> Self {
        match std::env::var("N42_VOTE_TRANSPORT").as_deref() {
            Ok("direct") => Self::Direct,
            Ok("both") => Self::Both,
            _ => Self::Gossip,
        }
    }
}

/// Votes remembered for de-duplication.
const DEDUPE_CAPACITY: usize = 8192;

type VoteKey = (bool, u64, u32, [u8; 96]);

/// The direct vote path's state on one node.
#[derive(Debug, Default)]
pub struct DirectVotes {
    mode: VoteTransport,
    peers: HashMap<u32, PeerId>,
    seen: HashSet<VoteKey>,
    order: VecDeque<VoteKey>,
    /// A direct vote has arrived: de-duplication is on from then.
    direct_seen: bool,
    /// Votes this node sent directly.
    pub sent: u64,
    /// Votes that arrived directly.
    pub received: u64,
    /// Copies dropped as duplicates.
    pub duplicates: u64,
    /// Votes that went by gossip because the leader's peer id was unknown
    /// (`direct` mode).
    pub fallbacks: u64,
}

impl DirectVotes {
    /// A fresh state for `mode`.
    pub fn new(mode: VoteTransport) -> Self {
        Self {
            mode,
            ..Self::default()
        }
    }

    /// The configured mode.
    pub const fn mode(&self) -> VoteTransport {
        self.mode
    }

    /// Whether this node announces itself (sends hellos).
    pub fn announces(&self) -> bool {
        self.mode != VoteTransport::Gossip
    }

    /// Records a verified hello: validator `index` is at `peer`.
    pub fn learn(&mut self, index: u32, peer: PeerId) {
        self.peers.insert(index, peer);
    }

    /// Forgets every validator mapped to `peer` (it disconnected).
    pub fn forget_peer(&mut self, peer: &PeerId) {
        self.peers.retain(|_, p| p != peer);
    }

    /// Where validator `index`'s votes go directly, if known.
    pub fn peer_of(&self, index: u32) -> Option<PeerId> {
        self.peers.get(&index).copied()
    }

    /// Notes a vote that arrived directly.
    pub const fn note_direct(&mut self) {
        self.direct_seen = true;
        self.received += 1;
    }

    /// Whether `message` should reach the engine: false for a second copy of
    /// a vote while de-duplication is on (this node sends directly, or has
    /// received a direct vote). Anything but a vote is always admitted.
    pub fn admit(&mut self, message: &ConsensusMessage) -> bool {
        if self.mode == VoteTransport::Gossip && !self.direct_seen {
            return true;
        }
        let key = match message {
            ConsensusMessage::Vote(v) => (false, v.view, v.voter, v.signature.to_bytes()),
            ConsensusMessage::CommitVote(v) => (true, v.view, v.voter, v.signature.to_bytes()),
            _ => return true,
        };
        if !self.seen.insert(key) {
            self.duplicates += 1;
            return false;
        }
        self.order.push_back(key);
        while self.order.len() > DEDUPE_CAPACITY {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use n42_h2_primitives::{consensus::Vote, BlsSecretKey};

    fn vote(view: u64, voter: u32, key: &BlsSecretKey) -> ConsensusMessage {
        ConsensusMessage::Vote(Vote {
            view,
            block_hash: B256::repeat_byte(1),
            voter,
            signature: key.sign(&view.to_be_bytes()),
        })
    }

    #[test]
    fn the_default_is_gossip_and_admits_everything() {
        assert_eq!(VoteTransport::default(), VoteTransport::Gossip);
        let key = BlsSecretKey::random().expect("key");
        let mut direct = DirectVotes::new(VoteTransport::Gossip);
        assert!(!direct.announces());
        assert!(direct.admit(&vote(1, 2, &key)));
        assert!(direct.admit(&vote(1, 2, &key)), "off: the engine dedupes as it always did");
    }

    /// A vote that arrives by both paths reaches the engine once; a forged
    /// copy with another signature is not taken for the real one.
    #[test]
    fn a_vote_by_both_paths_counts_once() {
        let key = BlsSecretKey::random().expect("key");
        let forger = BlsSecretKey::random().expect("key");
        let mut leader = DirectVotes::new(VoteTransport::Gossip);
        let real = vote(5, 3, &key);
        leader.note_direct();
        assert!(leader.admit(&real), "first copy (direct)");
        assert!(!leader.admit(&real), "second copy (gossip)");
        assert_eq!(leader.duplicates, 1);
        assert!(leader.admit(&vote(5, 3, &forger)), "a different signature is a different vote");
        assert!(leader.admit(&vote(6, 3, &key)), "another view");
    }

    #[test]
    fn hellos_map_validators_to_peers_until_they_disconnect() {
        let mut direct = DirectVotes::new(VoteTransport::Direct);
        assert!(direct.announces());
        let peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        assert_eq!(direct.peer_of(1), None);
        direct.learn(1, peer);
        assert_eq!(direct.peer_of(1), Some(peer));
        direct.forget_peer(&peer);
        assert_eq!(direct.peer_of(1), None);
    }
}
