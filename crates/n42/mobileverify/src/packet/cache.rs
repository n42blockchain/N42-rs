// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The packet window a node serves (`internal/mobileverify/packetcache.go`)
//! and the checks an incoming packet passes (`packetservice.go:144-182`).
//!
//! Packets are keyed by the sealed block hash. The window keeps blocks with
//! `number ≥ max_seen − window` (eviction runs when a new maximum arrives);
//! a peer's packet is refused past 8 per height, and outside
//! `[head − window, head + 2]` of the local head.

use std::collections::HashMap;

use alloy_primitives::B256;
use bytes::Bytes;
use parking_lot::RwLock;

use super::header::unmarshal_header;
use super::stream::StreamPacket;

/// Default `packet_window`.
pub const DEFAULT_PACKET_WINDOW: u64 = 256;
/// Peer packets accepted per height (`maxPeerPacketsPerHeight`).
pub const MAX_PEER_PACKETS_PER_HEIGHT: usize = 8;
/// How far past the local head a peer's packet may be.
pub const MAX_FUTURE_SKEW: u64 = 2;

/// Why an incoming packet was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacketValidationError {
    /// The packet does not decode.
    #[error("mobileverify: decode: {0}")]
    Decode(#[from] super::stream::PacketError),
    /// The header does not decode.
    #[error("mobileverify: header unmarshal: {0}")]
    Header(#[from] super::header::HeaderCodecError),
    /// The header does not hash to the packet's block hash.
    #[error("mobileverify: packet block hash does not match its header")]
    HashMismatch,
    /// The number is outside the local head's window.
    #[error("mobileverify: packet number {number} outside the local head window (head {head})")]
    OutsideWindow {
        /// The packet's block number.
        number: u64,
        /// The local head.
        head: u64,
    },
    /// No committed head yet, so no window to check the number against.
    #[error("mobileverify: no local head to check the packet number against")]
    NoHead,
}

/// Decodes `data`, decodes its header and checks that the header hashes to
/// the packet's block hash (gov5 `ValidatePacketBytes`). Returns `(hash, number)`.
pub fn validate_packet_bytes(data: &[u8]) -> Result<(B256, u64), PacketValidationError> {
    let pkt = StreamPacket::decode(data)?;
    let header = unmarshal_header(&pkt.header)?;
    if header.hash_slow() != pkt.block_hash {
        return Err(PacketValidationError::HashMismatch);
    }
    Ok((pkt.block_hash, header.number))
}

#[derive(Debug, Default)]
struct Inner {
    by_hash: HashMap<B256, Bytes>,
    by_num: HashMap<u64, Vec<B256>>,
    max_num: u64,
}

/// The rolling window of encoded packets.
#[derive(Debug)]
pub struct PacketCache {
    window: u64,
    inner: RwLock<Inner>,
}

impl Default for PacketCache {
    fn default() -> Self {
        Self::new(DEFAULT_PACKET_WINDOW)
    }
}

impl PacketCache {
    /// A cache for blocks within `window` of the highest seen (0 means 256).
    pub fn new(window: u64) -> Self {
        Self { window: if window == 0 { DEFAULT_PACKET_WINDOW } else { window }, inner: RwLock::default() }
    }

    /// The window in blocks.
    pub const fn window(&self) -> u64 {
        self.window
    }

    /// Stores a packet this node trusts (its own or the loopback sidecar's).
    /// Idempotent per hash.
    pub fn put(&self, block_hash: B256, block_number: u64, encoded: Bytes) -> bool {
        self.insert(block_hash, block_number, encoded, false)
    }

    /// Stores a gossiped packet, bounded per height. `true` if new.
    pub fn put_peer(&self, block_hash: B256, block_number: u64, encoded: Bytes) -> bool {
        self.insert(block_hash, block_number, encoded, true)
    }

    fn insert(&self, hash: B256, number: u64, encoded: Bytes, peer: bool) -> bool {
        let mut inner = self.inner.write();
        if inner.by_hash.contains_key(&hash) {
            return false;
        }
        if peer && inner.by_num.get(&number).is_some_and(|v| v.len() >= MAX_PEER_PACKETS_PER_HEIGHT) {
            return false;
        }
        inner.by_hash.insert(hash, encoded);
        inner.by_num.entry(number).or_default().push(hash);
        if number > inner.max_num {
            inner.max_num = number;
            if inner.max_num > self.window {
                let floor = inner.max_num - self.window;
                let old: Vec<u64> = inner.by_num.keys().copied().filter(|n| *n < floor).collect();
                for n in old {
                    if let Some(hashes) = inner.by_num.remove(&n) {
                        for h in hashes {
                            inner.by_hash.remove(&h);
                        }
                    }
                }
            }
        }
        true
    }

    /// The encoded packet for a block hash.
    pub fn get(&self, block_hash: &B256) -> Option<Bytes> {
        self.inner.read().by_hash.get(block_hash).cloned()
    }

    /// Whether a packet for the block hash is cached.
    pub fn has(&self, block_hash: &B256) -> bool {
        self.inner.read().by_hash.contains_key(block_hash)
    }

    /// Number of cached packets.
    pub fn len(&self) -> usize {
        self.inner.read().by_hash.len()
    }

    /// Whether nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether a peer packet at `number` is inside the local head's window
    /// (gov5 `acceptPeerNumber`); `head = None` accepts everything.
    pub const fn accepts_peer_number(&self, number: u64, head: Option<u64>) -> bool {
        let Some(head) = head else { return true };
        if number > head && number - head > MAX_FUTURE_SKEW {
            return false;
        }
        !(head > self.window && number < head - self.window)
    }

    /// Encodes and caches a packet this node produced (gov5 `PublishLocal`,
    /// cache half; the caller gossips the returned bytes).
    pub fn publish_local(&self, pkt: &StreamPacket, block_number: u64) -> Bytes {
        let encoded = Bytes::from(pkt.encode());
        self.put(pkt.block_hash, block_number, encoded.clone());
        encoded
    }

    /// Validates a gossiped packet and caches it if it fits the window and
    /// the per-height bound. Returns `(hash, number, newly_inserted)`.
    ///
    /// Refused while `head` is `None` (a node before its first commit): gov5
    /// has a head from its database by then, while here an unchecked number
    /// near `u64::MAX` would pin `max_num` and end eviction for good.
    pub fn validate_incoming(
        &self,
        data: Bytes,
        head: Option<u64>,
    ) -> Result<(B256, u64, bool), PacketValidationError> {
        let (hash, number) = validate_packet_bytes(&data)?;
        let Some(head) = head else { return Err(PacketValidationError::NoHead) };
        if !self.accepts_peer_number(number, Some(head)) {
            return Err(PacketValidationError::OutsideWindow { number, head });
        }
        let new = self.put_peer(hash, number, data);
        Ok((hash, number, new))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::header::{EMPTY_UNCLE_HASH, marshal_header};
    use alloy_consensus::Header;
    use n42_header::N42Header;

    fn packet(number: u64) -> (StreamPacket, B256) {
        let h = N42Header::from(Header { number, ommers_hash: EMPTY_UNCLE_HASH, ..Default::default() });
        let hash = h.hash_slow();
        let pkt = StreamPacket {
            block_hash: hash,
            header: Bytes::from(marshal_header(&h)),
            read_log: Bytes::from_static(&[0, 0, 0, 0]),
            ..Default::default()
        };
        (pkt, hash)
    }

    #[test]
    fn window_eviction() {
        let c = PacketCache::new(4);
        for n in 0..10u64 {
            c.put(B256::from(U256Ext::from(n)), n, Bytes::from_static(b"x"));
        }
        // max 9, floor 5: 5..=9 remain.
        assert_eq!(c.len(), 5);
        assert!(!c.has(&B256::from(U256Ext::from(4))));
        assert!(c.has(&B256::from(U256Ext::from(5))));
        // An older block may still enter (eviction runs on a new maximum only).
        c.put(B256::repeat_byte(0xEE), 1, Bytes::from_static(b"y"));
        assert!(c.has(&B256::repeat_byte(0xEE)));
    }

    #[test]
    fn per_height_bound_for_peers() {
        let c = PacketCache::new(256);
        for i in 0..10u8 {
            c.put_peer(B256::repeat_byte(i + 1), 7, Bytes::from_static(b"x"));
        }
        assert_eq!(c.len(), 8);
        assert!(c.put(B256::repeat_byte(0x99), 7, Bytes::from_static(b"x")));
    }

    /// Without a local head there is no window to judge a peer's number by:
    /// one packet numbered near `u64::MAX` would pin `max_num`, after which no
    /// new maximum ever comes and nothing is evicted again.
    #[test]
    fn a_peer_packet_cannot_pin_the_window_before_the_head_is_known() {
        let c = PacketCache::new(4);
        let (pkt, _) = packet(u64::MAX);
        assert_eq!(c.validate_incoming(Bytes::from(pkt.encode()), None), Err(PacketValidationError::NoHead));
        assert!(c.is_empty());
        for n in 0..10u64 {
            c.put(B256::from(U256Ext::from(n)), n, Bytes::from_static(b"x"));
        }
        assert_eq!(c.len(), 5, "eviction still runs");
    }

    #[test]
    fn validation() {
        let c = PacketCache::new(256);
        let (pkt, hash) = packet(1000);
        let bytes = Bytes::from(pkt.encode());
        assert_eq!(validate_packet_bytes(&bytes).unwrap(), (hash, 1000));
        assert_eq!(c.validate_incoming(bytes.clone(), Some(998)).unwrap(), (hash, 1000, true));
        assert_eq!(c.validate_incoming(bytes.clone(), Some(998)).unwrap(), (hash, 1000, false));
        assert!(matches!(
            c.validate_incoming(bytes.clone(), Some(997)),
            Err(PacketValidationError::OutsideWindow { .. })
        ));
        assert!(c.validate_incoming(bytes.clone(), Some(1256)).is_ok());
        assert!(c.validate_incoming(bytes, Some(1257)).is_err());
        let mut forged = pkt;
        forged.block_hash = B256::repeat_byte(1);
        assert_eq!(
            validate_packet_bytes(&forged.encode()).unwrap_err(),
            PacketValidationError::HashMismatch
        );
        let (p2, h2) = packet(5);
        assert_eq!(c.publish_local(&p2, 5), Bytes::from(p2.encode()));
        assert!(c.has(&h2));
    }

    struct U256Ext;
    impl U256Ext {
        fn from(n: u64) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&n.to_be_bytes());
            b
        }
    }
}
