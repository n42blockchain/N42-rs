// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A cache of 0x50 senders by transaction hash, shared by every path that
//! verifies signatures.
//!
//! reth's `SenderRecoveryCache` can only be filled through its own
//! recover-or-insert, one transaction at a time, which is exactly what batch
//! verification avoids. This cache is filled by whoever verified a batch (the
//! ingest, a follower's import) and read by the paths that would otherwise
//! verify again: the block import, the engine's own payload conversion. A
//! miss costs one verification; a hit costs a lookup.
//!
//! Sized by `N42_ALTSIG_SENDER_CACHE` (entries, a power of two; default 2^20,
//! about six blocks of the bench tier).

use alloy_primitives::{map::FbBuildHasher, Address, B256};
use std::sync::OnceLock;

struct Config;

impl fixed_cache::CacheConfig for Config {
    const STATS: bool = false;
}

/// The shared sender cache for 0x50 transactions.
pub struct AltSigSenderCache {
    cache: fixed_cache::Cache<B256, Address, FbBuildHasher<32>, Config>,
}

impl std::fmt::Debug for AltSigSenderCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AltSigSenderCache").finish_non_exhaustive()
    }
}

impl AltSigSenderCache {
    /// A cache of `entries` slots; `entries` is rounded up to a power of two
    /// of at least four.
    pub fn new(entries: usize) -> Self {
        let entries = entries.max(4).next_power_of_two();
        Self { cache: fixed_cache::Cache::new(entries, FbBuildHasher::<32>::default()) }
    }

    /// The process-wide cache.
    pub fn global() -> &'static Self {
        static GLOBAL: OnceLock<AltSigSenderCache> = OnceLock::new();
        GLOBAL.get_or_init(|| {
            let entries = std::env::var("N42_ALTSIG_SENDER_CACHE")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1 << 20);
            Self::new(entries)
        })
    }

    /// The sender recorded for `hash`, if any.
    pub fn get(&self, hash: &B256) -> Option<Address> {
        self.cache.get(hash)
    }

    /// Records `sender` for `hash`.
    pub fn insert(&self, hash: B256, sender: Address) {
        self.cache.insert(hash, sender);
    }
}

static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether this chain admits 0x50 transactions. Off until the node reads its
/// genesis (`altSigTx: true`) and says so with [`set_alt_sig_enabled`]; off,
/// the ingest drops them and block validation rejects a block carrying one.
pub fn alt_sig_enabled() -> bool {
    ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Records whether the chain admits 0x50 transactions.
pub fn set_alt_sig_enabled(enabled: bool) {
    ENABLED.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// Whether this node takes an ingested transaction's sender from the frame
/// that carried it instead of recovering it from the signature:
/// `N42_INGEST_VERIFY=leader`, against the default `all`.
///
/// The supply is a ceiling every member pays alike: each one ingests every
/// transaction and verifies its signature there -- ~11 us of CPU each -- on
/// the same cores its import and its build run on. Only a node about to
/// *build* needs the sender at ingest. A follower meets every transaction
/// again inside a block, where the vote road resolves senders anyway, so it
/// can hold the frame's word for the sender -- a claim -- and pay the
/// signature once, in batch, where the block is checked.
///
/// A claim is never an answer:
///
/// * the queue's lane is keyed by the claimed sender, so a wrong claim can
///   only misplace that one transaction in that one lane; it cannot be
///   mined, because nothing downstream takes the lane's key for a sender;
/// * a build on this node verifies every claimed transaction before it
///   includes it, in batch, and drops one whose signature says otherwise;
/// * the vote road verifies every transaction of a block whose sender it
///   holds only as a claim, compares the two, and refuses the block on a
///   mismatch -- all before the vote is released.
///
/// Read once, so a node's mode cannot change under a build.
pub fn senders_claimed_at_ingest() -> bool {
    static CLAIMED: OnceLock<bool> = OnceLock::new();
    *CLAIMED.get_or_init(|| {
        std::env::var("N42_INGEST_VERIFY").is_ok_and(|mode| mode.eq_ignore_ascii_case("leader"))
    })
}

/// `N42_INGEST_VERIFY=shard` with `N42_INGEST_SHARD=<i>/<n>`: this node's
/// shard of the ingest's signature work, as `(i, n)`, or `None` in any other
/// mode.
///
/// **A benchmark probe, unsafe under any fault** (form C of
/// `docs/VERIFY_ONCE_DESIGN.md`). A transaction whose hash falls in shard
/// `i` ([`shard_owner`]) is verified at ingest as under `all`; every other
/// one is admitted under the sender its frame claimed and recorded under
/// that claim in the sender cache -- and, unlike `leader`, *nothing
/// downstream re-verifies it*: not the builder (`claimed_build` sees the mode
/// off), not the vote road (it reads the cache's claim as an answer). A
/// generator that lies, or one faulty node, puts an unverified sender in a
/// block. It exists to measure what the sharded design (form B, with f+1
/// owners per shard and attestations) would deliver, and nothing else.
///
/// A malformed or missing `N42_INGEST_SHARD` reads as `None` here; the node
/// refuses to start on it first ([`ingest_verify_mode`]).
pub fn ingest_shard() -> Option<(u64, u64)> {
    static SHARD: OnceLock<Option<(u64, u64)>> = OnceLock::new();
    *SHARD.get_or_init(|| match ingest_verify_mode() {
        Ok(IngestVerify::Shard { index, count }) => Some((index, count)),
        _ => None,
    })
}

/// The ingest's verification mode, from `N42_INGEST_VERIFY` (and
/// `N42_INGEST_SHARD` for `shard`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestVerify {
    /// Every signature verified at ingest (the default, and any value this
    /// does not name).
    All,
    /// Claims queued unverified; the builder and the vote road verify them.
    Leader,
    /// This node verifies shard `index` of `count` at ingest and trusts the
    /// claim for the rest, with no re-verification anywhere (a probe).
    Shard {
        /// This node's shard.
        index: u64,
        /// The number of shards (nodes).
        count: u64,
    },
}

/// Reads the ingest's mode from the environment. An error only for `shard`
/// with `N42_INGEST_SHARD` missing or not `<i>/<n>` with `i < n`; the node
/// checks this at start and refuses to run on an error.
pub fn ingest_verify_mode() -> Result<IngestVerify, String> {
    parse_ingest_verify(
        std::env::var("N42_INGEST_VERIFY").ok().as_deref(),
        std::env::var("N42_INGEST_SHARD").ok().as_deref(),
    )
}

/// [`ingest_verify_mode`] on given values rather than the environment.
pub fn parse_ingest_verify(verify: Option<&str>, shard: Option<&str>) -> Result<IngestVerify, String> {
    let Some(verify) = verify else { return Ok(IngestVerify::All) };
    if verify.eq_ignore_ascii_case("leader") {
        return Ok(IngestVerify::Leader);
    }
    if !verify.eq_ignore_ascii_case("shard") {
        return Ok(IngestVerify::All);
    }
    let shard = shard.ok_or_else(|| {
        "N42_INGEST_VERIFY=shard needs N42_INGEST_SHARD=<index>/<count> (e.g. 0/3)".to_string()
    })?;
    let malformed = || format!("N42_INGEST_SHARD={shard:?} is not <index>/<count> with index < count (e.g. 0/3)");
    let (index, count) = shard.trim().split_once('/').ok_or_else(malformed)?;
    let index: u64 = index.trim().parse().map_err(|_| malformed())?;
    let count: u64 = count.trim().parse().map_err(|_| malformed())?;
    if count == 0 || index >= count {
        return Err(malformed());
    }
    Ok(IngestVerify::Shard { index, count })
}

/// The shard a transaction belongs to among `count`: the first eight bytes of
/// its hash, little-endian, modulo `count`.
pub fn shard_owner(hash: &B256, count: u64) -> u64 {
    let mut first = [0u8; 8];
    first.copy_from_slice(&hash[..8]);
    u64::from_le_bytes(first) % count.max(1)
}

/// The batch size for Ed25519 verification, from `N42_ED25519_BATCH`
/// (default 64, at most 256: the per-signature gain flattens past 64 and a
/// failed batch is retried one by one).
pub fn ed25519_batch_size() -> usize {
    static SIZE: OnceLock<usize> = OnceLock::new();
    *SIZE.get_or_init(|| {
        std::env::var("N42_ED25519_BATCH")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(64)
            .min(256)
    })
}

/// A cache of Ed25519 verifying keys by their 32 bytes, decompressed once.
///
/// `VerifyingKey::from_bytes` decompresses the point (a square root, ~250
/// field squarings), and the batch verifier was paying it for every
/// signature: on the loop136 profile `pow2k` alone was 19% of an execution
/// layer's CPU with the same few thousand senders signing every block. The
/// key is the sender's, and senders repeat; `N42_ED25519_KEY_CACHE=0` turns
/// the cache off. Bounded by sharding: each of 256 shards keeps at most
/// `KEY_SHARD_CAP` keys and is cleared when full.
const KEY_SHARDS: usize = 256;
const KEY_SHARD_CAP: usize = 1024; // 256 shards x 1024 keys x ~200 B: ~50 MB at most

type KeyShard = std::sync::RwLock<std::collections::HashMap<[u8; 32], ed25519_dalek::VerifyingKey, FbBuildHasher<32>>>;

fn key_shards() -> Option<&'static [KeyShard]> {
    static SHARDS: OnceLock<Option<Box<[KeyShard]>>> = OnceLock::new();
    SHARDS
        .get_or_init(|| {
            if std::env::var("N42_ED25519_KEY_CACHE").is_ok_and(|v| v == "0") {
                return None;
            }
            Some((0..KEY_SHARDS).map(|_| std::sync::RwLock::new(Default::default())).collect())
        })
        .as_deref()
}

/// The verifying key for `bytes`, from the cache or decompressed and cached;
/// `None` for bytes that are not a point (the caller reports the error).
/// A weak (small-order) key is never cached, so the caller's rejection of it
/// stays on the caller's path.
pub fn verifying_key(bytes: &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey> {
    let Some(shards) = key_shards() else {
        return ed25519_dalek::VerifyingKey::from_bytes(bytes).ok();
    };
    let shard = &shards[bytes[0] as usize];
    if let Some(found) = shard.read().unwrap_or_else(|p| p.into_inner()).get(bytes) {
        return Some(*found);
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(bytes).ok()?;
    if key.is_weak() {
        return Some(key);
    }
    let mut shard = shard.write().unwrap_or_else(|p| p.into_inner());
    if shard.len() >= KEY_SHARD_CAP {
        shard.clear();
    }
    shard.insert(*bytes, key);
    Some(key)
}

#[cfg(test)]
mod shard_tests {
    use super::*;

    /// The owner is the hash's first eight bytes, little-endian, modulo the
    /// count -- the rule every node of the probe must share.
    #[test]
    fn a_hash_belongs_to_the_shard_its_first_eight_bytes_name() {
        let mut hash = B256::ZERO;
        hash[0] = 7; // little-endian: the lowest byte
        assert_eq!(shard_owner(&hash, 3), 7 % 3);
        assert_eq!(shard_owner(&hash, 1), 0);
        hash[8] = 0xff; // past the first eight bytes: ignored
        assert_eq!(shard_owner(&hash, 3), 1);
        let mut high = B256::ZERO;
        high[7] = 1; // 1 << 56
        assert_eq!(shard_owner(&high, 3), (1u64 << 56) % 3);
        // Every shard gets a share of a spread of hashes.
        let mut seen = [0u32; 3];
        for i in 0u64..300 {
            seen[shard_owner(&alloy_primitives::keccak256(i.to_le_bytes()), 3) as usize] += 1;
        }
        assert!(seen.iter().all(|&n| n > 60), "{seen:?}");
    }

    #[test]
    fn the_mode_is_parsed_and_a_bad_shard_is_refused() {
        assert_eq!(parse_ingest_verify(None, None), Ok(IngestVerify::All));
        assert_eq!(parse_ingest_verify(Some("all"), Some("0/3")), Ok(IngestVerify::All));
        assert_eq!(parse_ingest_verify(Some("LEADER"), None), Ok(IngestVerify::Leader));
        assert_eq!(
            parse_ingest_verify(Some("shard"), Some("2/3")),
            Ok(IngestVerify::Shard { index: 2, count: 3 })
        );
        for bad in [None, Some("3/3"), Some("0/0"), Some("1"), Some("a/3"), Some("-1/3"), Some("")] {
            assert!(parse_ingest_verify(Some("shard"), bad).is_err(), "{bad:?}");
        }
    }
}

