// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The mobile membership registry (`internal/mobileverify/registry.go`).
//!
//! Registrations are PoP-verified into a *pending* set; [`Registry::commit_epoch`]
//! folds them, sorted by `blake3(pubkey)`, into the append-only *committed*
//! set, where a device's index is its append position and the accumulator
//! maps `blake3(pubkey48)` to `BE8(index)`. Only active committed keys may
//! attest. Revoked keys keep their index slot (historical certificates still
//! resolve) and may never register again.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::B256;
use blst::min_pk::PublicKey;
use parking_lot::RwLock;

use crate::accumulator::{Accumulator, key_hash};
use crate::bls::{self, PUBKEY_LEN, SIGNATURE_LEN};
use crate::error::MobileVerifyError;
use crate::pop::verify_pop;

/// A device's append position in the committed set.
pub type MobileIndex = u32;

/// A 48-byte compressed public key.
pub type Pubkey = [u8; PUBKEY_LEN];
/// A 96-byte compressed signature (here: a proof of possession).
pub type Pop = [u8; SIGNATURE_LEN];

/// Callback fired after each new pending registration (the gossip relay hook).
pub type OnRegister = Arc<dyn Fn(&Pubkey, &Pop) + Send + Sync>;

/// Snapshot magic `"MVRS"`.
pub const SNAPSHOT_MAGIC: u32 = 0x4d56_5253;
/// Snapshot format version.
pub const SNAPSHOT_VERSION: u8 = 0x01;
/// Bytes per snapshot entry: pubkey ‖ pop ‖ active ‖ lastSeenMs.
pub const SNAPSHOT_ENTRY_LEN: usize = 48 + 96 + 1 + 8;

/// Milliseconds since the Unix epoch (gov5 `NowMs`).
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

#[derive(Clone)]
struct Committed {
    pubkey: Pubkey,
    pk: PublicKey,
    pop: Pop,
    active: bool,
    last_seen_ms: u64,
}

#[derive(Default)]
struct Inner {
    committed: Vec<Committed>,
    by_key: HashMap<Pubkey, MobileIndex>,
    known: HashMap<Pubkey, MobileIndex>,
    pending: HashMap<Pubkey, Pop>,
    tree: Accumulator,
}

/// The accumulator-backed registry. Thread safe.
#[derive(Default)]
pub struct Registry {
    inner: RwLock<Inner>,
    on_register: RwLock<Option<OnRegister>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read();
        f.debug_struct("Registry")
            .field("committed", &inner.committed.len())
            .field("active", &inner.by_key.len())
            .field("pending", &inner.pending.len())
            .field("root", &inner.tree.root())
            .finish()
    }
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the hook called after each new pending registration.
    pub fn set_on_register(&self, hook: OnRegister) {
        *self.on_register.write() = Some(hook);
    }

    /// Verifies the PoP and admits the key to the pending set. Idempotent:
    /// a committed key returns `(index, true)`, a pending one `(0, false)`;
    /// a revoked key is refused. The hook fires only for a new key.
    pub fn register(&self, pubkey: &Pubkey, pop: &Pop) -> Result<(MobileIndex, bool), MobileVerifyError> {
        verify_pop(pubkey, pop)?;
        {
            let mut inner = self.inner.write();
            if let Some(idx) = inner.by_key.get(pubkey) {
                return Ok((*idx, true));
            }
            if inner.known.contains_key(pubkey) {
                return Err(MobileVerifyError::KeyPreviouslyRegistered);
            }
            if inner.pending.contains_key(pubkey) {
                return Ok((0, false));
            }
            inner.pending.insert(*pubkey, *pop);
        }
        let hook = self.on_register.read().clone();
        if let Some(hook) = hook {
            hook(pubkey, pop);
        }
        Ok((0, false))
    }

    /// Admits a registration learned from a peer (no hook). Returns whether
    /// it was new.
    pub fn adopt_pending(&self, pubkey: &Pubkey, pop: &Pop) -> Result<bool, MobileVerifyError> {
        verify_pop(pubkey, pop)?;
        let mut inner = self.inner.write();
        if inner.by_key.contains_key(pubkey) || inner.known.contains_key(pubkey) || inner.pending.contains_key(pubkey) {
            return Ok(false);
        }
        inner.pending.insert(*pubkey, *pop);
        Ok(true)
    }

    /// Folds the pending set into the committed set (gov5 `CommitEpoch`) at
    /// the current wall clock.
    pub fn commit_epoch(&self) -> (B256, usize) {
        self.commit_epoch_at(now_ms())
    }

    /// [`Self::commit_epoch`] with an explicit `lastSeenMs` for the new entries.
    pub fn commit_epoch_at(&self, now_ms: u64) -> (B256, usize) {
        let mut inner = self.inner.write();
        if inner.pending.is_empty() {
            return (inner.tree.root(), 0);
        }
        let mut batch: Vec<(B256, Pubkey, Pop)> =
            inner.pending.drain().map(|(pk, pop)| (key_hash(&pk), pk, pop)).collect();
        batch.sort_by(|a, b| a.0.cmp(&b.0));
        let mut n = 0;
        for (kh, pubkey, pop) in batch {
            if inner.known.contains_key(&pubkey) {
                continue;
            }
            let Ok(pk) = bls::decode_pubkey(&pubkey) else { continue };
            let Ok(idx) = MobileIndex::try_from(inner.committed.len()) else { break };
            inner.committed.push(Committed { pubkey, pk, pop, active: true, last_seen_ms: now_ms });
            inner.by_key.insert(pubkey, idx);
            inner.known.insert(pubkey, idx);
            inner.tree.put(kh, u64::from(idx).to_be_bytes().to_vec());
            n += 1;
        }
        (inner.tree.root(), n)
    }

    /// The accumulator root; all zeros when nothing is committed.
    pub fn root(&self) -> B256 {
        self.inner.read().tree.root()
    }

    /// The index of an active committed key; `None` for pending, revoked or
    /// unknown keys.
    pub fn lookup(&self, pubkey: &Pubkey) -> Option<MobileIndex> {
        self.inner.read().by_key.get(pubkey).copied()
    }

    /// Refreshes a committed key's liveness.
    pub fn mark_active(&self, pubkey: &Pubkey) {
        self.mark_active_at(pubkey, now_ms());
    }

    /// [`Self::mark_active`] at an explicit time.
    pub fn mark_active_at(&self, pubkey: &Pubkey, now_ms: u64) {
        let mut inner = self.inner.write();
        if let Some(idx) = inner.by_key.get(pubkey).copied()
            && let Some(e) = inner.committed.get_mut(idx as usize)
        {
            e.last_seen_ms = now_ms;
        }
    }

    /// Revokes an active key: it leaves the accumulator, keeps its slot.
    pub fn revoke(&self, pubkey: &Pubkey) -> (B256, bool) {
        let mut inner = self.inner.write();
        let Some(idx) = inner.by_key.remove(pubkey) else { return (inner.tree.root(), false) };
        let _ = inner.tree.delete(&key_hash(pubkey));
        if let Some(e) = inner.committed.get_mut(idx as usize) {
            e.active = false;
        }
        (inner.tree.root(), true)
    }

    /// Revokes `old` and admits `new` (with its PoP) to the pending set.
    pub fn rotate(&self, old: &Pubkey, new: &Pubkey, new_pop: &Pop) -> Result<B256, MobileVerifyError> {
        verify_pop(new, new_pop)?;
        let mut inner = self.inner.write();
        if inner.known.contains_key(new) || inner.pending.contains_key(new) {
            return Err(MobileVerifyError::KeyPreviouslyRegistered);
        }
        if let Some(idx) = inner.by_key.remove(old) {
            let _ = inner.tree.delete(&key_hash(old));
            if let Some(e) = inner.committed.get_mut(idx as usize) {
                e.active = false;
            }
        }
        inner.pending.insert(*new, *new_pop);
        Ok(inner.tree.root())
    }

    /// Revokes every active key last seen before `cutoff_ms`.
    pub fn prune_inactive(&self, cutoff_ms: u64) -> (B256, usize) {
        let mut guard = self.inner.write();
        let inner = &mut *guard;
        let mut pruned = 0;
        for e in &mut inner.committed {
            if !e.active || e.last_seen_ms >= cutoff_ms {
                continue;
            }
            let _ = inner.tree.delete(&key_hash(&e.pubkey));
            e.active = false;
            inner.by_key.remove(&e.pubkey);
            pruned += 1;
        }
        (inner.tree.root(), pruned)
    }

    /// The committed key at `idx` (revoked ones included).
    pub fn public_key(&self, idx: MobileIndex) -> Result<PublicKey, MobileVerifyError> {
        self.inner.read().committed.get(idx as usize).map(|e| e.pk).ok_or(MobileVerifyError::UnknownIndex)
    }

    /// Resolves a decoded signer mask to its keys; any out-of-range index
    /// fails the whole call.
    pub fn public_keys(&self, indices: &[MobileIndex]) -> Result<Vec<PublicKey>, MobileVerifyError> {
        let inner = self.inner.read();
        indices
            .iter()
            .map(|i| {
                inner.committed.get(*i as usize).map(|e| e.pk).ok_or(MobileVerifyError::UnknownIndexAt(u64::from(*i)))
            })
            .collect()
    }

    /// Number of active committed keys.
    pub fn count(&self) -> usize {
        self.inner.read().by_key.len()
    }

    /// Number of keys awaiting the next commit.
    pub fn pending_count(&self) -> usize {
        self.inner.read().pending.len()
    }

    /// One past the highest committed index (revoked slots included): the
    /// exclusive bound a signer mask's indices must fall under.
    pub fn index_bound(&self) -> usize {
        self.inner.read().committed.len()
    }

    /// The committed set in index order (gov5 `ExportCommitted`):
    /// `magic BE4 ‖ 0x01 ‖ count BE4 ‖ count × (pubkey48 ‖ pop96 ‖ active1 ‖ lastSeenMs BE8)`.
    pub fn export_committed(&self) -> Vec<u8> {
        let inner = self.inner.read();
        let mut out = Vec::with_capacity(9 + inner.committed.len() * SNAPSHOT_ENTRY_LEN);
        out.extend_from_slice(&SNAPSHOT_MAGIC.to_be_bytes());
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(&(inner.committed.len() as u32).to_be_bytes());
        for e in &inner.committed {
            out.extend_from_slice(&e.pubkey);
            out.extend_from_slice(&e.pop);
            out.push(u8::from(e.active));
            out.extend_from_slice(&e.last_seen_ms.to_be_bytes());
        }
        out
    }

    /// Rebuilds the committed set from an [`Self::export_committed`] payload
    /// (gov5 `ImportCommitted`); only on a registry with nothing committed.
    /// The caller must check the returned root against the anchored one.
    pub fn import_committed(&self, data: &[u8]) -> Result<B256, MobileVerifyError> {
        let snap = |s: String| MobileVerifyError::Other(s);
        if data.len() < 9 {
            return Err(snap("snapshot too short".into()));
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != SNAPSHOT_MAGIC || data[4] != SNAPSHOT_VERSION {
            return Err(snap("bad snapshot header".into()));
        }
        let count = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
        let body = &data[9..];
        if Some(body.len()) != count.checked_mul(SNAPSHOT_ENTRY_LEN) {
            return Err(snap(format!("snapshot length {} != {} entries", body.len(), count)));
        }
        let mut inner = self.inner.write();
        if !inner.committed.is_empty() {
            return Err(snap("ImportCommitted requires an empty committed set".into()));
        }
        let mut committed = Vec::with_capacity(count);
        let mut by_key = HashMap::with_capacity(count);
        let mut known = HashMap::with_capacity(count);
        let mut tree = Accumulator::new();
        for (i, entry) in body.chunks_exact(SNAPSHOT_ENTRY_LEN).enumerate() {
            let mut pubkey = [0u8; 48];
            pubkey.copy_from_slice(&entry[..48]);
            let mut pop = [0u8; 96];
            pop.copy_from_slice(&entry[48..144]);
            let active = match entry[144] {
                0 => false,
                1 => true,
                b => return Err(snap(format!("snapshot entry {i} bad active flag {b}"))),
            };
            let mut ls = [0u8; 8];
            ls.copy_from_slice(&entry[145..153]);
            if known.contains_key(&pubkey) {
                return Err(snap(format!("snapshot entry {i} duplicates a pubkey")));
            }
            let pk = verify_pop(&pubkey, &pop)
                .map_err(|e| snap(format!("snapshot entry {i} bad proof of possession: {e}")))?;
            let idx = i as MobileIndex;
            committed.push(Committed { pubkey, pk, pop, active, last_seen_ms: u64::from_be_bytes(ls) });
            known.insert(pubkey, idx);
            inner.pending.remove(&pubkey);
            if active {
                by_key.insert(pubkey, idx);
                tree.put(key_hash(&pubkey), u64::from(idx).to_be_bytes().to_vec());
            }
        }
        inner.committed = committed;
        inner.by_key = by_key;
        inner.known = known;
        inner.tree = tree;
        Ok(inner.tree.root())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::leaf_hash;
    use crate::keys::DeviceKey;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn key(i: u8) -> DeviceKey {
        DeviceKey::from_ikm(&[i; 32]).unwrap()
    }

    #[test]
    fn pending_then_committed() {
        let reg = Registry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        reg.set_on_register(Arc::new(move |_, _| {
            f.fetch_add(1, Ordering::SeqCst);
        }));
        let k = key(1);
        assert_eq!(reg.register(&k.pubkey(), &k.proof_of_possession()).unwrap(), (0, false));
        assert_eq!(reg.register(&k.pubkey(), &k.proof_of_possession()).unwrap(), (0, false));
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert_eq!(reg.lookup(&k.pubkey()), None);
        assert_eq!(reg.pending_count(), 1);
        let (root, n) = reg.commit_epoch_at(5);
        assert_eq!(n, 1);
        assert_eq!(root, leaf_hash(&key_hash(&k.pubkey()), &0u64.to_be_bytes()));
        assert_eq!(reg.register(&k.pubkey(), &k.proof_of_possession()).unwrap(), (0, true));
        assert_eq!(reg.lookup(&k.pubkey()), Some(0));
        assert_eq!(reg.count(), 1);
        assert_eq!(reg.index_bound(), 1);
        assert_eq!(reg.commit_epoch_at(6), (root, 0));
    }

    #[test]
    fn indices_follow_key_hash_order() {
        let reg = Registry::new();
        let keys: Vec<_> = (1..=5).map(key).collect();
        for k in &keys {
            reg.register(&k.pubkey(), &k.proof_of_possession()).unwrap();
        }
        reg.commit_epoch_at(1);
        let mut sorted: Vec<_> = keys.iter().map(|k| (key_hash(&k.pubkey()), k.pubkey())).collect();
        sorted.sort();
        for (i, (_, pk)) in sorted.iter().enumerate() {
            assert_eq!(reg.lookup(pk), Some(i as u32));
        }
    }

    #[test]
    fn revoked_key_must_rotate() {
        let reg = Registry::new();
        let k = key(3);
        reg.register(&k.pubkey(), &k.proof_of_possession()).unwrap();
        reg.commit_epoch_at(1);
        let (root, ok) = reg.revoke(&k.pubkey());
        assert!(ok);
        assert_eq!(root, B256::ZERO);
        assert_eq!(reg.index_bound(), 1);
        assert_eq!(reg.count(), 0);
        let err = reg.register(&k.pubkey(), &k.proof_of_possession()).unwrap_err();
        assert_eq!(err.to_string(), "mobileverify: key was already registered; rotate to a fresh key");
        assert!(reg.public_key(0).is_ok());
    }

    #[test]
    fn snapshot_round_trip() {
        let reg = Registry::new();
        for i in 1..=4 {
            let k = key(i);
            reg.register(&k.pubkey(), &k.proof_of_possession()).unwrap();
        }
        reg.commit_epoch_at(1000);
        let k5 = key(5);
        reg.register(&k5.pubkey(), &k5.proof_of_possession()).unwrap();
        reg.commit_epoch_at(2000);
        let first = reg.export_committed();
        reg.revoke(&key(2).pubkey());
        let snap = reg.export_committed();
        assert_eq!(&snap[..4], &SNAPSHOT_MAGIC.to_be_bytes());
        assert_eq!(snap[4], 1);
        assert_eq!(&snap[5..9], &5u32.to_be_bytes());
        assert_eq!(snap.len(), 9 + 5 * SNAPSHOT_ENTRY_LEN);
        assert_ne!(first, snap);

        let other = Registry::new();
        assert_eq!(other.import_committed(&snap).unwrap(), reg.root());
        assert_eq!(other.export_committed(), snap);
        assert_eq!(other.count(), 4);
        assert!(other.import_committed(&snap).is_err());
        assert!(Registry::new().import_committed(&snap[..20]).is_err());
    }
}
