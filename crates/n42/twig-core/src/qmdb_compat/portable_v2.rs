//! The tombstone portable snapshot (`docs/QMDB_COMPACTION_DESIGN.md` section 6).
//!
//! v1 ([`QmdbPortableSnapshot`]) is the complete positional slot log with
//! every slot's key and value. A compacting node keeps only the leaf hash of a
//! compacted twig's dead slots and cannot write it. The tombstone layout keeps
//! v1's header (plus `tombstones u64` after `entry_count`), its contiguous
//! slot order, its value bound and its Blake3 trailer, and lets a record be:
//!
//! | kind | rest | meaning |
//! | --- | --- | --- |
//! | 0 | `[key 32][len u32][value]` | dead slot with its payload |
//! | 1 | `[key 32][len u32][value]` | live slot |
//! | 2 | `[leaf_hash 32]` | tombstone: dead, payload dropped |
//! | 3 | `[count u16][leaf_root 32]` | a whole dead twig of tombstones, from its first slot, `count == 2048` |
//!
//! The magic's version byte is 3 (`N42QMDB\x03`), not 2: gov5 already writes
//! a different layout under `N42QMDB\x02` (its leaf-form export, gov5
//! `df01cff7`, `n42-qmdb-export --leaf-form`), and two layouts must never share
//! a magic. The design calls this layout "v2"; [`PortableFormat::V2`] names it.

use super::{
    twig_leaf_root, Hash, PortableReader, QmdbCompatTree, QmdbEntrySnapshot, QmdbPortableError,
    QmdbPortableSnapshot, QmdbSlotEntry, QmdbSlotSnapshot, QmdbSnapshot, QmdbSnapshotError, MAX_PORTABLE_VALUE_SIZE,
    NULL_HASH, PORTABLE_SNAPSHOT_DIGEST_SIZE, PORTABLE_SNAPSHOT_ENTRY_SIZE, PORTABLE_SNAPSHOT_HEADER_SIZE,
    PORTABLE_SNAPSHOT_MAGIC, TWIG_SIZE,
};

/// The tombstone layout's magic. See the module docs for why its version byte is 3.
pub const PORTABLE_SNAPSHOT_MAGIC_V2: &[u8; 8] = b"N42QMDB\x03";
/// Record kind 0: a dead slot with its payload (v1's `active = 0`).
pub const PORTABLE_KIND_DEAD: u8 = 0;
/// Record kind 1: a live slot (v1's `active = 1`).
pub const PORTABLE_KIND_LIVE: u8 = 1;
/// Record kind 2: a dead slot carrying only its leaf hash.
pub const PORTABLE_KIND_TOMBSTONE: u8 = 2;
/// Record kind 3: a whole twig of tombstones carrying only its leaf root.
pub const PORTABLE_KIND_DEAD_TWIG: u8 = 3;

/// The tombstone header: v1's plus `tombstones u64`.
const HEADER_SIZE_V2: usize = PORTABLE_SNAPSHOT_HEADER_SIZE + 8;
/// The smallest record an importer reads: a tombstone.
const TOMBSTONE_RECORD_SIZE: usize = 8 + 1 + 32;
/// A kind-3 record.
const DEAD_TWIG_RECORD_SIZE: usize = 8 + 1 + 2 + 32;

/// Which portable layout a snapshot is in, by its magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortableFormat {
    /// `N42QMDB\x01`: every slot with its key and value.
    V1,
    /// `N42QMDB\x03`: the tombstone layout (`docs/QMDB_COMPACTION_DESIGN.md` section 6).
    V2,
}

impl PortableFormat {
    /// The layout a magic names, `None` for any other.
    pub fn of_magic(magic: &[u8; 8]) -> Option<Self> {
        if magic == PORTABLE_SNAPSHOT_MAGIC {
            Some(Self::V1)
        } else if magic == PORTABLE_SNAPSHOT_MAGIC_V2 {
            Some(Self::V2)
        } else {
            None
        }
    }

    /// The layout of an encoded snapshot, from its first eight bytes.
    pub fn detect(encoded: &[u8]) -> Option<Self> {
        encoded.first_chunk::<8>().and_then(Self::of_magic)
    }

    /// The layout's magic.
    pub const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::V1 => PORTABLE_SNAPSHOT_MAGIC,
            Self::V2 => PORTABLE_SNAPSHOT_MAGIC_V2,
        }
    }
}

impl std::fmt::Display for PortableFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        })
    }
}

impl std::str::FromStr for PortableFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "v1" => Ok(Self::V1),
            "v2" | "tombstone" => Ok(Self::V2),
            other => Err(format!("unknown portable snapshot format {other:?} (v1 or v2)")),
        }
    }
}

/// A kind-3 run must start a twig and cover it whole, inside the slot log.
pub(super) fn check_dead_twig_run(slot: u64, count: u64, entry_count: u64) -> Result<(), QmdbPortableError> {
    let inside = slot.checked_add(count).is_some_and(|end| end <= entry_count);
    if !slot.is_multiple_of(TWIG_SIZE as u64) || count != TWIG_SIZE as u64 || !inside {
        return Err(QmdbPortableError::MisalignedDeadTwig { slot, count });
    }
    Ok(())
}

/// A portable snapshot over a [`QmdbSnapshot`], whose dead slots may keep only
/// their leaf hash ([`QmdbEntrySnapshot::leaf_hash`]): what a compacting node
/// holds, and what an importer rebuilds from either layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QmdbPortableTree {
    pub chain_id: u64,
    pub genesis_hash: Hash,
    pub block_number: u64,
    pub block_hash: Hash,
    pub root: Hash,
    /// Every slot below `next_slot`, in order.
    pub slots: QmdbSnapshot,
}

impl From<QmdbPortableSnapshot> for QmdbPortableTree {
    fn from(portable: QmdbPortableSnapshot) -> Self {
        let entries = portable
            .slots
            .entries
            .into_iter()
            .map(|entry| QmdbEntrySnapshot::new(entry.key, entry.value, entry.active))
            .collect();
        Self {
            chain_id: portable.chain_id,
            genesis_hash: portable.genesis_hash,
            block_number: portable.block_number,
            block_hash: portable.block_hash,
            root: portable.root,
            slots: QmdbSnapshot { next_slot: portable.slots.next_slot, entries, dead_twigs: Vec::new() },
        }
    }
}

impl QmdbPortableTree {
    /// The v1 form, refused (with the first such slot) when a slot keeps only
    /// its leaf hash.
    pub fn to_v1(&self) -> Result<QmdbPortableSnapshot, QmdbPortableError> {
        if let Some(slot) = self.slots.first_hash_only_slot() {
            return Err(QmdbPortableError::HashOnlySlot { slot });
        }
        let entries = self
            .slots
            .entries
            .iter()
            .enumerate()
            .map(|(slot, entry)| QmdbSlotEntry {
                slot: slot as u64,
                key: entry.key,
                value: entry.value.clone(),
                active: entry.active,
            })
            .collect();
        Ok(QmdbPortableSnapshot {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            block_number: self.block_number,
            block_hash: self.block_hash,
            root: self.root,
            slots: QmdbSlotSnapshot { next_slot: self.slots.next_slot, entries },
        })
    }

    /// For each full twig, the leaf root of its kind-3 record if it is
    /// written as one: always for a root-only twig
    /// ([`QmdbSnapshot::dead_twigs`], whose leaves are not known), and for
    /// a twig whose every slot is dead and hash-only when `whole_dead_twigs`
    /// is asked for.
    fn dead_twigs(&self, whole_dead_twigs: bool) -> Vec<Option<Hash>> {
        let entries = &self.slots.entries;
        let mut roots: Vec<Option<Hash>> = (0..entries.len() / TWIG_SIZE)
            .map(|twig| {
                let slots = &entries[twig * TWIG_SIZE..(twig + 1) * TWIG_SIZE];
                (whole_dead_twigs && slots.iter().all(|entry| entry.leaf_hash.is_some() && !entry.active)).then(|| {
                    let leaves: Vec<Hash> = slots.iter().map(|entry| entry.leaf_hash.unwrap_or(NULL_HASH)).collect();
                    twig_leaf_root(&leaves)
                })
            })
            .collect();
        for (twig, leaf_root) in &self.slots.dead_twigs {
            if let Some(root) = roots.get_mut(*twig as usize) {
                *root = Some(*leaf_root);
            }
        }
        roots
    }

    /// Encodes the snapshot in `format`. v1 is refused when a slot keeps only
    /// its leaf hash. v2 writes such slots as tombstones (kind 2) and, when
    /// `whole_dead_twigs` is set, a full twig made only of them as one kind-3
    /// record; a root-only twig ([`QmdbSnapshot::dead_twigs`], a kind-3
    /// import) is always kind 3, having no per-slot leaf hashes. A v2
    /// encoding of a tree with no hash-only slot differs from v1 only in the
    /// header and the kind bytes.
    pub fn encode(&self, format: PortableFormat, whole_dead_twigs: bool) -> Result<Vec<u8>, QmdbPortableError> {
        if format == PortableFormat::V1 {
            return self.to_v1()?.encode();
        }
        let entries = &self.slots.entries;
        if self.slots.next_slot != entries.len() as u64 {
            return Err(QmdbPortableError::NonPositional { entries: entries.len() as u64, next_slot: self.slots.next_slot });
        }
        if let Some((twig, _)) = self.slots.dead_twigs.iter().find(|(twig, _)| (twig + 1) * TWIG_SIZE as u64 > self.slots.next_slot) {
            return Err(QmdbPortableError::MisalignedDeadTwig { slot: twig * TWIG_SIZE as u64, count: TWIG_SIZE as u64 });
        }
        let dead_twigs = self.dead_twigs(whole_dead_twigs);
        let mut tombstones = dead_twigs.iter().filter(|dead| dead.is_some()).count() as u64;
        let mut capacity = HEADER_SIZE_V2 + PORTABLE_SNAPSHOT_DIGEST_SIZE;
        for (slot, entry) in entries.iter().enumerate() {
            if dead_twigs.get(slot / TWIG_SIZE).is_some_and(Option::is_some) {
                continue;
            }
            match entry.leaf_hash {
                Some(_) if entry.active => return Err(QmdbPortableError::ActiveTombstone { slot: slot as u64 }),
                Some(_) => {
                    tombstones += 1;
                    capacity += TOMBSTONE_RECORD_SIZE;
                }
                None => {
                    if entry.value.len() > MAX_PORTABLE_VALUE_SIZE {
                        return Err(QmdbPortableError::ValueTooLarge { slot: slot as u64, size: entry.value.len() });
                    }
                    capacity += PORTABLE_SNAPSHOT_ENTRY_SIZE + entry.value.len();
                }
            }
        }
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(PORTABLE_SNAPSHOT_MAGIC_V2);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.genesis_hash);
        out.extend_from_slice(&self.block_number.to_le_bytes());
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.slots.next_slot.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        out.extend_from_slice(&tombstones.to_le_bytes());
        let mut slot = 0;
        while slot < entries.len() {
            if let Some(Some(leaf_root)) = (slot % TWIG_SIZE == 0).then(|| dead_twigs.get(slot / TWIG_SIZE).copied().flatten()) {
                out.extend_from_slice(&(slot as u64).to_le_bytes());
                out.push(PORTABLE_KIND_DEAD_TWIG);
                out.extend_from_slice(&(TWIG_SIZE as u16).to_le_bytes());
                out.extend_from_slice(&leaf_root);
                slot += TWIG_SIZE;
                continue;
            }
            let entry = &entries[slot];
            out.extend_from_slice(&(slot as u64).to_le_bytes());
            match entry.leaf_hash {
                Some(leaf_hash) => {
                    out.push(PORTABLE_KIND_TOMBSTONE);
                    out.extend_from_slice(&leaf_hash);
                }
                None => {
                    out.push(if entry.active { PORTABLE_KIND_LIVE } else { PORTABLE_KIND_DEAD });
                    out.extend_from_slice(&entry.key);
                    out.extend_from_slice(&(entry.value.len() as u32).to_le_bytes());
                    out.extend_from_slice(&entry.value);
                }
            }
            slot += 1;
        }
        let digest = blake3::hash(&out);
        out.extend_from_slice(digest.as_bytes());
        Ok(out)
    }

    /// Decodes and authenticates either layout into the slots an importer
    /// rebuilds: a tombstone becomes a hash-only entry, a kind-3 run (its
    /// shape checked) a root-only twig ([`QmdbSnapshot::dead_twigs`]) whose
    /// slots are hash-only placeholders. Root and chain identity are checked
    /// by [`Self::verify_and_build`].
    pub fn decode(encoded: &[u8]) -> Result<(PortableFormat, Self), QmdbPortableError> {
        let format = PortableFormat::detect(encoded).ok_or(if encoded.len() < 8 {
            QmdbPortableError::Truncated
        } else {
            QmdbPortableError::UnsupportedVersion
        })?;
        if format == PortableFormat::V1 {
            return QmdbPortableSnapshot::decode(encoded).map(|portable| (format, portable.into()));
        }
        if encoded.len() < HEADER_SIZE_V2 + PORTABLE_SNAPSHOT_DIGEST_SIZE {
            return Err(QmdbPortableError::Truncated);
        }
        let (payload, claimed_digest) = encoded.split_at(encoded.len() - PORTABLE_SNAPSHOT_DIGEST_SIZE);
        if blake3::hash(payload).as_bytes() != claimed_digest {
            return Err(QmdbPortableError::ContentHashMismatch);
        }
        let mut reader = PortableReader::new(payload);
        reader.take(PORTABLE_SNAPSHOT_MAGIC_V2.len())?;
        let chain_id = reader.u64()?;
        let genesis_hash = reader.hash()?;
        let block_number = reader.u64()?;
        let block_hash = reader.hash()?;
        let root = reader.hash()?;
        let next_slot = reader.u64()?;
        let entry_count = reader.u64()?;
        let claimed_tombstones = reader.u64()?;
        if entry_count != next_slot {
            return Err(QmdbPortableError::NonPositional { entries: entry_count, next_slot });
        }
        // A kind-3 run covers a twig in 43 bytes, any other record one slot
        // in at least 41: a header claiming more slots than that is a lie.
        let most = (reader.remaining() / DEAD_TWIG_RECORD_SIZE + 1) as u64 * TWIG_SIZE as u64;
        if entry_count > most {
            return Err(QmdbPortableError::Truncated);
        }
        // Reserved for one record a slot; kind-3 runs grow it.
        let reserve = entry_count.min((reader.remaining() / TOMBSTONE_RECORD_SIZE) as u64);
        let mut entries = Vec::with_capacity(usize::try_from(reserve).map_err(|_| QmdbPortableError::Truncated)?);
        let mut tombstones = 0_u64;
        let mut dead_twigs = Vec::new();
        let mut expected = 0_u64;
        while expected < entry_count {
            let slot = reader.u64()?;
            if slot != expected {
                return Err(QmdbPortableError::NonContiguousSlotLog { expected, got: slot });
            }
            match reader.byte()? {
                kind @ (PORTABLE_KIND_DEAD | PORTABLE_KIND_LIVE) => {
                    let key = reader.hash()?;
                    let value_len = reader.u32()? as usize;
                    if value_len > MAX_PORTABLE_VALUE_SIZE {
                        return Err(QmdbPortableError::ValueTooLarge { slot, size: value_len });
                    }
                    let value = reader.take(value_len)?.to_vec();
                    entries.push(QmdbEntrySnapshot::new(key, value, kind == PORTABLE_KIND_LIVE));
                }
                PORTABLE_KIND_TOMBSTONE => {
                    tombstones += 1;
                    let leaf_hash = reader.hash()?;
                    entries.push(QmdbEntrySnapshot {
                        key: NULL_HASH,
                        value: Vec::new(),
                        active: false,
                        leaf_hash: Some(leaf_hash),
                    });
                }
                PORTABLE_KIND_DEAD_TWIG => {
                    let count = u64::from(reader.u16()?);
                    let leaf_root = reader.hash()?;
                    check_dead_twig_run(slot, count, entry_count)?;
                    tombstones += 1;
                    // A root-only twig: its slots are placeholders.
                    dead_twigs.push((slot / TWIG_SIZE as u64, leaf_root));
                    entries.extend((0..TWIG_SIZE).map(|_| QmdbEntrySnapshot {
                        key: NULL_HASH,
                        value: Vec::new(),
                        active: false,
                        leaf_hash: Some(NULL_HASH),
                    }));
                    expected += count;
                    continue;
                }
                kind => return Err(QmdbPortableError::InvalidRecordKind { slot, kind }),
            }
            expected += 1;
        }
        if reader.remaining() != 0 {
            return Err(QmdbPortableError::TrailingBytes(reader.remaining()));
        }
        if tombstones != claimed_tombstones {
            return Err(QmdbPortableError::TombstoneCount { header: claimed_tombstones, records: tombstones });
        }
        Ok((
            format,
            Self {
                chain_id,
                genesis_hash,
                block_number,
                block_hash,
                root,
                slots: QmdbSnapshot { next_slot, entries, dead_twigs },
            },
        ))
    }

    /// Enforces chain identity and rebuilds the split commitment: payload
    /// slots are hashed, tombstones keep their leaf hash (hash-only entries
    /// of the rebuilt tree, which `set_entry_file` writes as relocated
    /// groups), and the root must be the claimed one.
    pub fn verify_and_build(
        &self,
        expected_chain_id: u64,
        expected_genesis_hash: &Hash,
    ) -> Result<QmdbCompatTree, QmdbPortableError> {
        if self.chain_id != expected_chain_id {
            return Err(QmdbPortableError::WrongChainId { expected: expected_chain_id, got: self.chain_id });
        }
        if self.genesis_hash != *expected_genesis_hash {
            return Err(QmdbPortableError::WrongGenesisHash);
        }
        let tree = QmdbCompatTree::from_snapshot(&self.slots).map_err(|error| match error {
            QmdbSnapshotError::NonPositional { entries, next_slot } => {
                QmdbPortableError::NonPositional { entries: entries as u64, next_slot }
            }
            QmdbSnapshotError::NonContiguousSlotLog { expected, got } => {
                QmdbPortableError::NonContiguousSlotLog { expected, got }
            }
            QmdbSnapshotError::DuplicateActiveKey(_) => QmdbPortableError::RootMismatch,
            QmdbSnapshotError::ActiveHashOnly { slot } => QmdbPortableError::ActiveTombstone { slot },
            QmdbSnapshotError::InvalidDeadTwig { twig } => {
                QmdbPortableError::MisalignedDeadTwig { slot: twig * TWIG_SIZE as u64, count: TWIG_SIZE as u64 }
            }
            // A heap rebuild touches no entry file.
            QmdbSnapshotError::EntryFile(_) => QmdbPortableError::RootMismatch,
            QmdbSnapshotError::Index(reason) => QmdbPortableError::Io(format!("key index: {reason}")),
        })?;
        if tree.root() != self.root {
            return Err(QmdbPortableError::RootMismatch);
        }
        Ok(tree)
    }
}

/// The cross-client fixture set: a small tree with live, dead-with-payload,
/// tombstoned and whole-dead twigs (`testdata/portable_v2/`).
#[cfg(test)]
pub(crate) mod fixture {
    use super::*;
    use crate::qmdb_compat::QmdbOperation;

    pub(crate) const CHAIN_ID: u64 = 1143;
    pub(crate) const BLOCK_NUMBER: u64 = 42;

    pub(crate) fn tag(byte: u8) -> Hash {
        [byte; 32]
    }

    /// Keys sort as their numbers do, so a block appends them in that order.
    pub(crate) fn key(n: u64) -> Hash {
        let mut key = [0xab; 32];
        key[..8].copy_from_slice(&n.to_be_bytes());
        key
    }

    fn ops(keys: impl Iterator<Item = u64>, version: u8) -> Vec<QmdbOperation> {
        let mut ops: Vec<_> = keys
            .map(|n| QmdbOperation {
                key: key(n),
                value: (version != 0).then(|| vec![version, (n % 251) as u8]),
            })
            .collect();
        ops.sort_unstable_by_key(|op| op.key);
        ops
    }

    /// The fixture's blocks, applied to `tree`.
    ///
    /// Block 1 appends keys `0..4396` (twigs 0 and 1 full, twig 2 at 300).
    /// Block 2 deletes keys `0..2048` (twig 0 dies whole), rewrites the even
    /// keys of twig 1 (half of it dies) and keys `4096..4146` of twig 2 (dead
    /// with payload, twig 2 is never compacted): 5470 slots in three twigs.
    pub(crate) fn apply_blocks(tree: &mut QmdbCompatTree) -> Hash {
        tree.apply_sorted_ops(ops(0..4396, 1)).unwrap();
        let mut block = ops(0..2048, 0);
        block.extend(ops((2048..4096).step_by(2), 2));
        block.extend(ops(4096..4146, 2));
        block.sort_unstable_by_key(|op| op.key);
        tree.apply_sorted_ops(block).unwrap()
    }

    pub(crate) fn portable(slots: QmdbSnapshot, root: Hash) -> QmdbPortableTree {
        QmdbPortableTree {
            chain_id: CHAIN_ID,
            genesis_hash: tag(0x11),
            block_number: BLOCK_NUMBER,
            block_hash: tag(0x22),
            root,
            slots,
        }
    }

    /// `(uncompacted, compacted)`: the heap tree's slots and the slots of a
    /// file tree after compaction of twigs 0 and 1, and their common root.
    pub(crate) fn trees() -> (QmdbPortableTree, QmdbPortableTree) {
        let mut heap = QmdbCompatTree::new();
        let root = apply_blocks(&mut heap);
        let dir = std::env::temp_dir().join(format!("n42-portable-v2-fixture-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut file = QmdbCompatTree::new();
        file.set_entry_file(&dir.join("entries.log")).unwrap();
        assert_eq!(apply_blocks(&mut file), root);
        let report = file.compact_twigs(u64::MAX, 0.5, usize::MAX).unwrap();
        assert_eq!(report.twigs, 2, "twigs 0 and 1 compact, the partial twig 2 does not");
        assert_eq!(file.root(), root);
        let compacted = file.snapshot();
        drop(file);
        let _ = std::fs::remove_dir_all(&dir);
        (portable(heap.snapshot(), root), portable(compacted, root))
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{tag, trees, CHAIN_ID};
    use super::*;
    use crate::qmdb_compat::{verify_portable_stream, BlockUndo, QmdbPortableVerification, QmdbUndoError};
    use sha2::{Digest, Sha256};

    fn verify(bytes: &[u8]) -> Result<QmdbPortableVerification, QmdbPortableError> {
        verify_portable_stream(bytes, CHAIN_ID, &tag(0x11))
    }

    /// Re-seals a tampered payload with a fresh Blake3 trailer, so only the
    /// structural or root check can catch it.
    fn reseal(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.truncate(bytes.len() - PORTABLE_SNAPSHOT_DIGEST_SIZE);
        let digest = blake3::hash(&bytes);
        bytes.extend_from_slice(digest.as_bytes());
        bytes
    }

    /// Byte offset of `slot`'s record of `kind` (its slot and kind bytes).
    fn find_record(bytes: &[u8], slot: u64, kind: u8) -> usize {
        let mut needle = slot.to_le_bytes().to_vec();
        needle.push(kind);
        bytes.windows(needle.len()).position(|window| window == needle.as_slice()).expect("the record")
    }

    #[test]
    fn the_fixture_tree_has_every_slot_kind() {
        let (plain, compacted) = trees();
        let entries = &compacted.slots.entries;
        assert_eq!(compacted.slots.next_slot, 5470);
        assert!(entries[..TWIG_SIZE].iter().all(|e| e.leaf_hash.is_some() && !e.active), "twig 0 whole dead");
        let twig1 = &entries[TWIG_SIZE..2 * TWIG_SIZE];
        assert_eq!(twig1.iter().filter(|e| e.leaf_hash.is_some()).count(), 1024);
        assert_eq!(twig1.iter().filter(|e| e.active).count(), 1024);
        let twig2 = &entries[2 * TWIG_SIZE..];
        assert!(twig2.iter().all(|e| e.leaf_hash.is_none()));
        assert_eq!(twig2.iter().filter(|e| !e.active).count(), 50, "dead with payload");
        assert!(plain.slots.first_hash_only_slot().is_none());
    }

    #[test]
    fn v1_of_the_uncompacted_and_v2_of_the_compacted_verify_to_one_root() {
        let (plain, compacted) = trees();
        let v1 = plain.encode(PortableFormat::V1, false).unwrap();
        let v2 = compacted.encode(PortableFormat::V2, true).unwrap();
        let v2_tombstones = compacted.encode(PortableFormat::V2, false).unwrap();
        assert_eq!(&v1[..8], b"N42QMDB\x01");
        assert_eq!(&v2[..8], b"N42QMDB\x03");
        let (a, b, c) = (verify(&v1).unwrap(), verify(&v2).unwrap(), verify(&v2_tombstones).unwrap());
        assert_eq!((a.root, b.root, c.root), (plain.root, plain.root, plain.root));
        assert_eq!((a.format, b.format, c.format), (PortableFormat::V1, PortableFormat::V2, PortableFormat::V2));
        assert_eq!((a.live_count, b.live_count, c.live_count), (2348, 2348, 2348));
        assert_eq!((a.tombstones, b.tombstones, c.tombstones), (0, 1 + 1024, 2048 + 1024));
        assert!(v2.len() < v2_tombstones.len() && v2_tombstones.len() < v1.len());
        // v1 of the compacted tree is refused, naming the first hash-only slot.
        assert_eq!(compacted.encode(PortableFormat::V1, false), Err(QmdbPortableError::HashOnlySlot { slot: 0 }));
        // A v1 reader stops at the magic.
        assert_eq!(QmdbPortableSnapshot::decode(&v2_tombstones), Err(QmdbPortableError::UnsupportedVersion));
        // v2 of the uncompacted tree: no tombstones, and it verifies too.
        let v2_plain = plain.encode(PortableFormat::V2, true).unwrap();
        assert_eq!(verify(&v2_plain).unwrap().tombstones, 0);
        assert_eq!(v2_plain.len(), v1.len() + 8);
    }

    #[test]
    fn import_rebuilds_tombstones_as_hash_only_slots() {
        let (plain, compacted) = trees();
        let v1 = plain.encode(PortableFormat::V1, false).unwrap();
        let v2 = compacted.encode(PortableFormat::V2, false).unwrap();
        let (format, from_v1) = QmdbPortableTree::decode(&v1).unwrap();
        assert_eq!((format, &from_v1), (PortableFormat::V1, &plain));
        let (format, from_v2) = QmdbPortableTree::decode(&v2).unwrap();
        assert_eq!((format, &from_v2), (PortableFormat::V2, &compacted));
        let mut tree = from_v2.verify_and_build(CHAIN_ID, &tag(0x11)).unwrap();
        assert_eq!(tree.root(), plain.root);
        assert!(tree.has_hash_only_slots());
        // Into the entry file: tombstoned twigs become relocated groups and
        // the file tree reads the same root and proofs.
        let dir = std::env::temp_dir().join(format!("n42-portable-v2-import-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        tree.set_entry_file(&dir.join("entries.log")).unwrap();
        assert_eq!(tree.root(), plain.root);
        let live = super::fixture::key(2049);
        assert!(tree.prove(&live).unwrap().verify_for_key(&plain.root, &live));
        // A v1 re-export of the imported tree is refused; a v2 one is the same bytes.
        let again = super::fixture::portable(tree.snapshot(), tree.root());
        assert_eq!(again.encode(PortableFormat::V1, false), Err(QmdbPortableError::HashOnlySlot { slot: 0 }));
        assert_eq!(again.encode(PortableFormat::V2, false).unwrap(), v2);
        // Reviving a tombstoned slot needs its key: refused, nothing changed.
        let revive = BlockUndo { prev_next_slot: tree.next_slot(), slots_only: true, slots: vec![5], ..Default::default() };
        assert_eq!(tree.apply_undo(&revive), Err(QmdbUndoError::HashOnlySlot { slot: 5 }));
        let revive = BlockUndo { prev_next_slot: tree.next_slot(), slots_only: true, slots: vec![2048], ..Default::default() };
        assert_eq!(tree.apply_undo(&revive), Err(QmdbUndoError::HashOnlySlot { slot: 2048 }));
        assert_eq!(tree.root(), plain.root);
        drop(tree);
        let _ = std::fs::remove_dir_all(&dir);
        // A kind-3 twig imports too, as a root-only twig, and survives the
        // entry file and a reopen.
        let v2_dead_twig = compacted.encode(PortableFormat::V2, true).unwrap();
        import_kind_3(&v2_dead_twig, plain.root);
    }

    /// `bytes` (with a kind-3 twig 0) imported into a file tree: the root,
    /// a live key's proof, a reopen of the files, the refusals on twig 0's
    /// slots and a byte-equal v2 re-export.
    fn import_kind_3(bytes: &[u8], root: Hash) {
        let (format, imported) = QmdbPortableTree::decode(bytes).unwrap();
        assert_eq!(format, PortableFormat::V2);
        assert_eq!(imported.slots.dead_twigs, vec![(0, *twig_root_of(bytes))]);
        assert_eq!(imported.slots.first_hash_only_slot(), Some(0));
        let mut tree = imported.verify_and_build(CHAIN_ID, &tag(0x11)).unwrap();
        assert_eq!(tree.root(), root);
        // A heap round trip keeps the root-only twig.
        assert_eq!(super::fixture::portable(tree.snapshot(), root).encode(PortableFormat::V2, false).unwrap(), bytes);
        let dir = std::env::temp_dir().join(format!("n42-portable-v2-kind3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("entries.log");
        tree.set_entry_file(&path).unwrap();
        tree.sync_entries().unwrap();
        assert_eq!(tree.root(), root);
        let (next, active) = (tree.next_slot(), tree.active_bits());
        drop(tree);
        let (mut tree, kept) = QmdbCompatTree::from_entry_file(&path, next, &active).unwrap();
        assert_eq!(kept, next);
        assert_eq!(tree.root(), root);
        let live = super::fixture::key(2049);
        assert_eq!(tree.get(&live), Some([1u8, (2049 % 251) as u8].as_slice()));
        assert!(tree.prove(&live).unwrap().verify_for_key(&root, &live));
        assert_eq!(tree.get(&super::fixture::key(5)), None, "a key of the dead twig");
        let again = super::fixture::portable(tree.snapshot(), tree.root());
        assert_eq!(again.encode(PortableFormat::V1, false), Err(QmdbPortableError::HashOnlySlot { slot: 0 }));
        assert_eq!(again.encode(PortableFormat::V2, false).unwrap(), bytes);
        for slot in [0, 5, 2047] {
            let revive = BlockUndo { prev_next_slot: next, slots_only: true, slots: vec![slot], ..Default::default() };
            assert_eq!(tree.apply_undo(&revive), Err(QmdbUndoError::HashOnlySlot { slot }));
        }
        // Compaction leaves it alone; the tree extends.
        assert_eq!(tree.compact_twigs(u64::MAX, 0.0, usize::MAX).unwrap().twigs, 0);
        tree.set(super::fixture::key(9_999), vec![9]).unwrap();
        assert_ne!(tree.root(), root);
        drop(tree);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `bytes` as a node that reclaimed its dead rows writes it (a gov5 node
    /// with a leaf store): every kind-0 record becomes a kind-2 tombstone
    /// with the leaf hash of its payload.
    fn reclaimed_rows(bytes: &[u8]) -> (Vec<u8>, Vec<u64>) {
        let body = &bytes[..bytes.len() - PORTABLE_SNAPSHOT_DIGEST_SIZE];
        let mut out = body[..HEADER_SIZE_V2].to_vec();
        let mut reclaimed = Vec::new();
        let mut at = HEADER_SIZE_V2;
        while at < body.len() {
            let (slot, kind) = (&body[at..at + 8], body[at + 8]);
            let len = match kind {
                PORTABLE_KIND_DEAD | PORTABLE_KIND_LIVE => {
                    45 + u32::from_le_bytes(body[at + 41..at + 45].try_into().unwrap()) as usize
                }
                PORTABLE_KIND_TOMBSTONE => 41,
                _ => 43,
            };
            if kind == PORTABLE_KIND_DEAD {
                let leaf = crate::hash_leaf(body[at + 9..at + 41].try_into().unwrap(), &body[at + 45..at + len]);
                out.extend_from_slice(slot);
                out.push(PORTABLE_KIND_TOMBSTONE);
                out.extend_from_slice(&leaf);
                reclaimed.push(u64::from_le_bytes(slot.try_into().unwrap()));
            } else {
                out.extend_from_slice(&body[at..at + len]);
            }
            at += len;
        }
        let count = HEADER_SIZE_V2 - 8..HEADER_SIZE_V2;
        let tombstones = u64::from_le_bytes(out[count.clone()].try_into().unwrap()) + reclaimed.len() as u64;
        out[count].copy_from_slice(&tombstones.to_le_bytes());
        out.extend_from_slice(&[0; PORTABLE_SNAPSHOT_DIGEST_SIZE]);
        (reseal(out), reclaimed)
    }

    /// Tombstones in the partial (last) twig -- what a gov5 node that
    /// reclaimed its dead rows exports -- import into the entry file as
    /// hash-only log records, reopen, refuse revival and v1, and re-export
    /// byte for byte.
    #[test]
    fn tombstones_in_the_partial_twig_import_into_the_entry_file() {
        let (plain, compacted) = trees();
        for whole in [false, true] {
            let (bytes, reclaimed) = reclaimed_rows(&compacted.encode(PortableFormat::V2, whole).unwrap());
            assert_eq!(reclaimed.len(), 50);
            assert!(reclaimed.iter().all(|slot| slot / TWIG_SIZE as u64 == 2), "{reclaimed:?}");
            let (_, imported) = QmdbPortableTree::decode(&bytes).unwrap();
            let mut tree = imported.verify_and_build(CHAIN_ID, &tag(0x11)).unwrap();
            assert_eq!(tree.root(), plain.root);
            let dir = std::env::temp_dir().join(format!("n42-portable-v2-partial-{whole}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("entries.log");
            tree.set_entry_file(&path).unwrap();
            tree.sync_entries().unwrap();
            let (next, active) = (tree.next_slot(), tree.active_bits());
            drop(tree);
            let (mut tree, kept) = QmdbCompatTree::from_entry_file(&path, next, &active).unwrap();
            assert_eq!((kept, tree.root()), (next, plain.root));
            let live = super::fixture::key(4300);
            assert_eq!(tree.get(&live), Some([1u8, (4300 % 251) as u8].as_slice()));
            assert!(tree.prove(&live).unwrap().verify_for_key(&plain.root, &live));
            let again = super::fixture::portable(tree.snapshot(), tree.root());
            assert_eq!(again.encode(PortableFormat::V2, whole).unwrap(), bytes);
            assert!(matches!(again.encode(PortableFormat::V1, false), Err(QmdbPortableError::HashOnlySlot { .. })));
            let slot = reclaimed[0];
            let revive = BlockUndo { prev_next_slot: next, slots_only: true, slots: vec![slot], ..Default::default() };
            assert_eq!(tree.apply_undo(&revive), Err(QmdbUndoError::HashOnlySlot { slot }));
            // The partial twig fills and compacts over its hash-only records.
            for n in 0..800u64 {
                tree.set(super::fixture::key(10_000 + n), vec![7]).unwrap();
            }
            let extended = tree.root();
            assert!(tree.next_slot() > 3 * TWIG_SIZE as u64);
            tree.compact_twigs(u64::MAX, 0.0, usize::MAX).unwrap();
            assert_eq!(tree.root(), extended);
            tree.sync_entries().unwrap();
            let (next, active) = (tree.next_slot(), tree.active_bits());
            drop(tree);
            let (tree, _) = QmdbCompatTree::from_entry_file(&path, next, &active).unwrap();
            assert_eq!(tree.root(), extended);
            drop(tree);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// The leaf root of the kind-3 record at slot 0 of `bytes`.
    fn twig_root_of(bytes: &[u8]) -> &Hash {
        let at = find_record(bytes, 0, PORTABLE_KIND_DEAD_TWIG) + 9 + 2;
        bytes[at..at + 32].try_into().unwrap()
    }

    #[test]
    fn a_wrong_tombstone_fails_the_root_check() {
        let (_, compacted) = trees();
        for whole in [false, true] {
            let mut bytes = compacted.encode(PortableFormat::V2, whole).unwrap();
            let at = find_record(&bytes, 2048, PORTABLE_KIND_TOMBSTONE) + 9;
            bytes[at] ^= 0x01;
            let bytes = reseal(bytes);
            assert_eq!(verify(&bytes), Err(QmdbPortableError::RootMismatch));
            if !whole {
                let (_, tree) = QmdbPortableTree::decode(&bytes).unwrap();
                assert_eq!(tree.verify_and_build(CHAIN_ID, &tag(0x11)).err(), Some(QmdbPortableError::RootMismatch));
            }
        }
        // A wrong whole-twig leaf root as well.
        let mut bytes = compacted.encode(PortableFormat::V2, true).unwrap();
        let at = find_record(&bytes, 0, PORTABLE_KIND_DEAD_TWIG) + 9 + 2;
        bytes[at] ^= 0x01;
        assert_eq!(verify(&reseal(bytes)), Err(QmdbPortableError::RootMismatch));
        // Without the reseal, the digest catches any flip first.
        let mut bytes = compacted.encode(PortableFormat::V2, false).unwrap();
        let at = find_record(&bytes, 2048, PORTABLE_KIND_TOMBSTONE) + 9;
        bytes[at] ^= 0x01;
        assert_eq!(verify(&bytes), Err(QmdbPortableError::ContentHashMismatch));
    }

    /// A hand-built v2 stream: header for `entry_count` slots claiming
    /// `tombstones`, then `records`, then the trailer.
    fn stream(entry_count: u64, tombstones: u64, records: &[u8]) -> Vec<u8> {
        let mut out = PORTABLE_SNAPSHOT_MAGIC_V2.to_vec();
        out.extend_from_slice(&CHAIN_ID.to_le_bytes());
        out.extend_from_slice(&tag(0x11));
        out.extend_from_slice(&7u64.to_le_bytes());
        out.extend_from_slice(&tag(0x22));
        out.extend_from_slice(&[0; 32]);
        out.extend_from_slice(&entry_count.to_le_bytes());
        out.extend_from_slice(&entry_count.to_le_bytes());
        out.extend_from_slice(&tombstones.to_le_bytes());
        out.extend_from_slice(records);
        let digest = blake3::hash(&out);
        out.extend_from_slice(digest.as_bytes());
        out
    }

    fn live(slot: u64) -> Vec<u8> {
        let mut out = slot.to_le_bytes().to_vec();
        out.push(PORTABLE_KIND_LIVE);
        out.extend_from_slice(&tag(slot as u8));
        out.extend_from_slice(&1u32.to_le_bytes());
        out.push(7);
        out
    }

    fn dead_twig(slot: u64, count: u16) -> Vec<u8> {
        let mut out = slot.to_le_bytes().to_vec();
        out.push(PORTABLE_KIND_DEAD_TWIG);
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&tag(0x33));
        out
    }

    #[test]
    fn a_kind_3_run_not_at_a_twig_start_is_rejected() {
        let n = 2 * TWIG_SIZE as u64;
        // Starts at slot 1.
        let bytes = stream(n + 1, 1, &[live(0), dead_twig(1, 2048)].concat());
        assert_eq!(verify(&bytes), Err(QmdbPortableError::MisalignedDeadTwig { slot: 1, count: 2048 }));
        // Covers part of a twig.
        let bytes = stream(n, 1, &dead_twig(0, 1024));
        assert_eq!(verify(&bytes), Err(QmdbPortableError::MisalignedDeadTwig { slot: 0, count: 1024 }));
        // Runs past the slot log (a partial last twig).
        let bytes = stream(100, 1, &dead_twig(0, 2048));
        assert_eq!(verify(&bytes), Err(QmdbPortableError::MisalignedDeadTwig { slot: 0, count: 2048 }));
        // Well formed: one whole twig, then the next record at slot 2048.
        let bytes = stream(TWIG_SIZE as u64 + 1, 1, &[dead_twig(0, 2048), live(2048)].concat());
        assert_eq!(verify(&bytes), Err(QmdbPortableError::RootMismatch), "shape accepted, the zero root is wrong");
        // The record after a run must name `slot + count`.
        let bytes = stream(TWIG_SIZE as u64 + 1, 1, &[dead_twig(0, 2048), live(2047)].concat());
        assert_eq!(verify(&bytes), Err(QmdbPortableError::NonContiguousSlotLog { expected: 2048, got: 2047 }));
    }

    #[test]
    fn the_header_tombstone_count_and_record_kinds_are_checked() {
        let (_, compacted) = trees();
        let bytes = compacted.encode(PortableFormat::V2, false).unwrap();
        let mut lie = bytes.clone();
        lie[PORTABLE_SNAPSHOT_HEADER_SIZE] ^= 0x01;
        let lie = reseal(lie);
        let expected = || QmdbPortableError::TombstoneCount { header: 3072 ^ 1, records: 3072 };
        assert_eq!(verify(&lie), Err(expected()));
        assert_eq!(QmdbPortableTree::decode(&lie), Err(expected()));
        // Kind 4 is not a record; in v1, a flag of 2 is still an invalid flag.
        let mut bad = live(0);
        bad[8] = 4;
        assert_eq!(verify(&stream(1, 0, &bad)), Err(QmdbPortableError::InvalidRecordKind { slot: 0, kind: 4 }));
        let mut v1 = PORTABLE_SNAPSHOT_MAGIC.to_vec();
        v1.extend_from_slice(&stream(1, 0, &[])[8..PORTABLE_SNAPSHOT_HEADER_SIZE]);
        bad[8] = 2;
        v1.extend_from_slice(&bad);
        let digest = blake3::hash(&v1);
        v1.extend_from_slice(digest.as_bytes());
        assert_eq!(verify(&v1), Err(QmdbPortableError::InvalidActiveFlag { slot: 0, flag: 2 }));
    }

    #[test]
    fn the_format_parses_and_detects() {
        assert_eq!("v1".parse(), Ok(PortableFormat::V1));
        assert_eq!("v2".parse(), Ok(PortableFormat::V2));
        assert!("v3".parse::<PortableFormat>().is_err());
        assert_eq!(PortableFormat::detect(b"N42QMDB\x01..."), Some(PortableFormat::V1));
        assert_eq!(PortableFormat::detect(b"N42QMDB\x03..."), Some(PortableFormat::V2));
        // gov5's leaf-form export (`N42QMDB\x02`) is a different layout.
        assert_eq!(PortableFormat::detect(b"N42QMDB\x02..."), None);
        assert_eq!(PortableFormat::V2.to_string(), "v2");
    }

    /// The files of `testdata/portable_v2/`, by name.
    const FIXTURES: [&str; 4] = ["v1.bin", "v2.bin", "v2-tombstones.bin", "root.hex"];

    fn fixture_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/portable_v2")
    }

    fn fixture_bytes() -> Vec<(&'static str, Vec<u8>)> {
        let (plain, compacted) = trees();
        vec![
            ("v1.bin", plain.encode(PortableFormat::V1, false).unwrap()),
            ("v2.bin", compacted.encode(PortableFormat::V2, true).unwrap()),
            ("v2-tombstones.bin", compacted.encode(PortableFormat::V2, false).unwrap()),
            ("root.hex", format!("{}\n", hex::encode(plain.root)).into_bytes()),
        ]
    }

    /// Writes the fixture set: `N42_REGEN_PORTABLE_V2=1 cargo test -p
    /// n42-twig-core regenerate_portable_v2_fixtures -- --ignored`.
    #[test]
    #[ignore = "writes testdata; run by hand to regenerate"]
    fn regenerate_portable_v2_fixtures() {
        if std::env::var_os("N42_REGEN_PORTABLE_V2").is_none() {
            return;
        }
        let dir = fixture_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let mut manifest = String::new();
        for (name, bytes) in fixture_bytes() {
            std::fs::write(dir.join(name), &bytes).unwrap();
            manifest.push_str(&format!("{}  {name}\n", hex::encode(Sha256::digest(&bytes))));
        }
        std::fs::write(dir.join("SHA256SUMS"), manifest).unwrap();
    }

    /// The committed fixtures: their SHA-256 is the manifest's, the encoder
    /// reproduces them byte for byte, and all three verify to `root.hex`.
    #[test]
    fn the_portable_v2_fixtures_match_their_manifest_and_root() {
        let dir = fixture_dir();
        let manifest = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
        let mut named = 0;
        for line in manifest.lines() {
            let (sha, name) = line.split_once("  ").expect("`<sha256>  <name>` lines");
            let bytes = std::fs::read(dir.join(name)).unwrap();
            assert_eq!(hex::encode(Sha256::digest(&bytes)), sha, "{name}");
            named += 1;
        }
        assert_eq!(named, FIXTURES.len());
        for (name, bytes) in fixture_bytes() {
            assert_eq!(std::fs::read(dir.join(name)).unwrap(), bytes, "{name} is not what the encoder writes");
        }
        let root = std::fs::read_to_string(dir.join("root.hex")).unwrap();
        for name in &FIXTURES[..3] {
            let bytes = std::fs::read(dir.join(name)).unwrap();
            assert_eq!(hex::encode(verify(&bytes).unwrap().root), root.trim(), "{name}");
        }
    }
}
