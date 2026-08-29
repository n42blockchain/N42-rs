// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one QMDB forest a node keeps, shared by everything that computes,
//! checks, or proves a state root.
//!
//! The payload builder, the engine validator, and the mobile endpoint must all
//! see the same trees: a root the builder computed from one forest and a
//! validator checked against another would disagree even when both are
//! correct. So there is exactly one, behind a lock, cloned by handle.
//!
//! It starts uninitialised. The trees can only be restored once the node's
//! database is open and the canonical head is known, which happens after the
//! components that hold this handle are built. Until [`QmdbNodeState::initialize`]
//! runs, every operation fails — loudly, as an error the engine reports — rather
//! than computing a root from an empty forest and calling a real block invalid.
//!
//! # Persistence
//!
//! The canonical head's tree is written to disk when the head moves, and read
//! back at startup. A QMDB tree cannot be reconstructed from the execution
//! layer's state, because the root depends on the append history and reth's
//! tables do not keep it; so a snapshot that is missing or behind the database's
//! head is a node that cannot compute the next root, and it says so instead of
//! starting. The exception is a database at genesis, which is seeded from the
//! alloc exactly as gov5 does.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use alloy_primitives::{Address, B256};
use n42_qmdb_state::{
    BlockChanges, ForestSnapshot, PreparedBlock, QmdbForest, StateError, StateProofProvider,
};
use n42_twig_core::qmdb_compat::QmdbProof;
use reth_chainspec::ChainSpec;
use tracing::{debug, info, warn};

use crate::changes::changes_from_alloc;

const SNAPSHOT_FILE: &str = "forest.bin";
/// The canonical blocks applied since the base snapshot, oldest first.
const DELTA_FILE: &str = "forest-deltas.bin";
/// A base snapshot is rewritten — in the background, from a copy of the
/// tree — once the delta log grows past this, so a restart replays a bounded
/// amount and the log never becomes the state.
const DELTA_REWRITE_BYTES: u64 = 512 << 20;
/// ... or after this many canonical blocks, whichever comes first.
const DELTA_REWRITE_BLOCKS: u64 = 20_000;

/// Why the node's QMDB state could not be used.
#[derive(Debug, thiserror::Error)]
pub enum NodeStateError {
    /// A portable snapshot could not be used.
    #[error("portable QMDB snapshot: {0}")]
    Portable(String),
    /// Nothing has restored the trees yet. See the module docs.
    #[error("QMDB state is not initialised; the node cannot compute state roots yet")]
    Uninitialised,
    /// The snapshot on disk names a different head than the database.
    ///
    /// Behind means blocks were committed that the forest never saw; ahead
    /// means the database was rolled back under it. Neither can be repaired
    /// by replay here, since replaying needs the trees this node is missing.
    #[error(
        "QMDB snapshot is at block {snapshot_number} ({snapshot_hash}) but the database head is \
         block {head_number} ({head_hash}); the forest cannot be rebuilt from execution state"
    )]
    SnapshotMismatch {
        /// Where the snapshot stands.
        snapshot_number: u64,
        /// Its hash.
        snapshot_hash: B256,
        /// Where the database stands.
        head_number: u64,
        /// Its hash.
        head_hash: B256,
    },
    /// No snapshot, and the database is past genesis.
    #[error(
        "no QMDB snapshot at {path} and the database head is block {head_number}; a QMDB chain \
         cannot start from execution state alone"
    )]
    NoSnapshot {
        /// Where the snapshot was looked for.
        path: PathBuf,
        /// The database head.
        head_number: u64,
    },
    /// The genesis alloc produced a root other than the one in the genesis
    /// header — the chain spec was not built for QMDB.
    #[error(
        "genesis alloc has QMDB root {computed} but the genesis header carries {header}; \
         the chain spec must declare stateScheme \"qmdb\" so its genesis is built for QMDB"
    )]
    GenesisRootMismatch {
        /// What the alloc hashes to.
        computed: B256,
        /// What the header says.
        header: B256,
    },
    /// The trees themselves refused an operation.
    #[error(transparent)]
    State(#[from] StateError),
    /// The snapshot file could not be read or written.
    #[error("QMDB snapshot at {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: std::io::Error,
    },
    /// The snapshot file did not decode.
    #[error("QMDB snapshot at {path} is unreadable: {source}")]
    Decode {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: bincode::Error,
    },
}

struct Inner {
    forest: Mutex<Option<QmdbForest>>,
    chain: Arc<ChainSpec>,
    dir: PathBuf,
    persistence: Mutex<Persistence>,
}

/// One canonical block as the delta log records it: enough to re-apply it on
/// the persisted tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeltaRecord {
    number: u64,
    hash: B256,
    parent: B256,
    ops: Vec<n42_twig_core::qmdb_compat::QmdbOperation>,
}

/// Where the on-disk state stands: the base snapshot and the delta log
/// together cover the chain up to `covered`.
///
/// A forest at a live chain's scale is gigabytes; writing it whole for every
/// block was the cost of the first design, and it does not fit a block
/// period. So the base is rewritten in the background and only every so
/// often, and each canonical block appends its leaf operations to a log the
/// next start replays on the base.
#[derive(Default)]
struct Persistence {
    /// The head the base plus the log stand at; `None` until the first write.
    covered: Option<(u64, B256)>,
    /// The head of the base snapshot on disk.
    base: Option<(u64, B256)>,
    /// Bytes appended to the log since the base was last rewritten.
    delta_bytes: u64,
    /// A base rewrite in flight, with the head it will stand at.
    rewrite: Option<(std::thread::JoinHandle<Result<(), NodeStateError>>, (u64, B256))>,
}

/// A handle to the node's QMDB state. Cheap to clone; all clones share it.
#[derive(Clone)]
pub struct QmdbNodeState {
    inner: Arc<Inner>,
}

/// Two handles are equal when they share the forest — the only comparison that
/// means anything for a handle, and what lets types holding one keep their
/// derived `PartialEq`.
impl PartialEq for QmdbNodeState {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for QmdbNodeState {}

impl std::fmt::Debug for QmdbNodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let forest = self.lock();
        f.debug_struct("QmdbNodeState")
            .field("dir", &self.inner.dir)
            .field("initialised", &forest.is_some())
            .field("head", &forest.as_ref().map(QmdbForest::head))
            .finish()
    }
}

impl QmdbNodeState {
    /// A handle for `chain`, persisting under `dir`. Not yet usable — see
    /// [`Self::initialize`].
    pub fn new(chain: Arc<ChainSpec>, dir: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(Inner {
                forest: Mutex::new(None),
                chain,
                dir: dir.into(),
                persistence: Mutex::new(Persistence::default()),
            }),
        }
    }

    /// Where the snapshot lives.
    pub fn snapshot_path(&self) -> PathBuf {
        self.inner.dir.join(SNAPSHOT_FILE)
    }

    /// Where the delta log lives.
    pub fn delta_path(&self) -> PathBuf {
        self.inner.dir.join(DELTA_FILE)
    }

    fn persistence(&self) -> MutexGuard<'_, Persistence> {
        self.inner
            .persistence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock(&self) -> MutexGuard<'_, Option<QmdbForest>> {
        self.inner
            .forest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Runs `f` on the forest, or fails if nothing has initialised it.
    fn with_forest<T>(
        &self,
        f: impl FnOnce(&mut QmdbForest) -> Result<T, StateError>,
    ) -> Result<T, NodeStateError> {
        let mut guard = self.lock();
        let forest = guard.as_mut().ok_or(NodeStateError::Uninitialised)?;
        Ok(f(forest)?)
    }

    /// Restores the trees for a database whose canonical head is `head`.
    ///
    /// From the snapshot if it matches the head; from the alloc if the database
    /// is at genesis; otherwise an error, since a QMDB chain cannot start from
    /// execution state alone. Idempotent once initialised.
    ///
    /// The snapshot is read and decoded — or the alloc replayed — with the
    /// lock released: a forest is hundreds of megabytes on a live chain, and
    /// every other holder of this handle (the mobile endpoint's root and
    /// proofs, the engine's `is_initialized`, `Debug`) would otherwise wait
    /// out the file read behind the lock rather than answer at once that
    /// nothing is initialised yet. Two callers racing here both read; the
    /// first to take the lock installs, the second finds it done.
    pub fn initialize(&self, head: (u64, B256)) -> Result<(), NodeStateError> {
        if self.lock().is_some() {
            return Ok(());
        }
        let (head_number, head_hash) = head;
        let path = self.snapshot_path();

        let mut base = None;
        let forest = match read_snapshot(&path)? {
            Some(snapshot) if snapshot.head_hash == head_hash => {
                info!(target: "n42.qmdb", block = head_number, %head_hash, "restored the QMDB forest");
                base = Some((snapshot.head_number, snapshot.head_hash));
                QmdbForest::from_snapshot(&snapshot)?
            }
            Some(snapshot) => {
                // Behind the head: the delta log may carry the rest.
                let (snapshot_number, snapshot_hash) = (snapshot.head_number, snapshot.head_hash);
                let mut forest = QmdbForest::from_snapshot(&snapshot)?;
                let replayed = replay_deltas(&self.delta_path(), &mut forest, head_hash)?;
                if forest.head().1 != head_hash {
                    return Err(NodeStateError::SnapshotMismatch {
                        snapshot_number: forest.head().0,
                        snapshot_hash: forest.head().1,
                        head_number,
                        head_hash,
                    });
                }
                info!(target: "n42.qmdb", base = snapshot_number, %snapshot_hash, replayed, block = head_number, %head_hash, "restored the QMDB forest from the base snapshot and the delta log");
                base = Some((snapshot_number, snapshot_hash));
                forest
            }
            None if head_number == 0 => {
                let chain = &self.inner.chain;
                let forest =
                    QmdbForest::genesis(head_hash, &changes_from_alloc(&chain.genesis.alloc))?;
                let header_root = chain.genesis_header.state_root;
                if forest.root() != header_root {
                    return Err(NodeStateError::GenesisRootMismatch {
                        computed: forest.root(),
                        header: header_root,
                    });
                }
                info!(target: "n42.qmdb", root = %forest.root(), "seeded the QMDB forest from the genesis alloc");
                forest
            }
            None => {
                return Err(NodeStateError::NoSnapshot { path, head_number });
            }
        };
        let mut guard = self.lock();
        if guard.is_none() {
            let mut persistence = self.persistence();
            // Seeded from the alloc, nothing is on disk yet: the first
            // canonical head is written whole.
            persistence.covered = base.map(|_| forest.head());
            persistence.base = base;
            persistence.delta_bytes = std::fs::metadata(self.delta_path()).map(|m| m.len()).unwrap_or(0);
            *guard = Some(forest);
        }
        Ok(())
    }

    /// Restores the forest from a cross-client portable snapshot — gov5's
    /// `n42-qmdb-export` output, or this node's own [`Self::portable_export`]
    /// — for a database being initialised at the snapshot's block rather than
    /// at genesis. The snapshot is authenticated, bound to `(chain_id,
    /// genesis_hash)`, must be at `expected_head`, and its root must equal
    /// `expected_root`, the state root of the header the caller trusts.
    /// Persisted at once so the node's next start finds it under that head.
    pub fn initialize_from_portable(
        &self,
        portable: &[u8],
        chain_id: u64,
        genesis_hash: B256,
        expected_head: (u64, B256),
        expected_root: B256,
    ) -> Result<(), NodeStateError> {
        use n42_twig_core::qmdb_compat::QmdbPortableSnapshot;
        let snapshot = QmdbPortableSnapshot::decode(portable)
            .map_err(|e| NodeStateError::Portable(e.to_string()))?;
        let at = (snapshot.block_number, B256::from(snapshot.block_hash));
        if at != expected_head {
            return Err(NodeStateError::Portable(format!(
                "snapshot is at block {} {:?}, the header at {} {:?}",
                at.0, at.1, expected_head.0, expected_head.1
            )));
        }
        let tree = snapshot
            .verify_and_build(chain_id, &genesis_hash.0)
            .map_err(|e| NodeStateError::Portable(e.to_string()))?;
        let root = B256::from(tree.root());
        if root != expected_root {
            return Err(NodeStateError::Portable(format!(
                "snapshot root {root:?} is not the header's state root {expected_root:?}"
            )));
        }
        let mut forest = QmdbForest::from_tree(expected_head.0, expected_head.1, tree);
        write_snapshot(&self.snapshot_path(), &forest.snapshot()?)?;
        truncate_deltas(&self.delta_path())?;
        info!(target: "n42.qmdb", block = expected_head.0, head = %expected_head.1, %root, "restored the QMDB forest from a portable snapshot");
        {
            let mut persistence = self.persistence();
            persistence.covered = Some(expected_head);
            persistence.base = Some(expected_head);
            persistence.delta_bytes = 0;
        }
        *self.lock() = Some(forest);
        Ok(())
    }

    /// The persisted forest as a cross-client portable snapshot, for another
    /// node to start from. Reads the snapshot file; the node need not be
    /// running.
    pub fn portable_export(&self, chain_id: u64, genesis_hash: B256) -> Result<Vec<u8>, NodeStateError> {
        use n42_twig_core::qmdb_compat::{QmdbPortableSnapshot, QmdbSlotEntry, QmdbSlotSnapshot};
        let path = self.snapshot_path();
        let snapshot = read_snapshot(&path)?.ok_or(NodeStateError::NoSnapshot { path, head_number: 0 })?;
        let tree = QmdbForest::from_snapshot(&snapshot)?;
        let entries = snapshot
            .tree
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
        let portable = QmdbPortableSnapshot {
            chain_id,
            genesis_hash: genesis_hash.0,
            block_number: snapshot.head_number,
            block_hash: snapshot.head_hash.0,
            root: tree.root().0,
            slots: QmdbSlotSnapshot { next_slot: snapshot.tree.next_slot, entries },
            leaf_form: snapshot.tree.leaf_form.clone(),
        };
        portable.encode().map_err(|e| NodeStateError::Portable(e.to_string()))
    }

    /// Whether [`Self::initialize`] has run.
    pub fn is_initialized(&self) -> bool {
        self.lock().is_some()
    }

    /// Computes the tree a block would have on `parent`, for a producer that
    /// will learn the block's hash only after sealing the root into it.
    pub fn compute(&self, parent: B256, changes: &BlockChanges) -> Result<PreparedBlock, NodeStateError> {
        self.with_forest(|forest| forest.compute(parent, changes))
    }

    /// Files a producer's computed tree under the block it turned out to be.
    pub fn insert(&self, block_hash: B256, number: u64, prepared: PreparedBlock) -> Result<(), NodeStateError> {
        self.with_forest(|forest| forest.insert(block_hash, number, prepared))
    }

    /// Computes a validated block's root and files its tree if the header agrees.
    ///
    /// Returns the computed root either way — the validator compares it to the
    /// header and is the one that declares the block invalid — but only a block
    /// whose header matches gets a tree. Filing an invalid block's tree would
    /// let a later block build on state consensus never accepted.
    pub fn validate_block(
        &self,
        parent: B256,
        block_hash: B256,
        number: u64,
        changes: &BlockChanges,
        header_root: B256,
    ) -> Result<B256, NodeStateError> {
        self.with_forest(|forest| {
            if let Some(root) = forest.root_of(&block_hash) {
                return Ok(root);
            }
            let prepared = forest.compute(parent, changes)?;
            let root = prepared.root;
            if root == header_root {
                forest.insert(block_hash, number, prepared)?;
            } else {
                warn!(
                    target: "n42.qmdb",
                    %block_hash, number, computed = %root, header = %header_root,
                    "block's state root does not match its QMDB root",
                );
            }
            Ok(root)
        })
    }

    /// The root after `block_hash`, if its tree is held.
    pub fn root_of(&self, block_hash: &B256) -> Option<B256> {
        self.lock().as_ref()?.root_of(block_hash)
    }

    /// The canonical head the forest stands at.
    pub fn head(&self) -> Option<(u64, B256)> {
        self.lock().as_ref().map(QmdbForest::head)
    }

    /// Advances the canonical head and persists it: the blocks from the
    /// persisted head to the new one go to the delta log; the base snapshot
    /// is rewritten in the background once the log is long enough, and
    /// whole, at once, only when the new head does not descend from what
    /// is on disk.
    ///
    /// A head the forest does not hold is an error rather than a silent gap: it
    /// means a block reached the canonical chain without passing through this
    /// node's validation, and the forest can no longer compute the next root.
    pub fn on_canonical(&self, block_hash: B256) -> Result<(), NodeStateError> {
        let mut persistence = self.persistence();
        // A finished base rewrite: adopt it, and drop the log's prefix it
        // made redundant.
        if persistence.rewrite.as_ref().is_some_and(|(handle, _)| handle.is_finished()) {
            let (handle, at) = persistence.rewrite.take().expect("checked above");
            match handle.join() {
                Ok(Ok(())) => {
                    persistence.base = Some(at);
                    persistence.delta_bytes = trim_deltas(&self.delta_path(), at.0)?;
                    info!(target: "n42.qmdb", block = at.0, head = %at.1, log_bytes = persistence.delta_bytes, "base snapshot rewritten");
                }
                Ok(Err(err)) => warn!(target: "n42.qmdb", %err, "the base snapshot rewrite failed; the delta log keeps growing"),
                Err(_) => warn!(target: "n42.qmdb", "the base snapshot rewrite panicked; the delta log keeps growing"),
            }
        }
        let covered = persistence.covered;
        let (head, path, full) = self.with_forest(|forest| {
            let path = covered.and_then(|(_, from)| forest.path_between(from, block_hash));
            forest.set_canonical(block_hash)?;
            let head = forest.head();
            match path {
                Some(path) => Ok((head, path, None)),
                None => Ok((head, Vec::new(), Some(forest.snapshot()?))),
            }
        })?;
        if let Some(snapshot) = full {
            // Not an extension of what is on disk (first write, or a head the
            // log cannot reach): the whole tree, now.
            write_snapshot(&self.snapshot_path(), &snapshot)?;
            truncate_deltas(&self.delta_path())?;
            persistence.base = Some(head);
            persistence.delta_bytes = 0;
            debug!(target: "n42.qmdb", block = head.0, %block_hash, "persisted the QMDB head whole");
        } else {
            let mut bytes = 0u64;
            let mut log = open_delta_log(&self.delta_path())?;
            for (number, hash, parent, ops) in path {
                bytes += append_delta(&mut log, &DeltaRecord { number, hash, parent, ops })?;
            }
            use std::io::Write as _;
            log.flush().map_err(|source| NodeStateError::Io { path: self.delta_path(), source })?;
            persistence.delta_bytes += bytes;
            debug!(target: "n42.qmdb", block = head.0, %block_hash, log_bytes = persistence.delta_bytes, "appended the QMDB head to the delta log");
        }
        persistence.covered = Some(head);
        // Time for a new base? Copy the tree under the lock, write it off it.
        let since_base = persistence.base.map_or(u64::MAX, |(number, _)| head.0.saturating_sub(number));
        if persistence.rewrite.is_none()
            && (persistence.delta_bytes >= DELTA_REWRITE_BYTES || since_base >= DELTA_REWRITE_BLOCKS)
        {
            let snapshot = self.with_forest(|forest| forest.snapshot())?;
            let path = self.snapshot_path();
            let at = (snapshot.head_number, snapshot.head_hash);
            info!(target: "n42.qmdb", block = at.0, head = %at.1, "rewriting the base snapshot in the background");
            let handle = std::thread::Builder::new()
                .name("qmdb-base-snapshot".into())
                .spawn(move || write_snapshot(&path, &snapshot))
                .map_err(|source| NodeStateError::Io { path: self.snapshot_path(), source })?;
            persistence.rewrite = Some((handle, at));
        }
        Ok(())
    }

    /// Writes the base snapshot at the canonical head now, synchronously —
    /// for a shutdown, so the next start need not replay the log. Waits for
    /// a background rewrite first.
    pub fn persist_now(&self) -> Result<(), NodeStateError> {
        let mut persistence = self.persistence();
        if let Some((handle, _)) = persistence.rewrite.take() {
            let _ = handle.join();
        }
        let snapshot = self.with_forest(|forest| forest.snapshot())?;
        write_snapshot(&self.snapshot_path(), &snapshot)?;
        truncate_deltas(&self.delta_path())?;
        persistence.base = Some((snapshot.head_number, snapshot.head_hash));
        persistence.covered = persistence.base;
        persistence.delta_bytes = 0;
        Ok(())
    }
}

impl StateProofProvider for QmdbNodeState {
    fn state_root(&self) -> B256 {
        self.lock().as_ref().map(QmdbForest::root).unwrap_or_default()
    }

    fn prove_account(&self, address: Address) -> Option<QmdbProof> {
        self.lock().as_mut()?.prove_account(address)
    }

    fn prove_storage(&self, address: Address, slot: B256) -> Option<QmdbProof> {
        self.lock().as_mut()?.prove_storage(address, slot)
    }

    fn prove_account_anchored(&self, address: Address) -> Option<(B256, QmdbProof)> {
        let mut guard = self.lock();
        let forest = guard.as_mut()?;
        let proof = forest.prove_account(address)?;
        Some((forest.root(), proof))
    }

    fn prove_storage_anchored(&self, address: Address, slot: B256) -> Option<(B256, QmdbProof)> {
        let mut guard = self.lock();
        let forest = guard.as_mut()?;
        let proof = forest.prove_storage(address, slot)?;
        Some((forest.root(), proof))
    }
}

fn open_delta_log(path: &Path) -> Result<std::io::BufWriter<std::fs::File>, NodeStateError> {
    let io = |source| NodeStateError::Io { path: path.to_path_buf(), source };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let file = std::fs::OpenOptions::new().create(true).append(true).open(path).map_err(io)?;
    Ok(std::io::BufWriter::new(file))
}

/// Appends one record, length-prefixed; returns the bytes written.
fn append_delta(log: &mut std::io::BufWriter<std::fs::File>, record: &DeltaRecord) -> Result<u64, NodeStateError> {
    use std::io::Write as _;
    let bytes = bincode::serialize(record).map_err(|source| NodeStateError::Decode {
        path: PathBuf::from(DELTA_FILE),
        source,
    })?;
    let io = |source| NodeStateError::Io { path: PathBuf::from(DELTA_FILE), source };
    log.write_all(&(bytes.len() as u32).to_le_bytes()).map_err(io)?;
    log.write_all(&bytes).map_err(io)?;
    Ok(4 + bytes.len() as u64)
}

/// Every record of the log, in order. A truncated tail — a crash mid-append
/// — ends the read; what precedes it is whole.
fn read_deltas(path: &Path) -> Result<Vec<DeltaRecord>, NodeStateError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(NodeStateError::Io { path: path.to_path_buf(), source }),
    };
    let mut records = Vec::new();
    let mut cursor = 0usize;
    while cursor + 4 <= bytes.len() {
        let len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().expect("four bytes")) as usize;
        let start = cursor + 4;
        let Some(end) = start.checked_add(len).filter(|end| *end <= bytes.len()) else {
            warn!(target: "n42.qmdb", offset = cursor, "the delta log ends in a partial record; ignoring it");
            break;
        };
        let record: DeltaRecord = bincode::deserialize(&bytes[start..end]).map_err(|source| NodeStateError::Decode {
            path: path.to_path_buf(),
            source,
        })?;
        records.push(record);
        cursor = end;
    }
    Ok(records)
}

/// Re-applies the log's records that chain from the forest's head, stopping
/// at `target` if it is reached. Returns how many were applied.
fn replay_deltas(path: &Path, forest: &mut QmdbForest, target: B256) -> Result<usize, NodeStateError> {
    let mut applied = 0usize;
    for record in read_deltas(path)? {
        if forest.head().1 == target {
            break;
        }
        if record.parent != forest.head().1 {
            continue;
        }
        forest.apply_ops(record.parent, record.hash, record.number, record.ops)?;
        forest.set_canonical(record.hash)?;
        applied += 1;
    }
    Ok(applied)
}

/// Drops the log's records at or below `base_number`; returns the new size.
fn trim_deltas(path: &Path, base_number: u64) -> Result<u64, NodeStateError> {
    let keep: Vec<DeltaRecord> = read_deltas(path)?.into_iter().filter(|record| record.number > base_number).collect();
    let temp = path.with_extension("bin.tmp");
    let io = |source| NodeStateError::Io { path: path.to_path_buf(), source };
    {
        let file = std::fs::File::create(&temp).map_err(io)?;
        let mut log = std::io::BufWriter::new(file);
        for record in &keep {
            append_delta(&mut log, record)?;
        }
        use std::io::Write as _;
        log.flush().map_err(io)?;
    }
    std::fs::rename(&temp, path).map_err(io)?;
    std::fs::metadata(path).map(|m| m.len()).map_err(io)
}

fn truncate_deltas(path: &Path) -> Result<(), NodeStateError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(NodeStateError::Io { path: path.to_path_buf(), source }),
    }
}

fn read_snapshot(path: &Path) -> Result<Option<ForestSnapshot>, NodeStateError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(NodeStateError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    bincode::deserialize(&bytes)
        .map(Some)
        .map_err(|source| NodeStateError::Decode {
            path: path.to_path_buf(),
            source,
        })
}

/// Writes to a temporary file and renames, so a crash mid-write leaves the
/// previous snapshot rather than a truncated one. A truncated snapshot would
/// fail to decode and stop the node; a stale one is merely behind, which the
/// startup check reports.
fn write_snapshot(path: &Path, snapshot: &ForestSnapshot) -> Result<(), NodeStateError> {
    let io = |source| NodeStateError::Io {
        path: path.to_path_buf(),
        source,
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let bytes = bincode::serialize(snapshot).map_err(|source| NodeStateError::Decode {
        path: path.to_path_buf(),
        source,
    })?;
    let temp = path.with_extension("bin.tmp");
    std::fs::write(&temp, &bytes).map_err(io)?;
    std::fs::rename(&temp, path).map_err(io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_genesis::Genesis;

    fn qmdb_chain() -> Arc<ChainSpec> {
        let genesis: Genesis = serde_json::from_str(
            r#"{
                "config": { "chainId": 1143, "shanghaiTime": 0, "cancunTime": 0, "stateScheme": "qmdb" },
                "alloc": { "0x0000000000000000000000000000000000000001": { "balance": "0x64" } },
                "difficulty": "0x0", "gasLimit": "0x1c9c380", "timestamp": "0x0",
                "extraData": "0x", "nonce": "0x0",
                "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "coinbase": "0x0000000000000000000000000000000000000000",
                "number": "0x0", "gasUsed": "0x0",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }"#,
        )
        .unwrap();
        Arc::new(crate::chainspec::with_declared_state_scheme(genesis.into()).unwrap())
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("n42-qmdb-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn nothing_works_before_initialisation() {
        let state = QmdbNodeState::new(qmdb_chain(), scratch("uninit"));
        assert!(matches!(
            state.compute(B256::ZERO, &BlockChanges::new()),
            Err(NodeStateError::Uninitialised)
        ));
    }

    #[test]
    fn a_genesis_database_is_seeded_from_the_alloc() {
        let chain = qmdb_chain();
        let state = QmdbNodeState::new(chain.clone(), scratch("genesis"));
        state.initialize((0, chain.genesis_hash())).unwrap();
        assert_eq!(state.state_root(), chain.genesis_header.state_root);
    }

    /// The chain spec was parsed without the scheme, so its genesis header
    /// carries an MPT root. Seeding from the alloc gives a QMDB root, and the two
    /// must not be silently reconciled.
    #[test]
    fn a_genesis_built_for_mpt_is_refused() {
        let genesis: Genesis = serde_json::from_str(
            r#"{
                "config": { "chainId": 1143, "shanghaiTime": 0, "cancunTime": 0 },
                "alloc": { "0x0000000000000000000000000000000000000001": { "balance": "0x64" } },
                "difficulty": "0x0", "gasLimit": "0x1c9c380", "timestamp": "0x0",
                "extraData": "0x", "nonce": "0x0",
                "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "coinbase": "0x0000000000000000000000000000000000000000",
                "number": "0x0", "gasUsed": "0x0",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }"#,
        )
        .unwrap();
        let chain: Arc<ChainSpec> = Arc::new(genesis.into());
        let state = QmdbNodeState::new(chain.clone(), scratch("mpt-genesis"));
        assert!(matches!(
            state.initialize((0, chain.genesis_hash())),
            Err(NodeStateError::GenesisRootMismatch { .. })
        ));
    }

    #[test]
    fn the_head_survives_a_restart_and_a_stale_snapshot_is_refused() {
        let chain = qmdb_chain();
        let dir = scratch("restart");
        let genesis_hash = chain.genesis_hash();

        let state = QmdbNodeState::new(chain.clone(), &dir);
        state.initialize((0, genesis_hash)).unwrap();
        let block1 = B256::repeat_byte(0x11);
        let root = state
            .validate_block(genesis_hash, block1, 1, &BlockChanges::new(), {
                // Compute the expected root first so the header "matches".
                state.compute(genesis_hash, &BlockChanges::new()).unwrap().root
            })
            .unwrap();
        state.on_canonical(block1).unwrap();

        // A new process, same directory, database at block 1.
        let restarted = QmdbNodeState::new(chain.clone(), &dir);
        restarted.initialize((1, block1)).unwrap();
        assert_eq!(restarted.head(), Some((1, block1)));
        assert_eq!(restarted.state_root(), root);

        // A database that moved on without this forest.
        let behind = QmdbNodeState::new(chain, &dir);
        assert!(matches!(
            behind.initialize((5, B256::repeat_byte(0x55))),
            Err(NodeStateError::SnapshotMismatch { .. })
        ));
    }

    #[test]
    fn canonical_blocks_go_to_the_delta_log_and_a_restart_replays_them() {
        let chain = qmdb_chain();
        let dir = scratch("deltas");
        let genesis_hash = chain.genesis_hash();
        let state = QmdbNodeState::new(chain.clone(), &dir);
        state.initialize((0, genesis_hash)).unwrap();

        let mut parent = genesis_hash;
        let mut heads = Vec::new();
        for number in 1..=6u64 {
            let mut changes = BlockChanges::new();
            changes.accounts.insert(
                Address::with_last_byte(number as u8),
                Some(n42_qmdb_state::AccountState {
                    nonce: 0,
                    balance: alloy_primitives::U256::from(number * 1000),
                    code_hash: B256::from(n42_twig_core::qmdb_compat::GOV5_EMPTY_CODE_HASH),
                }),
            );
            let hash = B256::repeat_byte(0x10 + number as u8);
            let root = state.compute(parent, &changes).unwrap().root;
            state.validate_block(parent, hash, number, &changes, root).unwrap();
            state.on_canonical(hash).unwrap();
            heads.push((number, hash, root));
            parent = hash;
        }
        // The first canonical write is the base; the rest are log records.
        let base = read_snapshot(&state.snapshot_path()).unwrap().unwrap();
        assert_eq!(base.head_number, 1);
        assert_eq!(read_deltas(&state.delta_path()).unwrap().len(), 5);

        let (number, hash, root) = heads[5];
        let restarted = QmdbNodeState::new(chain.clone(), &dir);
        restarted.initialize((number, hash)).unwrap();
        assert_eq!(restarted.head(), Some((number, hash)));
        assert_eq!(restarted.state_root(), root);

        // A restart at an earlier canonical block replays up to it only.
        let (number, hash, root) = heads[2];
        let earlier = QmdbNodeState::new(chain.clone(), &dir);
        earlier.initialize((number, hash)).unwrap();
        assert_eq!(earlier.state_root(), root);

        // persist_now folds everything into the base.
        restarted.persist_now().unwrap();
        assert_eq!(read_snapshot(&restarted.snapshot_path()).unwrap().unwrap().head_number, 6);
        assert!(read_deltas(&restarted.delta_path()).unwrap().is_empty());
        let again = QmdbNodeState::new(chain, &dir);
        again.initialize((6, heads[5].1)).unwrap();
        assert_eq!(again.state_root(), heads[5].2);
    }

    #[test]
    fn concurrent_initialisation_installs_one_forest_and_reads_off_the_lock() {
        let chain = qmdb_chain();
        let dir = scratch("concurrent-init");
        let genesis_hash = chain.genesis_hash();
        // Write a snapshot at genesis so both callers take the file path.
        let seed = QmdbNodeState::new(chain.clone(), &dir);
        seed.initialize((0, genesis_hash)).unwrap();
        seed.on_canonical(genesis_hash).unwrap();
        assert!(seed.snapshot_path().exists());
        let root = seed.state_root();

        let state = QmdbNodeState::new(chain, &dir);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let state = &state;
                scope.spawn(move || state.initialize((0, genesis_hash)).unwrap());
            }
        });
        assert!(state.is_initialized());
        assert_eq!(state.head(), Some((0, genesis_hash)));
        assert_eq!(state.state_root(), root);
        // A third initialisation is a no-op, not a second forest.
        state.initialize((0, genesis_hash)).unwrap();
        assert_eq!(state.head(), Some((0, genesis_hash)));
    }

    #[test]
    fn an_anchored_proof_carries_the_root_it_verifies_against() {
        let chain = qmdb_chain();
        let state = QmdbNodeState::new(chain.clone(), scratch("anchored"));
        let genesis_hash = chain.genesis_hash();
        state.initialize((0, genesis_hash)).unwrap();
        let address: Address = "0x0000000000000000000000000000000000000001".parse().unwrap();
        let (root, proof) = state.prove_account_anchored(address).expect("the alloc account has a leaf");
        assert_eq!(root, state.state_root());
        assert!(proof.verify_for_key(&root.0, &proof.key), "the proof verifies against the root it came with");
        assert!(state.prove_storage_anchored(address, B256::ZERO).is_none(), "no storage leaf");
        assert!(
            QmdbNodeState::new(chain, scratch("anchored-uninit")).prove_account_anchored(address).is_none(),
            "nothing before initialisation"
        );
    }

    #[test]
    fn a_database_past_genesis_with_no_snapshot_cannot_start() {
        let chain = qmdb_chain();
        let state = QmdbNodeState::new(chain, scratch("no-snapshot"));
        assert!(matches!(
            state.initialize((7, B256::repeat_byte(0x77))),
            Err(NodeStateError::NoSnapshot { head_number: 7, .. })
        ));
    }

    #[test]
    fn a_block_whose_header_disagrees_gets_no_tree() {
        let chain = qmdb_chain();
        let state = QmdbNodeState::new(chain.clone(), scratch("mismatch"));
        let genesis_hash = chain.genesis_hash();
        state.initialize((0, genesis_hash)).unwrap();

        let bad = B256::repeat_byte(0xBB);
        let computed = state
            .validate_block(genesis_hash, bad, 1, &BlockChanges::new(), B256::repeat_byte(0xEE))
            .unwrap();
        assert_ne!(computed, B256::repeat_byte(0xEE), "the real root is reported");
        assert!(state.root_of(&bad).is_none(), "but the invalid block leaves no tree");
        assert!(matches!(
            state.on_canonical(bad),
            Err(NodeStateError::State(StateError::UnknownBlock(_)))
        ));
    }
}
