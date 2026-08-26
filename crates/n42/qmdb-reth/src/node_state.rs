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

/// Why the node's QMDB state could not be used.
#[derive(Debug, thiserror::Error)]
pub enum NodeStateError {
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
            }),
        }
    }

    /// Where the snapshot lives.
    pub fn snapshot_path(&self) -> PathBuf {
        self.inner.dir.join(SNAPSHOT_FILE)
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
    pub fn initialize(&self, head: (u64, B256)) -> Result<(), NodeStateError> {
        let mut guard = self.lock();
        if guard.is_some() {
            return Ok(());
        }
        let (head_number, head_hash) = head;
        let path = self.snapshot_path();

        let forest = match read_snapshot(&path)? {
            Some(snapshot) if snapshot.head_hash == head_hash => {
                info!(target: "n42.qmdb", block = head_number, %head_hash, "restored the QMDB forest");
                QmdbForest::from_snapshot(&snapshot)?
            }
            Some(snapshot) => {
                return Err(NodeStateError::SnapshotMismatch {
                    snapshot_number: snapshot.head_number,
                    snapshot_hash: snapshot.head_hash,
                    head_number,
                    head_hash,
                });
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
        *guard = Some(forest);
        Ok(())
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
        self.with_forest(|forest| {
            forest.insert(block_hash, number, prepared);
            Ok(())
        })
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
                forest.insert(block_hash, number, prepared);
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

    /// Advances the canonical head and persists its tree.
    ///
    /// A head the forest does not hold is an error rather than a silent gap: it
    /// means a block reached the canonical chain without passing through this
    /// node's validation, and the forest can no longer compute the next root.
    pub fn on_canonical(&self, block_hash: B256) -> Result<(), NodeStateError> {
        let snapshot = self.with_forest(|forest| {
            forest.set_canonical(block_hash)?;
            Ok(forest.snapshot())
        })?;
        write_snapshot(&self.snapshot_path(), &snapshot)?;
        debug!(target: "n42.qmdb", block = snapshot.head_number, %block_hash, "persisted the QMDB head");
        Ok(())
    }
}

impl StateProofProvider for QmdbNodeState {
    fn state_root(&self) -> B256 {
        self.lock().as_ref().map(QmdbForest::root).unwrap_or_default()
    }

    fn prove_account(&self, address: Address) -> Option<QmdbProof> {
        self.lock().as_ref()?.prove_account(address)
    }

    fn prove_storage(&self, address: Address, slot: B256) -> Option<QmdbProof> {
        self.lock().as_ref()?.prove_storage(address, slot)
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
