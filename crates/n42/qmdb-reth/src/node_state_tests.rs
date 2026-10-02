// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node state beyond the happy path: portable snapshots in both
//! directions, root computation from operations, the state-proof provider,
//! the read view's hand-off with the database, compaction and checkpoint
//! rotation driven step by step, and the file helpers' failure modes.
//!
//! Everything runs on small chains in per-test scratch directories; nothing
//! here depends on the 20,000-block rotation the existing suite uses.

use super::*;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, U256};
use n42_qmdb_state::AccountState;

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
    .expect("genesis");
    Arc::new(crate::chainspec::with_declared_state_scheme(genesis.into()).expect("qmdb chain"))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n42-qmdb-more-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The snapshot a node wrote at its first canonical block.
fn first_snapshot(name: &str) -> ForestSnapshot {
    let (state, _, _, _, _) = node_at(name, false, 1);
    read_snapshot(&state.snapshot_path()).expect("read").expect("the first checkpoint")
}

fn changes_for(number: u64) -> BlockChanges {
    let mut changes = BlockChanges::new();
    changes.set_account(
        Address::from_word(B256::from(U256::from(number))),
        AccountState { nonce: number, balance: U256::from(number), code_hash: B256::ZERO },
    );
    changes.set_account(
        Address::from_word(B256::from(U256::from(7u64))),
        AccountState { nonce: number, balance: U256::from(number * 3), code_hash: B256::ZERO },
    );
    changes
}

fn hash_of(number: u64) -> B256 {
    B256::from(U256::from(number) << 64)
}

/// Computes, files and canonicalises block `number` on `parent`.
fn advance(state: &QmdbNodeState, number: u64, parent: B256) -> (B256, B256) {
    let prepared = state.compute(parent, &changes_for(number)).expect("compute");
    let root = prepared.root;
    let hash = hash_of(number);
    state.insert(hash, number, prepared).expect("insert");
    state.on_canonical(hash).expect("canonical");
    (hash, root)
}

/// A started node standing at block `blocks`, with its head hash and root.
fn node_at(name: &str, entry_file: bool, blocks: u64) -> (QmdbNodeState, Arc<ChainSpec>, PathBuf, B256, B256) {
    let chain = qmdb_chain();
    let dir = scratch(name);
    let state = QmdbNodeState::new_with_entry_file(chain.clone(), &dir, entry_file);
    state.initialize((0, chain.genesis_hash())).expect("initialize");
    let (mut head, mut root) = (chain.genesis_hash(), state.state_root());
    for number in 1..=blocks {
        (head, root) = advance(&state, number, head);
    }
    (state, chain, dir, head, root)
}

// ---------------------------------------------------------------------------
// Portable snapshots
// ---------------------------------------------------------------------------

#[test]
fn a_portable_snapshot_started_node_continues_to_the_same_roots_in_both_storage_modes() {
    for entry_file in [false, true] {
        let name = format!("portable-{entry_file}");
        let (source, chain, _, head, root) = node_at(&name, entry_file, 3);
        let bytes = source.portable_export(1143, chain.genesis_hash()).expect("export");

        let target_dir = scratch(&format!("portable-target-{entry_file}"));
        let target = QmdbNodeState::new_with_entry_file(chain.clone(), &target_dir, entry_file);
        // A log left over from another chain in this datadir must not survive.
        std::fs::create_dir_all(&target_dir).expect("dir");
        std::fs::write(target.delta_log_path(), b"stale").expect("stale log");
        target
            .initialize_from_portable(&bytes, 1143, chain.genesis_hash(), (3, head), root)
            .expect("import");
        assert_eq!(target.head(), Some((3, head)));
        assert_eq!(target.state_root(), root);
        if !entry_file {
            assert!(!target.delta_log_path().exists(), "the stale log was removed");
        }

        // Both nodes extend the chain to the same root: the import is the state, not a copy of a number.
        let (_, source_root) = advance(&source, 4, head);
        let (_, target_root) = advance(&target, 4, head);
        assert_eq!(source_root, target_root, "entry_file={entry_file}");
    }
}

#[test]
fn a_portable_snapshot_that_does_not_match_its_header_is_refused_by_name() {
    let (source, chain, _, head, root) = node_at("portable-bad", false, 2);
    let bytes = source.portable_export(1143, chain.genesis_hash()).expect("export");
    let target = || QmdbNodeState::new(chain.clone(), scratch("portable-bad-target"));

    let err = target().initialize_from_portable(&bytes, 1143, chain.genesis_hash(), (9, head), root).expect_err("wrong height");
    assert!(matches!(&err, NodeStateError::Portable(m) if m.contains("snapshot is at block 2")), "{err}");

    let err = target()
        .initialize_from_portable(&bytes, 1143, chain.genesis_hash(), (2, head), B256::repeat_byte(1))
        .expect_err("wrong root");
    assert!(matches!(&err, NodeStateError::Portable(m) if m.contains("is not the header's state root")), "{err}");

    let err = target().initialize_from_portable(&bytes, 7, chain.genesis_hash(), (2, head), root).expect_err("another chain");
    assert!(matches!(err, NodeStateError::Portable(_)), "{err}");

    let err = target().initialize_from_portable(&[1, 2, 3], 1143, chain.genesis_hash(), (2, head), root).expect_err("garbage");
    assert!(matches!(err, NodeStateError::Portable(_)), "{err}");
    assert!(!target().is_initialized(), "a refused import leaves the node uninitialised");

    // Nothing persisted: nothing to export.
    let empty = QmdbNodeState::new(chain.clone(), scratch("portable-empty"));
    assert!(matches!(empty.portable_export(1143, chain.genesis_hash()), Err(NodeStateError::NoSnapshot { .. })));
}

// ---------------------------------------------------------------------------
// Roots from operations, renames, proofs, identity
// ---------------------------------------------------------------------------

#[test]
fn the_operations_api_computes_the_same_roots_as_the_changes_api_and_files_only_matching_blocks() {
    let (state, chain, _, _, _) = node_at("ops", false, 0);
    let parent = chain.genesis_hash();
    let changes = changes_for(1);
    let expected = state.compute(parent, &changes).expect("compute").root;
    let ops = || changes.operations();

    assert_eq!(state.compute_operations(parent, ops()).expect("ops").root, expected, "same root either way");
    let split = state.take_root_split(&parent).expect("the split is keyed by the parent");
    assert!(split.computed);
    assert!(state.take_root_split(&parent).is_none(), "taken once");

    // A header root that disagrees: the computed root comes back, nothing is filed.
    let block = hash_of(1);
    let root = state.validate_block_operations(parent, block, 1, ops(), B256::repeat_byte(5)).expect("validated");
    assert_eq!(root, expected);
    assert_eq!(state.root_of(&block), None, "a mismatching block gets no tree");

    // A matching one is filed, and asking again returns the filed root without computing.
    assert_eq!(state.validate_block_operations(parent, block, 1, ops(), expected).expect("validated"), expected);
    assert_eq!(state.root_of(&block), Some(expected));
    let again = state.validate_block_operations(parent, block, 1, changes_for(2).operations(), B256::ZERO).expect("again");
    assert_eq!(again, expected, "the filed block answers without recomputing");
    assert!(state.take_root_split(&block).is_some(), "the split is keyed by the block");

    // insert_block_operations files unconditionally and is idempotent.
    let second = hash_of(2);
    let second_root = state.insert_block_operations(parent, second, 1, changes_for(2).operations()).expect("insert");
    assert_ne!(second_root, expected);
    assert_eq!(state.root_of(&second), Some(second_root));
    assert_eq!(state.insert_block_operations(parent, second, 1, changes_for(9).operations()).expect("again"), second_root);

    // The changes-API validation has the same two outcomes.
    let third = hash_of(3);
    let third_changes = changes_for(3);
    let third_root = state.compute(parent, &third_changes).expect("compute").root;
    assert_eq!(state.validate_block(parent, third, 1, &third_changes, B256::repeat_byte(6)).expect("v"), third_root);
    assert_eq!(state.root_of(&third), None);
    assert_eq!(state.validate_block(parent, third, 1, &third_changes, third_root).expect("v"), third_root);
    assert_eq!(state.root_of(&third), Some(third_root));
    assert_eq!(state.validate_block(parent, third, 1, &changes_for(8), B256::ZERO).expect("v"), third_root);

    // A filed tree can be renamed once the block's real hash is known.
    let sealed = B256::repeat_byte(0xAB);
    state.rename(third, sealed).expect("rename");
    assert_eq!(state.root_of(&sealed), Some(third_root));
    assert_eq!(state.root_of(&third), None);
}

#[test]
fn nothing_is_computed_from_operations_before_initialisation() {
    let state = QmdbNodeState::new(qmdb_chain(), scratch("ops-uninit"));
    let ops = changes_for(1).operations();
    assert!(matches!(state.compute_operations(B256::ZERO, ops.clone()), Err(NodeStateError::Uninitialised)));
    assert!(matches!(
        state.validate_block_operations(B256::ZERO, B256::repeat_byte(1), 1, ops.clone(), B256::ZERO),
        Err(NodeStateError::Uninitialised)
    ));
    assert!(matches!(
        state.insert_block_operations(B256::ZERO, B256::repeat_byte(1), 1, ops),
        Err(NodeStateError::Uninitialised)
    ));
    assert_eq!(state.head(), None);
    assert_eq!(state.root_of(&B256::ZERO), None);
}

#[test]
fn proofs_are_given_for_what_the_state_holds_and_declined_for_what_it_does_not() {
    use alloy_primitives::keccak256;
    let chain = qmdb_chain();
    let state = QmdbNodeState::new(chain.clone(), scratch("proofs"));
    state.initialize((0, chain.genesis_hash())).expect("initialize");
    let known = Address::from_word(B256::from(U256::from(1u64)));
    let slot = B256::with_last_byte(3);
    let mut changes = changes_for(1);
    changes.set_storage(known, slot, U256::from(42u64));
    let prepared = state.compute(chain.genesis_hash(), &changes).expect("compute");
    let root = prepared.root;
    state.insert(hash_of(1), 1, prepared).expect("insert");
    state.on_canonical(hash_of(1)).expect("canonical");

    assert_eq!(state.state_root(), root);
    assert!(state.prove_account(known).is_some(), "a proof for a held account");
    assert!(state.prove_account(Address::with_last_byte(0xEE)).is_none());
    assert!(state.prove_storage(known, slot).is_some(), "a held slot");
    assert!(state.prove_storage(known, keccak256(b"never written")).is_none());

    // The identity: a state is equal to itself and to no other.
    let other = QmdbNodeState::new(chain, scratch("proofs-other"));
    assert!(state == state.clone());
    assert!(state != other);
    assert!(format!("{state:?}").contains("QmdbNodeState"));
}

// ---------------------------------------------------------------------------
// The read view and the database's persistence
// ---------------------------------------------------------------------------

fn viewed(name: &str, blocks: u64) -> (QmdbNodeState, Arc<crate::read_view::QmdbReadView>, Vec<B256>) {
    let chain = qmdb_chain();
    let state = QmdbNodeState::new_with_entry_file(chain.clone(), scratch(name), true);
    state.set_read_view_wanted(true);
    state.initialize((0, chain.genesis_hash())).expect("initialize");
    let view = state.read_view().expect("the view is built at initialisation");
    state.set_reader_keep_cap(128);
    assert_eq!(state.reader_keep_cap(), 128);
    assert!(state.read_view_ref().is_some());
    let mut hashes = vec![chain.genesis_hash()];
    for number in 1..=blocks {
        let (hash, _) = advance(&state, number, hashes[number as usize - 1]);
        hashes.push(hash);
    }
    (state, view, hashes)
}

#[test]
fn a_persisted_block_the_view_cannot_place_invalidates_it_and_releases_the_records() {
    // A block the tree does not have: the view's next, but off the tree's path.
    let (state, view, _) = viewed("view-unknown", 2);
    assert!(view.is_valid());
    state.on_persisted(&[(1, B256::repeat_byte(0x99))]);
    assert!(!view.is_valid(), "a persisted block whose changes are not on the path");

    // Past the next block: a gap.
    let (state, view, _) = viewed("view-gap", 2);
    state.on_persisted(&[(5, B256::repeat_byte(1))]);
    assert!(!view.is_valid(), "the database persisted past the view's next block");

    // The block the view stands on, named by another hash.
    let (state, view, _) = viewed("view-mismatch", 2);
    state.on_persisted(&[(0, B256::repeat_byte(2))]);
    assert!(!view.is_valid(), "a persisted block that is not the block the view holds");

    // Once invalid, later batches are answered by releasing records only.
    state.on_persisted(&[(1, B256::repeat_byte(3))]);
    state.on_persisted(&[]);
    assert!(!view.is_valid());

    // A block the view already holds is simply held.
    let (state, view, hashes) = viewed("view-held", 3);
    state.on_persisted(&[(1, hashes[1]), (2, hashes[2])]);
    assert_eq!(view.head(), (2, hashes[2]));
    state.on_persisted(&[(1, hashes[1])]);
    assert_eq!(view.head(), (2, hashes[2]), "an older persisted block changes nothing");
    assert!(view.is_valid());
}

#[test]
fn an_unwind_below_the_view_steps_it_back_and_one_above_it_changes_nothing() {
    let (state, view, hashes) = viewed("view-unwind", 6);
    for number in 1..=5u64 {
        state.on_persisted(&[(number, hashes[number as usize])]);
    }
    assert_eq!(view.head(), (5, hashes[5]));
    state.on_unwound(100);
    assert_eq!(view.head(), (5, hashes[5]), "above the head: nothing to undo");
    state.on_unwound(5);
    assert_eq!(view.head(), (5, hashes[5]), "at the head: nothing to undo");
    state.on_unwound(3);
    // Either the journals reach block 3 and the view steps back to it, or they
    // do not and the view is invalidated: it never keeps serving a head the
    // chain has left.
    assert!(!view.is_valid() || view.head() == (3, hashes[3]), "head {:?}", view.head());

    // No view at all: the notifications are no-ops.
    let chain = qmdb_chain();
    let plain = QmdbNodeState::new(chain.clone(), scratch("view-none"));
    plain.initialize((0, chain.genesis_hash())).expect("initialize");
    plain.on_persisted(&[(1, B256::ZERO)]);
    plain.on_unwound(0);
    assert!(plain.read_view().is_none());
    assert!(plain.read_view_ref().is_none());
}

// ---------------------------------------------------------------------------
// Compaction and checkpoint rotation, step by step
// ---------------------------------------------------------------------------

/// Rotates the log into the sealed segment as `rewrite_checkpoint` does.
fn seal_the_log(state: &QmdbNodeState) {
    std::fs::rename(state.delta_log_path(), state.sealed_log_path()).expect("rotate");
    state.cursor().log_len = 0;
}

#[test]
fn a_compaction_folds_the_sealed_segment_into_a_new_checkpoint_in_both_storage_modes() {
    for entry_file in [false, true] {
        let (state, chain, dir, head, root) = node_at(&format!("compact-{entry_file}"), entry_file, 4);
        assert!(state.delta_log_path().exists(), "deltas followed the first checkpoint");
        let (done_before, bytes_before, _, _) = state.compaction_stats();
        seal_the_log(&state);

        // A compaction for a head the segment does not reach is refused and keeps the segment.
        state.compact((4, B256::repeat_byte(9)));
        assert!(state.sealed_log_path().exists(), "entry_file={entry_file}: a failed compaction keeps its segment");
        assert_eq!(state.compaction_stats().0, done_before, "and is not counted");
        assert!(!state.cursor().compacting);

        state.compact((4, head));
        assert!(!state.sealed_log_path().exists(), "folded into the checkpoint and gone");
        let (done, bytes, _, _) = state.compaction_stats();
        assert_eq!(done, done_before + 1);
        assert!(bytes > 0 && bytes >= bytes_before);
        assert_eq!(state.compaction_phases().len(), 5);

        let restarted = QmdbNodeState::new_with_entry_file(chain, &dir, entry_file);
        restarted.initialize((4, head)).expect("restart");
        assert_eq!(restarted.head(), Some((4, head)));
        assert_eq!(restarted.state_root(), root, "entry_file={entry_file}");
    }
}

#[test]
fn a_due_checkpoint_rotates_the_log_and_the_compaction_runs_behind() {
    let (state, chain, dir, head, root) = node_at("rotate-steps", false, 4);
    let done_before = state.compaction_stats().0;

    // A compaction still running: the log keeps growing, nothing rotates.
    {
        let mut cursor = state.cursor();
        cursor.compacting = true;
        state.rewrite_checkpoint(head, &mut cursor).expect("deferred");
        cursor.compacting = false;
    }
    assert!(state.delta_log_path().exists());
    assert!(!state.sealed_log_path().exists());

    // No log to rotate: nothing happens.
    let log = std::fs::read(state.delta_log_path()).expect("log");
    std::fs::remove_file(state.delta_log_path()).expect("remove");
    {
        let mut cursor = state.cursor();
        state.rewrite_checkpoint(head, &mut cursor).expect("nothing to do");
    }
    assert!(!state.sealed_log_path().exists());
    std::fs::write(state.delta_log_path(), &log).expect("restore");

    // The log is sealed and compacted on a thread of its own.
    {
        let mut cursor = state.cursor();
        state.rewrite_checkpoint(head, &mut cursor).expect("rotated");
        assert_eq!(cursor.log_len, 0, "the log starts again");
    }
    state.wait_for_compaction();
    assert!(!state.sealed_log_path().exists());
    assert_eq!(state.compaction_stats().0, done_before + 1);

    // A segment a failed compaction left behind is retried before anything else rotates.
    let (state2, _, _, head2, _) = node_at("rotate-retry", false, 4);
    seal_the_log(&state2);
    {
        let mut cursor = state2.cursor();
        state2.rewrite_checkpoint(head2, &mut cursor).expect("retried");
    }
    state2.wait_for_compaction();
    assert!(!state2.sealed_log_path().exists(), "the leftover segment was folded");

    let restarted = QmdbNodeState::new(chain, &dir);
    restarted.initialize((4, head)).expect("restart");
    assert_eq!(restarted.state_root(), root);
}

#[test]
fn an_unreachable_checkpoint_directory_surfaces_as_an_io_error_not_a_panic() {
    let (state, _, dir, _, _) = node_at("io-fail", false, 2);
    let snapshot = read_snapshot(&state.snapshot_path()).expect("read").expect("the node persisted a snapshot");
    assert_eq!(snapshot.head_hash, hash_of(1), "the checkpoint was written at the first canonical block");
    // A file where the checkpoint's directory should be: it cannot be created.
    let blocker = dir.join("blocked");
    std::fs::write(&blocker, b"a file where a directory should be").expect("blocker");
    let bad = blocker.join("nested").join("snapshot.bin");
    let err = write_snapshot(&bad, &snapshot, &mut CompactPhases::default()).expect_err("cannot create the directory");
    assert!(matches!(err, NodeStateError::Io { ref path, .. } if path == &bad), "{err}");

    // Atomic: a good write leaves no temporary file and reads back the same.
    let good = dir.join("fresh").join("snapshot.bin");
    let len = write_snapshot(&good, &snapshot, &mut CompactPhases::default()).expect("written");
    assert_eq!(len, std::fs::metadata(&good).expect("meta").len());
    assert!(!good.with_extension("bin.tmp").exists());
    assert_eq!(read_snapshot(&good).expect("read").expect("some").head_hash, snapshot.head_hash);
}

#[test]
fn checkpoint_and_snapshot_files_that_are_missing_corrupt_or_not_files_are_told_apart() {
    let dir = scratch("files");
    std::fs::create_dir_all(&dir).expect("dir");

    assert!(read_snapshot(&dir.join("absent")).expect("absent is not an error").is_none());
    assert!(read_ckpt(&dir.join("absent")).expect("absent is not an error").is_none());

    let corrupt = dir.join("corrupt");
    std::fs::write(&corrupt, [0xffu8; 7]).expect("write");
    assert!(matches!(read_snapshot(&corrupt), Err(NodeStateError::Decode { .. })));
    assert!(matches!(read_ckpt(&corrupt), Err(NodeStateError::Decode { .. })));

    // A directory where a file should be is an I/O error, not "missing".
    assert!(matches!(read_snapshot(&dir), Err(NodeStateError::Io { .. })));
    assert!(matches!(read_ckpt(&dir), Err(NodeStateError::Io { .. })));
    assert!(matches!(replay_delta_log(&dir, first_snapshot("files-stub"), None), Err(NodeStateError::Io { .. })));

    // A checkpoint from an entry-file node round-trips through write_ckpt.
    let (_, _, node_dir, _, _) = node_at("files-ckpt", true, 1);
    let ckpt = read_ckpt(&node_dir.join(CKPT_FILE)).expect("read").expect("the node wrote a checkpoint");
    let path = dir.join("nested").join("forest.ckpt");
    let len = write_ckpt(&path, &ckpt, &mut CompactPhases::default()).expect("written");
    assert_eq!(len, std::fs::metadata(&path).expect("meta").len());
    assert_eq!(read_ckpt(&path).expect("read").expect("some").head_hash, ckpt.head_hash);
    let blocked = corrupt.join("under-a-file").join("forest.ckpt");
    assert!(matches!(write_ckpt(&blocked, &ckpt, &mut CompactPhases::default()), Err(NodeStateError::Io { .. })));
}

// ---------------------------------------------------------------------------
// The delta log
// ---------------------------------------------------------------------------

#[test]
fn replaying_a_log_skips_what_the_checkpoint_covers_and_stops_at_a_delta_it_cannot_read() {
    let (state, _, _, head, _) = node_at("replay", false, 4);
    let first = read_snapshot(&state.snapshot_path()).expect("read").expect("the first checkpoint");
    let log = state.delta_log_path();
    let log_len = std::fs::metadata(&log).expect("log").len();

    // From the first checkpoint the log reaches block 4.
    let (reached, good) = replay_delta_log(&log, first.clone(), None).expect("replay");
    assert_eq!(reached.head_hash, head);
    assert_eq!(good, log_len, "every record was good");

    // Onto a state that already holds them they are skipped, and counted as read.
    let (again, good) = replay_delta_log(&log, reached.clone(), None).expect("replay");
    assert_eq!(again.head_hash, head);
    assert_eq!(good, log_len);

    // Already at the stop: the log is not even opened.
    let (stopped, good) = replay_delta_log(&log, first.clone(), Some(first.head_hash)).expect("replay");
    assert_eq!((stopped.head_hash, good), (first.head_hash, 0));

    // Stopping part-way at a named block.
    let (partial, _) = replay_delta_log(&log, first.clone(), Some(hash_of(2))).expect("replay");
    assert_eq!(partial.head_hash, hash_of(2));

    // A record whose digest is right but whose payload is not a delta ends the replay there.
    let mut bytes = std::fs::read(&log).expect("log");
    let junk = [0xabu8; 9];
    bytes.extend_from_slice(&(junk.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&crc32fast::hash(&junk).to_le_bytes());
    bytes.extend_from_slice(&junk);
    let junk_log = log.with_extension("junk");
    std::fs::write(&junk_log, &bytes).expect("write");
    let (reached, good) = replay_delta_log(&junk_log, first.clone(), None).expect("replay");
    assert_eq!(reached.head_hash, head, "the good records before the junk were applied");
    assert_eq!(good, log_len, "and the junk was not counted");

    // A torn length field ends it too.
    let mut torn = std::fs::read(&log).expect("log");
    torn.extend_from_slice(&u64::MAX.to_le_bytes());
    torn.extend_from_slice(&[0u8; 4]);
    std::fs::write(&junk_log, &torn).expect("write");
    let (reached, good) = replay_delta_log(&junk_log, first, None).expect("replay");
    assert_eq!((reached.head_hash, good), (head, log_len));
}

#[test]
fn a_delta_is_appended_after_the_length_it_names_and_the_log_directory_is_made() {
    let (state, _, _, _, _) = node_at("append", false, 3);
    let log = state.delta_log_path();
    let first = read_snapshot(&state.snapshot_path()).expect("read").expect("snapshot");
    let (_, good) = replay_delta_log(&log, first, None).expect("replay");
    assert_eq!(good, std::fs::metadata(&log).expect("log").len());

    // The record count is a property of the file: copy the first delta out and append it elsewhere.
    let bytes = std::fs::read(&log).expect("log");
    let len = u64::from_le_bytes(bytes[..8].try_into().expect("eight")) as usize;
    let delta: ForestDelta = bincode::deserialize(&bytes[RECORD_HEADER..RECORD_HEADER + len]).expect("a delta");
    let elsewhere = scratch("append-elsewhere").join("deep").join("forest.log");
    let end = append_delta(&elsewhere, 0, &delta).expect("appended");
    assert_eq!(end, (RECORD_HEADER + len) as u64);
    assert_eq!(std::fs::metadata(&elsewhere).expect("meta").len(), end);

    // Appending "after" a shorter length truncates what was beyond it.
    let twice = append_delta(&elsewhere, end, &delta).expect("appended");
    assert_eq!(twice, end * 2);
    let again = append_delta(&elsewhere, end, &delta).expect("appended");
    assert_eq!(again, twice, "the second record was replaced, not duplicated");
    assert_eq!(std::fs::metadata(&elsewhere).expect("meta").len(), twice);

    // Under a file there is no directory to make.
    let blocker = elsewhere.with_file_name("blocker");
    std::fs::write(&blocker, b"x").expect("file");
    let err = append_delta(&blocker.join("sub").join("forest.log"), 0, &delta).expect_err("no directory");
    assert!(matches!(err, NodeStateError::Io { .. }), "{err}");
}
