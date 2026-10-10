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
    let (again, good) = replay_delta_log(&log, reached, None).expect("replay");
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

// ---------------------------------------------------------------------------
// Roots on a leased tree (N42_QMDB_COMPUTE_OFFLOCK) and batched persistence
// (N42_QMDB_PERSIST_BATCH)
// ---------------------------------------------------------------------------

/// A viewed state at genesis with the two switches set as given.
fn switched(name: &str, offlock: bool, batch: bool) -> (QmdbNodeState, Arc<crate::read_view::QmdbReadView>, B256) {
    let chain = qmdb_chain();
    let state = QmdbNodeState::new_with_entry_file(chain.clone(), scratch(name), true);
    state.set_compute_offlock(offlock);
    state.set_persist_batch(batch);
    state.set_read_view_wanted(true);
    state.initialize((0, chain.genesis_hash())).expect("initialize");
    state.set_reader_keep_cap(128);
    let view = state.read_view().expect("the view is built at initialisation");
    (state, view, chain.genesis_hash())
}

/// Block `number` on `parent` from leaf operations: odd blocks the way an
/// import files them (`insert_block_operations`), even ones the way a
/// producer does (`compute_operations`, then `insert`). Returns the root.
fn file_from_operations(state: &QmdbNodeState, number: u64, parent: B256) -> B256 {
    let ops = changes_for(number).ops();
    if number % 2 == 1 {
        state.insert_block_operations(parent, hash_of(number), number, ops).expect("insert operations")
    } else {
        let prepared = state.compute_operations(parent, ops).expect("compute operations");
        let root = prepared.root;
        state.insert(hash_of(number), number, prepared).expect("insert");
        root
    }
}

#[test]
fn a_root_on_a_leased_tree_equals_the_locked_one_and_the_views_agree() {
    let (locked, locked_view, genesis) = switched("offlock-equal-locked", false, false);
    let (leased, leased_view, _) = switched("offlock-equal-leased", true, true);
    let mut parent = genesis;
    for number in 1..=12u64 {
        let want = file_from_operations(&locked, number, parent);
        let got = file_from_operations(&leased, number, parent);
        assert_eq!(got, want, "block {number}'s root");
        assert_eq!(leased.root_of(&hash_of(number)), Some(want));
        locked.on_canonical(hash_of(number)).expect("canonical");
        leased.on_canonical(hash_of(number)).expect("canonical");
        parent = hash_of(number);
    }
    assert_eq!(leased.state_root(), locked.state_root());
    // A validated block's root, and a block already held, through the lease.
    let ops = changes_for(13).ops();
    let want = locked.validate_block_operations(parent, hash_of(13), 13, ops.clone(), B256::ZERO).expect("validate");
    let got = leased.validate_block_operations(parent, hash_of(13), 13, ops.clone(), B256::ZERO).expect("validate");
    assert_eq!(got, want, "a mismatching header still gets its computed root");
    assert_eq!(leased.root_of(&hash_of(13)), None, "and no tree");
    let filed = leased.validate_block_operations(parent, hash_of(13), 13, ops.clone(), want).expect("validate");
    assert_eq!(filed, want);
    assert_eq!(leased.root_of(&hash_of(13)), Some(want));
    assert_eq!(leased.insert_block_operations(parent, hash_of(13), 13, ops).expect("held"), want);

    let persisted: Vec<(u64, B256)> = (1..=10).map(|n| (n, hash_of(n))).collect();
    locked.on_persisted(&persisted[..4]);
    locked.on_persisted(&persisted[4..]);
    leased.on_persisted(&persisted[..4]);
    leased.on_persisted(&persisted[4..]);
    assert_eq!(leased_view.head(), locked_view.head());
    assert_eq!(leased_view.head(), (10, hash_of(10)));
    assert!(leased_view.is_valid() && locked_view.is_valid());
    for number in [3u64, 7, 10] {
        let address = Address::from_word(B256::from(U256::from(number)));
        assert_eq!(leased_view.account(&address, 10), locked_view.account(&address, 10));
        assert!(leased_view.account(&address, 10).is_some_and(|account| account.is_some()));
    }
    let counters = leased.offlock_counters();
    assert_eq!(counters.leased_roots, 14, "12 blocks and two validations computed on the lease");
    assert_eq!(counters.persist_fallbacks, 0, "every persisted block listed from its shared parts");
    assert_eq!(counters.persists, 2);
    assert_eq!(counters.persist_split.holds, 2, "one hold a batch");
    assert_eq!(locked.offlock_counters().persist_split.holds, 10, "one hold a block");
    assert_eq!(locked.offlock_counters().leased_roots, 0);
}

#[test]
fn a_rename_while_the_tree_is_leased_is_followed_and_tree_readers_wait_for_it() {
    let (state, view, genesis) = switched("offlock-lease-race", true, true);
    let mut parent = genesis;
    for number in 1..=4u64 {
        file_from_operations(&state, number, parent);
        state.on_canonical(hash_of(number)).expect("canonical");
        parent = hash_of(number);
    }
    // The same chain on the locked path, for the root block 5 must have.
    let (reference, _, _) = switched("offlock-lease-race-ref", false, false);
    let mut at = genesis;
    for number in 1..=4u64 {
        file_from_operations(&reference, number, at);
        at = hash_of(number);
    }
    let want = file_from_operations(&reference, 5, at);

    // Block 5's root, taken apart: the tree is leased on block 4 ...
    let mut lease = {
        let mut guard = state.lock_as("compute_operations");
        guard.as_mut().expect("initialised").lease_tree(hash_of(4)).expect("lease")
    };
    // ... and meanwhile a writer renames the parent, the persistence lists
    // and advances from shared parts, and a root is answered -- none of them
    // waits for the tree.
    let sealed = B256::repeat_byte(0x44);
    state.rename(hash_of(4), sealed).expect("a rename needs no tree");
    assert_eq!(state.root_of(&sealed), reference.root_of(&hash_of(4)));
    state.on_persisted(&[(1, hash_of(1)), (2, hash_of(2))]);
    assert_eq!(view.head(), (2, hash_of(2)));
    assert_eq!(state.offlock_counters().persist_fallbacks, 0);

    // A caller that needs the tree waits until it is back.
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waiter = {
        let (state, done) = (state.clone(), done.clone());
        std::thread::spawn(move || {
            let held = state.lock_as("checkpoint").as_ref().map(QmdbForest::tip);
            done.store(true, std::sync::atomic::Ordering::SeqCst);
            held
        })
    };
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(!done.load(std::sync::atomic::Ordering::SeqCst), "a tree reader waited for the lease");

    let computed = lease.compute(changes_for(5).ops());
    let (prepared, renamed) = {
        let mut guard = state.lock_as("lease_return");
        let returned = guard.as_mut().expect("initialised").return_tree(lease, computed).expect("return");
        state.inner.tree_back.notify_all();
        returned
    };
    assert!(renamed, "the parent moved while the tree was out");
    assert_eq!(prepared.parent(), sealed, "and the block is filed on its new hash");
    assert_eq!(prepared.root, want, "the same root as the locked path");
    waiter.join().expect("the waiter");
    assert!(state.offlock_counters().tree_waits >= 1);
    state.insert(hash_of(5), 5, prepared).expect("insert on the renamed parent");
    state.on_canonical(hash_of(5)).expect("canonical");

    // The lease refuses what needs the tree from a forest it was taken from.
    let mut forest = QmdbForest::from_tree(0, B256::ZERO, n42_twig_core::qmdb_compat::QmdbCompatTree::new());
    let lease = forest.lease_tree(B256::ZERO).expect("lease");
    assert!(forest.is_leased());
    assert!(matches!(forest.lease_tree(B256::ZERO), Err(StateError::TreeLeased)));
    assert!(matches!(forest.flush_entries_for_sync(), Err(StateError::TreeLeased)));
    assert!(matches!(forest.set_canonical_releasing(B256::ZERO), Err(StateError::TreeLeased)));
    assert!(forest.return_tree(lease, Err(StateError::TreeLeased)).is_err(), "a failed root returns its error");
    assert!(!forest.is_leased(), "and the tree");
}

#[test]
fn a_block_without_shared_parts_falls_back_to_the_tree() {
    // Blocks 1-3 on the locked path (no captured offsets), 4-6 on the lease.
    let (state, view, genesis) = switched("offlock-fallback", false, false);
    let mut parent = genesis;
    for number in 1..=6u64 {
        state.set_compute_offlock(number > 3);
        file_from_operations(&state, number, parent);
        state.on_canonical(hash_of(number)).expect("canonical");
        parent = hash_of(number);
    }
    state.set_persist_batch(true);
    state.on_persisted(&[(1, hash_of(1)), (2, hash_of(2))]);
    assert_eq!(view.head(), (2, hash_of(2)));
    assert_eq!(state.offlock_counters().persist_fallbacks, 1, "listed from the tree");
    state.on_persisted(&[(3, hash_of(3)), (4, hash_of(4))]);
    assert_eq!(state.offlock_counters().persist_fallbacks, 2, "one block without parts sends the batch to the tree");
    state.on_persisted(&[(5, hash_of(5)), (6, hash_of(6))]);
    assert_eq!(state.offlock_counters().persist_fallbacks, 2, "both from their parts");
    assert_eq!(view.head(), (6, hash_of(6)));
    assert!(view.is_valid());
}

#[test]
fn a_batched_persist_leaves_the_view_where_one_hold_a_block_does() {
    let run = |name: &str, batch: bool| {
        let (state, view, genesis) = switched(name, false, batch);
        let mut parent = genesis;
        for number in 1..=9u64 {
            let (hash, _) = advance(&state, number, parent);
            parent = hash;
        }
        let mut heads = Vec::new();
        // Two batches, a repeat of held blocks inside the next one, then a
        // batch that names a block the view does not hold after advancing.
        state.on_persisted(&[(1, hash_of(1)), (2, hash_of(2)), (3, hash_of(3))]);
        heads.push((view.head(), view.is_valid()));
        state.on_persisted(&[(2, hash_of(2)), (3, hash_of(3)), (4, hash_of(4)), (5, hash_of(5)), (4, hash_of(4))]);
        heads.push((view.head(), view.is_valid()));
        state.on_persisted(&[(6, hash_of(6)), (7, hash_of(7)), (7, B256::repeat_byte(7))]);
        heads.push((view.head(), view.is_valid()));
        let address = Address::from_word(B256::from(U256::from(7u64)));
        let read = view.account(&address, 7);
        (heads, read, state.offlock_counters().persist_split.holds)
    };
    let (each, each_read, each_holds) = run("batch-each", false);
    let (batched, batched_read, batched_holds) = run("batch-one", true);
    assert_eq!(batched, each);
    assert_eq!(each[1], ((5, hash_of(5)), true));
    assert_eq!(each[2], ((7, hash_of(7)), false), "advanced through 7, then invalidated by the mismatch");
    assert_eq!(batched_read, each_read);
    assert_eq!(each_holds, 7, "a hold a block (plus the release)");
    assert!(batched_holds < each_holds, "{batched_holds} holds batched");

    // A gap after advancing: both advance, then invalidate.
    let gap = |name: &str, batch: bool| {
        let (state, view, genesis) = switched(name, false, batch);
        let mut parent = genesis;
        for number in 1..=4u64 {
            let (hash, _) = advance(&state, number, parent);
            parent = hash;
        }
        state.on_persisted(&[(1, hash_of(1)), (2, hash_of(2)), (4, hash_of(4))]);
        (view.head(), view.is_valid())
    };
    assert_eq!(gap("batch-gap-one", true), gap("batch-gap-each", false));
    assert_eq!(gap("batch-gap-one2", true), ((2, hash_of(2)), false));
}

// ---------------------------------------------------------------------------
// Canonical heads recorded during a lease (N42_QMDB_CANONICAL_DEFER)
// ---------------------------------------------------------------------------

/// A block wide enough (512 accounts) that full twigs fall below the
/// retention window within a few dozen blocks and the trim has work.
fn wide_changes(number: u64) -> BlockChanges {
    let mut changes = BlockChanges::new();
    for i in 0..512u64 {
        changes.set_account(
            Address::from_word(B256::from(U256::from(number * 1000 + i))),
            AccountState { nonce: number, balance: U256::from(i + 1), code_hash: B256::ZERO },
        );
    }
    changes
}

/// Leases the tree on `parent`, as `with_leased_root` does.
fn take_lease(state: &QmdbNodeState, parent: B256) -> n42_qmdb_state::TreeLease {
    let mut guard = state.lock_as("compute_operations");
    guard.as_mut().expect("initialised").lease_tree(parent).expect("lease")
}

/// Computes `ops` on the lease and hands the tree back, as
/// `with_leased_root` does; asserts the owed trim was done by the return.
fn give_back(state: &QmdbNodeState, mut lease: n42_qmdb_state::TreeLease, ops: QmdbOps) -> PreparedBlock {
    let computed = lease.compute(ops);
    let mut guard = state.lock_as("lease_return");
    let forest = guard.as_mut().expect("initialised");
    let (prepared, _) = forest.return_tree(lease, computed).expect("return");
    state.inner.tree_back.notify_all();
    assert!(!forest.trim_due(), "the return does the owed trim");
    drop(forest.take_deferred_release());
    prepared
}

/// Calls `on_canonical` on another thread; whether it finished within
/// `patience`, and the handle to join.
fn canonical_on_the_side(
    state: &QmdbNodeState,
    hash: B256,
    patience: std::time::Duration,
) -> (bool, std::thread::JoinHandle<()>) {
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handle = {
        let (state, done) = (state.clone(), done.clone());
        std::thread::spawn(move || {
            state.on_canonical(hash).expect("canonical");
            done.store(true, std::sync::atomic::Ordering::SeqCst);
        })
    };
    let until = std::time::Instant::now() + patience;
    while !done.load(std::sync::atomic::Ordering::SeqCst) && std::time::Instant::now() < until {
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    (done.load(std::sync::atomic::Ordering::SeqCst), handle)
}

/// What the head move and the trim leave behind: the head, the trimmed and
/// total twigs, the root and whether the record 20 blocks below is still held.
fn forest_shape(state: &QmdbNodeState) -> ((u64, B256), (usize, usize), Option<B256>, bool) {
    let guard = state.lock_as("checkpoint");
    let forest = guard.as_ref().expect("initialised");
    let head = forest.head();
    let old = hash_of(head.0.saturating_sub(20));
    (head, forest.trimmed_twigs(), forest.root_of(&head.1), forest.root_of(&old).is_some())
}

#[test]
fn a_canonical_head_during_a_lease_is_seen_at_once_and_trimmed_by_the_return() {
    let (immediate, immediate_view, genesis) = switched("canon-defer-immediate", true, true);
    let (deferred, view, _) = switched("canon-defer-deferred", true, true);
    deferred.set_canonical_defer(true);
    for state in [&immediate, &deferred] {
        state.insert_block_operations(genesis, hash_of(1), 1, wide_changes(1).ops()).expect("block 1");
        state.on_canonical(hash_of(1)).expect("the first checkpoint");
    }
    let patience = std::time::Duration::from_millis(150);
    let mut leased_heads = 0u64;
    let mut expected_deferred = 0u64;
    let last = 40u64;
    for number in 2..=last {
        let parent = hash_of(number - 1);
        // Deferred: block `number` is computed on a lease, and the head
        // `number - 1` arrives meanwhile.
        let lease = take_lease(&deferred, parent);
        let waits = leased_heads % (CANONICAL_DEFER_MAX_STREAK + 1) == CANONICAL_DEFER_MAX_STREAK;
        leased_heads += 1;
        let (finished, handle) = canonical_on_the_side(&deferred, parent, patience);
        if waits {
            assert!(!finished, "head {}: the streak is spent, so it waits for the tree", number - 1);
        } else {
            expected_deferred += 1;
            assert!(finished, "head {}: recorded without waiting for the lease", number - 1);
            assert_eq!(deferred.head(), Some((number - 1, parent)), "the head is seen at once");
            assert_eq!(deferred.root_of(&parent), immediate.root_of(&parent));
            let guard = deferred.lock_as("root_of");
            assert!(guard.as_ref().expect("initialised").trim_due(), "the trim is owed");
        }
        let prepared = give_back(&deferred, lease, wide_changes(number).ops());
        handle.join().expect("the canonical thread");
        deferred.insert(hash_of(number), number, prepared).expect("insert");
        // Immediate: the same block, then the head, with the tree here.
        immediate.insert_block_operations(parent, hash_of(number), number, wide_changes(number).ops()).expect("insert");
        immediate.on_canonical(parent).expect("canonical");
        assert_eq!(forest_shape(&deferred), forest_shape(&immediate), "after head {}", number - 1);
        // The database persists in batches; the reader's keep moves with it.
        if number % 8 == 0 {
            let batch: Vec<(u64, B256)> = (number.saturating_sub(11).max(1)..=number - 4).map(|n| (n, hash_of(n))).collect();
            for (state, view) in [(&immediate, &immediate_view), (&deferred, &view)] {
                state.on_persisted(&batch);
                assert_eq!(view.head(), (number - 4, hash_of(number - 4)));
                assert!(view.is_valid(), "no record a reader keeps was cut");
            }
        }
    }
    assert_eq!(deferred.offlock_counters().deferred_canonicals, expected_deferred);
    assert_eq!(immediate.offlock_counters().deferred_canonicals, 0);
    let (trimmed, _) = forest_shape(&deferred).1;
    assert!(trimmed > 0, "the trims had work");

    // The last head with the tree here persists the deferred ones' deltas
    // too; a restart from either directory stands at the same state.
    for state in [&immediate, &deferred] {
        state.on_canonical(hash_of(last)).expect("canonical");
    }
    assert_eq!(forest_shape(&deferred), forest_shape(&immediate));
    let persisted: Vec<(u64, B256)> = (37..=39).map(|n| (n, hash_of(n))).collect();
    for (state, view) in [(&immediate, &immediate_view), (&deferred, &view)] {
        state.on_persisted(&persisted);
        assert_eq!(view.head(), (39, hash_of(39)));
        assert!(view.is_valid(), "no record a reader keeps was cut");
    }
    let root = immediate.state_root();
    assert_eq!(deferred.state_root(), root);
    for state in [immediate, deferred] {
        let dir = state.inner.dir.clone();
        drop(state);
        let restarted = QmdbNodeState::new_with_entry_file(qmdb_chain(), &dir, true);
        restarted.initialize((last, hash_of(last))).expect("restart");
        assert_eq!(restarted.state_root(), root);
    }
}

#[test]
fn a_branch_switch_during_a_lease_waits_and_takes_the_owed_trim_first() {
    let (state, view, genesis) = switched("canon-defer-reorg", true, true);
    let (reference, _, _) = switched("canon-defer-reorg-ref", false, false);
    state.set_canonical_defer(true);
    let mut parent = genesis;
    for number in 1..=20u64 {
        for s in [&state, &reference] {
            s.insert_block_operations(parent, hash_of(number), number, wide_changes(number).ops()).expect("insert");
            if number <= 18 {
                s.on_canonical(hash_of(number)).expect("canonical");
            }
        }
        parent = hash_of(number);
    }
    // A sibling of 20, on 19.
    let sibling = B256::repeat_byte(0x5a);
    for s in [&state, &reference] {
        s.insert_block_operations(hash_of(19), sibling, 20, wide_changes(99).ops()).expect("sibling");
    }
    // The tree is leased on 20; head 19 (on its path) defers its trim ...
    let lease = take_lease(&state, hash_of(20));
    let (finished, handle) = canonical_on_the_side(&state, hash_of(19), std::time::Duration::from_secs(2));
    assert!(finished);
    handle.join().expect("head 19");
    assert!(state.lock_as("root_of").as_ref().expect("initialised").trim_due());
    // ... and the switch to the sibling waits for the tree: it moves it.
    let (finished, handle) = canonical_on_the_side(&state, sibling, std::time::Duration::from_millis(150));
    assert!(!finished, "a branch switch waits for the leased tree");
    give_back(&state, lease, wide_changes(21).ops());
    handle.join().expect("the switch");
    reference.on_canonical(hash_of(19)).expect("canonical");
    reference.on_canonical(sibling).expect("canonical");
    assert_eq!(state.head(), Some((20, sibling)));
    assert_eq!(forest_shape(&state), forest_shape(&reference));
    assert_eq!(state.state_root(), reference.state_root());
    assert_eq!(state.offlock_counters().deferred_canonicals, 1);

    // The chain goes on from the sibling, and the view follows it.
    for s in [&state, &reference] {
        s.insert_block_operations(sibling, hash_of(21), 21, wide_changes(21).ops()).expect("21");
        s.on_canonical(hash_of(21)).expect("canonical");
    }
    assert_eq!(state.state_root(), reference.state_root());
    let persisted: Vec<(u64, B256)> = (1..=19).map(|n| (n, hash_of(n))).chain([(20, sibling), (21, hash_of(21))]).collect();
    state.on_persisted(&persisted);
    assert_eq!(view.head(), (21, hash_of(21)));
    assert!(view.is_valid());
}
