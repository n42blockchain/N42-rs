// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Consensus state across a restart.
//!
//! The property that matters is narrow and absolute: a validator that has signed
//! a vote in view N must never sign another one in view N, no matter what
//! happened in between. Everything else here — the checkpoint, the view, the
//! backoff — is convenience that costs a resync when it is lost.
//!
//! So the tests are about the crash window: what the node believes after a
//! restart that landed between signing and checkpointing, and what it does when
//! the file it needs to answer that is unreadable.

use std::path::PathBuf;

use n42_h2_consensus::VoteLogWriter;
use n42_h2_node::{ConsensusCheckpoint, ConsensusStore, StoreError};
use n42_h2_primitives::consensus::QuorumCertificate;

/// A scratch directory that cleans up after itself.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("n42-persistence-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn checkpoint(view: u64, voted: u64) -> ConsensusCheckpoint {
    ConsensusCheckpoint {
        view,
        locked_qc: QuorumCertificate::genesis(),
        last_committed_qc: QuorumCertificate::genesis(),
        consecutive_timeouts: 0,
        last_voted_view: voted,
        last_commit_voted_view: voted,
    }
}

#[test]
fn a_fresh_directory_has_nothing_to_recover() {
    let dir = TempDir::new("fresh");
    let store = ConsensusStore::open(&dir.0).expect("open");
    assert!(store.load().expect("load").is_none());
    assert_eq!(store.vote_log().expect("log").read().expect("read"), (0, 0));
}

#[test]
fn a_checkpoint_survives_a_restart() {
    let dir = TempDir::new("roundtrip");
    let store = ConsensusStore::open(&dir.0).expect("open");
    let saved = checkpoint(42, 41);
    store.save(&saved).expect("save");

    // A second process opening the same directory.
    let reopened = ConsensusStore::open(&dir.0).expect("reopen");
    assert_eq!(reopened.load().expect("load"), Some(saved));
}

/// The crash window this whole file exists for. The vote log is written before
/// the signature and the checkpoint after it, so a crash in between leaves the
/// log ahead. Recovering from the checkpoint alone would put the node back in a
/// view it had already signed — equivocation, indistinguishable to everyone else
/// from a validator deliberately signing two conflicting values.
#[test]
fn a_vote_logged_after_the_last_checkpoint_still_binds_the_restarted_node() {
    let dir = TempDir::new("crash-window");
    let store = ConsensusStore::open(&dir.0).expect("open");
    store.save(&checkpoint(10, 10)).expect("save");

    // Signed view 11, then the process died before checkpointing.
    let log = store.vote_log().expect("log");
    log.record_vote(11).expect("record");
    log.record_commit_vote(11).expect("record");

    let recovered = ConsensusStore::open(&dir.0)
        .expect("reopen")
        .load()
        .expect("load")
        .expect("a checkpoint");

    assert_eq!(recovered.last_voted_view, 11, "the log must win over the checkpoint");
    assert_eq!(recovered.last_commit_voted_view, 11);
    assert!(
        recovered.view > 10,
        "and the node must not resume in a view it already voted in",
    );
}

#[test]
fn the_vote_watermark_only_moves_forward() {
    let dir = TempDir::new("monotonic");
    let store = ConsensusStore::open(&dir.0).expect("open");
    let log = store.vote_log().expect("log");

    log.record_vote(7).expect("record");
    // A stale message, a replayed event, a bug upstream — none of them may lower
    // the watermark, because the only thing it protects is "have I signed here".
    log.record_vote(3).expect("record");
    assert_eq!(log.read().expect("read").0, 7);

    log.record_vote(9).expect("record");
    assert_eq!(log.read().expect("read").0, 9);
}

#[test]
fn the_two_watermarks_are_independent() {
    let dir = TempDir::new("independent");
    let store = ConsensusStore::open(&dir.0).expect("open");
    let log = store.vote_log().expect("log");

    // R2 lags R1 by a phase, so recording one must not clear the other.
    log.record_vote(9).expect("record");
    log.record_commit_vote(8).expect("record");
    assert_eq!(log.read().expect("read"), (9, 8));

    log.record_vote(10).expect("record");
    assert_eq!(log.read().expect("read"), (10, 8), "R1 must not reset R2");
}

/// A torn record and a whole one look identical without a checksum, and one of
/// them causes a double vote. Refusing to start is the only safe answer:
/// anything else is guessing which views were signed.
#[test]
fn a_corrupt_vote_log_stops_the_node_rather_than_guessing() {
    let dir = TempDir::new("corrupt");
    let store = ConsensusStore::open(&dir.0).expect("open");
    store.vote_log().expect("log").record_vote(5).expect("record");

    let path = dir.0.join("vote-log.bin");
    let mut bytes = std::fs::read(&path).expect("read");
    bytes[0] ^= 0xFF; // a flipped bit in the recorded view
    std::fs::write(&path, &bytes).expect("write");

    match ConsensusStore::open(&dir.0).expect("open").vote_log() {
        Err(StoreError::CorruptVoteLog { .. }) => {}
        other => panic!("expected the node to refuse to start, got {other:?}"),
    }
}

/// The checkpoint is written to a temporary file and renamed, so a crash during
/// the write leaves the previous one intact. Reading a half-written checkpoint
/// would resume the node on a QC that was never whole.
#[test]
fn a_half_written_checkpoint_does_not_replace_a_good_one() {
    let dir = TempDir::new("atomic");
    let store = ConsensusStore::open(&dir.0).expect("open");
    store.save(&checkpoint(10, 10)).expect("save");

    // What a crash mid-write leaves behind: a stray temp file. It must not be
    // mistaken for the checkpoint.
    std::fs::write(dir.0.join("consensus-checkpoint.json.tmp"), b"{ truncated")
        .expect("write");

    let recovered = store.load().expect("load").expect("still there");
    assert_eq!(recovered.view, 10);
}

#[test]
fn an_unreadable_checkpoint_is_reported_rather_than_silently_ignored() {
    let dir = TempDir::new("unreadable");
    let store = ConsensusStore::open(&dir.0).expect("open");
    std::fs::write(dir.0.join("consensus-checkpoint.json"), b"not json").expect("write");

    // Losing a checkpoint costs a resync, not safety — but it must not read as
    // "this node has never run", which would hide a filesystem problem.
    match store.load() {
        Err(StoreError::CorruptCheckpoint { .. }) => {}
        other => panic!("expected a corrupt-checkpoint error, got {other:?}"),
    }
}
