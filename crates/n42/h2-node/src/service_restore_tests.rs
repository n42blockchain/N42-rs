// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! AM37: a restart whose block journal holds a lock the set never committed.
//! The lock is executed back in as a side block, the head stays on the
//! committed block, and the committed sibling at the lock's height and its
//! children import and commit at once (run am35-am37rs4 kill 2: the lock was
//! made the head and the node imported nothing for 4 m 45 s).

use super::halt_tests::commit_qc_for;
use super::*;
use n42_h2_execution::ElCall;
use n42_h2_primitives::consensus::{ConsensusMessage, Decide};

/// Block `number` on `parent`, told apart from [`block`]'s by `extra`.
fn block_with_extra(number: u64, parent: B256, extra: u8) -> (B256, Header, alloy_primitives::Bytes) {
    let built = MockExecutionLayer::built_block_on(number, parent);
    let mut raw = built.execution_data.into_block_raw().expect("raw block").header;
    raw.extra_data = alloy_primitives::Bytes::from(vec![extra]);
    let header = n42_h2_consensus::N42Header::from(raw);
    let rlp = n42_h2_net::encode_block_rlp_raw(&header, &[], &[], None);
    (header.hash_slow(), header, alloy_primitives::Bytes::from(rlp))
}

async fn decide(rig: &mut Rig, view: u64, hash: B256) {
    let qc = commit_qc_for(rig, &[1, 2, 3], view, hash);
    let message = ConsensusMessage::Decide(Decide {
        view: qc.view,
        block_hash: qc.block_hash,
        commit_qc: qc,
        validator_changes_hash: B256::ZERO,
    });
    let _ = rig.svc.engine.process_event(ConsensusEvent::Message(message));
    drain(rig).await;
}

/// A body as the block topic delivers it: unsolicited.
fn gossip(rig: &mut Rig, rlp: &alloy_primitives::Bytes) {
    let data = compress_block_rlp(rlp).expect("snappy");
    rig.svc.handle_transport_event(TransportEvent::Block { from: None, data }).expect("ok");
}

async fn drain(rig: &mut Rig) {
    let mut events = Vec::new();
    for _ in 0..4 {
        within(rig.svc.drain_outputs(&mut events)).await.expect("drained");
    }
}

fn new_payloads(rig: &Rig, hash: B256) -> usize {
    rig.el.calls().iter().filter(|c| matches!(c, ElCall::NewPayload(h) | ElCall::NewPayloadBody(h) if *h == hash)).count()
}

fn headed_to(rig: &Rig, hash: B256) -> bool {
    rig.el.calls().iter().any(|c| matches!(c, ElCall::ForkchoiceUpdated(state) if state.head_block_hash == hash))
}

#[tokio::test]
async fn a_restored_uncommitted_lock_is_a_side_block_and_its_committed_sibling_imports() {
    let dir = std::env::temp_dir().join(format!("n42-am37-restore-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // A (1) committed, B (2) the lock: both journalled, both lost by the layer.
    let (a, _, body_a) = block(1, ID.genesis_hash);
    let (b, _, body_b) = block(2, a);
    {
        let mut journal = crate::block_journal::BlockJournal::open(&dir).expect("journal");
        journal.append(1, a, ID.genesis_hash, &body_a).expect("append a");
        journal.append(2, b, a, &body_b).expect("append b");
    }
    let mut rig = node(4, 0, None).await;
    let svc = rig.svc;
    rig.svc = svc
        .with_vote_rules(n42_h2_consensus::VoteRules::PROFILE1)
        .with_block_journal(crate::block_journal::BlockJournal::open(&dir).expect("journal"));
    // The checkpoint's commit: A at view 1.
    decide(&mut rig, 1, a).await;
    assert_eq!(rig.svc.engine.last_committed_qc().block_hash, a);

    assert_eq!(within(rig.svc.restore_block_journal()).await.expect("restore"), 2);
    assert_eq!(new_payloads(&rig, b), 1, "the lock is executed back in");
    assert!(headed_to(&rig, a), "the committed block is the head: {:?}", rig.el.calls());
    assert!(!headed_to(&rig, b), "the uncommitted lock is not made the head: {:?}", rig.el.calls());
    assert_eq!(rig.svc.driver.head(), a);
    assert!(rig.svc.engine.has_imported_block(&b), "the engine's gates still see the lock imported");
    assert!(rig.svc.block_journal().expect("journal").contains(&b), "and it is kept to serve");

    // The set committed S, B's sibling, and C on it.
    let (s, _, body_s) = block_with_extra(2, a, 0x5a);
    let (c, _, body_c) = block_with_extra(3, s, 0x5a);
    assert_ne!(s, b);
    gossip(&mut rig, &body_s);
    drain(&mut rig).await;
    decide(&mut rig, 3, s).await;
    assert!(new_payloads(&rig, s) >= 1, "the committed sibling reached the layer: {:?}", rig.el.calls());
    assert!(headed_to(&rig, s), "and was committed: {:?}", rig.el.calls());

    gossip(&mut rig, &body_c);
    drain(&mut rig).await;
    decide(&mut rig, 4, c).await;
    assert!(new_payloads(&rig, c) >= 1, "its child too: {:?}", rig.el.calls());
    assert!(headed_to(&rig, c), "committed: {:?}", rig.el.calls());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The committed sibling whose body is here but which nothing named
/// (its proposal refused by the lock, the body outside the tip's window)
/// is imported when its commit lands.
#[tokio::test]
async fn a_commit_imports_a_held_body_nothing_else_asked_for() {
    let mut rig = node(4, 0, None).await;
    let (a, header_a, body_a) = block(1, ID.genesis_hash);
    // A is imported and the head.
    rig.svc.handle_direct_body(body_a.into());
    drain(&mut rig).await;
    decide(&mut rig, 1, a).await;
    assert!(headed_to(&rig, a));
    // The tip is read as 2 (a lock on another branch): S at 2 is outside the
    // unsolicited window and waits.
    rig.svc.note_imported(header_a.number + 1);
    let (s, _, body_s) = block_with_extra(2, a, 0x77);
    gossip(&mut rig, &body_s);
    drain(&mut rig).await;
    assert_eq!(new_payloads(&rig, s), 0, "outside the window, unsolicited: not imported");
    decide(&mut rig, 2, s).await;
    assert!(new_payloads(&rig, s) >= 1, "the commit started its import: {:?}", rig.el.calls());
    assert!(headed_to(&rig, s), "and it was committed: {:?}", rig.el.calls());
}

/// A held child at `tip + 1` whose parent is not the head: the parent's
/// body is here, so it is imported.
#[tokio::test]
async fn a_held_child_at_tip_plus_one_on_another_branch_imports_its_parent() {
    let mut rig = node(4, 0, None).await;
    let (a, _, body_a) = block(1, ID.genesis_hash);
    rig.svc.handle_direct_body(body_a.into());
    drain(&mut rig).await;
    decide(&mut rig, 1, a).await;
    rig.svc.note_imported(2);
    let (s, _, body_s) = block_with_extra(2, a, 0x33);
    let (c, header_c, _) = block_with_extra(3, s, 0x33);
    gossip(&mut rig, &body_s);
    drain(&mut rig).await;
    assert_eq!(new_payloads(&rig, s), 0);
    rig.svc.remember_block(c, &header_c);
    rig.svc.held_bodies.push(c);
    let mut events = Vec::new();
    rig.svc.request_missing_held_parent(&mut events);
    drain(&mut rig).await;
    assert!(new_payloads(&rig, s) >= 1, "the parent was imported: {:?}", rig.el.calls());
}
