// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The request/response paths of the service: catch-up by range, fills of
//! named transactions, block-by-hash and range serving.
//!
//! The first group feeds synthetic transport events to one service. The
//! second connects two real services over loopback TCP and pumps their
//! transports by hand, so a request that carries a response channel really
//! crosses the wire and is answered by the other service's own handlers.

use super::*;
use n42_h2_net::RangeRequest;

/// `count` blocks numbered from 1 as a chain, with their gov5 RLP.
pub(super) fn chain(count: u64) -> Vec<(B256, Header, alloy_primitives::Bytes)> {
    let mut parent = B256::ZERO;
    let mut blocks = Vec::new();
    for number in 1..=count {
        let (hash, header, rlp) = block(number, parent);
        parent = hash;
        blocks.push((hash, header, rlp));
    }
    blocks
}

fn chunks(blocks: &[(B256, Header, alloy_primitives::Bytes)]) -> Vec<BlockChunk> {
    blocks.iter().map(|(_, _, rlp)| chunk(rlp)).collect()
}

/// `count` blocks numbered from 1 as a leader under gov5's profile seals
/// them: block `n` at view `n` embeds the commit QC of its parent (view
/// `n - 1`), signed by every key of `rig`'s set; the first embeds none. Each
/// block but the last is anchored by the header above it (depth 1).
fn anchored_chain(rig: &Rig, count: u64) -> Vec<(B256, Header, alloy_primitives::Bytes)> {
    anchored_chain_at(rig, count, 0)
}

/// [`anchored_chain`] with every view `views` later: another chain of the
/// same heights (every hash differs).
fn anchored_chain_at(rig: &Rig, count: u64, views: u64) -> Vec<(B256, Header, alloy_primitives::Bytes)> {
    let signers: Vec<usize> = (0..rig.keys.len()).collect();
    let mut parent = B256::ZERO;
    let mut blocks = Vec::new();
    for number in 1..=count {
        let view = views + number;
        let qc = if number == 1 { Vec::new() } else { header_qc(&rig.svc, &rig.keys, &signers, view - 1, parent, parent) };
        let block = block_with_extra(number, parent, view, qc);
        parent = block.0;
        blocks.push(block);
    }
    blocks
}

/// The blocks the execution layer was handed by `newPayload`, in order.
fn executed(rig: &Rig) -> Vec<B256> {
    rig.el.calls().iter().filter_map(|c| if let ElCall::NewPayload(h) = c { Some(*h) } else { None }).collect()
}

fn catching_up(rig: &mut Rig, peer: PeerId, next: u64, target: u64) {
    rig.svc.catch_up =
        Some(CatchUp::new(peer, next - 1, target));
}

async fn import(rig: &mut Rig) -> Vec<ServiceEvent> {
    let mut events = Vec::new();
    within(rig.svc.import_ranges(&mut events)).await;
    events
}

// ---------------------------------------------------------------------------
// Starting a catch-up
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_peer_ahead_of_the_execution_layer_starts_a_pull() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    rig.svc.pending_status.push((peer, 5));
    let mut events = Vec::new();
    within(rig.svc.consider_catch_up(&mut events)).await;
    let catch_up = rig.svc.catch_up.as_ref().expect("a pull started");
    assert_eq!((catch_up.peer, catch_up.next, catch_up.target, catch_up.started_at), (peer, 1, 5, 0));
    assert!(!catch_up.probing);
    assert_eq!(events, vec![ServiceEvent::Syncing { from: 0, to: 5 }]);
    assert_eq!(rig.svc.imported_height, Some(0), "the execution layer's height was read");
    assert!(rig.svc.pending_status.is_empty());
    assert_eq!(rig.svc.peer_heights[&peer], 5);
}

#[tokio::test]
async fn a_peer_level_with_us_or_a_pause_after_a_failure_starts_nothing() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let mut events = Vec::new();

    // Level with the execution layer: its height is read, nothing starts.
    rig.svc.pending_status.push((peer, 0));
    within(rig.svc.consider_catch_up(&mut events)).await;
    assert!(rig.svc.catch_up.is_none());
    assert!(events.is_empty());

    // Behind a height already known to be imported: the layer is not even asked.
    rig.svc.imported_height = Some(50);
    rig.svc.note_peer_height(peer, 40);
    within(rig.svc.consider_catch_up(&mut events)).await;
    assert!(rig.svc.catch_up.is_none());

    // The retry pause after a finished pull.
    rig.svc.imported_height = None;
    rig.svc.note_peer_height(peer, 90);
    rig.svc.catch_up_retry_after = Some(std::time::Instant::now() + Duration::from_secs(60));
    within(rig.svc.consider_catch_up(&mut events)).await;
    assert!(rig.svc.catch_up.is_none(), "no new pull inside the pause");
    rig.svc.catch_up_retry_after = None;
    within(rig.svc.consider_catch_up(&mut events)).await;
    assert!(rig.svc.catch_up.is_some(), "the pause over, the pull starts");
}

/// Sync standard §3.4.1: the target is the (f+1)-th highest advertised
/// height, never one peer's. In a set of four (f = 1) one peer claiming a
/// million while the others are level starts no pull, so it cannot make
/// the node wait or pull for ever; once a second peer is ahead the pull
/// goes as far as that one, and a pipelined pull asks the liar for nothing
/// past it either.
#[tokio::test]
async fn one_peer_alone_advertising_a_huge_height_neither_starts_nor_sizes_a_pull() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
    let (liar, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
    rig.svc.note_peer_height(liar, 1_000_000);
    rig.svc.note_peer_height(b, 0);
    rig.svc.note_peer_height(c, 0);
    let mut events = Vec::new();
    within(rig.svc.consider_catch_up(&mut events)).await;
    assert!(rig.svc.catch_up.is_none() && events.is_empty(), "no f+1 peers back the height");
    assert_eq!(rig.svc.quorum_height(), Some(0));

    rig.svc.note_peer_height(b, 5);
    within(rig.svc.consider_catch_up(&mut events)).await;
    let pull = rig.svc.catch_up.as_ref().expect("a second peer is ahead");
    assert_eq!(pull.target, 5, "as far as f+1 peers advertise");
    assert_eq!(events, vec![ServiceEvent::Syncing { from: 0, to: 5 }]);
    let capped: std::collections::HashMap<_, _> = rig.svc.pipeline_peers().into_iter().collect();
    assert_eq!(capped[&liar], 5, "a pipelined pull asks the liar nothing past it");
}

#[tokio::test]
async fn the_peer_whose_pull_failed_last_is_passed_over_for_another() {
    let mut rig = node(1, 0, None).await;
    let (tall, short) = (PeerId::random(), PeerId::random());
    rig.svc.note_peer_height(tall, 30);
    rig.svc.note_peer_height(short, 20);
    rig.svc.failed_peer = Some(tall);
    let mut events = Vec::new();
    within(rig.svc.consider_catch_up(&mut events)).await;
    let catch_up = rig.svc.catch_up.as_ref().expect("a pull");
    // The first window stops near the tip (0 + 8 x the far-ahead limit of
    // 1); a peer that has more serves it full and the pull probes on.
    assert_eq!((catch_up.peer, catch_up.target), (short, 8));

    // With no other peer the failed one is tried again.
    let mut rig = node(1, 0, None).await;
    rig.svc.note_peer_height(tall, 30);
    rig.svc.failed_peer = Some(tall);
    within(rig.svc.consider_catch_up(&mut events)).await;
    assert_eq!(rig.svc.catch_up.as_ref().map(|c| c.peer), Some(tall));
}

// ---------------------------------------------------------------------------
// Importing what came back
// ---------------------------------------------------------------------------

/// A range is executed in order as far as its headers anchor it: each
/// header embeds the commit QC of its parent, so the top block waits for the
/// header above it (sync standard §3.4.5-6) and is never executed by a pull
/// that ends without one.
#[tokio::test]
async fn a_range_reply_is_imported_in_order_then_the_pull_probes_past_the_target() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let blocks = anchored_chain(&rig, 3);
    catching_up(&mut rig, peer, 1, 3);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 3, step: 1 }, chunks(&blocks)));
    let events = import(&mut rig).await;

    assert!(events.is_empty(), "the target was reached but the peer may have more");
    for (hash, header, _) in &blocks[..2] {
        assert!(rig.svc.imported.contains(hash));
        assert!(rig.svc.body_store.contains_key(hash), "pulled bodies are servable");
        assert_eq!(rig.svc.block_headers[hash].number, header.number);
    }
    assert!(!rig.svc.imported.contains(&blocks[2].0), "the top block has no anchor yet");
    assert_eq!(rig.svc.imported_height, Some(2));
    assert_eq!(rig.svc.driver.head(), blocks[1].0, "each import became the head");
    assert_eq!(executed(&rig), vec![blocks[0].0, blocks[1].0], "in block order");
    let catch_up = rig.svc.catch_up.as_ref().expect("still pulling");
    assert!(catch_up.probing);
    assert_eq!((catch_up.next, catch_up.target), (4, 4 + MAX_RANGE_BLOCKS - 1));

    // The probe comes back empty: that was the peer's head. Its top block
    // stays unexecuted: the live path or the next pull brings it.
    rig.svc.pending_imports.push((peer, RangeRequest { start: 4, count: MAX_RANGE_BLOCKS, step: 1 }, Vec::new()));
    let events = import(&mut rig).await;
    assert_eq!(events, vec![ServiceEvent::Synced { height: 2, complete: true }]);
    assert!(rig.svc.catch_up.is_none());
    assert!(rig.svc.catch_up_retry_after.is_some());
    assert_eq!(rig.svc.failed_peer, None, "a complete pull clears the blame");
    assert_eq!(executed(&rig).len(), 2);
}

/// Sync standard §3.4.6 (replaces audit 2026-10 R2-I2's cap past the
/// committed height): a range no verified anchor covers is never executed.
/// Past the unanchored-tail bound of 64 blocks the tail is dropped and the
/// pull ends with a reason; the peer is not refused (§3.5), whether or not
/// anything is committed.
#[tokio::test]
async fn an_unanchored_tail_past_the_bound_ends_the_pull_with_nothing_executed() {
    for committed in [None, Some(0)] {
        let mut rig = node(1, 0, None).await;
        let peer = PeerId::random();
        let total = crate::sync_anchor::MAX_TAIL_BLOCKS as u64 + 6;
        let blocks = chain(total);
        rig.svc.committed_height = committed;
        catching_up(&mut rig, peer, 1, total);
        rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: total, step: 1 }, chunks(&blocks)));
        let mut events = Vec::new();
        for _ in 0..total.div_ceil(PULLED_BLOCKS_PER_STEP as u64) {
            events.extend(import(&mut rig).await);
        }
        assert!(executed(&rig).is_empty(), "nothing anchored, nothing executed");
        assert!(rig.svc.imported.is_empty());
        assert!(rig.svc.catch_up.is_none(), "the pull ended at the bound");
        assert!(rig.svc.pending_imports.is_empty(), "the rest of the reply is dropped");
        assert!(!rig.svc.refused_range_peers.contains_key(&peer), "an unanchored tail is not a fault");
        assert_eq!(rig.svc.failed_peer, Some(peer), "the next pull asks another peer first");
        assert_eq!(events, vec![ServiceEvent::Synced { height: 0, complete: false }]);
    }
}

/// `N42_SYNC_ANCHOR=observe` imports as before the anchor rule -- the
/// unproven cap past the committed height of audit 2026-10 R2-I2 included --
/// and counts what `enforce` would have refused.
#[tokio::test]
async fn under_observe_a_pull_far_past_the_committed_height_stops_at_the_first_unproven_block() {
    let mut rig = node(1, 0, None).await;
    rig.svc.sync_anchor_mode = SyncAnchorMode::Observe;
    let peer = PeerId::random();
    let total = MAX_UNPROVEN_PAST_COMMITTED + 6;
    let blocks = chain(total);
    rig.svc.committed_height = Some(0);
    catching_up(&mut rig, peer, 1, total);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: total, step: 1 }, chunks(&blocks)));
    let mut events = Vec::new();
    for _ in 0..total.div_ceil(PULLED_BLOCKS_PER_STEP as u64) {
        events.extend(import(&mut rig).await);
    }
    assert_eq!(rig.svc.imported.len() as u64, MAX_UNPROVEN_PAST_COMMITTED, "up to the bound");
    assert!(rig.svc.catch_up.is_none(), "the pull ended");
    assert!(rig.svc.refused_range_peers.contains_key(&peer), "and the peer is not asked for the gap again");
    assert!(events.contains(&ServiceEvent::Synced { height: MAX_UNPROVEN_PAST_COMMITTED, complete: false }), "{events:?}");
    assert_eq!(rig.svc.sync_anchor_would_refuse, MAX_UNPROVEN_PAST_COMMITTED, "every executed block was unanchored");
}

#[tokio::test]
async fn a_short_reply_before_the_target_asks_for_the_rest() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let blocks = chain(2);
    catching_up(&mut rig, peer, 1, 5);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 5, step: 1 }, chunks(&blocks)));
    let events = import(&mut rig).await;
    assert!(events.is_empty());
    let catch_up = rig.svc.catch_up.as_ref().expect("still pulling");
    assert_eq!((catch_up.next, catch_up.target, catch_up.probing), (3, 5, false));
}

#[tokio::test]
async fn a_reply_over_the_per_step_budget_is_finished_on_the_next_call() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let blocks = anchored_chain(&rig, PULLED_BLOCKS_PER_STEP as u64 + 8);
    let total = blocks.len() as u64;
    catching_up(&mut rig, peer, 1, total);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: total, step: 1 }, chunks(&blocks)));

    let events = import(&mut rig).await;
    assert!(events.is_empty());
    // One step's budget of blocks screened; the last waits for the header
    // above it, which is in the rest.
    assert_eq!(rig.svc.imported.len(), PULLED_BLOCKS_PER_STEP - 1, "one step's budget");
    assert_eq!(rig.svc.pending_imports.len(), 1, "the rest waits");
    let (_, rest, remaining) = &rig.svc.pending_imports[0];
    assert_eq!((rest.start, rest.count), (PULLED_BLOCKS_PER_STEP as u64 + 1, 8));
    assert_eq!(remaining.len(), 8);

    let events = import(&mut rig).await;
    assert!(events.is_empty());
    assert_eq!(rig.svc.imported.len() as u64, total - 1);
    assert!(rig.svc.pending_imports.is_empty());
    assert!(rig.svc.catch_up.as_ref().is_some_and(|c| c.probing), "now probing past the target");
}

#[tokio::test]
async fn blocks_gossip_already_imported_are_skipped_not_imported_twice() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let blocks = anchored_chain(&rig, 3);
    rig.svc.remember_imported(blocks[0].0);
    catching_up(&mut rig, peer, 1, 3);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 3, step: 1 }, chunks(&blocks)));
    import(&mut rig).await;
    assert_eq!(executed(&rig), vec![blocks[1].0], "only the second block went to the execution layer");
    assert!(rig.svc.catch_up.as_ref().is_some_and(|c| c.next == 4 && c.executed == 2), "but the pull moved past both");
}

#[tokio::test]
async fn a_reply_that_is_not_part_of_the_pull_is_dropped() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let blocks = chain(2);
    // No catch-up at all.
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 2, step: 1 }, chunks(&blocks)));
    import(&mut rig).await;
    assert!(rig.svc.imported.is_empty());

    // Another peer's reply, and a reply for another start.
    catching_up(&mut rig, peer, 1, 2);
    rig.svc.pending_imports.push((PeerId::random(), RangeRequest { start: 1, count: 2, step: 1 }, chunks(&blocks)));
    rig.svc.pending_imports.push((peer, RangeRequest { start: 9, count: 2, step: 1 }, chunks(&blocks)));
    let events = import(&mut rig).await;
    assert!(events.is_empty());
    assert!(rig.svc.imported.is_empty());
    assert!(rig.el.calls().is_empty());
    assert!(rig.svc.catch_up.is_some(), "the pull goes on");
}

#[tokio::test]
async fn a_pull_stops_and_blames_the_peer_when_its_reply_is_unusable() {
    let peer = PeerId::random();
    let blocks = chain(3);

    // An empty reply before the peer's head: it served none of the range.
    let mut rig = node(1, 0, None).await;
    catching_up(&mut rig, peer, 1, 3);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 3, step: 1 }, Vec::new()));
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 0, complete: false }]);
    assert_eq!(rig.svc.failed_peer, Some(peer));
    assert!(rig.svc.catch_up.is_none());

    // A block this node cannot read.
    let mut rig = node(1, 0, None).await;
    catching_up(&mut rig, peer, 1, 3);
    let junk = BlockChunk { fork_digest: [0; 4], rlp: alloy_primitives::Bytes::from_static(&[0xc0, 0x01]) };
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 3, step: 1 }, vec![junk]));
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 0, complete: false }]);
    assert_eq!(rig.svc.failed_peer, Some(peer));

    // Blocks out of order: the second block where the first is expected.
    let mut rig = node(1, 0, None).await;
    catching_up(&mut rig, peer, 1, 3);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 3, step: 1 }, vec![chunk(&blocks[1].2)]));
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 0, complete: false }]);
    assert!(rig.svc.imported.is_empty(), "nothing out of order is imported");

    // The execution layer refuses a block part-way: what was imported counts.
    let mut rig = node(1, 0, None).await;
    let blocks = anchored_chain(&rig, 3);
    catching_up(&mut rig, peer, 1, 3);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 3, step: 1 }, chunks(&blocks)));
    rig.el.set_behaviour(MockBehaviour { new_payload_error: Some("db closed".to_owned()), ..Default::default() });
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 0, complete: false }]);
    assert!(rig.svc.imported.is_empty());
}

/// The committed QC a gov5 leader embeds in a header: `signers` of `keys`
/// sign `signed` under the rig engine's profile, and the certificate names
/// `(view, named)`. A `signed` other than `named` is a forged certificate.
pub(super) fn header_qc(
    svc: &H2Service<MockExecutionLayer>,
    keys: &[BlsSecretKey],
    signers: &[usize],
    view: u64,
    named: B256,
    signed: B256,
) -> Vec<u8> {
    let message = svc.engine.signing_profile().commit_message(view, signed, B256::ZERO);
    qc_signed_over(svc, keys, signers, view, named, &message)
}

/// The same certificate signed in the prepare (vote) domain: what a
/// proposal's justify QC is, and not a sync anchor.
pub(super) fn prepare_qc(svc: &H2Service<MockExecutionLayer>, keys: &[BlsSecretKey], signers: &[usize], view: u64, named: B256) -> Vec<u8> {
    let message = svc.engine.signing_profile().vote_message(view, named);
    qc_signed_over(svc, keys, signers, view, named, &message)
}

/// gov5's `HotStuffQC` bytes naming `(view, named)`, signed over `message`.
pub(super) fn qc_signed_over(
    svc: &H2Service<MockExecutionLayer>,
    keys: &[BlsSecretKey],
    signers: &[usize],
    view: u64,
    named: B256,
    message: &[u8],
) -> Vec<u8> {
    let profile = svc.engine.signing_profile();
    let signatures: Vec<_> = signers.iter().map(|&i| profile.sign(&keys[i], message)).collect();
    let refs: Vec<_> = signatures.iter().collect();
    let aggregate = n42_h2_primitives::bls::AggregateSignature::aggregate(&refs).expect("aggregate");
    let mut bitmap = (keys.len() as u16).to_le_bytes().to_vec();
    bitmap.resize(2 + keys.len().div_ceil(8), 0);
    for &i in signers {
        bitmap[2 + i / 8] |= 1 << (i % 8);
    }
    // gov5's `HotStuffQC` SSZ: the view, then each field length-prefixed.
    let mut out = view.to_le_bytes().to_vec();
    for field in [named.as_slice(), &aggregate.to_bytes()[..], &bitmap[..]] {
        out.extend_from_slice(&(field.len() as u32).to_le_bytes());
        out.extend_from_slice(field);
    }
    let decoded = n42_h2_wire::h2_wire::decode_h2_qc(&out).expect("the codec reads it back");
    assert_eq!((decoded.view, decoded.block_hash), (view, named));
    out
}

/// A mock block whose header carries gov5's extra layout for `view` with
/// `qc` embedded.
fn block_with_extra(number: u64, parent: B256, view: u64, qc: Vec<u8>) -> (B256, Header, alloy_primitives::Bytes) {
    let built = MockExecutionLayer::built_block_on(number, parent);
    let mut header = n42_h2_consensus::N42Header::from(built.execution_data.clone().into_block_raw().expect("raw block").header);
    let extra = n42_h2_consensus::HeaderExtra { view, qc, seal: Some([0; n42_h2_consensus::EXTRA_SEAL_LEN]) };
    header.extra_data = extra.encode();
    let rlp = n42_h2_net::encode_block_rlp_raw(&header, &[], &[], None);
    (header.hash_slow(), header, alloy_primitives::Bytes::from(rlp))
}

/// Section 6.6 of `docs/MATURITY_HARDENING_2026_10.md`: a pulled range
/// whose third block carries a forged parent QC. The block the second
/// header anchors is executed; the second, whose anchor would be the forged
/// QC, and everything after are not; the peer is refused for the gap and not
/// asked again even when it is the only peer, and another peer is asked
/// instead.
#[tokio::test]
async fn a_pulled_block_with_a_forged_parent_qc_ends_the_batch_and_its_peer_is_not_asked_again() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
    rig.svc.sync_lazy_verify = false;
    let peer = PeerId::random();
    let quorum = [0, 1, 2];
    let mut blocks: Vec<(B256, Header, alloy_primitives::Bytes)> = Vec::new();
    let mut parent = B256::ZERO;
    for number in 1..=4u64 {
        let qc = match number {
            1 => Vec::new(),
            // Signed over another hash than the one it names.
            3 => header_qc(&rig.svc, &keys, &quorum, number - 1, parent, B256::repeat_byte(0x77)),
            _ => header_qc(&rig.svc, &keys, &quorum, number - 1, parent, parent),
        };
        let block = block_with_extra(number, parent, number, qc);
        parent = block.0;
        blocks.push(block);
    }
    catching_up(&mut rig, peer, 1, 4);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 4, step: 1 }, chunks(&blocks)));
    let events = import(&mut rig).await;

    assert_eq!(events, vec![ServiceEvent::Synced { height: 1, complete: false }]);
    assert_eq!(executed(&rig), vec![blocks[0].0], "the block an honest header anchored, and only that");
    assert!(blocks[1..].iter().all(|(hash, ..)| !rig.svc.imported.contains(hash)));
    assert_eq!(rig.svc.refused_range_peers.get(&peer), Some(&3));
    assert!(rig.svc.catch_up.is_none());

    // The only peer known, still claiming more: not asked again.
    rig.svc.catch_up_retry_after = None;
    rig.svc.note_peer_height(peer, 10);
    let mut events = Vec::new();
    within(rig.svc.consider_catch_up(&mut events)).await;
    assert!(rig.svc.catch_up.is_none(), "the refused peer is not re-asked for the gap");
    assert!(rig.el.calls().iter().all(|c| !matches!(c, ElCall::NewPayload(h) if *h == blocks[2].0)));

    // Another peer is, from above what was executed.
    let other = PeerId::random();
    rig.svc.note_peer_height(other, 10);
    within(rig.svc.consider_catch_up(&mut events)).await;
    let catch_up = rig.svc.catch_up.as_ref().expect("a pull from the other peer");
    assert_eq!((catch_up.peer, catch_up.next), (other, 2));
}

/// Audit 2026-10 round 3 (R3-C2): a block that arrived live was voted for
/// whatever its header carried, where gov5's `verifyHeaderWithBatch` refuses
/// a header whose embedded QC does not decode, names a view past the
/// header's own, or does not verify under a known set. A Rust quorum could
/// then certify a block every gov5 member rejects. Such a block's import no
/// longer reaches the engine, so no vote follows; a good QC still passes.
#[tokio::test]
async fn a_live_block_whose_header_qc_gov5_refuses_is_not_voted_for() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
    let quorum = [0, 1, 2];
    let parent = B256::ZERO;
    let refused = [
        ("forged", header_qc(&rig.svc, &keys, &quorum, 3, parent, B256::repeat_byte(0x77))),
        ("past the header's view", header_qc(&rig.svc, &keys, &quorum, 5, parent, parent)),
        ("undecodable", vec![0xff; 10]),
    ];
    let mut events = Vec::new();
    for (checked, (name, qc)) in [false, true].into_iter().flat_map(|c| refused.clone().map(|r| (c, r))) {
        let (hash, header, _) = block_with_extra(if checked { 2 } else { 1 }, parent, 4, qc);
        rig.svc.remember_block(hash, &header);
        let event = if checked { ConsensusEvent::BlockChecked(hash) } else { ConsensusEvent::BlockImported(hash) };
        rig.svc.apply_driver_action(DriverAction::Consensus(Box::new(event)), &mut events).expect("ok");
        assert!(!rig.svc.engine.has_imported_block(&hash), "{name} (checked: {checked}) reached the engine");
        assert!(!rig.svc.imported.contains(&hash), "{name} is not built on");
    }

    let good = header_qc(&rig.svc, &keys, &quorum, 3, parent, parent);
    let (hash, header, _) = block_with_extra(1, parent, 4, good);
    rig.svc.remember_block(hash, &header);
    rig.svc
        .apply_driver_action(DriverAction::Consensus(Box::new(ConsensusEvent::BlockImported(hash))), &mut events)
        .expect("ok");
    assert!(rig.svc.engine.has_imported_block(&hash), "a header QC that verifies passes");
    // None at all: nothing to check, as gov5.
    let (hash, header, _) = block_with_extra(1, parent, 5, Vec::new());
    rig.svc.remember_block(hash, &header);
    rig.svc
        .apply_driver_action(DriverAction::Consensus(Box::new(ConsensusEvent::BlockImported(hash))), &mut events)
        .expect("ok");
    assert!(rig.svc.engine.has_imported_block(&hash), "a header without a QC passes");
}

/// Audit 2026-10 R2-C9 (the remainder): under gov5's two-phase gate a held
/// header is what releases Round 1 (gov5's `tryHeaderVote`), once its QC
/// passes the check every vote of this node passes (R3-C2). Without the gate
/// a header tells the engine nothing.
#[tokio::test]
async fn under_the_two_phase_gate_a_header_reaches_the_engine_once_its_qc_passes() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
    let quorum = [0, 1, 2];
    let parent = B256::ZERO;
    let good = header_qc(&rig.svc, &keys, &quorum, 3, parent, parent);
    let (hash, header, _) = block_with_extra(1, parent, 4, good.clone());
    rig.svc.remember_block(hash, &header);
    assert!(!rig.svc.engine.knows_parent(&hash), "no gate: the header waits for the import");
    rig.svc.engine.set_two_phase_vote_gate(true);
    let (hash, header, _) = block_with_extra(2, parent, 4, good);
    rig.svc.remember_block(hash, &header);
    assert!(rig.svc.engine.knows_parent(&hash), "the gate: the header reaches the engine");
    let forged = header_qc(&rig.svc, &keys, &quorum, 3, parent, B256::repeat_byte(0x77));
    let (hash, header, _) = block_with_extra(3, parent, 4, forged);
    rig.svc.remember_block(hash, &header);
    assert!(!rig.svc.engine.knows_parent(&hash), "a header QC refused: no header vote");
}

/// A TC for `view`, signed by `signers`, over the genesis high QC.
fn timeout_cert(
    svc: &H2Service<MockExecutionLayer>,
    keys: &[BlsSecretKey],
    set: &ValidatorSet,
    signers: &[u32],
    view: u64,
) -> n42_h2_primitives::consensus::TimeoutCertificate {
    let profile = svc.engine.signing_profile();
    let mut collector = n42_h2_consensus::TimeoutCollector::new(view, set.len());
    for &sender in signers {
        collector
            .add_timeout(sender, profile.sign(&keys[sender as usize], &profile.timeout_message(view)), QuorumCertificate::genesis())
            .expect("distinct senders");
    }
    collector.build_tc_with_profile(set, profile).expect("a TC")
}

/// A vote from validator 1 for a view far ahead, carrying `tc` as gov5's
/// `SyncInfo` `high_tc`.
fn vote_carrying(svc: &H2Service<MockExecutionLayer>, keys: &[BlsSecretKey], view: u64, tc: Option<&n42_h2_primitives::consensus::TimeoutCertificate>) -> H2V4Envelope {
    let profile = svc.engine.signing_profile();
    let block_hash = B256::repeat_byte(0x42);
    n42_h2_wire::h2_v4::H2V4Envelope {
        identity: svc.identity,
        changes_hash: B256::ZERO,
        message: n42_h2_wire::h2_wire::H2Message::Vote(n42_h2_wire::h2_wire::H2Vote {
            view,
            block_hash,
            voter: 1,
            signature: profile.sign(&keys[1], &profile.vote_message(view, block_hash)),
            high_tc: tc.map(|tc| wire_bridge::tc_to_wire(tc).expect("wire TC")),
        }),
    }
}

/// Audit 2026-10 round 2 (R2-C1, the inbound half): gov5 piggybacks its
/// highest TC on votes, commit votes and timeouts (`SyncInfo`) and a lagging
/// member adopts it at once (`processEmbeddedTC`): it locks on the TC's high
/// QC and moves to the view after it. This node dropped the field, so a
/// member that missed the `NewView` waited out its own timeouts instead. A TC
/// that does not verify, or would not move the node, changes nothing.
#[tokio::test]
async fn a_tc_piggybacked_on_a_vote_moves_a_lagging_node_to_the_view_after_it() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
    assert_eq!(rig.svc.engine.current_view(), 1);

    // Signed over another view: does not verify, no move.
    let mut forged = timeout_cert(&rig.svc, &keys, &set, &[1, 2, 3], 5);
    forged.aggregate_signature = timeout_cert(&rig.svc, &keys, &set, &[1, 2, 3], 4).aggregate_signature;
    rig.svc.accept_envelope(&vote_carrying(&rig.svc, &keys, 7, Some(&forged)));
    assert_eq!(rig.svc.engine.current_view(), 1, "a TC that does not verify is ignored");

    let tc = timeout_cert(&rig.svc, &keys, &set, &[1, 2, 3], 5);
    rig.svc.accept_envelope(&vote_carrying(&rig.svc, &keys, 7, Some(&tc)));
    assert_eq!(rig.svc.engine.current_view(), 6, "the view after the TC's");

    // An older TC does not move it back.
    let old = timeout_cert(&rig.svc, &keys, &set, &[1, 2, 3], 3);
    rig.svc.accept_envelope(&vote_carrying(&rig.svc, &keys, 8, Some(&old)));
    assert_eq!(rig.svc.engine.current_view(), 6);
}

/// Audit 2026-10 round 2 (R2-R2): only the first body nobody asked for at a
/// height was imported at once (B-3), so an anonymous peer that sent a made-up
/// block first took the slot and the honest leader's block waited for its
/// proposal. A body sealed by the leader of the view its header names is
/// imported at once whatever came first; an unsealed or wrongly sealed
/// sibling still waits.
#[tokio::test]
async fn a_body_sealed_by_its_views_leader_is_imported_after_a_peers_made_up_one() {
    let (keys, set) = keys(1);
    let mut rig = node_in(&keys, &set, 0, None).await;
    let gossip = |rig: &mut Rig, rlp: &alloy_primitives::Bytes| {
        let data = compress_block_rlp(rlp).expect("snappy");
        rig.svc.handle_transport_event(TransportEvent::Block { from: None, data }).expect("ok");
    };
    let sealed = |parent: B256, view: u64, key: &BlsSecretKey| {
        let (_, mut header, _) = block_with_extra(1, parent, view, Vec::new());
        n42_h2_consensus::seal_header(&mut header, key).expect("seal");
        let rlp = n42_h2_net::encode_block_rlp_raw(&header, &[], &[], None);
        (header.hash_slow(), alloy_primitives::Bytes::from(rlp))
    };
    let (made_up, _, made_up_rlp) = block_with_extra(1, B256::repeat_byte(1), 3, Vec::new());
    gossip(&mut rig, &made_up_rlp);
    assert_eq!(rig.svc.ready_bodies, vec![made_up], "the first takes the height");

    let stranger = BlsSecretKey::random().expect("bls keygen");
    let (forged, forged_rlp) = sealed(B256::repeat_byte(2), 3, &stranger);
    gossip(&mut rig, &forged_rlp);
    assert!(!rig.svc.ready_bodies.contains(&forged), "a seal by anyone else does not count");

    let (leaders, leaders_rlp) = sealed(B256::repeat_byte(3), 3, &keys[0]);
    gossip(&mut rig, &leaders_rlp);
    assert!(rig.svc.ready_bodies.contains(&leaders), "the leader's block is imported at once");
}

/// Audit 2026-10 B-6: a step that returns early -- a range reply part
/// imported, the rest left for the next step -- still checks for local
/// faults: a vote-log halt ends it as it ends a step on the slow path.
#[tokio::test]
async fn a_step_on_the_fast_path_still_stops_on_a_local_fault() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let blocks = anchored_chain(&rig, PULLED_BLOCKS_PER_STEP as u64 * 6);
    let count = blocks.len() as u64;
    catching_up(&mut rig, peer, 1, count);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count, step: 1 }, chunks(&blocks)));
    rig.svc.engine.halt_voting("vote_log");
    let err = within(rig.svc.step()).await.expect_err("the fault ends the step");
    assert!(matches!(err, ServiceError::Fatal { reason: "vote_log", .. }), "{err:?}");
    assert!(!rig.svc.pending_imports.is_empty(), "the step took the fast path");
}

/// Audit 2026-10 A-7 and sync standard §3.3: a header QC proves the block it
/// names and the chain below it, not the block that carries it. A range
/// server that copies one real QC into blocks it made up above the certified
/// one gets nothing of them executed: they are never anchored. Only the
/// certified chain reaches the execution layer, and it is never committed,
/// safe or finalized by the pull.
#[tokio::test]
async fn a_header_qc_proves_the_chain_up_to_the_block_it_names_not_the_block_carrying_it() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
    let peer = PeerId::random();
    let quorum = [0, 1, 2];
    let mut blocks: Vec<(B256, Header, alloy_primitives::Bytes)> = Vec::new();
    let mut parent = B256::ZERO;
    let mut real_qc = Vec::new();
    for number in 1..=4u64 {
        let qc = match number {
            1 => Vec::new(),
            2 => header_qc(&rig.svc, &keys, &quorum, 1, parent, parent),
            3 => {
                real_qc = header_qc(&rig.svc, &keys, &quorum, 2, parent, parent);
                real_qc.clone()
            }
            // Made up above block 2: the same real QC, copied.
            _ => real_qc.clone(),
        };
        let block = block_with_extra(number, parent, number, qc);
        parent = block.0;
        blocks.push(block);
    }
    catching_up(&mut rig, peer, 1, 4);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 4, step: 1 }, chunks(&blocks)));
    import(&mut rig).await;

    assert_eq!(executed(&rig), vec![blocks[0].0, blocks[1].0], "only blocks 1 and 2 are certified");
    assert!(!rig.svc.imported.contains(&blocks[2].0) && !rig.svc.imported.contains(&blocks[3].0));
    assert_eq!(rig.svc.unproven_from, None, "nothing unproven was executed");
    assert_eq!(rig.svc.engine.last_committed_qc().view, 0, "a pulled block is not committed");
    for call in rig.el.calls() {
        if let ElCall::ForkchoiceUpdated(state) = call {
            assert!(
                blocks.iter().all(|(hash, ..)| *hash != state.safe_block_hash && *hash != state.finalized_block_hash),
                "a pulled block is never safe or finalized: {state:?}"
            );
        }
    }
}

/// Sections 6.6 and 6.9: a pulled block whose embedded QC names a view in an
/// epoch this node knows no validator set for (a cold node, or one further
/// behind than its epoch history) is checked by its parent link only, as
/// gov5's `verifyHeaderWithBatch`; a QC for a known view that does not
/// verify is still refused.
#[tokio::test]
async fn a_pulled_block_whose_qc_names_an_unknown_epoch_is_checked_by_its_parent_link_only() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
    *rig.svc.engine.epoch_manager_mut() = n42_h2_consensus::EpochManager::with_epoch_length(set.clone(), 10);
    let quorum = [0, 1, 2];
    let parent = B256::ZERO;

    // Epoch 2 (views 21..=30): neither the current epoch nor a staged one.
    let unknown = header_qc(&rig.svc, &keys, &quorum, 25, parent, B256::repeat_byte(0x77));
    let (_, header, _) = block_with_extra(1, parent, 30, unknown);
    rig.svc.check_pulled_block(&header).expect("an unknown set leaves the QC unchecked");

    // A known view whose certificate is forged: refused as before.
    let forged = header_qc(&rig.svc, &keys, &quorum, 3, parent, B256::repeat_byte(0x77));
    let (_, header, _) = block_with_extra(1, parent, 4, forged);
    assert!(rig.svc.check_pulled_block(&header).is_err(), "a known set still verifies the QC");

    // The parent link is checked either way.
    let unknown = header_qc(&rig.svc, &keys, &quorum, 25, parent, parent);
    let (_, header, _) = block_with_extra(2, B256::repeat_byte(0x09), 30, unknown);
    rig.svc.catch_up =
        Some(CatchUp { next: 2, prev_hash: Some(B256::repeat_byte(0x01)), ..CatchUp::new(PeerId::random(), 0, 4) });
    assert!(rig.svc.check_pulled_block(&header).is_err(), "a block that does not extend the last one");
}

/// Audit 2026-10 B-1 and sync standard §3.4.6: a range server whose chain
/// carries no certificate at all (a forged chain, or a stretch of a producer
/// that embeds none) gets none of it executed under `enforce`: the pull ends
/// at its head with the blocks held and dropped, no blame. An honest peer at
/// the same height is still pulled from.
#[tokio::test]
async fn an_uncertified_pulled_chain_does_not_stop_a_pull_from_an_honest_peer() {
    let mut rig = node(1, 0, None).await;
    let forger = PeerId::random();
    let forged = chain(4);
    catching_up(&mut rig, forger, 1, 4);
    rig.svc.pending_imports.push((forger, RangeRequest { start: 1, count: 4, step: 1 }, chunks(&forged)));
    import(&mut rig).await;
    rig.svc.pending_imports.push((forger, RangeRequest { start: 5, count: MAX_RANGE_BLOCKS, step: 1 }, Vec::new()));
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 0, complete: true }]);
    assert!(executed(&rig).is_empty(), "the uncertified chain did not reach the execution layer");
    assert!(!rig.svc.refused_range_peers.contains_key(&forger), "not blamed: it may be an honest legacy server");

    let honest = PeerId::random();
    rig.svc.catch_up_retry_after = None;
    rig.svc.peer_heights.remove(&forger);
    rig.svc.note_peer_height(honest, 4);
    let mut events = Vec::new();
    within(rig.svc.consider_catch_up(&mut events)).await;
    let catch_up = rig.svc.catch_up.as_ref().expect("the honest peer is pulled from");
    assert_eq!((catch_up.peer, catch_up.next), (honest, 1));
}

/// The same chain under `N42_SYNC_ANCHOR=observe`: imported as before the
/// rule, and every block `enforce` would have held is counted and logged.
#[tokio::test]
async fn under_observe_an_uncertified_chain_is_imported_and_logged() {
    let mut rig = node(1, 0, None).await;
    rig.svc.sync_anchor_mode = SyncAnchorMode::Observe;
    let peer = PeerId::random();
    let blocks = chain(4);
    catching_up(&mut rig, peer, 1, 4);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 4, step: 1 }, chunks(&blocks)));
    import(&mut rig).await;
    rig.svc.pending_imports.push((peer, RangeRequest { start: 5, count: MAX_RANGE_BLOCKS, step: 1 }, Vec::new()));
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 4, complete: true }]);
    assert_eq!(executed(&rig), blocks.iter().map(|b| b.0).collect::<Vec<_>>(), "imported as before");
    assert_eq!(rig.svc.sync_anchor_would_refuse, 4, "enforce would have executed none of them");

    // `off`: the same import, nothing counted.
    let mut rig = node(1, 0, None).await;
    rig.svc.sync_anchor_mode = SyncAnchorMode::Off;
    catching_up(&mut rig, peer, 1, 4);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 4, step: 1 }, chunks(&blocks)));
    import(&mut rig).await;
    assert_eq!(executed(&rig).len(), 4);
    assert_eq!(rig.svc.sync_anchor_would_refuse, 0);
}

/// A block that does not extend the one pulled before it is refused before
/// the execution layer sees it, whatever its certificate says.
#[tokio::test]
async fn a_pulled_block_that_does_not_extend_the_previous_one_is_refused() {
    let mut rig = node(1, 0, None).await;
    rig.svc.sync_lazy_verify = false;
    let peer = PeerId::random();
    let mut blocks = anchored_chain(&rig, 2);
    blocks.push(block(3, B256::repeat_byte(0x09)));
    catching_up(&mut rig, peer, 1, 3);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 3, step: 1 }, chunks(&blocks)));
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 1, complete: false }]);
    assert_eq!(executed(&rig), vec![blocks[0].0]);
    assert_eq!(rig.svc.refused_range_peers.get(&peer), Some(&3));
}

/// Sync standard §3.4: a peer that serves a made-up block in the middle of
/// an honest range, followed by a block that carries a real commit QC copied
/// from the honest chain. The QCs name honest blocks, so the made-up ones are
/// never anchored: nothing from the forged block up reaches the execution
/// layer, while the honest prefix below it does.
#[tokio::test]
async fn a_forged_block_mid_range_never_reaches_the_execution_layer() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
    rig.svc.sync_lazy_verify = false;
    let peer = PeerId::random();
    let real = anchored_chain(&rig, 6);
    let qc_of = |header: &Header| n42_h2_consensus::HeaderExtra::decode(&header.extra_data).expect("extra").qc;
    // Block 4 made up on the real block 3 (another view, so another hash),
    // carrying real block 4's QC; block 5 on top of it with real block 5's.
    let forged4 = block_with_extra(4, real[2].0, 9, qc_of(&real[3].1));
    let forged5 = block_with_extra(5, forged4.0, 10, qc_of(&real[4].1));
    assert_ne!(forged4.0, real[3].0);
    let served = vec![real[0].clone(), real[1].clone(), real[2].clone(), forged4.clone(), forged5.clone()];
    catching_up(&mut rig, peer, 1, 5);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 5, step: 1 }, chunks(&served)));
    assert!(import(&mut rig).await.is_empty());
    rig.svc.pending_imports.push((peer, RangeRequest { start: 6, count: MAX_RANGE_BLOCKS, step: 1 }, Vec::new()));
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 3, complete: true }]);
    assert_eq!(executed(&rig), vec![real[0].0, real[1].0, real[2].0], "the honest prefix, and only that");
    assert!(!rig.svc.imported.contains(&forged4.0) && !rig.svc.imported.contains(&forged5.0));
}

/// An anchor that arrives in a later range authenticates a block buffered
/// from an earlier one: the top of the first reply is executed once the
/// header above it comes in the next.
#[tokio::test]
async fn an_anchor_in_a_later_range_releases_a_block_buffered_from_an_earlier_one() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let blocks = anchored_chain(&rig, 5);
    catching_up(&mut rig, peer, 1, 5);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 5, step: 1 }, chunks(&blocks[..3])));
    assert!(import(&mut rig).await.is_empty());
    assert_eq!(executed(&rig), vec![blocks[0].0, blocks[1].0]);
    assert_eq!(rig.svc.catch_up.as_ref().map(|c| c.next), Some(4), "asks on");

    rig.svc.pending_imports.push((peer, RangeRequest { start: 4, count: 2, step: 1 }, chunks(&blocks[3..])));
    import(&mut rig).await;
    assert_eq!(executed(&rig), blocks[..4].iter().map(|b| b.0).collect::<Vec<_>>(), "block 3 released by block 4's QC");
}

/// gov5's 2026-11-24 finding, pinned for this node: under `enforce` a pulled
/// chain whose header QCs name views in many later epochs of the genesis
/// `epochLength` (20, the devnet's), with every step jumping over a boundary
/// so no view lands on one, is anchored all the way up. The engine is built
/// as `h2_validator` builds it (`EpochManager::new`: the static set answers
/// every view), so no epoch boundary has to be crossed for a set to be known.
#[tokio::test]
async fn a_pulled_chain_many_epochs_on_is_anchored_with_the_static_set() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
    rig.svc.engine.set_rotate_on_timeout(Some(1), 20);
    assert!(!rig.svc.engine.epoch_manager().epochs_enabled(), "the node's engine runs one static set");
    let quorum = [0, 1, 3];
    // Epochs (length 20) 2, 3, 5, 8, 21, 60: no view is a boundary's first.
    let views = [45u64, 63, 107, 168, 433, 1203];
    let peer = PeerId::random();
    let mut blocks: Vec<(B256, Header, alloy_primitives::Bytes)> = Vec::new();
    let mut parent = B256::ZERO;
    for (i, view) in views.iter().copied().enumerate() {
        let qc = if i == 0 { Vec::new() } else { header_qc(&rig.svc, &keys, &quorum, views[i - 1], parent, parent) };
        let block = block_with_extra(i as u64 + 1, parent, view, qc);
        parent = block.0;
        blocks.push(block);
    }
    catching_up(&mut rig, peer, 1, views.len() as u64);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: views.len() as u64, step: 1 }, chunks(&blocks)));
    import(&mut rig).await;
    let anchored: Vec<_> = blocks[..views.len() - 1].iter().map(|b| b.0).collect();
    assert_eq!(executed(&rig), anchored, "every block a later QC names is anchored; only the top is tail");
    assert!(!rig.svc.refused_range_peers.contains_key(&peer));
}

/// Sync standard §3.3: a header QC is an anchor only in the commit domain
/// and only under the set of its exact view. A prepare-domain QC, or a
/// commit QC whose set this node does not know (fails closed), anchors
/// nothing -- and neither is the peer's fault.
#[tokio::test]
async fn a_prepare_qc_or_a_qc_of_an_unknown_set_anchors_nothing_and_blames_no_one() {
    let (keys, set) = keys(4);
    let quorum = [0, 1, 2];
    for case in ["prepare", "unknown set"] {
        let mut rig = node_in(&keys, &set, 0, None).await;
        *rig.svc.engine.epoch_manager_mut() = n42_h2_consensus::EpochManager::with_epoch_length(set.clone(), 10);
        // Views 21..=30 are epoch 2, for which no set is known.
        let base = if case == "prepare" { 0 } else { 20 };
        let peer = PeerId::random();
        let mut blocks: Vec<(B256, Header, alloy_primitives::Bytes)> = Vec::new();
        let mut parent = B256::ZERO;
        for number in 1..=4u64 {
            let view = base + number;
            let qc = match (number, case) {
                (1, _) => Vec::new(),
                (_, "prepare") => prepare_qc(&rig.svc, &keys, &quorum, view - 1, parent),
                _ => header_qc(&rig.svc, &keys, &quorum, view - 1, parent, parent),
            };
            let block = block_with_extra(number, parent, view, qc);
            parent = block.0;
            blocks.push(block);
        }
        catching_up(&mut rig, peer, 1, 4);
        rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 4, step: 1 }, chunks(&blocks)));
        import(&mut rig).await;
        assert!(executed(&rig).is_empty(), "{case}: nothing anchored, nothing executed");
        assert!(!rig.svc.refused_range_peers.contains_key(&peer), "{case}: not a fault");
        assert!(rig.svc.catch_up.is_some(), "{case}: the pull goes on");
    }
}

/// A commit QC of this node's own, naming `hash` at `view`.
fn own_commit_qc(view: u64, hash: B256) -> n42_h2_primitives::consensus::QuorumCertificate {
    let mut qc = n42_h2_primitives::consensus::QuorumCertificate::genesis();
    qc.view = view;
    qc.block_hash = hash;
    qc
}

/// Sync standard §3.3, conflict: this node committed block X at height 2;
/// a peer serves an anchored chain whose block 3 names another block at
/// height 2. The importer halts with both blocks and both QCs' views on
/// record, executes nothing of that chain, and starts no later pull;
/// nothing is reorged and the peer is not refused for it.
#[tokio::test]
async fn an_anchored_chain_that_does_not_join_the_committed_head_halts_the_importer() {
    let mut rig = node(1, 0, None).await;
    rig.svc.sync_lazy_verify = false;
    let peer = PeerId::random();
    let ours = B256::repeat_byte(0x42);
    let mut events = Vec::new();
    rig.svc.sync_note_commit(Some(2), &own_commit_qc(50, ours), &mut events);
    assert!(rig.svc.sync_halt().is_none());
    let theirs = anchored_chain(&rig, 5);
    catching_up(&mut rig, peer, 3, 5);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 3, count: 3, step: 1 }, chunks(&theirs[2..])));
    let events = import(&mut rig).await;

    assert_eq!(events, vec![ServiceEvent::Synced { height: 2, complete: false }]);
    assert!(executed(&rig).is_empty(), "nothing of the conflicting chain is executed");
    assert!(rig.el.calls().iter().all(|c| !matches!(c, ElCall::ForkchoiceUpdated(_))), "no reorg");
    let halt = rig.svc.sync_halt().expect("halted");
    assert_eq!(halt.kind, crate::sync_safety::HaltKind::Conflict);
    assert_eq!((halt.first.hash, halt.first.number, halt.first.qc.view), (ours, Some(2), 50));
    assert_eq!((halt.second.hash, halt.second.number), (theirs[1].0, Some(2)));
    assert_eq!(halt.second.qc.view, 3, "the QC that authenticated block 3, from block 4's header");
    assert!(!rig.svc.refused_range_peers.contains_key(&peer), "a verified certificate is not the relay's fault");
    // And the whole node halts (crate::safety_halt), not the importer alone.
    assert_eq!(rig.svc.safety_halt().and_then(|h| h.evidence()).map(|e| e.source.as_str()), Some("sync"));
    assert_eq!(rig.svc.voting_halted(), Some("commit_conflict"));

    // No pull starts again, however far ahead a peer says it is.
    rig.svc.catch_up_retry_after = None;
    rig.svc.note_peer_height(PeerId::random(), 100);
    let mut events = Vec::new();
    within(rig.svc.consider_catch_up(&mut events)).await;
    assert!(rig.svc.catch_up.is_none() && events.is_empty(), "the importer stays halted");
}

/// Sync standard §3.3, equivocation: one peer's anchored chain is executed
/// up to block 3; a later pull from another peer brings a chain whose
/// authenticated block 4 names another block 3. Two verified certificates
/// for different blocks at height 3: halted as a conflict is, both kept as
/// evidence, the relaying peer not refused.
#[tokio::test]
async fn two_verified_anchors_for_different_blocks_at_one_height_halt_and_keep_the_evidence() {
    let mut rig = node(1, 0, None).await;
    rig.svc.sync_lazy_verify = false;
    let (first, second) = (PeerId::random(), PeerId::random());
    let a = anchored_chain(&rig, 4);
    catching_up(&mut rig, first, 1, 4);
    rig.svc.pending_imports.push((first, RangeRequest { start: 1, count: 4, step: 1 }, chunks(&a)));
    import(&mut rig).await;
    rig.svc.pending_imports.push((first, RangeRequest { start: 5, count: 1, step: 1 }, Vec::new()));
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 3, complete: true }]);
    assert_eq!(rig.svc.certified_head(), Some((3, a[2].0)), "the next pull starts on block 3");

    let b = anchored_chain_at(&rig, 6, 100);
    catching_up(&mut rig, second, 4, 6);
    rig.svc.pending_imports.push((second, RangeRequest { start: 4, count: 3, step: 1 }, chunks(&b[3..])));
    import(&mut rig).await;

    let ran = executed(&rig);
    assert_eq!(ran, a[..3].iter().map(|x| x.0).collect::<Vec<_>>(), "nothing of the second chain executed");
    let halt = rig.svc.sync_halt().expect("halted");
    assert_eq!(halt.kind, crate::sync_safety::HaltKind::Equivocation);
    assert_eq!((halt.first.hash, halt.second.hash), (a[2].0, b[2].0));
    assert_eq!((halt.first.qc.view, halt.second.qc.view), (3, 104));
    let evidence: Vec<_> = rig.svc.sync_equivocation_evidence().cloned().collect();
    assert_eq!(evidence, vec![halt.clone()], "both certificates kept");
    assert_eq!(rig.svc.safety_halt().map(|h| h.reason()), Some("equivocation"), "the node halts");
    assert!(!rig.svc.refused_range_peers.contains_key(&second));
}

#[tokio::test]
async fn a_short_probe_reply_ends_the_pull_only_at_the_height_the_probe_began_at() {
    for (probe_height, ends) in [(2u64, true), (5, false)] {
        let mut rig = node(1, 0, None).await;
        let peer = PeerId::random();
        let blocks = anchored_chain(&rig, 2);
        rig.svc.catch_up = Some(CatchUp { probing: true, probe_height, ..CatchUp::new(peer, 0, 1024) });
        rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 1024, step: 1 }, chunks(&blocks)));
        let events = import(&mut rig).await;
        if ends {
            // Block 2's anchor is not served: it stays unexecuted.
            assert_eq!(events, vec![ServiceEvent::Synced { height: 1, complete: true }]);
            assert!(rig.svc.catch_up.is_none());
        } else {
            // Short of the window but below the probe's height: a server's
            // byte cap, not the peer's head. The pull asks on.
            assert!(events.is_empty());
            assert_eq!(rig.svc.catch_up.as_ref().map(|c| c.next), Some(3));
        }
    }
}

#[tokio::test]
async fn an_empty_probe_ends_a_pull_that_already_made_progress() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    rig.svc.catch_up = Some(CatchUp { next: 11, executed: 10, probing: true, ..CatchUp::new(peer, 4, 1034) });
    rig.svc.pending_imports.push((peer, RangeRequest { start: 11, count: 1024, step: 1 }, Vec::new()));
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 10, complete: true }]);
}

/// Sync standard B2: a server that stops at its head -- cleanly, or (gov5
/// main, n42-26) with an error chunk the codec turns into a short reply --
/// leaves a prefix. The pull imports what of it is anchored and asks on from
/// after it; the refusal that answers that is where the peer's chain ends,
/// and the pull finishes without blaming the peer.
#[tokio::test]
async fn a_pull_asks_on_after_a_prefix_and_ends_without_blame_where_the_peer_stops() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let blocks = anchored_chain(&rig, 3);
    catching_up(&mut rig, peer, 1, 8);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 8, step: 1 }, chunks(&blocks)));
    assert!(import(&mut rig).await.is_empty());
    let catch_up = rig.svc.catch_up.as_ref().expect("still pulling");
    assert_eq!((catch_up.next, catch_up.probing), (4, false), "asks on from after the prefix");
    assert_eq!(rig.svc.imported_height, Some(2));

    let request = RangeRequest { start: 4, count: 5, step: 1 };
    rig.svc
        .handle_transport_event(TransportEvent::RangeFetched { peer, request, reply: Err("code 2: invalid block number".into()) })
        .expect("handled");
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 2, complete: true }]);
    assert!(rig.svc.catch_up.is_none());
    assert_eq!(rig.svc.failed_peer, None, "not blamed");
    assert!(!rig.svc.refused_range_peers.contains_key(&peer), "nor refused");
}

/// Replaces `rig`'s engine with one restored from a persisted commit of
/// `block_hash` at `view`, as a restart does: nothing committed live yet.
fn restore_commit(rig: &mut Rig, keys: &[BlsSecretKey], set: &ValidatorSet, block_hash: B256, view: u64) {
    let mut qc = n42_h2_primitives::consensus::QuorumCertificate::genesis();
    qc.view = view;
    qc.block_hash = block_hash;
    let (tx, rx) = mpsc::channel::<EngineOutput>(256);
    let mut engine = ConsensusEngine::with_recovered_state(
        0,
        keys[0].clone(),
        n42_h2_consensus::EpochManager::new(set.clone()),
        1_000,
        4_000,
        tx,
        view + 1,
        qc.clone(),
        qc,
        0,
        view,
    );
    engine.enable_h2_v4_signing(ID);
    rig.svc.engine = engine;
    rig.svc.outputs = rx;
}

/// Blocks 1..=`count` in `rig`'s execution layer.
async fn hold_chain(rig: &Rig, count: u64) -> Vec<(B256, Header, alloy_primitives::Bytes)> {
    use n42_h2_execution::ExecutionLayer;
    let blocks = chain(count);
    for (_, _, body) in &blocks {
        let payload = n42_h2_net::decode_block_rlp_raw(body, HeaderProfile::Ethereum).unwrap().execution_data();
        within(rig.el.new_payload(payload)).await.expect("accepted");
    }
    blocks
}

/// What a range may carry (sync standard Q-S5): the last live commit; before
/// one, after a restart, the restored commit's block, numbered by the
/// execution layer once and then known; with nothing committed, genesis.
#[tokio::test]
async fn the_range_ceiling_is_the_committed_height_or_after_a_restart_the_restored_commit() {
    let mut rig = node(1, 0, None).await;
    assert_eq!(rig.svc.serve_ceiling(), ServeCeiling::Height(0), "nothing committed");
    rig.svc.committed_height = Some(7);
    assert_eq!(rig.svc.serve_ceiling(), ServeCeiling::Height(7));

    let (keys, set) = keys(1);
    let mut rig = node_in(&keys, &set, 0, None).await;
    let blocks = hold_chain(&rig, 4).await;
    restore_commit(&mut rig, &keys, &set, blocks[1].0, 5);
    assert_eq!(rig.svc.serve_ceiling(), ServeCeiling::Block(blocks[1].0), "the layer is asked for its number");
    assert_eq!(within(rig.svc.unproven_after_restart()).await, Some(3), "blocks 3 and 4 are not committed");
    assert_eq!(rig.svc.restored_committed, Some((blocks[1].0, 2)));
    assert_eq!(rig.svc.serve_ceiling(), ServeCeiling::Height(2));
    rig.svc.committed_height = Some(4);
    assert_eq!(rig.svc.serve_ceiling(), ServeCeiling::Height(4), "a live commit takes over");
}

/// A restarted server, before its first live commit: a range is served up
/// to the restored commit and ends cleanly; one past it is refused with
/// gov5's server-error answer; and the status it advertises once it knows
/// the commit's number is that height, not its execution layer's head.
#[tokio::test]
async fn a_restarted_server_serves_and_advertises_up_to_its_restored_commit() {
    let (keys, set) = keys(1);
    let mut b = node_in(&keys, &set, 0, None).await;
    let blocks = hold_chain(&b, 4).await;
    restore_commit(&mut b, &keys, &set, blocks[1].0, 5);
    let mut a = node(1, 0, Some(b.addr.clone())).await;
    let target = peer_of(&b);
    let mut a_events = Vec::new();
    pump(&mut a, &mut b, (false, false), &mut a_events, |a, b, _| {
        !a.svc.transport.connected_peer_ids().is_empty() && !b.svc.transport.connected_peer_ids().is_empty()
    })
    .await;
    a.svc.catch_up =
        Some(CatchUp::new(target, 0, 10));

    a.svc.transport.request_range(target, RangeRequest { start: 1, count: 10, step: 1 });
    pump(&mut a, &mut b, (false, true), &mut a_events, |a, _, _| !a.svc.pending_imports.is_empty()).await;
    let served: Vec<B256> = a.svc.pending_imports[0]
        .2
        .iter()
        .map(|chunk| n42_h2_net::decode_block_rlp_raw(&chunk.rlp, HeaderProfile::Ethereum).unwrap().block_hash)
        .collect();
    assert_eq!(served, vec![blocks[0].0, blocks[1].0], "up to the restored commit, of the four held");
    assert_eq!(b.svc.restored_committed, Some((blocks[1].0, 2)), "the number is kept");

    a.svc.pending_imports.clear();
    a.svc.transport.request_range(target, RangeRequest { start: 3, count: 2, step: 1 });
    pump(&mut a, &mut b, (false, true), &mut a_events, |a, _, _| !a.svc.pending_imports.is_empty()).await;
    assert!(a.svc.pending_imports[0].2.is_empty(), "past the commit: refused");

    // A node connecting now reads the restored commit's height.
    let mut c = node(1, 0, Some(b.addr.clone())).await;
    let mut c_events = Vec::new();
    pump(&mut c, &mut b, (false, false), &mut c_events, |c, _, _| {
        c.svc.pending_status.iter().any(|(peer, _)| *peer == target)
    })
    .await;
    assert!(c.svc.pending_status.contains(&(target, 2)), "{:?}", c.svc.pending_status);
}

/// A restart with no live commit yet: the commit restored from the store
/// is the committed height at start-up -- before any range is asked of
/// the node, a peer connecting reads it as the status height and a range
/// is served up to it -- and the node's own catch-up starts on it and
/// checks the chain it pulls against it: an anchored chain whose block 3
/// names another block 2 than the restored commit halts the importer.
#[tokio::test]
async fn a_restarted_node_takes_its_restored_commit_as_the_committed_height_at_once() {
    let (keys, set) = keys(1);
    let mut b = node_in(&keys, &set, 0, None).await;
    let held = hold_chain(&b, 4).await;
    restore_commit(&mut b, &keys, &set, held[1].0, 5);
    let mut ignored = Vec::new();
    within(b.svc.drain_outputs(&mut ignored)).await.expect("drains");
    assert_eq!(b.svc.committed_height, Some(2), "at start-up, not on the first range request");
    assert_eq!(b.svc.serve_ceiling(), ServeCeiling::Height(2));
    assert_eq!(b.svc.unproven_from, Some(3), "blocks 3 and 4 are not committed");
    assert_eq!(b.svc.certified_head(), Some((2, held[1].0)));

    let target = peer_of(&b);
    let mut c = node(1, 0, Some(b.addr.clone())).await;
    let mut c_events = Vec::new();
    pump(&mut c, &mut b, (false, false), &mut c_events, |c, _, _| {
        c.svc.pending_status.iter().any(|(peer, _)| *peer == target)
    })
    .await;
    assert!(c.svc.pending_status.contains(&(target, 2)), "advertised at once: {:?}", c.svc.pending_status);

    // Its own catch-up: from the restored commit, against it.
    let peer = PeerId::random();
    let theirs = anchored_chain(&b, 6);
    b.svc.sync_lazy_verify = false;
    b.svc.note_peer_height(peer, 6);
    let mut events = Vec::new();
    within(b.svc.consider_catch_up(&mut events)).await;
    let pull = b.svc.catch_up.as_ref().expect("a pull");
    assert_eq!((pull.started_at, pull.next), (2, 3), "the restored commit is the base");
    b.svc.pending_imports.push((peer, RangeRequest { start: 3, count: 4, step: 1 }, chunks(&theirs[2..])));
    import(&mut b).await;
    let halt = b.svc.sync_halt().expect("the pulled chain does not join the restored commit");
    assert_eq!(halt.kind, crate::sync_safety::HaltKind::Conflict);
    assert_eq!((halt.first.hash, halt.first.qc.view), (held[1].0, 5));
    assert_eq!(halt.second.hash, theirs[1].0);
    assert!(executed(&b).iter().all(|h| theirs.iter().all(|t| t.0 != *h)), "none of it executed");
}

// ---------------------------------------------------------------------------
// Fill answers
// ---------------------------------------------------------------------------

/// A compact frame naming `count` transactions, and the transactions.
fn compact_frame(count: usize) -> (B256, alloy_primitives::Bytes, Vec<alloy_primitives::Bytes>) {
    let (hash, header, _) = block(2, B256::repeat_byte(1));
    let txs: Vec<alloy_primitives::Bytes> = (0..count).map(|i| alloy_primitives::Bytes::from(vec![0x02, i as u8, 0xee])).collect();
    let rlp = n42_h2_net::encode_block_rlp_raw(&header, &txs, &[], None);
    let hashes: Vec<B256> = txs.iter().map(keccak256).collect();
    let frame = n42_h2_consensus::encode_compact_body(&rlp, &hashes, HeaderProfile::Ethereum).expect("compact");
    (hash, alloy_primitives::Bytes::from(frame), txs)
}

#[tokio::test]
async fn a_peers_fill_is_merged_into_the_frame_of_record_and_the_block_is_assembled_again() {
    let mut rig = node(1, 0, None).await;
    let (hash, frame, txs) = compact_frame(4);
    let peer = PeerId::random();
    rig.svc.accept_compact_body(frame.clone(), Some(peer)).expect("compact");
    rig.svc.fill_rounds.insert(hash, FillRounds { rounds: 1, wanted_first: 2, wanted_last: 2, ..Default::default() });
    rig.svc.fill_asked.insert(hash, std::time::Instant::now());

    let request = n42_h2_net::BlockTxnsRequest { hash, indices: vec![0, 2] };
    rig.svc
        .handle_transport_event(TransportEvent::BlockTxnsFetched { peer, request, reply: Ok(vec![txs[0].clone(), txs[2].clone()]) })
        .expect("ok");
    let filled = rig.svc.compact_bodies[&hash].clone();
    assert!(filled.len() > frame.len(), "the frame of record now carries the fill");
    for tx in [&txs[0], &txs[2]] {
        assert!(filled.windows(tx.len()).any(|w| w == &tx[..]), "{tx:?} is in the frame");
    }
    assert!(!filled.windows(txs[1].len()).any(|w| w == &txs[1][..]), "a transaction not supplied is not");
    assert_eq!(rig.svc.fill_rounds[&hash].supplied, [0u32, 2].into_iter().collect());
    assert!(!rig.svc.fill_asked.contains_key(&hash), "the wait is over");
    assert!(rig.svc.driver.has_body(&hash), "the driver holds the assembled frame");
    assert!(rig.svc.ready_bodies.contains(&hash), "and its import is queued");

    // The second round's fill is merged with the first's, not applied to the original.
    let request = n42_h2_net::BlockTxnsRequest { hash, indices: vec![3] };
    rig.svc
        .handle_transport_event(TransportEvent::BlockTxnsFetched { peer, request, reply: Ok(vec![txs[3].clone()]) })
        .expect("ok");
    let again = rig.svc.compact_bodies[&hash].clone();
    for tx in [&txs[0], &txs[2], &txs[3]] {
        assert!(again.windows(tx.len()).any(|w| w == &tx[..]), "round two kept round one's fill");
    }
    assert_eq!(rig.svc.fill_rounds[&hash].supplied, [0u32, 2, 3].into_iter().collect());
}

#[tokio::test]
async fn a_fill_that_cannot_be_merged_or_is_miscounted_is_not_trusted() {
    let mut rig = node(1, 0, None).await;
    let (hash, frame, txs) = compact_frame(2);
    let peer = PeerId::random();
    rig.svc.accept_compact_body(frame, Some(peer)).expect("compact");

    // An index beyond the frame's listing cannot be merged: the whole body road.
    rig.svc.fill_rounds.insert(hash, FillRounds::default());
    let request = n42_h2_net::BlockTxnsRequest { hash, indices: vec![9] };
    rig.svc
        .handle_transport_event(TransportEvent::BlockTxnsFetched { peer, request, reply: Ok(vec![txs[0].clone()]) })
        .expect("ok");
    assert!(!rig.svc.compact_bodies.contains_key(&hash), "the compact body is given up");
    assert!(!rig.svc.fill_rounds.contains_key(&hash));
    assert!(rig.svc.awaiting_bodies.contains(&hash), "the whole body is asked for");

    // The wrong number of transactions for the positions asked.
    let (hash, frame, txs) = compact_frame(3);
    let peer = PeerId::random();
    rig.svc.accept_compact_body(frame, None).expect("compact");
    let request = n42_h2_net::BlockTxnsRequest { hash, indices: vec![0, 1] };
    rig.svc
        .handle_transport_event(TransportEvent::BlockTxnsFetched { peer, request, reply: Ok(vec![txs[0].clone()]) })
        .expect("ok");
    assert!(!rig.svc.compact_bodies.contains_key(&hash), "no one else to ask: given up");

    // A refusal with another peer queued asks that peer and keeps the frame.
    let (hash, frame, _) = compact_frame(3);
    rig.svc.compact_bodies.clear();
    rig.svc.body_requested_at.clear();
    rig.svc.accept_compact_body(frame, None).expect("compact");
    let next = PeerId::random();
    rig.svc.fill_peers.insert(hash, vec![next]);
    let request = n42_h2_net::BlockTxnsRequest { hash, indices: vec![1] };
    rig.svc
        .handle_transport_event(TransportEvent::BlockTxnsFetched { peer, request, reply: Err("not held whole".into()) })
        .expect("ok");
    assert!(rig.svc.compact_bodies.contains_key(&hash), "the compact road stays open");
    assert!(rig.svc.fill_peers[&hash].is_empty(), "the next peer was taken");

    // A fill for a frame that is gone is dropped quietly.
    let gone = B256::repeat_byte(0x99);
    let request = n42_h2_net::BlockTxnsRequest { hash: gone, indices: vec![0] };
    rig.svc
        .handle_transport_event(TransportEvent::BlockTxnsFetched { peer, request, reply: Ok(vec![txs[0].clone()]) })
        .expect("ok");
    assert!(!rig.svc.driver.has_body(&gone));
}

// ---------------------------------------------------------------------------
// Two real services over loopback
// ---------------------------------------------------------------------------

/// Pumps both transports, handing every event to its service, until `done`.
/// A service is drained (the loop's own post-event work) when its flag is set.
pub(super) async fn pump(
    a: &mut Rig,
    b: &mut Rig,
    drain: (bool, bool),
    a_events: &mut Vec<ServiceEvent>,
    mut done: impl FnMut(&Rig, &Rig, &[ServiceEvent]) -> bool,
) {
    let mut b_events = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if done(a, b, &a_events[..]) {
                return;
            }
            tokio::select! {
                event = a.svc.transport.next_event() => {
                    let event = event.expect("transport a open");
                    a.seen.push(transport_event_kind(&event));
                    a.svc.handle_transport_event(event).expect("a handles it");
                }
                event = b.svc.transport.next_event() => {
                    let event = event.expect("transport b open");
                    b.seen.push(transport_event_kind(&event));
                    b.svc.handle_transport_event(event).expect("b handles it");
                }
                () = tokio::time::sleep(Duration::from_millis(15)) => {}
            }
            if drain.0 {
                a.svc.drain_outputs(a_events).await.expect("a drains");
            }
            if drain.1 {
                b.svc.drain_outputs(&mut b_events).await.expect("b drains");
            }
        }
    })
    .await;
    assert!(result.is_ok(), "the pump did not reach its condition in time");
}

/// `a` dials `b`; returns once both see each other.
async fn pair(b_height: u64) -> (Rig, Rig) {
    let mut b = node(1, 0, None).await;
    b.svc.transport.set_advertised_height(b_height);
    let mut a = node(1, 0, Some(b.addr.clone())).await;
    let mut ignored = Vec::new();
    pump(&mut a, &mut b, (false, false), &mut ignored, |a, b, _| {
        !a.svc.transport.connected_peer_ids().is_empty() && !b.svc.transport.connected_peer_ids().is_empty()
    })
    .await;
    (a, b)
}

fn peer_of(rig: &Rig) -> PeerId {
    *rig.svc.transport.local_peer_id()
}

#[tokio::test]
async fn a_peer_whose_status_names_another_chain_is_disconnected() {
    let (mut a, mut b) = pair(0).await;
    let peer = peer_of(&b);
    a.svc
        .handle_transport_event(TransportEvent::StatusExchanged {
            peer,
            genesis_hash: B256::repeat_byte(0xEE),
            height: 9,
            fork_matches: false,
        })
        .expect("a handles it");
    assert!(!a.svc.peer_heights.contains_key(&peer), "a height from another chain is not kept");
    assert!(
        !a.svc.pending_status.iter().any(|(p, height)| *p == peer && *height == 9),
        "nor does it start a pull"
    );
    let mut events = Vec::new();
    pump(&mut a, &mut b, (false, false), &mut events, |a, b, _| {
        !a.svc.transport.connected_peer_ids().contains(&peer)
            && b.svc.transport.connected_peer_ids().is_empty()
    })
    .await;
}

#[tokio::test]
async fn a_named_direct_body_pulls_a_parent_missed_before_the_peer_connected() {
    let (mut a, mut b) = pair(0).await;
    let blocks = chain(2);
    for (_, _, body) in &blocks {
        let payload = n42_h2_net::decode_block_rlp_raw(body, HeaderProfile::Ethereum).unwrap().execution_data();
        b.el.new_payload(payload).await.unwrap();
    }
    // The fleet committed both before this node connected: a range serves
    // committed blocks only.
    b.svc.committed_height = Some(2);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (tx, mut rx) = mpsc::channel(4);
    crate::body_channel::listen(addr, tx).await.unwrap();
    let pushers = crate::body_channel::BodyPushers::connect(vec![addr]);
    pushers.announce(peer_of(&b).to_string());
    pushers.push(crate::body_channel::OfferedBody { full: blocks[1].2.clone(), compact: None });
    let received = within(rx.recv()).await.unwrap();
    a.svc.handle_direct_body(received);
    assert_eq!(a.svc.peer_heights[&peer_of(&b)], 2, "direct traffic must refresh the stale connect status");
    let mut events = Vec::new();
    within(a.svc.consider_catch_up(&mut events)).await;
    let pull = a.svc.catch_up.as_ref().unwrap();
    assert_eq!((pull.next, pull.target), (1, 2), "pull includes the absent parent");
    pump(&mut a, &mut b, (true, true), &mut events, |a, _, _| a.svc.driver.head() == blocks[1].0 && a.svc.catch_up.is_none()).await;
    assert!(a.el.block_by_hash(blocks[0].0).await.unwrap().is_some());
}

#[tokio::test]
async fn a_fetched_certified_child_pulls_its_missing_ancestry() {
    let (mut a, mut b) = pair(0).await;
    let blocks = chain(2);
    for (_, _, body) in &blocks {
        b.el.new_payload(n42_h2_net::decode_block_rlp_raw(body, HeaderProfile::Ethereum).unwrap().execution_data()).await.unwrap();
    }
    b.svc.committed_height = Some(2);
    a.svc.handle_transport_event(TransportEvent::BlockFetched {
        peer: peer_of(&b), hash: blocks[1].0, reply: Ok(chunk(&blocks[1].2)),
    }).unwrap();
    assert_eq!(a.svc.peer_heights[&peer_of(&b)], 2);
    let mut events = Vec::new();
    within(a.svc.consider_catch_up(&mut events)).await;
    assert_eq!(a.svc.catch_up.as_ref().unwrap().next, 1);
    pump(&mut a, &mut b, (true, true), &mut events, |a, _, _| a.svc.driver.head() == blocks[1].0 && a.svc.catch_up.is_none()).await;
    assert!(a.el.block_by_hash(blocks[0].0).await.unwrap().is_some());
}

#[tokio::test]
async fn an_unnamed_held_child_fetches_its_parent_without_a_peer_height_hint() {
    let (mut a, mut b) = pair(0).await;
    let blocks = chain(2);
    for (_, _, body) in &blocks {
        b.el.new_payload(n42_h2_net::decode_block_rlp_raw(body, HeaderProfile::Ethereum).unwrap().execution_data()).await.unwrap();
    }
    a.svc.imported_height = Some(0);
    a.svc.handle_direct_body(blocks[1].2.clone().into());
    a.svc.held_bodies.push(blocks[1].0);
    a.svc.peer_heights.clear();
    let mut events = Vec::new();
    within(a.svc.consider_catch_up(&mut events)).await;
    assert!(a.svc.awaiting_bodies.contains(&blocks[0].0), "the parent is requested even without a range target");
    assert!(a.svc.catch_up.is_none());
    assert!(events.iter().any(|event| matches!(event, ServiceEvent::PayloadMissing { block_hash } if *block_hash == blocks[0].0)));
    pump(&mut a, &mut b, (true, true), &mut events, |a, _, _| a.svc.driver.head() == blocks[1].0).await;
    assert!(a.el.block_by_hash(blocks[0].0).await.unwrap().is_some());
}

#[tokio::test]
async fn named_transactions_are_served_from_the_stored_whole_body() {
    let (mut a, mut b) = pair(0).await;
    let (hash, frame, txs) = compact_frame(5);
    // B holds the whole block; A holds only the compact frame and knows B built it.
    let (_, header, _) = block(2, B256::repeat_byte(1));
    let whole = n42_h2_net::encode_block_rlp_raw(&header, &txs, &[], None);
    b.svc.remember_body(hash, alloy_primitives::Bytes::from(whole));
    a.svc.accept_compact_body(frame.clone(), Some(peer_of(&b))).expect("compact");

    let mut events = Vec::new();
    a.svc
        .apply_driver_action(DriverAction::TransactionsMissing { block_hash: hash, indices: vec![0, 3] }, &mut events)
        .expect("ok");
    assert!(a.svc.fill_asked.contains_key(&hash), "the proposer was asked");
    assert_eq!(a.svc.fill_rounds[&hash].rounds, 1);

    let mut a_events = Vec::new();
    pump(&mut a, &mut b, (false, true), &mut a_events, |a, _, _| !a.svc.fill_asked.contains_key(&hash)).await;
    let filled = a.svc.compact_bodies[&hash].clone();
    assert!(filled.len() > frame.len());
    for tx in [&txs[0], &txs[3]] {
        assert!(filled.windows(tx.len()).any(|w| w == &tx[..]), "the served transaction is in the frame");
    }
    assert_eq!(a.svc.fill_rounds[&hash].supplied, [0u32, 3].into_iter().collect());
    assert!(a.svc.ready_bodies.contains(&hash));
}

#[tokio::test]
async fn a_node_holding_the_block_only_as_imported_serves_named_transactions_from_its_execution_layer() {
    let (mut a, mut b) = pair(0).await;
    // The block is in B's execution layer but not in its body store; it has no
    // transactions, so asking for position 0 is refused by name.
    let built = MockExecutionLayer::built_block(1);
    {
        use n42_h2_execution::ExecutionLayer;
        within(b.el.new_payload(built.execution_data.clone())).await.expect("accepted");
    }
    let (_, frame, _) = compact_frame(1);
    let hash = built.hash;
    a.svc.accept_compact_body(frame, Some(peer_of(&b))).expect("compact");
    // The frame is for another block; re-key it so the answer maps to this hash.
    let held = a.svc.compact_bodies.values().next().cloned().expect("a frame");
    a.svc.compact_bodies.clear();
    a.svc.compact_bodies.insert(hash, held);
    a.svc.body_from.insert(hash, peer_of(&b));

    let mut events = Vec::new();
    a.svc
        .apply_driver_action(DriverAction::TransactionsMissing { block_hash: hash, indices: vec![0] }, &mut events)
        .expect("ok");
    let mut a_events = Vec::new();
    pump(&mut a, &mut b, (false, true), &mut a_events, |a, _, _| !a.svc.compact_bodies.contains_key(&hash)).await;
    assert!(a.svc.awaiting_bodies.contains(&hash), "refused: A asks for the whole body instead");
    assert!(!a.svc.fill_rounds.contains_key(&hash));
}

#[tokio::test]
async fn a_block_asked_for_by_hash_is_served_from_the_store_or_the_execution_layer() {
    let (mut a, mut b) = pair(0).await;
    let (stored, _, rlp) = block(6, B256::repeat_byte(4));
    b.svc.remember_body(stored, rlp);
    // Another block lives only in B's execution layer.
    let built = MockExecutionLayer::built_block(1);
    {
        use n42_h2_execution::ExecutionLayer;
        within(b.el.new_payload(built.execution_data.clone())).await.expect("accepted");
    }
    let from_el = built.hash;
    let target = peer_of(&b);
    a.svc.transport.request_block(target, stored);
    a.svc.transport.request_block(target, from_el);

    let mut a_events = Vec::new();
    pump(&mut a, &mut b, (false, true), &mut a_events, |a, _, _| {
        a.svc.received_bodies.contains(&stored) && a.svc.received_bodies.contains(&from_el)
    })
    .await;
    assert!(a.svc.driver.has_payload(&stored));
    assert!(a.svc.driver.has_payload(&from_el));
    assert_eq!(a.svc.block_numbers[&stored], 6);
    assert_eq!(a.svc.block_numbers[&from_el], 1);
}

#[tokio::test]
async fn a_range_is_served_off_the_loop_and_its_slots_are_held_until_the_answer_is_sent() {
    let (mut a, mut b) = pair(0).await;
    let mut parent = B256::ZERO;
    for number in 1..=3 {
        let built = MockExecutionLayer::built_block_on(number, parent);
        parent = built.hash;
        use n42_h2_execution::ExecutionLayer;
        within(b.el.new_payload(built.execution_data)).await.expect("accepted");
    }
    b.svc.committed_height = Some(3);
    let target = peer_of(&b);
    a.svc.transport.request_range(target, RangeRequest { start: 2, count: 10, step: 1 });
    let mut a_events = Vec::new();
    pump(&mut a, &mut b, (false, true), &mut a_events, |a, _, _| !a.svc.pending_imports.is_empty()).await;
    let (peer, request, served) = &a.svc.pending_imports[0];
    assert_eq!(*peer, target);
    assert_eq!((request.start, request.count), (2, 10));
    assert_eq!(served.len(), 2, "blocks 2 and 3");

    // Four requests (one peer's share) to a node that is not draining: the
    // work runs off its loop, and each slot -- with its reply's bytes -- is
    // held until libp2p has sent the answer, not only until the work is done
    // (audit 2026-10 B-4).
    // `a` pulls from `b`, so the refusals of these requests past `b`'s
    // committed height reach its import queue (as empty replies).
    a.svc.pending_imports.clear();
    a.svc.catch_up =
        Some(CatchUp::new(target, 99, 103));
    let before = b.seen.len();
    for start in 100..104 {
        a.svc.transport.request_range(target, RangeRequest { start, count: 1, step: 1 });
    }
    pump(&mut a, &mut b, (false, false), &mut a_events, |_, b, _| b.seen.len() >= before + 4).await;
    assert!(a.svc.pending_imports.is_empty(), "nothing is answered until the loop hands it over");
    assert_eq!(slots_taken(&b.svc.serve_slots), 4, "held while the answers wait");

    // The loop hands the answers over; none was lost or refused, and the
    // slots come back once they are sent.
    pump(&mut a, &mut b, (false, true), &mut a_events, |a, b, _| {
        a.svc.pending_imports.len() == 4 && slots_taken(&b.svc.serve_slots) == 0
    })
    .await;
}

#[tokio::test]
async fn a_fifth_range_request_from_one_peer_is_refused_with_the_server_error_code() {
    let (mut a, mut b) = pair(0).await;
    let mut parent = B256::ZERO;
    for number in 1..=3 {
        let built = MockExecutionLayer::built_block_on(number, parent);
        parent = built.hash;
        use n42_h2_execution::ExecutionLayer;
        within(b.el.new_payload(built.execution_data)).await.expect("accepted");
    }
    b.svc.committed_height = Some(3);
    let target = peer_of(&b);
    // `a` pulls from `b`, so a refusal reaches its import queue (as an empty
    // reply) rather than only a log line.
    a.svc.catch_up =
        Some(CatchUp::new(target, 1, 2));

    // Four of `a`'s requests are in flight at `b` (held here, so the timing
    // of the mock execution layer cannot free them): `a`'s share is full.
    let held: Vec<_> = (0..MAX_SERVES_PER_PEER)
        .map(|_| ServeSlot::take(&b.svc.serve_slots, peer_of(&a)).expect("within the share"))
        .collect();

    // The fifth is refused with the server-error code: no block, although
    // `b` has block 2.
    a.svc.transport.request_range(target, RangeRequest { start: 2, count: 1, step: 1 });
    let mut a_events = Vec::new();
    pump(&mut a, &mut b, (false, true), &mut a_events, |a, _, _| !a.svc.pending_imports.is_empty()).await;
    assert!(a.svc.pending_imports[0].2.is_empty(), "the request past the share is refused");

    // With the share free again the same request is served.
    drop(held);
    a.svc.pending_imports.clear();
    a.svc.transport.request_range(target, RangeRequest { start: 2, count: 1, step: 1 });
    pump(&mut a, &mut b, (false, true), &mut a_events, |a, _, _| !a.svc.pending_imports.is_empty()).await;
    assert_eq!(a.svc.pending_imports[0].2.len(), 1, "block 2");
}

/// Two real services over loopback, one validator set: the member behind
/// pulls the honest peer's anchored chain and executes all of it but the
/// top block, whose anchor no header carries yet.
#[tokio::test]
async fn a_member_behind_its_peer_pulls_the_gap_and_finishes_level() {
    let (keys, set) = keys(1);
    let mut b = node_in(&keys, &set, 0, None).await;
    let b_height = 4u64;
    let blocks = anchored_chain(&b, b_height);
    b.svc.transport.set_advertised_height(b_height);
    {
        use n42_h2_execution::ExecutionLayer;
        for (hash, _, rlp) in &blocks {
            let decoded = n42_h2_net::decode_block_rlp_raw(rlp, HeaderProfile::Ethereum).expect("decodes");
            assert_eq!(decoded.block_hash, *hash);
            within(b.el.new_payload(decoded.execution_data())).await.expect("accepted");
        }
    }
    b.svc.committed_height = Some(b_height);
    let mut a = node_in(&keys, &set, 0, Some(b.addr.clone())).await;
    let mut a_events = Vec::new();
    pump(&mut a, &mut b, (true, true), &mut a_events, |_, _, events| {
        events.iter().any(|e| matches!(e, ServiceEvent::Synced { .. }))
    })
    .await;
    assert!(a_events.contains(&ServiceEvent::Syncing { from: 0, to: 4 }), "{a_events:?}");
    assert!(a_events.contains(&ServiceEvent::Synced { height: 3, complete: true }), "{a_events:?}");
    for (hash, _, _) in &blocks[..3] {
        assert!(a.svc.imported.contains(hash), "block {hash} was pulled");
    }
    assert!(!a.svc.imported.contains(&blocks[3].0), "the top block waits for its anchor");
    assert_eq!(a.svc.driver.head(), blocks[2].0);
    assert!(a.svc.catch_up.is_none());
    assert_eq!(a.svc.failed_peer, None);
}

/// A server holding an anchored chain of `held` blocks, `committed` of them
/// committed and advertised, serving sync v1.1 or not; and a member behind
/// it, asking over v1.1.
async fn behind_a_server(held: u64, committed: u64, serve_v11: bool) -> (Rig, Rig, Vec<(B256, Header, alloy_primitives::Bytes)>) {
    let (keys, set) = keys(1);
    set_sync_v11(true, serve_v11);
    let mut b = node_in(&keys, &set, 0, None).await;
    let blocks = anchored_chain(&b, held);
    {
        use n42_h2_execution::ExecutionLayer;
        for (hash, _, rlp) in &blocks {
            let decoded = n42_h2_net::decode_block_rlp_raw(rlp, HeaderProfile::Ethereum).expect("decodes");
            assert_eq!(decoded.block_hash, *hash);
            within(b.el.new_payload(decoded.execution_data())).await.expect("accepted");
        }
    }
    b.svc.transport.set_advertised_height(committed);
    b.svc.committed_height = Some(committed);
    set_sync_v11(true, true);
    let a = node_in(&keys, &set, 0, Some(b.addr.clone())).await;
    (a, b, blocks)
}

/// Sync v1.1 end to end between two n42-rs services: the member behind
/// pulls the gap over `bodies_by_range/2`, and before the pull ends asks
/// `commit_qc/1` for the block no pulled header anchors (the server's
/// committed head). The server finds the commit QC in its next canonical
/// header, the member verifies it, and the whole gap is executed -- where
/// over `/1` the top block waits for a live commit.
#[tokio::test]
async fn over_sync_v11_a_member_behind_pulls_the_gap_and_its_top_is_anchored_by_commit_qc() {
    let (mut a, mut b, blocks) = behind_a_server(5, 4, true).await;
    let mut a_events = Vec::new();
    pump(&mut a, &mut b, (true, true), &mut a_events, |_, _, events| {
        events.iter().any(|e| matches!(e, ServiceEvent::Synced { .. }))
    })
    .await;
    assert!(a_events.contains(&ServiceEvent::Syncing { from: 0, to: 4 }), "{a_events:?}");
    assert!(a_events.contains(&ServiceEvent::Synced { height: 4, complete: true }), "{a_events:?}");
    for (hash, _, _) in &blocks[..4] {
        assert!(a.svc.imported.contains(hash), "block {hash} was pulled");
    }
    assert!(!a.svc.imported.contains(&blocks[4].0), "nothing above the committed head is served");
    assert_eq!(a.svc.driver.head(), blocks[3].0);
    assert_eq!(a.svc.sync_v11_anchors, 1);
    assert!(b.seen.contains(&"range_v2_request"), "{:?}", b.seen);
    assert!(b.seen.contains(&"commit_qc_request"), "{:?}", b.seen);
    assert!(!b.seen.contains(&"range_request"), "{:?}", b.seen);
    assert!(a.svc.catch_up.is_none());
    assert_eq!(a.svc.failed_peer, None);
}

/// The same gap from a server that speaks only `/1` (gov5's main line,
/// n42-26): the pull falls back to `bodies_by_range/1`, no commit QC is
/// asked, and the top block waits for its anchor as before.
#[tokio::test]
async fn from_a_v1_only_server_the_pull_falls_back_to_bodies_by_range_1() {
    let (mut a, mut b, blocks) = behind_a_server(5, 4, false).await;
    let mut a_events = Vec::new();
    pump(&mut a, &mut b, (true, true), &mut a_events, |_, _, events| {
        events.iter().any(|e| matches!(e, ServiceEvent::Synced { .. }))
    })
    .await;
    assert!(a_events.contains(&ServiceEvent::Synced { height: 3, complete: true }), "{a_events:?}");
    for (hash, _, _) in &blocks[..3] {
        assert!(a.svc.imported.contains(hash), "block {hash} was pulled");
    }
    assert!(!a.svc.imported.contains(&blocks[3].0), "the top block waits for its anchor");
    assert_eq!(a.svc.sync_v11_anchors, 0);
    assert!(b.seen.contains(&"range_request"), "{:?}", b.seen);
    assert!(!b.seen.contains(&"range_v2_request"), "{:?}", b.seen);
    assert!(!b.seen.contains(&"commit_qc_request"), "{:?}", b.seen);
}

/// Mixed 4b-R: the pull's top block has no header after it to anchor it
/// and the server cannot answer `commit_qc/1`, but this node's engine
/// committed that block live before the pull reached it -- heard while the
/// block was not imported, the path that used to return before telling the
/// pull, so the joiner re-pulled the block every retry and left it
/// unexecuted until the next block came (~28 s). That commit anchors the
/// tail, and the whole gap is executed.
#[tokio::test]
async fn a_live_commit_heard_before_the_pull_anchors_its_tail() {
    let (mut a, mut b, blocks) = behind_a_server(5, 4, false).await;
    let mut a_events = Vec::new();
    let tail = blocks[3].0;
    let committed = EngineOutput::BlockCommitted { view: 50, block_hash: tail, commit_qc: own_commit_qc(50, tail), validator_changes: None };
    a.svc.handle_output(committed, &mut a_events).await.expect("handled");
    assert!(!a.svc.imported.contains(&tail), "not imported yet: the early path");
    pump(&mut a, &mut b, (true, true), &mut a_events, |_, _, events| {
        events.iter().any(|e| matches!(e, ServiceEvent::Synced { .. }))
    })
    .await;
    assert!(a_events.contains(&ServiceEvent::Synced { height: 4, complete: true }), "{a_events:?}");
    for (hash, _, _) in &blocks[..4] {
        assert!(a.svc.imported.contains(hash), "block {hash} was pulled and executed");
    }
    assert!(!a.svc.imported.contains(&blocks[4].0), "nothing above the committed head is served");
    assert_eq!(a.svc.sync_v11_anchors, 0, "anchored by the live commit, not commit_qc/1");
}

// ---------------------------------------------------------------------------
// Layout claims of compact frame descriptions (audit 2026-10 R2-X4)
// ---------------------------------------------------------------------------

/// A frame description of one block (the same header every call) under
/// `layout`.
fn frame_description(layout: &[(B256, u32)]) -> (B256, alloy_primitives::Bytes) {
    let (hash, header, _) = block(2, B256::repeat_byte(1));
    let rlp = n42_h2_net::encode_block_rlp_raw(&header, &[], &[], None);
    let frame = n42_h2_consensus::encode_compact_frame_body(&rlp, layout, HeaderProfile::Ethereum).expect("frames");
    (hash, alloy_primitives::Bytes::from(frame))
}

fn layout(k: u8) -> Vec<(B256, u32)> {
    vec![(B256::repeat_byte(0x30 + k), 2), (B256::repeat_byte(0x60 + k), 1)]
}

/// The claims the execution layer was handed, once `want` of them are in
/// (and every task spawned before them has run).
async fn claims_seen(rig: &Rig, want: usize) -> Vec<(B256, Option<n42_h2_execution::raw_engine::ClaimSource>)> {
    let seen = || {
        rig.el
            .calls()
            .into_iter()
            .filter_map(|call| match call {
                ElCall::ClaimLayout(hash, source) => Some((hash, source)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    within(async {
        while seen().len() < want {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    seen()
}

fn source_of(peer: &PeerId) -> Option<n42_h2_execution::raw_engine::ClaimSource> {
    Some(n42_h2_execution::raw_engine::claim_source_of(&peer.to_bytes()))
}

/// A second peer's frame description of a block already taken compact,
/// with another layout, reaches the execution layer as a claim under that
/// peer's source; the block is not imported a second time. One body alone
/// costs nothing: no claim, no bookkeeping.
#[tokio::test]
async fn distinct_frame_layouts_from_two_peers_both_reach_the_execution_layer_with_their_sources() {
    let mut rig = node(1, 0, None).await;
    let (first, second) = (PeerId::random(), PeerId::random());
    let (hash, body) = frame_description(&layout(0));
    let (_, _, fresh) = rig.svc.accept_compact_body(body, Some(first)).expect("first");
    assert!(fresh);
    assert!(rig.svc.compact_claims.is_empty(), "one body: the fast path keeps no claims");
    assert!(claims_seen(&rig, 0).await.is_empty());

    let (_, other) = frame_description(&layout(1));
    let (_, _, fresh) = rig.svc.accept_compact_body(other, Some(second)).expect("second");
    assert!(!fresh, "not imported again");
    assert_eq!(claims_seen(&rig, 1).await, vec![(hash, source_of(&second))]);
    let sources: Vec<_> = rig.svc.compact_claims[&hash].iter().map(|(source, _)| *source).collect();
    assert_eq!(sources, vec![source_of(&first), source_of(&second)], "the frame of record's sender first");
}

/// At most [`CLAIMS_PER_BLOCK`] layouts per block reach the execution
/// layer, one per peer, each distinct: a peer's second layout, a layout
/// already seen and a fifth peer's layout are dropped.
#[tokio::test]
async fn layout_claims_per_block_are_one_per_peer_distinct_and_bounded() {
    let mut rig = node(1, 0, None).await;
    let peers: Vec<PeerId> = (0..6).map(|_| PeerId::random()).collect();
    let (hash, body) = frame_description(&layout(0));
    rig.svc.accept_compact_body(body, Some(peers[0])).expect("first");
    let mut send = |k: u8, peer: PeerId| {
        let (_, body) = frame_description(&layout(k));
        rig.svc.accept_compact_body(body, Some(peer)).expect("compact");
    };
    send(1, peers[1]);
    send(2, peers[1]); // the same peer again: dropped
    send(0, peers[2]); // the frame of record's layout: dropped
    send(2, peers[2]);
    send(3, peers[3]);
    send(4, peers[4]); // a fifth layout: over the bound, dropped
    send(5, peers[5]);
    let mut seen = claims_seen(&rig, CLAIMS_PER_BLOCK - 1).await;
    seen.sort();
    let mut want: Vec<_> = peers[1..4].iter().map(|peer| (hash, source_of(peer))).collect();
    want.sort();
    assert_eq!(seen, want);
    assert_eq!(rig.svc.compact_claims[&hash].len(), CLAIMS_PER_BLOCK);

    // Bounded with the compact bodies: the claims go with the frame.
    rig.svc.forget_compact_body(hash);
    assert!(!rig.svc.compact_claims.contains_key(&hash));
}

#[path = "service_sync_tests.rs"]
mod sync_tests;
