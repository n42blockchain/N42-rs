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
fn chain(count: u64) -> Vec<(B256, Header, alloy_primitives::Bytes)> {
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

fn catching_up(rig: &mut Rig, peer: PeerId, next: u64, target: u64) {
    rig.svc.catch_up =
        Some(CatchUp { peer, next, target, started_at: next - 1, probing: false, probe_height: 0, prev_hash: None });
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

#[tokio::test]
async fn a_range_reply_is_imported_in_order_then_the_pull_probes_past_the_target() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let blocks = chain(3);
    catching_up(&mut rig, peer, 1, 3);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 3, step: 1 }, chunks(&blocks)));
    let events = import(&mut rig).await;

    assert!(events.is_empty(), "the target was reached but the peer may have more");
    for (hash, header, _) in &blocks {
        assert!(rig.svc.imported.contains(hash));
        assert!(rig.svc.body_store.contains_key(hash), "pulled bodies are servable");
        assert_eq!(rig.svc.block_headers[hash].number, header.number);
    }
    assert_eq!(rig.svc.imported_height, Some(3));
    assert_eq!(rig.svc.driver.head(), blocks[2].0, "each import became the head");
    let calls = rig.el.calls();
    let imported: Vec<B256> = calls.iter().filter_map(|c| if let ElCall::NewPayload(h) = c { Some(*h) } else { None }).collect();
    assert_eq!(imported, blocks.iter().map(|b| b.0).collect::<Vec<_>>(), "in block order");
    let catch_up = rig.svc.catch_up.as_ref().expect("still pulling");
    assert!(catch_up.probing);
    assert_eq!((catch_up.next, catch_up.target), (4, 4 + MAX_RANGE_BLOCKS - 1));

    // The probe comes back empty: that was the peer's head.
    rig.svc.pending_imports.push((peer, RangeRequest { start: 4, count: MAX_RANGE_BLOCKS, step: 1 }, Vec::new()));
    let events = import(&mut rig).await;
    assert_eq!(events, vec![ServiceEvent::Synced { height: 3, complete: true }]);
    assert!(rig.svc.catch_up.is_none());
    assert!(rig.svc.catch_up_retry_after.is_some());
    assert_eq!(rig.svc.failed_peer, None, "a complete pull clears the blame");
}

/// Audit 2026-10 round 2 (R2-I2): a peer's status height is not certified,
/// and a peer that serves full windows of blocks it made up keeps a probe
/// going for ever, moving the execution layer's head onto its chain. Past
/// [`MAX_UNPROVEN_PAST_COMMITTED`] blocks above what consensus committed, a
/// pulled block nothing proves ends the pull and the peer is refused for the
/// gap; below it (or with nothing committed yet) the pull runs as before.
#[tokio::test]
async fn a_pull_far_past_the_committed_height_stops_at_the_first_unproven_block() {
    let mut rig = node(1, 0, None).await;
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
    let blocks = chain(PULLED_BLOCKS_PER_STEP as u64 + 8);
    let total = blocks.len() as u64;
    catching_up(&mut rig, peer, 1, total);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: total, step: 1 }, chunks(&blocks)));

    let events = import(&mut rig).await;
    assert!(events.is_empty());
    assert_eq!(rig.svc.imported.len(), PULLED_BLOCKS_PER_STEP, "one step's budget");
    assert_eq!(rig.svc.pending_imports.len(), 1, "the rest waits");
    let (_, rest, remaining) = &rig.svc.pending_imports[0];
    assert_eq!((rest.start, rest.count), (PULLED_BLOCKS_PER_STEP as u64 + 1, 8));
    assert_eq!(remaining.len(), 8);

    let events = import(&mut rig).await;
    assert!(events.is_empty());
    assert_eq!(rig.svc.imported.len() as u64, total);
    assert!(rig.svc.pending_imports.is_empty());
    assert!(rig.svc.catch_up.as_ref().is_some_and(|c| c.probing), "now probing past the target");
}

#[tokio::test]
async fn blocks_gossip_already_imported_are_skipped_not_imported_twice() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let blocks = chain(2);
    rig.svc.remember_imported(blocks[0].0);
    catching_up(&mut rig, peer, 1, 2);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 2, step: 1 }, chunks(&blocks)));
    import(&mut rig).await;
    let imported: Vec<B256> =
        rig.el.calls().iter().filter_map(|c| if let ElCall::NewPayload(h) = c { Some(*h) } else { None }).collect();
    assert_eq!(imported, vec![blocks[1].0], "only the second block went to the execution layer");
    assert!(rig.svc.catch_up.as_ref().is_some_and(|c| c.next == 3), "but the pull moved past both");
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
    catching_up(&mut rig, peer, 1, 3);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 3, step: 1 }, chunks(&blocks)));
    rig.el.set_behaviour(MockBehaviour { new_payload_error: Some("db closed".to_owned()), ..Default::default() });
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 0, complete: false }]);
    assert!(rig.svc.imported.is_empty());
}

/// The committed QC a gov5 leader embeds in a header: `signers` of `keys`
/// sign `signed` under the rig engine's profile, and the certificate names
/// `(view, named)`. A `signed` other than `named` is a forged certificate.
fn header_qc(
    svc: &H2Service<MockExecutionLayer>,
    keys: &[BlsSecretKey],
    signers: &[usize],
    view: u64,
    named: B256,
    signed: B256,
) -> Vec<u8> {
    let profile = svc.engine.signing_profile();
    let message = profile.vote_message(view, signed);
    let signatures: Vec<_> = signers.iter().map(|&i| profile.sign(&keys[i], &message)).collect();
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
    let mut header = built.execution_data.clone().into_block_raw().expect("raw block").header;
    let extra = n42_h2_consensus::HeaderExtra { view, qc, seal: Some([0; n42_h2_consensus::EXTRA_SEAL_LEN]) };
    header.extra_data = extra.encode();
    let rlp = n42_h2_net::encode_block_rlp_raw(&header, &[], &[], None);
    (header.hash_slow(), header, alloy_primitives::Bytes::from(rlp))
}

/// Section 6.6 of `docs/MATURITY_HARDENING_2026_10.md`: a pulled range
/// whose third block carries a forged parent QC. The two blocks before it
/// are imported; it and the one after are not; the peer is refused for the
/// gap and not asked again even when it is the only peer, and another peer
/// is asked instead.
#[tokio::test]
async fn a_pulled_block_with_a_forged_parent_qc_ends_the_batch_and_its_peer_is_not_asked_again() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
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

    assert_eq!(events, vec![ServiceEvent::Synced { height: 2, complete: false }]);
    let imported: Vec<B256> =
        rig.el.calls().iter().filter_map(|c| if let ElCall::NewPayload(h) = c { Some(*h) } else { None }).collect();
    assert_eq!(imported, vec![blocks[0].0, blocks[1].0], "the blocks before the forged QC, and only those");
    assert!(!rig.svc.imported.contains(&blocks[2].0) && !rig.svc.imported.contains(&blocks[3].0));
    assert_eq!(rig.svc.refused_range_peers.get(&peer), Some(&3));
    assert!(rig.svc.catch_up.is_none());

    // The only peer known, still claiming more: not asked again.
    rig.svc.catch_up_retry_after = None;
    rig.svc.note_peer_height(peer, 10);
    let mut events = Vec::new();
    within(rig.svc.consider_catch_up(&mut events)).await;
    assert!(rig.svc.catch_up.is_none(), "the refused peer is not re-asked for the gap");
    assert!(rig.el.calls().iter().all(|c| !matches!(c, ElCall::NewPayload(h) if *h == blocks[2].0)));

    // Another peer is.
    let other = PeerId::random();
    rig.svc.note_peer_height(other, 10);
    within(rig.svc.consider_catch_up(&mut events)).await;
    let catch_up = rig.svc.catch_up.as_ref().expect("a pull from the other peer");
    // From block 2: its QC proves block 1, not block 2 itself (audit 2026-10
    // A-7). Block 2 comes back as held and is skipped.
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
/// member that missed the NewView waited out its own timeouts instead. A TC
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
    let mut blocks: Vec<(B256, Header, alloy_primitives::Bytes)> = Vec::new();
    let mut parent = B256::ZERO;
    for number in 1..=(PULLED_BLOCKS_PER_STEP as u64 * 6) {
        let block = block_with_extra(number, parent, number, Vec::new());
        parent = block.0;
        blocks.push(block);
    }
    let count = blocks.len() as u64;
    catching_up(&mut rig, peer, 1, count);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count, step: 1 }, chunks(&blocks)));
    rig.svc.engine.halt_voting("vote_log");
    let err = within(rig.svc.step()).await.expect_err("the fault ends the step");
    assert!(matches!(err, ServiceError::Fatal { reason: "vote_log", .. }), "{err:?}");
    assert!(!rig.svc.pending_imports.is_empty(), "the step took the fast path");
}

/// Audit 2026-10 A-7: a header QC proves the block it names and the chain
/// below it, not the block that carries it. A range server that copies one
/// real QC into blocks it made up above the certified one gets them past the
/// header check (gov5 accepts them too); they stay unproven for catch-up, and
/// a pulled block is never committed, safe or finalized -- the one defence
/// against such a chain is that only a commit settles a block.
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

    assert!(blocks.iter().all(|(hash, ..)| rig.svc.imported.contains(hash)), "every block passes the header check");
    assert_eq!(rig.svc.unproven_from, Some(3), "only blocks 1 and 2 are certified");
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
    rig.svc.catch_up = Some(CatchUp {
        peer: PeerId::random(),
        next: 2,
        target: 4,
        started_at: 0,
        probing: false,
        probe_height: 0,
        prev_hash: Some(B256::repeat_byte(0x01)),
    });
    assert!(rig.svc.check_pulled_block(&header).is_err(), "a block that does not extend the last one");
}

/// Audit 2026-10 B-1: a range server that answers a node behind it with a
/// chain whose headers carry no certificate it can check (here none at all)
/// gets that chain imported on its parent links alone, and the execution
/// layer's head moves to it. That head must not then stand for "caught up":
/// an honest peer at the same height still has to be pulled from, or the
/// node never leaves the forged chain -- a restart reads the same head.
#[tokio::test]
async fn an_uncertified_pulled_chain_does_not_stop_a_pull_from_an_honest_peer() {
    let mut rig = node(1, 0, None).await;
    let forger = PeerId::random();
    let forged = chain(4);
    catching_up(&mut rig, forger, 1, 4);
    rig.svc.pending_imports.push((forger, RangeRequest { start: 1, count: 4, step: 1 }, chunks(&forged)));
    import(&mut rig).await;
    assert!(
        rig.el.calls().iter().any(|c| matches!(c, ElCall::NewPayload(h) if *h == forged[3].0)),
        "the uncertified chain reached the execution layer"
    );

    let honest = PeerId::random();
    rig.svc.catch_up = None;
    rig.svc.catch_up_retry_after = None;
    rig.svc.peer_heights.remove(&forger);
    rig.svc.note_peer_height(honest, 4);
    let mut events = Vec::new();
    within(rig.svc.consider_catch_up(&mut events)).await;
    let catch_up = rig.svc.catch_up.as_ref().expect("the honest peer is pulled from");
    assert_eq!(catch_up.peer, honest);
}

/// A block that does not extend the one pulled before it is refused before
/// the execution layer sees it, whatever its certificate says.
#[tokio::test]
async fn a_pulled_block_that_does_not_extend_the_previous_one_is_refused() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let first = block(1, B256::ZERO);
    let stray = block(2, B256::repeat_byte(0x09));
    catching_up(&mut rig, peer, 1, 2);
    rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 2, step: 1 }, chunks(&[first.clone(), stray])));
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 1, complete: false }]);
    assert!(rig.svc.imported.contains(&first.0));
    assert_eq!(rig.svc.imported.len(), 1);
    assert_eq!(rig.svc.refused_range_peers.get(&peer), Some(&2));
}

#[tokio::test]
async fn a_short_probe_reply_ends_the_pull_only_at_the_height_the_probe_began_at() {
    for (probe_height, ends) in [(2u64, true), (5, false)] {
        let mut rig = node(1, 0, None).await;
        let peer = PeerId::random();
        let blocks = chain(2);
        rig.svc.catch_up =
            Some(CatchUp { peer, next: 1, target: 1024, started_at: 0, probing: true, probe_height, prev_hash: None });
        rig.svc.pending_imports.push((peer, RangeRequest { start: 1, count: 1024, step: 1 }, chunks(&blocks)));
        let events = import(&mut rig).await;
        if ends {
            assert_eq!(events, vec![ServiceEvent::Synced { height: 2, complete: true }]);
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
    rig.svc.catch_up = Some(CatchUp { peer, next: 11, target: 1034, started_at: 4, probing: true, probe_height: 0, prev_hash: None });
    rig.svc.pending_imports.push((peer, RangeRequest { start: 11, count: 1024, step: 1 }, Vec::new()));
    assert_eq!(import(&mut rig).await, vec![ServiceEvent::Synced { height: 10, complete: true }]);
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
    let (mut a, b) = pair(0).await;
    let blocks = chain(2);
    for (_, _, body) in &blocks {
        let payload = n42_h2_net::decode_block_rlp_raw(body, HeaderProfile::Ethereum).unwrap().execution_data();
        b.el.new_payload(payload).await.unwrap();
    }
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
    let mut b = b;
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
    a.svc.pending_imports.clear();
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
    let target = peer_of(&b);
    // `a` pulls from `b`, so a refusal reaches its import queue (as an empty
    // reply) rather than only a log line.
    a.svc.catch_up =
        Some(CatchUp { peer: target, next: 2, target: 2, started_at: 1, probing: false, probe_height: 0, prev_hash: None });

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

#[tokio::test]
async fn a_member_behind_its_peer_pulls_the_gap_and_finishes_level() {
    let (b_height, blocks) = (3u64, chain(3));
    let mut b = node(1, 0, None).await;
    b.svc.transport.set_advertised_height(b_height);
    {
        use n42_h2_execution::ExecutionLayer;
        for (hash, _, rlp) in &blocks {
            let decoded = n42_h2_net::decode_block_rlp_raw(rlp, HeaderProfile::Ethereum).expect("decodes");
            assert_eq!(decoded.block_hash, *hash);
            within(b.el.new_payload(decoded.execution_data())).await.expect("accepted");
        }
    }
    let mut a = node(1, 0, Some(b.addr.clone())).await;
    let mut a_events = Vec::new();
    pump(&mut a, &mut b, (true, true), &mut a_events, |_, _, events| {
        events.iter().any(|e| matches!(e, ServiceEvent::Synced { .. }))
    })
    .await;
    assert!(a_events.contains(&ServiceEvent::Syncing { from: 0, to: 3 }), "{a_events:?}");
    assert!(a_events.contains(&ServiceEvent::Synced { height: 3, complete: true }), "{a_events:?}");
    for (hash, _, _) in &blocks {
        assert!(a.svc.imported.contains(hash), "block {hash} was pulled");
    }
    assert_eq!(a.svc.driver.head(), blocks[2].0);
    assert!(a.svc.catch_up.is_none());
    assert_eq!(a.svc.failed_peer, None);
}
