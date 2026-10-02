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
    rig.svc.catch_up = Some(CatchUp { peer, next, target, started_at: next - 1, probing: false });
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
    assert_eq!((catch_up.peer, catch_up.target), (short, 20));

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

#[tokio::test]
async fn an_empty_probe_ends_a_pull_that_already_made_progress() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    rig.svc.catch_up = Some(CatchUp { peer, next: 11, target: 1034, started_at: 4, probing: true });
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
    let hashes: Vec<B256> = txs.iter().map(|tx| keccak256(tx)).collect();
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
async fn a_range_is_served_from_the_execution_layer_and_an_overfull_queue_is_refused() {
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

    // Nine requests at once to a node that is not draining: eight wait, the
    // ninth is refused with an empty answer.
    a.svc.pending_imports.clear();
    for start in 100..109 {
        a.svc.transport.request_range(target, RangeRequest { start, count: 1, step: 1 });
    }
    pump(&mut a, &mut b, (false, false), &mut a_events, |a, b, _| {
        b.svc.pending_ranges.len() == MAX_PENDING_RANGES && !a.svc.pending_imports.is_empty()
    })
    .await;
    assert_eq!(b.svc.pending_ranges.len(), MAX_PENDING_RANGES);
    assert!(a.svc.pending_imports[0].2.is_empty(), "the refused request is answered empty");
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
