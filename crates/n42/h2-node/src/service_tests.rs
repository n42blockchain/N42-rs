// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unit tests for the service loop's private bookkeeping.
//!
//! Each test builds one real [`H2Service`] (a libp2p transport listening on
//! `127.0.0.1:0`, a real consensus engine, the mock execution layer) and calls
//! the loop's private steps directly with synthetic transport events, so what
//! is asserted is the state the step leaves behind and the calls it makes on
//! the execution layer, not that a function ran. Nothing here waits on the
//! network without a bound.

use super::*;
use alloy_primitives::Address;
use n42_h2_consensus::{ValidatorInfo, ValidatorSet};
use n42_h2_execution::{ElCall, MockBehaviour, MockExecutionLayer};
use n42_h2_net::{BlockChunk, TransportConfig};
use n42_h2_primitives::bls::BlsSecretKey;

const ID: H2V4ChainIdentity = H2V4ChainIdentity { chain_id: 96, genesis_hash: B256::repeat_byte(0x42) };

/// Everything a test needs around one service.
struct Rig {
    svc: H2Service<MockExecutionLayer>,
    el: MockExecutionLayer,
    addr: libp2p::Multiaddr,
    /// The kind of every transport event a pump handed to the service.
    seen: Vec<&'static str>,
}

fn keys(count: usize) -> (Vec<BlsSecretKey>, ValidatorSet) {
    let keys: Vec<BlsSecretKey> = (0..count).map(|_| BlsSecretKey::random().expect("bls keygen")).collect();
    let infos: Vec<ValidatorInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| ValidatorInfo {
            address: Address::with_last_byte(i as u8 + 1),
            bls_public_key: key.public_key(),
            p2p_peer_id: None,
        })
        .collect();
    let faults = u32::from(count >= 4);
    (keys, ValidatorSet::new(&infos, faults))
}

/// One member of `count` validators, optionally dialing `dial`.
async fn node(count: usize, index: usize, dial: Option<libp2p::Multiaddr>) -> Rig {
    let (keys, set) = keys(count);
    node_in(&keys, &set, index, dial).await
}

async fn node_in(keys: &[BlsSecretKey], set: &ValidatorSet, index: usize, dial: Option<libp2p::Multiaddr>) -> Rig {
    let mut config = TransportConfig::new(ID).with_listen_addr("/ip4/127.0.0.1/tcp/0".parse().expect("addr"));
    if let Some(addr) = dial {
        config = config.with_peer(addr);
    }
    let mut transport = H2V4Transport::new(config).expect("transport");
    let listen = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match transport.next_event().await {
                Some(TransportEvent::Listening(addr)) => return addr,
                Some(_) => {}
                None => panic!("transport ended before listening"),
            }
        }
    })
    .await
    .expect("the transport starts listening");
    let addr = listen.with(libp2p::multiaddr::Protocol::P2p(*transport.local_peer_id()));
    let (tx, rx) = mpsc::channel::<EngineOutput>(256);
    let mut engine =
        ConsensusEngine::new(index as u32, keys[index].clone(), set.clone(), 1_000, 4_000, tx);
    engine.enable_h2_v4_signing(ID);
    let el = MockExecutionLayer::new();
    let driver = ExecutionDriver::new(el.clone(), ID.genesis_hash);
    let svc = H2Service::new(transport, engine, driver, rx, keys.len());
    Rig { svc, el, addr, seen: Vec::new() }
}

/// A block of the mock's shape and the gov5 RLP it travels as.
fn block(number: u64, parent: B256) -> (B256, Header, alloy_primitives::Bytes) {
    let built = MockExecutionLayer::built_block_on(number, parent);
    let header = built.execution_data.clone().into_block_raw().expect("raw block").header;
    let rlp = n42_h2_net::encode_block_rlp_raw(&header, &[], &[], None);
    (header.hash_slow(), header, alloy_primitives::Bytes::from(rlp))
}

fn chunk(rlp: &alloy_primitives::Bytes) -> BlockChunk {
    BlockChunk { fork_digest: [0; 4], rlp: rlp.clone() }
}

async fn within<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(30), f).await.expect("timed out")
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

#[test]
fn the_loop_spend_window_sums_per_kind_and_only_reports_slow_views() {
    let mut spend = LoopSpend::default();
    // Nothing is recorded before a commit opened a window.
    spend.note("body_in", std::time::Instant::now());
    assert!(spend.spent.is_empty());

    spend.open(3);
    spend.note("body_in", std::time::Instant::now());
    spend.note("body_in", std::time::Instant::now());
    spend.note("range", std::time::Instant::now());
    assert_eq!(spend.spent.len(), 2, "one entry per kind");
    assert_eq!(spend.spent[0].0, "body_in");
    assert_eq!(spend.spent[0].1, 2, "two body_in notes are counted together");
    assert_eq!((spend.spent[1].0, spend.spent[1].1), ("range", 1));
    // A window that closed at once is not worth a line.
    assert!(spend.close(4).is_none());
    assert!(spend.since.is_none(), "closing consumes the window");
    spend.spent.clear();

    // A slow window for the next view is reported, with what it holds.
    let long_ago = std::time::Instant::now().checked_sub(Duration::from_millis(80)).expect("clock");
    spend.since = Some((7, long_ago));
    spend.spent.push(("tx_gossip", 5, 1234));
    let (gap_us, parts) = spend.close(8).expect("an 80 ms window is reported");
    assert!(gap_us >= 80_000);
    assert_eq!(parts, vec![("tx_gossip", 5, 1234)]);
    assert!(spend.spent.is_empty(), "the parts are handed over");

    // A window that belongs to another view is dropped without a report.
    spend.since = Some((7, long_ago));
    assert!(spend.close(9).is_none());
    assert!(spend.since.is_none());
}

#[test]
fn a_fill_is_the_named_transactions_of_a_body_and_names_a_missing_index() {
    let (_, header, _) = block(1, B256::ZERO);
    let txs = vec![
        alloy_primitives::Bytes::from_static(&[0x01, 0xaa]),
        alloy_primitives::Bytes::from_static(&[0x02, 0xbb, 0xcc]),
        alloy_primitives::Bytes::from_static(&[0x03]),
    ];
    let body = n42_h2_net::encode_block_rlp_raw(&header, &txs, &[], None);
    let hash = header.hash_slow();

    let request = n42_h2_net::BlockTxnsRequest { hash, indices: vec![2, 0] };
    let fill = fill_from_body(&body, HeaderProfile::Ethereum, &request).expect("both positions exist");
    assert_eq!(fill, vec![txs[2].clone(), txs[0].clone()], "answered in the order asked");

    let request = n42_h2_net::BlockTxnsRequest { hash, indices: vec![1, 3] };
    let err = fill_from_body(&body, HeaderProfile::Ethereum, &request).expect_err("index 3 is past the end");
    assert_eq!(err, format!("block {hash} has no index 3"));

    let err = fill_from_body(&[0xde, 0xad], HeaderProfile::Ethereum, &request).expect_err("not a body");
    assert!(!err.is_empty(), "an unreadable body is refused with the decoder's reason");
}

#[tokio::test]
async fn a_range_is_served_from_the_start_until_the_first_missing_block() {
    let el = MockExecutionLayer::new();
    // Blocks 1..=3 are in the execution layer; 4 is not.
    let mut parent = B256::ZERO;
    for number in 1..=3 {
        let built = MockExecutionLayer::built_block_on(number, parent);
        parent = built.hash;
        use n42_h2_execution::ExecutionLayer;
        within(el.new_payload(built.execution_data)).await.expect("accepted");
    }
    let served = within(serve_range(&el, n42_h2_net::RangeRequest { start: 2, count: 10, step: 1 })).await;
    assert_eq!(served.len(), 2, "blocks 2 and 3, then block 4 is missing");
    for (rlp, number) in served.iter().zip([2u64, 3]) {
        let (_, header) = n42_h2_consensus::decode_block_body_header(rlp, HeaderProfile::Ethereum).expect("a body");
        assert_eq!(header.number, number);
    }
    let none = within(serve_range(&el, n42_h2_net::RangeRequest { start: 50, count: 5, step: 1 })).await;
    assert!(none.is_empty(), "nothing past the head");
    let capped = within(serve_range(&el, n42_h2_net::RangeRequest { start: 1, count: 1, step: 1 })).await;
    assert_eq!(capped.len(), 1, "count bounds the answer");
}

#[test]
fn transport_event_kinds_name_what_the_loop_logs() {
    assert_eq!(transport_event_kind(&TransportEvent::Rejected { from: None, reason: "x".into() }), "rejected");
    assert_eq!(transport_event_kind(&TransportEvent::Transactions { from: None, data: Vec::new() }), "transactions");
    assert_eq!(transport_event_kind(&TransportEvent::Block { from: None, data: Vec::new() }), "block");
    assert_eq!(transport_event_kind(&TransportEvent::Subscribed), "other");
}

// ---------------------------------------------------------------------------
// Builders and configuration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_pacing_sizes_the_re_ask_and_zero_turns_it_off() {
    let mut rig = node(1, 0, None).await;
    assert_eq!(rig.svc.propose_retry, PROPOSE_RETRY, "unconfigured: the default re-ask");

    rig.svc = rig.svc.with_block_pacing(Duration::from_millis(3_200));
    assert_eq!(rig.svc.propose_retry, Duration::from_millis(100), "a thirty-second of the pacing");
    assert_eq!(rig.svc.block_pacing, Some(Duration::from_millis(3_200)));

    rig.svc = rig.svc.with_block_pacing(Duration::from_secs(60));
    assert_eq!(rig.svc.propose_retry, PROPOSE_RETRY, "capped at the default");

    rig.svc = rig.svc.with_block_pacing(Duration::from_millis(100));
    assert_eq!(rig.svc.propose_retry, PROPOSE_RETRY_FLOOR, "a short pacing hits the floor");

    rig.svc = rig.svc.with_block_pacing(Duration::ZERO);
    assert_eq!(rig.svc.block_pacing, None, "a zero pacing is no pacing");
}

#[tokio::test]
async fn the_straggler_grace_is_off_at_zero_and_arms_progress_votes_otherwise() {
    let mut rig = node(1, 0, None).await;
    rig.svc = rig.svc.with_straggler_grace(Duration::ZERO);
    assert_eq!(rig.svc.straggler_grace, None);
    rig.svc = rig.svc.with_straggler_grace(Duration::from_millis(600));
    assert_eq!(rig.svc.straggler_grace, Some(Duration::from_millis(600)));
}

#[tokio::test]
async fn the_gov5_profile_switches_the_wire_and_keeps_the_seal_key() {
    let rig = node(1, 0, None).await;
    assert_eq!(rig.svc.header_profile, HeaderProfile::Ethereum);
    assert!(!rig.svc.native_wire);
    assert!(rig.svc.chain_seal_key.is_none());
    let svc = rig.svc.with_gov5_h2_profile(BlsSecretKey::random().expect("key"));
    assert_eq!(svc.header_profile, HeaderProfile::Gov5H2);
    assert!(svc.native_wire, "gov5 members read consensus on the native topic");
    assert!(svc.chain_seal_key.is_some(), "the build chain seals with this key");

    let rig = node(1, 0, None).await;
    let svc = rig.svc.with_header_profile(HeaderProfile::Gov5H2).with_direct_block_push(true).with_build_ahead(true);
    assert_eq!(svc.header_profile, HeaderProfile::Gov5H2);
    assert!(!svc.native_wire, "the profile alone does not change the topic");
    assert!(svc.direct_push);
    assert!(svc.prepare_ahead);
}

#[tokio::test]
async fn a_service_describes_itself_for_logs() {
    let rig = node(1, 0, None).await;
    let text = format!("{:?}", rig.svc);
    assert!(text.contains("H2Service"));
    assert!(text.contains("validator_count: 1"));
    assert!(text.contains("proposes: false"), "no builder was given");
    assert!(rig.svc.time_to_timeout() <= Duration::from_millis(1_000), "the view clock is the pacemaker's");
    assert!(rig.svc.time_to_timeout() > Duration::ZERO);
}

#[tokio::test]
async fn the_pacing_tick_is_the_head_seen_plus_the_pacing() {
    let mut rig = node(1, 0, None).await;
    let head = B256::repeat_byte(9);
    assert_eq!(rig.svc.pacing_tick(&head), None, "no pacing is configured");
    rig.svc = rig.svc.with_block_pacing(Duration::from_millis(400));
    assert_eq!(rig.svc.pacing_tick(&head), None, "the head has not been seen");
    let seen = std::time::Instant::now();
    rig.svc.block_seen.insert(head, seen);
    assert_eq!(rig.svc.pacing_tick(&head), Some(seen + Duration::from_millis(400)));
}

#[tokio::test]
async fn a_deferred_proposal_waits_for_the_tick_only_when_the_builder_declined_this_view() {
    let mut rig = node(1, 0, None).await;
    rig.svc = rig.svc.with_block_pacing(Duration::from_secs(30));
    let head = rig.svc.driver.head();
    let view = rig.svc.engine().current_view();
    rig.svc.block_seen.insert(head, std::time::Instant::now());
    assert!(rig.svc.deferred_pacing_tick().is_none(), "nothing is deferred");

    rig.svc.proposal_deferred = true;
    rig.svc.declined_view = Some(view);
    rig.svc.defer_reason = Some("the attribute builder declined");
    let tick = rig.svc.deferred_pacing_tick().expect("a tick 30 s ahead");
    assert!(tick > tokio::time::Instant::now() + Duration::from_secs(25));

    rig.svc.declined_view = Some(view + 1);
    assert!(rig.svc.deferred_pacing_tick().is_none(), "a decline for another view");
    rig.svc.declined_view = Some(view);
    rig.svc.defer_reason = Some("the parent is still importing");
    assert!(rig.svc.deferred_pacing_tick().is_none(), "another reason is not a pacing wait");
    rig.svc.defer_reason = Some("the attribute builder declined");
    rig.svc.block_seen.insert(head, std::time::Instant::now().checked_sub(Duration::from_secs(60)).expect("clock"));
    assert!(rig.svc.deferred_pacing_tick().is_none(), "a tick already in the past is not waited for");
}

// ---------------------------------------------------------------------------
// Per-block bookkeeping and its bounds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_body_request_is_rate_limited_per_block_and_the_memory_is_bounded() {
    let mut rig = node(1, 0, None).await;
    let hash = B256::repeat_byte(1);
    assert!(rig.svc.body_request_due(hash), "the first ask goes out");
    assert!(!rig.svc.body_request_due(hash), "the second, at once, does not");
    rig.svc.body_requested_at.insert(hash, std::time::Instant::now().checked_sub(BODY_REQUEST_INTERVAL).expect("clock"));
    assert!(rig.svc.body_request_due(hash), "after the interval it may be asked again");
    assert_eq!(rig.svc.body_requested_order.len(), 1, "a re-ask is not a new entry");

    for i in 0..(MAX_BODY_REQUEST_TIMES as u64 + 10) {
        rig.svc.body_request_due(B256::left_padding_from(&(i + 100).to_be_bytes()));
    }
    assert_eq!(rig.svc.body_requested_order.len(), MAX_BODY_REQUEST_TIMES);
    assert_eq!(rig.svc.body_requested_at.len(), MAX_BODY_REQUEST_TIMES, "the oldest are forgotten");
    assert!(!rig.svc.body_requested_at.contains_key(&hash), "the first hash was the first out");
}

#[tokio::test]
async fn the_body_store_keeps_the_most_recent_bodies_only() {
    let mut rig = node(1, 0, None).await;
    let limit = remembered_bodies();
    let hashes: Vec<B256> = (0..limit as u64 + 3).map(|i| B256::left_padding_from(&(i + 1).to_be_bytes())).collect();
    for hash in &hashes {
        rig.svc.remember_body(*hash, alloy_primitives::Bytes::from_static(b"body"));
    }
    assert_eq!(rig.svc.body_store.len(), limit);
    assert_eq!(rig.svc.body_store_order.len(), limit);
    for gone in &hashes[..3] {
        assert!(!rig.svc.body_store.contains_key(gone), "the oldest three went");
    }
    assert!(rig.svc.body_store.contains_key(hashes.last().expect("some")));
    // Storing the same block again neither grows the store nor reorders it.
    rig.svc.remember_body(hashes[5], alloy_primitives::Bytes::from_static(b"again"));
    assert_eq!(rig.svc.body_store_order.len(), limit);
}

#[tokio::test]
async fn remembered_blocks_are_bounded_and_carry_their_number_and_stamp() {
    let mut rig = node(1, 0, None).await;
    let (hash, header, _) = block(7, B256::repeat_byte(3));
    rig.svc.remember_block(hash, &header);
    assert_eq!(rig.svc.block_numbers.get(&hash), Some(&7));
    assert_eq!(rig.svc.block_timestamps.get(&hash), Some(&header.timestamp));
    assert_eq!(rig.svc.block_headers.get(&hash), Some(&header));
    assert!(rig.svc.block_seen.contains_key(&hash));
    let first_seen = rig.svc.block_seen[&hash];
    rig.svc.remember_block(hash, &header);
    assert_eq!(rig.svc.timestamp_order.len(), 1, "a block seen twice is one entry");
    assert_eq!(rig.svc.block_seen[&hash], first_seen, "and keeps its first arrival");

    for i in 0..REMEMBERED_TIMESTAMPS as u64 {
        let h = Header { number: 100 + i, ..Default::default() };
        rig.svc.remember_block(B256::left_padding_from(&(i + 1000).to_be_bytes()), &h);
    }
    assert_eq!(rig.svc.timestamp_order.len(), REMEMBERED_TIMESTAMPS);
    assert!(!rig.svc.block_headers.contains_key(&hash), "the first block was pushed out of every map");
    assert!(!rig.svc.block_numbers.contains_key(&hash));
    assert!(!rig.svc.block_seen.contains_key(&hash));
    assert!(!rig.svc.block_timestamps.contains_key(&hash));
}

#[tokio::test]
async fn imported_blocks_are_remembered_to_a_bound_and_heights_only_move_forward() {
    let mut rig = node(1, 0, None).await;
    let first = B256::repeat_byte(0xaa);
    rig.svc.remember_imported(first);
    rig.svc.remember_imported(first);
    assert_eq!(rig.svc.imported_order.len(), 1, "a hash twice is one entry");
    for i in 0..MAX_IMPORTED as u64 {
        rig.svc.remember_imported(B256::left_padding_from(&(i + 1).to_be_bytes()));
    }
    assert_eq!(rig.svc.imported.len(), MAX_IMPORTED);
    assert!(!rig.svc.imported.contains(&first), "the oldest import is forgotten");

    assert_eq!(rig.svc.imported_height, None);
    rig.svc.note_imported(10);
    rig.svc.note_imported(7);
    assert_eq!(rig.svc.imported_height, Some(10), "a lower height does not move the tip back");
    rig.svc.note_imported(11);
    assert_eq!(rig.svc.imported_height, Some(11));

    let peer = PeerId::random();
    rig.svc.note_peer_height(peer, 5);
    rig.svc.note_peer_height(peer, 3);
    assert_eq!(rig.svc.peer_heights[&peer], 5);
    rig.svc.note_peer_height(peer, 9);
    assert_eq!(rig.svc.peer_heights[&peer], 9);
}

#[tokio::test]
async fn far_ahead_is_judged_by_the_known_parent_then_by_height() {
    let mut rig = node(1, 0, None).await;
    let (parent_hash, parent, _) = block(5, B256::ZERO);
    let (child_hash, child, _) = block(7, parent_hash);
    // No header, or no tip: not far.
    assert!(!rig.svc.far_ahead(child_hash));
    rig.svc.remember_block(child_hash, &child);
    assert!(!rig.svc.far_ahead(child_hash), "no tip is known");
    rig.svc.note_imported(parent.number);
    assert!(rig.svc.far_ahead(child_hash), "7 is two past a tip of 5");
    // An imported parent overrides the height rule.
    rig.svc.remember_imported(parent_hash);
    assert!(!rig.svc.far_ahead(child_hash), "its parent is imported: it can be executed here");
}

#[tokio::test]
async fn a_held_block_is_logged_once_then_released_when_the_tip_catches_up() {
    let mut rig = node(1, 0, None).await;
    let (_, parent, _) = block(5, B256::ZERO);
    let (hash, child, _) = block(8, B256::repeat_byte(5));
    rig.svc.remember_block(hash, &child);
    rig.svc.note_imported(parent.number);

    let mut events = Vec::new();
    within(rig.svc.handle_output(EngineOutput::ExecuteBlock(hash), &mut events)).await.expect("held, not an error");
    assert_eq!(rig.svc.held_bodies, vec![hash], "the far-ahead block is held");
    assert!(rig.svc.held_since.contains_key(&hash));
    assert!(rig.svc.last_held_log.is_some(), "the first hold is announced");
    assert!(rig.el.calls().is_empty(), "nothing reached the execution layer");

    // Held a second time: still one entry.
    within(rig.svc.handle_output(EngineOutput::ExecuteBlock(hash), &mut events)).await.expect("ok");
    assert_eq!(rig.svc.held_bodies, vec![hash]);

    // Held "too long": exactly one warning is recorded for the block.
    rig.svc.held_since.insert(hash, std::time::Instant::now().checked_sub(HELD_TOO_LONG * 2).expect("clock"));
    rig.svc.say_held(hash);
    assert!(rig.svc.held_warned.contains(&hash));
    let warned_at = rig.svc.last_held_warn;
    rig.svc.say_held(hash);
    assert_eq!(rig.svc.last_held_warn, warned_at, "the warning is not repeated");

    // The tip catches up: the next drain releases it to the execution path.
    rig.svc.note_imported(7);
    within(rig.svc.drain_outputs(&mut events)).await.expect("drain");
    assert!(rig.svc.held_bodies.is_empty(), "released");
    assert!(!rig.svc.held_since.contains_key(&hash));
    assert!(!rig.svc.held_warned.contains(&hash));
}

#[tokio::test]
async fn the_held_list_is_bounded_and_drops_the_oldest() {
    let mut rig = node(1, 0, None).await;
    let (_, parent, _) = block(2, B256::ZERO);
    rig.svc.note_imported(parent.number);
    let mut hashes = Vec::new();
    for i in 0..(MAX_HELD_BODIES as u64 + 2) {
        let header = Header { number: 500 + i, parent_hash: B256::repeat_byte(1), ..Default::default() };
        let hash = B256::left_padding_from(&(i + 1).to_be_bytes());
        rig.svc.remember_block(hash, &header);
        hashes.push(hash);
        if hashes.len() > REMEMBERED_TIMESTAMPS {
            // Keep the header of every block this test holds.
            rig.svc.block_headers.insert(hash, header);
        }
    }
    // The bound on remembered headers dropped the early ones; give them back.
    for (i, hash) in hashes.iter().enumerate() {
        let header = Header { number: 500 + i as u64, parent_hash: B256::repeat_byte(1), ..Default::default() };
        rig.svc.block_headers.insert(*hash, header);
    }
    let mut events = Vec::new();
    for hash in &hashes {
        within(rig.svc.handle_output(EngineOutput::ExecuteBlock(*hash), &mut events)).await.expect("held");
    }
    assert_eq!(rig.svc.held_bodies.len(), MAX_HELD_BODIES);
    assert!(!rig.svc.held_bodies.contains(&hashes[0]), "the oldest was dropped to make room");
    assert!(!rig.svc.held_since.contains_key(&hashes[0]));
    assert!(rig.svc.held_bodies.contains(hashes.last().expect("some")));
}

// ---------------------------------------------------------------------------
// Bodies: whole, header-only and compact
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_body_taken_once_is_idempotent_and_handed_to_the_driver_as_bytes() {
    let mut rig = node(1, 0, None).await;
    let (hash, header, rlp) = block(4, B256::repeat_byte(2));
    let (got, got_header, fresh) = rig.svc.accept_body_once(rlp.clone()).expect("a readable body");
    assert_eq!((got, fresh), (hash, true));
    assert_eq!(got_header, header);
    assert!(rig.svc.driver.has_body(&hash), "the execution layer will be sent the bytes");
    assert!(rig.svc.body_store.contains_key(&hash), "and peers can be served them");
    assert_eq!(rig.svc.block_numbers.get(&hash), Some(&4));

    let (_, _, fresh) = rig.svc.accept_body_once(rlp).expect("the same body again");
    assert!(!fresh, "a second copy is not imported again");

    let err = rig.svc.accept_body_once(alloy_primitives::Bytes::from_static(&[1, 2, 3])).expect_err("garbage");
    assert!(matches!(err, n42_h2_consensus::BlockBodyError::InvalidRlp), "got {err:?}");
}

#[tokio::test]
async fn a_whole_body_after_its_compact_twin_is_stored_but_not_imported_twice() {
    let mut rig = node(1, 0, None).await;
    let (hash, _, rlp) = block(4, B256::repeat_byte(2));
    let compact = n42_h2_consensus::encode_compact_body(&rlp, &[], HeaderProfile::Ethereum).expect("compact");
    let from = PeerId::random();
    let (got, _, fresh) =
        rig.svc.accept_compact_body(alloy_primitives::Bytes::from(compact.clone()), Some(from)).expect("compact");
    assert_eq!((got, fresh), (hash, true));
    assert_eq!(rig.svc.body_from.get(&hash), Some(&from), "who pushed it is remembered");
    assert!(rig.svc.compact_bodies.contains_key(&hash));
    assert!(!rig.svc.body_store.contains_key(&hash), "a compact frame is never served as a gov5 body");

    // The same compact frame again does not replace the frame of record.
    let (_, _, fresh) = rig.svc.accept_compact_body(alloy_primitives::Bytes::from(compact), None).expect("again");
    assert!(!fresh);

    // The whole body arrives later: kept for peers, not imported again.
    let (_, _, fresh) = rig.svc.accept_body_once(rlp).expect("whole");
    assert!(!fresh, "the compact copy's import is under way");
    assert!(rig.svc.body_store.contains_key(&hash), "but the bytes are now servable");
}

#[tokio::test]
async fn compact_bodies_are_remembered_to_a_bound() {
    let mut rig = node(1, 0, None).await;
    let mut first = None;
    for number in 1..=(REMEMBERED_COMPACT_BODIES as u64 + 2) {
        let (hash, _, rlp) = block(number, B256::repeat_byte(number as u8));
        let compact = n42_h2_consensus::encode_compact_body(&rlp, &[], HeaderProfile::Ethereum).expect("compact");
        rig.svc.accept_compact_body(alloy_primitives::Bytes::from(compact), Some(PeerId::random())).expect("ok");
        rig.svc.fill_rounds.insert(hash, FillRounds::default());
        first.get_or_insert(hash);
    }
    assert_eq!(rig.svc.compact_bodies.len(), REMEMBERED_COMPACT_BODIES);
    let first = first.expect("one");
    assert!(!rig.svc.compact_bodies.contains_key(&first));
    assert!(!rig.svc.body_from.contains_key(&first), "the push's sender goes with it");
    assert!(!rig.svc.fill_rounds.contains_key(&first), "and so do its fill rounds");

    let err = rig.svc.accept_compact_body(alloy_primitives::Bytes::from_static(&[0xc0]), None).expect_err("not compact");
    assert!(!err.to_string().is_empty());
}

#[tokio::test]
async fn giving_up_on_a_compact_body_asks_for_the_whole_one_once() {
    let mut rig = node(1, 0, None).await;
    let (hash, _, rlp) = block(4, B256::repeat_byte(2));
    let compact = n42_h2_consensus::encode_compact_body(&rlp, &[], HeaderProfile::Ethereum).expect("compact");
    rig.svc.accept_compact_body(alloy_primitives::Bytes::from(compact), None).expect("compact");
    rig.svc.fill_rounds.insert(hash, FillRounds::default());
    assert!(rig.svc.compact_order.contains(&hash));

    rig.svc.forget_compact_body(hash);
    assert!(!rig.svc.compact_bodies.contains_key(&hash), "the frame is dropped");
    assert!(!rig.svc.compact_order.contains(&hash));
    assert!(!rig.svc.fill_rounds.contains_key(&hash));
    assert!(rig.svc.awaiting_bodies.contains(&hash), "the whole body is awaited");
    assert!(rig.svc.body_requested_at.contains_key(&hash), "and the ask is on record");

    // A second give-up inside the interval does not ask again.
    rig.svc.awaiting_bodies.remove(&hash);
    rig.svc.forget_compact_body(hash);
    assert!(!rig.svc.awaiting_bodies.contains(&hash), "rate limited");
}

#[tokio::test]
async fn an_unanswerable_fill_falls_back_to_the_whole_body_when_no_peer_is_left() {
    let mut rig = node(1, 0, None).await;
    let hash = B256::repeat_byte(0x77);
    let request = n42_h2_net::BlockTxnsRequest { hash, indices: vec![1, 2] };
    rig.svc.fill_rounds.insert(hash, FillRounds::default());
    rig.svc.ask_next_for_fill(request, "the peer has none");
    assert!(rig.svc.awaiting_bodies.contains(&hash), "no peer left: the whole body is asked for");
    assert!(!rig.svc.fill_rounds.contains_key(&hash));

    // With a peer queued behind, the next one is tried and the queue shrinks.
    let hash = B256::repeat_byte(0x78);
    let (a, b) = (PeerId::random(), PeerId::random());
    rig.svc.fill_peers.insert(hash, vec![a, b]);
    rig.svc.ask_next_for_fill(n42_h2_net::BlockTxnsRequest { hash, indices: vec![0] }, "refused");
    assert_eq!(rig.svc.fill_peers[&hash], vec![a], "the last queued peer was taken");
    assert!(!rig.svc.awaiting_bodies.contains(&hash), "the compact road is still open");
}

// ---------------------------------------------------------------------------
// Transport events that carry no channel
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gossiped_transactions_are_queued_remembered_and_capped() {
    let mut rig = node(1, 0, None).await;
    let txs = vec![alloy_primitives::Bytes::from_static(&[1, 1]), alloy_primitives::Bytes::from_static(&[2, 2, 2])];
    let data = compress_block_rlp(&encode_tx_batch(&txs).expect("batch")).expect("snappy");
    rig.svc.handle_transport_event(TransportEvent::Transactions { from: None, data }).expect("ok");
    assert_eq!(Vec::from(rig.svc.inbound_transactions.clone()), txs);
    let remembered: Vec<B256> = rig.svc.gossiped_transactions.iter().copied().collect();
    assert_eq!(remembered, vec![keccak256(&txs[0]), keccak256(&txs[1])], "echoes will be recognised");

    // Garbage is dropped without touching the queues.
    rig.svc
        .handle_transport_event(TransportEvent::Transactions { from: None, data: vec![0xff, 0xff, 0xff] })
        .expect("a bad payload is not an error");
    assert_eq!(rig.svc.inbound_transactions.len(), 2);

    // The inbound queue is capped, oldest out.
    let mut n = 0u32;
    while rig.svc.inbound_transactions.len() < INBOUND_TX_CAP || n < 3 {
        let batch: Vec<alloy_primitives::Bytes> = (0..200)
            .map(|_| {
                n += 1;
                alloy_primitives::Bytes::from(n.to_be_bytes().to_vec())
            })
            .collect();
        let data = compress_block_rlp(&encode_tx_batch(&batch).expect("batch")).expect("snappy");
        rig.svc.handle_transport_event(TransportEvent::Transactions { from: None, data }).expect("ok");
        if n > INBOUND_TX_CAP as u32 + 400 {
            break;
        }
    }
    assert_eq!(rig.svc.inbound_transactions.len(), INBOUND_TX_CAP);
    assert!(!rig.svc.inbound_transactions.contains(&txs[0]), "the first transaction was pushed out");
    assert!(rig.svc.gossiped_transactions.len() <= REMEMBERED_TIMESTAMPS * 16);
}

#[tokio::test]
async fn inbound_transactions_go_to_the_forwarder_without_waiting_for_it() {
    let mut rig = node(1, 0, None).await;
    // No forwarder: what was heard is dropped, not kept for ever.
    rig.svc.inbound_transactions.push_back(alloy_primitives::Bytes::from_static(&[1]));
    rig.svc.forward_inbound_transactions();
    assert!(rig.svc.inbound_transactions.is_empty());

    // A forwarder with room takes the whole queue in order.
    let (tx, mut rx) = mpsc::channel(TX_FORWARD_QUEUE);
    rig.svc.inbound_forward = Some(tx);
    let txs: Vec<alloy_primitives::Bytes> = (1..=3u8).map(|i| alloy_primitives::Bytes::from(vec![i])).collect();
    rig.svc.inbound_transactions.extend(txs.clone());
    rig.svc.forward_inbound_transactions();
    assert!(rig.svc.inbound_transactions.is_empty());
    assert_eq!(rx.try_recv().expect("one handoff"), txs);

    // A forwarder that is full: the batch is kept, in order, for the next step.
    let (tx, rx) = mpsc::channel(1);
    tx.try_send(Vec::new()).expect("fills the queue");
    rig.svc.inbound_forward = Some(tx);
    rig.svc.inbound_transactions.extend(txs.clone());
    rig.svc.forward_inbound_transactions();
    assert_eq!(Vec::from(rig.svc.inbound_transactions.clone()), txs, "kept, same order");
    assert!(rig.svc.inbound_forward.is_some());

    // A forwarder that went away is dropped along with the queue.
    drop(rx);
    rig.svc.forward_inbound_transactions();
    assert!(rig.svc.inbound_forward.is_none());
    assert!(rig.svc.inbound_transactions.is_empty());
}

#[tokio::test]
async fn a_status_is_queued_only_when_the_peer_is_on_our_chain() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let status = |fork_matches| TransportEvent::StatusExchanged {
        peer,
        genesis_hash: B256::ZERO,
        height: 12,
        fork_matches,
    };
    rig.svc.handle_transport_event(status(false)).expect("ok");
    assert!(rig.svc.pending_status.is_empty(), "a peer on another chain is never pulled from");
    rig.svc.handle_transport_event(status(true)).expect("ok");
    assert_eq!(rig.svc.pending_status, vec![(peer, 12)]);

    // The remaining informational events change nothing.
    rig.svc.handle_transport_event(TransportEvent::PeerConnected(peer)).expect("ok");
    rig.svc.handle_transport_event(TransportEvent::Rejected { from: None, reason: "bad".into() }).expect("ok");
    rig.svc.handle_transport_event(TransportEvent::DialFailed { peer: None, reason: "refused".into() }).expect("ok");
    rig.svc.handle_transport_event(TransportEvent::Subscribed).expect("ok");
    assert_eq!(rig.svc.pending_status.len(), 1);
}

#[tokio::test]
async fn a_range_reply_is_queued_and_a_refusal_is_handed_on_only_to_the_running_catch_up() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let request = n42_h2_net::RangeRequest { start: 4, count: 8, step: 1 };

    rig.svc
        .handle_transport_event(TransportEvent::RangeFetched { peer, request, reply: Ok(vec![chunk(&block(4, B256::ZERO).2)]) })
        .expect("ok");
    assert_eq!(rig.svc.pending_imports.len(), 1);
    assert_eq!(rig.svc.pending_imports[0].2.len(), 1);

    // A refusal with no catch-up is only logged.
    rig.svc.pending_imports.clear();
    rig.svc
        .handle_transport_event(TransportEvent::RangeFetched { peer, request, reply: Err("nope".into()) })
        .expect("ok");
    assert!(rig.svc.pending_imports.is_empty());

    // With this peer's catch-up running it becomes an empty reply for the import loop.
    rig.svc.catch_up = Some(CatchUp { peer, next: 4, target: 20, started_at: 3, probing: false });
    rig.svc
        .handle_transport_event(TransportEvent::RangeFetched { peer, request, reply: Err("nope".into()) })
        .expect("ok");
    assert_eq!(rig.svc.pending_imports.len(), 1);
    assert!(rig.svc.pending_imports[0].2.is_empty());
}

#[tokio::test]
async fn a_fetched_block_is_cached_only_when_it_is_the_block_asked_for() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let (hash, _, rlp) = block(3, B256::repeat_byte(1));

    // The wrong block under the right name.
    let (_, _, other) = block(9, B256::repeat_byte(1));
    rig.svc
        .handle_transport_event(TransportEvent::BlockFetched { peer, hash, reply: Ok(chunk(&other)) })
        .expect("ok");
    assert!(!rig.svc.driver.has_payload(&hash));
    assert!(rig.svc.received_bodies.is_empty());

    // Unreadable bytes.
    rig.svc
        .handle_transport_event(TransportEvent::BlockFetched { peer, hash, reply: Ok(chunk(&alloy_primitives::Bytes::from_static(&[1, 2]))) })
        .expect("ok");
    assert!(rig.svc.received_bodies.is_empty());

    // A refusal.
    rig.svc.handle_transport_event(TransportEvent::BlockFetched { peer, hash, reply: Err("not here".into()) }).expect("ok");
    rig.svc.handle_transport_event(TransportEvent::BlockFetchFailed { peer, hash, reason: "timeout".into() }).expect("ok");
    assert!(rig.svc.received_bodies.is_empty());

    // The right block.
    rig.svc.awaiting_bodies.insert(hash);
    rig.svc
        .handle_transport_event(TransportEvent::BlockFetched { peer, hash, reply: Ok(chunk(&rlp)) })
        .expect("ok");
    assert!(rig.svc.driver.has_payload(&hash), "the payload is cached for the engine's execute request");
    assert!(rig.svc.body_store.contains_key(&hash));
    assert_eq!(rig.svc.received_bodies, vec![hash]);
    assert_eq!(rig.svc.ready_bodies, vec![hash], "and its import is queued");
    assert!(!rig.svc.awaiting_bodies.contains(&hash), "no longer awaited");

    // The same answer again, from another peer: a decode for nothing, skipped.
    rig.svc.received_bodies.clear();
    rig.svc
        .handle_transport_event(TransportEvent::BlockFetched { peer: PeerId::random(), hash, reply: Ok(chunk(&rlp)) })
        .expect("ok");
    assert!(rig.svc.received_bodies.is_empty());
}

#[tokio::test]
async fn a_pushed_body_is_imported_once_whoever_sends_it() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let (hash, header, rlp) = block(6, B256::repeat_byte(4));

    rig.svc
        .handle_transport_event(TransportEvent::BlockPushed { peer, chunk: chunk(&alloy_primitives::Bytes::from_static(&[9])) })
        .expect("ok");
    assert!(rig.svc.received_bodies.is_empty(), "an unreadable push introduces nothing");

    rig.svc.handle_transport_event(TransportEvent::BlockPushed { peer, chunk: chunk(&rlp) }).expect("ok");
    assert_eq!(rig.svc.received_bodies, vec![hash]);
    assert_eq!(rig.svc.ready_bodies, vec![hash]);
    assert!(rig.svc.driver.has_payload(&hash));
    assert_eq!(rig.svc.block_headers.get(&hash), Some(&header));

    rig.svc.handle_transport_event(TransportEvent::BlockPushed { peer, chunk: chunk(&rlp) }).expect("ok");
    assert_eq!(rig.svc.received_bodies, vec![hash], "the copy that follows is recognised");
}

#[tokio::test]
async fn a_gossiped_block_is_decoded_cached_and_raises_the_senders_height() {
    let mut rig = node(1, 0, None).await;
    let peer = PeerId::random();
    let (hash, _, rlp) = block(11, B256::repeat_byte(4));
    let data = compress_block_rlp(&rlp).expect("snappy");
    rig.svc.handle_transport_event(TransportEvent::Block { from: Some(peer), data }).expect("ok");
    assert_eq!(rig.svc.peer_heights.get(&peer), Some(&11), "the block tells how far the sender is");
    assert!(rig.svc.body_store.contains_key(&hash));
    assert!(rig.svc.body_arrived.contains_key(&hash), "for the import timing line");
    assert_eq!(rig.svc.received_bodies, vec![hash]);

    rig.svc.received_bodies.clear();
    rig.svc.handle_transport_event(TransportEvent::Block { from: None, data: vec![1, 2, 3, 4] }).expect("ok");
    assert!(rig.svc.received_bodies.is_empty(), "an undecodable body is dropped");
}

#[tokio::test]
async fn a_body_from_the_direct_channel_is_taken_like_a_pushed_one() {
    let mut rig = node(1, 0, None).await;
    let (hash, _, rlp) = block(6, B256::repeat_byte(4));
    rig.svc.handle_direct_body(rlp.clone().into());
    assert_eq!(rig.svc.received_bodies, vec![hash]);
    assert!(rig.svc.driver.has_payload(&hash));
    assert!(rig.svc.body_arrived.contains_key(&hash));

    rig.svc.received_bodies.clear();
    rig.svc.handle_direct_body(rlp.into());
    assert!(rig.svc.received_bodies.is_empty(), "a duplicate costs nothing");
    rig.svc.handle_direct_body(vec![0u8, 1, 2].into());
    assert!(rig.svc.received_bodies.is_empty(), "an unreadable body is dropped");
}

#[tokio::test]
async fn bodies_that_arrived_are_reported_and_executed_on_the_next_drain() {
    let mut rig = node(1, 0, None).await;
    let (hash, _, rlp) = block(1, ID.genesis_hash);
    rig.svc.handle_direct_body(rlp.into());
    let mut events = Vec::new();
    within(rig.svc.drain_outputs(&mut events)).await.expect("drain");
    assert!(events.contains(&ServiceEvent::BodyReceived { block_hash: hash }));
    assert!(rig.svc.ready_bodies.is_empty(), "the queued import ran");
    assert!(
        rig.el.calls().iter().any(|c| matches!(c, ElCall::NewPayload(h) if *h == hash)),
        "the body went to the execution layer: {:?}",
        rig.el.calls()
    );
}

#[tokio::test]
async fn blocks_the_execution_layer_already_has_are_answered_without_asking_it_again() {
    let mut rig = node(1, 0, None).await;
    let hash = B256::repeat_byte(0x31);
    rig.svc.remember_imported(hash);
    let mut events = Vec::new();
    within(rig.svc.handle_output(EngineOutput::ExecuteBlock(hash), &mut events)).await.expect("ok");
    assert!(rig.el.calls().is_empty(), "no round trip for a block it holds");
    assert!(events.is_empty());
}

#[path = "service_loop_tests.rs"]
mod loop_tests;

#[path = "service_net_tests.rs"]
mod net_tests;

#[path = "service_mesh_tests.rs"]
mod mesh_tests;
