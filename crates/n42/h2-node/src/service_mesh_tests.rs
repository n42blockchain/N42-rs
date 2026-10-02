// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the service publishes once a gossip mesh exists: consensus messages
//! on both topics, queued messages flushed, block bodies by push and by
//! topic, and transactions. Two real services over loopback; the receiving
//! side's own handlers decide what arrived.

use super::net_tests::pump;
use super::*;
use crate::tx_source::tests::{ingest_server, MockRpc};
use serde_json::{json, Value};

/// Two members of one four-validator set, connected and meshed.
async fn meshed() -> (Rig, Rig) {
    let (keys, set) = keys(4);
    let mut a = node_in(&keys, &set, 0, None).await;
    let mut b = node_in(&keys, &set, 1, Some(a.addr.clone())).await;
    let mut ignored = Vec::new();
    pump(&mut a, &mut b, (false, false), &mut ignored, |a, b, _| {
        a.svc.transport.mesh_size() > 0 && b.svc.transport.mesh_size() > 0
    })
    .await;
    (a, b)
}

/// Publishes `hash`'s stored body on the block topic until the peer has it.
/// The block topic's mesh forms on its own heartbeat, a little after the v4
/// topic's, and a publish before that is refused (peers then fetch by hash),
/// so the publish is repeated; a duplicate is recognised by id and harmless.
async fn publish_until_held(a: &mut Rig, b: &mut Rig, hash: B256) {
    for _ in 0..60 {
        if b.svc.body_store.contains_key(&hash) {
            return;
        }
        let rlp = a.svc.body_store.get(&hash).expect("the body is stored").to_shared();
        a.svc.send_body(compress_block_rlp(&rlp).expect("snappy"), hash);
        settle(a, b, 150).await;
    }
    assert!(b.svc.body_store.contains_key(&hash), "the body never reached the peer");
}

/// Both transports run for `ms` milliseconds, events handled.
async fn settle(a: &mut Rig, b: &mut Rig, ms: u64) {
    let until = std::time::Instant::now() + Duration::from_millis(ms);
    let mut ignored = Vec::new();
    pump(a, b, (false, false), &mut ignored, move |_, _, _| std::time::Instant::now() >= until).await;
}

#[tokio::test]
async fn a_consensus_message_goes_out_on_the_v4_topic_and_is_heard_by_the_peer() {
    let (mut a, mut b) = meshed().await;
    a.svc.engine.on_timeout().expect("a timeout vote");
    let mut events = Vec::new();
    within(a.svc.drain_outputs(&mut events)).await.expect("drain");
    // Published, or queued if the mesh had no peer for the topic yet; flush
    // until it is out.
    for _ in 0..20 {
        if a.svc.outbox.is_empty() {
            break;
        }
        a.svc.flush_outbox(&mut events);
        settle(&mut a, &mut b, 100).await;
    }
    assert!(a.svc.outbox.is_empty(), "the message left the outbox");
    assert!(events.iter().any(|e| matches!(e, ServiceEvent::Published { view } if *view == 1)), "{events:?}");
    let mut ignored = Vec::new();
    pump(&mut a, &mut b, (false, false), &mut ignored, |_, b, _| b.seen.contains(&"envelope")).await;
}

#[tokio::test]
async fn under_gov5s_profile_consensus_goes_out_on_the_native_topic() {
    let (keys, set) = keys(4);
    let mut a = node_in(&keys, &set, 0, None).await;
    a.svc = a.svc.with_gov5_h2_profile(keys[0].clone());
    let mut b = node_in(&keys, &set, 1, Some(a.addr.clone())).await;
    let mut ignored = Vec::new();
    pump(&mut a, &mut b, (false, false), &mut ignored, |a, b, _| {
        a.svc.transport.mesh_size() > 0 && b.svc.transport.mesh_size() > 0
    })
    .await;
    a.svc.engine.on_timeout().expect("a timeout vote");
    let mut events = Vec::new();
    within(a.svc.drain_outputs(&mut events)).await.expect("drain");
    for _ in 0..20 {
        if a.svc.outbox.is_empty() {
            break;
        }
        a.svc.flush_outbox(&mut events);
        settle(&mut a, &mut b, 100).await;
    }
    assert!(a.svc.outbox.is_empty());
    pump(&mut a, &mut b, (false, false), &mut ignored, |_, b, _| b.seen.contains(&"native")).await;
    assert!(!b.seen.contains(&"envelope"), "a non-Decide message is not also put on the v4 topic");
}

#[tokio::test]
async fn messages_and_bodies_queued_before_the_mesh_are_sent_when_it_forms() {
    let (keys, set) = keys(4);
    let mut a = node_in(&keys, &set, 0, None).await;
    let mut b = node_in(&keys, &set, 1, Some(a.addr.clone())).await;
    a.svc.engine.on_timeout().expect("a timeout vote");
    let mut events = Vec::new();
    within(a.svc.drain_outputs(&mut events)).await.expect("drain");
    assert_eq!(a.svc.outbox.len(), 1, "no mesh yet: queued");
    let (hash, _, rlp) = block(3, B256::repeat_byte(1));
    a.svc.send_body(compress_block_rlp(&rlp).expect("snappy"), hash);
    assert_eq!(a.svc.body_outbox.len(), 1, "the body is queued too");
    a.svc.flush_outbox(&mut events);
    assert_eq!((a.svc.outbox.len(), a.svc.body_outbox.len()), (1, 1), "an empty mesh sends nothing");

    let mut ignored = Vec::new();
    pump(&mut a, &mut b, (false, false), &mut ignored, |a, b, _| {
        a.svc.transport.mesh_size() > 0 && b.svc.transport.mesh_size() > 0
    })
    .await;
    for _ in 0..20 {
        a.svc.flush_outbox(&mut events);
        if a.svc.outbox.is_empty() && a.svc.body_outbox.is_empty() {
            break;
        }
        settle(&mut a, &mut b, 100).await;
    }
    assert!(a.svc.outbox.is_empty() && a.svc.body_outbox.is_empty());
    pump(&mut a, &mut b, (false, false), &mut ignored, |_, b, _| b.seen.contains(&"envelope")).await;
    a.svc.remember_body(hash, rlp);
    publish_until_held(&mut a, &mut b, hash).await;
    assert!(b.seen.contains(&"block"), "and the body arrived on the block topic");
    assert!(events.iter().any(|e| matches!(e, ServiceEvent::Published { .. })));
}

#[tokio::test]
async fn pool_transactions_are_gossiped_once_and_what_the_fleet_sent_is_not_echoed() {
    let (mut a, mut b) = meshed().await;
    let (t1, t2, t3) = (Bytes::from_static(&[1, 1]), Bytes::from_static(&[2, 2]), Bytes::from_static(&[3, 3]));
    // The transactions topic meshes on its own heartbeat: the publish is
    // repeated until it is heard (a duplicate is recognised by id).
    for _ in 0..60 {
        if b.svc.inbound_transactions.len() >= 2 {
            break;
        }
        a.svc.publish_transactions(vec![t1.clone(), t2.clone()]);
        settle(&mut a, &mut b, 150).await;
    }
    assert_eq!(Vec::from(b.svc.inbound_transactions.clone()), vec![t1.clone(), t2.clone()]);
    assert_eq!(b.svc.gossiped_transactions.len(), 2, "B remembers what it heard");

    // t1 is known to have come from the fleet: only t3 goes out.
    a.svc.gossiped_transactions.push_back(keccak256(&t1));
    for _ in 0..60 {
        if b.svc.inbound_transactions.len() >= 3 {
            break;
        }
        a.svc.publish_transactions(vec![t1.clone(), t3.clone()]);
        settle(&mut a, &mut b, 150).await;
    }
    settle(&mut a, &mut b, 300).await;
    assert_eq!(Vec::from(b.svc.inbound_transactions.clone()), vec![t1.clone(), t2, t3], "t1 was not sent a second time");

    // A batch of nothing but echoes publishes nothing at all.
    let before = b.svc.inbound_transactions.len();
    a.svc.publish_transactions(vec![t1]);
    settle(&mut a, &mut b, 300).await;
    assert_eq!(b.svc.inbound_transactions.len(), before);
}

#[tokio::test]
async fn a_built_block_reaches_the_peer_by_the_topic_or_by_direct_push() {
    let (mut a, mut b) = meshed().await;
    let built = MockExecutionLayer::built_block(5);
    let mut ignored = Vec::new();

    // The topic: the default.
    a.svc.publish_body(&built.execution_data, built.header.as_ref(), &built.tx_hashes, &built.frame_layout, None);
    assert!(a.svc.body_store.contains_key(&built.hash), "the leader keeps its own body for peers that ask");
    publish_until_held(&mut a, &mut b, built.hash).await;
    assert!(b.seen.contains(&"block"), "arrived on the block topic");
    assert_eq!(b.svc.block_numbers[&built.hash], 5);

    // Direct push to every connected member: the topic is then not used.
    let built = MockExecutionLayer::built_block(6);
    a.svc.direct_push = true;
    let topic_before = b.seen.iter().filter(|k| **k == "block").count();
    a.svc.publish_body(&built.execution_data, built.header.as_ref(), &built.tx_hashes, &built.frame_layout, None);
    pump(&mut a, &mut b, (false, false), &mut ignored, |_, b, _| b.svc.body_store.contains_key(&built.hash)).await;
    settle(&mut a, &mut b, 300).await;
    assert_eq!(b.seen.iter().filter(|k| **k == "block").count(), topic_before, "a push that reached every member skips the topic");
    assert!(b.svc.received_bodies.contains(&built.hash));
}

#[tokio::test]
async fn the_pools_own_transactions_are_polled_and_gossiped_by_the_step() {
    let rpc = MockRpc::start({
        let served = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        move |req| {
            let result = match req["method"].as_str().unwrap_or_default() {
                "eth_newPendingTransactionFilter" => json!("0x1"),
                "eth_getFilterChanges" => {
                    if served.swap(true, std::sync::atomic::Ordering::SeqCst) { json!([]) } else { json!([B256::repeat_byte(9)]) }
                }
                "eth_getRawTransactionByHash" => json!("0x02abcd"),
                _ => json!(null),
            };
            json!({"jsonrpc": "2.0", "id": 1, "result": result})
        }
    })
    .await;
    let (mut a, mut b) = meshed().await;
    a.svc = a.svc.with_transaction_source(rpc.url.clone());
    assert!(a.svc.outbound_transactions.is_some());
    assert!(a.svc.inbound_forward.is_some());

    // The step publishes the batch the poller found; B's transport hears it.
    let heard = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                step = a.svc.step() => { step.expect("a step"); }
                event = b.svc.transport.next_event() => {
                    b.svc.handle_transport_event(event.expect("open")).expect("handled");
                    if !b.svc.inbound_transactions.is_empty() {
                        return Vec::from(b.svc.inbound_transactions.clone());
                    }
                }
            }
        }
    })
    .await
    .expect("the pool's transaction was gossiped");
    assert_eq!(heard, vec![Bytes::from_static(&[0x02, 0xab, 0xcd])]);
    assert_eq!(rpc.methods()[0], "eth_newPendingTransactionFilter");
}

#[tokio::test]
async fn gossiped_transactions_heard_by_the_service_are_posted_to_the_pool_or_the_ingest() {
    let rpc = MockRpc::start(|_| json!({"jsonrpc": "2.0", "id": 1, "result": []})).await;
    let mut rig = node(1, 0, None).await;
    rig.svc = rig.svc.with_transaction_source(rpc.url.clone());
    let heard = vec![Bytes::from_static(&[1, 2, 3]), Bytes::from_static(&[4, 5])];
    let data = compress_block_rlp(&encode_tx_batch(&heard).expect("batch")).expect("snappy");
    rig.svc.handle_transport_event(TransportEvent::Transactions { from: None, data: data.clone() }).expect("ok");
    rig.svc.forward_inbound_transactions();
    let posted = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(body) = rpc.bodies().iter().find(|b| b.as_array().is_some_and(|a| a.first().is_some_and(|c| c["method"] == "eth_sendRawTransaction"))) {
                return body.clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("posted to the pool");
    let params: Vec<Value> = posted.as_array().expect("batch").iter().map(|c| c["params"][0].clone()).collect();
    assert_eq!(params, vec![json!(heard[0]), json!(heard[1])]);

    // The ingest replaces the inbound forwarder only.
    let (addr, mut frames) = ingest_server(false).await;
    rig.svc = rig.svc.with_transaction_ingest(addr, 1);
    assert!(rig.svc.outbound_transactions.is_some(), "the outbound direction is untouched");
    rig.svc.handle_transport_event(TransportEvent::Transactions { from: None, data }).expect("ok");
    rig.svc.forward_inbound_transactions();
    let (_, frame) = tokio::time::timeout(Duration::from_secs(20), frames.recv()).await.expect("a frame").expect("open");
    assert_eq!(frame, vec![vec![1, 2, 3], vec![4, 5]]);
}

#[tokio::test]
async fn a_body_channel_gives_the_service_a_receiver_and_announces_its_identity() {
    let rig = node(1, 0, None).await;
    let (_tx, rx) = mpsc::channel(1);
    let pushers = crate::body_channel::BodyPushers::connect(Vec::new());
    let svc = rig.svc.with_body_channel(rx, pushers);
    assert!(svc.body_rx.is_some());
    let pushers = svc.body_pushers.as_ref().expect("kept for pushing");
    assert!(pushers.is_empty(), "no member to push to");
    // With nobody to push to the libp2p push and the topic are what is left.
    let mut svc = svc;
    svc.direct_push = true;
    let sent = svc.push_body(&alloy_primitives::Bytes::from_static(b"body"), None, B256::repeat_byte(1));
    assert!(!sent, "no connected peer: not every member was reached");
}
