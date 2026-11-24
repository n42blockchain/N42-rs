// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The range catch-up's speed and pipeline (sync standard S2/S5), over two
//! or more real services on loopback.

use super::*;

/// Pumps `a` and every server until `done`, draining `a` after every event
/// and again at once while it has a range reply left to import -- as the
/// service's step does on its fast path -- so the harness itself does not
/// pace the pull.
pub(super) async fn pump_many(
    a: &mut Rig,
    servers: &mut [Rig],
    a_events: &mut Vec<ServiceEvent>,
    secs: u64,
    mut done: impl FnMut(&Rig, &[ServiceEvent]) -> bool,
) {
    let mut ignored = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            if done(a, &a_events[..]) {
                return;
            }
            let picked = {
                let mut next = Vec::new();
                next.push(Box::pin(async {
                    let event = a.svc.transport.next_event().await.expect("transport a open");
                    (usize::MAX, event)
                })
                    as std::pin::Pin<Box<dyn std::future::Future<Output = (usize, TransportEvent)> + '_>>);
                for (i, server) in servers.iter_mut().enumerate() {
                    next.push(Box::pin(async move {
                        let event = server.svc.transport.next_event().await.expect("server transport open");
                        (i, event)
                    }));
                }
                let sleep = tokio::time::sleep(Duration::from_millis(1));
                tokio::pin!(sleep);
                tokio::select! {
                    (picked, _, _) = futures::future::select_all(next) => Some(picked),
                    () = &mut sleep => None,
                }
            };
            if let Some((who, event)) = picked {
                if who == usize::MAX {
                    a.svc.handle_transport_event(event).expect("a handles it");
                } else {
                    servers[who].svc.handle_transport_event(event).expect("server handles it");
                }
            }
            a.svc.drain_outputs(a_events).await.expect("a drains");
            for server in servers.iter_mut() {
                server.svc.drain_outputs(&mut ignored).await.expect("server drains");
            }
        }
    })
    .await;
    assert!(result.is_ok(), "the pump did not reach its condition in time");
}

/// A server holding `blocks` (executed in its layer, committed) that
/// advertises their height.
pub(super) async fn server_with(
    keys: &[BlsSecretKey],
    set: &ValidatorSet,
    blocks: &[(B256, Header, alloy_primitives::Bytes)],
    dial: Option<libp2p::Multiaddr>,
) -> Rig {
    use n42_h2_execution::ExecutionLayer;
    let mut server = node_in(keys, set, 0, dial).await;
    for (hash, _, rlp) in blocks {
        let decoded = n42_h2_net::decode_block_rlp_raw(rlp, HeaderProfile::Ethereum).expect("decodes");
        assert_eq!(decoded.block_hash, *hash);
        within(server.el.new_payload(decoded.execution_data())).await.expect("accepted");
    }
    let height = blocks.len() as u64;
    server.svc.transport.set_advertised_height(height);
    server.svc.committed_height = Some(height);
    server
}

/// One catch-up of `count` anchored blocks from one server on loopback,
/// with an execution layer that spends `np_ms` per `newPayload` and
/// `fcu_ms` per forkchoice. Returns the pull's timing.
async fn catch_up_once(count: u64, np_ms: u64, fcu_ms: u64) -> crate::sync_pipeline::CatchUpTimes {
    let (keys, set) = keys(1);
    let builder = node_in(&keys, &set, 0, None).await;
    let blocks = anchored_chain(&builder, count);
    drop(builder);
    let server = server_with(&keys, &set, &blocks, None).await;
    let mut a = node_in(&keys, &set, 0, Some(server.addr.clone())).await;
    a.el.set_behaviour(MockBehaviour {
        new_payload_delay: Some(Duration::from_millis(np_ms)),
        forkchoice_delay: Some(Duration::from_millis(fcu_ms)),
        ..Default::default()
    });
    let mut servers = vec![server];
    let mut events = Vec::new();
    pump_many(&mut a, &mut servers, &mut events, 120, |_, events| {
        events.iter().any(|e| matches!(e, ServiceEvent::Synced { .. }))
    })
    .await;
    assert!(events.contains(&ServiceEvent::Synced { height: count - 1, complete: true }), "{events:?}");
    a.svc.last_catch_up_times.clone().expect("the pull's timing")
}

/// Stage 1 of RS5: where a catch-up's time goes, printed. Several hundred
/// blocks, one server, an execution layer at 2 ms per `newPayload` and
/// 1 ms per forkchoice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_catch_up_of_several_hundred_blocks_reports_where_its_time_goes() {
    let times = catch_up_once(400, 2, 1).await;
    let ms = |d: Duration| d.as_millis();
    println!(
        "catch-up 400 blocks: executed {} in {} ms = {:.1} blocks/s; requests {} replies {} fetch {} ms (max {}) verify {} ms newPayload {} ms forkchoice {} ms ({} calls)",
        times.executed,
        ms(times.started.elapsed()),
        times.blocks_per_sec(),
        times.requests,
        times.replies,
        ms(times.fetch),
        ms(times.fetch_max),
        ms(times.verify),
        ms(times.new_payload),
        ms(times.forkchoice),
        times.forkchoices,
    );
    assert_eq!(times.executed, 399, "every block an anchor covers is executed");
    assert!(times.requests >= 1 && times.replies >= 1);
    assert!(times.new_payload >= Duration::from_millis(2 * 399));
}
