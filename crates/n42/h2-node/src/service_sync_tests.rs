// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The range catch-up's speed and pipeline (sync standard S2/S5), over two
//! or more real services on loopback.

use super::*;

/// What [`pump_many`] measured.
#[derive(Debug, Default)]
pub(super) struct Pumped {
    /// The longest single `drain_outputs` of the pulling node: how long its
    /// loop could not have handled a vote or a timeout.
    pub(super) max_drain: Duration,
}

/// Pumps `a` and every server until `done`, draining `a` after every event
/// and at once again while it has a range reply left to screen -- as the
/// service's step does on its fast path -- so the harness itself does not
/// pace the pull. A server for which `frozen` says so is neither polled nor
/// drained any more: a peer that stalls.
pub(super) async fn pump_many(
    a: &mut Rig,
    servers: &mut [Rig],
    a_events: &mut Vec<ServiceEvent>,
    secs: u64,
    frozen: impl Fn(usize, &Rig) -> bool,
    mut done: impl FnMut(&Rig, &[ServiceEvent]) -> bool,
) -> Pumped {
    let mut ignored = Vec::new();
    let mut pumped = Pumped::default();
    let result = tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            if done(a, &a_events[..]) {
                return;
            }
            let live: Vec<bool> = servers.iter().enumerate().map(|(i, s)| !frozen(i, s)).collect();
            let picked = {
                let mut next = Vec::new();
                next.push(Box::pin(async {
                    let event = a.svc.transport.next_event().await.expect("transport a open");
                    (usize::MAX, event)
                })
                    as std::pin::Pin<Box<dyn std::future::Future<Output = (usize, TransportEvent)> + '_>>);
                for (i, server) in servers.iter_mut().enumerate() {
                    if !live[i] {
                        continue;
                    }
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
                    let kind = if matches!(event, TransportEvent::RangeRequest { .. }) {
                        "range_request"
                    } else {
                        transport_event_kind(&event)
                    };
                    servers[who].seen.push(kind);
                    servers[who].svc.handle_transport_event(event).expect("server handles it");
                }
            }
            let at = std::time::Instant::now();
            a.svc.drain_outputs(a_events).await.expect("a drains");
            pumped.max_drain = pumped.max_drain.max(at.elapsed());
            for (i, server) in servers.iter_mut().enumerate() {
                if live[i] {
                    server.svc.drain_outputs(&mut ignored).await.expect("server drains");
                }
            }
        }
    })
    .await;
    assert!(result.is_ok(), "the pump did not reach its condition in time: {a_events:?}");
    pumped
}

/// A server holding `blocks` (executed in its layer, committed) that
/// advertises their height.
pub(super) async fn server_with(
    keys: &[BlsSecretKey],
    set: &ValidatorSet,
    blocks: &[(B256, Header, alloy_primitives::Bytes)],
) -> Rig {
    use n42_h2_execution::ExecutionLayer;
    let mut server = node_in(keys, set, 0, None).await;
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

/// The pulling node, dialing every server, with an execution layer that
/// spends `np_ms` per `newPayload` and `fcu_ms` per forkchoice, the pipeline
/// on or off.
async fn puller(keys: &[BlsSecretKey], set: &ValidatorSet, servers: &mut [Rig], np_ms: u64, fcu_ms: u64, pipeline: bool) -> Rig {
    let mut a = node_in(keys, set, 0, Some(servers[0].addr.clone())).await;
    for server in servers.iter().skip(1) {
        a.svc.transport.dial(server.addr.clone()).expect("dial");
    }
    a.svc.sync_pipeline = pipeline;
    a.el.set_behaviour(MockBehaviour {
        new_payload_delay: (np_ms > 0).then(|| Duration::from_millis(np_ms)),
        forkchoice_delay: (fcu_ms > 0).then(|| Duration::from_millis(fcu_ms)),
        ..Default::default()
    });
    let want = servers.len();
    let mut ignored = Vec::new();
    pump_many(&mut a, servers, &mut ignored, 30, |_, _| false, |a, _| a.svc.peer_heights.len() >= want).await;
    a
}

fn synced(events: &[ServiceEvent]) -> Option<(u64, bool)> {
    events.iter().rev().find_map(|e| match e {
        ServiceEvent::Synced { height, complete } => Some((*height, *complete)),
        _ => None,
    })
}

/// One catch-up of `count` anchored blocks from `servers_n` servers on
/// loopback. Returns the pull's timing and the pump's measurements.
async fn catch_up_once(
    count: u64,
    servers_n: usize,
    np_ms: u64,
    fcu_ms: u64,
    pipeline: bool,
) -> (crate::sync_pipeline::CatchUpTimes, Pumped, Rig) {
    let (keys, set) = keys(1);
    let builder = node_in(&keys, &set, 0, None).await;
    let blocks = anchored_chain(&builder, count);
    drop(builder);
    let mut servers = Vec::new();
    for _ in 0..servers_n {
        servers.push(server_with(&keys, &set, &blocks).await);
    }
    let mut a = puller(&keys, &set, &mut servers, np_ms, fcu_ms, pipeline).await;
    let mut events = Vec::new();
    let pumped = pump_many(&mut a, &mut servers, &mut events, 120, |_, _| false, |_, events| synced(events).is_some()).await;
    assert_eq!(synced(&events), Some((count - 1, true)), "{events:?}");
    let hashes: Vec<B256> = blocks[..count as usize - 1].iter().map(|b| b.0).collect();
    assert_eq!(executed(&a), hashes, "every anchored block executed once, in order");
    (a.svc.last_catch_up_times.clone().expect("the pull's timing"), pumped, a)
}

fn say(label: &str, times: &crate::sync_pipeline::CatchUpTimes, pumped: &Pumped) {
    let ms = |d: Duration| d.as_millis();
    println!(
        "{label}: executed {} in {} ms = {:.1} blocks/s; requests {} replies {} fetch {} ms (max {}) verify {} ms newPayload {} ms forkchoice {} ms ({} calls); longest loop drain {} ms",
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
        ms(pumped.max_drain),
    );
}

/// RS5 stage 1 and 2: where a catch-up of several hundred blocks spends its
/// time, serial against pipelined, printed. One server for both (the same
/// link), then the pipeline over three; an execution layer at 2 ms per
/// `newPayload` and 1 ms per forkchoice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_catch_up_of_several_hundred_blocks_serial_against_pipelined() {
    let (serial, serial_pump, _) = catch_up_once(400, 1, 2, 1, false).await;
    say("serial    1 peer ", &serial, &serial_pump);
    let (piped, piped_pump, _) = catch_up_once(400, 1, 2, 1, true).await;
    say("pipelined 1 peer ", &piped, &piped_pump);
    let (piped3, piped3_pump, _) = catch_up_once(400, 3, 2, 1, true).await;
    say("pipelined 3 peers", &piped3, &piped3_pump);
    assert_eq!(serial.executed, 399);
    assert_eq!(piped.executed, 399);
    assert_eq!(serial.forkchoices, 399, "serial: one forkchoice per block");
    assert!(piped.forkchoices < 100, "pipelined: one forkchoice per batch, not per block ({})", piped.forkchoices);
    assert!(piped3.requests >= 4, "ranges spread over the peers ({})", piped3.requests);
}

/// The consensus loop is not held by a pulled block's execution: with an
/// execution layer at 40 ms per block, the serial pull holds one drain for
/// a whole step of blocks, the pipelined one never for long.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loop_stays_free_while_the_importer_executes_pulled_blocks() {
    let (_, serial, _) = catch_up_once(80, 1, 40, 1, false).await;
    let (_, piped, _) = catch_up_once(80, 1, 40, 1, true).await;
    println!("longest loop drain: serial {} ms, pipelined {} ms", serial.max_drain.as_millis(), piped.max_drain.as_millis());
    assert!(serial.max_drain >= Duration::from_millis(1_000), "serial holds the loop for a step of blocks");
    assert!(piped.max_drain < Duration::from_millis(300), "pipelined: {:?}", piped.max_drain);
}

/// A peer that serves its first range and then stalls: its next range is
/// reassigned to the other peer after its deadline, and every block is
/// still executed once, in height order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_stalls_mid_pull_has_its_range_reassigned_and_order_holds() {
    let (keys, set) = keys(1);
    let builder = node_in(&keys, &set, 0, None).await;
    let count = 600;
    let blocks = anchored_chain(&builder, count);
    drop(builder);
    let mut servers = vec![server_with(&keys, &set, &blocks).await, server_with(&keys, &set, &blocks).await];
    let mut a = puller(&keys, &set, &mut servers, 0, 0, true).await;
    let mut events = Vec::new();
    // Server 1 is frozen once its second range request has arrived: it
    // answered one and never answers the next.
    let frozen = |i: usize, s: &Rig| i == 1 && s.seen.iter().filter(|k| **k == "range_request").count() >= 2;
    pump_many(&mut a, &mut servers, &mut events, 60, frozen, |_, events| synced(events).is_some()).await;
    assert_eq!(synced(&events), Some((count - 1, true)), "{events:?}");
    let hashes: Vec<B256> = blocks[..count as usize - 1].iter().map(|b| b.0).collect();
    assert_eq!(executed(&a), hashes, "every block once, in height order");
    assert_eq!(servers[1].seen.iter().filter(|k| **k == "range_request").count(), 2, "the stalled peer took two ranges");
}

/// A forging peer among honest ones: the forger's chain carries a QC that
/// does not verify from block 150 on. Nothing forged reaches `newPayload`;
/// the forger is refused for the gap and the honest peer's chain is
/// executed in full.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forging_peer_among_honest_ones_gets_nothing_forged_executed() {
    let (keys, set) = keys(1);
    let builder = node_in(&keys, &set, 0, None).await;
    let count = 300;
    let honest = anchored_chain(&builder, count);
    let mut forged = honest[..149].to_vec();
    let mut parent = forged[148].0;
    for number in 150..=count {
        // Signed over another hash than it names: a forged certificate.
        let qc = header_qc(&builder.svc, &builder.keys, &[0], number - 1, parent, B256::repeat_byte(7));
        let block = block_with_extra(number, parent, number, qc);
        parent = block.0;
        forged.push(block);
    }
    drop(builder);
    let mut servers = vec![server_with(&keys, &set, &honest).await, server_with(&keys, &set, &forged).await];
    let mut a = puller(&keys, &set, &mut servers, 0, 0, true).await;
    let mut events = Vec::new();
    pump_many(&mut a, &mut servers, &mut events, 60, |_, _| false, |_, events| {
        synced(events).is_some_and(|(height, complete)| complete && height == count - 1)
    })
    .await;
    let forged_hashes: HashSet<B256> = forged[149..].iter().map(|b| b.0).collect();
    let ran = executed(&a);
    assert!(ran.iter().all(|h| !forged_hashes.contains(h)), "a forged block reached newPayload");
    let hashes: Vec<B256> = honest[..count as usize - 1].iter().map(|b| b.0).collect();
    let mut seen = HashSet::new();
    let unique: Vec<B256> = ran.into_iter().filter(|h| seen.insert(*h)).collect();
    assert_eq!(unique, hashes, "the honest chain, in order");
}

/// The stall watchdog: an execution layer that stops answering mid-pull
/// leaves the executed head where it is while pulled blocks wait; the
/// pipeline gives up, says so, and the next pull runs serially and
/// finishes once the layer answers again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_importer_falls_back_to_the_serial_pull() {
    let (keys, set) = keys(1);
    let builder = node_in(&keys, &set, 0, None).await;
    let count = 300;
    let blocks = anchored_chain(&builder, count);
    drop(builder);
    let mut servers = vec![server_with(&keys, &set, &blocks).await];
    let mut a = puller(&keys, &set, &mut servers, 0, 0, true).await;
    a.svc.sync_stall = Duration::from_millis(500);
    let gate = Arc::new(tokio::sync::Semaphore::new(50));
    a.el.set_behaviour(MockBehaviour { new_payload_gate: Some(gate.clone()), ..Default::default() });
    let mut events = Vec::new();
    pump_many(&mut a, &mut servers, &mut events, 60, |_, _| false, |_, events| synced(events).is_some()).await;
    assert_eq!(synced(&events).map(|s| s.1), Some(false), "the stalled pull ends incomplete: {events:?}");
    assert!(!a.svc.sync_pipeline, "the pipeline is off after the fallback");
    assert!(a.svc.in_import.is_empty() && a.svc.pulled_importer.is_none());
    gate.add_permits(10_000);
    let mut events = Vec::new();
    pump_many(&mut a, &mut servers, &mut events, 60, |_, _| false, |_, events| {
        synced(events).is_some_and(|(_, complete)| complete)
    })
    .await;
    assert_eq!(synced(&events), Some((count - 1, true)), "{events:?}");
    assert_eq!(a.svc.last_catch_up_times.as_ref().map(|t| t.forkchoices > 0), Some(true));
    let mut seen = HashSet::new();
    let unique: Vec<B256> = executed(&a).into_iter().filter(|h| seen.insert(*h)).collect();
    let hashes: Vec<B256> = blocks[..count as usize - 1].iter().map(|b| b.0).collect();
    assert_eq!(unique, hashes, "the serial pull finished the chain, in order");
}
