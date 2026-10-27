// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The road's bounds (`docs/MATURITY_HARDENING_2026_10.md` 6.4): the
//! hold-window bound of the taken frames (`N42_ROAD_TAKEN_BOUND`), the
//! retire index (`N42_ROAD_RETIRE_INDEX`) and the refusal of frames above
//! the block gas limit.

use super::offlock_tests::flood;
use super::road::{Road, RoadFrame, ROAD_TAKEN_BOUND_SLACK};
use super::test_support::*;
use super::*;
use reth_transaction_pool::EthPooledTransaction;

const TX_GAS: u64 = 21_000;

/// A road frame of `members`, its id made distinct by `salt`.
fn road_frame(members: &[(Address, u64)], salt: u64) -> RoadFrame<EthPooledTransaction> {
    let now = std::time::Instant::now();
    let txs: Vec<Tx> =
        members.iter().map(|(s, n)| valid_for(tx_hashed(*s, *n), now, TransactionOrigin::External)).collect();
    let record = NewFrame {
        id: frame_id(members[0].0, members[0].1.wrapping_mul(7_919) ^ (salt << 32)),
        hashes: txs.iter().map(|t| *t.hash()).collect(),
        members: members.to_vec(),
        gas: TX_GAS * members.len() as u64,
    };
    RoadFrame::of(&record, FrameTxs::from(txs))
}

fn ids(frames: &[RoadFrame<EthPooledTransaction>]) -> Vec<B256> {
    frames.iter().map(|frame| frame.id).collect()
}

fn take_all(road: &Road<EthPooledTransaction>) -> Vec<RoadFrame<EthPooledTransaction>> {
    let mut gas = u64::MAX;
    road.take_upto(&mut gas)
}

/// The bound forgets a taken frame once more than `hold + slack` own
/// blocks were held since its take -- not one hold earlier -- and leaves
/// alone the frames retired before, the frames taken later and a frame
/// handed back and taken again (its age starts at the second take). A
/// forgotten frame's give-back is no longer recognised. Off, nothing is
/// forgotten.
#[test]
fn the_bound_forgets_exactly_the_frames_the_hold_window_passed() {
    let hold = 4usize;
    let window = hold as u64 + ROAD_TAKEN_BOUND_SLACK;
    for on in [false, true] {
        let road: Road<EthPooledTransaction> = Road::new(RoadMode::On);
        road.set_taken_bound(on);
        let (a, c, d, b) = (
            road_frame(&[(sender(1), 0)], 1),
            road_frame(&[(sender(2), 0)], 2),
            road_frame(&[(sender(3), 0)], 3),
            road_frame(&[(sender(4), 0)], 4),
        );
        for frame in [&a, &c, &d] {
            road.queue_frame(frame.clone());
        }
        assert_eq!(take_all(&road).len(), 3, "a, c and d taken at hold 0");
        // c is mined.
        let mut highest = AddressHashMap::default();
        highest.insert(sender(2), 0);
        assert_eq!(ids(&road.retire(&highest)), [c.id]);
        for _ in 0..5 {
            assert!(road.note_hold(hold).is_empty());
        }
        // d is handed back and taken again at hold 5.
        let (whole, rest) = road.recognize(d.txs.to_vec());
        assert_eq!((ids(&whole), rest.len()), (vec![d.id], 0));
        road.hand_back(whole);
        assert_eq!(ids(&take_all(&road)), [d.id]);
        for _ in 5..window {
            assert!(road.note_hold(hold).is_empty(), "nothing is older than the window yet");
        }
        assert_eq!(road.taken_len(), 2);
        road.queue_frame(b.clone());
        assert_eq!(ids(&take_all(&road)), [b.id], "b taken at hold {window}");
        // Hold window + 1: a (taken at 0) is past it, d and b are not.
        let dropped = road.note_hold(hold);
        if on {
            assert_eq!(ids(&dropped), [a.id]);
            assert_eq!(road.taken_len(), 2);
            let (whole, rest) = road.recognize(a.txs.to_vec());
            assert!(whole.is_empty(), "a forgotten frame is not recognised");
            assert_eq!(rest.len(), 1);
        } else {
            assert!(dropped.is_empty());
            assert_eq!(road.taken_len(), 3);
        }
        // d (taken at 5) leaves at 5 + window + 1, b stays.
        for _ in 0..4 {
            assert!(road.note_hold(hold).is_empty());
        }
        let dropped = road.note_hold(hold);
        let stats = road.counters.read();
        if on {
            assert_eq!(ids(&dropped), [d.id]);
            assert_eq!(road.taken_len(), 1);
            assert_eq!((stats.bounded, stats.taken_frames), (2, 1), "{stats:?}");
        } else {
            assert!(dropped.is_empty());
            assert_eq!((stats.bounded, stats.taken_frames), (0, 3), "{stats:?}");
        }
    }
}

/// Through the queue: a build's road take that is never held, handed back
/// or mined is forgotten once the own blocks held after it pass the
/// window; until then it is remembered.
#[test]
fn own_blocks_held_past_the_window_bound_a_leaked_take() {
    let q = TxQueue::<EthPooledTransaction>::with_run_length(64).with_frame_road(RoadMode::On);
    q.road.set_taken_bound(true);
    flood(&q, 100, 0, 2, 50);
    let (best, _plan, _) = q.frames_for_build_ahead(block_hash(0), 200 * TX_GAS, SelectMode::Parallel, false);
    assert_eq!(best.count(), 200);
    assert_eq!(q.road.taken_len(), 4);
    let now = std::time::Instant::now();
    let unrelated = |n: u64| vec![valid_for(tx_hashed(sender(9_999), n), now, TransactionOrigin::External)];
    let window = own_hold_blocks() as u64 + ROAD_TAKEN_BOUND_SLACK;
    for n in 1..=window {
        q.hold_own_block(n, block_hash(1_000 + n), unrelated(n));
    }
    assert_eq!(q.road.taken_len(), 4, "still inside the window");
    q.hold_own_block(window + 1, block_hash(1_000 + window + 1), unrelated(window + 1));
    assert_eq!(q.road.taken_len(), 0);
    let stats = q.road_stats();
    assert_eq!((stats.bounded, stats.taken_frames, stats.retired), (4, 0, 0), "{stats:?}");
}

/// A small deterministic generator (no `rand` in this crate).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The retire index finds exactly the frames the scan finds: two roads
/// driven through the same random history of admissions, takes,
/// give-backs and retires -- one scanning, one indexed -- retire the same
/// frames at every step and remember the same taken frames, and the index
/// always lists exactly the remembered frames.
#[test]
fn the_retire_index_retires_what_the_scan_retires() {
    const SENDERS: u64 = 12;
    for seed in 1..=8u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let scan: Road<EthPooledTransaction> = Road::new(RoadMode::On);
        scan.set_retire_index(false);
        let indexed: Road<EthPooledTransaction> = Road::new(RoadMode::On);
        indexed.set_retire_index(true);
        let mut next = [0u64; SENDERS as usize];
        let mut taken_txs: Vec<Vec<Tx>> = Vec::new();
        let mut salt = 0u64;
        for step in 0..600 {
            match rng.below(5) {
                0 | 1 => {
                    // A frame of 1-4 distinct senders at their next nonces.
                    let width = 1 + rng.below(4);
                    let mut members: Vec<(Address, u64)> = Vec::new();
                    while (members.len() as u64) < width {
                        let s = rng.below(SENDERS);
                        if members.iter().any(|(m, _)| *m == sender(s)) {
                            continue;
                        }
                        members.push((sender(s), next[s as usize]));
                        next[s as usize] += 1;
                    }
                    salt += 1;
                    let frame = road_frame(&members, salt);
                    scan.queue_frame(frame.clone());
                    indexed.queue_frame(frame);
                }
                2 => {
                    let gas = TX_GAS * rng.below(12);
                    let (mut g1, mut g2) = (gas, gas);
                    let a = scan.take_upto(&mut g1);
                    let b = indexed.take_upto(&mut g2);
                    assert_eq!(ids(&a), ids(&b), "seed {seed} step {step}");
                    taken_txs.extend(a.iter().map(|frame| frame.txs.to_vec()));
                }
                3 if !taken_txs.is_empty() => {
                    let pick = taken_txs.swap_remove(rng.below(taken_txs.len() as u64) as usize);
                    let (w1, r1) = scan.recognize(pick.clone());
                    let (w2, r2) = indexed.recognize(pick);
                    assert_eq!((ids(&w1), r1.len()), (ids(&w2), r2.len()), "seed {seed} step {step}");
                    scan.hand_back(w1);
                    indexed.hand_back(w2);
                }
                _ => {
                    let mut highest = AddressHashMap::default();
                    for s in 0..SENDERS {
                        if rng.below(3) == 0 && next[s as usize] > 0 {
                            highest.insert(sender(s), rng.below(next[s as usize]));
                        }
                    }
                    let mut r1 = ids(&scan.retire(&highest));
                    let mut r2 = ids(&indexed.retire(&highest));
                    r1.sort_unstable();
                    r2.sort_unstable();
                    assert_eq!(r1, r2, "seed {seed} step {step}");
                }
            }
            let (scan_ids, scan_index) = scan.taken_state();
            let (indexed_ids, _) = indexed.taken_state();
            assert_eq!(scan_ids, indexed_ids, "seed {seed} step {step}");
            assert!(scan_index.is_empty(), "the scanning road keeps no index");
            assert!(indexed.index_consistent(), "seed {seed} step {step}");
        }
        assert_eq!(scan.counters.read(), indexed.counters.read(), "seed {seed}");
    }
}

/// A frame of `members` through the ingest's door, with its gas.
fn push_members(queue: &TxQueue<EthPooledTransaction>, members: &[(Address, u64)], salt: u64) -> B256 {
    let txs: Vec<EthPooledTransaction> = members.iter().map(|(s, n)| tx_hashed(*s, *n)).collect();
    let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
    let id = frame_id(members[0].0, members[0].1.wrapping_mul(7_919) ^ salt);
    queue.push_frame(
        txs,
        Some(NewFrame { id, hashes, members: members.to_vec(), gas: TX_GAS * members.len() as u64 }),
    );
    id
}

/// A frame above the block gas limit is refused at admission (counted, its
/// transactions on the lanes' path) instead of waiting at the FIFO's front
/// for ever, and the frame behind it is admitted and taken by the next
/// build. Before any build has named a gas limit nothing is refused.
#[test]
fn an_oversize_frame_is_refused_and_the_frame_behind_it_is_taken() {
    let q = TxQueue::<EthPooledTransaction>::with_run_length(64).with_frame_road(RoadMode::On);
    // A build on the empty queue names the block gas limit: ten transfers.
    let (best, _, _) = q.frames_for_build_ahead(block_hash(0), 10 * TX_GAS, SelectMode::Parallel, false);
    assert_eq!(best.count(), 0);
    let big: Vec<(Address, u64)> = (0..11).map(|i| (sender(i), 0)).collect();
    push_members(&q, &big, 1);
    let stats = q.road_stats();
    assert_eq!((stats.refused_oversize, stats.frames, stats.flushes), (1, 0, 0), "{stats:?}");
    assert!(q.road.queued_ids().is_empty(), "nothing waits on the road");
    let small: Vec<(Address, u64)> = (20..25).map(|i| (sender(i), 0)).collect();
    let id = push_members(&q, &small, 2);
    assert_eq!(q.road.queued_ids(), [id]);
    let (best, plan, _) = q.frames_for_build_ahead(block_hash(0), 10 * TX_GAS, SelectMode::Parallel, false);
    let txs: Vec<Tx> = best.collect();
    assert_eq!(plan.frames.first().map(|f| f.id), Some(id), "{plan:?}");
    assert_eq!(pairs(&txs[..5]), small);
    assert_eq!(q.road_stats().refused_oversize, 1);

    // No build yet: no limit known, the same frame is admitted.
    let fresh = TxQueue::<EthPooledTransaction>::with_run_length(64).with_frame_road(RoadMode::On);
    push_members(&fresh, &big, 1);
    assert_eq!(fresh.road_stats().refused_oversize, 0);
    assert_eq!(fresh.road.queued_ids().len(), 1);
}
