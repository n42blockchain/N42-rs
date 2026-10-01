// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The id table at the ingest's shape (`docs/BREAKTHROUGH_DESIGN.md` 4B):
//! a table holding the flood's 2,000,000 recipients and 6,000 senders, and a
//! block's worth of resolutions (163,000 transactions, a sender and a
//! recipient each) over sixteen threads -- every address held, then every
//! address new. Ignored; run it pinned and on a quiet box:
//!
//! `MALLOC_CONF=... taskset -c 0-15 cargo test --release -p n42-account-ids --test bench -- --ignored --nocapture`
#![allow(missing_docs, unreachable_pub, unused_crate_dependencies)]

use std::time::Instant;

use alloy_primitives::Address;
use n42_account_ids::AccountIds;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn recipient(i: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&(i as u32).to_be_bytes());
    bytes[4] = 0x42;
    Address::from(bytes)
}

fn sender(i: u64) -> Address {
    // Spread over the key space, as derived keys' addresses are.
    let mut bytes = [0u8; 20];
    let x = (i + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    bytes[..8].copy_from_slice(&x.to_be_bytes());
    bytes[8..16].copy_from_slice(&x.rotate_left(17).to_le_bytes());
    bytes[19] = 0x5e;
    Address::from(bytes)
}

/// Resolves `addresses` split over `threads`; the wall in ms and the pool
/// time a resolve in ns.
fn timed(table: &AccountIds, addresses: &[Address], threads: usize) -> (f64, f64, u64, u64) {
    let chunk = addresses.len().div_ceil(threads);
    let at = Instant::now();
    let parts: Vec<(u64, u64, u128)> = std::thread::scope(|scope| {
        let handles: Vec<_> = addresses
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    let t = Instant::now();
                    let mut out = Vec::with_capacity(part.len());
                    let counts = table.resolve_into(part, &mut out).expect("room");
                    std::hint::black_box(&out);
                    (counts.new, counts.hit, t.elapsed().as_nanos())
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("joined")).collect()
    });
    let wall = at.elapsed().as_secs_f64() * 1e3;
    let pool_ns: u128 = parts.iter().map(|p| p.2).sum();
    let (new, hit) = parts.iter().fold((0, 0), |acc, p| (acc.0 + p.0, acc.1 + p.1));
    (wall, pool_ns as f64 / addresses.len() as f64, new, hit)
}

#[test]
#[ignore = "timing"]
fn bench_account_ids() {
    let threads = 16;
    let table = AccountIds::with_capacity(1 << 21);
    let at = Instant::now();
    let prefill: Vec<Address> = (0..2_000_000).map(recipient).chain((0..6_000).map(sender)).collect();
    let (_wall, _, new, _) = timed(&table, &prefill, threads);
    println!("prefill: {new} accounts in {:.0} ms on {threads} threads; id_bound {}", at.elapsed().as_secs_f64() * 1e3, table.id_bound());
    for round in 0..5 {
        // A block: 163,000 transfers, a sender and a recipient each, the
        // recipients scattered over the 2M (held) ...
        let held: Vec<Address> = (0..163_000u64)
            .flat_map(|i| [sender(i % 6_000), recipient((i * 7_919 + round * 104_729) % 2_000_000)])
            .collect();
        let (wall, ns, new, hit) = timed(&table, &held, threads);
        // ... and the same count of accounts the table has never seen.
        let fresh: Vec<Address> = (0..326_000u64).map(|i| recipient(2_000_000 + round * 326_000 + i)).collect();
        let (fwall, fns, fnew, fhit) = timed(&table, &fresh, threads);
        let (swall, sns, _, _) = timed(&table, &held, 1);
        println!(
            "round {round}: held 326k on {threads}: {wall:.2} ms wall, {ns:.0} ns a resolve (new {new} hit {hit}); \
             new 326k: {fwall:.2} ms, {fns:.0} ns (new {fnew} hit {fhit}); held on 1 thread: {swall:.1} ms, {sns:.0} ns; size {}",
            table.len()
        );
    }
}
