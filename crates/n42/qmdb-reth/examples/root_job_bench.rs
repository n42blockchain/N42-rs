// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The leader's QMDB root job at the fleet7 X22 shape, without the fleet.
//!
//! Seeds a forest with `--live` gov5 accounts (the flood's recipients and
//! senders) in an entry file, ages it with `--warm` blocks, then times
//! `--rounds` blocks of `--recipients` transfers' worth of accounts each:
//! every step the leader's root job takes on the output-shard path with
//! `N42_ROOT_OPS_AHEAD`, `N42_ROOT_OPS_BEFORE_GATE`, `N42_QMDB_COMPUTE_OFFLOCK`
//! and `N42_QMDB_PARALLEL_APPLY` on:
//!
//! - `ahead`: `operations_ahead` over the shards' accounts (encode, sort);
//! - `finish`: `OpsAhead::finish` with the residual's few accounts;
//! - `prehash`: `sort_and_hash_leaves` (the leaf hashes before the gate);
//! - `compute`: the lease, `TreeLease::compute_with_leaves` (the apply by
//!   phase, the delta) and `return_tree`;
//! - then `insert` and `set_canonical`, untimed, as the node files the block.
//!
//! Prints a line a block and the medians. Run it as the node runs, e.g.
//!
//! ```text
//! N42_QMDB_PARALLEL_APPLY=1 N42_ROOT_UPPER_DIRTY=1 \
//!   cargo run --release -p n42-qmdb-reth --example root_job_bench -- \
//!   --entry-dir /data/n42-build/scratch --noise 16
//! ```
//!
//! `--noise <n>` runs n threads reading a 1 GB buffer at random throughout
//! (the next block's execution beside the root job), and `--sweep-mb`
//! streams that many MB through the caches before every timed block.

use alloy_primitives::{Address, B256, U256};
use evm2::evm::AccountInfo;
use n42_qmdb_state::QmdbForest;
use n42_twig_core::qmdb_compat::{encode_gov5_account_value, gov5_account_key, QmdbCompatTree, QmdbOps};
use reth_trie::bundle_state::{AccountStatus, BundleAccount};
use std::time::Instant;

struct Args {
    live: u64,
    senders: u64,
    recipients: u64,
    block_senders: u64,
    warm: u64,
    rounds: u64,
    entry_dir: Option<std::path::PathBuf>,
    noise: usize,
    sweep_mb: usize,
    /// CPUs the rayon pool's threads are pinned to (`a-b,c`), if any.
    pool_cpus: Option<Vec<usize>>,
    /// CPUs the noise threads are pinned to, if any.
    noise_cpus: Option<Vec<usize>>,
}

/// `a-b,c,d-e` as a CPU list.
fn cpu_list(text: &str) -> Result<Vec<usize>, String> {
    let mut cpus = Vec::new();
    for part in text.split(',') {
        let mut ends = part.splitn(2, '-').map(|n| n.trim().parse::<usize>().map_err(|e| format!("{part}: {e}")));
        let first = ends.next().ok_or("empty cpu list")??;
        let last = ends.next().transpose()?.unwrap_or(first);
        cpus.extend(first..=last);
    }
    Ok(cpus)
}

/// Pins the calling thread to `cpus`.
fn pin(cpus: &[usize]) {
    // SAFETY: a zeroed cpu_set_t is the empty set; CPU_SET writes inside it,
    // and sched_setaffinity reads it.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        for cpu in cpus {
            libc::CPU_SET(*cpu, &mut set);
        }
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw const set);
    }
}

fn parse() -> Result<Args, String> {
    let mut args = Args {
        live: 2_000_000,
        senders: 18_750,
        recipients: 191_000,
        block_senders: 400,
        warm: 40,
        rounds: 15,
        entry_dir: None,
        noise: 0,
        sweep_mb: 512,
        pool_cpus: None,
        noise_cpus: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        let number = |v: String| v.replace('_', "").parse::<u64>().map_err(|e| format!("{flag}: {e}"));
        match flag.as_str() {
            "--live" => args.live = number(value()?)?,
            "--senders" => args.senders = number(value()?)?,
            "--recipients" => args.recipients = number(value()?)?,
            "--block-senders" => args.block_senders = number(value()?)?,
            "--warm" => args.warm = number(value()?)?,
            "--rounds" => args.rounds = number(value()?)?,
            "--entry-dir" => args.entry_dir = Some(value()?.into()),
            "--noise" => args.noise = number(value()?)? as usize,
            "--sweep-mb" => args.sweep_mb = number(value()?)? as usize,
            "--pool-cpus" => args.pool_cpus = Some(cpu_list(&value()?)?),
            "--noise-cpus" => args.noise_cpus = Some(cpu_list(&value()?)?),
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(args)
}

/// The flood's recipient address (`tx_flood::recipient`).
fn recipient(n: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&(n as u32).to_be_bytes());
    bytes[4] = 0x42;
    Address::new(bytes)
}

/// A sender: any address apart from the recipients'.
fn sender(n: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..8].copy_from_slice(&n.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes());
    bytes[12..].copy_from_slice(&n.to_be_bytes());
    bytes[8] = 0x5e;
    Address::new(bytes)
}

fn info(nonce: u64, balance: u64) -> AccountInfo {
    AccountInfo { nonce, balance: U256::from(balance), code_hash: alloy_primitives::KECCAK256_EMPTY, code: None, ..Default::default() }
}

fn changed(nonce: u64, balance: u64) -> BundleAccount {
    BundleAccount::new(Some(info(nonce, balance.wrapping_sub(1))), Some(info(nonce, balance)), Default::default(), AccountStatus::Changed)
}

/// A deterministic xorshift, so every run draws the same blocks.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn median(values: &[u64]) -> u64 {
    let mut values = values.to_vec();
    values.sort_unstable();
    values.get(values.len() / 2).copied().unwrap_or(0)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse()?;
    if let Some(cpus) = args.pool_cpus.clone() {
        rayon::ThreadPoolBuilder::new().start_handler(move |_| pin(&cpus)).build_global()?;
    }
    eprintln!(
        "live {} senders {} block: {} senders + {} recipients, warm {} rounds {} entry dir {:?} noise {} sweep {} MB, rayon threads {}",
        args.live,
        args.senders,
        args.block_senders,
        args.recipients,
        args.warm,
        args.rounds,
        args.entry_dir,
        args.noise,
        args.sweep_mb,
        rayon::current_num_threads()
    );
    let prague = true;
    // Seed: every recipient and sender once, as a genesis alloc would.
    let built_at = Instant::now();
    let mut tree = QmdbCompatTree::new();
    let seed: Vec<Address> = (0..args.live).map(recipient).chain((0..args.senders).map(sender)).collect();
    for chunk in seed.chunks(250_000) {
        let mut ops = QmdbOps::new();
        for address in chunk {
            ops.push(gov5_account_key(&address.0 .0), Some(&encode_gov5_account_value(0, &U256::from(1u64 << 60).to_be_bytes::<32>(), &alloy_primitives::KECCAK256_EMPTY.0)));
        }
        ops.sort();
        tree.apply_ops_phased(&ops)?;
    }
    let mut forest = QmdbForest::from_tree(0, B256::with_last_byte(1), tree);
    let entry_path = args.entry_dir.as_ref().map(|dir| dir.join(format!("root-job-bench-{}.entries", std::process::id())));
    if let Some(path) = &entry_path {
        std::fs::create_dir_all(path.parent().unwrap_or_else(|| std::path::Path::new(".")))?;
        forest = forest.with_entry_file(path)?;
    }
    eprintln!("seeded in {} ms", built_at.elapsed().as_millis());

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let noisy: Vec<_> = (0..args.noise)
        .map(|t| {
            let stop = std::sync::Arc::clone(&stop);
            let cpus = args.noise_cpus.clone();
            std::thread::spawn(move || {
                if let Some(cpus) = cpus {
                    pin(&cpus);
                }
                let buffer = vec![1u64; 1 << 27];
                let (mut x, mut sum) = (t as u64 + 1, 0u64);
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    for _ in 0..4096 {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        sum = sum.wrapping_add(buffer[(x as usize) & ((1 << 27) - 1)]);
                    }
                }
                sum
            })
        })
        .collect();
    let mut sweep = vec![0u64; args.sweep_mb << 17];

    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut parent = B256::with_last_byte(1);
    let names = [
        "ahead.encode", "ahead.sort", "finish", "prehash", "ops total", "compute", "  dupcheck", "  lookups", "  undo", "  retire",
        "  writes", "    w.pairs", "    w.entries", "  index", "  rehash", "  upper", "  apply", "  delta", "  note+return", "job",
    ];
    let mut rows: Vec<Vec<u64>> = Vec::new();
    for block in 1..=args.warm + args.rounds {
        let timed = block > args.warm;
        // The block's accounts: senders with 500 transfers each, recipients
        // drawn from the live set (each once, as a bundle holds them).
        let mut picked = std::collections::HashSet::with_capacity(args.recipients as usize);
        while (picked.len() as u64) < args.recipients {
            picked.insert(rng.next() % args.live);
        }
        let mut senders = std::collections::HashSet::with_capacity(args.block_senders as usize);
        while (senders.len() as u64) < args.block_senders {
            senders.insert(rng.next() % args.senders);
        }
        let accounts: Vec<(Address, BundleAccount)> = picked
            .iter()
            .map(|n| (recipient(*n), changed(0, 1_000_000_000 + block * 7 + *n)))
            .chain(senders.iter().map(|n| (sender(*n), changed(block * 500, (1u64 << 60) - block * 1000))))
            .collect();
        // The residual: the fee recipient, the system contracts' slots, and
        // two shard accounts the executor changed again.
        let coinbase = Address::with_last_byte(0xcb);
        let mut beacon = changed(1, 0);
        beacon.storage.insert(U256::from(block % 8191), reth_trie::bundle_state::StorageSlot::new_changed(U256::ZERO, U256::from(block)));
        beacon.storage.insert(U256::from(block % 8191 + 8191), reth_trie::bundle_state::StorageSlot::new_changed(U256::ZERO, U256::from(block * 3)));
        let residual: Vec<(Address, BundleAccount)> = vec![
            (coinbase, changed(0, block * 21_000)),
            (alloy_primitives::address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02"), beacon),
            (accounts[0].0, changed(9, 77 + block)),
            (accounts[1].0, changed(9, 78 + block)),
        ];
        let shard_refs: Vec<(&Address, &BundleAccount)> = accounts.iter().map(|(a, b)| (a, b)).collect();
        let replaced: Vec<(&Address, &BundleAccount)> = accounts[..2].iter().map(|(a, b)| (a, b)).collect();
        let newer: Vec<(&Address, &BundleAccount)> = residual.iter().map(|(a, b)| (a, b)).collect();

        if timed && args.sweep_mb > 0 {
            use rayon::prelude::*;
            sweep.par_chunks_mut(1 << 16).for_each(|chunk| chunk.iter_mut().for_each(|w| *w = w.wrapping_add(1)));
        }
        let job_at = Instant::now();
        let ahead = n42_qmdb_reth::operations_ahead(&shard_refs, prague);
        let (encode_us, sort_us) = (ahead.encode_us, ahead.sort_us);
        let finish_at = Instant::now();
        let mut ops = ahead.finish(&replaced, &newer, prague);
        let finish_us = finish_at.elapsed().as_micros() as u64;
        let prehash_at = Instant::now();
        let leaves = n42_qmdb_reth::sort_and_hash_leaves(&mut ops);
        let prehash_us = prehash_at.elapsed().as_micros() as u64;
        let ops_us = job_at.elapsed().as_micros() as u64;
        let op_count = ops.len();
        let compute_at = Instant::now();
        let mut lease = forest.lease_tree(parent)?;
        let computed = lease.compute_with_leaves(ops, leaves.as_ref());
        let (prepared, _) = forest.return_tree(lease, computed)?;
        let compute_us = compute_at.elapsed().as_micros() as u64;
        let job_us = job_at.elapsed().as_micros() as u64;
        let (_, p) = forest.last_compute();
        let (_note_us, delta_us, apply_us) = forest.last_compute_tail();
        let hash = B256::from(U256::from(block + 1));
        forest.insert(hash, block, prepared)?;
        forest.set_canonical(hash)?;
        parent = hash;
        let row = vec![
            encode_us,
            sort_us,
            finish_us,
            prehash_us,
            ops_us,
            compute_us,
            p.sort_us,
            p.leaves_us,
            p.undo_us,
            p.retire_us.saturating_sub(p.undo_us),
            p.writes_us,
            p.writes_pairs_us,
            p.writes_entries_us,
            p.index_us,
            p.rehash_us,
            p.root_us,
            apply_us,
            delta_us,
            compute_us.saturating_sub(apply_us + delta_us),
            job_us,
        ];
        println!(
            "block {block}{} ops {op_count} twigs {} dirty {}: {}",
            if timed { "" } else { " (warm)" },
            p.twigs,
            p.dirty_twigs,
            names.iter().zip(&row).map(|(n, v)| format!("{}={:.1}", n.trim(), *v as f64 / 1e3)).collect::<Vec<_>>().join(" ")
        );
        if timed {
            rows.push(row);
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for thread in noisy {
        let _ = thread.join();
    }
    println!("medians over {} blocks (ms):", rows.len());
    for (i, name) in names.iter().enumerate() {
        let column: Vec<u64> = rows.iter().map(|row| row[i]).collect();
        println!("  {name:<14} {:>7.2}", median(&column) as f64 / 1e3);
    }
    if let Some(path) = &entry_path {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}
