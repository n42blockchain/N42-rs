// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The QMDB root of a near-empty block, as a catch-up run computes it.
//!
//! `n42Engine_importRange` files one QMDB version per block from a worker
//! thread that is not one of rayon's (`bin/n42/src/catchup_import.rs`): on an
//! empty chain that root is what bounds the pull (`docs/P1_CATCHUP_PERF.md`
//! step 7, `docs/P1_RUN_ROOT_DESIGN.md`). This seeds a forest with `--live`
//! accounts in an entry file, then times `--rounds` blocks that each rewrite
//! `--updates` live keys (the reward accounts) and append `--appends` new
//! ones (the system contracts' ring-buffer slots), from a plain thread, the
//! way the import's root worker does: `compute_operations`, `insert`, and --
//! untimed, every `--run` blocks -- the canonical head.
//!
//! ```text
//! RAYON_NUM_THREADS=8 cargo run --release -p n42-qmdb-reth --example empty_block_root_bench -- \
//!   --entry-dir /data/n42-build/scratch
//! ```
//!
//! `--small-ops <n>` sets the block size up to which the apply stays on the
//! calling thread (`N42_QMDB_SMALL_APPLY_OPS`; 0 turns it off) for this run.

use alloy_primitives::{B256, U256};
use n42_qmdb_state::QmdbForest;
use n42_twig_core::qmdb_compat::{encode_gov5_account_value, gov5_account_key, QmdbCompatTree, QmdbOps};
use std::time::Instant;

fn key(n: u64) -> [u8; 32] {
    let mut bytes = [0u8; 20];
    bytes[..8].copy_from_slice(&n.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes());
    bytes[12..].copy_from_slice(&n.to_be_bytes());
    gov5_account_key(&bytes)
}

fn value(nonce: u64, balance: u64) -> Vec<u8> {
    encode_gov5_account_value(nonce, &U256::from(balance).to_be_bytes::<32>(), &alloy_primitives::KECCAK256_EMPTY.0)
}

fn quantile(values: &[u64], q: f64) -> u64 {
    let mut values = values.to_vec();
    values.sort_unstable();
    values.get(((values.len() as f64 - 1.0) * q) as usize).copied().unwrap_or(0)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut live, mut updates, mut appends, mut rounds, mut warm, mut run) = (100_000u64, 2u64, 3u64, 20_000u64, 2_000u64, 128u64);
    let mut entry_dir: Option<std::path::PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut next = || args.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--live" => live = next()?.parse()?,
            "--updates" => updates = next()?.parse()?,
            "--appends" => appends = next()?.parse()?,
            "--rounds" => rounds = next()?.parse()?,
            "--warm" => warm = next()?.parse()?,
            "--run" => run = next()?.parse()?,
            "--entry-dir" => entry_dir = Some(next()?.into()),
            "--small-ops" => n42_twig_core::qmdb_compat::set_small_apply_ops(Some(next()?.parse()?)),
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    eprintln!(
        "live {live} block: {updates} updates + {appends} appends, warm {warm} rounds {rounds} run {run} entry dir {entry_dir:?}, rayon threads {}, small apply up to {} ops",
        rayon::current_num_threads(),
        n42_twig_core::qmdb_compat::small_apply_ops(),
    );
    let mut tree = QmdbCompatTree::new();
    for chunk in (0..live).collect::<Vec<_>>().chunks(250_000) {
        let mut ops = QmdbOps::new();
        for n in chunk {
            ops.push(key(*n), Some(&value(0, 1 << 60)));
        }
        ops.sort();
        tree.apply_ops_phased(&ops)?;
    }
    let mut forest = QmdbForest::from_tree(0, B256::with_last_byte(1), tree);
    let entry_path = entry_dir.as_ref().map(|dir| dir.join(format!("empty-block-root-bench-{}.entries", std::process::id())));
    if let Some(path) = &entry_path {
        std::fs::create_dir_all(path.parent().unwrap_or_else(|| std::path::Path::new(".")))?;
        forest = forest.with_entry_file(path)?;
    }

    // Off rayon's pool, as the import's root worker is.
    let worker = std::thread::spawn(move || -> Result<(QmdbForest, Vec<[u64; 14]>, B256, u64), String> {
        let mut parent = B256::with_last_byte(1);
        let mut rows = Vec::with_capacity(rounds as usize);
        let mut pending_canonical = Vec::new();
        let mut wall_us = 0u64;
        for block in 1..=warm + rounds {
            let mut ops = QmdbOps::new();
            for k in 0..updates {
                ops.push(key((block + k * 7919) % live.max(1)), Some(&value(block, (1 << 60) + block)));
            }
            for k in 0..appends {
                ops.push(key(live + block * appends + k), Some(&value(0, block)));
            }
            ops.sort();
            let hash = B256::from(U256::from(block + 1));
            let at = Instant::now();
            let prepared = forest.compute_operations(parent, ops).map_err(|e| e.to_string())?;
            let compute_us = at.elapsed().as_nanos() as u64;
            let root = prepared.root;
            forest.insert(hash, block, prepared).map_err(|e| e.to_string())?;
            let total = at.elapsed().as_nanos() as u64;
            std::hint::black_box(root);
            let (move_us, p) = forest.last_compute();
            let (note_us, delta_us, apply_us) = forest.last_compute_tail();
            if block > warm {
                wall_us += total;
                rows.push([
                    total,
                    compute_us,
                    move_us * 1000,
                    apply_us * 1000,
                    p.sort_us * 1000,
                    p.leaves_us * 1000,
                    p.undo_us * 1000,
                    p.retire_us.saturating_sub(p.undo_us) * 1000,
                    p.writes_us * 1000,
                    p.index_us * 1000,
                    p.rehash_us * 1000,
                    p.root_us * 1000,
                    note_us * 1000,
                    delta_us * 1000,
                ]);
            }
            parent = hash;
            pending_canonical.push(hash);
            if pending_canonical.len() as u64 >= run {
                for hash in pending_canonical.drain(..) {
                    forest.set_canonical(hash).map_err(|e| e.to_string())?;
                }
            }
        }
        Ok((forest, rows, parent, wall_us))
    });
    let (forest, rows, head, wall_ns) = worker.join().map_err(|_| "the worker panicked")??;
    let names = [
        "root (compute+insert)",
        "  compute",
        "    move",
        "    apply",
  "      dupcheck",
        "      leaves+lookups",
        "      undo",
        "      retire",
        "      writes",
        "      index",
        "      rehash",
        "      upper",
        "    note",
        "    delta",
    ];
    println!("over {} blocks, microseconds (median / p90 / mean); sub-phases have 1 us resolution:", rows.len());
    for (i, name) in names.iter().enumerate() {
        let column: Vec<u64> = rows.iter().map(|row| row[i]).collect();
        let mean = column.iter().sum::<u64>() as f64 / column.len().max(1) as f64;
        println!("  {name:<24} {:>8.1} {:>8.1} {:>8.1}", quantile(&column, 0.5) as f64 / 1e3, quantile(&column, 0.9) as f64 / 1e3, mean / 1e3);
    }
    println!("root chain: {:.0} blocks/s; head root {}", rows.len() as f64 / (wall_ns as f64 / 1e9), forest.root_of(&head).unwrap_or_default());
    drop(forest);
    if let Some(path) = entry_path {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}
