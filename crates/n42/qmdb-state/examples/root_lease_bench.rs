// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Where a block's QMDB root goes under the forest's tree lease.
//!
//! Builds a forest of `--accounts` gov5 account leaves (optionally in an entry
//! file, as the fleet runs it), then computes `--blocks` blocks of `--ops`
//! account updates each (`--new` of them fresh accounts) through the same
//! path the node takes with `N42_QMDB_COMPUTE_OFFLOCK=1`: `lease_tree`,
//! `TreeLease::compute`, `return_tree`, `insert`, `set_canonical`. Prints the
//! lease hold and the apply's phases per block and their medians.
//!
//! ```text
//! RAYON_NUM_THREADS=16 cargo run --release -p n42-qmdb-state --example root_lease_bench -- \
//!     --accounts 4000000 --ops 200000 --blocks 12 --entry-dir /data/n42-build/scratch \
//!     --mode alternate
//! ```
//!
//! `--mode alternate` computes even blocks serially and odd ones with
//! `N42_QMDB_PARALLEL_APPLY` on, and prints a median table for each.

use alloy_primitives::B256;
use n42_qmdb_state::QmdbForest;
use n42_twig_core::qmdb_compat::{encode_gov5_account_value, gov5_account_key, QmdbCompatTree, QmdbOps};

struct Args {
    accounts: u64,
    ops: u64,
    new: u64,
    blocks: u64,
    entry_dir: Option<std::path::PathBuf>,
    /// `serial`, `parallel` or `alternate` (block by block, so both modes
    /// see the same machine); `env` follows `N42_QMDB_PARALLEL_APPLY`.
    mode: String,
}

fn parse() -> Result<Args, String> {
    let mut args = Args { accounts: 4_000_000, ops: 200_000, new: 0, blocks: 12, entry_dir: None, mode: "env".to_owned() };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        let number = |v: String| v.replace('_', "").parse::<u64>().map_err(|e| format!("{flag}: {e}"));
        match flag.as_str() {
            "--accounts" => args.accounts = number(value()?)?,
            "--ops" => args.ops = number(value()?)?,
            "--new" => args.new = number(value()?)?,
            "--blocks" => args.blocks = number(value()?)?,
            "--entry-dir" => args.entry_dir = Some(value()?.into()),
            "--mode" => args.mode = value()?,
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(args)
}

fn address(n: u64) -> [u8; 20] {
    let mut a = [0u8; 20];
    a[..8].copy_from_slice(&n.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes());
    a[12..].copy_from_slice(&n.to_be_bytes());
    a
}

fn account_value(out: &mut Vec<u8>, n: u64, round: u64) {
    let mut balance = [0u8; 32];
    balance[16..24].copy_from_slice(&(n ^ round).to_be_bytes());
    balance[24..].copy_from_slice(&(1_000_000_000_000_000_000u64 + round).to_be_bytes());
    out.extend_from_slice(&encode_gov5_account_value(round, &balance, &[0u8; 32]));
}

fn ops_for(accounts: impl Iterator<Item = u64>, round: u64) -> QmdbOps {
    let mut ops = QmdbOps::new();
    for n in accounts {
        ops.push_with(gov5_account_key(&address(n)), |out| account_value(out, n, round));
    }
    ops
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

/// One mode's lease holds, computes, applies (us) and phase rows.
type ModeStats = (Vec<u64>, Vec<u64>, Vec<u64>, Vec<Vec<u64>>);

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values.get(values.len() / 2).copied().unwrap_or(0)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse()?;
    eprintln!(
        "accounts {} ops {} (new {}) blocks {} entry file {:?} rayon threads {} mode {}",
        args.accounts,
        args.ops,
        args.new,
        args.blocks,
        args.entry_dir,
        rayon::current_num_threads(),
        args.mode,
    );
    let built_at = std::time::Instant::now();
    let mut tree = QmdbCompatTree::new();
    let mut next_account = 0u64;
    while next_account < args.accounts {
        let end = (next_account + 250_000).min(args.accounts);
        let mut ops = ops_for(next_account..end, 0);
        ops.sort();
        tree.apply_ops_phased(&ops)?;
        next_account = end;
    }
    let mut forest = QmdbForest::from_tree(0, B256::with_last_byte(1), tree);
    if let Some(dir) = &args.entry_dir {
        std::fs::create_dir_all(dir)?;
        forest = forest.with_entry_file(&dir.join(format!("root-lease-bench-{}.entries", std::process::id())))?;
    }
    eprintln!("built in {} ms", built_at.elapsed().as_millis());

    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut parent = B256::with_last_byte(1);
    // Per mode (0 serial, 1 parallel): holds, computes, applies, phase rows.
    let mut stats: [ModeStats; 2] = Default::default();
    for block in 1..=args.blocks {
        let parallel = match args.mode.as_str() {
            "serial" => false,
            "parallel" => true,
            "alternate" => block % 2 == 1,
            _ => n42_twig_core::qmdb_compat::parallel_apply_env(),
        };
        n42_twig_core::qmdb_compat::set_parallel_apply_on_this_thread(Some(parallel));
        let existing = args.ops - args.new.min(args.ops);
        let mut picked = std::collections::HashSet::with_capacity(existing as usize);
        while (picked.len() as u64) < existing {
            picked.insert(rng.next() % next_account);
        }
        let fresh = next_account..next_account + (args.ops - existing);
        next_account = fresh.end;
        let mut ops = ops_for(picked.into_iter().chain(fresh), block);
        ops.sort();

        // With the parallel apply the node hashes the leaves before it takes
        // the lease (`NodeState::with_leased_root`); so does the bench.
        let prehash_at = std::time::Instant::now();
        let leaves = parallel.then(|| n42_twig_core::qmdb_compat::LeafHashes::of(&ops));
        let prehash_us = prehash_at.elapsed().as_micros() as u64;
        let leased_at = std::time::Instant::now();
        let mut lease = forest.lease_tree(parent)?;
        let compute_at = std::time::Instant::now();
        let computed = lease.compute_with_leaves(ops, leaves.as_ref());
        let compute_us = compute_at.elapsed().as_micros() as u64;
        let (prepared, _) = forest.return_tree(lease, computed)?;
        let hold_us = leased_at.elapsed().as_micros() as u64;
        let (_, p) = forest.last_compute();
        let (note_us, delta_us, apply_us) = forest.last_compute_tail();
        let hash = B256::from(alloy_primitives::U256::from(block + 1));
        forest.insert(hash, block, prepared)?;
        forest.set_canonical(hash)?;
        parent = hash;
        println!(
            "block {block} {}: prehash {:.1} hold {:.1} ms compute {:.1} apply {:.1} | sort {} leaf_hashes {} lookups {} undo {} retire {} | writes {} (pairs {} undo {} twigs {} entries {} remove {}) index {} rehash {} root {} | delta {} note {} us",
            if parallel { "P" } else { "S" },
            prehash_us as f64 / 1e3,
            hold_us as f64 / 1e3,
            compute_us as f64 / 1e3,
            apply_us as f64 / 1e3,
            p.sort_us,
            p.leaf_hashes_us,
            p.leaves_us.saturating_sub(p.leaf_hashes_us),
            p.undo_us,
            p.retire_us.saturating_sub(p.undo_us),
            p.writes_us,
            p.writes_pairs_us,
            p.writes_undo_us,
            p.writes_twigs_us,
            p.writes_entries_us,
            p.writes_remove_us,
            p.index_us,
            p.rehash_us,
            p.root_us,
            delta_us,
            note_us,
        );
        // The first two blocks warm the scratch and the pools.
        if block > 2 {
            let (holds, computes, applies, rows) = &mut stats[usize::from(parallel)];
            holds.push(hold_us);
            applies.push(apply_us);
            computes.push(compute_us);
            rows.push(vec![
                prehash_us,
                p.sort_us,
                p.leaf_hashes_us,
                p.leaves_us.saturating_sub(p.leaf_hashes_us),
                p.undo_us,
                p.retire_us.saturating_sub(p.undo_us),
                p.writes_pairs_us,
                p.writes_undo_us,
                p.writes_twigs_us,
                p.writes_entries_us,
                p.writes_remove_us,
                p.writes_us,
                p.index_us,
                p.rehash_us,
                p.root_us,
                delta_us,
            ]);
        }
    }
    let names = [
        "prehash", "sort", "leaf_hashes", "lookups", "undo", "retire", "w.pairs", "w.undo", "w.twigs", "w.entries", "w.remove", "writes",
        "index", "rehash", "root", "delta",
    ];
    for (mode, (holds, computes, applies, rows)) in stats.iter_mut().enumerate() {
        if holds.is_empty() {
            continue;
        }
        println!(
            "median {} ({} blocks): hold {:.1} ms compute {:.1} apply {:.1}",
            if mode == 1 { "parallel" } else { "serial" },
            holds.len(),
            median(holds) as f64 / 1e3,
            median(computes) as f64 / 1e3,
            median(applies) as f64 / 1e3
        );
        for (i, name) in names.iter().enumerate() {
            let mut column: Vec<u64> = rows.iter().map(|row| row[i]).collect();
            println!("  {name:<12} {:>8.2} ms", median(&mut column) as f64 / 1e3);
        }
    }
    if let Some(dir) = &args.entry_dir {
        let _ = std::fs::remove_file(dir.join(format!("root-lease-bench-{}.entries", std::process::id())));
    }
    Ok(())
}
