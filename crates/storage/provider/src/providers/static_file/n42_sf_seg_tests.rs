// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42: the `Receipts` and `AccountChangeSets` segments written by the serial
//! path and by `N42_SF_PARALLEL_ENCODE=1`: every file compared byte for byte,
//! the rows read back through the unmodified reader, both paths mixed across a
//! reopen, an unwind and rewrite, and a crash heal.
//!
//! `bench_sf_receipts_changesets_batch` (ignored) times a five-block batch of
//! 200k receipts and 200k changeset entries under each switch.

#[cfg(test)]
mod tests {
    use crate::providers::{
        static_file::{
            manager::{StaticFileProviderBuilder, StaticFileWriter},
            n42_sf::{append_block_account_changeset, append_block_receipts},
        },
        StaticFileProvider,
    };
    use alloy_primitives::{Address, Bytes, Log, B256, U256};
    use n42_tx_types::{envelope::N42TxType, primitives::N42Primitives, Receipt};
    use reth_db_api::models::AccountBeforeTx;
    use reth_static_file_types::StaticFileSegment;
    use reth_storage_api::{ChangeSetReader, ReceiptProvider};
    use revm::{database::states::PlainStateReverts, state::AccountInfo};
    use std::{collections::BTreeMap, path::Path, time::Instant};

    type P = StaticFileProvider<N42Primitives>;

    const SIZES: &[usize] = &[0, 3, 10_000, 1, 0, 20_000, 8_191, 8_192, 12_345];

    fn provider(dir: &Path, blocks_per_file: u64) -> P {
        StaticFileProviderBuilder::read_write(dir)
            .with_blocks_per_file(blocks_per_file)
            .build()
            .expect("static file provider")
    }

    fn receipt(k: u64) -> Receipt {
        let logs = if k.is_multiple_of(11) {
            vec![Log::new_unchecked(
                Address::with_last_byte(k as u8),
                vec![B256::with_last_byte(k as u8)],
                Bytes::from(vec![k as u8; (k % 40) as usize]),
            )]
        } else {
            Vec::new()
        };
        Receipt {
            tx_type: if k.is_multiple_of(7) {
                N42TxType::Eth(alloy_consensus::TxType::Eip1559)
            } else {
                N42TxType::AltSig
            },
            success: !k.is_multiple_of(13),
            cumulative_gas_used: 21_000 * (k % 200_000 + 1),
            logs,
        }
    }

    fn receipt_blocks(sizes: &[usize]) -> Vec<Vec<Receipt>> {
        let mut k = 0u64;
        sizes
            .iter()
            .map(|&n| {
                (0..n)
                    .map(|_| {
                        k += 1;
                        receipt(k)
                    })
                    .collect()
            })
            .collect()
    }

    /// Reverts of `n` distinct addresses in hash order (unsorted), some
    /// created in the block (`None`), split over two transitions.
    fn reverts(block: u64, n: usize) -> PlainStateReverts {
        let entry = |i: usize| {
            let mut seed = [0u8; 16];
            seed[..8].copy_from_slice(&block.to_le_bytes());
            seed[8..].copy_from_slice(&(i as u64).to_le_bytes());
            let address = Address::from_slice(&alloy_primitives::keccak256(seed)[..20]);
            let info = (!i.is_multiple_of(9)).then(|| AccountInfo {
                balance: U256::from(i as u64 * 1_000_003),
                nonce: i as u64 % 977,
                ..Default::default()
            });
            (address, info)
        };
        let split = n / 3;
        let mut second: Vec<_> = (split..n).map(entry).collect();
        // Every 1,000th address of the first transition again in the second, with another
        // value: the sort must keep the two in their order (it is stable).
        for i in (0..split).step_by(1000) {
            let (address, _) = entry(i);
            second.push((address, Some(AccountInfo { nonce: 7, ..Default::default() })));
        }
        PlainStateReverts {
            accounts: vec![(0..split).map(entry).collect(), second],
            storage: Vec::new(),
        }
    }

    fn write_receipts(p: &P, blocks: &[Vec<Receipt>], first_block: u64, first_tx: u64, parallel: bool) {
        let mut w = p.get_writer(first_block, StaticFileSegment::Receipts).expect("writer");
        let mut tx = first_tx;
        for (i, receipts) in blocks.iter().enumerate() {
            w.increment_block(first_block + i as u64).expect("increment");
            append_block_receipts(&mut w, receipts, tx, parallel).expect("append");
            tx += receipts.len() as u64;
        }
        w.commit().expect("commit");
    }

    fn write_changesets(p: &P, sizes: &[usize], first_block: u64, parallel: bool) {
        let mut w = p.get_writer(first_block, StaticFileSegment::AccountChangeSets).expect("writer");
        for (i, &n) in sizes.iter().enumerate() {
            let block = first_block + i as u64;
            append_block_account_changeset(&mut w, &reverts(block, n), block, parallel)
                .expect("append");
        }
        w.commit().expect("commit");
    }

    fn files(dir: &Path, prefix: &str) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        for entry in std::fs::read_dir(dir).expect("dir") {
            let path = entry.expect("entry").path();
            let name = path.file_name().expect("name").to_string_lossy().to_string();
            if path.is_file() && name.starts_with(prefix) {
                out.insert(name, std::fs::read(&path).expect("read"));
            }
        }
        out
    }

    fn assert_same_files(a: &Path, b: &Path, prefix: &str) {
        let (fa, fb) = (files(a, prefix), files(b, prefix));
        assert!(!fa.is_empty(), "no {prefix} files in {a:?}");
        assert_eq!(fa.keys().collect::<Vec<_>>(), fb.keys().collect::<Vec<_>>());
        for (name, bytes) in &fa {
            assert!(bytes == &fb[name], "{name} differs ({} vs {} bytes)", bytes.len(), fb[name].len());
        }
    }

    const RECEIPTS: &str = "static_file_receipts";
    const CHANGESETS: &str = "static_file_account-change-sets";

    fn assert_receipts_read_back(p: &P, blocks: &[Vec<Receipt>]) {
        let all: Vec<_> = blocks.iter().flatten().collect();
        for (n, r) in all.iter().enumerate() {
            assert_eq!(&p.receipt(n as u64).expect("read").expect("present"), *r, "row {n}");
        }
        assert!(p.receipt(all.len() as u64).expect("read").is_none());
    }

    fn assert_changesets_read_back(p: &P, sizes: &[usize], first_block: u64) {
        for (i, &n) in sizes.iter().enumerate() {
            let block = first_block + i as u64;
            let mut expected: Vec<AccountBeforeTx> = reverts(block, n)
                .accounts
                .iter()
                .flatten()
                .map(|(address, info)| AccountBeforeTx {
                    address: *address,
                    info: info.clone().map(Into::into),
                })
                .collect();
            expected.sort_by_key(|c| c.address);
            assert_eq!(p.account_block_changeset(block).expect("read"), expected, "block {block}");
        }
    }

    #[test]
    fn receipts_parallel_is_byte_identical_and_readable() {
        let blocks = receipt_blocks(SIZES);
        let (a, b) = (tempfile::tempdir().expect("tmp"), tempfile::tempdir().expect("tmp"));
        let (pa, pb) = (provider(a.path(), 4), provider(b.path(), 4));
        write_receipts(&pa, &blocks, 0, 0, false);
        write_receipts(&pb, &blocks, 0, 0, true);
        assert_same_files(a.path(), b.path(), RECEIPTS);
        assert_receipts_read_back(&pa, &blocks);
        assert_receipts_read_back(&pb, &blocks);
    }

    #[test]
    fn changesets_parallel_is_byte_identical_and_readable() {
        let (a, b) = (tempfile::tempdir().expect("tmp"), tempfile::tempdir().expect("tmp"));
        let (pa, pb) = (provider(a.path(), 4), provider(b.path(), 4));
        write_changesets(&pa, SIZES, 0, false);
        write_changesets(&pb, SIZES, 0, true);
        assert_same_files(a.path(), b.path(), CHANGESETS);
        assert_changesets_read_back(&pa, SIZES, 0);
        assert_changesets_read_back(&pb, SIZES, 0);
    }

    #[test]
    fn both_segments_mix_paths_across_a_reopen() {
        let blocks = receipt_blocks(SIZES);
        let reference = tempfile::tempdir().expect("tmp");
        {
            let p = provider(reference.path(), 4);
            write_receipts(&p, &blocks, 0, 0, false);
            write_changesets(&p, SIZES, 0, false);
        }
        let split = 4;
        let first_tx = blocks[..split].iter().map(Vec::len).sum::<usize>() as u64;
        for fast_first in [true, false] {
            let dir = tempfile::tempdir().expect("tmp");
            {
                let p = provider(dir.path(), 4);
                write_receipts(&p, &blocks[..split], 0, 0, fast_first);
                write_changesets(&p, &SIZES[..split], 0, fast_first);
            }
            let p = provider(dir.path(), 4);
            write_receipts(&p, &blocks[split..], split as u64, first_tx, !fast_first);
            write_changesets(&p, &SIZES[split..], split as u64, !fast_first);
            assert_same_files(reference.path(), dir.path(), RECEIPTS);
            assert_same_files(reference.path(), dir.path(), CHANGESETS);
            assert_receipts_read_back(&p, &blocks);
            assert_changesets_read_back(&p, SIZES, 0);
        }
    }

    #[test]
    fn both_segments_unwind_and_rewrite() {
        let blocks = receipt_blocks(SIZES);
        let total: usize = blocks.iter().map(Vec::len).sum();
        let last = blocks.len() - 1;
        let removed = blocks[last - 1].len() + blocks[last].len();
        let mut dirs = Vec::new();
        for parallel in [false, true] {
            let dir = tempfile::tempdir().expect("tmp");
            let p = provider(dir.path(), 100);
            write_receipts(&p, &blocks, 0, 0, parallel);
            write_changesets(&p, SIZES, 0, parallel);
            {
                let mut w = p.latest_writer(StaticFileSegment::Receipts).expect("writer");
                w.prune_receipts(removed as u64, (last - 2) as u64).expect("prune");
                w.commit().expect("commit");
                let mut w = p.latest_writer(StaticFileSegment::AccountChangeSets).expect("writer");
                w.prune_account_changesets((last - 2) as u64).expect("prune");
                w.commit().expect("commit");
            }
            assert!(p.receipt((total - removed) as u64).expect("read").is_none());
            write_receipts(&p, &blocks[last - 1..], (last - 1) as u64, (total - removed) as u64, parallel);
            write_changesets(&p, &SIZES[last - 1..], (last - 1) as u64, parallel);
            assert_receipts_read_back(&p, &blocks);
            assert_changesets_read_back(&p, SIZES, 0);
            dirs.push(dir);
        }
        assert_same_files(dirs[0].path(), dirs[1].path(), RECEIPTS);
        assert_same_files(dirs[0].path(), dirs[1].path(), CHANGESETS);
    }

    /// Rows and the changeset sidecar synced, configuration not written: the
    /// next open heals both paths' files to the same state.
    #[test]
    fn both_segments_crash_heal() {
        let blocks = receipt_blocks(SIZES);
        let committed = 5;
        let mut dirs = Vec::new();
        for parallel in [false, true] {
            let dir = tempfile::tempdir().expect("tmp");
            {
                let p = provider(dir.path(), 100);
                write_receipts(&p, &blocks[..committed], 0, 0, parallel);
                write_changesets(&p, &SIZES[..committed], 0, parallel);
                let mut tx = blocks[..committed].iter().map(Vec::len).sum::<usize>() as u64;
                let mut w = p.latest_writer(StaticFileSegment::Receipts).expect("writer");
                for (i, receipts) in blocks[committed..].iter().enumerate() {
                    w.increment_block((committed + i) as u64).expect("increment");
                    append_block_receipts(&mut w, receipts, tx, parallel).expect("append");
                    tx += receipts.len() as u64;
                }
                w.sync_all().expect("sync");
                drop(w);
                let mut w = p.latest_writer(StaticFileSegment::AccountChangeSets).expect("writer");
                for (i, &n) in SIZES[committed..].iter().enumerate() {
                    let block = (committed + i) as u64;
                    append_block_account_changeset(&mut w, &reverts(block, n), block, parallel)
                        .expect("append");
                }
                w.sync_all().expect("sync");
            }
            let p = provider(dir.path(), 100);
            drop(p.latest_writer(StaticFileSegment::Receipts).expect("writer"));
            drop(p.latest_writer(StaticFileSegment::AccountChangeSets).expect("writer"));
            assert_receipts_read_back(&p, &blocks[..committed]);
            assert_changesets_read_back(&p, &SIZES[..committed], 0);
            assert!(p.account_block_changeset(committed as u64).expect("read").is_empty());
            dirs.push(dir);
        }
        assert_same_files(dirs[0].path(), dirs[1].path(), RECEIPTS);
        assert_same_files(dirs[0].path(), dirs[1].path(), CHANGESETS);
    }

    fn ms(t: Instant) -> f64 {
        t.elapsed().as_secs_f64() * 1e3
    }

    #[test]
    #[ignore = "benchmark: writes to N42_SF_BENCH_DIR"]
    fn bench_sf_receipts_changesets_batch() {
        const N: usize = 200_000;
        const BLOCKS: u64 = 5;
        let base = std::env::var("N42_SF_BENCH_DIR")
            .unwrap_or_else(|_| "/data/n42-build/agents/persist-sf/bench".to_string());
        let dir = Path::new(&base).join(format!("seg-{}", std::process::id()));
        let receipts: Vec<Receipt> = (1..=N as u64).map(receipt).collect();
        let block_reverts: Vec<_> = (0..BLOCKS).map(|b| reverts(b, N)).collect();
        for rep in 0..2 {
            for (name, parallel, writeback) in [
                ("serial", false, false),
                ("parallel", true, false),
                ("parallel+writeback", true, true),
            ] {
                let p: P = StaticFileProviderBuilder::read_write(dir.join(format!("{name}-{rep}")))
                    .with_metrics()
                    .build()
                    .expect("sf");
                // Receipts.
                let t = Instant::now();
                let mut w = p.get_writer(0, StaticFileSegment::Receipts).expect("writer");
                for b in 0..BLOCKS {
                    w.increment_block(b).expect("block");
                    append_block_receipts(&mut w, &receipts, b * N as u64, parallel).expect("append");
                    if writeback {
                        w.n42_start_writeback();
                    }
                }
                let r_append = ms(t);
                let t = Instant::now();
                w.sync_all().expect("sync");
                let r_sync = ms(t);
                drop(w);
                // Account changesets.
                let t = Instant::now();
                let mut w = p.get_writer(0, StaticFileSegment::AccountChangeSets).expect("writer");
                for (b, rv) in block_reverts.iter().enumerate() {
                    append_block_account_changeset(&mut w, rv, b as u64, parallel).expect("append");
                    if writeback {
                        w.n42_start_writeback();
                    }
                }
                let c_append = ms(t);
                let t = Instant::now();
                w.sync_all().expect("sync");
                let c_sync = ms(t);
                drop(w);
                p.finalize().expect("finalize");
                eprintln!(
                    "rep {rep} {name:>18}: receipts {:.1} ms a block (appends {r_append:.1}, sync \
                     {r_sync:.1}) | account changesets {:.1} ms a block (appends {c_append:.1}, \
                     sync {c_sync:.1})",
                    (r_append + r_sync) / BLOCKS as f64,
                    (c_append + c_sync) / BLOCKS as f64,
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
