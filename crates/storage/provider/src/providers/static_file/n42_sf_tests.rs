// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42: the `Transactions` static-file segment on 0x50 transfers.
//!
//! The tests write the same blocks through the serial path (one
//! `append_transaction` a row) and the parallel-encode path
//! (`N42_SF_PARALLEL_ENCODE=1`), then compare every file byte for byte, read
//! the rows back through the unmodified reader, unwind, heal after a crash
//! and mix both paths in one file.
//!
//! `bench_sf_transactions_200k` (ignored, run by hand) splits one 200k-transfer
//! block's segment write into its parts: encoding, the append loop, the sync,
//! and the raw cost of the same bytes; `bench_sf_transactions_batch` times a
//! five-block batch under each switch.

#[cfg(test)]
mod tests {
    use crate::providers::{
        static_file::{
            manager::{StaticFileProviderBuilder, StaticFileWriter},
            n42_sf::{append_block_transactions, encode_parallel},
        },
        StaticFileProvider,
    };
    use alloy_primitives::{Address, Bytes, U256};
    use n42_tx_types::{
        alt_sig::{AltSigTx, TxAltSig, ALG_ED25519},
        envelope::N42TxEnvelope,
        primitives::N42Primitives,
    };
    use reth_codecs::Compact;
    use reth_static_file_types::StaticFileSegment;
    use reth_storage_api::TransactionsProvider;
    use std::{
        collections::BTreeMap,
        io::Write as _,
        path::{Path, PathBuf},
        time::Instant,
    };

    /// A 0x50 transfer of the flood's shape: random key, signature and
    /// recipient, so nothing in it is compressible. The hash is the real one
    /// (the storage decode checks it in debug builds).
    fn transfer(i: u64) -> N42TxEnvelope {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&i.to_le_bytes());
        let h = alloy_primitives::keccak256(seed);
        let h2 = alloy_primitives::keccak256(h);
        let h3 = alloy_primitives::keccak256(h2);
        let tx = TxAltSig {
            chain_id: 94,
            nonce: i % 1000,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            to: Address::from_slice(&h2[..20]),
            value: U256::from(1_000_000_000_000u64 + i),
            input: Bytes::new(),
            access_list: Default::default(),
            alg_type: ALG_ED25519,
            pubkey: Bytes::copy_from_slice(h.as_slice()),
        };
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(h2.as_slice());
        sig[32..].copy_from_slice(h3.as_slice());
        N42TxEnvelope::AltSig(AltSigTx::new(tx, Bytes::copy_from_slice(&sig)))
    }

    /// An Ethereum transaction (tag 0 rows), so a block mixes both row kinds.
    fn eth_tx(i: u64) -> N42TxEnvelope {
        use alloy_consensus::{Signed, TxEip1559};
        let tx = TxEip1559 {
            chain_id: 94,
            nonce: i,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1,
            to: alloy_primitives::TxKind::Call(Address::with_last_byte(i as u8)),
            value: U256::from(i),
            input: Bytes::from(vec![i as u8; (i % 70) as usize]),
            ..Default::default()
        };
        let sig = alloy_primitives::Signature::test_signature();
        let signed = Signed::new_unhashed(tx, sig);
        N42TxEnvelope::Eth(reth_ethereum_primitives::TransactionSigned::from(signed))
    }

    /// Blocks of these sizes; transaction `k` overall is `make(k)`.
    fn blocks(sizes: &[usize]) -> Vec<Vec<N42TxEnvelope>> {
        let mut k = 0u64;
        sizes
            .iter()
            .map(|&n| {
                (0..n)
                    .map(|_| {
                        k += 1;
                        if k.is_multiple_of(7) {
                            eth_tx(k)
                        } else {
                            transfer(k)
                        }
                    })
                    .collect()
            })
            .collect()
    }

    fn provider(dir: &Path, blocks_per_file: u64) -> StaticFileProvider<N42Primitives> {
        StaticFileProviderBuilder::read_write(dir)
            .with_blocks_per_file(blocks_per_file)
            .build()
            .expect("static file provider")
    }

    /// Writes `blocks` from block `first_block` and tx number `first_tx`, block by
    /// block through `append_block_transactions`, then commits.
    fn write(
        p: &StaticFileProvider<N42Primitives>,
        blocks: &[Vec<N42TxEnvelope>],
        first_block: u64,
        first_tx: u64,
        parallel: bool,
        writeback: bool,
    ) {
        let mut w = p.get_writer(first_block, StaticFileSegment::Transactions).expect("writer");
        let mut tx = first_tx;
        for (i, txs) in blocks.iter().enumerate() {
            w.increment_block(first_block + i as u64).expect("increment");
            append_block_transactions(&mut w, txs, tx, parallel).expect("append");
            if writeback {
                w.n42_start_writeback();
            }
            tx += txs.len() as u64;
        }
        w.commit().expect("commit");
    }

    /// Every file of the segment directory, by name.
    fn files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        for entry in std::fs::read_dir(dir).expect("dir") {
            let path = entry.expect("entry").path();
            if path.is_file() {
                let name = path.file_name().expect("name").to_string_lossy().to_string();
                if name.starts_with("static_file_transactions") {
                    out.insert(name, std::fs::read(&path).expect("read"));
                }
            }
        }
        out
    }

    fn assert_same_files(a: &Path, b: &Path) {
        let (fa, fb) = (files(a), files(b));
        assert!(!fa.is_empty(), "no transactions files in {a:?}");
        assert_eq!(fa.keys().collect::<Vec<_>>(), fb.keys().collect::<Vec<_>>());
        for (name, bytes) in &fa {
            assert!(bytes == &fb[name], "{name} differs ({} vs {} bytes)", bytes.len(), fb[name].len());
        }
    }

    fn assert_reads_back(p: &StaticFileProvider<N42Primitives>, blocks: &[Vec<N42TxEnvelope>]) {
        let all: Vec<_> = blocks.iter().flatten().collect();
        for (n, tx) in all.iter().enumerate() {
            let read = p.transaction_by_id(n as u64).expect("read").expect("present");
            assert_eq!(&read, *tx, "row {n}");
        }
        assert!(p.transaction_by_id(all.len() as u64).expect("read").is_none());
    }

    const SIZES: &[usize] = &[0, 3, 10_000, 1, 0, 20_000, 8_191, 8_192, 12_345];

    /// Writes `blocks` through `encode_parallel` and either append path.
    fn write_encoded(
        p: &StaticFileProvider<N42Primitives>,
        blocks: &[Vec<N42TxEnvelope>],
        bulk: bool,
    ) {
        let mut w = p.get_writer(0, StaticFileSegment::Transactions).expect("writer");
        let mut tx = 0u64;
        for (i, txs) in blocks.iter().enumerate() {
            w.increment_block(i as u64).expect("increment");
            for chunk in encode_parallel(txs) {
                w.n42_append_transactions_encoded_with(bulk, tx, &chunk.rows, &chunk.lens)
                    .expect("append");
                tx += chunk.lens.len() as u64;
            }
        }
        w.commit().expect("commit");
    }

    /// The bulk append leaves every file byte for byte as the per-row append does (the
    /// configuration file carries `rows` and `max_row_size`), including multi-chunk blocks
    /// and empty ones, and the rows read back.
    #[test]
    fn bulk_append_is_byte_identical_and_readable() {
        let blocks = blocks(SIZES);
        let (a, b) = (tempfile::tempdir().expect("tmp"), tempfile::tempdir().expect("tmp"));
        let (pa, pb) = (provider(a.path(), 4), provider(b.path(), 4));
        write_encoded(&pa, &blocks, false);
        write_encoded(&pb, &blocks, true);
        assert_same_files(a.path(), b.path());
        assert_reads_back(&pa, &blocks);
        assert_reads_back(&pb, &blocks);
    }

    #[test]
    fn parallel_encode_is_byte_identical_and_readable() {
        let blocks = blocks(SIZES);
        for writeback in [false, true] {
            let (a, b) = (tempfile::tempdir().expect("tmp"), tempfile::tempdir().expect("tmp"));
            let (pa, pb) = (provider(a.path(), 4), provider(b.path(), 4));
            write(&pa, &blocks, 0, 0, false, false);
            write(&pb, &blocks, 0, 0, true, writeback);
            assert_same_files(a.path(), b.path());
            assert_reads_back(&pa, &blocks);
            assert_reads_back(&pb, &blocks);
        }
    }

    #[test]
    fn encode_parallel_chunks_are_the_serial_encoding() {
        let txs: Vec<_> = blocks(&[30_000]).remove(0);
        let mut serial = Vec::new();
        for tx in &txs {
            tx.to_compact(&mut serial);
        }
        let chunks = encode_parallel(&txs);
        assert!(chunks.len() > 1);
        assert_eq!(chunks.iter().map(|c| c.lens.len()).sum::<usize>(), txs.len());
        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.rows.iter().copied()).collect();
        assert_eq!(joined, serial);
    }

    /// Both paths in one file, in either order, and a node reopening files the
    /// other path wrote.
    #[test]
    fn paths_mix_in_one_file_and_across_restarts() {
        let blocks = blocks(SIZES);
        let reference = tempfile::tempdir().expect("tmp");
        write(&provider(reference.path(), 4), &blocks, 0, 0, false, false);

        for fast_first in [true, false] {
            let dir = tempfile::tempdir().expect("tmp");
            let split = 4;
            let first_tx = blocks[..split].iter().map(Vec::len).sum::<usize>() as u64;
            {
                let p = provider(dir.path(), 4);
                write(&p, &blocks[..split], 0, 0, fast_first, false);
            }
            // A restart: a new provider opens the files the other path wrote.
            let p = provider(dir.path(), 4);
            write(&p, &blocks[split..], split as u64, first_tx, !fast_first, false);
            assert_same_files(reference.path(), dir.path());
            assert_reads_back(&p, &blocks);
        }
    }

    /// Unwinding rows the fast path wrote, then writing again, leaves what the
    /// serial path leaves.
    #[test]
    fn unwind_after_parallel_encode() {
        let blocks = blocks(SIZES);
        let total: usize = blocks.iter().map(Vec::len).sum();
        let last = blocks.len() - 1;
        let mut dirs = Vec::new();
        for parallel in [false, true] {
            let dir = tempfile::tempdir().expect("tmp");
            let p = provider(dir.path(), 100);
            write(&p, &blocks, 0, 0, parallel, false);
            // Unwind the last two blocks.
            let removed = blocks[last - 1].len() + blocks[last].len();
            {
                let mut w = p.latest_writer(StaticFileSegment::Transactions).expect("writer");
                w.prune_transactions(removed as u64, (last - 2) as u64).expect("prune");
                w.commit().expect("commit");
            }
            assert!(p.transaction_by_id((total - removed) as u64).expect("read").is_none());
            // And write them again.
            write(
                &p,
                &blocks[last - 1..],
                (last - 1) as u64,
                (total - removed) as u64,
                parallel,
                false,
            );
            assert_reads_back(&p, &blocks);
            dirs.push(dir);
        }
        assert_same_files(dirs[0].path(), dirs[1].path());
    }

    /// A crash after the rows were synced but before the configuration was
    /// written: the consistency check at the next open heals both paths' files
    /// to the same state.
    #[test]
    fn crash_heal_after_parallel_encode() {
        let blocks = blocks(SIZES);
        let committed = 5;
        let mut dirs = Vec::new();
        for parallel in [false, true] {
            let dir = tempfile::tempdir().expect("tmp");
            {
                let p = provider(dir.path(), 100);
                write(&p, &blocks[..committed], 0, 0, parallel, false);
                let first_tx = blocks[..committed].iter().map(Vec::len).sum::<usize>() as u64;
                let mut w = p.latest_writer(StaticFileSegment::Transactions).expect("writer");
                let mut tx = first_tx;
                for (i, txs) in blocks[committed..].iter().enumerate() {
                    w.increment_block((committed + i) as u64).expect("increment");
                    append_block_transactions(&mut w, txs, tx, parallel).expect("append");
                    tx += txs.len() as u64;
                }
                // Data and offsets reach the disk; the configuration does not.
                w.sync_all().expect("sync");
            }
            let p = provider(dir.path(), 100);
            // Opening the writer runs the jar's consistency check (the heal).
            drop(p.latest_writer(StaticFileSegment::Transactions).expect("writer"));
            assert_reads_back(&p, &blocks[..committed]);
            dirs.push(dir);
        }
        assert_same_files(dirs[0].path(), dirs[1].path());
    }

    fn bench_dir() -> PathBuf {
        let base = std::env::var("N42_SF_BENCH_DIR")
            .unwrap_or_else(|_| "/data/n42-build/agents/persist-sf/bench".to_string());
        let dir = PathBuf::from(base).join(format!("run-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("bench dir");
        dir
    }

    fn ms(t: Instant) -> f64 {
        t.elapsed().as_secs_f64() * 1e3
    }

    #[test]
    #[ignore = "benchmark: writes ~40 MB to N42_SF_BENCH_DIR"]
    fn bench_sf_transactions_200k() {
        const N: u64 = 200_000;
        let txs: Vec<N42TxEnvelope> = (0..N).map(transfer).collect();
        let dir = bench_dir();

        for rep in 0..3 {
            // 1. Encoding alone, serial, into one buffer.
            let t = Instant::now();
            let mut all = Vec::with_capacity(48 << 20);
            let mut lens = Vec::with_capacity(N as usize);
            for tx in &txs {
                let before = all.len();
                tx.to_compact(&mut all);
                lens.push((all.len() - before) as u32);
            }
            let encode_ms = ms(t);
            let bytes = all.len();

            // 2. The same, in chunks on the global rayon pool.
            let t = Instant::now();
            let chunks = encode_parallel(&txs);
            let par_encode_ms = ms(t);
            assert_eq!(chunks.iter().map(|c| c.rows.len()).sum::<usize>(), bytes);

            // 3. The segment write as `write_transactions` does it, then its sync.
            let provider: StaticFileProvider<N42Primitives> =
                StaticFileProviderBuilder::read_write(dir.join(format!("sf-{rep}")))
                    .with_metrics()
                    .build()
                    .expect("sf");
            let t = Instant::now();
            let mut w = provider.get_writer(0, StaticFileSegment::Transactions).expect("writer");
            w.increment_block(0).expect("block");
            for (i, tx) in txs.iter().enumerate() {
                w.append_transaction(i as u64, tx).expect("append");
            }
            let append_ms = ms(t);
            let t = Instant::now();
            w.sync_all().expect("sync");
            let sync_ms = ms(t);
            drop(w);
            let t = Instant::now();
            provider.finalize().expect("finalize");
            let finalize_ms = ms(t);

            // 4. Pre-encoded rows through the writer's bulk append (per-row jar append).
            let provider2: StaticFileProvider<N42Primitives> =
                StaticFileProviderBuilder::read_write(dir.join(format!("pre-{rep}")))
                    .build()
                    .expect("sf");
            let mut w2 = provider2.get_writer(0, StaticFileSegment::Transactions).expect("writer");
            w2.increment_block(0).expect("block");
            let t = Instant::now();
            w2.append_transactions_encoded(0, &all, &lens).expect("append");
            let pre_append_ms = ms(t);
            let t = Instant::now();
            w2.sync_all().expect("sync");
            let pre_sync_ms = ms(t);
            drop(w2);

            // 5. Raw: a memcpy of the bytes, one write, one fsync.
            let t = Instant::now();
            let copy = all.clone();
            let memcpy_ms = ms(t);
            let t = Instant::now();
            let mut f = std::fs::File::create(dir.join(format!("raw-{rep}"))).expect("raw");
            f.write_all(&copy).expect("write");
            let raw_write_ms = ms(t);
            let t = Instant::now();
            f.sync_all().expect("fsync");
            let raw_sync_ms = ms(t);

            eprintln!(
                "rep {rep}: {N} txs, {bytes} B ({:.1} B/row) | encode serial {encode_ms:.1} ms, \
                 parallel {par_encode_ms:.1} ms | append_transaction loop {append_ms:.1} ms, \
                 sync_all {sync_ms:.1} ms, finalize {finalize_ms:.1} ms | pre-encoded bulk \
                 append {pre_append_ms:.1} ms, sync {pre_sync_ms:.1} ms | raw memcpy \
                 {memcpy_ms:.1} ms, one write {raw_write_ms:.1} ms, fsync {raw_sync_ms:.1} ms",
                bytes as f64 / N as f64
            );
        }
        if std::env::var("N42_SF_BENCH_KEEP").is_err() {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    #[ignore = "benchmark: writes ~190 MB a mode to N42_SF_BENCH_DIR"]
    fn bench_sf_transactions_batch() {
        const N: u64 = 200_000;
        const BLOCKS: u64 = 5;
        let txs: Vec<N42TxEnvelope> = (0..N).map(transfer).collect();
        let dir = bench_dir();
        for rep in 0..2 {
            for (name, parallel, writeback) in [
                ("serial", false, false),
                ("parallel", true, false),
                ("serial+writeback", false, true),
                ("parallel+writeback", true, true),
            ] {
                let p: StaticFileProvider<N42Primitives> =
                    StaticFileProviderBuilder::read_write(dir.join(format!("{name}-{rep}")))
                        .with_metrics()
                        .build()
                        .expect("sf");
                let start = Instant::now();
                let mut w = p.get_writer(0, StaticFileSegment::Transactions).expect("writer");
                let mut per_block = Vec::new();
                for b in 0..BLOCKS {
                    let t = Instant::now();
                    w.increment_block(b).expect("block");
                    append_block_transactions(&mut w, &txs, b * N, parallel).expect("append");
                    if writeback {
                        w.n42_start_writeback();
                    }
                    per_block.push(ms(t));
                }
                let t = Instant::now();
                w.sync_all().expect("sync");
                let sync_ms = ms(t);
                let total_ms = ms(start);
                drop(w);
                p.finalize().expect("finalize");
                let appends: Vec<String> = per_block.iter().map(|v| format!("{v:.1}")).collect();
                eprintln!(
                    "rep {rep} {name:>18}: {BLOCKS} x {N} txs | per block [{}] ms | sync_all \
                     {sync_ms:.1} ms | task {total_ms:.1} ms = {:.1} ms a block",
                    appends.join(", "),
                    total_ms / BLOCKS as f64
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
