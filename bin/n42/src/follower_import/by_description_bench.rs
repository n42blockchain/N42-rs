// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where a block described by its hashes (`N42_BLOCK_BY_DESCRIPTION`) spends
//! its road, measured on the fleet's shape: the flood's 0x50 transfers, the
//! queue filled by twelve ingest threads that decode what they queue from its
//! bytes the way the node's ingest does, a busy worker pool and the ingest
//! still pushing while the road runs.

use super::*;
use alloy_consensus::Header;
use alloy_primitives::{Bytes, U256};
use n42_engine_types::N42PooledTransaction;
use reth_revm::revm::database::{CacheDB, EmptyDB};
use reth_revm::revm::state::AccountInfo;

type Held = Arc<reth_transaction_pool::ValidPoolTransaction<N42PooledTransaction>>;

/// The flood's transfer: a 0x50 transaction under a per-sender key, with a
/// placeholder signature (nothing on this road verifies one) and its real
/// hash, so a body decoded from its bytes names the hashes the queue indexed.
pub(super) fn alt_transfer(key: u64, nonce: u64, to: Address, value: u128) -> TransactionSigned {
    let mut pubkey = [0u8; n42_tx_types::ED25519_PUBKEY_LEN];
    pubkey[..8].copy_from_slice(&key.to_be_bytes());
    pubkey[31] = 1;
    let tx = n42_tx_types::TxAltSig {
        chain_id: 1,
        nonce,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 10_000_000_000,
        gas_limit: 21_000,
        to,
        value: U256::from(value),
        input: Bytes::new(),
        access_list: Default::default(),
        alg_type: n42_tx_types::ALG_ED25519,
        pubkey: Bytes::copy_from_slice(&pubkey),
    };
    TransactionSigned::AltSig(n42_tx_types::AltSigTx::new(
        tx,
        Bytes::from(vec![9u8; n42_tx_types::ED25519_SIGNATURE_LEN]),
    ))
}

fn addr(i: u64) -> Address {
    let mut a = [0u8; 20];
    a[12..].copy_from_slice(&i.to_be_bytes());
    Address::from(a)
}

/// `senders x per` transfers to recipients drawn from `space` accounts, laid
/// out as the queue lays them out (`run` of a sender, then the next), with
/// `key_base` keeping two fixtures' senders apart.
fn fixture(key_base: u64, senders: u64, per: u64, space: u64, run: usize) -> (Vec<TransactionSigned>, Vec<Address>) {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64 ^ key_base;
    let lanes: Vec<Vec<TransactionSigned>> = (0..senders)
        .map(|s| {
            (0..per)
                .map(|k| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    alt_transfer(key_base + s, k, addr(1_000_000 + seed % space), 1_000 + u128::from(k))
                })
                .collect()
        })
        .collect();
    let mut txs = Vec::with_capacity((senders * per) as usize);
    let mut k = 0usize;
    while k < per as usize {
        for lane in &lanes {
            txs.extend(lane[k..(k + run).min(per as usize)].iter().cloned());
        }
        k += run;
    }
    let senders = txs.iter().map(|tx| tx.as_alt_sig().map_or(Address::ZERO, |alt| alt.sender())).collect();
    (txs, senders)
}

/// One shared copy of the bench's accounts, as a node's batches each open a
/// provider over one store.
#[derive(Debug, Clone)]
struct SharedDb(Arc<CacheDB<EmptyDB>>);

impl reth_revm::revm::Database for SharedDb {
    type Error = <CacheDB<EmptyDB> as reth_revm::revm::DatabaseRef>::Error;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        reth_revm::revm::DatabaseRef::basic_ref(&*self.0, address)
    }
    fn code_by_hash(&mut self, code_hash: B256) -> Result<reth_revm::revm::state::Bytecode, Self::Error> {
        reth_revm::revm::DatabaseRef::code_by_hash_ref(&*self.0, code_hash)
    }
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        reth_revm::revm::DatabaseRef::storage_ref(&*self.0, address, index)
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        reth_revm::revm::DatabaseRef::block_hash_ref(&*self.0, number)
    }
}

/// The transactions root over the queue's own transactions, encoded into one
/// buffer per chunk on the worker that reads them: no copy of a transaction
/// and no allocation per transaction.
fn root_over_held(held: &[Held]) -> B256 {
    use alloy_eips::Encodable2718 as _;
    use rayon::prelude::*;
    let chunk = held.len().div_ceil(128).max(1);
    let arenas: Vec<(Vec<u8>, Vec<usize>)> = held
        .par_chunks(chunk)
        .map(|chunk| {
            let mut buf = Vec::with_capacity(chunk.len() * 192);
            let mut ends = Vec::with_capacity(chunk.len());
            for tx in chunk {
                tx.transaction.transaction.inner().encode_2718(&mut buf);
                ends.push(buf.len());
            }
            (buf, ends)
        })
        .collect();
    let mut slices: Vec<&[u8]> = Vec::with_capacity(held.len());
    for (buf, ends) in &arenas {
        let mut start = 0;
        for &end in ends {
            slices.push(&buf[start..end]);
            start = end;
        }
    }
    n42_engine_types::assembler::parallel_ordered_trie_root(&slices)
}

/// `RAYON_NUM_THREADS=16 taskset -c 0-31 cargo test --release -p n42 --lib
/// bench_block_by_description -- --ignored --nocapture`.
/// `BENCH_SENDERS`/`BENCH_PER`/`BENCH_SPACE` shape the block (the defaults:
/// 380 x 429 over two million recipients, the fleet's).
#[test]
#[ignore = "timing"]
fn bench_block_by_description() {
    use alloy_eips::{Decodable2718 as _, Encodable2718 as _};
    use n42_h2_consensus::header_profile::N42HeaderProfile;
    use rayon::prelude::*;

    let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let (senders_n, per, space) = (env("BENCH_SENDERS", 380), env("BENCH_PER", 429), env("BENCH_SPACE", 2_000_000));
    let (txs, senders) = fixture(1 << 32, senders_n, per, space, 64);
    let count = txs.len();
    let header = Header {
        number: 20_000_000,
        beneficiary: addr(1),
        gas_limit: 10_000_000_000,
        base_fee_per_gas: Some(1_000_000_000),
        timestamp: 1_800_000_000,
        parent_beacon_block_root: Some(B256::ZERO),
        withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
        transactions_root: alloy_consensus::proofs::calculate_transaction_root(&txs),
        ..Default::default()
    };
    let announced = header.hash_slow();
    let raw: Vec<Bytes> = txs.par_iter().map(|tx| Bytes::from(tx.encoded_2718())).collect();
    let body = n42_h2_consensus::encode_block_rlp_raw(&header, &raw, &[], None);
    let hashes: Vec<B256> = txs.iter().map(|tx| *tx.tx_hash()).collect();
    let compact = n42_h2_consensus::encode_compact_body(&body, &hashes, N42HeaderProfile::Ethereum)
        .expect("the compact body encodes");

    // The queue as the ingest leaves it: twelve threads decoding every
    // transaction from its bytes and pushing it, interleaved with another
    // block's worth of other senders.
    let queue =
        Arc::new(n42_tx_queue::TxQueue::<N42PooledTransaction>::with_run_length(64).with_hash_index(count * 8));
    let (noise, noise_senders) = fixture(2 << 32, senders_n, per, space, 64);
    let noise_raw: Vec<Bytes> = noise.par_iter().map(|tx| Bytes::from(tx.encoded_2718())).collect();
    // What an ingest that kept each transaction's bytes would hold: the
    // frame's buffer, as the ingest reads it off the socket, one slice per
    // transaction.
    let kept_bytes: std::sync::Mutex<alloy_primitives::map::B256HashMap<Bytes>> = Default::default();
    let ingest = |queue: &n42_tx_queue::TxQueue<N42PooledTransaction>, raw: &[Bytes], senders: &[Address]| {
        let mut frame = alloy_primitives::bytes::BytesMut::with_capacity(raw.iter().map(|r| r.len()).sum());
        let mut slices = Vec::with_capacity(raw.len());
        for bytes in raw {
            frame.extend_from_slice(bytes);
            slices.push(Bytes::from(frame.split_to(bytes.len()).freeze()));
        }
        let mut kept = Vec::with_capacity(raw.len());
        queue.push(slices.into_iter().zip(senders).map(|(bytes, sender)| {
            let tx = TransactionSigned::decode_2718_exact(&bytes).expect("decodes");
            kept.push((*tx.tx_hash(), bytes.clone()));
            N42PooledTransaction::new(reth_primitives_traits::Recovered::new_unchecked(tx, *sender), bytes.len())
        }));
        kept_bytes.lock().unwrap_or_else(|p| p.into_inner()).extend(kept);
    };
    std::thread::scope(|scope| {
        for lane in 0..12usize {
            let (queue, raw, senders, noise_raw, noise_senders) = (&queue, &raw, &senders, &noise_raw, &noise_senders);
            scope.spawn(move || {
                let mut at = lane * 500;
                while at < raw.len() {
                    let end = (at + 500).min(raw.len());
                    ingest(queue, &raw[at..end], &senders[at..end]);
                    let nend = end.min(noise_raw.len());
                    if at < nend {
                        ingest(queue, &noise_raw[at..nend], &noise_senders[at..nend]);
                    }
                    at += 12 * 500;
                }
            });
        }
    });
    queue.drain_now();
    let kept: Vec<Bytes> = {
        let map = kept_bytes.lock().unwrap_or_else(|p| p.into_inner());
        hashes.iter().map(|hash| map.get(hash).cloned().unwrap_or_default()).collect()
    };

    // The state the block executes on: its senders funded, every recipient
    // present, and two million more accounts beside them.
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(addr(1), AccountInfo { balance: U256::from(7), ..Default::default() });
    for sender in &senders {
        db.insert_account_info(*sender, AccountInfo { balance: U256::from(10u128.pow(21)), ..Default::default() });
    }
    for tx in &txs {
        if let Some(to) = alloy_consensus::Transaction::to(tx)
            && !db.cache.accounts.contains_key(&to)
        {
            db.insert_account_info(to, AccountInfo { balance: U256::from(1u64), ..Default::default() });
        }
    }
    for i in 0..env("BENCH_SPARE", 2_000_000) {
        db.insert_account_info(addr(30_000_000 + i), AccountInfo { balance: U256::from(1u64), ..Default::default() });
    }
    let db = SharedDb(Arc::new(db));
    let evm_config = n42_engine_types::N42EvmConfig::new_with_evm_factory(
        reth_chainspec::MAINNET.clone(),
        n42_engine_types::fast_transfer::N42EvmFactory::with_fast_transfers(true),
    );
    let exec = |block: &RecoveredBlock<Block>| -> (f64, u64, u64) {
        let at = std::time::Instant::now();
        let (out, phases) = n42_engine_types::parallel_transfer::execute_transfers_with(
            &evm_config,
            block,
            db.clone(),
            &|| Some(db.clone()),
            true,
            false,
        )
        .expect("no execution error")
        .expect("the block qualifies");
        let ms = at.elapsed().as_micros() as f64 / 1000.0;
        assert_eq!(out.result.gas_used, 21_000 * count as u64);
        (ms, phases.groups_ms, phases.partition_ms)
    };

    let validator = n42_engine_types::engine_validator::N42EngineValidator::new(
        Arc::new((*reth_chainspec::MAINNET).clone()),
        N42HeaderProfile::Ethereum,
    );
    println!(
        "fixture: {count} 0x50 transfers, body {} MB, compact {} MB, queue {} held, {} rayon threads",
        body.len() / 1_000_000,
        compact.len() / 1_000_000,
        queue.hash_index_len(),
        rayon::current_num_threads(),
    );

    // Load: the pool busy and the ingest still pushing.
    let busy = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut pushers = Vec::new();
    for lane in 0..12u64 {
        let (queue, busy) = (Arc::clone(&queue), Arc::clone(&busy));
        pushers.push(std::thread::spawn(move || {
            let (more, more_senders) = fixture((3 + lane) << 32, 40, 27, 2_000_000, 64);
            let more_raw: Vec<Bytes> = more.iter().map(|tx| Bytes::from(tx.encoded_2718())).collect();
            let mut at = 0usize;
            while busy.load(std::sync::atomic::Ordering::Relaxed) {
                let end = (at + 500).min(more_raw.len());
                if at >= end {
                    at = 0;
                    continue;
                }
                queue.push(more_raw[at..end].iter().zip(&more_senders[at..end]).map(|(bytes, sender)| {
                    let tx = TransactionSigned::decode_2718_exact(bytes).expect("decodes");
                    N42PooledTransaction::new(reth_primitives_traits::Recovered::new_unchecked(tx, *sender), bytes.len())
                }));
                at = end;
                std::thread::sleep(std::time::Duration::from_millis(15));
            }
        }));
    }
    if env("BENCH_BUSY", 1) == 1 {
        let busy = Arc::clone(&busy);
        std::thread::spawn(move || {
            let load: Vec<u8> = (0..64 << 20).map(|i| (i % 251) as u8).collect();
            while busy.load(std::sync::atomic::Ordering::Relaxed) {
                let sum: u64 = load.par_chunks(4096).map(|c| c.iter().map(|b| u64::from(*b)).sum::<u64>()).sum();
                std::hint::black_box(sum);
            }
        });
    }

    let ms = |at: std::time::Instant| at.elapsed().as_micros() as f64 / 1000.0;
    for round in 0..env("BENCH_ROUNDS", 4) {
        let at = std::time::Instant::now();
        let (decoded, _) =
            validator.convert_body_to_block(announced, N42HeaderProfile::Ethereum, &body).expect("the body converts");
        let body_ms = ms(at);

        let at = std::time::Instant::now();
        let assembled = validator
            .convert_compact_body_to_block(announced, N42HeaderProfile::Ethereum, &compact, &queue, std::time::Duration::ZERO)
            .expect("the compact body assembles");
        let compact_ms = ms(at);
        assert_eq!(assembled.block.hash(), decoded.hash());

        let at = std::time::Instant::now();
        let described = validator
            .describe_compact_body(announced, N42HeaderProfile::Ethereum, &compact, &queue, std::time::Duration::ZERO)
            .expect("the description checks");
        let describe_ms = ms(at);
        let (d_describe, d_root) = (described.describe_us as f64 / 1000.0, described.root_us as f64 / 1000.0);
        // The road's part of the rest: the payload without its list and the
        // owned block; then, off the road, the list copied out.
        let mut described = described;
        let at = std::time::Instant::now();
        let mut payload = described.header_payload();
        let list = described.take_payload_list();
        let made = described.maker(&payload).make(&validator).expect("the described block is made");
        let into_ms = ms(at);
        let at = std::time::Instant::now();
        payload.payload.as_v1_mut().transactions = list.copy_out();
        let list_ms = ms(at);
        assert_eq!(made.block.hash(), decoded.hash(), "the described road is the same block");
        assert_eq!(payload.payload.as_v1().transactions, raw, "and the same payload");
        let made_copy = made.copy_us as f64 / 1000.0;
        let at = std::time::Instant::now();
        let described_senders = std::mem::take(&mut described.senders);
        drop(described);
        let release_described_ms = ms(at);
        let described_block = RecoveredBlock::new_sealed(made.block, described_senders);

        let at = std::time::Instant::now();
        let held: Vec<Held> = queue.get_by_hashes(&hashes).into_iter().flatten().collect();
        let lookup_ms = ms(at);
        assert_eq!(held.len(), count);

        let at = std::time::Instant::now();
        let touched: u64 = held.par_iter().map(|tx| tx.transaction.transaction.inner().encode_2718_len() as u64).sum();
        let touch_ms = ms(at);
        std::hint::black_box(touched);

        let at = std::time::Instant::now();
        let root = root_over_held(&held);
        let root_ms = ms(at);
        assert_eq!(root, header.transactions_root, "the root over the queue's transactions is the header's");

        let at = std::time::Instant::now();
        let kept_root = n42_engine_types::assembler::parallel_ordered_trie_root(&kept);
        let kept_ms = ms(at);
        assert_eq!(kept_root, header.transactions_root, "the root over the kept bytes is the header's");

        let at = std::time::Instant::now();
        let owned: Vec<TransactionSigned> = held.par_iter().map(|tx| tx.transaction.transaction.inner().clone()).collect();
        let copy_ms = ms(at);

        let at = std::time::Instant::now();
        drop(held);
        let release_ms = ms(at);

        let assembled_block = RecoveredBlock::new_sealed(assembled.block, assembled.senders);
        let decoded_block = RecoveredBlock::new_sealed(decoded, senders.clone());
        let copied_block = RecoveredBlock::new_sealed(
            SealedBlock::new_unhashed(Block {
                header: header.clone(),
                body: n42_tx_types::BlockBody { transactions: owned, ommers: Vec::new(), withdrawals: Some(Vec::new().into()) },
            }),
            senders.clone(),
        );
        let (dec, dec_groups, dec_part) = exec(&decoded_block);
        let (asm, asm_groups, asm_part) = exec(&assembled_block);
        let (cop, cop_groups, cop_part) = exec(&copied_block);
        let (des, des_groups, des_part) = exec(&described_block);
        drop(described_block);
        let at = std::time::Instant::now();
        drop(assembled_block);
        let drop_assembled_ms = ms(at);
        let at = std::time::Instant::now();
        drop(decoded_block);
        let drop_decoded_ms = ms(at);
        drop(copied_block);
        println!(
            "round {round}: body {body_ms:.1} | compact {compact_ms:.1} (assemble {:.1} root {:.1}) | described {describe_ms:.1} (pass {d_describe:.1} of which root {d_root:.1}) road rest {into_ms:.1} (copy {made_copy:.1}) off-road: list {list_ms:.1} release {release_described_ms:.1} | parts: lookup {lookup_ms:.1} touch {touch_ms:.1} root {root_ms:.1} kept-bytes root {kept_ms:.1} copy {copy_ms:.1} release {release_ms:.1} \
             | exec decoded {dec:.1} (groups {dec_groups} partition {dec_part}) assembled {asm:.1} ({asm_groups}/{asm_part}) copied {cop:.1} ({cop_groups}/{cop_part}) described {des:.1} ({des_groups}/{des_part}) | drop assembled {drop_assembled_ms:.1} decoded {drop_decoded_ms:.1}",
            assembled.assemble_us as f64 / 1000.0,
            assembled.root_us as f64 / 1000.0,
        );
    }
    busy.store(false, std::sync::atomic::Ordering::Relaxed);
    for pusher in pushers {
        let _ = pusher.join();
    }
}
