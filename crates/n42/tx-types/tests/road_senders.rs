// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a block's senders cost when nobody recovered them beforehand.
//!
//! `N42_INGEST_VERIFY=leader` does not remove the signature work, it moves
//! it: off the ingest's blocking pool, where it runs at the supply's rate on
//! the cores the import and the build share, and onto the two places a
//! sender is actually used -- the builder, once per transaction it includes,
//! and the vote road, once per transaction of a block it votes for. The
//! question the mode lives or dies by is what the road then costs, and it is
//! arithmetic before it is a fleet leg: a block of 163,000 transactions on
//! sixteen threads has 25 ms of budget only if a signature costs under
//! ~2.5 us, which no scheme here does.
//!
//! This measures it rather than asserting it:
//!
//! ```text
//! cargo test --release -p n42-tx-types --test road_senders -- --ignored --nocapture
//! BENCH_TXS=163000 BENCH_THREADS=16 N42_ED25519_BATCH=128 ...
//! ```
//!
//! What it read on the bench host (2026-09-22, an idle box, 163,000
//! transactions from 6,000 senders, `N42_ED25519_BATCH=128`):
//!
//! | | 16 threads | 28 threads | CPU a transaction |
//! | --- | --- | --- | --- |
//! | 0x50, batch | 132-135 ms | 76-78 ms | 13.0-13.5 us |
//! | 0x50, one at a time | 379-380 ms | 217 ms | 37.3 us |
//! | secp256k1, ecrecover | 308-310 ms | 177-179 ms | 30.3-30.9 us |
//!
//! and, with the signature off, the ingest's remaining per-transaction cost
//! (decode and hash, one thread) is 0.72 us for 0x50 and 0.16 us for
//! secp256k1.
//!
//! So the batch equation is 2.9x cheaper than verifying one 0x50 signature
//! at a time, and it is still 132 ms for a block's worth on the fleet's
//! sixteen threads -- against a vote road of 217 ms inside a 252 ms cycle.
//! The bar a relocation would have to clear, 25 ms for 163,000 on sixteen
//! threads, is 2.45 us of CPU a transaction; the cheapest signature here
//! costs 13. Moving the supply's work onto the road is therefore a 5.3x
//! (0x50) or 12.6x (secp256k1) overrun of that bar, and no arrangement of
//! threads changes it -- only a cheaper signature would.

use std::time::Instant;

use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{address, keccak256, Address, Bytes, Signature, TxKind, U256};
use n42_tx_types::{AltSigTx, TxAltSig, ALG_ED25519};
use rayon::prelude::*;
use reth_primitives_traits::SignerRecoverable as _;

/// Transactions a block holds at the fleet's bench tier.
fn bench_txs() -> usize {
    std::env::var("BENCH_TXS").ok().and_then(|v| v.parse().ok()).unwrap_or(163_000)
}

/// Threads the road's pool has. The fleet pins each node to sixteen
/// (`RAYON_NUM_THREADS=16`), and the number is the whole point of the
/// measurement, so it is set here rather than left to the box's core count.
fn bench_threads() -> usize {
    std::env::var("BENCH_THREADS").ok().and_then(|v| v.parse().ok()).unwrap_or(16)
}

/// The flood's sender set: distinct keys, because a batch of one key's
/// signatures is not what a block carries.
fn senders() -> usize {
    std::env::var("BENCH_SENDERS").ok().and_then(|v| v.parse().ok()).unwrap_or(6_000)
}

fn ed25519_key(index: usize) -> ed25519_dalek::SigningKey {
    let mut seed = Vec::with_capacity(32);
    seed.extend_from_slice(b"n42-road-senders-ed25519");
    seed.extend_from_slice(&(index as u64).to_be_bytes());
    ed25519_dalek::SigningKey::from_bytes(&keccak256(seed).0)
}

fn secp_key(index: usize) -> secp256k1::SecretKey {
    let mut seed = Vec::with_capacity(32);
    seed.extend_from_slice(b"n42-road-senders-secp256k1");
    seed.extend_from_slice(&(index as u64).to_be_bytes());
    let mut bytes = keccak256(seed);
    loop {
        match secp256k1::SecretKey::from_slice(bytes.as_slice()) {
            Ok(key) => return key,
            Err(_) => bytes = keccak256(bytes),
        }
    }
}

fn alt_block(count: usize, keys: usize) -> Vec<AltSigTx> {
    let signing: Vec<ed25519_dalek::SigningKey> = (0..keys).map(ed25519_key).collect();
    (0..count)
        .map(|i| {
            let key = &signing[i % keys];
            TxAltSig {
                chain_id: 94,
                nonce: (i / keys) as u64,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 10_000_000_000,
                gas_limit: 21_000,
                to: address!("00000000000000000000000000000000000000aa"),
                value: U256::from(1u64),
                input: Bytes::new(),
                access_list: Default::default(),
                alg_type: ALG_ED25519,
                pubkey: Bytes::copy_from_slice(key.verifying_key().as_bytes()),
            }
            .sign_ed25519(key)
        })
        .collect()
}

fn eth_block(count: usize, keys: usize) -> Vec<reth_ethereum_primitives::TransactionSigned> {
    let signing: Vec<secp256k1::SecretKey> = (0..keys).map(secp_key).collect();
    (0..count)
        .map(|i| {
            let key = &signing[i % keys];
            let tx = TxEip1559 {
                chain_id: 94,
                nonce: (i / keys) as u64,
                gas_limit: 21_000,
                max_fee_per_gas: 10_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
                to: TxKind::Call(address!("00000000000000000000000000000000000000bb")),
                value: U256::from(1u64),
                ..Default::default()
            };
            let message = secp256k1::Message::from_digest(tx.signature_hash().0);
            let (recovery_id, compact) =
                secp256k1::SECP256K1.sign_ecdsa_recoverable(&message, key).serialize_compact();
            let signature = Signature::new(
                U256::from_be_slice(&compact[..32]),
                U256::from_be_slice(&compact[32..]),
                i32::from(recovery_id) != 0,
            );
            tx.into_signed(signature).into()
        })
        .collect()
}

fn pool(threads: usize) -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("a thread pool of the asked-for size")
}

/// The road's whole sender pass for a block nobody recovered beforehand:
/// 0x50 through the batch equation, secp256k1 through ecrecover, both on a
/// pool of the fleet's width. Printed, never asserted -- the number is the
/// answer, and a box that is busy would only turn it into a flake.
#[test]
#[ignore = "timing"]
fn bench_road_sender_verification() {
    let count = bench_txs();
    let threads = bench_threads();
    let keys = senders().min(count.max(1));
    let pool = pool(threads);
    let batch = n42_tx_types::ed25519_batch_size();
    println!("block of {count} transactions from {keys} senders, {threads} threads, ed25519 batch {batch}");

    let alt = alt_block(count, keys);
    for round in 0..3 {
        let at = Instant::now();
        let verified: usize = pool.install(|| {
            (0..count)
                .collect::<Vec<usize>>()
                .par_chunks(batch)
                .map(|chunk| {
                    let refs: Vec<&AltSigTx> = chunk.iter().map(|&i| &alt[i]).collect();
                    n42_tx_types::verify_batch(&refs).into_iter().filter(Result::is_ok).count()
                })
                .sum()
        });
        let took = at.elapsed();
        println!(
            "0x50  batch  round {round}: {:>5} ms, {:>5.2} us/tx of wall, {:>5.1} us/tx of CPU ({verified} verified)",
            took.as_millis(),
            took.as_micros() as f64 / count as f64,
            took.as_micros() as f64 * threads as f64 / count as f64,
        );
    }
    for round in 0..2 {
        let at = Instant::now();
        let verified = pool.install(|| alt.par_iter().filter(|tx| tx.verify().is_ok()).count());
        let took = at.elapsed();
        println!(
            "0x50  single round {round}: {:>5} ms, {:>5.2} us/tx of wall, {:>5.1} us/tx of CPU ({verified} verified)",
            took.as_millis(),
            took.as_micros() as f64 / count as f64,
            took.as_micros() as f64 * threads as f64 / count as f64,
        );
    }
    drop(alt);

    let eth = eth_block(count, keys);
    for round in 0..3 {
        let at = Instant::now();
        let recovered: Vec<Address> =
            pool.install(|| eth.par_iter().filter_map(|tx| tx.recover_signer().ok()).collect());
        let took = at.elapsed();
        println!(
            "secp  recover round {round}: {:>5} ms, {:>5.2} us/tx of wall, {:>5.1} us/tx of CPU ({} recovered)",
            took.as_millis(),
            took.as_micros() as f64 / count as f64,
            took.as_micros() as f64 * threads as f64 / count as f64,
            recovered.len(),
        );
    }
}

/// What the ingest keeps paying with verification off: the decode and the
/// hash, without a signature. The difference between this and the numbers
/// above is exactly what `N42_INGEST_VERIFY=leader` moves.
#[test]
#[ignore = "timing"]
fn bench_ingest_without_verification() {
    use alloy_eips::eip2718::{Decodable2718, Encodable2718};
    let count = bench_txs();
    let keys = senders().min(count.max(1));
    println!("ingest of {count} transactions from {keys} senders, one thread");

    for (name, raws) in [
        ("0x50", alt_block(count, keys).iter().map(Encodable2718::encoded_2718).collect::<Vec<_>>()),
        ("secp", eth_block(count, keys).iter().map(Encodable2718::encoded_2718).collect::<Vec<_>>()),
    ] {
        for round in 0..2 {
            let at = Instant::now();
            let decoded = raws
                .iter()
                .filter_map(|raw| {
                    <n42_tx_types::N42PooledTxEnvelope as Decodable2718>::decode_2718_exact(raw.as_ref()).ok()
                })
                .count();
            let took = at.elapsed();
            println!(
                "{name} decode+hash round {round}: {:>5} ms, {:>5.2} us/tx ({decoded} decoded)",
                took.as_millis(),
                took.as_micros() as f64 / count as f64,
            );
        }
    }
}
