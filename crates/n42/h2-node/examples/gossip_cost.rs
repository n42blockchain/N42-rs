// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a full block costs to put on the wire, and to take off it.
//!
//! ```text
//! cargo run --release -p n42-h2-node --example gossip_cost -- [transactions]
//! ```
//!
//! The seven-node fleet's block cycle at the 480M tier has about 173 ms in it
//! that nothing accounts for directly: it is what is left after the leader's
//! payload build, the followers' import and the quorum are subtracted from the
//! measured cycle. A residual is the weakest number in a table — it collects
//! every error in the terms above it — so this measures the parts of it that
//! are computation rather than network: encoding a block's transactions to RLP,
//! compressing that, and undoing both on the receiving side.
//!
//! It also measures the *other* copy of the same block, the one that is easy to
//! forget: a validator and its execution layer talk over the Engine API, which
//! is JSON over HTTP, and every transaction crosses it hex-encoded — twice per
//! block on the fleet, once when the leader fetches its payload and once when
//! each follower submits it. That hop is inside the two largest terms of the
//! measured cycle (the 122 ms build and the 83 ms import), so its size decides
//! whether moving the validator and the node into one process is worth the
//! work.
//!
//! 22,857 is the default because that is a full 480M-gas block of 21,000-gas
//! transfers, which is what the fleet actually produces at that tier.

use std::time::Instant;

use alloy_consensus::{Header, SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use n42_h2_net::{compress_block_rlp, decompress_block_gossip, encode_block_rlp_parts};

fn main() {
    let count: usize = std::env::args()
        .nth(1)
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(22_857);

    let signer = PrivateKeySigner::random();
    let build = Instant::now();
    let transactions: Vec<TxEnvelope> = (0..count)
        .map(|nonce| {
            let tx = TxEip1559 {
                chain_id: 1143,
                nonce: nonce as u64,
                gas_limit: 21_000,
                max_fee_per_gas: 10_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
                to: TxKind::Call(Address::with_last_byte(0x42)),
                value: U256::from(1),
                ..Default::default()
            };
            let signature = signer.sign_hash_sync(&tx.signature_hash()).expect("sign");
            tx.into_signed(signature).into()
        })
        .collect();
    let built = build.elapsed();

    let header = Header::default();
    let rewards: Vec<(Address, U256)> = vec![
        (Address::with_last_byte(1), U256::from(1_000_000_000_000_000_000u64)),
        (Address::with_last_byte(2), U256::from(1_000_000_000_000_000_000u64)),
    ];

    // Each phase three times; report the best, since this is a cost floor and
    // the machine has other things on it.
    let mut encode_ns = u128::MAX;
    let mut rlp = Vec::new();
    for _ in 0..3 {
        let at = Instant::now();
        rlp = encode_block_rlp_parts(&header, &transactions, &rewards);
        encode_ns = encode_ns.min(at.elapsed().as_nanos());
    }

    let mut compress_ns = u128::MAX;
    let mut wire = Vec::new();
    for _ in 0..3 {
        let at = Instant::now();
        wire = compress_block_rlp(&rlp).expect("compress");
        compress_ns = compress_ns.min(at.elapsed().as_nanos());
    }

    let mut decompress_ns = u128::MAX;
    for _ in 0..3 {
        let at = Instant::now();
        let back = decompress_block_gossip(&wire).expect("decompress");
        decompress_ns = decompress_ns.min(at.elapsed().as_nanos());
        assert_eq!(back.len(), rlp.len());
    }

    // The Engine API's copy: `ExecutionPayloadV3`, JSON, transactions as hex.
    let payload_txs: Vec<alloy_primitives::Bytes> = transactions
        .iter()
        .map(|tx| alloy_primitives::Bytes::from(alloy_eips::eip2718::Encodable2718::encoded_2718(tx)))
        .collect();
    let mut json_ns = u128::MAX;
    let mut json = String::new();
    for _ in 0..3 {
        let at = Instant::now();
        json = serde_json::to_string(&payload_txs).expect("serialize");
        json_ns = json_ns.min(at.elapsed().as_nanos());
    }
    let mut parse_ns = u128::MAX;
    for _ in 0..3 {
        let at = Instant::now();
        let back: Vec<alloy_primitives::Bytes> =
            serde_json::from_str(&json).expect("deserialize");
        parse_ns = parse_ns.min(at.elapsed().as_nanos());
        assert_eq!(back.len(), payload_txs.len());
    }

    let ms = |ns: u128| ns as f64 / 1e6;
    println!("transactions : {count} (signed in {:.1}s)", built.as_secs_f64());
    println!("rlp          : {} bytes ({:.2} MB)", rlp.len(), rlp.len() as f64 / 1e6);
    println!(
        "compressed   : {} bytes ({:.2} MB, {:.1}% of raw)",
        wire.len(),
        wire.len() as f64 / 1e6,
        100.0 * wire.len() as f64 / rlp.len() as f64
    );
    println!();
    println!("encode  rlp  : {:8.2} ms   ({:.2} us/tx)", ms(encode_ns), encode_ns as f64 / 1000.0 / count as f64);
    println!("compress     : {:8.2} ms   ({:.0} MB/s)", ms(compress_ns), rlp.len() as f64 / 1e6 / (compress_ns as f64 / 1e9));
    println!("decompress   : {:8.2} ms   ({:.0} MB/s)", ms(decompress_ns), rlp.len() as f64 / 1e6 / (decompress_ns as f64 / 1e9));
    println!();
    println!(
        "leader side  : {:8.2} ms  (encode + compress, once per block)",
        ms(encode_ns + compress_ns)
    );
    println!(
        "follower side: {:8.2} ms  (decompress; the RLP decode that follows is not measured here)",
        ms(decompress_ns)
    );
    println!();
    println!("--- the same block over the Engine API (JSON, hex-encoded transactions) ---");
    println!(
        "json         : {} bytes ({:.2} MB, {:.1}x the RLP)",
        json.len(),
        json.len() as f64 / 1e6,
        json.len() as f64 / rlp.len() as f64
    );
    println!("serialize    : {:8.2} ms   (leader, once per block)", ms(json_ns));
    println!("deserialize  : {:8.2} ms   (follower, once per block)", ms(parse_ns));
    println!(
        "round trip   : {:8.2} ms   against {:.2} ms for the gossip wire form",
        ms(json_ns + parse_ns),
        ms(encode_ns + compress_ns + decompress_ns)
    );
}
