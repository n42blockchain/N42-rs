// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an invalid vote costs the BLS batch paths: the batch, then one
//! pairing check a position. Measurement only (senders are validators, so a
//! bad vote names its signer):
//!
//! ```text
//! cargo test --release -p n42-h2-primitives --test bls_fallback_cost -- --ignored --nocapture
//! ```
//!
//! Results: `docs/SIGNATURE_AND_BATCH_TX_SURVEY.md` section 5.

use n42_h2_primitives::bls::{
    BlsPublicKey, BlsSecretKey, BlsSignature, batch_verify_with_fallback, verify_same_message_with_fallback,
};
use std::time::Instant;

fn best_us(reps: usize, mut f: impl FnMut() -> usize) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..reps {
        let start = Instant::now();
        std::hint::black_box(f());
        best = best.min(start.elapsed().as_secs_f64());
    }
    best * 1e6
}

#[test]
#[ignore = "measurement; run in release with --nocapture"]
fn bls_vote_fallback_cost() {
    let reps: usize = std::env::var("BENCH_REPS").ok().and_then(|v| v.parse().ok()).unwrap_or(5);
    println!("best of {reps}; us for the whole set (amplification against all valid)");
    println!("| path | n | all valid | 1 invalid | f invalid |");
    println!("| --- | --- | --- | --- | --- |");
    for n in [7usize, 64, 512] {
        let f = (n - 1) / 3;
        let keys: Vec<BlsSecretKey> = (0..n)
            .map(|i| {
                let mut ikm = [7u8; 32];
                ikm[..8].copy_from_slice(&(i as u64).to_le_bytes());
                BlsSecretKey::key_gen(&ikm).expect("key")
            })
            .collect();
        let pks: Vec<BlsPublicKey> = keys.iter().map(BlsSecretKey::public_key).collect();
        let pk_refs: Vec<&BlsPublicKey> = pks.iter().collect();

        // One message (a vote for one block): the same-message batch.
        let message = [0x42u8; 40];
        let wrong = [0x43u8; 40];
        let sigs_with = |bad: usize| -> Vec<BlsSignature> {
            keys.iter().enumerate().map(|(i, k)| k.sign(if i < bad { &wrong } else { &message })).collect()
        };
        let mut row = Vec::new();
        for bad in [0, 1, f] {
            let sigs = sigs_with(bad);
            let refs: Vec<&BlsSignature> = sigs.iter().collect();
            let out = verify_same_message_with_fallback(&message, &refs, &pk_refs);
            assert_eq!(out.bad.len(), bad);
            row.push(best_us(reps, || verify_same_message_with_fallback(&message, &refs, &pk_refs).bad.len()));
        }
        println!(
            "| same message | {n} | {:.0} | {:.0} ({:.1}x) | {:.0} ({:.1}x, f={f}) |",
            row[0],
            row[1],
            row[1] / row[0],
            row[2],
            row[2] / row[0]
        );

        // Distinct messages (votes for different views / blocks).
        let messages: Vec<[u8; 40]> = (0..n)
            .map(|i| {
                let mut m = [0u8; 40];
                m[..8].copy_from_slice(&(i as u64).to_le_bytes());
                m
            })
            .collect();
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        let mut row = Vec::new();
        for bad in [0, 1, f] {
            let sigs: Vec<BlsSignature> =
                keys.iter().enumerate().map(|(i, k)| k.sign(if i < bad { &wrong } else { &messages[i] })).collect();
            let refs: Vec<&BlsSignature> = sigs.iter().collect();
            let out = batch_verify_with_fallback(&msg_refs, &refs, &pk_refs);
            assert_eq!(out.err().map_or(0, |b| b.len()), bad);
            row.push(best_us(reps, || {
                batch_verify_with_fallback(&msg_refs, &refs, &pk_refs).err().map_or(0, |b| b.len())
            }));
        }
        println!(
            "| distinct messages | {n} | {:.0} | {:.0} ({:.1}x) | {:.0} ({:.1}x, f={f}) |",
            row[0],
            row[1],
            row[1] / row[0],
            row[2],
            row[2] / row[0]
        );
    }
}
