// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The worst case of 0x50 batch verification: what an invalid or malformed
//! signature costs, and that the fallback names exactly the signatures the
//! reference names.
//!
//! An invalid 0x50 transaction at the ingest is never included, so its sender
//! pays no gas for the work it causes. The property test runs by default; the
//! cost table is a measurement:
//!
//! ```text
//! cargo test --release -p n42-tx-types --test batch_worst_case -- --ignored --nocapture
//! ```
//!
//! Results and the conclusion: `docs/SIGNATURE_AND_BATCH_TX_SURVEY.md` section 5.

use alloy_primitives::{Address, Bytes, U256};
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use n42_tx_types::{
    verify_batch, verify_batch_linear, verify_batch_with, AltSigError, AltSigTx, BatchFallback, TxAltSig,
    ALG_ED25519,
};
use sha2::{Digest, Sha512};
use std::time::Instant;

/// splitmix64: deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        out
    }

    fn scalar(&mut self) -> Scalar {
        Scalar::from_bytes_mod_order(self.bytes32())
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The point of order 2, `(0, -1)`.
fn order_two() -> EdwardsPoint {
    let mut y = [0xffu8; 32];
    y[0] = 0xec;
    y[31] = 0x7f;
    CompressedEdwardsY(y).decompress().expect("(0, -1) is on the curve")
}

/// 32 bytes that are not the encoding of a curve point.
fn off_curve() -> [u8; 32] {
    (2u8..).map(|y| {
        let mut b = [0u8; 32];
        b[0] = y;
        b
    })
    .find(|b| CompressedEdwardsY(*b).decompress().is_none())
    .expect("some small y is off the curve")
}

/// `s = L`, the smallest non-canonical scalar.
const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// What a generated transaction is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Valid,
    /// Valid under the cofactored rule: `R` carries a torsion component.
    ValidMixedR,
    /// Valid under the cofactored rule: the key carries a torsion component.
    ValidMixedKey,
    /// A signature over another message.
    WrongMessage,
    /// `s` off by one (still canonical).
    BadS,
    /// `R` is the identity (small order).
    SmallOrderR,
    /// `R` does not decompress.
    OffCurveR,
    /// `s >= L`.
    NonCanonicalS,
    /// 63 signature bytes.
    ShortSignature,
    /// A key that does not decompress.
    OffCurveKey,
    /// The identity as the key (small order).
    SmallOrderKey,
    /// 31 key bytes.
    ShortKey,
    /// `alg_type` 0x7f.
    UnknownAlg,
}

const KINDS: [Kind; 13] = [
    Kind::Valid,
    Kind::ValidMixedR,
    Kind::ValidMixedKey,
    Kind::WrongMessage,
    Kind::BadS,
    Kind::SmallOrderR,
    Kind::OffCurveR,
    Kind::NonCanonicalS,
    Kind::ShortSignature,
    Kind::OffCurveKey,
    Kind::SmallOrderKey,
    Kind::ShortKey,
    Kind::UnknownAlg,
];

/// A signing key: the secret scalar and its public point.
#[derive(Clone, Copy)]
struct Key {
    a: Scalar,
    point: EdwardsPoint,
}

impl Key {
    fn new(rng: &mut Rng) -> Self {
        let a = rng.scalar();
        Self { a, point: EdwardsPoint::mul_base(&a) }
    }
}

fn h_of(r: &[u8; 32], key: &[u8; 32], message: &[u8]) -> Scalar {
    let mut hash = Sha512::default();
    hash.update(r);
    hash.update(key);
    hash.update(message);
    Scalar::from_bytes_mod_order_wide(&hash.finalize().into())
}

/// A 0x50 transaction of `kind` signed by `key` (as `nonce`).
fn make(rng: &mut Rng, key: &Key, nonce: u64, kind: Kind) -> AltSigTx {
    let mut fields = TxAltSig {
        chain_id: 94,
        nonce,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 2,
        gas_limit: 21_000,
        to: Address::with_last_byte(7),
        value: U256::from(1u64),
        input: Bytes::new(),
        access_list: Default::default(),
        alg_type: ALG_ED25519,
        pubkey: Bytes::new(),
    };
    let key_point = if kind == Kind::ValidMixedKey { key.point + order_two() } else { key.point };
    let key_bytes = key_point.compress().to_bytes();
    fields.pubkey = Bytes::copy_from_slice(&key_bytes);
    match kind {
        Kind::OffCurveKey => fields.pubkey = Bytes::copy_from_slice(&off_curve()),
        Kind::SmallOrderKey => fields.pubkey = Bytes::copy_from_slice(&EdwardsPoint::default().compress().to_bytes()),
        Kind::ShortKey => fields.pubkey = Bytes::copy_from_slice(&key_bytes[..31]),
        Kind::UnknownAlg => fields.alg_type = 0x7f,
        _ => {}
    }
    let message = fields.signing_hash();
    let signed_message = if kind == Kind::WrongMessage { [0x55u8; 32] } else { message.0 };
    let r = rng.scalar();
    let r_point = EdwardsPoint::mul_base(&r);
    let r_point = if kind == Kind::ValidMixedR { r_point + order_two() } else { r_point };
    let r_bytes = match kind {
        Kind::SmallOrderR => EdwardsPoint::default().compress().to_bytes(),
        Kind::OffCurveR => off_curve(),
        _ => r_point.compress().to_bytes(),
    };
    let h = h_of(&r_bytes, &key_bytes, &signed_message);
    let mut s = r + h * key.a;
    if kind == Kind::BadS {
        s += Scalar::ONE;
    }
    let mut sig = Vec::with_capacity(64);
    sig.extend_from_slice(&r_bytes);
    sig.extend_from_slice(if kind == Kind::NonCanonicalS { &L_BYTES } else { s.as_bytes() });
    if kind == Kind::ShortSignature {
        sig.pop();
    }
    AltSigTx::new(fields, sig.into())
}

#[test]
fn the_generator_makes_what_it_names() {
    let mut rng = Rng(1);
    let key = Key::new(&mut rng);
    for kind in KINDS {
        let tx = make(&mut rng, &key, 0, kind);
        let verdict = tx.verify();
        let expected_ok = matches!(kind, Kind::Valid | Kind::ValidMixedR | Kind::ValidMixedKey);
        assert_eq!(verdict.is_ok(), expected_ok, "{kind:?}: {verdict:?}");
        match kind {
            Kind::NonCanonicalS => assert_eq!(verdict, Err(AltSigError::BadSignature)),
            Kind::OffCurveKey | Kind::SmallOrderKey => assert_eq!(verdict, Err(AltSigError::BadPubkey)),
            Kind::WrongMessage | Kind::BadS | Kind::SmallOrderR | Kind::OffCurveR => {
                assert_eq!(verdict, Err(AltSigError::Invalid))
            }
            _ => {}
        }
    }
}

/// Random batches with random invalid positions and malformed entries: every
/// fallback gives, position by position, the verdict of the linear reference
/// and of `AltSigTx::verify`.
#[test]
fn fallbacks_give_the_reference_verdicts() {
    let mut rng = Rng(0x0050_0050);
    let keys: Vec<Key> = (0..6).map(|_| Key::new(&mut rng)).collect();
    let cases = std::env::var("ALTSIG_PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(24usize);
    for case in 0..cases {
        let len = 1 + rng.below(if case % 4 == 0 { 140 } else { 24 });
        // Mostly valid, with a density of bad entries that varies by case:
        // none, one, a few, about half, all.
        let bad_per_mille = [0u64, 20, 100, 500, 1000][case % 5];
        let txs: Vec<AltSigTx> = (0..len)
            .map(|i| {
                let key = &keys[rng.below(keys.len())];
                let kind = if rng.next() % 1000 < bad_per_mille {
                    KINDS[3 + rng.below(KINDS.len() - 3)]
                } else {
                    KINDS[rng.below(3)]
                };
                make(&mut rng, key, i as u64, kind)
            })
            .collect();
        let refs: Vec<&AltSigTx> = txs.iter().collect();
        let reference = verify_batch_linear(&refs);
        let singles: Vec<_> = txs.iter().map(AltSigTx::verify).collect();
        assert_eq!(reference, singles, "case {case}: the reference is the single check");
        assert_eq!(verify_batch(&refs), reference, "case {case}: verify_batch");
        for fallback in [BatchFallback::Single, BatchFallback::Bisect] {
            assert_eq!(verify_batch_with(&refs, fallback), reference, "case {case}: {fallback:?}");
        }
    }
}

/// A pool of `chunks * chunk` transactions, each chunk built by `bad(chunk)`
/// (the positions that get `kind`; the rest are valid).
fn pool(
    rng: &mut Rng,
    keys: &[Key],
    chunks: usize,
    chunk: usize,
    kind: Kind,
    bad: &dyn Fn(usize) -> Vec<usize>,
) -> Vec<AltSigTx> {
    let positions = bad(chunk);
    let mut out = Vec::with_capacity(chunks * chunk);
    for c in 0..chunks {
        for i in 0..chunk {
            let n = c * chunk + i;
            let k = if positions.contains(&i) { kind } else { Kind::Valid };
            out.push(make(rng, &keys[n % keys.len()], n as u64, k));
        }
    }
    out
}

/// Microseconds a transaction: the best of `reps` passes over `txs` in chunks.
fn time_per_tx(txs: &[AltSigTx], chunk: usize, reps: usize, verify: &dyn Fn(&[&AltSigTx]) -> usize) -> f64 {
    let refs: Vec<&AltSigTx> = txs.iter().collect();
    let mut best = f64::MAX;
    let mut sink = 0usize;
    for _ in 0..reps {
        let start = Instant::now();
        for c in refs.chunks(chunk) {
            sink += verify(c);
        }
        best = best.min(start.elapsed().as_secs_f64());
    }
    std::hint::black_box(sink);
    best * 1e6 / txs.len() as f64
}

#[test]
#[ignore = "measurement; run in release with --nocapture"]
fn worst_case_cost_table() {
    let total: usize = std::env::var("BENCH_TXS").ok().and_then(|v| v.parse().ok()).unwrap_or(4096);
    let reps: usize = std::env::var("BENCH_REPS").ok().and_then(|v| v.parse().ok()).unwrap_or(5);
    let one_key = std::env::var("BENCH_ONE_KEY").is_ok_and(|v| v == "1");
    let mut rng = Rng(42);
    // Distinct keys by default: no key terms merge, the dearer batch.
    let keys: Vec<Key> = (0..if one_key { 1 } else { total }).map(|_| Key::new(&mut rng)).collect();
    type Bad = Box<dyn Fn(usize) -> Vec<usize>>;
    let scenarios: Vec<(&str, Kind, Bad)> = vec![
        ("all valid", Kind::Valid, Box::new(|_| vec![])),
        ("1 invalid, first", Kind::WrongMessage, Box::new(|_| vec![0])),
        ("1 invalid, middle", Kind::WrongMessage, Box::new(|n| vec![n / 2])),
        ("1 invalid, last", Kind::WrongMessage, Box::new(|n| vec![n - 1])),
        ("2 invalid (first, middle)", Kind::WrongMessage, Box::new(|n| vec![0, n / 2])),
        ("8 invalid (spread)", Kind::WrongMessage, Box::new(|n| (0..8).map(|i| i * n / 8).collect())),
        ("half invalid (alternate)", Kind::WrongMessage, Box::new(|n| (0..n).step_by(2).collect())),
        ("all invalid", Kind::WrongMessage, Box::new(|n| (0..n).collect())),
        ("1 small-order R", Kind::SmallOrderR, Box::new(|_| vec![0])),
        ("1 off-curve R", Kind::OffCurveR, Box::new(|_| vec![0])),
        ("all off-curve R", Kind::OffCurveR, Box::new(|n| (0..n).collect())),
        ("all small-order R", Kind::SmallOrderR, Box::new(|n| (0..n).collect())),
        ("1 non-canonical s", Kind::NonCanonicalS, Box::new(|_| vec![0])),
        ("all non-canonical s", Kind::NonCanonicalS, Box::new(|n| (0..n).collect())),
        ("all off-curve key", Kind::OffCurveKey, Box::new(|n| (0..n).collect())),
        ("all small-order key", Kind::SmallOrderKey, Box::new(|n| (0..n).collect())),
        ("all short signature", Kind::ShortSignature, Box::new(|n| (0..n).collect())),
    ];
    println!("txs a cell {total}, best of {reps}, keys {}", if one_key { "one" } else { "distinct" });
    for chunk in [64usize, 128, 256] {
        println!();
        println!("chunk {chunk}: us a transaction (amplification against all valid, linear)");
        println!("| case | linear (before) | single (after) | bisect |");
        println!("| --- | --- | --- | --- |");
        let mut base = 0.0;
        for (name, kind, bad) in &scenarios {
            let txs = pool(&mut rng, &keys, total / chunk, chunk, *kind, bad.as_ref());
            // Warm the key cache.
            let refs: Vec<&AltSigTx> = txs.iter().collect();
            let _ = verify_batch_linear(&refs);
            let linear = time_per_tx(&txs, chunk, reps, &|c| verify_batch_linear(c).iter().filter(|r| r.is_ok()).count());
            let single = time_per_tx(&txs, chunk, reps, &|c| {
                verify_batch_with(c, BatchFallback::Single).iter().filter(|r| r.is_ok()).count()
            });
            let bisect = time_per_tx(&txs, chunk, reps, &|c| {
                verify_batch_with(c, BatchFallback::Bisect).iter().filter(|r| r.is_ok()).count()
            });
            if *name == "all valid" {
                base = linear;
            }
            println!(
                "| {name} | {linear:.2} ({:.2}x) | {single:.2} ({:.2}x) | {bisect:.2} ({:.2}x) |",
                linear / base,
                single / base,
                bisect / base
            );
        }
    }
    // The single check alone, for reference.
    let txs = pool(&mut rng, &keys, 1, 1024, Kind::Valid, &|_| vec![]);
    let single = time_per_tx(&txs, 1, reps, &|c| c.iter().filter(|tx| tx.verify().is_ok()).count());
    println!();
    println!("AltSigTx::verify alone: {single:.2} us");
}
