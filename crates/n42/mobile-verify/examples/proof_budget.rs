// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The phone's proof budget, measured piece by piece: what a light client downloads and
//! verifies to read one account or one storage slot, and to trust the root it reads against.
//!
//! ```text
//! cargo run --release -p n42-mobile-verify --example proof_budget -- [accounts 1000000] [samples 20000]
//! ```
//!
//! - **State.** A [`QmdbCompatTree`] of `accounts` accounts in gov5's leaf encoding (1 in 100 a
//!   contract with a code hash), `accounts / 2` storage slots spread over the contracts, then
//!   `accounts / 4` account rewrites, so a quarter of the slots below the cursor are dead the way a
//!   live QMDB's are. Proofs are cut with [`QmdbCompatTree::prove`] (what `n42_getProof` and
//!   `mobile_getProof` serve), encoded in gov5's v2 layout, then decoded and verified with
//!   [`QmdbProof::decode`] + [`QmdbProof::verify_for_key`] one at a time on one thread.
//! - **Past height.** Proofs cut after the initial load, before the rewrites, verified against the
//!   root the tree had then. `history.rs` rebuilds exactly that tree for a past block and cuts the
//!   same layout; this does not go through `history.rs`.
//! - **Exclusion.** QMDB proofs prove membership only; an absent key has no proof (the RPC answers
//!   `found: false` on the node's word). The run checks that `prove` returns `None` and says so.
//! - **Finality.** An H2-v4 `Decide` (what `mobile_finality` serves) over a seven-key validator set
//!   (the fleet7 genesis) with a quorum of five signers: envelope bytes, snappy gossip bytes, and
//!   `decode_envelope` + `verify_h2_v4_decide` time. A gov5 header (RLP, from the h2-consensus
//!   fixtures) is what binds the decided hash to a state root: its size and keccak time.
//! - **Committee evidence.** For scale only: a BLS aggregate checked against 512 keys (the fleet7
//!   genesis `committeeSize`). That evidence is not a root of trust (see
//!   `docs/PROOF_TRUST_INVENTORY.md`).
//!
//! Allocation is counted by a wrapping global allocator; "peak" is the most bytes live during one
//! decode + verify above what was live before it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use alloy_primitives::{keccak256, B256};
use n42_h2_consensus::{h2_finality::verify_h2_v4_decide, ValidatorInfo, ValidatorSet};
use n42_h2_primitives::bls::{AggregateSignature, BlsPublicKey, BlsSecretKey, BlsSignature};
use n42_h2_wire::h2_v4::{
    commit_signing_message, decode_envelope, encode_envelope, encode_gossip, H2V4ChainIdentity, H2V4Envelope,
};
use n42_h2_wire::h2_wire::{H2Decide, H2Message, H2QuorumCertificate};
use n42_twig_core::qmdb_compat::{
    encode_gov5_account_value, gov5_account_key, gov5_storage_key, QmdbCompatTree, QmdbProof,
};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator and only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Runs `f` and returns its result and the most bytes it held live at once.
fn peak_of<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let out = f();
    (out, PEAK.load(Ordering::Relaxed).saturating_sub(base))
}

/// splitmix64: deterministic, dependency free.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn address(i: u64) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[..8].copy_from_slice(&i.to_be_bytes());
    out[8..16].copy_from_slice(&i.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes());
    out
}

fn account_value(rng: &mut Rng, contract: bool) -> Vec<u8> {
    let mut balance = [0u8; 32];
    let len = 6 + rng.below(7) as usize; // 6..12 significant bytes
    for byte in &mut balance[32 - len..] {
        *byte = rng.next() as u8;
    }
    balance[32 - len] |= 1;
    let code_hash = if contract { *keccak256(rng.next().to_be_bytes()) } else { [0u8; 32] };
    encode_gov5_account_value(1 + rng.below(2000), &balance, &code_hash)
}

fn slot_value(rng: &mut Rng) -> Vec<u8> {
    let mut value = [0u8; 32];
    value[24..].copy_from_slice(&rng.next().to_be_bytes());
    value[24] |= 1;
    value.to_vec()
}

#[derive(Default)]
struct Series {
    bytes: Vec<usize>,
    nanos: Vec<u64>,
    peak: usize,
    upper: Vec<usize>,
}

impl Series {
    fn report(&mut self, label: &str) {
        self.bytes.sort_unstable();
        self.nanos.sort_unstable();
        self.upper.sort_unstable();
        let pick = |v: &[u64], q: f64| v[((v.len() - 1) as f64 * q) as usize];
        let pickb = |v: &[usize], q: f64| v[((v.len() - 1) as f64 * q) as usize];
        println!(
            "{label:<28} n={:>6}  bytes min/med/max {:>5}/{:>5}/{:>5}  upper path {}..{}  verify us med {:>6.2} p99 {:>6.2} max {:>7.2}  peak alloc {} B",
            self.nanos.len(),
            pickb(&self.bytes, 0.0),
            pickb(&self.bytes, 0.5),
            pickb(&self.bytes, 1.0),
            pickb(&self.upper, 0.0),
            pickb(&self.upper, 1.0),
            pick(&self.nanos, 0.5) as f64 / 1e3,
            pick(&self.nanos, 0.99) as f64 / 1e3,
            pick(&self.nanos, 1.0) as f64 / 1e3,
            self.peak,
        );
    }
}

/// Decodes and verifies every encoded proof against `root`, one at a time.
fn measure(proofs: &[(Vec<u8>, [u8; 32])], root: &[u8; 32]) -> Series {
    let mut series = Series::default();
    for (encoded, key) in proofs {
        let start = Instant::now();
        let (ok, peak) = peak_of(|| {
            QmdbProof::decode(encoded).map(|p| (p.verify_for_key(root, key), p.upper_path.len()))
        });
        let elapsed = start.elapsed();
        let (ok, upper) = ok.expect("proof decodes");
        assert!(ok, "proof verifies");
        series.bytes.push(encoded.len());
        series.nanos.push(elapsed.as_nanos() as u64);
        series.peak = series.peak.max(peak);
        series.upper.push(upper);
    }
    series
}

fn cut(tree: &QmdbCompatTree, keys: &[[u8; 32]]) -> Vec<(Vec<u8>, [u8; 32])> {
    keys.iter()
        .map(|key| (tree.prove(key).expect("live key").encode().expect("encodes"), *key))
        .collect()
}

fn timed<T>(label: &str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    println!("{label}: {:.1} s", start.elapsed().as_secs_f64());
    out
}

fn quantiles(mut nanos: Vec<u64>) -> (f64, f64) {
    nanos.sort_unstable();
    let q = |p: f64| nanos[((nanos.len() - 1) as f64 * p) as usize] as f64 / 1e3;
    (q(0.5), q(0.99))
}

fn finality() {
    let identity = H2V4ChainIdentity { chain_id: 94, genesis_hash: B256::repeat_byte(0x11) };
    let keys: Vec<BlsSecretKey> =
        (1..=7u8).map(|seed| BlsSecretKey::key_gen(&[seed; 32]).expect("keygen")).collect();
    let validators: Vec<ValidatorInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| ValidatorInfo {
            address: alloy_primitives::Address::with_last_byte(i as u8 + 1),
            bls_public_key: key.public_key(),
            p2p_peer_id: None,
        })
        .collect();
    let set = ValidatorSet::new(&validators, 2);
    let quorum = set.quorum_size();
    for signers in [quorum, keys.len()] {
        let view = 1_234_567;
        let block_hash = B256::repeat_byte(0x44);
        let changes_hash = B256::repeat_byte(0x22);
        let message = commit_signing_message(identity, view, block_hash, changes_hash);
        let sigs: Vec<BlsSignature> = keys[..signers].iter().map(|k| k.sign_h2_v4(&message)).collect();
        let refs: Vec<&BlsSignature> = sigs.iter().collect();
        let mut bitmap = Vec::with_capacity(2 + keys.len().div_ceil(8));
        bitmap.extend_from_slice(&(keys.len() as u16).to_le_bytes());
        bitmap.resize(2 + keys.len().div_ceil(8), 0);
        for i in 0..signers {
            bitmap[2 + i / 8] |= 1 << (i % 8);
        }
        let qc = H2QuorumCertificate {
            view,
            block_hash,
            aggregate_signature: AggregateSignature::aggregate(&refs).expect("aggregate").to_bytes().to_vec(),
            signers_bitmap: bitmap,
        };
        let envelope =
            H2V4Envelope { identity, changes_hash, message: H2Message::Decide(H2Decide { view, block_hash, commit_qc: qc }) };
        let wire = encode_envelope(&envelope).expect("encodes");
        let gossip = encode_gossip(&envelope).expect("encodes");
        let mut nanos = Vec::new();
        let mut peak = 0;
        for _ in 0..300 {
            let start = Instant::now();
            let (proof, p) = peak_of(|| {
                let decoded = decode_envelope(&wire, identity).expect("decodes");
                verify_h2_v4_decide(&decoded, &set)
            });
            nanos.push(start.elapsed().as_nanos() as u64);
            proof.expect("verifies");
            peak = peak.max(p);
        }
        let (med, p99) = quantiles(nanos);
        println!(
            "decide 7 validators, {signers} signers: envelope {} B, snappy gossip {} B, decode+verify us med {med:.0} p99 {p99:.0}, peak alloc {peak} B",
            wire.len(),
            gossip.len()
        );
    }

    let header = include_bytes!("../../h2-consensus/testdata/header_field_parity/gov5_header_bal22_slot23_root24.rlp");
    let mut nanos = Vec::new();
    for _ in 0..10_000 {
        let start = Instant::now();
        std::hint::black_box(keccak256(std::hint::black_box(&header[..])));
        nanos.push(start.elapsed().as_nanos() as u64);
    }
    let (med, p99) = quantiles(nanos);
    println!("gov5 header RLP (fixture gov5_header_bal22_slot23_root24): {} B, keccak us med {med:.2} p99 {p99:.2}", header.len());

    // Committee-evidence scale: one aggregate over 512 keys.
    let committee: Vec<BlsSecretKey> = (0..512u32)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[..4].copy_from_slice(&i.to_le_bytes());
            ikm[31] = 0xA5;
            BlsSecretKey::key_gen(&ikm).expect("keygen")
        })
        .collect();
    let message = [0x5Au8; 40];
    let sigs: Vec<BlsSignature> = committee.iter().map(|k| k.sign_h2_v4(&message)).collect();
    let refs: Vec<&BlsSignature> = sigs.iter().collect();
    let aggregate = AggregateSignature::aggregate(&refs).expect("aggregate");
    let pks: Vec<BlsPublicKey> = committee.iter().map(BlsSecretKey::public_key).collect();
    let pk_refs: Vec<&BlsPublicKey> = pks.iter().collect();
    let mut nanos = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        AggregateSignature::verify_h2_v4_aggregate(&message, &aggregate, &pk_refs).expect("verifies");
        nanos.push(start.elapsed().as_nanos() as u64);
    }
    let (med, p99) = quantiles(nanos);
    println!(
        "BLS aggregate over 512 keys (committee size): sig 96 B + 512 x 48 B keys = {} B if shipped, verify us med {med:.0} p99 {p99:.0}",
        96 + 512 * 48
    );
}

fn main() {
    let mut args = std::env::args().skip(1);
    let accounts: u64 = args.next().map_or(1_000_000, |a| a.parse().expect("accounts"));
    let samples: usize = args.next().map_or(20_000, |a| a.parse().expect("samples"));
    let contracts = (accounts / 100).max(1);
    let slots = accounts / 2;
    let rewrites = accounts / 4;
    println!("shape: {accounts} accounts ({contracts} contracts), {slots} storage slots, {rewrites} account rewrites; {samples} samples per series");

    let mut rng = Rng(0x0042_0042);
    let mut tree = QmdbCompatTree::new();
    timed("load", || {
        for i in 0..accounts {
            let value = account_value(&mut rng, i < contracts);
            tree.set(gov5_account_key(&address(i)), value).expect("set");
        }
        for j in 0..slots {
            let contract = address(j % contracts);
            let mut slot = [0u8; 32];
            slot[24..].copy_from_slice(&(j / contracts).to_be_bytes());
            tree.set(gov5_storage_key(&contract, &slot), slot_value(&mut rng)).expect("set");
        }
    });
    let past_root = timed("past root", || tree.root());

    let mut pick = Rng(7);
    let account_keys: Vec<[u8; 32]> =
        (0..samples).map(|_| gov5_account_key(&address(pick.below(accounts)))).collect();
    let storage_keys: Vec<[u8; 32]> = (0..samples)
        .map(|_| {
            let j = pick.below(slots);
            let mut slot = [0u8; 32];
            slot[24..].copy_from_slice(&(j / contracts).to_be_bytes());
            gov5_storage_key(&address(j % contracts), &slot)
        })
        .collect();
    let past_accounts = timed("cut past account proofs", || cut(&tree, &account_keys));
    let past_storage = timed("cut past storage proofs", || cut(&tree, &storage_keys));

    timed("rewrites", || {
        for _ in 0..rewrites {
            let i = rng.below(accounts);
            let value = account_value(&mut rng, i < contracts);
            tree.set(gov5_account_key(&address(i)), value).expect("set");
        }
    });
    let head_root = timed("head root", || tree.root());
    println!("tree: {} live keys, {} slots below the cursor", tree.len(), tree.next_slot());
    let head_accounts = timed("cut head account proofs", || cut(&tree, &account_keys));
    let head_storage = timed("cut head storage proofs", || cut(&tree, &storage_keys));

    let absent = gov5_account_key(&address(accounts + 1));
    assert!(tree.prove(&absent).is_none());
    println!("exclusion: an absent key has no proof in the QMDB v2 format (prove -> None); nothing to measure");

    // Warm the verifier once so the first sample does not pay page faults.
    let _ = measure(&head_accounts[..head_accounts.len().min(100)], &head_root);
    measure(&head_accounts, &head_root).report("account, head");
    measure(&head_storage, &head_root).report("storage slot, head");
    measure(&past_accounts, &past_root).report("account, past height");
    measure(&past_storage, &past_root).report("storage slot, past height");

    finality();
}
