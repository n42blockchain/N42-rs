// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Behavioural tests for the ingest's frame decoding, recovery paths, gate
//! helpers and wire protocol.
//!
//! The ingest keeps its counters in process-wide statics, so every test that
//! reads a counter delta, or flips the 0x50 flag, holds [`counter_lock`]; the
//! tests of the older modules that touch the same state take it too.

#![allow(clippy::await_holding_lock)]

use super::*;
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Signature, TxKind, U256};
use n42_engine_types::N42PooledTransaction;
use n42_tx_types::{TxAltSig, ALG_ED25519};
use reth_ethereum_primitives::PooledTransactionVariant;
use reth_transaction_pool::noop::NoopTransactionPool;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

type Pool = NoopTransactionPool<N42PooledTransaction>;

static COUNTERS: Mutex<()> = Mutex::new(());

/// Serialises the tests that read the ingest's global counters or the 0x50 flag.
pub(crate) fn counter_lock() -> MutexGuard<'static, ()> {
    COUNTERS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn load(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------- builders

/// A signed 0x50 transaction; seeds and nonces here are chosen not to collide
/// with the other test modules, which share the global sender cache.
fn alt_tx(seed: u8, nonce: u64) -> AltSigTx {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    TxAltSig {
        chain_id: 94,
        nonce,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 2_000_000_000,
        gas_limit: 21_000,
        to: Address::repeat_byte(0xaa),
        value: U256::from(1u64),
        input: Bytes::new(),
        access_list: Default::default(),
        alg_type: ALG_ED25519,
        pubkey: Bytes::copy_from_slice(key.verifying_key().as_bytes()),
    }
    .sign_ed25519(&key)
}

/// The same transaction with one signature byte flipped.
fn broken_alt_tx(seed: u8, nonce: u64) -> AltSigTx {
    let (tx, signature, _) = alt_tx(seed, nonce).into_parts();
    let mut bad = signature.to_vec();
    bad[10] ^= 0x40;
    AltSigTx::new(tx, Bytes::from(bad))
}

fn alt(seed: u8, nonce: u64) -> N42PooledTxEnvelope {
    N42PooledTxEnvelope::AltSig(alt_tx(seed, nonce))
}

fn secp_key(index: u8) -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_slice(&[index; 32]).expect("a valid key")
}

fn secp_address(index: u8) -> Address {
    let public = secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &secp_key(index));
    Address::from_slice(&keccak256(&public.serialize_uncompressed()[1..])[12..])
}

/// A signed EIP-1559 transfer from the sender of `key_index`.
fn eth_tx(key_index: u8, nonce: u64) -> N42PooledTxEnvelope {
    let tx = TxEip1559 {
        chain_id: 94,
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 10_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(Address::repeat_byte(0xbb)),
        value: U256::from(1u64),
        ..Default::default()
    };
    let message = secp256k1::Message::from_digest(tx.signature_hash().0);
    let (recovery_id, compact) = secp256k1::SECP256K1
        .sign_ecdsa_recoverable(&message, &secp_key(key_index))
        .serialize_compact();
    let signature = Signature::new(
        U256::from_be_slice(&compact[..32]),
        U256::from_be_slice(&compact[32..]),
        i32::from(recovery_id) != 0,
    );
    N42PooledTxEnvelope::Eth(PooledTransactionVariant::Eip1559(tx.into_signed(signature)))
}

/// An EIP-1559 transfer whose signature cannot recover (r = s = 0).
fn unrecoverable_eth_tx(nonce: u64) -> N42PooledTxEnvelope {
    let tx = TxEip1559 { chain_id: 94, nonce, gas_limit: 21_000, ..Default::default() };
    let signature = Signature::new(U256::ZERO, U256::ZERO, false);
    N42PooledTxEnvelope::Eth(PooledTransactionVariant::Eip1559(tx.into_signed(signature)))
}

fn raw(tx: &N42PooledTxEnvelope) -> Bytes {
    Bytes::from(tx.encoded_2718())
}

fn recover(
    pooled: Vec<N42PooledTxEnvelope>,
    claims: Vec<Address>,
    shard: Option<(u64, u64)>,
    attested: bool,
) -> Vec<N42PooledTransaction> {
    recover_decoded_in::<Pool>(pooled, claims, None, shard, attested)
}

fn sender_of(txs: &[N42PooledTransaction], hash: &B256) -> Address {
    txs.iter().find(|tx| tx.hash() == hash).expect("the transaction came out").sender()
}

fn alt_sender(tx: &AltSigTx) -> Address {
    tx.sender()
}

// ---------------------------------------------------------- decode_frame

#[test]
fn decode_drops_the_undecodable_and_keeps_claims_aligned() {
    let _g = counter_lock();
    let (a, b) = (alt(60, 70_000), eth_tx(1, 0));
    let raws = vec![raw(&a), Bytes::from_static(&[0xff, 0x01, 0x02]), raw(&b)];
    let claims = vec![Address::repeat_byte(1), Address::repeat_byte(2), Address::repeat_byte(3)];
    let before = load(&STATS.dropped_decode);

    let (decoded, kept) = decode_frame::<Pool>(raws, claims);

    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].hash(), a.hash());
    assert_eq!(decoded[1].hash(), b.hash());
    assert_eq!(kept, vec![Address::repeat_byte(1), Address::repeat_byte(3)]);
    assert_eq!(load(&STATS.dropped_decode) - before, 1);
}

#[test]
fn decode_ignores_claims_that_do_not_match_the_frame() {
    let _g = counter_lock();
    let tx = alt(60, 70_001);
    // Too few claims: none are kept, and the transactions still decode.
    let (decoded, kept) = decode_frame::<Pool>(
        vec![raw(&tx), raw(&tx)],
        vec![Address::repeat_byte(1)],
    );
    assert_eq!(decoded.len(), 2);
    assert!(kept.is_empty());
    // No claims at all.
    let (decoded, kept) = decode_frame::<Pool>(vec![raw(&tx)], Vec::new());
    assert_eq!(decoded.len(), 1);
    assert!(kept.is_empty());
}

#[test]
fn decode_of_only_garbage_yields_nothing_and_counts_every_drop() {
    let _g = counter_lock();
    let before = load(&STATS.dropped_decode);
    let (decoded, kept) = decode_frame::<Pool>(
        vec![Bytes::from_static(b"\x01"), Bytes::from_static(b"\xc0"), Bytes::new()],
        Vec::new(),
    );
    assert!(decoded.is_empty() && kept.is_empty());
    assert_eq!(load(&STATS.dropped_decode) - before, 3);
}

// ------------------------------------------------------ recover_decoded_in

#[test]
fn ecdsa_transactions_are_recovered_to_their_real_sender() {
    let _g = counter_lock();
    let txs = vec![eth_tx(3, 0), eth_tx(4, 0), eth_tx(3, 1)];
    let hashes: Vec<B256> = txs.iter().map(|tx| *tx.hash()).collect();
    let (claimed_before, verified_before) = (load(&STATS.claimed), load(&STATS.verified_at_ingest));

    let out = recover(txs, Vec::new(), None, false);

    assert_eq!(out.len(), 3);
    assert_eq!(sender_of(&out, &hashes[0]), secp_address(3));
    assert_eq!(sender_of(&out, &hashes[1]), secp_address(4));
    assert_eq!(sender_of(&out, &hashes[2]), secp_address(3));
    assert_eq!(load(&STATS.verified_at_ingest) - verified_before, 3);
    assert_eq!(load(&STATS.claimed) - claimed_before, 0);
}

#[test]
fn the_recovery_cache_gives_the_same_senders() {
    let _g = counter_lock();
    let cache = reth_evm::SenderRecoveryCache::new(64);
    let txs = vec![eth_tx(5, 0), eth_tx(6, 0)];
    for _ in 0..2 {
        // The second pass is served from the cache and must not change the answer.
        let out = recover_decoded_in::<Pool>(txs.clone(), Vec::new(), Some(&cache), None, false);
        assert_eq!(out.len(), 2);
        assert_eq!(sender_of(&out, txs[0].hash()), secp_address(5));
        assert_eq!(sender_of(&out, txs[1].hash()), secp_address(6));
    }
}

#[test]
fn an_unrecoverable_signature_is_dropped_and_counted() {
    let _g = counter_lock();
    let good = eth_tx(7, 0);
    let good_hash = *good.hash();
    let before = load(&STATS.dropped_signature);

    let out = recover(vec![unrecoverable_eth_tx(0), good, unrecoverable_eth_tx(1)], Vec::new(), None, false);

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].hash(), &good_hash);
    assert_eq!(out[0].sender(), secp_address(7));
    assert_eq!(load(&STATS.dropped_signature) - before, 2);
}

#[test]
fn a_claiming_frame_is_queued_under_the_claims_without_verification() {
    let _g = counter_lock();
    n42_tx_types::set_alt_sig_enabled(true);
    // The unrecoverable transaction would be dropped if anything verified it.
    let txs = vec![eth_tx(8, 0), unrecoverable_eth_tx(5), alt(61, 70_100)];
    let hashes: Vec<B256> = txs.iter().map(|tx| *tx.hash()).collect();
    let claims = vec![Address::repeat_byte(0x11), Address::repeat_byte(0x22), Address::repeat_byte(0x33)];
    let (claimed_before, verified_before) = (load(&STATS.claimed), load(&STATS.verified_at_ingest));
    let (shard_claimed, shard_verified) = (load(&STATS.shard_claimed), load(&STATS.shard_verified));

    let out = recover(txs, claims, None, false);

    assert_eq!(out.len(), 3);
    assert_eq!(sender_of(&out, &hashes[0]), Address::repeat_byte(0x11));
    assert_eq!(sender_of(&out, &hashes[1]), Address::repeat_byte(0x22));
    assert_eq!(sender_of(&out, &hashes[2]), Address::repeat_byte(0x33));
    assert_eq!(load(&STATS.claimed) - claimed_before, 3);
    assert_eq!(load(&STATS.verified_at_ingest) - verified_before, 0);
    // Not shard mode: the shard counters stay put.
    assert_eq!(load(&STATS.shard_claimed), shard_claimed);
    assert_eq!(load(&STATS.shard_verified), shard_verified);
}

#[test]
fn claims_of_the_wrong_length_are_not_used() {
    let _g = counter_lock();
    let tx = eth_tx(9, 0);
    let hash = *tx.hash();
    let out = recover(vec![tx], vec![Address::repeat_byte(1), Address::repeat_byte(2)], None, false);
    assert_eq!(out.len(), 1);
    assert_eq!(sender_of(&out, &hash), secp_address(9), "verified, as with no claim");
}

#[test]
fn a_claiming_frame_still_refuses_0x50_on_a_chain_that_does_not_enable_it() {
    let _g = counter_lock();
    n42_tx_types::set_alt_sig_enabled(false);
    let (eth, a) = (eth_tx(10, 0), alt(61, 70_101));
    let eth_hash = *eth.hash();
    let before = load(&STATS.dropped_altsig_disabled);

    let out = recover(vec![eth, a], vec![Address::repeat_byte(1), Address::repeat_byte(2)], None, false);

    n42_tx_types::set_alt_sig_enabled(true);
    assert_eq!(out.len(), 1);
    assert_eq!(sender_of(&out, &eth_hash), Address::repeat_byte(1));
    assert_eq!(load(&STATS.dropped_altsig_disabled) - before, 1);
}

#[test]
fn unclaimed_0x50_is_dropped_wholesale_when_the_chain_does_not_enable_it() {
    let _g = counter_lock();
    n42_tx_types::set_alt_sig_enabled(false);
    let eth = eth_tx(11, 0);
    let eth_hash = *eth.hash();
    let (dropped, batches) = (load(&STATS.dropped_altsig_disabled), load(&STATS.altsig_batches));

    let out = recover(vec![alt(62, 70_200), eth, alt(62, 70_201)], Vec::new(), None, false);

    n42_tx_types::set_alt_sig_enabled(true);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].hash(), &eth_hash);
    assert_eq!(load(&STATS.dropped_altsig_disabled) - dropped, 2);
    assert_eq!(load(&STATS.altsig_batches), batches, "nothing was handed to the batch verifier");
}

#[test]
fn a_broken_0x50_signature_is_dropped_and_its_neighbours_survive() {
    let _g = counter_lock();
    n42_tx_types::set_alt_sig_enabled(true);
    let good_a = alt_tx(63, 70_300);
    let good_b = alt_tx(64, 70_301);
    let bad = broken_alt_tx(65, 70_302);
    let pooled = vec![
        N42PooledTxEnvelope::AltSig(good_a.clone()),
        N42PooledTxEnvelope::AltSig(bad),
        N42PooledTxEnvelope::AltSig(good_b.clone()),
    ];
    let (dropped, txs, verified) =
        (load(&STATS.dropped_altsig), load(&STATS.altsig_txs), load(&STATS.verified_at_ingest));

    let out = recover(pooled, Vec::new(), None, false);

    assert_eq!(out.len(), 2);
    assert_eq!(sender_of(&out, good_a.hash()), alt_sender(&good_a));
    assert_eq!(sender_of(&out, good_b.hash()), alt_sender(&good_b));
    assert_eq!(load(&STATS.dropped_altsig) - dropped, 1);
    assert_eq!(load(&STATS.altsig_txs) - txs, 3);
    assert_eq!(load(&STATS.verified_at_ingest) - verified, 2);
}

#[test]
fn a_verified_0x50_sender_is_cached_and_not_verified_twice() {
    let _g = counter_lock();
    n42_tx_types::set_alt_sig_enabled(true);
    let tx = alt_tx(66, 70_400);
    let hash = *tx.hash();
    let first = recover(vec![N42PooledTxEnvelope::AltSig(tx.clone())], Vec::new(), None, false);
    assert_eq!(first.len(), 1);
    assert_eq!(AltSigSenderCache::global().get(&hash), Some(alt_sender(&tx)));

    let verified_before = load(&STATS.altsig_txs);
    let second = recover(vec![N42PooledTxEnvelope::AltSig(tx.clone())], Vec::new(), None, false);
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].sender(), alt_sender(&tx));
    assert_eq!(load(&STATS.altsig_txs), verified_before, "the second pass was a cache hit");
}

#[test]
fn an_attested_frame_keeps_the_0x50_gate_and_verifies_other_transactions() {
    let _g = counter_lock();
    n42_tx_types::set_alt_sig_enabled(false);
    let eth = eth_tx(12, 0);
    let eth_hash = *eth.hash();
    // A 0x50 transaction whose signature is broken: attested admission would
    // take it if the chain enabled the type.
    let pooled = vec![N42PooledTxEnvelope::AltSig(broken_alt_tx(67, 70_500)), eth];
    let before = load(&STATS.dropped_altsig_disabled);
    let attested_before = load(&STATS.attested_txs);

    let out = recover(pooled, Vec::new(), None, true);

    n42_tx_types::set_alt_sig_enabled(true);
    assert_eq!(out.len(), 1);
    assert_eq!(sender_of(&out, &eth_hash), secp_address(12), "an Ethereum transaction is verified");
    assert_eq!(load(&STATS.dropped_altsig_disabled) - before, 1);
    assert_eq!(load(&STATS.attested_txs), attested_before);
}

#[test]
fn an_attested_frame_admits_0x50_on_its_key_and_counts_them() {
    let _g = counter_lock();
    n42_tx_types::set_alt_sig_enabled(true);
    let broken = broken_alt_tx(68, 70_600);
    let hash = *broken.hash();
    let expected = alt_sender(&broken);
    let before = (load(&STATS.attested_txs), load(&STATS.altsig_txs));

    let out = recover(vec![N42PooledTxEnvelope::AltSig(broken)], Vec::new(), None, true);

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].sender(), expected);
    assert_eq!(AltSigSenderCache::global().get(&hash), Some(expected));
    assert_eq!(load(&STATS.attested_txs) - before.0, 1);
    assert_eq!(load(&STATS.altsig_txs), before.1, "no signature work");
}

#[test]
fn shard_mode_ignores_the_shard_without_claims() {
    let _g = counter_lock();
    n42_tx_types::set_alt_sig_enabled(true);
    let tx = eth_tx(13, 0);
    let hash = *tx.hash();
    let before = (load(&STATS.shard_claimed), load(&STATS.shard_verified));

    // No claims: the shard does not apply and the frame is verified as under `all`.
    let out = recover(vec![tx], Vec::new(), Some((0, 2)), false);

    assert_eq!(sender_of(&out, &hash), secp_address(13));
    assert_eq!((load(&STATS.shard_claimed), load(&STATS.shard_verified)), before);
}

#[test]
fn shard_mode_verifies_its_ecdsa_shard_and_claims_the_rest() {
    let _g = counter_lock();
    n42_tx_types::set_alt_sig_enabled(true);
    let shard = (0u64, 2u64);
    let txs: Vec<N42PooledTxEnvelope> = (0..24u64).map(|n| eth_tx(14, n)).collect();
    let claim = Address::repeat_byte(0x77);
    let mine: Vec<bool> = txs.iter().map(|tx| in_my_shard(tx.hash(), shard)).collect();
    let owned = mine.iter().filter(|m| **m).count() as u64;
    assert!(owned > 0 && owned < 24, "a spread across shards: {owned}");
    let hashes: Vec<B256> = txs.iter().map(|tx| *tx.hash()).collect();
    let before = (load(&STATS.shard_claimed), load(&STATS.shard_verified));

    let out = recover(txs, vec![claim; 24], Some(shard), false);

    assert_eq!(out.len(), 24);
    for (at, hash) in hashes.iter().enumerate() {
        let expected = if mine[at] { secp_address(14) } else { claim };
        assert_eq!(sender_of(&out, hash), expected, "transaction {at}, in shard: {}", mine[at]);
    }
    assert_eq!(load(&STATS.shard_verified) - before.1, owned);
    assert_eq!(load(&STATS.shard_claimed) - before.0, 24 - owned);
}

#[test]
fn the_shard_and_sender_counters_add_a_frames_tally() {
    let _g = counter_lock();
    let before = (
        load(&STATS.claimed),
        load(&STATS.verified_at_ingest),
        load(&STATS.shard_claimed),
        load(&STATS.shard_verified),
    );
    count_senders(0, 0);
    count_shard(0, 0);
    assert_eq!(
        before,
        (
            load(&STATS.claimed),
            load(&STATS.verified_at_ingest),
            load(&STATS.shard_claimed),
            load(&STATS.shard_verified)
        ),
        "an empty tally changes nothing"
    );
    count_senders(5, 7);
    count_shard(3, 11);
    assert_eq!(load(&STATS.claimed) - before.0, 5);
    assert_eq!(load(&STATS.verified_at_ingest) - before.1, 7);
    assert_eq!(load(&STATS.shard_claimed) - before.2, 3);
    assert_eq!(load(&STATS.shard_verified) - before.3, 11);
}

// ---------------------------------------------------------- frame_attested

fn trusted(key: &ed25519_dalek::SigningKey, min: usize) -> FrameAttest {
    FrameAttest {
        gateways: n42_tx_types::FrameGateways::new(vec![key.verifying_key()], min),
        chain_id: 94,
    }
}

#[test]
fn a_frame_without_settings_or_attestations_is_not_attested() {
    let _g = counter_lock();
    let key = ed25519_dalek::SigningKey::from_bytes(&[90; 32]);
    let config = trusted(&key, 1);
    let hashes = vec![B256::repeat_byte(1), B256::repeat_byte(2)];
    let root = n42_tx_types::frame_root(&hashes);
    let attestation = n42_tx_types::FrameAttestation::sign(&key, 94, root);
    let before = (load(&STATS.frames_attested), load(&STATS.frames_attest_short), load(&STATS.frames_attest_bad));

    // No gateway configured on this node.
    assert_eq!(frame_attested(2, &hashes, std::slice::from_ref(&attestation), None), (false, None));
    // Gateways configured, but the frame carries no attestation.
    assert_eq!(frame_attested(2, &hashes, &[], Some(&config)), (false, None));

    assert_eq!(
        before,
        (load(&STATS.frames_attested), load(&STATS.frames_attest_short), load(&STATS.frames_attest_bad))
    );
}

#[test]
fn a_frame_missing_a_transaction_cannot_be_attested() {
    let _g = counter_lock();
    let key = ed25519_dalek::SigningKey::from_bytes(&[90; 32]);
    let config = trusted(&key, 1);
    let hashes = vec![B256::repeat_byte(1), B256::repeat_byte(2)];
    let root = n42_tx_types::frame_root(&hashes);
    let attestation = n42_tx_types::FrameAttestation::sign(&key, 94, root);
    let short_before = load(&STATS.frames_attest_short);

    // The frame carried three transactions; only two decoded.
    assert_eq!(frame_attested(3, &hashes, std::slice::from_ref(&attestation), Some(&config)), (false, None));
    // Nothing decoded at all.
    assert_eq!(frame_attested(0, &[], std::slice::from_ref(&attestation), Some(&config)), (false, None));

    assert_eq!(load(&STATS.frames_attest_short) - short_before, 2);
}

#[test]
fn a_valid_attestation_admits_and_returns_the_frame_root() {
    let _g = counter_lock();
    let key = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
    let config = trusted(&key, 1);
    let hashes = vec![B256::repeat_byte(3), B256::repeat_byte(4), B256::repeat_byte(5)];
    let root = n42_tx_types::frame_root(&hashes);
    let attestation = n42_tx_types::FrameAttestation::sign(&key, 94, root);
    let before = (load(&STATS.frames_attested), load(&STATS.frames_attest_short));

    let verdict = frame_attested(3, &hashes, std::slice::from_ref(&attestation), Some(&config));

    assert_eq!(verdict, (true, Some(root)));
    assert_eq!(load(&STATS.frames_attested) - before.0, 1);
    assert_eq!(load(&STATS.frames_attest_short), before.1);
}

#[test]
fn an_attestation_on_another_chain_or_root_is_short_or_bad() {
    let _g = counter_lock();
    let key = ed25519_dalek::SigningKey::from_bytes(&[92; 32]);
    let config = trusted(&key, 1);
    let hashes = vec![B256::repeat_byte(6), B256::repeat_byte(7)];
    let root = n42_tx_types::frame_root(&hashes);

    // Signed for chain 95, checked on chain 94: not a valid signature of this chain.
    let other_chain = n42_tx_types::FrameAttestation::sign(&key, 95, root);
    let before = (load(&STATS.frames_attested), load(&STATS.frames_attest_short), load(&STATS.frames_attest_bad));
    let (attested, returned_root) = frame_attested(2, &hashes, std::slice::from_ref(&other_chain), Some(&config));
    assert!(!attested);
    assert_eq!(returned_root, Some(root), "the root is computed once and reused as the frame id");
    assert_eq!(load(&STATS.frames_attested), before.0);
    assert_eq!(load(&STATS.frames_attest_short) - before.1, 1);
    assert_eq!(load(&STATS.frames_attest_bad) - before.2, 1);
}

// ---------------------------------------------------------------- frame_of

#[test]
fn frame_of_refuses_a_recovered_set_that_is_not_the_frames() {
    let _g = counter_lock();
    n42_tx_types::set_alt_sig_enabled(true);
    let pooled = vec![alt(69, 70_700), alt(69, 70_701)];
    let hashes: Vec<B256> = pooled.iter().map(|tx| *tx.hash()).collect();
    let recovered = recover(pooled, Vec::new(), None, false);
    assert_eq!(recovered.len(), 2);
    // Same count, but one hash the recovery never produced.
    let foreign = vec![hashes[0], B256::repeat_byte(0xfe)];
    assert_eq!(frame_of(2, foreign, None, &recovered), None);
    // The right hashes in order describe the frame: members in frame order.
    let frame = frame_of(2, hashes.clone(), Some(B256::repeat_byte(9)), &recovered).expect("whole frame");
    assert_eq!(frame.id, B256::repeat_byte(9), "a given root is the id");
    assert_eq!(frame.hashes, hashes);
    assert_eq!(frame.gas, 42_000);
    assert_eq!(frame.members.iter().map(|(_, nonce)| *nonce).collect::<Vec<_>>(), vec![70_700, 70_701]);
    // An empty frame is never described.
    assert_eq!(frame_of::<N42PooledTransaction>(0, Vec::new(), None, &[]), None);
}

#[test]
fn a_frame_with_an_undecodable_member_comes_back_unaligned() {
    let _g = counter_lock();
    n42_tx_types::set_alt_sig_enabled(true);
    let pooled = vec![alt(69, 70_800), alt(69, 70_801)];
    let before = load(&STATS.frames_unaligned);

    // The frame carried three transactions; the third was dropped at decode.
    let (recovered, frame) = recover_frame_with::<Pool>(3, pooled, Vec::new(), &[], None, None, None);

    assert_eq!(recovered.len(), 2, "the two good ones are still admitted");
    assert!(frame.is_none());
    assert_eq!(load(&STATS.frames_unaligned) - before, 1);
}

// ------------------------------------------------------------- gate helpers

#[test]
fn the_gate_view_is_the_pending_count_against_the_mark_plus_lag_allowance() {
    let pool = Pool::new();
    let head = Arc::new(AtomicU64::new(0));

    // Nothing pending: open against any positive mark, shut against zero.
    assert_eq!(gate_view(&pool, None, &head, 10, 0), GateView { open: true, depth: 0, limit: 10 });
    assert_eq!(gate_view(&pool, None, &head, 0, 0), GateView { open: false, depth: 0, limit: 0 });
    assert!(gate_open(&pool, None, &head, 10, 0));
    assert!(!gate_open(&pool, None, &head, 0, 0));

    // The chain is ahead of the pool by two blocks: two allowances are added.
    head.store(2, Ordering::Relaxed);
    assert_eq!(gate_view(&pool, None, &head, 0, 100), GateView { open: true, depth: 0, limit: 200 });
    // The lag is capped at four blocks.
    head.store(1_000, Ordering::Relaxed);
    assert_eq!(gate_view(&pool, None, &head, 5, 100).limit, 405);
    // A pool ahead of the chain never subtracts.
    let ahead = Arc::new(AtomicU64::new(0));
    assert_eq!(gate_view(&pool, None, &ahead, 5, 100).limit, 5);
}

#[test]
fn a_block_is_pending_through_the_public_opener_only_when_the_gate_is_not_strict() {
    let before = BLOCK_PENDING_UNTIL_MS.load(Ordering::Acquire);
    open_gate_for_block(124);
    if gate_strict() {
        // The default: the opening is opt-in, so nothing happens.
        assert_eq!(BLOCK_PENDING_UNTIL_MS.load(Ordering::Acquire), before);
        assert_eq!(block_pending_now(), None);
    } else {
        assert!(BLOCK_PENDING_UNTIL_MS.load(Ordering::Acquire) > before);
        assert_eq!(block_pending_now(), Some(124));
    }
}

#[test]
fn warnings_are_rate_limited_to_one_a_second() {
    // Either limiter: once a call is allowed, the next one inside the
    // second is not. (Another test may hold the slot first, so wait for one.)
    for allowed in [drop_warn_allowed as fn() -> bool, gate_warn_allowed as fn() -> bool] {
        let mut first = false;
        for _ in 0..30 {
            if allowed() {
                first = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(first, "a warning slot opens within three seconds");
        assert!(!allowed(), "a second warning inside the second is refused");
    }
}

#[test]
fn the_gate_clock_never_goes_backwards() {
    let a = gate_clock_ms();
    let b = gate_clock_ms();
    assert!(b >= a);
}

#[tokio::test(start_paused = true)]
async fn the_watcher_wakes_a_waiter_when_the_pools_depth_is_under_the_mark() {
    // The watcher reads the (empty) pool and finds the gate open; the waiter's
    // own reading stays shut for 300 ms of runtime time. The waiter would
    // otherwise sleep to its 2 s warning cap, so waking early is the watcher.
    spawn_gate_watcher(Pool::new(), None, Arc::new(AtomicU64::new(0)), 10, 0);
    let shut_until = tokio::time::Instant::now() + Duration::from_millis(300);
    let view = move || GateView { open: tokio::time::Instant::now() >= shut_until, depth: 1, limit: 0 };
    match wait_at_gate(view, || None, Some(Duration::from_secs(15))).await {
        GateExit::Open(waited) => {
            assert!(waited >= Duration::from_millis(300), "{waited:?}");
            assert!(waited < Duration::from_secs(1), "{waited:?}: the waiter slept to its cap");
        }
        other => panic!("the gate should have opened: {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_long_wait_warns_once_and_is_then_forced_on_the_deadline() {
    let forced = load(&GATE_FORCED);
    let exit = wait_at_gate(
        || GateView { open: false, depth: 9, limit: 1 },
        || None,
        Some(Duration::from_secs(5)),
    )
    .await;
    match exit {
        GateExit::Forced(waited) => assert!(waited >= Duration::from_secs(5), "{waited:?}"),
        other => panic!("{other:?}"),
    }
    assert!(load(&GATE_FORCED) > forced);
}

// ----------------------------------------------------------------- defaults

fn unset(name: &str) -> bool {
    std::env::var_os(name).is_none()
}

#[test]
fn defaults_hold_when_the_environment_does_not_override_them() {
    if unset("N42_TX_INGEST_ASYNC_FRAMES") {
        assert_eq!(async_frames_in_flight(), ASYNC_FRAMES_IN_FLIGHT);
    }
    #[cfg(target_os = "linux")]
    if unset("N42_TX_INGEST_RECOVER_NICE") {
        assert_eq!(recovery_nice(), 0);
    }
    #[cfg(target_os = "linux")]
    if unset("N42_TX_INGEST_RECOVER_PIN") {
        assert_eq!(recovery_pin(), 0);
    }
    if unset("N42_TX_INGEST_RECOVER_PARALLEL") {
        assert_eq!(recovery_slot_count(), None);
        assert_eq!(recovery_slots().available_permits(), tokio::sync::Semaphore::MAX_PERMITS);
    }
    if unset("N42_TX_INGEST_HIGH_WATER") {
        assert_eq!(high_water(), 90_000);
    }
    if unset("N42_TX_INGEST_BLOCK_TXS") {
        assert_eq!(block_txs_allowance(), 0);
    }
    if unset("N42_TX_INGEST_GATE_MAX_WAIT_MS") {
        assert_eq!(gate_max_wait(), Some(Duration::from_secs(15)));
    }
    if unset("N42_TX_INGEST_DIRECT") {
        assert!(!direct_to_queue());
    }
    if unset("N42_TX_INGEST_UNBUFFERED") {
        assert!(!unbuffered_reads());
    }
    if unset("N42_TX_INGEST_GATE_FOR_BLOCK") {
        assert!(gate_strict(), "the opening is opt-in");
    }
}

#[test]
#[cfg(target_os = "linux")]
fn recovery_threads_keep_their_priority_and_affinity_by_default() {
    if unset("N42_TX_INGEST_RECOVER_NICE") && unset("N42_TX_INGEST_RECOVER_PIN") {
        // Both are no-ops by default: run on a fresh thread and compare its nice value.
        let nice = |tid: libc::id_t| unsafe { libc::getpriority(libc::PRIO_PROCESS, tid) };
        std::thread::spawn(move || {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::id_t;
            let before = nice(tid);
            let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw mut set) };
            apply_recovery_nice();
            apply_recovery_affinity();
            let mut after: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw mut after) };
            assert_eq!(nice(tid), before);
            assert!(unsafe { libc::CPU_EQUAL(&set, &after) });
        })
        .join()
        .unwrap();
    }
}

#[test]
#[cfg(target_os = "linux")]
fn physical_cores_are_a_sorted_subset_of_the_affinity_set() {
    let cores = physical_cores();
    assert!(!cores.is_empty());
    assert!(cores.windows(2).all(|w| w[0] < w[1]), "ascending and unique: {cores:?}");
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw mut set) }, 0);
    for cpu in cores {
        assert!(unsafe { libc::CPU_ISSET(*cpu, &set) }, "cpu {cpu} is outside the process's set");
    }
}

#[test]
fn frame_attest_is_absent_until_serve_reads_the_environment() {
    // `serve` is what initialises the settings, and with no gateway
    // configured they stay `None` for good.
    if unset("N42_FRAME_GATEWAYS") {
        init_frame_attest(94);
        assert!(frame_attest().is_none());
    }
}

// -------------------------------------------------------------------- wire

mod wire {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    type Handle = tokio::task::JoinHandle<std::io::Result<()>>;

    /// A client socket and the task serving its peer end.
    async fn connect() -> (TcpStream, Handle) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let handle = tokio::spawn(serve_connection(server, Pool::new(), None, Arc::new(AtomicU64::new(0)), Setup::from_env(false)));
        (client, handle)
    }

    /// One frame as it goes on the wire.
    fn frame(claims: Option<&[Address]>, txs: &[Bytes], attestations: Option<u8>) -> Vec<u8> {
        let mut header = txs.len() as u32;
        if claims.is_some() {
            header |= FRAME_CLAIMS_SENDERS;
        }
        if attestations.is_some() {
            header |= FRAME_ATTESTED;
        }
        let mut out = header.to_le_bytes().to_vec();
        for (at, tx) in txs.iter().enumerate() {
            out.extend_from_slice(&(tx.len() as u32).to_le_bytes());
            if let Some(claims) = claims {
                out.extend_from_slice(claims[at].as_slice());
            }
            out.extend_from_slice(tx);
        }
        if let Some(n) = attestations {
            out.push(n);
            out.extend(std::iter::repeat_n(0u8, n as usize * n42_tx_types::FRAME_ATTESTATION_LEN));
        }
        out
    }

    async fn reply(client: &mut TcpStream) -> (u32, u32) {
        let accepted = tokio::time::timeout(Duration::from_secs(10), client.read_u32_le())
            .await
            .expect("an answer")
            .unwrap();
        let pending = client.read_u32_le().await.unwrap();
        (accepted, pending)
    }

    /// The connection ends with `InvalidData` and the message names the reason.
    async fn refused(handle: Handle, mut client: TcpStream, contains: &str) {
        let err = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("the connection ended")
            .unwrap()
            .expect_err("the frame is refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains(contains), "{err}");
        // The server closed its end: the client reads end of stream.
        let mut sink = Vec::new();
        assert_eq!(client.read_to_end(&mut sink).await.unwrap_or(0), 0);
    }

    #[tokio::test]
    async fn an_empty_frame_closes_the_connection() {
        let (mut client, handle) = connect().await;
        client.write_all(&0u32.to_le_bytes()).await.unwrap();
        refused(handle, client, "frame of 0 transactions").await;
    }

    #[tokio::test]
    async fn a_frame_over_the_cap_closes_the_connection() {
        let (mut client, handle) = connect().await;
        client.write_all(&(MAX_FRAME_TXS + 1).to_le_bytes()).await.unwrap();
        refused(handle, client, "frame of 10001 transactions").await;
    }

    #[tokio::test]
    async fn flag_bits_do_not_hide_an_empty_count() {
        let (mut client, handle) = connect().await;
        client
            .write_all(&(FRAME_CLAIMS_SENDERS | FRAME_ATTESTED).to_le_bytes())
            .await
            .unwrap();
        refused(handle, client, "frame of 0 transactions").await;
    }

    #[tokio::test]
    async fn a_zero_length_transaction_closes_the_connection() {
        let (mut client, handle) = connect().await;
        client.write_all(&1u32.to_le_bytes()).await.unwrap();
        client.write_all(&0u32.to_le_bytes()).await.unwrap();
        refused(handle, client, "transaction of 0 bytes").await;
    }

    #[tokio::test]
    async fn an_oversized_transaction_closes_the_connection() {
        let (mut client, handle) = connect().await;
        client.write_all(&1u32.to_le_bytes()).await.unwrap();
        client.write_all(&(MAX_TX_BYTES + 1).to_le_bytes()).await.unwrap();
        refused(handle, client, &format!("transaction of {} bytes", MAX_TX_BYTES + 1)).await;
    }

    #[tokio::test]
    async fn individually_valid_lengths_cannot_build_an_unbounded_frame() {
        let (mut client, handle) = connect().await;
        let per = MAX_TX_BYTES as usize;
        let count = MAX_FRAME_BYTES / per;
        client.write_all(&((count + 1) as u32).to_le_bytes()).await.unwrap();
        let bytes = vec![0u8; per];
        for _ in 0..count {
            client.write_all(&MAX_TX_BYTES.to_le_bytes()).await.unwrap();
            client.write_all(&bytes).await.unwrap();
        }
        // Refuse from the next length alone, before waiting for its body.
        client.write_all(&1u32.to_le_bytes()).await.unwrap();
        refused(handle, client, "frame exceeds").await;
    }

    #[tokio::test]
    async fn a_bad_attestation_count_closes_the_connection() {
        for n in [0u8, 17] {
            let (mut client, handle) = connect().await;
            let tx = Bytes::from_static(b"x");
            // The header, the one entry and the count byte; the count is refused
            // before any attestation is read.
            let mut bytes = frame(None, std::slice::from_ref(&tx), Some(0));
            *bytes.last_mut().unwrap() = n;
            client.write_all(&bytes).await.unwrap();
            refused(handle, client, &format!("frame of {n} attestations")).await;
        }
    }

    #[tokio::test]
    async fn a_connection_closed_between_frames_ends_cleanly() {
        let (mut client, handle) = connect().await;
        client.shutdown().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(10), handle).await.unwrap().unwrap();
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn a_connection_closed_inside_a_frame_is_an_error() {
        let (mut client, handle) = connect().await;
        client.write_all(&2u32.to_le_bytes()).await.unwrap();
        client.write_all(&5u32.to_le_bytes()).await.unwrap();
        client.write_all(b"ab").await.unwrap(); // three bytes short
        client.shutdown().await.unwrap();
        let err = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .unwrap()
            .unwrap()
            .expect_err("a truncated frame");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_frame_of_garbage_is_answered_with_nothing_accepted() {
        let _g = counter_lock();
        let before = load(&STATS.dropped_decode);
        let (mut client, handle) = connect().await;
        let txs = vec![Bytes::from_static(b"\xff\x00"), Bytes::from_static(b"\xc0\xc0\xc0")];
        client.write_all(&frame(None, &txs, None)).await.unwrap();

        assert_eq!(reply(&mut client).await, (0, 0));
        assert_eq!(load(&STATS.dropped_decode) - before, 2);

        drop(client);
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn valid_frames_are_recovered_and_counted_even_when_the_pool_refuses_them() {
        let _g = counter_lock();
        n42_tx_types::set_alt_sig_enabled(true);
        let (mut client, handle) = connect().await;
        let txs: Vec<Bytes> = (0..3).map(|n| raw(&alt(70, 71_000 + n))).collect();
        let before = (
            load(&STATS.frames),
            load(&STATS.txs),
            load(&STATS.altsig_txs),
            load(&STATS.verified_at_ingest),
            load(&STATS.claimed),
        );
        client.write_all(&frame(None, &txs, None)).await.unwrap();

        // The no-op pool refuses every insert, so nothing is acknowledged,
        // but the frame is read, recovered, handed to the pool and counted.
        assert_eq!(reply(&mut client).await, (0, 0));
        assert_eq!(load(&STATS.frames) - before.0, 1);
        assert_eq!(load(&STATS.txs) - before.1, 3);
        assert_eq!(load(&STATS.altsig_txs) - before.2, 3);
        assert_eq!(load(&STATS.verified_at_ingest) - before.3, 3);
        assert_eq!(load(&STATS.claimed), before.4);

        drop(client);
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn claiming_and_attested_frames_are_walked_past_and_answered_in_order() {
        let _g = counter_lock();
        n42_tx_types::set_alt_sig_enabled(true);
        let (mut client, handle) = connect().await;
        let a: Vec<Bytes> = (0..2).map(|n| raw(&alt(71, 72_000 + n))).collect();
        let b: Vec<Bytes> = (0..2).map(|n| raw(&alt(71, 72_010 + n))).collect();
        let c: Vec<Bytes> = (0..1).map(|n| raw(&alt(71, 72_020 + n))).collect();
        let claims = [Address::repeat_byte(1), Address::repeat_byte(2)];
        let claimed_before = load(&STATS.claimed);
        let frames_before = load(&STATS.frames);

        // Three frames pipelined without waiting for an answer: one that
        // claims senders, one that carries three attestations, and a plain one.
        let mut wire = frame(Some(&claims), &a, None);
        wire.extend(frame(None, &b, Some(3)));
        wire.extend(frame(None, &c, None));
        client.write_all(&wire).await.unwrap();

        for _ in 0..3 {
            assert_eq!(reply(&mut client).await, (0, 0));
        }
        assert_eq!(load(&STATS.frames) - frames_before, 3);
        // This node does not take claims (the default mode), so the claim was
        // read off the wire and discarded: every transaction was verified.
        assert_eq!(load(&STATS.claimed), claimed_before);

        drop(client);
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn admit_returns_zero_for_an_empty_decode_and_counts_nothing() {
        let _g = counter_lock();
        let before = (load(&STATS.frames), load(&STATS.txs));
        let accepted = admit::<Pool>(&Pool::new(), &Setup::from_env(false), vec![Bytes::from_static(b"\x05")], Vec::new(), Vec::new(), None).await;
        assert_eq!(accepted, 0);
        assert_eq!((load(&STATS.frames), load(&STATS.txs)), before);
    }

    #[tokio::test]
    async fn serve_listens_and_answers_a_frame() {
        let _g = counter_lock();
        // Find a free port, release it and let `serve` bind it.
        let port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let server = tokio::spawn(serve(addr, Pool::new(), None, Arc::new(AtomicU64::new(0)), 94));

        let mut client = None;
        for _ in 0..100 {
            if let Ok(stream) = TcpStream::connect(addr).await {
                client = Some(stream);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut client = client.expect("the ingest is listening");
        let before = load(&STATS.dropped_decode);
        client.write_all(&frame(None, &[Bytes::from_static(b"\xff")], None)).await.unwrap();
        assert_eq!(reply(&mut client).await, (0, 0));
        assert_eq!(load(&STATS.dropped_decode) - before, 1);
        server.abort();
    }

    #[tokio::test]
    async fn serve_reports_a_bind_failure() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap();
        let err = serve(addr, Pool::new(), None, Arc::new(AtomicU64::new(0)), 94)
            .await
            .expect_err("the port is taken");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    }

    /// Four connections of eight frames of 25 transactions each, delivered
    /// to a queue straight from the ingest (direct, asynchronous), with two
    /// recovery slots. Returns each sender's nonces in the order a build is
    /// offered them, and the frames the queue indexed.
    fn deliver(own_runtime: bool) -> (std::collections::BTreeMap<Address, Vec<u64>>, usize) {
        const CONNECTIONS: u8 = 4;
        const FRAMES: u64 = 8;
        const PER: u64 = 25;
        let queue: n42_tx_queue::TxQueue<N42PooledTransaction> = n42_tx_queue::TxQueue::new();
        let (runtime, slots) = if own_runtime {
            (runtime::build(2, Some(2)).expect("the ingest runtime"), Slots::Blocking(runtime::BlockingSlots::new(Some(2))))
        } else {
            (
                tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("a runtime"),
                Slots::Async(Arc::new(tokio::sync::Semaphore::new(2))),
            )
        };
        let setup = Setup {
            queue: Some(queue.clone()),
            direct: true,
            asynchronous: true,
            gate: 1 << 40,
            allowance: 0,
            slots,
        };
        let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).expect("a listener");
        let addr = listener.local_addr().expect("an address");
        runtime.spawn(serve_on(listener, Pool::new(), None, Arc::new(AtomicU64::new(0)), setup));
        let clients: Vec<_> = (0..CONNECTIONS)
            .map(|c| {
                std::thread::spawn(move || {
                    use std::io::{Read as _, Write as _};
                    let key = 80 + c;
                    let mut wire = Vec::new();
                    for f in 0..FRAMES {
                        let txs: Vec<Bytes> = (0..PER).map(|n| raw(&eth_tx(key, f * PER + n))).collect();
                        wire.extend(frame(None, &txs, None));
                    }
                    let mut stream = std::net::TcpStream::connect(addr).expect("connected");
                    stream.write_all(&wire).expect("frames written");
                    for _ in 0..FRAMES {
                        let mut answer = [0u8; 8];
                        stream.read_exact(&mut answer).expect("an answer");
                        let accepted = u32::from_le_bytes([answer[0], answer[1], answer[2], answer[3]]);
                        assert_eq!(u64::from(accepted), PER, "every transaction of the frame acknowledged");
                    }
                })
            })
            .collect();
        for client in clients {
            client.join().expect("a client failed");
        }
        // The answers go out before the admission: wait for the queue.
        let total = usize::from(CONNECTIONS) * (FRAMES * PER) as usize;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while (queue.len() < total || queue.frames_indexed() < usize::from(CONNECTIONS) * FRAMES as usize)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut by_sender: std::collections::BTreeMap<Address, Vec<u64>> = Default::default();
        for tx in queue.best_for_build(B256::repeat_byte(1)) {
            by_sender.entry(tx.sender()).or_default().push(tx.nonce());
        }
        let frames = queue.frames_indexed();
        runtime.shutdown_background();
        (by_sender, frames)
    }

    /// `N42_INGEST_RUNTIME=1`: the ingest on its own runtime with the slots
    /// taken on the blocking side delivers exactly what it delivers on the
    /// caller's runtime with the async semaphore -- every frame, indexed
    /// whole, each sender's nonces in order with none missing.
    #[test]
    fn the_ingest_runtime_delivers_the_same_frames_in_the_same_order() {
        let _g = counter_lock();
        let (on, frames_on) = deliver(true);
        let (off, frames_off) = deliver(false);
        assert_eq!(frames_on, 32);
        assert_eq!(frames_off, 32);
        assert_eq!(on.len(), 4);
        for c in 0..4u8 {
            let nonces = on.get(&secp_address(80 + c)).expect("every sender delivered");
            assert_eq!(*nonces, (0..200).collect::<Vec<u64>>(), "sender {c} in nonce order, none missing");
        }
        assert_eq!(on, off);
    }

    #[test]
    fn the_frame_hook_is_set_once() {
        fn first(_: B256, _: &[B256], _: &dyn std::any::Any) {}
        fn second(_: B256, _: &[B256], _: &dyn std::any::Any) {}
        set_frame_hook(first);
        let installed = *FRAME_HOOK.get().expect("a hook is installed");
        set_frame_hook(second);
        assert!(
            std::ptr::fn_addr_eq(*FRAME_HOOK.get().unwrap(), installed),
            "a second call does not replace the hook"
        );
        let _ = AtomicBool::new(false);
    }
}
