// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixtures shared by the queue's test modules: transactions with distinct
//! keccak hashes, senders, and frames in the ingest's shapes.

use super::*;
use alloy_primitives::{Signature, TxKind, U256};
use reth_transaction_pool::EthPooledTransaction;

pub(crate) type Tx = Arc<ValidPoolTransaction<EthPooledTransaction>>;

pub(crate) fn tx_hashed(sender: Address, nonce: u64) -> EthPooledTransaction {
    use alloy_consensus::{Signed, TxEip1559};
    let inner = TxEip1559 {
        chain_id: 1,
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        to: TxKind::Call(Address::repeat_byte(9)),
        value: U256::from(1),
        ..Default::default()
    };
    let mut seed = [0u8; 28];
    seed[..20].copy_from_slice(sender.as_slice());
    seed[20..].copy_from_slice(&nonce.to_be_bytes());
    let signed = Signed::new_unchecked(inner, Signature::test_signature(), alloy_primitives::keccak256(seed));
    let recovered = reth_primitives_traits::Recovered::new_unchecked(
        reth_ethereum_primitives::TransactionSigned::from(signed),
        sender,
    );
    EthPooledTransaction::new(recovered, 120)
}

pub(crate) fn sender(index: u64) -> Address {
    let mut a = [0u8; 20];
    a[..8].copy_from_slice(&(index.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1).to_be_bytes());
    Address::from(a)
}

pub(crate) fn frame_id(who: Address, first: u64) -> B256 {
    let mut seed = [0u8; 29];
    seed[..20].copy_from_slice(who.as_slice());
    seed[20..28].copy_from_slice(&first.to_be_bytes());
    seed[28] = 0xa7;
    alloy_primitives::keccak256(seed)
}

/// One frame of one sender's `len` nonces from `first` (the flood's shape),
/// through the ingest's door.
pub(crate) fn frame(queue: &TxQueue<EthPooledTransaction>, who: Address, first: u64, len: u64) {
    let members: Vec<(Address, u64)> = (first..first + len).map(|n| (who, n)).collect();
    let txs: Vec<EthPooledTransaction> = members.iter().map(|(s, n)| tx_hashed(*s, *n)).collect();
    let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
    queue.push_frame(txs, Some(NewFrame { id: frame_id(who, first), hashes, members, gas: 21_000 * len }));
}

/// A frame of two senders interleaved (a sender with more than one run).
pub(crate) fn mixed_frame(queue: &TxQueue<EthPooledTransaction>, a: (Address, u64), b: (Address, u64), len: u64) {
    let mut members = Vec::new();
    for k in 0..len {
        members.push((a.0, a.1 + k));
        members.push((b.0, b.1 + k));
    }
    let txs: Vec<EthPooledTransaction> = members.iter().map(|(s, n)| tx_hashed(*s, *n)).collect();
    let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
    let id = frame_id(a.0, a.1 ^ (b.1 << 32) ^ 0x5a5a);
    queue.push_frame(txs, Some(NewFrame { id, hashes, members, gas: 21_000 * 2 * len }));
}

/// `rounds` frames of `per` nonces for each of `senders` senders, one frame
/// of each sender in turn, plus a mixed frame every few rounds.
pub(crate) fn fill(queue: &TxQueue<EthPooledTransaction>, senders: u64, rounds: u64, per: u64, from_round: u64) {
    for r in from_round..from_round + rounds {
        for s in 0..senders {
            frame(queue, sender(s), r * per, per);
        }
        if r % 3 == 1 {
            // Two senders of their own, interleaved in one frame.
            // Their nonces count the mixed frames, so they run on.
            let m = (r - 1) / 3;
            mixed_frame(queue, (sender(1_000), m * per), (sender(1_001), m * per), per);
        }
    }
}

pub(crate) fn pairs(txs: &[Tx]) -> Vec<(Address, u64)> {
    txs.iter().map(|t| (t.sender(), t.nonce())).collect()
}

pub(crate) fn block_hash(n: u64) -> B256 {
    B256::from(U256::from(0xb10c_0000_u64 + n))
}
