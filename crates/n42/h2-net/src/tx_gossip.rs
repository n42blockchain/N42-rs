// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's transaction gossip: `/n42/<fork digest>/transaction_v2/ssz_snappy`.
//!
//! A message is raw-snappy over either one EIP-2718 transaction as it stands
//! or, since gov5's tx broadcaster batches, a marker byte `0x7e` followed by
//! the RLP list of such transactions (`internal/sync/tx_batch_wire.go`). The
//! marker cannot be the first byte of a transaction: typed envelopes start
//! below `0x7f` — well, at a type byte no chain uses — and legacy RLP lists at
//! `0xc0` or above. A batch carries at most 256 transactions and 256 KiB.
//!
//! What a Rust member does with the topic: every transaction it hears goes
//! into its execution layer's pool over `eth_sendRawTransaction`, so a Rust
//! leader seals the fleet's transactions; every transaction its own pool
//! admits goes out on the topic, so a Go leader seals the ones submitted
//! here. Neither direction is consensus: a transaction that fails to arrive
//! waits for the next leader that has it.

use alloy_primitives::Bytes;
use alloy_rlp::{Decodable, Encodable};

/// The byte a batch starts with.
pub const TX_BATCH_MARKER: u8 = 0x7e;
/// Transactions per batch, gov5's `txBatchMaxTxs`.
pub const TX_BATCH_MAX_TXS: usize = 256;
/// Bytes per encoded batch, gov5's `txBatchMaxBytes`.
pub const TX_BATCH_MAX_BYTES: usize = 256 * 1024;

/// Why a transaction message could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxGossipError {
    /// The message is empty.
    #[error("empty transaction message")]
    Empty,
    /// The batch does not decode as an RLP list of byte strings.
    #[error("transaction batch is not an RLP list of transactions")]
    InvalidBatch,
    /// More transactions than gov5 accepts in one message.
    #[error("transaction batch of {0} exceeds the {TX_BATCH_MAX_TXS} cap")]
    TooMany(usize),
    /// A larger message than gov5 sends.
    #[error("transaction batch of {0} bytes exceeds the {TX_BATCH_MAX_BYTES} cap")]
    TooLarge(usize),
}

/// Frames `transactions` (each an EIP-2718 encoding) as one batch message,
/// before compression. Callers keep batches within the caps.
pub fn encode_tx_batch(transactions: &[Bytes]) -> Result<Vec<u8>, TxGossipError> {
    if transactions.len() > TX_BATCH_MAX_TXS {
        return Err(TxGossipError::TooMany(transactions.len()));
    }
    let mut out = vec![TX_BATCH_MARKER];
    transactions.to_vec().encode(&mut out);
    if out.len() > TX_BATCH_MAX_BYTES {
        return Err(TxGossipError::TooLarge(out.len()));
    }
    Ok(out)
}

/// The transactions of a decompressed message: a batch, or one transaction
/// as gov5's older nodes sent them. The transactions themselves are not
/// decoded here; the execution layer's pool judges them.
pub fn decode_tx_batch(payload: &[u8]) -> Result<Vec<Bytes>, TxGossipError> {
    match payload.first() {
        None => Err(TxGossipError::Empty),
        Some(&TX_BATCH_MARKER) => {
            let mut cursor = &payload[1..];
            let transactions =
                Vec::<Bytes>::decode(&mut cursor).map_err(|_| TxGossipError::InvalidBatch)?;
            if !cursor.is_empty() || transactions.is_empty() {
                return Err(TxGossipError::InvalidBatch);
            }
            if transactions.len() > TX_BATCH_MAX_TXS {
                return Err(TxGossipError::TooMany(transactions.len()));
            }
            Ok(transactions)
        }
        Some(_) => Ok(vec![Bytes::copy_from_slice(payload)]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_round_trips_and_a_bare_transaction_is_one() {
        let txs = vec![Bytes::from_static(&[0x02, 0xf8, 0x01]), Bytes::from_static(&[0xf8, 0x02, 0x03])];
        let encoded = encode_tx_batch(&txs).unwrap();
        assert_eq!(encoded[0], TX_BATCH_MARKER);
        assert_eq!(decode_tx_batch(&encoded).unwrap(), txs);
        assert_eq!(decode_tx_batch(&[0xf8, 0x02, 0x03]).unwrap(), vec![Bytes::from_static(&[0xf8, 0x02, 0x03])]);
        assert_eq!(decode_tx_batch(&[]), Err(TxGossipError::Empty));
        assert_eq!(decode_tx_batch(&[TX_BATCH_MARKER, 0xc0]), Err(TxGossipError::InvalidBatch));
    }

    #[test]
    fn the_caps_are_gov5s() {
        let many: Vec<Bytes> = (0..TX_BATCH_MAX_TXS + 1).map(|_| Bytes::from_static(&[0x02])).collect();
        assert_eq!(encode_tx_batch(&many), Err(TxGossipError::TooMany(TX_BATCH_MAX_TXS + 1)));
        let big = vec![Bytes::from(vec![0u8; TX_BATCH_MAX_BYTES])];
        assert!(matches!(encode_tx_batch(&big), Err(TxGossipError::TooLarge(_))));
    }
}
