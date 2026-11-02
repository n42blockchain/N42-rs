// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's protobuf transaction (`types_pb.Transaction`,
//! `common/transaction/transaction.go:475-488`), the form a StreamPacket
//! carries. A packet's transactions have `from` (field 11) set: gov5's
//! `AsMessage` trusts it and skips sender recovery. Bytes starting with
//! `0xFF` are gov5's compact storage form, accepted inside a packet but not
//! decoded here.
//!
//! gov5 writes `V`/`R`/`S` in `Marshal` (fields 16/14/15) but not in the
//! hash-relevant `MarshalV2`; both decode with [`decode_transaction`].

use alloy_primitives::{Address, B256, U256};
use prost::Message;

pub use super::proto::{PbAccessTuple, PbTransaction};
use super::proto::{address_to_h160, h160_to_address, h256_to_hash, h256_to_u256, hash_to_h256, u256_to_h256};

/// First byte of gov5's compact transaction storage form.
pub const COMPACT_MARKER: u8 = 0xFF;

/// A transaction that does not decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxCodecError {
    /// gov5's compact storage form.
    #[error("compact transaction encoding is not supported")]
    Compact,
    /// The protobuf does not decode.
    #[error("transaction protobuf: {0}")]
    Proto(String),
}

/// Whether `bytes` are gov5's compact storage form.
pub fn is_compact(bytes: &[u8]) -> bool {
    bytes.first() == Some(&COMPACT_MARKER)
}

/// Decodes a protobuf transaction.
pub fn decode_transaction(bytes: &[u8]) -> Result<PbTransaction, TxCodecError> {
    if is_compact(bytes) {
        return Err(TxCodecError::Compact);
    }
    PbTransaction::decode(bytes).map_err(|e| TxCodecError::Proto(e.to_string()))
}

/// Encodes a protobuf transaction (Go `proto.Marshal`).
pub fn encode_transaction(tx: &PbTransaction) -> Vec<u8> {
    tx.encode_to_vec()
}

impl PbTransaction {
    /// The sender (`from`, field 11), when set.
    pub fn sender(&self) -> Option<Address> {
        self.from.as_ref().map(|h| h160_to_address(Some(h)))
    }

    /// Sets the sender.
    pub fn set_sender(&mut self, from: &Address) {
        self.from = Some(address_to_h160(from));
    }

    /// The recipient; `None` for a creation.
    pub fn recipient(&self) -> Option<Address> {
        self.to.as_ref().map(|h| h160_to_address(Some(h)))
    }

    /// Sets the recipient.
    pub fn set_recipient(&mut self, to: &Address) {
        self.to = Some(address_to_h160(to));
    }

    /// The transferred value (absent → 0).
    pub fn value_u256(&self) -> U256 {
        h256_to_u256(self.value.as_ref())
    }

    /// The legacy gas price (absent → 0).
    pub fn gas_price_u256(&self) -> U256 {
        h256_to_u256(self.gas_price.as_ref())
    }

    /// The EIP-1559 fee cap (absent → 0).
    pub fn max_fee_u256(&self) -> U256 {
        h256_to_u256(self.fee_per_gas.as_ref())
    }

    /// The EIP-1559 tip cap (absent → 0).
    pub fn max_priority_fee_u256(&self) -> U256 {
        h256_to_u256(self.priority_fee_per_gas.as_ref())
    }

    /// The transaction hash field (field 13), when set.
    pub fn hash_field(&self) -> Option<B256> {
        self.hash.as_ref().map(|h| h256_to_hash(Some(h)))
    }

    /// Converts a uint256 to gov5's H256 (`convertUint256IntToH256IfSet`).
    pub fn h256(v: &U256) -> super::proto::H256 {
        u256_to_h256(v)
    }

    /// Converts a hash to gov5's H256.
    pub fn hash256(h: &B256) -> super::proto::H256 {
        hash_to_h256(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_fee_round_trip() {
        let mut tx = PbTransaction {
            r#type: 2,
            nonce: 9,
            gas: 21_000,
            chain_id: 94,
            data: vec![1, 2, 3],
            sign: vec![0x55; 65],
            ..Default::default()
        };
        tx.gas_price = Some(PbTransaction::h256(&U256::from(7u64)));
        tx.fee_per_gas = Some(PbTransaction::h256(&U256::from(7u64)));
        tx.priority_fee_per_gas = Some(PbTransaction::h256(&U256::from(1u64)));
        tx.value = Some(PbTransaction::h256(&U256::from(10u64).pow(U256::from(18u64))));
        tx.set_sender(&Address::repeat_byte(0xAA));
        tx.set_recipient(&Address::repeat_byte(0xBB));
        let enc = encode_transaction(&tx);
        let dec = decode_transaction(&enc).unwrap();
        assert_eq!(dec, tx);
        assert_eq!(dec.sender(), Some(Address::repeat_byte(0xAA)));
        assert_eq!(dec.recipient(), Some(Address::repeat_byte(0xBB)));
        assert_eq!(dec.value_u256(), U256::from(10u64).pow(U256::from(18u64)));
        // Field order: type(1) first, then nonce(2).
        assert_eq!(&enc[..4], &[0x08, 0x02, 0x10, 0x09]);
        assert_eq!(decode_transaction(&[0xFF, 0]).unwrap_err(), TxCodecError::Compact);
    }
}
