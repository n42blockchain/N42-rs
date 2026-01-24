// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Serialization and deserialization utilities for N42 beacon types
//!
//! This module provides helper functions for encoding and decoding
//! N42 beacon chain types to/from bytes.
//!
//! Note: The actual `Compress` and `Decompress` trait implementations
//! are in `reth-db-api/src/models/beacon.rs` to satisfy Rust's orphan rules.

use crate::StorageResult;
use n42_primitives::{BeaconBlock, BeaconState};

/// Encode a BeaconState to JSON bytes
pub fn encode_beacon_state(state: &BeaconState) -> StorageResult<Vec<u8>> {
    serde_json::to_vec(state).map_err(Into::into)
}

/// Decode a BeaconState from JSON bytes
pub fn decode_beacon_state(bytes: &[u8]) -> StorageResult<BeaconState> {
    serde_json::from_slice(bytes).map_err(Into::into)
}

/// Encode a BeaconBlock to JSON bytes
pub fn encode_beacon_block(block: &BeaconBlock) -> StorageResult<Vec<u8>> {
    serde_json::to_vec(block).map_err(Into::into)
}

/// Decode a BeaconBlock from JSON bytes
pub fn decode_beacon_block(bytes: &[u8]) -> StorageResult<BeaconBlock> {
    serde_json::from_slice(bytes).map_err(Into::into)
}

/// Encode any serializable value to JSON bytes
pub fn encode_json<T: serde::Serialize>(value: &T) -> StorageResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(Into::into)
}

/// Decode any deserializable value from JSON bytes
pub fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> StorageResult<T> {
    serde_json::from_slice(bytes).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beacon_state_roundtrip() {
        let state = BeaconState::default();

        let encoded = encode_beacon_state(&state).expect("encode should succeed");
        let decoded = decode_beacon_state(&encoded).expect("decode should succeed");

        assert_eq!(
            serde_json::to_string(&state).unwrap(),
            serde_json::to_string(&decoded).unwrap()
        );
    }

    #[test]
    fn test_beacon_block_roundtrip() {
        let block = BeaconBlock::default();

        let encoded = encode_beacon_block(&block).expect("encode should succeed");
        let decoded = decode_beacon_block(&encoded).expect("decode should succeed");

        assert_eq!(
            serde_json::to_string(&block).unwrap(),
            serde_json::to_string(&decoded).unwrap()
        );
    }

    #[test]
    fn test_invalid_json_decode() {
        let invalid = b"not valid json";
        let result = decode_beacon_state(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_decode() {
        let empty = b"";
        let result = decode_beacon_state(empty);
        assert!(result.is_err());
    }
}
