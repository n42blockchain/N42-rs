// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

use crate::{
    table::{Compress, Decompress},
    DatabaseError,
};
use bytes::{BufMut, BytesMut};
use n42_primitives::{BeaconBlock, BeaconState};

impl Decompress for BeaconState {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        serde_json::from_slice(value)
            .map_err(|e| DatabaseError::Other(format!("serde_json deserialize error: {e}")))
    }
}

impl Compress for BeaconState {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let json_bytes =
            serde_json::to_vec(self).expect("BeaconState serialization should not fail");
        buf.put_slice(&json_bytes);
    }
}

impl Compress for BeaconBlock {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let json_bytes = serde_json::to_vec(self).expect("BeaconBlock serialization failed");
        buf.put_slice(&json_bytes);
    }
}

impl Decompress for BeaconBlock {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        serde_json::from_slice(value)
            .map_err(|e| DatabaseError::Other(format!("Decompression failed: {}", e)))
    }
}

impl<
        T: merkle_db_rs::Value
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + serde::de::DeserializeOwned,
    > Decompress for merkle_db_rs::tree::Tree<T>
{
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        serde_json::from_slice(value)
            .map_err(|e| DatabaseError::Other(format!("serde_json deserialize error: {e}")))
    }
}

impl<
        T: merkle_db_rs::Value
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + serde::Serialize,
    > Compress for merkle_db_rs::tree::Tree<T>
{
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let json_bytes = serde_json::to_vec(self).expect("Tree serialization should not fail");
        buf.put_slice(&json_bytes);
    }
}
