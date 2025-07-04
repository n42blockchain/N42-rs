//! Implements [`Compress`] and [`Decompress`] for beacon structs

use n42_primitives::{BeaconBlock, BeaconState};
use crate::{
    table::{Compress, Decompress},
    DatabaseError,
};

impl Decompress for BeaconBlock {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        let bytes = value.as_ref();
        let beacon_block: Result<BeaconBlock, _> = serde_json::from_slice(bytes);
        beacon_block.map_err(|e| DatabaseError::Other(e.to_string()))
    }
}

impl Compress for BeaconBlock {
    type Compressed = Vec<u8>;
    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let serialized = serde_json::to_vec(&self).expect("Serialization should not fail");
        buf.put_slice(&serialized);
    }
}

impl Decompress for BeaconState {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        let bytes = value.as_ref();
        let beacon_block: Result<BeaconState, _> = serde_json::from_slice(bytes);
        beacon_block.map_err(|e| DatabaseError::Other(e.to_string()))
    }
}

impl Compress for BeaconState {
    type Compressed = Vec<u8>;
    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let serialized = serde_json::to_vec(&self).expect("Serialization should not fail");
        buf.put_slice(&serialized);
    }
}
