use n42_primitives::{BeaconState,BeaconBlock};
use crate::{
    table::{Compress, Decompress},
    DatabaseError,
};
use bytes::{BufMut, BytesMut};

impl Decompress for BeaconState {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        serde_json::from_slice(value)
            .map_err(|e| DatabaseError::Other(format!("serde_json deserialize error: {e}")))
    }
}

impl Compress for BeaconState {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let json_bytes = serde_json::to_vec(self)
            .expect("BeaconState serialization should not fail");
        buf.put_slice(&json_bytes);
    }
}

impl Compress for BeaconBlock {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let json_bytes = serde_json::to_vec(self)
            .expect("BeaconBlock serialization failed");
        buf.put_slice(&json_bytes);
    }
}

impl Decompress for BeaconBlock {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        serde_json::from_slice(value)
            .map_err(|e| DatabaseError::Other(format!("Decompression failed: {}", e)))
    }
}