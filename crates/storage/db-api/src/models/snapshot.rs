//! Implements [`Compress`] and [`Decompress`] for [`Snapshot`]

use n42_primitives::Snapshot;
use crate::{
    table::{Compress, Decompress},
    DatabaseError,
};



impl Decompress for Snapshot{
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        let bytes = value.as_ref();
        let snapshot: Result<Snapshot, _> = serde_json::from_slice(bytes);
        snapshot.map_err(|e| DatabaseError::Other(e.to_string()))
    }
}

impl Compress for Snapshot{
    type Compressed = Vec<u8>;
    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let serialized = serde_json::to_vec(&self).expect("Serialization should not fail");
        buf.put_slice(&serialized);
    }
}
