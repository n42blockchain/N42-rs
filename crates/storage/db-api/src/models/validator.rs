use n42_primitives::{Validator,ValidatorBeforeTx};
use crate::{
    table::{Compress, Decompress},
    DatabaseError,
};
use bytes::{BufMut, BytesMut};

impl Decompress for Validator {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        serde_json::from_slice(value).map_err(|_| DatabaseError::Decode)
    }
}
impl Compress for Validator {
    type Compressed = BytesMut;

    fn compress(self) -> Self::Compressed {
        let mut buf = BytesMut::new();
        self.compress_to_buf(&mut buf);
        buf
    }

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let serialized = serde_json::to_vec(&self).expect("Serialization should not fail");
        buf.put(serialized.as_slice());
    }
}



impl Decompress for ValidatorBeforeTx {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        serde_json::from_slice(value).map_err(|_| DatabaseError::Decode)
    }
}

impl Compress for ValidatorBeforeTx {
    type Compressed = BytesMut;

    fn compress(self) -> Self::Compressed {
        let mut buf = BytesMut::new();
        self.compress_to_buf(&mut buf);
        buf
    }

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let serialized = serde_json::to_vec(&self).expect("Serialization should not fail");
        buf.put(serialized.as_slice());
    }
}