//! The bincode 1 free-function wire format: little endian, fixed-width lengths
//! and integers, with trailing bytes accepted. Used for existing consensus hashes
//! and persisted checkpoints; changing this configuration changes those bytes.
use serde::{Serialize, de::DeserializeOwned};

#[derive(Debug, thiserror::Error)]
pub enum ErrorKind {
    #[error(transparent)]
    Encode(#[from] bincode_reloaded::error::EncodeError),
    #[error(transparent)]
    Decode(#[from] bincode_reloaded::error::DecodeError),
}
pub type Error = Box<ErrorKind>;

pub fn serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    bincode_reloaded::serde::encode_to_vec(value, bincode_reloaded::config::legacy())
        .map_err(|e| Box::new(ErrorKind::Encode(e)))
}

pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    bincode_reloaded::serde::decode_from_slice(bytes, bincode_reloaded::config::legacy())
        .map(|(value, _)| value)
        .map_err(|e| Box::new(ErrorKind::Decode(e)))
}

pub fn serialize_into<W: std::io::Write, T: Serialize + ?Sized>(
    mut writer: W,
    value: &T,
) -> Result<(), Error> {
    bincode_reloaded::serde::encode_into_std_write(
        value,
        &mut writer,
        bincode_reloaded::config::legacy(),
    )
    .map(|_| ())
    .map_err(|e| Box::new(ErrorKind::Encode(e)))
}

pub fn deserialize_from<R: std::io::Read, T: DeserializeOwned>(mut reader: R) -> Result<T, Error> {
    bincode_reloaded::serde::decode_from_std_read(&mut reader, bincode_reloaded::config::legacy())
        .map_err(|e| Box::new(ErrorKind::Decode(e)))
}
