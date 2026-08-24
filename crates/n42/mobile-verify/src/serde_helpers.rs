/// Serde helper for `[u8; 48]` (BLS12-381 public key bytes).
///
/// Standard serde only derives Serialize/Deserialize for arrays up to `[T; 32]`.
/// This module provides the `#[serde(with = "...")]` implementation for 48-byte arrays
/// used across receipt, commitment, and other BLS pubkey fields.
pub mod pubkey_48 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if v.len() != 48 {
            return Err(serde::de::Error::custom(format!(
                "expected 48 bytes for BLS public key, got {}",
                v.len()
            )));
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&v);
        Ok(arr)
    }
}
