use serde_utils::hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use std::fmt;
use std::marker::PhantomData;
// use alloy_primitives::private::arbitrary;
use ssz::{Decode, Encode};
use tree_hash::TreeHash;
use crate::error::Error;

/// Generic implementations which are only generally useful for docs.
pub mod generics {
    pub use crate::crypto::GenericPublicKeyBytes;
}

/// Defines all the fundamental BLS points which should be exported by this crate by making
/// concrete the generic type parameters using the points from some external BLS library (e.g.,BLST).
macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {
            use $mod as bls_variant;
            use crate::crypto::generics::*;
            pub type PublicKeyBytes = GenericPublicKeyBytes<bls_variant::PublicKey>;
        }
    };
}

#[cfg(feature = "fake_crypto")]
define_mod!(
    fake_crypto_implementations,
    crate::crypto::types
);

#[cfg(feature = "fake_crypto")]
pub use fake_crypto_implementations::*;

/// Provides the externally-facing, core BLS types.
pub mod types {
    pub use super::PublicKey;
}

#[derive(Clone)]
pub struct PublicKey([u8; PUBLIC_KEY_BYTES_LEN]);

/// The byte-length of a BLS public key when serialized in compressed form.
pub const PUBLIC_KEY_BYTES_LEN: usize = 48;

pub struct GenericPublicKeyBytes<Pub> {
    bytes: [u8; PUBLIC_KEY_BYTES_LEN],
    _phantom: PhantomData<Pub>,
}

impl<Pub> Copy for GenericPublicKeyBytes<Pub> {}

impl<Pub> Clone for GenericPublicKeyBytes<Pub> {
    fn clone(&self) -> Self {
        *self
    }
}


impl<Pub> GenericPublicKeyBytes<Pub> {
    /// Instantiates `Self` with all-zeros.
    pub fn empty() -> Self {
        Self {
            bytes: [0; PUBLIC_KEY_BYTES_LEN],
            _phantom: PhantomData,
        }
    }

    /// Returns a slice of the bytes contained in `self`.
    ///
    /// The bytes are not verified (i.e., they may not represent a valid BLS point).
    pub fn as_serialized(&self) -> &[u8] {
        &self.bytes
    }

    /// Clones the bytes in `self`.
    ///
    /// The bytes are not verified (i.e., they may not represent a valid BLS point).
    pub fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.bytes
    }

    /// Returns `self.serialize()` as a `0x`-prefixed hex string.
    pub fn as_hex_string(&self) -> String {
        format!("{:?}", self)
    }

    /// Instantiates `Self` from bytes.
    ///
    /// The bytes are not fully verified (i.e., they may not represent a valid BLS point). Only the
    /// byte-length is checked.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == PUBLIC_KEY_BYTES_LEN {
            let mut pk_bytes = [0; PUBLIC_KEY_BYTES_LEN];
            pk_bytes[..].copy_from_slice(bytes);
            Ok(Self {
                bytes: pk_bytes,
                _phantom: PhantomData,
            })
        } else {
            Err(Error::InvalidByteLength {
                got: bytes.len(),
                expected: PUBLIC_KEY_BYTES_LEN,
            })
        }
    }
}

impl<Pub> Eq for GenericPublicKeyBytes<Pub> {}

impl<Pub> PartialEq for GenericPublicKeyBytes<Pub> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

impl<Pub> Encode for GenericPublicKeyBytes<Pub> {
    impl_ssz_encode!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub> Decode for GenericPublicKeyBytes<Pub> {
    impl_ssz_decode!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub> TreeHash for GenericPublicKeyBytes<Pub> {
    impl_tree_hash!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub> fmt::Display for GenericPublicKeyBytes<Pub> {
    impl_display!();
}

impl<Pub> std::str::FromStr for GenericPublicKeyBytes<Pub> {
    impl_from_str!();
}

impl<Pub> Serialize for GenericPublicKeyBytes<Pub> {
    impl_serde_serialize!();
}

impl<'de, Pub> Deserialize<'de> for GenericPublicKeyBytes<Pub> {
    impl_serde_deserialize!();
}

impl<Pub> fmt::Debug for GenericPublicKeyBytes<Pub> {
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<Pub: 'static> arbitrary::Arbitrary<'_> for GenericPublicKeyBytes<Pub> {
    impl_arbitrary!(PUBLIC_KEY_BYTES_LEN);
}