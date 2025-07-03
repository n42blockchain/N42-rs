use serde_utils::hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
// use alloy_primitives::private::arbitrary;
use ssz::{Decode, Encode};
use tree_hash::TreeHash;
use crate::error::Error;

/// The byte-length of a BLS signature when serialized in compressed form.
pub const SIGNATURE_BYTES_LEN: usize = 96;
/// The byte-length of a BLS public key when serialized in compressed form.
pub const PUBLIC_KEY_BYTES_LEN: usize = 48;

/// Generic implementations which are only generally useful for docs.
pub mod generics {
    pub use crate::crypto::GenericPublicKeyBytes;
    pub use crate::crypto::GenericSignatureBytes;
}

/// Defines all the fundamental BLS points which should be exported by this crate by making
/// concrete the generic type parameters using the points from some external BLS library (e.g.,BLST).
macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {
            use $mod as bls_variant;
            use crate::crypto::generics::*;
            pub type PublicKeyBytes = GenericPublicKeyBytes<bls_variant::PublicKey>;
            pub type SignatureBytes =
                GenericSignatureBytes<bls_variant::PublicKey, bls_variant::Signature>;
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
    pub use super::Signature;
}

#[derive(Clone)]
pub struct PublicKey([u8; PUBLIC_KEY_BYTES_LEN]);

#[derive(Clone)]
pub struct Signature([u8; SIGNATURE_BYTES_LEN]);


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

impl<Pub> Hash for GenericPublicKeyBytes<Pub> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes[..].hash(state);
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


/// A wrapper around some bytes that may or may not be a `GenericSignature` in compressed form.
///
/// This struct is useful for two things:
///
/// - Lazily verifying a serialized signature.
/// - Storing some bytes that are actually invalid (required in the case of a `Deposit` message).
#[derive(Clone)]
pub struct GenericSignatureBytes<Pub, Sig> {
    bytes: [u8; SIGNATURE_BYTES_LEN],
    _phantom_public_key: PhantomData<Pub>,
    _phantom_signature: PhantomData<Sig>,
}

impl<Pub, Sig> PartialEq for GenericSignatureBytes<Pub, Sig> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

impl<Pub, Sig> Hash for GenericSignatureBytes<Pub, Sig> {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.bytes.hash(hasher);
    }
}

impl<Pub, Sig> Encode for GenericSignatureBytes<Pub, Sig> {
    impl_ssz_encode!(SIGNATURE_BYTES_LEN);
}

impl<Pub, Sig> Decode for GenericSignatureBytes<Pub, Sig> {
    impl_ssz_decode!(SIGNATURE_BYTES_LEN);
}

impl<Pub, Sig> TreeHash for GenericSignatureBytes<Pub, Sig> {
    impl_tree_hash!(SIGNATURE_BYTES_LEN);
}

impl<Pub, Sig> fmt::Display for GenericSignatureBytes<Pub, Sig> {
    impl_display!();
}

impl<Pub, Sig> std::str::FromStr for GenericSignatureBytes<Pub, Sig> {
    impl_from_str!();
}

impl<Pub, Sig> Serialize for GenericSignatureBytes<Pub, Sig> {
    impl_serde_serialize!();
}

impl<'de, Pub, Sig> Deserialize<'de> for GenericSignatureBytes<Pub, Sig> {
    impl_serde_deserialize!();
}

impl<Pub, Sig> fmt::Debug for GenericSignatureBytes<Pub, Sig> {
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<Pub: 'static, Sig: 'static> arbitrary::Arbitrary<'_> for GenericSignatureBytes<Pub, Sig> {
    impl_arbitrary!(SIGNATURE_BYTES_LEN);
}