use serde_utils::hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use serde::{Deserialize as serdeD, Serialize as serdeS};
use ssz::{Decode, Encode};
use tree_hash::TreeHash;
use zeroize::Zeroize;
use crate::error::Error;

/// The byte-length of a BLS signature when serialized in compressed form.
pub const SIGNATURE_BYTES_LEN: usize = 96;
/// The byte-length of a BLS public key when serialized in compressed form.
pub const PUBLIC_KEY_BYTES_LEN: usize = 48;
/// The byte-length of a BLS secret key.
pub const SECRET_KEY_BYTES_LEN: usize = 32;
/// Represents the public key at infinity.
pub const INFINITY_PUBLIC_KEY: [u8; PUBLIC_KEY_BYTES_LEN] = [
    0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Generic implementations which are only generally useful for docs.
pub mod generics {
    pub use crate::crypto::GenericPublicKeyBytes;
    pub use crate::crypto::GenericSignatureBytes;
    pub use crate::crypto::GenericKeypair;
    pub use crate::crypto::GenericSecretKey;
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
            pub type SecretKey = GenericSecretKey<
                bls_variant::Signature,
                bls_variant::PublicKey,
                bls_variant::SecretKey,
            >;
            pub type Keypair = GenericKeypair<
                bls_variant::PublicKey,
                bls_variant::SecretKey,
                bls_variant::Signature,
            >;
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
    pub use super::SecretKey;
}

#[derive(Clone)]
pub struct PublicKey([u8; PUBLIC_KEY_BYTES_LEN]);

#[derive(Clone)]
pub struct Signature([u8; SIGNATURE_BYTES_LEN]);

#[derive(Clone)]
pub struct SecretKey([u8; SECRET_KEY_BYTES_LEN]);

impl PublicKey {
    fn infinity() -> Self {
        Self(INFINITY_PUBLIC_KEY)
    }
}

impl TPublicKey for PublicKey {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.0
    }
}

impl TSecretKey<Signature, PublicKey> for SecretKey {
    fn random() -> Self {
        Self([0; SECRET_KEY_BYTES_LEN])
    }
    fn serialize(&self) -> ZeroizeHash {
        let mut bytes = [0; SECRET_KEY_BYTES_LEN];
        bytes[..].copy_from_slice(&self.0[..]);
        bytes.into()
    }
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut sk = Self::random();
        sk.0[..].copy_from_slice(&bytes[0..SECRET_KEY_BYTES_LEN]);
        Ok(sk)
    }
    fn public_key(&self) -> PublicKey {
        PublicKey::infinity()
    }
}

impl TSignature<PublicKey> for Signature {
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.0
    }

}

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

/// A simple wrapper around `PublicKey` and `GenericSecretKey`.
#[derive(Clone)]
pub struct GenericKeypair<Pub, Sec, Sig> {
    pub pk: GenericPublicKey<Pub>,
    pub sk: GenericSecretKey<Sig, Pub, Sec>,
    _phantom: PhantomData<Sig>,
}

impl<Pub, Sec, Sig> GenericKeypair<Pub, Sec, Sig>
where
    Pub: TPublicKey,
    Sec: TSecretKey<Sig, Pub>,
    Sig: TSignature<Pub>,
{
    /// Instantiate `Self` from a public and secret key.
    ///
    /// This function does not check to ensure that `pk` is derived from `sk`. It would be a logic
    /// error to supply such a `pk`.
    pub fn from_components(pk: GenericPublicKey<Pub>, sk: GenericSecretKey<Sig, Pub, Sec>) -> Self {
        Self {
            pk,
            sk,
            _phantom: PhantomData,
        }
    }
}

/// A BLS public key that is generic across some BLS point (`Pub`).
///
/// Provides generic functionality whilst deferring all serious cryptographic operations to `Pub`.
#[derive(Clone)]
pub struct GenericPublicKey<Pub> {
    /// The underlying point which performs *actual* cryptographic operations.
    point: Pub,
}
impl<Pub> GenericPublicKey<Pub>
where
    Pub: TPublicKey,
{
    /// Returns `self.serialize()` as a `0x`-prefixed hex string.
    pub fn as_hex_string(&self) -> String {
        // format!("{:?}", self) 这里溢出
        hex::encode(self.serialize())
    }

    pub fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.point.serialize()
    }

    pub(crate) fn from_point(point: Pub) -> Self {
        Self { point }
    }
}


/// Implemented on some struct from a BLS library so it may be used as the `point` in a
/// `GenericPublicKey`.
pub trait TPublicKey: Sized + Clone {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN];

}

impl<Pub: TPublicKey> Eq for GenericPublicKey<Pub> {}

impl<Pub: TPublicKey> PartialEq for GenericPublicKey<Pub> {
    fn eq(&self, other: &Self) -> bool {
        self.serialize()[..] == other.serialize()[..]
    }
}

/// Hashes the `self.serialize()` bytes.
impl<Pub: TPublicKey> Hash for GenericPublicKey<Pub> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.serialize()[..].hash(state);
    }
}

impl<Pub: TPublicKey> Encode for GenericPublicKey<Pub> {
    impl_ssz_encode!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub: TPublicKey> Decode for GenericPublicKey<Pub> {
    impl_ssz_decode!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub: TPublicKey> TreeHash for GenericPublicKey<Pub> {
    impl_tree_hash!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub: TPublicKey> fmt::Display for GenericPublicKey<Pub> {
    impl_display!();
}

impl<Pub: TPublicKey> std::str::FromStr for GenericPublicKey<Pub> {
    impl_from_str!();
}

impl<Pub: TPublicKey> Serialize for GenericPublicKey<Pub> {
    impl_serde_serialize!();
}

impl<'de, Pub: TPublicKey> Deserialize<'de> for GenericPublicKey<Pub> {
    impl_serde_deserialize!();
}
impl<Pub: TPublicKey> fmt::Debug for GenericPublicKey<Pub> {
    impl_debug!();
}
#[derive(Zeroize, serdeD, serdeS)]
#[zeroize(drop)]
#[serde(transparent)]
pub struct ZeroizeHash([u8; SECRET_KEY_BYTES_LEN]);

impl ZeroizeHash {
    /// Instantiates `Self` with all zeros.
    pub fn zero() -> Self {
        Self([0; SECRET_KEY_BYTES_LEN])
    }

    /// Returns a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns a mutable reference to the underlying bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<[u8; SECRET_KEY_BYTES_LEN]> for ZeroizeHash {
    fn from(array: [u8; SECRET_KEY_BYTES_LEN]) -> Self {
        Self(array)
    }
}

impl<Pub: TPublicKey + 'static> arbitrary::Arbitrary<'_> for GenericPublicKey<Pub> {
    impl_arbitrary!(PUBLIC_KEY_BYTES_LEN);
}



#[derive(Clone)]
pub struct GenericSecretKey<Sig, Pub, Sec> {
    /// The underlying point which performs *actual* cryptographic operations.
    point: Sec,
    _phantom_signature: PhantomData<Sig>,
    _phantom_public_key: PhantomData<Pub>,
}
impl<Sig, Pub, Sec> GenericSecretKey<Sig, Pub, Sec>
where
    Sig: TSignature<Pub>,
    Pub: TPublicKey,
    Sec: TSecretKey<Sig, Pub>,
{
    pub fn serialize(&self) -> ZeroizeHash {
        self.point.serialize()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SECRET_KEY_BYTES_LEN {
            Err(Error::InvalidSecretKeyLength {
                got: bytes.len(),
                expected: SECRET_KEY_BYTES_LEN,
            })
        } else if bytes.iter().all(|b| *b == 0) {
            Err(Error::InvalidZeroSecretKey)
        } else {
            Ok(Self {
                point: Sec::deserialize(bytes)?,
                _phantom_signature: PhantomData,
                _phantom_public_key: PhantomData,
            })
        }
    }

    /// Returns the public key that corresponds to self.
    pub fn public_key(&self) -> GenericPublicKey<Pub> {
        GenericPublicKey::from_point(self.point.public_key())
    }
}

pub trait TSignature<GenericPublicKey>: Sized + Clone {
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN];

}

pub trait TSecretKey<SignaturePoint, PublicKeyPoint>: Sized {
    fn random() -> Self;
    fn serialize(&self) -> ZeroizeHash;
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
    fn public_key(&self) -> PublicKeyPoint;

}

