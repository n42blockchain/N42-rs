use std::fmt;
use std::hash::{Hash, Hasher};
use rand::Rng;
use std::marker::PhantomData;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize as serdeD, Serialize as serdeS};
use crate::Hash256;
use zeroize::Zeroize;
pub use blst::min_pk as blst_core;
#[cfg(feature = "supranational")]
use blst::BLST_ERROR as BlstError;
use ssz::{Decode, Encode};
use tree_hash::TreeHash;
use serde_utils::hex::encode as hex_encode;





/// The byte-length of a BLS secret key.
pub const SECRET_KEY_BYTES_LEN: usize = 32;
pub const PUBLIC_KEY_BYTES_LEN: usize = 48;
pub const SIGNATURE_BYTES_LEN: usize = 96;
pub const PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN: usize = 96;
pub const SIGNATURE_UNCOMPRESSED_BYTES_LEN: usize = 192;
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const INFINITY_PUBLIC_KEY: [u8; PUBLIC_KEY_BYTES_LEN] = [
    0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub mod generics{
    pub use crate::blst::GenericSecretKey;
    pub use crate::blst::GenericKeypair;
    pub use crate::blst::GenericPublicKeyBytes;
    pub use crate::blst::GenericSignatureBytes;
}


macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {
            use $mod as bls_variant;

            use crate::blst::generics::*;
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

#[cfg(feature = "supranational")]
define_mod!(blst_implementations, crate::blst::types);

#[cfg(all(feature = "supranational", not(feature = "fake_crypto"),))]
pub use blst_implementations::*;

pub mod types {
    pub use super::blst_core::PublicKey;
    pub use super::blst_core::SecretKey;
    pub use super::blst_core::Signature;
    // pub use super::verify_signature_sets;
    // pub use super::BlstAggregatePublicKey as AggregatePublicKey;
    // pub use super::BlstAggregateSignature as AggregateSignature;
    // pub use super::SignatureSet;
}


#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// An error was raised from the Supranational BLST BLS library.
    #[cfg(feature = "supranational")]
    BlstError(BlstError),
    /// The provided bytes were an incorrect length.
    InvalidByteLength { got: usize, expected: usize },
    /// The provided secret key bytes were an incorrect length.
    InvalidSecretKeyLength { got: usize, expected: usize },
    /// The public key represents the point at infinity, which is invalid.
    InvalidInfinityPublicKey,
    /// The secret key is all zero bytes, which is invalid.
    InvalidZeroSecretKey,
}

#[cfg(feature = "supranational")]
impl From<BlstError> for Error {
    fn from(e: BlstError) -> Error {
        Error::BlstError(e)
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
impl<Pub> GenericPublicKeyBytes<Pub>
where
    Pub: TPublicKey,
{
    /// Decompress and deserialize the bytes in `self` into an actual public key.
    ///
    /// May fail if the bytes are invalid.
    pub fn decompress(&self) -> Result<GenericPublicKey<Pub>, Error> {
        GenericPublicKey::deserialize(&self.bytes)
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

#[derive(Clone, PartialEq, Eq)]
pub struct GenericSignature<Pub, Sig> {
    /// The underlying point which performs *actual* cryptographic operations.
    point: Option<Sig>,
    /// True if this point is equal to the `INFINITY_SIGNATURE`.
    pub(crate) is_infinity: bool,
    _phantom: PhantomData<Pub>,
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

    /// Instantiates `Self` from a randomly generated secret key.
    pub fn random() -> Self {
        let sk = GenericSecretKey::random();
        Self {
            pk: sk.public_key(),
            sk,
            _phantom: PhantomData,
        }
    }
}





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

    /// Deserialize `self` from compressed bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes == &INFINITY_PUBLIC_KEY[..] {
            Err(Error::InvalidInfinityPublicKey)
        } else {
            Ok(Self {
                point: Pub::deserialize(bytes)?,
            })
        }
    }

    pub(crate) fn from_point(point: Pub) -> Self {
        Self { point }
    }

    /// Returns a reference to the underlying BLS point.
    pub(crate) fn point(&self) -> &Pub {
        &self.point
    }
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

#[cfg(feature = "arbitrary")]
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
    /// Instantiate `Self` from some secure source of entropy.
    pub fn random() -> Self {
        Self {
            point: Sec::random(),
            _phantom_signature: PhantomData,
            _phantom_public_key: PhantomData,
        }
    }

    pub fn public_key(&self) -> GenericPublicKey<Pub> {
        GenericPublicKey::from_point(self.point.public_key())
    }

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
}


pub trait TPublicKey: Sized + Clone {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN];
    /// Deserialize `self` from compressed bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}
pub trait TSecretKey<SignaturePoint, PublicKeyPoint>: Sized {
    fn random() -> Self;
    fn serialize(&self) -> ZeroizeHash;
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
    fn public_key(&self) -> PublicKeyPoint;
}
pub trait TSignature<GenericPublicKey>: Sized + Clone {
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN];
    /// Deserialize `self` from compressed bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
    /// Returns `true` if `self` is a signature across `msg` by `pubkey`.
    fn verify(&self, pubkey: &GenericPublicKey, msg: Hash256) -> bool;
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

impl TPublicKey for blst_core::PublicKey {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.compress()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        // key_validate accepts uncompressed bytes too so enforce byte length here.
        // It also does subgroup checks, noting infinity check is done in `generic_public_key.rs`.
        if bytes.len() != PUBLIC_KEY_BYTES_LEN {
            return Err(Error::InvalidByteLength {
                got: bytes.len(),
                expected: PUBLIC_KEY_BYTES_LEN,
            });
        }
        Self::key_validate(bytes).map_err(Into::into)
    }
}

impl TSignature<blst_core::PublicKey> for blst_core::Signature {
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.to_bytes()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes).map_err(Into::into)
    }

    fn verify(&self, pubkey: &blst_core::PublicKey, msg: Hash256) -> bool {
        // Public keys have already been checked for subgroup and infinity
        // Check Signature inside function for subgroup
        self.verify(true, msg.as_slice(), DST, &[], pubkey, false) == BlstError::BLST_SUCCESS
    }
}

impl TSecretKey<blst_core::Signature, blst_core::PublicKey> for blst_core::SecretKey {
    fn random() -> Self {
        let rng = &mut rand::thread_rng();
        let ikm: [u8; 32] = rng.gen();

        Self::key_gen(&ikm, &[]).unwrap()
    }

    fn public_key(&self) -> blst_core::PublicKey {
        self.sk_to_pk()
    }


    fn serialize(&self) -> ZeroizeHash {
        self.to_bytes().into()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes).map_err(Into::into)
    }
}
