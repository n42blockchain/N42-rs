use std::borrow::Cow;
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
use crate::Hash256;

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
/// Represents the signature at infinity.
pub const INFINITY_SIGNATURE: [u8; SIGNATURE_BYTES_LEN] = [
    0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];
/// The compressed bytes used to represent `GenericSignature::empty()`.
pub const NONE_SIGNATURE: [u8; SIGNATURE_BYTES_LEN] = [0; SIGNATURE_BYTES_LEN];
/// The compressed bytes used to represent `GenericAggregateSignature::empty()`.
pub const EMPTY_SIGNATURE_SERIALIZATION: [u8; SIGNATURE_BYTES_LEN] = [0; SIGNATURE_BYTES_LEN];

/// Generic implementations which are only generally useful for docs.
pub mod generics {
    pub use crate::crypto::GenericPublicKeyBytes;
    pub use crate::crypto::GenericSignatureBytes;
    pub use crate::crypto::GenericKeypair;
    pub use crate::crypto::GenericSecretKey;
    pub use crate::crypto::GenericPublicKey;
    pub use crate::crypto::GenericSignature;
    pub use crate::crypto::GenericAggregateSignature;
}

/// Defines all the fundamental BLS points which should be exported by this crate by making
/// concrete the generic type parameters using the points from some external BLS library (e.g.,BLST).
macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {
            use $mod as bls_variant;
            use crate::crypto::generics::*;
            pub type BlsPublicKey = GenericPublicKey<bls_variant::PublicKey>;   // 改成BlsPublicKey正确跳转
            pub type PublicKeyBytes = GenericPublicKeyBytes<bls_variant::PublicKey>;
            pub type BlsSignature = GenericSignature<bls_variant::PublicKey, bls_variant::Signature>; // 改成BlsSignature正确跳转
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
            pub type BlsAggregateSignature = GenericAggregateSignature< // 改成BlsAggregateSignature正确跳转
                bls_variant::PublicKey,
                bls_variant::AggregatePublicKey,
                bls_variant::Signature,
                bls_variant::AggregateSignature,
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
    pub use super::SignatureSet;
    pub use super::AggregateSignature;
    pub use super::AggregatePublicKey;
}

#[derive(Clone)]
pub struct PublicKey([u8; PUBLIC_KEY_BYTES_LEN]);
impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

#[derive(Clone)]
pub struct Signature([u8; SIGNATURE_BYTES_LEN]);
impl Signature {
    fn infinity() -> Self {
        Self([0; SIGNATURE_BYTES_LEN])
    }
}

#[derive(Clone)]
pub struct SecretKey([u8; SECRET_KEY_BYTES_LEN]);

pub type SignatureSet<'a> = GenericSignatureSet<
    'a,
    PublicKey,
    AggregatePublicKey,
    Signature,
    AggregateSignature,
>;

#[derive(Clone)]
pub struct AggregatePublicKey([u8; PUBLIC_KEY_BYTES_LEN]);
impl TAggregatePublicKey<PublicKey> for AggregatePublicKey {}
impl Eq for AggregatePublicKey {}
impl PartialEq for AggregatePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

#[derive(Clone)]
pub struct AggregateSignature([u8; SIGNATURE_BYTES_LEN]);
impl Eq for AggregateSignature {}
impl PartialEq for AggregateSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}
impl AggregateSignature {
    fn infinity() -> Self {
        Self(INFINITY_SIGNATURE)
    }
}

impl TAggregateSignature<PublicKey, AggregatePublicKey, Signature> for AggregateSignature {
    fn infinity() -> Self {
        Self::infinity()
    }
    fn add_assign(&mut self, _other: &Signature) {
        // Do nothing.
    }
    fn fast_aggregate_verify(
        &self,
        _msg: Hash256,
        _pubkeys: &[&GenericPublicKey<PublicKey>],
    ) -> bool {
        true
    }
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        let mut bytes = [0; SIGNATURE_BYTES_LEN];

        bytes[..].copy_from_slice(&self.0);

        bytes
    }
}
impl PublicKey {
    fn infinity() -> Self {
        Self(INFINITY_PUBLIC_KEY)
    }
}

impl TPublicKey for PublicKey {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.0
    }
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut pubkey = Self::infinity();
        pubkey.0[..].copy_from_slice(&bytes[0..PUBLIC_KEY_BYTES_LEN]);
        Ok(pubkey)
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
    fn sign(&self, _message: Hash256) -> Signature {
        Signature::infinity()
    }
}

impl TSignature<PublicKey> for Signature {
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.0
    }
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut signature = Self::infinity();
        signature.0[..].copy_from_slice(&bytes[0..SIGNATURE_BYTES_LEN]);
        Ok(signature)
    }
    fn verify(&self, _pubkey: &PublicKey, _msg: Hash256) -> bool {
        true
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for Signature {}
impl std::hash::Hash for Signature {
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        self.0.hash(hasher);
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

impl<Pub, Sig> GenericSignatureBytes<Pub, Sig>
where
    Sig: TSignature<Pub>,
    Pub: TPublicKey,
{
    /// Decompress and deserialize the bytes in `self` into an actual signature.
    ///
    /// May fail if the bytes are invalid.
    pub fn decompress(&self) -> Result<GenericSignature<Pub, Sig>, Error> {
        let is_infinity = self.bytes[..] == INFINITY_SIGNATURE[..];
        Sig::deserialize(&self.bytes).map(|point| GenericSignature::from_point(point, is_infinity))
    }
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


/// Implemented on some struct from a BLS library so it may be used as the `point` in a
/// `GenericPublicKey`.
pub trait TPublicKey: Sized + Clone {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN];
    /// Deserialize `self` from compressed bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
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
    pub fn sign(&self, message: Hash256) -> Sig {
        self.point.sign(message)
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

    /// Returns the public key that corresponds to self.
    pub fn public_key(&self) -> GenericPublicKey<Pub> {
        GenericPublicKey::from_point(self.point.public_key())
    }
}

pub trait TSignature<GenericPublicKey>: Sized + Clone {
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN];
    /// Deserialize `self` from compressed bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
    /// Returns `true` if `self` is a signature across `msg` by `pubkey`.
    fn verify(&self, pubkey: &GenericPublicKey, msg: Hash256) -> bool;
}

pub trait TSecretKey<SignaturePoint, PublicKeyPoint>: Sized {
    fn random() -> Self;
    fn serialize(&self) -> ZeroizeHash;
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
    fn public_key(&self) -> PublicKeyPoint;
    fn sign(&self, message: Hash256) -> SignaturePoint;
}


/// A generic way to represent a signature across a message by multiple public keys.
///
/// This struct is primarily useful in a collection (e.g., `Vec<GenericSignatureSet>`) so we can perform
/// multiple-signature verification which is much faster than verifying each signature
/// individually.
#[derive(Clone)]
pub struct GenericSignatureSet<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: Clone,
    AggSig: Clone,
{
    pub signature: Cow<'a, GenericAggregateSignature<Pub, AggPub, Sig, AggSig>>,
    pub(crate) signing_keys: Vec<Cow<'a, GenericPublicKey<Pub>>>,
    pub(crate) message: Hash256,
    _phantom: PhantomData<Sig>,
}

impl<'a, Pub, AggPub, Sig, AggSig> GenericSignatureSet<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: TAggregatePublicKey<Pub> + Clone,
    Sig: TSignature<Pub> + Clone,
    AggSig: TAggregateSignature<Pub, AggPub, Sig> + Clone,
{
    /// Instantiate self where `signature` is only signed by a single public key.
    pub fn single_pubkey(
        signature: impl Into<WrappedSignature<'a, Pub, AggPub, Sig, AggSig>>,
        signing_key: Cow<'a, GenericPublicKey<Pub>>,
        message: Hash256,
    ) -> Self {
        Self {
            signature: signature.into().aggregate,
            signing_keys: vec![signing_key],
            message,
            _phantom: PhantomData,
        }
    }
    /// Instantiate self where `signature` is signed by multiple public keys.
    pub fn multiple_pubkeys(
        signature: impl Into<WrappedSignature<'a, Pub, AggPub, Sig, AggSig>>,
        signing_keys: Vec<Cow<'a, GenericPublicKey<Pub>>>,
        message: Hash256,
    ) -> Self {
        Self {
            signature: signature.into().aggregate,
            signing_keys,
            message,
            _phantom: PhantomData,
        }
    }

    /// Returns `true` if `self.signature` is a signature across `self.message` by
    /// `self.signing_keys`.
    pub fn verify(self) -> bool {
        let pubkeys = self
            .signing_keys
            .iter()
            .map(|pk| pk.as_ref())
            .collect::<Vec<_>>();

        self.signature
            .fast_aggregate_verify(self.message, &pubkeys[..])
    }
}

/// A generic way to represent a `GenericSignature` or `GenericAggregateSignature`.
pub struct WrappedSignature<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: Clone,
    AggSig: Clone,
{
    aggregate: Cow<'a, GenericAggregateSignature<Pub, AggPub, Sig, AggSig>>,
}
impl<'a, Pub, AggPub, Sig, AggSig> From<&'a GenericSignature<Pub, Sig>>
for WrappedSignature<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: TSignature<Pub> + Clone,
    AggSig: TAggregateSignature<Pub, AggPub, Sig> + Clone,
{
    fn from(sig: &'a GenericSignature<Pub, Sig>) -> Self {
        let mut aggregate: GenericAggregateSignature<Pub, AggPub, Sig, AggSig> =
            GenericAggregateSignature::infinity();
        aggregate.add_assign(sig);
        WrappedSignature {
            aggregate: Cow::Owned(aggregate),
        }
    }
}

impl<'a, Pub, AggPub, Sig, AggSig> From<&'a GenericAggregateSignature<Pub, AggPub, Sig, AggSig>>
for WrappedSignature<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: Clone,
    AggSig: Clone,
{
    fn from(aggregate: &'a GenericAggregateSignature<Pub, AggPub, Sig, AggSig>) -> Self {
        WrappedSignature {
            aggregate: Cow::Borrowed(aggregate),
        }
    }
}

/// A BLS aggregate signature that is generic across:
///
/// - `Pub`: A BLS public key.
/// - `AggPub`: A BLS aggregate public key.
/// - `Sig`: A BLS signature.
/// - `AggSig`: A BLS aggregate signature.
///
/// Provides generic functionality whilst deferring all serious cryptographic operations to the
/// generics.
#[derive(Clone, PartialEq)]
pub struct GenericAggregateSignature<Pub, AggPub, Sig, AggSig> {
    /// The underlying point which performs *actual* cryptographic operations.
    point: Option<AggSig>,
    /// True if this point is equal to the `INFINITY_SIGNATURE`.
    pub(crate) is_infinity: bool,
    _phantom_pub: PhantomData<Pub>,
    _phantom_agg_pub: PhantomData<AggPub>,
    _phantom_sig: PhantomData<Sig>,
}
impl<Pub, AggPub, Sig, AggSig> GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    /// Initialize `Self` to the infinity value which can then have other signatures aggregated
    /// upon it.
    pub fn infinity() -> Self {
        Self {
            point: Some(AggSig::infinity()),
            is_infinity: true,
            _phantom_pub: PhantomData,
            _phantom_agg_pub: PhantomData,
            _phantom_sig: PhantomData,
        }
    }

    /// Aggregates a signature onto `self`.
    pub fn add_assign(&mut self, other: &GenericSignature<Pub, Sig>) {
        if let Some(other_point) = other.point() {
            self.is_infinity = self.is_infinity && other.is_infinity;
            if let Some(self_point) = &mut self.point {
                self_point.add_assign(other_point)
            } else {
                let mut self_point = AggSig::infinity();
                self_point.add_assign(other_point);
                self.point = Some(self_point)
            }
        }
    }

    /// Returns `true` if `self` is equal to the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.is_infinity
    }

    /// Serialize `self` as compressed bytes.
    pub fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        if let Some(point) = &self.point {
            point.serialize()
        } else {
            EMPTY_SIGNATURE_SERIALIZATION
        }
    }
}
impl<Pub, AggPub, Sig, AggSig> GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: TAggregatePublicKey<Pub> + Clone,
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    /// Verify that `self` represents an aggregate signature where all `pubkeys` have signed `msg`.
    pub fn fast_aggregate_verify(&self, msg: Hash256, pubkeys: &[&GenericPublicKey<Pub>]) -> bool {
        if pubkeys.is_empty() {
            return false;
        }

        match self.point.as_ref() {
            Some(point) => point.fast_aggregate_verify(msg, pubkeys),
            None => false,
        }
    }
}

impl<Pub, AggPub, Sig, AggSig> Encode for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_ssz_encode!(SIGNATURE_BYTES_LEN);
}

impl<Pub, AggPub, Sig, AggSig> Decode for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_ssz_decode!(SIGNATURE_BYTES_LEN);
}

impl<Pub, AggPub, Sig, AggSig> TreeHash for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_tree_hash!(SIGNATURE_BYTES_LEN);
}

/// Hashes the `self.serialize()` bytes.
#[allow(clippy::derived_hash_with_manual_eq)]
impl<Pub, AggPub, Sig, AggSig> Hash for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.serialize().hash(state);
    }
}

impl<Pub, AggPub, Sig, AggSig> fmt::Display for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_display!();
}

impl<Pub, AggPub, Sig, AggSig> std::str::FromStr
for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_from_str!();
}

impl<Pub, AggPub, Sig, AggSig> Serialize for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_serde_serialize!();
}

impl<'de, Pub, AggPub, Sig, AggSig> Deserialize<'de>
for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_serde_deserialize!();
}

impl<Pub, AggPub, Sig, AggSig> fmt::Debug for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<Pub, AggPub, Sig, AggSig> arbitrary::Arbitrary<'_>
for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Pub: 'static,
    AggPub: 'static,
    Sig: TSignature<Pub> + 'static,
    AggSig: TAggregateSignature<Pub, AggPub, Sig> + 'static,
{
    impl_arbitrary!(SIGNATURE_BYTES_LEN);
}

/// Implemented on some struct from a BLS library so it may be used internally in this crate.
pub trait TAggregatePublicKey<Pub>: Sized + Clone {
    // fn to_public_key(&self) -> GenericPublicKey<Pub>;
    //
    // // NOTE: this API *could* take a `&[&Pub]` as that's what the underlying library needs,
    // // but it seems that this type would rarely occur due to our use of wrapper structs
    // fn aggregate(pubkeys: &[GenericPublicKey<Pub>]) -> Result<Self, Error>;
}
/// Implemented on some struct from a BLS library so it may be used as the `point` in an
/// `GenericAggregateSignature`.
///
pub trait TAggregateSignature<Pub, AggPub, Sig>: Sized + Clone {
    /// Initialize `Self` to the infinity value which can then have other signatures aggregated
    /// upon it.
    fn infinity() -> Self;
    /// Verify that `self` represents an aggregate signature where all `pubkeys` have signed `msg`.
    fn fast_aggregate_verify(&self, msg: Hash256, pubkeys: &[&GenericPublicKey<Pub>]) -> bool;
    /// Aggregates a signature onto `self`.
    fn add_assign(&mut self, other: &Sig);
    /// Serialize `self` as compressed bytes.
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN];
}

/// A BLS signature that is generic across:
///
/// - `Pub`: A BLS public key.
/// - `Sig`: A BLS signature.
///
/// Provides generic functionality whilst deferring all serious cryptographic operations to the
/// generics.
#[derive(Clone, PartialEq, Eq)]
pub struct GenericSignature<Pub, Sig> {
    /// The underlying point which performs *actual* cryptographic operations.
    point: Option<Sig>,
    /// True if this point is equal to the `INFINITY_SIGNATURE`.
    pub(crate) is_infinity: bool,
    _phantom: PhantomData<Pub>,
}
impl<Pub, Sig> GenericSignature<Pub, Sig>
where
    Sig: TSignature<Pub>,
{
    /// Instantiates `Self` from a `point`.
    pub(crate) fn from_point(point: Sig, is_infinity: bool) -> Self {
        Self {
            point: Some(point),
            is_infinity,
            _phantom: PhantomData,
        }
    }

    /// Serialize `self` as compressed bytes.
    pub fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        if let Some(point) = &self.point {
            point.serialize()
        } else {
            NONE_SIGNATURE
        }
    }
    /// Returns a reference to the underlying BLS point.
    pub(crate) fn point(&self) -> Option<&Sig> {
        self.point.as_ref()
    }
}

impl<Pub, Sig> GenericSignature<Pub, Sig>
where
    Sig: TSignature<Pub>,
    Pub: TPublicKey + Clone,
{
    /// Returns `true` if `self` is a signature across `msg` by `pubkey`.
    pub fn verify(&self, pubkey: &GenericPublicKey<Pub>, msg: Hash256) -> bool {
        if let Some(point) = &self.point {
            point.verify(pubkey.point(), msg)
        } else {
            false
        }
    }
}

impl<PublicKey, T: TSignature<PublicKey>> Encode for GenericSignature<PublicKey, T> {
    impl_ssz_encode!(SIGNATURE_BYTES_LEN);
}

impl<PublicKey, T: TSignature<PublicKey>> Decode for GenericSignature<PublicKey, T> {
    impl_ssz_decode!(SIGNATURE_BYTES_LEN);
}

impl<PublicKey, T: TSignature<PublicKey>> TreeHash for GenericSignature<PublicKey, T> {
    impl_tree_hash!(SIGNATURE_BYTES_LEN);
}

/// Hashes the `self.serialize()` bytes.
impl<PublicKey, T: TSignature<PublicKey>> Hash for GenericSignature<PublicKey, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.serialize().hash(state);
    }
}

impl<PublicKey, T: TSignature<PublicKey>> fmt::Display for GenericSignature<PublicKey, T> {
    impl_display!();
}

impl<PublicKey, T: TSignature<PublicKey>> std::str::FromStr for GenericSignature<PublicKey, T> {
    impl_from_str!();
}

impl<PublicKey, T: TSignature<PublicKey>> Serialize for GenericSignature<PublicKey, T> {
    impl_serde_serialize!();
}

impl<'de, PublicKey, T: TSignature<PublicKey>> Deserialize<'de> for GenericSignature<PublicKey, T> {
    impl_serde_deserialize!();
}

impl<PublicKey, T: TSignature<PublicKey>> fmt::Debug for GenericSignature<PublicKey, T> {
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<PublicKey: 'static, T: TSignature<PublicKey> + 'static> arbitrary::Arbitrary<'_>
for GenericSignature<PublicKey, T>
{
    impl_arbitrary!(SIGNATURE_BYTES_LEN);
}