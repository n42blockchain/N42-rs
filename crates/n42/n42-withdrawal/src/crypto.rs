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

use std::fmt;
use std::marker::PhantomData;
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

/// Contains the functions required for a `Debug` implementation.
///
/// Does not include the `Impl` section since it gets very complicated when it comes to generics.
macro_rules! impl_debug {
    () => {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", hex_encode(&self.serialize().to_vec()))
        }
    };
}
impl<Pub> fmt::Debug for GenericPublicKeyBytes<Pub> {
    impl_debug!();
}

impl<Pub> Copy for GenericPublicKeyBytes<Pub> {}

impl<Pub> Clone for GenericPublicKeyBytes<Pub> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Pub> Eq for GenericPublicKeyBytes<Pub> {}

impl<Pub> PartialEq for GenericPublicKeyBytes<Pub> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

