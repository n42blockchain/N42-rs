/// Defines all the fundamental BLS points which should be exported by this crate by making
/// concrete the generic type parameters using the points from some external BLS library (e.g.,BLST).
macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {

            pub type PublicKey = GenericPublicKey<bls_variant::PublicKey>;
            pub type PublicKeyBytes = GenericPublicKeyBytes<bls_variant::PublicKey>;

        }
    };
}

define_mod!(
    fake_crypto_implementations,
    crate::impls::fake_crypto::types
);

/// Provides the externally-facing, core BLS types.
pub mod types {
    pub use super::PublicKey;
}

#[derive(Clone)]
pub struct PublicKey([u8; PUBLIC_KEY_BYTES_LEN]);

/// The byte-length of a BLS public key when serialized in compressed form.
pub const PUBLIC_KEY_BYTES_LEN: usize = 48;