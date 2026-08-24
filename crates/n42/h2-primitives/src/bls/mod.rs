mod aggregate;
mod keys;
mod verify;

/// BLS12-381 Domain Separation Tag for signatures.
///
/// Single definition used across signing, verification, and aggregation.
pub(crate) const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// H2-v4 uses gov5's deployed proof-of-possession ciphersuite. Keeping this
/// separate from the native Rust domain avoids changing existing validators.
pub(crate) const H2_V4_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub use aggregate::AggregateSignature;
pub use keys::{BlsError, BlsPublicKey, BlsSecretKey, BlsSignature};
pub use verify::{
    batch_verify, batch_verify_h2_v4, batch_verify_h2_v4_with_fallback, batch_verify_with_fallback,
};
