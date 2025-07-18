pub mod common;

// mod reward;
mod reward_and_penalties;
mod per_epoch_processing;
mod validator_statuses;
mod base;
mod errors;
mod arith;
mod slashings;
mod spec;
mod beaconstate;
mod slot_epoch_macros;
mod slot_epoch;
mod pending_attestation;
mod attestation_data;
mod signing_data;
mod slot_data;
mod relative_epoch;
mod beacon_committee;
mod committee_cache;
mod get_attesting_indices;
mod attestation;
mod shuffle_list;
mod fork_name;

pub use tree_hash::Hash256;
pub use ssz_types::{typenum, typenum::Unsigned, BitList, BitVector, FixedVector, VariableList};
use bytes::{BufMut, BytesMut};
// pub fn add(left: u64, right: u64) -> u64 {
//     left + right
// }



// pub const NUM_FLAG_INDICES: usize = 3;





// /// Defines all the fundamental BLS points which should be exported by this crate by making
// /// concrete the generic type parameters using the points from some external BLS library (e.g.,BLST).
// macro_rules! define_mod {
//     ($name: ident, $mod: path) => {
//         pub mod $name {
//             use $mod as bls_variant;
//
//             use crate::generics::*;
//
//             pub use bls_variant::{verify_signature_sets, SignatureSet};
//
//             pub type PublicKey = GenericPublicKey<bls_variant::PublicKey>;
//             pub type PublicKeyBytes = GenericPublicKeyBytes<bls_variant::PublicKey>;
//             pub type AggregatePublicKey =
//                 GenericAggregatePublicKey<bls_variant::PublicKey, bls_variant::AggregatePublicKey>;
//             pub type Signature = GenericSignature<bls_variant::PublicKey, bls_variant::Signature>;
//             pub type BlsWrappedSignature<'a> = WrappedSignature<
//                 'a,
//                 bls_variant::PublicKey,
//                 bls_variant::AggregatePublicKey,
//                 bls_variant::Signature,
//                 bls_variant::AggregateSignature,
//             >;
//             pub type AggregateSignature = GenericAggregateSignature<
//                 bls_variant::PublicKey,
//                 bls_variant::AggregatePublicKey,
//                 bls_variant::Signature,
//                 bls_variant::AggregateSignature,
//             >;
//             pub type SignatureBytes =
//                 GenericSignatureBytes<bls_variant::PublicKey, bls_variant::Signature>;
//             pub type SecretKey = GenericSecretKey<
//                 bls_variant::Signature,
//                 bls_variant::PublicKey,
//                 bls_variant::SecretKey,
//             >;
//             pub type Keypair = GenericKeypair<
//                 bls_variant::PublicKey,
//                 bls_variant::SecretKey,
//                 bls_variant::Signature,
//             >;
//         }
//     };
// }
//
// #[cfg(feature = "supranational")]
// define_mod!(blst_implementations, crate::impls::blst::types);
// #[cfg(feature = "fake_crypto")]
// define_mod!(
//     fake_crypto_implementations,
//     crate::impls::fake_crypto::types
// );



/// Returns `int` as little-endian bytes with a length of 4.
pub fn int_to_bytes4(int: u32) -> [u8; 4] {
    int.to_le_bytes()
}

/// Returns `int` as little-endian bytes with a length of 8.
pub fn int_to_bytes8(int: u64) -> Vec<u8> {
    let mut bytes = BytesMut::with_capacity(8);
    bytes.put_u64_le(int);
    bytes.to_vec()
}









