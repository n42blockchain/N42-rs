// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! BLS12-381 min-pk with gov5's exact decode and verify semantics
//! (`crypto/bls/blst` in N42-gov5).
//!
//! gov5 decodes a public key with blst `Uncompress` then `KeyValidate`
//! (subgroup check, infinity rejected), a signature with `Uncompress` then
//! `SigValidate(false)` (subgroup check, infinity allowed: an aggregate may be
//! the identity), and verifies with `Verify(false, pk, false, msg, dst)`, the
//! checks having run at decode. Aggregation sums points without re-validating.
//! The error strings are gov5's, because they end up in HTTP error bodies.

use blst::BLST_ERROR;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};

/// The domain separation tag gov5 signs proofs of possession and receipts
/// under (`crypto/bls/blst/signature.go:18`): the standard proof-of-possession
/// ciphersuite, no augmentation.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Length of a compressed G1 public key.
pub const PUBKEY_LEN: usize = 48;
/// Length of a compressed G2 signature.
pub const SIGNATURE_LEN: usize = 96;

/// gov5's error for bytes that do not decompress to a G1 point.
pub const ERR_PUBKEY_UNMARSHAL: &str = "could not unmarshal bytes into public key";
/// gov5's error for a public key that fails `KeyValidate` (`common.ErrInfinitePubKey`).
pub const ERR_PUBKEY_INFINITE: &str = "received an infinite public key";
/// gov5's error for bytes that do not decompress to a G2 point.
pub const ERR_SIG_UNMARSHAL: &str = "could not unmarshal bytes into signature";
/// gov5's error for a signature outside the G2 subgroup.
pub const ERR_SIG_NOT_IN_GROUP: &str = "signature not in group";

/// Decodes a compressed public key the way gov5's `PublicKeyFromBytes` does.
pub fn decode_pubkey(bytes: &[u8; PUBKEY_LEN]) -> Result<PublicKey, &'static str> {
    let pk = PublicKey::uncompress(bytes).map_err(|_| ERR_PUBKEY_UNMARSHAL)?;
    pk.validate().map_err(|_| ERR_PUBKEY_INFINITE)?;
    Ok(pk)
}

/// Decodes a compressed signature the way gov5's `SignatureFromBytes` does.
pub fn decode_signature(bytes: &[u8; SIGNATURE_LEN]) -> Result<Signature, &'static str> {
    let sig = Signature::uncompress(bytes).map_err(|_| ERR_SIG_UNMARSHAL)?;
    sig.validate(false).map_err(|_| ERR_SIG_NOT_IN_GROUP)?;
    Ok(sig)
}

/// Verifies an already-decoded signature under [`DST`] (gov5 `Signature.Verify`).
pub fn verify(sig: &Signature, pk: &PublicKey, msg: &[u8]) -> bool {
    sig.verify(false, msg, DST, &[], pk, false) == BLST_ERROR::BLST_SUCCESS
}

/// Sums signatures in G2 without validation (gov5 `AggregateSignatures`).
/// `None` for an empty input.
pub fn aggregate_signatures(sigs: &[&Signature]) -> Option<Signature> {
    if sigs.is_empty() {
        return None;
    }
    AggregateSignature::aggregate(sigs, false).ok().map(|a| a.to_signature())
}

/// Sums public keys in G1 without validation (gov5 `AggregateMultiplePubkeys`).
/// `None` for an empty input.
pub fn aggregate_pubkeys(pks: &[&PublicKey]) -> Option<PublicKey> {
    if pks.is_empty() {
        return None;
    }
    AggregatePublicKey::aggregate(pks, false).ok().map(|a| a.to_public_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage_and_identity() {
        assert_eq!(decode_pubkey(&[0u8; 48]).unwrap_err(), ERR_PUBKEY_UNMARSHAL);
        // Compressed identity: 0xc0 then zeros. Decompresses, fails KeyValidate.
        let mut inf = [0u8; 48];
        inf[0] = 0xc0;
        assert_eq!(decode_pubkey(&inf).unwrap_err(), ERR_PUBKEY_INFINITE);
        // The identity signature is accepted (aggregates may be the identity).
        let mut sig_inf = [0u8; 96];
        sig_inf[0] = 0xc0;
        assert!(decode_signature(&sig_inf).is_ok());
        assert_eq!(decode_signature(&[0u8; 96]).unwrap_err(), ERR_SIG_UNMARSHAL);
    }
}
