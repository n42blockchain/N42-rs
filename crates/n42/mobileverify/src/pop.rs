// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proof of possession for registration (`internal/mobileverify/registry.go:51-64`).

use blst::min_pk::PublicKey;

use crate::bls::{self, PUBKEY_LEN, SIGNATURE_LEN};
use crate::error::MobileVerifyError;
use crate::gojson;

/// The 24-byte tag that prefixes a proof-of-possession message.
pub const POP_TAG: &[u8; 24] = b"n42/mobileverify/pop/v1\x00";

/// Length of a proof-of-possession message: tag ‖ pubkey.
pub const POP_MESSAGE_LEN: usize = POP_TAG.len() + PUBKEY_LEN;

/// The message a registrant signs: `"n42/mobileverify/pop/v1\0" ‖ pubkey48`.
pub fn pop_message(pubkey: &[u8; PUBKEY_LEN]) -> [u8; POP_MESSAGE_LEN] {
    let mut out = [0u8; POP_MESSAGE_LEN];
    out[..POP_TAG.len()].copy_from_slice(POP_TAG);
    out[POP_TAG.len()..].copy_from_slice(pubkey);
    out
}

/// Verifies a proof of possession; returns the decoded key (gov5 `verifyPoP`).
pub fn verify_pop(pubkey: &[u8; PUBKEY_LEN], pop: &[u8; SIGNATURE_LEN]) -> Result<PublicKey, MobileVerifyError> {
    let pk = bls::decode_pubkey(pubkey).map_err(MobileVerifyError::BadPopPubkey)?;
    let sig = bls::decode_signature(pop).map_err(MobileVerifyError::BadPopSignature)?;
    if !bls::verify(&sig, &pk, &pop_message(pubkey)) {
        return Err(MobileVerifyError::BadPop);
    }
    Ok(pk)
}

/// The registration body exactly as the SDK POSTs it
/// (`cmd/evmsdk/mobileverify_client.go`: `json.Marshal` of a map, keys
/// sorted, hex without `0x`; the proof-of-work nonce, when solved, as a decimal string).
pub fn register_request_json(pubkey: &[u8; PUBKEY_LEN], pop: &[u8; SIGNATURE_LEN], pow_nonce: Option<u64>) -> String {
    let mut obj = gojson::Obj::new().str("pop", &hex::encode(pop));
    if let Some(n) = pow_nonce {
        obj = obj.str("pow_nonce", &n.to_string());
    }
    obj.str("pubkey", &hex::encode(pubkey)).finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceKey;

    #[test]
    fn pop_message_layout() {
        let pk = [0xABu8; 48];
        let m = pop_message(&pk);
        assert_eq!(m.len(), 72);
        assert_eq!(&m[..24], b"n42/mobileverify/pop/v1\0");
        assert_eq!(&m[24..], &pk);
    }

    #[test]
    fn verify_pop_accepts_and_rejects() {
        let a = DeviceKey::from_ikm(&[1u8; 32]).unwrap();
        let b = DeviceKey::from_ikm(&[2u8; 32]).unwrap();
        assert!(verify_pop(&a.pubkey(), &a.proof_of_possession()).is_ok());
        let err = verify_pop(&a.pubkey(), &b.proof_of_possession()).unwrap_err();
        assert_eq!(err.to_string(), "mobileverify: invalid proof of possession");
        let err = verify_pop(&[0u8; 48], &a.proof_of_possession()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "mobileverify: invalid proof of possession: pubkey decode: could not unmarshal bytes into public key"
        );
        let err = verify_pop(&a.pubkey(), &[0u8; 96]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "mobileverify: invalid proof of possession: signature decode: could not unmarshal bytes into signature"
        );
    }
}
