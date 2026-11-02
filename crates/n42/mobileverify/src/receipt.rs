// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A mobile verifier's receipt (`internal/mobileverify/receipt.go`) and the
//! JSON body `POST /mobileverify/receipt` takes (`httpserver.go:217-254`).
//!
//! The signed message is 72 bytes: `block_hash ‖ block_number u64 LE ‖
//! computed_receipts_root`; `timestampMs` is not signed.

use alloy_primitives::B256;

use crate::bls::{self, PUBKEY_LEN, SIGNATURE_LEN};
use crate::error::MobileVerifyError;
use crate::gojson::{self, BadJson};

/// Length of the receipt signing message.
pub const SIGNING_MESSAGE_LEN: usize = 32 + 8 + 32;

/// The canonical 72-byte receipt message.
pub fn signing_message(block_hash: B256, block_number: u64, receipts_root: B256) -> [u8; SIGNING_MESSAGE_LEN] {
    let mut out = [0u8; SIGNING_MESSAGE_LEN];
    out[..32].copy_from_slice(block_hash.as_slice());
    out[32..40].copy_from_slice(&block_number.to_le_bytes());
    out[40..].copy_from_slice(receipts_root.as_slice());
    out
}

/// One device's attestation of its own re-execution of a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// The attested block's hash.
    pub block_hash: B256,
    /// The attested block's number.
    pub block_number: u64,
    /// The receipts root the device computed.
    pub computed_receipts_root: B256,
    /// The device's compressed G1 key.
    pub verifier_pubkey: [u8; PUBKEY_LEN],
    /// The compressed G2 signature over [`signing_message`].
    pub signature: [u8; SIGNATURE_LEN],
    /// The device's clock at signing; not signed.
    pub timestamp_ms: u64,
}

impl Receipt {
    /// The message this receipt signs.
    pub fn message(&self) -> [u8; SIGNING_MESSAGE_LEN] {
        signing_message(self.block_hash, self.block_number, self.computed_receipts_root)
    }

    /// Verifies the signature against the embedded key (gov5 `VerifySignature`).
    pub fn verify_signature(&self) -> Result<(), MobileVerifyError> {
        let pk = bls::decode_pubkey(&self.verifier_pubkey).map_err(MobileVerifyError::BadReceiptPubkey)?;
        let sig = bls::decode_signature(&self.signature).map_err(MobileVerifyError::BadReceiptSigDecode)?;
        if !bls::verify(&sig, &pk, &self.message()) {
            return Err(MobileVerifyError::BadReceiptSignature);
        }
        Ok(())
    }

    /// The request body exactly as the SDK POSTs it
    /// (`cmd/evmsdk/mobileverify_client.go:303-310`: `json.Marshal` of a map,
    /// so keys sorted, hex without `0x`, numbers as JSON numbers).
    pub fn to_request_json(&self) -> String {
        gojson::Obj::new()
            .str("blockHash", &hex::encode(self.block_hash))
            .num("blockNumber", self.block_number)
            .str("pubkey", &hex::encode(self.verifier_pubkey))
            .str("receiptsRoot", &hex::encode(self.computed_receipts_root))
            .str("signature", &hex::encode(self.signature))
            .num("timestampMs", self.timestamp_ms)
            .finish()
    }
}

/// Why a receipt request body was refused, as gov5 answers it (400).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptRequestError {
    /// The body is not a JSON object of the right field types.
    #[error("bad json")]
    BadJson,
    /// A hex field does not decode to its exact length.
    #[error("bad hex field lengths")]
    BadHex,
}

impl From<BadJson> for ReceiptRequestError {
    fn from(_: BadJson) -> Self {
        Self::BadJson
    }
}

/// Parses a `POST /mobileverify/receipt` body the way gov5 does.
pub fn parse_receipt_request(body: &[u8]) -> Result<Receipt, ReceiptRequestError> {
    let obj = gojson::decode_object(body)?;
    let o = obj.as_ref();
    let block_hash = gojson::get_string(o, "blockHash")?;
    let block_number = gojson::get_u64(o, "blockNumber")?;
    let receipts_root = gojson::get_string(o, "receiptsRoot")?;
    let pubkey = gojson::get_string(o, "pubkey")?;
    let signature = gojson::get_string(o, "signature")?;
    let timestamp_ms = gojson::get_u64(o, "timestampMs")?;
    let bad = ReceiptRequestError::BadHex;
    Ok(Receipt {
        block_hash: B256::from(gojson::hex_into::<32>(&block_hash).ok_or(bad)?),
        block_number,
        computed_receipts_root: B256::from(gojson::hex_into::<32>(&receipts_root).ok_or(bad)?),
        verifier_pubkey: gojson::hex_into::<48>(&pubkey).ok_or(bad)?,
        signature: gojson::hex_into::<96>(&signature).ok_or(bad)?,
        timestamp_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceKey;

    /// gov5 `sdk_compat_test.go:21`: `hash[i] = i`, `root[i] = 0xFF - i`,
    /// number 13220145.
    #[test]
    fn message_layout_matches_gov5_pin() {
        let hash = B256::from(core::array::from_fn::<u8, 32, _>(|i| i as u8));
        let root = B256::from(core::array::from_fn::<u8, 32, _>(|i| 0xFF - i as u8));
        let m = signing_message(hash, 13_220_145, root);
        assert_eq!(&m[..32], hash.as_slice());
        assert_eq!(&m[32..40], &13_220_145u64.to_le_bytes());
        assert_eq!(&m[40..], root.as_slice());
    }

    #[test]
    fn json_round_trip_and_verify() {
        let k = DeviceKey::from_ikm(&[9u8; 32]).unwrap();
        let hash = B256::repeat_byte(1);
        let root = B256::repeat_byte(2);
        let r = Receipt {
            block_hash: hash,
            block_number: 42,
            computed_receipts_root: root,
            verifier_pubkey: k.pubkey(),
            signature: k.sign_receipt(hash, 42, root),
            timestamp_ms: 7,
        };
        r.verify_signature().unwrap();
        let parsed = parse_receipt_request(r.to_request_json().as_bytes()).unwrap();
        assert_eq!(parsed, r);
        let mut bad = r;
        bad.block_number = 43;
        assert_eq!(bad.verify_signature().unwrap_err().to_string(), "mobileverify: invalid receipt signature");
        assert_eq!(parse_receipt_request(b"{").unwrap_err(), ReceiptRequestError::BadJson);
        assert_eq!(parse_receipt_request(b"{}").unwrap_err(), ReceiptRequestError::BadHex);
        assert_eq!(
            parse_receipt_request(br#"{"blockNumber":"1"}"#).unwrap_err(),
            ReceiptRequestError::BadJson
        );
    }
}
