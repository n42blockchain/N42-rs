use alloy_primitives::B256;
use n42_h2_primitives::{BlsPublicKey, BlsSecretKey, BlsSignature};
use serde::{Deserialize, Serialize};

use crate::serde_helpers::pubkey_48;

/// Verification receipt returned from a mobile device to the IDC node.
///
/// After re-executing a block, the phone computes the receipts root and
/// returns it to the IDC node. The IDC node checks the value against the
/// expected receipts root to confirm the phone actually executed the block.
/// Uses BLS12-381 signatures to prevent tampering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReceipt {
    pub block_hash: B256,
    pub block_number: u64,
    /// The receipts root computed by re-executing the block on the phone.
    /// The IDC node compares this against the expected value.
    pub computed_receipts_root: B256,
    /// BLS12-381 public key of the verifier (48 bytes).
    #[serde(with = "pubkey_48")]
    pub verifier_pubkey: [u8; 48],
    /// BLS12-381 signature over the receipt content.
    pub signature: BlsSignature,
    /// Milliseconds since UNIX epoch when verification completed.
    pub timestamp_ms: u64,
}

/// Builds the canonical signing message for a receipt.
///
/// Format: `block_hash(32B) || block_number(8B LE) || computed_receipts_root(32B)`
///
/// `timestamp_ms` is intentionally excluded from the signed data so that all
/// phones attesting to the same `(block_hash, block_number, receipts_root)`
/// produce signatures over an identical 72-byte message. This enables efficient
/// BLS aggregate verification via `fast_aggregate_verify` (2 pairings regardless
/// of participant count), mirroring the Ethereum beacon-chain approach where
/// per-validator timing is metadata, not part of the signed attestation.
pub fn build_signing_message(
    block_hash: &B256,
    block_number: u64,
    computed_receipts_root: &B256,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(72);
    msg.extend_from_slice(block_hash.as_slice());
    msg.extend_from_slice(&block_number.to_le_bytes());
    msg.extend_from_slice(computed_receipts_root.as_slice());
    msg
}

impl VerificationReceipt {
    /// Checks whether the computed receipts root matches the expected value.
    ///
    /// This is called on the IDC side after receiving the receipt from the phone.
    pub fn matches_expected(&self, expected_receipts_root: &B256) -> bool {
        self.computed_receipts_root == *expected_receipts_root
    }

    /// Constructs the canonical signing message for this receipt.
    pub fn signing_message(&self) -> Vec<u8> {
        build_signing_message(
            &self.block_hash,
            self.block_number,
            &self.computed_receipts_root,
        )
    }

    /// Verifies the BLS12-381 signature on this receipt.
    pub fn verify_signature(&self) -> Result<(), ReceiptError> {
        let pubkey = BlsPublicKey::from_bytes(&self.verifier_pubkey)
            .map_err(|_| ReceiptError::InvalidPublicKey)?;
        pubkey
            .verify(&self.signing_message(), &self.signature)
            .map_err(|_| ReceiptError::InvalidSignature)
    }
}

/// Creates a signed verification receipt after executing a block.
pub fn sign_receipt(
    block_hash: B256,
    block_number: u64,
    computed_receipts_root: B256,
    timestamp_ms: u64,
    signing_key: &BlsSecretKey,
) -> VerificationReceipt {
    let verifier_pubkey = signing_key.public_key().to_bytes();
    let msg = build_signing_message(&block_hash, block_number, &computed_receipts_root);
    let signature = signing_key.sign(&msg);

    VerificationReceipt {
        block_hash,
        block_number,
        computed_receipts_root,
        verifier_pubkey,
        signature,
        timestamp_ms,
    }
}

/// Encodes a `VerificationReceipt` with a wire header.
///
/// Format: `wire_header(4B) + block_hash(32B) + block_number(8B LE)`
///       `+ computed_receipts_root(32B)`
///       `+ verifier_pubkey(48B) + signature(96B) + timestamp_ms(8B LE)`
pub fn encode_receipt(receipt: &VerificationReceipt) -> Vec<u8> {
    use crate::wire;

    let mut buf = Vec::with_capacity(wire::HEADER_SIZE + 32 + 8 + 32 + 48 + 96 + 8);
    wire::encode_header(&mut buf, wire::VERSION_1, 0x00);
    buf.extend_from_slice(receipt.block_hash.as_slice());
    buf.extend_from_slice(&receipt.block_number.to_le_bytes());
    buf.extend_from_slice(receipt.computed_receipts_root.as_slice());
    buf.extend_from_slice(&receipt.verifier_pubkey);
    buf.extend_from_slice(&receipt.signature.to_bytes());
    buf.extend_from_slice(&receipt.timestamp_ms.to_le_bytes());
    buf
}

/// Decodes a `VerificationReceipt` from versioned wire format.
pub fn decode_receipt(data: &[u8]) -> Result<VerificationReceipt, crate::wire::WireError> {
    use crate::wire::{self, WireError};

    let (_header, payload) = wire::decode_header(data)?;

    // Payload: block_hash(32) + block_number(8) + computed_receipts_root(32) + pubkey(48) + sig(96) + ts(8) = 224
    const RECEIPT_PAYLOAD_SIZE: usize = 32 + 8 + 32 + 48 + 96 + 8;
    if payload.len() < RECEIPT_PAYLOAD_SIZE {
        return Err(WireError::UnexpectedEof(payload.len()));
    }

    let mut pos = 0;

    let block_hash = B256::from_slice(&payload[pos..pos + 32]);
    pos += 32;
    let block_number = u64::from_le_bytes(
        payload[pos..pos + 8]
            .try_into()
            .map_err(|_| WireError::UnexpectedEof(pos + 8))?,
    );
    pos += 8;
    let computed_receipts_root = B256::from_slice(&payload[pos..pos + 32]);
    pos += 32;

    let mut verifier_pubkey = [0u8; 48];
    verifier_pubkey.copy_from_slice(&payload[pos..pos + 48]);
    pos += 48;

    let sig_bytes: [u8; 96] = payload[pos..pos + 96]
        .try_into()
        .map_err(|_| WireError::UnexpectedEof(pos))?;
    let signature =
        BlsSignature::from_bytes(&sig_bytes).map_err(|_| WireError::InvalidTag(0, pos))?;
    pos += 96;

    let timestamp_ms = u64::from_le_bytes(
        payload[pos..pos + 8]
            .try_into()
            .map_err(|_| WireError::UnexpectedEof(pos + 8))?,
    );

    Ok(VerificationReceipt {
        block_hash,
        block_number,
        computed_receipts_root,
        verifier_pubkey,
        signature,
        timestamp_ms,
    })
}

/// Receipt verification errors.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    /// The BLS12-381 public key is malformed.
    #[error("invalid BLS12-381 public key")]
    InvalidPublicKey,

    /// The BLS12-381 signature verification failed.
    #[error("invalid BLS12-381 signature")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use n42_h2_primitives::BlsSecretKey;

    /// Helper: creates a signed receipt with the given parameters.
    fn make_receipt(
        block_hash: B256,
        block_number: u64,
        computed_receipts_root: B256,
        timestamp_ms: u64,
        sk: &BlsSecretKey,
    ) -> VerificationReceipt {
        sign_receipt(
            block_hash,
            block_number,
            computed_receipts_root,
            timestamp_ms,
            sk,
        )
    }

    #[test]
    fn test_sign_and_verify() {
        let sk = BlsSecretKey::key_gen(&[42u8; 32]).unwrap();
        let block_hash = B256::from([1u8; 32]);
        let computed_rr = B256::from([0xAA; 32]);
        let receipt = make_receipt(block_hash, 100, computed_rr, 1_700_000_000_000, &sk);

        assert_eq!(receipt.verifier_pubkey, sk.public_key().to_bytes());
        assert_eq!(receipt.block_hash, block_hash);
        assert_eq!(receipt.block_number, 100);
        assert_eq!(receipt.computed_receipts_root, computed_rr);
        assert_eq!(receipt.timestamp_ms, 1_700_000_000_000);

        receipt
            .verify_signature()
            .expect("signature should be valid");
    }

    #[test]
    fn test_verify_tampered_receipt() {
        let sk = BlsSecretKey::key_gen(&[42u8; 32]).unwrap();
        let block_hash = B256::from([1u8; 32]);
        let mut receipt = make_receipt(
            block_hash,
            100,
            B256::from([0xAA; 32]),
            1_700_000_000_000,
            &sk,
        );

        receipt.block_number = 999;

        let result = receipt.verify_signature();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReceiptError::InvalidSignature
        ));
    }

    #[test]
    fn test_matches_expected() {
        let sk = BlsSecretKey::key_gen(&[42u8; 32]).unwrap();
        let block_hash = B256::from([2u8; 32]);
        let expected = B256::from([0xBB; 32]);

        let receipt = make_receipt(block_hash, 1, expected, 0, &sk);
        assert!(receipt.matches_expected(&expected));
        assert!(!receipt.matches_expected(&B256::from([0xCC; 32])));
    }

    #[test]
    fn test_signing_message_deterministic() {
        let sk = BlsSecretKey::key_gen(&[42u8; 32]).unwrap();
        let block_hash = B256::from([3u8; 32]);
        let rr = B256::from([0xDD; 32]);

        let receipt1 = make_receipt(block_hash, 50, rr, 12345, &sk);
        let receipt2 = make_receipt(block_hash, 50, rr, 12345, &sk);

        assert_eq!(receipt1.signing_message(), receipt2.signing_message());

        let receipt3 = make_receipt(block_hash, 51, rr, 12345, &sk);
        assert_ne!(receipt1.signing_message(), receipt3.signing_message());

        // 32 (block_hash) + 8 (block_number) + 32 (computed_receipts_root) = 72
        // timestamp_ms is excluded from signed data to enable BLS aggregation.
        assert_eq!(receipt1.signing_message().len(), 72);
    }

    #[test]
    fn test_receipt_bincode_roundtrip() {
        let sk = BlsSecretKey::key_gen(&[42u8; 32]).unwrap();
        let block_hash = B256::from([7u8; 32]);
        let receipt = make_receipt(block_hash, 500, B256::from([0xEE; 32]), 99999, &sk);

        let encoded = bincode::serialize(&receipt).expect("receipt should serialize");
        let decoded: VerificationReceipt =
            bincode::deserialize(&encoded).expect("receipt should deserialize");

        assert_eq!(decoded.block_hash, receipt.block_hash);
        assert_eq!(decoded.block_number, receipt.block_number);
        assert_eq!(
            decoded.computed_receipts_root,
            receipt.computed_receipts_root
        );
        assert_eq!(decoded.verifier_pubkey, receipt.verifier_pubkey);
        assert_eq!(decoded.timestamp_ms, receipt.timestamp_ms);
        decoded
            .verify_signature()
            .expect("deserialized receipt should have valid signature");
    }

    #[test]
    fn test_receipt_versioned_roundtrip() {
        let sk = BlsSecretKey::key_gen(&[42u8; 32]).unwrap();
        let block_hash = B256::from([8u8; 32]);
        let receipt = make_receipt(block_hash, 1000, B256::from([0xFF; 32]), 555_555, &sk);

        let encoded = encode_receipt(&receipt);
        let decoded = decode_receipt(&encoded).expect("versioned decode should succeed");

        assert_eq!(decoded.block_hash, receipt.block_hash);
        assert_eq!(decoded.block_number, receipt.block_number);
        assert_eq!(
            decoded.computed_receipts_root,
            receipt.computed_receipts_root
        );
        assert_eq!(decoded.verifier_pubkey, receipt.verifier_pubkey);
        assert_eq!(decoded.timestamp_ms, receipt.timestamp_ms);
        decoded
            .verify_signature()
            .expect("versioned receipt should have valid signature");
    }

    #[test]
    fn test_receipt_versioned_header_check() {
        let sk = BlsSecretKey::key_gen(&[42u8; 32]).unwrap();
        let receipt = make_receipt(B256::ZERO, 0, B256::ZERO, 0, &sk);
        let encoded = encode_receipt(&receipt);
        assert_eq!(encoded[0], 0x4E);
        assert_eq!(encoded[1], 0x32);
        assert_eq!(encoded[2], 0x01);
    }
}
