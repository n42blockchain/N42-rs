// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for clique_utils module - signature recovery and seal hash computation

use super::clique_utils::{
    public_key_to_address, recover_address, recover_address_generic, seal_hash, seal_hash_generic,
    RecoveryError, SIGNATURE_LENGTH,
};
use super::Header;
use alloy_primitives::{keccak256, Address, Bloom, Bytes, B256, B64, U256};
use secp256k1::{ecdsa::RecoveryId, Message, PublicKey, SecretKey, SECP256K1};

/// Create a test header with default values
fn create_test_header() -> Header {
    Header {
        parent_hash: B256::ZERO,
        ommers_hash: B256::ZERO,
        beneficiary: Address::ZERO,
        state_root: B256::ZERO,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Bloom::ZERO,
        difficulty: U256::ZERO,
        number: 1,
        gas_limit: 8_000_000,
        gas_used: 21000,
        timestamp: 1600000000,
        extra_data: Bytes::new(),
        mix_hash: B256::ZERO,
        nonce: B64::ZERO,
        base_fee_per_gas: Some(1000000000),
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
        requests_hash: None,
    }
}

/// Sign a header with given secret key
fn sign_header(header: &mut Header, secret_key: &SecretKey) {
    // Set initial vanity (32 bytes) + placeholder for signature
    header.extra_data = Bytes::from(vec![0u8; 32 + SIGNATURE_LENGTH]);

    // Compute seal hash (which excludes the signature portion)
    let hash = seal_hash(header);

    // Create message and sign
    let message = Message::from_digest(hash.into());
    let (recovery_id, sig) = SECP256K1
        .sign_ecdsa_recoverable(&message, secret_key)
        .serialize_compact();

    // Build extra_data: 32 bytes vanity + signature (64 + 1)
    let mut extra_data = vec![0u8; 32]; // 32 byte vanity
    extra_data.extend_from_slice(&sig);
    extra_data.push(i32::from(recovery_id) as u8);

    header.extra_data = Bytes::from(extra_data);
}

#[test]
fn test_signature_length_constant() {
    assert_eq!(SIGNATURE_LENGTH, 65, "Signature length should be 64 + 1");
}

#[test]
fn test_recovery_error_display() {
    assert_eq!(
        format!("{}", RecoveryError::MissingSignature),
        "Missing signature"
    );
    assert_eq!(
        format!("{}", RecoveryError::InvalidMessage),
        "Invalid message"
    );
    assert_eq!(
        format!("{}", RecoveryError::InvalidRecoveryId),
        "Invalid recovery ID"
    );
    assert_eq!(
        format!("{}", RecoveryError::InvalidSignatureFormat),
        "Invalid signature format"
    );
    assert_eq!(
        format!("{}", RecoveryError::FailedToRecoverPublicKey),
        "Failed to recover public key"
    );
}

#[test]
fn test_seal_hash_deterministic() {
    let header = create_test_header();
    let hash1 = seal_hash(&header);
    let hash2 = seal_hash(&header);
    assert_eq!(hash1, hash2, "seal_hash should be deterministic");
}

#[test]
fn test_seal_hash_changes_with_header_fields() {
    let header1 = create_test_header();
    let mut header2 = create_test_header();
    header2.number = 2;

    let hash1 = seal_hash(&header1);
    let hash2 = seal_hash(&header2);

    assert_ne!(
        hash1, hash2,
        "Different block numbers should produce different hashes"
    );
}

#[test]
fn test_seal_hash_excludes_signature() {
    let mut header = create_test_header();

    // Set extra_data with vanity + signature placeholder
    let mut extra_with_sig1 = vec![0u8; 32];
    extra_with_sig1.extend_from_slice(&[0xaa; SIGNATURE_LENGTH]);
    header.extra_data = Bytes::from(extra_with_sig1);
    let hash1 = seal_hash(&header);

    // Change the signature portion
    let mut extra_with_sig2 = vec![0u8; 32];
    extra_with_sig2.extend_from_slice(&[0xbb; SIGNATURE_LENGTH]);
    header.extra_data = Bytes::from(extra_with_sig2);
    let hash2 = seal_hash(&header);

    assert_eq!(
        hash1, hash2,
        "Seal hash should exclude signature from extra_data"
    );
}

#[test]
fn test_recover_address_missing_signature() {
    let header = create_test_header();
    let result = recover_address(&header);
    assert!(result.is_err(), "Should fail with missing signature");
}

#[test]
fn test_recover_address_short_extra_data() {
    let mut header = create_test_header();
    header.extra_data = Bytes::from(vec![0u8; SIGNATURE_LENGTH - 1]);

    let result = recover_address(&header);
    assert!(result.is_err(), "Should fail with short extra_data");
}

#[test]
fn test_sign_and_recover_address() {
    let secret_key = SecretKey::from_slice(&[0x01; 32]).expect("valid key");
    let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);
    let expected_address = public_key_to_address(public_key);

    let mut header = create_test_header();
    sign_header(&mut header, &secret_key);

    let recovered = recover_address(&header).expect("should recover address");
    assert_eq!(
        recovered, expected_address,
        "Recovered address should match signer"
    );
}

#[test]
fn test_recover_address_generic_consistency() {
    let secret_key = SecretKey::from_slice(&[0x02; 32]).expect("valid key");

    let mut header = create_test_header();
    sign_header(&mut header, &secret_key);

    let addr1 = recover_address(&header).expect("should recover");
    let addr2 = recover_address_generic(&header).expect("should recover generic");

    assert_eq!(addr1, addr2, "Both functions should return same address");
}

#[test]
fn test_seal_hash_generic_consistency() {
    let header = create_test_header();

    let hash1 = seal_hash(&header);
    let hash2 = seal_hash_generic(&header);

    assert_eq!(
        hash1, hash2,
        "seal_hash and seal_hash_generic should produce same result"
    );
}

#[test]
fn test_public_key_to_address() {
    // Use a known test vector
    let secret_key = SecretKey::from_slice(&[
        0xac, 0x03, 0x74, 0x67, 0x3e, 0xe4, 0x13, 0x56, 0x1f, 0x8e, 0xf5, 0x7d, 0x87, 0x8a, 0x4b,
        0x5d, 0x71, 0x82, 0x25, 0x2d, 0x86, 0x67, 0x77, 0x90, 0x5e, 0x1d, 0x8d, 0x15, 0x4a, 0x19,
        0x8f, 0x3c,
    ])
    .expect("valid key");

    let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);
    let address = public_key_to_address(public_key);

    // Address should be 20 bytes
    assert_eq!(address.len(), 20);

    // Address should be derived from last 20 bytes of keccak256(public_key_uncompressed[1..])
    let pubkey_bytes = public_key.serialize_uncompressed();
    let hash = keccak256(&pubkey_bytes[1..]);
    let expected_address = Address::from_slice(&hash[12..]);

    assert_eq!(address, expected_address);
}

#[test]
fn test_seal_hash_with_base_fee() {
    let mut header1 = create_test_header();
    header1.base_fee_per_gas = Some(1000000000);

    let mut header2 = create_test_header();
    header2.base_fee_per_gas = Some(2000000000);

    let hash1 = seal_hash(&header1);
    let hash2 = seal_hash(&header2);

    assert_ne!(
        hash1, hash2,
        "Different base fees should produce different hashes"
    );
}

#[test]
fn test_seal_hash_without_base_fee() {
    let mut header1 = create_test_header();
    header1.base_fee_per_gas = None;

    let mut header2 = create_test_header();
    header2.base_fee_per_gas = Some(1000000000);

    let hash1 = seal_hash(&header1);
    let hash2 = seal_hash(&header2);

    assert_ne!(
        hash1, hash2,
        "With/without base fee should produce different hashes"
    );
}

#[test]
fn test_multiple_signers() {
    let keys: Vec<SecretKey> = (1..=5u8)
        .map(|i| SecretKey::from_slice(&[i; 32]).expect("valid key"))
        .collect();

    for key in &keys {
        let public_key = PublicKey::from_secret_key(SECP256K1, key);
        let expected_address = public_key_to_address(public_key);

        let mut header = create_test_header();
        sign_header(&mut header, key);

        let recovered = recover_address(&header).expect("should recover");
        assert_eq!(recovered, expected_address);
    }
}

#[test]
fn test_header_with_various_extra_data_lengths() {
    let secret_key = SecretKey::from_slice(&[0x03; 32]).expect("valid key");

    // Test with different vanity lengths (before signature)
    for vanity_len in [32, 64, 128] {
        let mut header = create_test_header();

        // Compute seal hash before signing
        let hash = seal_hash(&header);
        let message = Message::from_digest(hash.into());
        let (recovery_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(&message, &secret_key)
            .serialize_compact();

        // Build extra_data with varying vanity length
        let mut extra_data = vec![0u8; vanity_len];
        extra_data.extend_from_slice(&sig);
        extra_data.push(i32::from(recovery_id) as u8);
        header.extra_data = Bytes::from(extra_data);

        let result = recover_address(&header);
        assert!(
            result.is_ok(),
            "Should recover address with vanity_len={}",
            vanity_len
        );
    }
}

#[test]
fn test_invalid_recovery_id() {
    let mut header = create_test_header();

    // Build extra_data with invalid recovery id (> 3)
    let mut extra_data = vec![0u8; 32]; // vanity
    extra_data.extend_from_slice(&[0x00; 64]); // fake signature
    extra_data.push(255); // invalid recovery id

    header.extra_data = Bytes::from(extra_data);

    let result = recover_address(&header);
    assert!(result.is_err(), "Should fail with invalid recovery id");
}
