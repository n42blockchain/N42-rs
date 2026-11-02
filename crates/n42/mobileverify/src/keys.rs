// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A device's BLS key, derived the way gov5's SDK derives it
//! (`cmd/evmsdk/blst.go:22-33`): the stored secret is a 32-byte input keying
//! material fed to blst `KeyGen(ikm)` with empty info, not a raw scalar.

use n42_h2_primitives::bls::{BlsError, BlsSecretKey};

use crate::bls::{DST, PUBKEY_LEN, SIGNATURE_LEN};
use crate::pop::pop_message;
use crate::receipt::signing_message;
use alloy_primitives::B256;

/// A mobile verifier's signing key.
#[derive(Debug, Clone)]
pub struct DeviceKey {
    sk: BlsSecretKey,
    pubkey: [u8; PUBKEY_LEN],
}

impl DeviceKey {
    /// Derives the key from a 32-byte IKM (blst `KeyGen(ikm, info = "")`).
    pub fn from_ikm(ikm: &[u8; 32]) -> Result<Self, BlsError> {
        let sk = BlsSecretKey::key_gen(ikm)?;
        let pubkey = sk.public_key().to_bytes();
        Ok(Self { sk, pubkey })
    }

    /// The 32-byte big-endian secret scalar blst `KeyGen` derived.
    pub fn secret_scalar(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }

    /// The compressed G1 public key.
    pub const fn pubkey(&self) -> [u8; PUBKEY_LEN] {
        self.pubkey
    }

    /// gov5's `AddrHex`: the first 20 bytes of the public key.
    pub fn address(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        out.copy_from_slice(&self.pubkey[..20]);
        out
    }

    /// Signs `msg` under the proof-of-possession DST.
    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.sk.sign_with_dst(msg, DST).to_bytes()
    }

    /// The registration proof of possession: a signature over
    /// [`pop_message`] of this key.
    pub fn proof_of_possession(&self) -> [u8; SIGNATURE_LEN] {
        self.sign(&pop_message(&self.pubkey))
    }

    /// Signs the 72-byte receipt message for `(block_hash, number, root)`.
    pub fn sign_receipt(&self, block_hash: B256, number: u64, receipts_root: B256) -> [u8; SIGNATURE_LEN] {
        self.sign(&signing_message(block_hash, number, receipts_root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::{decode_pubkey, decode_signature, verify};

    #[test]
    fn signs_under_the_pop_dst() {
        let key = DeviceKey::from_ikm(&[7u8; 32]).unwrap();
        let pk = decode_pubkey(&key.pubkey()).unwrap();
        let sig = decode_signature(&key.proof_of_possession()).unwrap();
        assert!(verify(&sig, &pk, &pop_message(&key.pubkey())));
        assert!(!verify(&sig, &pk, b"other"));
        assert_eq!(key.address(), key.pubkey()[..20]);
    }
}
