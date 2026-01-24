// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use blst::min_pk::SecretKey;
use rand::RngCore;

/// Generate a new BLS12-381 keypair.
///
/// Returns a tuple of (private_key_hex, public_key_hex).
pub fn generate_bls12_381_keypair() -> eyre::Result<(String, String)> {
    let mut rng = rand::rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let sk = SecretKey::key_gen(&ikm, &[])
        .map_err(|e| eyre::eyre!("SecretKey::key_gen() error {e:?}"))?;

    // Securely clear the input key material
    ikm.fill(0);

    let pk = sk.sk_to_pk();

    let privkey_hex = hex::encode(sk.to_bytes());
    let pubkey_hex = hex::encode(pk.to_bytes());

    Ok((privkey_hex, pubkey_hex))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn test_generate_bls12_381_keypair_ok() {
        let result = generate_bls12_381_keypair();
        assert!(result.is_ok());
        let (privkey_hex, pubkey_hex) = result.unwrap();

        let result = Vec::from_hex(privkey_hex);
        assert!(result.is_ok());

        let result = SecretKey::from_bytes(&result.unwrap());
        assert!(result.is_ok());
        let sk = result.unwrap();

        let pk = sk.sk_to_pk();
        let result = hex::encode(pk.to_bytes());
        assert_eq!(result, pubkey_hex);
    }
}
