use tiny_keccak::{Keccak, Hasher};
use secp256k1::{PublicKey, Message, Secp256k1, rand::rngs::OsRng};
use alloy_primitives::{Address, Bytes, Keccak256};
use reth_primitives::Header;
use std::{str::FromStr, collections::HashMap};
use reth_network::config::SecretKey;

pub struct TesterAccountPool {
   pub accounts: HashMap<String, SecretKey>,
}

impl TesterAccountPool {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    // Returns the Ethereum address for a given signer label
     pub fn address(&mut self, account: &str) -> Address {
        if account.is_empty() {
            return Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
        }
        if !self.accounts.contains_key(account) {
            let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
            self.accounts.insert(account.to_string(), secret_key);
        }
        // Initialize secp256k1 context
        let secp = Secp256k1::new();

        // Get the corresponding public key
        let secret_key = self.accounts.get(account).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, secret_key);

    // Serialize the public key in uncompressed format (65 bytes)
    let public_key_uncompressed = public_key.serialize_uncompressed();

    // Hash the last 64 bytes of the uncompressed public key
    let mut keccak = Keccak::v256();
    keccak.update(&public_key_uncompressed[1..]); // Skip the first byte (0x04)
    let mut output = [0u8; 32];
    keccak.finalize(&mut output);

    // Take the last 20 bytes as the address
    let address = &output[12..];
    Address::from_slice(address)
    }

     pub fn secret_key(&mut self, account: &str) -> SecretKey {
        if !self.accounts.contains_key(account) {
            let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
            self.accounts.insert(account.to_string(), secret_key);
        }
        *self.accounts.get(account).unwrap()
     }

}
