use secp256k1::{PublicKey, Message, Secp256k1};
use alloy_primitives::{Address, B256, Bytes as AlloyBytes, B64, BlockNumber};
use alloy_genesis::{ChainConfig, Genesis,CliqueConfig};
use secp256k1::rand::rngs::OsRng;
use reth_primitives::{Header,Block};
use std::str::FromStr;
use bytes::{BytesMut};
use sha3::{Digest, Keccak256};
use reth_provider::{
    test_utils::create_test_provider_factory_with_chain_spec,
    providers::{BlockchainProvider, StaticFileProvider}, ProviderFactory
};
use reth_blockchain_tree::noop::NoopBlockchainTree;
use std::collections::HashMap;
use std::hash::Hash;
use reth_chainspec::ChainSpec as chain_spec;
use reth_transaction_pool::test_utils::testing_pool;
use reth_evm::test_utils::MockExecutorProvider;
use reth_consensus::test_utils::TestConsensus;
use reth_db::{test_utils::{create_test_rw_db, create_test_static_files_dir}};
use reth_db_common::init::init_genesis;
use reth_network::{config::SecretKey, NetworkConfigBuilder, NetworkManager};

pub const EXTRA_VANITY: usize = 32; // Placeholder for extra vanity size
pub const DIFF_IN_TURN: B256 = B256::from(1);    // Placeholder difficulty
pub const EXTRA_SEAL: usize = 65;

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
        // let public_key = PublicKey::from_secret_key(&self.accounts[account]);
        // Initialize secp256k1 context
        let secp = Secp256k1::new();

        // Get the corresponding public key
        let secret_key = self.accounts.get(account).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, secret_key);
        Address::from_slice(&public_key.serialize()[1..21])
    }

    // Calculate a Clique digital signature for the given block and embed it into the header
    pub fn sign(&mut self, header: &mut Header, signer: &str) {
        // Ensure we have a persistent key for the signer
        let secp = Secp256k1::new();
        let secret_key = self.accounts.entry(signer.to_string())
            .or_insert_with(|| SecretKey::new(&mut OsRng));

        // Compute the seal hash
        let seal_hash = seal_hash(header);
        let message = Message::from_slice(&seal_hash).expect("32 bytes");

        // Sign the header
        let sig = secp.sign_ecdsa(&message, secret_key);

        // Serialize the signature to bytes and embed it in extra_data
        let sig_bytes = sig.serialize_compact();
        let extra_len = header.extra_data.len();

        // Ensure there's enough space for the signature in extra_data
        if extra_len < sig_bytes.len() {
            let mut extra_data_mut = BytesMut::from(&header.extra_data[..]);
            extra_data_mut.resize((extra_len + sig_bytes.len()), 0);
            header.extra_data = AlloyBytes::from(extra_data_mut.freeze());
        }

        header.extra_data[extra_len - sig_bytes.len()..].copy_from_slice(&sig_bytes);
    }


    // Creates a checkpoint from the authorized signers and embeds it in the header
    pub fn checkpoint(&mut self, header: &mut Header, signers: &[String]) {
        let mut auth_addresses: Vec<Address> = signers.iter()
            .map(|signer| self.address(signer))
            .collect();

        auth_addresses.sort_by(|a, b| a.0.cmp(&b.0));
        for (i, address) in auth_addresses.iter().enumerate() {
            header.extra_data[i * Address.len()] = address.clone().into();
        }
    }

    // // Compute the hash for the header (equivalent of Go's SealHash function)
    // fn seal_hash(&self, header: &Header) -> U256 {
    //     // Normally, SealHash would compute a keccak256 hash of the RLP-encoded
    //     // block header with some fields excluded (like extra-data signatures).
    //     // Here, we'll just hash the header's fields for simplicity.
    //     let mut hash_data = vec![];
    //     hash_data.extend_from_slice(&header.parent_hash.as_bytes());
    //     hash_data.extend_from_slice(&header.ommers_hash.as_bytes());
    //     hash_data.extend_from_slice(&header.beneficiary.as_bytes());
    //     // You can add more fields as needed.
    //     U256::from(keccak256(&hash_data))
    // }
}

fn seal_hash(header: &Header) -> [u8; 32] {
    // Normally, SealHash would compute a keccak256 hash of the RLP-encoded
    // block header with some fields excluded (like extra-data signatures).
    // Here, we'll hash the header's fields for simplicity.

    let mut hasher = Keccak256::new();
    hasher.update(header.parent_hash.as_bytes());
    hasher.update(header.ommers_hash.as_bytes());
    hasher.update(header.beneficiary.as_bytes());
    // Add more fields as needed based on your header structure.

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
