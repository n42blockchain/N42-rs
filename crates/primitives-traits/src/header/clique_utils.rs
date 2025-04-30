use alloy_rlp::{length_of_length, Encodable};
use bytes::BufMut;
use secp256k1::{Message, SECP256K1, Error as SecpError, ecdsa::{RecoverableSignature, RecoveryId}, PublicKey};
use std::error::Error;
use super::{BlockHeader, Header};
use alloy_primitives::{U256, hex, Bloom, BlockNumber, keccak256, B64, B256, Address, Bytes, FixedBytes};

#[derive(Debug)]
pub enum RecoveryError {
    MissingSignature,
    InvalidMessage,
    InvalidRecoveryId,
    InvalidSignatureFormat,
    FailedToRecoverPublicKey,
    EcdsaError(SecpError),
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSignature => write!(f, "Missing signature"),
            Self::InvalidMessage => write!(f, "Invalid message"),
            Self::InvalidRecoveryId => write!(f, "Invalid recovery ID"),
            Self::InvalidSignatureFormat => write!(f, "Invalid signature format"),
            Self::FailedToRecoverPublicKey => write!(f, "Failed to recover public key"),
            Self::EcdsaError(e) => write!(f, "ECDSA error: {}", e),
        }
    }
}

impl From<SecpError> for RecoveryError {
    fn from(err: SecpError) -> Self {
        Self::EcdsaError(err)
    }
}

impl std::error::Error for RecoveryError {}
///  indicates the byte length required to carry a signature with recovery id.
///  Fixed number of extra-data suffix bytes reserved for signer seal
pub const SIGNATURE_LENGTH: usize = 64 + 1;

// recover_address extracts the Ethereum account address from a signed header.
pub fn recover_address(header: &Header) -> Result<Address, Box<dyn Error>> {
    // Retrieve the signature from the header extra-data
    if header.extra_data.len() < SIGNATURE_LENGTH {
        return Err(Box::new(RecoveryError::MissingSignature));
    }
    let signature = &header.extra_data[header.extra_data.len() - SIGNATURE_LENGTH..];

    // Recover the public key and the Ethereum address
    let message = Message::from_digest(seal_hash(header).into());

    let signature = RecoverableSignature::from_compact(
        &signature[..64],
        RecoveryId::from_i32(i32::from(signature[64]))?,
    )?;

    Ok(public_key_to_address(SECP256K1.recover_ecdsa(&message, &signature)?))
}

// SealHash returns the hash of a block prior to it being sealed.
pub fn seal_hash(header: &Header) -> B256 {

    struct LocalHeader {
        parent_hash: B256,
        ommers_hash: B256,
        beneficiary: Address,
        state_root: B256,
        transactions_root: B256,
        receipts_root: B256,
        logs_bloom: Bloom,
        difficulty: U256,
        number: BlockNumber,
        gas_limit: u64,
        gas_used: u64,
        timestamp: u64,
        extra_data: Bytes,
        mix_hash: B256,
        nonce: u64,
        base_fee_per_gas: Option<u64>,
    }

    impl LocalHeader {
        fn header_payload_length(&self) -> usize {
            let mut length = 0;
            length += self.parent_hash.length(); // Hash of the previous block.
            length += self.ommers_hash.length(); // Hash of uncle blocks.
            length += self.beneficiary.length(); // Address that receives rewards.
            length += self.state_root.length(); // Root hash of the state object.
            length += self.transactions_root.length(); // Root hash of transactions in the block.
            length += self.receipts_root.length(); // Hash of transaction receipts.
            length += self.logs_bloom.length(); // Data structure containing event logs.
            length += self.difficulty.length(); // Difficulty value of the block.
            length += U256::from(self.number).length(); // Block number.
            length += U256::from(self.gas_limit).length(); // Maximum gas allowed.
            length += U256::from(self.gas_used).length(); // Actual gas used.
            length += self.timestamp.length(); // Block timestamp.
            length += self.extra_data.length(); // Additional arbitrary data.
            length += self.mix_hash.length(); // Hash used for mining.
            length += B64::new(self.nonce.to_be_bytes()).length(); // Nonce for mining.

            if let Some(base_fee) = self.base_fee_per_gas {
                // Adding base fee length if it exists.
                length += U256::from(base_fee).length();
            }
            length
        }
    }


    impl Encodable for LocalHeader {
        fn encode(&self, out: &mut dyn BufMut) {
            // Create a header indicating the encoded content is a list with the payload length computed
            // from the header's payload calculation function.
            let list_header =
                alloy_rlp::Header { list: true, payload_length: self.header_payload_length() };
            list_header.encode(out);

            // Encode each header field sequentially
            self.parent_hash.encode(out); // Encode parent hash.
            self.ommers_hash.encode(out); // Encode ommer's hash.
            self.beneficiary.encode(out); // Encode beneficiary.
            self.state_root.encode(out); // Encode state root.
            self.transactions_root.encode(out); // Encode transactions root.
            self.receipts_root.encode(out); // Encode receipts root.
            self.logs_bloom.encode(out); // Encode logs bloom.
            self.difficulty.encode(out); // Encode difficulty.
            U256::from(self.number).encode(out); // Encode block number.
            U256::from(self.gas_limit).encode(out); // Encode gas limit.
            U256::from(self.gas_used).encode(out); // Encode gas used.
            self.timestamp.encode(out); // Encode timestamp.
            self.extra_data.encode(out); // Encode extra data.
            self.mix_hash.encode(out); // Encode mix hash.
            B64::new(self.nonce.to_be_bytes()).encode(out); // Encode nonce.

            // Encode base fee.
            if let Some(ref base_fee) = self.base_fee_per_gas {
                U256::from(*base_fee).encode(out);
            }
        }

        fn length(&self) -> usize {
            let mut length = 0;
            length += self.header_payload_length();
            length += length_of_length(length);
            length
        }
    }

    // 初始化局部结构体
    let mut sig_header = LocalHeader {
        parent_hash: header.parent_hash,
        ommers_hash: header.ommers_hash,
        beneficiary: header.beneficiary,
        state_root: header.state_root,
        transactions_root: header.transactions_root,
        receipts_root: header.receipts_root,
        logs_bloom: header.logs_bloom,
        difficulty: header.difficulty,
        number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: Bytes::new(),
        mix_hash: header.mix_hash,
        nonce: u64::from(header.nonce),
        base_fee_per_gas: header.base_fee_per_gas,
    };

    // Handle the extra field, excluding the last CRYPTO_SIGNATURE_LENGTH bytes
    if header.extra_data.len() > SIGNATURE_LENGTH {
        sig_header.extra_data = Bytes::from(header.extra_data[..header.extra_data.len() - SIGNATURE_LENGTH].to_vec());
    }

    keccak256(alloy_rlp::encode(&sig_header))
}

// Copied from crates/primitives/src/transaction/util.rs
// reth-primitives crate can not be used here because of cyclic dependency
pub fn public_key_to_address(public: PublicKey) -> Address {
    // strip out the first byte because that should be the SECP256K1_TAG_PUBKEY_UNCOMPRESSED
    // tag returned by libsecp's uncompressed pubkey serialization
    let hash = keccak256(&public.serialize_uncompressed()[1..]);
    Address::from_slice(&hash[12..])
}
