use ethers::{
    prelude::*,
};
use alloy_primitives::Address;
use hex::FromHex;
use n42_primitives::{DepositData, DEPOSIT_AMOUNT};
use ssz_derive::{Decode, Encode};
use tree_hash::Hash256;
use tree_hash_derive::TreeHash;
use tree_hash::TreeHash;
use alloy_primitives::{B256, FixedBytes};
use serde::{Deserialize, Serialize};
//use n42_withdrawals::chain_spec::ChainSpec;
use blst::min_pk::SecretKey;
use ethers::abi::Token;
//use ethers::types::{Address, TransactionRequest, U256, NameOrAddress};
use ethers::types::{TransactionRequest, U256, NameOrAddress};
use ethers::utils::keccak256;
use ethers::utils::WEI_IN_ETHER;
use tracing::debug;

pub const DEVNET_DEPOSIT_CONTRACT_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

pub const EIP7002_CONTRACT_ADDRESS: &str = "0x00000961Ef480Eb55e80D19ad83579A64c007002";

pub fn create_deposit_unsigned_tx(
    deposit_contract_address: String,
    validator_private_key: String,
    withdrawal_address: String,
    deposit_value_in_wei: U256,
    ) -> eyre::Result<TransactionRequest> {

    let addr_hex = withdrawal_address
        .strip_prefix("0x")
        .unwrap_or(&withdrawal_address);
    let addr_bytes = hex::decode(addr_hex)
        .map_err(|e| eyre::eyre!("invalid withdrawal_address: {}", e))?;
    if addr_bytes.len() != 20 {
        return Err(eyre::eyre!("withdrawal_address is 20 bytes，but got {} bytes", addr_bytes.len()).into());
    }
    let addr = Address::from_slice(&addr_bytes);

    let creds = withdrawal_credentials(addr);
    debug!("withdrawal_credentials: 0x{}", hex::encode(&creds));

    let sk = SecretKey::from_bytes(&Vec::from_hex(&validator_private_key).unwrap()).unwrap();
    let pk = sk.sk_to_pk();

    let pubkey = pk;
    debug!("pubkey: {:?}", hex::encode(pubkey.to_bytes()));

    let mut deposit_data = DepositData {
        //pubkey: PublicKeyBytes::deserialize(&pubkey.to_bytes()).unwrap(),
        pubkey: alloy_primitives::FixedBytes(pubkey.to_bytes()),
        withdrawal_credentials: creds,
        //signature: SignatureBytes::empty(),
        signature: Default::default(),
        amount: (deposit_value_in_wei / U256::exp10(9)).as_u64(),
    };
    //let spec = ChainSpec::n42();
    //deposit_data.signature = deposit_data.create_signature(&GenericSecretKey::deserialize(&sk.serialize()).unwrap(),
    deposit_data.signature = deposit_data.create_signature(&sk,
   // &spec
    );

    debug!("signed deposit: {:#?}", deposit_data);
    let root = deposit_data.tree_hash_root();
    debug!("deposit_data_root: {}", root);

    // 1. Compute function selector
    let selector = &keccak256("deposit(bytes,bytes,bytes,bytes32)".as_bytes())[0..4];
    // 2. Encode the function parameters
    let encoded_args = ethers::abi::encode(&[
        Token::Bytes(pubkey.to_bytes().to_vec()),
        Token::Bytes(deposit_data.withdrawal_credentials.to_vec()),
        Token::Bytes(deposit_data.signature.to_vec()),
        Token::FixedBytes(root.to_vec()),
    ]);

    // 3. Build calldata = selector + params
    let mut calldata = selector.to_vec();
    calldata.extend(encoded_args);

    // 4. Build an unsigned transaction with ETH value transfer
    let contract_address: ethers::types::Address =
deposit_contract_address
        .parse()
        .unwrap();

    debug!("deposit_value_in_wei: {deposit_value_in_wei:?}");
    let tx = TransactionRequest {
        to: Some(NameOrAddress::Address(contract_address)),
        data: Some(calldata.into()),
        value: Some(deposit_value_in_wei),
        ..Default::default()
    };

    debug!("deposit Unsigned tx: {:?}", tx);

    Ok(tx)
}

pub fn withdrawal_credentials(withdrawal_address: alloy_primitives::Address) -> B256 {
    let mut credentials = [0u8; 32];
    credentials[0] = 0x01;
    credentials[12..].copy_from_slice(withdrawal_address.as_slice());
    B256::from(credentials)
}

pub fn create_get_exit_fee_unsigned_tx() -> eyre::Result<TransactionRequest> {
    let contract_address: ethers::types::Address = EIP7002_CONTRACT_ADDRESS
        .parse()
        .unwrap();
    let tx = TransactionRequest {
        to: Some(NameOrAddress::Address(contract_address)),
        data: Some(Bytes::new()),
        ..Default::default()
    };

    debug!("get_exit_fee Unsigned tx: {:?}", tx);

    Ok(tx)
}

pub fn create_exit_unsigned_tx(
        validator_public_key: String,
        fee: Option<U256>,
    ) -> eyre::Result<TransactionRequest> {
    let contract_address: ethers::types::Address = EIP7002_CONTRACT_ADDRESS
        .parse()
        .unwrap();
    let pubkey_bytes = hex::decode(validator_public_key)?;

    let mut data = Vec::with_capacity(56);
    data.extend_from_slice(&pubkey_bytes);
    data.extend_from_slice(&u64::min_value().to_be_bytes());

    let tx = TransactionRequest {
        to: Some(contract_address.into()),
        data: Some(Bytes::from(data)),
        value: Some(fee.unwrap_or(U256::from(1u64))),
        ..Default::default()
    };

    debug!("exit Unsigned tx: {:?}", tx);

    Ok(tx)
}
