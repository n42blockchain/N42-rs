use ethers::{
    prelude::*,
};
use alloy_primitives::Address;
use hex::FromHex;
use n42_primitives::{DepositData};
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

pub use reth_chainspec::{
    DEVNET_DEPOSIT_CONTRACT_ADDRESS,
    TESTNET_DEPOSIT_CONTRACT_ADDRESS,
};

pub const EIP7002_CONTRACT_ADDRESS: &str = "0x00000961Ef480Eb55e80D19ad83579A64c007002";

pub fn create_deposit_unsigned_tx(
    deposit_contract_address: &str,
    validator_private_key: &str,
    withdrawal_address: &str,
    deposit_value_in_wei: &U256,
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

    let creds = withdrawal_credentials(&addr);
    debug!("withdrawal_credentials: 0x{}", hex::encode(&creds));

    let validator_private_key = validator_private_key.strip_prefix("0x").unwrap_or(&validator_private_key);
    let sk = SecretKey::from_bytes(&Vec::from_hex(validator_private_key)?)
            .map_err(|e| eyre::eyre!("SecretKey::from_bytes() error {e:?}"))?;
    let pk = sk.sk_to_pk();

    let pubkey = pk;
    debug!("pubkey: {:?}", hex::encode(pubkey.to_bytes()));

    let mut deposit_data = DepositData {
        pubkey: alloy_primitives::FixedBytes(pubkey.to_bytes()),
        withdrawal_credentials: creds,
        //signature: SignatureBytes::empty(),
        signature: Default::default(),
        amount: (deposit_value_in_wei / U256::exp10(9)).as_u64(),
    };
    //let spec = ChainSpec::n42();
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
        .parse()?;

    debug!("deposit_value_in_wei: {deposit_value_in_wei:?}");
    let tx = TransactionRequest {
        to: Some(NameOrAddress::Address(contract_address)),
        data: Some(calldata.into()),
        value: Some(deposit_value_in_wei.clone()),
        ..Default::default()
    };

    debug!("deposit Unsigned tx: {:?}", tx);

    Ok(tx)
}

fn withdrawal_credentials(withdrawal_address: &alloy_primitives::Address) -> B256 {
    let mut credentials = [0u8; 32];
    credentials[0] = 0x01;
    credentials[12..].copy_from_slice(withdrawal_address.as_slice());
    B256::from(credentials)
}

pub fn create_get_exit_fee_unsigned_tx() -> eyre::Result<TransactionRequest> {
    let contract_address: ethers::types::Address = EIP7002_CONTRACT_ADDRESS
        .parse()?;
    let tx = TransactionRequest {
        to: Some(NameOrAddress::Address(contract_address)),
        data: Some(Bytes::new()),
        ..Default::default()
    };

    debug!("get_exit_fee Unsigned tx: {:?}", tx);

    Ok(tx)
}

pub fn create_exit_unsigned_tx(
        validator_public_key: &str,
        fee: &Option<U256>,
    ) -> eyre::Result<TransactionRequest> {
    let contract_address: ethers::types::Address = EIP7002_CONTRACT_ADDRESS
        .parse()?;

    let pubkey_hex = validator_public_key
        .strip_prefix("0x")
        .unwrap_or(&validator_public_key);
    let pubkey_bytes = hex::decode(pubkey_hex)
        .map_err(|e| eyre::eyre!("invalid validator_public_key: {}", e))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_deposit_unsigned_tx_0x_prefix_hex_inputs_ok() {
        let deposit_contract_address = DEVNET_DEPOSIT_CONTRACT_ADDRESS.to_string();
        let validator_private_key = "0x6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec";
        let withdrawal_address = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720";
        let deposit_value_in_wei: U256 = "0x1bc16d674ec800000".parse::<U256>().unwrap();
        let result = create_deposit_unsigned_tx(
            &deposit_contract_address,
            validator_private_key,
            withdrawal_address,
            &deposit_value_in_wei,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_exit_unsigned_tx_0x_prefix_hex_inputs_ok() {
        let validator_public_key = "0x8a2470d8ccb2e43b3b5295cfee71508f8808e166e5f152d5af9fe022d95e300dc7c5814f2c9eb71e2da8412beb61c53a";
        let exit_fee_in_wei: U256 = "0x1".parse::<U256>().unwrap();
        let result = create_exit_unsigned_tx(
            validator_public_key,
            &Some(exit_fee_in_wei),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_deposit_unsigned_tx_no_0x_prefix_hex_inputs_ok() {
        let deposit_contract_address = "5FbDB2315678afecb367f032d93F642f64180aa3";
        let validator_private_key = "6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec";
        let withdrawal_address = "a0Ee7A142d267C1f36714E4a8F75612F20a79720";
        let deposit_value_in_wei: U256 = "1bc16d674ec800000".parse::<U256>().unwrap();
        let result = create_deposit_unsigned_tx(
            deposit_contract_address,
            validator_private_key,
            withdrawal_address,
            &deposit_value_in_wei,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_exit_unsigned_tx_no_0x_prefix_hex_inputs_ok() {
        let validator_public_key = "8a2470d8ccb2e43b3b5295cfee71508f8808e166e5f152d5af9fe022d95e300dc7c5814f2c9eb71e2da8412beb61c53a";
        let exit_fee_in_wei: U256 = "1".parse::<U256>().unwrap();
        let result = create_exit_unsigned_tx(
            validator_public_key,
            &Some(exit_fee_in_wei),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_deposit_invalid_inputs_no_panic() {
        let result = create_deposit_unsigned_tx(
            "x",
            Default::default(),
            Default::default(),
            &Default::default(),
        );
        assert!(result.is_err());

        let result = create_deposit_unsigned_tx(
            Default::default(),
            "x",
            Default::default(),
            &Default::default(),
        );

        assert!(result.is_err());
        let result = create_deposit_unsigned_tx(
            Default::default(),
            Default::default(),
            "x",
            &Default::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_exit_unsigned_tx_invalid_inputs_no_panic() {
        let result = create_exit_unsigned_tx(
            "x",
            &Default::default(),
        );
        assert!(result.is_err());
    }

}
