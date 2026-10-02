// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::{Address, B256};
use blst::min_pk::SecretKey;
use ethers::abi::Token;
use ethers::prelude::*;
use ethers::types::{NameOrAddress, TransactionRequest, U256};
use ethers::utils::keccak256;
use hex::FromHex;
use n42_primitives::DepositData;
use tracing::debug;
use tree_hash::TreeHash;

pub use reth_chainspec::{DEVNET_DEPOSIT_CONTRACT_ADDRESS, TESTNET_DEPOSIT_CONTRACT_ADDRESS};

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
    let addr_bytes =
        hex::decode(addr_hex).map_err(|e| eyre::eyre!("invalid withdrawal_address: {}", e))?;
    if addr_bytes.len() != 20 {
        return Err(eyre::eyre!(
            "withdrawal_address is 20 bytes, but got {} bytes",
            addr_bytes.len()
        ));
    }
    let addr = Address::from_slice(&addr_bytes);

    let creds = withdrawal_credentials(&addr);
    debug!("withdrawal_credentials: 0x{}", hex::encode(&creds));

    let validator_private_key = validator_private_key
        .strip_prefix("0x")
        .unwrap_or(&validator_private_key);
    let sk = SecretKey::from_bytes(&Vec::from_hex(validator_private_key)?)
        .map_err(|e| eyre::eyre!("SecretKey::from_bytes() error {e:?}"))?;
    let pk = sk.sk_to_pk();
    debug!("pubkey: {:?}", hex::encode(pk.to_bytes()));

    let amount_in_gwei = deposit_value_in_wei / U256::exp10(9);
    if amount_in_gwei > U256::from(u64::MAX) {
        return Err(eyre::eyre!("deposit amount too large to fit in u64"));
    }

    let mut deposit_data = DepositData {
        pubkey: alloy_primitives::FixedBytes(pk.to_bytes()),
        withdrawal_credentials: creds,
        signature: Default::default(),
        amount: amount_in_gwei.as_u64(),
    };
    //let spec = ChainSpec::n42();
    deposit_data.signature = deposit_data.create_signature(
        &sk,
        // &spec
    );

    debug!("signed deposit: {:#?}", deposit_data);
    let root = deposit_data.tree_hash_root();
    debug!("deposit_data_root: {}", root);

    // 1. Compute function selector
    let selector = &keccak256("deposit(bytes,bytes,bytes,bytes32)".as_bytes())[0..4];
    // 2. Encode the function parameters
    let encoded_args = ethers::abi::encode(&[
        Token::Bytes(pk.to_bytes().to_vec()),
        Token::Bytes(deposit_data.withdrawal_credentials.to_vec()),
        Token::Bytes(deposit_data.signature.to_vec()),
        Token::FixedBytes(root.to_vec()),
    ]);

    // 3. Build calldata = selector + params
    let mut calldata = selector.to_vec();
    calldata.extend(encoded_args);

    // 4. Build an unsigned transaction with ETH value transfer
    let contract_address: ethers::types::Address = deposit_contract_address.parse()?;

    debug!("deposit_value_in_wei: {deposit_value_in_wei:?}");
    let tx = TransactionRequest {
        to: Some(NameOrAddress::Address(contract_address)),
        data: Some(calldata.into()),
        value: Some(deposit_value_in_wei.clone()),
        // Use a safe fixed gas value for validator deposit tx;
        // this works for validator numbers up to at least 1M+ validators(ethereum mainnet)
        gas: Some(300_000u64.into()),
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
    let contract_address: ethers::types::Address = EIP7002_CONTRACT_ADDRESS.parse()?;
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
    let contract_address: ethers::types::Address = EIP7002_CONTRACT_ADDRESS.parse()?;

    let pubkey_hex = validator_public_key
        .strip_prefix("0x")
        .unwrap_or(validator_public_key);
    let pubkey_bytes =
        hex::decode(pubkey_hex).map_err(|e| eyre::eyre!("invalid validator_public_key: {}", e))?;

    // BLS12-381 public key must be exactly 48 bytes
    if pubkey_bytes.len() != 48 {
        return Err(eyre::eyre!(
            "validator_public_key must be 48 bytes, but got {} bytes",
            pubkey_bytes.len()
        ));
    }

    let mut data = Vec::with_capacity(56);
    data.extend_from_slice(&pubkey_bytes);
    data.extend_from_slice(&u64::MIN.to_be_bytes());

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
        let validator_private_key =
            "0x6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec";
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
        let result = create_exit_unsigned_tx(validator_public_key, &Some(exit_fee_in_wei));
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_deposit_unsigned_tx_no_0x_prefix_hex_inputs_ok() {
        let deposit_contract_address = "5FbDB2315678afecb367f032d93F642f64180aa3";
        let validator_private_key =
            "6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec";
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
        let result = create_exit_unsigned_tx(validator_public_key, &Some(exit_fee_in_wei));
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
        let result = create_exit_unsigned_tx("x", &Default::default());
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    const SK: &str = "6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec";
    const WITHDRAWAL: &str = "a0Ee7A142d267C1f36714E4a8F75612F20a79720";
    const CONTRACT: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

    fn calldata(tx: &TransactionRequest) -> Vec<u8> {
        tx.data.clone().expect("calldata").to_vec()
    }

    #[test]
    fn the_deposit_calldata_is_selector_then_four_abi_arguments_for_this_key() {
        let value: U256 = "0x1bc16d674ec800000".parse().unwrap();
        let tx = create_deposit_unsigned_tx(CONTRACT, SK, WITHDRAWAL, &value).unwrap();
        let data = calldata(&tx);
        let selector = &keccak256(b"deposit(bytes,bytes,bytes,bytes32)")[..4];
        assert_eq!(&data[..4], selector);

        let tokens = ethers::abi::decode(
            &[
                ethers::abi::ParamType::Bytes,
                ethers::abi::ParamType::Bytes,
                ethers::abi::ParamType::Bytes,
                ethers::abi::ParamType::FixedBytes(32),
            ],
            &data[4..],
        )
        .expect("well-formed ABI arguments");
        let pk = blst::min_pk::SecretKey::from_bytes(&hex::decode(SK).unwrap()).unwrap().sk_to_pk();
        assert_eq!(tokens[0].clone().into_bytes().unwrap(), pk.to_bytes().to_vec());

        // 0x01 prefix, eleven zero bytes, then the withdrawal address.
        let creds = tokens[1].clone().into_bytes().unwrap();
        assert_eq!(creds.len(), 32);
        assert_eq!(creds[0], 0x01);
        assert!(creds[1..12].iter().all(|b| *b == 0));
        assert_eq!(hex::encode(&creds[12..]), WITHDRAWAL.to_lowercase());

        let signature = tokens[2].clone().into_bytes().unwrap();
        assert_eq!(signature.len(), 96, "a BLS12-381 G2 signature");

        // The root is the SSZ root of the signed deposit data, recomputable here.
        let data_root = tokens[3].clone().into_fixed_bytes().unwrap();
        let mut deposit = DepositData {
            pubkey: alloy_primitives::FixedBytes(pk.to_bytes()),
            withdrawal_credentials: B256::from_slice(&creds),
            signature: Default::default(),
            amount: 32_000_000_000,
        };
        deposit.signature = alloy_primitives::FixedBytes::from_slice(&signature);
        assert_eq!(data_root, deposit.tree_hash_root().to_vec());

        assert_eq!(tx.value, Some(value));
        assert_eq!(tx.gas, Some(300_000u64.into()));
        let to = tx.to.expect("a recipient");
        assert_eq!(to, NameOrAddress::Address(CONTRACT.parse().unwrap()));
    }

    #[test]
    fn the_deposit_amount_in_the_data_is_the_value_in_gwei() {
        // 1 ETH and 2 ETH must give different roots (the amount is signed), and
        // the same inputs the same root (signing is deterministic).
        let one = create_deposit_unsigned_tx(CONTRACT, SK, WITHDRAWAL, &U256::exp10(18)).unwrap();
        let again = create_deposit_unsigned_tx(CONTRACT, SK, WITHDRAWAL, &U256::exp10(18)).unwrap();
        let two = create_deposit_unsigned_tx(CONTRACT, SK, WITHDRAWAL, &(U256::exp10(18) * 2)).unwrap();
        assert_eq!(calldata(&one), calldata(&again));
        assert_ne!(calldata(&one), calldata(&two));
    }

    #[test]
    fn an_amount_beyond_u64_gwei_is_refused() {
        let too_much = U256::from(u64::MAX) * U256::exp10(9) + U256::exp10(9);
        let err = create_deposit_unsigned_tx(CONTRACT, SK, WITHDRAWAL, &too_much).unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
        // The largest representable amount is accepted.
        let max = U256::from(u64::MAX) * U256::exp10(9);
        assert!(create_deposit_unsigned_tx(CONTRACT, SK, WITHDRAWAL, &max).is_ok());
    }

    #[test]
    fn deposit_input_errors_name_the_offending_argument() {
        let one = U256::one();
        let err = create_deposit_unsigned_tx(CONTRACT, SK, "zz", &one).unwrap_err();
        assert!(err.to_string().contains("invalid withdrawal_address"), "{err}");
        let err = create_deposit_unsigned_tx(CONTRACT, SK, "abcd", &one).unwrap_err();
        assert!(err.to_string().contains("got 2 bytes"), "{err}");
        let err = create_deposit_unsigned_tx(CONTRACT, "nothex", WITHDRAWAL, &one).unwrap_err();
        assert!(!err.to_string().is_empty());
        let err = create_deposit_unsigned_tx(CONTRACT, "00", WITHDRAWAL, &one).unwrap_err();
        assert!(err.to_string().contains("SecretKey::from_bytes"), "{err}");
        let err = create_deposit_unsigned_tx("not an address", SK, WITHDRAWAL, &one).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn the_exit_fee_query_has_empty_calldata_and_no_value() {
        let tx = create_get_exit_fee_unsigned_tx().unwrap();
        assert_eq!(tx.to, Some(NameOrAddress::Address(EIP7002_CONTRACT_ADDRESS.parse().unwrap())));
        assert!(calldata(&tx).is_empty());
        assert_eq!(tx.value, None);
    }

    #[test]
    fn an_exit_is_the_pubkey_plus_a_zero_amount_and_the_fee_defaults_to_one_wei() {
        let pubkey = "8a2470d8ccb2e43b3b5295cfee71508f8808e166e5f152d5af9fe022d95e300dc7c5814f2c9eb71e2da8412beb61c53a";
        let default = create_exit_unsigned_tx(pubkey, &None).unwrap();
        let data = calldata(&default);
        assert_eq!(data.len(), 56);
        assert_eq!(hex::encode(&data[..48]), pubkey);
        assert_eq!(&data[48..], &[0u8; 8], "amount 0 means a full exit");
        assert_eq!(default.value, Some(U256::one()));

        let paid = create_exit_unsigned_tx(&format!("0x{pubkey}"), &Some(U256::from(77u64))).unwrap();
        assert_eq!(paid.value, Some(U256::from(77u64)));
        assert_eq!(calldata(&paid), data, "the prefix does not change the payload");
    }

    #[test]
    fn exit_pubkeys_of_the_wrong_length_or_not_hex_are_refused() {
        let err = create_exit_unsigned_tx(&"ab".repeat(47), &None).unwrap_err();
        assert!(err.to_string().contains("got 47 bytes"), "{err}");
        let err = create_exit_unsigned_tx(&"ab".repeat(49), &None).unwrap_err();
        assert!(err.to_string().contains("got 49 bytes"), "{err}");
        let err = create_exit_unsigned_tx("zz", &None).unwrap_err();
        assert!(err.to_string().contains("invalid validator_public_key"), "{err}");
    }
}
