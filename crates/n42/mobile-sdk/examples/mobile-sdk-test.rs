// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use ::rand::RngCore;
use blst::min_pk::SecretKey;
use clap::{Command, Parser, Subcommand};
use alloy_primitives::Address;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use ethers_core::types::U256;
use futures_util::future::join_all;
use hex::FromHex;
use mobile_sdk::blst_utils::generate_bls12_381_keypair;
use mobile_sdk::{
    deposit_exit::{
        self, create_deposit_unsigned_tx, create_exit_unsigned_tx, create_get_exit_fee_unsigned_tx,
        DEVNET_DEPOSIT_CONTRACT_ADDRESS,
    },
    run_client,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::str::FromStr;
use tokio::fs;
use tokio::io::{self, AsyncReadExt};
use tokio::time::sleep;
use tracing::{debug, info, Level};
use tracing_appender::non_blocking;
use tracing_subscriber::{fmt, EnvFilter};

const _32eth_hex_in_wei: &str = "0x1bc16d674ec800000";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidatorCredential {
    validator_private_key: String,
    validator_public_key: String,
    withdrawal_private_key: String,
    withdrawal_address: String,
}

#[derive(Parser, Debug)]
#[command(
    name = "mobile-sdk-test",
    author,
    version,
    about = "deposit, exit, validate"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Args, Debug)]
struct CommonArgs {
    #[arg(short, long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Deposit {
        #[command(flatten)]
        common: CommonArgs,

        /// Optional validator_private_key [default: random if not supplied].
        #[arg(short, long)]
        validator_private_key: Option<String>,
        #[arg(short, long)]
        withdrawal_address: String,
        #[arg(short, long)]
        deposit_private_key: String,

        /// Optional deposit_value_wei_in_hex [default: 32ETH if not supplied].
        #[arg(long, default_value = _32eth_hex_in_wei)] // 32 ETH in wei in hex
        deposit_value_wei_in_hex: U256,

        /// Optional deposit_contract_address [default: devnet deposit contract address].
        #[arg(long, default_value_t = DEVNET_DEPOSIT_CONTRACT_ADDRESS.to_string())]
        deposit_contract_address: String,
    },
    Exit {
        #[command(flatten)]
        common: CommonArgs,

        #[arg(short, long)]
        withdrawal_private_key: String,
        #[arg(short, long)]
        validator_public_key: String,
    },
    Validate {
        #[command(flatten)]
        common: CommonArgs,

        #[arg(short, long)]
        validator_private_key: Option<String>,

        #[arg(short, long, default_value = "ws://127.0.0.1:8546")]
        ws_rpc_url: String,
    },
    GenerateBLS12381Keypair {},
    GenerateCredentials {
        #[arg(short, long)]
        number_of_validators: u64,
    },
    DepositForValidators {
        #[command(flatten)]
        common: CommonArgs,

        #[arg(short, long)]
        deposit_private_key: String,

        /// Optional deposit_contract_address [default: devnet deposit contract address].
        #[arg(long, default_value_t = DEVNET_DEPOSIT_CONTRACT_ADDRESS.to_string())]
        deposit_contract_address: String,

        #[arg(short, long)]
        validator_credentials_file: Option<String>,
    },
    ValidateForValidators {
        #[command(flatten)]
        common: CommonArgs,

        #[arg(short, long)]
        validator_credentials_file: Option<String>,

        #[arg(short, long, default_value = "ws://127.0.0.1:8546")]
        ws_rpc_url: String,
    },
    ExitForValidators {
        #[command(flatten)]
        common: CommonArgs,

        #[arg(short, long)]
        validator_credentials_file: Option<String>,
    },
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Default level = info, but can be overridden by RUST_LOG
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let (non_blocking, _guard) = non_blocking(std::io::stderr());
    fmt()
        .with_writer(non_blocking)
        .with_env_filter(filter)
        .init();

    let args = Cli::parse();
    debug!("args {args:?}");

    match args.command {
        Commands::Deposit {
            validator_private_key,
            withdrawal_address,
            deposit_private_key,
            deposit_value_wei_in_hex,
            deposit_contract_address,
            common,
        } => {
            deposit(
                &deposit_contract_address,
                validator_private_key.as_deref(),
                &withdrawal_address,
                &deposit_private_key,
                &deposit_value_wei_in_hex,
                &common.rpc_url,
            )
            .await?;
        }
        Commands::Exit {
            withdrawal_private_key,
            common,
            validator_public_key,
        } => {
            exit(
                &withdrawal_private_key,
                &common.rpc_url,
                &validator_public_key,
            )
            .await?;
        }
        Commands::Validate {
            validator_private_key,
            ws_rpc_url,
            common: _,
        } => {
            validate(validator_private_key.as_deref(), &ws_rpc_url).await?;
        }
        Commands::GenerateBLS12381Keypair {} => {
            let keypair = generate_bls12_381_keypair()?;
            println!("keypair: {keypair:?}");
        }
        Commands::GenerateCredentials {
            number_of_validators,
        } => {
            generate_credentials(number_of_validators)?;
        }
        Commands::DepositForValidators {
            deposit_private_key,
            deposit_contract_address,
            validator_credentials_file,
            common,
        } => {
            let validator_credentials =
                get_validator_credentials(validator_credentials_file).await?;
            info!("number of validators: {}", validator_credentials.len());
            let num_successes = deposit_for_validators(
                &common.rpc_url,
                &deposit_contract_address,
                &deposit_private_key,
                &validator_credentials,
            )
            .await?;
            info!("deposited for {num_successes:?} validators");
        }
        Commands::ValidateForValidators {
            validator_credentials_file,
            common,
            ws_rpc_url,
        } => {
            let validator_credentials =
                get_validator_credentials(validator_credentials_file).await?;
            info!("number of validators: {}", validator_credentials.len());
            validate_for_validators(&ws_rpc_url, &validator_credentials).await?;
        }
        Commands::ExitForValidators {
            validator_credentials_file,
            common,
        } => {
            let validator_credentials =
                get_validator_credentials(validator_credentials_file).await?;
            info!("number of validators: {}", validator_credentials.len());
            let _ = exit_for_validators(&common.rpc_url, &validator_credentials).await?;
        }
    }

    Ok(())
}

// The SDK keeps its existing transaction types and JSON for C/JNI callers.
// Alloy accepts the same Ethereum JSON fields, including `data` and hex quantities.
fn to_alloy_transaction(
    tx: ethers_core::types::TransactionRequest,
) -> eyre::Result<alloy_rpc_types_eth::TransactionRequest> {
    // ethers deliberately omits chain_id from its RPC JSON. Preserve it for
    // local signing instead of letting the provider replace an explicit value.
    let chain_id = tx.chain_id.map(|id| id.as_u64());
    let mut converted: alloy_rpc_types_eth::TransactionRequest =
        serde_json::from_value(serde_json::to_value(tx)?)?;
    converted.chain_id = chain_id;
    Ok(converted)
}

async fn send_legacy_transaction<P: Provider>(
    provider: &P,
    tx: ethers_core::types::TransactionRequest,
) -> eyre::Result<alloy_provider::PendingTransactionBuilder<alloy_network::Ethereum>> {
    let mut tx = to_alloy_transaction(tx)?;
    // The old ethers TransactionRequest used legacy gas pricing. Setting it
    // explicitly keeps Alloy's fee filler from changing the transaction type.
    if tx.gas_price.is_none() {
        tx.gas_price = Some(provider.get_gas_price().await?);
    }
    Ok(provider.send_transaction(tx).await?)
}

async fn deposit(
    deposit_contract_address: &str,
    validator_private_key: Option<&str>,
    withdrawal_address: &str,
    deposit_private_key: &str,
    deposit_value_wei_in_hex: &U256,
    rpc_url: &str,
) -> eyre::Result<()> {
    let sk = match validator_private_key {
        Some(validator_private_key) => {
            let bytes = Vec::from_hex(validator_private_key)
                .map_err(|e| eyre::eyre!("invalid validator_private_key hex: {}", e))?;
            SecretKey::from_bytes(&bytes)
                .map_err(|e| eyre::eyre!("invalid validator_private_key: {:?}", e))?
        }
        None => {
            let mut rng = ::rand::rng();
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);

            let sk = SecretKey::key_gen(&ikm, &[])
                .map_err(|e| eyre::eyre!("SecretKey::key_gen() error: {:?}", e))?;
            // Securely clear the input key material
            ikm.fill(0);
            // Note: Private key not logged for security reasons
            info!("generated new validator private key");
            sk
        }
    };

    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);

    let code = provider.get_code_at(deposit_contract_address.parse()?).await?;
    if code.is_empty() {
        return Err(eyre::eyre!(
            "deposit contract is not deployed at {deposit_contract_address}"
        ));
    }

    let unsigned_tx = create_deposit_unsigned_tx(
        deposit_contract_address,
        &hex::encode(&sk.to_bytes()),
        withdrawal_address,
        deposit_value_wei_in_hex,
    )?;

    let wallet = PrivateKeySigner::from_str(deposit_private_key)?;

    let client = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url.parse()?);

    let pending_tx = send_legacy_transaction(&client, unsigned_tx).await?;

    let receipt = pending_tx.get_receipt().await?;
    if !receipt.status() {
        return Err(eyre::eyre!("deposit transaction reverted"));
    }
    let transaction_receipt = receipt;
    debug!("deposit transaction_receipt {transaction_receipt:?}");

    Ok(())
}

async fn deposit_multiple(
    deposit_contract_address: &str,
    credentials: &[(
        /* withdrawal_address: */ &str,
        /* validator_private_key: */ &str,
    )],
    deposit_private_key: &str,
    deposit_value_wei_in_hex: &U256,
    rpc_url: &str,
) -> eyre::Result<()> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);

    let code = provider.get_code_at(deposit_contract_address.parse()?).await?;
    if code.is_empty() {
        return Err(eyre::eyre!(
            "deposit contract is not deployed at {deposit_contract_address}"
        ));
    }

    let wallet = PrivateKeySigner::from_str(deposit_private_key)?;
    let wallet_address = wallet.address();

    let client = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url.parse()?);

    let mut last_pending = None;
    let mut nonce = client
        .get_transaction_count(wallet_address)
        .pending()
        .await?;
    for (withdrawal_address, validator_private_key) in credentials {
        let bytes = Vec::from_hex(validator_private_key)
            .map_err(|e| eyre::eyre!("invalid validator_private_key hex: {}", e))?;
        let sk = SecretKey::from_bytes(&bytes)
            .map_err(|e| eyre::eyre!("invalid validator_private_key: {:?}", e))?;
        let mut unsigned_tx = create_deposit_unsigned_tx(
            deposit_contract_address,
            &hex::encode(&sk.to_bytes()),
            withdrawal_address,
            deposit_value_wei_in_hex,
        )?;
        unsigned_tx.nonce = Some(nonce.into());
        nonce += 1;

        let pending = send_legacy_transaction(&client, unsigned_tx).await?;
        debug!("deposit send_transaction pending {pending:?}");
        last_pending = Some(pending);
    }

    if let Some(pending) = last_pending {
        let receipt = pending.get_receipt().await?;
        if !receipt.status() {
            return Err(eyre::eyre!("deposit transaction reverted"));
        }
        let transaction_receipt = receipt;
        debug!("deposit transaction_receipt {transaction_receipt:?}");
    };

    Ok(())
}

async fn exit(
    withdrawal_private_key: &str,
    rpc_url: &str,
    validator_public_key: &str,
) -> eyre::Result<()> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);

    let exit_contract_address = Address::from_str(deposit_exit::EIP7002_CONTRACT_ADDRESS)?;

    let code = provider.get_code_at(exit_contract_address).await?;
    if code.is_empty() {
        return Err(eyre::eyre!(
            "exit contract is not deployed at {exit_contract_address}"
        ));
    }

    let wallet = PrivateKeySigner::from_str(withdrawal_private_key)?;

    let client = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url.parse()?);

    let unsigned_tx = create_get_exit_fee_unsigned_tx()?;

    let raw = client.call(to_alloy_transaction(unsigned_tx)?).await?;

    let fee = U256::from_big_endian(raw.as_ref());

    let unsigned_tx = create_exit_unsigned_tx(validator_public_key, &Some(fee))?;

    let pending_tx = send_legacy_transaction(&client, unsigned_tx).await?;

    let receipt = pending_tx.get_receipt().await?;
    if !receipt.status() {
        return Err(eyre::eyre!("exit transaction reverted"));
    }
    let transaction_receipt = receipt;
    debug!("exit transaction_receipt {transaction_receipt:?}");

    Ok(())
}

fn generate_credentials(number_of_validators: u64) -> eyre::Result<()> {
    let validator_credentials = (0..number_of_validators)
        .map(|_| generate_credential())
        .collect::<Vec<_>>();
    let json = serde_json::to_string_pretty(&validator_credentials)?;
    println!("{}", json);
    Ok(())
}

fn generate_credential() -> ValidatorCredential {
    let mut rng = ::rand::rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let validator_private_key = SecretKey::key_gen(&ikm, &[])
        .expect("SecretKey::key_gen() should not fail with 32 random bytes");
    // Securely clear the input key material
    ikm.fill(0);
    let validator_public_key = hex::encode(validator_private_key.sk_to_pk().to_bytes());

    let wallet = PrivateKeySigner::random();
    let withdrawal_private_key = hex::encode(wallet.to_bytes());
    let withdrawal_address = hex::encode(wallet.address().as_slice());

    ValidatorCredential {
        validator_private_key: hex::encode(validator_private_key.to_bytes()),
        validator_public_key,
        withdrawal_private_key,
        withdrawal_address,
    }
}

async fn deposit_for_validators(
    rpc_url: &str,
    deposit_contract_address: &str,
    deposit_private_key: &str,
    validator_credentials: &[ValidatorCredential],
) -> eyre::Result<u64> {
    let credentials = validator_credentials
        .iter()
        .map(|v| {
            (
                v.withdrawal_address.as_str(),
                v.validator_private_key.as_str(),
            )
        })
        .collect::<Vec<_>>();
    let chunk_size = 256;
    for (i, credentials_chunk) in credentials.chunks(chunk_size).enumerate() {
        debug!(
            "Depositing for validators from {:?} to {:?}",
            chunk_size * i,
            chunk_size * (i + 1) - 1
        );
        deposit_multiple(
            deposit_contract_address,
            credentials_chunk,
            deposit_private_key,
            &_32eth_hex_in_wei.into(),
            rpc_url,
        )
        .await?;
    }

    Ok(validator_credentials.len() as u64)
}

async fn validate(validator_private_key: Option<&str>, ws_rpc_url: &str) -> eyre::Result<()> {
    let validator_private_key = match validator_private_key {
        Some(v) => v.to_owned(),
        None => {
            let mut rng = ::rand::rng();
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);

            let sk = SecretKey::key_gen(&ikm, &[])
                .map_err(|e| eyre::eyre!("SecretKey::key_gen() error: {:?}", e))?;
            // Securely clear the input key material
            ikm.fill(0);
            hex::encode(sk.to_bytes())
        }
    };
    while let Err(e) = run_client(ws_rpc_url, &validator_private_key).await {
        info!("run_client error: {e}, retrying...");
        sleep(Duration::from_secs(5)).await;
    }
    Ok(())
}

async fn validate_for_validators(
    ws_rpc_url: &str,
    validator_credentials: &[ValidatorCredential],
) -> eyre::Result<()> {
    let tasks = validator_credentials
        .iter()
        .map(move |validator_credential| {
            let ws_rpc_url_clone = ws_rpc_url.to_owned();
            let validator_private_key = validator_credential.validator_private_key.clone();
            tokio::spawn(async move {
                while let Err(e) = run_client(&ws_rpc_url_clone, &validator_private_key).await {
                    info!("run_client error: {e}, retrying...");
                    sleep(Duration::from_secs(5)).await;
                }
            })
        });
    join_all(tasks).await;
    Ok(())
}

async fn exit_for_validators(
    rpc_url: &str,
    validator_credentials: &[ValidatorCredential],
) -> eyre::Result<u64> {
    let mut num_successes = 0;
    for validator_credential in validator_credentials {
        let ValidatorCredential {
            validator_private_key: _,
            validator_public_key,
            withdrawal_private_key,
            withdrawal_address: _,
        } = validator_credential;
        match exit(withdrawal_private_key, rpc_url, validator_public_key).await {
            Ok(_) => {
                num_successes += 1;
                info!("exited for {num_successes} validators");
            }
            Err(e) => {
                info!("exit_for_validators error: {e}");
                break;
            }
        }
    }

    Ok(num_successes)
}
async fn get_validator_credentials(
    validator_credentials_file: Option<String>,
) -> eyre::Result<Vec<ValidatorCredential>> {
    let validator_credentials_str = if let Some(file) = validator_credentials_file {
        fs::read_to_string(file).await?
    } else {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer).await?;
        buffer
    };
    let validator_credentials: Vec<ValidatorCredential> =
        serde_json::from_str(&validator_credentials_str)?;
    Ok(validator_credentials)
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    use alloy_consensus::SignableTransaction;
    use alloy_network::NetworkTransactionBuilder;

    #[test]
    fn alloy_preserves_the_sdk_transactions_and_legacy_signing_hashes() {
        let deposit = create_deposit_unsigned_tx(
            "0x5FbDB2315678afecb367f032d93F642f64180aa3",
            "6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec",
            "a0Ee7A142d267C1f36714E4a8F75612F20a79720",
            &U256::from(32_000_000_000_000_000_000u128),
        ).unwrap();
        let exit = create_exit_unsigned_tx(&"ab".repeat(48), &Some(U256::MAX)).unwrap();
        let fee_query = create_get_exit_fee_unsigned_tx().unwrap();
        for mut original in [deposit, exit, fee_query] {
            original.chain_id = Some(42u64.into());
            original.nonce = Some(7u64.into());
            original.gas = Some(300_000u64.into());
            original.gas_price = Some(9_000_000_000u64.into());
            let expected_hash = original.sighash();
            let converted = to_alloy_transaction(original.clone()).unwrap();
            assert_eq!(converted.nonce, Some(7));
            assert_eq!(converted.chain_id, Some(42));
            assert_eq!(converted.gas, Some(300_000));
            assert_eq!(converted.gas_price, Some(9_000_000_000));
            assert_eq!(converted.input.input().unwrap().as_ref(), original.data.as_ref().unwrap().as_ref());
            let unsigned = converted.build_unsigned().unwrap();
            assert_eq!(unsigned.signature_hash().as_slice(), expected_hash.as_bytes());
        }
    }
}
