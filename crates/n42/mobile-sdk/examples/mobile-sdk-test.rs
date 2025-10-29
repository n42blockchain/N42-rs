use ethers::{
    prelude::*,
};
use ethers::middleware::SignerMiddleware;
use ethers_signers::{LocalWallet, WalletError};
use futures_util::future::join_all;
use mobile_sdk::blst_utils::generate_bls12_381_keypair;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::{self, AsyncReadExt};
use tokio::time::sleep;
use std::time::Duration;
use std::{str::FromStr, sync::Arc};
use clap::{Command, Parser, Subcommand};
use hex::FromHex;
use mobile_sdk::{deposit_exit::{self, create_deposit_unsigned_tx, create_get_exit_fee_unsigned_tx, create_exit_unsigned_tx,
DEVNET_DEPOSIT_CONTRACT_ADDRESS,
}, run_client};
use blst::min_pk::SecretKey;
use ::rand::RngCore;
use tracing::{debug, info, Level};

abigen!(
    DepositContract,
    "src/deposit.json",
    event_derives(serde::Deserialize, serde::Serialize)
);

abigen!(
    ExitContract,
    "src/exit_contract.json",
);

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
    GenerateBLS12381Keypair {
    },
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
    tracing_subscriber::fmt::init();

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
        }=> {
            deposit(&deposit_contract_address, validator_private_key.as_deref(), &withdrawal_address, &deposit_private_key, &deposit_value_wei_in_hex, &common.rpc_url).await?;
        },
        Commands::Exit {
            withdrawal_private_key,
            common,
            validator_public_key,
        }=> {
            exit(&withdrawal_private_key, &common.rpc_url, &validator_public_key).await?;
        },
        Commands::Validate {
            validator_private_key,
            ws_rpc_url,
            common,
        }=> {
            validate(validator_private_key.as_deref(), &ws_rpc_url).await?;
        },
        Commands::GenerateBLS12381Keypair {
        }=> {
            let keypair = generate_bls12_381_keypair()?;
            println!("keypair: {keypair:?}");
        }
        Commands::GenerateCredentials {
            number_of_validators,
        } => {
            generate_credentials(number_of_validators)?;
        },
        Commands::DepositForValidators {
            deposit_private_key,
            deposit_contract_address,
            validator_credentials_file,
            common,
        }=> {
            let validator_credentials = get_validator_credentials(validator_credentials_file).await?;
            println!("number of validators: {}", validator_credentials.len());
            let _ = deposit_for_validators(&common.rpc_url, &deposit_contract_address, &deposit_private_key, &validator_credentials).await?;
        },
        Commands::ValidateForValidators {
            validator_credentials_file,
            common,
            ws_rpc_url,
        }=> {
            let validator_credentials = get_validator_credentials(validator_credentials_file).await?;
            println!("number of validators: {}", validator_credentials.len());
            validate_for_validators(&ws_rpc_url, &validator_credentials).await?;
        },
        Commands::ExitForValidators {
            validator_credentials_file,
            common,
        }=> {
            let validator_credentials = get_validator_credentials(validator_credentials_file).await?;
            println!("number of validators: {}", validator_credentials.len());
            let _ = exit_for_validators(&common.rpc_url, &validator_credentials).await?;
        },
    }

    Ok(())
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
            let sk = SecretKey::from_bytes(&Vec::from_hex(&validator_private_key).unwrap()).unwrap();
            sk
        },
        None => {
            let mut rng = ::rand::thread_rng();
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);

            let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
            println!("generated validator_private_key: {sk:?}");
            sk
        }
    };

    let provider = Provider::<Http>::try_from(rpc_url)?;
    let chain_id = provider.get_chainid().await?.as_u64();

    let code = provider.get_code(deposit_contract_address, None).await?;
    if code.is_empty() {
        return Err(eyre::eyre!("deposit contract is not deployed at {deposit_contract_address}"));
    }

    let unsigned_tx = create_deposit_unsigned_tx(deposit_contract_address, &hex::encode(&sk.to_bytes()), withdrawal_address, deposit_value_wei_in_hex)?;

    let wallet = LocalWallet::from_str(&deposit_private_key)?
        .with_chain_id(chain_id);

    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    let deposit_address = Address::from_str(&deposit_contract_address)?;

    let deposit_contract = DepositContract::new(deposit_address, client.clone());

    let pending_tx = client.send_transaction(unsigned_tx, None).await?;

    let receipt = pending_tx
        .await?
        .ok_or(eyre::eyre!("pending tx is None"))?;
    let transaction_receipt = match receipt.status {
        Some(v) => {
            if v == U64::from(1) {
                receipt
            } else {
                return Err(eyre::eyre!("receipt status={v:?}"));
            }
        },
        None => {
            return Err(eyre::eyre!("receipt status is None"));
        }
    };
    debug!("deposit transaction_receipt {transaction_receipt:?}");

    Ok(())
}

async fn exit(
        withdrawal_private_key: &str,
        rpc_url: &str,
        validator_public_key: &str,
    ) -> eyre::Result<()> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let chain_id = provider.get_chainid().await?.as_u64();

    let exit_contract_address = Address::from_str(deposit_exit::EIP7002_CONTRACT_ADDRESS)?;

    let code = provider.get_code(exit_contract_address, None).await?;
    if code.is_empty() {
        return Err(eyre::eyre!("exit contract is not deployed at {exit_contract_address}"));
    }

    let wallet = LocalWallet::from_str(&withdrawal_private_key)?
        .with_chain_id(chain_id);

    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    let unsigned_tx = create_get_exit_fee_unsigned_tx()?;

    let raw =
        client
        .provider()
        .call(&unsigned_tx.into(), None)
        .await?;

    let fee = U256::from_big_endian(&raw.0);

    let unsigned_tx = create_exit_unsigned_tx(validator_public_key, &Some(fee))?;

    let pending_tx =
        client
        .send_transaction(unsigned_tx, None)
        .await?;

    let receipt = pending_tx
        .await?
        .ok_or(eyre::eyre!("pending tx is None"))?;
    let transaction_receipt = match receipt.status {
        Some(v) => {
            if v == U64::from(1) {
                receipt
            } else {
                return Err(eyre::eyre!("receipt status={v:?}"));
            }
        },
        None => {
            return Err(eyre::eyre!("receipt status is None"));
        }
    };
    debug!("exit transaction_receipt {transaction_receipt:?}");

    Ok(())
}

fn generate_credentials(
        number_of_validators: u64,
    ) -> eyre::Result<()> {
    let validator_credentials = (0..number_of_validators).map(|_| generate_credential()).collect::<Vec<_>>();
    let json = serde_json::to_string_pretty(&validator_credentials)?;
    println!("{}", json);
    Ok(())
}

fn generate_credential(
    ) -> ValidatorCredential {
    let mut rng = ::rand::thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let validator_private_key = SecretKey::key_gen(&ikm, &[]).unwrap();
    let validator_public_key = hex::encode(validator_private_key.sk_to_pk().to_bytes());

    let wallet = LocalWallet::new(&mut ethers::core::rand::thread_rng());
    let withdrawal_private_key = hex::encode(wallet.signer().to_bytes());
    let withdrawal_address = hex::encode(wallet.address().to_fixed_bytes());

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
    let mut num_successes = 0;
    for validator_credential in validator_credentials {
        let ValidatorCredential {
            validator_private_key,
            validator_public_key,
            withdrawal_private_key,
            withdrawal_address,
        } = validator_credential;
        match deposit(
            deposit_contract_address,
            Some(validator_private_key),
            withdrawal_address,
            deposit_private_key,
            &_32eth_hex_in_wei.into(),
            rpc_url,
            ).await {
            Ok(_) => {
                num_successes += 1;
                println!("deposited for {num_successes} validators");
            }
            Err(e) => {
                info!("deposit_for_validators error: {e}");
                break;
            }
        }
    }

    Ok(num_successes)
}

async fn validate(
    validator_private_key: Option<&str>,
    rpc_url: &str,
    ) -> eyre::Result<()> {
    let validator_private_key = match validator_private_key {
        Some(v) => v.to_owned(),
        None => {
            let mut rng = ::rand::thread_rng();
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);

            let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
            hex::encode(sk.to_bytes())
        }
    };
    while let Err(e) = run_client(&rpc_url, &validator_private_key).await {
        info!("run_client error: {e}, retrying...");
        sleep(Duration::from_secs(5)).await;
    }
    Ok(())
}

async fn validate_for_validators(
    ws_rpc_url: &str,
    validator_credentials: &[ValidatorCredential],
    ) -> eyre::Result<()> {
    let tasks = validator_credentials.iter().map(
        move |validator_credential| {
            let validator_private_key = &validator_credential.validator_private_key;
            async move {
                while let Err(e) = run_client(&ws_rpc_url, &validator_private_key).await {
                    info!("run_client error: {e}, retrying...");
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
    );
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
            validator_private_key,
            validator_public_key,
            withdrawal_private_key,
            withdrawal_address,
        } = validator_credential;
        match exit(
            withdrawal_private_key,
            rpc_url,
            validator_public_key,
            ).await {
            Ok(_) => {
                num_successes += 1;
                println!("exited for {num_successes} validators");
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
    let validator_credentials: Vec<ValidatorCredential> = serde_json::from_str(&validator_credentials_str)?;
    Ok(validator_credentials)
}
