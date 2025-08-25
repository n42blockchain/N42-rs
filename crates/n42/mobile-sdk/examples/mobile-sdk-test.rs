use ethers::{
    prelude::*,
};
use ethers::middleware::SignerMiddleware;
use ethers_signers::{LocalWallet, WalletError};
use std::{str::FromStr, sync::Arc};
use clap::{Command, Parser, Subcommand};
use hex::FromHex;
use mobile_sdk::{deposit_exit::{self, create_deposit_unsigned_tx, create_get_exit_fee_unsigned_tx, create_exit_unsigned_tx}, run_client};
use blst::min_pk::SecretKey;
use ::rand::RngCore;
use tracing::info;

abigen!(
    DepositContract,
    "src/deposit.json",
    event_derives(serde::Deserialize, serde::Serialize)
);

abigen!(
    ExitContract,
    "src/exit_contract.json",
);

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

        #[arg(short, long)]
        validator_private_key: Option<String>,
        #[arg(short, long)]
        withdrawal_address: String,
        #[arg(short, long, default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")]
        deposit_private_key: String,
    },
    Exit {
        #[command(flatten)]
        common: CommonArgs,

        #[arg(short, long, default_value = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6")]
        withdrawal_private_key: String,
        #[arg(short, long, default_value = "b758091fbfafd4bd5db58616a3db1725e8147c5c38dd62dd052db3d42b420ed47d2584ed219f9e42702da0a5c8864a5f")]
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
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Cli::parse();

    match args.command {
        Commands::Deposit {
            validator_private_key,
            withdrawal_address,
            deposit_private_key,
            common,
        }=> {
            deposit(validator_private_key, withdrawal_address, deposit_private_key, common.rpc_url).await?;
        },
        Commands::Exit {
            withdrawal_private_key,
            common,
            validator_public_key,
        }=> {
            exit(withdrawal_private_key, common.rpc_url, validator_public_key).await?;
        },
        Commands::Validate {
            validator_private_key,
            ws_rpc_url,
            common,
        }=> {
            validate(validator_private_key, ws_rpc_url).await?;
        }
    }

    Ok(())
}

async fn deposit(
    validator_private_key: Option<String>,
    withdrawal_address: String,
    deposit_private_key: String,
    rpc_url: String,
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
            sk
        }
    };

    let deposit_contract_address = deposit_exit::DEVNET_DEPOSIT_CONTRACT_ADDRESS;
    let unsigned_tx = create_deposit_unsigned_tx(deposit_contract_address.to_owned(), hex::encode(&sk.to_bytes()), withdrawal_address)?;

    let provider = Provider::<Http>::try_from(rpc_url)?;
    let chain_id = provider.get_chainid().await?.as_u64();

    let wallet = LocalWallet::from_str(&deposit_private_key)?
        .with_chain_id(chain_id);

    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    let deposit_address = Address::from_str(deposit_contract_address)?;

    let deposit_contract = DepositContract::new(deposit_address, client.clone());

    let pending_tx = client.send_transaction(unsigned_tx, None).await?;

    let receipt = pending_tx
        .await?
        .ok_or(eyre::eyre!("TransactionDropped"))?;
    let transaction_receipt = match receipt.status {
        Some(v) => {
            if v == U64::from(1) {
                receipt
            } else {
                return Err(eyre::eyre!("TransactionDropped"));
            }
        },
        None => {
            return Err(eyre::eyre!("TransactionDropped"));
        }
    };
    info!("deposit transaction_receipt {transaction_receipt:?}");

    Ok(())
}

async fn exit(
        withdrawal_private_key: String,
        rpc_url: String,
        validator_public_key: String,
    ) -> eyre::Result<()> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let chain_id = provider.get_chainid().await?.as_u64();

    let wallet = LocalWallet::from_str(&withdrawal_private_key)?
        .with_chain_id(chain_id);

    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    let exit_contract_address = Address::from_str(deposit_exit::EIP7002_CONTRACT_ADDRESS)?;

    let unsigned_tx = create_get_exit_fee_unsigned_tx()?;

    let raw =
        client
        .provider()
        .call(&unsigned_tx.into(), None)
        .await?;

    let fee = U256::from_big_endian(&raw.0);

    let unsigned_tx = create_exit_unsigned_tx(validator_public_key, Some(fee))?;

    let pending_tx =
        client
        .send_transaction(unsigned_tx, None)
        .await?;

    let receipt = pending_tx
        .await?
        .ok_or(eyre::eyre!("TransactionDropped"))?;
    let transaction_receipt = match receipt.status {
        Some(v) => {
            if v == U64::from(1) {
                receipt
            } else {
                return Err(eyre::eyre!("TransactionDropped"));
            }
        },
        None => {
            return Err(eyre::eyre!("TransactionDropped"));
        }
    };
    info!("exit transaction_receipt {transaction_receipt:?}");

    Ok(())
}

async fn validate(
    validator_private_key: Option<String>,
    rpc_url: String,
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
            sk
        }
    };
    run_client(&rpc_url, &sk).await?;
    Ok(())
}
