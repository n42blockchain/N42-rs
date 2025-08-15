use clap::{Command, Parser, Subcommand};
use hex::FromHex;
use mobile_sdk::run_client;
use blst::min_pk::SecretKey;
use rand::RngCore;

const WS_URL: &str = "ws://127.0.0.1:8546";

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short, long)]
    validator_private_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let sk = match cli.validator_private_key {
        Some(validator_private_key) => {
            let sk = SecretKey::from_bytes(&Vec::from_hex(&validator_private_key).unwrap()).unwrap();
            sk
        },
        None => {
            let mut rng = rand::thread_rng();
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);

            let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
            sk
        }
    };

    run_client(WS_URL, &sk).await
}
