use deposit_sdk::SdkError;
use std::{fs};
use ethers::types::H256;
use std::path::PathBuf;
use deposit_sdk::{EthStakingSdk, DepositData, DEPOSIT_CONTRACT_ADDRESS, withdrawal_credentials};
use hex::FromHex;
use tree_hash::TreeHash;
use clap::{Command, Parser, Subcommand};
use keystore::Address;
use keystore::blst::{GenericSecretKey, PublicKeyBytes, SignatureBytes};
use keystore::keystore::{ Keystore};
use n42_withdrawals::chain_spec::ChainSpec;
use blst::min_pk::SecretKey;
use rand::RngCore;

#[derive(Parser, Debug)]
#[command(
    name = "test",
    author,
    version,
    about = "deposit"
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
        /// 提现地址 (Hex 格式，带或不带 0x 前缀)
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
}

/// cargo run -p deposit_sdk --example deposit_test -- \
///   --withdrawal-address 0xd6e82b1eddbc48f735422c816c69da3a08d7dea7
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    }

    Ok(())
}

async fn deposit(
    validator_private_key: Option<String>,
    withdrawal_address: String,
    deposit_private_key: String,
    rpc_url: String,
    ) -> Result<(), Box<dyn std::error::Error>> {

    // 处理提现地址，去掉 "0x" 前缀并解码
    let addr_hex = withdrawal_address
        .strip_prefix("0x")
        .unwrap_or(&withdrawal_address);
    let addr_bytes = hex::decode(addr_hex)
        .map_err(|e| format!("无效的提现地址 hex: {}", e))?;
    if addr_bytes.len() != 20 {
        return Err(format!("提现地址必须 20 字节，但得到 {} 字节", addr_bytes.len()).into());
    }
    let addr = Address::from_slice(&addr_bytes);

    // 计算 withdrawal_credentials
    let creds = withdrawal_credentials(addr);
    println!("withdrawal_credentials: 0x{}", hex::encode(&creds));

    let sk = match validator_private_key {
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
    let pk = sk.sk_to_pk();

    let pubkey = pk;
    //println!("pubkey: {}", pubkey.as_hex_string());
    println!("pubkey: {:?}", hex::encode(pubkey.to_bytes()));

    // 构造 DepositData 并签名
    let mut deposit_data = DepositData {
        pubkey: PublicKeyBytes::deserialize(&pubkey.to_bytes()).unwrap(),
        withdrawal_credentials: creds,
        signature: SignatureBytes::empty(),
        amount: 32_000_000_000,
    };
    let spec = ChainSpec::n42();
    deposit_data.signature = deposit_data.create_signature(&GenericSecretKey::deserialize(&sk.serialize()).unwrap(), &spec);

    // 输出结果
    println!("signed deposit: {:#?}", deposit_data);
    let root = deposit_data.tree_hash_root();
    println!("deposit_data_root: {}", root);

    // 质押部分
    let deposit_contract_address = DEPOSIT_CONTRACT_ADDRESS;
    let sdk = EthStakingSdk::new(&rpc_url, &deposit_private_key, deposit_contract_address).await?;

    let pubkey_hex = deposit_data.pubkey.as_hex_string();
    let creds_hex = hex::encode(&deposit_data.withdrawal_credentials);
    let signature_hex = deposit_data.signature.as_hex_string();
    let deposit_data_root_hex = format!("{:x}", deposit_data.tree_hash_root());
    println!("pubkey_hex = {}", pubkey_hex);
    println!("creds_hex = {}", creds_hex);
    println!("signature_hex = {}", signature_hex);
    println!("deposit_data_root_hex = {}", deposit_data_root_hex);

    let receipt = sdk
        .deposit(
            &pubkey_hex,
            &creds_hex,
            &signature_hex,
            &deposit_data_root_hex,
        )
        .await
        .map_err(|e| format!("调用 deposit 失败: {:?}", e))?;

    println!("✅ 质押成功，tx_hash = {:?}", receipt.transaction_hash);

    Ok(())
}

async fn exit(
        withdrawal_private_key: String,
        rpc_url: String,
        validator_public_key: String,
    ) -> Result<(), SdkError> {

    let deposit_contract_address = DEPOSIT_CONTRACT_ADDRESS;


    // --- 执行操作 ---
    println!("正在实例化 Staking SDK...");
    let sdk = EthStakingSdk::new(
        &rpc_url,
        &withdrawal_private_key,
        deposit_contract_address,
    ).await?;

    println!("\n即将为验证者 {} 发起退出...", validator_public_key);

    match sdk.request_exit(&validator_public_key).await {
        Ok(receipt) => {
            let tx_hash_bytes: H256 = receipt.transaction_hash;
            println!("\n🎉 成功！退出请求已提交。");
            println!("   - 交易哈希: {:?}", tx_hash_bytes);
            println!("   - 区块号: {}", receipt.block_number.unwrap_or_default());
            println!("\n重要提示：这仅代表退出请求已上链，资金到账需要等待共识层处理，请在区块浏览器上跟踪验证者状态。");
        }
        Err(e) => {
            eprintln!("\n❌ 操作失败: {}", e);
        }
    }

    Ok(())
}
