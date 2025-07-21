use std::{fs};
use std::path::PathBuf;
use deposit_sdk::{EthStakingSdk, DepositData, DEPOSIT_CONTRACT_ADDRESS, withdrawal_credentials};
use tree_hash::TreeHash;
use clap::Parser;
use keystore::Address;
use keystore::blst::{PublicKeyBytes, SignatureBytes};
use keystore::keystore::{ Keystore};
use n42_withdrawals::chain_spec::ChainSpec;

/// 从 keystore 生成以太坊存款数据
#[derive(Parser, Debug)]
#[command(
    name = "deposit_test",
    author,
    version,
    about = "从 Keystore 解密并生成存款数据（DepositData）"
)]
struct Cli {
    /// Keystore JSON 文件路径
    #[arg(short, long, value_name = "FILE")]
    keystore_path: PathBuf,

    /// Keystore 解密密码
    #[arg(short, long)]
    password: String,

    /// 提现地址 (Hex 格式，带或不带 0x 前缀)
    #[arg(short, long)]
    withdrawal_address: String,
}

/// cargo run -p deposit_sdk --example deposit_test -- \
///   --keystore-path /Users/macbook/Desktop/wjh/work/N42-rs/crates/n42/deposit_sdk/examples/keystore1.json \
///   --password test-password \
///   --withdrawal-address 0xd6e82b1eddbc48f735422c816c69da3a08d7dea7
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // 处理提现地址，去掉 "0x" 前缀并解码
    let addr_hex = cli
        .withdrawal_address
        .strip_prefix("0x")
        .unwrap_or(&cli.withdrawal_address);
    let addr_bytes = hex::decode(addr_hex)
        .map_err(|e| format!("无效的提现地址 hex: {}", e))?;
    if addr_bytes.len() != 20 {
        return Err(format!("提现地址必须 20 字节，但得到 {} 字节", addr_bytes.len()).into());
    }
    let addr = Address::from_slice(&addr_bytes);

    // 计算 withdrawal_credentials
    let creds = withdrawal_credentials(addr);
    println!("withdrawal_credentials: 0x{}", hex::encode(&creds));

    // 读取并解析 keystore JSON
    let keystore_json = fs::read_to_string(&cli.keystore_path)
        .map_err(|e| format!("读取 keystore 文件失败 {:?}: {}", cli.keystore_path, e))?;
    let keystore: Keystore = serde_json::from_str(&keystore_json)
        .map_err(|e| format!("解析 keystore JSON 失败: {}", e))?;

    // 解密 keystore，获取 Keypair
    let keypair = keystore
        .decrypt_keypair(cli.password.as_bytes())
        .map_err(|e| format!("解密 keystore 失败: {:?}", e))?;

    // 获取并打印公钥
    let pubkey = {
        let bytes = keypair.pk.serialize();
        PublicKeyBytes::deserialize(&bytes)
            .map_err(|e| format!("PublicKeyBytes deserialize 失败: {:?}", e))?
    };
    println!("pubkey: {}", pubkey.as_hex_string());

    // 构造 DepositData 并签名
    let mut deposit_data = DepositData {
        pubkey,
        withdrawal_credentials: creds,
        signature: SignatureBytes::empty(),
        amount: 32_000_000_000,
    };
    let spec = ChainSpec::n42();
    deposit_data.signature = deposit_data.create_signature(&keypair.sk, &spec);

    // 输出结果
    println!("signed deposit: {:#?}", deposit_data);
    let root = deposit_data.tree_hash_root();
    println!("deposit_data_root: {}", root);

    // 质押部分
    let rpc = "https://testrpc.n42.world";
    let private_key  = "006ae52779c5a935d02b2d7eab3e01ef9cba11fa068edbcb529a3e9673d8fb7e";
    let deposit_contract_address = DEPOSIT_CONTRACT_ADDRESS;
    let sdk = EthStakingSdk::new(rpc, private_key, deposit_contract_address).await?;

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