use std::{env, fs};
use std::fs::File;
use std::io::Write;
use deposit_sdk::{EthStakingSdk, SdkError, DepositData};
use deposit_sdk::deposit::withdrawal_credentials;
use hex_literal::hex;
use keystore::keystore::{keypair_from_secret, KeystoreBuilder, PlainText};

/// 测试提现凭证的生成
/// 运行命令 cargo run --package deposit_sdk --example deposit_test
// fn main() {
//     let addr = Address::from(hex!("d6e82b1eddbc48f735422c816c69da3a08d7dea7")); // 示例地址
//     let creds = withdrawal_credentials(addr);
//     println!("withdrawal_credentials: 0x{}", hex::encode(creds));
// }

/// 测试公钥pubkey的生成
/// 运行命令 本crate下 cargo run --package deposit_sdk --example deposit_test
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 定义一个非0的密钥， 钱包解密而来
    let secret = PlainText::from(vec![2u8; 32]);

    // 生成 keypair
    let keypair = keypair_from_secret(secret.as_bytes()).expect("keypair_from_secret 失败");

    // 生成 keystore
    let password = b"test-password123";
    // 密钥派生路径
    // let path = "m/12381/3600/0/0/0".to_string();
    let path = "m/12381/3600/0/0/0".to_string();

    let keystore = KeystoreBuilder::new(&keypair, password, path)
        .expect("KeystoreBuilder::new 失败")
        .build()
        .expect("keystore build 失败");

    // 输出 keystore JSON
    let json = serde_json::to_string_pretty(&keystore).unwrap();
    println!("{}", json);

    // // 保存 keystore
    // let mut file = std::fs::File("examples/keystore1.json").unwrap();
    // file.write_all(json.as_bytes()).unwrap();

    //  解密获得keypair
    let keypair = keystore
        .decrypt_keypair(password.as_ref())
        .map_err(|e| format!("Failed to decrypt keystore {:?}", e))?;

    let pubkey = keypair.pk.clone();
    println!("pubkey: {}", pubkey.as_hex_string());


    Ok(())

}







// // 运行命令 cargo run -p deposit_cli
// #[tokio::main]
// async fn main() -> Result<(), SdkError> {
//     // 公司测试网质押地址
//     let rpc = "https://testrpc.n42.world";
//     let private_key  = "006ae52779c5a935d02b2d7eab3e01ef9cba11fa068edbcb529a3e9673d8fb7e";
//     let deposit_contract_address = "0x29a625941FA7B43be23b4309CD76e4d1BE688429";
//
//     // 实例化 SDK
//     let sdk = EthStakingSdk::new(rpc, private_key, deposit_contract_address).await?;
//
//     // 质押数据 (通过 eth2.0-deposit-cli 生成)
//     let pubkey  = "849bba145a71dcfc283c682513c081667873b48df6743183a0048f654b73f74506c68e19504ddb6115965b6595724c16";
//     let creds   = "00d6e82b1eddbc48f735422c816c69da3a08d7dea79748e05d2faec5ad8222fb";
//     let signature     = "ad52f272da0ba1a18ef11d644b0d6b172efb113b0b9cf59f25d935e3eaef8c60069854e17f978ca949aa3abacc28eec4110b949acbb32091b83a3e575a4572ebdf13ee278d02a3601fda7cef6a7a8112595beaf9958f721ad2356f8cb2d4c3c0";
//     let data_root = "65a4eb5913e277ecad4c15106c792d6c9cb69aa4921dbe3595aa42aa80409422";
//
//     // 调用 deposit
//     let receipt = sdk.deposit(pubkey, creds, signature, data_root).await?;
//
//     println!("✅ 质押成功，tx_hash={:?}", receipt.transaction_hash);
//     Ok(())
// }

// // 运行命令 cargo run -p deposit_cli -- /Users/macbook/Desktop/wjh/work/N42-rs/crates/n42/deposit_sdk/src/deposit_data-1752484020.json
// #[tokio::main]
// async fn main() -> Result<(), SdkError> {
//     // 接受命令行参数：JSON 路径 2是判断是否加上了路径参数
//     let args: Vec<String> = env::args().collect();
//     if args.len() != 2 {
//         eprintln!("Usage: deposit_cli <deposit_data.json>");
//         std::process::exit(1);
//     }
//     let json_path = &args[1];
//     println!("📄 读取质押数据：{}", json_path);
//
//     let content = fs::read_to_string(json_path)
//         .map_err(|e| SdkError::Config(format!("读取文件失败: {}", e)))?;
//     let items: Vec<DepositData> = serde_json::from_str(&content)
//         .map_err(|e| SdkError::Config(format!("解析 JSON 失败: {}", e)))?;
//
//     // 取第一个条目,一共就一个
//     let data = items.get(0)
//         .ok_or_else(|| SdkError::Config("JSON 文件中没有质押项".into()))?;
//     println!("🔍 公钥前缀: {}...", &data.pubkey[..10]);  // 说明读取成功
//
//     let rpc = "https://testrpc.n42.world";
//     let private_key = "006ae52779c5a935d02b2d7eab3e01ef9cba11fa068edbcb529a3e9673d8fb7e";
//     let contract_address = "0x29a625941FA7B43be23b4309CD76e4d1BE688429";
//     let sdk = EthStakingSdk::new(rpc, private_key, contract_address).await?;
//
//     // 执行质押
//     let receipt = sdk.deposit(
//         &data.pubkey,
//         &data.withdrawal_credentials,
//         &data.signature,
//         &data.deposit_data_root,
//     ).await?;
//
//     println!("✅ 质押成功，tx_hash={:?}", receipt.transaction_hash);
//     Ok(())
// }