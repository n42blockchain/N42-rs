use keystore::keystore::{keypair_from_secret, KeystoreBuilder, PlainText};
use std::fs::File;
use std::io::Write;

fn main() {
    // 定义一个非0的密钥， 钱包解密而来
    let secret = PlainText::from(vec![1u8; 32]);

    // 生成 keypair
    let keypair = keypair_from_secret(secret.as_bytes()).expect("keypair_from_secret 失败");

    // 生成 keystore
    let password = b"test-password";
    // 密钥派生路径
    let path = "m/12381/3600/0/0/0".to_string();

    let keystore = KeystoreBuilder::new(&keypair, password, path)
        .expect("KeystoreBuilder::new 失败")
        .build()
        .expect("keystore build 失败");

    // 输出 keystore JSON
    let json = serde_json::to_string_pretty(&keystore).unwrap();
    println!("{}", json);

    // 保存 keystore
    let mut file = File::create("examples/keystore1.json").unwrap();
    file.write_all(json.as_bytes()).unwrap();
}