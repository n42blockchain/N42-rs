use crate::{EthStakingSdk, SdkError};
use keystore::{Hash256, Address};

#[tokio::main]
async fn main() -> Result<(), SdkError> {
    // 配置部分
    let rpc = "https://rpc.sepolia.org";    // 执行层节点
    let private_key  = "006ae52779c5a935d02b2d7eab3e01ef9cba11fa068edbcb529a3e9673d8fb7e";
    let deposit_contract_address = "0x00000000219ab540356cbb839cbe05303d7705fa";

    // 实例化 SDK
    let sdk = EthStakingSdk::new(rpc, private_key, deposit_contract_address).await?;

    // 质押数据 (通过 eth2.0-deposit-cli 生成)
    let pubkey  = "849bba145a71dcfc283c682513c081667873b48df6743183a0048f654b73f74506c68e19504ddb6115965b6595724c16";
    let creds   = "00d6e82b1eddbc48f735422c816c69da3a08d7dea79748e05d2faec5ad8222fb";
    let signature     = "ad52f272da0ba1a18ef11d644b0d6b172efb113b0b9cf59f25d935e3eaef8c60069854e17f978ca949aa3abacc28eec4110b949acbb32091b83a3e575a4572ebdf13ee278d02a3601fda7cef6a7a8112595beaf9958f721ad2356f8cb2d4c3c0";
    let data_root = "65a4eb5913e277ecad4c15106c792d6c9cb69aa4921dbe3595aa42aa80409422";

    // 调用 deposit
    let receipt = sdk.deposit(pubkey, creds, signature, data_root).await?;

    println!("✅ 质押成功，tx_hash={:?}", receipt.transaction_hash);
    Ok(())
}

// 提现凭证的生成
pub fn withdrawal_credentials(withdrawal_address: Address) -> Hash256 {
    let mut credentials = [0u8; 32];
    credentials[0] = 0x01;
    credentials[12..].copy_from_slice(withdrawal_address.as_slice());
    Hash256::from(credentials)
}