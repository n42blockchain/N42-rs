use deposit_sdk::{EthStakingSdk, SdkError, DEPOSIT_CONTRACT_ADDRESS};

/// cargo run -p deposit_sdk --example exit_test
#[tokio::main]
async fn main() -> Result<(), SdkError> {
    // 必须使用支持 EIP-7002 的网络的 RPC (例如 Sepolia 测试网)
    let rpc = "https://testrpc.n42.world";
    // let rpc = "https://eth-sepolia.g.alchemy.com/v2/aXuir_dKa9BeC6-kZ-V2yetNYs7y-b4P";
    // 这个私钥对应的账户支付发起退出交易的 Gas 费
    let caller_private_key = "006ae52779c5a935d02b2d7eab3e01ef9cba11fa068edbcb529a3e9673d8fb7e";
    let deposit_contract_address = DEPOSIT_CONTRACT_ADDRESS;

    // 要退出的验证者的公钥
    let validator_to_exit_pubkey = "aa1a1c26055a329817a5759d877a2795f9499b97d6056edde0eea39512f24e8bc874b4471f0501127abb1ea0d9f68ac1";

    println!("正在实例化 Staking SDK...");
    let sdk = EthStakingSdk::new(rpc, caller_private_key, deposit_contract_address).await?;

    println!("\n即将为验证者 {} 发起退出...", validator_to_exit_pubkey);

    match sdk.request_exit(validator_to_exit_pubkey).await {
        Ok(receipt) => {
            println!("\n🎉 成功！退出请求已提交。");
            println!("   - 交易哈希: 0x{}", hex::encode(receipt.transaction_hash));
            println!("   - 区块号: {}", receipt.block_number.unwrap_or_default());
            println!("\n重要提示：这仅代表退出请求已上链，资金到账需要等待共识层处理，请在 Beaconcha.in 等浏览器上跟踪验证者状态。");
        }
        Err(e) => {
            eprintln!("\n❌ 操作失败: {}", e);
        }
    }

    Ok(())
}