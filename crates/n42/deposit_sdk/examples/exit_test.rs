use deposit_sdk::{EthStakingSdk, SdkError, DEPOSIT_CONTRACT_ADDRESS};
use ethers::types::H256;

/// cargo run -p deposit_sdk --example exit_test
#[tokio::main]
async fn main() -> Result<(), SdkError> {
    let rpc = "https://testrpc.n42.world";
    let caller_private_key = "006ae52779c5a935d02b2d7eab3e01ef9cba11fa068edbcb529a3e9673d8fb7e";

    let deposit_contract_address = DEPOSIT_CONTRACT_ADDRESS;

    let validator_to_exit_pubkey = "aa1a1c26055a329817a5759d877a2795f9499b97d6056edde0eea39512f24e8bc874b4471f0501127abb1ea0d9f68ac1";

    // --- 执行操作 ---
    println!("正在实例化 Staking SDK...");
    let sdk = EthStakingSdk::new(
        rpc,
        caller_private_key,
        deposit_contract_address,
    ).await?;

    println!("\n即将为验证者 {} 发起退出...", validator_to_exit_pubkey);

    match sdk.request_exit(validator_to_exit_pubkey).await {
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