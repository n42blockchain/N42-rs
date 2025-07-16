#![allow(missing_docs)]


pub mod deposit;

use ethers::{
    prelude::*,
    providers::{Middleware},
    signers::{Signer},

};
use std::str::FromStr;
use std::sync::Arc;
use url::ParseError;
use hex::FromHexError;
use thiserror::Error;
use ethers::middleware::SignerMiddleware;
use ethers::utils::WEI_IN_ETHER;
use ethers_signers::{LocalWallet, WalletError};
use serde::Deserialize;
use crate::DepositContract;
use n42_withdrawals::crypto::{PublicKeyBytes, SignatureBytes};
use n42_withdrawals::Hash256;

// 读取指定的质押abi文件，创建一个叫DepositContract的rust模块，DepositContract::new(address, client) 来实例化它
abigen
!(
    DepositContract,
    "src/deposit.json",
    event_derives(serde::Deserialize, serde::Serialize)
);


#[derive(Debug, Error)]
pub enum SdkError {
    #[error("配置错误: {0}")]
    Config(String),

    #[error("URL 解析失败: {0}")]
    Url(#[from] ParseError),

    #[error("Provider 错误: {0}")]
    Provider(#[from] ProviderError),

    #[error("Wallet 错误: {0}")]
    Wallet(#[from] WalletError),

    #[error("合约调用错误: {0}")]
    Contract(String),

    #[error("Hex 解码失败: {0}")]
    Hex(#[from] FromHexError),

    #[error("交易被丢弃或失败")]
    TransactionDropped,
}

// 从 ContractError 转成我们的 String 变体
impl From<ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>> for SdkError {
    fn from(e: ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>) -> Self {
        SdkError::Contract(e.to_string())
    }
}

// 序列化时字段名对应到json字段名
#[derive(Deserialize, Debug)]
pub struct DepositData {
    pub pubkey: PublicKeyBytes,
    #[serde(rename = "withdrawal_credentials")]
    pub withdrawal_credentials: Hash256,
    pub signature: SignatureBytes,
    #[serde(rename = "deposit_data_root")]
    pub deposit_data_root: Hash256,
}

pub struct EthStakingSdk {
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    contract: DepositContract<SignerMiddleware<Provider<Http>, LocalWallet>>,
}

impl EthStakingSdk {
    /// 新建一个 sdk 实例
    pub async fn new(
        rpc_url: &str,
        private_key_hex: &str,
        contract_address: &str,
    ) -> Result<Self, SdkError> {
        // 解析url 连接到执行层节点
        let provider = Provider::<Http>::try_from(rpc_url)?;
        // 获取当前的链id
        let chain_id = provider.get_chainid().await?.as_u64();

        // 用私钥创建一个钱包
        let wallet = LocalWallet::from_str(private_key_hex)?
            .with_chain_id(chain_id);

        // 用provider和钱包客户端
        let client = SignerMiddleware::new(provider, wallet);
        let client = Arc::new(client);

        // 解析合约地址
        let address = Address::from_str(contract_address)
            .map_err(|e| SdkError::Config(format!("合约地址解析失败: {}", e)))?;

        // 生成合约实例
        let contract = DepositContract::new(address, client.clone());

        Ok(Self { client, contract })
    }

    /// 向存款合约发送 32 ETH 完成质押
    pub async fn deposit(
        &self,
        validator_pubkey_hex: &str,
        withdrawal_credentials_hex: &str,
        signature_hex: &str,
        deposit_data_root_hex: &str,
    ) -> Result<TransactionReceipt, SdkError> {
        // 把hex -> 二进制格式
        let pubkey = Bytes::from(hex::decode(validator_pubkey_hex)?);
        let creds  = Bytes::from(hex::decode(withdrawal_credentials_hex)?);
        let sig    = Bytes::from(hex::decode(signature_hex)?);
        let root: [u8; 32] = hex::decode(deposit_data_root_hex)?
            .try_into()
            .map_err(|_| SdkError::Config("deposit_data_root 必须是 32 字节".into()))?;

        // 计算 32ETH 的 wei 值
        let value = WEI_IN_ETHER.checked_mul(U256::from(32u64))
            .ok_or_else(|| SdkError::Config("价值计算溢出".into()))?;

        // 调用合约 deposit(...) 并发送 32 ETH
        let mut call = self
            .contract
            .deposit(pubkey, creds, sig, root)
            .value(value);

        let pending_tx = call.send().await?;

        // 等待区块确认
        let receipt = pending_tx
            .await?
            .ok_or(SdkError::TransactionDropped)?;
        Ok(receipt)
    }
}