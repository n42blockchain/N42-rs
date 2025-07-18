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
use serde::{Deserialize, Serialize};
use crate::DepositContract;
use keystore::blst::{PublicKeyBytes, SecretKey, SignatureBytes};
use keystore::Hash256;
use n42_withdrawals::withdrawal::SignedRoot;
use tree_hash_derive::TreeHash;
use n42_withdrawals::chain_spec::ChainSpec;


// 读取指定的质押abi文件，创建一个叫DepositContract的rust模块，DepositContract::new(address, client) 来实例化它
abigen!(
    DepositContract,
    "src/deposit.json",
    event_derives(serde::Deserialize, serde::Serialize)
);

abigen!(
    Eip7002Contract,
    "src/eip7002_contract.json",
);

/// 质押合约地址 公司的
pub const DEPOSIT_CONTRACT_ADDRESS: &str = "0x29a625941FA7B43be23b4309CD76e4d1BE688429";
/// 退出合约地址 公司的
pub const EIP7002_CONTRACT_ADDRESS: &str = "0xEFf1e899B6460dC7aBca481798C52638993595D6";
// /// 质押合约地址 eth的
// pub const DEPOSIT_CONTRACT_ADDRESS: &str = "0x00000000219ab540356cbb839cbe05303d7705fa";
// /// 退出合约地址 eth的
// pub const EIP7002_CONTRACT_ADDRESS: &str = "0x00000961Ef480Eb55e80D19ad83579A64c007002";

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
#[derive(Deserialize, Debug, TreeHash)]
pub struct DepositData {
    pub pubkey: PublicKeyBytes,
    #[serde(rename = "withdrawal_credentials")]
    pub withdrawal_credentials: Hash256,
    pub signature: SignatureBytes,
    #[serde(rename = "deposit_data_root")]
    // pub deposit_data_root: Hash256,
    pub amount: u64,
}
impl DepositData {
    pub fn as_deposit_message(&self) -> DepositMessage {
        DepositMessage {
            pubkey: self.pubkey,
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
        }
    }

    /// Generate the signature for a given DepositData details.
    pub fn create_signature(&self, secret_key: &SecretKey, spec: &ChainSpec) -> SignatureBytes {
        // println!("create_signature");
        let domain = spec.get_deposit_domain();
        // println!("domain: 0x{}", hex::encode(domain));
        let msg = self.as_deposit_message().signing_root(domain);
        // println!("signing_root: 0x{}", hex::encode(msg));
        SignatureBytes::from(secret_key.sign(msg))
    }
}

#[derive(TreeHash, Serialize, Deserialize,)]
pub struct DepositMessage {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}
impl SignedRoot for DepositMessage {}



pub struct EthStakingSdk {
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    deposit_contract: DepositContract<SignerMiddleware<Provider<Http>, LocalWallet>>,
    exit_contract: Eip7002Contract<SignerMiddleware<Provider<Http>, LocalWallet>>,
}

impl EthStakingSdk {
    /// 新建一个 sdk 实例
    pub async fn new(
        rpc_url: &str,
        private_key_hex: &str,
        deposit_contract_address: &str,
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

        // 解析质押合约地址
        let deposit_address = Address::from_str(deposit_contract_address)
            .map_err(|e| SdkError::Config(format!("存款合约地址解析失败: {}", e)))?;
        let deposit_contract = DepositContract::new(deposit_address, client.clone());

        // 解析退出合约
        let exit_address = Address::from_str(EIP7002_CONTRACT_ADDRESS)
            .map_err(|e| SdkError::Config(format!("EIP-7002 合约地址解析失败: {}", e)))?;
        let exit_contract = Eip7002Contract::new(exit_address, client.clone());


        Ok(Self { client, deposit_contract, exit_contract})
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
        let call = self
            .deposit_contract
            .deposit(pubkey, creds, sig, root)
            .value(value);

        let pending_tx = call.send().await?;

        // 等待区块确认
        let receipt = pending_tx
            .await?
            .ok_or(SdkError::TransactionDropped)?;
        Ok(receipt)
    }
    pub async fn request_exit(
        &self,
        validator_pubkey_hex: &str,
    ) -> Result<TransactionReceipt, SdkError> {
        println!("🚀 正在为验证者 {}... 发起退出请求", &validator_pubkey_hex[..10]);

        // 1. 将公钥的十六进制字符串转换为 48 字节数组
        let pubkey_bytes: [u8; 48] = hex::decode(validator_pubkey_hex)?
            .try_into()
            .map_err(|_| SdkError::Config("validator_pubkey 必须是 48 字节".into()))?;

        // 2. 构建合约调用
        let call = self.exit_contract.withdraw_validator(pubkey_bytes);

        // 发送交易
        let pending_tx = call.send().await?;
        println!("交易已发送，等待确认... Tx Hash: {:?}", pending_tx.tx_hash());

        let receipt = pending_tx
            .await?
            .ok_or(SdkError::TransactionDropped)?;

        println!("✅ 退出请求已成功上链！Block: {}", receipt.block_number.unwrap_or_default());

        Ok(receipt)
    }
}