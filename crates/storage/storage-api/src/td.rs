use alloy_primitives::{BlockHash, U256};
use reth_storage_errors::provider::ProviderResult;

pub trait TdProvider{
    /// get td by block hash
    fn load_td(&self, block_hash: &BlockHash) -> ProviderResult<Option<U256>>;
}

pub trait TdProviderWriter{
    /// save td
    fn save_td(&self, block_hash: &BlockHash, td: U256) -> ProviderResult<()>;
}

