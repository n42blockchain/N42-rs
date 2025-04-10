use reth_primitives::Verifiers;
use alloy_eips::BlockHashOrNumber;
use reth_storage_errors::provider::ProviderResult;
/// lytest
pub trait VerifiersProvider:Send+Sync{
    /// lytest
    fn verifiers_by_block(&self,id:BlockHashOrNumber,timestamp:u64,)->ProviderResult<Option<Verifiers>>;
}