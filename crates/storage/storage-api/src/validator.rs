use auto_impl::auto_impl;
use alloy_primitives::Address;
use reth_storage_errors::provider::ProviderResult;
use n42_primitives::{Validator,ValidatorChangeset,ValidatorBeforeTx};
use std::ops::RangeInclusive;
use alloy_primitives::BlockNumber;
/// Validator reader
#[auto_impl(&, Arc, Box)]
pub trait ValidatorReader: Send + Sync {
    fn basic_validator(&self, address: Address) -> ProviderResult<Option<Validator>>;
}
pub trait ValidatorChangeWriter{
    fn unwind_validator(&self, range: RangeInclusive<BlockNumber>) -> ProviderResult<()>;
    fn write_validator_changes(&self,changes: ValidatorChangeset) -> ProviderResult<()>;
    fn remove_validator(&self, range: RangeInclusive<BlockNumber>) -> ProviderResult<()>;
    fn take_validator(&mut self, range: RangeInclusive<BlockNumber>) -> ProviderResult<ValidatorChangeset>;
    fn unwind_validator_history_indices<'a>(&self, changesets: impl Iterator<Item = &'a (BlockNumber, ValidatorBeforeTx)>,) -> ProviderResult<usize>;
}