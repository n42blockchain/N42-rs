use auto_impl::auto_impl;
use alloy_primitives::Address;
use reth_storage_errors::provider::ProviderResult;
use n42_primitives::{Validator,ValidatorChangeset,ValidatorBeforeTx,ValidatorRevert};
use std::ops::RangeInclusive;
use alloy_primitives::BlockNumber;
use std::collections::BTreeMap;
/// Validator reader
#[auto_impl(&, Arc, Box)]
pub trait ValidatorReader: Send + Sync {
    fn basic_validator(&self, address: Address) -> ProviderResult<Option<Validator>>;
    fn changed_validators_and_blocks_with_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<BTreeMap<Address, Vec<BlockNumber>>>;
}

#[auto_impl(&, Arc, Box)]
pub trait ValidatorChangeWriter{
    fn write_validator_reverts(&self,first_block:BlockNumber,validator_reverts:ValidatorRevert,)->ProviderResult<()>;
    fn insert_validator_history_index(&self,validator_transitions:impl IntoIterator<Item=(Address,impl IntoIterator<Item=BlockNumber>)>,) -> ProviderResult<()>;
    fn unwind_validator(&self, range: RangeInclusive<BlockNumber>) -> ProviderResult<()>;
    fn write_validator_changes(&self,changes: ValidatorChangeset) -> ProviderResult<()>;
    fn remove_validator(&self, range: RangeInclusive<BlockNumber>) -> ProviderResult<()>;
    fn take_validator(&self, range: RangeInclusive<BlockNumber>) -> ProviderResult<ValidatorChangeset>;
    fn unwind_validator_history_indices<'a>(&self, changesets: impl Iterator<Item = &'a (BlockNumber, ValidatorBeforeTx)>,) -> ProviderResult<usize>;
}