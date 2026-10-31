// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's chain spec: reth's [`ChainSpec`] with [`N42Header`] as the
//! header type.
//!
//! reth requires `NodeTypes::ChainSpec: EthChainSpec<Header = HeaderTy<_>>`,
//! so a node whose header is [`N42Header`] needs a chain spec whose genesis
//! header is one. This wraps the parsed [`ChainSpec`] instead of forking it
//! generic: everything but the genesis header is read from the inner spec
//! (which the CLI, the `init`/`db` commands and the QMDB helpers keep using),
//! and the genesis header is the inner one without a registry root, so its
//! hash is the same.

use crate::N42Header;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use alloy_eips::{eip1559::BaseFeeParams, eip7840::BlobParams};
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, U256};
use core::fmt::Display;
use reth_chainspec::{
    Chain, ChainSpec, DepositContract, EthChainSpec, EthereumHardfork, EthereumHardforks, ForkCondition, ForkFilter,
    ForkId, Hardfork, Hardforks, Head,
};
use reth_network_peers::NodeRecord;
use reth_primitives_traits::SealedHeader;

/// reth's [`ChainSpec`] with an [`N42Header`] genesis header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N42ChainSpec {
    inner: Arc<ChainSpec>,
    genesis_header: SealedHeader<N42Header>,
}

impl N42ChainSpec {
    /// Wraps `inner`. The genesis header carries no registry root.
    pub fn new(inner: Arc<ChainSpec>) -> Self {
        let genesis_header = crate::seal_from_alloy(inner.sealed_genesis_header());
        Self { inner, genesis_header }
    }

    /// The wrapped Ethereum-header chain spec.
    pub const fn inner(&self) -> &Arc<ChainSpec> {
        &self.inner
    }

    /// The sealed genesis header.
    pub fn sealed_genesis_header(&self) -> SealedHeader<N42Header> {
        self.genesis_header.clone()
    }

    /// Whether a header at `timestamp` carries the slot number
    /// ([`reth_chainspec::qmdb::glamsterdam_active_at`]).
    pub fn glamsterdam_active_at(&self, timestamp: u64) -> bool {
        reth_chainspec::qmdb::glamsterdam_active_at(self.inner.genesis(), timestamp)
    }

    /// Whether a header at `timestamp` carries `mobileRegistryRoot`
    /// ([`reth_chainspec::qmdb::mobile_registry_root_in_header_at`]).
    pub fn mobile_registry_root_in_header_at(&self, timestamp: u64) -> bool {
        reth_chainspec::qmdb::mobile_registry_root_in_header_at(self.inner.genesis(), timestamp)
    }
}

impl From<Arc<ChainSpec>> for N42ChainSpec {
    fn from(inner: Arc<ChainSpec>) -> Self {
        Self::new(inner)
    }
}

impl From<ChainSpec> for N42ChainSpec {
    fn from(inner: ChainSpec) -> Self {
        Self::new(Arc::new(inner))
    }
}

impl core::ops::Deref for N42ChainSpec {
    type Target = ChainSpec;

    fn deref(&self) -> &ChainSpec {
        &self.inner
    }
}

impl EthChainSpec for N42ChainSpec {
    type Header = N42Header;

    fn chain(&self) -> Chain {
        self.inner.chain
    }

    fn base_fee_params_at_block(&self, block_number: u64) -> BaseFeeParams {
        EthChainSpec::base_fee_params_at_block(&*self.inner, block_number)
    }

    fn base_fee_params_at_timestamp(&self, timestamp: u64) -> BaseFeeParams {
        EthChainSpec::base_fee_params_at_timestamp(&*self.inner, timestamp)
    }

    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        EthChainSpec::blob_params_at_timestamp(&*self.inner, timestamp)
    }

    fn deposit_contract(&self) -> Option<&DepositContract> {
        EthChainSpec::deposit_contract(&*self.inner)
    }

    fn genesis_hash(&self) -> B256 {
        self.genesis_header.hash()
    }

    fn prune_delete_limit(&self) -> usize {
        EthChainSpec::prune_delete_limit(&*self.inner)
    }

    fn display_hardforks(&self) -> Box<dyn Display> {
        EthChainSpec::display_hardforks(&*self.inner)
    }

    fn genesis_header(&self) -> &N42Header {
        self.genesis_header.header()
    }

    fn genesis(&self) -> &Genesis {
        EthChainSpec::genesis(&*self.inner)
    }

    fn bootnodes(&self) -> Option<Vec<NodeRecord>> {
        EthChainSpec::bootnodes(&*self.inner)
    }

    fn is_optimism(&self) -> bool {
        EthChainSpec::is_optimism(&*self.inner)
    }

    fn final_paris_total_difficulty(&self) -> Option<U256> {
        EthChainSpec::final_paris_total_difficulty(&*self.inner)
    }

    fn is_n42_attestation_mandatory(&self, timestamp: u64) -> bool {
        EthChainSpec::is_n42_attestation_mandatory(&*self.inner, timestamp)
    }
}

impl Hardforks for N42ChainSpec {
    fn fork<H: Hardfork>(&self, fork: H) -> ForkCondition {
        Hardforks::fork(&*self.inner, fork)
    }

    fn forks_iter(&self) -> impl Iterator<Item = (&dyn Hardfork, ForkCondition)> {
        Hardforks::forks_iter(&*self.inner)
    }

    fn fork_id(&self, head: &Head) -> ForkId {
        Hardforks::fork_id(&*self.inner, head)
    }

    fn latest_fork_id(&self) -> ForkId {
        Hardforks::latest_fork_id(&*self.inner)
    }

    fn fork_filter(&self, head: Head) -> ForkFilter {
        Hardforks::fork_filter(&*self.inner, head)
    }
}

impl EthereumHardforks for N42ChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        EthereumHardforks::ethereum_fork_activation(&*self.inner, fork)
    }
}

impl alloy_evm::eth::spec::EthExecutorSpec for N42ChainSpec {
    fn deposit_contract_address(&self) -> Option<Address> {
        alloy_evm::eth::spec::EthExecutorSpec::deposit_contract_address(&*self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_genesis_hash_is_the_inner_specs() {
        for spec in [reth_chainspec::MAINNET.clone(), reth_chainspec::N42_DEVNET.clone()] {
            let n42 = N42ChainSpec::new(spec.clone());
            assert_eq!(EthChainSpec::genesis_hash(&n42), spec.genesis_hash());
            assert_eq!(n42.sealed_genesis_header().hash_slow(), spec.genesis_hash());
            assert_eq!(n42.genesis_header().mobile_registry_root, None);
            assert_eq!(n42.latest_fork_id(), spec.latest_fork_id());
        }
    }
}
