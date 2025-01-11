use alloy_primitives::B256;
use reth_eth_wire_types::NewBlock;

/// Provides client for downloading blocks.
#[auto_impl::auto_impl(&, Arc)]
pub trait BlockAnnounceProvider {
    /// Announce a block over devp2p
    fn announce_block(&self, block: NewBlock, hash: B256);
}
