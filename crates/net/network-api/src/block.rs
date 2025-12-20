use std::collections::HashSet;
use alloy_primitives::{BlockHash, TxHash, B256};
use derive_more::Error;
use reth_errors::BlockExecutionError;
use reth_eth_wire_types::NewBlock;
use reth_tokio_util::EventStream;
use reth_consensus::ConsensusError;

/// block import error.
#[derive(Debug, Clone)]
pub struct N42BlockImportOutcome<B> {
    /// The block hash that caused the error.
    pub hash: BlockHash,

    /// The result after validating the block
    pub result: Result<NewBlock<B>, N42BlockImportError>
}


/// Represents the specific error type within a block error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum N42BlockImportError {
    /// The block encountered a validation error.
    #[error(transparent)]
    Validation(#[from] ConsensusError),
    // The block encountered an execution error.
    // #[error(transparent)]
    // Execution(#[from] BlockExecutionError),
}


/// Provides client for downloading blocks.
#[auto_impl::auto_impl(&, Arc)]
pub trait BlockAnnounceProvider {
    type Block;
    /// Announce a block over devp2p
    fn announce_block(&self, block: NewBlock<Self::Block>, hash: B256);

    /// subscribe a new [`NewBlock`] listener channel.
    fn subscribe_block(&self) -> EventStream<NewBlock<Self::Block>>;

    fn validated_block(&self, result: N42BlockImportOutcome<Self::Block>);

}
