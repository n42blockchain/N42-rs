use std::fmt::{Debug, Formatter};
use std::time::{SystemTime};
use reth_consensus::{Consensus, ConsensusError};
use crate::apos::{AposError,APos,EXTRA_VANITY,NONCE_AUTH_VOTE,NONCE_DROP_VOTE,DIFF_IN_TURN,DIFF_NO_TURN};
use reth_primitives::{
    proofs, Block, BlockBody, BlockWithSenders, Header, SealedBlock, SealedHeader,
};
use alloy_primitives::{U256};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_evm::provider::EvmEnvProvider;
use reth_storage_api::{BlockReader, HeaderProvider, SnapshotProvider, SnapshotProviderWriter, StateProviderFactory};

