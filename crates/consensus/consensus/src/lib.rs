// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

//! Consensus protocol functions

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{fmt::Debug, string::String, vec::Vec};
use alloy_consensus::Header;
use alloy_primitives::{Address, BlockHash, BlockNumber, Bloom, B256, U256};
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{
    constants::{MAXIMUM_GAS_LIMIT_BLOCK, MINIMUM_GAS_LIMIT},
    transaction::error::InvalidTransactionError,
    Block, GotExpected, GotExpectedBoxed, NodePrimitives, RecoveredBlock, SealedBlock,
    SealedHeader,
};

use alloc::collections::BTreeMap;
use core::time::Duration;
use n42_primitives::Snapshot;

/// A consensus implementation that does nothing.
pub mod noop;

#[cfg(any(test, feature = "test-utils"))]
/// test helpers for mocking consensus
pub mod test_utils;

/// [`Consensus`] implementation which knows full node primitives and is able to validation block's
/// execution outcome.
#[auto_impl::auto_impl(&, Arc)]
pub trait FullConsensus<N: NodePrimitives>: Consensus<N::Block> {
    /// Validate a block considering world state, i.e. things that can not be checked before
    /// execution.
    ///
    /// See the Yellow Paper sections 4.3.2 "Holistic Validity".
    ///
    /// Note: validating blocks does not include other validations of the Consensus
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<N::Block>,
        result: &BlockExecutionResult<N::Receipt>,
    ) -> Result<(), ConsensusError>;
}

/// Consensus is a protocol that chooses canonical chain.
#[auto_impl::auto_impl(&, Arc)]
pub trait Consensus<B: Block>: HeaderValidator<B::Header> {
    /// The error type related to consensus.
    type Error;

    /// Ensures that body field values match the header.
    fn validate_body_against_header(
        &self,
        body: &B::Body,
        header: &SealedHeader<B::Header>,
    ) -> Result<(), Self::Error>;

    /// Validate a block disregarding world state, i.e. things that can be checked before sender
    /// recovery and execution.
    ///
    /// See the Yellow Paper sections 4.3.2 "Holistic Validity", 4.3.4 "Block Header Validity", and
    /// 11.1 "Ommer Validation".
    ///
    /// **This should not be called for the genesis block**.
    ///
    /// Note: validating blocks does not include other validations of the Consensus
    fn validate_block_pre_execution(&self, block: &SealedBlock<B>) -> Result<(), Self::Error>;

    /// for N42
    fn prepare(&self, parent_header: &SealedHeader) -> Result<Header, ConsensusError> {
        Ok(Header::default())
    }

    /// for N42
    fn seal(&self, header: &mut Header) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn set_eth_signer_by_key(&self, eth_signer_key: Option<String>) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn get_eth_signer_address(&self) -> Result<Option<Address>, ConsensusError> {
        Ok(Some(Address::ZERO))
    }

    fn snapshot(
        &self,
        number: u64,
        hash: B256,
        parents: Option<Vec<Header>>,
    ) -> Result<Snapshot, ConsensusError> {
        Ok(Snapshot::default())
    }

    fn propose(&self, address: Address, auth: bool) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn discard(&self, address: Address) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn proposals(&self) -> Result<BTreeMap<Address, bool>, ConsensusError> {
        Ok(BTreeMap::new())
    }

    fn total_difficulty(&self, hash: B256) -> U256 {
        U256::from(0)
    }

    fn wiggle(&self, parent_number: u64, parent_hash: BlockHash, difficulty: U256) -> Duration {
        Duration::from_secs(0)
    }
}

/// HeaderValidator is a protocol that validates headers and their relationships.
#[auto_impl::auto_impl(&, Arc)]
pub trait HeaderValidator<H = Header>: Debug + Send + Sync {
    /// Validate if header is correct and follows consensus specification.
    ///
    /// This is called on standalone header to check if all hashes are correct.
    fn validate_header(&self, header: &SealedHeader<H>) -> Result<(), ConsensusError>;

    /// Validate that the header information regarding parent are correct.
    /// This checks the block number, timestamp, basefee and gas limit increment.
    ///
    /// This is called before properties that are not in the header itself (like total difficulty)
    /// have been computed.
    ///
    /// **This should not be called for the genesis block**.
    ///
    /// Note: Validating header against its parent does not include other HeaderValidator
    /// validations.
    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<H>,
        parent: &SealedHeader<H>,
    ) -> Result<(), ConsensusError>;

    /// Validates the given headers
    ///
    /// This ensures that the first header is valid on its own and all subsequent headers are valid
    /// on its own and valid against its parent.
    ///
    /// Note: this expects that the headers are in natural order (ascending block number)
    fn validate_header_range(
        &self,
        headers: &[SealedHeader<H>],
    ) -> Result<(), HeaderConsensusError<H>>
    where
        H: Clone,
    {
        if let Some((initial_header, remaining_headers)) = headers.split_first() {
            self.validate_header(initial_header)
                .map_err(|e| HeaderConsensusError(e, initial_header.clone()))?;
            let mut parent = initial_header;
            for child in remaining_headers {
                self.validate_header(child)
                    .map_err(|e| HeaderConsensusError(e, child.clone()))?;
                self.validate_header_against_parent(child, parent)
                    .map_err(|e| HeaderConsensusError(e, child.clone()))?;
                parent = child;
            }
        }
        Ok(())
    }
}

/// Consensus Errors
#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum ConsensusError {
    /// Error when the gas used in the header exceeds the gas limit.
    #[error("block used gas ({gas_used}) is greater than gas limit ({gas_limit})")]
    HeaderGasUsedExceedsGasLimit {
        /// The gas used in the block header.
        gas_used: u64,
        /// The gas limit in the block header.
        gas_limit: u64,
    },
    /// Error when the gas the gas limit is more than the maximum allowed.
    #[error(
        "header gas limit ({gas_limit}) exceed the maximum allowed gas limit ({MAXIMUM_GAS_LIMIT_BLOCK})"
    )]
    HeaderGasLimitExceedsMax {
        /// The gas limit in the block header.
        gas_limit: u64,
    },

    /// Error when block gas used doesn't match expected value
    #[error("block gas used mismatch: {gas}; gas spent by each transaction: {gas_spent_by_tx:?}")]
    BlockGasUsed {
        /// The gas diff.
        gas: GotExpected<u64>,
        /// Gas spent by each transaction
        gas_spent_by_tx: Vec<(u64, u64)>,
    },

    /// Error when the hash of block ommer is different from the expected hash.
    #[error("mismatched block ommer hash: {0}")]
    BodyOmmersHashDiff(GotExpectedBoxed<B256>),

    /// Error when the state root in the block is different from the expected state root.
    #[error("mismatched block state root: {0}")]
    BodyStateRootDiff(GotExpectedBoxed<B256>),

    /// Error when the transaction root in the block is different from the expected transaction
    /// root.
    #[error("mismatched block transaction root: {0}")]
    BodyTransactionRootDiff(GotExpectedBoxed<B256>),

    /// Error when the receipt root in the block is different from the expected receipt root.
    #[error("receipt root mismatch: {0}")]
    BodyReceiptRootDiff(GotExpectedBoxed<B256>),

    /// Error when header bloom filter is different from the expected bloom filter.
    #[error("header bloom filter mismatch: {0}")]
    BodyBloomLogDiff(GotExpectedBoxed<Bloom>),

    /// Error when the withdrawals root in the block is different from the expected withdrawals
    /// root.
    #[error("mismatched block withdrawals root: {0}")]
    BodyWithdrawalsRootDiff(GotExpectedBoxed<B256>),

    /// Error when the requests hash in the block is different from the expected requests
    /// hash.
    #[error("mismatched block requests hash: {0}")]
    BodyRequestsHashDiff(GotExpectedBoxed<B256>),

    /// Error when a block with a specific hash and number is already known.
    #[error("block with [hash={hash}, number={number}] is already known")]
    BlockKnown {
        /// The hash of the known block.
        hash: BlockHash,
        /// The block number of the known block.
        number: BlockNumber,
    },

    /// Error when the parent hash of a block is not known.
    #[error("block parent [hash={hash}] is not known")]
    ParentUnknown {
        /// The hash of the unknown parent block.
        hash: BlockHash,
    },

    /// Error when the block number does not match the parent block number.
    #[error(
        "block number {block_number} does not match parent block number {parent_block_number}"
    )]
    ParentBlockNumberMismatch {
        /// The parent block number.
        parent_block_number: BlockNumber,
        /// The block number.
        block_number: BlockNumber,
    },

    /// Error when the parent hash does not match the expected parent hash.
    #[error("mismatched parent hash: {0}")]
    ParentHashMismatch(GotExpectedBoxed<B256>),

    /// Error when the block timestamp is in the future compared to our clock time.
    #[error(
        "block timestamp {timestamp} is in the future compared to our clock time {present_timestamp}"
    )]
    TimestampIsInFuture {
        /// The block's timestamp.
        timestamp: u64,
        /// The current timestamp.
        present_timestamp: u64,
    },

    /// Error when the base fee is missing.
    #[error("base fee missing")]
    BaseFeeMissing,

    /// Error when there is a transaction signer recovery error.
    #[error("transaction signer recovery error")]
    TransactionSignerRecoveryError,

    /// Error when the extra data length exceeds the maximum allowed.
    #[error("extra data {len} exceeds max length")]
    ExtraDataExceedsMax {
        /// The length of the extra data.
        len: usize,
    },

    /// Error when the difficulty after a merge is not zero.
    #[error("difficulty after merge is not zero")]
    TheMergeDifficultyIsNotZero,

    /// Error when the nonce after a merge is not zero.
    #[error("nonce after merge is not zero")]
    TheMergeNonceIsNotZero,

    /// Error when the ommer root after a merge is not empty.
    #[error("ommer root after merge is not empty")]
    TheMergeOmmerRootIsNotEmpty,

    /// Error when the withdrawals root is missing.
    #[error("missing withdrawals root")]
    WithdrawalsRootMissing,

    /// Error when the requests hash is missing.
    #[error("missing requests hash")]
    RequestsHashMissing,

    /// Error when an unexpected withdrawals root is encountered.
    #[error("unexpected withdrawals root")]
    WithdrawalsRootUnexpected,

    /// Error when an unexpected requests hash is encountered.
    #[error("unexpected requests hash")]
    RequestsHashUnexpected,

    /// Error when withdrawals are missing.
    #[error("missing withdrawals")]
    BodyWithdrawalsMissing,

    /// Error when requests are missing.
    #[error("missing requests")]
    BodyRequestsMissing,

    /// Error when blob gas used is missing.
    #[error("missing blob gas used")]
    BlobGasUsedMissing,

    /// Error when unexpected blob gas used is encountered.
    #[error("unexpected blob gas used")]
    BlobGasUsedUnexpected,

    /// Error when excess blob gas is missing.
    #[error("missing excess blob gas")]
    ExcessBlobGasMissing,

    /// Error when unexpected excess blob gas is encountered.
    #[error("unexpected excess blob gas")]
    ExcessBlobGasUnexpected,

    /// Error when the parent beacon block root is missing.
    #[error("missing parent beacon block root")]
    ParentBeaconBlockRootMissing,

    /// Error when an unexpected parent beacon block root is encountered.
    #[error("unexpected parent beacon block root")]
    ParentBeaconBlockRootUnexpected,

    /// Error when blob gas used exceeds the maximum allowed.
    #[error("blob gas used {blob_gas_used} exceeds maximum allowance {max_blob_gas_per_block}")]
    BlobGasUsedExceedsMaxBlobGasPerBlock {
        /// The actual blob gas used.
        blob_gas_used: u64,
        /// The maximum allowed blob gas per block.
        max_blob_gas_per_block: u64,
    },

    /// Error when blob gas used is not a multiple of blob gas per blob.
    #[error(
        "blob gas used {blob_gas_used} is not a multiple of blob gas per blob {blob_gas_per_blob}"
    )]
    BlobGasUsedNotMultipleOfBlobGasPerBlob {
        /// The actual blob gas used.
        blob_gas_used: u64,
        /// The blob gas per blob.
        blob_gas_per_blob: u64,
    },

    /// Error when excess blob gas is not a multiple of blob gas per blob.
    #[error(
        "excess blob gas {excess_blob_gas} is not a multiple of blob gas per blob {blob_gas_per_blob}"
    )]
    ExcessBlobGasNotMultipleOfBlobGasPerBlob {
        /// The actual excess blob gas.
        excess_blob_gas: u64,
        /// The blob gas per blob.
        blob_gas_per_blob: u64,
    },

    /// Error when the blob gas used in the header does not match the expected blob gas used.
    #[error("blob gas used mismatch: {0}")]
    BlobGasUsedDiff(GotExpected<u64>),

    /// Error for a transaction that violates consensus.
    #[error(transparent)]
    InvalidTransaction(InvalidTransactionError),

    /// Error when the block's base fee is different from the expected base fee.
    #[error("block base fee mismatch: {0}")]
    BaseFeeDiff(GotExpected<u64>),

    /// Error when there is an invalid excess blob gas.
    #[error(
        "invalid excess blob gas: {diff}; \
            parent excess blob gas: {parent_excess_blob_gas}, \
            parent blob gas used: {parent_blob_gas_used}"
    )]
    ExcessBlobGasDiff {
        /// The excess blob gas diff.
        diff: GotExpected<u64>,
        /// The parent excess blob gas.
        parent_excess_blob_gas: u64,
        /// The parent blob gas used.
        parent_blob_gas_used: u64,
    },

    /// Error when the child gas limit exceeds the maximum allowed increase.
    #[error("child gas_limit {child_gas_limit} max increase is {parent_gas_limit}/1024")]
    GasLimitInvalidIncrease {
        /// The parent gas limit.
        parent_gas_limit: u64,
        /// The child gas limit.
        child_gas_limit: u64,
    },

    /// Error indicating that the child gas limit is below the minimum allowed limit.
    ///
    /// This error occurs when the child gas limit is less than the specified minimum gas limit.
    #[error(
        "child gas limit {child_gas_limit} is below the minimum allowed limit ({MINIMUM_GAS_LIMIT})"
    )]
    GasLimitInvalidMinimum {
        /// The child gas limit.
        child_gas_limit: u64,
    },

    /// Error indicating that the block gas limit is above the allowed maximum.
    ///
    /// This error occurs when the gas limit is more than the specified maximum gas limit.
    #[error("child gas limit {block_gas_limit} is above the maximum allowed limit ({MAXIMUM_GAS_LIMIT_BLOCK})")]
    GasLimitInvalidBlockMaximum {
        /// block gas limit.
        block_gas_limit: u64,
    },

    /// Error when the child gas limit exceeds the maximum allowed decrease.
    #[error("child gas_limit {child_gas_limit} max decrease is {parent_gas_limit}/1024")]
    GasLimitInvalidDecrease {
        /// The parent gas limit.
        parent_gas_limit: u64,
        /// The child gas limit.
        child_gas_limit: u64,
    },

    /// Error when the block timestamp is in the past compared to the parent timestamp.
    #[error(
        "block timestamp {timestamp} is in the past compared to the parent timestamp {parent_timestamp}"
    )]
    TimestampIsInPast {
        /// The parent block's timestamp.
        parent_timestamp: u64,
        /// The block's timestamp.
        timestamp: u64,
    },
    // for N42
    #[error("unknown block")]
    UnknownBlock,
    #[error("beneficiary in checkpoint block non-zero")]
    InvalidCheckpointBeneficiary,
    #[error("vote nonce not 0x00..0 or 0xff..f")]
    InvalidVote,
    #[error("vote nonce in checkpoint block non-zero")]
    InvalidCheckpointVote,
    #[error("extra-data 32 byte vanity prefix missing")]
    MissingVanity,
    #[error("extra-data 65 byte signature suffix missing")]
    MissingSignature,
    #[error("non-checkpoint block contains extra signer list")]
    ErrExtraSigners,
    #[error("invalid signer list on checkpoint block")]
    InvalidCheckpointSigners,
    #[error("invalid difficulty")]
    InvalidDifficulty,
    #[error("unauthorized signer")]
    UnauthorizedSigner,
    #[error("recently signed")]
    RecentlySigned,
    #[error("sign header err")]
    SignHeaderError,
    #[error("save snapshot err")]
    SaveSnapshotError,
    #[error("no signer set")]
    NoSignerSet,
    #[error("apos error detail {detail}")]
    AposErrorDetail { detail: String },
    /// Other, likely an injected L2 error.
    #[error("{0}")]
    Other(String),
}

impl ConsensusError {
    /// Returns `true` if the error is a state root error.
    pub const fn is_state_root_error(&self) -> bool {
        matches!(self, Self::BodyStateRootDiff(_))
    }
}

impl From<InvalidTransactionError> for ConsensusError {
    fn from(value: InvalidTransactionError) -> Self {
        Self::InvalidTransaction(value)
    }
}

/// `HeaderConsensusError` combines a `ConsensusError` with the `SealedHeader` it relates to.
#[derive(thiserror::Error, Debug)]
#[error("Consensus error: {0}, Invalid header: {1:?}")]
pub struct HeaderConsensusError<H>(ConsensusError, SealedHeader<H>);

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{b256, Bloom, B256};
    use reth_primitives_traits::{GotExpected, GotExpectedBoxed};

    // ==================== ConsensusError Tests ====================

    #[test]
    fn test_consensus_error_gas_used_exceeds_limit() {
        let err = ConsensusError::HeaderGasUsedExceedsGasLimit {
            gas_used: 30_000_001,
            gas_limit: 30_000_000,
        };
        assert!(err.to_string().contains("30000001"));
        assert!(err.to_string().contains("30000000"));
    }

    #[test]
    fn test_consensus_error_gas_limit_exceeds_max() {
        let err = ConsensusError::HeaderGasLimitExceedsMax {
            gas_limit: u64::MAX,
        };
        assert!(err.to_string().contains("gas limit"));
    }

    #[test]
    fn test_consensus_error_block_gas_used() {
        let err = ConsensusError::BlockGasUsed {
            gas: GotExpected {
                got: 100,
                expected: 200,
            },
            gas_spent_by_tx: vec![(0, 50), (1, 50)],
        };
        assert!(err.to_string().contains("mismatch"));
    }

    #[test]
    fn test_consensus_error_body_ommers_hash_diff() {
        let hash1 = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let hash2 = b256!("0000000000000000000000000000000000000000000000000000000000000002");
        let err = ConsensusError::BodyOmmersHashDiff(GotExpectedBoxed::from(GotExpected {
            got: hash1,
            expected: hash2,
        }));
        assert!(err.to_string().contains("ommer"));
    }

    #[test]
    fn test_consensus_error_body_state_root_diff() {
        let hash1 = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let hash2 = b256!("0000000000000000000000000000000000000000000000000000000000000002");
        let err = ConsensusError::BodyStateRootDiff(GotExpectedBoxed::from(GotExpected {
            got: hash1,
            expected: hash2,
        }));
        assert!(err.is_state_root_error());
        assert!(err.to_string().contains("state root"));
    }

    #[test]
    fn test_consensus_error_body_transaction_root_diff() {
        let hash1 = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let hash2 = b256!("0000000000000000000000000000000000000000000000000000000000000002");
        let err = ConsensusError::BodyTransactionRootDiff(GotExpectedBoxed::from(GotExpected {
            got: hash1,
            expected: hash2,
        }));
        assert!(!err.is_state_root_error());
        assert!(err.to_string().contains("transaction root"));
    }

    #[test]
    fn test_consensus_error_body_receipt_root_diff() {
        let hash1 = B256::ZERO;
        let hash2 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let err = ConsensusError::BodyReceiptRootDiff(GotExpectedBoxed::from(GotExpected {
            got: hash1,
            expected: hash2,
        }));
        assert!(err.to_string().contains("receipt root"));
    }

    #[test]
    fn test_consensus_error_body_bloom_log_diff() {
        let bloom1 = Bloom::ZERO;
        let bloom2 = Bloom::ZERO;
        let err = ConsensusError::BodyBloomLogDiff(GotExpectedBoxed::from(GotExpected {
            got: bloom1,
            expected: bloom2,
        }));
        assert!(err.to_string().contains("bloom"));
    }

    #[test]
    fn test_consensus_error_body_withdrawals_root_diff() {
        let hash1 = B256::ZERO;
        let hash2 = B256::ZERO;
        let err = ConsensusError::BodyWithdrawalsRootDiff(GotExpectedBoxed::from(GotExpected {
            got: hash1,
            expected: hash2,
        }));
        assert!(err.to_string().contains("withdrawals root"));
    }

    #[test]
    fn test_consensus_error_body_requests_hash_diff() {
        let hash1 = B256::ZERO;
        let hash2 = B256::ZERO;
        let err = ConsensusError::BodyRequestsHashDiff(GotExpectedBoxed::from(GotExpected {
            got: hash1,
            expected: hash2,
        }));
        assert!(err.to_string().contains("requests hash"));
    }

    #[test]
    fn test_consensus_error_block_known() {
        let err = ConsensusError::BlockKnown {
            hash: B256::ZERO,
            number: 100,
        };
        assert!(err.to_string().contains("already known"));
        assert!(err.to_string().contains("100"));
    }

    #[test]
    fn test_consensus_error_parent_unknown() {
        let err = ConsensusError::ParentUnknown { hash: B256::ZERO };
        assert!(err.to_string().contains("parent"));
        assert!(err.to_string().contains("not known"));
    }

    #[test]
    fn test_consensus_error_parent_block_number_mismatch() {
        let err = ConsensusError::ParentBlockNumberMismatch {
            parent_block_number: 99,
            block_number: 101,
        };
        assert!(err.to_string().contains("99"));
        assert!(err.to_string().contains("101"));
    }

    #[test]
    fn test_consensus_error_parent_hash_mismatch() {
        let hash1 = B256::ZERO;
        let hash2 = B256::ZERO;
        let err = ConsensusError::ParentHashMismatch(GotExpectedBoxed::from(GotExpected {
            got: hash1,
            expected: hash2,
        }));
        assert!(err.to_string().contains("parent hash"));
    }

    #[test]
    fn test_consensus_error_timestamp_in_future() {
        let err = ConsensusError::TimestampIsInFuture {
            timestamp: 1000000,
            present_timestamp: 999999,
        };
        assert!(err.to_string().contains("future"));
    }

    #[test]
    fn test_consensus_error_timestamp_in_past() {
        let err = ConsensusError::TimestampIsInPast {
            parent_timestamp: 1000000,
            timestamp: 999999,
        };
        assert!(err.to_string().contains("past"));
    }

    #[test]
    fn test_consensus_error_base_fee_missing() {
        let err = ConsensusError::BaseFeeMissing;
        assert!(err.to_string().contains("base fee"));
    }

    #[test]
    fn test_consensus_error_transaction_signer_recovery() {
        let err = ConsensusError::TransactionSignerRecoveryError;
        assert!(err.to_string().contains("signer recovery"));
    }

    #[test]
    fn test_consensus_error_extra_data_exceeds_max() {
        let err = ConsensusError::ExtraDataExceedsMax { len: 1000 };
        assert!(err.to_string().contains("1000"));
    }

    #[test]
    fn test_consensus_error_merge_difficulty_not_zero() {
        let err = ConsensusError::TheMergeDifficultyIsNotZero;
        assert!(err.to_string().contains("difficulty"));
        assert!(err.to_string().contains("zero"));
    }

    #[test]
    fn test_consensus_error_merge_nonce_not_zero() {
        let err = ConsensusError::TheMergeNonceIsNotZero;
        assert!(err.to_string().contains("nonce"));
    }

    #[test]
    fn test_consensus_error_merge_ommer_root_not_empty() {
        let err = ConsensusError::TheMergeOmmerRootIsNotEmpty;
        assert!(err.to_string().contains("ommer root"));
    }

    #[test]
    fn test_consensus_error_withdrawals_root_missing() {
        let err = ConsensusError::WithdrawalsRootMissing;
        assert!(err.to_string().contains("withdrawals root"));
    }

    #[test]
    fn test_consensus_error_requests_hash_missing() {
        let err = ConsensusError::RequestsHashMissing;
        assert!(err.to_string().contains("requests hash"));
    }

    #[test]
    fn test_consensus_error_withdrawals_root_unexpected() {
        let err = ConsensusError::WithdrawalsRootUnexpected;
        assert!(err.to_string().contains("unexpected"));
    }

    #[test]
    fn test_consensus_error_requests_hash_unexpected() {
        let err = ConsensusError::RequestsHashUnexpected;
        assert!(err.to_string().contains("unexpected"));
    }

    #[test]
    fn test_consensus_error_body_withdrawals_missing() {
        let err = ConsensusError::BodyWithdrawalsMissing;
        assert!(err.to_string().contains("missing withdrawals"));
    }

    #[test]
    fn test_consensus_error_body_requests_missing() {
        let err = ConsensusError::BodyRequestsMissing;
        assert!(err.to_string().contains("missing requests"));
    }

    #[test]
    fn test_consensus_error_blob_gas_used_missing() {
        let err = ConsensusError::BlobGasUsedMissing;
        assert!(err.to_string().contains("blob gas"));
    }

    #[test]
    fn test_consensus_error_blob_gas_used_unexpected() {
        let err = ConsensusError::BlobGasUsedUnexpected;
        assert!(err.to_string().contains("unexpected"));
    }

    #[test]
    fn test_consensus_error_excess_blob_gas_missing() {
        let err = ConsensusError::ExcessBlobGasMissing;
        assert!(err.to_string().contains("excess blob gas"));
    }

    #[test]
    fn test_consensus_error_excess_blob_gas_unexpected() {
        let err = ConsensusError::ExcessBlobGasUnexpected;
        assert!(err.to_string().contains("unexpected"));
    }

    #[test]
    fn test_consensus_error_parent_beacon_block_root_missing() {
        let err = ConsensusError::ParentBeaconBlockRootMissing;
        assert!(err.to_string().contains("parent beacon block root"));
    }

    #[test]
    fn test_consensus_error_parent_beacon_block_root_unexpected() {
        let err = ConsensusError::ParentBeaconBlockRootUnexpected;
        assert!(err.to_string().contains("unexpected"));
    }

    #[test]
    fn test_consensus_error_blob_gas_used_exceeds_max() {
        let err = ConsensusError::BlobGasUsedExceedsMaxBlobGasPerBlock {
            blob_gas_used: 1000000,
            max_blob_gas_per_block: 500000,
        };
        assert!(err.to_string().contains("1000000"));
        assert!(err.to_string().contains("500000"));
    }

    #[test]
    fn test_consensus_error_blob_gas_used_not_multiple() {
        let err = ConsensusError::BlobGasUsedNotMultipleOfBlobGasPerBlob {
            blob_gas_used: 131073,
            blob_gas_per_blob: 131072,
        };
        assert!(err.to_string().contains("not a multiple"));
    }

    #[test]
    fn test_consensus_error_excess_blob_gas_not_multiple() {
        let err = ConsensusError::ExcessBlobGasNotMultipleOfBlobGasPerBlob {
            excess_blob_gas: 131073,
            blob_gas_per_blob: 131072,
        };
        assert!(err.to_string().contains("not a multiple"));
    }

    #[test]
    fn test_consensus_error_blob_gas_used_diff() {
        let err = ConsensusError::BlobGasUsedDiff(GotExpected {
            got: 100,
            expected: 200,
        });
        assert!(err.to_string().contains("mismatch"));
    }

    #[test]
    fn test_consensus_error_base_fee_diff() {
        let err = ConsensusError::BaseFeeDiff(GotExpected {
            got: 100,
            expected: 200,
        });
        assert!(err.to_string().contains("base fee"));
    }

    #[test]
    fn test_consensus_error_excess_blob_gas_diff() {
        let err = ConsensusError::ExcessBlobGasDiff {
            diff: GotExpected {
                got: 100,
                expected: 200,
            },
            parent_excess_blob_gas: 50,
            parent_blob_gas_used: 50,
        };
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn test_consensus_error_gas_limit_invalid_increase() {
        let err = ConsensusError::GasLimitInvalidIncrease {
            parent_gas_limit: 30_000_000,
            child_gas_limit: 31_000_000,
        };
        assert!(err.to_string().contains("increase"));
    }

    #[test]
    fn test_consensus_error_gas_limit_invalid_minimum() {
        let err = ConsensusError::GasLimitInvalidMinimum {
            child_gas_limit: 100,
        };
        assert!(err.to_string().contains("minimum"));
    }

    #[test]
    fn test_consensus_error_gas_limit_invalid_block_maximum() {
        let err = ConsensusError::GasLimitInvalidBlockMaximum {
            block_gas_limit: u64::MAX,
        };
        assert!(err.to_string().contains("maximum"));
    }

    #[test]
    fn test_consensus_error_gas_limit_invalid_decrease() {
        let err = ConsensusError::GasLimitInvalidDecrease {
            parent_gas_limit: 30_000_000,
            child_gas_limit: 29_000_000,
        };
        assert!(err.to_string().contains("decrease"));
    }

    // ==================== N42 Specific Error Tests ====================

    #[test]
    fn test_consensus_error_unknown_block() {
        let err = ConsensusError::UnknownBlock;
        assert!(err.to_string().contains("unknown block"));
    }

    #[test]
    fn test_consensus_error_invalid_checkpoint_beneficiary() {
        let err = ConsensusError::InvalidCheckpointBeneficiary;
        assert!(err.to_string().contains("checkpoint"));
        assert!(err.to_string().contains("beneficiary"));
    }

    #[test]
    fn test_consensus_error_invalid_vote() {
        let err = ConsensusError::InvalidVote;
        assert!(err.to_string().contains("vote nonce"));
    }

    #[test]
    fn test_consensus_error_invalid_checkpoint_vote() {
        let err = ConsensusError::InvalidCheckpointVote;
        assert!(err.to_string().contains("checkpoint"));
    }

    #[test]
    fn test_consensus_error_missing_vanity() {
        let err = ConsensusError::MissingVanity;
        assert!(err.to_string().contains("vanity"));
    }

    #[test]
    fn test_consensus_error_missing_signature() {
        let err = ConsensusError::MissingSignature;
        assert!(err.to_string().contains("signature"));
    }

    #[test]
    fn test_consensus_error_extra_signers() {
        let err = ConsensusError::ErrExtraSigners;
        assert!(err.to_string().contains("extra signer"));
    }

    #[test]
    fn test_consensus_error_invalid_checkpoint_signers() {
        let err = ConsensusError::InvalidCheckpointSigners;
        assert!(err.to_string().contains("signer list"));
    }

    #[test]
    fn test_consensus_error_invalid_difficulty() {
        let err = ConsensusError::InvalidDifficulty;
        assert!(err.to_string().contains("invalid difficulty"));
    }

    #[test]
    fn test_consensus_error_unauthorized_signer() {
        let err = ConsensusError::UnauthorizedSigner;
        assert!(err.to_string().contains("unauthorized"));
    }

    #[test]
    fn test_consensus_error_recently_signed() {
        let err = ConsensusError::RecentlySigned;
        assert!(err.to_string().contains("recently signed"));
    }

    #[test]
    fn test_consensus_error_sign_header_error() {
        let err = ConsensusError::SignHeaderError;
        assert!(err.to_string().contains("sign header"));
    }

    #[test]
    fn test_consensus_error_save_snapshot_error() {
        let err = ConsensusError::SaveSnapshotError;
        assert!(err.to_string().contains("save snapshot"));
    }

    #[test]
    fn test_consensus_error_no_signer_set() {
        let err = ConsensusError::NoSignerSet;
        assert!(err.to_string().contains("no signer"));
    }

    #[test]
    fn test_consensus_error_apos_error_detail() {
        let err = ConsensusError::AposErrorDetail {
            detail: "test error".to_string(),
        };
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_consensus_error_other() {
        let err = ConsensusError::Other("custom error".to_string());
        assert_eq!(err.to_string(), "custom error");
    }

    // ==================== ConsensusError Properties Tests ====================

    #[test]
    fn test_consensus_error_equality() {
        let err1 = ConsensusError::UnknownBlock;
        let err2 = ConsensusError::UnknownBlock;
        assert_eq!(err1, err2);
    }

    #[test]
    fn test_consensus_error_clone() {
        let err = ConsensusError::UnknownBlock;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_is_state_root_error_false_cases() {
        assert!(!ConsensusError::UnknownBlock.is_state_root_error());
        assert!(!ConsensusError::BaseFeeMissing.is_state_root_error());
        assert!(!ConsensusError::InvalidVote.is_state_root_error());
    }

    #[test]
    fn test_is_state_root_error_true_case() {
        let err = ConsensusError::BodyStateRootDiff(GotExpectedBoxed::from(GotExpected {
            got: B256::ZERO,
            expected: B256::ZERO,
        }));
        assert!(err.is_state_root_error());
    }
}
