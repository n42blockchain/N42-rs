// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42 APoS consensus trait definitions

use crate::AposResult;
use alloy_consensus::Header;
use alloy_primitives::{Address, BlockHash, B256, U256};
use hashbrown::HashMap;
use n42_primitives::Snapshot;
use reth_primitives_traits::SealedHeader;
use std::time::Duration;

/// APoS (Authority Proof of Stake) consensus extension trait.
///
/// This trait extends the base reth `Consensus` trait with N42-specific
/// functionality for the APoS consensus mechanism.
///
/// # Implementors
///
/// This trait should be implemented by consensus engines that support
/// the N42 APoS protocol, such as `APos` in `n42-clique`.
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait AposConsensus: Send + Sync {
    /// Prepare a new block header based on the parent header.
    ///
    /// This method is called before block production to initialize
    /// the header fields according to APoS rules.
    ///
    /// # Arguments
    /// * `parent_header` - The sealed parent block header
    ///
    /// # Returns
    /// A new header with APoS-specific fields initialized
    fn prepare(&self, parent_header: &SealedHeader) -> AposResult<Header>;

    /// Seal a block header with the signer's signature.
    ///
    /// This method adds the signature to the header's extra_data field,
    /// completing the block sealing process.
    ///
    /// # Arguments
    /// * `header` - The header to seal (modified in place)
    fn seal(&self, header: &mut Header) -> AposResult<()>;

    /// Validate a block header according to APoS rules.
    ///
    /// This performs APoS-specific validation beyond the standard
    /// Ethereum header validation.
    ///
    /// # Arguments
    /// * `header` - The header to validate
    /// * `parent` - The parent header
    fn validate_header(&self, header: &Header, parent: &Header) -> AposResult<()>;
}

/// Snapshot management for APoS consensus.
///
/// Snapshots capture the state of the signer set at specific block heights,
/// enabling efficient validation and fork choice.
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait SnapshotManager: Send + Sync {
    /// Get or create a snapshot at the specified block.
    ///
    /// # Arguments
    /// * `number` - Block number
    /// * `hash` - Block hash
    /// * `parents` - Optional list of parent headers for building the snapshot
    fn snapshot(
        &self,
        number: u64,
        hash: B256,
        parents: Option<Vec<Header>>,
    ) -> AposResult<Snapshot>;

    /// Get the latest snapshot.
    fn latest_snapshot(&self) -> AposResult<Snapshot>;

    /// Check if a snapshot exists for the given block.
    fn has_snapshot(&self, number: u64, hash: B256) -> bool;
}

/// Signer key management for APoS.
///
/// Manages the private key used for signing blocks.
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait SignerManager: Send + Sync {
    /// Set the signer private key.
    ///
    /// # Arguments
    /// * `key` - Optional hex-encoded private key. Pass `None` to clear.
    ///
    /// # Security
    /// The key should be handled securely and not logged.
    fn set_signer_key(&self, key: Option<String>) -> AposResult<()>;

    /// Get the current signer's address.
    ///
    /// # Returns
    /// `Some(address)` if a signer is configured, `None` otherwise.
    fn get_signer_address(&self) -> AposResult<Option<Address>>;

    /// Check if a signer is configured and ready.
    fn is_signer_ready(&self) -> bool {
        self.get_signer_address()
            .map(|addr| addr.is_some())
            .unwrap_or(false)
    }
}

/// Voting and proposal management for APoS.
///
/// Handles validator voting for adding/removing signers.
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait VotingManager: Send + Sync {
    /// Propose to authorize or deauthorize an address.
    ///
    /// # Arguments
    /// * `address` - The address to vote on
    /// * `authorize` - `true` to authorize, `false` to deauthorize
    fn propose(&self, address: Address, authorize: bool) -> AposResult<()>;

    /// Discard a pending proposal.
    ///
    /// # Arguments
    /// * `address` - The address to stop voting on
    fn discard(&self, address: Address) -> AposResult<()>;

    /// Get all current pending proposals.
    ///
    /// # Returns
    /// Map of address to authorization status (`true` = authorize, `false` = deauthorize)
    fn proposals(&self) -> AposResult<HashMap<Address, bool>>;

    /// Check if there's a pending proposal for an address.
    fn has_proposal(&self, address: &Address) -> bool {
        self.proposals()
            .map(|p| p.contains_key(address))
            .unwrap_or(false)
    }
}

/// Difficulty and timing calculations for APoS.
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait DifficultyCalculator: Send + Sync {
    /// Get the total difficulty at a block.
    ///
    /// # Arguments
    /// * `hash` - Block hash
    fn total_difficulty(&self, hash: B256) -> U256;

    /// Calculate the wiggle time for a block.
    ///
    /// The wiggle time is an additional random delay added to prevent
    /// simultaneous block proposals from multiple signers.
    ///
    /// # Arguments
    /// * `parent_number` - Parent block number
    /// * `parent_hash` - Parent block hash
    /// * `difficulty` - Block difficulty
    ///
    /// # Returns
    /// Duration to wait before proposing
    fn wiggle(&self, parent_number: u64, parent_hash: BlockHash, difficulty: U256) -> Duration;

    /// Calculate the expected difficulty for a block.
    ///
    /// # Arguments
    /// * `signer` - The block signer's address
    /// * `snapshot` - Current snapshot
    fn calculate_difficulty(&self, signer: Address, snapshot: &Snapshot) -> u64;
}

/// Combined trait for full APoS consensus functionality.
///
/// Implementors provide complete APoS consensus support.
pub trait FullAposConsensus:
    AposConsensus + SnapshotManager + SignerManager + VotingManager + DifficultyCalculator
{
}

// Blanket implementation for types implementing all required traits
impl<T> FullAposConsensus for T where
    T: AposConsensus + SnapshotManager + SignerManager + VotingManager + DifficultyCalculator
{
}
