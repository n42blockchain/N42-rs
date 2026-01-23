// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// use ethcore::snapshot::{ManifestData, SnapshotService};
use reth_primitives::arbitrary;
use std::collections::HashMap;
use std::error::Error;

use std::time::{Duration, Instant};

use alloy_primitives::Sealable;
use reth_primitives_traits::AlloyBlockHeader;
use reth_primitives_traits::BlockHeader as BlockHeaderTrait;

use alloy_primitives::{hex, Address, B256, U256};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};

use tracing::info;

const NONCE_AUTH_VOTE: [u8; 8] = hex!("ffffffffffffffff"); // Magic nonce number to vote on adding a new signer
const NONCE_DROP_VOTE: [u8; 8] = hex!("0000000000000000"); // Magic nonce number to vote on removing a signer

#[derive(Debug)]
pub enum VotingError {
    InvalidVotingChain,
    UnauthorizedSigner,
    SignerRecentlySigned,
    InvalidVote,
    RecoverError(String),
}

//
//
impl std::fmt::Display for VotingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVotingChain => write!(f, "Invalid voting chain"),
            Self::UnauthorizedSigner => write!(f, "Unauthorized signer"),
            Self::SignerRecentlySigned => write!(f, "Signer recently signed"),
            Self::InvalidVote => write!(f, "Invalid vote"),
            Self::RecoverError(e) => write!(f, "Recover signer error: {}", e),
        }
    }
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    RlpEncodable,
    RlpDecodable,
    Arbitrary,
    Default,
)]
pub struct Vote {
    /// Authorized signer that cast this vote
    pub signer: Address,
    /// Block number the vote was cast in (expire old votes)
    pub block: u64,
    /// Account being voted on to change its authorization
    pub address: Address,
    /// Whether to authorize or deauthorize the voted account
    pub authorize: bool,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    RlpEncodable,
    RlpDecodable,
    Arbitrary,
    Default,
)]
pub struct Tally {
    /// Whether the vote is about authorizing or kicking someone
    pub authorize: bool,
    /// Number of votes until now wanting to pass the proposal
    pub votes: u32,
}
/// aposconfig
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable, Arbitrary,
)]
pub struct APosConfig {
    /// Number of seconds between blocks to enforce
    pub period: u64,
    /// Epoch length to reset votes and checkpoint
    pub epoch: u64,
    /// Reward epoch duration
    pub reward_epoch: u64,
    /// Maximum reward limit per epoch
    pub reward_limit: U256,
    /// Deposit contract
    pub deposit_contract: Address,
}

impl Default for APosConfig {
    fn default() -> Self {
        Self {
            period: 8,
            epoch: 3000,
            reward_epoch: 10800,
            reward_limit: U256::from(0x6F05B59D3B20000_u64),
            deposit_contract: Address::ZERO,
        }
    }
}

/// snapshot
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Arbitrary, Default)]
pub struct Snapshot {
    /// Consensus engine parameters to fine tune behavior
    pub config: APosConfig,
    /// Block number where the snapshot was created
    pub number: u64,
    /// checkpoint hash where the snapshot was created
    pub hash: B256,
    /// Set of authorized signers at this moment
    pub signers: Vec<Address>,
    /// Set of recent signers for spam protections
    pub recents: HashMap<u64, Address>,
    /// List of votes cast in chronological order
    pub votes: Vec<Vote>,
    /// Current vote tally to avoid recalculating
    pub tally: HashMap<Address, Tally>,
}

impl Snapshot {
    /// create a new Snapshot
    pub fn new_snapshot(
        config: APosConfig,
        number: u64,
        hash: B256,
        signers: Vec<Address>,
    ) -> Self {
        let mut snap = Self {
            config,
            number,
            hash,
            signers: Vec::new(),
            recents: HashMap::new(),
            votes: Vec::new(),
            tally: HashMap::new(),
        };

        for signer in signers {
            snap.signers.push(signer);
        }
        snap
    }

    /// Create a deep copy of the snapshot
    pub fn copy(&self) -> Self {
        Self {
            config: self.config.clone(),
            number: self.number,
            hash: self.hash,
            signers: self.signers.clone(),
            recents: self.recents.clone(),
            votes: self.votes.clone(),
            tally: self.tally.clone(),
        }

        // No need for special handling for votes if Vec<T> implements Clone
        // Deep copy is handled by the clone method for each type.
    }

    /// ecrecover
    // pub fn ecrecover(&self, header: Header) -> Result<Address, Box<dyn Error>> {
    //     (self.ecrecover)(header)
    // }

    /// `valid_vote` returns whether it makes sense to cast the specified vote in the
    /// given snapshot context (e.g. don't try to add an already authorized signer).
    pub fn valid_vote(&self, address: Address, authorize: bool) -> bool {
        if self.signers.iter().any(|x| x == &address) {
            !authorize
        } else {
            authorize
        }
    }

    /// cast Add a new vote to the voting statistics
    pub fn cast(&mut self, address: Address, authorize: bool) -> bool {
        // Ensure the vote is meaningful
        if !self.valid_vote(address, authorize) {
            return false;
        }
        // Cast the vote into an existing or new tally
        if let Some(tally) = self.tally.get_mut(&address) {
            tally.votes += 1;
        } else {
            self.tally.insert(
                address,
                Tally {
                    authorize,
                    votes: 1,
                },
            );
        }
        true
    }

    /// uncast removes a previously cast vote from the tally.
    pub fn uncast(&mut self, address: Address, authorize: bool) -> bool {
        if let Some(tally) = self.tally.get_mut(&address) {
            //Ensure that we only remove eligible votes
            if tally.authorize != authorize {
                return false;
            }
            //Otherwise, remove this vote
            if tally.votes > 1 {
                tally.votes -= 1;
            } else {
                self.tally.remove(&address);
            }
            true
        } else {
            // If there's no tally, it's a dangling vote, just drop
            false
        }
    }

    /// Create a new authorization snapshot using the given header information
    pub fn apply<F, H>(&self, headers: Vec<H>, func: F) -> Result<Self, VotingError>
    where
        F: Fn(H) -> Result<Address, Box<dyn Error>>,
        H: BlockHeaderTrait,
    {
        //If there is no header information, return the current snapshot directly
        if headers.is_empty() {
            return Ok(self.clone());
        }

        //Check the validity of header information
        for i in 0..headers.len() - 1 {
            if headers[i + 1].number() != headers[i].number() + 1 {
                return Err(VotingError::InvalidVotingChain);
            }
        }
        if headers[0].number() != self.number + 1 {
            return Err(VotingError::InvalidVotingChain);
        }

        //Create a new snapshot
        let mut snap = self.copy();
        let start = Instant::now();
        let logged = Instant::now();

        for (i, i_header) in headers.iter().enumerate() {
            let header = i_header;
            let number = header.number();

            //If it is a checkpoint block, remove all votes
            if number % self.config.epoch == 0 {
                snap.votes.clear();
                snap.tally.clear();
            }

            //Remove the oldest signer from the recent signer collection to allow them to sign again
            let limit = snap.signers.len() as u64 / 2 + 1;
            if number >= limit {
                snap.recents.remove(&(number - limit));
            }

            //Verify the signer and check if they are in the signer list
            let signer =
                func(header.clone()).map_err(|e| VotingError::RecoverError(e.to_string()))?;
            if !snap.signers.contains(&signer) {
                return Err(VotingError::UnauthorizedSigner);
            }

            if snap.recents.values().any(|&recent| recent == signer) {
                return Err(VotingError::SignerRecentlySigned);
            }
            snap.recents.insert(number, signer);

            //Discard any previous votes of the signer
            while let Some(i) = snap
                .votes
                .iter()
                .position(|vote| vote.signer == signer && vote.address == header.beneficiary())
            {
                snap.uncast(snap.votes[i].address, snap.votes[i].authorize);
                snap.votes.remove(i);
            }

            //Count new votes
            let authorize = match header.nonce().ok_or(VotingError::InvalidVotingChain)? {
                nonce if hex::encode(nonce) == hex::encode(NONCE_AUTH_VOTE) => true,
                nonce if hex::encode(nonce) == hex::encode(NONCE_DROP_VOTE) => false,
                _ => return Err(VotingError::InvalidVote),
            };

            if snap.cast(header.beneficiary(), authorize) {
                snap.votes.push(Vote {
                    signer,
                    block: number,
                    address: header.beneficiary(),
                    authorize,
                });
            }

            //If the vote is passed, update the list of signatories
            if let Some(tally) = snap.tally.get(&header.beneficiary()) {
                if tally.votes
                    > (snap.signers.len() / 2)
                        .try_into()
                        .map_err(|_| VotingError::InvalidVotingChain)?
                {
                    if tally.authorize {
                        snap.signers.push(header.beneficiary());
                    } else {
                        if let Some(pos) =
                            snap.signers.iter().position(|x| *x == header.beneficiary())
                        {
                            snap.signers.remove(pos);
                        }
                        // snap.signers.remove(header.beneficiary);

                        //Reduce the signer list and delete any remaining recent cache
                        let limit = snap.signers.len() as u64 / 2 + 1;
                        if number >= limit {
                            snap.recents.remove(&(number - limit));
                        }

                        //Discard any previous votes of the revoked authorized signatory
                        while let Some(i) = snap
                            .votes
                            .iter()
                            .position(|vote| vote.signer == header.beneficiary())
                        {
                            snap.uncast(snap.votes[i].address, snap.votes[i].authorize);
                            snap.votes.remove(i);
                        }
                    }

                    //Discard any previous votes that have just changed the account
                    snap.votes
                        .retain(|vote| vote.address != header.beneficiary());
                    snap.tally.remove(&header.beneficiary());
                }
            }

            //If the operation takes too long, notify the user regularly
            if logged.elapsed() > Duration::from_secs(8) {
                info!(
                    target: "Apos",
                    "Reconstructing voting history: i={}, headers.len()={}, elapsed={:?}",
                    i,
                    headers.len(),
                    start.elapsed()
                );
            }
        }

        if start.elapsed() > Duration::from_secs(8) {
            info!(
                target: "Apos",
                "Reconstructed voting history: headers.len()={}, elapsed={:?}",
                headers.len(),
                start.elapsed()
            );
        }

        snap.number = headers
            .last()
            .ok_or(VotingError::InvalidVotingChain)?
            .number();
        snap.hash = headers
            .last()
            .ok_or(VotingError::InvalidVotingChain)?
            .hash_slow();

        Ok(snap)
    }

    /// signers retrieves the list of authorized signers in ascending order.
    pub fn signers(&self) -> Vec<Address> {
        let sigs: Vec<Address> = self.signers.to_vec();
        //sigs.sort();
        sigs
    }

    /// inturn returns if a signer at a given block height is in-turn or not.
    pub fn inturn(&self, number: u64, signer: &Address) -> bool {
        let signers = self.signers();
        let mut offset = 0;

        //Find the position of the given signer in the sorted list
        while offset < signers.len() && &signers[offset] != signer {
            offset += 1;
        }

        //Determine whether the signer of a given block height is an in turn signer
        ((number - 1) % signers.len() as u64) == offset as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    // Test addresses for testing
    fn test_signers() -> Vec<Address> {
        vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
            address!("0000000000000000000000000000000000000003"),
        ]
    }

    fn default_config() -> APosConfig {
        APosConfig::default()
    }

    // ==================== APosConfig Tests ====================

    #[test]
    fn test_apos_config_default() {
        let config = APosConfig::default();
        assert_eq!(config.period, 8);
        assert_eq!(config.epoch, 3000);
        assert_eq!(config.reward_epoch, 10800);
        assert_eq!(config.deposit_contract, Address::ZERO);
    }

    #[test]
    fn test_apos_config_clone() {
        let config = APosConfig {
            period: 15,
            epoch: 5000,
            reward_epoch: 20000,
            reward_limit: U256::from(1000000u64),
            deposit_contract: address!("1234567890123456789012345678901234567890"),
        };
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    #[test]
    fn test_apos_config_serialization() {
        let config = APosConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: APosConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    // ==================== Vote Tests ====================

    #[test]
    fn test_vote_default() {
        let vote = Vote::default();
        assert_eq!(vote.signer, Address::ZERO);
        assert_eq!(vote.block, 0);
        assert_eq!(vote.address, Address::ZERO);
        assert!(!vote.authorize);
    }

    #[test]
    fn test_vote_creation() {
        let signer = address!("0000000000000000000000000000000000000001");
        let target = address!("0000000000000000000000000000000000000002");
        let vote = Vote {
            signer,
            block: 100,
            address: target,
            authorize: true,
        };
        assert_eq!(vote.signer, signer);
        assert_eq!(vote.block, 100);
        assert_eq!(vote.address, target);
        assert!(vote.authorize);
    }

    #[test]
    fn test_vote_serialization() {
        let vote = Vote {
            signer: address!("0000000000000000000000000000000000000001"),
            block: 100,
            address: address!("0000000000000000000000000000000000000002"),
            authorize: true,
        };
        let json = serde_json::to_string(&vote).unwrap();
        let deserialized: Vote = serde_json::from_str(&json).unwrap();
        assert_eq!(vote, deserialized);
    }

    // ==================== Tally Tests ====================

    #[test]
    fn test_tally_default() {
        let tally = Tally::default();
        assert!(!tally.authorize);
        assert_eq!(tally.votes, 0);
    }

    #[test]
    fn test_tally_creation() {
        let tally = Tally {
            authorize: true,
            votes: 5,
        };
        assert!(tally.authorize);
        assert_eq!(tally.votes, 5);
    }

    #[test]
    fn test_tally_serialization() {
        let tally = Tally {
            authorize: true,
            votes: 10,
        };
        let json = serde_json::to_string(&tally).unwrap();
        let deserialized: Tally = serde_json::from_str(&json).unwrap();
        assert_eq!(tally, deserialized);
    }

    // ==================== VotingError Tests ====================

    #[test]
    fn test_voting_error_display() {
        assert_eq!(
            format!("{}", VotingError::InvalidVotingChain),
            "Invalid voting chain"
        );
        assert_eq!(
            format!("{}", VotingError::UnauthorizedSigner),
            "Unauthorized signer"
        );
        assert_eq!(
            format!("{}", VotingError::SignerRecentlySigned),
            "Signer recently signed"
        );
        assert_eq!(format!("{}", VotingError::InvalidVote), "Invalid vote");
        assert_eq!(
            format!("{}", VotingError::RecoverError("test error".to_string())),
            "Recover signer error: test error"
        );
    }

    // ==================== Snapshot Tests ====================

    #[test]
    fn test_snapshot_new() {
        let signers = test_signers();
        let hash = B256::ZERO;
        let snap = Snapshot::new_snapshot(default_config(), 0, hash, signers.clone());

        assert_eq!(snap.number, 0);
        assert_eq!(snap.hash, hash);
        assert_eq!(snap.signers, signers);
        assert!(snap.recents.is_empty());
        assert!(snap.votes.is_empty());
        assert!(snap.tally.is_empty());
    }

    #[test]
    fn test_snapshot_copy() {
        let signers = test_signers();
        let mut snap = Snapshot::new_snapshot(default_config(), 100, B256::ZERO, signers);

        // Add some state
        snap.recents
            .insert(99, address!("0000000000000000000000000000000000000001"));
        snap.votes.push(Vote {
            signer: address!("0000000000000000000000000000000000000001"),
            block: 100,
            address: address!("0000000000000000000000000000000000000004"),
            authorize: true,
        });

        let copied = snap.copy();
        assert_eq!(snap.number, copied.number);
        assert_eq!(snap.hash, copied.hash);
        assert_eq!(snap.signers, copied.signers);
        assert_eq!(snap.recents, copied.recents);
        assert_eq!(snap.votes, copied.votes);
    }

    #[test]
    fn test_snapshot_valid_vote_authorize_new_signer() {
        let signers = test_signers();
        let snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers);

        // New signer should be valid for authorization
        let new_signer = address!("0000000000000000000000000000000000000004");
        assert!(snap.valid_vote(new_signer, true));
        // New signer should not be valid for de-authorization
        assert!(!snap.valid_vote(new_signer, false));
    }

    #[test]
    fn test_snapshot_valid_vote_deauthorize_existing_signer() {
        let signers = test_signers();
        let snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers.clone());

        // Existing signer should be valid for de-authorization
        assert!(snap.valid_vote(signers[0], false));
        // Existing signer should not be valid for authorization
        assert!(!snap.valid_vote(signers[0], true));
    }

    #[test]
    fn test_snapshot_cast_new_vote() {
        let signers = test_signers();
        let mut snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers);

        let new_signer = address!("0000000000000000000000000000000000000004");
        assert!(snap.cast(new_signer, true));
        assert!(snap.tally.contains_key(&new_signer));
        assert_eq!(snap.tally.get(&new_signer).unwrap().votes, 1);
        assert!(snap.tally.get(&new_signer).unwrap().authorize);
    }

    #[test]
    fn test_snapshot_cast_multiple_votes() {
        let signers = test_signers();
        let mut snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers);

        let new_signer = address!("0000000000000000000000000000000000000004");
        snap.cast(new_signer, true);
        snap.cast(new_signer, true);
        snap.cast(new_signer, true);

        assert_eq!(snap.tally.get(&new_signer).unwrap().votes, 3);
    }

    #[test]
    fn test_snapshot_cast_invalid_vote() {
        let signers = test_signers();
        let mut snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers.clone());

        // Try to authorize an already authorized signer (invalid)
        assert!(!snap.cast(signers[0], true));
        // Should not create a tally entry
        assert!(!snap.tally.contains_key(&signers[0]));
    }

    #[test]
    fn test_snapshot_uncast_vote() {
        let signers = test_signers();
        let mut snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers);

        let new_signer = address!("0000000000000000000000000000000000000004");
        snap.cast(new_signer, true);
        snap.cast(new_signer, true);
        assert_eq!(snap.tally.get(&new_signer).unwrap().votes, 2);

        // Uncast one vote
        assert!(snap.uncast(new_signer, true));
        assert_eq!(snap.tally.get(&new_signer).unwrap().votes, 1);

        // Uncast last vote should remove tally entry
        assert!(snap.uncast(new_signer, true));
        assert!(!snap.tally.contains_key(&new_signer));
    }

    #[test]
    fn test_snapshot_uncast_wrong_type() {
        let signers = test_signers();
        let mut snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers);

        let new_signer = address!("0000000000000000000000000000000000000004");
        snap.cast(new_signer, true); // authorize vote

        // Try to uncast as deauthorize (wrong type)
        assert!(!snap.uncast(new_signer, false));
        // Original vote should remain
        assert_eq!(snap.tally.get(&new_signer).unwrap().votes, 1);
    }

    #[test]
    fn test_snapshot_uncast_nonexistent() {
        let signers = test_signers();
        let mut snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers);

        let new_signer = address!("0000000000000000000000000000000000000004");
        // Try to uncast a vote that doesn't exist
        assert!(!snap.uncast(new_signer, true));
    }

    #[test]
    fn test_snapshot_signers() {
        let signers = test_signers();
        let snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers.clone());

        let retrieved = snap.signers();
        assert_eq!(retrieved, signers);
    }

    #[test]
    fn test_snapshot_inturn() {
        let signers = test_signers();
        let snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers.clone());

        // Block 1: (1-1) % 3 = 0, so signers[0] is in turn
        assert!(snap.inturn(1, &signers[0]));
        assert!(!snap.inturn(1, &signers[1]));
        assert!(!snap.inturn(1, &signers[2]));

        // Block 2: (2-1) % 3 = 1, so signers[1] is in turn
        assert!(!snap.inturn(2, &signers[0]));
        assert!(snap.inturn(2, &signers[1]));
        assert!(!snap.inturn(2, &signers[2]));

        // Block 3: (3-1) % 3 = 2, so signers[2] is in turn
        assert!(!snap.inturn(3, &signers[0]));
        assert!(!snap.inturn(3, &signers[1]));
        assert!(snap.inturn(3, &signers[2]));

        // Block 4: (4-1) % 3 = 0, so signers[0] is in turn again
        assert!(snap.inturn(4, &signers[0]));
    }

    #[test]
    fn test_snapshot_inturn_unknown_signer() {
        let signers = test_signers();
        let snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers);

        let unknown = address!("0000000000000000000000000000000000000099");
        // Unknown signer should never be in turn
        assert!(!snap.inturn(1, &unknown));
        assert!(!snap.inturn(2, &unknown));
        assert!(!snap.inturn(3, &unknown));
    }

    #[test]
    fn test_snapshot_serialization() {
        let signers = test_signers();
        let mut snap = Snapshot::new_snapshot(default_config(), 100, B256::ZERO, signers);
        snap.recents
            .insert(99, address!("0000000000000000000000000000000000000001"));

        let json = serde_json::to_string(&snap).unwrap();
        let deserialized: Snapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(snap.number, deserialized.number);
        assert_eq!(snap.hash, deserialized.hash);
        assert_eq!(snap.signers, deserialized.signers);
    }

    #[test]
    fn test_nonce_constants() {
        // Verify nonce constants are correct
        assert_eq!(NONCE_AUTH_VOTE, [0xff; 8]);
        assert_eq!(NONCE_DROP_VOTE, [0x00; 8]);
    }

    // ==================== Integration-like Tests ====================

    #[test]
    fn test_voting_workflow() {
        let signers = test_signers();
        let mut snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers.clone());

        let new_signer = address!("0000000000000000000000000000000000000004");

        // Three signers vote to add a new signer
        // With 3 signers, need > 1 vote (i.e., 2 votes) to pass
        snap.cast(new_signer, true); // Vote 1
        snap.votes.push(Vote {
            signer: signers[0],
            block: 1,
            address: new_signer,
            authorize: true,
        });

        snap.cast(new_signer, true); // Vote 2
        snap.votes.push(Vote {
            signer: signers[1],
            block: 2,
            address: new_signer,
            authorize: true,
        });

        // Check tally
        let tally = snap.tally.get(&new_signer).unwrap();
        assert_eq!(tally.votes, 2);
        assert!(tally.authorize);

        // 2 > 3/2 = 1, so the vote passes
        assert!(tally.votes > (snap.signers.len() / 2) as u32);
    }

    #[test]
    fn test_deauthorization_workflow() {
        let signers = test_signers();
        let mut snap = Snapshot::new_snapshot(default_config(), 0, B256::ZERO, signers.clone());

        // Vote to remove signers[2]
        snap.cast(signers[2], false); // Vote 1
        snap.cast(signers[2], false); // Vote 2

        let tally = snap.tally.get(&signers[2]).unwrap();
        assert_eq!(tally.votes, 2);
        assert!(!tally.authorize); // This is a deauthorization vote
    }
}
