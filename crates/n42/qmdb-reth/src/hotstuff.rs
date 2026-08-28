// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The HotStuff-2 parameters a genesis declares, read the way gov5 reads them.
//!
//! `gov5` keeps the validator set and the pacemaker settings in the chain
//! config, under `"hotstuff": {...}` (`params.HotStuffConfig`). A node that
//! takes the same genesis file therefore already knows its fleet: who the
//! validators are, in the order a QC's signer bitmap indexes them, and how
//! long a view may take. Reading them from the genesis, rather than from a
//! second file, is what keeps a Rust member and a Go member of one chain
//! from ever disagreeing about the set.

use alloy_genesis::Genesis;
use alloy_primitives::Address;
use n42_h2_consensus::ValidatorInfo;
use n42_h2_primitives::BlsPublicKey;
use serde::Deserialize;

/// The genesis config key `gov5` keeps `HotStuff` settings under.
pub const HOTSTUFF_KEY: &str = "hotstuff";

/// One validator as the genesis lists it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GenesisValidator {
    /// Fee recipient and on-chain identity.
    pub address: Address,
    /// The BLS public key votes are verified against, `0x`-prefixed hex.
    #[serde(rename = "blsKey")]
    pub bls_key: String,
}

/// `params.HotStuffConfig`, as far as this node uses it.
///
/// Unknown fields are ignored on purpose: `gov5`'s block carries settings for
/// subsystems this node does not have (the simulated committee pool, dev
/// rewards), and a genesis that adds one must not stop a Rust node reading
/// the rest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HotStuffGenesisConfig {
    /// Target block interval in seconds. Engine API timestamps are whole
    /// seconds, so this is also the floor on how often a leader may propose.
    #[serde(default = "default_period")]
    pub period: u64,
    /// First view timeout, milliseconds.
    #[serde(default = "default_base_timeout")]
    pub base_timeout: u64,
    /// Ceiling on the backed-off view timeout, milliseconds.
    #[serde(default = "default_max_timeout")]
    pub max_timeout: u64,
    /// Blocks per epoch. The `v4` interop profile pins the validator set, so a
    /// chain meant for mixed fleets sets this out of reach.
    #[serde(default)]
    pub epoch_length: u64,
    /// The validator set, in QC bitmap order.
    #[serde(default)]
    pub validators: Vec<GenesisValidator>,
    /// Whether the chain speaks the `H2-v4` cross-client wire profile.
    #[serde(default)]
    pub interop_v4: bool,
    /// gov5's fixed per-block dev reward in wei, credited to the block's
    /// coinbase (the leader) and, when one is named, to the dev faucet
    /// address as well (`hotstuff/adapter.go` `Finalize`). Consensus-relevant:
    /// it is in every block's state root. Zero pays nothing.
    #[serde(default)]
    pub dev_block_reward: u64,
    /// The dev faucet paid the same reward each block, if any.
    #[serde(default)]
    pub dev_faucet_address: Option<alloy_primitives::Address>,
}

impl HotStuffGenesisConfig {
    /// The rewards gov5 pays in a block whose coinbase is `coinbase`, in
    /// gov5's order: the coinbase first, then the faucet. Empty when the
    /// chain pays none.
    pub fn block_rewards(&self, coinbase: alloy_primitives::Address) -> Vec<(alloy_primitives::Address, alloy_primitives::U256)> {
        if self.dev_block_reward == 0 {
            return Vec::new();
        }
        let amount = alloy_primitives::U256::from(self.dev_block_reward);
        let mut rewards = vec![(coinbase, amount)];
        if let Some(faucet) = self.dev_faucet_address.filter(|faucet| !faucet.is_zero()) {
            rewards.push((faucet, amount));
        }
        rewards
    }
}

const fn default_period() -> u64 {
    3
}
const fn default_base_timeout() -> u64 {
    6_000
}
const fn default_max_timeout() -> u64 {
    30_000
}

/// Why the `HotStuff` block could not be used.
#[derive(Debug, thiserror::Error)]
pub enum HotStuffConfigError {
    /// The genesis has no `hotstuff` block — it is not a `HotStuff` chain, or
    /// its validators live somewhere this node does not look.
    #[error("genesis config has no \"hotstuff\" block")]
    Missing,
    /// The block is present but not in the shape gov5 writes.
    #[error("genesis \"hotstuff\" block: {0}")]
    Shape(String),
    /// A validator's BLS key is not a valid `G1` point.
    #[error("validator {index} ({address}) has an invalid BLS key")]
    InvalidKey {
        /// Position in the list.
        index: usize,
        /// The validator's address.
        address: Address,
    },
    /// The chain says it is `HotStuff` but lists nobody to run it.
    #[error("genesis \"hotstuff\" block lists no validators")]
    NoValidators,
}

impl HotStuffGenesisConfig {
    /// Reads the block from a genesis, or `None` if there is none.
    pub fn from_genesis(genesis: &Genesis) -> Result<Self, HotStuffConfigError> {
        let raw: serde_json::Value = genesis
            .config
            .extra_fields
            .get_deserialized(HOTSTUFF_KEY)
            .ok_or(HotStuffConfigError::Missing)?
            .map_err(|e| HotStuffConfigError::Shape(e.to_string()))?;
        serde_json::from_value(raw).map_err(|e| HotStuffConfigError::Shape(e.to_string()))
    }

    /// The validator set in the form the consensus engine takes, in genesis
    /// order — which is bitmap order, so this must not be sorted or deduplicated.
    pub fn validator_set(&self) -> Result<Vec<ValidatorInfo>, HotStuffConfigError> {
        if self.validators.is_empty() {
            return Err(HotStuffConfigError::NoValidators);
        }
        self.validators
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                let invalid = || HotStuffConfigError::InvalidKey {
                    index,
                    address: validator.address,
                };
                let bytes = alloy_primitives::hex::decode(validator.bls_key.trim_start_matches("0x"))
                    .map_err(|_| invalid())?;
                let bytes: [u8; 48] = bytes.try_into().map_err(|_| invalid())?;
                let bls_public_key = BlsPublicKey::from_bytes(&bytes).map_err(|_| invalid())?;
                Ok(ValidatorInfo {
                    address: validator.address,
                    bls_public_key,
                    p2p_peer_id: None,
                })
            })
            .collect()
    }

    /// The largest fault tolerance the set supports: `f = (n - 1) / 3`.
    pub const fn fault_tolerance(&self) -> u32 {
        (self.validators.len() as u32).saturating_sub(1) / 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_chainspec::N42_DEVNET;

    /// The checked-in devnet is the reference: a `QMDB` `HotStuff` chain whose
    /// genesis both clients can load.
    #[test]
    fn the_devnet_genesis_declares_a_usable_hotstuff_fleet() {
        let config = HotStuffGenesisConfig::from_genesis(&N42_DEVNET.genesis).expect("a hotstuff block");
        assert_eq!(config.period, 3);
        assert_eq!(config.base_timeout, 6_000);
        assert_eq!(config.max_timeout, 30_000);
        assert!(config.interop_v4, "the devnet speaks the v4 cross-client profile");
        let set = config.validator_set().expect("valid keys");
        assert_eq!(set.len(), 4);
        assert_eq!(config.fault_tolerance(), 1);
        // Order is bitmap order and must survive parsing untouched.
        assert_eq!(set[0].address, config.validators[0].address);
    }

    #[test]
    fn the_devnet_is_a_qmdb_chain_with_every_fork_at_genesis() {
        use reth_chainspec::{qmdb::state_scheme, qmdb::StateScheme, EthereumHardforks};
        let spec = &*N42_DEVNET;
        assert_eq!(state_scheme(&spec.genesis), StateScheme::Qmdb);
        let ts = spec.genesis.timestamp;
        assert!(spec.is_shanghai_active_at_timestamp(ts));
        assert!(spec.is_cancun_active_at_timestamp(ts));
        assert!(spec.is_prague_active_at_timestamp(ts));
        assert!(spec.is_osaka_active_at_timestamp(ts));
        // The genesis header carries the forest root of the alloc, and the
        // fork fields a gov5 `ToBlock` sets for the same schedule.
        let header = spec.genesis_header.header();
        assert_eq!(header.state_root, reth_chainspec::qmdb::qmdb_genesis_root(&spec.genesis).unwrap());
        assert!(header.requests_hash.is_some(), "Prague at genesis: empty requests hash");
        assert!(header.parent_beacon_block_root.is_some(), "Cancun at genesis");
        assert!(header.withdrawals_root.is_some(), "Shanghai at genesis");
        assert_eq!(header.difficulty, alloy_primitives::U256::ZERO, "a BFT chain is post-merge from block 0");
    }

    #[test]
    fn a_genesis_without_the_block_says_so() {
        let genesis: Genesis = serde_json::from_str(
            r#"{"config":{"chainId":1},"alloc":{},"difficulty":"0x0","gasLimit":"0x1","timestamp":"0x0",
                "extraData":"0x","nonce":"0x0","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
                "coinbase":"0x0000000000000000000000000000000000000000","number":"0x0","gasUsed":"0x0",
                "parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000"}"#,
        )
        .unwrap();
        assert!(matches!(HotStuffGenesisConfig::from_genesis(&genesis), Err(HotStuffConfigError::Missing)));
    }
}
