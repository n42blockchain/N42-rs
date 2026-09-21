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
    /// Consecutive views one validator leads before the rotation moves on:
    /// the leader of view `v` is validator `(v / leaderTenure) % n`.
    ///
    /// 1 is gov5's round-robin and the only value a mixed fleet can run. A
    /// larger value lets a leader build its next block while the fleet is
    /// still importing the one it just proposed, which takes one of the two
    /// executions every block costs off the critical path. The price is
    /// liveness: a leader that stops proposing costs up to `leaderTenure`
    /// view timeouts instead of one, because a timeout advances the view by
    /// one and the tenure counts views.
    #[serde(default = "default_leader_tenure")]
    pub leader_tenure: u64,
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
    /// gov5's simulated BLS committee pool. When enabled, every header's
    /// parent beacon root is the Blake3 of the parent's committee evidence;
    /// see `n42_h2_consensus::committee_pool`.
    #[serde(default)]
    pub committee_pool: Option<CommitteePoolGenesis>,
}

/// `hotstuff.committeePool` in the genesis.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitteePoolGenesis {
    /// Whether the pool is in force.
    #[serde(default)]
    pub enabled: bool,
    /// The 32-byte master seed, hex.
    #[serde(default)]
    pub seed_hex: String,
    /// Keys in the pool.
    #[serde(default)]
    pub pool_size: usize,
    /// Signers drawn per block.
    #[serde(default)]
    pub committee_size: usize,
    /// Blocks over which the active pool grows to its full size.
    #[serde(default)]
    pub ramp_blocks: u64,
}

impl CommitteePoolGenesis {
    /// The pool's configuration, when enabled. The seed must be 32 bytes.
    pub fn config(&self) -> Result<Option<n42_h2_consensus::CommitteePoolConfig>, String> {
        if !self.enabled {
            return Ok(None);
        }
        let seed: alloy_primitives::B256 = self
            .seed_hex
            .parse()
            .map_err(|e| format!("hotstuff.committeePool.seedHex must be 32-byte hex: {e}"))?;
        Ok(Some(n42_h2_consensus::CommitteePoolConfig {
            seed,
            pool_size: self.pool_size,
            committee_size: self.committee_size,
            ramp_blocks: self.ramp_blocks,
        }))
    }
}

impl HotStuffGenesisConfig {
    /// The committee pool the chain runs, built from the genesis; `None`
    /// when the chain has none.
    pub fn committee_pool(&self) -> Result<Option<n42_h2_consensus::SimulatedCommitteePool>, String> {
        let Some(config) = self.committee_pool.as_ref().map(CommitteePoolGenesis::config).transpose()?.flatten() else {
            return Ok(None);
        };
        n42_h2_consensus::SimulatedCommitteePool::new(config).map(Some).map_err(|e| e.to_string())
    }

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
const fn default_leader_tenure() -> u64 {
    1
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

    // ------------------------------------------------------------- the bench fleets --
    // The genesis files `scripts/fleet7.sh` and `scripts/fleet7-bench.sh` run
    // on. They reach a node only through `--chain <path>`, so nothing in
    // `reth_chainspec::spec` names them and nothing else would notice if one
    // stopped parsing, stopped being a QMDB chain, or lost a validator.

    const FLEET7: &str = include_str!("../../../chainspec/res/genesis/n42_fleet7.json");
    const FLEET7_BENCH: &str = include_str!("../../../chainspec/res/genesis/n42_fleet7_bench.json");
    const FLEET4: &str = include_str!("../../../chainspec/res/genesis/n42_fleet4.json");
    const FLEET4_BENCH: &str = include_str!("../../../chainspec/res/genesis/n42_fleet4_bench.json");

    /// The seed `scripts/fleet7-env.sh` derives every fleet's keys from.
    const FLEET_SEED: &str = "n42-fleet7-validator";

    fn spec_of(json: &str) -> reth_chainspec::ChainSpec {
        let genesis: Genesis = serde_json::from_str(json).expect("the fleet genesis parses");
        // `--chain <path>` reaches the same place: `N42ChainSpecParser::parse`
        // builds the spec from the `Genesis` and `From<Genesis>` puts the QMDB
        // root in the header.
        reth_chainspec::ChainSpec::from(genesis)
    }

    /// Both fleets must build the same header from the same alloc, or a leg run
    /// on one is not comparable with a leg run on the other.
    fn assert_qmdb_header(spec: &reth_chainspec::ChainSpec) {
        use reth_chainspec::qmdb::{qmdb_genesis_root, state_scheme, StateScheme};
        assert_eq!(state_scheme(&spec.genesis), StateScheme::Qmdb);
        assert_eq!(
            spec.genesis_header.header().state_root,
            qmdb_genesis_root(&spec.genesis).expect("a QMDB root for the alloc")
        );
    }

    fn assert_fleet(json: &str, nodes: usize, period: u64, gas_limit: u64) {
        use n42_h2_consensus::ValidatorSet;

        let spec = spec_of(json);
        assert_qmdb_header(&spec);
        assert_eq!(spec.chain().id(), 1143);
        assert_eq!(spec.genesis.gas_limit, gas_limit);

        let config = HotStuffGenesisConfig::from_genesis(&spec.genesis).expect("a hotstuff block");
        assert_eq!(config.period, period);
        assert!(config.interop_v4, "the fleet speaks the v4 cross-client profile");

        let set = config.validator_set().expect("valid keys");
        assert_eq!(set.len(), nodes);
        let f = config.fault_tolerance();
        assert_eq!(f, (nodes as u32 - 1) / 3);
        let validators = ValidatorSet::try_new(&set, f).expect("f is within the set's tolerance");
        assert_eq!(validators.quorum_size(), nodes - f as usize);

        // Order is bitmap order and must survive parsing untouched.
        for (index, info) in set.iter().enumerate() {
            assert_eq!(info.address, config.validators[index].address);
        }

        // The keys are `h2_keygen --seed n42-fleet7-validator`'s, which derives
        // validator `i` from the index alone. That is why `f7_place_keys` can
        // write a four-key set with `--count 4` and node `i` still holds the key
        // this file names -- and why a smaller fleet's file is the larger one's
        // list truncated rather than a new set.
        for (index, info) in set.iter().enumerate() {
            let ikm: [u8; 32] = alloy_primitives::keccak256(format!("{FLEET_SEED}-{index}")).0;
            let secret = n42_h2_primitives::BlsSecretKey::key_gen(&ikm).expect("a derived key");
            assert_eq!(
                secret.public_key(),
                info.bls_public_key,
                "validator {index} is not the seed's key; the genesis and f7_place_keys disagree"
            );
        }
    }

    #[test]
    fn the_seven_node_fleet_genesis_is_a_seven_validator_qmdb_chain() {
        assert_fleet(FLEET7, 7, 3, 0x1c9c380);
        assert_fleet(FLEET7_BENCH, 7, 1, 0x1c9c3800);
    }

    #[test]
    fn the_four_node_fleet_genesis_is_a_four_validator_qmdb_chain() {
        // Quorum 3 of 4: the leader's own vote plus two followers' (f = 1).
        assert_fleet(FLEET4, 4, 3, 0x1c9c380);
        assert_fleet(FLEET4_BENCH, 4, 1, 0x1c9c3800);
    }

    /// The four-node files are the seven-node ones with the validator list
    /// truncated and NOTHING else touched (`scripts/fleet-genesis.py`). Read as
    /// JSON rather than through `Genesis`, so a field this node ignores today --
    /// a committee-pool setting, a fork time -- cannot drift between the fleets
    /// unnoticed.
    #[test]
    fn the_four_node_fleet_differs_from_the_seven_only_in_its_validators() {
        for (seven, four) in [(FLEET7, FLEET4), (FLEET7_BENCH, FLEET4_BENCH)] {
            let mut seven: serde_json::Value = serde_json::from_str(seven).unwrap();
            let four: serde_json::Value = serde_json::from_str(four).unwrap();
            let list = seven["config"]["hotstuff"]["validators"].as_array().unwrap();
            assert_eq!(list.len(), 7);
            let truncated = serde_json::Value::Array(list[..4].to_vec());
            seven["config"]["hotstuff"]["validators"] = truncated;
            assert_eq!(seven, four, "re-run scripts/fleet-genesis.py --nodes 4");
        }
    }

    /// The `hotstuff` block lives in `config`, which the genesis header does not
    /// cover, so the two fleets share a genesis hash and therefore a fork digest:
    /// their members would mesh on the wire and diverge only at the committee
    /// evidence. Asserted rather than merely written down -- it is why the two
    /// fleets get separate `F7_ROOT`s and are never run at the same time.
    #[test]
    fn the_two_fleets_share_a_genesis_hash() {
        assert_eq!(spec_of(FLEET7).genesis_hash(), spec_of(FLEET4).genesis_hash());
        assert_eq!(spec_of(FLEET7_BENCH).genesis_hash(), spec_of(FLEET4_BENCH).genesis_hash());
    }
}
