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
/// the rest. A profile-1 genesis (`"n42Profile": 1`) is the exception: its
/// key list is closed and checked at start-up by [`crate::profile1`], and
/// [`Self::from_genesis`] writes the profile's from-view-0 switches into the
/// fields below.
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
    ///
    /// Read from a JSON integer (gov5's `uint64`, every pre-profile genesis)
    /// or a decimal string of wei (profile 1, standard AM8, where a number is
    /// refused by `crate::profile1`).
    #[serde(default, deserialize_with = "deserialize_wei")]
    pub dev_block_reward: alloy_primitives::U256,
    /// The dev faucet paid the same reward each block, if any.
    #[serde(default)]
    pub dev_faucet_address: Option<alloy_primitives::Address>,
    /// gov5's simulated BLS committee pool. When enabled, every header's
    /// parent beacon root is the Blake3 of the parent's committee evidence;
    /// see `n42_h2_consensus::committee_pool`.
    #[serde(default)]
    pub committee_pool: Option<CommitteePoolGenesis>,
    /// gov5's two-phase vote gate (`twoPhaseVoteGate`): Round 1 votes no
    /// longer wait for the import, so the commit vote is the execution
    /// attestation and waits for it instead. This node holds its commit vote
    /// the same way; its Round 1 stays import-gated.
    #[serde(default)]
    pub two_phase_vote_gate: bool,
    /// gov5's `rotateOnTimeoutView` (`params.HotStuffConfig`, branch
    /// `feat/hotstuff-rotate-on-timeout`): a timeout certificate for a view
    /// at or above this one moves the chain to the first view of the next
    /// leader-tenure window instead of `view + 1`, so a dead leader loses the
    /// rest of its tenure (N42-SYNC-SPEC section 10). Absent (or `null`) is
    /// the classic view change; 0 applies from the first view. Consensus-
    /// critical: every member must carry the same value, and no environment
    /// variable changes it.
    #[serde(default)]
    pub rotate_on_timeout_view: Option<u64>,
    /// Profile 1's pacing (`blockIntervalMs`, standard A17): a leader
    /// proposes no earlier than this long after it first held the parent.
    /// Absent on pre-profile chains, which pace by `period`.
    #[serde(default)]
    pub block_interval_ms: Option<u64>,
    /// Profile 1's first view timeout (`baseTimeoutMs`, A16).
    #[serde(default)]
    pub base_timeout_ms: Option<u64>,
    /// Profile 1's backoff ceiling (`maxTimeoutMs`, A16).
    #[serde(default)]
    pub max_timeout_ms: Option<u64>,
    /// Profile 1's fixed block gas limit (`gasLimit`, A23).
    #[serde(default)]
    pub gas_limit: Option<u64>,
    /// Profile 1's block size bound in decoded RLP bytes (`maxBlockBytes`,
    /// B15), for production and every carrier.
    #[serde(default)]
    pub max_block_bytes: Option<u64>,
    /// Profile 1's deferred-execution depth (`deferredExecutionDepth`, A10).
    /// Read through `reth_chainspec::qmdb::deferred_execution_depth`, which
    /// knows where each kind of chain keeps it.
    #[serde(default)]
    pub deferred_execution_depth: Option<u64>,
    /// The validated profile-1 view of the genesis, when it declares
    /// `"n42Profile": 1` and passes [`crate::profile1::profile1`]; see
    /// [`Self::profile1`]. Never read from JSON.
    #[serde(skip)]
    pub profile1: Option<crate::profile1::Profile1Config>,
}

/// Reads a wei amount from a JSON unsigned integer or a decimal string.
fn deserialize_wei<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<alloy_primitives::U256, D::Error> {
    use serde::de::Error as _;
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(number) => number
            .as_u64()
            .map(alloy_primitives::U256::from)
            .ok_or_else(|| D::Error::custom(format!("a wei amount must be an unsigned integer, found {number}"))),
        serde_json::Value::String(text) => parse_decimal_wei(&text).map_err(D::Error::custom),
        serde_json::Value::Null => Ok(alloy_primitives::U256::ZERO),
        other => Err(D::Error::custom(format!("a wei amount must be an integer or a decimal string, found {other}"))),
    }
}

/// A decimal string of wei: digits only, no sign, no `0x`, no exponent.
pub(crate) fn parse_decimal_wei(text: &str) -> Result<alloy_primitives::U256, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("a wei amount string must be decimal digits, found {text:?}"));
    }
    alloy_primitives::U256::from_str_radix(text, 10).map_err(|e| format!("{text:?} is not a 256-bit wei amount: {e}"))
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
        if self.dev_block_reward.is_zero() {
            return Vec::new();
        }
        let amount = self.dev_block_reward;
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
    /// The block turns on a consensus rule this node does not implement, so
    /// running it would split the fleet the moment the rule applies.
    #[error(
        "genesis \"hotstuff\" block sets {field} = {value}, a consensus rule this node does not \
         implement; it would not follow the rest of the fleet once the rule applies. Remove the \
         field (absent or null keeps the rule off) or run a build that implements it"
    )]
    Unimplemented {
        /// The genesis key, as gov5 spells it.
        field: &'static str,
        /// Its value, as JSON.
        value: String,
    },
}

/// `hotstuff` keys that switch on a consensus rule this node does not
/// implement. [`HotStuffGenesisConfig`] ignores keys it does not know, so a
/// key listed here is refused by [`refuse_unimplemented_rules`] instead of
/// being dropped in silence.
///
/// Empty today: `rotateOnTimeoutView` (sync standard section 10.3), the one
/// key listed until now, is implemented and read into
/// [`HotStuffGenesisConfig::rotate_on_timeout_view`]. A gov5 rule this node
/// does not run yet goes here until it does.
///
/// Only listed keys are refused, not every unknown key: gov5 writes settings
/// for subsystems this node does not have, and those must still load.
pub const UNIMPLEMENTED_ACTIVATING_FIELDS: &[&str] = &[];

/// Refuses a genesis whose `hotstuff` block sets one of
/// [`UNIMPLEMENTED_ACTIVATING_FIELDS`] to anything but `null`. A genesis
/// without a `hotstuff` block, or with a malformed one, is left to
/// [`HotStuffGenesisConfig::from_genesis`].
pub fn refuse_unimplemented_rules(genesis: &Genesis) -> Result<(), HotStuffConfigError> {
    refuse_listed_rules(genesis, UNIMPLEMENTED_ACTIVATING_FIELDS)
}

/// [`refuse_unimplemented_rules`] over an explicit key list, so the
/// mechanism stays testable while the shipped list is empty.
fn refuse_listed_rules(genesis: &Genesis, fields: &[&'static str]) -> Result<(), HotStuffConfigError> {
    let Some(hotstuff) = genesis.config.extra_fields.get(HOTSTUFF_KEY).and_then(serde_json::Value::as_object) else {
        return Ok(());
    };
    for &field in fields {
        match hotstuff.get(field) {
            None | Some(serde_json::Value::Null) => {}
            Some(value) => return Err(HotStuffConfigError::Unimplemented { field, value: value.to_string() }),
        }
    }
    Ok(())
}

impl HotStuffGenesisConfig {
    /// Reads the block from a genesis, or `None` if there is none.
    ///
    /// On a profile-1 genesis the profile's switches are written into the
    /// fields (`apply_profile1`) and, when the genesis is valid, the typed
    /// [`crate::profile1::Profile1Config`] is attached ([`Self::profile1`]).
    /// An invalid profile-1 genesis is refused at start-up by
    /// [`crate::check_genesis`]; here it reads without the attachment.
    pub fn from_genesis(genesis: &Genesis) -> Result<Self, HotStuffConfigError> {
        let mut config = Self::from_genesis_unvalidated(genesis)?;
        if reth_chainspec::qmdb::is_profile1(genesis) {
            config.profile1 = crate::profile1::profile1(genesis).ok().flatten();
        }
        Ok(config)
    }

    /// The validated profile-1 parameters of the chain, or `None` on a
    /// chain without `"n42Profile": 1`. The one typed source the header,
    /// vote and pacing rules of profile 1 read.
    pub const fn profile1(&self) -> Option<&crate::profile1::Profile1Config> {
        self.profile1.as_ref()
    }

    /// The vote and execution-write rules the chain runs: profile 1's when
    /// the genesis is a valid profile-1 genesis ([`Self::profile1`]),
    /// today's otherwise. What `h2_validator` hands
    /// `H2Service::with_vote_rules`.
    pub const fn vote_rules(&self) -> n42_h2_consensus::VoteRules {
        if self.profile1.is_some() {
            n42_h2_consensus::VoteRules::PROFILE1
        } else {
            n42_h2_consensus::VoteRules::TODAY
        }
    }

    /// [`Self::from_genesis`] without the profile-1 validation (which itself
    /// reads the block through this).
    pub(crate) fn from_genesis_unvalidated(genesis: &Genesis) -> Result<Self, HotStuffConfigError> {
        let raw: serde_json::Value = genesis
            .config
            .extra_fields
            .get_deserialized(HOTSTUFF_KEY)
            .ok_or(HotStuffConfigError::Missing)?
            .map_err(|e| HotStuffConfigError::Shape(e.to_string()))?;
        let mut config: Self = serde_json::from_value(raw).map_err(|e| HotStuffConfigError::Shape(e.to_string()))?;
        if reth_chainspec::qmdb::is_profile1(genesis) {
            config.apply_profile1();
        }
        Ok(config)
    }

    /// The switches profile 1 turns on from view 0 / block 0, written into
    /// the fields every consumer already reads, so no call site needs to
    /// know about the profile (`docs/MIXED_PRODUCTION_STANDARD.md`). The
    /// genesis itself is validated by [`crate::profile1::profile1`] at
    /// start-up; a field it makes mandatory but this finds absent keeps the
    /// pre-profile value here, and the start-up refusal names it.
    fn apply_profile1(&mut self) {
        // A16: the `*Ms` names replace `baseTimeout` / `maxTimeout`.
        if let Some(base) = self.base_timeout_ms {
            self.base_timeout = base;
        }
        if let Some(max) = self.max_timeout_ms {
            self.max_timeout = max;
        }
        // A17: `blockIntervalMs` replaces `period`. Engine API timestamps
        // are whole seconds, so the period the leader stamps from is the
        // interval rounded up to a second.
        if let Some(interval) = self.block_interval_ms {
            self.period = interval.div_ceil(1000).max(1);
        }
        // A22: rotate-on-timeout from view 0.
        self.rotate_on_timeout_view = Some(0);
        // A13 / AM19 / AM23: the vote gates are `n42_h2_consensus::VoteRules`
        // (`Self::vote_rules`), not gov5's `twoPhaseVoteGate` (refused on
        // profile 1): its header-vote road is closed there, so the flag stays
        // off and the two cannot pull in different directions.
        self.two_phase_vote_gate = false;
        // A14: H2-v4 signing only.
        self.interop_v4 = true;
        // A19: the committee pool is always on; the `enabled` flag is gone.
        if let Some(pool) = self.committee_pool.as_mut() {
            pool.enabled = true;
        }
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

    /// Audit 2026-10 R2-C9: gov5's production genesis turns the two-phase
    /// gate on; it used to be dropped as an unknown field.
    #[test]
    fn the_two_phase_vote_gate_is_read() {
        let on: HotStuffGenesisConfig = serde_json::from_str(r#"{"twoPhaseVoteGate":true}"#).unwrap();
        assert!(on.two_phase_vote_gate);
        let off: HotStuffGenesisConfig = serde_json::from_str("{}").unwrap();
        assert!(!off.two_phase_vote_gate);
        assert!(!HotStuffGenesisConfig::from_genesis(&N42_DEVNET.genesis).unwrap().two_phase_vote_gate);
    }

    /// gov5's `rotateOnTimeoutView`: absent or null is off, a number is the
    /// first TC view the rule applies to (0 included).
    #[test]
    fn the_rotate_on_timeout_view_is_read() {
        let parse = |json: &str| serde_json::from_str::<HotStuffGenesisConfig>(json).unwrap().rotate_on_timeout_view;
        assert_eq!(parse("{}"), None);
        assert_eq!(parse(r#"{"rotateOnTimeoutView":null}"#), None);
        assert_eq!(parse(r#"{"rotateOnTimeoutView":0}"#), Some(0));
        assert_eq!(parse(r#"{"rotateOnTimeoutView":100}"#), Some(100));
        assert!(serde_json::from_str::<HotStuffGenesisConfig>(r#"{"rotateOnTimeoutView":-1}"#).is_err());
        assert_eq!(HotStuffGenesisConfig::from_genesis(&N42_DEVNET.genesis).unwrap().rotate_on_timeout_view, None);
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

    fn with_hotstuff(hotstuff: &str) -> Genesis {
        serde_json::from_str(&format!(r#"{{"config":{{"chainId":1,"hotstuff":{hotstuff}}},"alloc":{{}}}}"#))
            .expect("a genesis")
    }

    /// A listed key is refused only when it activates: absent or null is
    /// off, any value switches the rule on. Run over a test-only list, since
    /// the shipped list is empty.
    #[test]
    fn a_listed_rule_is_refused_only_when_it_activates() {
        const LIST: &[&str] = &["testOnlyRuleView"];
        for off in [r#"{"leaderTenure":8}"#, r#"{"leaderTenure":8,"testOnlyRuleView":null}"#] {
            refuse_listed_rules(&with_hotstuff(off), LIST).expect(off);
        }
        for on in ["0", "100", "18446744073709551615"] {
            let genesis = with_hotstuff(&format!(r#"{{"leaderTenure":8,"testOnlyRuleView":{on}}}"#));
            match refuse_listed_rules(&genesis, LIST) {
                Err(HotStuffConfigError::Unimplemented { field: "testOnlyRuleView", value }) => {
                    assert_eq!(value, on);
                }
                other => panic!("{on}: {other:?}"),
            }
            // The config reader itself still ignores the key.
            HotStuffGenesisConfig::from_genesis(&genesis).expect("still a hotstuff block");
        }
        // Unknown keys outside the list keep loading.
        refuse_listed_rules(&with_hotstuff(r#"{"fastPropose":true,"ethELCompat":true}"#), LIST).expect("not listed");
        // No hotstuff block at all: nothing to refuse.
        let plain: Genesis = serde_json::from_str(r#"{"config":{"chainId":1},"alloc":{}}"#).unwrap();
        refuse_listed_rules(&plain, LIST).expect("no hotstuff block");
    }

    /// `rotateOnTimeoutView` is implemented: any value loads and the parsed
    /// config carries it (gov5's `*uint64`, absent or null = off).
    #[test]
    fn rotate_on_timeout_loads_and_is_carried() {
        assert!(UNIMPLEMENTED_ACTIVATING_FIELDS.is_empty());
        for (json, want) in [
            (r#"{"leaderTenure":8}"#, None),
            (r#"{"leaderTenure":8,"rotateOnTimeoutView":null}"#, None),
            (r#"{"leaderTenure":8,"rotateOnTimeoutView":0}"#, Some(0)),
            (r#"{"leaderTenure":8,"rotateOnTimeoutView":100}"#, Some(100)),
            (r#"{"leaderTenure":8,"rotateOnTimeoutView":18446744073709551615}"#, Some(u64::MAX)),
        ] {
            let genesis = with_hotstuff(json);
            refuse_unimplemented_rules(&genesis).expect(json);
            let config = HotStuffGenesisConfig::from_genesis(&genesis).expect(json);
            assert_eq!(config.rotate_on_timeout_view, want, "{json}");
        }
    }
}
