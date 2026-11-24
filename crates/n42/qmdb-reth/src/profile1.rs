// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Profile 1 of the mixed block production standard, the genesis and
//! configuration layer (`docs/MIXED_PRODUCTION_STANDARD.md`, sections 1 and
//! 5, decisions O4/O8/O9, amendments AM5, AM8-AM12, AM16, AM17, AM22).
//!
//! `"n42Profile": 1` in the genesis `config` is the single switch that says
//! "every rule of profile 1, from block 0" (P2). On such a genesis:
//!
//! - [`profile1`] validates the file fail-closed (P4): a CLOSED key list for
//!   `config`, `config.hotstuff`, `config.hotstuff.committeePool` and each
//!   validator, no legacy activation field, every mandatory field present and
//!   in range, every Ethereum fork field present and 0. It returns the typed
//!   [`Profile1Config`]. [`crate::check_genesis`] calls it, so `n42 node`,
//!   `n42 init` and `h2_validator --chain` refuse such a genesis before
//!   anything starts.
//! - The activation predicates the node already consults answer "on from
//!   block 0" (or "off") without the call sites knowing about the profile:
//!   `reth_chainspec::qmdb` (deferred execution, Amsterdam, `MobileAnchor`,
//!   0x50, frame blocks, QMDB) and [`crate::HotStuffGenesisConfig::from_genesis`]
//!   (timeouts, pacing, rotate-on-timeout, the two-phase vote gate, H2-v4,
//!   the committee pool). [`ACTIVATIONS`] lists them.
//! - [`refuse_overrides`] refuses the environment variables and flags that
//!   could change a consensus-visible value (P3, J4, AM10).
//!
//! A genesis without `n42Profile` is untouched by all of this (AM9).

use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, U256};
pub use reth_chainspec::qmdb::{is_profile1, N42_PROFILE_1, N42_PROFILE_KEY};
use serde_json::{Map, Value};

use crate::hotstuff::{parse_decimal_wei, GenesisValidator, HotStuffGenesisConfig, HOTSTUFF_KEY};

// ------------------------------------------------------------------ key lists --
//
// gov5 publishes the authoritative closed key list with the standard genesis
// file (AM12). These tables are built from section 5 and the amendments; diff
// them against gov5's list whenever it changes, and change both together.

/// Every key a profile-1 genesis `config` may carry (section 5). Any other
/// key refuses the start.
pub const CONFIG_KEYS: &[&str] = &[
    "chainId",
    N42_PROFILE_KEY,
    "homesteadBlock",
    "eip150Block",
    "eip155Block",
    "eip158Block",
    "byzantiumBlock",
    "constantinopleBlock",
    "petersburgBlock",
    "istanbulBlock",
    "berlinBlock",
    "londonBlock",
    "mergeNetsplitBlock",
    "terminalTotalDifficulty",
    "terminalTotalDifficultyPassed",
    "shanghaiTime",
    "cancunTime",
    "pragueTime",
    "osakaTime",
    "amsterdamTime",
    "blobSchedule",
    "consensus",
    "stateScheme",
    HOTSTUFF_KEY,
];

/// The Ethereum fork fields a profile-1 genesis must carry, each `0`: they
/// name the EVM rule set and nothing else (P2, A4).
pub const ZERO_FORK_FIELDS: &[&str] = &[
    "homesteadBlock",
    "eip150Block",
    "eip155Block",
    "eip158Block",
    "byzantiumBlock",
    "constantinopleBlock",
    "petersburgBlock",
    "istanbulBlock",
    "berlinBlock",
    "londonBlock",
    "mergeNetsplitBlock",
    "shanghaiTime",
    "cancunTime",
    "pragueTime",
    "osakaTime",
    "amsterdamTime",
];

/// Every key `config.hotstuff` carries on profile 1; all are mandatory
/// (section 5 with AM12, AM16, AM22).
pub const HOTSTUFF_KEYS: &[&str] = &[
    "validators",
    "leaderTenure",
    "baseTimeoutMs",
    "maxTimeoutMs",
    "blockIntervalMs",
    "epochLength",
    "deferredExecutionDepth",
    "gasLimit",
    "maxBlockBytes",
    "committeePool",
    "devBlockReward",
    "devFaucetAddress",
];

/// Every key `config.hotstuff.committeePool` carries; all mandatory (A19).
pub const COMMITTEE_POOL_KEYS: &[&str] = &["seedHex", "poolSize", "committeeSize", "rampBlocks"];

/// Every key one `config.hotstuff.validators[i]` carries; both mandatory (A3).
pub const VALIDATOR_KEYS: &[&str] = &["address", "blsKey"];

/// `config` fields that switched a rule on at a time or block on earlier
/// chains. On profile 1 every such rule holds from block 0 and the field is
/// refused (P2, P5), with the rule it named.
pub const LEGACY_CONFIG_FIELDS: &[(&str, &str)] = &[
    ("deferredExecutionTime", "deferred execution is on from block 1 (A10)"),
    ("deferredExecutionDepth", "the depth is config.hotstuff.deferredExecutionDepth (A10, O4)"),
    ("mobileAnchorTime", "MobileAnchor holds from block 0 (A20)"),
    ("glamsterdamTime", "Amsterdam is spelled amsterdamTime: 0 (A4, AM1)"),
    ("unchangedAccountNoOpTime", "the unchanged-account no-op rule holds from block 1 (A9)"),
    ("storageNetChangeTime", "the storage net-change rule holds from block 1 (D5)"),
    ("rotateOnTimeoutView", "rotate-on-timeout holds from view 0 (A22)"),
    ("balTime", "element 22 is the 0x80 gap (B12, O6)"),
    ("eofTime", "EOF is off (O10)"),
    ("ltHashTime", "no LtHash summary in profile 1 (AM20)"),
    ("interopV4", "H2-v4 is the only signing profile (A14)"),
    ("twoPhaseVoteGate", "the vote gate of A13 always applies"),
    ("altSigTx", "type 0x50 is not in profile 1 (A11, O3)"),
    ("frameBlocks", "frame blocks are not in profile 1 (A12)"),
    ("fusakaTime", "forks are spelled the Ethereum way (A4)"),
    ("pectraTime", "forks are spelled the Ethereum way (A4)"),
    ("shanghaiBlock", "no block-number forks (A4, P5)"),
    ("cancunBlock", "no block-number forks (A4, P5)"),
];

/// `config.hotstuff` fields of earlier chains that profile 1 replaces or
/// turns into a constant.
pub const LEGACY_HOTSTUFF_FIELDS: &[(&str, &str)] = &[
    ("period", "pacing is blockIntervalMs (A17)"),
    ("baseTimeout", "the field is baseTimeoutMs (A16)"),
    ("maxTimeout", "the field is maxTimeoutMs (A16)"),
    ("rotateOnTimeoutView", "rotate-on-timeout holds from view 0 (A22)"),
    ("twoPhaseVoteGate", "the vote gate of A13 always applies"),
    ("interopV4", "H2-v4 is the only signing profile (A14)"),
    ("fastPropose", "local pacing is not a genesis field (A21)"),
    ("minProposeDelayMs", "local pacing is not a genesis field (A21)"),
    ("ethELCompat", "not a genesis field (A21)"),
    ("deferredExecutionTime", "deferred execution is on from block 1 (A10)"),
];

/// `config.hotstuff.committeePool` fields of earlier chains.
pub const LEGACY_COMMITTEE_POOL_FIELDS: &[(&str, &str)] = &[
    ("enabled", "the committee pool is always on (A19)"),
    ("allowHandover", "no handover in profile 1 (A19)"),
];

/// The deferred-execution depth profile 1 runs (A10, O4). This node also
/// runs depth 2 on its own chains, but no other client does, so on profile 1
/// a depth of 2 is refused as gov5's V8 case `deferred_depth_2` requires.
pub const PROFILE1_DEFERRED_EXECUTION_DEPTH: u64 = 1;

/// The smallest validator set profile 1 runs (A3: `n >= 4`).
pub const MIN_VALIDATORS: usize = 4;

/// One gwei in wei: rewards are paid as EIP-4895 withdrawals (AM12).
const GWEI: u64 = 1_000_000_000;

// -------------------------------------------------------------- activations --

/// Every activation predicate the node consults, what profile 1 makes of it,
/// and the switch it feeds. Documentation and a test target: the switches
/// themselves read the genesis (`reth_chainspec::qmdb`, `HotStuffGenesisConfig`).
pub const ACTIVATIONS: &[(&str, bool, &str)] = &[
    ("deferred execution at hotstuff.deferredExecutionDepth", true, "reth_chainspec::qmdb::deferred_execution_time = Some(0), deferred_execution_depth"),
    ("Amsterdam execution (gov5's Glamsterdam set)", true, "reth_chainspec::qmdb::glamsterdam_time = Some(0); reth's own Amsterdam unscheduled (spec.rs from_genesis)"),
    ("slotNumber header field", true, "reth_chainspec::qmdb::glamsterdam_active_at"),
    ("mobileRegistryRoot header field", true, "reth_chainspec::qmdb::mobile_anchor_time = Some(0)"),
    ("N42-native transaction and EVM rules (no blobs)", true, "reth_chainspec::qmdb::is_n42_native"),
    ("QMDB state commitment", true, "reth_chainspec::qmdb::state_scheme"),
    ("rotate-on-timeout", true, "HotStuffGenesisConfig::rotate_on_timeout_view = Some(0)"),
    ("profile-1 vote rules (Round 1 after check, CommitVote after own import, no progress or direct-only votes, split tags)", true, "HotStuffGenesisConfig::vote_rules -> H2Service::with_vote_rules (two_phase_vote_gate stays off)"),
    ("H2-v4 signing", true, "HotStuffGenesisConfig::interop_v4"),
    ("committee pool / parentBeaconRoot link", true, "HotStuffGenesisConfig::committee_pool (enabled)"),
    ("QC embedding in Extra", true, "unconditional on a --chain validator (h2_validator gov5 profile)"),
    ("unchanged-account no-op, storage net change", true, "unconditional in n42-qmdb-state (no switch)"),
    ("type 0x50 AltSig", false, "reth_chainspec::qmdb::alt_sig_tx_enabled"),
    ("frame blocks", false, "reth_chainspec::qmdb::frame_blocks_enabled"),
];

// ------------------------------------------------------------------- errors --

/// Why a genesis or a start-up configuration is refused on profile 1.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Profile1Error {
    /// `n42Profile` set to something other than the integer 1.
    #[error("genesis config {N42_PROFILE_KEY} = {0}: this node implements profile {N42_PROFILE_1} only")]
    UnsupportedProfile(String),
    /// A key outside the closed lists.
    #[error("profile-1 genesis: unknown key {0}; the profile's key list is closed (standard P4, AM12)")]
    UnknownKey(String),
    /// A legacy activation or replaced field.
    #[error("profile-1 genesis: legacy field {path} is refused: {reason} (standard P2)")]
    LegacyField {
        /// Where, e.g. `config.deferredExecutionTime`.
        path: String,
        /// What profile 1 does instead.
        reason: &'static str,
    },
    /// A mandatory field is absent.
    #[error("profile-1 genesis: mandatory field {0} is missing (no default applies)")]
    Missing(String),
    /// A field present with a value outside what profile 1 allows.
    #[error("profile-1 genesis: {path} {reason}")]
    Invalid {
        /// Where.
        path: String,
        /// What is wrong.
        reason: String,
    },
    /// An environment variable or flag that could change a consensus-visible
    /// value.
    #[error(
        "profile 1: {name} is set{detail}: {reason}. On a profile-1 chain the genesis is the only \
         source of consensus-visible values (standard P3, J4, AM10); unset it"
    )]
    Override {
        /// The variable or flag.
        name: String,
        /// The value, when the rule depends on it.
        detail: String,
        /// Why it is refused.
        reason: &'static str,
    },
}

fn invalid(path: impl Into<String>, reason: impl Into<String>) -> Profile1Error {
    Profile1Error::Invalid { path: path.into(), reason: reason.into() }
}

// ------------------------------------------------------------------- config --

/// A validated profile-1 genesis: every consensus parameter the profile
/// reads from it (A2), nothing from anywhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile1Config {
    /// `config.chainId` (A1).
    pub chain_id: u64,
    /// The fixed validator set, in QC bitmap order (A3, AM5).
    pub validators: Vec<GenesisValidator>,
    /// Views per leader (A15), at least 1.
    pub leader_tenure: u64,
    /// First view timeout, ms (A16).
    pub base_timeout_ms: u64,
    /// Backoff ceiling, ms (A16), at least `base_timeout_ms`.
    pub max_timeout_ms: u64,
    /// Minimum pacing after the parent is held, ms (A17).
    pub block_interval_ms: u64,
    /// Views per epoch (A18), at least 1.
    pub epoch_length: u64,
    /// How many blocks back the execution a header carries is (A10).
    pub deferred_execution_depth: u64,
    /// Every header's gas limit (A23), equal to the genesis header's.
    pub gas_limit: u64,
    /// The block size bound, decoded RLP bytes (B15).
    pub max_block_bytes: u64,
    /// The committee pool (A19).
    pub committee_pool: n42_h2_consensus::CommitteePoolConfig,
    /// Wei per block to the coinbase and to the faucet (A8, AM8): a whole
    /// number of gwei, at most `u64::MAX` gwei.
    pub dev_block_reward_wei: U256,
    /// The faucet, never zero (AM16).
    pub dev_faucet_address: Address,
}

impl Profile1Config {
    /// The block reward in gwei, as the withdrawals carry it.
    pub fn dev_block_reward_gwei(&self) -> u64 {
        // Validated: whole gwei, at most u64::MAX gwei.
        u64::try_from(self.dev_block_reward_wei / U256::from(GWEI)).unwrap_or(u64::MAX)
    }
}

/// Validates a genesis against profile 1 when it declares it.
///
/// `Ok(None)`: no `n42Profile` key, a pre-profile chain, read as before.
/// `Ok(Some(_))`: a valid profile-1 genesis. `Err(_)`: refused; the message
/// names the key or value at fault.
pub fn profile1(genesis: &Genesis) -> Result<Option<Profile1Config>, Profile1Error> {
    let Some(declared) = genesis.config.extra_fields.get(N42_PROFILE_KEY) else {
        return Ok(None);
    };
    if declared.as_u64() != Some(N42_PROFILE_1) {
        return Err(Profile1Error::UnsupportedProfile(declared.to_string()));
    }
    debug_assert!(is_profile1(genesis));

    // The `config` object as JSON: the typed fields alloy knows (absent ones
    // are skipped when serialised) and every extra field.
    let config = serde_json::to_value(&genesis.config).map_err(|e| invalid("config", e.to_string()))?;
    let config = config.as_object().ok_or_else(|| invalid("config", "is not an object"))?;
    check_keys(config, "config", CONFIG_KEYS, LEGACY_CONFIG_FIELDS, |key, value| {
        // alloy writes `daoForkSupport: false` for every config; only a true
        // one is a key the genesis set.
        key == "daoForkSupport" && value == &Value::Bool(false)
    })?;
    for field in ZERO_FORK_FIELDS {
        let value = u64_field(config, "config", field)?;
        if value != 0 {
            return Err(invalid(format!("config.{field}"), format!("must be 0, found {value}")));
        }
    }
    match genesis.config.terminal_total_difficulty {
        None => return Err(Profile1Error::Missing("config.terminalTotalDifficulty".into())),
        Some(ttd) if !ttd.is_zero() => {
            return Err(invalid("config.terminalTotalDifficulty", format!("must be 0, found {ttd}")))
        }
        Some(_) => {}
    }
    if !genesis.config.terminal_total_difficulty_passed {
        return Err(invalid("config.terminalTotalDifficultyPassed", "must be true"));
    }
    expect_string(config, "config", "consensus", "hotstuff")?;
    expect_string(config, "config", "stateScheme", "qmdb")?;

    // `config.hotstuff`.
    let hotstuff = object_field(config, "config", HOTSTUFF_KEY)?;
    let hs = "config.hotstuff";
    check_keys(hotstuff, hs, HOTSTUFF_KEYS, LEGACY_HOTSTUFF_FIELDS, |_, _| false)?;
    for key in HOTSTUFF_KEYS {
        if !hotstuff.contains_key(*key) {
            return Err(Profile1Error::Missing(format!("{hs}.{key}")));
        }
    }
    let leader_tenure = u64_field(hotstuff, hs, "leaderTenure")?;
    if leader_tenure == 0 {
        return Err(invalid(format!("{hs}.leaderTenure"), "must be at least 1 (A15, AM12)"));
    }
    let epoch_length = u64_field(hotstuff, hs, "epochLength")?;
    if epoch_length == 0 {
        return Err(invalid(format!("{hs}.epochLength"), "must be at least 1 (A18, AM12)"));
    }
    let block_interval_ms = u64_field(hotstuff, hs, "blockIntervalMs")?;
    if block_interval_ms == 0 {
        return Err(invalid(format!("{hs}.blockIntervalMs"), "must be at least 1 (A17)"));
    }
    let base_timeout_ms = u64_field(hotstuff, hs, "baseTimeoutMs")?;
    if base_timeout_ms == 0 {
        return Err(invalid(format!("{hs}.baseTimeoutMs"), "must be at least 1 (A16)"));
    }
    let max_timeout_ms = u64_field(hotstuff, hs, "maxTimeoutMs")?;
    if max_timeout_ms < base_timeout_ms {
        return Err(invalid(
            format!("{hs}.maxTimeoutMs"),
            format!("{max_timeout_ms} is below baseTimeoutMs {base_timeout_ms} (A16)"),
        ));
    }
    let deferred_execution_depth = reth_chainspec::qmdb::check_deferred_execution_depth(genesis)
        .map_err(|e| invalid(format!("{hs}.deferredExecutionDepth"), e.to_string()))?;
    if deferred_execution_depth != PROFILE1_DEFERRED_EXECUTION_DEPTH {
        return Err(invalid(
            format!("{hs}.deferredExecutionDepth"),
            format!(
                "{deferred_execution_depth} is not implemented on profile 1, which runs depth \
                 {PROFILE1_DEFERRED_EXECUTION_DEPTH} (A10, O4: a deeper depth is a later profile change; gov5 V8 deferred_depth_2)"
            ),
        ));
    }
    let gas_limit = u64_field(hotstuff, hs, "gasLimit")?;
    if gas_limit == 0 {
        return Err(invalid(format!("{hs}.gasLimit"), "must be above 0 (A23)"));
    }
    if gas_limit != genesis.gas_limit {
        return Err(invalid(
            format!("{hs}.gasLimit"),
            format!("{gas_limit} differs from the genesis header's gasLimit {} (A23)", genesis.gas_limit),
        ));
    }
    let max_block_bytes = u64_field(hotstuff, hs, "maxBlockBytes")?;
    if max_block_bytes == 0 || usize::try_from(max_block_bytes).is_err() {
        return Err(invalid(format!("{hs}.maxBlockBytes"), format!("{max_block_bytes} is not a usable size (B15)")));
    }

    // Validators: a closed object each, n >= 4.
    let validators = hotstuff
        .get("validators")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("{hs}.validators"), "must be an array"))?;
    if validators.len() < MIN_VALIDATORS {
        return Err(invalid(
            format!("{hs}.validators"),
            format!("lists {} validators; profile 1 needs at least {MIN_VALIDATORS} (A3)", validators.len()),
        ));
    }
    for (index, validator) in validators.iter().enumerate() {
        let path = format!("{hs}.validators[{index}]");
        let validator = validator.as_object().ok_or_else(|| invalid(&path, "must be an object"))?;
        check_keys(validator, &path, VALIDATOR_KEYS, &[], |_, _| false)?;
        for key in VALIDATOR_KEYS {
            if !validator.contains_key(*key) {
                return Err(Profile1Error::Missing(format!("{path}.{key}")));
            }
        }
    }

    // The committee pool.
    let pool_path = format!("{hs}.committeePool");
    let pool = object_field(hotstuff, hs, "committeePool")?;
    check_keys(pool, &pool_path, COMMITTEE_POOL_KEYS, LEGACY_COMMITTEE_POOL_FIELDS, |_, _| false)?;
    for key in COMMITTEE_POOL_KEYS {
        if !pool.contains_key(*key) {
            return Err(Profile1Error::Missing(format!("{pool_path}.{key}")));
        }
    }

    // The reward: a decimal string of wei, whole gwei, at most u64::MAX gwei.
    let reward_path = format!("{hs}.devBlockReward");
    let dev_block_reward_wei = match hotstuff.get("devBlockReward") {
        Some(Value::String(text)) => parse_decimal_wei(text).map_err(|e| invalid(&reward_path, e))?,
        Some(other) => {
            return Err(invalid(&reward_path, format!("must be a decimal string of wei (AM8), found {other}")))
        }
        None => return Err(Profile1Error::Missing(reward_path)),
    };
    let gwei = U256::from(GWEI);
    if !(dev_block_reward_wei % gwei).is_zero() {
        return Err(invalid(&reward_path, format!("{dev_block_reward_wei} wei is not a whole number of gwei (AM12)")));
    }
    if dev_block_reward_wei / gwei > U256::from(u64::MAX) {
        return Err(invalid(&reward_path, format!("{dev_block_reward_wei} wei is above u64::MAX gwei (AM12, AM16)")));
    }
    let faucet_path = format!("{hs}.devFaucetAddress");
    let dev_faucet_address: Address = hotstuff
        .get("devFaucetAddress")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&faucet_path, "must be an address string"))?
        .parse()
        .map_err(|e| invalid(&faucet_path, format!("is not an address: {e}")))?;
    if dev_faucet_address.is_zero() {
        return Err(invalid(&faucet_path, "must not be the zero address (AM16)"));
    }

    // The typed reading every consumer uses, normalised for profile 1.
    let typed = HotStuffGenesisConfig::from_genesis_unvalidated(genesis).map_err(|e| invalid(hs, e.to_string()))?;
    typed.validator_set().map_err(|e| invalid(format!("{hs}.validators"), e.to_string()))?;
    let committee_pool = typed
        .committee_pool
        .as_ref()
        .ok_or_else(|| Profile1Error::Missing(pool_path.clone()))?
        .config()
        .map_err(|e| invalid(&pool_path, e))?
        .ok_or_else(|| invalid(&pool_path, "is not enabled"))?;
    // The shape `SimulatedCommitteePool::new` refuses, checked without
    // deriving the pool's keys (200,000 of them on the standard genesis).
    if committee_pool.pool_size == 0
        || committee_pool.committee_size == 0
        || committee_pool.committee_size > committee_pool.pool_size
    {
        return Err(invalid(
            &pool_path,
            format!(
                "poolSize {} / committeeSize {} is not a pool (both above 0, committee within the pool)",
                committee_pool.pool_size, committee_pool.committee_size
            ),
        ));
    }

    // The genesis header's constant fields (A6, B3).
    if !genesis.extra_data.is_empty() {
        return Err(invalid("extraData", "must be empty (A6)"));
    }
    if !genesis.difficulty.is_zero() {
        return Err(invalid("difficulty", "must be 0 (B3)"));
    }
    if genesis.nonce != 0 {
        return Err(invalid("nonce", "must be 0 (B3)"));
    }
    if genesis.mix_hash != B256::ZERO {
        return Err(invalid("mixHash", "must be zero (B3)"));
    }
    if !genesis.coinbase.is_zero() {
        return Err(invalid("coinbase", "must be the zero address (section 5)"));
    }

    // A7's second clause (the first, a storage-only entry, is
    // `n42_qmdb_state::validate_alloc`, applied to every chain).
    for (address, account) in &genesis.alloc {
        if let Some((slot, _)) = account.storage.iter().flatten().find(|(_, value)| **value == B256::ZERO) {
            return Err(invalid(format!("alloc.{address}.storage.{slot}"), "is a zero-valued storage entry (A7)"));
        }
    }

    Ok(Some(Profile1Config {
        chain_id: genesis.config.chain_id,
        validators: typed.validators,
        leader_tenure,
        base_timeout_ms,
        max_timeout_ms,
        block_interval_ms,
        epoch_length,
        deferred_execution_depth,
        gas_limit,
        max_block_bytes,
        committee_pool,
        dev_block_reward_wei,
        dev_faucet_address,
    }))
}

/// Refuses a key outside `allowed`, naming a legacy one with its reason.
fn check_keys(
    object: &Map<String, Value>,
    path: &str,
    allowed: &[&str],
    legacy: &[(&str, &'static str)],
    tolerated: impl Fn(&str, &Value) -> bool,
) -> Result<(), Profile1Error> {
    for (key, value) in object {
        if let Some((_, reason)) = legacy.iter().find(|(name, _)| name == key) {
            return Err(Profile1Error::LegacyField { path: format!("{path}.{key}"), reason });
        }
        if !allowed.contains(&key.as_str()) && !tolerated(key, value) {
            return Err(Profile1Error::UnknownKey(format!("{path}.{key}")));
        }
    }
    Ok(())
}

fn u64_field(object: &Map<String, Value>, path: &str, key: &str) -> Result<u64, Profile1Error> {
    match object.get(key) {
        None | Some(Value::Null) => Err(Profile1Error::Missing(format!("{path}.{key}"))),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| invalid(format!("{path}.{key}"), format!("must be an unsigned integer, found {value}"))),
    }
}

fn object_field<'a>(object: &'a Map<String, Value>, path: &str, key: &str) -> Result<&'a Map<String, Value>, Profile1Error> {
    match object.get(key) {
        None | Some(Value::Null) => Err(Profile1Error::Missing(format!("{path}.{key}"))),
        Some(value) => value.as_object().ok_or_else(|| invalid(format!("{path}.{key}"), "must be an object")),
    }
}

fn expect_string(object: &Map<String, Value>, path: &str, key: &str, want: &str) -> Result<(), Profile1Error> {
    match object.get(key) {
        None | Some(Value::Null) => Err(Profile1Error::Missing(format!("{path}.{key}"))),
        Some(Value::String(found)) if found == want => Ok(()),
        Some(other) => Err(invalid(format!("{path}.{key}"), format!("must be {want:?}, found {other}"))),
    }
}

/// The fixed block gas limit of a profile-1 genesis (A23): what the builder
/// targets instead of `--builder.gaslimit`. `None` on any other chain.
pub fn fixed_gas_limit(genesis: &Genesis) -> Option<u64> {
    hotstuff_u64(genesis, "gasLimit")
}

/// The block size bound of a profile-1 genesis in bytes (B15): the wire and
/// byte-budget cap instead of `N42_MAX_GOSSIP_MB`. `None` on any other chain.
pub fn max_block_bytes(genesis: &Genesis) -> Option<usize> {
    hotstuff_u64(genesis, "maxBlockBytes").and_then(|bytes| usize::try_from(bytes).ok())
}

fn hotstuff_u64(genesis: &Genesis, key: &str) -> Option<u64> {
    if !is_profile1(genesis) {
        return None;
    }
    genesis.config.extra_fields.get(HOTSTUFF_KEY)?.get(key)?.as_u64()
}

// ------------------------------------------------------- environment, flags --

/// When a variable or flag in [`FORBIDDEN_ENV`] / [`FORBIDDEN_FLAGS`] refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// Present at all, whatever the value (the empty string included).
    Set,
    /// Present with a value that is not one of these (compared trimmed and
    /// case-insensitively). Fail closed: a typo refuses too.
    NotOneOf(&'static [&'static str]),
}

impl When {
    fn refuses(self, value: &str) -> bool {
        match self {
            Self::Set => true,
            Self::NotOneOf(allowed) => {
                let value = value.trim();
                !allowed.iter().any(|ok| ok.eq_ignore_ascii_case(value))
            }
        }
    }
}

/// Values that read as "off" for an `n42_env::flag` switch.
const OFF: &[&str] = &["", "0", "false", "off", "no"];

/// One refused setting: the name (a trailing `*` matches a prefix), when it
/// refuses, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    /// The variable or flag.
    pub name: &'static str,
    /// When it refuses.
    pub when: When,
    /// Why, in one line.
    pub reason: &'static str,
}

/// Environment variables refused on a profile-1 chain (J4, AM10). Variables
/// this node reads that change no consensus-visible value (threads,
/// allocator, parallel build/import, persistence and caches, ingest, logging,
/// the `N42_PROFILE=x22` knobs) stay allowed. The ones the standard's review
/// asked about, each allowed for the reason given:
///
/// | Knob | Why it stays allowed |
/// |---|---|
/// | `N42_CHECK_BEFORE_SLOT` | the vote still waits for this execution layer's check of that very block (a check-only answer it vouches for); the commit vote still waits for the own import (`VoteRules`) |
/// | `N42_IMPORT_ONCE` | keys sharing one execution layer share its one import and check of the block; the answer is the same |
/// | `N42_COMPACT_BODY` | the body's shape on the direct push channel between this client's members; the block and the topic's body are unchanged |
/// | `N42_BLOCK_BY_DESCRIPTION` | the follower checks the same transactions, held by reference instead of copied |
/// | `N42_BODY_ONCE` | the body reaches the execution layer as it arrived instead of decoded twice |
/// | `N42_TAKE_COMPACT` | the leader's build answer leaves out bytes it never reads; the block is the same |
/// | `N42_BLOCK_TOPIC_ALWAYS` | the topic is skipped only when the direct push reached every connected member, so a member without it (gov5) still gets the topic |
/// | `N42_FOLLOWER_EXEC_GATE` | how many executions overlap on this node's worker pool |
/// | `--builder.extradata` | this node's builder ignores it: a header's `extraData` is the HotStuff seal |
pub const FORBIDDEN_ENV: &[Rule] = &[
    Rule { name: "N42_MAX_GOSSIP_MB", when: When::Set, reason: "the block size bound is config.hotstuff.maxBlockBytes (B15)" },
    Rule { name: "N42_FRAME_BLOCKS", when: When::NotOneOf(OFF), reason: "frame blocks are not in profile 1 (A12)" },
    Rule { name: "N42_VOTE_TRANSPORT", when: When::NotOneOf(&["", "gossip", "both"]), reason: "every consensus message goes on the gossip topic; direct-only votes are not standard (E16)" },
    Rule { name: "N42_VOTE_BEFORE_SLOT", when: When::NotOneOf(OFF), reason: "no vote before its A13 gate (E8)" },
    Rule { name: "N42_VOTE_BEFORE_IMPORT", when: When::NotOneOf(OFF), reason: "no vote before its A13 gate (E8)" },
    Rule { name: "N42_VOTE_LOG_NOSYNC", when: When::NotOneOf(OFF), reason: "an unsynced vote log can equivocate after a crash (E7)" },
    Rule { name: "N42_BENCH_UNSAFE", when: When::NotOneOf(OFF), reason: "it unlocks paths that skip checks (J4)" },
    Rule { name: "N42_INGEST_VERIFY", when: When::NotOneOf(&["", "all"]), reason: "a node takes another's word for a sender (J4)" },
    Rule { name: "N42_FRAME_GATEWAYS", when: When::Set, reason: "frames attested by a bench gateway key skip checks; no frames in profile 1 (A12, J4)" },
    Rule { name: "N42_SYNC_ANCHOR", when: When::NotOneOf(&["", "enforce", "on", "1", "true"]), reason: "anchored ranges are enforced (section 3)" },
    Rule { name: "N42_SETTLEMENT_TAGS", when: When::NotOneOf(&["", "split"]), reason: "safe and finalized are the split tags; legacy reports uncertified blocks as finalized (E14, AM19)" },
    Rule { name: "N42_DEFERRED_DEPTH*", when: When::Set, reason: "the depth is config.hotstuff.deferredExecutionDepth (A10; gov5's name)" },
];

/// Command-line flags refused on a profile-1 chain. `n42` and `h2_validator`
/// share one table; a flag one of them does not have is never present there.
pub const FORBIDDEN_FLAGS: &[Rule] = &[
    Rule { name: "--builder.gaslimit", when: When::Set, reason: "every header's gas limit is config.hotstuff.gasLimit (A23)" },
    Rule { name: "--block-interval-ms", when: When::Set, reason: "pacing is config.hotstuff.blockIntervalMs (A17)" },
    Rule { name: "--timeout-ms", when: When::Set, reason: "the view timeouts are config.hotstuff.baseTimeoutMs / maxTimeoutMs (A16)" },
    Rule { name: "--fault-tolerance", when: When::Set, reason: "f = (n - 1) / 3 over the genesis set (A3)" },
    Rule { name: "--chain-id", when: When::Set, reason: "the chain id comes from the genesis (A1)" },
    Rule { name: "--genesis", when: When::Set, reason: "the genesis hash is computed from the genesis file (A1)" },
    Rule { name: "--validators", when: When::Set, reason: "the validator set is config.hotstuff.validators (A3, AM5)" },
    Rule { name: "--straggler-grace-ms", when: When::NotOneOf(&["0"]), reason: "the straggler grace sends progress votes, which are not in profile 1 (E9)" },
];

/// Refuses, on a profile-1 genesis, any of [`FORBIDDEN_ENV`] in `vars` and
/// any of [`FORBIDDEN_FLAGS`] in `args` (both `--flag value` and
/// `--flag=value`). Does nothing on any other genesis (AM10).
pub fn refuse_overrides<V, A>(genesis: &Genesis, vars: V, args: A) -> Result<(), Profile1Error>
where
    V: IntoIterator<Item = (String, String)>,
    A: IntoIterator<Item = String>,
{
    if !is_profile1(genesis) {
        return Ok(());
    }
    let mut vars: Vec<(String, String)> = vars.into_iter().collect();
    vars.sort();
    for rule in FORBIDDEN_ENV {
        for (name, value) in &vars {
            let matches = match rule.name.strip_suffix('*') {
                Some(prefix) => name.starts_with(prefix),
                None => name == rule.name,
            };
            if matches && rule.when.refuses(value) {
                let detail = match rule.when {
                    When::Set if rule.name.ends_with('*') => format!(" ({name}={value:?})"),
                    When::Set => String::new(),
                    When::NotOneOf(_) => format!(" to {value:?}"),
                };
                return Err(Profile1Error::Override { name: name.clone(), detail, reason: rule.reason });
            }
        }
    }
    let args: Vec<String> = args.into_iter().collect();
    for (position, arg) in args.iter().enumerate() {
        for rule in FORBIDDEN_FLAGS {
            let value = if arg == rule.name {
                Some(args.get(position + 1).map_or("", String::as_str))
            } else {
                arg.strip_prefix(rule.name).and_then(|rest| rest.strip_prefix('='))
            };
            if let Some(value) = value.filter(|value| rule.when.refuses(value)) {
                let detail = match rule.when {
                    When::Set => String::new(),
                    When::NotOneOf(_) => format!(" to {value:?}"),
                };
                return Err(Profile1Error::Override { name: rule.name.to_owned(), detail, reason: rule.reason });
            }
        }
    }
    Ok(())
}

/// [`refuse_overrides`] over this process's environment and command line:
/// the one check `n42` (every command with a chain: `node`, `init`, ...)
/// and `h2_validator --chain` run at start-up, after the `N42_PROFILE`
/// knobs are applied and reconciled with the chain.
pub fn refuse_process_overrides(genesis: &Genesis) -> Result<(), Profile1Error> {
    let vars = std::env::vars_os()
        .map(|(name, value)| (name.to_string_lossy().into_owned(), value.to_string_lossy().into_owned()));
    let args = std::env::args_os().skip(1).map(|arg| arg.to_string_lossy().into_owned());
    refuse_overrides(genesis, vars, args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_chainspec::{qmdb, EthereumHardforks};
    use reth_cli::chainspec::ChainSpecParser as _;
    use std::path::{Path, PathBuf};

    fn genesis_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../chainspec/res/genesis")
    }

    /// The DRAFT profile-1 genesis: section 5 with the amendments' values and
    /// the four dev validators. gov5 cuts the authoritative file; this one
    /// exists to test loading.
    fn draft_path() -> PathBuf {
        genesis_dir().join("n42_profile1_draft.json")
    }

    fn parse(path: &Path) -> eyre::Result<std::sync::Arc<reth_chainspec::ChainSpec>> {
        crate::N42ChainSpecParser::parse(path.to_str().expect("utf-8 path"))
    }

    fn draft() -> std::sync::Arc<reth_chainspec::ChainSpec> {
        parse(&draft_path()).unwrap_or_else(|e| panic!("the draft loads: {e:#}"))
    }

    #[test]
    fn the_draft_loads_with_the_amendments_values() {
        let spec = draft();
        let config = profile1(&spec.genesis).expect("valid").expect("a profile-1 genesis");
        assert_eq!(config.chain_id, 1144);
        assert_eq!(config.validators.len(), 4);
        assert_eq!(config.leader_tenure, 1);
        assert_eq!(config.base_timeout_ms, 24_000);
        assert_eq!(config.max_timeout_ms, 96_000);
        assert_eq!(config.block_interval_ms, 8_000);
        assert_eq!(config.epoch_length, 10_800);
        assert_eq!(config.deferred_execution_depth, 1);
        assert_eq!(config.gas_limit, 480_000_000);
        assert_eq!(config.max_block_bytes, 64 << 20);
        assert_eq!(config.committee_pool.pool_size, 200_000);
        assert_eq!(config.committee_pool.committee_size, 512);
        assert_eq!(config.dev_block_reward_gwei(), 1_000_000_000);
        assert!(!config.dev_faucet_address.is_zero());
        assert_eq!(fixed_gas_limit(&spec.genesis), Some(480_000_000));
        assert_eq!(max_block_bytes(&spec.genesis), Some(64 << 20));
    }

    /// Every switch the node consults reads "on from block 0" (or "off") on
    /// the draft, through the functions the call sites already use.
    #[test]
    fn every_activation_predicate_is_fed_from_the_profile() {
        let spec = draft();
        let g = &spec.genesis;
        let ts = g.timestamp;
        assert!(qmdb::is_profile1(g));
        assert_eq!(qmdb::deferred_execution_time(g), Some(0));
        assert!(qmdb::deferred_execution_active_at(g, ts));
        assert_eq!(qmdb::check_deferred_execution_depth(g), Ok(1));
        assert_eq!(qmdb::deferred_execution_depth_at(g, ts + 1), 1);
        assert!(qmdb::glamsterdam_active_at(g, ts));
        assert!(qmdb::glamsterdam_execution_active_at(g, ts));
        assert!(qmdb::mobile_registry_root_in_header_at(g, ts));
        assert!(qmdb::is_n42_native(g));
        assert_eq!(qmdb::state_scheme(g), qmdb::StateScheme::Qmdb);
        assert!(!qmdb::alt_sig_tx_enabled(g));
        assert!(!qmdb::frame_blocks_enabled(g));
        // AM1: amsterdamTime is gov5's Glamsterdam set, not reth's bundle.
        assert!(!spec.is_amsterdam_active_at_timestamp(ts));
        assert!(spec.is_osaka_active_at_timestamp(ts));
        let header = spec.genesis_header();
        assert_eq!(header.state_root, qmdb::qmdb_genesis_root(g).expect("a root"));
        assert_eq!(header.block_access_list_hash, Some(alloy_eips::eip7928::EMPTY_BLOCK_ACCESS_LIST_HASH));
        assert_eq!(header.slot_number, None);
        assert!(header.extra_data.is_empty());
        assert_eq!(header.gas_limit, 480_000_000);

        let hotstuff = HotStuffGenesisConfig::from_genesis(g).expect("a hotstuff block");
        assert_eq!(hotstuff.profile1(), profile1(g).expect("valid").as_ref(), "the typed config is attached");
        assert_eq!(hotstuff.rotate_on_timeout_view, Some(0));
        assert!(!hotstuff.two_phase_vote_gate, "VoteRules carries the gate on profile 1");
        assert_eq!(hotstuff.vote_rules(), n42_h2_consensus::VoteRules::PROFILE1);
        assert!(hotstuff.interop_v4);
        assert_eq!(hotstuff.base_timeout, 24_000);
        assert_eq!(hotstuff.max_timeout, 96_000);
        assert_eq!(hotstuff.period, 8);
        assert_eq!(hotstuff.leader_tenure, 1);
        assert_eq!(hotstuff.epoch_length, 10_800);
        let pool = hotstuff.committee_pool.as_ref().expect("a pool");
        assert!(pool.enabled, "A19: always on");
        assert!(pool.config().expect("a seed").is_some());
        assert_eq!(hotstuff.dev_block_reward, U256::from(10u64).pow(U256::from(18)));
        assert_eq!(hotstuff.block_rewards(Address::repeat_byte(7)).len(), 2);
        assert_eq!(ACTIVATIONS.len(), 14);
    }

    /// A genesis without `n42Profile` is not a profile-1 genesis and none of
    /// this applies to it: every shipped file still reads `None` here (the
    /// parser test in `chainspec.rs` loads each one).
    #[test]
    fn shipped_pre_profile_geneses_are_untouched() {
        let mut checked = 0;
        for dir in [genesis_dir(), genesis_dir().join("gov5")] {
            for entry in std::fs::read_dir(&dir).expect("the genesis directory") {
                let path = entry.expect("an entry").path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_owned();
                if path.extension().is_none_or(|e| e != "json")
                    || name == "n42_devnet_validators.json"
                    || name == "n42_profile1_draft.json"
                {
                    continue;
                }
                let spec = parse(&path).unwrap_or_else(|e| panic!("{name}: {e:#}"));
                assert!(!qmdb::is_profile1(&spec.genesis), "{name}");
                assert_eq!(profile1(&spec.genesis), Ok(None), "{name}");
                if let Ok(hotstuff) = HotStuffGenesisConfig::from_genesis(&spec.genesis) {
                    assert!(hotstuff.profile1().is_none(), "{name}");
                    assert_eq!(hotstuff.vote_rules(), n42_h2_consensus::VoteRules::TODAY, "{name}");
                }
                refuse_overrides(
                    &spec.genesis,
                    [("N42_FRAME_BLOCKS".to_owned(), "1".to_owned()), ("N42_MAX_GOSSIP_MB".to_owned(), "64".to_owned())],
                    ["--builder.gaslimit".to_owned(), "1".to_owned()],
                )
                .unwrap_or_else(|e| panic!("{name}: {e}"));
                checked += 1;
            }
        }
        assert!(checked >= 20, "{checked}");
    }

    /// Every refused-genesis fixture (V8's refused cases plus this node's
    /// own) is refused by the parser `n42 node`, `n42 init` and
    /// `h2_validator --chain` use, with a message naming the cause.
    #[test]
    fn every_refused_fixture_is_refused_naming_the_cause() {
        const CASES: &[(&str, &str)] = &[
            ("refused_unknown_config_key", "unknown key config.someNewRuleTime"),
            ("refused_unknown_hotstuff_key", "unknown key config.hotstuff.slotMs"),
            ("refused_unknown_validator_key", "unknown key config.hotstuff.validators[2].peerId"),
            ("refused_legacy_deferred_execution_time", "legacy field config.deferredExecutionTime"),
            ("refused_legacy_mobile_anchor_time", "legacy field config.mobileAnchorTime"),
            ("refused_legacy_alt_sig_tx", "legacy field config.altSigTx"),
            ("refused_legacy_frame_blocks", "legacy field config.frameBlocks"),
            ("refused_legacy_eof_time", "legacy field config.eofTime"),
            ("refused_legacy_rotate_on_timeout_view", "legacy field config.hotstuff.rotateOnTimeoutView"),
            ("refused_legacy_period", "legacy field config.hotstuff.period"),
            ("refused_legacy_pool_enabled", "legacy field config.hotstuff.committeePool.enabled"),
            ("refused_missing_leader_tenure", "mandatory field config.hotstuff.leaderTenure is missing"),
            ("refused_missing_epoch_length", "mandatory field config.hotstuff.epochLength is missing"),
            ("refused_missing_deferred_depth", "mandatory field config.hotstuff.deferredExecutionDepth is missing"),
            ("refused_missing_max_block_bytes", "mandatory field config.hotstuff.maxBlockBytes is missing"),
            ("refused_missing_amsterdam_time", "mandatory field config.amsterdamTime is missing"),
            ("refused_missing_state_scheme", "mandatory field config.stateScheme is missing"),
            ("refused_zero_leader_tenure", "config.hotstuff.leaderTenure must be at least 1"),
            ("refused_zero_epoch_length", "config.hotstuff.epochLength must be at least 1"),
            ("refused_max_timeout_below_base", "config.hotstuff.maxTimeoutMs 1000 is below baseTimeoutMs 24000"),
            ("refused_depth_not_implemented", "deferredExecutionDepth must be 1 or 2, found 3"),
            ("refused_gas_limit_mismatch", "differs from the genesis header's gasLimit 480000000"),
            ("refused_nonzero_fork", "config.cancunTime must be 0, found 5"),
            ("refused_extra_data", "extraData must be empty"),
            ("refused_three_validators", "lists 3 validators"),
            ("refused_reward_not_whole_gwei", "1000000000000000001 wei is not a whole number of gwei"),
            ("refused_reward_above_u64_gwei", "above u64::MAX gwei"),
            ("refused_reward_json_number", "devBlockReward must be a decimal string of wei"),
            ("refused_zero_faucet", "devFaucetAddress must not be the zero address"),
            ("refused_storage_only_alloc", "nonce 0, zero balance and empty code"),
            ("refused_zero_value_storage", "zero-valued storage entry"),
            ("refused_profile_2", "n42Profile = 2"),
            ("refused_profile_string", "n42Profile = \"1\""),
        ];
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/profile1");
        let on_disk = std::fs::read_dir(&dir)
            .expect("the fixture directory")
            .filter(|entry| entry.as_ref().expect("an entry").path().extension().is_some_and(|e| e == "json"))
            .count();
        assert_eq!(on_disk, CASES.len(), "every fixture has a case and every case a fixture");
        for (name, cause) in CASES {
            let err = parse(&dir.join(format!("{name}.json"))).expect_err(name);
            let message = format!("{err:#}");
            assert!(message.contains(cause), "{name}: {message}");
        }
    }

    // ------------------------------------------------ gov5's vectors (V1, V8) --

    fn gov5_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/profile1/gov5")
    }

    /// gov5's published closed key lists (V8 `allowed-keys.json`) are exactly
    /// this node's tables.
    #[test]
    fn gov5_allowed_keys_equal_the_closed_tables() {
        let raw = std::fs::read_to_string(gov5_dir().join("V8/allowed-keys.json")).expect("V8 allowed keys");
        let allowed: Value = serde_json::from_str(&raw).expect("json");
        let keys = |section: &str| -> std::collections::BTreeSet<String> {
            ["mandatory", "optional"]
                .iter()
                .flat_map(|kind| allowed[section][*kind].as_array().expect("a list").iter())
                .map(|key| key.as_str().expect("a key").to_owned())
                .collect()
        };
        let ours = |table: &[&str]| table.iter().map(|key| (*key).to_owned()).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(keys("config"), ours(CONFIG_KEYS));
        assert_eq!(keys("config.hotstuff"), ours(HOTSTUFF_KEYS));
        assert_eq!(keys("config.hotstuff.committeePool"), ours(COMMITTEE_POOL_KEYS));
        assert_eq!(keys("config.hotstuff.validators[]"), ours(VALIDATOR_KEYS));
        // The one optional key on both sides.
        assert_eq!(allowed["config"]["optional"], serde_json::json!(["blobSchedule"]));
    }

    /// gov5's V1 test genesis (the AM22 values) loads through the parser and
    /// [`profile1`].
    #[test]
    fn gov5_genesis_8s_loads() {
        let spec = parse(&gov5_dir().join("V1/genesis_8s.json")).unwrap_or_else(|e| panic!("genesis_8s: {e:#}"));
        let config = profile1(&spec.genesis).expect("valid").expect("a profile-1 genesis");
        assert_eq!(
            (config.chain_id, config.leader_tenure, config.base_timeout_ms, config.max_timeout_ms),
            (1144, 1, 24_000, 96_000)
        );
        assert_eq!((config.block_interval_ms, config.epoch_length, config.deferred_execution_depth), (8_000, 10_800, 1));
        assert_eq!((config.gas_limit, config.max_block_bytes, config.validators.len()), (480_000_000, 64 << 20, 4));
        let hotstuff = HotStuffGenesisConfig::from_genesis(&spec.genesis).expect("a hotstuff block");
        assert_eq!(hotstuff.profile1(), Some(&config));
    }

    /// Each of gov5's 14 refused geneses (V8 `refused/`) is refused here.
    #[test]
    fn gov5_refused_cases_are_refused() {
        let dir = gov5_dir().join("V8/refused");
        let mut cases = 0;
        for entry in std::fs::read_dir(&dir).expect("V8 refused") {
            let path = entry.expect("an entry").path();
            let case: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
            let name = case["case"].as_str().expect("a case name");
            let genesis: Genesis = serde_json::from_value(case["genesis"].clone()).expect("a genesis");
            let err = crate::check_genesis(&genesis).expect_err(name);
            println!("{name}: {err:#}");
            cases += 1;
        }
        assert_eq!(cases, 14);
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn a_consensus_visible_override_refuses_naming_it() {
        let spec = draft();
        let g = &spec.genesis;
        for (name, value) in [
            ("N42_MAX_GOSSIP_MB", "64"),
            ("N42_FRAME_BLOCKS", "1"),
            ("N42_VOTE_TRANSPORT", "direct"),
            ("N42_VOTE_BEFORE_SLOT", "1"),
            ("N42_VOTE_BEFORE_IMPORT", "true"),
            ("N42_VOTE_LOG_NOSYNC", "1"),
            ("N42_BENCH_UNSAFE", "1"),
            ("N42_INGEST_VERIFY", "leader"),
            ("N42_FRAME_GATEWAYS", "0xabc"),
            ("N42_SYNC_ANCHOR", "observe"),
            ("N42_SYNC_ANCHOR", "off"),
            ("N42_DEFERRED_DEPTH_K", "2"),
            ("N42_SETTLEMENT_TAGS", "legacy"),
        ] {
            let err = refuse_overrides(g, env(&[("N42_PROFILE", "x22"), (name, value)]), args(&[])).expect_err(name);
            assert!(err.to_string().contains(name), "{name}: {err}");
        }
        for flags in [
            &["node", "--builder.gaslimit", "480000000"][..],
            &["node", "--builder.gaslimit=60000000"],
            &["--block-interval-ms", "500"],
            &["--timeout-ms", "6000"],
            &["--fault-tolerance", "0"],
            &["--chain-id", "1144"],
            &["--genesis", "0x00"],
            &["--validators", "v.json"],
            &["--straggler-grace-ms", "600"],
        ] {
            let err = refuse_overrides(g, env(&[]), args(flags)).expect_err(flags[flags.len() - 1]);
            let flag = flags.iter().find(|f| f.starts_with("--")).expect("a flag");
            let flag = flag.split('=').next().expect("a name");
            assert!(err.to_string().contains(flag), "{flags:?}: {err}");
        }
    }

    #[test]
    fn local_knobs_stay_allowed_on_profile_1() {
        let spec = draft();
        refuse_overrides(
            &spec.genesis,
            env(&[
                ("N42_PROFILE", "x22"),
                ("N42_SETTLEMENT_TAGS", "split"),
                ("N42_VOTE_TRANSPORT", "both"),
                ("N42_CHECK_BEFORE_SLOT", "1"),
                ("N42_IMPORT_ONCE", "1"),
                ("N42_COMPACT_BODY", "1"),
                ("N42_BLOCK_BY_DESCRIPTION", "1"),
                ("N42_BODY_ONCE", "1"),
                ("N42_TAKE_COMPACT", "1"),
                ("N42_BLOCK_TOPIC_ALWAYS", "1"),
                ("N42_FOLLOWER_EXEC_GATE", "0"),
                ("N42_SYNC_ANCHOR", "enforce"),
                ("N42_FRAME_BLOCKS", "0"),
                ("N42_BENCH_UNSAFE", ""),
                ("N42_INGEST_VERIFY", "all"),
                ("N42_PARALLEL_BUILD", "1"),
                ("MALLOC_CONF", "thp:always"),
            ]),
            args(&["node", "--chain", "x.json", "--straggler-grace-ms", "0", "--http", "--genesis-extra", "1", "--builder.extradata", "n42"]),
        )
        .expect("nothing consensus-visible");
    }
}
