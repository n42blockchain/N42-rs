//! Which state commitment a chain uses, and the genesis header that follows.
//!
//! gov5 declares the scheme in the chain config as `"stateScheme": "qmdb"`
//! (`params.ChainConfig.StateScheme`); a chain without the field is a
//! Merkle-Patricia chain. This reads the same field from the same place, so
//! one genesis file describes the chain to both clients.
//!
//! On a QMDB chain the genesis header's state root is the twig-forest root of
//! the alloc, not its Merkle-Patricia root — gov5 seeds the forest at init and
//! writes that root into the header (`internal/genesis_qmdb.go`). Two nodes
//! that disagree on the genesis state root disagree on the genesis hash and
//! never connect, so every path that builds a genesis header goes through
//! [`genesis_header`] here.

use alloy_consensus::Header;
use alloy_genesis::Genesis;
use alloy_primitives::B256;
use n42_qmdb_state::{changes_from_alloc, QmdbForest, StateError};
use reth_ethereum_forks::ChainHardforks;

/// The genesis config key gov5 reads the scheme from.
pub const STATE_SCHEME_KEY: &str = "stateScheme";

/// The value that selects QMDB.
pub const STATE_SCHEME_QMDB: &str = "qmdb";

/// Genesis `config` key of the mixed block production standard's profile
/// (`docs/MIXED_PRODUCTION_STANDARD.md`): `"n42Profile": 1` is the single
/// switch that says "every rule of profile 1, from block 0". A genesis
/// without it is read exactly as before.
pub const N42_PROFILE_KEY: &str = "n42Profile";

/// The one profile this build implements.
pub const N42_PROFILE_1: u64 = 1;

/// Whether the genesis declares profile 1 (`"n42Profile": 1`).
///
/// Every activation predicate in this module answers "on from block 0" (or
/// "off") on such a chain, so no call site needs to know about the profile.
/// Any other value of the key is refused at start-up by
/// `n42_qmdb_reth::profile1`; here it reads as "not profile 1".
pub fn is_profile1(genesis: &Genesis) -> bool {
    genesis.config.extra_fields.get(N42_PROFILE_KEY).and_then(serde_json::Value::as_u64) == Some(N42_PROFILE_1)
}

/// How a chain commits to its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateScheme {
    /// Merkle-Patricia trie: Ethereum's, and what an unlabelled chain uses.
    Mpt,
    /// QMDB twig forest: the native chain's.
    Qmdb,
}

/// Reads the scheme a genesis declares.
///
/// Absent means MPT, matching gov5's default; a present value that is not
/// `"qmdb"` also means MPT, since gov5's other presets are all trie-shaped.
pub fn state_scheme(genesis: &Genesis) -> StateScheme {
    // Profile 1 is QMDB only (standard A5); its genesis still writes the
    // field, and start-up refuses one that does not.
    if is_profile1(genesis) {
        return StateScheme::Qmdb;
    }
    let declared: Option<String> = genesis
        .config
        .extra_fields
        .get_deserialized(STATE_SCHEME_KEY)
        .and_then(Result::ok);
    match declared.as_deref() {
        Some(STATE_SCHEME_QMDB) => StateScheme::Qmdb,
        _ => StateScheme::Mpt,
    }
}

/// Genesis `config` key that enables the 0x50 alternative-signature
/// transaction (`docs/spec/N42_TX_0x50.md`).
pub const ALT_SIG_TX_KEY: &str = "altSigTx";

/// Whether a genesis enables the 0x50 alternative-signature transaction.
/// Absent or anything but `true` means disabled: the type is rejected at
/// admission and in block validation.
pub fn alt_sig_tx_enabled(genesis: &Genesis) -> bool {
    // Not in profile 1 (standard A11, O3).
    if is_profile1(genesis) {
        return false;
    }
    genesis
        .config
        .extra_fields
        .get_deserialized::<bool>(ALT_SIG_TX_KEY)
        .and_then(Result::ok)
        .unwrap_or(false)
}

/// Genesis `config` key that makes a frame-aligned block's transactions root
/// the frame tree (`docs/BREAKTHROUGH_DESIGN.md` step 1): the binary Merkle
/// root over its frames' roots (`n42_tx_types::frame_tree_root`) instead of
/// the ordered MPT root. A body that is not frame-aligned keeps the MPT root.
pub const FRAME_BLOCKS_KEY: &str = "frameBlocks";

/// Whether a genesis enables frame blocks. Absent or anything but `true`
/// means disabled: every block's transactions root is the MPT root.
pub fn frame_blocks_enabled(genesis: &Genesis) -> bool {
    // Not in profile 1 (standard A12).
    if is_profile1(genesis) {
        return false;
    }
    genesis
        .config
        .extra_fields
        .get_deserialized::<bool>(FRAME_BLOCKS_KEY)
        .and_then(Result::ok)
        .unwrap_or(false)
}

/// Genesis `config` key: the timestamp from which headers carry the
/// execution of their *parent* -- deferred execution
/// (`docs/PHASE_D_DEFERRED_EXECUTION.md`). Absent means never.
pub const DEFERRED_EXECUTION_TIME_KEY: &str = "deferredExecutionTime";

/// The deferred-execution fork time, if the genesis declares one.
pub fn deferred_execution_time(genesis: &Genesis) -> Option<u64> {
    // Profile 1: always on, from block 1 (standard A10). 0 is the gate the
    // bench chains that run deferred execution from genesis carry.
    if is_profile1(genesis) {
        return Some(0);
    }
    genesis
        .config
        .extra_fields
        .get_deserialized::<u64>(DEFERRED_EXECUTION_TIME_KEY)
        .and_then(Result::ok)
}

/// Whether a header with `timestamp` carries its parent's execution: its
/// `stateRoot`, `receiptsRoot`, `logsBloom` and `gasUsed` are those of the
/// parent after execution, and the block's own are in its child's header.
pub fn deferred_execution_active_at(genesis: &Genesis, timestamp: u64) -> bool {
    deferred_execution_time(genesis).is_some_and(|at| timestamp >= at)
}

/// Genesis `config` key: gov5's Amsterdam fork time (`params.ChainConfig.GlamsterdamTime`).
/// From it a native header carries EIP-7843's `slotNumber` (element 23), equal
/// to the block number (`docs/HEADER_FIELD_PARITY.md` section 4).
pub const GLAMSTERDAM_TIME_KEY: &str = "glamsterdamTime";

/// Genesis `config` key: gov5's MobileAnchor fork time
/// (`params.ChainConfig.MobileAnchorTime`). With Glamsterdam also active a
/// native header carries `mobileRegistryRoot` (element 24).
pub const MOBILE_ANCHOR_TIME_KEY: &str = "mobileAnchorTime";

/// The time from which headers carry the slot number: gov5's
/// `glamsterdamTime`, or reth's `amsterdamTime` for a genesis that names the
/// fork the Ethereum way; the earlier of the two when both are set. `None`
/// means never.
pub fn glamsterdam_time(genesis: &Genesis) -> Option<u64> {
    // Profile 1: `amsterdamTime: 0` names gov5's Glamsterdam rule set from
    // block 0 (standard A4, AM1); `glamsterdamTime` itself is refused there.
    if is_profile1(genesis) {
        return Some(0);
    }
    let gov5 = genesis.config.extra_fields.get_deserialized::<u64>(GLAMSTERDAM_TIME_KEY).and_then(Result::ok);
    match (gov5, genesis.config.amsterdam_time) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Whether a header with `timestamp` must carry the slot number (and, before
/// it, must not): gov5's `IsGlamsterdam`.
pub fn glamsterdam_active_at(genesis: &Genesis, timestamp: u64) -> bool {
    glamsterdam_time(genesis).is_some_and(|at| timestamp >= at)
}

/// Genesis `config` key gov5 reads the consensus engine from
/// (`params.ChainConfig.Consensus`).
pub const CONSENSUS_KEY: &str = "consensus";

/// Whether the genesis describes an N42-native chain: gov5's `IsN42Native`
/// (`params/config.go:473`), consensus `hotstuff` or `apos`, or a `hotstuff`
/// / `apos` section in the config.
pub fn is_n42_native(genesis: &Genesis) -> bool {
    if is_profile1(genesis) {
        return true;
    }
    let fields = &genesis.config.extra_fields;
    let consensus: Option<String> = fields.get_deserialized(CONSENSUS_KEY).and_then(Result::ok);
    matches!(consensus.as_deref(), Some("hotstuff" | "apos")) || fields.contains_key("hotstuff") || fields.contains_key("apos")
}

/// Whether a block with `timestamp` executes under the Amsterdam rules
/// (revm's `SpecId::AMSTERDAM`) although reth's own Amsterdam hardfork is not
/// scheduled: an N42-native chain past gov5's `glamsterdamTime`. gov5 runs
/// its Amsterdam state transition on any chain where `IsGlamsterdam` holds,
/// native ones included (`internal/state_transition.go`), while the header
/// and payload keep the native shape (no EIP-7928 block access list, gov5's
/// `UsesEIP7928AccessList`), so reth's `EthereumHardfork::Amsterdam`, which
/// the header and payload validation hang off, stays off
/// (`docs/GLAMSTERDAM_EXECUTION_PARITY.md`).
pub fn glamsterdam_execution_active_at(genesis: &Genesis, timestamp: u64) -> bool {
    is_n42_native(genesis) && glamsterdam_active_at(genesis, timestamp)
}

/// gov5's `mobileAnchorTime`, if the genesis declares one.
pub fn mobile_anchor_time(genesis: &Genesis) -> Option<u64> {
    // Profile 1: MobileAnchor from block 0 (standard A20).
    if is_profile1(genesis) {
        return Some(0);
    }
    genesis.config.extra_fields.get_deserialized::<u64>(MOBILE_ANCHOR_TIME_KEY).and_then(Result::ok)
}

/// Whether a header with `timestamp` must carry `mobileRegistryRoot` (and
/// otherwise must not): gov5's `IsMobileRegistryRootInHeader`, MobileAnchor
/// and Glamsterdam both active. A `mobileAnchorTime` earlier than Glamsterdam
/// takes effect at Glamsterdam, so a header never carries the root without
/// the slot.
pub fn mobile_registry_root_in_header_at(genesis: &Genesis, timestamp: u64) -> bool {
    mobile_anchor_time(genesis).is_some_and(|at| timestamp >= at) && glamsterdam_active_at(genesis, timestamp)
}

/// Genesis `config` key: how many blocks behind a header the execution result
/// it carries is (`docs/DEFERRED_DEPTH_2_DESIGN.md`). Absent means 1: a
/// header carries its parent's result. At 2 it carries its parent's
/// parent's. A chain constant, read once, for every block at or past
/// [`DEFERRED_EXECUTION_TIME_KEY`].
pub const DEFERRED_EXECUTION_DEPTH_KEY: &str = "deferredExecutionDepth";

/// The deepest deferred-execution depth the rule is defined for.
pub const MAX_DEFERRED_EXECUTION_DEPTH: u64 = 2;

/// The deepest depth this build of the node runs. A depth the rule defines
/// but the node does not yet implement is refused at start-up.
pub const SUPPORTED_DEFERRED_EXECUTION_DEPTH: u64 = 2;

/// Why a genesis's `deferredExecutionDepth` is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeferredDepthError {
    /// Not a JSON integer (a string, a float, `null`, a negative number...).
    NotAnInteger(String),
    /// An integer outside `1..=MAX_DEFERRED_EXECUTION_DEPTH`.
    OutOfRange(u64),
    /// The depth is set but `deferredExecutionTime` is absent.
    WithoutGate,
    /// `deferredExecutionTime` is present but not an unsigned integer.
    MalformedGate(String),
    /// A depth above 1 with the gate after the genesis timestamp: a depth
    /// above 1 applies from block 1 or not at all.
    GateAfterGenesis {
        /// `deferredExecutionTime`.
        gate: u64,
        /// The genesis timestamp.
        genesis: u64,
    },
    /// A valid depth this build of the node does not implement yet.
    NotImplemented(u64),
    /// A profile-1 genesis without `hotstuff.deferredExecutionDepth`, which
    /// the profile makes mandatory (standard O4).
    MissingOnProfile1,
}

impl core::fmt::Display for DeferredDepthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAnInteger(value) => {
                write!(f, "{DEFERRED_EXECUTION_DEPTH_KEY} must be an integer 1 or 2, found {value}")
            }
            Self::OutOfRange(depth) => {
                write!(f, "{DEFERRED_EXECUTION_DEPTH_KEY} must be 1 or 2, found {depth}")
            }
            Self::WithoutGate => {
                write!(f, "{DEFERRED_EXECUTION_DEPTH_KEY} is set but {DEFERRED_EXECUTION_TIME_KEY} is not")
            }
            Self::MalformedGate(value) => {
                write!(f, "{DEFERRED_EXECUTION_TIME_KEY} must be an unsigned integer, found {value}")
            }
            Self::GateAfterGenesis { gate, genesis } => write!(
                f,
                "{DEFERRED_EXECUTION_DEPTH_KEY} above 1 needs {DEFERRED_EXECUTION_TIME_KEY} at or before the \
                 genesis timestamp {genesis}, found {gate}"
            ),
            Self::NotImplemented(depth) => write!(
                f,
                "{DEFERRED_EXECUTION_DEPTH_KEY} {depth} is not implemented by this node yet (it runs depth \
                 {SUPPORTED_DEFERRED_EXECUTION_DEPTH} at most)"
            ),
            Self::MissingOnProfile1 => write!(
                f,
                "a profile-1 genesis must set hotstuff.{DEFERRED_EXECUTION_DEPTH_KEY} (no default applies)"
            ),
        }
    }
}

impl core::error::Error for DeferredDepthError {}

/// The chain's deferred-execution depth, parsed strictly: absent is 1; a
/// present value must be the integer 1 or 2, and needs
/// `deferredExecutionTime` beside it (an unsigned integer); a depth above 1
/// needs that gate at or before the genesis timestamp.
///
/// Strict because the other parsers here swallow a malformed value, and for
/// the depth that would be a silent change of rule: a typo would give depth 1,
/// and a depth-1 member of a depth-2 fleet refuses every header.
pub fn deferred_execution_depth(genesis: &Genesis) -> Result<u64, DeferredDepthError> {
    if is_profile1(genesis) {
        return profile1_deferred_execution_depth(genesis);
    }
    let Some(value) = genesis.config.extra_fields.get(DEFERRED_EXECUTION_DEPTH_KEY) else {
        return Ok(1);
    };
    let gate = match genesis.config.extra_fields.get(DEFERRED_EXECUTION_TIME_KEY) {
        None => return Err(DeferredDepthError::WithoutGate),
        Some(gate) => gate.as_u64().ok_or_else(|| DeferredDepthError::MalformedGate(gate.to_string()))?,
    };
    let depth = value.as_u64().ok_or_else(|| DeferredDepthError::NotAnInteger(value.to_string()))?;
    if !(1..=MAX_DEFERRED_EXECUTION_DEPTH).contains(&depth) {
        return Err(DeferredDepthError::OutOfRange(depth));
    }
    if depth > 1 && gate > genesis.timestamp {
        return Err(DeferredDepthError::GateAfterGenesis { gate, genesis: genesis.timestamp });
    }
    Ok(depth)
}

/// Profile 1 keeps the depth under `config.hotstuff` (standard section 5,
/// A10, O4), mandatory, with no gate: deferred execution is on from block 1.
fn profile1_deferred_execution_depth(genesis: &Genesis) -> Result<u64, DeferredDepthError> {
    let value = genesis
        .config
        .extra_fields
        .get("hotstuff")
        .and_then(|hotstuff| hotstuff.get(DEFERRED_EXECUTION_DEPTH_KEY))
        .ok_or(DeferredDepthError::MissingOnProfile1)?;
    let depth = value.as_u64().ok_or_else(|| DeferredDepthError::NotAnInteger(value.to_string()))?;
    if !(1..=MAX_DEFERRED_EXECUTION_DEPTH).contains(&depth) {
        return Err(DeferredDepthError::OutOfRange(depth));
    }
    Ok(depth)
}

/// [`deferred_execution_depth`], and refused when this build of the node
/// does not implement the depth: what a node calls at start-up.
pub fn check_deferred_execution_depth(genesis: &Genesis) -> Result<u64, DeferredDepthError> {
    let depth = deferred_execution_depth(genesis)?;
    if depth > SUPPORTED_DEFERRED_EXECUTION_DEPTH {
        return Err(DeferredDepthError::NotImplemented(depth));
    }
    Ok(depth)
}

/// The depth a header stamped `timestamp` follows: 1 before the gate (where
/// a header carries its own execution and the depth is moot), the chain's
/// depth at or past it.
///
/// A value [`deferred_execution_depth`] refuses reads as 1 here: the node
/// refuses to start on such a genesis ([`check_deferred_execution_depth`]),
/// so on a running node this is the validated depth.
pub fn deferred_execution_depth_at(genesis: &Genesis, timestamp: u64) -> u64 {
    if !deferred_execution_active_at(genesis, timestamp) {
        return 1;
    }
    deferred_execution_depth(genesis).unwrap_or(1)
}

/// The QMDB root of a genesis allocation.
pub fn qmdb_genesis_root(genesis: &Genesis) -> Result<B256, StateError> {
    // The hash the forest is filed under does not affect the root; the real
    // genesis hash is not known until this root is in the header.
    let forest = QmdbForest::genesis(B256::ZERO, &changes_from_alloc(&genesis.alloc))?;
    Ok(forest.root())
}

/// The genesis header for `genesis` under the scheme it declares.
///
/// reth's header with, on a QMDB chain, the state root replaced by the forest
/// root of the alloc. Everything else — fork-dependent fields included — is
/// exactly what reth derives, which is also exactly what gov5's `ToBlock`
/// derives; the reproduction of gov5's `mainnet_qmdb` genesis hash in
/// `n42-qmdb-reth` is the test of that claim.
pub fn genesis_header(genesis: &Genesis, hardforks: &ChainHardforks) -> Header {
    let mut header = crate::make_genesis_header(genesis, hardforks);
    if state_scheme(genesis) == StateScheme::Qmdb {
        // The alloc is a fixed input; a root it cannot produce is a bug in the
        // conversion, and a genesis with a wrong root is a chain nobody else is
        // on. Neither is recoverable at runtime.
        header.state_root = qmdb_genesis_root(genesis)
            .expect("a genesis allocation always has a QMDB root");
    }
    if is_profile1(genesis) {
        // The mixed production standard, profile 1 (A6 with B3, B8/AM3, B10,
        // B12), as gov5 writes it (vector V1): ommers hash zero, the
        // requests hash the empty trie root, element 22 the 0x80 gap, slot
        // number 0. Element 24 (`mobileRegistryRoot`, zero) is not an
        // Ethereum field: it is in the hash ([`sealed_genesis_header`]) and on
        // the N42 header.
        header.ommers_hash = B256::ZERO;
        header.requests_hash = Some(alloy_consensus::EMPTY_ROOT_HASH);
        header.block_access_list_hash = None;
        header.slot_number = Some(0);
    }
    header
}

/// [`genesis_header`], sealed. On a profile-1 genesis the hash is the N42
/// header's, which carries `mobileRegistryRoot` (zero) as element 24 after
/// the Ethereum fields; every other genesis hashes as reth does.
pub fn sealed_genesis_header(
    genesis: &Genesis,
    hardforks: &ChainHardforks,
) -> reth_primitives_traits::SealedHeader<Header> {
    let header = genesis_header(genesis, hardforks);
    if !is_profile1(genesis) {
        return reth_primitives_traits::SealedHeader::new_unhashed(header);
    }
    let hash = hash_with_zero_registry_root(&header);
    reth_primitives_traits::SealedHeader::new(header, hash)
}

/// keccak of the N42 header with `mobileRegistryRoot` zero: the Ethereum
/// fields through the requests hash, then element 22 (the access-list hash,
/// `0x80` when absent), element 23 (the slot number) and element 24 (a zero
/// 32-byte string). alloy's own encoding stops at the last present field and
/// knows no element 24, so the three are written here.
fn hash_with_zero_registry_root(header: &Header) -> B256 {
    use alloy_rlp::Encodable as _;
    let mut head = header.clone();
    head.block_access_list_hash = None;
    head.slot_number = None;
    let mut ethereum = Vec::new();
    head.encode(&mut ethereum);
    let mut cursor = ethereum.as_slice();
    let list = alloy_rlp::Header::decode(&mut cursor).expect("a header encodes as a list");
    let mut payload = cursor[..list.payload_length].to_vec();
    match header.block_access_list_hash {
        Some(hash) => hash.encode(&mut payload),
        None => payload.push(alloy_rlp::EMPTY_STRING_CODE),
    }
    header.slot_number.unwrap_or_default().encode(&mut payload);
    B256::ZERO.encode(&mut payload);
    let mut out = Vec::with_capacity(payload.len() + 9);
    alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut out);
    out.extend_from_slice(&payload);
    alloy_primitives::keccak256(out)
}

#[cfg(test)]
mod header_field_gate_tests {
    use super::*;

    fn genesis(config: &str) -> Genesis {
        serde_json::from_str(&format!(r#"{{"config":{{"chainId":1{config}}},"alloc":{{}}}}"#)).expect("parses")
    }

    #[test]
    fn no_fork_time_means_never() {
        let g = genesis("");
        assert_eq!(glamsterdam_time(&g), None);
        assert!(!glamsterdam_active_at(&g, u64::MAX));
        assert!(!mobile_registry_root_in_header_at(&g, u64::MAX));
    }

    #[test]
    fn the_root_needs_both_forks() {
        // MobileAnchor first: the root waits for Glamsterdam.
        let g = genesis(r#","mobileAnchorTime":50,"glamsterdamTime":100"#);
        assert!(!glamsterdam_active_at(&g, 99));
        assert!(glamsterdam_active_at(&g, 100));
        assert!(!mobile_registry_root_in_header_at(&g, 60));
        assert!(!mobile_registry_root_in_header_at(&g, 99));
        assert!(mobile_registry_root_in_header_at(&g, 100));
        // Glamsterdam first: the slot alone until MobileAnchor.
        let g = genesis(r#","mobileAnchorTime":200,"glamsterdamTime":100"#);
        assert!(glamsterdam_active_at(&g, 150));
        assert!(!mobile_registry_root_in_header_at(&g, 150));
        assert!(mobile_registry_root_in_header_at(&g, 200));
        // MobileAnchor without Glamsterdam: never.
        let g = genesis(r#","mobileAnchorTime":0"#);
        assert!(!mobile_registry_root_in_header_at(&g, u64::MAX));
    }

    #[test]
    fn reths_amsterdam_time_counts_and_the_earlier_wins() {
        assert_eq!(glamsterdam_time(&genesis(r#","amsterdamTime":7"#)), Some(7));
        assert_eq!(glamsterdam_time(&genesis(r#","amsterdamTime":7,"glamsterdamTime":5"#)), Some(5));
        assert_eq!(glamsterdam_time(&genesis(r#","amsterdamTime":3,"glamsterdamTime":5"#)), Some(3));
    }

    #[test]
    fn amsterdam_execution_needs_a_native_chain() {
        // A native chain: from its glamsterdamTime on.
        let g = genesis(r#","consensus":"hotstuff","glamsterdamTime":100"#);
        assert!(is_n42_native(&g));
        assert!(!glamsterdam_execution_active_at(&g, 99));
        assert!(glamsterdam_execution_active_at(&g, 100));
        let g = genesis(r#","consensus":"apos","glamsterdamTime":0"#);
        assert!(glamsterdam_execution_active_at(&g, 0));
        let g = genesis(r#","hotstuff":{},"glamsterdamTime":0"#);
        assert!(glamsterdam_execution_active_at(&g, 0));
        // A native chain without the fork: never.
        let g = genesis(r#","consensus":"hotstuff""#);
        assert!(!glamsterdam_execution_active_at(&g, u64::MAX));
        // Not native: the slot rule may hold, the execution rule does not.
        let g = genesis(r#","consensus":"clique","glamsterdamTime":0"#);
        assert!(!is_n42_native(&g));
        assert!(glamsterdam_active_at(&g, 0));
        assert!(!glamsterdam_execution_active_at(&g, 0));
    }

    #[test]
    fn bundled_native_genesis_files() {
        let gated: Genesis =
            serde_json::from_str(include_str!("../res/genesis/n42_devnet_mobileanchor.json")).expect("parses");
        assert!(glamsterdam_execution_active_at(&gated, 0));
        let devnet: Genesis = serde_json::from_str(include_str!("../res/genesis/n42_devnet.json")).expect("parses");
        assert!(is_n42_native(&devnet));
        assert!(!glamsterdam_execution_active_at(&devnet, u64::MAX));
    }

    #[test]
    fn chain_94_never_carries_the_root_while_glamsterdam_is_unscheduled() {
        // gov5 7529e2e9 unscheduled Glamsterdam on chain 94; MobileAnchor alone
        // does not put the root in the header.
        let g: Genesis = serde_json::from_str(include_str!("../res/genesis/gov5/mainnet_qmdb_staggered.json"))
            .expect("chain 94 parses");
        assert_eq!(glamsterdam_time(&g), None);
        let anchor = mobile_anchor_time(&g).expect("chain 94 schedules mobileAnchorTime");
        assert!(!glamsterdam_active_at(&g, u64::MAX));
        assert!(!mobile_registry_root_in_header_at(&g, anchor));
        assert!(!mobile_registry_root_in_header_at(&g, u64::MAX));
        // The native devnet schedules neither.
        let devnet: Genesis = serde_json::from_str(include_str!("../res/genesis/n42_devnet.json")).expect("parses");
        assert_eq!(glamsterdam_time(&devnet), None);
        assert_eq!(mobile_anchor_time(&devnet), None);
    }
}

#[cfg(test)]
mod glamsterdam_genesis_tests {
    use alloy_genesis::Genesis;
    use alloy_primitives::b256;
    use alloy_rlp::Encodable;

    fn spec(json: &str) -> crate::ChainSpec {
        crate::ChainSpec::from_genesis(serde_json::from_str::<Genesis>(json).expect("a bundled genesis parses"))
    }

    /// gov5's genesis for a chain whose `glamsterdamTime` is at genesis carries
    /// the empty block-access-list hash and no slot number: 22 elements, hash
    /// measured from gov5's `n42 init` (audit-notes/devnet/mv4h2).
    #[test]
    fn a_glamsterdam_genesis_matches_gov5() {
        let spec = spec(include_str!("../res/genesis/n42_devnet_mobileanchor.json"));
        let header = spec.genesis_header();
        assert_eq!(header.block_access_list_hash, Some(alloy_eips::eip7928::EMPTY_BLOCK_ACCESS_LIST_HASH));
        assert_eq!(header.slot_number, None);
        let mut rlp = Vec::new();
        header.encode(&mut rlp);
        let mut buf = rlp.as_slice();
        let list = alloy_rlp::Header::decode(&mut buf).expect("a list");
        assert!(list.list);
        let mut elements = 0;
        while !buf.is_empty() {
            let item = alloy_rlp::Header::decode(&mut buf).expect("an element");
            buf = &buf[item.payload_length..];
            elements += 1;
        }
        assert_eq!(elements, 22, "gov5's 21 elements plus the empty BAL hash, no slot");
        assert_eq!(
            spec.genesis_hash(),
            b256!("0x9e8628a6dae0ce078dbd21b2e0d91c3f4389272aa597efae3a499b5ac62ffc95")
        );
    }

    #[test]
    fn chains_without_glamsterdam_at_genesis_keep_their_hashes() {
        assert_eq!(
            spec(include_str!("../res/genesis/n42_devnet.json")).genesis_hash(),
            b256!("0x112489f0dd526cd9dcf3bd9352f723a66182b41cc93f33615175828e5e16ae60")
        );
        let chain94 = spec(include_str!("../res/genesis/gov5/mainnet_qmdb_staggered.json"));
        assert_eq!(chain94.genesis_header().block_access_list_hash, None);
        assert_eq!(
            chain94.genesis_hash(),
            b256!("0xa2d2ff5d814552bb9a113b68ad7ed2b824fbb52caed42dbe573068845b57be99")
        );
    }
}

#[cfg(test)]
mod frame_blocks_tests {
    use super::*;

    fn genesis(json: &str) -> Genesis {
        serde_json::from_str(json).expect("a bundled genesis parses")
    }

    #[test]
    fn frame_blocks_are_on_for_the_bench_chains_only() {
        for bench in [
            include_str!("../res/genesis/n42_fleet3_bench.json"),
            include_str!("../res/genesis/n42_fleet4_bench.json"),
            include_str!("../res/genesis/n42_fleet7_bench.json"),
        ] {
            assert!(frame_blocks_enabled(&genesis(bench)));
        }
        for other in [
            include_str!("../res/genesis/n42_fleet7.json"),
            include_str!("../res/genesis/n42_devnet.json"),
        ] {
            assert!(!frame_blocks_enabled(&genesis(other)));
        }
    }
}
