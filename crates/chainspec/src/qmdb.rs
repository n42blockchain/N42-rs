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
    header
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
