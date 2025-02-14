//! Ethereum protocol-related constants

use alloy_primitives::{b256, B256};

/// Gas units, for example [`GIGAGAS`].
pub mod gas_units;
pub use gas_units::{GIGAGAS, KILOGAS, MEGAGAS};

/// n42 block gas limit
pub const N42_BLOCK_GAS_LIMIT: u64 = 9_223_372_036_854_775_807;

/// The n42 mainnet genesis hash:
/// `0x138734b7044254e5ecbabf8056f5c2b73cd0847aaa5acac7345507cbeab387b8`
pub const N42_GENESIS_HASH: B256 =
    b256!("138734b7044254e5ecbabf8056f5c2b73cd0847aaa5acac7345507cbeab387b8");

/// The client version: `reth/v{major}.{minor}.{patch}`
pub const RETH_CLIENT_VERSION: &str = concat!("reth/v", env!("CARGO_PKG_VERSION"));

/// Minimum gas limit allowed for transactions.
pub const MINIMUM_GAS_LIMIT: u64 = 5000;

/// Holesky genesis hash: `0xb5f7f912443c940f21fd611f12828d75b534364ed9e95ca4e307729a4661bde4`
pub const HOLESKY_GENESIS_HASH: B256 =
    b256!("b5f7f912443c940f21fd611f12828d75b534364ed9e95ca4e307729a4661bde4");

/// The number of blocks to unwind during a reorg that already became a part of canonical chain.
///
/// In reality, the node can end up in this particular situation very rarely. It would happen only
/// if the node process is abruptly terminated during ongoing reorg and doesn't boot back up for
/// long period of time.
///
/// Unwind depth of `3` blocks significantly reduces the chance that the reorged block is kept in
/// the database.
pub const BEACON_CONSENSUS_REORG_UNWIND_DEPTH: u64 = 3;
