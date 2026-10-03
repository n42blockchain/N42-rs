// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! reth v2.5.1's in-memory overlay state provider. reth v2.7.0 removed it from
//! `reth-chain-state`; our vendored `reth-provider` carries it again
//! (`providers/state/memory_overlay.rs`), because `BlockchainProvider` reads
//! state under the tree's in-memory blocks through it instead of flattening
//! them into `reth-storage-overlay`'s execution overlay. Re-exported here for
//! the builder and the follower import, which lay executed parents that are
//! not yet in the tree over a historical provider.

pub use reth_provider::{MemoryOverlayStateProvider, MemoryOverlayStateProviderRef};
