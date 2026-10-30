// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Consensus client

/// Beacon-layer state machine.
pub mod beacon;
/// Metrics of the consensus client.
pub mod metrics;
/// Migration of old chain data into the beacon tables.
pub mod migrate;
pub mod miner;
/// Network access for beacon blocks.
pub mod network;
/// Storage of beacon blocks and states.
pub mod storage;
