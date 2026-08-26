// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An Engine API client that implements the HotStuff-2 execution-layer seam.
//!
//! [`n42_h2_execution::ExecutionLayer`] is the trait consensus drives; this is
//! the adapter that makes it a real execution client. It speaks the published
//! Engine API over authenticated JSON-RPC rather than reth's internal handles,
//! which means one adapter drives reth, this repo's own node, and gov5's
//! `eth-el` mode — and the consensus side still takes no reth dependency.
//!
//! ```no_run
//! # use std::time::Duration;
//! # use alloy_rpc_types_engine::JwtSecret;
//! # use n42_h2_el_rpc::{EngineApiClient, HttpTransport};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let transport = HttpTransport::new(
//!     "http://127.0.0.1:8551".parse()?,
//!     JwtSecret::from_file(std::path::Path::new("jwt.hex"))?,
//!     Duration::from_secs(8),
//! )?;
//! let el = EngineApiClient::new(transport);
//! # let _ = el;
//! # Ok(())
//! # }
//! ```

pub mod engine;
pub mod transport;

pub use engine::{
    built_block_from_envelope, forkchoice_method, new_payload_call, EngineApiClient,
};
pub use transport::{
    HttpTransport, JsonRpcTransport, RpcError, TransportError, UNKNOWN_PAYLOAD, UNSUPPORTED_FORK,
};
