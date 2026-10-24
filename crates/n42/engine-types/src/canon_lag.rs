// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical notification receivers whose lag is visible.
//!
//! The execution layer's heap grows with whole block bodies under load, and
//! tokio's broadcast keeps a notification alive until its slowest receiver has
//! read it. Each wrapped receiver says by name when it is that receiver.

use futures_util::stream::BoxStream;
use n42_tx_types::N42Primitives;
use reth_chain_state::CanonStateNotification;
use tokio::sync::broadcast::Receiver;

pub use reth_chain_state::watched_notifications;

/// [`watched_notifications`] for this node's primitives.
pub fn watched(
    name: &'static str,
    rx: Receiver<CanonStateNotification<N42Primitives>>,
) -> BoxStream<'static, CanonStateNotification<N42Primitives>> {
    watched_notifications(name, rx)
}
