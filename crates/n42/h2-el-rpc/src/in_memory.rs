// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The execution layer's count of unpersisted in-memory blocks, polled
//! beside the consensus loop.
//!
//! The leader's build throttle (`n42_h2_node::build_throttle`) reads this
//! count on the service loop, where nothing may wait on the execution layer.
//! A task asks this repo's execution layer (`n42Engine_inMemoryBlocks`, its
//! canonical head minus its last persisted block) on a connection of its
//! own and leaves the answer in an atomic the loop reads for free.
//!
//! An execution layer that does not answer the method (a stock one) is asked
//! once; the gauge then stays unknown and the throttle never delays. A
//! failed poll also reads as unknown rather than as the last value, so a
//! stale count can never hold a proposal.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::transport::{JsonRpcTransport, TransportError, METHOD_NOT_FOUND};

/// The method on this repo's execution layer (`bin/n42/src/engine_ext.rs`).
pub const IN_MEMORY_BLOCKS_METHOD: &str = "n42Engine_inMemoryBlocks";

/// The gauge's "not known".
const UNKNOWN: u64 = u64::MAX;

/// The last count read, shared between the poller and its readers.
#[derive(Clone, Debug)]
pub struct InMemoryGauge(Arc<AtomicU64>);

impl Default for InMemoryGauge {
    fn default() -> Self {
        Self(Arc::new(AtomicU64::new(UNKNOWN)))
    }
}

impl InMemoryGauge {
    /// The last count read; `None` when it is not known.
    pub fn get(&self) -> Option<u64> {
        let value = self.0.load(Ordering::Relaxed);
        (value != UNKNOWN).then_some(value)
    }

    fn set(&self, value: Option<u64>) {
        // A count of `u64::MAX` cannot happen; clamped so it never reads as
        // unknown.
        let stored = value.map_or(UNKNOWN, |count| count.min(UNKNOWN - 1));
        self.0.store(stored, Ordering::Relaxed);
    }
}

/// What one poll found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll {
    /// Asked; the gauge holds the answer or, after a failure, unknown.
    Again,
    /// The execution layer does not have the method; there is no point
    /// asking again.
    Unsupported,
}

/// Asks once and records the answer in `gauge`.
pub async fn poll_once<T: JsonRpcTransport>(transport: &T, gauge: &InMemoryGauge) -> Poll {
    match transport.call(IN_MEMORY_BLOCKS_METHOD, Vec::new()).await {
        Ok(value) => {
            gauge.set(value.as_u64());
            Poll::Again
        }
        Err(TransportError::Rpc(err)) if err.code == METHOD_NOT_FOUND => {
            gauge.set(None);
            Poll::Unsupported
        }
        Err(_) => {
            gauge.set(None);
            Poll::Again
        }
    }
}

/// Starts a task polling `transport` every `every` and returns the gauge it
/// fills. The task ends when the execution layer turns out not to have the
/// method; the gauge then stays unknown.
pub fn spawn_poller<T: JsonRpcTransport>(transport: T, every: Duration) -> InMemoryGauge {
    let gauge = InMemoryGauge::default();
    let filled = gauge.clone();
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(every);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut first = true;
        loop {
            ticks.tick().await;
            match poll_once(&transport, &filled).await {
                Poll::Again => {
                    if first && let Some(count) = filled.get() {
                        info!(target: "n42.h2.el", count, every_ms = every.as_millis() as u64, "unpersisted-block count: first reading");
                        first = false;
                    }
                }
                Poll::Unsupported => {
                    warn!(target: "n42.h2.el", "the execution layer has no {IN_MEMORY_BLOCKS_METHOD}; the build throttle stays off");
                    return;
                }
            }
        }
    });
    gauge
}
