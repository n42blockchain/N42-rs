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
//!
//! The same task reads the last persisted block number
//! (`n42Engine_persistedBlock`) on the same tick, for the driver's finalized
//! tag (`n42_h2_execution::settlement`): one poller, two answers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::transport::{JsonRpcTransport, TransportError, METHOD_NOT_FOUND};

/// The method on this repo's execution layer (`bin/n42/src/engine_ext.rs`).
pub const IN_MEMORY_BLOCKS_METHOD: &str = "n42Engine_inMemoryBlocks";

/// The persisted block number, on the same execution layer.
pub const PERSISTED_BLOCK_METHOD: &str = "n42Engine_persistedBlock";

/// The gauge's "not known".
const UNKNOWN: u64 = u64::MAX;

/// The persisted gauge's "the execution layer does not have the method".
const NOT_REPORTED: u64 = u64::MAX - 1;

/// The last count read, shared between the poller and its readers, and the
/// last persisted block number read beside it.
#[derive(Clone, Debug)]
pub struct InMemoryGauge(Arc<AtomicU64>, Arc<AtomicU64>);

impl Default for InMemoryGauge {
    fn default() -> Self {
        Self(Arc::new(AtomicU64::new(UNKNOWN)), Arc::new(AtomicU64::new(UNKNOWN)))
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

    /// The last persisted block number read, as the driver's finalized tag
    /// wants it.
    pub fn persisted(&self) -> n42_h2_execution::PersistedHeight {
        match self.1.load(Ordering::Relaxed) {
            UNKNOWN => n42_h2_execution::PersistedHeight::Unknown,
            NOT_REPORTED => n42_h2_execution::PersistedHeight::NotReported,
            number => n42_h2_execution::PersistedHeight::Known(number),
        }
    }

    fn set_persisted(&self, value: n42_h2_execution::PersistedHeight) {
        let stored = match value {
            n42_h2_execution::PersistedHeight::Known(number) => number.min(NOT_REPORTED - 1),
            n42_h2_execution::PersistedHeight::Unknown => UNKNOWN,
            n42_h2_execution::PersistedHeight::NotReported => NOT_REPORTED,
        };
        self.1.store(stored, Ordering::Relaxed);
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

/// Asks once for the persisted block number and records it in `gauge`.
pub async fn poll_persisted_once<T: JsonRpcTransport>(transport: &T, gauge: &InMemoryGauge) -> Poll {
    match transport.call(PERSISTED_BLOCK_METHOD, Vec::new()).await {
        Ok(value) => {
            gauge.set_persisted(
                value.as_u64().map_or(n42_h2_execution::PersistedHeight::Unknown, n42_h2_execution::PersistedHeight::Known),
            );
            Poll::Again
        }
        Err(TransportError::Rpc(err)) if err.code == METHOD_NOT_FOUND => {
            gauge.set_persisted(n42_h2_execution::PersistedHeight::NotReported);
            Poll::Unsupported
        }
        Err(_) => {
            gauge.set_persisted(n42_h2_execution::PersistedHeight::Unknown);
            Poll::Again
        }
    }
}

/// Starts a task polling `transport` every `every` and returns the gauge it
/// fills: the unpersisted-block count and the persisted block number, each
/// until the execution layer turns out not to have its method (that reading
/// then stays unknown, or "not reported" for the persisted block). The task
/// ends when neither is left.
pub fn spawn_poller<T: JsonRpcTransport>(transport: T, every: Duration) -> InMemoryGauge {
    let gauge = InMemoryGauge::default();
    let filled = gauge.clone();
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(every);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut first = true;
        let mut first_persisted = true;
        let (mut count_on, mut persisted_on) = (true, true);
        while count_on || persisted_on {
            ticks.tick().await;
            if count_on {
                match poll_once(&transport, &filled).await {
                    Poll::Again => {
                        if first && let Some(count) = filled.get() {
                            info!(target: "n42.h2.el", count, every_ms = every.as_millis() as u64, "unpersisted-block count: first reading");
                            first = false;
                        }
                    }
                    Poll::Unsupported => {
                        warn!(target: "n42.h2.el", "the execution layer has no {IN_MEMORY_BLOCKS_METHOD}; the build throttle stays off");
                        count_on = false;
                    }
                }
            }
            if persisted_on {
                match poll_persisted_once(&transport, &filled).await {
                    Poll::Again => {
                        if first_persisted
                            && let n42_h2_execution::PersistedHeight::Known(number) = filled.persisted()
                        {
                            info!(target: "n42.h2.el", number, "persisted block: first reading");
                            first_persisted = false;
                        }
                    }
                    Poll::Unsupported => {
                        warn!(target: "n42.h2.el", "the execution layer has no {PERSISTED_BLOCK_METHOD}; the finalized tag follows the safe tag");
                        persisted_on = false;
                    }
                }
            }
        }
    });
    gauge
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::RpcError;
    use serde_json::{json, Value};
    use std::sync::Mutex;

    /// Answers each call with the next scripted result and counts the calls.
    struct Scripted(Mutex<(Vec<Result<Value, TransportError>>, usize)>);

    impl Scripted {
        fn new(mut answers: Vec<Result<Value, TransportError>>) -> Self {
            answers.reverse();
            Self(Mutex::new((answers, 0)))
        }
        fn calls(&self) -> usize {
            self.0.lock().map(|state| state.1).unwrap_or_default()
        }
    }

    #[async_trait::async_trait]
    impl JsonRpcTransport for Scripted {
        async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, TransportError> {
            assert!(params.is_empty());
            if method == PERSISTED_BLOCK_METHOD {
                // Scripted answers are for the count; this one is a stock
                // execution layer's.
                return Err(TransportError::Rpc(RpcError {
                    code: METHOD_NOT_FOUND,
                    message: "the method does not exist".into(),
                }));
            }
            assert_eq!(method, IN_MEMORY_BLOCKS_METHOD);
            let mut state = self.0.lock().map_err(|_| TransportError::Transport("poisoned".into()))?;
            state.1 += 1;
            state.0.pop().unwrap_or_else(|| Err(TransportError::Transport("no more answers".into())))
        }
    }

    #[tokio::test]
    async fn a_poll_records_the_count_and_a_failure_reads_as_unknown() {
        let gauge = InMemoryGauge::default();
        assert_eq!(gauge.get(), None, "unknown until read");
        let transport = Scripted::new(vec![
            Ok(json!(57)),
            Err(TransportError::Transport("timed out".into())),
            Ok(json!(12)),
            Ok(Value::Null),
        ]);
        assert_eq!(poll_once(&transport, &gauge).await, Poll::Again);
        assert_eq!(gauge.get(), Some(57));
        assert_eq!(poll_once(&transport, &gauge).await, Poll::Again);
        assert_eq!(gauge.get(), None, "a failed poll never leaves a stale count");
        assert_eq!(poll_once(&transport, &gauge).await, Poll::Again);
        assert_eq!(gauge.get(), Some(12));
        assert_eq!(poll_once(&transport, &gauge).await, Poll::Again);
        assert_eq!(gauge.get(), None, "a node that does not say");
    }

    #[tokio::test]
    async fn a_stock_execution_layer_is_asked_once() {
        let transport = Arc::new(Scripted::new(vec![Err(TransportError::Rpc(RpcError {
            code: METHOD_NOT_FOUND,
            message: "the method does not exist".into(),
        }))]));
        struct Shared(Arc<Scripted>);
        #[async_trait::async_trait]
        impl JsonRpcTransport for Shared {
            async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, TransportError> {
                self.0.call(method, params).await
            }
        }
        let gauge = spawn_poller(Shared(Arc::clone(&transport)), Duration::from_millis(5));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(transport.calls(), 1, "the poller stopped at the first \"method not found\"");
        assert_eq!(gauge.get(), None);
    }

    /// Answers the persisted-block method with the scripted results.
    struct Persisted(Mutex<Vec<Result<Value, TransportError>>>);

    #[async_trait::async_trait]
    impl JsonRpcTransport for Persisted {
        async fn call(&self, method: &str, _params: Vec<Value>) -> Result<Value, TransportError> {
            assert_eq!(method, PERSISTED_BLOCK_METHOD);
            let mut answers = self.0.lock().map_err(|_| TransportError::Transport("poisoned".into()))?;
            answers.pop().unwrap_or_else(|| Err(TransportError::Transport("no more answers".into())))
        }
    }

    #[tokio::test]
    async fn the_persisted_block_is_read_and_a_failure_or_a_stock_layer_says_so() {
        use n42_h2_execution::PersistedHeight;
        let gauge = InMemoryGauge::default();
        assert_eq!(gauge.persisted(), PersistedHeight::Unknown, "unknown until read");
        let mut answers = vec![
            Ok(json!(812)),
            Err(TransportError::Transport("timed out".into())),
            Err(TransportError::Rpc(RpcError { code: METHOD_NOT_FOUND, message: "no".into() })),
        ];
        answers.reverse();
        let transport = Persisted(Mutex::new(answers));
        assert_eq!(poll_persisted_once(&transport, &gauge).await, Poll::Again);
        assert_eq!(gauge.persisted(), PersistedHeight::Known(812));
        assert_eq!(gauge.get(), None, "the count is a reading of its own");
        assert_eq!(poll_persisted_once(&transport, &gauge).await, Poll::Again);
        assert_eq!(gauge.persisted(), PersistedHeight::Unknown, "a failed poll never leaves a stale height");
        assert_eq!(poll_persisted_once(&transport, &gauge).await, Poll::Unsupported);
        assert_eq!(gauge.persisted(), PersistedHeight::NotReported);
    }

    #[test]
    fn a_count_never_reads_as_unknown() {
        let gauge = InMemoryGauge::default();
        gauge.set(Some(u64::MAX));
        assert_eq!(gauge.get(), Some(u64::MAX - 1));
        gauge.set(Some(0));
        assert_eq!(gauge.get(), Some(0));
    }
}
