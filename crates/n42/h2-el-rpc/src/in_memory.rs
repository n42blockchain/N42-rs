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

/// How long a reading must hold before the persistence watch speaks again,
/// and how long the unpersisted count must stay over [`LAG_BLOCKS`] before it
/// is called a lag.
const WATCH_INTERVAL: Duration = Duration::from_secs(10);

/// The unpersisted-block count past which the execution layer's persistence
/// is said to lag (the engine persists past a threshold of 2-8 blocks).
const LAG_BLOCKS: u64 = 16;

/// What the persistence watch has to say about one reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WatchEvent {
    /// The persisted block moved from `from` to `to`.
    Advanced { from: u64, to: u64, unpersisted: Option<u64> },
    /// More than [`LAG_BLOCKS`] blocks have stood unpersisted for `for_secs`.
    Lagging { persisted: Option<u64>, unpersisted: u64, for_secs: u64 },
}

/// Turns the poller's readings into rate-limited operator lines: the
/// persisted block advancing (at most one line per [`WATCH_INTERVAL`],
/// naming the whole move since the last one) and the unpersisted count
/// standing over [`LAG_BLOCKS`] for longer than [`WATCH_INTERVAL`] (repeated
/// once per interval while it lasts). Without these a run shows only the
/// first reading, and an execution layer that persists nothing for minutes
/// looks exactly like a healthy one.
#[derive(Debug, Default)]
struct PersistenceWatch {
    /// The persisted block the last advance line named (or the first seen).
    logged: Option<u64>,
    /// When the last advance line was written.
    advanced_at: Option<std::time::Instant>,
    /// When the unpersisted count went over the lag bound, if it is over.
    lag_since: Option<std::time::Instant>,
    /// When the last lag line was written.
    lag_logged_at: Option<std::time::Instant>,
}

impl PersistenceWatch {
    fn observe(&mut self, now: std::time::Instant, persisted: Option<u64>, unpersisted: Option<u64>) -> Vec<WatchEvent> {
        let due = |at: Option<std::time::Instant>| at.is_none_or(|at| now.duration_since(at) >= WATCH_INTERVAL);
        let mut events = Vec::new();
        if let Some(number) = persisted {
            match self.logged {
                None => self.logged = Some(number),
                Some(from) if number != from && due(self.advanced_at) => {
                    events.push(WatchEvent::Advanced { from, to: number, unpersisted });
                    self.logged = Some(number);
                    self.advanced_at = Some(now);
                }
                Some(_) => {}
            }
        }
        match unpersisted {
            Some(count) if count > LAG_BLOCKS => {
                let since = *self.lag_since.get_or_insert(now);
                let held = now.duration_since(since);
                if held >= WATCH_INTERVAL && due(self.lag_logged_at) {
                    events.push(WatchEvent::Lagging { persisted, unpersisted: count, for_secs: held.as_secs() });
                    self.lag_logged_at = Some(now);
                }
            }
            // Unknown leaves the lag clock as it is; a count at or under the
            // bound ends the lag.
            None => {}
            Some(_) => {
                self.lag_since = None;
                self.lag_logged_at = None;
            }
        }
        events
    }
}

fn log_watch_event(event: WatchEvent) {
    match event {
        WatchEvent::Advanced { from, to, unpersisted } => {
            let head = unpersisted.map(|count| to.saturating_add(count));
            info!(target: "n42.h2.el", from, persisted = to, ?unpersisted, ?head, "persisted block advanced");
        }
        WatchEvent::Lagging { persisted, unpersisted, for_secs } => {
            let head = persisted.map(|number| number.saturating_add(unpersisted));
            info!(
                target: "n42.h2.el",
                ?head, ?persisted, unpersisted, for_secs,
                "persistence lagging: head={} persisted={} unpersisted={unpersisted}",
                head.map_or_else(|| "?".to_owned(), |n| n.to_string()),
                persisted.map_or_else(|| "?".to_owned(), |n| n.to_string()),
            );
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
        let mut watch = PersistenceWatch::default();
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
            let persisted = match filled.persisted() {
                n42_h2_execution::PersistedHeight::Known(number) => Some(number),
                _ => None,
            };
            for event in watch.observe(std::time::Instant::now(), persisted, filled.get()) {
                log_watch_event(event);
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

    #[test]
    fn the_persistence_watch_names_advances_and_lags_at_most_once_an_interval() {
        let start = std::time::Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let mut watch = PersistenceWatch::default();
        assert!(watch.observe(at(0), Some(0), Some(3)).is_empty(), "the first reading is the baseline");
        assert_eq!(
            watch.observe(at(1), Some(4), Some(2)),
            vec![WatchEvent::Advanced { from: 0, to: 4, unpersisted: Some(2) }]
        );
        assert!(watch.observe(at(5), Some(8), Some(2)).is_empty(), "rate-limited");
        assert_eq!(
            watch.observe(at(11), Some(9), Some(1)),
            vec![WatchEvent::Advanced { from: 4, to: 9, unpersisted: Some(1) }],
            "the line names the whole move since the last one"
        );
        // Over the bound: silent until it has held for the interval.
        assert!(watch.observe(at(20), Some(9), Some(17)).is_empty());
        assert!(watch.observe(at(29), Some(9), Some(25)).is_empty());
        assert_eq!(
            watch.observe(at(30), Some(9), Some(26)),
            vec![WatchEvent::Lagging { persisted: Some(9), unpersisted: 26, for_secs: 10 }]
        );
        assert!(watch.observe(at(35), None, None).is_empty(), "an unknown reading keeps the clock");
        assert_eq!(
            watch.observe(at(40), Some(9), Some(36)),
            vec![WatchEvent::Lagging { persisted: Some(9), unpersisted: 36, for_secs: 20 }]
        );
        // Back under the bound ends the lag; a new one starts its own clock.
        let events = watch.observe(at(41), Some(40), Some(2));
        assert_eq!(events, vec![WatchEvent::Advanced { from: 9, to: 40, unpersisted: Some(2) }]);
        assert!(watch.observe(at(45), Some(40), Some(20)).is_empty());
        assert!(watch.observe(at(54), Some(40), Some(20)).is_empty());
        assert_eq!(watch.observe(at(55), Some(40), Some(20)).len(), 1);
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
