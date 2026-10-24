//! N42: canonical notification receivers whose lag is visible.
//!
//! `tokio::sync::broadcast` keeps a value alive until its slowest receiver has
//! read it, so a receiver that runs up to `capacity - 1` notifications behind
//! silently keeps that many blocks (bodies, execution outcomes) alive. The
//! stream returned here is the same stream `canonical_state_stream()` gives,
//! but it says when its receiver falls behind, and by how much.

use crate::{CanonStateNotification, CanonStateNotifications};
use futures_util::stream::{self, BoxStream, StreamExt};
use reth_primitives_traits::NodePrimitives;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::error::RecvError;

/// Backlog above which a receiver is reported as lagging.
const LAG_WARN_THRESHOLD: usize = 8;
/// At most one lag warning per receiver per this interval.
const LAG_WARN_INTERVAL: Duration = Duration::from_secs(5);
/// A summary of the receiver's backlog is logged every this many notifications.
const LAG_SUMMARY_EVERY: u64 = 1024;

struct Watch<N: NodePrimitives> {
    name: &'static str,
    rx: CanonStateNotifications<N>,
    last_warn: Option<Instant>,
    max_behind: usize,
    seen: u64,
}

/// Wraps a canonical notification receiver into a stream that reports its lag.
///
/// On each notification the receiver's remaining backlog (`rx.len()`) is read:
/// above 8 a warning names the receiver (at most one per 5 s), a running maximum
/// is logged at INFO every 1024 notifications, and a `Lagged` error is logged
/// once per occurrence. The stream ends when the channel closes.
pub fn watched_notifications<N: NodePrimitives>(
    name: &'static str,
    rx: CanonStateNotifications<N>,
) -> BoxStream<'static, CanonStateNotification<N>> {
    let state = Watch { name, rx, last_warn: None, max_behind: 0, seen: 0 };
    stream::unfold(state, |mut state| async move {
        loop {
            match state.rx.recv().await {
                Ok(notification) => {
                    let behind = state.rx.len();
                    let name = state.name;
                    state.seen += 1;
                    state.max_behind = state.max_behind.max(behind);
                    if behind > LAG_WARN_THRESHOLD {
                        let now = Instant::now();
                        if state.last_warn.is_none_or(|at| now.duration_since(at) >= LAG_WARN_INTERVAL)
                        {
                            state.last_warn = Some(now);
                            tracing::warn!(target: "n42.canon", name, behind, "canonical subscriber lag");
                        }
                    }
                    if state.seen % LAG_SUMMARY_EVERY == 0 {
                        tracing::info!(
                            target: "n42.canon",
                            name,
                            max_behind = state.max_behind,
                            seen = state.seen,
                            "canonical subscriber lag summary"
                        );
                        state.max_behind = 0;
                    }
                    return Some((notification, state));
                }
                Err(RecvError::Lagged(skipped)) => {
                    let name = state.name;
                    tracing::warn!(target: "n42.canon", name, skipped, "canonical subscriber fell behind");
                }
                Err(RecvError::Closed) => return None,
            }
        }
    })
    .boxed()
}
