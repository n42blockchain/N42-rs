// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `N42_ANSWER_AT_INSERT=1` (off by default): an own block's import is
//! answered VALID as soon as its executed insert has been handed to the
//! engine, and the header-only `newPayload` that used to come before the
//! answer runs behind it.
//!
//! # What the header `newPayload` is for
//!
//! On the own-block roads (`request::OWN_BLOCK`, a follower key's request for
//! a block this layer built) the block reaches reth's tree as an
//! `InsertExecutedBlock`, and the header-only `newPayload` after it is a
//! confirmation pass that costs ~22 ms a block at E=1. That covers the trip
//! to the engine and the time inside it (loop351 stage ag: seal+173 to
//! seal+194 ms).
//! In the tree (reth v2.7.0 `engine/tree`):
//!
//! - the insert is fire-and-forget. `ExecutedInsert::done` says only that the
//!   engine loop forwarded it; the tree drops an insert at or below its
//!   canonical number or for a hash it holds, and logs and drops one its
//!   validator refuses. The `newPayload` finds the hash
//!   (`AlreadySeen(Valid)`) or, if the insert was dropped, executes the block
//!   itself or answers SYNCING;
//! - it checks for an invalid ancestor (`find_invalid_ancestor`);
//! - it converts the sealed payload back to a block, which proves that the
//!   header hashes to the hash consensus named;
//! - it makes the block canonical if an earlier forkchoice named it as the
//!   sync target. The validator runs its commit again once the block lands
//!   (`our own block landed; the commit that was answered SYNCING runs
//!   again`), and that forkchoice does the same.
//!
//! The pass adds no state. Nothing reads the result except the answer.
//!
//! # Ordering
//!
//! The `newPayload` is put on the engine's channel *before* the answer is
//! written ([`dispatch`]), and only its reply is awaited later. The insert is
//! already on the tree's queue by then (`done` fires after the engine loop
//! forwarded it). The engine handle's channel is FIFO, and the orchestrator
//! forwards each message to the tree in order. So the tree sees insert,
//! `newPayload`, then anything the validator sends after hearing the answer
//! (its commit forkchoice above all). A forkchoice cannot overtake the pending
//! `newPayload` and always finds the block filed. Nothing has to be queued or
//! awaited for it.
//!
//! # Failure
//!
//! A deferred `newPayload` that comes back other than VALID, or not at all,
//! is logged at ERROR and latched ([`Deferred::failure`]). Every later
//! own-block answer under the switch then fails with that message until the
//! node restarts. A follower key's road falls through to its ordinary import,
//! whose `newPayload` reports the engine's real status; the leader key's
//! `OWN_BLOCK` hears the error. So a bad block is never answered VALID twice.
//! To make "the next answer" well defined, an answer waits for the previous
//! own block's deferred `newPayload` ([`Deferred::settle`]). That one has
//! usually landed already: the answers are 20-60 ms apart, and the pass takes
//! ~18 ms in the engine.
//!
//! # What stays the same
//!
//! - Every key sharing the layer hears the same VALID: the import-once owner
//!   publishes the status this road returns.
//! - The depth-2 check of a parent's execution reads the build store (the
//!   kept sealed builds and their fields), which the engine pass never
//!   touched.
//! - `N42_ANSWER_LAYOUT_ONLY` and the build-ahead roads are untouched.

use alloy_primitives::B256;
use alloy_rpc_types_engine::PayloadStatus;
use reth_engine_primitives::{BeaconOnNewPayloadError, ConsensusEngineHandle};
use reth_payload_primitives::PayloadTypes;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use tokio::sync::watch;
use tracing::{debug, error, info};

/// Parses `N42_ANSWER_AT_INSERT`: on only for `1`.
pub fn enabled_from(raw: Option<&str>) -> bool {
    raw == Some("1")
}

/// `N42_ANSWER_AT_INSERT`, read once and logged when first read (the raw
/// payload channel reads it at start-up).
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        let on = enabled_from(std::env::var("N42_ANSWER_AT_INSERT").ok().as_deref());
        info!(target: "n42.payload_serve", answer_at_insert = on, "N42_ANSWER_AT_INSERT");
        on
    })
}

/// The process's deferred `newPayload` tracker when the switch is on.
pub fn active() -> Option<&'static Arc<Deferred>> {
    static GLOBAL: OnceLock<Arc<Deferred>> = OnceLock::new();
    enabled().then(|| GLOBAL.get_or_init(|| Arc::new(Deferred::default())))
}

/// A `newPayload` reply still to come.
pub type Reply = Pin<Box<dyn Future<Output = Result<PayloadStatus, BeaconOnNewPayloadError>> + Send>>;

/// Puts `data`'s `newPayload` on the engine's channel now and returns its
/// reply to await later.
///
/// `ConsensusEngineHandle::new_payload` sends the message in the part of its
/// body before the reply's `await`, so one poll is enough to send it.
/// `a_dispatched_new_payload_is_on_the_channel_before_any_await` pins this
/// upstream behaviour.
pub fn dispatch<T>(engine: &ConsensusEngineHandle<T>, data: T::ExecutionData) -> Reply
where
    T: PayloadTypes,
{
    let engine = engine.clone();
    let mut reply: Reply = Box::pin(async move { engine.new_payload(data).await });
    let mut cx = Context::from_waker(Waker::noop());
    match reply.as_mut().poll(&mut cx) {
        Poll::Ready(outcome) => Box::pin(std::future::ready(outcome)),
        Poll::Pending => reply,
    }
}

/// The deferred `newPayload` passes of own blocks answered at insert.
#[derive(Debug, Default)]
pub struct Deferred {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// Completion of the most recently tracked pass.
    last: Option<watch::Receiver<bool>>,
    /// The first pass that did not come back VALID; latched until restart.
    failure: Option<String>,
}

impl Deferred {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The latched failure, if any deferred pass did not come back VALID.
    pub fn failure(&self) -> Option<String> {
        self.state().failure.clone()
    }

    /// Takes over block `number`'s dispatched `reply` and awaits it on a task
    /// of its own. Returns the previous pass's completion, for [`Self::settle`].
    pub fn track(self: &Arc<Self>, number: u64, hash: B256, reply: Reply) -> Option<watch::Receiver<bool>> {
        let (done_tx, done_rx) = watch::channel(false);
        let previous = self.state().last.replace(done_rx);
        let this = Arc::clone(self);
        let started = std::time::Instant::now();
        tokio::spawn(async move {
            let outcome = reply.await;
            let np_ms = started.elapsed().as_millis() as u64;
            let failure = match outcome {
                Ok(status) if status.status.is_valid() => None,
                Ok(status) => Some(format!("engine answered {:?}", status.status)),
                Err(err) => Some(format!("engine: {err}")),
            };
            match failure {
                None => debug!(target: "n42.payload_serve", number, ?hash, np_ms, "deferred newPayload of an own block answered VALID"),
                Some(why) => {
                    let message = format!(
                        "own block {number} ({hash}) was answered VALID at insert (N42_ANSWER_AT_INSERT) but its deferred newPayload failed: {why}; every later own-block answer fails until restart"
                    );
                    error!(target: "n42.payload_serve", number, ?hash, np_ms, "{message}");
                    this.state().failure.get_or_insert(message);
                }
            }
            let _ = done_tx.send(true);
        });
        previous
    }

    /// Waits for the previous pass, then fails if any pass has failed.
    pub async fn settle(&self, previous: Option<watch::Receiver<bool>>) -> Result<(), String> {
        if let Some(mut previous) = previous
            && previous.wait_for(|done| *done).await.is_err()
        {
            return Err("the previous own block's deferred newPayload ended without an answer".to_owned());
        }
        self.failure().map_or(Ok(()), Err)
    }
}

#[cfg(test)]
#[path = "answer_at_insert_tests.rs"]
mod tests;
