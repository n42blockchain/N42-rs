// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `newPayload` that follows an own block's executed insert, and what the
//! engine thread did for both (`docs/PLAN_6M_2026_11.md`, the engine thread).
//!
//! Under `N42_STATE_READY_WITHOUT_MERGE` the hand-off inserts an own block as
//! executed and then sends the engine a `newPayload` for it carrying the
//! block's transactions: the safety net for an insert the tree drops as
//! outdated (a sibling made canonical a moment before), which the payload's
//! own execution then covers. When the tree kept the insert, the
//! `newPayload` is reth's already-seen road: the tree converts the payload
//! (`convert_payload_to_block`) only to drop the block. That conversion finds
//! the sealed block kept for it -- shared with the tree's own copy, so it is
//! copied, 200,000 transactions on the engine thread, and the copy is freed
//! there too. That was the ~30 ms of engine-thread CPU per full own block.
//!
//! [`settle`] sends that `newPayload` (or, under `N42_SKIP_OWN_NEW_PAYLOAD=1`,
//! does not, once the tree has said it kept the insert and the invalid-header
//! latch is clear) and prints one line per block with the engine-thread
//! steps, waits and work apart:
//!
//! - `insert_queue_us`: the executed insert sent until the tree's hook ran
//!   (the engine's queue and the orchestrator in front of it);
//! - `insert_hook_us` / `insert_hook_cpu_us`: the hook on the engine thread;
//! - `np_queue_us`: the `newPayload` sent until its conversion started;
//! - `np_convert_us` / `np_convert_cpu_us`: the conversion, wall and thread
//!   CPU (the difference is the thread descheduled or blocked);
//! - `np_convert_road`, `np_convert_lock_us`, `np_convert_copy_us`: how it
//!   produced the block, the sealed store's lock wait, the copy;
//! - `np_after_convert_us`: the conversion's return until the reply reached
//!   the hand-off (the copy freed on the engine thread, the reply's wake-up);
//! - `np_us`: the whole `newPayload` round trip;
//! - `np_skipped`, `accept_wait_us`: the skip and how long it waited to learn
//!   the insert was kept.
//! - `np_latched`: sent although the insert was kept, the latch being set.
//!
//! ## The skip
//!
//! The tree's executed-insert hook is called only for an insert it keeps
//! (reth's `on_engine_message`, `InsertExecutedBlock`: an outdated or
//! already-held block returns before it), and `N42TreeValidator` records
//! that call (`n42_qmdb_reth::engine_steps`). After it, the block is in the
//! tree's state, and a `newPayload` for it takes `insert_block_or_payload`'s
//! first branch -- `AlreadySeen(Valid)`, nothing executed, nothing stored --
//! after `find_invalid_ancestor`. So with the insert kept the `newPayload`
//! changes nothing, and its answer is VALID unless that check finds an
//! invalid entry. Without the tree's word within [`ACCEPT_BOUND`] the
//! `newPayload` goes as before (and executes the block if the insert was
//! dropped).
//!
//! ## The invalid-header latch
//!
//! The one answer the skip could change is reth's invalid-ancestor verdict
//! (reth v2.11.0, `crates/engine/tree/src/tree/mod.rs`):
//!
//! - `on_new_payload` (mod.rs:739) calls `find_invalid_ancestor` (mod.rs:2616)
//!   before anything else: INVALID when the block's own hash, or its lowest
//!   buffered ancestor (the parent when nothing is buffered), is in the
//!   invalid-header cache.
//! - `InsertExecutedBlock` (mod.rs:1604-1641) checks only "outdated" and
//!   "already held"; it never looks at that cache, so a block can be held
//!   with its parent recorded invalid
//!   (`crates/ethereum/node/tests/own_block_insert.rs` builds that case).
//!
//! The cache is private, but it starts empty, and the launcher sets a
//! process-wide latch before its first write
//! (`reth_node_builder::launch::invalid_latch`, which lists every write site:
//! mod.rs:3355 through the tree's validator or consensus, both wrapped;
//! mod.rs:1855 only after a backfill start, wrapped; mod.rs:2594 only over an
//! existing entry). The latch is never cleared, and the skip requires it
//! clear, read after the tree's word that it kept the insert:
//!
//! - engine thread: latch set (in the wrapper, before the failure returns)
//!   -> cache write -> ... -> our insert's hook -> `note_accepted`;
//! - here: `wait_accepted` (the same mutex as `note_accepted`) -> latch read.
//!
//! So a cache write anywhere before the hook is seen as a set latch, and the
//! `newPayload` is sent (and answered INVALID if it should be). A clear latch
//! means the cache was empty when the tree kept the insert and stayed empty
//! until the read: a `newPayload` taken next by the engine would have found
//! no entry and changed nothing, and taking it next is a schedule the engine
//! could always have run. A write after the read is unordered against the
//! `newPayload` today as well. Once the latch is set, every later own block's
//! `newPayload` is sent for the rest of the process (`np_latched`).

use alloy_primitives::B256;
use alloy_rpc_types_engine::{ExecutionData, PayloadStatus, PayloadStatusEnum};
use n42_qmdb_reth::engine_steps;
use reth_engine_primitives::{BeaconOnNewPayloadError, ConsensusEngineHandle};
use reth_payload_primitives::PayloadTypes;
use std::time::{Duration, Instant};
use tracing::info;

/// The switch's name.
pub const SKIP_ENV: &str = "N42_SKIP_OWN_NEW_PAYLOAD";

/// The precopy switch's name: the own block's `newPayload` is still sent,
/// but the sealed store gets its own copy of the body first, made here, so
/// the engine's conversion moves it instead of copying it on the engine
/// thread (`built_executions::precopy_sealed`). reth sees the same payload
/// and gets the same block, so it changes nothing toward reth and needs no
/// acknowledgement.
pub const PRECOPY_ENV: &str = "N42_OWN_PAYLOAD_PRECOPY";

/// Whether the precopy is on (`1`), read once.
pub fn precopy_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var(PRECOPY_ENV).ok().as_deref() == Some("1"))
}

/// How long the hand-off waits for the tree's word that it kept the insert
/// before sending the `newPayload` after all.
pub const ACCEPT_BOUND: Duration = Duration::from_millis(250);

/// `N42_SKIP_OWN_NEW_PAYLOAD`: on only for `1`.
pub fn skip_from(raw: Option<&str>) -> bool {
    raw == Some("1")
}

/// Whether the switch is on, read once.
pub fn skip_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| skip_from(std::env::var(SKIP_ENV).ok().as_deref()))
}

/// The `newPayload` round trip as the hand-off saw it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Settled {
    /// Not sent: the tree kept the insert.
    pub skipped: bool,
    /// The wait for the tree's word, microseconds (0 without the switch).
    pub accept_wait_us: u64,
    /// Sent although the insert was kept: the invalid-header latch was set.
    pub latched: bool,
    /// The precopy of the body, microseconds (`None`: not made).
    pub precopy_us: Option<u64>,
    /// When the `newPayload` was sent.
    pub sent_at: Option<Instant>,
    /// When its reply came back.
    pub replied_at: Option<Instant>,
}

/// The own block's `newPayload` after its executed insert (sent at
/// `insert_sent_at`, `inserted` when it was forwarded): sent, or skipped when
/// `skip`, the tree kept the insert and the invalid-header latch is clear.
/// Then the block's engine-thread line.
pub async fn settle<T>(
    engine: &ConsensusEngineHandle<T>,
    data: ExecutionData,
    number: u64,
    sealed_hash: B256,
    inserted: bool,
    insert_sent_at: Instant,
    skip: bool,
) -> Result<PayloadStatus, BeaconOnNewPayloadError>
where
    T: PayloadTypes<ExecutionData = ExecutionData>,
{
    let (status, settled) =
        settle_quiet(engine, data, sealed_hash, inserted, skip, precopy_enabled(), ACCEPT_BOUND, || {
            reth_node_builder::invalid_latch::is_latched()
        })
        .await;
    log_steps(number, sealed_hash, insert_sent_at, &settled, engine_steps::take(sealed_hash));
    status
}

/// [`settle`] without the line, with the bound and the latch given (tests).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn settle_quiet<T>(
    engine: &ConsensusEngineHandle<T>,
    data: ExecutionData,
    sealed_hash: B256,
    inserted: bool,
    skip: bool,
    precopy: bool,
    bound: Duration,
    latched: impl Fn() -> bool,
) -> (Result<PayloadStatus, BeaconOnNewPayloadError>, Settled)
where
    T: PayloadTypes<ExecutionData = ExecutionData>,
{
    let mut settled = Settled::default();
    if skip && inserted {
        let waited_at = Instant::now();
        let accepted = tokio::task::spawn_blocking(move || engine_steps::wait_accepted(sealed_hash, bound))
            .await
            .ok()
            .flatten();
        settled.accept_wait_us = waited_at.elapsed().as_micros() as u64;
        // Read after the tree's word (module docs, "The invalid-header latch").
        if accepted.is_some() && latched() {
            settled.latched = true;
        } else if accepted.is_some() {
            settled.skipped = true;
            // Dropped here, not on the engine thread.
            drop(data);
            return (Ok(PayloadStatus::new(PayloadStatusEnum::Valid, Some(sealed_hash))), settled);
        }
    }
    if precopy && inserted {
        // On a blocking thread, behind the answer: off the engine thread and
        // off the seal path. The insert shares the body with the store; the
        // copy is the store's own, for the conversion to move.
        settled.precopy_us = tokio::task::spawn_blocking(move || {
            n42_engine_types::built_executions::precopy_sealed(sealed_hash)
        })
        .await
        .ok()
        .flatten();
    }
    settled.sent_at = Some(Instant::now());
    let status = engine.new_payload(data).await;
    settled.replied_at = Some(Instant::now());
    (status, settled)
}

fn since(later: Option<Instant>, earlier: Option<Instant>) -> u64 {
    match (later, earlier) {
        (Some(later), Some(earlier)) => later.saturating_duration_since(earlier).as_micros() as u64,
        _ => 0,
    }
}

fn log_steps(number: u64, sealed_hash: B256, insert_sent_at: Instant, settled: &Settled, steps: Option<engine_steps::EngineSteps>) {
    let steps = steps.unwrap_or_default();
    info!(
        target: "n42.payload_serve",
        number,
        hash = %sealed_hash,
        np_skipped = settled.skipped,
        accept_wait_us = settled.accept_wait_us,
        np_latched = settled.latched,
        np_precopy_us = settled.precopy_us,
        insert_accepted = steps.accepted_at.is_some(),
        insert_queue_us = since(steps.accepted_at, Some(insert_sent_at)),
        insert_hook_us = steps.insert_hook_us,
        insert_hook_cpu_us = steps.insert_hook_cpu_us,
        np_us = since(settled.replied_at, settled.sent_at),
        np_queue_us = since(steps.convert_at, settled.sent_at),
        np_convert_us = steps.convert_us,
        np_convert_cpu_us = steps.convert_cpu_us,
        np_convert_road = steps.convert_road.as_str(),
        np_convert_lock_us = steps.convert_lock_us,
        np_convert_copy_us = steps.convert_copy_us,
        np_convert_txs = steps.convert_txs,
        np_after_convert_us = since(settled.replied_at, steps.convert_done_at),
        "own block's engine-thread steps"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_engine_primitives::BeaconEngineMessage;
    use n42_engine_types::N42EngineTypes;
    use tokio::sync::mpsc;

    #[test]
    fn the_switch_reads_one() {
        assert!(skip_from(Some("1")));
        for raw in [None, Some(""), Some("0"), Some("true"), Some(" 1")] {
            assert!(!skip_from(raw), "{raw:?}");
        }
    }

    fn data(hash: B256) -> ExecutionData {
        let header = n42_header::N42Header::default();
        n42_h2_consensus::execution_data_from_raw_parts(hash, &header, Vec::new(), Vec::new(), None)
    }

    /// An engine that answers VALID and counts the `newPayload`s it got.
    fn counting_engine() -> (ConsensusEngineHandle<N42EngineTypes>, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let (tx, mut rx) = mpsc::unbounded_channel::<BeaconEngineMessage<N42EngineTypes>>();
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = std::sync::Arc::clone(&seen);
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let BeaconEngineMessage::NewPayload { tx, .. } = message {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = tx.send(Ok(PayloadStatus::from_status(PayloadStatusEnum::Valid)));
                }
            }
        });
        (ConsensusEngineHandle::new(tx), seen)
    }

    /// The skip happens only with the tree's word that it kept the insert;
    /// without it (an insert dropped as outdated, or never forwarded) the
    /// `newPayload` goes, as it always did, and so it does with the switch off.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_kept_insert_skips_the_payload_and_anything_else_sends_it() {
        use std::sync::atomic::Ordering::SeqCst;
        let (engine, seen) = counting_engine();
        let bound = Duration::from_millis(40);

        let kept = B256::with_last_byte(0xD1);
        engine_steps::note_accepted(kept, engine_steps::Span::start());
        let (status, settled) = settle_quiet(&engine, data(kept), kept, true, true, false, bound, || false).await;
        assert_eq!(status.expect("status"), PayloadStatus::new(PayloadStatusEnum::Valid, Some(kept)));
        assert!(settled.skipped);
        assert_eq!(seen.load(SeqCst), 0, "no newPayload for a kept insert");

        let dropped = B256::with_last_byte(0xD2);
        let (status, settled) = settle_quiet(&engine, data(dropped), dropped, true, true, false, bound, || false).await;
        assert!(status.expect("status").status.is_valid());
        assert!(!settled.skipped && settled.accept_wait_us >= 40_000, "waited the bound, then sent");
        assert_eq!(seen.load(SeqCst), 1);

        let not_forwarded = B256::with_last_byte(0xD3);
        engine_steps::note_accepted(not_forwarded, engine_steps::Span::start());
        let (_, settled) = settle_quiet(&engine, data(not_forwarded), not_forwarded, false, true, false, bound, || false).await;
        assert!(!settled.skipped, "an insert not forwarded is never skipped");
        assert_eq!(seen.load(SeqCst), 2);

        let off = B256::with_last_byte(0xD4);
        engine_steps::note_accepted(off, engine_steps::Span::start());
        let (_, settled) = settle_quiet(&engine, data(off), off, true, false, false, bound, || false).await;
        assert!(!settled.skipped && settled.accept_wait_us == 0, "switch off: sent at once");
        assert_eq!(seen.load(SeqCst), 3);
    }

    /// The precopy keeps the `newPayload`: it is sent whether or not the
    /// tree kept the insert, and it is sent after the copy was made.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_precopy_still_sends_the_payload() {
        use std::sync::atomic::Ordering::SeqCst;
        let (engine, seen) = counting_engine();
        let bound = Duration::from_millis(40);
        let kept = B256::with_last_byte(0xE1);
        engine_steps::note_accepted(kept, engine_steps::Span::start());
        let (status, settled) = settle_quiet(&engine, data(kept), kept, true, false, true, bound, || false).await;
        assert!(status.expect("status").status.is_valid());
        assert!(!settled.skipped && settled.sent_at.is_some());
        // Nothing kept under this hash in the sealed store: no copy made.
        assert_eq!(settled.precopy_us, None);
        assert_eq!(seen.load(SeqCst), 1);
    }

    /// A set latch sends the `newPayload` for a kept insert; the latch is
    /// read only once the tree has kept it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_set_latch_sends_the_payload_for_a_kept_insert() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let (engine, seen) = counting_engine();
        let bound = Duration::from_millis(40);

        let kept = B256::with_last_byte(0xF1);
        engine_steps::note_accepted(kept, engine_steps::Span::start());
        let reads = AtomicUsize::new(0);
        let (status, settled) = settle_quiet(&engine, data(kept), kept, true, true, false, bound, || {
            reads.fetch_add(1, SeqCst);
            true
        })
        .await;
        assert!(status.expect("status").status.is_valid(), "the engine's answer, not ours");
        assert!(!settled.skipped && settled.latched && settled.sent_at.is_some());
        assert_eq!(seen.load(SeqCst), 1);
        assert_eq!(reads.load(SeqCst), 1);

        // Not kept: sent without reading the latch.
        let dropped = B256::with_last_byte(0xF2);
        let reads = AtomicUsize::new(0);
        let (_, settled) = settle_quiet(&engine, data(dropped), dropped, true, true, false, bound, || {
            reads.fetch_add(1, SeqCst);
            false
        })
        .await;
        assert!(!settled.skipped && !settled.latched);
        assert_eq!(reads.load(SeqCst), 0);
        assert_eq!(seen.load(SeqCst), 2);
    }
}
