// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The range catch-up's measurement and pipeline (sync standard S2/S5).
//!
//! [`CatchUpTimes`] records where a pull's time goes -- the round trip of
//! each range request, screening and anchoring of the pulled blocks, and the
//! execution layer's `newPayload` and forkchoice -- and is logged on one line
//! when the pull ends.

use std::time::{Duration, Instant};

/// Where one catch-up's time went. Summed over the pull; logged when it ends
/// (`catch-up timing`).
#[derive(Debug, Clone)]
pub(crate) struct CatchUpTimes {
    /// When the pull started.
    pub(crate) started: Instant,
    /// Range requests sent.
    pub(crate) requests: u64,
    /// Range replies received (empty and refused ones included).
    pub(crate) replies: u64,
    /// Sum over replies of request sent to reply received.
    pub(crate) fetch: Duration,
    /// The slowest single request to reply.
    pub(crate) fetch_max: Duration,
    /// Decoding, screening, QC checks and anchor bookkeeping of pulled blocks.
    pub(crate) verify: Duration,
    /// `newPayload` of pulled blocks, summed (off the loop in the pipeline).
    pub(crate) new_payload: Duration,
    /// Forkchoice updates that made pulled blocks the head.
    pub(crate) forkchoice: Duration,
    /// Forkchoice updates sent.
    pub(crate) forkchoices: u64,
    /// Pulled blocks executed by this pull.
    pub(crate) executed: u64,
    /// Bytes of pulled blocks received.
    pub(crate) bytes: u64,
}

impl CatchUpTimes {
    /// Times of a pull starting now.
    pub(crate) fn start() -> Self {
        Self {
            started: Instant::now(),
            requests: 0,
            replies: 0,
            fetch: Duration::ZERO,
            fetch_max: Duration::ZERO,
            verify: Duration::ZERO,
            new_payload: Duration::ZERO,
            forkchoice: Duration::ZERO,
            forkchoices: 0,
            executed: 0,
            bytes: 0,
        }
    }

    /// One reply arrived `elapsed` after its request.
    pub(crate) fn note_reply(&mut self, elapsed: Duration) {
        self.replies += 1;
        self.fetch += elapsed;
        self.fetch_max = self.fetch_max.max(elapsed);
    }

    /// Executed pulled blocks per second of the pull's wall time.
    pub(crate) fn blocks_per_sec(&self) -> f64 {
        let secs = self.started.elapsed().as_secs_f64();
        if secs <= 0.0 { 0.0 } else { self.executed as f64 / secs }
    }

    /// Logs the pull's timing on one line.
    pub(crate) fn log(&self, mode: &'static str, complete: bool) {
        let ms = |d: Duration| d.as_millis() as u64;
        let wall = self.started.elapsed();
        tracing::info!(
            target: "n42.h2.node",
            mode,
            complete,
            executed = self.executed,
            wall_ms = ms(wall),
            blocks_per_s = format_args!("{:.1}", self.blocks_per_sec()),
            requests = self.requests,
            replies = self.replies,
            bytes = self.bytes,
            fetch_ms = ms(self.fetch),
            fetch_max_ms = ms(self.fetch_max),
            verify_ms = ms(self.verify),
            new_payload_ms = ms(self.new_payload),
            forkchoice_ms = ms(self.forkchoice),
            forkchoices = self.forkchoices,
            "catch-up timing"
        );
    }
}
