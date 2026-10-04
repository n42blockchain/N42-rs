// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The leader's build throttle: a proposal held back while this node's
//! execution layer carries too many unpersisted blocks.
//!
//! Persistence runs beside the chain and costs about 110 ms of wall a block;
//! a leader cycling at 120 ms (`docs/BREAKTHROUGH_DESIGN.md` 10.66-10.67)
//! leaves more unpersisted blocks in memory every block of its tenure, and
//! past roughly 100 of them its later follower imports slow from ~200 ms to
//! over a second and the chain collapses. reth's own bound
//! (`--engine.persistence-backpressure-threshold`) stops the growth by not
//! draining the engine's message channel, which stalls `newPayload` and
//! `forkchoiceUpdated` -- consensus messages -- and costs timeout
//! certificates. This throttle slows the producer instead.
//!
//! # Where it sits, and why there
//!
//! On the proposal, not on the build. The service awaits the build it
//! proposes inline (`build_block_on`, which waits for the chained build's
//! answer), so a delay put on the build start -- in the execution layer or in
//! the chain's start -- would be a delay the service loop sits in, with
//! votes and imports unread. A proposal deferred is the existing "not yet"
//! of the pacing: the service returns to its loop, keeps voting and
//! importing, and asks again at the target. Builds stay one ahead of
//! proposals (`ChainState.slot` in `n42-h2-el-rpc`), so a later proposal is
//! a later take and a later start of the build after it: production slows
//! by exactly the delay, the build already made for the held proposal is
//! kept (its parent and attributes do not change while it waits; the
//! timestamp is the parent's plus the period, never the wall clock), and
//! nothing empty or extra is built.
//!
//! # The curve
//!
//! With the count of unpersisted blocks `n`, `SOFT` and `HARD`:
//!
//! - `n < SOFT`: no delay;
//! - `SOFT <= n < HARD`: the proposal goes `pacing * (n - SOFT) / (HARD - SOFT)`
//!   after its tick, so production slows smoothly and persistence catches up;
//! - `n >= HARD`: held until `n` is back under `HARD`, at most `max_hold`
//!   (default 2 s, under the 6 s view timeout of the bench genesis), after
//!   which it goes anyway with one WARN for the episode.
//!
//! The delay is measured from the first time the proposal is asked for in
//! the view, which is its pacing tick; the count is read again at every ask,
//! so a backlog that drains shortens the wait. All of the state lives here,
//! keyed by view: the service's sleep towards the target can be dropped and
//! made again any number of times without moving the target.
//!
//! Off unless `N42_BUILD_THROTTLE_HARD` is set above 0. `N42_BUILD_THROTTLE_SOFT`
//! unset, 0 or not under `HARD` means no soft band (a hold at `HARD` only).
//! An unknown count (no reading yet, a stock execution layer, a failed poll)
//! never delays.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::warn;

/// `N42_BUILD_THROTTLE_MAX_HOLD_MS`'s default.
pub const MAX_HOLD_DEFAULT: Duration = Duration::from_secs(2);

/// The reason a proposal held by the throttle gives (`defer_reason`).
pub const THROTTLE_REASON: &str = "the build throttle holds the proposal";

/// The thresholds (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThrottleConfig {
    /// Where the delay starts; equal to `hard` when there is no soft band.
    pub soft: u64,
    /// Where the proposal is held.
    pub hard: u64,
    /// The longest a hold lasts before the proposal goes anyway.
    pub max_hold: Duration,
}

/// What the curve asks for at one count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delay {
    /// No delay, or a delay of this much after the tick.
    After(Duration),
    /// Held until the count is back under `hard`.
    Hold,
}

impl ThrottleConfig {
    /// From `N42_BUILD_THROTTLE_SOFT`, `N42_BUILD_THROTTLE_HARD` and
    /// `N42_BUILD_THROTTLE_MAX_HOLD_MS`. `None` (off) unless `HARD` is above 0.
    pub fn from_env() -> Option<Self> {
        let var = |name: &str| std::env::var(name).ok();
        Self::from_values(
            var("N42_BUILD_THROTTLE_SOFT").as_deref(),
            var("N42_BUILD_THROTTLE_HARD").as_deref(),
            var("N42_BUILD_THROTTLE_MAX_HOLD_MS").as_deref(),
        )
    }

    /// [`Self::from_env`] on the values given. A value that does not parse
    /// counts as unset.
    pub fn from_values(soft: Option<&str>, hard: Option<&str>, max_hold_ms: Option<&str>) -> Option<Self> {
        let number = |value: Option<&str>| value.and_then(|v| v.trim().parse::<u64>().ok()).filter(|n| *n > 0);
        let hard = number(hard)?;
        let soft = number(soft).filter(|soft| *soft < hard).unwrap_or(hard);
        let max_hold = number(max_hold_ms).map_or(MAX_HOLD_DEFAULT, Duration::from_millis);
        Some(Self { soft, hard, max_hold })
    }

    /// The curve at `count`. `pacing` scales the soft band; without one the
    /// band delays nothing (there is no interval to slow by).
    pub fn delay(&self, count: u64, pacing: Option<Duration>) -> Delay {
        if count >= self.hard {
            return Delay::Hold;
        }
        if count < self.soft {
            return Delay::After(Duration::ZERO);
        }
        let Some(pacing) = pacing else { return Delay::After(Duration::ZERO) };
        // soft <= count < hard, so the band is at least one block wide.
        let band = self.hard.saturating_sub(self.soft).max(1);
        let into = count.saturating_sub(self.soft);
        let nanos = pacing.as_nanos().saturating_mul(u128::from(into)) / u128::from(band);
        Delay::After(Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX)))
    }
}

/// What the throttle says about the proposal asked for now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Propose.
    Go,
    /// Not before this instant; ask again then (or sooner).
    WaitUntil(Instant),
}

/// What the last proposal let through was throttled by, for its line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// The unpersisted-block count read; `None` when it was not known.
    pub in_mem: Option<u64>,
    /// How long the proposal was held after its first ask in the view.
    pub delay_ms: u64,
}

/// Reads this node's count of unpersisted in-memory blocks; `None` when it
/// is not known. Called from the service loop, so it must not wait.
pub type InMemoryCount = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// The throttle's state (see the module docs).
pub struct BuildThrottle {
    config: ThrottleConfig,
    count: InMemoryCount,
    /// The view being asked about, and when it was first asked about.
    view: Option<(u64, Instant)>,
    /// When the current hold began; `None` while not holding.
    hold_since: Option<Instant>,
    /// Whether this view has already been counted as a hard hold.
    held_this_view: bool,
    /// Whether the current episode (views at or above `hard`, back to back)
    /// has already said it gave up holding.
    escape_warned: bool,
    /// Views held at `hard` since the start, for the proposal line.
    hard_holds: u64,
    /// The target the service sleeps towards while the proposal is held.
    wake: Option<(u64, Instant)>,
    last: Applied,
}

impl std::fmt::Debug for BuildThrottle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildThrottle")
            .field("config", &self.config)
            .field("view", &self.view)
            .field("hold_since", &self.hold_since)
            .field("hard_holds", &self.hard_holds)
            .finish_non_exhaustive()
    }
}

impl BuildThrottle {
    /// A throttle on `config`, reading the count through `count`.
    pub fn new(config: ThrottleConfig, count: InMemoryCount) -> Self {
        Self {
            config,
            count,
            view: None,
            hold_since: None,
            held_this_view: false,
            escape_warned: false,
            hard_holds: 0,
            wake: None,
            last: Applied::default(),
        }
    }

    /// The thresholds.
    pub const fn config(&self) -> ThrottleConfig {
        self.config
    }

    /// Reads the count and decides ([`Self::check`]).
    pub fn ask(&mut self, view: u64, pacing: Option<Duration>, now: Instant) -> Verdict {
        let count = (self.count)();
        self.check(view, count, pacing, now)
    }

    /// Whether the proposal of `view`, asked for at `now` with `count`
    /// unpersisted blocks, may go.
    pub fn check(&mut self, view: u64, count: Option<u64>, pacing: Option<Duration>, now: Instant) -> Verdict {
        let first = match self.view {
            Some((asked, first)) if asked == view => first,
            _ => {
                self.view = Some((view, now));
                self.hold_since = None;
                self.held_this_view = false;
                now
            }
        };
        let verdict = match count.map(|count| self.config.delay(count, pacing)) {
            None => {
                self.hold_since = None;
                Verdict::Go
            }
            Some(Delay::Hold) => {
                let since = *self.hold_since.get_or_insert(now);
                if !self.held_this_view {
                    self.held_this_view = true;
                    self.hard_holds = self.hard_holds.saturating_add(1);
                }
                let until = since.checked_add(self.config.max_hold).unwrap_or(now);
                if now >= until {
                    if !self.escape_warned {
                        self.escape_warned = true;
                        warn!(
                            target: "n42.h2.node",
                            view,
                            in_mem = count.unwrap_or_default(),
                            hard = self.config.hard,
                            max_hold_ms = self.config.max_hold.as_millis() as u64,
                            "build throttle: the unpersisted blocks stayed at the hard bound for the whole hold; proposing anyway"
                        );
                    }
                    Verdict::Go
                } else {
                    Verdict::WaitUntil(until)
                }
            }
            Some(Delay::After(delay)) => {
                self.hold_since = None;
                self.escape_warned = false;
                match first.checked_add(delay) {
                    Some(at) if at > now => Verdict::WaitUntil(at),
                    _ => Verdict::Go,
                }
            }
        };
        match verdict {
            Verdict::Go => {
                self.wake = None;
                self.last = Applied {
                    in_mem: count,
                    delay_ms: now.saturating_duration_since(first).as_millis() as u64,
                };
            }
            Verdict::WaitUntil(at) => self.wake = Some((view, at)),
        }
        verdict
    }

    /// The instant the held proposal of `view` is to be asked for again.
    pub fn wake_for(&self, view: u64) -> Option<Instant> {
        self.wake.filter(|(held, _)| *held == view).map(|(_, at)| at)
    }

    /// What the last proposal let through was throttled by.
    pub const fn last_applied(&self) -> Applied {
        self.last
    }

    /// Views held at the hard bound since the start.
    pub const fn hard_holds(&self) -> u64 {
        self.hard_holds
    }
}
