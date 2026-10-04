// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;

const PACING: Duration = Duration::from_millis(100);

fn config(soft: u64, hard: u64) -> ThrottleConfig {
    ThrottleConfig { soft, hard, max_hold: MAX_HOLD_DEFAULT }
}

fn throttle(soft: u64, hard: u64) -> BuildThrottle {
    BuildThrottle::new(config(soft, hard), Arc::new(|| None))
}

#[test]
fn below_soft_there_is_no_delay() {
    let c = config(40, 80);
    for count in [0, 1, 20, 39] {
        assert_eq!(c.delay(count, Some(PACING)), Delay::After(Duration::ZERO), "count {count}");
    }
}

#[test]
fn the_soft_band_grows_linearly_to_one_pacing_interval() {
    let c = config(40, 80);
    assert_eq!(c.delay(40, Some(PACING)), Delay::After(Duration::ZERO), "at SOFT the delay starts from zero");
    assert_eq!(c.delay(50, Some(PACING)), Delay::After(Duration::from_millis(25)));
    assert_eq!(c.delay(60, Some(PACING)), Delay::After(Duration::from_millis(50)), "mid-band: half an interval");
    assert_eq!(c.delay(79, Some(PACING)), Delay::After(Duration::from_micros(97_500)));
    // Monotone over the band.
    let mut last = Duration::ZERO;
    for count in 40..80 {
        let Delay::After(delay) = c.delay(count, Some(PACING)) else { panic!("held inside the band at {count}") };
        assert!(delay >= last && delay < PACING, "count {count}: {delay:?}");
        last = delay;
    }
}

#[test]
fn at_and_above_hard_the_proposal_is_held() {
    let c = config(40, 80);
    for count in [80, 81, 500] {
        assert_eq!(c.delay(count, Some(PACING)), Delay::Hold, "count {count}");
    }
}

#[test]
fn without_a_pacing_the_band_delays_nothing_but_hard_still_holds() {
    let c = config(40, 80);
    assert_eq!(c.delay(60, None), Delay::After(Duration::ZERO));
    assert_eq!(c.delay(80, None), Delay::Hold);
}

#[test]
fn the_delay_is_counted_from_the_first_ask_of_the_view() {
    let mut t = throttle(40, 80);
    let tick = Instant::now();
    // Mid-band: 50 ms after the first ask, whenever it is asked again.
    assert_eq!(t.check(7, Some(60), Some(PACING), tick), Verdict::WaitUntil(tick + Duration::from_millis(50)));
    assert_eq!(
        t.check(7, Some(60), Some(PACING), tick + Duration::from_millis(30)),
        Verdict::WaitUntil(tick + Duration::from_millis(50))
    );
    assert_eq!(t.check(7, Some(60), Some(PACING), tick + Duration::from_millis(50)), Verdict::Go);
    assert_eq!(t.last_applied(), Applied { in_mem: Some(60), delay_ms: 50 });
    // A backlog that drained meanwhile lets the proposal go sooner.
    let next = tick + Duration::from_secs(1);
    assert!(matches!(t.check(8, Some(70), Some(PACING), next), Verdict::WaitUntil(_)));
    assert_eq!(t.check(8, Some(39), Some(PACING), next + Duration::from_millis(10)), Verdict::Go);
    assert_eq!(t.last_applied().delay_ms, 10);
}

#[test]
fn a_hard_hold_lasts_until_the_count_is_back_under_hard() {
    let mut t = throttle(40, 80);
    let tick = Instant::now();
    assert_eq!(t.check(3, Some(90), Some(PACING), tick), Verdict::WaitUntil(tick + MAX_HOLD_DEFAULT));
    assert_eq!(t.hard_holds(), 1);
    // Back in the band 300 ms later: the band's delay from the tick has
    // long passed, so the proposal goes.
    assert_eq!(t.check(3, Some(60), Some(PACING), tick + Duration::from_millis(300)), Verdict::Go);
    assert_eq!(t.last_applied(), Applied { in_mem: Some(60), delay_ms: 300 });
    assert_eq!(t.hard_holds(), 1, "one view held, counted once");
}

#[test]
fn off_unless_hard_is_set_above_zero() {
    assert_eq!(ThrottleConfig::from_values(None, None, None), None, "unset: off");
    assert_eq!(ThrottleConfig::from_values(Some("40"), None, None), None, "SOFT alone: off");
    assert_eq!(ThrottleConfig::from_values(Some("40"), Some("0"), None), None, "HARD 0: off");
    assert_eq!(ThrottleConfig::from_values(Some("40"), Some("lots"), Some("500")), None, "HARD unparsable: off");
    assert_eq!(
        ThrottleConfig::from_values(Some("40"), Some("80"), None),
        Some(ThrottleConfig { soft: 40, hard: 80, max_hold: MAX_HOLD_DEFAULT })
    );
    assert_eq!(
        ThrottleConfig::from_values(Some(" 40 "), Some("80"), Some("750")),
        Some(ThrottleConfig { soft: 40, hard: 80, max_hold: Duration::from_millis(750) })
    );
}

#[test]
fn a_soft_unset_zero_or_not_under_hard_leaves_no_band() {
    for soft in [None, Some("0"), Some("80"), Some("120"), Some("x")] {
        let c = ThrottleConfig::from_values(soft, Some("80"), Some("0")).expect("on");
        assert_eq!(c.soft, 80, "{soft:?}");
        assert_eq!(c.max_hold, MAX_HOLD_DEFAULT, "a zero max hold is the default");
        assert_eq!(c.delay(79, Some(PACING)), Delay::After(Duration::ZERO));
        assert_eq!(c.delay(80, Some(PACING)), Delay::Hold);
    }
}

#[test]
fn an_unknown_count_never_delays() {
    let mut t = throttle(40, 80);
    let now = Instant::now();
    assert_eq!(t.check(1, None, Some(PACING), now), Verdict::Go);
    assert_eq!(t.last_applied(), Applied { in_mem: None, delay_ms: 0 });
    assert_eq!(t.hard_holds(), 0);
    // Through the reader as well.
    let mut read = BuildThrottle::new(config(40, 80), Arc::new(|| None));
    assert_eq!(read.ask(1, Some(PACING), now), Verdict::Go);
}

#[test]
fn a_hold_that_outlasts_max_hold_proposes_anyway_and_warns_once_per_episode() {
    let mut t = throttle(40, 80);
    let tick = Instant::now();
    let held = |t: &mut BuildThrottle, view, at| t.check(view, Some(120), Some(PACING), at);
    assert_eq!(held(&mut t, 5, tick), Verdict::WaitUntil(tick + MAX_HOLD_DEFAULT));
    assert_eq!(held(&mut t, 5, tick + Duration::from_millis(1_999)), Verdict::WaitUntil(tick + MAX_HOLD_DEFAULT));
    assert!(!t.escape_warned);
    assert_eq!(held(&mut t, 5, tick + MAX_HOLD_DEFAULT), Verdict::Go, "the hold is bounded");
    assert!(t.escape_warned, "said once");
    assert_eq!(t.last_applied(), Applied { in_mem: Some(120), delay_ms: 2_000 });
    // The next view of the same episode holds again, bounded again, and
    // does not warn a second time.
    let next = tick + Duration::from_secs(3);
    assert_eq!(held(&mut t, 6, next), Verdict::WaitUntil(next + MAX_HOLD_DEFAULT));
    assert_eq!(held(&mut t, 6, next + MAX_HOLD_DEFAULT), Verdict::Go);
    assert!(t.escape_warned);
    assert_eq!(t.hard_holds(), 2, "one per held view");
    // Under HARD the episode ends; the next one warns afresh.
    assert_eq!(t.check(7, Some(10), Some(PACING), next + Duration::from_secs(3)), Verdict::Go);
    assert!(!t.escape_warned);
}

#[test]
fn the_max_hold_is_configurable() {
    let c = ThrottleConfig::from_values(None, Some("80"), Some("150")).expect("on");
    let mut t = BuildThrottle::new(c, Arc::new(|| Some(80)));
    let tick = Instant::now();
    assert_eq!(t.ask(1, Some(PACING), tick), Verdict::WaitUntil(tick + Duration::from_millis(150)));
    assert_eq!(t.ask(1, Some(PACING), tick + Duration::from_millis(150)), Verdict::Go);
}
