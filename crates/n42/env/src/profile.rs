// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adopted-configuration presets: `N42_PROFILE=<name>`.
//!
//! The measured fleet configuration is dozens of knobs; a binary started
//! without them silently runs something else. A profile is that knob set
//! carried by the binary: [`apply_or_exit`], called first thing in `main`,
//! sets every knob of the named profile that the operator left unset (a set
//! knob always wins, `=0` included), before any thread starts and before any
//! `OnceLock` reads a knob. An unknown profile name stops the process.
//!
//! Only `N42_*` knobs are in a profile. `MALLOC_CONF` is read by the
//! allocator before `main` and `TOKIO_WORKER_THREADS` / `RAYON_NUM_THREADS`
//! size pools the launcher owns, so the fleet scripts keep setting those.

/// One knob of a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Knob {
    /// The environment variable.
    pub name: &'static str,
    /// The value the profile gives it.
    pub value: &'static str,
}

const fn k(name: &'static str, value: &'static str) -> Knob {
    Knob { name, value }
}

/// X22, the configuration adopted on 2026-10-24 (`docs/BREAKTHROUGH_DESIGN.md`
/// 10.227, confirmed 10.228, on main 10.230): every row of `docs/KNOBS.md`
/// whose status is `adopted`, with the value an X22 leg of
/// `scripts/fleet7-runs/run-loop351.sh` (stages fh-fl) passes. That is the
/// cumulative stage sets X3-X22 (each comment names the stage set and round
/// where the docs give one; S1/S2 are loop351's section 19 items) and the
/// X22 base set every leg since X11 carries, tuned values whose compiled
/// default differs included. Not here: the `bench-only` knobs the leg also
/// passes (bench gateway key, shared import, storage mode, history index,
/// settlement tags, persistence ordering, instrumentation) and the
/// launcher's non-`N42_*` variables.
pub const X22: &[Knob] = &[
    // X3: the hand-off copies.
    k("N42_QMDB_RENAME_DEFER", "1"),
    k("N42_HANDOFF_HEAD_MOVE", "number"),
    k("N42_HANDOFF_NO_CLONE", "1"),
    // X4.
    k("N42_HANDOFF_MOVE_BODY", "1"),
    // X5.
    k("N42_CANON_NOTIFY_LEAN", "1"),
    // X6.
    k("N42_QUEUE_OFFLOCK", "1"),
    // X7.
    k("N42_QMDB_COMPUTE_OFFLOCK", "1"),
    k("N42_QMDB_PERSIST_BATCH", "1"),
    // X9.
    k("N42_SHARD_MIX", "1"),
    k("N42_QMDB_PARALLEL_APPLY", "1"),
    k("N42_SF_BULK_APPEND", "1"),
    // X10.
    k("N42_PLAN_AHEAD_WAIT_MS", "30"),
    // X11: the core layout (C16).
    k("N42_CORE_LAYOUT", "isolate"),
    k("N42_CORE_LAYOUT_BUILD_CORES", "64"),
    k("N42_CORE_LAYOUT_CRITICAL_CORES", "16"),
    k("N42_CORE_LAYOUT_SIBLINGS", "background"),
    k("N42_CORE_LAYOUT_BEHIND", "background"),
    // loop351 S1 and S2 (section 19 items 1-2).
    k("N42_CHECK_BEFORE_SLOT", "1"),
    k("N42_LEADER_LAYERS", "6"),
    // X13 (stage br, 2026-10-15).
    k("N42_ANSWER_BEFORE_REVERTS", "1"),
    // X14 (stage bu, 2026-10-16).
    k("N42_REGISTER_FREE_OFFLOCK", "1"),
    // X15 (2026-10-16).
    k("N42_HANDOFF_DONE_FIRST", "1"),
    k("N42_SHARDS_READY_FIRST", "1"),
    // X16 (stage cb).
    k("N42_TX_QUEUE_DRAIN_RUNS", "1"),
    k("N42_PRUNE_LEAN", "1"),
    // X17 (stage ce).
    k("N42_BUILD_AHEAD_AT_SEAL", "1"),
    k("N42_ROOT_UPPER_DIRTY", "1"),
    k("N42_ROOT_OPS_BEFORE_GATE", "1"),
    // X18 (stage cy, 2026-10-19).
    k("N42_ANSWER_AT_INSERT", "1"),
    k("N42_STATE_READY_WITHOUT_MERGE", "1"),
    k("N42_QUEUE_PRUNE_THREAD", "1"),
    k("N42_PRUNE_MIN_FOLD", "4"),
    // X19 (round 10.193).
    k("N42_MERGE_ELIDE", "1"),
    // X20 (round 10.210).
    k("N42_RECEIPTS_ON_BUILD_POOL", "1"),
    k("N42_RECEIPTS_FUSED", "1"),
    k("N42_PARALLEL_BUILD_THREADS", "32"),
    k("N42_FRAME_ROAD", "1"),
    k("N42_ROAD_RESEED_AT_FLUSH", "1"),
    // X21 (round 10.220).
    k("N42_SF_DROP_CACHE", "1"),
    // X22 (round 10.227).
    k("N42_QUEUE_FREE_THREADS", "2"),
    // X22 base (the loop351 `ALLA` line and its per-leg additions; every
    // leg since X11 carries them). Frame blocks and the pull by frames
    // (step 1 phase B; plan-ahead body: SHARED_EXECUTION_SCOPE.md 16.4 item 2).
    k("N42_FRAME_BLOCKS", "1"),
    k("N42_PLAN_AHEAD", "1"),
    k("N42_PULL_BY_FRAMES", "1"),
    k("N42_PLAN_AHEAD_BODY", "1"),
    k("N42_PLAN_AHEAD_BODY_THREADS", "16"),
    // X22 base: the body sent once, compact and checked by description.
    k("N42_BODY_ONCE", "1"),
    k("N42_COMPACT_BODY", "1"),
    k("N42_BLOCK_BY_DESCRIPTION", "1"),
    k("N42_TAKE_COMPACT", "1"),
    k("N42_ANSWER_LAYOUT_ONLY", "1"),
    k("N42_COMMIT_FCU_ASYNC", "1"),
    // X22 base: the leader's build chain (plan v6 attempts J, G2, G3; defect
    // 18b for the tenure's first build).
    k("N42_BUILD_CHAIN", "1"),
    k("N42_BUILD_ON_SEAL", "1"),
    k("N42_BUILD_ON_OUTPUT", "1"),
    k("N42_BUILD_START_ASYNC", "1"),
    k("N42_SEAL_AT_EXEC", "1"),
    k("N42_STATE_AFTER_PULL", "1"),
    k("N42_TENURE_FIRST_ON_OUTPUT", "1"),
    k("N42_ENGINE_TAKE_SEALED", "1"),
    k("N42_FIELDS_AT_SEAL", "1"),
    // X22 base: the parallel build (build batches: SHARED_EXECUTION_SCOPE.md
    // 16.4 item 4).
    k("N42_PARALLEL_BUILD", "1"),
    k("N42_BUILDER_PULLER", "1024"),
    k("N42_BUILD_BATCHES", "128"),
    k("N42_BUILD_COLLECT_IN_PLACE", "1"),
    // X22 base: the output shards and what runs behind the seal
    // (SHARED_EXECUTION_SCOPE.md 15, 16.2, 16.4 item 1).
    k("N42_OUTPUT_SHARDS", "16"),
    k("N42_OUTPUT_INDEX", "1"),
    k("N42_OUTPUT_INDEX_LIVE", "1"),
    k("N42_LIVE_INDEX_DEFER", "1"),
    k("N42_FREEZE_AFTER_SEAL", "1"),
    k("N42_ROOT_OPS_AHEAD", "1"),
    k("N42_SEAL_ON_COUNTERS", "1"),
    k("N42_FREEZE_POOL", "own"),
    // X22 base: the follower's import (exec/fields early:
    // BREAKTHROUGH_DESIGN.md section 5 step 5a).
    k("N42_FOLLOWER_PARALLEL", "1"),
    k("N42_FOLLOWER_GRAFT", "1"),
    k("N42_FOLLOWER_PARTITION_HASH", "1"),
    k("N42_FOLLOWER_PARTITION_AHEAD", "1"),
    k("N42_FOLLOWER_FREE_ASYNC", "1"),
    k("N42_FOLLOWER_BUILD_PATH", "1"),
    k("N42_FOLLOWER_ROOT_ON_BUILD_POOL", "1"),
    k("N42_FOLLOWER_FRAME_SCAN", "1"),
    k("N42_FOLLOWER_COPY_ASIDE", "1"),
    k("N42_FOLLOWER_EXEC_EARLY", "1"),
    k("N42_FOLLOWER_FIELDS_EARLY", "1"),
    // X22 base: the raw payload channel on its own runtime.
    k("N42_ROAD_RUNTIME", "1"),
    // 6.4 road bounds (MATURITY_HARDENING_2026_10.md; stage fm pair 2026-10-27).
    k("N42_ROAD_TAKEN_BOUND", "1"),
    k("N42_ROAD_RETIRE_INDEX", "1"),
    // X22 base: QMDB (entry file: QMDB_ENTRY_LOG.md step 1) and static files.
    k("N42_QMDB_ENTRY_FILE", "1"),
    k("N42_QMDB_RETAIN_DEPTH", "16"),
    k("N42_SF_PARALLEL_ENCODE", "1"),
    k("N42_SF_EARLY_WRITEBACK", "1"),
    // X22 base: ingest, queue and the build throttle.
    k("N42_TX_INGEST_RECOVER_PARALLEL", "24"),
    k("N42_TX_QUEUE_DRAIN_CHUNK", "8192"),
    k("N42_TX_QUEUE_RUN", "64"),
    k("N42_ED25519_BATCH", "256"),
    k("N42_ALTSIG_SENDER_CACHE", "4194304"),
    k("N42_BUILD_THROTTLE_SOFT", "48"),
    k("N42_BUILD_THROTTLE_HARD", "80"),
    // X22 base: votes and the local GossipSub queue bounds.
    k("N42_VOTE_TRANSPORT", "direct"),
    k("N42_VOTE_AGGREGATE_VERIFY", "1"),
    k("N42_GOSSIP_HANDLER_QUEUE", "64"),
    k("N42_GOSSIP_MAX_IHAVE", "500"),
];

/// The environment variable that names the profile.
pub const PROFILE_VAR: &str = "N42_PROFILE";

/// Every profile by name (matched case-insensitively).
pub const PROFILES: &[(&str, &[Knob])] = &[("x22", X22)];

/// The knobs of profile `name`, or `None` for a name no profile has.
pub fn knobs(name: &str) -> Option<&'static [Knob]> {
    let name = name.trim();
    PROFILES.iter().find(|(known, _)| known.eq_ignore_ascii_case(name)).map(|(_, knobs)| *knobs)
}

/// A profile name that matches none of [`PROFILES`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownProfile(pub String);

impl std::fmt::Display for UnknownProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let known: Vec<&str> = PROFILES.iter().map(|(name, _)| *name).collect();
        write!(f, "{PROFILE_VAR}={:?} names no profile (known: {})", self.0, known.join(", "))
    }
}

impl std::error::Error for UnknownProfile {}

/// What applying a profile did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The profile's name as given.
    pub profile: String,
    /// Knobs the profile set (they were unset).
    pub set: Vec<Knob>,
    /// Knobs of the profile the operator had already set, left as they were.
    pub kept: Vec<&'static str>,
}

/// The plan for profile `name` given which knobs are already set: the knobs
/// to set and the ones to keep. `None` profile (unset, blank or `none`)
/// plans nothing.
pub fn plan(
    name: Option<&str>,
    is_set: impl Fn(&str) -> bool,
) -> Result<Option<Applied>, UnknownProfile> {
    let Some(name) = name.map(str::trim).filter(|n| !n.is_empty() && !n.eq_ignore_ascii_case("none"))
    else {
        return Ok(None);
    };
    let knobs = knobs(name).ok_or_else(|| UnknownProfile(name.to_owned()))?;
    let (kept, set): (Vec<&Knob>, Vec<&Knob>) = knobs.iter().partition(|knob| is_set(knob.name));
    Ok(Some(Applied {
        profile: name.to_owned(),
        set: set.into_iter().copied().collect(),
        kept: kept.into_iter().map(|knob| knob.name).collect(),
    }))
}

/// Applies the profile `N42_PROFILE` names: sets each of its knobs that is
/// not already in the environment (set to anything, the empty string
/// included).
///
/// # Safety
///
/// Calls [`std::env::set_var`]: the caller guarantees no other thread reads
/// or writes the environment while this runs, i.e. it is called at the top
/// of `main` before the program spawns any thread.
pub unsafe fn apply() -> Result<Option<Applied>, UnknownProfile> {
    let name = std::env::var_os(PROFILE_VAR).map(|raw| raw.to_string_lossy().into_owned());
    let applied = plan(name.as_deref(), |knob| std::env::var_os(knob).is_some())?;
    if let Some(applied) = &applied {
        for knob in &applied.set {
            // SAFETY: the caller's contract (no other thread touches the
            // environment while this runs).
            unsafe { std::env::set_var(knob.name, knob.value) };
        }
    }
    Ok(applied)
}

/// [`apply`] for a binary's `main`: an unknown profile prints the error and
/// exits with status 2; an applied one prints one line to stderr naming how
/// many knobs it set and which ones the operator's environment kept.
///
/// # Safety
///
/// As for [`apply`]: the top of `main`, before any thread exists.
pub unsafe fn apply_or_exit(binary: &str) -> Option<Applied> {
    // SAFETY: forwarded from this function's own contract.
    match unsafe { apply() } {
        Ok(Some(applied)) => {
            eprintln!(
                "{binary}: {PROFILE_VAR}={} set {} knob(s); kept from the environment: [{}]",
                applied.profile,
                applied.set.len(),
                applied.kept.join(", ")
            );
            Some(applied)
        }
        Ok(None) => None,
        Err(err) => {
            eprintln!("error: {binary}: {err}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{lock, set, unset};
    use std::collections::{BTreeSet, HashSet};

    #[test]
    fn names_are_unique_and_values_non_empty() {
        for (profile, knobs) in PROFILES {
            let mut seen = HashSet::new();
            for knob in *knobs {
                assert!(seen.insert(knob.name), "{profile}: {} twice", knob.name);
                assert!(knob.name.starts_with("N42_"), "{profile}: {}", knob.name);
                assert!(!knob.value.trim().is_empty(), "{profile}: {} has no value", knob.name);
            }
        }
    }

    /// The profile and `docs/KNOBS.md` cannot drift: every knob of X22 is a
    /// row of that file marked `adopted`, and every `adopted` row is in X22.
    #[test]
    fn x22_is_exactly_the_adopted_rows_of_knobs_md() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../docs/KNOBS.md");
        let doc = std::fs::read_to_string(path).expect("docs/KNOBS.md is readable");
        let mut adopted = BTreeSet::new();
        let mut documented = BTreeSet::new();
        for line in doc.lines() {
            let Some(rest) = line.strip_prefix("| `") else { continue };
            let Some((name, _)) = rest.split_once('`') else { continue };
            documented.insert(name.to_owned());
            if line.trim_end().ends_with("| adopted |") {
                adopted.insert(name.to_owned());
            }
        }
        let profile: BTreeSet<String> = X22.iter().map(|knob| knob.name.to_owned()).collect();
        let undocumented: Vec<_> = profile.difference(&documented).collect();
        assert!(undocumented.is_empty(), "X22 knobs missing from docs/KNOBS.md: {undocumented:?}");
        let not_adopted: Vec<_> = profile.difference(&adopted).collect();
        assert!(not_adopted.is_empty(), "X22 knobs not marked adopted in docs/KNOBS.md: {not_adopted:?}");
        let missing: Vec<_> = adopted.difference(&profile).collect();
        assert!(missing.is_empty(), "adopted rows of docs/KNOBS.md missing from X22: {missing:?}");
    }

    #[test]
    fn known_names_match_case_insensitively() {
        assert_eq!(knobs("x22"), Some(X22));
        assert_eq!(knobs(" X22 "), Some(X22));
        assert_eq!(knobs("x21"), None);
    }

    #[test]
    fn no_profile_plans_nothing() {
        for name in [None, Some(""), Some("  "), Some("none"), Some("NONE")] {
            assert_eq!(plan(name, |_| false), Ok(None), "{name:?}");
        }
    }

    #[test]
    fn unknown_profile_is_an_error() {
        let err = plan(Some("x99"), |_| false).unwrap_err();
        assert_eq!(err, UnknownProfile("x99".into()));
        assert!(err.to_string().contains("x22"), "the message lists the known profiles");
    }

    #[test]
    fn a_set_knob_is_never_overridden() {
        let applied = plan(Some("x22"), |name| name == "N42_MERGE_ELIDE" || name == "N42_LEADER_LAYERS")
            .unwrap()
            .unwrap();
        assert_eq!(applied.kept, vec!["N42_LEADER_LAYERS", "N42_MERGE_ELIDE"]);
        assert_eq!(applied.set.len(), X22.len() - 2);
        assert!(applied.set.iter().all(|knob| knob.name != "N42_MERGE_ELIDE"));
    }

    #[test]
    fn apply_sets_only_unset_knobs() {
        let _guard = lock();
        set(PROFILE_VAR, "x22");
        set("N42_MERGE_ELIDE", "0");
        set("N42_QUEUE_FREE_THREADS", "");
        unset("N42_FRAME_ROAD");
        // SAFETY: the test holds the environment lock; nothing else in this
        // binary reads these names.
        let applied = unsafe { apply() }.unwrap().unwrap();
        assert_eq!(std::env::var("N42_MERGE_ELIDE").as_deref(), Ok("0"), "=0 is the operator's choice");
        assert_eq!(std::env::var("N42_QUEUE_FREE_THREADS").as_deref(), Ok(""), "an empty value counts as set");
        assert_eq!(std::env::var("N42_FRAME_ROAD").as_deref(), Ok("1"));
        assert!(applied.kept.contains(&"N42_MERGE_ELIDE"));
        for knob in X22 {
            unset(knob.name);
        }
        unset(PROFILE_VAR);
    }

    #[test]
    fn apply_without_a_profile_touches_nothing() {
        let _guard = lock();
        unset(PROFILE_VAR);
        unset("N42_FRAME_ROAD");
        // SAFETY: as above.
        assert_eq!(unsafe { apply() }, Ok(None));
        assert!(std::env::var_os("N42_FRAME_ROAD").is_none());
    }
}
