// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The performance paths written against revm 43 that reth v2.9.0 (evm2) has
//! not got yet: the fast transfer, the parallel builder and follower graft,
//! the batch state and the warm-ahead pool (`docs/RETH_2_9_0_UPGRADE.md`).
//!
//! They are built only with the `legacy-revm-paths` cargo feature, which is
//! off by default and is removed path by path as each one is ported (stage
//! F5). Without it every knob that selects one of them is still recognised:
//! a node started with one set logs once that it is not available and runs
//! the stock evm2 path instead.

/// Whether the revm-era paths are compiled in (the `legacy-revm-paths`
/// feature).
pub const LEGACY_REVM_PATHS: bool = cfg!(feature = "legacy-revm-paths");

/// Every knob read by a path behind `legacy-revm-paths` and not yet ported to
/// evm2. Ported (F5c, `crate::parallel_build`): `N42_PARALLEL_BUILD`,
/// `N42_PARALLEL_BUILD_THREADS`, `N42_BUILD_BATCHES`, `N42_BUILD_ONE_WAVE`,
/// `N42_FREEZE_POOL(_THREADS)`, `N42_PLAN_AHEAD_BODY(_THREADS)`. Ported
/// (F5d, `crate::parallel_build::import_block`): `N42_FOLLOWER_PARALLEL`;
/// subsumed by it, since the evm2 import always runs sender groups on batch
/// states and folds them at finish: `N42_FOLLOWER_GRAFT`,
/// `N42_FOLLOWER_BATCH_STATE`, `N42_FOLLOWER_SENDER_GROUPS`.
pub const KNOBS: &[&str] = &[
    "N42_FAST_TRANSFER",
    "N42_FOLLOWER_GRAFT_INDEX",
    "N42_FOLLOWER_GRAFT_RANGES",
    "N42_FOLLOWER_GRAFT_STREAM",
    "N42_FOLLOWER_BUILD_PATH",
    "N42_FOLLOWER_FREE_ASYNC",
    "N42_FOLLOWER_MERGE_BEHIND",
    "N42_FOLLOWER_PARTITION_AHEAD",
    "N42_FOLLOWER_PARTITION_HASH",
    "N42_BUILD_COLLECT_IN_PLACE",
    "N42_BUILD_GRAFT_NO_CACHE",
    "N42_BUILD_MLP",
    "N42_BUILD_PREFETCH",
    "N42_GRAFT_BASE_SWAP",
    "N42_GRAFT_INDEX",
    "N42_GRAFT_PREFAULT",
    "N42_GRAFT_RANGES",
    "N42_GRAFT_SHARDED",
    "N42_GRAFT_STREAM",
    "N42_PHASE_TIMERS",
    "N42_PLAN_AHEAD_WARM",
    "N42_READ_SET",
];

/// The knobs of [`KNOBS`] set to something other than off, in order.
pub fn set_knobs() -> Vec<&'static str> {
    KNOBS
        .iter()
        .copied()
        .filter(|name| {
            std::env::var(name).is_ok_and(|value| n42_env::parse_flag(&value) != Some(false) && !value.trim().is_empty())
        })
        .collect()
}

/// Logs once, when this build lacks `legacy-revm-paths`, every knob of
/// [`KNOBS`] that is set: "not available on evm2 yet". The node then runs
/// the stock evm2 execution for what the knob would have switched.
pub fn warn_unavailable_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    if LEGACY_REVM_PATHS {
        return;
    }
    ONCE.call_once(|| {
        let set = set_knobs();
        if !set.is_empty() {
            tracing::warn!(
                target: "n42::evm",
                knobs = %set.join(","),
                "not available on evm2 yet: these paths are built only with the legacy-revm-paths \
                 feature; running the stock evm2 execution"
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_knob_is_named_once() {
        let mut names = KNOBS.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), KNOBS.len());
        assert!(names.iter().all(|name| name.starts_with("N42_")));
    }
}
