// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Knobs that no longer select anything.
//!
//! The revm-era performance paths (the `BundleState` graft, the warm-ahead
//! pool, the read set and the prefetchers) were removed when the node moved
//! to evm2 (reth v2.9.0, stage F6a, 2026-11-06); the evm2 builder and import
//! fold batch states instead and read the overlay directly. A launch script
//! may still pass their knobs, so a node started with one of them set logs
//! one warning naming it and otherwise ignores it (`docs/KNOBS.md`, status
//! `retired`). The follower's shard-merge knobs joined them when the
//! runtime-dead build-path merge was removed after F6a (stream I1).

use std::sync::Once;

/// The knobs retired on evm2 (2026-11-06), sorted.
pub const RETIRED_ON_EVM2: &[&str] = &[
    "N42_BUILD_GRAFT_NO_CACHE",
    "N42_BUILD_MLP",
    "N42_BUILD_PREFETCH",
    "N42_FOLLOWER_GRAFT_INDEX",
    "N42_FOLLOWER_GRAFT_RANGES",
    "N42_FOLLOWER_GRAFT_STREAM",
    "N42_FOLLOWER_CHECK_ON_SHARDS",
    "N42_FOLLOWER_MERGE_BEHIND",
    "N42_FOLLOWER_SHARDS_KEPT",
    "N42_GRAFT_BASE_SWAP",
    "N42_GRAFT_INDEX",
    "N42_GRAFT_PREFAULT",
    "N42_GRAFT_RANGES",
    "N42_GRAFT_SHARDED",
    "N42_GRAFT_STREAM",
    "N42_PLAN_AHEAD_WARM",
    "N42_READ_SET",
    "N42_SHARDS_MERGE_OFF_PATH",
];

/// The knobs of [`RETIRED_ON_EVM2`] that are set to a non-empty value, in
/// order. Any non-empty value counts, `0` included: the knob is ignored
/// either way, and a script that still names it is worth one line.
pub fn set_retired() -> Vec<&'static str> {
    RETIRED_ON_EVM2
        .iter()
        .copied()
        .filter(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
        .collect()
}

/// Logs once per process every knob of [`RETIRED_ON_EVM2`] that is set.
pub fn warn_retired_once() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let set = set_retired();
        if !set.is_empty() {
            tracing::warn!(
                target: "n42::env",
                knobs = %set.join(","),
                "retired on evm2 (2026-11-06): these knobs select nothing and are ignored"
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{lock, set, unset};

    #[test]
    fn every_retired_knob_is_named_once_and_sorted() {
        let mut names = RETIRED_ON_EVM2.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names, RETIRED_ON_EVM2);
        assert!(names.iter().all(|name| name.starts_with("N42_")));
    }

    #[test]
    fn a_set_retired_knob_is_reported_and_an_empty_one_is_not() {
        let _guard = lock();
        for name in RETIRED_ON_EVM2 {
            unset(name);
        }
        set("N42_READ_SET", "1");
        set("N42_GRAFT_STREAM", "");
        set("N42_FOLLOWER_GRAFT_STREAM", "0");
        assert_eq!(set_retired(), vec!["N42_FOLLOWER_GRAFT_STREAM", "N42_READ_SET"]);
        for name in RETIRED_ON_EVM2 {
            unset(name);
        }
        assert!(set_retired().is_empty());
    }
}
