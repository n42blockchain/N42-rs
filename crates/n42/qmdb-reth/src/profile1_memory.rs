// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Memory defaults of a profile-1 member (`docs/P1_MEMORY.md`).
//!
//! A profile-1 chain runs 8-second blocks of a few hundred transactions, but
//! the node sizes its thread pools by the host's cores and reth's cross-block
//! execution cache for Ethereum mainnet. On a many-core host that is the bulk
//! of a member's memory: every thread keeps the stack pages it once touched
//! and its own allocator cache, and the execution cache fills its pages as
//! blocks touch accounts. None of it is consensus-visible.
//!
//! On a chain whose genesis declares profile 1, the binaries size those for
//! the profile unless the operator chose otherwise: a command-line flag or an
//! environment variable the operator set always wins, and
//! `N42_P1_MEMORY=0` turns every default here off. A chain without
//! `n42Profile` is untouched (the fleet and bench paths do not change).
//!
//! The chain is known only after the command line is parsed, but the thread
//! pools that matter are sized before that (clap runs the chain parser, which
//! computes the genesis root on rayon's global pool and opens a QMDB tree),
//! so [`peek_args`] reads the genesis file named by `--chain` first, the way
//! the parser will, and [`set_env_defaults`] runs before it.

use std::path::Path;

use reth_chainspec::qmdb::{N42_PROFILE_1, N42_PROFILE_KEY};

/// `N42_P1_MEMORY=0` turns the profile-1 memory defaults off (on by default,
/// and only ever on a profile-1 chain).
pub const MEMORY_KNOB: &str = "N42_P1_MEMORY";

/// `N42_P1_CORES=<n>`: the cores a profile-1 member sizes its pools by
/// (default [`DEFAULT_CORES`], never more than the host has; `0` keeps the
/// host's count).
pub const CORES_KNOB: &str = "N42_P1_CORES";

/// `N42_P1_CROSS_BLOCK_CACHE_MB=<n>`: reth's cross-block execution cache on
/// a profile-1 member (default [`DEFAULT_CROSS_BLOCK_CACHE_MB`]).
pub const CROSS_BLOCK_CACHE_KNOB: &str = "N42_P1_CROSS_BLOCK_CACHE_MB";

/// `N42_P1_ROCKSDB_CACHE_MB=<n>`: the `RocksDB` block cache on a profile-1
/// member (default [`DEFAULT_ROCKSDB_CACHE_MB`]).
pub const ROCKSDB_CACHE_KNOB: &str = "N42_P1_ROCKSDB_CACHE_MB";

/// `N42_P1_RPC_CACHE_MB=<n>`: the byte bound of each of the RPC state
/// cache's block, receipt and block-access-list caches on a profile-1 member
/// (default [`DEFAULT_RPC_CACHE_MB`]).
pub const RPC_CACHE_KNOB: &str = "N42_P1_RPC_CACHE_MB";

/// The cores a profile-1 member sizes its pools by.
pub const DEFAULT_CORES: usize = 8;

/// reth's cross-block execution cache on a profile-1 member, in MiB (reth's
/// default is 4096).
pub const DEFAULT_CROSS_BLOCK_CACHE_MB: usize = 256;

/// The `RocksDB` block cache (transaction hash index) on a profile-1 member,
/// in MiB (reth's default is 128).
pub const DEFAULT_ROCKSDB_CACHE_MB: usize = 32;

/// Each RPC state cache's byte bound on a profile-1 member, in MiB (reth's
/// are 2 GiB of blocks, 1 GiB of receipts, 500 MiB of block access lists).
/// Every canonical block's receipts are copied into it, so a catch-up of
/// heavy blocks filled the receipt cache to ~750 MiB (`docs/P1_MEMORY.md`).
pub const DEFAULT_RPC_CACHE_MB: usize = 64;

/// What a profile-1 member sizes by, after the knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryDefaults {
    /// Threads per pool sized by the core count (`None`: the host's count).
    pub cores: Option<usize>,
    /// reth's cross-block execution cache, MiB.
    pub cross_block_cache_mb: usize,
    /// The `RocksDB` block cache, MiB.
    pub rocksdb_cache_mb: usize,
    /// Each RPC state cache's byte bound, MiB.
    pub rpc_cache_mb: usize,
}

impl MemoryDefaults {
    /// The defaults with the knobs applied: `None` when `N42_P1_MEMORY` is off.
    pub fn from_env() -> Option<Self> {
        if !n42_env::flag(MEMORY_KNOB, true) {
            return None;
        }
        let host = std::thread::available_parallelism().map_or(DEFAULT_CORES, |n| n.get());
        let cores = match n42_env::parse(CORES_KNOB, DEFAULT_CORES) {
            0 => None,
            n => Some(n.min(host)),
        };
        let cross_block_cache_mb = n42_env::parse(CROSS_BLOCK_CACHE_KNOB, DEFAULT_CROSS_BLOCK_CACHE_MB);
        let rocksdb_cache_mb = n42_env::parse(ROCKSDB_CACHE_KNOB, DEFAULT_ROCKSDB_CACHE_MB);
        let rpc_cache_mb = n42_env::parse(RPC_CACHE_KNOB, DEFAULT_RPC_CACHE_MB);
        Some(Self { cores, cross_block_cache_mb, rocksdb_cache_mb, rpc_cache_mb })
    }

    /// The defaults for a process started with `args` (the program name
    /// excluded): `Some` only when `--chain` names a profile-1 genesis file
    /// and the knobs leave the defaults on.
    pub fn for_args(args: &[String]) -> Option<Self> {
        if peek_args(args) { Self::from_env() } else { None }
    }
}

/// The jemalloc options a profile-1 member runs with: one arena per core of
/// [`MemoryDefaults::cores`] instead of jemalloc's four per host core (1,016
/// on a 254-core host, each keeping its own dirty pages and metadata), and
/// the background threads that return decayed pages without waiting for the
/// arena's next allocation. `None` when the pools follow the host's cores.
pub fn malloc_conf(defaults: &MemoryDefaults) -> Option<String> {
    defaults.cores.map(|cores| format!("narenas:{cores},background_thread:true"))
}

/// The `MALLOC_CONF` a profile-1 member restarts with, given the one it was
/// started with: [`malloc_conf`] when none was set, the operator's options
/// after it when they do not choose the arena count (jemalloc reads them in
/// order, so the operator's later options win), and `None` -- nothing to do
/// -- when they do choose it, which is also how the restarted process
/// recognises itself.
pub fn malloc_conf_to_apply(defaults: &MemoryDefaults, current: Option<&str>) -> Option<String> {
    let ours = malloc_conf(defaults)?;
    match current.map(str::trim) {
        None | Some("") => Some(ours),
        Some(current) if current.contains("narenas") => None,
        Some(current) => Some(format!("{ours},{current}")),
    }
}

/// Restarts this program (same pid, same arguments, same `argv[0]`) with
/// [`malloc_conf_to_apply`] in `MALLOC_CONF`: jemalloc reads its options once,
/// before `main`, so a profile-1 member started without them can only take
/// them by `exec`ing itself. Returns without restarting when there is nothing
/// to apply, and with the error when the `exec` fails (the caller goes on
/// with the allocator as it is).
///
/// Call it first thing in `main`, before any thread exists.
#[cfg(unix)]
pub fn reexec_with_malloc_conf(defaults: &MemoryDefaults) -> Option<std::io::Error> {
    use std::os::unix::process::CommandExt;

    let current = std::env::var("MALLOC_CONF").ok();
    let conf = malloc_conf_to_apply(defaults, current.as_deref())?;
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => return Some(err),
    };
    let mut args = std::env::args_os();
    let arg0 = args.next().unwrap_or_else(|| exe.clone().into_os_string());
    // `exec` returns only on failure.
    Some(std::process::Command::new(exe).arg0(arg0).args(args).env("MALLOC_CONF", conf).exec())
}

/// Not on unix: the allocator stays as it is.
#[cfg(not(unix))]
pub fn reexec_with_malloc_conf(_defaults: &MemoryDefaults) -> Option<std::io::Error> {
    None
}

/// The QMDB prefault knobs a profile-1 member sets when the environment
/// leaves them unset (`crates/n42/twig-core/src/prefault.rs`). Their
/// defaults keep memory faulted in ahead for the fleet's 163,000-operation
/// blocks -- 512 clean twig trees (64 MiB), a 64 MiB populated append window,
/// two 8 MiB offsets segments -- in every process that opens a QMDB tree,
/// the validator's genesis-root computation included. A profile-1 block is a
/// few hundred operations: one twig (2,048 entries) lasts several blocks.
/// The values change when a page is faulted, never a byte of the tree.
pub const PREFAULT_KNOBS: &[(&str, &str)] = &[
    ("N42_TWIG_POOL_FLOOR", "16"),
    ("N42_QMDB_APPEND_AHEAD_MB", "8"),
    ("N42_QMDB_OFFSET_SEGMENTS_AHEAD", "1"),
];

/// The QMDB layout knob a profile-1 member sets when the environment leaves
/// it unset: the tree's entries in `qmdb/entries.log` (8 B of offset and a bit
/// per slot in memory) instead of the heap (~160 B per entry, a `Vec` that
/// grows by doubling: 1 GiB at the heavy catch-up's peak). A heap-mode
/// datadir migrates once at the first start (`QmdbNodeState`'s version-1
/// checkpoint migration) and stays in file mode afterwards, whatever the
/// environment says; roots and wire bytes are the same.
pub const LAYOUT_KNOBS: &[(&str, &str)] = &[("N42_QMDB_ENTRY_FILE", "1")];

/// Sets, where the environment leaves them unset, `RAYON_NUM_THREADS` to
/// [`MemoryDefaults::cores`] -- every rayon pool built with the default size
/// follows it: the global pool (which clap's chain parser starts for the
/// genesis root), reth's RPC blocking pool -- and every [`PREFAULT_KNOBS`]
/// and [`LAYOUT_KNOBS`] entry. Returns what it set, as `NAME=value`.
///
/// # Safety
///
/// Writes the process environment: call it from `main` before any thread
/// that could read or write the environment exists, and before any of the
/// variables is read (the knobs are read once, at first use; rayon reads
/// `RAYON_NUM_THREADS` when a pool is built).
pub unsafe fn set_env_defaults(defaults: &MemoryDefaults) -> Vec<String> {
    let mut set = Vec::new();
    let cores = defaults.cores.map(|cores| cores.to_string());
    let rayon = cores.as_deref().map(|cores| ("RAYON_NUM_THREADS", cores));
    let knobs = PREFAULT_KNOBS.iter().chain(LAYOUT_KNOBS).copied();
    for (name, value) in rayon.into_iter().chain(knobs) {
        if std::env::var_os(name).is_none() {
            // SAFETY: the caller guarantees no concurrent environment access.
            unsafe { std::env::set_var(name, value) };
            set.push(format!("{name}={value}"));
        }
    }
    set
}

/// The value of `--chain` in `args` (`--chain <v>` or `--chain=<v>`), the last
/// one if repeated, as clap reads it.
pub fn chain_arg(args: &[String]) -> Option<&str> {
    let mut found = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--chain" {
            found = iter.next().map(String::as_str);
        } else if let Some(value) = arg.strip_prefix("--chain=") {
            found = Some(value);
        }
    }
    found
}

/// Whether `flag` (`--name`) appears in `args`, alone or as `--name=<v>`.
pub fn flag_given(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag || arg.strip_prefix(flag).is_some_and(|rest| rest.starts_with('=')))
}

/// Whether the genesis file at `path` declares profile 1. A name that is not
/// a readable JSON file (a built-in chain) is not profile 1; the chain parser
/// reports a malformed file on its own.
pub fn genesis_file_is_profile1(path: &Path) -> bool {
    let Ok(raw) = std::fs::read(path) else { return false };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&raw) else { return false };
    value.get("config").and_then(|config| config.get(N42_PROFILE_KEY)).and_then(serde_json::Value::as_u64)
        == Some(N42_PROFILE_1)
}

/// Whether `args` start a process on a profile-1 genesis file.
pub fn peek_args(args: &[String]) -> bool {
    chain_arg(args).is_some_and(|chain| genesis_file_is_profile1(Path::new(chain)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn chain_arg_reads_both_spellings_and_the_last() {
        assert_eq!(chain_arg(&args(&["node", "--chain", "a.json"])), Some("a.json"));
        assert_eq!(chain_arg(&args(&["node", "--chain=b.json"])), Some("b.json"));
        assert_eq!(chain_arg(&args(&["--chain", "a", "--chain=b"])), Some("b"));
        assert_eq!(chain_arg(&args(&["node", "--chain"])), None);
        assert_eq!(chain_arg(&args(&["node", "--chains", "x"])), None);
    }

    #[test]
    fn flag_given_matches_whole_names() {
        let list = args(&["node", "--cpu-cores", "4", "--engine.cross-block-cache-size=64"]);
        assert!(flag_given(&list, "--cpu-cores"));
        assert!(flag_given(&list, "--engine.cross-block-cache-size"));
        assert!(!flag_given(&list, "--cpu"));
        assert!(!flag_given(&list, "--engine.cross-block-cache"));
    }

    #[test]
    fn only_a_profile1_genesis_file_counts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p1 = dir.path().join("p1.json");
        std::fs::write(&p1, r#"{"config":{"chainId":7,"n42Profile":1},"alloc":{}}"#).expect("write");
        let other = dir.path().join("other.json");
        std::fs::write(&other, r#"{"config":{"chainId":7},"alloc":{}}"#).expect("write");
        let two = dir.path().join("two.json");
        std::fs::write(&two, r#"{"config":{"n42Profile":2}}"#).expect("write");
        assert!(genesis_file_is_profile1(&p1));
        assert!(!genesis_file_is_profile1(&other));
        assert!(!genesis_file_is_profile1(&two));
        assert!(!genesis_file_is_profile1(Path::new("dev")));
        assert!(peek_args(&args(&["node", "--chain", p1.to_str().expect("utf8")])));
        assert!(!peek_args(&args(&["node", "--chain", "dev"])));
        assert!(!peek_args(&args(&["node"])));
    }

    #[test]
    fn malloc_conf_leaves_an_operator_arena_count_alone() {
        let defaults = MemoryDefaults { cores: Some(8), cross_block_cache_mb: 256, rocksdb_cache_mb: 32, rpc_cache_mb: 64 };
        let ours = "narenas:8,background_thread:true";
        assert_eq!(malloc_conf_to_apply(&defaults, None).as_deref(), Some(ours));
        assert_eq!(malloc_conf_to_apply(&defaults, Some(" ")).as_deref(), Some(ours));
        // The operator's options come after ours, so theirs win.
        assert_eq!(
            malloc_conf_to_apply(&defaults, Some("prof:true,background_thread:false")).as_deref(),
            Some("narenas:8,background_thread:true,prof:true,background_thread:false")
        );
        // An arena count already chosen (the operator's, or ours after the
        // restart) means nothing to apply: no restart loop.
        assert_eq!(malloc_conf_to_apply(&defaults, Some("narenas:32")), None);
        assert_eq!(malloc_conf_to_apply(&defaults, Some(ours)), None);
        let host = MemoryDefaults { cores: None, ..defaults };
        assert_eq!(malloc_conf_to_apply(&host, None), None);
    }

    #[test]
    fn the_v1_genesis_is_profile1() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/profile1/gov5/V1/genesis_8s.json");
        assert!(genesis_file_is_profile1(&path));
    }
}
