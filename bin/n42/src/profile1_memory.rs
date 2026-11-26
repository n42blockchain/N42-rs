// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The profile-1 memory defaults of `n42` (`docs/P1_MEMORY.md`,
//! [`n42_qmdb_reth::profile1_memory`]): on a profile-1 genesis, unless the
//! operator chose otherwise,
//!
//! - rayon's global pool gets [`MemoryDefaults::cores`] threads
//!   ([`n42_qmdb_reth::profile1_memory::size_rayon_global`], before clap's
//!   chain parser starts it; an operator's `RAYON_NUM_THREADS` wins);
//! - `--cpu-cores` (tokio's workers and reth's CPU, RPC, blocking, proof and
//!   prewarming pools) and `--engine.cross-block-cache-size` take the
//!   profile's values ([`apply_to_node_command`]; a flag on the command line
//!   wins).

use std::num::NonZeroUsize;

use n42_qmdb_reth::profile1_memory::{flag_given, MemoryDefaults};
use reth_node_core::args::EngineArgs;

/// The flag that sizes reth's pools by a core count.
pub const CPU_CORES_FLAG: &str = "--cpu-cores";
/// The flag that sizes reth's cross-block execution cache.
pub const CROSS_BLOCK_CACHE_FLAG: &str = "--engine.cross-block-cache-size";

/// The process's arguments (program name excluded), lossy UTF-8.
pub fn process_args() -> Vec<String> {
    std::env::args_os().skip(1).map(|arg| arg.to_string_lossy().into_owned()).collect()
}

/// After the command line is parsed: the node command's engine arguments
/// the operator left unset take the profile's values. Returns what it set.
pub fn apply_to_node_command(defaults: &MemoryDefaults, args: &[String], engine: &mut EngineArgs) -> Vec<String> {
    let mut set = Vec::new();
    if let Some(cores) = defaults.cores.and_then(NonZeroUsize::new)
        && !flag_given(args, CPU_CORES_FLAG)
    {
        engine.cpu_cores = Some(cores);
        set.push(format!("{CPU_CORES_FLAG} {cores}"));
    }
    if !flag_given(args, CROSS_BLOCK_CACHE_FLAG) {
        engine.cross_block_cache_size = defaults.cross_block_cache_mb;
        set.push(format!("{CROSS_BLOCK_CACHE_FLAG} {}", defaults.cross_block_cache_mb));
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn unset_flags_take_the_profile_values() {
        let defaults = MemoryDefaults { cores: Some(8), cross_block_cache_mb: 256 };
        let mut engine = EngineArgs::default();
        let set = apply_to_node_command(&defaults, &args(&["node", "--chain", "g.json"]), &mut engine);
        assert_eq!(engine.cpu_cores, NonZeroUsize::new(8));
        assert_eq!(engine.cross_block_cache_size, 256);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn an_operator_flag_wins() {
        let defaults = MemoryDefaults { cores: Some(8), cross_block_cache_mb: 256 };
        let mut engine = EngineArgs { cpu_cores: NonZeroUsize::new(32), cross_block_cache_size: 1024, ..Default::default() };
        let set = apply_to_node_command(
            &defaults,
            &args(&["node", "--cpu-cores", "32", "--engine.cross-block-cache-size=1024"]),
            &mut engine,
        );
        assert_eq!(engine.cpu_cores, NonZeroUsize::new(32));
        assert_eq!(engine.cross_block_cache_size, 1024);
        assert!(set.is_empty());
    }

    #[test]
    fn host_cores_leave_cpu_cores_unset() {
        let defaults = MemoryDefaults { cores: None, cross_block_cache_mb: 256 };
        let mut engine = EngineArgs::default();
        apply_to_node_command(&defaults, &args(&["node"]), &mut engine);
        assert_eq!(engine.cpu_cores, None);
        assert_eq!(engine.cross_block_cache_size, 256);
    }
}
