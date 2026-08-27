//! Stable execution-path classification shared by live consensus and replay.
//!
//! Workload and scheduling are independent. In particular, distributing
//! independent historical blocks across workers is not live PEVM, and neither
//! historical mode may write the live canonical chain through this crate's
//! Engine API seam.

/// Where the executed block came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionWorkload {
    /// Offline replay or ordered catch-up of already-known blocks.
    HistoricalReplay,
    /// A block on the latency-sensitive active consensus path.
    Live,
}

/// How transactions or independent blocks are scheduled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionScheduling {
    /// Parent-ordered blocks using reth's ordinary sequential EVM executor.
    Sequential,
    /// PEVM/Block-STM-style parallel transaction execution within a block.
    Pevm,
    /// Independent historical blocks distributed across workers.
    IndependentBlocks,
}

/// Complete execution classification used for metrics and safety gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionPath {
    /// Workload class.
    workload: ExecutionWorkload,
    /// Scheduling class.
    scheduling: ExecutionScheduling,
}

impl ExecutionPath {
    /// Independent historical blocks executed by the external `pevm` harness.
    pub const HISTORICAL_PEVM: Self = Self {
        workload: ExecutionWorkload::HistoricalReplay,
        scheduling: ExecutionScheduling::Pevm,
    };

    /// Planned witness replay: blocks are independent and worker-sharded.
    pub const HISTORICAL_PARALLEL_BLOCKS: Self = Self {
        workload: ExecutionWorkload::HistoricalReplay,
        scheduling: ExecutionScheduling::IndependentBlocks,
    };

    /// Parent-ordered range catch-up through Engine API `newPayload` and FCU.
    pub const HISTORICAL_SEQUENTIAL: Self = Self {
        workload: ExecutionWorkload::HistoricalReplay,
        scheduling: ExecutionScheduling::Sequential,
    };

    /// Production execution today: reth's sequential EVM on the H2 live path.
    pub const LIVE_SEQUENTIAL: Self = Self {
        workload: ExecutionWorkload::Live,
        scheduling: ExecutionScheduling::Sequential,
    };

    /// Reserved for a future, explicitly qualified live PEVM integration.
    pub const LIVE_PEVM: Self = Self {
        workload: ExecutionWorkload::Live,
        scheduling: ExecutionScheduling::Pevm,
    };

    /// Workload axis.
    pub const fn workload(self) -> ExecutionWorkload {
        self.workload
    }

    /// Scheduling axis.
    pub const fn scheduling(self) -> ExecutionScheduling {
        self.scheduling
    }

    /// Stable low-cardinality metric label.
    pub const fn label(self) -> &'static str {
        match (self.workload, self.scheduling) {
            (ExecutionWorkload::HistoricalReplay, ExecutionScheduling::Pevm) => "historical_pevm",
            (ExecutionWorkload::HistoricalReplay, ExecutionScheduling::IndependentBlocks) => {
                "historical_parallel_blocks"
            }
            (ExecutionWorkload::HistoricalReplay, ExecutionScheduling::Sequential) => {
                "historical_sequential"
            }
            (ExecutionWorkload::Live, ExecutionScheduling::Sequential) => "live_sequential",
            (ExecutionWorkload::Live, ExecutionScheduling::Pevm) => "live_pevm",
            (ExecutionWorkload::Live, ExecutionScheduling::IndependentBlocks) => {
                "live_parallel_blocks_invalid"
            }
        }
    }

    /// Whether this path is implemented by the current canonical Engine API adapter.
    pub const fn uses_current_engine_api(self) -> bool {
        matches!(self.scheduling, ExecutionScheduling::Sequential)
    }

    /// Whether this path may update canonical fork choice.
    pub const fn may_write_canonical_state(self) -> bool {
        matches!(self, Self::HISTORICAL_SEQUENTIAL | Self::LIVE_SEQUENTIAL)
    }

    /// Whether this path may start and resolve a canonical payload build.
    pub const fn may_start_payload_build(self) -> bool {
        matches!(self, Self::LIVE_SEQUENTIAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_keep_workload_and_scheduling_separate() {
        assert_eq!(ExecutionPath::HISTORICAL_PEVM.label(), "historical_pevm");
        assert_eq!(
            ExecutionPath::HISTORICAL_PARALLEL_BLOCKS.label(),
            "historical_parallel_blocks"
        );
        assert_eq!(
            ExecutionPath::HISTORICAL_SEQUENTIAL.label(),
            "historical_sequential"
        );
        assert_eq!(ExecutionPath::LIVE_SEQUENTIAL.label(), "live_sequential");
        assert_eq!(ExecutionPath::LIVE_PEVM.label(), "live_pevm");

        assert!(ExecutionPath::HISTORICAL_SEQUENTIAL.uses_current_engine_api());
        assert!(ExecutionPath::LIVE_SEQUENTIAL.uses_current_engine_api());
        assert!(!ExecutionPath::HISTORICAL_PEVM.uses_current_engine_api());
        assert!(!ExecutionPath::HISTORICAL_PARALLEL_BLOCKS.uses_current_engine_api());
        assert!(!ExecutionPath::LIVE_PEVM.uses_current_engine_api());

        assert!(ExecutionPath::HISTORICAL_SEQUENTIAL.may_write_canonical_state());
        assert!(ExecutionPath::LIVE_SEQUENTIAL.may_write_canonical_state());
        assert!(!ExecutionPath::HISTORICAL_PEVM.may_write_canonical_state());
        assert!(!ExecutionPath::HISTORICAL_PARALLEL_BLOCKS.may_write_canonical_state());
        assert!(!ExecutionPath::LIVE_PEVM.may_write_canonical_state());

        assert!(ExecutionPath::LIVE_SEQUENTIAL.may_start_payload_build());
        assert!(!ExecutionPath::HISTORICAL_SEQUENTIAL.may_start_payload_build());
        assert!(!ExecutionPath::LIVE_PEVM.may_start_payload_build());
    }
}
