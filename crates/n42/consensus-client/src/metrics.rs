use reth_metrics::{
    metrics::{Counter, Gauge, Histogram},
    Metrics,
};

#[derive(Metrics)]
#[metrics(scope = "consensus.client")]
pub(crate) struct MinerMetrics {
    /// How many verifications were submitted.
    pub(crate) num_verification_submission: Counter,
    /// How many block hash mismatches happpened.
    pub(crate) num_verification_block_hash_mismatch: Counter,
}
