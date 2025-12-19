use reth_metrics::{
    metrics::{Counter, Gauge, Histogram},
    Metrics,
};

#[derive(Metrics)]
#[metrics(scope = "blockchain.provider")]
pub(crate) struct BlockchainProviderMetrics {
    /// How many verification get_tree_by_hash_for_validator happened in getting a beacon state.
    pub(crate) num_get_tree_by_hash_for_validator_in_getting_a_beacon_state: Counter,

    /// Histogram of get_beacon_state_by_hash durations (in seconds)
    pub(crate) get_beacon_state_by_hash_duration: Histogram,
    /// Histogram of get_beacon_block_by_hash durations (in seconds)
    pub(crate) get_beacon_block_by_hash_duration: Histogram,
}
