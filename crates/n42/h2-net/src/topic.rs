// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gossip topic strings, matching gov5's `internal/p2p/topics.go`.

use libp2p::gossipsub::IdentTopic;

/// gov5's `GossipProtocolAndDigest` prefix, minus the fork digest.
pub const GOSSIP_TOPIC_PREFIX: &str = "/n42/";

/// The transport-encoding suffix every gov5 gossip topic carries.
pub const SSZ_SNAPPY_SUFFIX: &str = "/ssz_snappy";

/// gov5's `H2V4Topic` — the chain-bound HotStuff-2 v4 topic, *without* the
/// encoding suffix. Kept separate because gov5's scoring switch matches on this
/// substring (`gossip_scoring_params.go`), while subscription uses the full
/// string below.
pub const H2_V4_TOPIC_BASE: &str = "/n42/h2/4";

/// The full topic a node subscribes to: `/n42/h2/4/ssz_snappy`.
///
/// Note this topic is NOT fork-digest scoped, unlike gov5's block and
/// hotstuff_consensus topics — the v4 envelope carries full chain identity in
/// its own header instead, which is what makes it cross-client.
pub const H2_V4_TOPIC: &str = "/n42/h2/4/ssz_snappy";

/// The v4 Decide topic.
pub fn h2_v4_topic() -> IdentTopic {
    IdentTopic::new(H2_V4_TOPIC)
}

/// A fork-digest-scoped gov5 topic: `/n42/<first 4 genesis bytes>/<kind>/ssz_snappy`.
pub fn fork_scoped_topic(genesis_hash: alloy_primitives::B256, kind: &str) -> IdentTopic {
    let digest = alloy_primitives::hex::encode(&genesis_hash.as_slice()[..4]);
    IdentTopic::new(format!("{GOSSIP_TOPIC_PREFIX}{digest}/{kind}{SSZ_SNAPPY_SUFFIX}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_topic_matches_gov5_constant() {
        // gov5: H2V4Topic = "/n42/" + GossipH2V4Message, subscribed with
        // "/ssz_snappy" appended (internal/p2p/pubsub_filter_test.go).
        assert_eq!(H2_V4_TOPIC_BASE, "/n42/h2/4");
        assert_eq!(H2_V4_TOPIC, format!("{H2_V4_TOPIC_BASE}{SSZ_SNAPPY_SUFFIX}"));
        assert_eq!(h2_v4_topic().to_string(), "/n42/h2/4/ssz_snappy");
    }

    #[test]
    fn fork_scoped_topics_use_the_four_byte_digest() {
        let genesis = alloy_primitives::b256!(
            "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
        );
        assert_eq!(
            fork_scoped_topic(genesis, "hotstuff_consensus").to_string(),
            "/n42/d4e56740/hotstuff_consensus/ssz_snappy"
        );
    }
}
