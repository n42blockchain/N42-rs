// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's profile-1 vector V9 (GossipSub parameters,
//! `testdata/profile1/gov5/V9`, a byte-exact copy) against this node's
//! router configuration.
//!
//! The wire contract -- topic strings (G2), the message id (G3) and the
//! message-size cap after profile 1's `maxBlockBytes` (B15) -- must match
//! exactly. The mesh, gossip and history values (G4) are asserted wherever
//! rust-libp2p's gossipsub has the same knob; the go-libp2p-pubsub fields it
//! has no counterpart for are listed in [`NO_COUNTERPART`], so a new field in
//! the vector fails the test until it is placed.
//!
//! Peer scoring is not configured here: gov5 runs it only with discovery on,
//! and this node always runs on an explicit peer list (gov5's discovery-off
//! mode, which runs without scoring).

use std::time::Duration;

use alloy_primitives::{hex, B256};
use n42_h2_net::{
    block_gossip::gov5_block_topic,
    config::{GOSSIP_SUB_D, GOSSIP_SUB_D_HI, GOSSIP_SUB_D_LO, SEEN_MESSAGES_TTL},
    gov5_gossipsub_config, gov5_message_id_parts, max_block_chunk, max_gossip_size, max_gossip_wire_size,
    set_max_block_bytes,
    topic::{fork_scoped_topic, H2_V4_TOPIC},
    MOBILEVERIFY_PACKET_KIND, MOBILEVERIFY_REGISTRATION_KIND,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// SHA-256 of `gossipsub_parameters.json` as gov5 published it.
const PARAMETERS_SHA256: &str = "b315f30b8b9682486ab750f7aa7ab3bbaa84bd62f8941c74492208479fad8716";

/// Profile 1's `maxBlockBytes` (B15): 64 MiB.
const PROFILE1_MAX_BLOCK_BYTES: u64 = 64 << 20;

/// go-libp2p-pubsub `GossipSubParams` fields rust-libp2p's gossipsub has no
/// setting for (dialing is the swarm's, IDONTWANT bookkeeping and the slow
/// heartbeat warning are internal there).
const NO_COUNTERPART: &[&str] = &[
    "ConnectionTimeout",
    "Connectors",
    "MaxPendingConnections",
    "DirectConnectInitialDelay",
    "SlowHeartbeatWarning",
    "IDontWantMessageTTL",
    "MaxIDontWantLength",
    "MaxIDontWantMessages",
];

/// Sets profile 1's block bound before anything reads the gossip cap (the
/// cap is read once per process, and the tests run in parallel).
fn profile1() {
    static SET: std::sync::Once = std::sync::Once::new();
    SET.call_once(|| set_max_block_bytes(PROFILE1_MAX_BLOCK_BYTES).expect("the profile-1 bound"));
}

fn vector() -> Value {
    profile1();
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/profile1/gov5/V9/gossipsub_parameters.json");
    let raw = std::fs::read(path).expect("V9");
    assert_eq!(hex::encode(Sha256::digest(&raw)), PARAMETERS_SHA256, "V9 is not gov5's byte-exact copy");
    serde_json::from_slice(&raw).expect("json")
}

fn genesis(v: &Value) -> B256 {
    v["genesisHash"].as_str().expect("hash").parse().expect("B256")
}

fn number(value: &Value) -> u64 {
    value.as_u64().expect("an integer")
}

fn ms(value: &Value) -> Duration {
    Duration::from_millis(number(value))
}

#[test]
fn topic_strings_match_gov5() {
    let v = vector();
    let genesis = genesis(&v);
    assert_eq!(hex::encode(&genesis[..4]), v["forkDigest"].as_str().expect("digest"));
    let topics = v["topics"].as_array().expect("topics");
    assert_eq!(topics.len(), 11);
    for t in topics {
        let name = t["name"].as_str().expect("name");
        let expected = t["topic"].as_str().expect("topic");
        let ours = match name {
            "block" => gov5_block_topic(genesis).to_string(),
            "h2/4" => H2_V4_TOPIC.to_string(),
            "mobileverify_packet" => fork_scoped_topic(genesis, MOBILEVERIFY_PACKET_KIND).to_string(),
            "mobileverify_registration" => fork_scoped_topic(genesis, MOBILEVERIFY_REGISTRATION_KIND).to_string(),
            // The transport joins these under their gov5 names; the rest
            // (blob_sidecar, zk_proof, the cohort topics) are not in G2 and
            // this node does not join them, but the string rule is the same.
            other => fork_scoped_topic(genesis, other).to_string(),
        };
        assert_eq!(ours, expected, "topic {name}");
    }
    // Every G2 topic is one the transport subscribes to (mobileverify only
    // when serving phones); none outside G2 is.
    let in_g2: Vec<&str> =
        topics.iter().filter(|t| t["inG2"].as_bool() == Some(true)).map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        in_g2,
        ["block", "transaction_v2", "hotstuff_consensus", "h2/4", "mobileverify_packet", "mobileverify_registration"]
    );
}

#[test]
fn message_ids_match_gov5() {
    let v = vector();
    let genesis = genesis(&v);
    let rows = v["messageIds"].as_array().expect("messageIds");
    assert_eq!(rows.len(), 4);
    for row in rows {
        let topic = row["topic"].as_str().expect("topic");
        let data = hex::decode(row["data"].as_str().expect("data")).expect("hex");
        assert_eq!(
            format!("0x{}", hex::encode(gov5_message_id_parts(genesis, topic, &data))),
            row["messageId"].as_str().expect("id"),
            "{topic} / {}",
            row["data"]
        );
    }
}

#[test]
fn router_options_match_gov5() {
    let v = vector();
    let router = &v["router"];
    // B15: the chain's bound replaces the default; the router cap is its
    // snappy-encoded bound.
    assert_eq!(max_gossip_size() as u64, number(&router["maxDecodedMessageBytes"]));
    assert_eq!(max_block_chunk(), number(&router["maxDecodedMessageBytes"]));
    assert_eq!(max_gossip_wire_size() as u64, number(&router["maxMessageSizeBytes"]));
    let cfg = gov5_gossipsub_config(genesis(&v)).expect("config");
    assert_eq!(cfg.max_transmit_size() as u64, number(&router["maxMessageSizeBytes"]));
    // StrictNoSign + no author.
    assert_eq!(router["messageSignaturePolicy"], "StrictNoSign");
    assert!(router["noAuthor"].as_bool().expect("bool"));
    assert!(matches!(cfg.validation_mode(), libp2p::gossipsub::ValidationMode::Anonymous));
    assert_eq!(cfg.duplicate_cache_time(), ms(&router["seenMessagesTTLMs"]));
    assert_eq!(SEEN_MESSAGES_TTL, ms(&router["seenMessagesTTLMs"]));
    assert_eq!(router["protocolSuffix"], "/ssz_snappy");
}

#[test]
fn gossipsub_params_match_gov5() {
    let v = vector();
    let p = &v["gossipSubParams"];
    let cfg = gov5_gossipsub_config(genesis(&v)).expect("config");
    let checks: &[(&str, u64, u64)] = &[
        ("D", cfg.mesh_n() as u64, number(&p["D"])),
        ("Dlo", cfg.mesh_n_low() as u64, number(&p["Dlo"])),
        ("Dhi", cfg.mesh_n_high() as u64, number(&p["Dhi"])),
        ("Dlazy", cfg.gossip_lazy() as u64, number(&p["Dlazy"])),
        ("Dout", cfg.mesh_outbound_min() as u64, number(&p["Dout"])),
        ("Dscore", cfg.retain_scores() as u64, number(&p["Dscore"])),
        ("HistoryLength", cfg.history_length() as u64, number(&p["HistoryLength"])),
        ("HistoryGossip", cfg.history_gossip() as u64, number(&p["HistoryGossip"])),
        ("GossipRetransmission", u64::from(cfg.gossip_retransimission()), number(&p["GossipRetransmission"])),
        ("OpportunisticGraftPeers", cfg.opportunistic_graft_peers() as u64, number(&p["OpportunisticGraftPeers"])),
        ("OpportunisticGraftTicks", cfg.opportunistic_graft_ticks(), number(&p["OpportunisticGraftTicks"])),
        ("DirectConnectTicks", cfg.check_explicit_peers_ticks(), number(&p["DirectConnectTicks"])),
        ("MaxIHaveLength", cfg.max_control_messages_sent() as u64, number(&p["MaxIHaveLength"])),
        ("MaxIHaveMessages", cfg.max_ihave_messages_heartbeat() as u64, number(&p["MaxIHaveMessages"])),
        ("IDontWantMessageThreshold", cfg.idontwant_message_size_threshold() as u64, number(&p["IDontWantMessageThreshold"])),
        ("HeartbeatInterval", cfg.heartbeat_interval().as_millis() as u64, number(&p["HeartbeatInterval"])),
        ("HeartbeatInitialDelay", cfg.heartbeat_initial_delay().as_millis() as u64, number(&p["HeartbeatInitialDelay"])),
        ("FanoutTTL", cfg.fanout_ttl().as_millis() as u64, number(&p["FanoutTTL"])),
        ("PruneBackoff", cfg.prune_backoff().as_millis() as u64, number(&p["PruneBackoff"])),
        ("UnsubscribeBackoff", cfg.unsubscribe_backoff().as_millis() as u64, number(&p["UnsubscribeBackoff"])),
        ("GraftFloodThreshold", cfg.graft_flood_threshold().as_millis() as u64, number(&p["GraftFloodThreshold"])),
        ("IWantFollowupTime", cfg.iwant_followup_time().as_millis() as u64, number(&p["IWantFollowupTime"])),
    ];
    let diffs: Vec<String> = checks
        .iter()
        .filter(|(_, ours, gov5)| ours != gov5)
        .map(|(name, ours, gov5)| format!("{name}: ours {ours}, gov5 {gov5}"))
        .collect();
    assert!(diffs.is_empty(), "GossipSub parameters differ from gov5: {diffs:?}");
    assert_eq!(cfg.gossip_factor(), p["GossipFactor"].as_f64().expect("float"), "GossipFactor");
    assert_eq!((GOSSIP_SUB_D, GOSSIP_SUB_D_LO, GOSSIP_SUB_D_HI), (8, 6, 12));

    // PrunePeers is the peer-exchange list a PRUNE carries; this node, like
    // gov5, does not run peer exchange, so the count is never used.
    assert_eq!(number(&p["PrunePeers"]), 16);
    assert!(!cfg.do_px());

    // Every field of the vector is either asserted above or listed as
    // having no counterpart.
    let asserted: Vec<&str> = checks.iter().map(|(name, _, _)| *name).chain(["GossipFactor", "PrunePeers"]).collect();
    for field in p.as_object().expect("params").keys() {
        assert!(
            asserted.contains(&field.as_str()) || NO_COUNTERPART.contains(&field.as_str()),
            "gossipSubParams.{field} is neither asserted nor listed"
        );
    }
}
