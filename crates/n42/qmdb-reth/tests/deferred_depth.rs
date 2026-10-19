// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! T1 of `docs/DEFERRED_DEPTH_2_DESIGN.md`: `deferredExecutionDepth` is parsed
//! strictly (`reth_chainspec::qmdb`, re-exported here; the vendored
//! chainspec crate's own lib tests do not build).

use alloy_genesis::Genesis;
use n42_qmdb_reth::{
    check_deferred_execution_depth, check_deferred_execution_depth_up_to, deferred_depth3_opted_in_from,
    deferred_execution_depth, deferred_execution_depth_at, supported_deferred_execution_depth, DeferredDepthError,
    SUPPORTED_DEFERRED_EXECUTION_DEPTH,
};

fn genesis(config: serde_json::Value, timestamp: u64) -> Genesis {
    let mut genesis = Genesis { timestamp, ..Default::default() };
    if let serde_json::Value::Object(map) = config {
        for (key, value) in map {
            genesis.config.extra_fields.insert(key, value);
        }
    }
    genesis
}

#[test]
fn the_depth_is_parsed_strictly() {
    use serde_json::json;
    // Absent is 1, with or without the gate.
    assert_eq!(deferred_execution_depth(&genesis(json!({}), 0)), Ok(1));
    assert_eq!(deferred_execution_depth(&genesis(json!({ "deferredExecutionTime": 0 }), 0)), Ok(1));
    // 1, 2 and 3 with the gate at genesis.
    for depth in [1u64, 2, 3] {
        let g = genesis(json!({ "deferredExecutionTime": 0, "deferredExecutionDepth": depth }), 0);
        assert_eq!(deferred_execution_depth(&g), Ok(depth));
        assert_eq!(deferred_execution_depth_at(&g, 5), depth);
    }
    // The gate equal to the genesis timestamp is "at genesis".
    let at = genesis(json!({ "deferredExecutionTime": 100, "deferredExecutionDepth": 2 }), 100);
    assert_eq!(deferred_execution_depth(&at), Ok(2));
    // Anything else is refused, never read as 1.
    for (value, err) in [
        (json!("2"), DeferredDepthError::NotAnInteger("\"2\"".into())),
        (json!(null), DeferredDepthError::NotAnInteger("null".into())),
        (json!(2.0), DeferredDepthError::NotAnInteger("2.0".into())),
        (json!(-1), DeferredDepthError::NotAnInteger("-1".into())),
        (json!(0), DeferredDepthError::OutOfRange(0)),
        (json!(4), DeferredDepthError::OutOfRange(4)),
        (json!(64), DeferredDepthError::OutOfRange(64)),
    ] {
        let g = genesis(json!({ "deferredExecutionTime": 0, "deferredExecutionDepth": value }), 0);
        assert_eq!(deferred_execution_depth(&g), Err(err));
    }
    // The depth without the gate, even 1, is an error, not a no-op.
    for depth in [1u64, 2] {
        let g = genesis(json!({ "deferredExecutionDepth": depth }), 0);
        assert_eq!(deferred_execution_depth(&g), Err(DeferredDepthError::WithoutGate));
    }
    // A gate that does not parse is refused here (the gate's own parser reads it as never).
    let g = genesis(json!({ "deferredExecutionTime": "0", "deferredExecutionDepth": 2 }), 0);
    assert_eq!(deferred_execution_depth(&g), Err(DeferredDepthError::MalformedGate("\"0\"".into())));
    // Depth 2 with the gate after genesis is refused; depth 1 there is fine.
    let late = genesis(json!({ "deferredExecutionTime": 101, "deferredExecutionDepth": 2 }), 100);
    assert_eq!(
        deferred_execution_depth(&late),
        Err(DeferredDepthError::GateAfterGenesis { gate: 101, genesis: 100 })
    );
    let late_one = genesis(json!({ "deferredExecutionTime": 101, "deferredExecutionDepth": 1 }), 100);
    assert_eq!(deferred_execution_depth(&late_one), Ok(1));
    // Before the gate the depth is moot and reads 1.
    assert_eq!(deferred_execution_depth_at(&late_one, 100), 1);
}

#[test]
fn the_node_refuses_a_depth_it_does_not_implement() {
    use serde_json::json;
    let one = genesis(json!({ "deferredExecutionTime": 0, "deferredExecutionDepth": 1 }), 0);
    assert_eq!(check_deferred_execution_depth(&one), Ok(1));
    assert_eq!(check_deferred_execution_depth(&genesis(json!({}), 0)), Ok(1));
    let two = genesis(json!({ "deferredExecutionTime": 0, "deferredExecutionDepth": 2 }), 0);
    let checked = check_deferred_execution_depth(&two);
    if SUPPORTED_DEFERRED_EXECUTION_DEPTH >= 2 {
        assert_eq!(checked, Ok(2));
    } else {
        assert_eq!(checked, Err(DeferredDepthError::NotImplemented(2)));
    }
    // Depth 3 is defined by the rule but not run by this node yet: it
    // parses and is refused at start-up.
    let three = genesis(json!({ "deferredExecutionTime": 0, "deferredExecutionDepth": 3 }), 0);
    assert_eq!(deferred_execution_depth(&three), Ok(3));
    let checked = check_deferred_execution_depth(&three);
    if supported_deferred_execution_depth() >= 3 {
        assert_eq!(checked, Ok(3));
    } else {
        assert_eq!(checked, Err(DeferredDepthError::NotImplemented(3)));
    }
    // The opt-in (`N42_DEFERRED_DEPTH3=1`) runs it; the default does not.
    assert_eq!(SUPPORTED_DEFERRED_EXECUTION_DEPTH, 2);
    assert_eq!(check_deferred_execution_depth_up_to(&three, 3), Ok(3));
    assert_eq!(check_deferred_execution_depth_up_to(&three, 2), Err(DeferredDepthError::NotImplemented(3)));
    assert_eq!(check_deferred_execution_depth_up_to(&two, 3), Ok(2));
    assert!(DeferredDepthError::NotImplemented(3).to_string().contains("N42_DEFERRED_DEPTH3=1"));
    for (value, on) in [(None, false), (Some("1"), true), (Some(" 1 "), true), (Some("0"), false), (Some("true"), false), (Some(""), false)] {
        assert_eq!(deferred_depth3_opted_in_from(value), on, "{value:?}");
    }
    // Errors of the value come first.
    let bad = genesis(json!({ "deferredExecutionTime": 0, "deferredExecutionDepth": 4 }), 0);
    assert_eq!(check_deferred_execution_depth(&bad), Err(DeferredDepthError::OutOfRange(4)));
    // Depth 3 with the gate after genesis is refused like depth 2.
    let late = genesis(json!({ "deferredExecutionTime": 101, "deferredExecutionDepth": 3 }), 100);
    assert_eq!(deferred_execution_depth(&late), Err(DeferredDepthError::GateAfterGenesis { gate: 101, genesis: 100 }));
    // The messages name the defined range.
    assert_eq!(
        DeferredDepthError::OutOfRange(4).to_string(),
        "deferredExecutionDepth must be 1..=3, found 4"
    );
}

#[test]
fn the_bundled_genesis_files_are_depth_one() {
    for file in [
        include_str!("../../../chainspec/res/genesis/n42_fleet3_bench.json"),
        include_str!("../../../chainspec/res/genesis/n42_fleet4_bench.json"),
        include_str!("../../../chainspec/res/genesis/n42_fleet7_bench.json"),
        include_str!("../../../chainspec/res/genesis/n42_fleet7.json"),
        include_str!("../../../chainspec/res/genesis/n42_devnet.json"),
    ] {
        let genesis: Genesis = serde_json::from_str(file).expect("a bundled genesis parses");
        assert_eq!(check_deferred_execution_depth(&genesis), Ok(1));
    }
}

/// Step 7: the depth-2 bench files are copies of the depth-1 ones with
/// `deferredExecutionDepth: 2` and a different `extraData`, so their genesis
/// hash -- and with it the fork digest and the block-gossip topic -- differs
/// from the depth-1 chain's: a depth-1 and a depth-2 binary given different
/// files never meet on the wire.
#[test]
fn the_depth_two_bench_files_are_chains_of_their_own() {
    for (one, two) in [
        (
            include_str!("../../../chainspec/res/genesis/n42_fleet3_bench.json"),
            include_str!("../../../chainspec/res/genesis/n42_fleet3_bench_d2.json"),
        ),
        (
            include_str!("../../../chainspec/res/genesis/n42_fleet7_bench.json"),
            include_str!("../../../chainspec/res/genesis/n42_fleet7_bench_d2.json"),
        ),
    ] {
        let one: Genesis = serde_json::from_str(one).expect("a genesis");
        let two: Genesis = serde_json::from_str(two).expect("a genesis");
        assert_eq!(check_deferred_execution_depth(&one), Ok(1));
        assert_eq!(check_deferred_execution_depth(&two), Ok(2));
        assert_eq!(one.alloc, two.alloc);
        assert_eq!(one.timestamp, two.timestamp);
        assert_ne!(one.extra_data, two.extra_data);
        let hash = |genesis: Genesis| {
            n42_qmdb_reth::with_declared_state_scheme(reth_chainspec::ChainSpec::from(genesis))
                .expect("a qmdb chain")
                .genesis_hash()
        };
        assert_ne!(hash(one), hash(two), "a depth-2 chain has its own genesis hash");
    }
}
