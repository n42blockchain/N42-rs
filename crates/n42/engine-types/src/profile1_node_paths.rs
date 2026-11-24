// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's profile-1 hashes through the node's own paths, not only the
//! `N42Header` codec: the genesis as `--chain <file>` parses it (the QMDB
//! root rewrite included) and as the database stores it, and every block of
//! vectors V1 (blocks 1-2) and V5 (six blocks) as the node hands a built
//! block to the engine (`block_to_payload`), converts a payload back into
//! the block it executes and stores (`convert_payload_to_block`, with the
//! profile and header rules the node's validator builder reads from the
//! chain), and stores the header (`Compact`).

use crate::{
    engine_types::N42EngineTypes,
    engine_validator::{header_profile_for, N42EngineValidator},
    profile1_vectors::{b256, chain, decode, gov5_dir, hex, rewards},
};
use alloy_primitives::B256;
use n42_header::{N42ChainSpec, N42Header};
use reth_chainspec::EthChainSpec as _;
use reth_cli::chainspec::ChainSpecParser as _;
use reth_codecs::Compact as _;
use reth_payload_primitives::PayloadTypes as _;
use reth_primitives_traits::{SealedBlock, SealedHeader};
use serde_json::Value;
use std::{path::PathBuf, sync::Arc};

fn json(path: PathBuf) -> Value {
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&raw).expect("json")
}

fn v1() -> Value {
    json(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../h2-consensus/testdata/profile1/header_profile_v1.json"))
}

fn v1_genesis_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../qmdb-reth/testdata/profile1/gov5/V1/genesis_8s.json")
}

/// The header as the database stores and reads it back.
fn stored(header: &N42Header) -> N42Header {
    let mut buf = Vec::new();
    let len = header.to_compact(&mut buf);
    N42Header::from_compact(&buf, len).0
}

/// The genesis the node runs on: `--chain <file>` through the CLI's parser,
/// wrapped as the node's chain spec, carries gov5's hash and RLP, and the
/// stored header keeps both.
#[test]
fn the_parsed_genesis_is_gov5s() {
    let v1 = v1();
    let parsed = n42_qmdb_reth::N42ChainSpecParser::parse(v1_genesis_path().to_str().expect("utf-8")).expect("parses");
    assert_eq!(parsed.genesis_hash(), b256(&v1["genesisHash"]), "the parser's genesis hash");
    let spec = N42ChainSpec::new(parsed);
    let genesis = spec.sealed_genesis_header();
    assert_eq!(spec.genesis_hash(), b256(&v1["genesisHash"]));
    assert_eq!(genesis.header().mobile_registry_root, Some(B256::ZERO));
    assert_eq!(alloy_rlp::encode(genesis.header()), hex(&v1["genesis"]["rlp"]), "genesis RLP");
    assert_eq!(genesis.hash_slow(), genesis.hash(), "the header hashes to its seal");
    assert_eq!(stored(genesis.header()).hash_slow(), genesis.hash(), "the stored genesis");
}

/// One vector block through the node's paths; returns its hash.
fn through_the_node(spec: &Arc<N42ChainSpec>, name: &str, rlp: &Value, hash: B256, transactions: &[Value]) -> B256 {
    let raw = hex(rlp);
    let header: N42Header = alloy_rlp::Decodable::decode(&mut raw.as_slice()).expect("the header decodes");
    assert!(header.mobile_registry_root.is_some() && header.slot_number.is_some(), "{name}: a profile-1 header");
    let body = n42_tx_types::BlockBody {
        transactions: transactions.iter().map(|tx| decode(&hex(tx)).expect("a transaction")).collect(),
        ommers: Vec::new(),
        withdrawals: Some(rewards(spec.inner(), header.beneficiary).into()),
    };
    // The leader's built block, sealed as the builder seals it.
    let built = SealedBlock::seal_slow(n42_tx_types::Block { header: header.clone(), body });
    assert_eq!(built.hash(), hash, "{name}: the built block's hash");

    // Handed to the engine and converted back, as the engine tree does with
    // every payload, the leader's own and a follower's alike.
    let payload = N42EngineTypes::block_to_payload(built, None);
    assert_eq!(payload.block_hash(), hash, "{name}: the payload's block hash");
    let validator = N42EngineValidator::new(spec.clone(), header_profile_for(spec.as_ref()))
        .with_header_rules(crate::hotstuff_consensus::chain_header_rules(spec.as_ref()));
    let converted = <N42EngineValidator<N42ChainSpec> as reth_engine_primitives::PayloadValidator<N42EngineTypes>>::convert_payload_to_block(
        &validator, payload,
    )
    .unwrap_or_else(|e| panic!("{name}: convert_payload_to_block: {e}"));
    assert_eq!(converted.hash(), hash, "{name}: the converted block's hash");
    assert_eq!(converted.header(), &header, "{name}: the converted header");
    assert_eq!(converted.header().hash_slow(), hash, "{name}: the converted header rehashes");
    assert_eq!(alloy_rlp::encode(converted.header()), raw, "{name}: the converted header's RLP");

    // Stored and read back, and resealed from what was read.
    let back = stored(converted.header());
    assert_eq!(back, header, "{name}: the stored header");
    assert_eq!(SealedHeader::seal_slow(back).hash(), hash, "{name}: the stored header's hash");
    converted.header().parent_hash
}

/// V1's blocks 1 and 2 and V5's six blocks keep gov5's hashes through the
/// node's build, engine and storage paths, each naming its predecessor (the
/// first, the parsed genesis).
#[test]
fn gov5_blocks_keep_their_hashes_through_the_node() {
    let v1 = v1();
    let spec = Arc::new(N42ChainSpec::from(chain(&serde_json::json!({}))));
    let mut parent = spec.genesis_hash();
    for block in v1["headers"].as_array().expect("headers") {
        let name = block["name"].as_str().expect("name");
        let hash = b256(&block["hash"]);
        assert_eq!(through_the_node(&spec, name, &block["rlp"], hash, &[]), parent, "{name}: parent hash");
        parent = hash;
    }

    let v5 = json(gov5_dir().join("V5/header_validity.json"));
    let spec = Arc::new(N42ChainSpec::from(chain(&v5["allocAdditions"])));
    assert_eq!(spec.genesis_hash(), b256(&v5["genesisHash"]));
    let mut parent = spec.genesis_hash();
    let mut count = 0;
    for block in v5["blocks"].as_array().expect("blocks") {
        let name = block["name"].as_str().expect("name");
        let hash = b256(&block["hash"]);
        let txs = block["transactions"].as_array().expect("transactions");
        assert_eq!(through_the_node(&spec, name, &block["rlp"], hash, txs), parent, "{name}: parent hash");
        parent = hash;
        count += 1;
    }
    assert_eq!(count, 6);
}
