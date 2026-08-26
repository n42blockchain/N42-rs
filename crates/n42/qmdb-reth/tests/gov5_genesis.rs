// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reproducing a gov5 QMDB chain's genesis hash from its own alloc.
//!
//! `gov5`'s `mainnet_qmdb` (chain id 94) is a live `HotStuff` chain whose genesis
//! header carries the QMDB root of `allocs/mainnet.json`. Its hash is pinned
//! in gov5 as `params.MainnetQMDBGenesisHash`. Arriving at the same hash here
//! means every part of the genesis pipeline agrees with gov5 byte for byte:
//! the leaf encoding of 2,322 accounts, their sorted append into the forest,
//! the root, and the header fields reth derives from the fork schedule.
//!
//! The genesis parameters are gov5's `mainnetQMDBGenesisBlock()`: timestamp
//! 1678174066, difficulty `params.GenesisDifficulty` (131072), gas limit
//! `params.GenesisGasLimit` (4712388), empty extra data, and the
//! `mainnet_qmdb.json` chain config with every block fork at 0 and Prague at
//! 1780894800 — after the genesis timestamp, so no requests hash.

use alloy_primitives::{b256, B256};
use n42_qmdb_reth::{qmdb_genesis_root, state_scheme, with_declared_state_scheme, StateScheme};
use reth_chainspec::ChainSpec;

const GOV5_MAINNET_QMDB_GENESIS_HASH: B256 =
    b256!("5fcf94b7a5e7e337005c4b6333904983d9e5aa97e950bf1b63d42fb0be81ee69");

fn gov5_mainnet_qmdb_genesis() -> alloy_genesis::Genesis {
    let alloc = include_str!("../testdata/gov5_mainnet_alloc.json");
    let json = format!(
        r#"{{
            "config": {{
                "chainId": 94,
                "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0,
                "byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0,
                "istanbulBlock": 0, "muirGlacierBlock": 0, "berlinBlock": 0, "londonBlock": 0,
                "arrowGlacierBlock": 0,
                "shanghaiTime": 0, "cancunTime": 0,
                "pragueTime": 1780894800, "osakaTime": 1780894800,
                "stateScheme": "qmdb"
            }},
            "nonce": "0x0",
            "timestamp": "0x{timestamp:x}",
            "extraData": "0x",
            "gasLimit": "0x{gas_limit:x}",
            "difficulty": "0x{difficulty:x}",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "coinbase": "0x0000000000000000000000000000000000000000",
            "number": "0x0",
            "gasUsed": "0x0",
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "alloc": {alloc}
        }}"#,
        timestamp = 1678174066u64,
        gas_limit = 4712388u64,
        difficulty = 131072u64,
    );
    serde_json::from_str(&json).expect("a genesis")
}

#[test]
fn gov5_mainnet_qmdb_genesis_hash_is_reproduced_from_its_alloc() {
    let genesis = gov5_mainnet_qmdb_genesis();
    assert_eq!(genesis.alloc.len(), 2322);
    assert_eq!(state_scheme(&genesis), StateScheme::Qmdb);

    // The same file without the scheme is an MPT chain with a different hash.
    let mut as_mpt = genesis.clone();
    as_mpt.config.extra_fields = Default::default();
    let mpt_hash = ChainSpec::from(as_mpt).genesis_hash();

    // `From<Genesis>` already builds the QMDB header; the explicit rewrite is
    // a no-op on it.
    let spec: ChainSpec = genesis.into();
    assert_eq!(spec.genesis_header.state_root, qmdb_genesis_root(&spec.genesis).unwrap());
    assert_eq!(with_declared_state_scheme(spec.clone()).unwrap().genesis_hash(), spec.genesis_hash());
    assert_ne!(spec.genesis_hash(), mpt_hash, "the MPT genesis is a different chain");
    assert_eq!(
        spec.genesis_hash(),
        GOV5_MAINNET_QMDB_GENESIS_HASH,
        "genesis header {:#?}",
        spec.genesis_header.header(),
    );
}
