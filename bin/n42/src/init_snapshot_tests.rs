// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests of the snapshot initialiser: the header and dump parsers, the
//! refusals of `init`, and `write_state_v2` against a real (temporary) datadir.

use super::*;
use alloy_primitives::{hex, Bytes};
use reth_db_api::{cursor::DbDupCursorRO, transaction::DbTx};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
};

/// A unique scratch directory under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "n42-init-snapshot-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("scratch dir");
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn genesis_json(scheme: Option<&str>) -> String {
    let scheme_field = scheme.map(|s| format!(r#", "stateScheme": "{s}""#)).unwrap_or_default();
    format!(
        r#"{{
            "config": {{ "chainId": 1143, "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0,
                         "eip158Block": 0, "byzantiumBlock": 0, "constantinopleBlock": 0,
                         "petersburgBlock": 0, "istanbulBlock": 0, "berlinBlock": 0, "londonBlock": 0,
                         "terminalTotalDifficulty": 0, "shanghaiTime": 0, "cancunTime": 0{scheme_field} }},
            "alloc": {{ "0x0000000000000000000000000000000000000001": {{ "balance": "0x64" }} }},
            "difficulty": "0x0", "gasLimit": "0x1c9c380", "timestamp": "0x0",
            "extraData": "0x", "nonce": "0x0",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "coinbase": "0x0000000000000000000000000000000000000000",
            "number": "0x0", "gasUsed": "0x0",
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
        }}"#
    )
}

fn header_rlp(header: &Header) -> Vec<u8> {
    let mut out = Vec::new();
    alloy_rlp::Encodable::encode(header, &mut out);
    out
}

fn sample_header() -> Header {
    Header { number: 7, gas_limit: 30_000_000, timestamp: 1_234, ..Default::default() }
}

fn init_args(scratch: &Scratch, scheme: Option<&str>) -> InitArgs {
    let genesis = scratch.path("genesis.json");
    fs::write(&genesis, genesis_json(scheme)).unwrap();
    InitArgs::parse_from([
        "init".to_owned(),
        "--chain".to_owned(),
        genesis.display().to_string(),
        "--datadir".to_owned(),
        scratch.path("datadir").display().to_string(),
        "--state".to_owned(),
        scratch.path("state.jsonl").display().to_string(),
        "--header".to_owned(),
        scratch.path("header.rlp").display().to_string(),
        "--qmdb".to_owned(),
        scratch.path("snapshot.bin").display().to_string(),
    ])
}

fn run_init(scratch: &Scratch) -> eyre::Result<()> {
    init(init_args(scratch, Some("qmdb")), reth_tasks::Runtime::test())
}

/// The snapshot's header: `number` and `root` are what the checks read.
fn write_header(scratch: &Scratch, number: u64, root: B256) {
    let header = Header { number, state_root: root, ..Default::default() };
    fs::write(scratch.path("header.rlp"), header_rlp(&header)).unwrap();
}

fn root_line(root: B256) -> String {
    format!("{{\"root\":\"{root}\"}}\n")
}

#[test]
fn a_header_file_may_hold_raw_rlp() {
    let scratch = Scratch::new();
    let header = sample_header();
    let path = scratch.path("raw.rlp");
    fs::write(&path, header_rlp(&header)).unwrap();
    assert_eq!(read_header_from_file(&path).unwrap(), header);
}

#[test]
fn a_header_file_may_hold_hex_with_or_without_the_prefix_and_a_newline() {
    let scratch = Scratch::new();
    let header = sample_header();
    let hex_text = hex::encode(header_rlp(&header));
    for (name, text) in [
        ("prefixed", format!("0x{hex_text}\n")),
        ("bare", hex_text.clone()),
        ("padded", format!("  {hex_text}  \n")),
    ] {
        let path = scratch.path(name);
        fs::write(&path, text).unwrap();
        assert_eq!(read_header_from_file(&path).unwrap(), header, "{name}");
    }
}

#[test]
fn a_header_file_with_trailing_bytes_or_bad_content_is_refused() {
    let scratch = Scratch::new();
    let mut rlp = header_rlp(&sample_header());
    rlp.extend_from_slice(&[0, 0, 0]);
    let trailing = scratch.path("trailing.rlp");
    fs::write(&trailing, &rlp).unwrap();
    let err = read_header_from_file(&trailing).unwrap_err();
    assert!(err.to_string().contains("3 trailing bytes"), "{err}");

    let garbage = scratch.path("garbage.rlp");
    fs::write(&garbage, [0xff, 0x01, 0x02]).unwrap();
    let err = read_header_from_file(&garbage).unwrap_err();
    assert!(format!("{err:#}").contains("header RLP"), "{err:#}");

    let bad_hex = scratch.path("bad.hex");
    fs::write(&bad_hex, "0xzz").unwrap();
    let err = read_header_from_file(&bad_hex).unwrap_err();
    assert!(format!("{err:#}").contains("header hex"), "{err:#}");

    let empty = scratch.path("empty");
    fs::write(&empty, "").unwrap();
    assert!(read_header_from_file(&empty).is_err(), "an empty file is not a header");

    let err = read_header_from_file(&scratch.path("missing")).unwrap_err();
    assert!(format!("{err:#}").contains("header file"), "{err:#}");
}

#[test]
fn the_dump_lines_parse_as_reth_init_state_writes_them() {
    let root: RootLine = serde_json::from_str(&format!(r#"{{"root":"{}"}}"#, B256::repeat_byte(0xAB))).unwrap();
    assert_eq!(root.root, B256::repeat_byte(0xAB));

    let line = format!(
        r#"{{"address":"{}","balance":"0x10","nonce":3,"code":"0x6001","storage":{{"{}":"{}"}}}}"#,
        Address::repeat_byte(5),
        B256::with_last_byte(1),
        B256::with_last_byte(9)
    );
    let parsed: DumpLine = serde_json::from_str(&line).unwrap();
    assert_eq!(parsed.address, Address::repeat_byte(5));
    assert_eq!(parsed.account.balance, U256::from(16));
    assert_eq!(parsed.account.nonce, Some(3));
    assert_eq!(parsed.account.code, Some(Bytes::from_static(&[0x60, 0x01])));
    assert_eq!(parsed.account.storage.unwrap().len(), 1);

    assert!(serde_json::from_str::<DumpLine>(r#"{"balance":"0x1"}"#).is_err(), "an address is required");
    assert!(serde_json::from_str::<RootLine>(r#"{"state":"0x1"}"#).is_err());
}

#[test]
fn only_qmdb_chains_pass_the_scheme_check() {
    let scratch = Scratch::new();
    let qmdb = init_args(&scratch, Some("qmdb"));
    require_qmdb(&qmdb.env.chain).expect("a qmdb chain");
    let mpt = init_args(&scratch, None);
    let err = require_qmdb(&mpt.env.chain).unwrap_err();
    assert!(err.to_string().contains("does not use the QMDB state scheme"), "{err}");
}

#[test]
fn init_refuses_a_chain_that_is_not_on_qmdb_before_touching_the_datadir() {
    let scratch = Scratch::new();
    let err = init(init_args(&scratch, None), reth_tasks::Runtime::test()).unwrap_err();
    assert!(err.to_string().contains("does not use the QMDB state scheme"), "{err}");
    assert!(!scratch.path("datadir").exists(), "nothing was created");
}

#[test]
fn init_reports_a_missing_header_file() {
    let scratch = Scratch::new();
    let err = run_init(&scratch).unwrap_err();
    assert!(format!("{err:#}").contains("header file"), "{err:#}");
}

#[test]
fn init_refuses_a_state_dump_with_another_root() {
    let scratch = Scratch::new();
    write_header(&scratch, 0, B256::repeat_byte(1));
    fs::write(scratch.path("state.jsonl"), root_line(B256::repeat_byte(2))).unwrap();
    let err = run_init(&scratch).unwrap_err();
    assert!(err.to_string().contains("is not the header's state root"), "{err}");
}

#[test]
fn init_refuses_an_empty_malformed_or_missing_state_file() {
    let scratch = Scratch::new();
    write_header(&scratch, 0, B256::repeat_byte(1));
    fs::write(scratch.path("state.jsonl"), "").unwrap();
    let err = run_init(&scratch).unwrap_err();
    assert!(err.to_string().contains("state file is empty"), "{err}");

    fs::write(scratch.path("state.jsonl"), "not json\n").unwrap();
    let err = run_init(&scratch).unwrap_err();
    assert!(format!("{err:#}").contains("first line must be"), "{err:#}");

    fs::remove_file(scratch.path("state.jsonl")).unwrap();
    let err = run_init(&scratch).unwrap_err();
    assert!(format!("{err:#}").contains("state file"), "{err:#}");
}

fn account_line(address: Address, balance: u64, code: Option<&[u8]>, slots: &[(u8, u8)]) -> String {
    let mut storage = BTreeMap::new();
    for (key, value) in slots {
        storage.insert(B256::with_last_byte(*key), B256::with_last_byte(*value));
    }
    let mut account = serde_json::json!({
        "address": address,
        "balance": format!("0x{balance:x}"),
        "nonce": 1,
    });
    if let Some(code) = code {
        account["code"] = serde_json::json!(Bytes::copy_from_slice(code));
    }
    if !storage.is_empty() {
        account["storage"] = serde_json::to_value(&storage).unwrap();
    }
    account.to_string()
}

/// A provider factory over a fresh temporary datadir, genesis-initialised.
macro_rules! open_factory {
    ($scratch:expr) => {
        init_args(&$scratch, Some("qmdb"))
            .env
            .init::<N42Node>(AccessRights::RW, reth_tasks::Runtime::test())
            .expect("environment")
            .provider_factory
    };
}

#[test]
fn write_state_v2_stores_hashed_accounts_code_and_storage() {
    let scratch = Scratch::new();
    let factory = open_factory!(scratch);
    let (alice, bob) = (Address::repeat_byte(0xA1), Address::repeat_byte(0xB2));
    let code = [0x60u8, 0x00, 0x60, 0x00];
    let lines = vec![
        Ok(account_line(alice, 1_000, None, &[])),
        Ok(String::new()),
        Ok(account_line(bob, 5, Some(&code), &[(1, 11), (2, 22)])),
    ];
    let (accounts, slots) = write_state_v2(&factory, 1, lines.into_iter()).expect("written");
    assert_eq!((accounts, slots), (2, 2));

    let provider = factory.provider().unwrap();
    let tx = provider.tx_ref();
    let stored = tx.get::<tables::HashedAccounts>(keccak256(alice)).unwrap().expect("alice");
    assert_eq!((stored.nonce, stored.balance, stored.bytecode_hash), (1, U256::from(1_000), None));
    let stored = tx.get::<tables::HashedAccounts>(keccak256(bob)).unwrap().expect("bob");
    let code_hash = keccak256(code);
    assert_eq!(stored.bytecode_hash, Some(code_hash));
    assert_eq!(tx.get::<tables::Bytecodes>(code_hash).unwrap().expect("code").original_byte_slice(), code);
    let mut cursor = tx.cursor_dup_read::<tables::HashedStorages>().unwrap();
    let entries: Vec<_> = cursor.walk_dup(Some(keccak256(bob)), None).unwrap().map(|r| r.unwrap().1).collect();
    assert_eq!(entries.len(), 2);
    for (key, value) in [(1u8, 11u64), (2, 22)] {
        let hashed = keccak256(B256::with_last_byte(key));
        assert!(entries.iter().any(|e| e.key == hashed && e.value == U256::from(value)), "slot {key}");
    }
}

#[test]
fn write_state_v2_names_a_bad_line_and_rejects_invalid_bytecode() {
    // A failed run leaves the changeset writer advanced, so each refusal gets
    // its own datadir.
    let failure = |lines: Vec<std::io::Result<String>>| {
        let scratch = Scratch::new();
        let factory = open_factory!(scratch);
        write_state_v2(&factory, 1, lines.into_iter()).unwrap_err()
    };
    let err = failure(vec![Ok("{".to_owned())]);
    assert!(format!("{err:#}").contains("account line"), "{err:#}");

    // 0xEF-prefixed code is not valid contract bytecode.
    let line = account_line(Address::repeat_byte(3), 1, Some(&[0xEF, 0x01, 0x02]), &[]);
    let err = failure(vec![Ok(line)]);
    assert!(err.to_string().contains("invalid bytecode for"), "{err}");

    let err = failure(vec![Err(std::io::Error::other("disk gone"))]);
    assert!(err.to_string().contains("disk gone"), "{err}");
}

#[test]
fn write_state_v2_commits_in_chunks_without_losing_accounts() {
    let scratch = Scratch::new();
    let factory = open_factory!(scratch);
    // Two accounts of 60,000 slots overflow COMMIT_UNITS together, so the
    // second one starts a new chunk after the first is committed.
    let big = |address: Address| {
        let mut storage = serde_json::Map::new();
        for i in 0..60_000u32 {
            storage.insert(format!("{:#066x}", i + 1), serde_json::json!(format!("{:#066x}", 1)));
        }
        serde_json::json!({"address": address, "balance": "0x1", "storage": storage}).to_string()
    };
    let (first, second) = (Address::repeat_byte(0xC1), Address::repeat_byte(0xC2));
    let (accounts, slots) =
        write_state_v2(&factory, 1, vec![Ok(big(first)), Ok(big(second))].into_iter()).expect("written");
    assert_eq!((accounts, slots), (2, 120_000));
    let provider = factory.provider().unwrap();
    for address in [first, second] {
        assert!(provider.tx_ref().get::<tables::HashedAccounts>(keccak256(address)).unwrap().is_some());
    }
    assert_eq!(provider.tx_ref().entries::<tables::HashedStorages>().unwrap(), 120_000);
}
