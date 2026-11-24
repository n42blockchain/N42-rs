// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's profile-1 conformance vectors V3 (QMDB write sets) and V4
//! (transaction validity), run against this node's execution
//! (`testdata/profile1/gov5`, byte-exact copies; see its README).
//!
//! Both run on the standard genesis plus one funded sender. Its
//! execution-relevant fields equal V1's `genesis_8s.json` (only the slot
//! values differ), so that file is the chain here, with the vector's
//! `allocAdditions` added and loaded through the profile-1 checks.
//!
//! V3: each block is executed by the stock import (`N42EvmConfig`'s
//! executor), its bundle turned into QMDB operations by
//! `n42_qmdb_reth::sorted_operations_from_execution` under
//! `system_caller_leaf_at`, exactly as the node's root phase does, and the
//! operations and the root are compared with gov5's. The block rewards are the
//! withdrawals the validator puts in its payload attributes
//! (`HotStuffGenesisConfig::block_rewards` -> `rewards_to_withdrawals`).
//!
//! V4: each transaction is judged by this node's stages: the EIP-2718 decode
//! (consensus envelope and pooled envelope), sender recovery, the native
//! chain's type gates, the per-transaction block-gas bound every path applies
//! (pool `ExceedsGasLimit`, builder `GasBudget`, follower includability), and
//! the stock import of block 1 carrying the transaction alone.

use crate::n42_evm::N42EvmConfig;
use alloy_eips::{eip2718::Decodable2718 as _, Typed2718 as _};
use alloy_primitives::{Address, B256, U256};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, CacheDB, EmptyDB},
};
use n42_tx_types::N42TxEnvelope;
use reth_evm::{execute::Executor as _, ConfigureEvm as _};
use reth_primitives_traits::{RecoveredBlock, SignedTransaction as _};
use reth_trie::bundle_state::BundleState;
use serde_json::Value;
use std::{path::PathBuf, sync::Arc};

pub(crate) type Config = N42EvmConfig<n42_header::N42ChainSpec>;

pub(crate) fn gov5_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/profile1/gov5")
}

fn vector(name: &str) -> Value {
    let path = gov5_dir().join(name);
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&raw).expect("vector json")
}

pub(crate) fn hex(value: &Value) -> Vec<u8> {
    alloy_primitives::hex::decode(value.as_str().expect("a hex string")).expect("hex")
}

pub(crate) fn b256(value: &Value) -> B256 {
    B256::from_slice(&hex(value))
}

fn address(value: &Value) -> Address {
    value.as_str().expect("an address").parse().expect("address")
}

fn u64_of(value: &Value) -> u64 {
    value.as_u64().expect("a number")
}

/// V1's test genesis (the standard genesis's execution fields) plus
/// `additions`, through the checks the node's chain-spec parser applies.
pub(crate) fn chain(additions: &Value) -> Arc<reth_chainspec::ChainSpec> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../qmdb-reth/testdata/profile1/gov5/V1/genesis_8s.json");
    let mut genesis: Value = serde_json::from_slice(&std::fs::read(path).expect("genesis_8s.json")).expect("json");
    for (who, account) in additions.as_object().expect("allocAdditions") {
        genesis["alloc"][who] = account.clone();
    }
    let genesis: alloy_genesis::Genesis = serde_json::from_value(genesis).expect("a genesis");
    n42_qmdb_reth::chainspec::check_genesis(&genesis).expect("a valid profile-1 genesis");
    assert!(n42_qmdb_reth::profile1::profile1(&genesis).expect("valid").is_some(), "a profile-1 genesis");
    Arc::new(reth_chainspec::ChainSpec::from(genesis))
}

pub(crate) fn config(spec: &Arc<reth_chainspec::ChainSpec>) -> Config {
    N42EvmConfig::new(Arc::new(n42_header::N42ChainSpec::from((**spec).clone())))
}

/// The genesis state as the executor reads it.
pub(crate) fn genesis_state(spec: &reth_chainspec::ChainSpec) -> CacheDB<EmptyDB> {
    let mut db = CacheDB::new(EmptyDB::default());
    for (who, account) in &spec.genesis.alloc {
        let mut info = AccountInfo { balance: account.balance, nonce: account.nonce.unwrap_or_default(), ..Default::default() };
        if let Some(code) = &account.code {
            info = info.with_code(Bytecode::new_raw(code.clone()));
        }
        db.insert_account_info(who, info);
        for (slot, value) in account.storage.iter().flatten() {
            db.insert_account_storage(who, &U256::from_be_bytes(slot.0), &U256::from_be_bytes(value.0));
        }
    }
    db
}

/// A block's post-state written back into `db` for the next block.
pub(crate) fn apply(db: &mut CacheDB<EmptyDB>, bundle: &BundleState) {
    for (who, account) in &bundle.state {
        match &account.info {
            Some(info) => {
                let mut info = info.clone();
                if info.code.is_none() {
                    info.code = bundle.contracts.get(&info.code_hash).cloned();
                }
                db.insert_account_info(who, info);
            }
            None => {
                db.cache.accounts.insert(*who, None);
                db.cache.storage.entry(*who).or_default().wipe();
            }
        }
        for (slot, value) in &account.storage {
            db.insert_account_storage(who, slot, &value.present_value);
        }
    }
}

/// The withdrawals a profile-1 block pays (A8): what the validator hands its
/// execution layer as payload attributes (`h2_validator`'s rewards).
pub(crate) fn rewards(spec: &reth_chainspec::ChainSpec, coinbase: Address) -> Vec<alloy_eips::eip4895::Withdrawal> {
    let hotstuff = n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(&spec.genesis).expect("a hotstuff genesis");
    n42_h2_consensus::rewards_to_withdrawals(&hotstuff.block_rewards(coinbase)).expect("whole gwei")
}

/// The vector's header fields as an executable N42 header.
fn header(fields: &Value) -> n42_header::N42Header {
    n42_header::N42Header::from(alloy_consensus::Header {
        number: u64_of(&fields["number"]),
        timestamp: u64_of(&fields["timestamp"]),
        parent_hash: b256(&fields["parentHash"]),
        beneficiary: address(&fields["coinbase"]),
        gas_limit: u64_of(&fields["gasLimit"]),
        base_fee_per_gas: Some(u64_of(&fields["baseFeePerGas"])),
        parent_beacon_block_root: Some(b256(&fields["parentBeaconBlockRoot"])),
        mix_hash: b256(&fields["prevRandao"]),
        withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
        ..Default::default()
    })
}

pub(crate) fn decode(raw: &[u8]) -> Result<N42TxEnvelope, String> {
    let mut buf = raw;
    let tx = N42TxEnvelope::decode_2718(&mut buf).map_err(|e| e.to_string())?;
    if !buf.is_empty() {
        return Err("trailing bytes".to_owned());
    }
    Ok(tx)
}

fn block_of(
    spec: &reth_chainspec::ChainSpec,
    fields: &Value,
    txs: Vec<N42TxEnvelope>,
) -> Result<RecoveredBlock<n42_tx_types::Block>, String> {
    let header = header(fields);
    let senders = txs.iter().map(|tx| tx.try_recover().map_err(|e| format!("recover: {e}"))).collect::<Result<Vec<_>, _>>()?;
    let body = n42_tx_types::BlockBody {
        transactions: txs,
        ommers: Vec::new(),
        withdrawals: Some(rewards(spec, header.beneficiary).into()),
    };
    Ok(RecoveredBlock::new_unhashed(n42_tx_types::Block::new(header, body), senders))
}

// --------------------------------------------------------------------- V3 --

/// One expected operation: key, and the value (`None` = delete).
type Op = (B256, Option<Vec<u8>>);

fn expected_ops(block: &Value) -> Vec<Op> {
    let mut ops: Vec<Op> = Vec::new();
    for op in block["accountOps"].as_array().expect("accountOps") {
        let value = (op["op"] == "write").then(|| hex(&op["qmdbValue"]));
        ops.push((b256(&op["qmdbKeyHash"]), value));
    }
    for op in block["storageOps"].as_array().expect("storageOps") {
        let value = (op["op"] == "write").then(|| hex(&op["value"]));
        ops.push((b256(&op["qmdbKeyHash"]), value));
    }
    ops.sort();
    ops
}

/// What one V3 block came to on this node.
#[derive(Debug)]
struct V3Block {
    case: String,
    ours: Vec<Op>,
    theirs: Vec<Op>,
    our_root: B256,
    their_root: B256,
    must_not_appear: Vec<(Address, bool)>,
}

/// Runs a V3 file's blocks in order, each on the post-state of the one before
/// (ours, so a difference carries forward and is reported where it starts).
fn run_v3(file: &str) -> (B256, B256, Vec<V3Block>) {
    let vector = vector(file);
    let spec = chain(&vector["allocAdditions"]);
    let c = config(&spec);
    let blocks = vector["blocks"].as_array().expect("blocks");

    // gov5's genesis hash, as block 1 names it. The forest files the genesis
    // under it; execution reads the parent hash from each vector header, so
    // nothing below depends on this node's own genesis hash
    // (`v3_genesis_hash_equals_gov5` checks that separately).
    let genesis_hash = b256(&blocks[0]["header"]["parentHash"]);
    let alloc = n42_qmdb_reth::changes_from_alloc(&spec.genesis.alloc);
    let mut forest = n42_qmdb_state::QmdbForest::genesis(genesis_hash, &alloc).expect("the genesis forest");
    let genesis_root = forest.root();
    assert_eq!(spec.genesis_header().state_root, genesis_root, "the genesis header carries the forest root");

    let mut db = genesis_state(&spec);
    let mut parent = genesis_hash;
    let mut out = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let case = block["case"].as_str().expect("case").to_owned();
        let txs = block["transactions"]
            .as_array()
            .expect("transactions")
            .iter()
            .map(|raw| decode(&hex(raw)).expect("a V3 transaction decodes"))
            .collect();
        let recovered = block_of(&spec, &block["header"], txs).expect("a V3 block");
        let output = c.executor(db.clone()).execute(&recovered).unwrap_or_else(|e| panic!("{case}: execution: {e}"));
        let leaf = n42_qmdb_reth::system_caller_leaf_at(&*spec, recovered.header().timestamp);
        let ops = n42_qmdb_reth::sorted_operations_from_execution(&output.state, leaf);
        let mut ours: Vec<Op> = ops.to_operations().into_iter().map(|op| (B256::from(op.key), op.value)).collect();
        ours.sort();
        let prepared = forest.compute_operations(parent, ops).expect("the block applies");
        let our_root = prepared.root;
        // The next block names gov5's hash of this one as its parent.
        let hash = blocks.get(i + 1).map(|next| b256(&next["header"]["parentHash"])).unwrap_or(B256::with_last_byte(0xee));
        forest.insert(hash, recovered.header().number, prepared).expect("filed");
        parent = hash;
        apply(&mut db, &output.state);
        let must_not_appear = block["mustNotAppear"]
            .as_array()
            .expect("mustNotAppear")
            .iter()
            .map(|who| {
                let who = address(who);
                let key = B256::from(n42_twig_core::qmdb_compat::gov5_account_key(&who.0 .0));
                (who, ours.iter().any(|(k, _)| *k == key))
            })
            .collect();
        out.push(V3Block {
            case,
            theirs: expected_ops(block),
            ours,
            our_root,
            their_root: b256(&block["qmdbStateRoot"]),
            must_not_appear,
        });
    }
    (genesis_root, b256(&vector["genesisQmdbStateRoot"]), out)
}

/// The keys of the system contracts every block writes slots of (EIP-4788,
/// EIP-2935).
fn system_contract_account_keys() -> [(Address, B256); 2] {
    [
        alloy_eips::eip4788::BEACON_ROOTS_ADDRESS,
        alloy_eips::eip2935::HISTORY_STORAGE_ADDRESS,
    ]
    .map(|who| (who, B256::from(n42_twig_core::qmdb_compat::gov5_account_key(&who.0 .0))))
}

fn assert_v3(file: &str, cases: usize) {
    let (our_genesis, their_genesis, blocks) = run_v3(file);
    assert_eq!(blocks.len(), cases, "{file}: every block ran");
    assert!(blocks.iter().all(|block| !block.theirs.is_empty()), "{file}: no empty expectation");
    assert_eq!(our_genesis, their_genesis, "{file}: genesis QMDB root");
    let mut differences = Vec::new();
    for block in &blocks {
        for (who, present) in &block.must_not_appear {
            assert!(!present, "{file} {}: {who} must not appear", block.case);
        }
        if block.ours != block.theirs || block.our_root != block.their_root {
            let only_ours: Vec<_> = block.ours.iter().filter(|op| !block.theirs.contains(op)).collect();
            let only_theirs: Vec<_> = block.theirs.iter().filter(|op| !block.ours.contains(op)).collect();
            differences.push(format!(
                "{}: root ours {} gov5 {}; only ours {only_ours:?}; only gov5 {only_theirs:?}",
                block.case, block.our_root, block.their_root
            ));
        }
    }
    assert!(differences.is_empty(), "{file}:\n{}", differences.join("\n"));
}

/// The genesis header hash with the vector's alloc additions equals the one
/// gov5's block 1 names. Ignored on main: the gov5-shaped profile-1 genesis
/// header (ommers hash zero, requests hash the empty trie root, slot number 0,
/// `mobileRegistryRoot` as element 24) is built by `fix(chainspec): build
/// gov5's profile-1 genesis header` (merged with the profile-1 header rules).
#[test]
fn v3_genesis_hash_equals_gov5() {
    for file in ["V3/main.json", "V3/system_address_live.json"] {
        let vector = vector(file);
        let spec = chain(&vector["allocAdditions"]);
        assert_eq!(spec.genesis_hash(), b256(&vector["blocks"][0]["header"]["parentHash"]), "{file}");
    }
}

/// V3 `main.json`: seven blocks, every write set and root equal to gov5's.
#[test]
fn v3_main_write_sets_and_roots_equal_gov5() {
    assert_v3("V3/main.json", 7);
}

/// V3 `system_address_live.json`: `0xff..fe` exists (1 wei) and is never
/// written (D3): on profile 1 the system caller's leaf is off
/// (`system_caller_leaf_at` is false under Glamsterdam execution).
#[test]
fn v3_system_address_live_write_sets_and_roots_equal_gov5() {
    assert_v3("V3/system_address_live.json", 2);
}

/// Open point 1 of V3 (PIN 1): an account whose only change in a block is
/// storage -- the EIP-4788 and EIP-2935 contracts, written by the block-start
/// system calls -- gets an ACCOUNT op on this node too, with its unchanged
/// value. The bundle keeps an account with changed slots
/// (`BundleAccount::info` = its present info) and
/// `sorted_operations_from_execution` encodes every bundle account
/// (`changes.rs` `encode_account_pieces`), so the account leaf is rewritten
/// and the root moves with it, as gov5's `unchangedThisBlock` does today.
#[test]
fn v3_a_storage_only_account_gets_an_account_op() {
    let (_, _, blocks) = run_v3("V3/main.json");
    let empty = blocks.iter().find(|block| block.case == "empty-block").expect("the empty block");
    for (who, key) in system_contract_account_keys() {
        let ours = empty.ours.iter().find(|(k, _)| *k == key);
        let theirs = empty.theirs.iter().find(|(k, _)| *k == key);
        assert!(ours.is_some(), "{who}: an account op on this node");
        assert_eq!(ours, theirs, "{who}: the same account op as gov5's");
    }
    // Every block: both contracts' account leaves are written.
    for block in &blocks {
        for (who, key) in system_contract_account_keys() {
            assert!(block.ours.iter().any(|(k, _)| *k == key), "{}: {who}", block.case);
        }
    }
}

// --------------------------------------------------------------------- V4 --

/// This node's verdict on one V4 transaction: the first stage that refused.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refused {
    /// The consensus envelope (block bodies, payloads) does not decode it.
    Decode(String),
    /// A native profile-1 chain's type gate: 0x03 (D4), 0x50 without
    /// `altSigTx` (the pool, the ingest and `N42Consensus` refuse it).
    TypeRule(&'static str),
    /// Its gas limit exceeds the block's gas limit: refused by the pool
    /// (reth `ExceedsGasLimit`), never selected by the builder (`GasBudget`)
    /// and refused by the follower's includability check and the import.
    BlockGas(u64),
    /// The stock import of block 1 carrying it alone refuses.
    Execution(String),
}

fn judge(spec: &Arc<reth_chainspec::ChainSpec>, c: &Config, block: &Value, raw: &[u8]) -> Result<(), Refused> {
    let tx = decode(raw).map_err(Refused::Decode)?;
    if tx.is_eip4844() {
        return Err(Refused::TypeRule("blob transaction on a native chain (D4)"));
    }
    if tx.is_alt_sig() && !reth_chainspec::qmdb::alt_sig_tx_enabled(&spec.genesis) {
        return Err(Refused::TypeRule("0x50 without altSigTx"));
    }
    let gas_limit = alloy_consensus::Transaction::gas_limit(&tx);
    if gas_limit > u64_of(&block["gasLimit"]) {
        return Err(Refused::BlockGas(gas_limit));
    }
    let recovered = block_of(spec, block, vec![tx]).map_err(Refused::Execution)?;
    c.executor(genesis_state(spec)).execute(&recovered).map(|_| ()).map_err(|e| Refused::Execution(e.to_string()))
}

/// The stock import alone (no type gate, no includability check) on block 1
/// carrying the decoded transaction: what block execution says by itself.
fn import_alone(spec: &Arc<reth_chainspec::ChainSpec>, c: &Config, block: &Value, raw: &[u8]) -> Result<(), String> {
    let tx = decode(raw)?;
    let recovered = block_of(spec, block, vec![tx])?;
    c.executor(genesis_state(spec)).execute(&recovered).map(|_| ()).map_err(|e| e.to_string())
}

/// Every V4 case judged; `(case, gov5 verdict, gov5 stage, ours)`.
fn run_v4() -> Vec<(String, String, String, Result<(), Refused>)> {
    let vector = vector("V4/transactions.json");
    let spec = chain(&vector["allocAdditions"]);
    let c = config(&spec);
    vector["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| {
            let ours = judge(&spec, &c, &vector["block"], &hex(&case["raw"]));
            (
                case["case"].as_str().expect("case").to_owned(),
                case["verdict"].as_str().expect("verdict").to_owned(),
                case["refusedAt"].as_str().unwrap_or("-").to_owned(),
                ours,
            )
        })
        .collect()
}

/// V4: every case gets gov5's verdict (valid / invalid) on this node. The
/// stage may differ and is printed; the verdict is the vector.
#[test]
fn v4_transaction_verdicts_equal_gov5() {
    let mut differences = Vec::new();
    for (case, verdict, stage, ours) in run_v4() {
        println!("{case:24} gov5 {verdict:7} at {stage:10} | ours {ours:?}");
        let valid = ours.is_ok();
        if valid != (verdict == "valid") {
            differences.push(format!("{case}: gov5 {verdict} at {stage}, ours {ours:?}"));
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

/// The import alone already gives gov5's verdict for every case but 0x50,
/// whose refusal on a chain without `altSigTx` is `N42Consensus`'s
/// pre-execution rule (`consensus.rs` `alt_sig_allowed`), the pool's and the
/// ingest's (gov5's 0x50 case is a type-2 payload under the 0x50 byte: it
/// decodes as an alternative-signature envelope here and fails its signature
/// recovery, so the import refuses it as well, for another reason). The type
/// gates above are not what carries the other verdicts.
#[test]
fn v4_the_import_alone_gives_the_verdicts_but_the_alt_sig_gate() {
    let vector = vector("V4/transactions.json");
    let spec = chain(&vector["allocAdditions"]);
    let c = config(&spec);
    for case in vector["cases"].as_array().expect("cases") {
        let name = case["case"].as_str().expect("case");
        let alone = import_alone(&spec, &c, &vector["block"], &hex(&case["raw"]));
        println!("{name:24} import alone {alone:?}");
        if name == "type-0x50" {
            continue;
        }
        assert_eq!(alone.is_ok(), case["verdict"] == "valid", "{name}: {alone:?}");
    }
}

/// C5 (PIN 2): a transaction whose gas is at the 2^32-1 cap, or over it, is
/// above the 480M block gas limit and refused for that; one at exactly the
/// block gas limit is valid and executes.
#[test]
fn v4_c5_gas_above_the_block_limit_is_refused() {
    let verdicts = run_v4();
    let of = |name: &str| verdicts.iter().find(|(case, ..)| case == name).map(|(.., ours)| ours.clone()).expect(name);
    assert_eq!(of("gas-at-block-limit"), Ok(()));
    assert_eq!(of("gas-at-cap"), Err(Refused::BlockGas(u32::MAX as u64)));
    assert_eq!(of("gas-over-cap"), Err(Refused::BlockGas(1 << 32)));
    // And the import alone refuses it too: the executor's per-transaction
    // check against the block's available gas, before any state is touched.
    let vector = vector("V4/transactions.json");
    let spec = chain(&vector["allocAdditions"]);
    let c = config(&spec);
    for name in ["gas-at-cap", "gas-over-cap"] {
        let case = vector["cases"].as_array().expect("cases").iter().find(|case| case["case"] == name).expect(name);
        let tx = decode(&hex(&case["raw"])).expect("decodes");
        let block = block_of(&spec, &vector["block"], vec![tx]).expect("a block");
        let refused = c.executor(genesis_state(&spec)).execute(&block).expect_err("the import refuses");
        assert!(refused.to_string().contains("gas"), "{name}: {refused}");
    }
}

/// The bytes a V4 case decodes to on the pooled envelope (the pool and the
/// RPC's `eth_sendRawTransaction`): the same decode verdict as the consensus
/// envelope, for every case.
#[test]
fn v4_pooled_decode_agrees_with_the_consensus_decode() {
    let vector = vector("V4/transactions.json");
    for case in vector["cases"].as_array().expect("cases") {
        let raw = hex(&case["raw"]);
        let consensus = decode(&raw).is_ok();
        let pooled = n42_tx_types::N42PooledTxEnvelope::decode_2718(&mut raw.as_slice()).is_ok();
        // A type-3 transaction without a sidecar is a consensus form only.
        if case["typeByte"] == "0x03" {
            assert!(consensus && !pooled, "{}", case["case"]);
        } else {
            assert_eq!(consensus, pooled, "{}", case["case"]);
        }
    }
}
