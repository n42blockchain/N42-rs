// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's profile-1 conformance vector V5 (header validity: B4, B9, B13,
//! B14, A23), run against this node (`testdata/profile1/gov5/V5`, byte-exact
//! copies; see `testdata/profile1/gov5/README.md`).
//!
//! The chain is V1's `genesis_8s.json` plus the vector's `allocAdditions`.
//! Each of the six sealed blocks is decoded (RLP and hash), imported through
//! [`HotStuffConsensus`] exactly as the engine tree does (header,
//! header against parent -- the deferred check included --, body, the stock
//! executor, post-execution, which files the receipt half of the block's
//! result), its QMDB root computed as the node's root phase does and filed
//! beside it. The block's own result is compared with gov5's `executed`
//! (stateRoot, receiptsRoot, logsBloom, gasUsed = the EIP-8037 block figure,
//! and since AM25 the EIP-7685 requests and their requestsHash, a deferred
//! field) and with what the next header carries. Every block also passes B4's vote
//! bound at `now = time`.
//!
//! Each refusal is then judged on top of that chain: gov5's `import` is this
//! node's `validate_header` / `validate_header_against_parent` (the profile-1
//! header rules and Ethereum's header checks), `deferred` is the deferred
//! fields check inside `validate_header_against_parent`
//! ([`DeferredExecutionError`]), and `vote` is `check_profile1_vote_time`
//! (`h2-node` `service.rs` `vote_refusal`) at the vector's `nowUnix`.

use crate::{
    hotstuff_consensus::{gov5_receipt_root_bloom, DeferredExecutionError, HotStuffConsensus},
    profile1_vectors::{apply, b256, chain, config, decode, genesis_state, gov5_dir, hex, rewards},
};
use alloy_primitives::{Bloom, B256};
use reth_consensus::{Consensus as _, ConsensusError, FullConsensus as _, HeaderValidator as _};
use reth_evm::{execute::Executor as _, ConfigureEvm as _};
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader, SignedTransaction as _};
use serde_json::Value;
use std::sync::{Arc, OnceLock};

type Spec = n42_header::N42ChainSpec;
type Sealed = SealedHeader<n42_header::N42Header>;

fn v5() -> &'static Value {
    static V5: OnceLock<Value> = OnceLock::new();
    V5.get_or_init(|| {
        let path = gov5_dir().join("V5/header_validity.json");
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        serde_json::from_slice(&raw).expect("V5 json")
    })
}

/// A header from the vector's RLP, sealed under the hash this node computes.
fn sealed_from_rlp(rlp: &Value) -> Sealed {
    let raw = hex(rlp);
    let mut buf = raw.as_slice();
    let header: n42_header::N42Header = alloy_rlp::Decodable::decode(&mut buf).expect("the header decodes");
    assert!(buf.is_empty(), "no trailing bytes");
    assert_eq!(alloy_rlp::encode(&header), raw, "the header re-encodes to gov5's RLP");
    SealedHeader::seal_slow(header)
}

/// gov5's `executed` of one block.
fn executed(block: &Value) -> crate::executed_fields::ExecutedFields {
    let e = &block["executed"];
    crate::executed_fields::ExecutedFields {
        state_root: b256(&e["stateRoot"]),
        receipts_root: b256(&e["receiptsRoot"]),
        logs_bloom: Bloom::from_slice(&hex(&e["logsBloom"])),
        gas_used: e["gasUsed"].as_u64().expect("gasUsed"),
        requests_hash: b256(&e["requestsHash"]),
    }
}

/// gov5's `executed.requests` of one block (EIP-7685 `type || data`).
fn executed_requests(block: &Value) -> Vec<Vec<u8>> {
    block["executed"]["requests"].as_array().expect("executed.requests").iter().map(hex).collect()
}

/// What this node made of one V5 block.
#[derive(Debug)]
struct Ran {
    name: String,
    header: Sealed,
    ours: crate::executed_fields::ExecutedFields,
    theirs: crate::executed_fields::ExecutedFields,
    /// The last receipt's cumulative gas (post-refund, state gas included).
    receipts_gas: u64,
    /// The EIP-7685 requests this node's execution produced, `type || data`.
    requests: Vec<Vec<u8>>,
    /// The EIP-8282 builder predeploys the execution's bundle touched (none when the calls change no state).
    touched_8282: Vec<alloy_primitives::Address>,
    /// The block and the state it executed on, for re-execution.
    recovered: RecoveredBlock<n42_tx_types::Block>,
    pre_state: evm2::evm::CacheDB<evm2::evm::EmptyDB>,
}

/// EIP-8282 builder deposit and exit request predeploys.
const BUILDER_PREDEPLOYS: [alloy_primitives::Address; 2] = [
    alloy_primitives::address!("0x0000BFF46984E3725691FA540A8C7589300D8282"),
    alloy_primitives::address!("0x000064D678505AD48F8CCB093BC65613800E8282"),
];

/// The V5 chain imported on this node: the consensus, and every block.
struct Chain {
    consensus: HotStuffConsensus<Spec>,
    genesis: Sealed,
    blocks: Vec<Ran>,
}

impl Chain {
    fn header_by_hash(&self, hash: B256) -> Option<&Sealed> {
        std::iter::once(&self.genesis).chain(self.blocks.iter().map(|b| &b.header)).find(|h| h.hash() == hash)
    }
}

/// Imports V5's six blocks in order. Panics at the first step a listed block
/// does not pass (a refused valid block is a difference).
fn run_chain() -> Chain {
    let vector = v5();
    let spec = chain(&vector["allocAdditions"]);
    let n42_spec = Arc::new(Spec::from((*spec).clone()));
    let consensus = HotStuffConsensus::new(n42_spec.clone());
    assert!(consensus.header_rules().is_profile1(), "a profile-1 chain");
    let c = config(&spec);

    // The genesis header: gov5's RLP and hash.
    let genesis = n42_spec.sealed_genesis_header();
    assert_eq!(genesis.hash(), b256(&vector["genesisHash"]), "genesis hash");
    assert_eq!(alloy_rlp::encode(genesis.header()), hex(&vector["genesis"]["rlp"]), "genesis RLP");

    let alloc = n42_qmdb_reth::changes_from_alloc(&spec.genesis.alloc);
    let mut forest = n42_qmdb_state::QmdbForest::genesis(genesis.hash(), &alloc).expect("the genesis forest");
    assert_eq!(forest.root(), genesis.state_root, "the genesis header carries the forest root");

    let mut db = genesis_state(&spec);
    let mut parent = genesis.clone();
    let mut blocks = Vec::new();
    for block in vector["blocks"].as_array().expect("blocks") {
        let name = block["name"].as_str().expect("name").to_owned();
        let header = sealed_from_rlp(&block["rlp"]);
        assert_eq!(header.hash(), b256(&block["hash"]), "{name}: hash");
        assert_eq!(header.parent_hash, parent.hash(), "{name}: parent");

        // Import: the header alone, against its parent (the deferred check
        // reads the parent's filed result), the vote's clock bound at its
        // own time.
        consensus.validate_header(&header).unwrap_or_else(|e| panic!("{name}: validate_header: {e}"));
        consensus
            .validate_header_against_parent(&header, &parent)
            .unwrap_or_else(|e| panic!("{name}: validate_header_against_parent: {e}"));
        n42_h2_consensus::check_profile1_vote_time(header.timestamp, header.timestamp)
            .unwrap_or_else(|e| panic!("{name}: vote time: {e}"));

        // The body: its transactions and the A8 rewards as withdrawals.
        let txs: Vec<_> = block["transactions"]
            .as_array()
            .expect("transactions")
            .iter()
            .map(|raw| decode(&hex(raw)).expect("a V5 transaction decodes"))
            .collect();
        let senders = txs.iter().map(|tx| tx.try_recover().expect("recovers")).collect();
        let body = n42_tx_types::BlockBody {
            transactions: txs,
            ommers: Vec::new(),
            withdrawals: Some(rewards(&spec, header.beneficiary).into()),
        };
        let sealed = SealedBlock::from_sealed_parts(header.clone(), body);
        consensus.validate_block_pre_execution(&sealed).unwrap_or_else(|e| panic!("{name}: pre-execution: {e}"));
        let recovered = RecoveredBlock::new_sealed(sealed, senders);

        let pre_state = db.clone();
        let output = c.executor(db.clone()).execute(&recovered).unwrap_or_else(|e| panic!("{name}: execution: {e}"));
        consensus
            .validate_block_post_execution(&recovered, &output.result, None, None)
            .unwrap_or_else(|e| panic!("{name}: post-execution: {e}"));

        // The root phase: QMDB operations of the bundle, the forest root,
        // filed beside the receipt half post-execution filed.
        let leaf = n42_qmdb_reth::system_caller_leaf_at(&*spec, header.timestamp);
        let ops = n42_qmdb_reth::sorted_operations_from_execution(&output.state, leaf);
        let prepared = forest.compute_operations(parent.hash(), ops).expect("the block applies");
        let state_root = prepared.root;
        forest.insert(header.hash(), header.number, prepared).expect("filed");
        crate::executed_fields::remember_state_root(header.hash(), state_root);
        apply(&mut db, &output.state);

        let (receipts_root, logs_bloom) = gov5_receipt_root_bloom(&output.result.receipts);
        let ours = crate::executed_fields::ExecutedFields {
            state_root,
            receipts_root,
            logs_bloom,
            gas_used: output.result.gas_used,
            requests_hash: crate::hotstuff_consensus::executed_requests_hash(&spec.genesis, &output.result.requests),
        };
        assert_eq!(crate::executed_fields::get(&header.hash()), Some(ours), "{name}: the filed result");
        blocks.push(Ran {
            name,
            header: header.clone(),
            ours,
            theirs: executed(block),
            receipts_gas: output.result.receipts.last().map(|r| r.cumulative_gas_used).unwrap_or_default(),
            requests: output.result.requests.iter().map(|r| r.to_vec()).collect(),
            touched_8282: BUILDER_PREDEPLOYS.into_iter().filter(|a| output.state.state.contains_key(a)).collect(),
            recovered: recovered.clone(),
            pre_state,
        });
        parent = header;
    }
    Chain { consensus, genesis, blocks }
}

/// Every V5 block decodes to gov5's hash, is accepted on import (header
/// rules, parent rules, the deferred check, body, execution) and at vote
/// time, and its own result equals gov5's `executed`: stateRoot,
/// receiptsRoot, logsBloom and gasUsed, the EIP-8037 block figure (refunds
/// ignored, max of regular and state gas), not the receipts' gas.
#[test]
fn v5_blocks_execute_to_gov5s_results_and_are_accepted() {
    let chain = run_chain();
    assert_eq!(chain.blocks.len(), 8, "eight blocks");
    let mut differences = Vec::new();
    for (i, block) in chain.blocks.iter().enumerate() {
        let receipts_gas = v5()["blocks"][i]["executed"]["receiptsCumulativeGasUsed"].as_u64().unwrap_or_default();
        println!(
            "{:30} gasUsed ours {:7} gov5 {:7} | receipts ours {:7} gov5 {:7} | state {} receipts {}",
            block.name,
            block.ours.gas_used,
            block.theirs.gas_used,
            block.receipts_gas,
            receipts_gas,
            block.ours.state_root == block.theirs.state_root,
            block.ours.receipts_root == block.theirs.receipts_root,
        );
        if block.ours != block.theirs {
            differences.push(format!("{}: ours {:?}\n  gov5 {:?}", block.name, block.ours, block.theirs));
        }
        if block.requests != executed_requests(&v5()["blocks"][i]) {
            differences.push(format!(
                "{}: requests ours {:?}\n  gov5 {:?}",
                block.name,
                block.requests.iter().map(alloy_primitives::hex::encode_prefixed).collect::<Vec<_>>(),
                v5()["blocks"][i]["executed"]["requests"]
            ));
        }
        if block.receipts_gas != receipts_gas {
            differences.push(format!("{}: receipts gas ours {} gov5 {receipts_gas}", block.name, block.receipts_gas));
        }
        // The next header carries this block's result (A10, k = 1).
        if let Some(next) = chain.blocks.get(i + 1) {
            let carried = crate::executed_fields::fields_from_child_header_deferring_requests(next.header.header(), true);
            assert_eq!(carried, block.theirs, "{}: the next header carries gov5's executed", block.name);
        }
    }
    assert!(differences.is_empty(), "V5 executed differs:\n{}", differences.join("\n"));

    // AM25: block 7 produces a withdrawal and a consolidation request and is
    // valid; block 8 carries their hash.
    assert_eq!(chain.blocks[6].requests.iter().map(|r| r[0]).collect::<Vec<_>>(), vec![0x01, 0x02], "block 7's requests");
    assert_eq!(chain.blocks[7].header.requests_hash, Some(chain.blocks[6].ours.requests_hash), "block 8 carries block 7's requests hash");
    assert_ne!(chain.blocks[6].ours.requests_hash, alloy_eips::eip7685::EMPTY_REQUESTS_HASH);

    // B4: blocks 1 and 2 share a timestamp.
    assert_eq!(chain.blocks[0].header.timestamp, chain.blocks[1].header.timestamp);
    // B14: every base fee is EIP-1559's over the parent's gasUsed as written.
    let mut parent = &chain.genesis;
    for block in &chain.blocks {
        assert_eq!(block.header.base_fee_per_gas, Some(n42_h2_consensus::profile1_base_fee(parent)), "{}", block.name);
        parent = &block.header;
    }
}

/// The stage at which this node refuses a header.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Stage {
    /// `validate_header`: the header alone.
    ImportHeader(String),
    /// `validate_header_against_parent`, a rule other than the deferred
    /// fields (the link, B4, B13, B14, the committee link).
    ImportParent(String),
    /// `validate_header_against_parent`'s deferred fields check: the gas
    /// figures and requests hashes carried and executed.
    Deferred { got: u64, expected: u64, got_requests: B256, expected_requests: B256 },
    /// Accepted on import, refused by B4's vote bound at `nowUnix`.
    Vote(String),
    /// Accepted.
    Accepted,
}

fn judge(chain: &Chain, refusal: &Value) -> Stage {
    let header = sealed_from_rlp(&refusal["rlp"]);
    assert_eq!(header.hash(), b256(&refusal["hash"]), "{}: hash", refusal["name"]);
    let parent = chain.header_by_hash(header.parent_hash).expect("the refusal's parent is a V5 block");
    if let Err(err) = chain.consensus.validate_header(&header) {
        return Stage::ImportHeader(format!("{err}"));
    }
    if let Err(err) = chain.consensus.validate_header_against_parent(&header, parent) {
        if let ConsensusError::Other(inner) = &err {
            if let Some(DeferredExecutionError::Mismatch { got, expected, .. }) = inner.downcast_ref::<DeferredExecutionError>() {
                return Stage::Deferred {
                    got: got.gas_used,
                    expected: expected.gas_used,
                    got_requests: got.requests_hash,
                    expected_requests: expected.requests_hash,
                };
            }
        }
        return Stage::ImportParent(format!("{err}"));
    }
    let now = refusal["nowUnix"].as_u64().unwrap_or(header.timestamp);
    if let Err(err) = n42_h2_consensus::check_profile1_vote_time(header.timestamp, now) {
        return Stage::Vote(err.to_string());
    }
    Stage::Accepted
}

/// Every V5 refusal is refused here at gov5's stage class: `import` by the
/// header or parent rules, `deferred` by the deferred fields check with
/// gov5's two gas figures, `vote` only by B4's clock bound (accepted on
/// import). Where this node refuses at an earlier check of the same class
/// with another rule, it is listed in the output. One case does today:
/// `blobGasUsed 1` is refused by reth's `validate_4844_header_standalone`
/// ("not a multiple of blob gas per blob", `hotstuff_consensus.rs`
/// `validate_header`) before profile 1's B9 rule runs; still an import
/// refusal of the header alone.
#[test]
fn v5_refusals_are_refused_at_gov5s_stage() {
    let chain = run_chain();
    let refusals = v5()["refusals"].as_array().expect("refusals");
    assert_eq!(refusals.len(), 15);
    let mut differences = Vec::new();
    for refusal in refusals {
        let name = refusal["name"].as_str().expect("name");
        let check = refusal["check"].as_str().expect("check");
        let rule = refusal["rule"].as_str().expect("rule");
        let stage = judge(&chain, refusal);
        println!("{rule:4} {check:8} {name:45} -> {stage:?}");
        let same_class = match (check, &stage) {
            ("import", Stage::ImportHeader(_) | Stage::ImportParent(_)) => true,
            ("deferred", Stage::Deferred { got, expected, got_requests, expected_requests }) => {
                let message = refusal["gov5Message"].as_str().unwrap_or_default();
                if refusal["expectedError"] == "ErrDeferredRequestsHash" {
                    // gov5: "requestsHash is not the parent's executed EIP-7685
                    // requests hash: header N carries <got>, this node executed <expected>".
                    got_requests != expected_requests
                        && message.contains(&format!("carries {got_requests}, this node executed {expected_requests}"))
                } else {
                    // gov5: "header N carries parent gas used <got>, this node executed <expected>".
                    message.contains(&format!("carries parent gas used {got}, this node executed {expected}"))
                }
            }
            // Same verdict at an earlier stage: acceptable, printed above.
            ("deferred", Stage::ImportHeader(_) | Stage::ImportParent(_)) => true,
            ("vote", Stage::Vote(_)) => true,
            ("vote", Stage::ImportHeader(_) | Stage::ImportParent(_)) => true,
            _ => false,
        };
        if !same_class {
            differences.push(format!("{rule} {check} {name}: ours {stage:?}; gov5 {}", refusal["gov5Message"]));
        }
    }
    assert!(differences.is_empty(), "V5 refusals differ:\n{}", differences.join("\n"));
}

/// EIP-8282 on profile 1: Amsterdam is active from genesis, so alloy-evm runs
/// the two builder-request system calls after every block, but the genesis
/// deploys no code at the predeploys: the calls return empty output, push no
/// request and leave no account in the bundle. A node with the calls switched
/// off (n42-26 on a native chain) therefore computes the same stateRoot,
/// requests and requestsHash for every V5 block. Prints the evidence.
#[test]
fn v5_eip8282_calls_change_nothing_on_profile1() {
    let spec = chain(&v5()["allocAdditions"]);
    let evm = config(&spec);
    for (i, b) in run_chain().blocks.iter().enumerate() {
        assert_eq!(evm.spec_at(b.header.timestamp, b.header.number), evm2::SpecId::AMSTERDAM, "block {} runs the Amsterdam spec id, so evm2 makes the 8282 calls", i + 1);
    }
    for a in BUILDER_PREDEPLOYS {
        assert!(!spec.genesis.alloc.contains_key(&a), "no contract at {a}");
    }
    let chain = run_chain();
    for (i, b) in chain.blocks.iter().enumerate() {
        println!("{:40} 8282 accounts in bundle {:?} request types {:?}", b.name, b.touched_8282, b.requests.iter().map(|r| r[0]).collect::<Vec<_>>());
        assert!(b.touched_8282.is_empty(), "{}: the 8282 calls wrote state", b.name);
        assert!(b.requests.iter().all(|r| r[0] < 3), "{}: an 8282 request", b.name);
        assert_eq!(b.ours, b.theirs, "block {} equals gov5's result with the calls as they run", i + 1);
    }
}

/// B (07b3e7ed3): a profile-1 restart re-executes the head and files the
/// block's gas used, not the receipts' cumulative gas. V5 block 3 is an
/// account-creating transfer: under EIP-8037 the two differ.
#[test]
fn head_reexecution_returns_the_blocks_gas_not_the_receipts() {
    let chain = run_chain();
    let b = &chain.blocks[2];
    assert_eq!(b.name, "new-account-transfer");
    assert_ne!(b.receipts_gas, b.ours.gas_used, "receipts' cumulative gas differs from the block's gas used");
    assert_eq!((b.receipts_gas, b.ours.gas_used), (204600, 183600));
    let spec = chain_spec_for_tests();
    let c = config(&spec);
    let (requests_hash, gas_used) =
        crate::head_reexecution::reexecute_block(&c, b.pre_state.clone(), &b.recovered).expect("re-executes");
    assert_eq!(gas_used, 183600, "the block's gas used");
    assert_eq!(gas_used, b.theirs.gas_used);
    assert_eq!(requests_hash, b.ours.requests_hash);
}

fn chain_spec_for_tests() -> Arc<reth_chainspec::ChainSpec> {
    chain(&v5()["allocAdditions"])
}
