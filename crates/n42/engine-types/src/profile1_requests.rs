// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! AM25 (`docs/MIXED_PRODUCTION_STANDARD.md`): on a profile-1 chain block
//! execution produces EIP-7685 requests exactly as on Ethereum, a block that
//! produces them is valid, and `requestsHash` is a deferred field -- header N
//! carries the requests hash of block N-1's execution.
//!
//! The scenario is the one-transaction halt AM24 allowed: a fee-paying call to
//! the EIP-7002 contract (and three EIP-7251 consolidations, more than the two
//! a block dequeues) on V1's `genesis_8s.json`. Each block is executed by the
//! stock import (`N42EvmConfig`'s executor), checked after execution by
//! `HotStuffConsensus` (which files its result), and the next header is checked
//! against that result with `validate_header_against_parent` -- the check both
//! the import and the Round-1 vote gate run (`bin/n42/src/follower_import.rs`,
//! `validate_against_parent`).

use crate::{hotstuff_consensus::HotStuffConsensus, n42_evm::N42EvmConfig};
use alloy_consensus::{SignableTransaction as _, TxEip1559, TxEnvelope};
use alloy_eips::{
    eip2718::{Decodable2718 as _, Encodable2718 as _},
    eip7685::{Requests, EMPTY_REQUESTS_HASH},
};
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_signer::SignerSync as _;
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, CacheDB, EmptyDB},
};
use n42_tx_types::N42TxEnvelope;
use reth_chainspec::EthChainSpec as _;
use reth_consensus::{FullConsensus as _, HeaderValidator as _};
use reth_evm::{execute::Executor as _, ConfigureEvm as _};
use reth_primitives_traits::{RecoveredBlock, SealedHeader, SignedTransaction as _};
use reth_trie::bundle_state::BundleState;
use std::{path::PathBuf, sync::Arc};

const WITHDRAWAL_REQUESTS: Address = alloy_eips::eip7002::WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS;
const CONSOLIDATION_REQUESTS: Address = alloy_eips::eip7251::CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS;

fn sender() -> alloy_signer_local::PrivateKeySigner {
    alloy_signer_local::PrivateKeySigner::from_bytes(&B256::repeat_byte(0x25)).expect("a key")
}

/// V1's `genesis_8s.json` (profile 1), plus one funded sender.
fn chain() -> Arc<n42_header::N42ChainSpec> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../qmdb-reth/testdata/profile1/gov5/V1/genesis_8s.json");
    let mut genesis: serde_json::Value = serde_json::from_slice(&std::fs::read(path).expect("genesis_8s.json")).expect("json");
    genesis["alloc"][format!("{:?}", sender().address())] = serde_json::json!({ "balance": "0xd3c21bcecceda1000000" });
    let genesis: alloy_genesis::Genesis = serde_json::from_value(genesis).expect("a genesis");
    n42_qmdb_reth::chainspec::check_genesis(&genesis).expect("a valid profile-1 genesis");
    assert!(reth_chainspec::qmdb::is_profile1(&genesis), "a profile-1 genesis");
    assert!(crate::hotstuff_consensus::requests_hash_deferred(&genesis));
    Arc::new(n42_header::N42ChainSpec::from(reth_chainspec::ChainSpec::from(genesis)))
}

fn genesis_state(spec: &n42_header::N42ChainSpec) -> CacheDB<EmptyDB> {
    let mut db = CacheDB::new(EmptyDB::default());
    for (who, account) in &spec.genesis().alloc {
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

fn apply(db: &mut CacheDB<EmptyDB>, bundle: &BundleState) {
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

/// A signed fee-paying call to a request contract (the fee at an empty
/// queue is 1 wei; the call pays a gwei, which the contract keeps).
fn call(chain_id: u64, nonce: u64, to: Address, input: Vec<u8>) -> N42TxEnvelope {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: 10_000_000,
        max_fee_per_gas: 100_000_000_000,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(to),
        value: U256::from(1_000_000_000u64),
        access_list: Default::default(),
        input: Bytes::from(input),
    };
    let signature = sender().sign_hash_sync(&tx.signature_hash()).expect("signed");
    let raw = TxEnvelope::from(tx.into_signed(signature)).encoded_2718();
    N42TxEnvelope::decode_2718(&mut raw.as_slice()).expect("decodes")
}

/// The child of `parent` carrying `carried` as its deferred fields, with the
/// profile-1 parent rules satisfied (link, time, base fee, committee link).
fn child(
    c: &HotStuffConsensus<n42_header::N42ChainSpec>,
    spec: &n42_header::N42ChainSpec,
    parent: &SealedHeader<n42_header::N42Header>,
    carried: crate::executed_fields::ExecutedFields,
) -> n42_header::N42Header {
    let coinbase = Address::repeat_byte(0xc0);
    let withdrawals = rewards(spec, coinbase);
    let parent_beacon_root = c
        .committee_pool()
        .map(|pool| pool.parent_beacon_root(parent.number, &parent.hash(), &parent.receipts_root).expect("the link"))
        .unwrap_or_default();
    n42_header::N42Header::from(alloy_consensus::Header {
        parent_hash: parent.hash(),
        number: parent.number + 1,
        timestamp: parent.timestamp + 8,
        beneficiary: coinbase,
        gas_limit: parent.gas_limit,
        base_fee_per_gas: Some(n42_h2_consensus::profile1_base_fee(parent.header())),
        parent_beacon_block_root: Some(parent_beacon_root),
        withdrawals_root: Some(alloy_consensus::proofs::calculate_withdrawals_root(&withdrawals)),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        state_root: carried.state_root,
        receipts_root: carried.receipts_root,
        logs_bloom: carried.logs_bloom,
        gas_used: carried.gas_used,
        requests_hash: Some(carried.requests_hash),
        ..Default::default()
    })
}

fn rewards(spec: &n42_header::N42ChainSpec, coinbase: Address) -> Vec<alloy_eips::eip4895::Withdrawal> {
    let hotstuff = n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(spec.genesis()).expect("a hotstuff genesis");
    n42_h2_consensus::rewards_to_withdrawals(&hotstuff.block_rewards(coinbase)).expect("whole gwei")
}

fn with_requests_hash(header: &n42_header::N42Header, hash: B256) -> SealedHeader<n42_header::N42Header> {
    let mut header = header.clone();
    header.requests_hash = Some(hash);
    SealedHeader::seal_slow(header)
}

#[test]
fn a_block_that_produces_requests_is_valid_and_its_child_carries_their_hash() {
    let spec = chain();
    let c = HotStuffConsensus::new(Arc::clone(&spec));
    let config = N42EvmConfig::new(Arc::clone(&spec));
    let chain_id = spec.chain().id();
    let genesis = SealedHeader::seal_slow(spec.genesis_header().clone());
    assert_eq!(genesis.requests_hash, Some(EMPTY_REQUESTS_HASH), "genesis carries sha256(\"\")");

    // Block 1: one withdrawal request and three consolidation requests; a
    // block dequeues at most two consolidations, so the queue drains over
    // blocks 1 and 2.
    let pubkey = |byte: u8| vec![byte; 48];
    let withdrawal = [pubkey(0x11), 5_000_000_000u64.to_be_bytes().to_vec()].concat();
    let txs = vec![
        call(chain_id, 0, WITHDRAWAL_REQUESTS, withdrawal),
        call(chain_id, 1, CONSOLIDATION_REQUESTS, [pubkey(0x21), pubkey(0x31)].concat()),
        call(chain_id, 2, CONSOLIDATION_REQUESTS, [pubkey(0x22), pubkey(0x32)].concat()),
        call(chain_id, 3, CONSOLIDATION_REQUESTS, [pubkey(0x23), pubkey(0x33)].concat()),
    ];

    let mut db = genesis_state(&spec);
    let mut parent = genesis.clone();
    let mut carried_hashes = Vec::new();
    let mut produced = Vec::new();
    for number in 1..=4u64 {
        // The header carries the parent's execution, requests hash included.
        let carried = crate::hotstuff_consensus::parent_executed_fields(spec.genesis(), &parent).expect("the parent's result");
        let header = child(&c, &spec, &parent, carried);
        carried_hashes.push(carried.requests_hash);
        let sealed = SealedHeader::seal_slow(header.clone());
        // The import and the Round-1 vote gate: the carried value passes...
        c.validate_header_against_parent(&sealed, &parent)
            .unwrap_or_else(|err| panic!("block {number} carrying its parent's requests hash: {err}"));
        // ... and any other value is refused.
        let wrong = if carried.requests_hash == EMPTY_REQUESTS_HASH { B256::repeat_byte(0x7a) } else { EMPTY_REQUESTS_HASH };
        assert!(
            c.validate_header_against_parent(&with_requests_hash(&header, wrong), &parent).is_err(),
            "block {number}: a header carrying {wrong} instead of {} is refused",
            carried.requests_hash
        );

        let body = n42_tx_types::BlockBody {
            transactions: if number == 1 { txs.clone() } else { Vec::new() },
            ommers: Vec::new(),
            withdrawals: Some(rewards(&spec, header.beneficiary).into()),
        };
        let senders = body.transactions.iter().map(|tx| tx.try_recover().expect("recovers")).collect();
        let block = RecoveredBlock::new_sealed(
            reth_primitives_traits::SealedBlock::from_sealed_parts(sealed.clone(), body),
            senders,
        );
        let output = config.executor(db.clone()).execute(&block).unwrap_or_else(|e| panic!("block {number} executes: {e}"));
        if number == 1 {
            assert!(output.result.receipts.iter().all(|receipt| receipt.success), "every request call succeeds");
        }
        // Valid on profile 1 whatever requests it produced (AM24's refusal is gone).
        crate::executed_fields::remember_state_root(sealed.hash(), alloy_primitives::keccak256(sealed.hash()));
        c.validate_block_post_execution(&block, &output.result, None, None)
            .unwrap_or_else(|err| panic!("block {number} with {} request lists: {err}", output.result.requests.len()));
        produced.push(output.result.requests.clone());
        apply(&mut db, &output.state);
        parent = sealed;
    }

    let types = |requests: &Requests| requests.iter().map(|request| request[0]).collect::<Vec<_>>();
    // Block 1: the withdrawal request and two of the three consolidations.
    assert_eq!(types(&produced[0]), vec![0x01, 0x02], "block 1's requests: {:?}", produced[0]);
    assert_eq!(produced[0].iter().find(|r| r[0] == 0x02).map(|r| (r.len() - 1) / 116), Some(2), "two consolidations dequeued");
    // Block 2: the third consolidation, still queued.
    assert_eq!(types(&produced[1]), vec![0x02], "block 2's requests: {:?}", produced[1]);
    assert_eq!(produced[1][0].len() - 1, 116, "one consolidation");
    // Blocks 3 and 4: the queues are empty.
    assert!(produced[2].is_empty() && produced[3].is_empty());

    // Header N carries block N-1's requests hash; blocks 1 and 2 the genesis's
    // and block 1's respectively.
    assert_eq!(carried_hashes[0], EMPTY_REQUESTS_HASH, "block 1 carries sha256(\"\")");
    assert_eq!(carried_hashes[1], produced[0].requests_hash(), "block 2 carries block 1's requests hash");
    assert_ne!(carried_hashes[1], EMPTY_REQUESTS_HASH);
    assert_eq!(carried_hashes[2], produced[1].requests_hash(), "block 3 carries block 2's requests hash");
    assert_eq!(carried_hashes[3], EMPTY_REQUESTS_HASH, "block 4 carries block 3's: no requests");
    // The chain went on past the requests: block 5 is carried from block 4.
    let last = crate::hotstuff_consensus::parent_executed_fields(spec.genesis(), &parent).expect("block 4's result");
    assert_eq!(last.requests_hash, EMPTY_REQUESTS_HASH);
}

/// Off profile 1 the deferred fields' requests hash stays neutral: a deferred
/// (non-profile) chain files the hash of no requests whatever the block
/// produced, and reads none from a header.
#[test]
fn off_profile_1_the_requests_hash_is_not_a_deferred_field() {
    let genesis = alloy_genesis::Genesis::default();
    assert!(!crate::hotstuff_consensus::requests_hash_deferred(&genesis));
    let mut requests = Requests::default();
    requests.push_request_with_type(0x01, [1u8, 2, 3]);
    assert_eq!(crate::hotstuff_consensus::executed_requests_hash(&genesis, &requests), EMPTY_REQUESTS_HASH);
    let header = alloy_consensus::Header { requests_hash: Some(B256::repeat_byte(9)), ..Default::default() };
    assert_eq!(crate::executed_fields::fields_from_child_header(&header).requests_hash, EMPTY_REQUESTS_HASH);
    assert_eq!(
        crate::executed_fields::fields_from_child_header_deferring_requests(&header, true).requests_hash,
        B256::repeat_byte(9)
    );
}
