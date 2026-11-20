// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42: the engine with a block inserted as already executed and its
//! `newPayload` sent after the insert, against the same block with the
//! `newPayload` left out (`N42_SKIP_OWN_NEW_PAYLOAD` in `bin/n42`), on reth's
//! real engine tree.
//!
//! Its own test binary: the executed-insert channel
//! (`reth_node_builder::executed_inserts`) is process-wide and its receiver
//! goes to the first node launched, which must be the node under test.

#![allow(missing_docs)]

use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use reth_chainspec::EthereumHardfork;
use reth_e2e_test_utils::{transaction::TransactionTestContext, E2ETestSetupExt};
use reth_ethereum_primitives::EthPrimitives;
use reth_node_builder::executed_inserts::{sender, ExecutedInsert};
use reth_node_ethereum::{EthEngineTypes, EthereumNode};
use reth_payload_primitives::{BuiltPayloadExecutedBlock, PayloadTypes};
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use reth_provider::{BlockNumReader, BlockReader, HeaderProvider, StateProviderFactory};
use std::sync::Arc;

type Executed = BuiltPayloadExecutedBlock<EthPrimitives>;

/// The executed block a reference node holds for `hash`, as the builder
/// would hand it over.
fn executed_from<P>(provider: &P, hash: B256) -> Executed
where
    P: CanonicalState,
{
    let block = provider.executed(hash);
    Executed {
        recovered_block: Arc::clone(&block.recovered_block),
        execution_output: Arc::clone(&block.execution_output),
        hashed_state: Arc::new(block.hashed_state().as_ref().clone().into()),
        trie_updates: Arc::new(block.trie_updates().as_ref().clone().into()),
    }
}

/// The in-memory executed block of a node.
trait CanonicalState {
    fn executed(&self, hash: B256) -> reth_chain_state::ExecutedBlock<EthPrimitives>;
}

impl<N> CanonicalState for reth_provider::providers::BlockchainProvider<N>
where
    N: reth_provider::providers::ProviderNodeTypes<Primitives = EthPrimitives>,
{
    fn executed(&self, hash: B256) -> reth_chain_state::ExecutedBlock<EthPrimitives> {
        self.canonical_in_memory_state().state_by_hash(hash).expect("held in memory").block()
    }
}

/// Hands `block` to the engine as executed; `true` once forwarded.
async fn insert(block: Executed) -> bool {
    let (done, forwarded) = tokio::sync::oneshot::channel();
    sender().send(ExecutedInsert { block: Box::new(block), done }).expect("engine loop");
    tokio::time::timeout(std::time::Duration::from_secs(10), forwarded)
        .await
        .expect("forwarded in time")
        .expect("answered")
}

/// What two nodes must agree on after a block: head, its header and body,
/// and the accounts the block touched.
async fn view<P>(provider: &P, accounts: &[Address]) -> (u64, B256, B256, usize, Vec<Option<(u64, alloy_primitives::U256)>>)
where
    P: BlockNumReader + BlockReader<Block = reth_ethereum_primitives::Block> + HeaderProvider + StateProviderFactory,
{
    let number = provider.best_block_number().expect("best");
    let hash = provider.block_hash(number).expect("hash").expect("canonical hash");
    let header = provider.header(hash).expect("header").expect("header held");
    let body = provider.block_by_hash(hash).expect("block").expect("block held").body.transactions.len();
    let state = provider.latest().expect("latest state");
    let accounts = accounts
        .iter()
        .map(|a| state.basic_account(a).expect("account").map(|acc| (acc.nonce, acc.balance)))
        .collect();
    (number, hash, alloy_consensus::BlockHeader::state_root(&header), body, accounts)
}

/// A transfer with the next nonce.
async fn next_tx(wallet: &reth_e2e_test_utils::wallet::Wallet, nonce: &mut u64) -> alloy_primitives::Bytes {
    let raw = TransactionTestContext::transfer_tx_bytes_with_nonce(1, wallet.inner.clone(), *nonce).await;
    *nonce += 1;
    raw
}

fn same(hash: B256) -> ForkchoiceState {
    ForkchoiceState { head_block_hash: hash, safe_block_hash: hash, finalized_block_hash: hash }
}

/// One own block through (a) executed insert, `newPayload`, forkchoice and
/// (b) executed insert, forkchoice: the same statuses, head and state as a
/// node that imported it the ordinary way. Then the fallbacks: a block whose
/// insert never landed needs its `newPayload` (forkchoice alone is not
/// VALID), and a held block whose parent the engine recorded invalid is
/// answered INVALID by `newPayload` -- the answer a skip would not give,
/// which is why `N42_SKIP_OWN_NEW_PAYLOAD` stays behind `N42_BENCH_UNSAFE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inserted_block_is_the_same_with_or_without_its_new_payload() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    // The node under test first: it takes the executed-insert receiver.
    let (skip, _) = EthereumNode::test_setup_for(EthereumHardfork::Cancun).build_single().await?;
    // Blocks stay in the reference's memory (its executed blocks are read
    // back): no persistence during the test.
    let (mut others, wallet) = EthereumNode::test_setup_for(EthereumHardfork::Cancun)
        .with_tree_config_modifier(|config| config.with_persistence_backpressure_threshold(2_000).with_persistence_threshold(1_000))
        .with_num_nodes(2)
        .with_connect_nodes(false)
        .build()
        .await?;
    let reference = others.pop().expect("reference");
    let mut producer = others.pop().expect("producer");
    let sender_address = alloy_signer::Signer::address(&wallet.inner);
    // The sender, the block's beneficiary and every recipient so far.
    let mut accounts = vec![sender_address];
    let mut nonce = 0u64;
    let note = |accounts: &mut Vec<Address>, block: &SealedBlock<reth_ethereum_primitives::Block>| {
        accounts.push(block.header().beneficiary);
        for tx in &block.body().transactions {
            if let Some(to) = alloy_consensus::Transaction::to(tx) {
                accounts.push(to);
            }
        }
    };

    for with_new_payload in [true, false] {
        producer.rpc.inject_tx(next_tx(&wallet, &mut nonce).await).await?;
        let payload = producer.advance_block().await?;
        let hash = payload.block().hash();
        note(&mut accounts, payload.block());

        // The reference imports it the ordinary way: executed by newPayload.
        let reference_status = reference.submit_payload_with_status(payload.clone()).await?;
        let reference_fcu = reference.update_forkchoice(hash, hash).await?;
        assert_eq!(reference_status.status, PayloadStatusEnum::Valid);
        assert!(reference_fcu.payload_status.is_valid());

        // The node under test is handed the reference's execution.
        assert!(insert(executed_from(&reference.inner.provider, hash)).await, "forwarded");
        if with_new_payload {
            let status = skip.submit_payload_with_status(payload.clone()).await?;
            assert_eq!(status.status, PayloadStatusEnum::Valid, "already held: VALID");
            assert_eq!(status.latest_valid_hash, Some(hash));
        }
        let fcu = skip.inner.add_ons_handle.beacon_engine_handle.fork_choice_updated(same(hash), None).await?;
        assert_eq!(fcu.payload_status.status, reference_fcu.payload_status.status);
        assert_eq!(fcu.payload_status.latest_valid_hash, reference_fcu.payload_status.latest_valid_hash);
        assert_eq!(
            view(&skip.inner.provider, &accounts).await,
            view(&reference.inner.provider, &accounts).await,
            "with_new_payload={with_new_payload}"
        );

        if !with_new_payload {
            // A newPayload arriving after all changes nothing.
            let before = view(&skip.inner.provider, &accounts).await;
            let late = skip.submit_payload_with_status(payload).await?;
            assert_eq!(late.status, PayloadStatusEnum::Valid);
            assert_eq!(view(&skip.inner.provider, &accounts).await, before);
        }
    }

    // Fallback: no insert landed -- as for an insert the tree dropped or
    // evicted before the block's newPayload (N42_OWN_PAYLOAD_PRECOPY keeps
    // that newPayload, carrying the full block). Forkchoice alone does not
    // make the block canonical; the newPayload executes it, and the node
    // ends up where the reference is.
    producer.rpc.inject_tx(next_tx(&wallet, &mut nonce).await).await?;
    let payload = producer.advance_block().await?;
    let hash = payload.block().hash();
    note(&mut accounts, payload.block());
    let alone = skip.inner.add_ons_handle.beacon_engine_handle.fork_choice_updated(same(hash), None).await?;
    assert!(!alone.payload_status.is_valid(), "not held: {:?}", alone.payload_status.status);
    assert_eq!(skip.submit_payload_with_status(payload.clone()).await?.status, PayloadStatusEnum::Valid);
    assert!(skip.update_forkchoice(hash, hash).await?.payload_status.is_valid());
    reference.submit_payload(payload).await?;
    assert!(reference.update_forkchoice(hash, hash).await?.payload_status.is_valid());
    assert_eq!(view(&skip.inner.provider, &accounts).await, view(&reference.inner.provider, &accounts).await);

    // A held block whose parent the engine recorded invalid. The parent: the
    // next block with a wrong state root, resealed, so it executes and fails.
    producer.rpc.inject_tx(next_tx(&wallet, &mut nonce).await).await?;
    let next = producer.advance_block().await?;
    reference.submit_payload(next.clone()).await?;
    let next_hash = next.block().hash();
    assert!(reference.update_forkchoice(next_hash, next_hash).await?.payload_status.is_valid());
    let mut bad = next.block().clone().into_block();
    bad.header.state_root = B256::repeat_byte(0x42);
    let bad = SealedBlock::seal_slow(bad);
    let bad_status = skip.inner.add_ons_handle.beacon_engine_handle
        .new_payload(<EthEngineTypes as PayloadTypes>::block_to_payload(bad.clone(), None))
        .await?;
    assert!(matches!(bad_status.status, PayloadStatusEnum::Invalid { .. }), "{:?}", bad_status.status);
    // The child, inserted as executed: the insert does not look at the parent.
    let template = executed_from(&reference.inner.provider, next_hash);
    let mut child = template.recovered_block.sealed_block().clone().into_block();
    child.header.parent_hash = bad.hash();
    child.header.number = bad.number + 1;
    let child = SealedBlock::seal_slow(child);
    let senders = template.recovered_block.senders().to_vec();
    let child_hash = child.hash();
    assert!(
        insert(Executed {
            recovered_block: Arc::new(RecoveredBlock::new_sealed(child.clone(), senders)),
            ..template
        })
        .await
    );
    let answer = skip.inner.add_ons_handle.beacon_engine_handle
        .new_payload(<EthEngineTypes as PayloadTypes>::block_to_payload(child, None))
        .await?;
    assert!(
        matches!(answer.status, PayloadStatusEnum::Invalid { .. }),
        "a held block over an invalid parent is INVALID to newPayload: {:?}",
        answer.status
    );
    let _ = child_hash;
    Ok(())
}
