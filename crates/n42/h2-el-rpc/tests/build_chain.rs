// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The build chain, against an execution layer that only exists here.
//!
//! What has to be true is one thing: a chained build is the block the request
//! would have asked for, or it is thrown away. Everything else in this file
//! serves that -- the block the chain produced is compared, by hash, with the
//! block the same request draws from a client that never chained; a request
//! naming any other parent, or any other attributes, must leave the chained
//! build unused; and nothing may chain unless the caller hinted *and* a
//! sealer is installed, because the parent hash the chain builds on is a
//! header only the consensus side can make.
//!
//! The execution layer here is a socket that speaks the raw channel: it
//! records what it was asked, answers a build-on-own with the header of the
//! block it would have built, and -- when the request hinted -- sends that
//! header on its own frame first, which is the whole mechanism.

use std::sync::{Arc, Mutex};

use alloy_consensus::{BlockBody, Header, TxEnvelope};
use alloy_eips::eip4895::{Withdrawal, Withdrawals};
use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::PayloadAttributes;
use n42_h2_el_rpc::{EngineApiClient, JsonRpcTransport, RpcError, TransportError};
use n42_h2_execution::raw_engine::{self, ChainHint};
use n42_h2_execution::{ChainAhead, ExecutionLayer};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One build-on-own request as the execution layer saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Asked {
    parent: B256,
    attrs: PayloadAttributes,
    hint: Option<ChainHint>,
}

/// An execution layer that answers build-on-own and nothing else.
#[derive(Debug, Default)]
struct FakeEl {
    asked: Mutex<Vec<Asked>>,
    /// Whether to answer a hinted request with a chain header frame. A real
    /// one always does; off here to test what a caller does without it.
    send_chain_header: bool,
    /// How long the "build" takes before it seals. The chain header goes out
    /// then, as the real builder's does -- it answers on its early seal --
    /// and the block follows after [`FINISH`]. The order matters more than
    /// the numbers: the request for the next block is sent when the chain
    /// header arrives, and the proposal takes the previous one when the
    /// block does, so a chain header that arrived before its predecessor had
    /// been taken would find the slot full and stop the chain. That is the
    /// real timing (250 ms of build against a proposal ~110 ms behind) and
    /// the reason this is not instant.
    build: std::time::Duration,
    /// Refuse every request whose parent is in here, with this message --
    /// the execution layer saying it cannot build on that parent.
    refuse: Mutex<Vec<(B256, String)>>,
}

/// The gap between a build's seal and its block, as the real one spends it
/// encoding ~26 MB.
const FINISH: std::time::Duration = std::time::Duration::from_millis(10);

impl FakeEl {
    /// The block this execution layer builds for a request: a header with
    /// everything the attributes decide, so two requests that differ in any
    /// attribute produce two different hashes.
    fn build(parent: &Header, attrs: &PayloadAttributes) -> Header {
        Header {
            parent_hash: parent.hash_slow(),
            number: parent.number + 1,
            timestamp: attrs.timestamp,
            beneficiary: attrs.suggested_fee_recipient,
            mix_hash: attrs.prev_randao,
            parent_beacon_block_root: attrs.parent_beacon_block_root,
            gas_limit: attrs.target_gas_limit.unwrap_or(30_000_000),
            withdrawals_root: Some(alloy_consensus::proofs::calculate_withdrawals_root(
                &Withdrawals::new(attrs.withdrawals.clone().unwrap_or_default()),
            )),
            // A header's optional fields are positional in RLP: one set with
            // an earlier one absent does not decode back.
            base_fee_per_gas: Some(7),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            ..Default::default()
        }
    }

    async fn serve(self: Arc<Self>, listener: tokio::net::TcpListener) {
        while let Ok((mut stream, _)) = listener.accept().await {
            let el = Arc::clone(&self);
            tokio::spawn(async move {
                loop {
                    let Ok(kind) = stream.read_u8().await else { return };
                    if kind != raw_engine::request::BUILD_ON_OWN {
                        return;
                    }
                    let Ok(len) = stream.read_u32_le().await else { return };
                    let mut frame = vec![0u8; len as usize];
                    if stream.read_exact(&mut frame).await.is_err() {
                        return;
                    }
                    let (parent, attrs, hint, _want_hashes) =
                        raw_engine::decode_build_on_own(&frame).expect("the frame decodes");
                    el.asked.lock().expect("not poisoned").push(Asked {
                        parent: parent.hash_slow(),
                        attrs: attrs.clone(),
                        hint,
                    });
                    let refusal = el
                        .refuse
                        .lock()
                        .expect("not poisoned")
                        .iter()
                        .find(|(hash, _)| *hash == parent.hash_slow())
                        .map(|(_, message)| message.clone());
                    if let Some(message) = refusal {
                        let mut out = vec![2u8];
                        out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                        out.extend_from_slice(message.as_bytes());
                        if stream.write_all(&out).await.is_err() {
                            return;
                        }
                        continue;
                    }
                    tokio::time::sleep(el.build).await;
                    let built = Self::build(&parent, &attrs);
                    if hint.is_some() && el.send_chain_header {
                        let rlp = alloy_rlp::encode(&built);
                        let mut out = vec![raw_engine::reply::CHAIN_HEADER];
                        out.extend_from_slice(&(rlp.len() as u32).to_le_bytes());
                        out.extend_from_slice(&rlp);
                        if stream.write_all(&out).await.is_err() {
                            return;
                        }
                        // The block, behind the seal.
                        tokio::time::sleep(FINISH).await;
                    }
                    let block = alloy_consensus::Block::<TxEnvelope> {
                        header: built,
                        body: BlockBody {
                            transactions: Vec::new(),
                            ommers: Vec::new(),
                            withdrawals: Some(Withdrawals::new(attrs.withdrawals.unwrap_or_default())),
                        },
                    };
                    let rlp = alloy_rlp::encode(&block);
                    let mut out = vec![1u8];
                    out.extend_from_slice(&(rlp.len() as u32).to_le_bytes());
                    out.extend_from_slice(&rlp);
                    // No requests, no access list.
                    out.push(0);
                    out.push(0);
                    if stream.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    }
}

/// A transport that knows one method: where the raw channel is.
#[derive(Debug)]
struct Endpoint(std::net::SocketAddr);

#[async_trait::async_trait]
impl JsonRpcTransport for Endpoint {
    async fn call(&self, method: &str, _params: Vec<Value>) -> Result<Value, TransportError> {
        if method == "n42Engine_payloadEndpoint" {
            return Ok(json!(self.0.to_string()));
        }
        Err(TransportError::Rpc(RpcError { code: -32601, message: "method not found".into() }))
    }
}

/// The consensus side, as the chain sees it: a seal that depends on the view,
/// and the next block's attributes derived from the header that seal made.
///
/// Both of those are what the real one does -- gov5's stamp-and-sign, and the
/// node's own attributes closure reading the sealed header as its head. What
/// matters for the test is only that they are *deterministic functions of the
/// same inputs* as the proposal path's, because that is the whole reason a
/// chained build can be the right block.
fn sealer() -> n42_h2_execution::ChainSealer {
    Arc::new(|built: &Header, built_with: &PayloadAttributes, view: u64| {
        let mut sealed = built.clone();
        sealed.extra_data = view.to_le_bytes().to_vec().into();
        let next = PayloadAttributes {
            timestamp: built_with.timestamp + 1,
            prev_randao: built_with.prev_randao,
            suggested_fee_recipient: built_with.suggested_fee_recipient,
            withdrawals: built_with.withdrawals.clone(),
            // Stands in for the committee evidence: an attribute of the next
            // block that only the *sealed* parent decides.
            parent_beacon_block_root: Some(sealed.hash_slow()),
            slot_number: built_with.slot_number.map(|slot| slot + 1),
            target_gas_limit: None,
        };
        Some((sealed, next))
    })
}

fn attrs(timestamp: u64) -> PayloadAttributes {
    PayloadAttributes {
        timestamp,
        prev_randao: B256::repeat_byte(7),
        suggested_fee_recipient: Address::repeat_byte(9),
        withdrawals: Some(vec![Withdrawal { index: 1, validator_index: 2, address: Address::repeat_byte(3), amount: 4 }]),
        parent_beacon_block_root: Some(B256::repeat_byte(5)),
        slot_number: Some(41),
        target_gas_limit: None,
    }
}

fn parent() -> Header {
    Header { number: 40, gas_limit: 30_000_000, ..Default::default() }
}

/// Waits for the execution layer to have been asked `n` times, or gives up.
/// A chained request is written by a task, so counting it needs a moment.
async fn asked_at_least(el: &Arc<FakeEl>, n: usize) -> Vec<Asked> {
    for _ in 0..200 {
        let asked = el.asked.lock().expect("not poisoned").clone();
        if asked.len() >= n {
            return asked;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    el.asked.lock().expect("not poisoned").clone()
}

/// Starts the fake execution layer and a client pointed at it.
async fn fleet(send_chain_header: bool) -> (Arc<FakeEl>, EngineApiClient<Endpoint>) {
    fleet_with(send_chain_header, std::time::Duration::from_millis(60)).await
}

async fn fleet_with(
    send_chain_header: bool,
    build: std::time::Duration,
) -> (Arc<FakeEl>, EngineApiClient<Endpoint>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let addr = listener.local_addr().expect("has an address");
    let el = Arc::new(FakeEl {
        asked: Mutex::new(Vec::new()),
        send_chain_header,
        build,
        refuse: Mutex::new(Vec::new()),
    });
    tokio::spawn(Arc::clone(&el).serve(listener));
    (el, EngineApiClient::new(Endpoint(addr)))
}

/// The happy path: the chain starts on the header the execution layer sealed
/// early, and the request that follows finds the block it would have asked
/// for -- the same hash a client that never chained gets for the same parent
/// and the same attributes.
#[tokio::test]
async fn a_chained_build_is_the_block_the_request_would_have_built() {
    let (el, client) = fleet(true).await;
    client.set_chain_sealer(sealer());

    // The request for block 41, hinting that block 42 is ours too.
    let first = client
        .build_on_own_block_chaining(&parent(), attrs(1_000), Some(ChainAhead { view: 7 }))
        .await
        .expect("answered")
        .expect("built");
    assert_eq!(first.number, 41);

    // What the chain sealed and asked for next -- the same functions the
    // proposal path would use a moment later.
    let (sealed, next) = sealer()(&FakeEl::build(&parent(), &attrs(1_000)), &attrs(1_000), 7).expect("seals");
    let chained = client
        .build_on_own_block_chaining(&sealed, next.clone(), Some(ChainAhead { view: 8 }))
        .await
        .expect("answered")
        .expect("built");

    // The same block a client that never chained draws for that request.
    let (plain_el, plain) = fleet(false).await;
    let expected = plain
        .build_on_own_block_chaining(&sealed, next.clone(), None)
        .await
        .expect("answered")
        .expect("built");
    assert_eq!(chained.hash, expected.hash, "the chained block is the block the request would have built");
    assert_eq!(plain_el.asked.lock().expect("not poisoned").len(), 1);

    // Two requests reached the execution layer, and the second is the chain's:
    // it named the sealed parent, carried the same attributes, and said so.
    let asked = el.asked.lock().expect("not poisoned").clone();
    assert_eq!(asked[0].hint, Some(ChainHint { view: 7, chained: false }));
    assert_eq!(asked[1].parent, sealed.hash_slow());
    assert_eq!(asked[1].attrs, next);
    assert_eq!(asked[1].hint, Some(ChainHint { view: 8, chained: true }), "the chain carries on");
    // Exactly one request was the proposal's: the one that seeded the chain.
    // Anything more would mean a chained build was not taken. A trailing
    // chained request nobody has asked for yet is the chain running its one
    // block ahead, which is what it is for.
    let from_the_proposal = asked.iter().filter(|one| one.hint.is_none_or(|hint| !hint.chained)).count();
    assert_eq!(from_the_proposal, 1, "the proposal's request was answered from the chain, not repeated");
}

/// Without the hint there is no chain: the execution layer is never told the
/// next height is ours, so it sends no header and nothing is built ahead.
#[tokio::test]
async fn nothing_chains_without_the_hint() {
    let (el, client) = fleet(true).await;
    client.set_chain_sealer(sealer());

    client
        .build_on_own_block_chaining(&parent(), attrs(1_000), None)
        .await
        .expect("answered")
        .expect("built");
    let (sealed, next) = sealer()(&FakeEl::build(&parent(), &attrs(1_000)), &attrs(1_000), 7).expect("seals");
    client
        .build_on_own_block_chaining(&sealed, next, None)
        .await
        .expect("answered")
        .expect("built");

    let asked = el.asked.lock().expect("not poisoned").clone();
    assert_eq!(asked.len(), 2, "each request went to the execution layer on its own");
    assert!(asked.iter().all(|one| one.hint.is_none()));
}

/// And no chain without a sealer, however loudly the caller hints: the parent
/// a chained build stands on is a header only the consensus side can make.
#[tokio::test]
async fn nothing_chains_without_a_sealer() {
    let (el, client) = fleet(true).await;
    client
        .build_on_own_block_chaining(&parent(), attrs(1_000), Some(ChainAhead { view: 7 }))
        .await
        .expect("answered")
        .expect("built");
    let asked = el.asked.lock().expect("not poisoned").clone();
    assert_eq!(asked.len(), 1);
    assert!(asked[0].hint.is_none(), "no sealer, no hint on the wire");
}

/// A request naming another parent does not take the chained build. It is
/// discarded and the request is put to the execution layer as it would have
/// been without a chain at all.
#[tokio::test]
async fn a_request_for_another_parent_discards_the_chained_build() {
    let (el, client) = fleet(true).await;
    client.set_chain_sealer(sealer());
    client
        .build_on_own_block_chaining(&parent(), attrs(1_000), Some(ChainAhead { view: 7 }))
        .await
        .expect("answered")
        .expect("built");

    // The view timed out and the block was sealed under another one: a
    // different header, so a different parent hash.
    let (mut elsewhere, next) =
        sealer()(&FakeEl::build(&parent(), &attrs(1_000)), &attrs(1_000), 9).expect("seals");
    elsewhere.extra_data = 9u64.to_le_bytes().to_vec().into();
    let built = client
        .build_on_own_block_chaining(&elsewhere, next.clone(), Some(ChainAhead { view: 9 }))
        .await
        .expect("answered")
        .expect("built");
    assert_eq!(built.execution_data.payload.parent_hash(), elsewhere.hash_slow());

    // The chained build went out and was answered; the request that followed
    // it went out too, on the parent consensus really sealed -- and the chain
    // picked up again from there, which is the point of counting a fourth.
    let asked = asked_at_least(&el, 4).await;
    assert_eq!(asked.len(), 4);
    assert_eq!(asked[1].parent, sealed_elsewhere(), "the chain built on the header it guessed");
    assert_eq!(asked[2].parent, elsewhere.hash_slow());
    assert_eq!(asked[2].attrs, next);
    assert_eq!(asked[3].hint.map(|hint| hint.chained), Some(true));
    assert_eq!(asked[3].parent, sealer()(&FakeEl::build(&elsewhere, &next), &next, 9).expect("seals").0.hash_slow());
}

/// The header the chain guessed in the test above: the build on the original
/// parent, sealed for the view the hint named.
fn sealed_elsewhere() -> B256 {
    sealer()(&FakeEl::build(&parent(), &attrs(1_000)), &attrs(1_000), 7).expect("seals").0.hash_slow()
}

/// Same parent, different attributes: also not the block that was asked for.
#[tokio::test]
async fn a_request_with_other_attributes_discards_the_chained_build() {
    let (el, client) = fleet(true).await;
    client.set_chain_sealer(sealer());
    client
        .build_on_own_block_chaining(&parent(), attrs(1_000), Some(ChainAhead { view: 7 }))
        .await
        .expect("answered")
        .expect("built");

    let (sealed, next) = sealer()(&FakeEl::build(&parent(), &attrs(1_000)), &attrs(1_000), 7).expect("seals");
    let moved = PayloadAttributes { timestamp: next.timestamp + 3, ..next };
    client
        .build_on_own_block_chaining(&sealed, moved.clone(), Some(ChainAhead { view: 8 }))
        .await
        .expect("answered")
        .expect("built");

    let asked = asked_at_least(&el, 4).await;
    assert_eq!(asked.len(), 4);
    assert_eq!(asked[2].attrs, moved, "the request was put as it stands, never adjusted to fit");
    assert_eq!(asked[3].hint.map(|hint| hint.chained), Some(true), "the chain resumes from the request");
}

/// The steady state, which no test covered before: three chained builds in a
/// row, each taken by the proposal that follows it.
///
/// A chain that works for one block and then stops is the shape the loop193
/// legs actually ran in -- every chained build after the first was refused --
/// and the tests passed throughout, because none of them asked for a second.
#[tokio::test]
async fn three_chained_builds_in_a_row() {
    let (el, client) = fleet(true).await;
    client.set_chain_sealer(sealer());

    // The request that seeds the chain; everything after it is the chain's.
    let mut head = parent();
    let mut attributes = attrs(1_000);
    let mut view = 7;
    let mut numbers = Vec::new();
    let first = client
        .build_on_own_block_chaining(&head, attributes.clone(), Some(ChainAhead { view }))
        .await
        .expect("answered")
        .expect("built");
    numbers.push(first.number);

    for _ in 0..3 {
        let (sealed, next) = sealer()(&FakeEl::build(&head, &attributes), &attributes, view).expect("seals");
        view += 1;
        let built = client
            .build_on_own_block_chaining(&sealed, next.clone(), Some(ChainAhead { view }))
            .await
            .expect("answered")
            .expect("built");
        assert_eq!(
            built.execution_data.payload.parent_hash(),
            sealed.hash_slow(),
            "every block in the chain stands on the header the proposal sealed"
        );
        numbers.push(built.number);
        head = sealed;
        attributes = next;
    }

    assert_eq!(numbers, vec![41, 42, 43, 44]);
    let asked = asked_at_least(&el, 4).await;
    // One request from the proposal -- the one that seeded the chain -- and
    // the rest from the chain. The four builds above came from four of them;
    // a fifth may be in flight, which is the chain's one block ahead.
    let from_the_proposal = asked.iter().filter(|one| one.hint.is_none_or(|hint| !hint.chained)).count();
    assert_eq!(from_the_proposal, 1, "the proposal never had to repeat a request the chain had served");
    assert!(asked.len() >= 4);
    assert!(asked[0].hint.is_some() && !asked[0].hint.expect("hinted").chained);
    for one in &asked[1..] {
        assert_eq!(one.hint.map(|hint| hint.chained), Some(true));
    }
    // And they form a chain: each request's parent is the block before it.
    for pair in asked.windows(2) {
        assert_ne!(pair[0].parent, pair[1].parent);
    }
}

/// A refusal is acted on when it arrives, not when the proposal asks.
///
/// The execution layer refuses in about a millisecond and the proposal's
/// request comes ~275 ms later (loop193 W1b: `lead_ms=273 wait_ms=0` on every
/// one of them). A slot left full for that long is a slot nothing may replace
/// and a `chain discarded` line that says nothing about why.
#[tokio::test]
async fn a_refused_chained_build_frees_the_slot_at_once() {
    let (el, client) = fleet(true).await;
    client.set_chain_sealer(sealer());

    // The chain's own request -- on the header the chain seals -- is the one
    // the execution layer will not serve.
    let (sealed, next) = sealer()(&FakeEl::build(&parent(), &attrs(1_000)), &attrs(1_000), 7).expect("seals");
    el.refuse
        .lock()
        .expect("not poisoned")
        .push((sealed.hash_slow(), "deferred execution: the parent's execution result is not known here".to_owned()));

    client
        .build_on_own_block_chaining(&parent(), attrs(1_000), Some(ChainAhead { view: 7 }))
        .await
        .expect("answered")
        .expect("built");
    // The chained request went out and was refused. Give the task the moment
    // it needs to hear that.
    asked_at_least(&el, 2).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // The proposal now asks for the same block. With the slot already empty
    // this is an ordinary request, answered in one build -- not a wait on a
    // build that will never come.
    el.refuse.lock().expect("not poisoned").clear();
    let at = std::time::Instant::now();
    let built = client
        .build_on_own_block_chaining(&sealed, next, Some(ChainAhead { view: 8 }))
        .await
        .expect("answered")
        .expect("built");
    assert_eq!(built.number, 42);
    assert!(
        at.elapsed() < std::time::Duration::from_millis(500),
        "the refusal was already known; nothing was waited out"
    );
}

/// One ahead, never two. The execution layer offers a chain header for the
/// chained build as well; while nobody has taken the first, the second must
/// not start.
#[tokio::test]
async fn at_most_one_chained_build_is_outstanding() {
    let (el, client) = fleet(true).await;
    client.set_chain_sealer(sealer());
    client
        .build_on_own_block_chaining(&parent(), attrs(1_000), Some(ChainAhead { view: 7 }))
        .await
        .expect("answered")
        .expect("built");

    // The chained request is answered with a chain header of its own, which
    // would start a third build if the slot were not held. Give it time to.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let asked = el.asked.lock().expect("not poisoned").clone();
    assert_eq!(asked.len(), 2, "the chain runs one block ahead of the last request and no further");
}

