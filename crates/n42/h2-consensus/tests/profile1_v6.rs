// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's profile-1 vector V6 (consensus messages,
//! `testdata/profile1/gov5/V6`, a byte-exact copy) against this node's codec,
//! signing domains and engine.
//!
//! - Bytes: every message's H2-v4 preimage, signature (signed here with the
//!   vector's test keys and verified), SSZ wire, envelope and snappy gossip
//!   form equal gov5's; every certificate verifies against the genesis set.
//! - Sizes: QC, Decide, NewView at n = 4, 100 (gov5's full Decide and
//!   NewView verified against its 100 keys) and 512.
//! - Verdicts: each of gov5's 19 cases replayed on a profile-1 engine
//!   (`VoteRules::PROFILE1`, H2-v4 signing, tenure 1) built from the
//!   vector's four validators, with the refused inputs built as the case
//!   describes them.

use alloy_primitives::B256;
use n42_h2_consensus::{
    protocol::quorum::{verify_commit_qc_with_profile, verify_qc_with_profile, verify_tc_with_profile, ConsensusSigningProfile},
    wire_bridge, ConsensusEngine, ConsensusEvent, EngineOutput, ValidatorInfo, ValidatorSet, VoteRules,
};
use n42_h2_primitives::{
    bls::AggregateSignature,
    consensus::{ConsensusMessage, H2V4ChainIdentity, QuorumCertificate},
    BlsPublicKey, BlsSecretKey, BlsSignature,
};
use n42_h2_wire::{
    h2_v4::{self, H2V4Envelope},
    h2_wire::{self, H2Message, H2QuorumCertificate},
};
use serde_json::Value;
use tokio::sync::mpsc;

fn vector() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/profile1/gov5/V6/consensus_messages_v6.json");
    serde_json::from_slice(&std::fs::read(path).expect("V6")).expect("json")
}

fn hex(value: &Value) -> Vec<u8> {
    alloy_primitives::hex::decode(value.as_str().expect("hex string")).expect("hex")
}

fn number(value: &Value) -> u64 {
    value.as_u64().unwrap_or_else(|| value.as_str().expect("a number").parse().expect("decimal"))
}

struct V6 {
    json: Value,
    identity: H2V4ChainIdentity,
    profile: ConsensusSigningProfile,
    sks: Vec<BlsSecretKey>,
    set: ValidatorSet,
}

fn load() -> V6 {
    let json = vector();
    let identity = H2V4ChainIdentity {
        chain_id: number(&json["chainId"]),
        genesis_hash: B256::from_slice(&hex(&json["genesisHash"])),
    };
    let mut sks = Vec::new();
    let mut infos = Vec::new();
    for v in json["validators"].as_array().expect("validators") {
        let sk = BlsSecretKey::from_bytes(&hex(&v["blsSecretKey"]).try_into().expect("32 bytes")).expect("a key");
        let pk = BlsPublicKey::from_bytes(&hex(&v["blsPublicKey"]).try_into().expect("48 bytes")).expect("a key");
        assert_eq!(sk.public_key().to_bytes(), pk.to_bytes(), "the secret key is the public key's");
        infos.push(ValidatorInfo {
            address: v["address"].as_str().expect("address").parse().expect("address"),
            bls_public_key: pk,
            p2p_peer_id: None,
        });
        sks.push(sk);
    }
    // f = 1 of 4, quorum 3 (the genesis set, AM5).
    let set = ValidatorSet::new(&infos, 1);
    V6 { json, identity, profile: ConsensusSigningProfile::H2V4(identity), sks, set }
}

impl V6 {
    fn message(&self, name: &str) -> &Value {
        self.json["messages"].as_array().expect("messages").iter().find(|m| m["name"] == name).expect(name)
    }

    fn envelope(&self, name: &str) -> H2V4Envelope {
        h2_v4::decode_gossip(&hex(&self.message(name)["gossipSnappy"]), self.identity).expect("gov5's gossip decodes")
    }

    fn wire(&self, name: &str) -> H2Message {
        self.envelope(name).message
    }

    fn engine_message(&self, message: H2Message) -> Result<ConsensusMessage, wire_bridge::BridgeError> {
        let envelope = H2V4Envelope { identity: self.identity, changes_hash: B256::ZERO, message };
        wire_bridge::to_engine(&envelope, 4)
    }

    fn engine(&self, me: u32) -> (ConsensusEngine, mpsc::Receiver<EngineOutput>) {
        let (tx, rx) = mpsc::channel(4096);
        let mut engine = ConsensusEngine::new(me, self.sks[me as usize].clone(), self.set.clone(), 24_000, 96_000, tx);
        engine.enable_h2_v4_signing(self.identity);
        engine.set_vote_rules(VoteRules::PROFILE1);
        engine.set_leader_tenure(number(&self.json["leaderTenure"]));
        engine.set_two_phase_vote_gate(true);
        (engine, rx)
    }

    /// An aggregate over `preimage` by `keys` with a 4-wide bitmap of
    /// validators 0, 1, 2 (gov5's form: u16 count then the bits).
    fn aggregate(&self, keys: &[BlsSecretKey], preimage: &[u8]) -> Vec<u8> {
        let sigs: Vec<BlsSignature> = keys.iter().map(|sk| self.profile.sign(sk, preimage)).collect();
        let refs: Vec<&BlsSignature> = sigs.iter().collect();
        AggregateSignature::aggregate(&refs).expect("an aggregate").to_bytes().to_vec()
    }

    fn quorum_keys(&self) -> Vec<BlsSecretKey> {
        self.sks[..3].to_vec()
    }
}

/// Four keys of a set that is not the genesis set.
fn foreign_keys() -> Vec<BlsSecretKey> {
    (0..3u8).map(|i| BlsSecretKey::key_gen(&[0xf0 + i; 32]).expect("a key")).collect()
}

fn signature_bytes(sig: &BlsSignature) -> Vec<u8> {
    sig.to_bytes().to_vec()
}

fn outputs(rx: &mut mpsc::Receiver<EngineOutput>) -> Vec<EngineOutput> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

/// The single signature, signer and preimage a message carries, or the
/// certificate's aggregate with its preimage.
fn signed_part(v6: &V6, message: &H2Message) -> (Vec<u8>, Vec<u8>, Option<u32>) {
    let id = v6.identity;
    match message {
        H2Message::Proposal(p) => (
            h2_v4::proposal_signing_message(id, p.view, p.block_hash, B256::ZERO).to_vec(),
            signature_bytes(&p.signature),
            Some(p.proposer),
        ),
        H2Message::Vote(v) => (h2_v4::vote_signing_message(id, v.view, v.block_hash).to_vec(), signature_bytes(&v.signature), Some(v.voter)),
        H2Message::CommitVote(v) => (
            h2_v4::commit_signing_message(id, v.view, v.block_hash, B256::ZERO).to_vec(),
            signature_bytes(&v.signature),
            Some(v.voter),
        ),
        H2Message::PrepareQc(q) => (h2_v4::vote_signing_message(id, q.qc.view, q.qc.block_hash).to_vec(), q.qc.aggregate_signature.clone(), None),
        H2Message::Decide(d) => (
            h2_v4::commit_signing_message(id, d.commit_qc.view, d.commit_qc.block_hash, B256::ZERO).to_vec(),
            d.commit_qc.aggregate_signature.clone(),
            None,
        ),
        H2Message::Timeout(t) => (h2_v4::timeout_signing_message(id, t.view).to_vec(), signature_bytes(&t.signature), Some(t.sender)),
        H2Message::NewView(n) => (h2_v4::new_view_signing_message(id, n.view).to_vec(), signature_bytes(&n.signature), Some(n.leader)),
    }
}

fn engine_qc(qc: &H2QuorumCertificate, n: usize) -> QuorumCertificate {
    wire_bridge::qc_to_engine(qc, n, "test").expect("a canonical QC")
}

/// Every message: preimage, signature, wire, envelope and gossip bytes equal
/// gov5's, the signature is what this node signs with the same key, and
/// every certificate inside verifies against the genesis set.
#[test]
fn v6_message_bytes_equal_gov5() {
    let v6 = load();
    let messages = v6.json["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 8);
    for m in messages {
        let name = m["name"].as_str().expect("name");
        let gossip = hex(&m["gossipSnappy"]);
        let envelope = h2_v4::decode_gossip(&gossip, v6.identity).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(envelope.changes_hash, B256::ZERO, "{name}");
        assert_eq!(h2_wire::encode_message(&envelope.message).expect("encodes"), hex(&m["wire"]), "{name}: wire");
        assert_eq!(h2_v4::encode_envelope(&envelope).expect("encodes"), hex(&m["h2v4Envelope"]), "{name}: envelope");
        assert_eq!(h2_v4::encode_gossip(&envelope).expect("encodes"), gossip, "{name}: snappy");
        assert_eq!(number(&m["view"]), message_view(&envelope.message), "{name}: view");

        let (preimage, signature, signer) = signed_part(&v6, &envelope.message);
        assert_eq!(preimage, hex(&m["signingPreimage"]), "{name}: preimage");
        assert_eq!(signature, hex(&m["signature"]), "{name}: signature");
        match signer {
            Some(i) => {
                let ours = v6.profile.sign(&v6.sks[i as usize], &preimage);
                assert_eq!(signature_bytes(&ours), signature, "{name}: this node signs the same bytes");
                assert!(v6.profile.verify_single(&v6.sks[i as usize].public_key(), &preimage, &ours), "{name}");
            }
            None => assert_eq!(v6.aggregate(&v6.quorum_keys(), &preimage), signature, "{name}: the same aggregate"),
        }

        // Every certificate the message carries, in its domain.
        match &envelope.message {
            H2Message::Proposal(p) => verify_qc_with_profile(&engine_qc(&p.justify_qc, 4), &v6.set, v6.profile)
                .or_else(|_| verify_commit_qc_with_profile(&engine_qc(&p.justify_qc, 4), &v6.set, &B256::ZERO, v6.profile))
                .unwrap_or_else(|e| panic!("{name}: justify {e}")),
            H2Message::PrepareQc(q) => verify_qc_with_profile(&engine_qc(&q.qc, 4), &v6.set, v6.profile).expect("PrepareQC"),
            H2Message::Decide(d) => {
                verify_commit_qc_with_profile(&engine_qc(&d.commit_qc, 4), &v6.set, &B256::ZERO, v6.profile).expect("CommitQC")
            }
            H2Message::Timeout(t) => verify_qc_with_profile(&engine_qc(&t.high_qc, 4), &v6.set, v6.profile).expect("highQC"),
            H2Message::NewView(n) => {
                let tc = wire_bridge::tc_to_engine(&n.timeout_certificate, 4).expect("a canonical TC");
                verify_tc_with_profile(&tc, &v6.set, v6.profile).expect("TC");
                verify_qc_with_profile(&tc.high_qc, &v6.set, v6.profile).expect("TC highQC");
            }
            H2Message::Vote(_) | H2Message::CommitVote(_) => {}
        }
    }
}

fn message_view(message: &H2Message) -> u64 {
    match message {
        H2Message::Proposal(p) => p.view,
        H2Message::Vote(v) | H2Message::CommitVote(v) => v.view,
        H2Message::PrepareQc(q) => q.view,
        H2Message::Timeout(t) => t.view,
        H2Message::NewView(n) => n.view,
        H2Message::Decide(d) => d.view,
    }
}

fn bitmap(n: usize, signers: usize) -> Vec<u8> {
    let mut out = (n as u16).to_le_bytes().to_vec();
    let mut bits = vec![0u8; n.div_ceil(8)];
    for i in 0..signers {
        bits[i / 8] |= 1 << (i % 8);
    }
    out.extend(bits);
    out
}

/// QC, Decide and NewView sizes at n = 4, 100 and 512; gov5's n = 100
/// Decide and NewView decode, re-encode byte for byte and verify against its
/// 100 keys.
#[test]
fn v6_sizes_and_the_100_member_certificates() {
    let v6 = load();
    for size in v6.json["sizes"].as_array().expect("sizes") {
        let n = number(&size["n"]) as usize;
        let quorum = number(&size["quorum"]) as usize;
        assert_eq!(quorum, n - (n - 1) / 3, "n = {n}: quorum 2f + 1");
        let (decide, new_view) = if n == 4 {
            (v6.wire("decide_v2"), v6.wire("newview_tc_epoch_boundary"))
        } else if n == 100 {
            let decide = h2_wire::decode_message(&hex(&size["decideWire"])).expect("gov5's Decide decodes");
            let new_view = h2_wire::decode_message(&hex(&size["newViewWire"])).expect("gov5's NewView decodes");
            assert_eq!(h2_wire::encode_message(&decide).expect("encodes"), hex(&size["decideWire"]));
            assert_eq!(h2_wire::encode_message(&new_view).expect("encodes"), hex(&size["newViewWire"]));
            let infos: Vec<ValidatorInfo> = size["blsPublicKeys"]
                .as_array()
                .expect("keys")
                .iter()
                .enumerate()
                .map(|(i, key)| ValidatorInfo {
                    address: alloy_primitives::Address::with_last_byte(i as u8),
                    bls_public_key: BlsPublicKey::from_bytes(&hex(key).try_into().expect("48 bytes")).expect("a key"),
                    p2p_peer_id: None,
                })
                .collect();
            let set = ValidatorSet::new(&infos, 33);
            assert_eq!(set.quorum_size(), quorum);
            let H2Message::Decide(d) = &decide else { panic!("a Decide") };
            verify_commit_qc_with_profile(&engine_qc(&d.commit_qc, n), &set, &B256::ZERO, v6.profile).expect("the 100-member CommitQC");
            let H2Message::NewView(nv) = &new_view else { panic!("a NewView") };
            let tc = wire_bridge::tc_to_engine(&nv.timeout_certificate, n).expect("a canonical TC");
            verify_tc_with_profile(&tc, &set, v6.profile).expect("the 100-member TC");
            verify_qc_with_profile(&tc.high_qc, &set, v6.profile).expect("the TC's highQC");
            assert!(v6.profile.verify_single(set.get_public_key(nv.leader).expect("leader"), &h2_v4::new_view_signing_message(v6.identity, nv.view), &nv.signature));
            (decide, new_view)
        } else {
            // n = 512: the shapes, with placeholder signatures (the sizes
            // depend on n alone).
            let mut decide = v6.wire("decide_v2");
            let mut new_view = v6.wire("newview_tc_epoch_boundary");
            if let H2Message::Decide(d) = &mut decide {
                d.commit_qc.signers_bitmap = bitmap(n, quorum);
            }
            if let H2Message::NewView(nv) = &mut new_view {
                nv.timeout_certificate.signers_bitmap = bitmap(n, quorum);
                nv.timeout_certificate.high_qc.signers_bitmap = bitmap(n, quorum);
            }
            (decide, new_view)
        };
        let H2Message::Decide(d) = &decide else { panic!("a Decide") };
        let qc_len = h2_wire::encode_h2_qc(&d.commit_qc).expect("a QC").len();
        let decide_len = h2_wire::encode_message(&decide).expect("encodes").len();
        let nv_envelope = H2V4Envelope { identity: v6.identity, changes_hash: B256::ZERO, message: new_view.clone() };
        let nv_len = h2_wire::encode_message(&new_view).expect("encodes").len();
        let envelope_len = h2_v4::encode_envelope(&nv_envelope).expect("encodes").len();
        assert_eq!(
            (qc_len as u64, decide_len as u64, nv_len as u64, envelope_len as u64),
            (
                number(&size["qcSszBytes"]),
                number(&size["decideWireBytes"]),
                number(&size["newViewWireBytes"]),
                number(&size["newViewEnvelopeBytes"])
            ),
            "n = {n}"
        );
        // The TC: the NewView wire less the TC is 121 bytes at every n (the
        // kind byte, view, leader, signature and offsets), so gov5's TC size
        // is the one this codec writes.
        assert_eq!(nv_len as u64 - number(&size["tcSszBytes"]), 121, "n = {n}: TC size");
        if n != 512 {
            let gossip_len = h2_v4::encode_gossip(&nv_envelope).expect("encodes").len();
            assert_eq!(gossip_len as u64, number(&size["newViewGossipBytes"]), "n = {n}: gossip");
        }
    }
}

// ------------------------------------------------------------- verdicts --

/// `round1_gate`: proposal_v2 to validator 0. The header alone casts no
/// vote, nor does the check without the import ... in this engine the
/// execution layer's check (`BlockChecked`) is the release, and it cannot pass
/// before the parent's import (the check compares the header's carried
/// execution with this node's own execution of the parent). The vote cast is
/// gov5's prepare_vote_v2, byte for byte.
#[test]
fn v6_round1_gate() {
    let v6 = load();
    let (mut engine, mut rx) = v6.engine(0);
    let proposal = v6.engine_message(v6.wire("proposal_v2")).expect("bridged");
    let ConsensusMessage::Proposal(p) = &proposal else { panic!("a proposal") };
    let (block, parent) = (p.block_hash, p.justify_qc.block_hash);
    engine.process_event(ConsensusEvent::Message(proposal)).expect("proposal_v2 accepted");
    engine.header_known(block, parent).expect("the header");
    assert_eq!(votes(&outputs(&mut rx)).len(), 0, "no Round 1 on the header");
    engine.process_event(ConsensusEvent::BlockChecked(block)).expect("the check");
    let cast = votes(&outputs(&mut rx));
    assert_eq!(cast.len(), 1, "Round 1 on the check");
    let gov5 = v6.wire("prepare_vote_v2");
    let H2Message::Vote(want) = &gov5 else { panic!("a vote") };
    assert_eq!((cast[0].view, cast[0].block_hash, cast[0].voter), (want.view, want.block_hash, want.voter));
    assert_eq!(cast[0].signature, want.signature, "prepare_vote_v2 byte for byte");
}

fn votes(out: &[EngineOutput]) -> Vec<n42_h2_primitives::consensus::Vote> {
    out.iter()
        .filter_map(|o| match o {
            EngineOutput::SendToValidator(_, ConsensusMessage::Vote(v)) | EngineOutput::BroadcastMessage(ConsensusMessage::Vote(v)) => Some(v.clone()),
            _ => None,
        })
        .collect()
}

fn commit_votes(out: &[EngineOutput]) -> Vec<n42_h2_primitives::consensus::CommitVote> {
    out.iter()
        .filter_map(|o| match o {
            EngineOutput::SendToValidator(_, ConsensusMessage::CommitVote(v))
            | EngineOutput::BroadcastMessage(ConsensusMessage::CommitVote(v)) => Some(v.clone()),
            _ => None,
        })
        .collect()
}

/// `round1_refused_block`: a block whose check fails (the execution layer
/// rejects it) gets no prepare vote, imported or not.
#[test]
fn v6_round1_refused_block() {
    let v6 = load();
    let (mut engine, mut rx) = v6.engine(0);
    let proposal = v6.engine_message(v6.wire("proposal_v2")).expect("bridged");
    let ConsensusMessage::Proposal(p) = &proposal else { panic!("a proposal") };
    let (block, parent) = (p.block_hash, p.justify_qc.block_hash);
    engine.process_event(ConsensusEvent::Message(proposal)).expect("accepted");
    engine.header_known(block, parent).expect("the header");
    engine.process_event(ConsensusEvent::BlockRejected(block)).expect("the rejection");
    assert!(votes(&outputs(&mut rx)).is_empty(), "no Round 1 on a refused block");
}

/// `round2_gate`: after Round 1, prepare_qc_v2 casts no commit vote until
/// this node's own import of block 2 (and, AM35, its durable write); then
/// gov5's commit_vote_v2.
#[test]
fn v6_round2_gate() {
    let v6 = load();
    let (mut engine, mut rx) = v6.engine(0);
    let proposal = v6.engine_message(v6.wire("proposal_v2")).expect("bridged");
    let ConsensusMessage::Proposal(p) = &proposal else { panic!("a proposal") };
    let (block, parent) = (p.block_hash, p.justify_qc.block_hash);
    engine.process_event(ConsensusEvent::Message(proposal)).expect("accepted");
    engine.header_known(block, parent).expect("the header");
    engine.process_event(ConsensusEvent::BlockChecked(block)).expect("the check");
    let _ = outputs(&mut rx);
    let pqc = v6.engine_message(v6.wire("prepare_qc_v2")).expect("bridged");
    engine.process_event(ConsensusEvent::Message(pqc)).expect("prepare_qc_v2 accepted");
    assert!(commit_votes(&outputs(&mut rx)).is_empty(), "no commit vote on the check alone");
    engine.process_event(ConsensusEvent::BlockImported(block)).expect("the import");
    // AM35: and on the block's durable write here (the node's journal).
    assert!(commit_votes(&outputs(&mut rx)).is_empty(), "no commit vote before the block is durable (AM35)");
    engine.process_event(ConsensusEvent::BlockDurable(block)).expect("durable");
    let cast = commit_votes(&outputs(&mut rx));
    assert_eq!(cast.len(), 1, "the commit vote on the own import and the durable write");
    let gov5 = v6.wire("commit_vote_v2");
    let H2Message::CommitVote(want) = &gov5 else { panic!("a commit vote") };
    assert_eq!(cast[0].signature, want.signature, "commit_vote_v2 byte for byte");
}

fn resigned_proposal(v6: &V6, signer: u32, preimage: &[u8], mut edit: impl FnMut(&mut h2_wire::H2Proposal)) -> ConsensusMessage {
    let mut wire = v6.wire("proposal_v2");
    let H2Message::Proposal(p) = &mut wire else { panic!("a proposal") };
    edit(p);
    p.proposer = signer;
    p.signature = v6.profile.sign(&v6.sks[signer as usize], preimage);
    v6.engine_message(wire).expect("bridged")
}

fn refused(engine: &mut ConsensusEngine, message: ConsensusMessage) -> String {
    engine.process_event(ConsensusEvent::Message(message)).expect_err("refused").to_string()
}

/// `proposal_wrong_proposer`, `proposal_vote_domain_signature`,
/// `proposal_justify_foreign_set`.
#[test]
fn v6_proposal_refusals() {
    let v6 = load();
    let H2Message::Proposal(p) = v6.wire("proposal_v2") else { panic!("a proposal") };
    let proposal_preimage = h2_v4::proposal_signing_message(v6.identity, p.view, p.block_hash, B256::ZERO);
    let vote_preimage = h2_v4::vote_signing_message(v6.identity, p.view, p.block_hash);

    let (mut engine, _rx) = v6.engine(0);
    let err = refused(&mut engine, resigned_proposal(&v6, 3, &proposal_preimage, |_| {}));
    println!("proposal_wrong_proposer: {err}");
    assert!(err.to_lowercase().contains("proposer"), "{err}");

    let (mut engine, _rx) = v6.engine(0);
    let err = refused(&mut engine, resigned_proposal(&v6, 2, &vote_preimage, |_| {}));
    println!("proposal_vote_domain_signature: {err}");
    assert!(err.to_lowercase().contains("signature"), "{err}");

    let (mut engine, _rx) = v6.engine(0);
    let justify_preimage = h2_v4::vote_signing_message(v6.identity, p.justify_qc.view, p.justify_qc.block_hash);
    let foreign = v6.aggregate(&foreign_keys(), &justify_preimage);
    let err = refused(&mut engine, resigned_proposal(&v6, 2, &proposal_preimage, |p| p.justify_qc.aggregate_signature = foreign.clone()));
    println!("proposal_justify_foreign_set: {err}");
    assert!(err.to_lowercase().contains("quorum") || err.to_lowercase().contains("qc"), "{err}");
}

/// `lock_refuses_lower_justify` and `lock_moves_to_higher_justify`: a view-3
/// proposal (leader 3) justified by the view-1 QC is refused by a node locked
/// on the view-2 PrepareQC; one on block 2 justified by that PrepareQC is
/// accepted by a node locked at view 1, which moves its lock to view 2.
#[test]
fn v6_lock_rules() {
    let v6 = load();
    let H2Message::Proposal(p2) = v6.wire("proposal_v2") else { panic!("a proposal") };
    let H2Message::PrepareQc(pqc2) = v6.wire("prepare_qc_v2") else { panic!("a PrepareQC") };
    let view1_qc = p2.justify_qc.clone();
    let block3 = B256::repeat_byte(0x33);
    let proposal3 = |justify: H2QuorumCertificate| {
        let mut wire = v6.wire("proposal_v2");
        let H2Message::Proposal(p) = &mut wire else { panic!("a proposal") };
        p.view = 3;
        p.block_hash = block3;
        p.justify_qc = justify;
        p.proposer = 3;
        p.signature = v6.profile.sign(&v6.sks[3], &h2_v4::proposal_signing_message(v6.identity, 3, block3, B256::ZERO));
        v6.engine_message(wire).expect("bridged")
    };
    // A node that saw proposal_v2 and prepare_qc_v2: locked at view 2.
    let locked_at_2 = || {
        let (mut engine, rx) = v6.engine(0);
        let proposal = v6.engine_message(v6.wire("proposal_v2")).expect("bridged");
        engine.process_event(ConsensusEvent::Message(proposal)).expect("accepted");
        engine.header_known(p2.block_hash, view1_qc.block_hash).expect("the header");
        engine.process_event(ConsensusEvent::BlockChecked(p2.block_hash)).expect("the check");
        let pqc = v6.engine_message(H2Message::PrepareQc(pqc2.clone())).expect("bridged");
        engine.process_event(ConsensusEvent::Message(pqc)).expect("accepted");
        (engine, rx)
    };
    let (mut engine, _rx) = locked_at_2();
    assert_eq!(engine.locked_qc().view, 2, "locked on the view-2 PrepareQC");
    // To view 3, where the proposal is judged (a proposal for a later view
    // is held until then): block 2's Decide.
    let decide = v6.engine_message(v6.wire("decide_v2")).expect("bridged");
    engine.process_event(ConsensusEvent::Message(decide)).expect("decide_v2");
    assert_eq!((engine.current_view(), engine.locked_qc().view), (3, 2));
    let err = refused(&mut engine, proposal3(view1_qc.clone()));
    println!("lock_refuses_lower_justify: {err}");
    assert!(err.to_lowercase().contains("lock") || err.to_lowercase().contains("safety"), "{err}");

    // Locked at view 1 (proposal_v2 seen, no PrepareQC yet): the view-3
    // proposal justified by the view-2 PrepareQC is accepted, the lock moves,
    // and the prepare vote follows the check.
    let (mut engine, mut rx) = v6.engine(0);
    let proposal = v6.engine_message(v6.wire("proposal_v2")).expect("bridged");
    engine.process_event(ConsensusEvent::Message(proposal)).expect("accepted");
    assert_eq!(engine.locked_qc().view, 1);
    engine.process_event(ConsensusEvent::Message(proposal3(pqc2.qc.clone()))).expect("accepted");
    assert_eq!(engine.locked_qc().view, 2, "the lock moved to view 2");
    engine.header_known(block3, p2.block_hash).expect("the header");
    engine.process_event(ConsensusEvent::BlockChecked(block3)).expect("the check");
    assert!(votes(&outputs(&mut rx)).iter().any(|v| v.view == 3 && v.block_hash == block3), "the prepare vote for view 3");
}

/// `prepare_qc_foreign_set`, `prepare_qc_legacy_domain`,
/// `prepare_qc_commit_domain`: each refused by the PrepareQC check.
#[test]
fn v6_prepare_qc_refusals() {
    let v6 = load();
    let H2Message::PrepareQc(pqc) = v6.wire("prepare_qc_v2") else { panic!("a PrepareQC") };
    let H2Message::Decide(decide) = v6.wire("decide_v2") else { panic!("a Decide") };
    let vote_preimage = h2_v4::vote_signing_message(v6.identity, pqc.view, pqc.block_hash);
    let legacy_preimage = h2_wire::gov5_prepare_signing_message(pqc.view, pqc.block_hash);
    let cases = [
        ("prepare_qc_foreign_set", v6.aggregate(&foreign_keys(), &vote_preimage)),
        ("prepare_qc_legacy_domain", v6.aggregate(&v6.quorum_keys(), &legacy_preimage)),
        ("prepare_qc_commit_domain", decide.commit_qc.aggregate_signature.clone()),
    ];
    for (name, aggregate) in cases {
        let mut bad = pqc.clone();
        bad.qc.aggregate_signature = aggregate;
        // The certificate check itself.
        let err = verify_qc_with_profile(&engine_qc(&bad.qc, 4), &v6.set, v6.profile).expect_err(name).to_string();
        println!("{name}: {err}");
        // And on the engine, at the view it is for.
        let (mut engine, mut rx) = v6.engine(0);
        let proposal = v6.engine_message(v6.wire("proposal_v2")).expect("bridged");
        engine.process_event(ConsensusEvent::Message(proposal)).expect("accepted");
        engine.header_known(pqc.block_hash, B256::ZERO).ok();
        engine.process_event(ConsensusEvent::BlockChecked(pqc.block_hash)).expect("the check");
        engine.process_event(ConsensusEvent::BlockImported(pqc.block_hash)).expect("the import");
        let _ = outputs(&mut rx);
        let message = v6.engine_message(H2Message::PrepareQc(bad)).expect("bridged");
        let result = engine.process_event(ConsensusEvent::Message(message));
        println!("{name} on the engine: {result:?}");
        assert!(result.is_err(), "{name}: refused");
        assert!(commit_votes(&outputs(&mut rx)).is_empty(), "{name}: no commit vote");
        assert_eq!(engine.locked_qc().view, 1, "{name}: the lock did not move");
    }
}

/// `decide_valid`, `decide_prepare_domain`, `decide_foreign_set`,
/// `decide_wrong_width`.
#[test]
fn v6_decide_verdicts() {
    let v6 = load();
    let H2Message::Decide(decide) = v6.wire("decide_v2") else { panic!("a Decide") };
    let H2Message::PrepareQc(pqc) = v6.wire("prepare_qc_v2") else { panic!("a PrepareQC") };

    let (mut engine, mut rx) = v6.engine(0);
    engine.process_event(ConsensusEvent::Message(v6.engine_message(H2Message::Decide(decide.clone())).expect("bridged"))).expect("decide_valid");
    let out = outputs(&mut rx);
    assert!(
        out.iter().any(|o| matches!(o, EngineOutput::BlockCommitted { block_hash, .. } if *block_hash == decide.block_hash)),
        "block 2 committed: {out:?}"
    );
    assert_eq!(engine.current_view(), 3, "the view advances to 3");

    let commit_preimage = h2_v4::commit_signing_message(v6.identity, decide.view, decide.block_hash, B256::ZERO);
    for (name, aggregate) in [
        ("decide_prepare_domain", pqc.qc.aggregate_signature.clone()),
        ("decide_foreign_set", v6.aggregate(&foreign_keys(), &commit_preimage)),
    ] {
        let mut bad = decide.clone();
        bad.commit_qc.aggregate_signature = aggregate;
        let (mut engine, mut rx) = v6.engine(0);
        let err = refused(&mut engine, v6.engine_message(H2Message::Decide(bad)).expect("bridged"));
        println!("{name}: {err}");
        assert!(err.to_lowercase().contains("commit qc"), "{name}: {err}");
        assert!(!outputs(&mut rx).iter().any(|o| matches!(o, EngineOutput::BlockCommitted { .. })), "{name}: not committed");
    }

    // A 5-bit bitmap for a 4-member set: refused where the wire meets the
    // engine (the bridge reads a bitmap only against the set's width).
    let mut bad = decide.clone();
    bad.commit_qc.signers_bitmap = bitmap(5, 3);
    let err = v6.engine_message(H2Message::Decide(bad)).expect_err("decide_wrong_width");
    println!("decide_wrong_width: {err}");
    assert!(matches!(err, wire_bridge::BridgeError::InvalidBitmap { expected: 4, .. }), "{err}");
}

fn new_view_with(v6: &V6, edit: impl FnOnce(&mut h2_wire::H2NewView)) -> ConsensusMessage {
    let mut wire = v6.wire("newview_tc_epoch_boundary");
    let H2Message::NewView(nv) = &mut wire else { panic!("a NewView") };
    edit(nv);
    v6.engine_message(wire).expect("bridged")
}

/// `tc_epoch_boundary_follower`, `tc_foreign_set`, `tc_wrong_next_view`,
/// `tc_leader_proposes_on_high_qc`.
#[test]
fn v6_timeout_certificate_verdicts() {
    let v6 = load();
    let H2Message::NewView(nv) = v6.wire("newview_tc_epoch_boundary") else { panic!("a NewView") };
    let epoch_length = number(&v6.json["epochLength"]);
    assert_eq!(nv.view, epoch_length + 1, "the NewView lands one view past the TC (tenure 1)");

    // Follower: view 10801, lock = the TC's highQC (view 2), set unchanged.
    let (mut engine, _rx) = v6.engine(0);
    engine.process_event(ConsensusEvent::Message(new_view_with(&v6, |_| {}))).expect("tc_epoch_boundary_follower");
    assert_eq!(engine.current_view(), nv.view);
    assert_eq!(engine.locked_qc().view, nv.timeout_certificate.high_qc.view);

    // A TC aggregated by a foreign set.
    let timeout_preimage = h2_v4::timeout_signing_message(v6.identity, nv.timeout_certificate.view);
    let foreign = v6.aggregate(&foreign_keys(), &timeout_preimage);
    let (mut engine, _rx) = v6.engine(0);
    let err = refused(&mut engine, new_view_with(&v6, |nv| nv.timeout_certificate.aggregate_signature = foreign));
    println!("tc_foreign_set: {err}");
    assert!(err.contains("timeout certificate") || err.contains("TC"), "{err}");
    assert_eq!(engine.current_view(), 1, "view unchanged");

    // A NewView for view 10802 (signed by its leader) carrying the TC of 10800.
    let (mut engine, _rx) = v6.engine(0);
    let view = nv.view + 1;
    // Tenure 1: the leader of view v is validator v mod 4 (leader(2) = 2 and
    // leader(10801) = 1 in the vector).
    let leader = (view % 4) as u32;
    let err = refused(
        &mut engine,
        new_view_with(&v6, |nv| {
            nv.view = view;
            nv.leader = leader;
            nv.signature = v6.profile.sign(&v6.sks[leader as usize], &h2_v4::new_view_signing_message(v6.identity, view));
        }),
    );
    println!("tc_wrong_next_view: {err}");
    assert!(err.contains("does not precede"), "{err}");

    // The leader of the boundary view proposes on the TC's highQC: gov5's
    // proposal_after_tc, byte for byte.
    let H2Message::Proposal(after) = v6.wire("proposal_after_tc") else { panic!("a proposal") };
    let (mut engine, mut rx) = v6.engine(after.proposer);
    assert_eq!((nv.view % 4) as u32, after.proposer);
    engine.process_event(ConsensusEvent::Message(new_view_with(&v6, |_| {}))).expect("the NewView");
    engine.process_event(ConsensusEvent::BlockReady(after.block_hash, None)).expect("block ready");
    let proposed: Vec<_> = outputs(&mut rx)
        .into_iter()
        .filter_map(|o| match o {
            EngineOutput::BroadcastMessage(ConsensusMessage::Proposal(p)) => Some(p),
            _ => None,
        })
        .collect();
    assert_eq!(proposed.len(), 1, "one proposal");
    let wire = wire_bridge::to_wire(&ConsensusMessage::Proposal(proposed[0].clone()), v6.identity, B256::ZERO).expect("to wire");
    assert_eq!(
        h2_wire::encode_message(&wire.message).expect("encodes"),
        hex(&v6.message("proposal_after_tc")["wire"]),
        "proposal_after_tc byte for byte"
    );
}

/// Every verdict case of the file is one of the tests above.
#[test]
fn v6_every_verdict_case_is_covered() {
    let covered = [
        "round1_gate",
        "round1_refused_block",
        "proposal_wrong_proposer",
        "proposal_vote_domain_signature",
        "proposal_justify_foreign_set",
        "lock_refuses_lower_justify",
        "lock_moves_to_higher_justify",
        "round2_gate",
        "prepare_qc_foreign_set",
        "prepare_qc_legacy_domain",
        "prepare_qc_commit_domain",
        "decide_prepare_domain",
        "decide_foreign_set",
        "decide_wrong_width",
        "decide_valid",
        "tc_epoch_boundary_follower",
        "tc_leader_proposes_on_high_qc",
        "tc_foreign_set",
        "tc_wrong_next_view",
    ];
    let v6 = load();
    let cases: Vec<&str> = v6.json["verdicts"].as_array().expect("verdicts").iter().map(|v| v["case"].as_str().expect("case")).collect();
    assert_eq!(cases, covered);
}
