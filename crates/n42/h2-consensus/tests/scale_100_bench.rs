// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the consensus certificates cost at 100+ validators (AM17 / AM22 of
//! `docs/MIXED_PRODUCTION_STANDARD.md`). Measurement only, no criterion:
//!
//! ```text
//! cargo test --release -p n42-h2-consensus --test scale_100_bench -- --ignored --nocapture
//! ```
//!
//! Every number is the best of `BENCH_REPS` (default 5) on one thread, under
//! the H2-v4 profile (the mixed fleet's ciphersuite). Results:
//! `docs/SCALE_100_VALIDATORS.md`.

use alloy_primitives::{Address, B256};
use n42_h2_consensus::header_profile::HeaderExtra;
use n42_h2_consensus::protocol::quorum::{
    verify_commit_qc_with_profile, verify_qc_any_domain_with_profile, verify_qc_with_profile,
    verify_tc_with_profile, ConsensusSigningProfile,
};
use n42_h2_consensus::wire_bridge::{qc_to_wire, tc_to_wire};
use n42_h2_consensus::{
    CommitteePoolConfig, SimulatedCommitteePool, TimeoutCollector, ValidatorInfo, ValidatorSet,
    VoteCollector,
};
use n42_h2_primitives::bls::AggregateSignature;
use n42_h2_primitives::consensus::{H2V4ChainIdentity, QuorumCertificate};
use n42_h2_primitives::{BlsSecretKey, BlsSignature};
use n42_h2_wire::h2_wire::{
    encode_h2_qc, H2Message, H2NewView, H2Proposal, H2Timeout, H2Vote,
};
use n42_h2_wire::encode_message;
use std::time::Instant;

fn reps() -> usize {
    std::env::var("BENCH_REPS").ok().and_then(|v| v.parse().ok()).unwrap_or(5)
}

/// Best wall time of `reps` runs, in microseconds.
fn best_us<T>(reps: usize, mut f: impl FnMut() -> T) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..reps {
        let start = Instant::now();
        std::hint::black_box(f());
        best = best.min(start.elapsed().as_secs_f64());
    }
    best * 1e6
}

fn profile() -> ConsensusSigningProfile {
    ConsensusSigningProfile::H2V4(H2V4ChainIdentity { chain_id: 94, genesis_hash: B256::repeat_byte(0x94) })
}

fn keys(n: usize) -> (Vec<BlsSecretKey>, ValidatorSet) {
    let sks: Vec<BlsSecretKey> = (0..n)
        .map(|i| {
            let mut ikm = [0x5au8; 32];
            ikm[..8].copy_from_slice(&(i as u64).to_le_bytes());
            BlsSecretKey::key_gen(&ikm).expect("key")
        })
        .collect();
    let infos: Vec<ValidatorInfo> = sks
        .iter()
        .enumerate()
        .map(|(i, sk)| ValidatorInfo {
            address: Address::left_padding_from(&(i as u64).to_be_bytes()),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        })
        .collect();
    let f = (n as u32 - 1) / 3;
    (sks, ValidatorSet::new(&infos, f))
}

const VIEW: u64 = 1_000;

fn block() -> B256 {
    B256::repeat_byte(0xb1)
}

/// A PrepareQC signed by the first quorum of the set.
fn prepare_qc(sks: &[BlsSecretKey], vs: &ValidatorSet) -> QuorumCertificate {
    let p = profile();
    let msg = p.vote_message(VIEW, block());
    let mut c = VoteCollector::new(VIEW, block(), vs.len());
    for (i, sk) in sks.iter().enumerate().take(vs.quorum_size()) {
        c.add_verified_vote(i as u32, p.sign(sk, &msg)).expect("distinct");
    }
    c.build_qc_with_profile_message(vs, &msg, p).expect("qc")
}

fn commit_qc(sks: &[BlsSecretKey], vs: &ValidatorSet) -> QuorumCertificate {
    let p = profile();
    let msg = p.commit_message(VIEW, block(), B256::ZERO);
    let mut c = VoteCollector::new(VIEW, block(), vs.len());
    for (i, sk) in sks.iter().enumerate().take(vs.quorum_size()) {
        c.add_verified_vote(i as u32, p.sign(sk, &msg)).expect("distinct");
    }
    c.build_qc_with_profile_message(vs, &msg, p).expect("qc")
}

#[test]
#[ignore = "measurement; run in release with --nocapture"]
fn scale_100_certificate_costs() {
    let reps = reps();
    let p = profile();
    println!("best of {reps}, one thread, H2-v4 ciphersuite; times in microseconds");

    // One vote.
    let (sks, vs) = keys(200);
    let msg = p.vote_message(VIEW, block());
    let sig = p.sign(&sks[0], &msg);
    let pk = vs.get_public_key(0).expect("pk").clone();
    println!("sign one vote             : {:8.1}", best_us(reps, || p.sign(&sks[0], &msg)));
    println!("verify one vote           : {:8.1}", best_us(reps, || p.verify_single(&pk, &msg, &sig)));

    println!();
    println!("| n | quorum | verify QC (prepare) | verify QC any-domain, commit QC | verify commit QC | verify TC | QC wire B | header extra B | TC wire B | NewView wire B | Timeout wire B | Proposal wire B |");
    println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    for n in [7usize, 100, 128, 200, 512] {
        let (sks, vs) = keys(n);
        let qc = prepare_qc(&sks, &vs);
        let cqc = commit_qc(&sks, &vs);
        let t_qc = best_us(reps, || verify_qc_with_profile(&qc, &vs, p).expect("valid"));
        // A commit QC through the any-domain path pays the prepare attempt first.
        let t_any = best_us(reps, || verify_qc_any_domain_with_profile(&cqc, &vs, &B256::ZERO, p).expect("valid"));
        let t_cqc = best_us(reps, || verify_commit_qc_with_profile(&cqc, &vs, &B256::ZERO, p).expect("valid"));

        // A TC from a quorum of timeouts, each carrying the same high QC.
        let tmsg = p.timeout_message(VIEW + 1);
        let mut tcol = TimeoutCollector::new(VIEW + 1, vs.len());
        for (i, sk) in sks.iter().enumerate().take(vs.quorum_size()) {
            tcol.add_verified_timeout(i as u32, p.sign(sk, &tmsg), qc.clone()).expect("distinct");
        }
        let tc = tcol.build_tc_with_profile(&vs, p).expect("tc");
        let t_tc = best_us(reps, || verify_tc_with_profile(&tc, &vs, p).expect("valid"));

        let wqc = qc_to_wire(&qc).expect("wire");
        let qc_bytes = encode_h2_qc(&wqc).expect("encode");
        let extra = HeaderExtra::with_committed_qc(VIEW, qc_bytes.clone()).encode();
        let wtc = tc_to_wire(&tc).expect("wire");
        let nv = encode_message(&H2Message::NewView(H2NewView {
            view: VIEW + 2,
            timeout_certificate: wtc.clone(),
            leader: 1,
            signature: sig.clone(),
        }))
        .expect("encode");
        let tmo = encode_message(&H2Message::Timeout(H2Timeout {
            view: VIEW + 2,
            high_qc: wqc.clone(),
            sender: 1,
            signature: sig.clone(),
            high_tc: Some(wtc.clone()),
        }))
        .expect("encode");
        let prop = encode_message(&H2Message::Proposal(H2Proposal {
            view: VIEW + 1,
            block_hash: block(),
            justify_qc: wqc.clone(),
            proposer: 1,
            signature: sig.clone(),
            prepare_qc: Some(wqc.clone()),
            tx_root_hash: B256::ZERO,
        }))
        .expect("encode");
        // The TC's own encoding: a NewView less its fixed fields.
        let tc_len = {
            let empty = encode_message(&H2Message::Vote(H2Vote {
                view: 1,
                block_hash: block(),
                voter: 1,
                signature: sig.clone(),
                high_tc: None,
            }))
            .expect("encode")
            .len();
            let with = encode_message(&H2Message::Vote(H2Vote {
                view: 1,
                block_hash: block(),
                voter: 1,
                signature: sig.clone(),
                high_tc: Some(wtc),
            }))
            .expect("encode")
            .len();
            with - empty
        };
        println!(
            "| {n} | {} | {t_qc:.0} | {t_any:.0} | {t_cqc:.0} | {t_tc:.0} | {} | {} | {tc_len} (+4 len) | {} | {} | {} |",
            vs.quorum_size(),
            qc_bytes.len(),
            extra.len(),
            nv.len(),
            tmo.len(),
            prop.len(),
        );
    }

    // Forming a QC from a quorum of votes: verify each as it arrives (the
    // engine's default), the collector's unverified tail (randomised
    // multi-message batch over one message), and a same-message batch.
    println!();
    println!("| n | quorum | verify each + aggregate | collector tail (multi-message batch) | same-message batch + aggregate | aggregate only |");
    println!("| --- | --- | --- | --- | --- | --- |");
    for n in [7usize, 100, 200] {
        let (sks, vs) = keys(n);
        let q = vs.quorum_size();
        let sigs: Vec<BlsSignature> = sks.iter().take(q).map(|sk| p.sign(sk, &msg)).collect();
        let pks: Vec<_> = (0..q).map(|i| vs.get_public_key(i as u32).expect("pk")).collect();
        let sig_refs: Vec<&BlsSignature> = sigs.iter().collect();
        let t_each = best_us(reps, || {
            for i in 0..q {
                assert!(p.verify_single(pks[i], &msg, &sigs[i]));
            }
            AggregateSignature::aggregate(&sig_refs).expect("agg")
        });
        let t_tail = best_us(reps, || {
            let mut c = VoteCollector::new(VIEW, block(), vs.len());
            for (i, s) in sigs.iter().enumerate() {
                c.add_vote(i as u32, s.clone()).expect("distinct");
            }
            c.build_qc_with_profile_message(&vs, &msg, p).expect("qc")
        });
        let t_same = best_us(reps, || {
            let out = p.verify_same_message(&msg, &sig_refs, &pks);
            assert!(out.bad.is_empty());
            AggregateSignature::aggregate(&sig_refs).expect("agg")
        });
        let t_agg = best_us(reps, || AggregateSignature::aggregate(&sig_refs).expect("agg"));
        println!("| {n} | {q} | {t_each:.0} | {t_tail:.0} | {t_same:.0} | {t_agg:.0} |");
    }

    // A TC formed from n timeouts: verify each timeout signature as it
    // arrives (today) against one same-message batch.
    println!();
    println!("| n | timeouts verified one by one | same-message batch | build TC from verified |");
    println!("| --- | --- | --- | --- |");
    for n in [100usize, 200] {
        let (sks, vs) = keys(n);
        let q = vs.quorum_size();
        let tmsg = p.timeout_message(VIEW + 1);
        let sigs: Vec<BlsSignature> = sks.iter().take(q).map(|sk| p.sign(sk, &tmsg)).collect();
        let pks: Vec<_> = (0..q).map(|i| vs.get_public_key(i as u32).expect("pk")).collect();
        let sig_refs: Vec<&BlsSignature> = sigs.iter().collect();
        let t_each = best_us(reps, || (0..q).all(|i| p.verify_single(pks[i], &tmsg, &sigs[i])));
        let t_same = best_us(reps, || p.verify_same_message(&tmsg, &sig_refs, &pks).bad.is_empty());
        let qc = prepare_qc(&sks, &vs);
        let t_build = best_us(reps, || {
            let mut c = TimeoutCollector::new(VIEW + 1, vs.len());
            for (i, s) in sigs.iter().enumerate() {
                c.add_verified_timeout(i as u32, s.clone(), qc.clone()).expect("distinct");
            }
            c.build_tc_with_profile(&vs, p).expect("tc")
        });
        println!("| {n} | {t_each:.0} | {t_same:.0} | {t_build:.0} |");
    }

    // The committee pool's per-block evidence (512 signers), beside the set.
    let pool = SimulatedCommitteePool::new(CommitteePoolConfig {
        seed: B256::repeat_byte(0x42),
        pool_size: 4096,
        committee_size: 512,
        ramp_blocks: 0,
    })
    .expect("pool");
    let t_ev = best_us(reps, || pool.build_evidence(7, &block(), &B256::ZERO).expect("evidence"));
    let ev_len = pool.build_evidence(7, &block(), &B256::ZERO).expect("evidence").marshal().len();
    println!();
    println!("committee evidence (pool 4096, 512 signers): build {t_ev:.0} us, {ev_len} bytes");
}
