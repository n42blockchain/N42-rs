// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Behavioural tests for the `APos` engine, run against reth's in-memory mock provider.

use super::*;
use alloy_genesis::{CliqueConfig, Genesis};
use alloy_primitives::keccak256;
use n42_tx_types::Block as Blk;
use reth_chainspec::ChainSpec;
use reth_provider::test_utils::MockEthProvider;

type Engine = APos<MockEthProvider, ChainSpec>;

const GENESIS_TS: u64 = 1_000_000;
const PERIOD: u64 = 3;

fn key(i: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(i + 1)).unwrap()
}

fn key_hex(i: u8) -> String {
    format!("{:#x}", B256::repeat_byte(i + 1))
}

fn spec(epoch: u64) -> Arc<ChainSpec> {
    let mut genesis = Genesis::default();
    genesis.config.clique = Some(CliqueConfig {
        period: Some(PERIOD),
        epoch: Some(epoch),
    });
    Arc::new(ChainSpec::from(genesis))
}

/// A header with a valid shape for a non-checkpoint block; tests tweak single fields.
fn base_header(number: u64) -> Header {
    Header {
        number,
        timestamp: GENESIS_TS + number,
        difficulty: DIFF_IN_TURN,
        nonce: B64::ZERO,
        extra_data: Bytes::from(vec![0u8; EXTRA_VANITY + EXTRA_SEAL]),
        ..Default::default()
    }
}

/// Sign `header` the way `seal` does, with an arbitrary key.
fn sign_with(header: &mut Header, signer: &PrivateKeySigner) {
    let sig = signer.sign_hash_sync(&seal_hash(header)).unwrap();
    let mut extra = BytesMut::from(&header.extra_data[..]);
    let start = extra.len() - SIGNATURE_LENGTH;
    extra[start..].copy_from_slice(&sig.as_bytes());
    *extra.last_mut().unwrap() -= 27;
    header.extra_data = Bytes::from(extra.freeze());
}

struct Env {
    provider: MockEthProvider,
    spec: Arc<ChainSpec>,
    n_signers: u8,
    genesis: SealedHeader,
}

impl Env {
    /// A chain whose genesis authorises keys `0..n`.
    fn new(n: u8, epoch: u64) -> Self {
        let provider = MockEthProvider::default();
        let mut extra = vec![0u8; EXTRA_VANITY];
        for i in 0..n {
            extra.extend_from_slice(key(i).address().as_slice());
        }
        extra.extend_from_slice(&[0u8; EXTRA_SEAL]);
        let header = Header {
            number: 0,
            timestamp: GENESIS_TS,
            difficulty: U256::from(1),
            extra_data: Bytes::from(extra),
            ..Default::default()
        };
        let genesis = SealedHeader::seal_slow(header);
        provider.add_header(genesis.hash(), genesis.header().clone());
        Self {
            provider,
            spec: spec(epoch),
            n_signers: n,
            genesis,
        }
    }

    fn engine_with(&self, key_idx: Option<u8>) -> Engine {
        APos::new(
            self.provider.clone(),
            self.spec.clone(),
            key_idx.map(key_hex),
        )
    }

    fn engine(&self, key_idx: u8) -> Engine {
        self.engine_with(Some(key_idx))
    }

    /// Prepare and seal a block on `parent` with the engine of `key_idx`, then register it.
    fn build(&self, key_idx: u8, parent: &SealedHeader) -> Result<SealedHeader, ConsensusError> {
        let e = self.engine(key_idx);
        let mut h = Consensus::<Blk>::prepare(&e, parent)?;
        Consensus::<Blk>::seal(&e, &mut h)?;
        let sealed = SealedHeader::seal_slow(h);
        self.provider
            .add_header(sealed.hash(), sealed.header().clone());
        Ok(sealed)
    }

    /// Build `count` blocks, each by the in-turn signer.
    fn chain(&self, count: u64) -> Vec<SealedHeader> {
        let mut out = vec![self.genesis.clone()];
        for n in 1..=count {
            let idx = ((n - 1) % self.n_signers as u64) as u8;
            let parent = out.last().unwrap().clone();
            out.push(self.build(idx, &parent).unwrap());
        }
        out
    }
}

fn detail(e: ConsensusError) -> String {
    match e {
        ConsensusError::AposErrorDetail { detail } => detail,
        other => panic!("expected AposErrorDetail, got {other:?}"),
    }
}

// ---------------------------------------------------------------- AposError

#[test]
fn apos_error_display_texts_are_distinct_and_stable() {
    let all = [
        (AposError::UnknownBlock, "unknown block"),
        (
            AposError::InvalidCheckpointBeneficiary,
            "beneficiary in checkpoint block non-zero",
        ),
        (AposError::InvalidVote, "vote nonce not 0x00..0 or 0xff..f"),
        (
            AposError::InvalidCheckpointVote,
            "vote nonce in checkpoint block non-zero",
        ),
        (
            AposError::MissingVanity,
            "extra-data 32 byte vanity prefix missing",
        ),
        (
            AposError::MissingSignature,
            "extra-data 65 byte signature suffix missing",
        ),
        (
            AposError::ExtraSigners,
            "non-checkpoint block contains extra signer list",
        ),
        (
            AposError::InvalidCheckpointSigners,
            "invalid signer list on checkpoint block",
        ),
        (
            AposError::MismatchingCheckpointSigners,
            "mismatching signer list on checkpoint block",
        ),
        (AposError::InvalidMixDigest, "non-zero mix digest"),
        (AposError::InvalidUncleHash, "non-empty uncle hash"),
        (AposError::InvalidDifficulty, "invalid difficulty"),
        (AposError::WrongDifficulty, "wrong difficulty"),
        (AposError::InvalidTimestamp, "invalid timestamp"),
        (AposError::InvalidVotingChain, "invalid voting chain"),
        (AposError::UnauthorizedSigner, "unauthorized signer"),
        (AposError::RecentlySigned, "recently signed"),
        (
            AposError::NoTransactions,
            "sealing paused while waiting for transactions",
        ),
    ];
    let mut seen = std::collections::HashSet::new();
    for (err, text) in all {
        assert_eq!(err.to_string(), text);
        assert!(seen.insert(text));
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert_eq!(boxed.to_string(), text);
    }
}

// ------------------------------------------------------- construction/signer

#[test]
fn new_reads_period_and_epoch_from_the_chain_spec() {
    let env = Env::new(3, 17);
    let e = env.engine(0);
    assert_eq!(e.config.period, PERIOD);
    assert_eq!(e.config.epoch, 17);
}

#[test]
fn new_keeps_default_config_without_clique_section() {
    let provider = MockEthProvider::default();
    let spec = Arc::new(ChainSpec::from(Genesis::default()));
    let e: Engine = APos::new(provider, spec, None);
    assert_eq!(e.config, APosConfig::default());
    assert_eq!(Consensus::<Blk>::get_eth_signer_address(&e).unwrap(), None);
}

#[test]
fn new_with_valid_key_exposes_its_address() {
    let env = Env::new(3, 100);
    let e = env.engine(1);
    assert_eq!(
        Consensus::<Blk>::get_eth_signer_address(&e).unwrap(),
        Some(key(1).address())
    );
    assert_eq!(
        SignerManager::get_signer_address(&e).unwrap(),
        Some(key(1).address())
    );
}

#[test]
fn new_with_unparsable_key_leaves_no_signer() {
    let env = Env::new(3, 100);
    let e: Engine = APos::new(env.provider.clone(), env.spec.clone(), Some("zz".into()));
    assert_eq!(Consensus::<Blk>::get_eth_signer_address(&e).unwrap(), None);
}

#[test]
fn set_eth_signer_by_key_replaces_and_clears_the_signer() {
    let env = Env::new(3, 100);
    let e = env.engine_with(None);
    Consensus::<Blk>::set_eth_signer_by_key(&e, Some(key_hex(2))).unwrap();
    assert_eq!(
        Consensus::<Blk>::get_eth_signer_address(&e).unwrap(),
        Some(key(2).address())
    );
    Consensus::<Blk>::set_eth_signer_by_key(&e, None).unwrap();
    assert_eq!(Consensus::<Blk>::get_eth_signer_address(&e).unwrap(), None);
}

#[test]
fn set_eth_signer_by_key_rejects_bad_hex_and_keeps_old_signer() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    let err = Consensus::<Blk>::set_eth_signer_by_key(&e, Some("not hex".into())).unwrap_err();
    assert!(detail(err).starts_with("Invalid signer key format"));
    // The all-zero scalar is not a valid secp256k1 key.
    let err = Consensus::<Blk>::set_eth_signer_by_key(&e, Some(format!("{:#x}", B256::ZERO)))
        .unwrap_err();
    assert!(detail(err).starts_with("Failed to create signer from key"));
    assert_eq!(
        Consensus::<Blk>::get_eth_signer_address(&e).unwrap(),
        Some(key(0).address())
    );
}

#[test]
fn signer_manager_set_key_validates_input() {
    let env = Env::new(3, 100);
    let e = env.engine_with(None);
    let err = SignerManager::set_signer_key(&e, Some("garbage".into())).unwrap_err();
    assert!(matches!(
        err,
        n42_consensus_traits::AposError::InvalidSignerKey(_)
    ));
    assert_eq!(SignerManager::get_signer_address(&e).unwrap(), None);

    SignerManager::set_signer_key(&e, Some(key_hex(0))).unwrap();
    assert_eq!(
        SignerManager::get_signer_address(&e).unwrap(),
        Some(key(0).address())
    );
    SignerManager::set_signer_key(&e, None).unwrap();
    assert_eq!(SignerManager::get_signer_address(&e).unwrap(), None);
}

#[test]
fn debug_output_shows_config_and_signer() {
    let env = Env::new(3, 100);
    let s = format!("{:?}", env.engine(0));
    assert!(s.starts_with("APos"));
    assert!(s.contains("config"));
    assert!(s.contains("signer"));
}

#[test]
fn close_is_a_noop_and_seal_hash_delegates() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    assert!(e.close().is_ok());
    let h = base_header(1);
    assert_eq!(e.seal_hash(&h), seal_hash(&h));
}

// ----------------------------------------------------------------- proposals

#[test]
fn proposals_can_be_added_overwritten_and_discarded() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    let a = Address::repeat_byte(0xaa);
    let b = Address::repeat_byte(0xbb);
    assert!(Consensus::<Blk>::proposals(&e).unwrap().is_empty());

    Consensus::<Blk>::propose(&e, a, true).unwrap();
    Consensus::<Blk>::propose(&e, b, false).unwrap();
    let p = Consensus::<Blk>::proposals(&e).unwrap();
    assert_eq!(p.len(), 2);
    assert_eq!(p[&a], true);
    assert_eq!(p[&b], false);

    // A second proposal for the same address replaces the first.
    Consensus::<Blk>::propose(&e, a, false).unwrap();
    assert_eq!(Consensus::<Blk>::proposals(&e).unwrap()[&a], false);

    Consensus::<Blk>::discard(&e, a).unwrap();
    let p = Consensus::<Blk>::proposals(&e).unwrap();
    assert_eq!(p.len(), 1);
    assert!(p.contains_key(&b));
    // Discarding an unknown address is not an error.
    Consensus::<Blk>::discard(&e, a).unwrap();
}

// ------------------------------------------------------------------ snapshot

#[test]
fn genesis_snapshot_lists_the_signers_from_extra_data() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    let snap = Consensus::<Blk>::snapshot(&e, 0, env.genesis.hash(), None).unwrap();
    assert_eq!(snap.number, 0);
    assert_eq!(snap.hash, env.genesis.hash());
    assert_eq!(
        snap.signers,
        vec![key(0).address(), key(1).address(), key(2).address()]
    );
    assert!(snap.recents.is_empty());
    assert!(snap.votes.is_empty());
}

#[test]
fn snapshot_of_unknown_hash_is_unknown_block() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    let err = Consensus::<Blk>::snapshot(&e, 5, B256::repeat_byte(9), None).unwrap_err();
    assert!(matches!(err, ConsensusError::UnknownBlock));
}

#[test]
fn snapshot_follows_the_chain_and_tracks_recent_signers() {
    let env = Env::new(3, 100);
    let chain = env.chain(3);
    let e = env.engine(0);
    let snap = Consensus::<Blk>::snapshot(&e, 3, chain[3].hash(), None).unwrap();
    assert_eq!(snap.number, 3);
    assert_eq!(snap.hash, chain[3].hash());
    // limit = 3/2+1 = 2: block 1's entry has been released, 2 and 3 are recent.
    assert_eq!(snap.recents.len(), 2);
    assert_eq!(snap.recents[&2], key(1).address());
    assert_eq!(snap.recents[&3], key(2).address());
    // The result is cached under the head hash and is stable.
    let again = Consensus::<Blk>::snapshot(&e, 3, chain[3].hash(), None).unwrap();
    assert_eq!(again, snap);
}

#[test]
fn snapshot_with_wrong_parent_header_is_refused() {
    let env = Env::new(3, 100);
    let chain = env.chain(2);
    let e = env.engine(0);
    // Pass block 1 as the "parent" of block 2's hash: hash/number do not match.
    let err = Consensus::<Blk>::snapshot(
        &e,
        2,
        chain[2].hash(),
        Some(vec![chain[1].header().clone()]),
    )
    .unwrap_err();
    assert!(matches!(err, ConsensusError::UnknownBlock));
}

#[test]
fn snapshot_with_unauthorized_block_signer_is_invalid_difficulty() {
    let env = Env::new(3, 100);
    // Block 1 sealed by a key that is not in the signer list.
    let mut h = base_header(1);
    h.parent_hash = env.genesis.hash();
    sign_with(&mut h, &key(7));
    let sealed = SealedHeader::seal_slow(h);
    env.provider.add_header(sealed.hash(), sealed.header().clone());

    let e = env.engine(0);
    let err = Consensus::<Blk>::snapshot(&e, 1, sealed.hash(), None).unwrap_err();
    assert!(matches!(err, ConsensusError::InvalidDifficulty));
}

#[test]
fn two_votes_from_distinct_signers_authorise_a_new_signer() {
    let env = Env::new(3, 100);
    let newcomer = Address::repeat_byte(0xdd);
    // Block 1 (key 1) and block 2 (key 2) both vote to add `newcomer`.
    let e1 = env.engine(1);
    Consensus::<Blk>::propose(&e1, newcomer, true).unwrap();
    let mut h1 = Consensus::<Blk>::prepare(&e1, &env.genesis).unwrap();
    assert_eq!(h1.beneficiary, newcomer);
    assert_eq!(h1.nonce, B64::from(NONCE_AUTH_VOTE));
    Consensus::<Blk>::seal(&e1, &mut h1).unwrap();
    let b1 = SealedHeader::seal_slow(h1);
    env.provider.add_header(b1.hash(), b1.header().clone());

    let snap1 = Consensus::<Blk>::snapshot(&e1, 1, b1.hash(), None).unwrap();
    assert_eq!(snap1.signers.len(), 3, "one vote is not a majority");
    assert_eq!(snap1.votes.len(), 1);

    let e2 = env.engine(2);
    Consensus::<Blk>::propose(&e2, newcomer, true).unwrap();
    let mut h2 = Consensus::<Blk>::prepare(&e2, &b1).unwrap();
    Consensus::<Blk>::seal(&e2, &mut h2).unwrap();
    let b2 = SealedHeader::seal_slow(h2);
    env.provider.add_header(b2.hash(), b2.header().clone());

    let snap2 = Consensus::<Blk>::snapshot(&e2, 2, b2.hash(), None).unwrap();
    assert_eq!(snap2.signers.len(), 4);
    assert!(snap2.signers.contains(&newcomer));
    assert!(snap2.votes.is_empty(), "votes on the new signer are cleared");
    assert!(snap2.tally.is_empty());
}

// ------------------------------------------------------------------- prepare

#[test]
fn prepare_without_a_signer_fails() {
    let env = Env::new(3, 100);
    let e = env.engine_with(None);
    let err = Consensus::<Blk>::prepare(&e, &env.genesis).unwrap_err();
    assert!(matches!(err, ConsensusError::NoSignerSet));
}

#[test]
fn prepare_on_unknown_parent_is_unknown_block() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    let orphan = SealedHeader::seal_slow(base_header(9));
    let err = Consensus::<Blk>::prepare(&e, &orphan).unwrap_err();
    assert!(matches!(err, ConsensusError::UnknownBlock));
}

#[test]
fn prepare_fills_the_consensus_fields() {
    let env = Env::new(3, 100);
    // Block 1 is in turn for key 0 (index (1-1) % 3) and out of turn for key 1.
    let in_turn = Consensus::<Blk>::prepare(&env.engine(0), &env.genesis).unwrap();
    assert_eq!(in_turn.number, 1);
    assert_eq!(in_turn.parent_hash, env.genesis.hash());
    assert_eq!(in_turn.difficulty, DIFF_IN_TURN);
    assert_eq!(in_turn.timestamp, GENESIS_TS + PERIOD);
    assert_eq!(in_turn.beneficiary, Address::ZERO);
    assert_eq!(in_turn.nonce, B64::ZERO);
    assert_eq!(in_turn.mix_hash, B256::ZERO);
    assert_eq!(in_turn.extra_data.len(), EXTRA_VANITY + EXTRA_SEAL);
    assert!(in_turn.extra_data.iter().all(|b| *b == 0));

    let out_turn = Consensus::<Blk>::prepare(&env.engine(1), &env.genesis).unwrap();
    assert_eq!(out_turn.difficulty, DIFF_NO_TURN);
}

#[test]
fn prepare_votes_for_a_pending_proposal() {
    let env = Env::new(3, 100);
    let e = env.engine(1);
    let target = Address::repeat_byte(0x42);

    Consensus::<Blk>::propose(&e, target, true).unwrap();
    let h = Consensus::<Blk>::prepare(&e, &env.genesis).unwrap();
    assert_eq!(h.beneficiary, target);
    assert_eq!(h.nonce, B64::from(NONCE_AUTH_VOTE));

    Consensus::<Blk>::propose(&e, target, false).unwrap();
    let h = Consensus::<Blk>::prepare(&e, &env.genesis).unwrap();
    assert_eq!(h.beneficiary, target);
    assert_eq!(h.nonce, B64::from(NONCE_DROP_VOTE));

    Consensus::<Blk>::discard(&e, target).unwrap();
    let h = Consensus::<Blk>::prepare(&e, &env.genesis).unwrap();
    assert_eq!(h.beneficiary, Address::ZERO);
}

#[test]
fn prepare_on_checkpoint_embeds_signers_and_ignores_proposals() {
    let env = Env::new(3, 4);
    let chain = env.chain(3);
    let e = env.engine(1);
    Consensus::<Blk>::propose(&e, Address::repeat_byte(0x42), true).unwrap();
    let h = Consensus::<Blk>::prepare(&e, &chain[3]).unwrap();
    assert_eq!(h.number, 4);
    assert_eq!(h.beneficiary, Address::ZERO);
    assert_eq!(h.nonce, B64::ZERO);
    assert_eq!(
        h.extra_data.len(),
        EXTRA_VANITY + 3 * Address::len_bytes() + EXTRA_SEAL
    );
    assert_eq!(
        &h.extra_data[EXTRA_VANITY..EXTRA_VANITY + 20],
        key(0).address().as_slice()
    );
}

// ---------------------------------------------------------------------- seal

#[test]
fn seal_refuses_genesis() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    let mut h = base_header(0);
    assert!(matches!(
        Consensus::<Blk>::seal(&e, &mut h),
        Err(ConsensusError::UnknownBlock)
    ));
}

#[test]
fn seal_without_signer_fails() {
    let env = Env::new(3, 100);
    let e = env.engine_with(None);
    let mut h = base_header(1);
    h.parent_hash = env.genesis.hash();
    assert!(matches!(
        Consensus::<Blk>::seal(&e, &mut h),
        Err(ConsensusError::NoSignerSet)
    ));
}

#[test]
fn seal_by_unlisted_signer_is_unauthorized() {
    let env = Env::new(3, 100);
    let e = env.engine(9);
    let mut h = base_header(1);
    h.parent_hash = env.genesis.hash();
    assert!(matches!(
        Consensus::<Blk>::seal(&e, &mut h),
        Err(ConsensusError::UnauthorizedSigner)
    ));
}

#[test]
fn seal_by_recent_signer_is_refused() {
    let env = Env::new(3, 100);
    let b1 = env.build(1, &env.genesis).unwrap();
    // Key 1 signed block 1 and must wait floor(3/2)+1 = 2 blocks.
    let e = env.engine(1);
    let mut h = Consensus::<Blk>::prepare(&e, &b1).unwrap();
    assert!(matches!(
        Consensus::<Blk>::seal(&e, &mut h),
        Err(ConsensusError::RecentlySigned)
    ));
}

#[test]
fn seal_on_unknown_parent_is_unknown_block() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    let mut h = base_header(5);
    h.parent_hash = B256::repeat_byte(3);
    assert!(matches!(
        Consensus::<Blk>::seal(&e, &mut h),
        Err(ConsensusError::UnknownBlock)
    ));
}

#[test]
fn seal_signs_so_the_signer_is_recoverable_and_verify_seal_accepts() {
    let env = Env::new(3, 100);
    let b1 = env.build(1, &env.genesis).unwrap();
    assert_eq!(
        n42_clique_utils::recover_address_generic(b1.header()).unwrap(),
        key(1).address()
    );
    let e = env.engine(0);
    let snap = Consensus::<Blk>::snapshot(&e, 0, env.genesis.hash(), None).unwrap();
    e.verify_seal(&snap, b1.header(), None).unwrap();
}

// --------------------------------------------------------------- verify_seal

#[test]
fn verify_seal_refuses_genesis_and_unlisted_signer_and_wrong_difficulty() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    let snap = Consensus::<Blk>::snapshot(&e, 0, env.genesis.hash(), None).unwrap();

    let err = e.verify_seal(&snap, &base_header(0), None).unwrap_err();
    assert_eq!(err.to_string(), AposError::UnknownBlock.to_string());

    // Signed by an outsider.
    let mut h = base_header(1);
    sign_with(&mut h, &key(8));
    let err = e.verify_seal(&snap, &h, None).unwrap_err();
    assert_eq!(err.to_string(), AposError::UnauthorizedSigner.to_string());

    // Key 0 is in turn at block 1, so DIFF_NO_TURN is wrong...
    let mut h = base_header(1);
    h.difficulty = DIFF_NO_TURN;
    sign_with(&mut h, &key(0));
    let err = e.verify_seal(&snap, &h, None).unwrap_err();
    assert_eq!(err.to_string(), AposError::WrongDifficulty.to_string());

    // ...and key 1 is out of turn, so DIFF_IN_TURN is wrong.
    let mut h = base_header(1);
    h.difficulty = DIFF_IN_TURN;
    sign_with(&mut h, &key(1));
    let err = e.verify_seal(&snap, &h, None).unwrap_err();
    assert_eq!(err.to_string(), AposError::WrongDifficulty.to_string());

    // The matching difficulties pass.
    let mut h = base_header(1);
    h.difficulty = DIFF_NO_TURN;
    sign_with(&mut h, &key(1));
    e.verify_seal(&snap, &h, None).unwrap();
}

#[test]
fn verify_seal_refuses_a_signer_seen_recently() {
    let env = Env::new(3, 100);
    let chain = env.chain(1);
    let e = env.engine(0);
    // Snapshot after block 1 (signed by key 0); block 2 re-signed by key 0.
    let snap = Consensus::<Blk>::snapshot(&e, 1, chain[1].hash(), None).unwrap();
    let mut h = base_header(2);
    h.difficulty = DIFF_NO_TURN;
    sign_with(&mut h, &key(0));
    let err = e.verify_seal(&snap, &h, None).unwrap_err();
    assert_eq!(err.to_string(), AposError::RecentlySigned.to_string());
}

// ----------------------------------------------------------- validate_header

fn check(env: &Env, h: Header) -> Result<(), ConsensusError> {
    env.engine(0).validate_header(&SealedHeader::seal_slow(h))
}

#[test]
fn validate_header_accepts_well_formed_headers() {
    let env = Env::new(3, 4);
    check(&env, base_header(1)).unwrap();
    let mut out_of_turn = base_header(2);
    out_of_turn.nonce = B64::from(NONCE_AUTH_VOTE);
    out_of_turn.difficulty = DIFF_NO_TURN;
    check(&env, out_of_turn).unwrap();
    // A checkpoint with three signers in extra-data.
    let mut cp = base_header(4);
    cp.extra_data = Bytes::from(vec![0u8; EXTRA_VANITY + 60 + EXTRA_SEAL]);
    check(&env, cp).unwrap();
}

#[test]
fn validate_header_refuses_genesis_and_future_blocks() {
    let env = Env::new(3, 4);
    assert!(matches!(
        check(&env, base_header(0)),
        Err(ConsensusError::UnknownBlock)
    ));
    let mut h = base_header(1);
    h.timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    match check(&env, h.clone()) {
        Err(ConsensusError::TimestampIsInFuture { timestamp, .. }) => {
            assert_eq!(timestamp, h.timestamp)
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn validate_header_enforces_vote_rules() {
    let env = Env::new(3, 4);
    // Checkpoint with a beneficiary.
    let mut h = base_header(4);
    h.beneficiary = Address::repeat_byte(1);
    assert!(matches!(
        check(&env, h),
        Err(ConsensusError::InvalidCheckpointBeneficiary)
    ));
    // Nonce that is neither magic value.
    let mut h = base_header(1);
    h.nonce = B64::from(1u64);
    assert!(matches!(check(&env, h), Err(ConsensusError::InvalidVote)));
    // Checkpoint with an authorise nonce.
    let mut h = base_header(4);
    h.nonce = B64::from(NONCE_AUTH_VOTE);
    assert!(matches!(
        check(&env, h),
        Err(ConsensusError::InvalidCheckpointVote)
    ));
}

#[test]
fn validate_header_enforces_extra_data_layout() {
    let env = Env::new(3, 4);
    let with_extra = |n: u64, len: usize| {
        let mut h = base_header(n);
        h.extra_data = Bytes::from(vec![0u8; len]);
        h
    };
    assert!(matches!(
        check(&env, with_extra(1, EXTRA_VANITY - 1)),
        Err(ConsensusError::MissingVanity)
    ));
    assert!(matches!(
        check(&env, with_extra(1, EXTRA_VANITY + EXTRA_SEAL - 1)),
        Err(ConsensusError::MissingSignature)
    ));
    assert!(matches!(
        check(&env, with_extra(1, EXTRA_VANITY + EXTRA_SEAL + 20)),
        Err(ConsensusError::ErrExtraSigners)
    ));
    assert!(matches!(
        check(&env, with_extra(4, EXTRA_VANITY + EXTRA_SEAL + 19)),
        Err(ConsensusError::InvalidCheckpointSigners)
    ));
}

#[test]
fn validate_header_enforces_difficulty_values() {
    let env = Env::new(3, 4);
    for bad in [U256::ZERO, U256::from(3), U256::from(100)] {
        let mut h = base_header(1);
        h.difficulty = bad;
        assert!(
            matches!(check(&env, h), Err(ConsensusError::InvalidDifficulty)),
            "difficulty {bad} must be refused"
        );
    }
}

#[test]
fn validate_header_range_is_a_noop_for_any_input() {
    let env = Env::new(3, 4);
    let e = env.engine(0);
    assert!(e.validate_header_range(&[]).is_ok());
    assert!(e
        .validate_header_range(&[env.genesis.clone(), SealedHeader::seal_slow(base_header(1))])
        .is_ok());
}

// ------------------------------------------- validate_header_against_parent

#[test]
fn validate_against_parent_accepts_a_sealed_chain_and_records_td() {
    let env = Env::new(3, 100);
    let chain = env.chain(3);
    let v = env.engine(0);
    for n in 1..=3 {
        v.validate_header_against_parent(&chain[n], &chain[n - 1])
            .unwrap();
    }
}

#[test]
fn validate_against_parent_accepts_genesis_number_without_checks() {
    let env = Env::new(3, 100);
    let v = env.engine(0);
    v.validate_header_against_parent(&env.genesis, &env.genesis)
        .unwrap();
}

#[test]
fn validate_against_parent_reports_seal_failures_as_detail() {
    let env = Env::new(3, 100);
    let v = env.engine(0);

    // Unlisted signer.
    let mut h = base_header(1);
    h.parent_hash = env.genesis.hash();
    h.difficulty = DIFF_NO_TURN;
    sign_with(&mut h, &key(8));
    let err = v
        .validate_header_against_parent(&SealedHeader::seal_slow(h), &env.genesis)
        .unwrap_err();
    assert_eq!(detail(err), AposError::UnauthorizedSigner.to_string());

    // Right signer, wrong difficulty for its turn.
    let mut h = base_header(1);
    h.parent_hash = env.genesis.hash();
    h.difficulty = DIFF_NO_TURN; // key 0 is in turn at block 1
    sign_with(&mut h, &key(0));
    let err = v
        .validate_header_against_parent(&SealedHeader::seal_slow(h), &env.genesis)
        .unwrap_err();
    assert_eq!(detail(err), AposError::WrongDifficulty.to_string());
}

#[test]
fn validate_against_parent_refuses_a_header_whose_parent_hash_differs() {
    let env = Env::new(3, 100);
    let chain = env.chain(2);
    let v = env.engine(0);
    // Block 2 is checked against block 0 instead of block 1.
    let err = v
        .validate_header_against_parent(&chain[2], &chain[0])
        .unwrap_err();
    assert!(matches!(err, ConsensusError::UnknownBlock));
}

#[test]
fn validate_against_parent_checks_the_checkpoint_signer_list() {
    let env = Env::new(3, 4);
    let chain = env.chain(4);
    let v = env.engine(0);
    // The honestly built checkpoint passes.
    v.validate_header_against_parent(&chain[4], &chain[3]).unwrap();

    // Same block but with the signer list reversed, re-signed by the in-turn signer.
    let mut h = chain[4].header().clone();
    let mut extra = h.extra_data.to_vec();
    let list = &mut extra[EXTRA_VANITY..EXTRA_VANITY + 60];
    list[..20].copy_from_slice(key(2).address().as_slice());
    list[40..].copy_from_slice(key(0).address().as_slice());
    h.extra_data = Bytes::from(extra);
    sign_with(&mut h, &key(0));
    let err = v
        .validate_header_against_parent(&SealedHeader::seal_slow(h), &chain[3])
        .unwrap_err();
    assert!(matches!(err, ConsensusError::InvalidCheckpointSigners));
}

// ---------------------------------------------------------- total difficulty

#[test]
fn total_difficulty_accumulates_block_difficulties() {
    let env = Env::new(3, 100);
    let chain = env.chain(3);
    let mut expected = U256::ZERO;
    // A fresh engine rebuilds the cache from the provider (genesis TD is seeded as zero).
    let e = env.engine(0);
    for h in &chain[1..] {
        expected += h.difficulty;
        assert_eq!(
            Consensus::<Blk>::total_difficulty(&e, h.hash()),
            expected,
            "td at block {}",
            h.number
        );
    }
    assert_eq!(
        Consensus::<Blk>::total_difficulty(&e, chain[0].hash()),
        U256::ZERO
    );
}

#[test]
fn total_difficulty_of_unknown_hash_is_zero() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    assert_eq!(
        Consensus::<Blk>::total_difficulty(&e, B256::repeat_byte(0x77)),
        U256::ZERO
    );
}

#[test]
fn total_difficulty_is_derived_from_the_parent_for_a_block_added_later() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    // Prime the cache (genesis only), then add a block behind the engine's back.
    assert_eq!(
        Consensus::<Blk>::total_difficulty(&e, env.genesis.hash()),
        U256::ZERO
    );
    let b1 = env.build(1, &env.genesis).unwrap();
    assert_eq!(
        Consensus::<Blk>::total_difficulty(&e, b1.hash()),
        b1.difficulty
    );
}

// -------------------------------------------------------------------- wiggle

#[test]
fn wiggle_is_zero_when_in_turn_and_bounded_when_out_of_turn() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    for _ in 0..20 {
        assert_eq!(
            Consensus::<Blk>::wiggle(&e, 0, env.genesis.hash(), DIFF_IN_TURN),
            Duration::ZERO
        );
        let w = Consensus::<Blk>::wiggle(&e, 0, env.genesis.hash(), DIFF_NO_TURN);
        assert!(w < Duration::from_millis(3 * 500), "wiggle {w:?} too long");
    }
}

#[test]
fn wiggle_is_zero_when_the_snapshot_cannot_be_built() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    for _ in 0..10 {
        assert_eq!(
            Consensus::<Blk>::wiggle(&e, 4, B256::repeat_byte(5), DIFF_NO_TURN),
            Duration::ZERO
        );
    }
}

// ------------------------------------------------------------- cached reads

#[test]
fn cached_reads_are_stored_per_block_hash() {
    let env = Env::new(3, 100);
    let e = env.engine(0);
    let h1 = keccak256(b"one");
    let h2 = keccak256(b"two");
    assert!(Consensus::<Blk>::get_cached_reads(&e, h1).unwrap().is_none());
    Consensus::<Blk>::set_cached_reads(&e, h1, CachedReads::default()).unwrap();
    assert!(Consensus::<Blk>::get_cached_reads(&e, h1).unwrap().is_some());
    assert!(Consensus::<Blk>::get_cached_reads(&e, h2).unwrap().is_none());
}

// ------------------------------------------------------------ calc_difficulty

#[test]
fn calc_difficulty_follows_the_next_block_turn() {
    let signers = vec![key(0).address(), key(1).address(), key(2).address()];
    let snap = Snapshot::new_snapshot(APosConfig::default(), 4, B256::ZERO, signers.clone());
    // Next block is 5; (5 - 1) % 3 == 1.
    assert_eq!(calc_difficulty(&snap, &signers[1]), DIFF_IN_TURN);
    assert_eq!(calc_difficulty(&snap, &signers[0]), DIFF_NO_TURN);
    assert_eq!(calc_difficulty(&snap, &signers[2]), DIFF_NO_TURN);
    // An address outside the list is never in turn.
    assert_eq!(calc_difficulty(&snap, &Address::repeat_byte(9)), DIFF_NO_TURN);
}
