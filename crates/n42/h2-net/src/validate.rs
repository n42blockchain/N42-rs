// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate, then forward (mixed production standard, amendment AM36),
//! profile 1 only.
//!
//! GossipSub forwards a message once this node reports a verdict on it. On a
//! profile-1 chain the verdict comes from the stateless checks here, per
//! topic (AM36 item 5):
//!
//! * **Reject** (not forwarded, the delivering peer is penalised): the message
//!   does not decode as its topic's type, or a field is out of range.
//! * **Ignore** (not forwarded, no penalty): a well-formed consensus message
//!   for a view below this node's latest commit QC (item 6), a transaction
//!   batch naming a type outside profile 1's set or carrying nothing (item
//!   8), a mobile packet outside the head window (item 4).
//! * **Accept**: everything else, future views included (no cap here; the
//!   engine buffers them).
//!
//! A stale consensus message is still handed to the engine (AM34 item 6: late
//! votes and proposals prove equivocations across a view boundary). In
//! rust-libp2p the message reaches the application before the verdict is
//! reported, so "deliver, then Ignore" is the transport returning the event
//! and reporting Ignore for it.
//!
//! BLS signatures are not verified here (AM36 item 2 allows it, it does not
//! require it): every relay hop on the vote path would pay a pairing.
//!
//! A chain that is not profile 1 keeps the transport's earlier behaviour:
//! accepted once it decodes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use n42_h2_wire::h2_wire::{H2Message, H2QuorumCertificate, H2TimeoutCertificate};

use crate::block_gossip::{decompress_block_gossip, HeaderProfile};
use crate::transport::MobileTopic;
use crate::tx_gossip::{decode_tx_batch, TxGossipError, TX_BATCH_MARKER};

/// What this node tells GossipSub about one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipVerdict {
    /// Forward it.
    Accept,
    /// Do not forward it; penalise the peer that delivered it.
    Reject(String),
    /// Do not forward it; no penalty.
    Ignore(&'static str),
}

impl GossipVerdict {
    pub(crate) fn acceptance(&self) -> libp2p::gossipsub::MessageAcceptance {
        match self {
            Self::Accept => libp2p::gossipsub::MessageAcceptance::Accept,
            Self::Reject(_) => libp2p::gossipsub::MessageAcceptance::Reject,
            Self::Ignore(_) => libp2p::gossipsub::MessageAcceptance::Ignore,
        }
    }
}

/// The view of this node's latest commit QC, shared between the consensus
/// loop (which raises it) and the transport (which reads it to judge
/// staleness). Zero means unknown: nothing is stale.
#[derive(Debug, Clone, Default)]
pub struct CommitViewHint(Arc<AtomicU64>);

impl CommitViewHint {
    /// A hint at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Raises the hint to `view`; it never moves back.
    pub fn raise(&self, view: u64) {
        self.0.fetch_max(view, Ordering::Relaxed);
    }

    /// The latest commit view known.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A check for a `mobileverify_packet` message, installed once the mobile
/// verification service runs (it holds the head the window is judged
/// against).
pub type MobilePacketCheck = Arc<dyn Fn(&[u8]) -> GossipVerdict + Send + Sync>;

/// Where the packet check is installed; until it is, packets are ignored
/// (nothing to judge them with).
#[derive(Clone, Default)]
pub struct MobilePacketGate(Arc<OnceLock<MobilePacketCheck>>);

impl MobilePacketGate {
    /// An empty gate.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the check; a second call is ignored.
    pub fn install(&self, check: MobilePacketCheck) {
        let _ = self.0.set(check);
    }

    fn check(&self, data: &[u8]) -> GossipVerdict {
        match self.0.get() {
            Some(check) => check(data),
            None => GossipVerdict::Ignore("mobileverify service not running yet"),
        }
    }
}

impl std::fmt::Debug for MobilePacketGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MobilePacketGate").field("installed", &self.0.get().is_some()).finish()
    }
}

/// What a profile-1 transport needs to validate before forwarding.
#[derive(Debug, Clone)]
pub struct Profile1Gossip {
    /// The genesis validator set's size: the `n` of every signer bitmap
    /// (AM36 item 10, AM5) and the bound on a signer index.
    pub validator_count: usize,
    /// The header profile a block body is decoded under.
    pub header_profile: HeaderProfile,
    /// The latest commit QC's view, raised by the consensus loop.
    pub commit_view: CommitViewHint,
    /// The mobile packet check, installed by the mobile service.
    pub mobile_packets: MobilePacketGate,
}

impl Profile1Gossip {
    /// Profile-1 validation for a genesis set of `validator_count` members.
    pub fn new(validator_count: usize, header_profile: HeaderProfile) -> Self {
        Self {
            validator_count,
            header_profile,
            commit_view: CommitViewHint::new(),
            mobile_packets: MobilePacketGate::new(),
        }
    }

    /// The verdict on a decoded consensus message (HotStuff native topic or
    /// H2-v4 topic; the decoder has checked the chain identity already).
    pub fn consensus_verdict(&self, message: &H2Message) -> GossipVerdict {
        if let Err(reason) = check_consensus_fields(message, self.validator_count) {
            return GossipVerdict::Reject(reason);
        }
        if is_stale(message, self.commit_view.get()) {
            return GossipVerdict::Ignore("view below the latest commit QC");
        }
        GossipVerdict::Accept
    }

    /// The verdict on a block topic payload (raw snappy).
    pub fn block_verdict(&self, data: &[u8]) -> GossipVerdict {
        match check_block(data, self.header_profile) {
            Ok(()) => GossipVerdict::Accept,
            Err(reason) => GossipVerdict::Reject(reason),
        }
    }

    /// The verdict on a mobileverify message.
    pub fn mobile_verdict(&self, topic: MobileTopic, data: &[u8]) -> GossipVerdict {
        match topic {
            MobileTopic::Packet => self.mobile_packets.check(data),
            MobileTopic::Registration => registration_verdict(data),
        }
    }
}

/// The verdict on an H2-v4 payload that did not decode for this chain
/// (AM36 item 11, gov5's rule): another chain's identity is ignored, since
/// the v4 topic name carries no chain and an honest member of another chain
/// may publish on it; anything else is rejected.
pub fn envelope_error_verdict(err: &n42_h2_wire::h2_v4::H2V4Error) -> GossipVerdict {
    match err {
        n42_h2_wire::h2_v4::H2V4Error::ChainIdentityMismatch => GossipVerdict::Ignore("another chain's identity"),
        err => GossipVerdict::Reject(format!("envelope: {err}")),
    }
}

/// gov5's registration: `pubkey(48) || pop(96)`. The proof of possession is
/// verified on adoption, not here.
pub const REGISTRATION_LEN: usize = 48 + 96;

/// The verdict on a `mobileverify_registration` payload.
pub fn registration_verdict(data: &[u8]) -> GossipVerdict {
    if data.len() == REGISTRATION_LEN {
        GossipVerdict::Accept
    } else {
        GossipVerdict::Reject(format!("registration of {} bytes, want {REGISTRATION_LEN}", data.len()))
    }
}

/// The view every message carries.
pub const fn message_view(message: &H2Message) -> u64 {
    match message {
        H2Message::Proposal(m) => m.view,
        H2Message::Vote(m) | H2Message::CommitVote(m) => m.view,
        H2Message::PrepareQc(m) => m.view,
        H2Message::Timeout(m) => m.view,
        H2Message::NewView(m) => m.view,
        H2Message::Decide(m) => m.view,
    }
}

/// AM36 item 6: a message for a view strictly below the latest commit QC's
/// view, except a Decide or a NewView (the engine handles those at any view,
/// gov5's rule). The committed view itself is not stale; zero is unknown.
pub const fn is_stale(message: &H2Message, commit_view: u64) -> bool {
    if matches!(message, H2Message::Decide(_) | H2Message::NewView(_)) {
        return false;
    }
    message_view(message) < commit_view
}

/// The view no message, QC or TC may name (AM34 item 3).
const VIEW_MAX: u64 = u64::MAX;

fn view_in_range(view: u64, what: &str) -> Result<(), String> {
    if view == VIEW_MAX { Err(format!("{what} view 2^64-1")) } else { Ok(()) }
}

/// AM36 item 10: `u16 LE n` then `ceil(n/8)` bytes, bit `i` = signer `i`
/// (LSB first), `n` the set size; no bit past `n` set. The genesis QC (view
/// 0) is the handler's to judge: it crosses the wire with an empty bitmap.
fn bitmap_in_range(bitmap: &[u8], view: u64, n: usize, what: &str) -> Result<(), String> {
    if view == 0 {
        return Ok(());
    }
    let bad = || Err(format!("{what} signer bitmap is not {n} signers wide"));
    let Some(count) = bitmap.get(..2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize) else {
        return bad();
    };
    if count != n || bitmap.len() != 2 + n.div_ceil(8) {
        return bad();
    }
    if !n.is_multiple_of(8)
        && let Some(last) = bitmap.last()
        && last >> (n % 8) != 0
    {
        return Err(format!("{what} signer bitmap names an index outside the set of {n}"));
    }
    Ok(())
}

fn qc_in_range(qc: &H2QuorumCertificate, n: usize, what: &str) -> Result<(), String> {
    view_in_range(qc.view, what)?;
    bitmap_in_range(&qc.signers_bitmap, qc.view, n, what)
}

fn tc_in_range(tc: &H2TimeoutCertificate, n: usize, what: &str) -> Result<(), String> {
    view_in_range(tc.view, what)?;
    bitmap_in_range(&tc.signers_bitmap, tc.view, n, what)?;
    qc_in_range(&tc.high_qc, n, what)
}

/// A TC piggybacked as `high_tc` (gov5's `SyncInfo`): an honest node records
/// a higher TC it cannot use yet without verifying it and sends it on, so
/// only the view bound says something about the sender (gov5's rule).
fn piggybacked_tc_in_range(tc: Option<&H2TimeoutCertificate>) -> Result<(), String> {
    let Some(tc) = tc else { return Ok(()) };
    view_in_range(tc.view, "piggybacked TC")?;
    view_in_range(tc.high_qc.view, "piggybacked TC high QC")
}

fn signer_in_range(index: u32, n: usize, what: &str) -> Result<(), String> {
    if (index as usize) < n { Ok(()) } else { Err(format!("{what} {index} outside the set of {n}")) }
}

/// AM36 item 5 for HotStuff and H2-v4: every view below 2^64-1, a proposal's
/// justify QC below the proposal's view, a Decide's commit QC at the
/// Decide's view, every certificate's bitmap the genesis set's width, every
/// signer index inside the set (`n` is fixed on profile 1, AM5).
pub fn check_consensus_fields(message: &H2Message, n: usize) -> Result<(), String> {
    view_in_range(message_view(message), "message")?;
    match message {
        H2Message::Proposal(p) => {
            signer_in_range(p.proposer, n, "proposer")?;
            qc_in_range(&p.justify_qc, n, "justify QC")?;
            if p.justify_qc.view >= p.view {
                return Err(format!("justify QC view {} not below proposal view {}", p.justify_qc.view, p.view));
            }
            if let Some(qc) = &p.prepare_qc {
                qc_in_range(qc, n, "prepare QC")?;
            }
        }
        H2Message::Vote(v) | H2Message::CommitVote(v) => {
            signer_in_range(v.voter, n, "voter")?;
            piggybacked_tc_in_range(v.high_tc.as_ref())?;
        }
        H2Message::PrepareQc(m) => qc_in_range(&m.qc, n, "prepare QC")?,
        H2Message::Timeout(t) => {
            signer_in_range(t.sender, n, "timeout sender")?;
            qc_in_range(&t.high_qc, n, "timeout high QC")?;
            piggybacked_tc_in_range(t.high_tc.as_ref())?;
        }
        H2Message::NewView(m) => {
            signer_in_range(m.leader, n, "new-view leader")?;
            tc_in_range(&m.timeout_certificate, n, "new-view TC")?;
        }
        H2Message::Decide(d) => {
            qc_in_range(&d.commit_qc, n, "commit QC")?;
            if d.commit_qc.view != d.view {
                return Err(format!("decide view {} but commit QC view {}", d.view, d.commit_qc.view));
            }
        }
    }
    Ok(())
}

/// AM36 item 5 for the block topic: the snappy length matches and is within
/// the block byte limit, and the body decodes (`[header, txs, verifiers,
/// rewards(, access list)]` under the chain's header profile). Transactions
/// are left as bytes, as the consumer leaves them.
pub fn check_block(data: &[u8], profile: HeaderProfile) -> Result<(), String> {
    let rlp = decompress_block_gossip(data).map_err(|e| format!("block: {e}"))?;
    n42_h2_consensus::decode_raw_block_body_ref(&rlp, profile).map_err(|e| format!("block: {e}"))?;
    Ok(())
}

/// How one transaction of a `transaction_v2` message stands against
/// profile 1's set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxClass {
    /// Legacy, 2930, 1559 or 7702, and it decodes.
    InSet,
    /// A well-formed transaction of another type, or an EIP-2718 type this
    /// client cannot decode at all.
    Outside,
    /// Neither a legacy RLP list nor a typed envelope, or a known type whose
    /// payload does not decode.
    Malformed,
}

fn decodes_fully(bytes: &[u8]) -> bool {
    let mut cursor = bytes;
    TxEnvelope::decode_2718(&mut cursor).is_ok() && cursor.is_empty()
}

fn classify_tx(bytes: &[u8]) -> TxClass {
    match bytes.first() {
        None => TxClass::Malformed,
        // A legacy transaction: an RLP list.
        Some(0xc0..=0xff) => {
            if decodes_fully(bytes) { TxClass::InSet } else { TxClass::Malformed }
        }
        Some(0x01 | 0x02 | 0x04) => {
            if decodes_fully(bytes) { TxClass::InSet } else { TxClass::Malformed }
        }
        // 4844: known here, outside profile 1.
        Some(0x03) => {
            if decodes_fully(bytes) { TxClass::Outside } else { TxClass::Malformed }
        }
        // Any other EIP-2718 type byte, 0x50 included: outside the set.
        Some(0x00..=0x7f) => TxClass::Outside,
        // 0x80..0xbf: an RLP byte string, neither form.
        Some(_) => TxClass::Malformed,
    }
}

/// AM36 item 8 for `transaction_v2` (raw snappy over one transaction or a
/// `0x7e` batch): bytes that do not decode as a transaction reject the
/// message; a batch that decodes but names a type outside {0x00, 0x01, 0x02,
/// 0x04}, or carries nothing, is ignored.
pub fn transactions_verdict(data: &[u8]) -> GossipVerdict {
    let payload = match decompress_block_gossip(data) {
        Ok(payload) => payload,
        Err(e) => return GossipVerdict::Reject(format!("transactions: {e}")),
    };
    let transactions = match decode_tx_batch(&payload) {
        Ok(transactions) => transactions,
        Err(TxGossipError::InvalidBatch) if payload == [TX_BATCH_MARKER, alloy_rlp::EMPTY_LIST_CODE] => {
            return GossipVerdict::Ignore("empty transaction batch");
        }
        Err(e) => return GossipVerdict::Reject(format!("transactions: {e}")),
    };
    let mut outside = false;
    for tx in &transactions {
        match classify_tx(tx) {
            TxClass::InSet => {}
            TxClass::Outside => outside = true,
            TxClass::Malformed => return GossipVerdict::Reject("transactions: an entry does not decode".into()),
        }
    }
    if outside { GossipVerdict::Ignore("transaction type outside profile 1") } else { GossipVerdict::Accept }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, U256};
    use alloy_rlp::Encodable;
    use n42_h2_primitives::bls::BlsSecretKey;
    use n42_h2_wire::h2_wire::{H2Decide, H2NewView, H2Proposal, H2Timeout, H2Vote};

    const N: usize = 4;

    fn bitmap(n: usize, signers: &[usize]) -> Vec<u8> {
        let mut out = (n as u16).to_le_bytes().to_vec();
        out.resize(2 + n.div_ceil(8), 0);
        for i in signers {
            out[2 + i / 8] |= 1 << (i % 8);
        }
        out
    }

    fn qc(view: u64) -> H2QuorumCertificate {
        H2QuorumCertificate {
            view,
            block_hash: B256::repeat_byte(1),
            aggregate_signature: vec![0; 96],
            signers_bitmap: bitmap(N, &[0, 1, 2]),
        }
    }

    fn signature() -> n42_h2_primitives::bls::BlsSignature {
        BlsSecretKey::from_bytes(&[7; 32]).unwrap().sign(b"x")
    }

    fn vote(view: u64) -> H2Message {
        H2Message::Vote(H2Vote { view, block_hash: B256::ZERO, voter: 1, signature: signature(), high_tc: None })
    }

    fn proposal(view: u64, justify: u64) -> H2Message {
        H2Message::Proposal(H2Proposal {
            view,
            block_hash: B256::ZERO,
            justify_qc: qc(justify),
            proposer: 0,
            signature: signature(),
            prepare_qc: None,
            tx_root_hash: B256::ZERO,
        })
    }

    fn decide(view: u64, qc_view: u64) -> H2Message {
        H2Message::Decide(H2Decide { view, block_hash: B256::repeat_byte(1), commit_qc: qc(qc_view) })
    }

    fn p1() -> Profile1Gossip {
        Profile1Gossip::new(N, HeaderProfile::Gov5H2)
    }

    #[test]
    fn a_well_formed_message_is_accepted_at_and_above_the_commit_view() {
        let p = p1();
        p.commit_view.raise(10);
        assert_eq!(p.consensus_verdict(&vote(10)), GossipVerdict::Accept);
        assert_eq!(p.consensus_verdict(&vote(1_000_000)), GossipVerdict::Accept, "no future cap");
        assert_eq!(p.consensus_verdict(&proposal(11, 10)), GossipVerdict::Accept);
        assert_eq!(p.consensus_verdict(&decide(5, 5)), GossipVerdict::Accept, "a Decide is never stale");
    }

    #[test]
    fn a_stale_message_is_ignored_not_rejected() {
        let p = p1();
        assert_eq!(p.consensus_verdict(&vote(3)), GossipVerdict::Accept, "unknown commit view: nothing stale");
        p.commit_view.raise(10);
        p.commit_view.raise(4);
        assert_eq!(p.commit_view.get(), 10, "the hint never moves back");
        assert!(matches!(p.consensus_verdict(&vote(9)), GossipVerdict::Ignore(_)));
        assert!(matches!(p.consensus_verdict(&proposal(9, 8)), GossipVerdict::Ignore(_)));
        let new_view = H2Message::NewView(H2NewView {
            view: 2,
            timeout_certificate: H2TimeoutCertificate {
                view: 1,
                aggregate_signature: vec![0; 96],
                signers_bitmap: bitmap(N, &[0, 1, 2]),
                high_qc: qc(0),
            },
            leader: 2,
            signature: signature(),
        });
        assert_eq!(p.consensus_verdict(&new_view), GossipVerdict::Accept, "a NewView is never stale");
    }

    #[test]
    fn out_of_range_fields_are_rejected() {
        let p = p1();
        let reject = |m: &H2Message| matches!(p.consensus_verdict(m), GossipVerdict::Reject(_));
        assert!(reject(&vote(u64::MAX)));
        assert!(reject(&proposal(5, 5)), "justify QC not below the proposal");
        assert!(reject(&proposal(5, 7)));
        assert!(reject(&decide(5, 4)), "commit QC view differs from the Decide's");
        let mut wide = qc(4);
        wide.signers_bitmap = bitmap(N + 1, &[0]);
        assert!(reject(&H2Message::Decide(H2Decide { view: 4, block_hash: B256::ZERO, commit_qc: wide })));
        let mut outside = qc(4);
        outside.signers_bitmap[2] |= 1 << N;
        assert!(reject(&H2Message::Decide(H2Decide { view: 4, block_hash: B256::ZERO, commit_qc: outside })));
        let mut short = qc(4);
        short.signers_bitmap.pop();
        assert!(reject(&H2Message::Decide(H2Decide { view: 4, block_hash: B256::ZERO, commit_qc: short })));
        let H2Message::Vote(mut v) = vote(3) else { unreachable!() };
        v.voter = N as u32;
        assert!(reject(&H2Message::Vote(v)), "voter outside the set");
        let timeout = H2Message::Timeout(H2Timeout {
            view: 6,
            high_qc: qc(u64::MAX),
            sender: 0,
            signature: signature(),
            high_tc: None,
        });
        assert!(reject(&timeout), "a nested QC at 2^64-1");
        // The genesis QC (view 0, empty bitmap) is the handler's.
        let mut genesis = qc(0);
        genesis.signers_bitmap.clear();
        let first = H2Message::Proposal(H2Proposal {
            view: 1,
            block_hash: B256::ZERO,
            justify_qc: genesis,
            proposer: 1,
            signature: signature(),
            prepare_qc: None,
            tx_root_hash: B256::ZERO,
        });
        assert_eq!(p.consensus_verdict(&first), GossipVerdict::Accept);
    }

    #[test]
    fn a_piggybacked_tc_is_only_bound_checked() {
        let p = p1();
        let tc = |view| H2TimeoutCertificate {
            view,
            aggregate_signature: vec![0; 96],
            signers_bitmap: bitmap(N + 3, &[0]),
            high_qc: qc(1),
        };
        let with = |tc| H2Message::Vote(H2Vote { view: 3, block_hash: B256::ZERO, voter: 0, signature: signature(), high_tc: Some(tc) });
        assert_eq!(p.consensus_verdict(&with(tc(2))), GossipVerdict::Accept);
        assert!(matches!(p.consensus_verdict(&with(tc(u64::MAX))), GossipVerdict::Reject(_)));
    }

    fn snappy(bytes: &[u8]) -> Vec<u8> {
        snap::raw::Encoder::new().compress_vec(bytes).unwrap()
    }

    fn signed_1559() -> Vec<u8> {
        use alloy_consensus::{SignableTransaction, TxEip1559};
        use alloy_eips::eip2718::Encodable2718;
        let tx = TxEip1559 { chain_id: 1, gas_limit: 21_000, ..Default::default() };
        let sig = alloy_primitives::Signature::new(U256::from(1), U256::from(1), false);
        TxEnvelope::from(tx.into_signed(sig)).encoded_2718()
    }

    fn batch(entries: &[Vec<u8>]) -> Vec<u8> {
        let entries: Vec<alloy_primitives::Bytes> = entries.iter().cloned().map(Into::into).collect();
        snappy(&crate::tx_gossip::encode_tx_batch(&entries).unwrap())
    }

    #[test]
    fn transactions_follow_item_8() {
        let good = signed_1559();
        assert_eq!(transactions_verdict(&snappy(&good)), GossipVerdict::Accept);
        assert_eq!(transactions_verdict(&batch(&[good.clone(), good.clone()])), GossipVerdict::Accept);
        // A type this client cannot decode, 0x05 and 0x50: ignored.
        assert!(matches!(transactions_verdict(&batch(&[good.clone(), vec![0x05, 0xc0]])), GossipVerdict::Ignore(_)));
        assert!(matches!(transactions_verdict(&batch(&[vec![0x50, 1, 2, 3]])), GossipVerdict::Ignore(_)));
        // An empty batch: ignored.
        let mut empty = vec![TX_BATCH_MARKER];
        Vec::<alloy_primitives::Bytes>::new().encode(&mut empty);
        assert!(matches!(transactions_verdict(&snappy(&empty)), GossipVerdict::Ignore(_)));
        // A truncated known type, a byte string, broken snappy: rejected.
        let truncated = good[..good.len() - 3].to_vec();
        assert!(matches!(transactions_verdict(&batch(&[good, truncated])), GossipVerdict::Reject(_)));
        assert!(matches!(transactions_verdict(&batch(&[vec![0x85, 1, 2, 3, 4, 5]])), GossipVerdict::Reject(_)));
        assert!(matches!(transactions_verdict(b"\xffnot snappy"), GossipVerdict::Reject(_)));
    }

    #[test]
    fn another_chains_v4_message_is_ignored_and_a_broken_one_rejected() {
        use n42_h2_primitives::consensus::H2V4ChainIdentity;
        use n42_h2_wire::h2_v4::{decode_gossip, encode_gossip, H2V4Envelope};
        let ours = H2V4ChainIdentity { chain_id: 1, genesis_hash: B256::repeat_byte(1) };
        let theirs = H2V4ChainIdentity { chain_id: 2, genesis_hash: B256::repeat_byte(2) };
        let wire = encode_gossip(&H2V4Envelope { identity: theirs, changes_hash: B256::ZERO, message: vote(3) }).unwrap();
        let err = decode_gossip(&wire, ours).unwrap_err();
        assert!(matches!(envelope_error_verdict(&err), GossipVerdict::Ignore(_)));
        let err = decode_gossip(b"junk", ours).unwrap_err();
        assert!(matches!(envelope_error_verdict(&err), GossipVerdict::Reject(_)));
    }

    #[test]
    fn registrations_are_exactly_pubkey_and_pop() {
        assert_eq!(registration_verdict(&[0; REGISTRATION_LEN]), GossipVerdict::Accept);
        assert!(matches!(registration_verdict(&[0; REGISTRATION_LEN - 1]), GossipVerdict::Reject(_)));
        assert!(matches!(registration_verdict(&[0; REGISTRATION_LEN + 1]), GossipVerdict::Reject(_)));
    }

    #[test]
    fn packets_wait_for_the_service() {
        let p = p1();
        assert!(matches!(p.mobile_verdict(MobileTopic::Packet, b"x"), GossipVerdict::Ignore(_)));
        p.mobile_packets.install(Arc::new(|data: &[u8]| {
            if data == b"ok" { GossipVerdict::Accept } else { GossipVerdict::Reject("bad".into()) }
        }));
        assert_eq!(p.mobile_verdict(MobileTopic::Packet, b"ok"), GossipVerdict::Accept);
        assert!(matches!(p.mobile_verdict(MobileTopic::Packet, b"no"), GossipVerdict::Reject(_)));
    }

    #[test]
    fn a_block_that_does_not_decode_is_rejected() {
        assert!(check_block(&snappy(b"\xc0"), HeaderProfile::Gov5H2).is_err());
        assert!(check_block(b"\xffnot snappy", HeaderProfile::Gov5H2).is_err());
    }
}
