// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Translation between gov5's v4 wire messages and the engine's own types.
//!
//! [`n42_h2_wire::H2Message`] is what crosses the network — gov5's byte layout,
//! fixed by a cross-client contract. [`ConsensusMessage`] is what the engine
//! reasons about. They line up field for field, but they are not the same shape,
//! and two of the differences are load-bearing:
//!
//! **Signer bitmaps have opposite bit order.** gov5 encodes a QC's signers as a
//! `uint16` little-endian validator count followed by LSB-first bits — validator
//! *i* is bit `1 << (i % 8)` of byte `2 + i / 8`. The engine holds them in a
//! `BitVec<u8, Msb0>`, where index *i* is bit `7 - (i % 8)`. Copying the bytes
//! across would silently reverse every group of eight signers, producing a
//! bitmap that still passes a length check and still names *some* quorum — which
//! is exactly the kind of bug that survives until a fleet disagrees about who
//! signed. Both directions here go through the validator index.
//!
//! **The wire carries a `high_tc` the engine has no field for.** gov5 piggybacks
//! a timeout certificate on votes and timeouts to speed up view recovery. This
//! engine recovers without it, so inbound `high_tc` is dropped and outbound
//! messages never carry one. That costs recovery latency after a timeout, never
//! safety: a TC is evidence used to *justify* a view jump, and ignoring evidence
//! can only make this node slower to advance, not willing to advance further
//! than it should.
//!
//! `changes_hash` lives on the envelope, not the message, because it is bound
//! into the BLS preimage of every commit vote — so translation happens at the
//! envelope level in both directions. The engine keeps its own per-block cache
//! of it and only `Decide` carries it explicitly (a `Decide` has no signature of
//! its own, so it must name the hash its commit QC was signed under). Outbound,
//! the caller supplies it: this layer does not decide what the fleet's
//! reconfiguration policy is.
//!
//! Validator changes are the one asymmetry that is refused rather than dropped.
//! The engine's `Proposal` can carry them; the v4 wire format has no field for
//! them, and the deployed profile pins `changes_hash` to zero. Encoding such a
//! proposal would put a message on the wire that every peer reads as
//! change-free, so the two sides would commit different validator sets from the
//! same block. That is a consensus split, so it is an error here.

use alloy_primitives::B256;
use bitvec::order::Msb0;
use bitvec::vec::BitVec;
use n42_h2_primitives::bls::BlsSignature;
use n42_h2_primitives::consensus::{
    CommitVote, ConsensusMessage, Decide, NewView, PrepareQC, Proposal, QuorumCertificate,
    TimeoutCertificate, TimeoutMessage, Vote,
};
use n42_h2_primitives::consensus::H2V4ChainIdentity;
use n42_h2_wire::h2_v4::H2V4Envelope;
use n42_h2_wire::h2_wire::{
    H2Decide, H2NewView, H2PrepareQc, H2Proposal, H2QuorumCertificate, H2Timeout,
    H2TimeoutCertificate, H2Vote,
};
use n42_h2_wire::H2Message;

/// Why a message could not be translated.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// A signer bitmap was not canonical for the validator set: wrong length,
    /// wrong embedded count, or padding bits set past the end of the set.
    /// Accepting one would mean disagreeing with gov5 about who signed.
    #[error("{component} signer bitmap is not canonical for a validator set of {expected}")]
    InvalidBitmap {
        /// Which certificate carried it.
        component: &'static str,
        /// The validator count the bitmap was checked against.
        expected: usize,
    },
    /// An aggregate signature was not a valid BLS signature.
    #[error("{component} aggregate signature is not a valid BLS signature")]
    InvalidSignature {
        /// Which certificate carried it.
        component: &'static str,
    },
    /// A proposal carried validator changes, which the v4 wire format cannot
    /// express. See the module docs: encoding it anyway would split the fleet.
    #[error("proposal carries validator changes, which the v4 wire format cannot express")]
    ValidatorChangesNotRepresentable,
    /// The validator set is larger than a `uint16` count can encode.
    #[error("validator set of {0} is too large for the v4 signer bitmap")]
    ValidatorSetTooLarge(usize),
    /// A `Decide` names a different `validator_changes_hash` than the envelope
    /// it would be sent in. The two must agree: peers verify the commit QC
    /// against the envelope's copy, and the engine against the message's, so a
    /// mismatch means the same Decide is valid on one side and not the other.
    #[error("Decide names changes hash {decide}, envelope carries {envelope}")]
    ChangesHashMismatch {
        /// What the message says.
        decide: B256,
        /// What the envelope would say.
        envelope: B256,
    },
}

/// The number of validators a bitmap encodes, or `None` if it is malformed.
///
/// gov5 writes the count into the bitmap itself, so this can be read before the
/// validator set is known — useful for rejecting a message from a fleet running
/// a different set size without doing any crypto.
pub fn bitmap_validator_count(bitmap: &[u8]) -> Option<usize> {
    bitmap
        .get(..2)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_le_bytes)
        .map(usize::from)
}

/// Decodes a gov5 signer bitmap into the engine's `Msb0` bit vector.
///
/// Canonical form is strict on purpose: the embedded count must equal
/// `validator_count`, the length must be exactly the bytes that count needs, and
/// padding bits past the end must be zero. A bitmap that merely *parses* is not
/// good enough — two clients that disagree about the signer set of a QC will
/// disagree about whether it reaches quorum.
fn decode_bitmap(
    bitmap: &[u8],
    validator_count: usize,
    component: &'static str,
) -> Result<BitVec<u8, Msb0>, BridgeError> {
    let err = || BridgeError::InvalidBitmap {
        component,
        expected: validator_count,
    };
    let byte_count = validator_count.div_ceil(8);
    if bitmap_validator_count(bitmap) != Some(validator_count) || bitmap.len() != 2 + byte_count {
        return Err(err());
    }
    if !validator_count.is_multiple_of(8) {
        let used_mask = (1u16 << (validator_count % 8)) as u8 - 1;
        if bitmap.last().is_some_and(|last| last & !used_mask != 0) {
            return Err(err());
        }
    }

    let mut bits = BitVec::<u8, Msb0>::repeat(false, validator_count);
    for index in 0..validator_count {
        // gov5 is LSB-first within each byte; `bits` is Msb0. Going through the
        // index is what keeps the two orders from being confused.
        if bitmap[2 + index / 8] & (1 << (index % 8)) != 0 {
            bits.set(index, true);
        }
    }
    Ok(bits)
}

/// Encodes the engine's bit vector into gov5's signer bitmap.
fn encode_bitmap(bits: &BitVec<u8, Msb0>) -> Result<Vec<u8>, BridgeError> {
    let validator_count = bits.len();
    let count = u16::try_from(validator_count)
        .map_err(|_| BridgeError::ValidatorSetTooLarge(validator_count))?;
    let mut bitmap = Vec::with_capacity(2 + validator_count.div_ceil(8));
    bitmap.extend_from_slice(&count.to_le_bytes());
    bitmap.resize(2 + validator_count.div_ceil(8), 0);
    for (index, bit) in bits.iter().enumerate() {
        if *bit {
            bitmap[2 + index / 8] |= 1 << (index % 8);
        }
    }
    Ok(bitmap)
}

/// The empty QC gov5 uses for the genesis view.
///
/// It has no signers and no signature, so it cannot go through the normal
/// decode path — there is nothing to verify and no set size to check against.
///
/// Two spellings of its bitmap exist and both have to be accepted. The wire
/// codec rejects a bitmap whose embedded count is zero, so a genesis QC crosses
/// the network with an *empty* bitmap; `[0, 0]` is the in-memory spelling used
/// elsewhere in this crate. Emitting `[0, 0]` is what made every proposal this
/// node built unpublishable, with the failure surfacing as "non-canonical
/// bitmap" three layers away from the cause.
fn is_genesis_qc(qc: &H2QuorumCertificate) -> bool {
    qc.view == 0
        && qc.block_hash == B256::ZERO
        && qc.aggregate_signature.is_empty()
        && (qc.signers_bitmap.is_empty() || qc.signers_bitmap == [0, 0])
}

fn signature_from_wire(
    bytes: &[u8],
    component: &'static str,
) -> Result<BlsSignature, BridgeError> {
    let bytes: [u8; 96] = bytes
        .try_into()
        .map_err(|_| BridgeError::InvalidSignature { component })?;
    BlsSignature::from_bytes(&bytes).map_err(|_| BridgeError::InvalidSignature { component })
}

/// Translates a wire QC into the engine's representation.
pub fn qc_to_engine(
    qc: &H2QuorumCertificate,
    validator_count: usize,
    component: &'static str,
) -> Result<QuorumCertificate, BridgeError> {
    if is_genesis_qc(qc) {
        return Ok(QuorumCertificate::genesis());
    }
    Ok(QuorumCertificate {
        view: qc.view,
        block_hash: qc.block_hash,
        aggregate_signature: signature_from_wire(&qc.aggregate_signature, component)?,
        signers: decode_bitmap(&qc.signers_bitmap, validator_count, component)?,
    })
}

/// Translates an engine QC onto the wire.
pub fn qc_to_wire(qc: &QuorumCertificate) -> Result<H2QuorumCertificate, BridgeError> {
    if qc.signers.is_empty() && qc.view == 0 && qc.block_hash == B256::ZERO {
        return Ok(H2QuorumCertificate {
            view: 0,
            block_hash: B256::ZERO,
            aggregate_signature: Vec::new(),
            // Empty, not [0, 0]: the wire codec rejects a zero count.
            signers_bitmap: Vec::new(),
        });
    }
    Ok(H2QuorumCertificate {
        view: qc.view,
        block_hash: qc.block_hash,
        aggregate_signature: qc.aggregate_signature.to_bytes().to_vec(),
        signers_bitmap: encode_bitmap(&qc.signers)?,
    })
}

/// Translates a wire TC into the engine's representation.
pub fn tc_to_engine(
    tc: &H2TimeoutCertificate,
    validator_count: usize,
) -> Result<TimeoutCertificate, BridgeError> {
    Ok(TimeoutCertificate {
        view: tc.view,
        aggregate_signature: signature_from_wire(&tc.aggregate_signature, "TimeoutCertificate")?,
        signers: decode_bitmap(&tc.signers_bitmap, validator_count, "TimeoutCertificate")?,
        high_qc: qc_to_engine(&tc.high_qc, validator_count, "TimeoutCertificate.high_qc")?,
    })
}

/// Translates an engine TC onto the wire.
pub fn tc_to_wire(tc: &TimeoutCertificate) -> Result<H2TimeoutCertificate, BridgeError> {
    Ok(H2TimeoutCertificate {
        view: tc.view,
        aggregate_signature: tc.aggregate_signature.to_bytes().to_vec(),
        signers_bitmap: encode_bitmap(&tc.signers)?,
        high_qc: qc_to_wire(&tc.high_qc)?,
    })
}

/// Translates an envelope received from the fleet into what the engine consumes.
///
/// `validator_count` is the size of the set the certificates in this message are
/// expected to have been signed by. A mismatch is rejected rather than guessed
/// at: a bitmap read against the wrong set size names the wrong signers.
pub fn to_engine(
    envelope: &H2V4Envelope,
    validator_count: usize,
) -> Result<ConsensusMessage, BridgeError> {
    Ok(match &envelope.message {
        H2Message::Proposal(p) => ConsensusMessage::Proposal(Proposal {
            view: p.view,
            block_hash: p.block_hash,
            justify_qc: qc_to_engine(&p.justify_qc, validator_count, "Proposal.justify_qc")?,
            proposer: p.proposer,
            signature: p.signature.clone(),
            prepare_qc: p
                .prepare_qc
                .as_ref()
                .map(|qc| qc_to_engine(qc, validator_count, "Proposal.prepare_qc"))
                .transpose()?,
            // gov5 always carries a tx root; the engine treats it as optional
            // because its own proposals predate Baby Raptr DA.
            tx_root_hash: Some(p.tx_root_hash),
            // The v4 profile is static-validator. A proposal off this wire
            // cannot carry changes, which is different from carrying none:
            // `None` tells followers to clear their pending queue, which is the
            // correct instruction on a chain that has no reconfiguration.
            validator_changes: None,
        }),
        // `high_tc` is dropped here — see the module docs. It is a recovery
        // accelerator, and this engine recovers without it.
        H2Message::Vote(v) => ConsensusMessage::Vote(Vote {
            view: v.view,
            block_hash: v.block_hash,
            voter: v.voter,
            signature: v.signature.clone(),
        }),
        H2Message::CommitVote(v) => ConsensusMessage::CommitVote(CommitVote {
            view: v.view,
            block_hash: v.block_hash,
            voter: v.voter,
            signature: v.signature.clone(),
        }),
        H2Message::PrepareQc(p) => ConsensusMessage::PrepareQC(PrepareQC {
            view: p.view,
            block_hash: p.block_hash,
            qc: qc_to_engine(&p.qc, validator_count, "PrepareQC.qc")?,
        }),
        H2Message::Timeout(t) => ConsensusMessage::Timeout(TimeoutMessage {
            view: t.view,
            high_qc: qc_to_engine(&t.high_qc, validator_count, "Timeout.high_qc")?,
            sender: t.sender,
            signature: t.signature.clone(),
        }),
        H2Message::NewView(n) => ConsensusMessage::NewView(NewView {
            view: n.view,
            timeout_cert: tc_to_engine(&n.timeout_certificate, validator_count)?,
            leader: n.leader,
            signature: n.signature.clone(),
        }),
        H2Message::Decide(d) => ConsensusMessage::Decide(Decide {
            view: d.view,
            block_hash: d.block_hash,
            commit_qc: qc_to_engine(&d.commit_qc, validator_count, "Decide.commit_qc")?,
            // A Decide has no signature of its own, so it must name the hash its
            // commit QC was signed under, and the envelope is where the wire
            // carries it.
            validator_changes_hash: envelope.changes_hash,
        }),
    })
}

/// Translates a message the engine emits into a gov5 wire envelope.
///
/// `changes_hash` is the value the message's signatures were produced under.
/// The engine keeps it per block, so the caller reads it from there; on a
/// static-validator v4 chain it is [`B256::ZERO`] throughout. It is a parameter
/// rather than an assumption because getting it wrong makes every commit vote
/// this node sends unverifiable, with no local symptom.
pub fn to_wire(
    message: &ConsensusMessage,
    identity: H2V4ChainIdentity,
    changes_hash: B256,
) -> Result<H2V4Envelope, BridgeError> {
    let message = match message {
        ConsensusMessage::Proposal(p) => {
            if p.validator_changes.as_ref().is_some_and(|c| !c.is_empty()) {
                return Err(BridgeError::ValidatorChangesNotRepresentable);
            }
            H2Message::Proposal(H2Proposal {
                view: p.view,
                block_hash: p.block_hash,
                justify_qc: qc_to_wire(&p.justify_qc)?,
                proposer: p.proposer,
                signature: p.signature.clone(),
                prepare_qc: p.prepare_qc.as_ref().map(qc_to_wire).transpose()?,
                // gov5's field is not optional. A proposal with no tx root is
                // encoded as the zero hash, which is what gov5 itself sends for
                // an empty block.
                tx_root_hash: p.tx_root_hash.unwrap_or(B256::ZERO),
            })
        }
        ConsensusMessage::Vote(v) => H2Message::Vote(H2Vote {
            view: v.view,
            block_hash: v.block_hash,
            voter: v.voter,
            signature: v.signature.clone(),
            high_tc: None,
        }),
        ConsensusMessage::CommitVote(v) => H2Message::CommitVote(H2Vote {
            view: v.view,
            block_hash: v.block_hash,
            voter: v.voter,
            signature: v.signature.clone(),
            high_tc: None,
        }),
        ConsensusMessage::PrepareQC(p) => H2Message::PrepareQc(H2PrepareQc {
            view: p.view,
            block_hash: p.block_hash,
            qc: qc_to_wire(&p.qc)?,
        }),
        ConsensusMessage::Timeout(t) => H2Message::Timeout(H2Timeout {
            view: t.view,
            high_qc: qc_to_wire(&t.high_qc)?,
            sender: t.sender,
            signature: t.signature.clone(),
            high_tc: None,
        }),
        ConsensusMessage::NewView(n) => H2Message::NewView(H2NewView {
            view: n.view,
            timeout_certificate: tc_to_wire(&n.timeout_cert)?,
            leader: n.leader,
            signature: n.signature.clone(),
        }),
        ConsensusMessage::Decide(d) => {
            if d.validator_changes_hash != changes_hash {
                return Err(BridgeError::ChangesHashMismatch {
                    decide: d.validator_changes_hash,
                    envelope: changes_hash,
                });
            }
            H2Message::Decide(H2Decide {
                view: d.view,
                block_hash: d.block_hash,
                commit_qc: qc_to_wire(&d.commit_qc)?,
            })
        }
    };
    Ok(H2V4Envelope {
        identity,
        changes_hash,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use n42_h2_wire::h2_v4::{decode_envelope, encode_envelope};

    #[derive(serde::Deserialize)]
    struct Fixture {
        chain_id: u64,
        genesis_hash: String,
        validator_public_keys: Vec<String>,
        envelope_hex: String,
    }

    fn fixture() -> (H2V4Envelope, usize, Vec<u8>) {
        let f: Fixture =
            serde_json::from_str(include_str!("../testdata/h2_v4_finality_v1.json")).unwrap();
        let identity = H2V4ChainIdentity {
            chain_id: f.chain_id,
            genesis_hash: B256::from_slice(&hex::decode(&f.genesis_hash).unwrap()),
        };
        let bytes = hex::decode(&f.envelope_hex).unwrap();
        let envelope = decode_envelope(&bytes, identity).unwrap();
        (envelope, f.validator_public_keys.len(), bytes)
    }

    /// The whole point of the bridge: what comes off gov5's wire and goes back
    /// on must be the same bytes. Anything that survives a decode but not a
    /// re-encode is a message this node would relay in a form its peers reject.
    #[test]
    fn gov5_envelope_round_trips_through_the_engine_types_byte_for_byte() {
        let (envelope, validator_count, original_bytes) = fixture();

        let engine_message = to_engine(&envelope, validator_count).unwrap();
        let back = to_wire(&engine_message, envelope.identity, envelope.changes_hash).unwrap();

        assert_eq!(back, envelope, "envelope did not survive the round trip");
        assert_eq!(
            encode_envelope(&back).unwrap(),
            original_bytes,
            "re-encoded bytes differ from gov5's fixture"
        );
    }

    /// gov5 packs signers LSB-first; the engine holds them Msb0. A byte copy
    /// would reverse each group of eight and still look well-formed, so this
    /// pins the actual layout rather than just checking a round trip.
    #[test]
    fn signer_bitmaps_keep_gov5_bit_order_rather_than_the_engines() {
        // Five validators, only index 0 signed.
        let bitmap = vec![5, 0, 0b0000_0001];
        let bits = decode_bitmap(&bitmap, 5, "test").unwrap();

        assert!(bits[0], "validator 0 signed");
        assert_eq!(bits.count_ones(), 1);
        // The Msb0 view of that same byte would name validator 7 — outside a
        // 5-validator set entirely, which is how this bug hides.
        assert!(!bits[4]);

        assert_eq!(encode_bitmap(&bits).unwrap(), bitmap);
    }

    #[test]
    fn signer_bitmaps_round_trip_for_every_subset_of_a_nine_validator_set() {
        // Nine crosses a byte boundary, which is where a bit-order or padding
        // mistake shows up.
        for mask in 0u32..(1 << 9) {
            let mut bits = BitVec::<u8, Msb0>::repeat(false, 9);
            for index in 0..9 {
                if mask & (1 << index) != 0 {
                    bits.set(index, true);
                }
            }
            let encoded = encode_bitmap(&bits).unwrap();
            assert_eq!(encoded.len(), 2 + 2);
            assert_eq!(bitmap_validator_count(&encoded), Some(9));
            assert_eq!(decode_bitmap(&encoded, 9, "test").unwrap(), bits);
        }
    }

    #[test]
    fn non_canonical_bitmaps_are_rejected() {
        // Padding bits set past the end of the set. gov5 never emits this, and
        // accepting it would let two peers read different signer sets from the
        // same bytes.
        let padded = vec![5, 0, 0b0010_0001];
        assert!(decode_bitmap(&padded, 5, "test").is_err());

        // Embedded count disagrees with the set size.
        let wrong_count = vec![4, 0, 0b0000_0001];
        assert!(decode_bitmap(&wrong_count, 5, "test").is_err());

        // Length disagrees with the count.
        let short = vec![9, 0, 0b0000_0001];
        assert!(decode_bitmap(&short, 9, "test").is_err());
    }

    #[test]
    /// The genesis QC is what every first proposal's `justify_qc` is, so getting
    /// its encoding wrong makes a node unable to propose at all — and the wire
    /// codec reports that as a bitmap error, three layers from the cause.
    fn the_genesis_qc_encodes_to_something_the_wire_codec_accepts() {
        let engine = QuorumCertificate::genesis();
        let wire = qc_to_wire(&engine).unwrap();

        // Empty, not [0, 0]: `validate_bitmap` rejects an embedded count of
        // zero, so [0, 0] would be refused on the way out.
        assert!(wire.signers_bitmap.is_empty());

        let envelope = H2V4Envelope {
            identity: H2V4ChainIdentity {
                chain_id: 96,
                genesis_hash: B256::repeat_byte(0x42),
            },
            changes_hash: B256::ZERO,
            message: H2Message::Decide(H2Decide {
                view: 1,
                block_hash: B256::repeat_byte(0x11),
                commit_qc: wire.clone(),
            }),
        };
        encode_envelope(&envelope).expect("a genesis QC must be encodable");

        // Both spellings decode back to the same genesis QC: the wire uses an
        // empty bitmap, the rest of this crate writes [0, 0].
        assert_eq!(qc_to_engine(&wire, 4, "test").unwrap().view, 0);
        let legacy = H2QuorumCertificate {
            signers_bitmap: vec![0, 0],
            ..wire
        };
        assert_eq!(qc_to_engine(&legacy, 4, "test").unwrap().view, 0);
    }

    #[test]
    fn a_proposal_carrying_validator_changes_is_refused_not_silently_flattened() {
        let (envelope, validator_count, _) = fixture();
        let identity = envelope.identity;
        let decide = to_engine(&envelope, validator_count).unwrap();
        let ConsensusMessage::Decide(decide) = decide else {
            panic!("fixture is a Decide");
        };

        let proposal = ConsensusMessage::Proposal(Proposal {
            view: decide.view,
            block_hash: decide.block_hash,
            justify_qc: decide.commit_qc.clone(),
            proposer: 0,
            signature: decide.commit_qc.aggregate_signature.clone(),
            prepare_qc: None,
            tx_root_hash: None,
            validator_changes: Some(vec![
                n42_h2_primitives::consensus::ValidatorChange::Remove {
                    address: alloy_primitives::Address::with_last_byte(9),
                },
            ]),
        });

        match to_wire(&proposal, identity, B256::ZERO) {
            Err(BridgeError::ValidatorChangesNotRepresentable) => {}
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_decide_disagreeing_with_its_envelope_about_changes_hash_is_refused() {
        let (envelope, validator_count, _) = fixture();
        let message = to_engine(&envelope, validator_count).unwrap();

        // Same message, envelope claiming a different changes hash. Peers verify
        // the commit QC against the envelope's copy and the engine against the
        // message's, so letting this through makes one Decide valid on one side
        // and invalid on the other.
        match to_wire(&message, envelope.identity, B256::repeat_byte(0xAB)) {
            Err(BridgeError::ChangesHashMismatch { .. }) => {}
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_bitmap_read_against_the_wrong_validator_count_is_rejected() {
        let (envelope, validator_count, _) = fixture();
        // Guessing the set size would name the wrong signers while still
        // producing a plausible-looking quorum.
        assert!(to_engine(&envelope, validator_count + 1).is_err());
        assert!(to_engine(&envelope, validator_count - 1).is_err());
    }
}
