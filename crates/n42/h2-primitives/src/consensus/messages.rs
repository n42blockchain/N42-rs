use crate::bls::BlsSignature;
use alloy_primitives::{Address, B256};
use bitvec::prelude::*;
use serde::{Deserialize, Serialize};

/// Compact serde helper for `BitVec<u8, Msb0>`.
///
/// The default bitvec serde serializes each bit as a separate `bool` (1 byte each
/// in bincode), making a 500-bit vector occupy 508 bytes instead of 65.
///
/// This module serializes as `(u16 bit_count, Vec<u8> packed_bytes)` — the same
/// layout the raw `BitVec` uses in memory.
mod packed_bits {
    use bitvec::prelude::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bv: &BitVec<u8, Msb0>, s: S) -> Result<S::Ok, S::Error> {
        let bit_count = bv.len() as u16;
        let raw_bytes: &[u8] = bv.as_raw_slice();
        (bit_count, raw_bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BitVec<u8, Msb0>, D::Error> {
        let (bit_count, raw_bytes): (u16, Vec<u8>) = Deserialize::deserialize(d)?;
        let needed = (bit_count as usize).div_ceil(8);
        if raw_bytes.len() != needed {
            return Err(serde::de::Error::custom(format!(
                "packed_bits: expected {needed} bytes for {bit_count} bits, got {}",
                raw_bytes.len()
            )));
        }
        let mut bv = BitVec::<u8, Msb0>::from_vec(raw_bytes);
        bv.truncate(bit_count as usize);
        Ok(bv)
    }
}

/// View number (monotonically increasing round identifier).
pub type ViewNumber = u64;

/// Validator index within the validator set.
pub type ValidatorIndex = u32;

/// A quorum certificate: aggregated BLS signature + signer bitmap.
/// Proves that n-f validators from the active set signed a particular message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// The view this QC was formed in.
    pub view: ViewNumber,
    /// Block hash that was voted on.
    pub block_hash: B256,
    /// Aggregated BLS signature from n-f validators.
    pub aggregate_signature: BlsSignature,
    /// Bitmap indicating which validators signed (1 bit per validator).
    #[serde(with = "packed_bits")]
    pub signers: BitVec<u8, Msb0>,
}

impl QuorumCertificate {
    /// Returns the number of signers.
    pub fn signer_count(&self) -> usize {
        self.signers.count_ones()
    }

    /// Creates a genesis QC (no signatures, view 0) with a deterministic dummy signature.
    /// The signature is never verified; the genesis QC is a sentinel value.
    pub fn genesis() -> Self {
        use crate::bls::BlsSecretKey;

        let ikm = [1u8; 32];
        let dummy_sig = BlsSecretKey::key_gen(&ikm)
            .expect("deterministic genesis key derivation should succeed")
            .sign(b"genesis");

        Self {
            view: 0,
            block_hash: B256::ZERO,
            aggregate_signature: dummy_sig,
            signers: BitVec::new(),
        }
    }
}

/// A timeout certificate: proves that n-f validators timed out in a given view.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeoutCertificate {
    /// The view that timed out.
    pub view: ViewNumber,
    /// Aggregated timeout signature.
    pub aggregate_signature: BlsSignature,
    /// Bitmap of validators that timed out.
    #[serde(with = "packed_bits")]
    pub signers: BitVec<u8, Msb0>,
    /// The highest QC known by any of the timeout signers.
    pub high_qc: QuorumCertificate,
}

/// A proposed validator set change, carried in [`Proposal`] messages so that
/// all validators apply the same changes at CommitQC time.
///
/// Without this, `pending_adds` / `pending_removes` in the epoch manager are
/// local to the node that received the admin RPC call, leading to split-brain
/// at epoch boundaries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ValidatorChange {
    /// Add a new validator to the set at the next epoch boundary.
    Add {
        address: Address,
        bls_public_key: crate::BlsPublicKey,
        // No `skip_serializing_if`/`default` attrs: bincode is positional and
        // skipping a field on the wire makes the receiver fail with
        // "unexpected end of file" — exactly the silent rejection that
        // prevented dynamic validator changes from propagating.
        p2p_peer_id: Option<String>,
    },
    /// Remove a validator by address at the next epoch boundary.
    Remove { address: Address },
}

/// Leader proposal message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    /// Current view number.
    pub view: ViewNumber,
    /// Hash of the proposed block.
    pub block_hash: B256,
    /// The QC that justifies this proposal (from the previous round).
    pub justify_qc: QuorumCertificate,
    /// Proposer's validator index.
    pub proposer: ValidatorIndex,
    /// Proposer's BLS signature over (view, block_hash).
    pub signature: BlsSignature,
    /// Piggybacked PrepareQC from the previous view (chained mode).
    /// When present, allows followers to receive the PrepareQC earlier
    /// without waiting for the separate PrepareQC broadcast.
    /// None if the previous view timed out or no QC was formed.
    pub prepare_qc: Option<QuorumCertificate>,
    /// Transaction root hash for Baby Raptr DA verification.
    /// Followers compare against actual tx root after block import.
    #[serde(default)]
    pub tx_root_hash: Option<B256>,
    /// Proposed validator set changes (commit-then-activate protocol).
    ///
    /// When the leader has pending validator additions/removals (from admin RPC),
    /// they are included here so that **all** validators apply identical changes
    /// at CommitQC time.  Followers replace their own local pending queue with
    /// the leader's changes upon receiving the proposal.  `None` means the leader
    /// has no pending changes; followers must clear their own pending queue to
    /// stay consistent.
    #[serde(default)]
    pub validator_changes: Option<Vec<ValidatorChange>>,
}

/// Vote message (Round 1: Prepare).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    /// View being voted on.
    pub view: ViewNumber,
    /// Block hash being voted for.
    pub block_hash: B256,
    /// Voter's validator index.
    pub voter: ValidatorIndex,
    /// BLS signature over (view, block_hash).
    pub signature: BlsSignature,
}

/// Commit vote (Round 2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitVote {
    /// View being committed.
    pub view: ViewNumber,
    /// Block hash being committed.
    pub block_hash: B256,
    /// Voter's validator index.
    pub voter: ValidatorIndex,
    /// BLS signature over ("commit", view, block_hash).
    pub signature: BlsSignature,
}

/// Timeout message: sent when a validator's timer expires.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeoutMessage {
    /// View that timed out.
    pub view: ViewNumber,
    /// The highest QC this validator knows of.
    pub high_qc: QuorumCertificate,
    /// Sender's validator index.
    pub sender: ValidatorIndex,
    /// BLS signature over `timeout_signing_message(view)` (`"timeout" || view`).
    pub signature: BlsSignature,
}

/// NewView message: sent by the new leader after collecting a TC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewView {
    /// The new view number.
    pub view: ViewNumber,
    /// The timeout certificate that triggered the view change.
    pub timeout_cert: TimeoutCertificate,
    /// New leader's validator index.
    pub leader: ValidatorIndex,
    /// BLS signature over `newview_signing_message(view)` (`"newview" || view`).
    pub signature: BlsSignature,
}

/// PrepareQC message: leader broadcasts after forming Round 1 QC.
/// Validators receive this and respond with CommitVote (Round 2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrepareQC {
    /// The view this QC was formed in.
    pub view: ViewNumber,
    /// Block hash that was voted on.
    pub block_hash: B256,
    /// The quorum certificate formed from Round 1 votes.
    pub qc: QuorumCertificate,
}

/// Decide message: leader broadcasts after forming CommitQC.
/// Tells all followers the block is committed so they can finalize and advance view.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decide {
    /// The view this decision is for.
    pub view: ViewNumber,
    /// Block hash that was committed.
    pub block_hash: B256,
    /// The CommitQC that proves n-f validators committed.
    pub commit_qc: QuorumCertificate,
    /// Blake3 hash of the serialized `validator_changes` from the Proposal.
    /// Non-zero when the committed Proposal carried validator changes.
    ///
    /// Followers that missed the Proposal use this to detect missing changes
    /// and request resync.  Only the hash is carried (not the full changes)
    /// because the Decide has no BLS signature — carrying unauthenticated
    /// data would be a security risk.
    #[serde(default)]
    pub validator_changes_hash: B256,
}

/// Current consensus protocol wire format version.
/// Increment for wire-format or consensus-rule changes that make mixed-version
/// validator operation unsafe.
// v3 (HotStuff-2 audit Plan #2): R2 commit-vote signing message now includes
//     the proposal's `validator_changes_hash`. Old nodes signing under the v2
//     46-byte format will fail BLS verification on new nodes — this is a
//     wire-format breaking change requiring a coordinated upgrade.
// v4: QC/TC quorum changed from 2f+1 to n-f. The wire payload is unchanged,
//     but mixed v3/v4 validators can disagree on certificate validity whenever
//     n != 3f+1. Leader payload construction also became LockedQC-authoritative.
//     Mixed deployments cannot guarantee either rule, so deployment requires a
//     coordinated upgrade.
pub const CONSENSUS_PROTOCOL_VERSION: u16 = 4;

/// Versioned wrapper for consensus messages on the wire.
///
/// Enables safe rolling upgrades: a node running version N can detect
/// and reject messages from version N+1 rather than silently failing
/// to deserialize them. All nodes in a deployment must share the same
/// version; the version field enables graceful error reporting during
/// the upgrade window.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionedMessage {
    /// Protocol version of the message format.
    pub version: u16,
    /// The actual consensus message.
    pub message: ConsensusMessage,
}

/// Envelope for all consensus messages on the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConsensusMessage {
    Proposal(Proposal),
    Vote(Vote),
    CommitVote(CommitVote),
    PrepareQC(PrepareQC),
    Timeout(TimeoutMessage),
    NewView(NewView),
    Decide(Decide),
}

impl ConsensusMessage {
    /// Returns the view number this message references. Used by the orchestrator
    /// to gate rate limits without having to pattern-match on every variant.
    pub fn view(&self) -> ViewNumber {
        match self {
            Self::Proposal(p) => p.view,
            Self::Vote(v) => v.view,
            Self::CommitVote(cv) => cv.view,
            Self::PrepareQC(pqc) => pqc.view,
            Self::Timeout(t) => t.view,
            Self::NewView(nv) => nv.view,
            Self::Decide(d) => d.view,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::BlsSecretKey;

    fn dummy_signature() -> BlsSignature {
        BlsSecretKey::random().unwrap().sign(b"dummy")
    }

    #[test]
    fn test_consensus_message_serde_roundtrip() {
        let sig = dummy_signature();

        let vote = Vote {
            view: 42,
            block_hash: B256::from([0xaa; 32]),
            voter: 7,
            signature: sig,
        };

        let msg = ConsensusMessage::Vote(vote);

        let encoded = bincode::serialize(&msg).expect("serialize ConsensusMessage should succeed");
        let decoded: ConsensusMessage =
            bincode::deserialize(&encoded).expect("deserialize ConsensusMessage should succeed");

        // Verify the decoded message matches the original.
        match decoded {
            ConsensusMessage::Vote(v) => {
                assert_eq!(v.view, 42);
                assert_eq!(v.block_hash, B256::from([0xaa; 32]));
                assert_eq!(v.voter, 7);
            }
            other => panic!("expected ConsensusMessage::Vote, got {:?}", other),
        }
    }

    #[test]
    fn test_quorum_certificate_signer_count() {
        let sig = dummy_signature();

        // Create a bitmap with 10 bits, set bits 0, 3, 7 (3 signers).
        let mut signers = bitvec![u8, Msb0; 0; 10];
        signers.set(0, true);
        signers.set(3, true);
        signers.set(7, true);

        let qc = QuorumCertificate {
            view: 5,
            block_hash: B256::from([0xbb; 32]),
            aggregate_signature: sig,
            signers,
        };

        assert_eq!(
            qc.signer_count(),
            3,
            "signer_count should reflect the number of set bits"
        );
    }

    #[test]
    fn test_all_message_variants_serde_roundtrip() {
        let sig = dummy_signature();
        let genesis_qc = QuorumCertificate::genesis();

        let variants: Vec<ConsensusMessage> = vec![
            ConsensusMessage::Proposal(Proposal {
                view: 1,
                block_hash: B256::repeat_byte(0x11),
                justify_qc: genesis_qc.clone(),
                proposer: 0,
                signature: sig.clone(),
                prepare_qc: None,
                tx_root_hash: None,
                validator_changes: None,
            }),
            ConsensusMessage::Vote(Vote {
                view: 2,
                block_hash: B256::repeat_byte(0x22),
                voter: 1,
                signature: sig.clone(),
            }),
            ConsensusMessage::CommitVote(CommitVote {
                view: 3,
                block_hash: B256::repeat_byte(0x33),
                voter: 2,
                signature: sig.clone(),
            }),
            ConsensusMessage::PrepareQC(PrepareQC {
                view: 4,
                block_hash: B256::repeat_byte(0x44),
                qc: genesis_qc.clone(),
            }),
            ConsensusMessage::Timeout(TimeoutMessage {
                view: 5,
                high_qc: genesis_qc.clone(),
                sender: 3,
                signature: sig.clone(),
            }),
            ConsensusMessage::NewView(NewView {
                view: 6,
                timeout_cert: TimeoutCertificate {
                    view: 5,
                    aggregate_signature: sig.clone(),
                    signers: BitVec::new(),
                    high_qc: genesis_qc.clone(),
                },
                leader: 0,
                signature: sig.clone(),
            }),
            ConsensusMessage::Decide(Decide {
                view: 7,
                block_hash: B256::repeat_byte(0x77),
                commit_qc: genesis_qc.clone(),
                validator_changes_hash: B256::ZERO,
            }),
        ];

        for (i, msg) in variants.iter().enumerate() {
            let encoded = bincode::serialize(msg)
                .unwrap_or_else(|e| panic!("variant {} serialize failed: {}", i, e));
            let decoded: ConsensusMessage = bincode::deserialize(&encoded)
                .unwrap_or_else(|e| panic!("variant {} deserialize failed: {}", i, e));

            let orig_variant = format!("{:?}", msg).split('(').next().unwrap().to_string();
            let decoded_variant = format!("{:?}", decoded)
                .split('(')
                .next()
                .unwrap()
                .to_string();
            assert_eq!(orig_variant, decoded_variant);
        }
    }

    #[test]
    fn test_versioned_message_serde_roundtrip() {
        let sig = dummy_signature();
        let vote = Vote {
            view: 100,
            block_hash: B256::repeat_byte(0xEE),
            voter: 5,
            signature: sig,
        };
        let versioned = VersionedMessage {
            version: CONSENSUS_PROTOCOL_VERSION,
            message: ConsensusMessage::Vote(vote),
        };

        let encoded = bincode::serialize(&versioned).expect("serialize VersionedMessage");
        let decoded: VersionedMessage =
            bincode::deserialize(&encoded).expect("deserialize VersionedMessage");

        assert_eq!(decoded.version, CONSENSUS_PROTOCOL_VERSION);
        match decoded.message {
            ConsensusMessage::Vote(v) => {
                assert_eq!(v.view, 100);
                assert_eq!(v.voter, 5);
                assert_eq!(v.block_hash, B256::repeat_byte(0xEE));
            }
            other => panic!("expected Vote, got {:?}", other),
        }
    }

    #[test]
    fn test_timeout_certificate_serde_roundtrip() {
        let sig = dummy_signature();
        let genesis_qc = QuorumCertificate::genesis();

        let tc = TimeoutCertificate {
            view: 42,
            aggregate_signature: sig,
            signers: {
                let mut s = bitvec![u8, Msb0; 0; 4];
                s.set(0, true);
                s.set(2, true);
                s
            },
            high_qc: genesis_qc,
        };

        let encoded = bincode::serialize(&tc).expect("serialize TC");
        let decoded: TimeoutCertificate = bincode::deserialize(&encoded).expect("deserialize TC");

        assert_eq!(decoded.view, 42);
        assert_eq!(decoded.signers.count_ones(), 2);
        assert!(decoded.signers[0]);
        assert!(!decoded.signers[1]);
        assert!(decoded.signers[2]);
        assert!(!decoded.signers[3]);
        assert_eq!(decoded.high_qc.view, 0, "high_qc should be genesis");
    }

    #[test]
    fn test_genesis_qc() {
        let qc = QuorumCertificate::genesis();
        assert_eq!(qc.view, 0);
        assert_eq!(qc.block_hash, B256::ZERO);
        assert_eq!(qc.signer_count(), 0);
        assert!(qc.signers.is_empty());
    }

    // ── packed_bits tests ──────────────────────────────────────────

    #[test]
    fn packed_bits_roundtrip_bincode() {
        let bv = bitvec![u8, Msb0; 1, 0, 1, 1, 0, 0, 1];
        let qc = QuorumCertificate {
            view: 1,
            block_hash: B256::ZERO,
            aggregate_signature: dummy_signature(),
            signers: bv.clone(),
        };
        let encoded = bincode::serialize(&qc).unwrap();
        let decoded: QuorumCertificate = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.signers, bv);
        assert_eq!(decoded.signers.len(), 7);
    }

    #[test]
    fn packed_bits_roundtrip_json() {
        let bv = bitvec![u8, Msb0; 1, 1, 0, 1, 0];
        let qc = QuorumCertificate {
            view: 1,
            block_hash: B256::ZERO,
            aggregate_signature: dummy_signature(),
            signers: bv.clone(),
        };
        let json = serde_json::to_string(&qc).unwrap();
        let decoded: QuorumCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.signers, bv);
    }

    #[test]
    fn packed_bits_empty() {
        let bv = BitVec::<u8, Msb0>::new();
        let qc = QuorumCertificate {
            view: 1,
            block_hash: B256::ZERO,
            aggregate_signature: dummy_signature(),
            signers: bv.clone(),
        };
        let encoded = bincode::serialize(&qc).unwrap();
        let decoded: QuorumCertificate = bincode::deserialize(&encoded).unwrap();
        assert!(decoded.signers.is_empty());
    }

    #[test]
    fn packed_bits_500_validators() {
        let mut bv = bitvec![u8, Msb0; 0; 500];
        bv.set(0, true);
        bv.set(499, true);
        let qc = QuorumCertificate {
            view: 1,
            block_hash: B256::ZERO,
            aggregate_signature: dummy_signature(),
            signers: bv.clone(),
        };
        let encoded = bincode::serialize(&qc).unwrap();
        let decoded: QuorumCertificate = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.signers.len(), 500);
        assert!(decoded.signers[0]);
        assert!(!decoded.signers[1]);
        assert!(decoded.signers[499]);
        // Compact: 2 (count) + 8 (bincode len prefix) + 63 (packed bytes) = 73 bytes for signers
        // vs old format: 2 + 8 + 500 = 510 bytes
    }

    #[test]
    fn packed_bits_rejects_length_mismatch() {
        // Craft a (bit_count=100, raw_bytes=[0u8; 5]) — needs 13 bytes, has 5
        let bad: (u16, Vec<u8>) = (100, vec![0u8; 5]);
        let _bad_bytes = bincode::serialize(&bad).unwrap();
        // Wrap in a QC-like structure: prepend view(8) + hash(32) + sig (bincode bytes)
        // Easier: just test packed_bits directly via QC deserialization
        // Actually, construct the full bincode manually is complex.
        // Instead test that a short raw_bytes is rejected via serde_json:
        let _json = r#"{"view":1,"block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","aggregate_signature":"placeholder","signers":[100,[0,0,0,0,0]]}"#;
        // This won't parse cleanly because aggregate_signature isn't valid.
        // Use a simpler approach: serialize a valid QC, tamper with the signers field.
        let bv = bitvec![u8, Msb0; 1, 0, 1];
        let qc = QuorumCertificate {
            view: 1,
            block_hash: B256::ZERO,
            aggregate_signature: dummy_signature(),
            signers: bv,
        };
        let mut json_val: serde_json::Value = serde_json::to_value(&qc).unwrap();
        // Tamper signers: set bit_count to 100 but keep 1 byte of data
        json_val["signers"] = serde_json::json!([100, [0xA0]]);
        let result: Result<QuorumCertificate, _> = serde_json::from_value(json_val);
        assert!(
            result.is_err(),
            "should reject bit_count > raw_bytes capacity"
        );
    }

    // ── ValidatorChange tests ──────────────────────────────────────

    #[test]
    fn validator_change_serde_roundtrip() {
        let sk = BlsSecretKey::random().unwrap();
        let changes = vec![
            ValidatorChange::Add {
                address: Address::repeat_byte(0x01),
                bls_public_key: sk.public_key(),
                p2p_peer_id: Some("12D3KooW...".to_string()),
            },
            ValidatorChange::Remove {
                address: Address::repeat_byte(0x02),
            },
        ];
        let encoded = bincode::serialize(&changes).unwrap();
        let decoded: Vec<ValidatorChange> = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        match &decoded[0] {
            ValidatorChange::Add {
                address,
                p2p_peer_id,
                ..
            } => {
                assert_eq!(*address, Address::repeat_byte(0x01));
                assert_eq!(p2p_peer_id.as_deref(), Some("12D3KooW..."));
            }
            _ => panic!("expected Add"),
        }
        match &decoded[1] {
            ValidatorChange::Remove { address } => {
                assert_eq!(*address, Address::repeat_byte(0x02));
            }
            _ => panic!("expected Remove"),
        }
    }

    // ── Decide with validator_changes_hash ──────────────────────────

    #[test]
    fn decide_changes_hash_serde_roundtrip() {
        let genesis_qc = QuorumCertificate::genesis();
        let decide = Decide {
            view: 42,
            block_hash: B256::repeat_byte(0xDD),
            commit_qc: genesis_qc,
            validator_changes_hash: B256::repeat_byte(0xAB),
        };
        let encoded = bincode::serialize(&decide).unwrap();
        let decoded: Decide = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.validator_changes_hash, B256::repeat_byte(0xAB));
    }

    #[test]
    fn decide_changes_hash_defaults_to_zero() {
        // Simulate old Decide without validator_changes_hash (backward compat)
        let genesis_qc = QuorumCertificate::genesis();
        let old_decide = serde_json::json!({
            "view": 42,
            "block_hash": B256::repeat_byte(0xDD),
            "commit_qc": serde_json::to_value(&genesis_qc).unwrap(),
        });
        let decoded: Decide = serde_json::from_value(old_decide).unwrap();
        assert_eq!(decoded.validator_changes_hash, B256::ZERO);
    }
}
