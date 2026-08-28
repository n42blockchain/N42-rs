//! Strict compatibility codec for gov5's current HotStuff-2 wire format.
//!
//! gov5 uses a hand-written little-endian, length-prefixed encoding rather
//! than canonical SSZ. This module pins every current message shape so a Rust
//! node can observe and validate the legacy network during the H2-v4 migration.
//! It deliberately does not make legacy messages eligible for voting: gov5's
//! commit signature domain does not yet bind Rust's validator-change hash.

use alloy_primitives::B256;
use n42_h2_primitives::BlsSignature;

const MAX_ENVELOPE_PAYLOAD: usize = 8 * 1024;
const MAX_SIGNATURE: usize = 256;
const MAX_BITMAP: usize = 1024;
const MAX_QC: usize = 2 * 1024;
const MAX_HIGH_TC: usize = 4 * 1024;
const MAX_VALIDATORS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum H2MessageKind {
    Proposal = 1,
    Vote = 2,
    CommitVote = 3,
    PrepareQc = 4,
    Timeout = 5,
    NewView = 6,
    Decide = 7,
}

impl TryFrom<u8> for H2MessageKind {
    type Error = H2WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Proposal),
            2 => Ok(Self::Vote),
            3 => Ok(Self::CommitVote),
            4 => Ok(Self::PrepareQc),
            5 => Ok(Self::Timeout),
            6 => Ok(Self::NewView),
            7 => Ok(Self::Decide),
            _ => Err(H2WireError::UnknownMessageKind(value)),
        }
    }
}

impl H2MessageKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::Vote => "vote",
            Self::CommitVote => "commit_vote",
            Self::PrepareQc => "prepare_qc",
            Self::Timeout => "timeout",
            Self::NewView => "new_view",
            Self::Decide => "decide",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2Envelope {
    pub kind: H2MessageKind,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2QuorumCertificate {
    pub view: u64,
    pub block_hash: B256,
    pub aggregate_signature: Vec<u8>,
    /// Exact gov5 representation: uint16 validator count followed by bits.
    pub signers_bitmap: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2TimeoutCertificate {
    pub view: u64,
    pub aggregate_signature: Vec<u8>,
    pub signers_bitmap: Vec<u8>,
    pub high_qc: H2QuorumCertificate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2Proposal {
    pub view: u64,
    pub block_hash: B256,
    pub justify_qc: H2QuorumCertificate,
    pub proposer: u32,
    pub signature: BlsSignature,
    pub prepare_qc: Option<H2QuorumCertificate>,
    pub tx_root_hash: B256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2Vote {
    pub view: u64,
    pub block_hash: B256,
    pub voter: u32,
    pub signature: BlsSignature,
    pub high_tc: Option<H2TimeoutCertificate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2PrepareQc {
    pub view: u64,
    pub block_hash: B256,
    pub qc: H2QuorumCertificate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2Timeout {
    pub view: u64,
    pub high_qc: H2QuorumCertificate,
    pub sender: u32,
    pub signature: BlsSignature,
    pub high_tc: Option<H2TimeoutCertificate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2NewView {
    pub view: u64,
    pub timeout_certificate: H2TimeoutCertificate,
    pub leader: u32,
    pub signature: BlsSignature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2Decide {
    pub view: u64,
    pub block_hash: B256,
    pub commit_qc: H2QuorumCertificate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum H2Message {
    Proposal(H2Proposal),
    Vote(H2Vote),
    CommitVote(H2Vote),
    PrepareQc(H2PrepareQc),
    Timeout(H2Timeout),
    NewView(H2NewView),
    Decide(H2Decide),
}

impl H2Message {
    pub const fn kind(&self) -> H2MessageKind {
        match self {
            Self::Proposal(_) => H2MessageKind::Proposal,
            Self::Vote(_) => H2MessageKind::Vote,
            Self::CommitVote(_) => H2MessageKind::CommitVote,
            Self::PrepareQc(_) => H2MessageKind::PrepareQc,
            Self::Timeout(_) => H2MessageKind::Timeout,
            Self::NewView(_) => H2MessageKind::NewView,
            Self::Decide(_) => H2MessageKind::Decide,
        }
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum H2WireError {
    #[error("H2 message is truncated")]
    Truncated,
    #[error("H2 message has trailing bytes")]
    TrailingBytes,
    #[error("H2 envelope payload is {actual} bytes; maximum is {max}")]
    EnvelopeTooLarge { actual: usize, max: usize },
    #[error("H2 byte field is {actual} bytes; maximum is {max}")]
    FieldTooLarge { actual: usize, max: usize },
    #[error("unknown H2 message kind {0}")]
    UnknownMessageKind(u8),
    #[error("expected H2 Vote envelope, got {0:?}")]
    WrongMessageKind(H2MessageKind),
    #[error("H2 block hash must be 32 bytes, got {0}")]
    InvalidBlockHashLength(usize),
    #[error("H2 BLS signature must be 96 bytes, got {0}")]
    InvalidSignatureLength(usize),
    #[error("invalid H2 BLS signature")]
    InvalidSignature,
    #[error("invalid non-canonical H2 signer bitmap")]
    InvalidBitmap,
    #[error("invalid gov5 H2 snappy payload: {0}")]
    InvalidSnappy(String),
}

/// Decode gov5's `type || payload_len_le || payload` envelope.
pub fn decode_envelope(data: &[u8]) -> Result<H2Envelope, H2WireError> {
    let (&kind, rest) = data.split_first().ok_or(H2WireError::Truncated)?;
    let (payload, consumed) = read_bytes(rest, MAX_ENVELOPE_PAYLOAD)?;
    if consumed != rest.len() {
        return Err(H2WireError::TrailingBytes);
    }
    Ok(H2Envelope {
        kind: kind.try_into()?,
        payload: payload.to_vec(),
    })
}

pub fn decode_message(data: &[u8]) -> Result<H2Message, H2WireError> {
    let envelope = decode_envelope(data)?;
    let payload = &envelope.payload;
    match envelope.kind {
        H2MessageKind::Proposal => decode_proposal(payload).map(H2Message::Proposal),
        H2MessageKind::Vote => decode_vote_payload(payload).map(H2Message::Vote),
        H2MessageKind::CommitVote => decode_vote_payload(payload).map(H2Message::CommitVote),
        H2MessageKind::PrepareQc => decode_prepare_qc(payload).map(H2Message::PrepareQc),
        H2MessageKind::Timeout => decode_timeout(payload).map(H2Message::Timeout),
        H2MessageKind::NewView => decode_new_view(payload).map(H2Message::NewView),
        H2MessageKind::Decide => decode_decide(payload).map(H2Message::Decide),
    }
}

pub fn encode_message(message: &H2Message) -> Result<Vec<u8>, H2WireError> {
    let payload = match message {
        H2Message::Proposal(value) => encode_proposal(value)?,
        H2Message::Vote(value) | H2Message::CommitVote(value) => encode_vote_payload(value)?,
        H2Message::PrepareQc(value) => encode_prepare_qc(value)?,
        H2Message::Timeout(value) => encode_timeout(value)?,
        H2Message::NewView(value) => encode_new_view(value)?,
        H2Message::Decide(value) => encode_decide(value)?,
    };
    encode_envelope(message.kind(), &payload)
}

pub fn decode_vote(data: &[u8]) -> Result<H2Vote, H2WireError> {
    match decode_message(data)? {
        H2Message::Vote(vote) => Ok(vote),
        other => Err(H2WireError::WrongMessageKind(other.kind())),
    }
}

pub fn encode_vote(vote: &H2Vote) -> Result<Vec<u8>, H2WireError> {
    encode_message(&H2Message::Vote(vote.clone()))
}

/// Decode the raw Snappy block carried on gov5's `ssz_snappy` gossip topic.
pub fn decode_gov5_gossip_message(data: &[u8]) -> Result<H2Message, H2WireError> {
    let decoded_len = snap::raw::decompress_len(data)
        .map_err(|error| H2WireError::InvalidSnappy(error.to_string()))?;
    if decoded_len > MAX_ENVELOPE_PAYLOAD + 5 {
        return Err(H2WireError::EnvelopeTooLarge {
            actual: decoded_len,
            max: MAX_ENVELOPE_PAYLOAD + 5,
        });
    }
    let decoded = crate::snappy::decompress_raw(data)
        .map_err(|error| H2WireError::InvalidSnappy(error.to_string()))?;
    decode_message(&decoded)
}

/// Encode a canonical gov5 H2 message as a raw Snappy gossip block.
pub fn encode_gov5_gossip_message(message: &H2Message) -> Result<Vec<u8>, H2WireError> {
    let encoded = encode_message(message)?;
    crate::snappy::compress_raw(&encoded)
        .map_err(|error| H2WireError::InvalidSnappy(error.to_string()))
}

/// gov5 Round-1/proposal domain: `view_le || block_hash`.
pub fn gov5_prepare_signing_message(view: u64, block_hash: B256) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&view.to_le_bytes());
    out[8..].copy_from_slice(block_hash.as_slice());
    out
}

/// gov5 Round-2 domain. This is observation-only until H2-v4 unifies the
/// validator-change commitment used by the Rust consensus implementation.
pub fn gov5_commit_signing_message(view: u64, block_hash: B256) -> [u8; 46] {
    let mut out = [0u8; 46];
    out[..6].copy_from_slice(b"commit");
    out[6..14].copy_from_slice(&view.to_le_bytes());
    out[14..].copy_from_slice(block_hash.as_slice());
    out
}

pub fn gov5_timeout_signing_message(view: u64) -> [u8; 15] {
    let mut out = [0u8; 15];
    out[..7].copy_from_slice(b"timeout");
    out[7..].copy_from_slice(&view.to_le_bytes());
    out
}

pub fn gov5_new_view_signing_message(view: u64) -> [u8; 15] {
    let mut out = [0u8; 15];
    out[..7].copy_from_slice(b"newview");
    out[7..].copy_from_slice(&view.to_le_bytes());
    out
}

fn decode_proposal(data: &[u8]) -> Result<H2Proposal, H2WireError> {
    let mut offset = 0;
    let view = read_u64(data, &mut offset)?;
    let block_hash = read_hash(data, &mut offset)?;
    let justify_qc = decode_qc(read_bytes_at(data, &mut offset, MAX_QC)?)?;
    let proposer = read_u32(data, &mut offset)?;
    let signature = read_signature(data, &mut offset)?;
    let prepare_qc_bytes = read_bytes_at(data, &mut offset, MAX_QC)?;
    let prepare_qc = if prepare_qc_bytes.is_empty() {
        None
    } else {
        Some(decode_qc(prepare_qc_bytes)?)
    };
    let tx_root_hash = read_hash(data, &mut offset)?;
    finish(data, offset)?;
    Ok(H2Proposal {
        view,
        block_hash,
        justify_qc,
        proposer,
        signature,
        prepare_qc,
        tx_root_hash,
    })
}

fn encode_proposal(value: &H2Proposal) -> Result<Vec<u8>, H2WireError> {
    let justify_qc = encode_qc(&value.justify_qc)?;
    let prepare_qc = value.prepare_qc.as_ref().map(encode_qc).transpose()?;
    let mut out = Vec::new();
    out.extend_from_slice(&value.view.to_le_bytes());
    put_limited_bytes(&mut out, value.block_hash.as_slice(), 32)?;
    put_limited_bytes(&mut out, &justify_qc, MAX_QC)?;
    out.extend_from_slice(&value.proposer.to_le_bytes());
    put_signature(&mut out, &value.signature)?;
    put_limited_bytes(&mut out, prepare_qc.as_deref().unwrap_or_default(), MAX_QC)?;
    put_limited_bytes(&mut out, value.tx_root_hash.as_slice(), 32)?;
    Ok(out)
}

fn decode_vote_payload(data: &[u8]) -> Result<H2Vote, H2WireError> {
    let mut offset = 0;
    let view = read_u64(data, &mut offset)?;
    let block_hash = read_hash(data, &mut offset)?;
    let voter = read_u32(data, &mut offset)?;
    let signature = read_signature(data, &mut offset)?;
    // Older gov5 messages omitted the optional trailing field.
    let high_tc = if offset == data.len() {
        None
    } else {
        decode_optional_tc(read_bytes_at(data, &mut offset, MAX_HIGH_TC)?)?
    };
    finish(data, offset)?;
    Ok(H2Vote {
        view,
        block_hash,
        voter,
        signature,
        high_tc,
    })
}

fn encode_vote_payload(value: &H2Vote) -> Result<Vec<u8>, H2WireError> {
    let high_tc = value.high_tc.as_ref().map(encode_high_tc).transpose()?;
    let mut out = Vec::new();
    out.extend_from_slice(&value.view.to_le_bytes());
    put_limited_bytes(&mut out, value.block_hash.as_slice(), 32)?;
    out.extend_from_slice(&value.voter.to_le_bytes());
    put_signature(&mut out, &value.signature)?;
    put_limited_bytes(
        &mut out,
        high_tc.as_deref().unwrap_or_default(),
        MAX_HIGH_TC,
    )?;
    Ok(out)
}

fn decode_prepare_qc(data: &[u8]) -> Result<H2PrepareQc, H2WireError> {
    let mut offset = 0;
    let value = H2PrepareQc {
        view: read_u64(data, &mut offset)?,
        block_hash: read_hash(data, &mut offset)?,
        qc: decode_qc(read_bytes_at(data, &mut offset, MAX_QC)?)?,
    };
    finish(data, offset)?;
    Ok(value)
}

fn encode_prepare_qc(value: &H2PrepareQc) -> Result<Vec<u8>, H2WireError> {
    let qc = encode_qc(&value.qc)?;
    let mut out = Vec::new();
    out.extend_from_slice(&value.view.to_le_bytes());
    put_limited_bytes(&mut out, value.block_hash.as_slice(), 32)?;
    put_limited_bytes(&mut out, &qc, MAX_QC)?;
    Ok(out)
}

fn decode_timeout(data: &[u8]) -> Result<H2Timeout, H2WireError> {
    let mut offset = 0;
    let view = read_u64(data, &mut offset)?;
    let high_qc = decode_qc(read_bytes_at(data, &mut offset, MAX_QC)?)?;
    let sender = read_u32(data, &mut offset)?;
    let signature = read_signature(data, &mut offset)?;
    let high_tc = if offset == data.len() {
        None
    } else {
        decode_optional_tc(read_bytes_at(data, &mut offset, MAX_HIGH_TC)?)?
    };
    finish(data, offset)?;
    Ok(H2Timeout {
        view,
        high_qc,
        sender,
        signature,
        high_tc,
    })
}

fn encode_timeout(value: &H2Timeout) -> Result<Vec<u8>, H2WireError> {
    let high_qc = encode_qc(&value.high_qc)?;
    let high_tc = value.high_tc.as_ref().map(encode_high_tc).transpose()?;
    let mut out = Vec::new();
    out.extend_from_slice(&value.view.to_le_bytes());
    put_limited_bytes(&mut out, &high_qc, MAX_QC)?;
    out.extend_from_slice(&value.sender.to_le_bytes());
    put_signature(&mut out, &value.signature)?;
    put_limited_bytes(
        &mut out,
        high_tc.as_deref().unwrap_or_default(),
        MAX_HIGH_TC,
    )?;
    Ok(out)
}

fn decode_new_view(data: &[u8]) -> Result<H2NewView, H2WireError> {
    let mut offset = 0;
    let value = H2NewView {
        view: read_u64(data, &mut offset)?,
        timeout_certificate: decode_tc(read_bytes_at(data, &mut offset, MAX_HIGH_TC)?)?,
        leader: read_u32(data, &mut offset)?,
        signature: read_signature(data, &mut offset)?,
    };
    finish(data, offset)?;
    Ok(value)
}

fn encode_new_view(value: &H2NewView) -> Result<Vec<u8>, H2WireError> {
    let tc = encode_high_tc(&value.timeout_certificate)?;
    let mut out = Vec::new();
    out.extend_from_slice(&value.view.to_le_bytes());
    put_limited_bytes(&mut out, &tc, MAX_HIGH_TC)?;
    out.extend_from_slice(&value.leader.to_le_bytes());
    put_signature(&mut out, &value.signature)?;
    Ok(out)
}

fn decode_decide(data: &[u8]) -> Result<H2Decide, H2WireError> {
    let mut offset = 0;
    let value = H2Decide {
        view: read_u64(data, &mut offset)?,
        block_hash: read_hash(data, &mut offset)?,
        commit_qc: decode_qc(read_bytes_at(data, &mut offset, MAX_QC)?)?,
    };
    finish(data, offset)?;
    Ok(value)
}

fn encode_decide(value: &H2Decide) -> Result<Vec<u8>, H2WireError> {
    let qc = encode_qc(&value.commit_qc)?;
    let mut out = Vec::new();
    out.extend_from_slice(&value.view.to_le_bytes());
    put_limited_bytes(&mut out, value.block_hash.as_slice(), 32)?;
    put_limited_bytes(&mut out, &qc, MAX_QC)?;
    Ok(out)
}

fn decode_qc(data: &[u8]) -> Result<H2QuorumCertificate, H2WireError> {
    let mut offset = 0;
    let view = read_u64(data, &mut offset)?;
    let block_hash = read_hash(data, &mut offset)?;
    let aggregate_signature = read_bytes_at(data, &mut offset, MAX_SIGNATURE)?.to_vec();
    let signers_bitmap = read_bytes_at(data, &mut offset, MAX_BITMAP)?.to_vec();
    validate_bitmap(&signers_bitmap)?;
    finish(data, offset)?;
    Ok(H2QuorumCertificate {
        view,
        block_hash,
        aggregate_signature,
        signers_bitmap,
    })
}

/// Decodes the canonical Gov5 SSZ representation of a quorum certificate.
///
/// Gov5 persists `lockedQC` and `lastCommittedQC` using this exact wire
/// representation. Exposing the bounded decoder lets the authenticated
/// bootstrap tool consume that durable state without duplicating SSZ parsing.
pub fn decode_h2_qc(data: &[u8]) -> Result<H2QuorumCertificate, H2WireError> {
    decode_qc(data)
}

fn encode_qc(value: &H2QuorumCertificate) -> Result<Vec<u8>, H2WireError> {
    validate_bitmap(&value.signers_bitmap)?;
    let mut out = Vec::new();
    out.extend_from_slice(&value.view.to_le_bytes());
    put_limited_bytes(&mut out, value.block_hash.as_slice(), 32)?;
    put_limited_bytes(&mut out, &value.aggregate_signature, MAX_SIGNATURE)?;
    put_limited_bytes(&mut out, &value.signers_bitmap, MAX_BITMAP)?;
    Ok(out)
}

fn decode_optional_tc(data: &[u8]) -> Result<Option<H2TimeoutCertificate>, H2WireError> {
    if data.is_empty() {
        Ok(None)
    } else {
        decode_tc(data).map(Some)
    }
}

fn decode_tc(data: &[u8]) -> Result<H2TimeoutCertificate, H2WireError> {
    let mut offset = 0;
    let view = read_u64(data, &mut offset)?;
    let aggregate_signature = read_bytes_at(data, &mut offset, MAX_SIGNATURE)?.to_vec();
    let signers_bitmap = read_bytes_at(data, &mut offset, MAX_BITMAP)?.to_vec();
    validate_bitmap(&signers_bitmap)?;
    let high_qc = decode_qc(read_bytes_at(data, &mut offset, MAX_QC)?)?;
    finish(data, offset)?;
    Ok(H2TimeoutCertificate {
        view,
        aggregate_signature,
        signers_bitmap,
        high_qc,
    })
}

fn encode_tc(value: &H2TimeoutCertificate) -> Result<Vec<u8>, H2WireError> {
    validate_bitmap(&value.signers_bitmap)?;
    let high_qc = encode_qc(&value.high_qc)?;
    let mut out = Vec::new();
    out.extend_from_slice(&value.view.to_le_bytes());
    put_limited_bytes(&mut out, &value.aggregate_signature, MAX_SIGNATURE)?;
    put_limited_bytes(&mut out, &value.signers_bitmap, MAX_BITMAP)?;
    put_limited_bytes(&mut out, &high_qc, MAX_QC)?;
    Ok(out)
}

/// Encode a HighTC only when its complete nested representation fits the same schema bound used
/// by decoding. Keeping this check at the object boundary prevents public encoders from emitting
/// a message that compliant peers (and our own decoder) must reject.
fn encode_high_tc(value: &H2TimeoutCertificate) -> Result<Vec<u8>, H2WireError> {
    let encoded = encode_tc(value)?;
    if encoded.len() > MAX_HIGH_TC {
        return Err(H2WireError::FieldTooLarge {
            actual: encoded.len(),
            max: MAX_HIGH_TC,
        });
    }
    Ok(encoded)
}

fn validate_bitmap(bitmap: &[u8]) -> Result<(), H2WireError> {
    if bitmap.is_empty() {
        return Ok(());
    }
    if bitmap.len() < 2 {
        return Err(H2WireError::InvalidBitmap);
    }
    let count = u16::from_le_bytes([bitmap[0], bitmap[1]]) as usize;
    if count == 0 || count > MAX_VALIDATORS {
        return Err(H2WireError::InvalidBitmap);
    }
    let expected = 2 + count.div_ceil(8);
    if bitmap.len() != expected {
        return Err(H2WireError::InvalidBitmap);
    }
    if !count.is_multiple_of(8) {
        let used_mask = (1u8 << (count % 8)) - 1;
        if bitmap[expected - 1] & !used_mask != 0 {
            return Err(H2WireError::InvalidBitmap);
        }
    }
    Ok(())
}

fn encode_envelope(kind: H2MessageKind, payload: &[u8]) -> Result<Vec<u8>, H2WireError> {
    if payload.len() > MAX_ENVELOPE_PAYLOAD {
        return Err(H2WireError::EnvelopeTooLarge {
            actual: payload.len(),
            max: MAX_ENVELOPE_PAYLOAD,
        });
    }
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind as u8);
    put_bytes(&mut out, payload)?;
    Ok(out)
}

fn read_hash(data: &[u8], offset: &mut usize) -> Result<B256, H2WireError> {
    let bytes = read_bytes_at(data, offset, 32)?;
    if bytes.len() != 32 {
        return Err(H2WireError::InvalidBlockHashLength(bytes.len()));
    }
    Ok(B256::from_slice(bytes))
}

fn read_signature(data: &[u8], offset: &mut usize) -> Result<BlsSignature, H2WireError> {
    let bytes = read_bytes_at(data, offset, MAX_SIGNATURE)?;
    if bytes.len() != 96 {
        return Err(H2WireError::InvalidSignatureLength(bytes.len()));
    }
    let bytes: [u8; 96] = bytes.try_into().expect("length checked");
    BlsSignature::from_bytes(&bytes).map_err(|_| H2WireError::InvalidSignature)
}

fn put_signature(out: &mut Vec<u8>, signature: &BlsSignature) -> Result<(), H2WireError> {
    put_limited_bytes(out, &signature.to_bytes(), MAX_SIGNATURE)
}

fn read_u64(data: &[u8], offset: &mut usize) -> Result<u64, H2WireError> {
    let bytes = take(data, offset, 8)?;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32, H2WireError> {
    let bytes = take(data, offset, 4)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

fn read_bytes(data: &[u8], max: usize) -> Result<(&[u8], usize), H2WireError> {
    if data.len() < 4 {
        return Err(H2WireError::Truncated);
    }
    let len = u32::from_le_bytes(data[..4].try_into().expect("length checked")) as usize;
    if len > max {
        return Err(H2WireError::FieldTooLarge { actual: len, max });
    }
    let end = 4usize.checked_add(len).ok_or(H2WireError::Truncated)?;
    let bytes = data.get(4..end).ok_or(H2WireError::Truncated)?;
    Ok((bytes, end))
}

fn read_bytes_at<'a>(
    data: &'a [u8],
    offset: &mut usize,
    max: usize,
) -> Result<&'a [u8], H2WireError> {
    let (bytes, consumed) = read_bytes(data.get(*offset..).ok_or(H2WireError::Truncated)?, max)?;
    *offset = offset.checked_add(consumed).ok_or(H2WireError::Truncated)?;
    Ok(bytes)
}

fn take<'a>(data: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], H2WireError> {
    let end = offset.checked_add(len).ok_or(H2WireError::Truncated)?;
    let bytes = data.get(*offset..end).ok_or(H2WireError::Truncated)?;
    *offset = end;
    Ok(bytes)
}

fn finish(data: &[u8], offset: usize) -> Result<(), H2WireError> {
    if offset == data.len() {
        Ok(())
    } else {
        Err(H2WireError::TrailingBytes)
    }
}

fn put_limited_bytes(out: &mut Vec<u8>, data: &[u8], max: usize) -> Result<(), H2WireError> {
    if data.len() > max {
        return Err(H2WireError::FieldTooLarge {
            actual: data.len(),
            max,
        });
    }
    put_bytes(out, data)
}

fn put_bytes(out: &mut Vec<u8>, data: &[u8]) -> Result<(), H2WireError> {
    let len = u32::try_from(data.len()).map_err(|_| H2WireError::FieldTooLarge {
        actual: data.len(),
        max: u32::MAX as usize,
    })?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixture {
        schema: String,
        signature_domains: SignatureDomains,
        vote_gossip_hex: String,
        messages: Vec<FixtureMessage>,
    }

    #[derive(Deserialize)]
    struct SignatureDomains {
        prepare_hex: String,
        commit_hex: String,
        timeout_hex: String,
        new_view_hex: String,
    }

    #[derive(Deserialize)]
    struct FixtureMessage {
        name: String,
        #[serde(rename = "type")]
        kind: u8,
        wire_hex: String,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../testdata/cross_client_h2_v1.json"))
            .expect("valid cross-client fixture")
    }

    #[test]
    fn decodes_and_reencodes_all_gov5_message_fixtures() {
        let fixture = fixture();
        assert_eq!(fixture.schema, "n42-h2-gov5-v1");
        assert_eq!(fixture.messages.len(), 7);
        for item in fixture.messages {
            let wire = hex::decode(&item.wire_hex).expect("fixture hex");
            let message = decode_message(&wire)
                .unwrap_or_else(|error| panic!("decode {}: {error}", item.name));
            assert_eq!(message.kind() as u8, item.kind, "{} kind", item.name);
            assert_eq!(
                encode_message(&message).unwrap(),
                wire,
                "{} re-encode",
                item.name
            );
            let gossip = encode_gov5_gossip_message(&message).unwrap();
            assert_eq!(
                decode_gov5_gossip_message(&gossip).unwrap(),
                message,
                "{} snappy gossip",
                item.name
            );
        }
    }

    #[test]
    fn matches_gov5_signature_domain_fixtures() {
        let fixture = fixture();
        let block_hash = B256::repeat_byte(0xbb);
        assert_eq!(
            hex::encode(gov5_prepare_signing_message(
                0x2122_2324_2526_2728,
                block_hash
            )),
            fixture.signature_domains.prepare_hex
        );
        assert_eq!(
            hex::encode(gov5_commit_signing_message(
                0x2122_2324_2526_2728,
                block_hash
            )),
            fixture.signature_domains.commit_hex
        );
        assert_eq!(
            hex::encode(gov5_timeout_signing_message(0x3132_3334_3536_3738)),
            fixture.signature_domains.timeout_hex
        );
        assert_eq!(
            hex::encode(gov5_new_view_signing_message(0x4142_4344_4546_4748)),
            fixture.signature_domains.new_view_hex
        );
    }

    #[test]
    fn decodes_go_snappy_gossip_fixture() {
        let fixture = fixture();
        let gossip = hex::decode(fixture.vote_gossip_hex).expect("fixture hex");
        let decoded = decode_gov5_gossip_message(&gossip).expect("Go Snappy payload");
        assert_eq!(decoded.kind(), H2MessageKind::Vote);
        let vote = match decoded {
            H2Message::Vote(vote) => vote,
            _ => unreachable!("kind checked"),
        };
        assert_eq!(vote.view, 0x2122_2324_2526_2728);
        assert_eq!(vote.block_hash, B256::repeat_byte(0xbb));
        assert!(vote.high_tc.is_some());
    }

    #[test]
    fn vote_encoder_rejects_oversized_high_tc_before_emitting_wire_bytes() {
        let fixture = fixture();
        let gossip = hex::decode(fixture.vote_gossip_hex).expect("fixture hex");
        let mut vote = match decode_gov5_gossip_message(&gossip).unwrap() {
            H2Message::Vote(vote) => vote,
            _ => unreachable!("fixture is a vote"),
        };
        vote.high_tc
            .as_mut()
            .expect("fixture carries HighTC")
            .aggregate_signature = vec![0; MAX_SIGNATURE + 1];
        assert_eq!(
            encode_vote(&vote),
            Err(H2WireError::FieldTooLarge {
                actual: MAX_SIGNATURE + 1,
                max: MAX_SIGNATURE,
            })
        );
    }

    #[test]
    fn rejects_non_canonical_or_oversized_messages() {
        assert_eq!(decode_envelope(&[]), Err(H2WireError::Truncated));
        assert_eq!(
            decode_envelope(&[2, 1, 0, 0, 0]),
            Err(H2WireError::Truncated)
        );
        let mut oversized = vec![2];
        oversized.extend_from_slice(&((MAX_ENVELOPE_PAYLOAD + 1) as u32).to_le_bytes());
        assert_eq!(
            decode_envelope(&oversized),
            Err(H2WireError::FieldTooLarge {
                actual: MAX_ENVELOPE_PAYLOAD + 1,
                max: MAX_ENVELOPE_PAYLOAD,
            })
        );

        let fixture = fixture();
        let mut trailing = hex::decode(&fixture.messages[0].wire_hex).unwrap();
        trailing.push(0);
        assert_eq!(decode_message(&trailing), Err(H2WireError::TrailingBytes));
        assert_eq!(
            validate_bitmap(&[1, 0, 0x81]),
            Err(H2WireError::InvalidBitmap)
        );
        let mut encoded_field = Vec::new();
        assert_eq!(
            put_limited_bytes(&mut encoded_field, &vec![0; MAX_HIGH_TC + 1], MAX_HIGH_TC,),
            Err(H2WireError::FieldTooLarge {
                actual: MAX_HIGH_TC + 1,
                max: MAX_HIGH_TC,
            })
        );
    }
}
