// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A binary form of the Engine API's `newPayload`, for the loopback channel
//! between this repo's validator and its execution layer.
//!
//! `engine_newPayload` carries every transaction hex-encoded inside JSON. On
//! the follower that is the largest thing between a body arriving and a vote
//! going out that is not the block's own execution: measured on the
//! seven-node fleet at the 163,000-transaction tier, ~285 ms of a 922 ms
//! receive-to-vote where the execution layer's own import is 637. Here the
//! same [`ExecutionData`] is a length-prefixed byte stream: the transactions
//! are copied once, nothing is hex, nothing is parsed twice.
//!
//! Little-endian throughout; both ends are the same host. Not a consensus
//! artefact and not versioned beyond the leading byte.

use alloy_eips::eip4895::Withdrawal;
use alloy_eips::eip7685::{Requests, RequestsOrHash};
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar, ExecutionPayloadV1,
    ExecutionPayloadV2, ExecutionPayloadV3, ExecutionPayloadV4, PayloadAttributes, PayloadStatus,
    PayloadStatusEnum, PraguePayloadFields,
};
use n42_h2_consensus::header_profile::N42HeaderProfile;

const VERSION: u8 = 1;

/// Request kinds on the channel.
pub mod request {
    /// `u64` payload id follows; the answer is the built block.
    pub const GET_PAYLOAD: u8 = 1;
    /// `u32` length and an encoded [`super::ExecutionData`] follow; the
    /// answer is an encoded [`super::PayloadStatus`].
    pub const NEW_PAYLOAD: u8 = 2;
    /// `u32` length and the RLP of a *sealed header* follow: a block this
    /// execution layer built and still keeps (see `built_executions`), to be
    /// imported without the 19 MB payload travelling back over the wire.
    /// The answer is an encoded [`super::PayloadStatus`], or an error
    /// (`unknown build`) telling the caller to send the whole payload.
    pub const OWN_BLOCK: u8 = 3;
    /// `u32` length and an encoded build-on-own request follow (the RLP of a
    /// *sealed header* this execution layer built and still keeps, and the
    /// [`super::PayloadAttributes`] of the block to build on it): build the
    /// next block on that build's own post-state now, without waiting for
    /// the engine to import the parent or for a forkchoice to name it. The
    /// answer is the built block in `GET_PAYLOAD`'s shape, or an error
    /// (`unknown build`, `no direct builder`) telling the caller to start
    /// the build the ordinary way.
    pub const BUILD_ON_OWN: u8 = 4;
    /// `u32` length and an encoded foreign-body request follow (see
    /// [`super::encode_foreign_body`]): another node's block **as the bytes
    /// the gossip delivered it in**, `[header, txs, verifiers, rewards]`,
    /// plus the block hash consensus voted on and the header profile the
    /// sender read it under. The execution layer decodes that once, in
    /// parallel, straight into the block its import takes -- where
    /// `NEW_PAYLOAD` has the validator decode the body, re-encode 163,000
    /// transactions into a frame of their own and the execution layer parse
    /// them a second time (51.5 ms of hand-off and 55 ms of
    /// `convert_payload_to_block` on a 261 ms R1, loop179).
    ///
    /// The answers are `NEW_PAYLOAD`'s -- a [`super::reply::CHECKED`] frame
    /// then a [`super::reply::VALUE`] one -- with [`super::reply::ERROR`]
    /// meaning "not this way": the caller sends the same block as a
    /// `NEW_PAYLOAD` payload, as the own-block path falls back today.
    pub const FOREIGN_BODY: u8 = 5;
    /// [`FOREIGN_BODY`]'s frame, carrying a *compact* body instead of the
    /// gossip one: the same block with its transactions named by hash
    /// rather than carried (`n42_h2_consensus::compact_body`,
    /// `N42_COMPACT_BODY=1`). The execution layer assembles the block from
    /// its own transaction queue -- where every one of them already sits,
    /// decoded, with the sender its ingest recovered -- and checks the
    /// transactions root of what it assembled against the header's.
    ///
    /// Answers are [`FOREIGN_BODY`]'s. [`super::reply::ERROR`] is again
    /// "not this way", and it covers one case the full body has not: a
    /// transaction this node does not hold. The caller then asks its peers
    /// for the whole body and the ordinary road takes over.
    pub const COMPACT_BODY: u8 = 6;
    /// [`GET_PAYLOAD`], with the block's transaction hashes appended to the
    /// answer: what the compact body names its transactions by. The builder
    /// has them cached on the transactions it built the block from, so they
    /// cost a copy of 32 bytes each there and a keccak over 26 MB on the
    /// proposal path here.
    ///
    /// A kind of its own rather than a flag, because the answer's shape has
    /// to follow the request on a connection that is reused: an execution
    /// layer that predates it refuses the request, the caller's channel
    /// falls back to JSON for that build, and no compact body is made.
    pub const GET_PAYLOAD_HASHED: u8 = 7;
}

/// Reply kinds on the channel.
pub mod reply {
    /// The answer follows: `u32` length and the encoded value.
    pub const VALUE: u8 = 1;
    /// An error follows: `u32` length and the message.
    pub const ERROR: u8 = 2;
    /// `NEW_PAYLOAD` only, under deferred execution
    /// (docs/PHASE_D_DEFERRED_EXECUTION.md): the block was *checked* -- its
    /// header's execution fields match this execution layer's result for the
    /// parent and its transactions are includable on the parent's state --
    /// and is now executing. `u32` length and an encoded
    /// [`super::PayloadStatus`] (VALID) follow, then the final answer as a
    /// [`VALUE`] or [`ERROR`] frame once the block is imported. A block
    /// before the fork, or one this execution layer does not check ahead,
    /// gets no such frame.
    pub const CHECKED: u8 = 3;
    /// [`super::request::BUILD_ON_OWN`] only, and only when the request
    /// carried a chain hint (see [`super::ChainHint`]): the block was sealed
    /// early by the builder and its *built* header follows (`u32` length and
    /// the header's RLP), before the block itself. The caller stamps and
    /// seals that header for the view it will propose it under and can send
    /// the next build's request at once -- the chain -- instead of waiting
    /// for the ~26 MB block to be encoded, to travel, and for the proposal
    /// to go out (measured at loop190/191 as 68-84 ms of a 360 ms cycle with
    /// the builder idle, plus 33-42 ms of request overhead after it).
    ///
    /// A request without a hint gets no such frame, which is what makes the
    /// whole path opt-in and an old caller's traffic unchanged.
    pub const CHAIN_HEADER: u8 = 4;
}

struct Writer(Vec<u8>);
impl Writer {
    fn u8(&mut self, v: u8) { self.0.push(v); }
    fn u32(&mut self, v: u32) { self.0.extend_from_slice(&v.to_le_bytes()); }
    fn u64(&mut self, v: u64) { self.0.extend_from_slice(&v.to_le_bytes()); }
    fn fixed(&mut self, v: &[u8]) { self.0.extend_from_slice(v); }
    fn bytes(&mut self, v: &[u8]) { self.u32(v.len() as u32); self.0.extend_from_slice(v); }
}

struct Reader<'a> {
    rest: &'a [u8],
    /// The whole buffer as shared bytes, when the caller has it: `bytes()`
    /// then slices instead of copying (163,000 transactions a payload).
    shared: Option<&'a Bytes>,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.rest.len() < n { return Err(format!("truncated: wanted {n}, have {}", self.rest.len())); }
        let (a, b) = self.rest.split_at(n); self.rest = b; Ok(a)
    }
    fn u8(&mut self) -> Result<u8, String> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, String> { Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4"))) }
    fn u64(&mut self) -> Result<u64, String> { Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8"))) }
    fn b256(&mut self) -> Result<B256, String> { Ok(B256::from_slice(self.take(32)?)) }
    fn bytes(&mut self) -> Result<Bytes, String> {
        let n = self.u32()? as usize;
        let part = self.take(n)?;
        Ok(match self.shared {
            Some(whole) => {
                let start = part.as_ptr() as usize - whole.as_ptr() as usize;
                whole.slice(start..start + n)
            }
            None => Bytes::copy_from_slice(part),
        })
    }
}

/// Encodes an [`ExecutionData`] for the channel.
pub fn encode_execution_data(data: &ExecutionData) -> Vec<u8> {
    let v1 = data.payload.as_v1();
    let size = 512 + v1.transactions.iter().map(|t| t.len() + 4).sum::<usize>();
    let mut w = Writer(Vec::with_capacity(size));
    w.u8(VERSION);
    w.u8(match &data.payload {
        ExecutionPayload::V1(_) => 1,
        ExecutionPayload::V2(_) => 2,
        ExecutionPayload::V3(_) => 3,
        ExecutionPayload::V4(_) => 4,
    });
    w.fixed(v1.parent_hash.as_slice());
    w.fixed(v1.fee_recipient.as_slice());
    w.fixed(v1.state_root.as_slice());
    w.fixed(v1.receipts_root.as_slice());
    w.fixed(v1.logs_bloom.as_slice());
    w.fixed(v1.prev_randao.as_slice());
    w.u64(v1.block_number);
    w.u64(v1.gas_limit);
    w.u64(v1.gas_used);
    w.u64(v1.timestamp);
    w.bytes(&v1.extra_data);
    w.fixed(&v1.base_fee_per_gas.to_be_bytes::<32>());
    w.fixed(v1.block_hash.as_slice());
    w.fixed(&v1.difficulty.to_be_bytes::<32>());
    w.fixed(v1.nonce.as_slice());
    w.u32(v1.transactions.len() as u32);
    for tx in &v1.transactions {
        w.bytes(tx);
    }
    if let Some(v2) = data.payload.as_v2() {
        w.u32(v2.withdrawals.len() as u32);
        for wd in &v2.withdrawals {
            w.u64(wd.index); w.u64(wd.validator_index); w.fixed(wd.address.as_slice()); w.u64(wd.amount);
        }
    }
    if let Some(v3) = data.payload.as_v3() {
        w.u64(v3.blob_gas_used);
        w.u64(v3.excess_blob_gas);
    }
    if let ExecutionPayload::V4(v4) = &data.payload {
        w.bytes(&v4.block_access_list);
        w.u64(v4.slot_number);
    }
    match data.sidecar.cancun() {
        Some(cancun) => {
            w.u8(1);
            w.fixed(cancun.parent_beacon_block_root.as_slice());
            w.u32(cancun.versioned_hashes.len() as u32);
            for h in &cancun.versioned_hashes { w.fixed(h.as_slice()); }
        }
        None => w.u8(0),
    }
    match data.sidecar.prague() {
        Some(prague) => {
            w.u8(1);
            match &prague.requests {
                RequestsOrHash::Hash(hash) => { w.u8(0); w.fixed(hash.as_slice()); }
                RequestsOrHash::Requests(requests) => {
                    w.u8(1);
                    w.u32(requests.len() as u32);
                    for r in requests.iter() { w.bytes(r); }
                }
            }
        }
        None => w.u8(0),
    }
    w.0
}

/// Decodes what [`encode_execution_data`] produced.
pub fn decode_execution_data(buf: &[u8]) -> Result<ExecutionData, String> {
    decode_with(Reader { rest: buf, shared: None })
}

/// [`decode_execution_data`] over shared bytes: the transactions are slices
/// of `buf`, not copies.
pub fn decode_execution_data_shared(buf: &Bytes) -> Result<ExecutionData, String> {
    decode_with(Reader { rest: buf, shared: Some(buf) })
}

fn decode_with(mut r: Reader<'_>) -> Result<ExecutionData, String> {
    if r.u8()? != VERSION { return Err("unknown raw engine version".into()); }
    let kind = r.u8()?;
    let parent_hash = r.b256()?;
    let fee_recipient = Address::from_slice(r.take(20)?);
    let state_root = r.b256()?;
    let receipts_root = r.b256()?;
    let logs_bloom = Bloom::from_slice(r.take(256)?);
    let prev_randao = r.b256()?;
    let block_number = r.u64()?;
    let gas_limit = r.u64()?;
    let gas_used = r.u64()?;
    let timestamp = r.u64()?;
    let extra_data = r.bytes()?;
    let base_fee_per_gas = U256::from_be_slice(r.take(32)?);
    let block_hash = r.b256()?;
    let difficulty = U256::from_be_slice(r.take(32)?);
    let nonce = B64::from_slice(r.take(8)?);
    let n = r.u32()? as usize;
    let mut transactions = Vec::with_capacity(n);
    for _ in 0..n { transactions.push(r.bytes()?); }
    let v1 = ExecutionPayloadV1 {
        parent_hash, fee_recipient, state_root, receipts_root, logs_bloom, prev_randao, block_number,
        gas_limit, gas_used, timestamp, extra_data, base_fee_per_gas, block_hash, transactions,
        difficulty, nonce,
    };
    let payload = if kind == 1 {
        ExecutionPayload::V1(v1)
    } else {
        let n = r.u32()? as usize;
        let mut withdrawals = Vec::with_capacity(n);
        for _ in 0..n {
            let index = r.u64()?; let validator_index = r.u64()?;
            let address = Address::from_slice(r.take(20)?); let amount = r.u64()?;
            withdrawals.push(Withdrawal { index, validator_index, address, amount });
        }
        let v2 = ExecutionPayloadV2 { payload_inner: v1, withdrawals };
        if kind == 2 {
            ExecutionPayload::V2(v2)
        } else {
            let blob_gas_used = r.u64()?; let excess_blob_gas = r.u64()?;
            let v3 = ExecutionPayloadV3 { payload_inner: v2, blob_gas_used, excess_blob_gas };
            if kind == 3 {
                ExecutionPayload::V3(v3)
            } else if kind == 4 {
                let block_access_list = r.bytes()?; let slot_number = r.u64()?;
                ExecutionPayload::V4(ExecutionPayloadV4 { payload_inner: v3, block_access_list, slot_number })
            } else {
                return Err(format!("unknown payload kind {kind}"));
            }
        }
    };
    let cancun = if r.u8()? == 1 {
        let parent_beacon_block_root = r.b256()?;
        let n = r.u32()? as usize;
        let mut versioned_hashes = Vec::with_capacity(n);
        for _ in 0..n { versioned_hashes.push(r.b256()?); }
        Some(CancunPayloadFields { parent_beacon_block_root, versioned_hashes })
    } else { None };
    let prague = if r.u8()? == 1 {
        let requests = if r.u8()? == 0 {
            RequestsOrHash::Hash(r.b256()?)
        } else {
            let n = r.u32()? as usize;
            let mut list = Vec::with_capacity(n);
            for _ in 0..n { list.push(r.bytes()?); }
            RequestsOrHash::Requests(Requests::new(list))
        };
        Some(PraguePayloadFields { requests })
    } else { None };
    let sidecar = match (cancun, prague) {
        (None, _) => ExecutionPayloadSidecar::none(),
        (Some(c), None) => ExecutionPayloadSidecar::v3(c),
        (Some(c), Some(p)) => ExecutionPayloadSidecar::v4(c, p),
    };
    Ok(ExecutionData::new(payload, sidecar))
}

/// Which header shape the body was read under, on the wire.
///
/// Both ends derive it from the same genesis, so a mismatch is a
/// misconfiguration rather than something to negotiate -- it is sent so the
/// execution layer can say so and refuse, instead of decoding a header under
/// the wrong rules.
const fn profile_byte(profile: N42HeaderProfile) -> u8 {
    match profile {
        N42HeaderProfile::Ethereum => 0,
        N42HeaderProfile::Gov5H2 => 1,
    }
}

/// Encodes a foreign block's gossip body for [`request::FOREIGN_BODY`].
///
/// `block_hash` is the hash the proposal named and consensus voted on; the
/// body is the wire form exactly as it arrived, one opaque field. Nothing in
/// it is re-encoded: the whole point is that these bytes are parsed once, on
/// the other side.
pub fn encode_foreign_body(block_hash: B256, profile: N42HeaderProfile, body: &[u8]) -> Vec<u8> {
    let mut w = Writer(Vec::with_capacity(body.len() + 64));
    w.u8(VERSION);
    w.fixed(block_hash.as_slice());
    w.u8(profile_byte(profile));
    w.bytes(body);
    w.0
}

/// Decodes what [`encode_foreign_body`] produced.
///
/// The body comes back as a slice of `buf`: the ~25 MB frame is read where
/// it was received, never copied to be read. The caller's buffer therefore
/// outlives nothing it hands on -- see `convert_body_to_block`, which copies
/// what it keeps.
pub fn decode_foreign_body(buf: &[u8]) -> Result<(B256, N42HeaderProfile, &[u8]), String> {
    let mut r = Reader { rest: buf, shared: None };
    if r.u8()? != VERSION {
        return Err("unknown raw engine version".into());
    }
    let block_hash = r.b256()?;
    let profile = match r.u8()? {
        0 => N42HeaderProfile::Ethereum,
        1 => N42HeaderProfile::Gov5H2,
        other => return Err(format!("unknown header profile {other}")),
    };
    let len = r.u32()? as usize;
    let body = r.take(len)?;
    if !r.rest.is_empty() {
        return Err(format!("foreign body frame has {} trailing bytes", r.rest.len()));
    }
    Ok((block_hash, profile, body))
}

/// What a caller adds to a build-on-own request when the height after the
/// one being built is its own as well.
///
/// The hint is what licenses the execution layer to answer with a
/// [`reply::CHAIN_HEADER`] frame; without one it behaves exactly as before.
/// It is never a guess on the execution layer's side: the caller knows the
/// leader schedule, the execution layer does not, so the chain only ever
/// runs where consensus said it may.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainHint {
    /// The view the block being built now will be proposed under, which is
    /// what its header's extra data is stamped with. The caller needs it
    /// back with the early-sealed header to produce the very header it will
    /// propose; carrying it here means the execution layer never has to
    /// know what a view is.
    pub view: u64,
    /// Whether this request is itself one the chain issued rather than one
    /// the proposal path made. Carried only so the execution layer's build
    /// line says `chained=true` beside the phase numbers; nothing on the
    /// execution side behaves differently for it.
    pub chained: bool,
}

/// The tag of the chain hint in a request's optional tail. A tail whose tag
/// is not known is skipped rather than refused: the tail is additive, and a
/// peer that learns a new one must not break an older one.
const TAIL_CHAIN_HINT: u8 = 1;

/// The tag that asks for the built block's transaction hashes to be
/// appended to the answer (see [`request::GET_PAYLOAD_HASHED`]). No
/// payload of its own: the tag is the request.
const TAIL_WANT_HASHES: u8 = 2;

/// Encodes a build-on-own request: the sealed header of the block just built
/// (RLP) and the attributes of the block to build on it.
pub fn encode_build_on_own(header: &alloy_consensus::Header, attrs: &PayloadAttributes) -> Vec<u8> {
    encode_build_on_own_chaining(header, attrs, None, false)
}

/// [`encode_build_on_own`] with a chain hint appended.
///
/// The hint goes in a tail *after* every field the first version of this
/// frame had, and the decoder stops at the end of the buffer, so the two
/// directions of a mixed fleet both fail safe: an execution layer that
/// predates the tail reads the fields it knows and ignores the rest (no
/// chaining), and one that knows the tail reads no hint out of a frame that
/// has none (no chaining). Nothing chains unless both ends agree.
pub fn encode_build_on_own_chaining(
    header: &alloy_consensus::Header,
    attrs: &PayloadAttributes,
    chain: Option<ChainHint>,
    want_hashes: bool,
) -> Vec<u8> {
    let rlp = alloy_rlp::encode(header);
    let mut w = Writer(Vec::with_capacity(rlp.len() + 128 + attrs.withdrawals.as_ref().map_or(0, |w| w.len() * 44)));
    w.u8(VERSION);
    w.bytes(&rlp);
    w.u64(attrs.timestamp);
    w.fixed(attrs.prev_randao.as_slice());
    w.fixed(attrs.suggested_fee_recipient.as_slice());
    match &attrs.withdrawals {
        Some(withdrawals) => {
            w.u8(1);
            w.u32(withdrawals.len() as u32);
            for wd in withdrawals {
                w.u64(wd.index); w.u64(wd.validator_index); w.fixed(wd.address.as_slice()); w.u64(wd.amount);
            }
        }
        None => w.u8(0),
    }
    match attrs.parent_beacon_block_root {
        Some(root) => { w.u8(1); w.fixed(root.as_slice()); }
        None => w.u8(0),
    }
    match attrs.slot_number {
        Some(slot) => { w.u8(1); w.u64(slot); }
        None => w.u8(0),
    }
    match attrs.target_gas_limit {
        Some(limit) => { w.u8(1); w.u64(limit); }
        None => w.u8(0),
    }
    if let Some(hint) = chain {
        w.u8(TAIL_CHAIN_HINT);
        w.u64(hint.view);
        w.u8(u8::from(hint.chained));
    }
    if want_hashes {
        w.u8(TAIL_WANT_HASHES);
    }
    w.0
}

/// Decodes what [`encode_build_on_own`] produced, with the chain hint when
/// the frame carries one.
pub fn decode_build_on_own(
    buf: &[u8],
) -> Result<(alloy_consensus::Header, PayloadAttributes, Option<ChainHint>, bool), String> {
    use alloy_rlp::Decodable;
    let mut r = Reader { rest: buf, shared: None };
    if r.u8()? != VERSION { return Err("unknown raw engine version".into()); }
    let rlp = r.bytes()?;
    let header = alloy_consensus::Header::decode(&mut &rlp[..]).map_err(|e| format!("header: {e}"))?;
    let timestamp = r.u64()?;
    let prev_randao = r.b256()?;
    let suggested_fee_recipient = Address::from_slice(r.take(20)?);
    let withdrawals = if r.u8()? == 1 {
        let n = r.u32()? as usize;
        let mut list = Vec::with_capacity(n);
        for _ in 0..n {
            let index = r.u64()?; let validator_index = r.u64()?;
            let address = Address::from_slice(r.take(20)?); let amount = r.u64()?;
            list.push(Withdrawal { index, validator_index, address, amount });
        }
        Some(list)
    } else { None };
    let parent_beacon_block_root = if r.u8()? == 1 { Some(r.b256()?) } else { None };
    let slot_number = if r.u8()? == 1 { Some(r.u64()?) } else { None };
    let target_gas_limit = if r.u8()? == 1 { Some(r.u64()?) } else { None };
    // The tail. Empty in every frame written before it existed, so its
    // absence is "no hint" rather than a truncated frame.
    let mut chain = None;
    let mut want_hashes = false;
    while !r.rest.is_empty() {
        match r.u8()? {
            TAIL_CHAIN_HINT => chain = Some(ChainHint { view: r.u64()?, chained: r.u8()? == 1 }),
            TAIL_WANT_HASHES => want_hashes = true,
            // A tag from a newer peer. Its length is not known here, so
            // there is nothing to skip to: stop reading and keep what was
            // understood. Fields are only ever appended, so everything
            // before this point is still exactly right.
            _ => break,
        }
    }
    Ok((header, PayloadAttributes { timestamp, prev_randao, suggested_fee_recipient, withdrawals, parent_beacon_block_root, slot_number, target_gas_limit }, chain, want_hashes))
}

/// Encodes a [`PayloadStatus`] for the channel.
pub fn encode_payload_status(status: &PayloadStatus) -> Vec<u8> {
    let mut w = Writer(Vec::with_capacity(80));
    let (kind, error) = match &status.status {
        PayloadStatusEnum::Valid => (0u8, None),
        PayloadStatusEnum::Invalid { validation_error } => (1, Some(validation_error.to_string())),
        PayloadStatusEnum::Syncing => (2, None),
        PayloadStatusEnum::Accepted => (3, None),
    };
    w.u8(kind);
    match status.latest_valid_hash { Some(h) => { w.u8(1); w.fixed(h.as_slice()); } None => w.u8(0) }
    w.bytes(error.unwrap_or_default().as_bytes());
    w.0
}

/// Decodes what [`encode_payload_status`] produced.
pub fn decode_payload_status(buf: &[u8]) -> Result<PayloadStatus, String> {
    let mut r = Reader { rest: buf, shared: None };
    let kind = r.u8()?;
    let latest_valid_hash = if r.u8()? == 1 { Some(r.b256()?) } else { None };
    let error = String::from_utf8_lossy(&r.bytes()?).into_owned();
    let status = match kind {
        0 => PayloadStatusEnum::Valid,
        1 => PayloadStatusEnum::Invalid { validation_error: error },
        2 => PayloadStatusEnum::Syncing,
        3 => PayloadStatusEnum::Accepted,
        other => return Err(format!("unknown payload status {other}")),
    };
    Ok(PayloadStatus { status, latest_valid_hash })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v1() -> ExecutionPayloadV1 {
        ExecutionPayloadV1 {
            parent_hash: B256::repeat_byte(1), fee_recipient: Address::repeat_byte(2), state_root: B256::repeat_byte(3),
            receipts_root: B256::repeat_byte(4), logs_bloom: Bloom::repeat_byte(5), prev_randao: B256::repeat_byte(6),
            block_number: 7, gas_limit: 8, gas_used: 9, timestamp: 10, extra_data: Bytes::from_static(&[0xaa, 0xbb]),
            base_fee_per_gas: U256::from(11), block_hash: B256::repeat_byte(12),
            transactions: vec![Bytes::from_static(&[0x02, 0x01]), Bytes::from_static(&[0xf8, 0x00, 0x11])],
            difficulty: U256::from(13), nonce: B64::repeat_byte(14),
        }
    }

    #[test]
    fn execution_data_round_trips_in_every_shape() {
        let wd = Withdrawal { index: 1, validator_index: 2, address: Address::repeat_byte(3), amount: 4 };
        let v2 = ExecutionPayloadV2 { payload_inner: v1(), withdrawals: vec![wd] };
        let v3 = ExecutionPayloadV3 { payload_inner: v2.clone(), blob_gas_used: 5, excess_blob_gas: 6 };
        let v4 = ExecutionPayloadV4 { payload_inner: v3.clone(), block_access_list: Bytes::from_static(&[0xc0]), slot_number: 9 };
        let cancun = CancunPayloadFields { parent_beacon_block_root: B256::repeat_byte(7), versioned_hashes: vec![B256::repeat_byte(8)] };
        let prague = PraguePayloadFields { requests: RequestsOrHash::Requests(Requests::new(vec![Bytes::from_static(&[0x01, 0x02])])) };
        let cases = vec![
            ExecutionData::new(ExecutionPayload::V1(v1()), ExecutionPayloadSidecar::none()),
            ExecutionData::new(ExecutionPayload::V2(v2), ExecutionPayloadSidecar::none()),
            ExecutionData::new(ExecutionPayload::V3(v3), ExecutionPayloadSidecar::v3(cancun.clone())),
            ExecutionData::new(ExecutionPayload::V4(v4), ExecutionPayloadSidecar::v4(cancun.clone(), prague)),
            ExecutionData::new(ExecutionPayload::V1(v1()), ExecutionPayloadSidecar::v4(cancun, PraguePayloadFields { requests: RequestsOrHash::Hash(B256::repeat_byte(9)) })),
        ];
        for data in cases {
            let back = decode_execution_data(&encode_execution_data(&data)).expect("decodes");
            assert_eq!(format!("{back:?}"), format!("{data:?}"));
        }
    }

    #[test]
    fn build_on_own_round_trips_with_and_without_the_optional_fields() {
        let header = alloy_consensus::Header { number: 41, gas_used: 3_423_000_000, extra_data: Bytes::from_static(&[9, 9]), ..Default::default() };
        let full = PayloadAttributes {
            timestamp: 1_700_000_000,
            prev_randao: B256::repeat_byte(5),
            suggested_fee_recipient: Address::repeat_byte(6),
            withdrawals: Some(vec![Withdrawal { index: 1, validator_index: 2, address: Address::repeat_byte(3), amount: 4 }]),
            parent_beacon_block_root: Some(B256::repeat_byte(7)),
            slot_number: Some(42),
            target_gas_limit: Some(3_600_000_000),
        };
        let bare = PayloadAttributes { withdrawals: None, parent_beacon_block_root: None, slot_number: None, target_gas_limit: None, ..full.clone() };
        for attrs in [full, bare] {
            let (h, a, chain, hashes) = decode_build_on_own(&encode_build_on_own(&header, &attrs)).expect("decodes");
            assert_eq!(h, header);
            assert_eq!(a, attrs);
            assert_eq!(chain, None, "a frame without a tail hints nothing");
            assert!(!hashes, "and asks for nothing");
            let hinted = encode_build_on_own_chaining(&header, &attrs, Some(ChainHint { view: 4242, chained: true }), true);
            let (h, a, chain, hashes) = decode_build_on_own(&hinted).expect("decodes");
            assert_eq!(h, header);
            assert_eq!(a, attrs);
            assert_eq!(chain, Some(ChainHint { view: 4242, chained: true }));
            assert!(hashes, "the hash tail is read beside the hint");
            // The hint is a tail: everything before it is the frame an
            // execution layer that predates it reads, byte for byte.
            let plain = encode_build_on_own(&header, &attrs);
            assert_eq!(&hinted[..plain.len()], &plain[..], "the hint only appends");
            // And a tag this build does not know leaves the fields intact.
            let mut unknown = plain.clone();
            unknown.push(0xfe);
            unknown.extend_from_slice(&7u64.to_le_bytes());
            let (h, a, chain, hashes) = decode_build_on_own(&unknown).expect("decodes");
            assert_eq!((h, a, chain, hashes), (header.clone(), attrs.clone(), None, false));
        }
    }
    #[test]
    fn a_foreign_body_round_trips_and_is_not_copied() {
        let body = vec![0xab; 4096];
        let hash = B256::repeat_byte(0x5a);
        for profile in [N42HeaderProfile::Ethereum, N42HeaderProfile::Gov5H2] {
            let frame = encode_foreign_body(hash, profile, &body);
            let (back_hash, back_profile, back_body) = decode_foreign_body(&frame).expect("decodes");
            assert_eq!(back_hash, hash);
            assert_eq!(back_profile, profile);
            assert_eq!(back_body, &body[..]);
            // A slice of the frame, not a copy of the body: the whole point
            // is that the ~25 MB it carries is read where it landed.
            let start = back_body.as_ptr() as usize - frame.as_ptr() as usize;
            assert!(start + back_body.len() <= frame.len());
        }
    }

    #[test]
    fn a_truncated_or_padded_foreign_body_is_refused() {
        let frame = encode_foreign_body(B256::ZERO, N42HeaderProfile::Gov5H2, &[1, 2, 3]);
        assert!(decode_foreign_body(&frame[..frame.len() - 1]).is_err());
        let mut padded = frame.clone();
        padded.push(0);
        assert!(decode_foreign_body(&padded).is_err());
        let mut wrong_version = frame;
        wrong_version[0] = VERSION + 1;
        assert!(decode_foreign_body(&wrong_version).is_err());
    }

    #[test]
    fn payload_status_round_trips() {
        for status in [
            PayloadStatus::new(PayloadStatusEnum::Valid, Some(B256::repeat_byte(1))),
            PayloadStatus::new(PayloadStatusEnum::Invalid { validation_error: "bad".into() }, None),
            PayloadStatus::new(PayloadStatusEnum::Syncing, None),
            PayloadStatus::new(PayloadStatusEnum::Accepted, None),
        ] {
            let back = decode_payload_status(&encode_payload_status(&status)).unwrap();
            assert_eq!(back.status, status.status);
            assert_eq!(back.latest_valid_hash, status.latest_valid_hash);
        }
    }
}
