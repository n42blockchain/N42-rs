// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `/rpc/bodies_by_range/2/ssz_snappy` (sync standard §5.1), byte for byte
//! with gov5's `syncwire` (`RangeRequest`, `RangeEnd`) and `v11/range.go`
//! (`ServeRangeV2`, `ReadRangeV2`).
//!
//! ```text
//! Request (32 B):  start u64 ‖ count u64 (1..1024) ‖ max_bytes u64 (0 = 64 MiB) ‖ flags u64
//!                  flags bit0 HEADERS_ONLY; all other bits MUST be 0
//! Response:        0..count chunks 0x00 ‖ digest[4] ‖ framed(RLP block | RLP header)
//!                  then exactly one 0x10 ‖ framed(RangeEnd)
//! RangeEnd (17 B): next u64 ‖ served_bytes u64 ‖ reason u8
//! ```
//!
//! - [`RangeV2Builder`] is the server's core: it decides, block by block,
//!   what the reply carries and why it ends; the caller feeds it the blocks
//!   of its committed chain.
//! - [`check_range_v2`] is the client's: the §5.1 client MUSTs (contiguous,
//!   parent-linked, the END consistent with the chunks), a violation being a
//!   provable fault of the server (§3.5).
//! - [`RangeV2Codec`] carries both over libp2p request-response.

use std::io;

use alloy_primitives::{keccak256, Bytes, B256};
use alloy_rlp::{Decodable, Header as RlpHeader};
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use libp2p::StreamProtocol;

use super::frame::{self, CodeError, EndReason};

/// The protocol id.
pub const BODIES_BY_RANGE_V2_PROTOCOL: &str = "/rpc/bodies_by_range/2/ssz_snappy";

/// The protocol id, negotiated.
pub fn bodies_by_range_v2_protocol() -> StreamProtocol {
    StreamProtocol::new(BODIES_BY_RANGE_V2_PROTOCOL)
}

/// The encoded size of a [`RangeV2Request`].
pub const RANGE_V2_REQUEST_LEN: usize = 32;
/// The most blocks (or headers) one request may ask for.
pub const MAX_RANGE_V2_COUNT: u64 = 1024;
/// The byte budget of `max_bytes = 0`.
pub const DEFAULT_RANGE_V2_BYTES: u64 = 64 << 20;
/// The server cap on a reply's decoded bytes.
pub const MAX_RANGE_V2_REPLY_BYTES: u64 = 128 << 20;
/// The largest header a HEADERS_ONLY chunk (or a `commit_qc/1` header) may be.
pub const MAX_HEADER_BYTES: u64 = 64 << 10;
/// The HEADERS_ONLY flag.
pub const FLAG_HEADERS_ONLY: u64 = 1;

/// The `bodies_by_range/2` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RangeV2Request {
    /// The first block number.
    pub start: u64,
    /// How many, 1..1024.
    pub count: u64,
    /// The decoded-byte budget the requester asks for (0 = 64 MiB).
    pub max_bytes: u64,
    /// bit0 HEADERS_ONLY.
    pub flags: u64,
}

impl RangeV2Request {
    /// Full bodies of `count` blocks from `start`, the server's default budget.
    pub const fn bodies(start: u64, count: u64) -> Self {
        Self { start, count, max_bytes: 0, flags: 0 }
    }

    /// The 32 bytes on the wire.
    pub fn encode(&self) -> [u8; RANGE_V2_REQUEST_LEN] {
        let mut out = [0u8; RANGE_V2_REQUEST_LEN];
        out[0..8].copy_from_slice(&self.start.to_le_bytes());
        out[8..16].copy_from_slice(&self.count.to_le_bytes());
        out[16..24].copy_from_slice(&self.max_bytes.to_le_bytes());
        out[24..32].copy_from_slice(&self.flags.to_le_bytes());
        out
    }

    /// Decodes and validates a request; the error is gov5's message, which
    /// the server answers with under `0x01 INVALID_REQUEST`.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != RANGE_V2_REQUEST_LEN {
            return Err("syncwire: wrong message length".to_owned());
        }
        let word = |i: usize| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap_or_default());
        let request = Self { start: word(0), count: word(1), max_bytes: word(2), flags: word(3) };
        if request.count == 0 || request.count > MAX_RANGE_V2_COUNT {
            return Err(format!("syncwire: range count {} outside 1..{MAX_RANGE_V2_COUNT}", request.count));
        }
        if request.flags & !FLAG_HEADERS_ONLY != 0 {
            return Err(format!("syncwire: reserved range flag bits {:#x} set", request.flags & !FLAG_HEADERS_ONLY));
        }
        if request.start.checked_add(request.count).is_none() {
            return Err("syncwire: range overflows u64".to_owned());
        }
        Ok(request)
    }

    /// The HEADERS_ONLY flag.
    pub const fn headers_only(&self) -> bool {
        self.flags & FLAG_HEADERS_ONLY != 0
    }

    /// The decoded-byte budget a server applies: `min(max_bytes or 64 MiB,
    /// 128 MiB)`.
    pub const fn budget(&self) -> u64 {
        let wanted = if self.max_bytes == 0 { DEFAULT_RANGE_V2_BYTES } else { self.max_bytes };
        if wanted > MAX_RANGE_V2_REPLY_BYTES {
            MAX_RANGE_V2_REPLY_BYTES
        } else {
            wanted
        }
    }

    /// The first number past the range.
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.count)
    }
}

/// The END trailer of `bodies_by_range/2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RangeEnd {
    /// The first number not served.
    pub next: u64,
    /// The sum of the decoded payload lengths sent.
    pub served_bytes: u64,
    /// Why the reply ended.
    pub reason: EndReason,
}

impl RangeEnd {
    /// The 17 bytes on the wire.
    pub fn encode(&self) -> [u8; frame::END_LEN] {
        let mut out = [0u8; frame::END_LEN];
        out[0..8].copy_from_slice(&self.next.to_le_bytes());
        out[8..16].copy_from_slice(&self.served_bytes.to_le_bytes());
        out[16] = self.reason.as_u8();
        out
    }

    /// Decodes an END payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != frame::END_LEN {
            return Err("syncwire: wrong message length".to_owned());
        }
        let next = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or_default());
        let served_bytes = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or_default());
        let reason =
            EndReason::from_u8(bytes[16]).ok_or_else(|| format!("syncwire: unknown END reason {}", bytes[16]))?;
        Ok(Self { next, served_bytes, reason })
    }

    /// The §5.1 client checks of an END against the `chunks` payloads of
    /// `bytes` decoded bytes that came before it (gov5's `CheckRangeEnd`).
    pub fn check(&self, request: &RangeV2Request, chunks: u64, bytes: u64) -> Result<(), String> {
        if self.next != request.start.saturating_add(chunks) {
            return Err(format!("END next {}, but {chunks} chunks from {} were sent", self.next, request.start));
        }
        if self.served_bytes != bytes {
            return Err(format!("END served_bytes {}, chunks carried {bytes}", self.served_bytes));
        }
        if (self.reason == EndReason::Complete) != (self.next == request.end()) {
            return Err(format!(
                "END reason {} with next {} for start {} count {}",
                self.reason.as_u8(),
                self.next,
                request.start,
                request.count
            ));
        }
        if chunks == 0 && !self.reason.allows_empty() {
            return Err(format!("END reason {} with no chunk", self.reason.as_u8()));
        }
        if chunks > request.count {
            return Err(format!("{chunks} chunks for a count of {}", request.count));
        }
        Ok(())
    }
}

/// What a chunk's payload says about its place in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemLinks {
    /// The block number.
    pub number: u64,
    /// The block hash, keccak of the RLP header.
    pub hash: B256,
    /// The parent hash.
    pub parent: B256,
}

/// The header fields that place a payload in the chain: a block
/// `[header, txs, verifiers, rewards, ...]` or, under HEADERS_ONLY, a bare
/// RLP header.
pub fn item_links(payload: &[u8], headers_only: bool) -> Result<ItemLinks, String> {
    let header_rlp = if headers_only {
        payload
    } else {
        let mut rest = payload;
        let outer = RlpHeader::decode(&mut rest).map_err(|e| format!("block RLP: {e}"))?;
        if !outer.list || outer.payload_length != rest.len() {
            return Err("block RLP is not one list".to_owned());
        }
        let mut item = rest;
        let inner = RlpHeader::decode(&mut item).map_err(|e| format!("header RLP: {e}"))?;
        let consumed = rest.len() - item.len() + inner.payload_length;
        if consumed > rest.len() {
            return Err("header RLP runs past the block".to_owned());
        }
        &rest[..consumed]
    };
    let mut cursor = header_rlp;
    let header = n42_h2_consensus::N42Header::decode(&mut cursor).map_err(|e| format!("header: {e}"))?;
    if !cursor.is_empty() {
        return Err("bytes after the header".to_owned());
    }
    Ok(ItemLinks { number: header.number, hash: keccak256(header_rlp), parent: header.parent_hash })
}

/// One item a server offers [`RangeV2Builder`]: a block's (or header's)
/// payload and its links.
#[derive(Debug, Clone)]
pub struct RangeItem {
    /// The chunk payload: the gov5 block RLP, or the RLP header.
    pub payload: Bytes,
    /// The block hash.
    pub hash: B256,
    /// The parent hash.
    pub parent: B256,
}

/// The server core of `bodies_by_range/2` (gov5's `ServeRangeV2`):
/// committed canonical items contiguous and parent-linked from the start,
/// stopping before an item that would push the reply past its byte budget
/// (the first is always sent), at the committed head (CANONICAL_END), at an
/// item the server does not hold or that does not link (NOT_AVAILABLE).
///
/// Drive it with [`Self::wanted`] / [`Self::offer`] until `wanted` says
/// `None`, then [`Self::finish`].
#[derive(Debug)]
pub struct RangeV2Builder {
    request: RangeV2Request,
    budget: u64,
    head: u64,
    end: RangeEnd,
    prev: B256,
    payloads: Vec<Bytes>,
    stopped: bool,
}

impl RangeV2Builder {
    /// A reply to `request` from a server whose committed head is
    /// `committed_head`.
    pub const fn new(request: RangeV2Request, committed_head: u64) -> Self {
        Self {
            request,
            budget: request.budget(),
            head: committed_head,
            end: RangeEnd { next: request.start, served_bytes: 0, reason: EndReason::Complete },
            prev: B256::ZERO,
            payloads: Vec::new(),
            stopped: false,
        }
    }

    /// The request being answered.
    pub const fn request(&self) -> &RangeV2Request {
        &self.request
    }

    /// The number to offer next, or `None` once the reply is decided.
    pub fn wanted(&mut self) -> Option<u64> {
        if self.stopped || self.end.next >= self.request.end() {
            return None;
        }
        if self.end.next > self.head {
            self.stop(EndReason::CanonicalEnd);
            return None;
        }
        Some(self.end.next)
    }

    /// Offers the item [`Self::wanted`] named; `None` when the server does
    /// not hold it. `false` when the reply is decided.
    pub fn offer(&mut self, item: Option<RangeItem>) -> bool {
        let Some(item) = item else {
            self.stop(EndReason::NotAvailable);
            return false;
        };
        let first = self.end.next == self.request.start;
        if !first && item.parent != self.prev {
            // A canonical hole.
            self.stop(EndReason::NotAvailable);
            return false;
        }
        let len = item.payload.len() as u64;
        if !first && self.end.served_bytes.saturating_add(len) > self.budget {
            self.stop(EndReason::ByteBudget);
            return false;
        }
        self.end.served_bytes += len;
        self.end.next += 1;
        self.prev = item.hash;
        self.payloads.push(item.payload);
        true
    }

    /// Ends the reply early for a reason of the server's own (its count
    /// cap, its rate limit, shutdown).
    pub const fn stop(&mut self, reason: EndReason) {
        if !self.stopped {
            self.stopped = true;
            self.end.reason = reason;
        }
    }

    /// The payloads and the END; the reason is COMPLETE exactly when
    /// everything asked for was served.
    pub fn finish(mut self) -> (Vec<Bytes>, RangeEnd) {
        if self.end.next == self.request.end() {
            self.end.reason = EndReason::Complete;
        }
        (self.payloads, self.end)
    }

    /// The reply ready for the codec.
    pub fn into_reply(self) -> RangeV2Reply {
        let (payloads, end) = self.finish();
        RangeV2Reply::Served { payloads, end: Some(end) }
    }
}

/// A `bodies_by_range/2` reply, as written or as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeV2Reply {
    /// Data chunks, then the END trailer. Read side: `end` is `None` when
    /// the stream ended without one (a soft fault, §5.1), or ended in an
    /// error chunk or a cut after a prefix (the prefix is kept).
    Served {
        /// The chunk payloads, in order.
        payloads: Vec<Bytes>,
        /// The END trailer.
        end: Option<RangeEnd>,
    },
    /// A single error chunk before any data.
    Refused(CodeError),
}

/// The wire bytes of a reply: data chunks carry `context` (the fork digest).
pub fn encode_range_v2_reply(reply: &RangeV2Reply, context: &[u8; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    match reply {
        RangeV2Reply::Served { payloads, end } => {
            for payload in payloads {
                frame::append_chunk(&mut out, frame::CODE_SUCCESS, Some(context), payload);
            }
            if let Some(end) = end {
                frame::append_chunk(&mut out, frame::CODE_END, None, &end.encode());
            }
        }
        RangeV2Reply::Refused(err) => frame::append_error(&mut out, err.code, &err.message),
    }
    out
}

/// Reads a reply (gov5's `ReadRangeV2` minus the request checks, which
/// [`check_range_v2`] applies). `max_item` bounds one payload,
/// `max_total` the reply's decoded bytes (the rest is read as a cut).
pub async fn read_range_v2_reply<T>(io: &mut T, max_item: u64, max_total: u64) -> io::Result<RangeV2Reply>
where
    T: AsyncRead + Unpin,
{
    let mut payloads: Vec<Bytes> = Vec::new();
    let mut total = 0u64;
    loop {
        if total > max_total || payloads.len() as u64 > MAX_RANGE_V2_COUNT {
            // More than any reply may carry: keep the prefix, no END.
            return Ok(RangeV2Reply::Served { payloads, end: None });
        }
        let chunk = match frame::read_chunk(io, true, max_item).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return Ok(RangeV2Reply::Served { payloads, end: None }),
            Err(_) if !payloads.is_empty() => return Ok(RangeV2Reply::Served { payloads, end: None }),
            Err(err) => return Err(err),
        };
        match chunk.code {
            frame::CODE_SUCCESS => {
                total = total.saturating_add(chunk.payload.len() as u64);
                payloads.push(chunk.payload.into());
            }
            frame::CODE_END => {
                let end = RangeEnd::decode(&chunk.payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                return Ok(RangeV2Reply::Served { payloads, end: Some(end) });
            }
            _ if !payloads.is_empty() => return Ok(RangeV2Reply::Served { payloads, end: None }),
            _ => return Ok(RangeV2Reply::Refused(chunk.as_error())),
        }
    }
}

/// A reply checked against its request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedRange {
    /// The payloads, contiguous from the request's start and parent-linked.
    pub payloads: Vec<Bytes>,
    /// The END, `None` when the server sent none (soft fault, no score).
    pub end: Option<RangeEnd>,
}

/// The §5.1 client MUSTs (gov5's `ReadRangeV2` checks): every payload is the
/// next number and links to the one before, no more chunks than asked, a
/// HEADERS_ONLY header within its cap, and an END consistent with the
/// chunks. `Err` is a provable fault of the server (§3.5); a refusal is
/// returned as itself.
pub fn check_range_v2(request: &RangeV2Request, reply: RangeV2Reply) -> Result<Result<CheckedRange, CodeError>, String> {
    let (payloads, end) = match reply {
        RangeV2Reply::Refused(err) => return Ok(Err(err)),
        RangeV2Reply::Served { payloads, end } => (payloads, end),
    };
    let mut prev = B256::ZERO;
    let mut bytes = 0u64;
    for (i, payload) in payloads.iter().enumerate() {
        let want = request.start + i as u64;
        if i as u64 >= request.count {
            return Err(format!("more chunks than the count {}", request.count));
        }
        if request.headers_only() && payload.len() as u64 > MAX_HEADER_BYTES {
            return Err(format!("header {want} of {} bytes", payload.len()));
        }
        let links = item_links(payload, request.headers_only()).map_err(|e| format!("chunk {want}: {e}"))?;
        if links.number != want || (i > 0 && links.parent != prev) {
            return Err(format!("chunk {want} is block {} (parent-linked {})", links.number, i == 0 || links.parent == prev));
        }
        prev = links.hash;
        bytes += payload.len() as u64;
    }
    if let Some(end) = &end {
        end.check(request, payloads.len() as u64, bytes)?;
    }
    Ok(Ok(CheckedRange { payloads, end }))
}

/// What a server reads off an inbound stream: the request, or gov5's
/// INVALID_REQUEST message for one that does not decode.
pub type InboundRangeV2 = Result<RangeV2Request, String>;

/// The request-response codec. libp2p clones it per stream.
#[derive(Debug, Clone)]
pub struct RangeV2Codec {
    /// The context bytes of data chunks: the genesis hash's first four.
    context: [u8; 4],
    /// How long a reply is read for, from when its request was written.
    read_deadline: Option<std::time::Duration>,
    sent_at: Option<tokio::time::Instant>,
}

impl RangeV2Codec {
    /// A codec writing `context` on data chunks, reading a reply for at most
    /// `read_deadline` (the prefix read by then is kept).
    pub const fn new(context: [u8; 4], read_deadline: Option<std::time::Duration>) -> Self {
        Self { context, read_deadline, sent_at: None }
    }
}

impl request_response::Codec for RangeV2Codec {
    type Protocol = StreamProtocol;
    type Request = InboundRangeV2;
    type Response = RangeV2Reply;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        Ok(match frame::read_request_checked(io, RANGE_V2_REQUEST_LEN as u64).await? {
            Ok(payload) => RangeV2Request::decode(&payload),
            Err(message) => Err(message),
        })
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let max_item = crate::config::max_block_chunk();
        let read = read_range_v2_reply(io, max_item, MAX_RANGE_V2_REPLY_BYTES);
        match self.read_deadline {
            None => read.await,
            Some(after) => {
                let at = self.sent_at.unwrap_or_else(tokio::time::Instant::now) + after;
                tokio::time::timeout_at(at, read)
                    .await
                    .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "range v2 reply timed out")))
            }
        }
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, request: Self::Request) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let request = request.map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        if self.read_deadline.is_some() {
            self.sent_at = Some(tokio::time::Instant::now());
        }
        io.write_all(&frame::framed(&request.encode())).await?;
        io.close().await
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, reply: Self::Response) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match &reply {
            RangeV2Reply::Served { payloads, end } => {
                // Chunk by chunk, so a large reply is not copied whole once more.
                for payload in payloads {
                    let mut chunk = Vec::with_capacity(payload.len() / 2 + 32);
                    frame::append_chunk(&mut chunk, frame::CODE_SUCCESS, Some(&self.context), payload);
                    io.write_all(&chunk).await?;
                }
                if let Some(end) = end {
                    io.write_all(&frame::chunk(frame::CODE_END, None, &end.encode())).await?;
                }
            }
            RangeV2Reply::Refused(err) => io.write_all(&frame::error_chunk(err.code, &err.message)).await?,
        }
        io.close().await
    }
}

/// The request-response behaviour.
pub type RangeV2Behaviour = request_response::Behaviour<RangeV2Codec>;

/// libp2p's timer on a v2 range stream (§6.2: 60 s); the codec stops
/// reading two seconds before it and keeps the prefix.
pub const RANGE_V2_STREAM_TIMEOUT: std::time::Duration = frame::STREAM_REQUEST_TIMEOUT;

/// Serving and requesting `bodies_by_range/2` on the chain whose fork digest
/// is `context`.
pub fn range_v2_behaviour(context: [u8; 4]) -> RangeV2Behaviour {
    request_response::Behaviour::with_codec(
        RangeV2Codec::new(context, Some(RANGE_V2_STREAM_TIMEOUT - std::time::Duration::from_secs(2))),
        [(bodies_by_range_v2_protocol(), request_response::ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(RANGE_V2_STREAM_TIMEOUT),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_v11::vectors;
    use futures::FutureExt;
    use std::collections::BTreeMap;

    /// The chain the vectors were served from, as far as they show it:
    /// block bodies by number, headers by number.
    struct VectorChain {
        bodies: BTreeMap<u64, Bytes>,
        headers: BTreeMap<u64, Bytes>,
        context: [u8; 4],
    }

    fn vector_chain() -> VectorChain {
        let file = vectors::load("bodies_by_range_2.json");
        let genesis = vectors::bytes(&file["genesis_hash"]);
        let mut chain = VectorChain { bodies: BTreeMap::new(), headers: BTreeMap::new(), context: genesis[..4].try_into().unwrap() };
        for case in file["cases"].as_array().unwrap() {
            let request = RangeV2Request::decode(&vectors::bytes(&case["request_payload"]));
            let Ok(request) = request else { continue };
            for chunk in vectors::listed_chunks(case).into_iter().filter(|c| c.code == frame::CODE_SUCCESS) {
                let links = item_links(&chunk.payload, request.headers_only()).unwrap();
                let into = if request.headers_only() { &mut chain.headers } else { &mut chain.bodies };
                into.insert(links.number, chunk.payload.into());
            }
        }
        chain
    }

    /// gov5's vector server: committed head 10, bodies held from 7 (the
    /// node joined by state sync at pivot 6), headers from 6.
    fn serve(chain: &VectorChain, request: RangeV2Request) -> RangeV2Reply {
        let mut builder = RangeV2Builder::new(request, 10);
        while let Some(number) = builder.wanted() {
            let source = if request.headers_only() { &chain.headers } else { &chain.bodies };
            let item = source.get(&number).map(|payload| {
                let links = item_links(payload, request.headers_only()).unwrap();
                RangeItem { payload: payload.clone(), hash: links.hash, parent: links.parent }
            });
            if !builder.offer(item) {
                break;
            }
        }
        builder.into_reply()
    }

    #[test]
    fn every_vector_case_is_served_byte_for_byte() {
        let chain = vector_chain();
        assert_eq!(chain.bodies.keys().copied().collect::<Vec<_>>(), vec![7, 8, 9, 10]);
        let file = vectors::load("bodies_by_range_2.json");
        for case in file["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let wire = frame::decode_request(&vectors::bytes(&case["request_wire"]), 32).unwrap();
            let reply = match RangeV2Request::decode(&wire) {
                Ok(request) => {
                    let fields = &case["request_fields"];
                    assert_eq!(request.start, fields["start"].as_u64().unwrap(), "{name}");
                    assert_eq!(request.count, fields["count"].as_u64().unwrap(), "{name}");
                    assert_eq!(request.max_bytes, fields["max_bytes"].as_u64().unwrap(), "{name}");
                    assert_eq!(request.flags, fields["flags"].as_u64().unwrap(), "{name}");
                    assert_eq!(frame::framed(&request.encode()), vectors::bytes(&case["request_wire"]), "{name}: request encode");
                    serve(&chain, request)
                }
                Err(message) => RangeV2Reply::Refused(CodeError { code: frame::CODE_INVALID_REQUEST, message }),
            };
            let encoded = encode_range_v2_reply(&reply, &chain.context);
            assert_eq!(hex::encode(&encoded), hex::encode(vectors::bytes(&case["response_wire"])), "{name}: served reply");
        }
    }

    #[test]
    fn every_vector_case_reads_and_checks_as_gov5_reads_it() {
        let file = vectors::load("bodies_by_range_2.json");
        for case in file["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let response = vectors::bytes(&case["response_wire"]);
            let reply = read_range_v2_reply(&mut &response[..], 64 << 20, MAX_RANGE_V2_REPLY_BYTES)
                .now_or_never()
                .unwrap()
                .unwrap();
            let fields = &case["request_fields"];
            let request = RangeV2Request {
                start: fields["start"].as_u64().unwrap(),
                count: fields["count"].as_u64().unwrap(),
                max_bytes: fields["max_bytes"].as_u64().unwrap(),
                flags: fields["flags"].as_u64().unwrap(),
            };
            let listed = vectors::listed_chunks(case);
            match check_range_v2(&request, reply).unwrap_or_else(|e| panic!("{name}: {e}")) {
                Ok(checked) => {
                    let end_chunk = listed.iter().find(|c| c.code == frame::CODE_END).unwrap();
                    let end = checked.end.unwrap();
                    assert_eq!(end.encode().to_vec(), end_chunk.payload, "{name}");
                    let listed_end = &case["response_chunks"].as_array().unwrap().last().unwrap()["end"];
                    assert_eq!(end.next, listed_end["next"].as_u64().unwrap(), "{name}");
                    assert_eq!(end.served_bytes, listed_end["served_bytes"].as_u64().unwrap(), "{name}");
                    assert_eq!(u64::from(end.reason.as_u8()), listed_end["reason"].as_u64().unwrap(), "{name}");
                    assert_eq!(checked.payloads.len(), listed.len() - 1, "{name}");
                }
                Err(refused) => {
                    assert_eq!(refused.code, frame::CODE_INVALID_REQUEST, "{name}");
                    assert_eq!(refused.message, listed[0].as_error().message, "{name}");
                    assert_eq!(refused.message, "syncwire: range count 0 outside 1..1024");
                }
            }
        }
    }

    #[test]
    fn requests_are_validated_with_gov5s_messages() {
        let ok = RangeV2Request { start: 5, count: 3, max_bytes: 0, flags: 1 };
        assert_eq!(RangeV2Request::decode(&ok.encode()), Ok(ok));
        assert_eq!(RangeV2Request::decode(&[0; 31]).unwrap_err(), "syncwire: wrong message length");
        let mut bad = ok;
        bad.count = 1025;
        assert_eq!(RangeV2Request::decode(&bad.encode()).unwrap_err(), "syncwire: range count 1025 outside 1..1024");
        bad = ok;
        bad.flags = 3;
        assert_eq!(RangeV2Request::decode(&bad.encode()).unwrap_err(), "syncwire: reserved range flag bits 0x2 set");
        bad = ok;
        bad.start = u64::MAX;
        assert_eq!(RangeV2Request::decode(&bad.encode()).unwrap_err(), "syncwire: range overflows u64");
        assert_eq!(RangeV2Request::bodies(1, 1).budget(), 64 << 20);
        assert_eq!(RangeV2Request { max_bytes: 1 << 40, ..ok }.budget(), 128 << 20);
    }

    fn served_and_end(reply: &RangeV2Reply) -> (usize, RangeEnd) {
        match reply {
            RangeV2Reply::Served { payloads, end } => (payloads.len(), end.unwrap()),
            RangeV2Reply::Refused(err) => panic!("refused: {err}"),
        }
    }

    #[test]
    fn a_hole_in_the_chain_ends_the_reply_not_available() {
        let mut chain = vector_chain();
        chain.bodies.remove(&9);
        let reply = serve(&chain, RangeV2Request::bodies(7, 4));
        let (served, end) = served_and_end(&reply);
        assert_eq!((served, end.next, end.reason), (2, 9, EndReason::NotAvailable));
        // A block that does not link to the one before is a hole too.
        let mut chain = vector_chain();
        let eight = chain.bodies[&8].clone();
        chain.bodies.insert(9, eight);
        let mut builder = RangeV2Builder::new(RangeV2Request::bodies(7, 3), 10);
        while let Some(n) = builder.wanted() {
            let payload = chain.bodies[&n].clone();
            let links = item_links(&payload, false).unwrap();
            if !builder.offer(Some(RangeItem { payload, hash: links.hash, parent: links.parent })) {
                break;
            }
        }
        let (payloads, end) = builder.finish();
        assert_eq!((payloads.len(), end.reason), (2, EndReason::NotAvailable));
    }

    #[test]
    fn a_server_stop_is_its_reason_and_complete_wins_when_all_was_served() {
        let mut builder = RangeV2Builder::new(RangeV2Request::bodies(7, 1), 10);
        builder.stop(EndReason::RateLimited);
        assert_eq!(builder.wanted(), None);
        let (payloads, end) = builder.finish();
        assert!(payloads.is_empty());
        assert_eq!(end.reason, EndReason::RateLimited);
        end.check(&RangeV2Request::bodies(7, 1), 0, 0).unwrap();
    }

    #[test]
    fn an_end_that_contradicts_the_chunks_is_a_fault() {
        let chain = vector_chain();
        let request = RangeV2Request::bodies(7, 3);
        let RangeV2Reply::Served { payloads, end } = serve(&chain, request) else { panic!() };
        let end = end.unwrap();
        let tampered = [
            RangeEnd { next: 9, ..end },
            RangeEnd { served_bytes: end.served_bytes + 1, ..end },
            RangeEnd { reason: EndReason::ByteBudget, ..end },
        ];
        for bad in tampered {
            let reply = RangeV2Reply::Served { payloads: payloads.clone(), end: Some(bad) };
            assert!(check_range_v2(&request, reply).is_err(), "{bad:?}");
        }
        // Out of order, or more than asked for.
        let mut swapped = payloads.clone();
        swapped.swap(0, 1);
        assert!(check_range_v2(&request, RangeV2Reply::Served { payloads: swapped, end: None }).is_err());
        let short = RangeV2Request::bodies(7, 2);
        assert!(check_range_v2(&short, RangeV2Reply::Served { payloads: payloads.clone(), end: None }).is_err());
        // No END at all is a soft fault: the chunks are kept.
        let checked = check_range_v2(&request, RangeV2Reply::Served { payloads, end: None }).unwrap().unwrap();
        assert_eq!(checked.payloads.len(), 3);
        assert!(checked.end.is_none());
    }

    #[test]
    fn an_error_after_a_prefix_keeps_the_prefix_and_before_it_is_the_answer() {
        let chain = vector_chain();
        let reply = serve(&chain, RangeV2Request::bodies(7, 2));
        let RangeV2Reply::Served { payloads, .. } = &reply else { panic!() };
        let mut wire = Vec::new();
        frame::append_chunk(&mut wire, frame::CODE_SUCCESS, Some(&chain.context), &payloads[0]);
        wire.extend(frame::error_chunk(frame::CODE_SERVER_ERROR, "boom"));
        let read = read_range_v2_reply(&mut &wire[..], 64 << 20, MAX_RANGE_V2_REPLY_BYTES).now_or_never().unwrap().unwrap();
        assert_eq!(read, RangeV2Reply::Served { payloads: vec![payloads[0].clone()], end: None });
        let wire = frame::rate_limited_chunk(1000);
        let read = read_range_v2_reply(&mut &wire[..], 64 << 20, MAX_RANGE_V2_REPLY_BYTES).now_or_never().unwrap().unwrap();
        let RangeV2Reply::Refused(err) = read else { panic!() };
        assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(1)));
    }

    #[test]
    fn the_codec_round_trips_a_request_a_refusal_and_a_reply() {
        use libp2p::request_response::Codec as _;
        let chain = vector_chain();
        let mut codec = RangeV2Codec::new(chain.context, None);
        let protocol = bodies_by_range_v2_protocol();
        let request = RangeV2Request::bodies(8, 3);
        let mut wire = Vec::new();
        futures::executor::block_on(codec.write_request(&protocol, &mut futures::io::Cursor::new(&mut wire), Ok(request))).unwrap();
        let read = futures::executor::block_on(codec.read_request(&protocol, &mut &wire[..])).unwrap();
        assert_eq!(read, Ok(request));
        // A request longer than 32 bytes is refused with gov5's message.
        let long = frame::framed(&[0u8; 40]);
        let read = futures::executor::block_on(codec.read_request(&protocol, &mut &long[..])).unwrap();
        assert_eq!(read, Err("syncwire: declared length above the cap: 40 > 32".to_owned()));

        for reply in [serve(&chain, request), RangeV2Reply::Refused(CodeError { code: 1, message: "no".into() })] {
            let mut wire = Vec::new();
            futures::executor::block_on(codec.write_response(&protocol, &mut futures::io::Cursor::new(&mut wire), reply.clone()))
                .unwrap();
            assert_eq!(wire, encode_range_v2_reply(&reply, &chain.context));
            let read = futures::executor::block_on(codec.read_response(&protocol, &mut &wire[..])).unwrap();
            assert_eq!(read, reply);
        }
    }
}
