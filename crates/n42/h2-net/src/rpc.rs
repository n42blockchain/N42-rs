// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `/rpc/status/1/ssz_snappy` request-response codec.
//!
//! Answering this is what keeps a connection to a gov5 node alive. gov5 sends a
//! status request on connect and drops peers that cannot answer, so without this
//! an observer is disconnected a few seconds in, before any gossip arrives.
//!
//! Both directions are implemented: gov5 initiates, but a node that only responds
//! never learns the peer's head, and `maintainPeerStatuses` on the gov5 side
//! re-requests periodically.

use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use libp2p::StreamProtocol;

use crate::status::{
    decode_h256, encode_h256, frame_payload, framed_len_limit, unframe_payload_limit, Status,
    RESPONSE_CODE_SUCCESS, STATUS_PROTOCOL,
};
use alloy_primitives::B256;

/// The negotiated protocol.
pub fn status_protocol() -> StreamProtocol {
    StreamProtocol::new(STATUS_PROTOCOL)
}

/// Largest framed status message accepted off the wire.
///
/// A status is 72 bytes uncompressed; this bound only has to stop a peer from
/// making us buffer indefinitely while we look for a frame boundary.
const MAX_FRAMED_BYTES: usize = 64 * 1024;

/// Reads one varint+snappy-framed payload.
///
/// Reads incrementally and asks [`framed_len`] after each chunk where the
/// message ends, rather than reading to EOF. Reading to EOF would depend on the
/// peer half-closing the stream, which gov5 does not promise, and would break
/// outright if it ever pipelined two messages down one stream.
async fn read_framed<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    read_framed_limit(io, MAX_FRAMED_BYTES, crate::status::MAX_CHUNK_SIZE).await
}

/// Reads one `varint(len) ‖ framed-snappy` chunk, bounded both on the wire and
/// once decoded.
///
/// Reads exactly the chunk and not a byte more: a range reply is several of
/// these back to back on one stream, and a reader that buffered ahead would
/// swallow the start of the next.
async fn read_framed_limit<T>(io: &mut T, max_wire: usize, max_decoded: u64) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let declared = read_varint(io).await?;
    if declared > max_decoded {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            crate::status::StatusError::TooLong { got: declared }.to_string(),
        ));
    }
    read_framed_body(io, declared, max_wire).await
}

/// The varint that opens a chunk: the uncompressed length to come.
async fn read_varint<T>(io: &mut T) -> io::Result<u64>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::with_capacity(10);
    loop {
        let mut byte = [0u8; 1];
        io.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if byte[0] < 0x80 {
            break;
        }
        if buf.len() >= 10 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "length varint too long"));
        }
    }
    crate::status::decode_varint(&buf).map(|(value, _)| value).map_err(to_io)
}

/// The framed-snappy body of a chunk whose varint has been read and whose
/// declared length has been accepted by the caller: whole snappy frames — a
/// 4-byte header naming the body length — until `declared` bytes are
/// accounted for, then decoded.
async fn read_framed_body<T>(io: &mut T, declared: u64, max_wire: usize) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = crate::status::encode_varint(declared);
    loop {
        if let Some(end) = framed_len_limit(&buf, declared).map_err(to_io)? {
            if end != buf.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "frame ended mid snappy chunk"));
            }
            return unframe_payload_limit(&buf, declared).map_err(to_io);
        }
        let mut header = [0u8; 4];
        io.read_exact(&mut header).await?;
        let body_len = u32::from_le_bytes([header[1], header[2], header[3], 0]) as usize;
        if buf.len() + 4 + body_len > max_wire {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame exceeded {max_wire} bytes without completing"),
            ));
        }
        buf.extend_from_slice(&header);
        let start = buf.len();
        buf.resize(start + body_len, 0);
        io.read_exact(&mut buf[start..]).await?;
    }
}

fn to_io(e: crate::status::StatusError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// Codec for gov5's status handshake.
#[derive(Debug, Clone, Default)]
pub struct StatusCodec;

#[async_trait]
impl request_response::Codec for StatusCodec {
    type Protocol = StreamProtocol;
    type Request = Status;
    type Response = Status;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let ssz = read_framed(io).await?;
        Status::from_ssz(&ssz).map_err(to_io)
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        // A response is prefixed with a result byte; anything non-zero means the
        // rest of the stream is an error string, not a status.
        let mut code = [0u8; 1];
        io.read_exact(&mut code).await?;
        if code[0] != RESPONSE_CODE_SUCCESS {
            return Err(io::Error::other(format!(
                "peer returned response code {}",
                code[0]
            )));
        }
        let ssz = read_framed(io).await?;
        Status::from_ssz(&ssz).map_err(to_io)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let framed = frame_payload(&req.to_ssz()).map_err(to_io)?;
        io.write_all(&framed).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let mut out = vec![RESPONSE_CODE_SUCCESS];
        out.extend_from_slice(&frame_payload(&res.to_ssz()).map_err(to_io)?);
        io.write_all(&out).await?;
        io.close().await
    }
}

/// The request-response behaviour for the status protocol.
pub type StatusBehaviour = request_response::Behaviour<StatusCodec>;

/// Builds the status behaviour, supporting both inbound and outbound.
pub fn status_behaviour() -> StatusBehaviour {
    request_response::Behaviour::with_codec(
        StatusCodec,
        [(status_protocol(), request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use futures::io::Cursor;
    use request_response::Codec as _;

    fn sample() -> Status {
        Status::new(
            "3bec3e862313f3f4f21a3f222fd90921cc01d246edcf19c52fd5c4e43f5c7a99"
                .parse()
                .unwrap(),
            42,
        )
    }

    #[tokio::test]
    async fn request_roundtrips_through_the_codec() {
        let mut codec = StatusCodec;
        let mut out = Vec::new();
        codec
            .write_request(&status_protocol(), &mut out, sample())
            .await
            .unwrap();

        let mut cursor = Cursor::new(out);
        let got = codec
            .read_request(&status_protocol(), &mut cursor)
            .await
            .unwrap();
        assert_eq!(got, sample());
    }

    #[tokio::test]
    async fn response_roundtrips_and_carries_the_success_byte() {
        let mut codec = StatusCodec;
        let mut out = Vec::new();
        codec
            .write_response(&status_protocol(), &mut out, sample())
            .await
            .unwrap();
        assert_eq!(out[0], RESPONSE_CODE_SUCCESS);

        let mut cursor = Cursor::new(out);
        let got = codec
            .read_response(&status_protocol(), &mut cursor)
            .await
            .unwrap();
        assert_eq!(got, sample());
    }

    /// The bytes gov5 actually puts on the wire must parse — this reads the
    /// pinned fixture rather than something this crate produced.
    #[tokio::test]
    async fn reads_gov5_generated_wire_bytes() {
        #[derive(serde::Deserialize)]
        struct V {
            genesis_hash: String,
            height: u64,
            request_hex: String,
            response_hex: String,
        }
        #[derive(serde::Deserialize)]
        struct Vs {
            vectors: Vec<V>,
        }
        let vs: Vs =
            serde_json::from_str(include_str!("../testdata/gov5_status_v1.json")).unwrap();

        let mut codec = StatusCodec;
        for v in vs.vectors {
            let want = Status::new(v.genesis_hash.parse::<B256>().unwrap(), v.height);

            let mut req = Cursor::new(hex::decode(&v.request_hex).unwrap());
            assert_eq!(
                codec.read_request(&status_protocol(), &mut req).await.unwrap(),
                want
            );

            let mut res = Cursor::new(hex::decode(&v.response_hex).unwrap());
            assert_eq!(
                codec.read_response(&status_protocol(), &mut res).await.unwrap(),
                want
            );
        }
    }

    #[tokio::test]
    async fn a_non_success_response_code_is_an_error_not_a_bad_parse() {
        let mut codec = StatusCodec;
        let mut bytes = vec![2u8]; // responseCodeInvalidRequest
        bytes.extend_from_slice(&frame_payload(&sample().to_ssz()).unwrap());
        let mut cursor = Cursor::new(bytes);
        let err = codec
            .read_response(&status_protocol(), &mut cursor)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("response code 2"), "{err}");
    }

    #[tokio::test]
    async fn a_truncated_frame_reports_eof_rather_than_hanging() {
        let mut codec = StatusCodec;
        let full = frame_payload(&sample().to_ssz()).unwrap();
        let mut cursor = Cursor::new(full[..full.len() / 2].to_vec());
        let err = codec
            .read_request(&status_protocol(), &mut cursor)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// Two messages back to back: the reader must consume exactly the first.
    #[tokio::test]
    async fn does_not_swallow_a_following_message() {
        let mut codec = StatusCodec;
        let first = sample();
        let second = Status::new(B256::repeat_byte(0x11), 7);
        let mut bytes = frame_payload(&first.to_ssz()).unwrap();
        bytes.extend_from_slice(&frame_payload(&second.to_ssz()).unwrap());

        let mut cursor = Cursor::new(bytes);
        assert_eq!(
            codec.read_request(&status_protocol(), &mut cursor).await.unwrap(),
            first
        );
    }
}

/// gov5's fetch-on-miss protocol (`internal/sync/rpc_block_by_hash.go`): a
/// bare 32-byte hash on the stream, answered with a status byte, the 4-byte
/// fork digest, and the block's RLP as one `varint ‖ framed-snappy` chunk —
/// or a non-zero status byte and a framed error message. gov5 asks every
/// connected peer for a block it hears of but does not hold: the parent of a
/// gossiped block, or the block a proposal names; without an answer a Go
/// member that fell behind by one sibling stays behind.
pub const BLOCK_BY_HASH_PROTOCOL: &str = "/rpc/block_by_hash/1/ssz_snappy";

/// The protocol as libp2p names it.
pub fn block_by_hash_protocol() -> StreamProtocol {
    StreamProtocol::new(BLOCK_BY_HASH_PROTOCOL)
}

/// gov5 `responseCodeInvalidRequest`.
pub const RESPONSE_CODE_INVALID_REQUEST: u8 = 1;
/// gov5 `responseCodeServerError`, which is what it answers for a block it
/// does not have.
pub const RESPONSE_CODE_SERVER_ERROR: u8 = 2;
/// gov5 `encoder.MaxBlockChunkSize`.
pub const MAX_BLOCK_CHUNK: u64 = 64 << 20;
/// Bound on the compressed chunk as it arrives.
const MAX_BLOCK_WIRE_BYTES: usize = (MAX_BLOCK_CHUNK as usize) + (MAX_BLOCK_CHUNK as usize) / 6 + 32;

/// A served block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockChunk {
    /// The chain's fork digest, as gov5 writes before the block.
    pub fork_digest: [u8; 4],
    /// gov5's block RLP: `[header, txs, verifiers, rewards]`.
    pub rlp: Vec<u8>,
}

/// What a `block_by_hash` request comes back with: the block, or the peer's
/// error message.
pub type BlockReply = Result<BlockChunk, String>;

/// The codec.
#[derive(Debug, Clone, Default)]
pub struct BlockByHashCodec;

#[async_trait]
impl request_response::Codec for BlockByHashCodec {
    type Protocol = StreamProtocol;
    type Request = B256;
    type Response = BlockReply;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut hash = [0u8; 32];
        io.read_exact(&mut hash).await?;
        Ok(B256::from(hash))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut code = [0u8; 1];
        io.read_exact(&mut code).await?;
        if code[0] != RESPONSE_CODE_SUCCESS {
            let message = read_framed(io).await.unwrap_or_default();
            return Ok(Err(format!(
                "code {}: {}",
                code[0],
                String::from_utf8_lossy(&message)
            )));
        }
        let mut fork_digest = [0u8; 4];
        io.read_exact(&mut fork_digest).await?;
        let rlp = read_framed_limit(io, MAX_BLOCK_WIRE_BYTES, MAX_BLOCK_CHUNK).await?;
        Ok(Ok(BlockChunk { fork_digest, rlp }))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        hash: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(hash.as_slice()).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        reply: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let out = encode_block_reply(&reply).map_err(to_io)?;
        io.write_all(&out).await?;
        io.close().await
    }
}

/// The bytes gov5's `writeBlockChunk` / `writeErrorResponseToStream` put on
/// the stream for a reply.
pub fn encode_block_reply(reply: &BlockReply) -> Result<Vec<u8>, crate::status::StatusError> {
    match reply {
        Ok(chunk) => {
            let mut out = Vec::with_capacity(5 + chunk.rlp.len());
            out.push(RESPONSE_CODE_SUCCESS);
            out.extend_from_slice(&chunk.fork_digest);
            out.extend_from_slice(&frame_payload(&chunk.rlp)?);
            Ok(out)
        }
        Err(message) => {
            let mut out = vec![RESPONSE_CODE_SERVER_ERROR];
            out.extend_from_slice(&frame_payload(message.as_bytes())?);
            Ok(out)
        }
    }
}

/// The request-response behaviour for the protocol.
pub type BlockByHashBehaviour = request_response::Behaviour<BlockByHashCodec>;

/// Serving and requesting.
pub fn block_by_hash_behaviour() -> BlockByHashBehaviour {
    request_response::Behaviour::with_codec(
        BlockByHashCodec,
        [(block_by_hash_protocol(), request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

#[cfg(test)]
mod block_by_hash_tests {
    use super::*;
    use crate::status::unframe_payload;
    use futures::executor::block_on;
    use libp2p::request_response::Codec as _;

    #[test]
    fn a_served_block_is_status_digest_and_one_framed_chunk() {
        let chunk = BlockChunk {
            fork_digest: [0x11, 0x24, 0x89, 0xf0],
            rlp: vec![0xc4, 0xc0, 0xc0, 0xc0, 0xc0],
        };
        let bytes = encode_block_reply(&Ok(chunk.clone())).unwrap();
        assert_eq!(bytes[0], RESPONSE_CODE_SUCCESS);
        assert_eq!(&bytes[1..5], &chunk.fork_digest);
        assert_eq!(unframe_payload(&bytes[5..]).unwrap(), chunk.rlp);

        // And it reads back through the codec, as the Go requester reads it.
        let mut codec = BlockByHashCodec;
        let proto = block_by_hash_protocol();
        let reply = block_on(codec.read_response(&proto, &mut futures::io::Cursor::new(bytes))).unwrap();
        assert_eq!(reply, Ok(chunk));
    }

    #[test]
    fn a_missing_block_is_gov5s_server_error_with_a_framed_message() {
        let bytes = encode_block_reply(&Err("block not found".into())).unwrap();
        assert_eq!(bytes[0], RESPONSE_CODE_SERVER_ERROR);
        assert_eq!(unframe_payload(&bytes[1..]).unwrap(), b"block not found");
        let mut codec = BlockByHashCodec;
        let proto = block_by_hash_protocol();
        let reply = block_on(codec.read_response(&proto, &mut futures::io::Cursor::new(bytes))).unwrap();
        assert_eq!(reply, Err("code 2: block not found".into()));
    }

    #[test]
    fn the_request_is_the_bare_hash() {
        let mut codec = BlockByHashCodec;
        let proto = block_by_hash_protocol();
        let hash = B256::repeat_byte(0xAB);
        let mut wire = Vec::new();
        block_on(codec.write_request(&proto, &mut wire, hash)).unwrap();
        assert_eq!(wire, hash.as_slice());
        let back = block_on(codec.read_request(&proto, &mut futures::io::Cursor::new(wire))).unwrap();
        assert_eq!(back, hash);
    }
}

/// gov5's range sync (`internal/sync/rpc_blocks_by_range.go`), which is how
/// a member that starts behind catches up: `BodiesByRangeRequest {start,
/// count, step}` as SSZ in one framed chunk, answered with the blocks in
/// order, each as a `block_by_hash`-style chunk, the stream closing after the
/// last. Only `bodies_by_range` is registered on the Go side; there is no
/// headers-by-range handler to match.
pub const BODIES_BY_RANGE_PROTOCOL: &str = "/rpc/bodies_by_range/1/ssz_snappy";

/// The protocol as libp2p names it.
pub fn bodies_by_range_protocol() -> StreamProtocol {
    StreamProtocol::new(BODIES_BY_RANGE_PROTOCOL)
}

/// gov5's `maxRequestBlocks`: the most blocks one range request may name.
pub const MAX_RANGE_BLOCKS: u64 = 1024;

/// The most decoded bytes one range reply may carry, across all its blocks.
///
/// The per-block cap ([`MAX_BLOCK_CHUNK`], 64 MiB) times the block cap
/// ([`MAX_RANGE_BLOCKS`]) is 64 GiB — a bound in name only. A reply is held
/// whole until the stream closes (libp2p's request-response hands back one
/// value), so what a peer can make this node buffer is what this constant
/// says. gov5 has no such budget to match, and a gov5 server serves the
/// whole range whatever its blocks weigh; 256 MiB is over a thousand blocks
/// of a quarter megabyte each, well past what the devnet's blocks run. A
/// reply that would cross the budget is not refused — the peer broke no
/// rule — it ends at the last block that fits, and the requester asks for
/// the rest from where the reply ended, as it does for any short reply.
/// This node's own range server stops at the same budget
/// (`n42_h2_node`'s `serve_range`), so between two of these nodes the cut
/// is made before the bytes are sent.
pub const MAX_RANGE_BYTES: u64 = 256 << 20;

// The budget always fits the largest single block, so a reply is never
// empty for want of room.
const _: () = assert!(MAX_RANGE_BYTES >= MAX_BLOCK_CHUNK);

/// A range of blocks by number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeRequest {
    /// First block number.
    pub start: u64,
    /// How many.
    pub count: u64,
    /// Stride; gov5 serves every request as stride 1.
    pub step: u64,
}

/// SSZ size of the request: offset, count, step, then the 32-byte start.
pub const RANGE_REQUEST_SSZ_LEN: usize = 4 + 8 + 8 + 32;

impl RangeRequest {
    /// gov5's SSZ: a container of `{StartBlockNumber: H256, Count: u64, Step:
    /// u64}` where the H256 is variable-size (an offset in the fixed part),
    /// and encoded as gov5 encodes a number in an H256 — four little-endian
    /// words of the big-endian value.
    pub fn to_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RANGE_REQUEST_SSZ_LEN);
        out.extend_from_slice(&20u32.to_le_bytes());
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&self.step.to_le_bytes());
        let start = B256::from(alloy_primitives::U256::from(self.start));
        out.extend_from_slice(&encode_h256(&start));
        out
    }

    /// The inverse.
    pub fn from_ssz(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != RANGE_REQUEST_SSZ_LEN {
            return Err(format!("range request is {} bytes, want {RANGE_REQUEST_SSZ_LEN}", bytes.len()));
        }
        let offset = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
        if offset != 20 {
            return Err(format!("range request start offset {offset}, want 20"));
        }
        let count = u64::from_le_bytes(bytes[4..12].try_into().expect("8 bytes"));
        let step = u64::from_le_bytes(bytes[12..20].try_into().expect("8 bytes"));
        let start = decode_h256(&bytes[20..52]);
        if start.as_slice()[..24].iter().any(|b| *b != 0) {
            return Err("range request start does not fit a block number".into());
        }
        let start = u64::from_be_bytes(start.as_slice()[24..32].try_into().expect("8 bytes"));
        Ok(Self { start, count, step })
    }
}

/// What a range request comes back with: the blocks served, in order, or the
/// peer's error.
pub type RangeReply = Result<Vec<BlockChunk>, String>;

/// The codec.
#[derive(Debug, Clone, Default)]
pub struct BodiesByRangeCodec;

#[async_trait]
impl request_response::Codec for BodiesByRangeCodec {
    type Protocol = StreamProtocol;
    type Request = RangeRequest;
    type Response = RangeReply;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let ssz = read_framed(io).await?;
        RangeRequest::from_ssz(&ssz).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_range_reply(io, MAX_RANGE_BLOCKS, MAX_RANGE_BYTES).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let framed = frame_payload(&request.to_ssz()).map_err(to_io)?;
        io.write_all(&framed).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        reply: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match reply {
            Ok(chunks) => {
                for chunk in chunks {
                    io.write_all(&encode_block_reply(&Ok(chunk)).map_err(to_io)?).await?;
                }
            }
            Err(message) => {
                io.write_all(&encode_block_reply(&Err(message)).map_err(to_io)?).await?;
            }
        }
        io.close().await
    }
}

/// Reads a range reply: block chunks until the stream closes, or a refusal.
///
/// Bounded three ways before anything is allocated for a chunk: the block
/// count (`max_blocks` — the reply is refused at the first block past it,
/// which is not read), the per-block declared length ([`MAX_BLOCK_CHUNK`]),
/// and the running total of declared lengths (`max_bytes`, a budget for the
/// whole reply). All three read the varint a chunk opens with, so a peer
/// declaring past a bound costs one varint, not a buffer. The first two are
/// protocol violations and fail the reply; the budget is this node's own
/// limit, so a reply that would cross it is returned as the blocks read so
/// far — a short reply, which the catch-up continues from — and the stream
/// is left standing at the varint of the block that did not fit. Only when
/// not even the first block fits is the reply an error.
async fn read_range_reply<T>(io: &mut T, max_blocks: u64, max_bytes: u64) -> io::Result<RangeReply>
where
    T: AsyncRead + Unpin + Send,
{
    let mut chunks = Vec::new();
    let mut total = 0u64;
    loop {
        let mut code = [0u8; 1];
        if io.read(&mut code).await? == 0 {
            // The stream closing is how gov5 ends a range.
            return Ok(Ok(chunks));
        }
        if code[0] != RESPONSE_CODE_SUCCESS {
            let message = read_framed(io).await.unwrap_or_default();
            return Ok(Err(format!("code {}: {}", code[0], String::from_utf8_lossy(&message))));
        }
        if chunks.len() as u64 >= max_blocks {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "peer served more blocks than a range allows"));
        }
        let mut fork_digest = [0u8; 4];
        io.read_exact(&mut fork_digest).await?;
        let declared = read_varint(io).await?;
        if declared > MAX_BLOCK_CHUNK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                crate::status::StatusError::TooLong { got: declared }.to_string(),
            ));
        }
        total = total.saturating_add(declared);
        if total > max_bytes {
            if chunks.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("range reply's first block of {declared} bytes is past the {max_bytes} byte budget"),
                ));
            }
            // The blocks before this one are the reply; the stream is dropped
            // with this block's body unread.
            return Ok(Ok(chunks));
        }
        let rlp = read_framed_body(io, declared, MAX_BLOCK_WIRE_BYTES).await?;
        chunks.push(BlockChunk { fork_digest, rlp });
    }
}

/// The request-response behaviour for the protocol.
pub type BodiesByRangeBehaviour = request_response::Behaviour<BodiesByRangeCodec>;

/// Serving and requesting.
pub fn bodies_by_range_behaviour() -> BodiesByRangeBehaviour {
    request_response::Behaviour::with_codec(
        BodiesByRangeCodec,
        [(bodies_by_range_protocol(), request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

#[cfg(test)]
mod bodies_by_range_tests {
    use super::*;
    use futures::executor::block_on;
    use libp2p::request_response::Codec as _;

    #[test]
    fn the_request_is_gov5s_ssz_container() {
        let request = RangeRequest { start: 7, count: 64, step: 1 };
        let ssz = request.to_ssz();
        assert_eq!(ssz.len(), RANGE_REQUEST_SSZ_LEN);
        assert_eq!(&ssz[0..4], &20u32.to_le_bytes());
        assert_eq!(&ssz[4..12], &64u64.to_le_bytes());
        assert_eq!(&ssz[12..20], &1u64.to_le_bytes());
        // A number in an H256: the low word carries it, little-endian, in
        // the last of the four words.
        assert_eq!(&ssz[20..44], &[0u8; 24]);
        assert_eq!(&ssz[44..52], &7u64.to_le_bytes());
        assert_eq!(RangeRequest::from_ssz(&ssz).unwrap(), request);
    }

    #[test]
    fn a_range_reply_is_chunks_until_the_stream_closes() {
        let chunks = vec![
            BlockChunk { fork_digest: [1, 2, 3, 4], rlp: vec![0xc4, 0xc0, 0xc0, 0xc0, 0xc0] },
            BlockChunk { fork_digest: [1, 2, 3, 4], rlp: vec![0xc4, 0xc0, 0xc0, 0xc0, 0xc1] },
        ];
        let mut codec = BodiesByRangeCodec;
        let proto = bodies_by_range_protocol();
        let mut wire = Vec::new();
        block_on(codec.write_response(&proto, &mut wire, Ok(chunks.clone()))).unwrap();
        let back = block_on(codec.read_response(&proto, &mut futures::io::Cursor::new(wire))).unwrap();
        assert_eq!(back, Ok(chunks));

        let mut empty = Vec::new();
        block_on(codec.write_response(&proto, &mut empty, Ok(vec![]))).unwrap();
        assert!(empty.is_empty());
        let none = block_on(codec.read_response(&proto, &mut futures::io::Cursor::new(empty))).unwrap();
        assert_eq!(none, Ok(vec![]));

        let mut refused = Vec::new();
        block_on(codec.write_response(&proto, &mut refused, Err("no".into()))).unwrap();
        let err = block_on(codec.read_response(&proto, &mut futures::io::Cursor::new(refused))).unwrap();
        assert_eq!(err, Err("code 2: no".into()));
    }

    #[test]
    fn the_request_round_trips_through_the_codec() {
        let mut codec = BodiesByRangeCodec;
        let proto = bodies_by_range_protocol();
        let request = RangeRequest { start: 100, count: 3, step: 1 };
        let mut wire = Vec::new();
        block_on(codec.write_request(&proto, &mut wire, request)).unwrap();
        let back = block_on(codec.read_request(&proto, &mut futures::io::Cursor::new(wire))).unwrap();
        assert_eq!(back, request);
    }

    fn reply_of(sizes: &[usize]) -> Vec<u8> {
        let mut wire = Vec::new();
        for (i, size) in sizes.iter().enumerate() {
            let chunk = BlockChunk { fork_digest: [1, 2, 3, 4], rlp: vec![i as u8; *size] };
            wire.extend_from_slice(&encode_block_reply(&Ok(chunk)).unwrap());
        }
        wire
    }

    #[test]
    fn a_reply_past_the_byte_budget_ends_at_the_last_block_that_fits() {
        let wire = reply_of(&[100, 100, 100]);
        // 300 bytes declared in all: fits a 300 budget whole.
        let ok = block_on(read_range_reply(&mut futures::io::Cursor::new(wire.clone()), 10, 300)).unwrap();
        assert_eq!(ok.unwrap().len(), 3);
        // Not a 299 one: the third block does not fit, so the reply is the
        // first two — a short reply, not an error — and the stream stands
        // at the third block's varint, its body unread.
        let mut cursor = futures::io::Cursor::new(wire.clone());
        let short = block_on(read_range_reply(&mut cursor, 10, 299)).unwrap().unwrap();
        assert_eq!(short.len(), 2);
        assert_eq!(short[1].rlp, vec![1u8; 100]);
        let two_blocks = reply_of(&[100, 100]).len();
        let varint = crate::status::encode_varint(100).len();
        assert_eq!(cursor.position() as usize, two_blocks + 1 + 4 + varint);
        // The budget is on declared, uncompressed bytes, so a peer cannot
        // slip under it by compressing well: 100 zero bytes frame to far
        // fewer on the wire, and still count as 100.
        assert!(wire.len() < 300, "wire is {} bytes", wire.len());
        let short = block_on(read_range_reply(&mut futures::io::Cursor::new(wire.clone()), 10, 150)).unwrap().unwrap();
        assert_eq!(short.len(), 1);
        // A budget the first block alone is past is the one case that is an
        // error: there is nothing to serve short of it.
        let err = block_on(read_range_reply(&mut futures::io::Cursor::new(wire), 10, 99)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("first block"), "{err}");
    }

    #[test]
    fn a_reply_with_too_many_blocks_is_refused_at_the_first_extra_one() {
        let wire = reply_of(&[5, 5, 5]);
        let ok = block_on(read_range_reply(&mut futures::io::Cursor::new(wire.clone()), 3, 1 << 20)).unwrap();
        assert_eq!(ok.unwrap().len(), 3);
        // With a cap of two, the third block's status byte is read and the
        // reply refused before its body is: the cursor stands at its digest.
        let mut cursor = futures::io::Cursor::new(wire.clone());
        let err = block_on(read_range_reply(&mut cursor, 2, 1 << 20)).unwrap_err();
        assert!(err.to_string().contains("more blocks"), "{err}");
        let two_blocks = reply_of(&[5, 5]).len();
        assert_eq!(cursor.position() as usize, two_blocks + 1);
    }

    #[test]
    fn a_block_declared_past_the_chunk_cap_is_refused_before_its_body() {
        let mut wire = vec![RESPONSE_CODE_SUCCESS, 1, 2, 3, 4];
        wire.extend_from_slice(&crate::status::encode_varint(MAX_BLOCK_CHUNK + 1));
        wire.extend_from_slice(&[0u8; 64]);
        let mut cursor = futures::io::Cursor::new(wire);
        let err = block_on(read_range_reply(&mut cursor, MAX_RANGE_BLOCKS, MAX_RANGE_BYTES)).unwrap_err();
        assert!(err.to_string().contains("exceeds max chunk size"), "{err}");
        // Only the status, digest and varint were consumed.
        assert_eq!(cursor.position(), 5 + crate::status::encode_varint(MAX_BLOCK_CHUNK + 1).len() as u64);
    }

    #[test]
    fn the_codec_applies_the_production_bounds() {
        // A thousand and twenty-five tiny blocks: past the block cap.
        let wire = reply_of(&vec![1; MAX_RANGE_BLOCKS as usize + 1]);
        let mut codec = BodiesByRangeCodec;
        let proto = bodies_by_range_protocol();
        let err = block_on(codec.read_response(&proto, &mut futures::io::Cursor::new(wire))).unwrap_err();
        assert!(err.to_string().contains("more blocks"), "{err}");
        assert_eq!(MAX_RANGE_BYTES, 256 * 1024 * 1024);
    }
}
