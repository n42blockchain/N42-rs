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
    frame_payload, framed_len_limit, unframe_payload_limit, Status, RESPONSE_CODE_SUCCESS,
    STATUS_PROTOCOL,
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
async fn read_framed_limit<T>(io: &mut T, max_wire: usize, max_decoded: u64) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::with_capacity(128);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = framed_len_limit(&buf, max_decoded).map_err(to_io)? {
            return unframe_payload_limit(&buf[..end], max_decoded).map_err(to_io);
        }
        if buf.len() > max_wire {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame exceeded {max_wire} bytes without completing"),
            ));
        }
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream ended mid frame",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
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
