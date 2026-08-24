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
    frame_payload, framed_len, unframe_payload, Status, RESPONSE_CODE_SUCCESS, STATUS_PROTOCOL,
};

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
    let mut buf = Vec::with_capacity(128);
    let mut chunk = [0u8; 512];
    loop {
        if let Some(end) = framed_len(&buf).map_err(to_io)? {
            return unframe_payload(&buf[..end]).map_err(to_io);
        }
        if buf.len() > MAX_FRAMED_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("status frame exceeded {MAX_FRAMED_BYTES} bytes without completing"),
            ));
        }
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream ended mid status frame",
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
