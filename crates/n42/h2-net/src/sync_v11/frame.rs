// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The framing every v1.1 sync protocol shares (sync standard §1.2, §3,
//! §5.0), byte for byte with gov5's `internal/sync/syncwire/framing.go`.
//!
//! - A **request** is `uvarint(len) ‖ snappy-framed(payload)`; the requester
//!   half-closes its side.
//! - A **response chunk** is `code u8 ‖ [context 4] ‖ uvarint(len) ‖
//!   snappy-framed(payload)`. The 4 context bytes (the genesis hash's first
//!   four, the fork digest) appear only on the SUCCESS block and header
//!   chunks of `bodies_by_range/2`.
//! - An **error chunk** is `code ‖ uvarint(len) ‖ snappy-framed(utf8)`, no
//!   context bytes; the message is at most [`MAX_ERROR_MESSAGE`] bytes and is
//!   optional on the wire (the code is the answer). `0x04 RATE_LIMITED`
//!   carries the decimal `retry_after_ms`.
//! - The **END trailer** (`0x10`) closes the streamed replies of
//!   `bodies_by_range/2` and `qmdb_twigs/1`: a 17-byte payload whose layout is
//!   the protocol's, ending in an [`EndReason`].
//!
//! The snappy layer is the framing format (stream identifier, then
//! compressed `0x00` or uncompressed `0x01` chunks with a masked CRC-32C).
//! An empty payload is framed as nothing at all: gov5's buffered writer emits
//! no stream identifier when nothing was written, and its reader reads none
//! for a declared length of zero.
//!
//! Everything here is protocol-agnostic and free of libp2p; the protocol
//! modules next to it build on [`append_chunk`] / [`read_chunk`].

use std::io;
use std::time::Duration;

use futures::{AsyncRead, AsyncReadExt};

use crate::status::encode_varint;

/// SUCCESS: a data chunk.
pub const CODE_SUCCESS: u8 = 0x00;
/// INVALID_REQUEST: malformed, out of bounds, wrong length, reserved flag set.
pub const CODE_INVALID_REQUEST: u8 = 0x01;
/// SERVER_ERROR: internal failure.
pub const CODE_SERVER_ERROR: u8 = 0x02;
/// RESOURCE_UNAVAILABLE: pruned, pivot not servable, unknown hash.
pub const CODE_RESOURCE_UNAVAILABLE: u8 = 0x03;
/// RATE_LIMITED: the message is the decimal `retry_after_ms`.
pub const CODE_RATE_LIMITED: u8 = 0x04;
/// END: the terminal trailer of a streamed reply.
pub const CODE_END: u8 = 0x10;

/// The longest error message written or read (gov5's `MaxErrorMessage`).
pub const MAX_ERROR_MESSAGE: usize = 256;

/// The size of every END payload (`RangeEnd`, `TwigsEnd`).
pub const END_LEN: usize = 17;

/// The `retry_after_ms` a server over quota answers with (gov5's
/// `v11RetryAfterMs`).
pub const DEFAULT_RETRY_AFTER_MS: u64 = 1000;

/// The largest request payload any v1.1 protocol takes (§6.1: requests are
/// bounded by `MaxChunkSize`, 1 MiB).
pub const MAX_REQUEST_BYTES: u64 = 1 << 20;

/// Time to the first chunk of a reply (§6.2).
pub const FIRST_CHUNK_TIMEOUT: Duration = Duration::from_secs(10);

/// Whole-request time of a v2 range or twig stream (§6.2).
pub const STREAM_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Whole-request time of the single-chunk protocols (§6.2).
pub const SMALL_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The per-chunk deadline of §6.2, for readers and (against slowloris
/// readers) writers: `10 s + len / (1 MiB/s)`.
pub fn chunk_timeout(len: usize) -> Duration {
    FIRST_CHUNK_TIMEOUT + Duration::from_secs_f64(len as f64 / f64::from(1u32 << 20))
}

/// Why a streamed reply ended (§5.0), the last byte of its END payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EndReason {
    /// Everything asked for was served.
    Complete = 0,
    /// The next item would have pushed the reply past its byte budget.
    ByteBudget = 1,
    /// The server's count cap.
    CountCap = 2,
    /// The server's committed head was reached.
    CanonicalEnd = 3,
    /// The server does not hold the next item (pruned, a hole).
    NotAvailable = 4,
    /// The server stopped for its rate limit.
    RateLimited = 5,
    /// The server is shutting down.
    ShuttingDown = 6,
}

impl EndReason {
    /// The reason a byte names; `None` for an unknown one.
    pub const fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Complete,
            1 => Self::ByteBudget,
            2 => Self::CountCap,
            3 => Self::CanonicalEnd,
            4 => Self::NotAvailable,
            5 => Self::RateLimited,
            6 => Self::ShuttingDown,
            _ => return None,
        })
    }

    /// The byte on the wire.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether a reply may end with this reason having served nothing
    /// (§5.1: zero items only with reason 3, 4, 5 or 6).
    pub const fn allows_empty(self) -> bool {
        (self as u8) >= Self::CanonicalEnd as u8
    }
}

/// `payload` in the snappy framing format, as gov5's `snappy.NewBufferedWriter`
/// writes it. Empty for an empty payload.
pub fn snappy_frame(payload: &[u8]) -> Vec<u8> {
    use std::io::Write;
    if payload.is_empty() {
        return Vec::new();
    }
    let mut encoder = snap::write::FrameEncoder::new(Vec::with_capacity(payload.len() / 2 + 64));
    // Writing into a Vec cannot fail; neither can flushing into one.
    if encoder.write_all(payload).is_err() {
        return Vec::new();
    }
    encoder.into_inner().unwrap_or_default()
}

/// Appends `uvarint(len(payload)) ‖ snappy-framed(payload)` (gov5's
/// `AppendFramed`).
pub fn append_framed(dst: &mut Vec<u8>, payload: &[u8]) {
    dst.extend_from_slice(&encode_varint(payload.len() as u64));
    dst.extend_from_slice(&snappy_frame(payload));
}

/// `uvarint(len(payload)) ‖ snappy-framed(payload)`: a request on the wire.
pub fn framed(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() / 2 + 32);
    append_framed(&mut out, payload);
    out
}

/// Appends one response chunk: `code ‖ [context] ‖ framed(payload)`.
/// `context` is `Some` only for the block and header chunks of
/// `bodies_by_range/2`.
pub fn append_chunk(dst: &mut Vec<u8>, code: u8, context: Option<&[u8; 4]>, payload: &[u8]) {
    dst.push(code);
    if let Some(context) = context {
        dst.extend_from_slice(context);
    }
    append_framed(dst, payload);
}

/// One response chunk as bytes.
pub fn chunk(code: u8, context: Option<&[u8; 4]>, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() / 2 + 32);
    append_chunk(&mut out, code, context, payload);
    out
}

/// Appends an error chunk `code ‖ framed(utf8 message)`, the message cut to
/// [`MAX_ERROR_MESSAGE`] bytes as gov5 cuts it.
pub fn append_error(dst: &mut Vec<u8>, code: u8, message: &str) {
    let bytes = message.as_bytes();
    append_chunk(dst, code, None, &bytes[..bytes.len().min(MAX_ERROR_MESSAGE)]);
}

/// An error chunk as bytes.
pub fn error_chunk(code: u8, message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    append_error(&mut out, code, message);
    out
}

/// The `0x04 RATE_LIMITED` chunk: `0x04 ‖ framed(decimal retry_after_ms)`.
pub fn rate_limited_chunk(retry_after_ms: u64) -> Vec<u8> {
    error_chunk(CODE_RATE_LIMITED, &retry_after_ms.to_string())
}

/// One response chunk as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// The result code (byte 0).
    pub code: u8,
    /// The context bytes, when the reader expected them on a SUCCESS chunk.
    pub context: Option<[u8; 4]>,
    /// The decoded payload; the message of an error chunk (empty when the
    /// server sent none or it did not decode).
    pub payload: Vec<u8>,
}

impl Chunk {
    /// A SUCCESS chunk.
    pub const fn is_success(&self) -> bool {
        self.code == CODE_SUCCESS
    }

    /// The END trailer.
    pub const fn is_end(&self) -> bool {
        self.code == CODE_END
    }

    /// The chunk as an error, for a code other than SUCCESS and END.
    pub fn as_error(&self) -> CodeError {
        CodeError { code: self.code, message: String::from_utf8_lossy(&self.payload).into_owned() }
    }
}

/// A non-SUCCESS, non-END chunk a server answered with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("remote returned code {code:#04x}: {message}")]
pub struct CodeError {
    /// The result code.
    pub code: u8,
    /// Its message (possibly empty).
    pub message: String,
}

impl CodeError {
    /// How long to back off, for a `0x04 RATE_LIMITED` with a decimal
    /// message; `None` otherwise. Clients back off by it with no score
    /// (§6.3).
    pub fn retry_after(&self) -> Option<Duration> {
        (self.code == CODE_RATE_LIMITED)
            .then(|| self.message.trim().parse::<u64>().ok())
            .flatten()
            .map(Duration::from_millis)
    }
}

/// The longest wire form a framed payload of `declared` bytes may take: the
/// snappy worst case (`32 + n + n/6`) plus the stream identifier and slack,
/// as gov5's reader bounds it (`MaxEncodedLen(n) + 64`).
fn max_wire_len(declared: u64) -> u64 {
    32 + declared + declared / 6 + 64
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Reads a uvarint a byte at a time. `Ok(None)` when the stream ends before
/// its first byte.
async fn read_uvarint<T>(io: &mut T) -> io::Result<Option<u64>>
where
    T: AsyncRead + Unpin,
{
    let mut value = 0u64;
    for i in 0..10u32 {
        let mut byte = [0u8; 1];
        if io.read(&mut byte).await? == 0 {
            if i == 0 {
                return Ok(None);
            }
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if byte[0] < 0x80 {
            if i == 9 && byte[0] > 1 {
                return Err(invalid("uvarint overflow"));
            }
            return Ok(Some(value | (u64::from(byte[0]) << (7 * i))));
        }
        value |= u64::from(byte[0] & 0x7f) << (7 * i);
    }
    Err(invalid("uvarint overflow"))
}

/// Reads `uvarint(len) ‖ snappy-framed(payload)` and refuses a declared
/// length above `max` before allocating (gov5's `ReadFramed`).
///
/// Reads exactly the frame and not a byte more: a streamed reply is several
/// chunks back to back, and a reader that buffered ahead would swallow the
/// start of the next. An end of stream anywhere is `UnexpectedEof`.
pub async fn read_framed<T>(io: &mut T, max: u64) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin,
{
    let declared = read_uvarint(io).await?.ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    read_framed_body(io, declared, max).await
}

async fn read_framed_body<T>(io: &mut T, declared: u64, max: u64) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin,
{
    if declared > max {
        return Err(invalid(format!("declared length above the cap: {declared} > {max}")));
    }
    if declared == 0 {
        return Ok(Vec::new());
    }
    let max_wire = max_wire_len(declared);
    let mut frames: Vec<u8> = Vec::with_capacity(declared.min(1 << 16) as usize);
    let mut produced = 0u64;
    let mut skippable = 0usize;
    while produced < declared {
        let mut header = [0u8; 4];
        io.read_exact(&mut header).await?;
        let body_len = u32::from_le_bytes([header[1], header[2], header[3], 0]) as usize;
        if (frames.len() + 4 + body_len) as u64 > max_wire {
            return Err(invalid(format!("framed payload exceeds {max_wire} wire bytes")));
        }
        frames.extend_from_slice(&header);
        let start = frames.len();
        frames.resize(start + body_len, 0);
        io.read_exact(&mut frames[start..]).await?;
        let body = &frames[start..];
        match header[0] {
            0x00 | 0x01 if body_len < 4 => return Err(invalid("snappy data chunk shorter than its CRC")),
            0x00 => {
                produced += snap::raw::decompress_len(&body[4..]).map_err(|e| invalid(e.to_string()))? as u64;
            }
            0x01 => produced += (body_len - 4) as u64,
            0x80..=0xff => {
                skippable += 1;
                if skippable > 16 {
                    return Err(invalid("too many skippable snappy chunks"));
                }
            }
            other => return Err(invalid(format!("reserved snappy chunk type {other:#x}"))),
        }
        if produced > declared {
            return Err(invalid("snappy data exceeds the declared length"));
        }
    }
    let mut out = Vec::with_capacity(declared as usize);
    let mut decoder = snap::read::FrameDecoder::new(&frames[..]);
    std::io::Read::read_to_end(&mut decoder, &mut out).map_err(|e| invalid(format!("snappy: {e}")))?;
    if out.len() as u64 != declared {
        return Err(invalid(format!("framed payload is {} bytes, declared {declared}", out.len())));
    }
    Ok(out)
}

/// Reads a request payload of at most `max` bytes (the server side).
pub async fn read_request<T>(io: &mut T, max: u64) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin,
{
    read_framed(io, max).await
}

/// Reads a request payload of at most `max` bytes as gov5's v1.1 servers
/// read one: a declared length above `max` is `Ok(Err(message))` with
/// gov5's message (`syncwire: declared length above the cap: N > max`), which
/// the server answers under `0x01 INVALID_REQUEST`; a stream that breaks is
/// the `io::Error`.
pub async fn read_request_checked<T>(io: &mut T, max: u64) -> io::Result<Result<Vec<u8>, String>>
where
    T: AsyncRead + Unpin,
{
    let declared = read_uvarint(io).await?.ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    if declared > max {
        return Ok(Err(format!("syncwire: declared length above the cap: {declared} > {max}")));
    }
    read_framed_body(io, declared, max).await.map(Ok)
}

/// Reads one response chunk (gov5's `ReadChunk`). `with_context` says
/// SUCCESS chunks carry the 4 context bytes; `max` bounds a SUCCESS
/// payload, an END payload is bounded by [`END_LEN`] and an error message
/// by [`MAX_ERROR_MESSAGE`].
///
/// `Ok(None)` only when the stream ends cleanly before the code byte. The
/// message of an error chunk is optional: one that is absent or does not
/// decode leaves the payload empty, and the chunk is still returned.
pub async fn read_chunk<T>(io: &mut T, with_context: bool, max: u64) -> io::Result<Option<Chunk>>
where
    T: AsyncRead + Unpin,
{
    let mut code = [0u8; 1];
    if io.read(&mut code).await? == 0 {
        return Ok(None);
    }
    let code = code[0];
    match code {
        CODE_SUCCESS => {
            let context = if with_context {
                let mut context = [0u8; 4];
                io.read_exact(&mut context).await?;
                Some(context)
            } else {
                None
            };
            let payload = read_framed(io, max).await?;
            Ok(Some(Chunk { code, context, payload }))
        }
        CODE_END => {
            let payload = read_framed(io, END_LEN as u64).await?;
            Ok(Some(Chunk { code, context: None, payload }))
        }
        _ => {
            let payload = read_framed(io, MAX_ERROR_MESSAGE as u64).await.unwrap_or_default();
            Ok(Some(Chunk { code, context: None, payload }))
        }
    }
}

/// Every chunk of a complete reply held in memory (tests, vectors, loopback
/// peers): chunks until the bytes run out.
pub fn decode_chunks(mut bytes: &[u8], with_context: bool, max: u64) -> io::Result<Vec<Chunk>> {
    use futures::FutureExt;
    let mut out = Vec::new();
    loop {
        match read_chunk(&mut bytes, with_context, max).now_or_never() {
            Some(Ok(Some(chunk))) => out.push(chunk),
            Some(Ok(None)) => return Ok(out),
            Some(Err(err)) => return Err(err),
            None => return Err(invalid("an in-memory read did not complete")),
        }
    }
}

/// A framed request held in memory, decoded (tests, vectors, loopback peers).
/// The whole input must be the one frame.
pub fn decode_request(mut bytes: &[u8], max: u64) -> io::Result<Vec<u8>> {
    use futures::FutureExt;
    let payload = match read_framed(&mut bytes, max).now_or_never() {
        Some(result) => result?,
        None => return Err(invalid("an in-memory read did not complete")),
    };
    if !bytes.is_empty() {
        return Err(invalid(format!("{} bytes after the request", bytes.len())));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_framed_payload_round_trips() {
        for len in [1usize, 4, 17, 1000, 70_000, 300_000] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            let wire = framed(&payload);
            assert_eq!(decode_request(&wire, len as u64).unwrap(), payload);
            assert!(decode_request(&wire, len as u64 - 1).is_err(), "a declared length above the cap is refused");
        }
    }

    #[test]
    fn an_empty_payload_is_the_bare_length() {
        assert_eq!(framed(&[]), vec![0]);
        assert_eq!(decode_request(&[0], 0).unwrap(), Vec::<u8>::new());
        // A chunk with an empty payload is followed directly by the next.
        let mut wire = chunk(CODE_SUCCESS, None, &[]);
        wire.extend(chunk(CODE_SUCCESS, None, b"x"));
        let chunks = decode_chunks(&wire, false, 16).unwrap();
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].payload.is_empty());
        assert_eq!(chunks[1].payload, b"x");
    }

    #[test]
    fn a_rate_limited_chunk_is_code_four_and_decimal_milliseconds() {
        let wire = rate_limited_chunk(DEFAULT_RETRY_AFTER_MS);
        // 0x04 ‖ uvarint(4) ‖ stream identifier ‖ uncompressed chunk of "1000".
        assert_eq!(&wire[..2], &[0x04, 0x04]);
        assert_eq!(&wire[2..12], b"\xff\x06\x00\x00sNaPpY");
        assert_eq!(wire[12], 0x01);
        assert!(wire.ends_with(b"1000"));
        let chunks = decode_chunks(&wire, true, 1 << 20).unwrap();
        assert_eq!(chunks.len(), 1);
        let err = chunks[0].as_error();
        assert_eq!(err.code, CODE_RATE_LIMITED);
        assert_eq!(err.retry_after(), Some(Duration::from_millis(1000)));
        assert_eq!(error_chunk(CODE_INVALID_REQUEST, "x").as_slice().first(), Some(&CODE_INVALID_REQUEST));
    }

    #[test]
    fn an_error_message_is_cut_to_its_cap() {
        let long = "e".repeat(1000);
        let chunks = decode_chunks(&error_chunk(CODE_SERVER_ERROR, &long), false, 0).unwrap();
        assert_eq!(chunks[0].payload.len(), MAX_ERROR_MESSAGE);
    }

    #[test]
    fn an_error_chunk_without_a_message_still_answers() {
        // The message is optional on the wire: the bare code is the answer.
        let chunks = decode_chunks(&[CODE_RESOURCE_UNAVAILABLE], false, 0).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].code, CODE_RESOURCE_UNAVAILABLE);
        assert!(chunks[0].payload.is_empty());
    }

    #[test]
    fn a_truncated_success_chunk_is_an_error_not_a_clean_end() {
        let wire = chunk(CODE_SUCCESS, Some(&[1, 2, 3, 4]), b"hello world");
        for cut in 1..wire.len() {
            assert!(decode_chunks(&wire[..cut], true, 1 << 20).is_err(), "cut at {cut}");
        }
        assert!(decode_chunks(&[], true, 1 << 20).unwrap().is_empty(), "no bytes is a clean end");
    }

    #[test]
    fn a_declared_length_above_the_cap_is_refused_before_reading_on() {
        // uvarint(2^40) and nothing else: refused on the length alone.
        let mut wire = vec![CODE_SUCCESS];
        wire.extend(encode_varint(1 << 40));
        assert!(decode_chunks(&wire, false, 64 << 20).is_err());
    }

    #[test]
    fn end_reasons_round_trip() {
        for byte in 0..=6u8 {
            assert_eq!(EndReason::from_u8(byte).map(EndReason::as_u8), Some(byte));
        }
        assert_eq!(EndReason::from_u8(7), None);
        assert!(!EndReason::ByteBudget.allows_empty());
        assert!(EndReason::CanonicalEnd.allows_empty());
    }

    #[test]
    fn the_chunk_deadline_grows_with_the_chunk() {
        assert_eq!(chunk_timeout(0), Duration::from_secs(10));
        assert_eq!(chunk_timeout(1 << 20), Duration::from_secs(11));
    }
}
