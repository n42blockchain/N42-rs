// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `/rpc/commit_qc/1/ssz_snappy` (sync standard §5.2), byte for byte with
//! gov5's `syncwire` (`CommitQCRequest`, `CommitQCResponse`) and
//! `v11/commitqc.go` (`ServeCommitQC`, `ReadCommitQC`).
//!
//! ```text
//! Request (40 B):  number u64 ‖ hash Bytes32       (both zero: "your highest")
//! Response:        one SUCCESS chunk (no context bytes):
//!                  qc_len u32 ‖ QC wire ‖ header_count u16 ‖ header_count × (u32 len ‖ RLP header)
//!                  or 0x03 RESOURCE_UNAVAILABLE
//! ```
//!
//! The server returns the lowest commit QC it holds naming the requested
//! committed block or a descendant -- its persisted last commit QC, or one
//! embedded in a header of its committed chain above the target -- with the
//! headers from that QC's block down to the target (none past 256).
//!
//! The client ([`check_commit_qc`]) checks the reply's shape: the first
//! header is the QC's block, the headers are a descending parent-hash chain,
//! the lowest is the requested block. The QC's signature is the caller's to
//! verify (§3.3: commit domain, the set of its own epoch, no fallback); once
//! it verifies, the requested block is authenticated.

use std::future::Future;
use std::io;

use alloy_primitives::{Bytes, B256};
use alloy_rlp::Decodable;
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use libp2p::StreamProtocol;
use n42_h2_consensus::N42Header;
use n42_h2_wire::h2_wire::{decode_h2_qc, encode_h2_qc, H2QuorumCertificate};

use super::bodies::MAX_HEADER_BYTES;
use super::frame::{self, CodeError};

/// The protocol id.
pub const COMMIT_QC_PROTOCOL: &str = "/rpc/commit_qc/1/ssz_snappy";

/// The protocol id, negotiated.
pub fn commit_qc_protocol() -> StreamProtocol {
    StreamProtocol::new(COMMIT_QC_PROTOCOL)
}

/// The encoded size of a [`CommitQcRequest`].
pub const COMMIT_QC_REQUEST_LEN: usize = 40;
/// The largest QC wire form (§6.1).
pub const MAX_QC_BYTES: usize = 2048;
/// The most headers one reply carries.
pub const MAX_COMMIT_QC_HEADERS: usize = 256;
/// The largest SUCCESS payload of the protocol.
pub const MAX_COMMIT_QC_PAYLOAD: u64 = (4 + MAX_QC_BYTES + 2 + MAX_COMMIT_QC_HEADERS * (4 + MAX_HEADER_BYTES as usize)) as u64;
/// How many canonical headers above the target a server reads looking for
/// an embedded QC that reaches it (gov5's `CommitQCScanLimit`).
pub const COMMIT_QC_SCAN_LIMIT: u64 = 4096;

/// The `commit_qc/1` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommitQcRequest {
    /// The block number.
    pub number: u64,
    /// The block hash; zero asks by number (and with number zero, for the
    /// server's highest QC).
    pub hash: B256,
}

impl CommitQcRequest {
    /// The highest commit QC the server holds.
    pub const HIGHEST: Self = Self { number: 0, hash: B256::ZERO };

    /// The 40 bytes on the wire.
    pub fn encode(&self) -> [u8; COMMIT_QC_REQUEST_LEN] {
        let mut out = [0u8; COMMIT_QC_REQUEST_LEN];
        out[..8].copy_from_slice(&self.number.to_le_bytes());
        out[8..].copy_from_slice(self.hash.as_slice());
        out
    }

    /// Decodes a request (gov5 checks the length only).
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != COMMIT_QC_REQUEST_LEN {
            return Err("syncwire: wrong message length".to_owned());
        }
        Ok(Self {
            number: u64::from_le_bytes(bytes[..8].try_into().unwrap_or_default()),
            hash: B256::from_slice(&bytes[8..]),
        })
    }

    /// Whether this asks for the server's highest QC.
    pub fn is_highest(&self) -> bool {
        *self == Self::HIGHEST
    }
}

/// The SUCCESS payload: the QC's wire form and the RLP headers from the QC's
/// block down to the requested number.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommitQcResponse {
    /// The QC, §1.2 wire form.
    pub qc: Vec<u8>,
    /// RLP headers, the QC's block first.
    pub headers: Vec<Bytes>,
}

impl CommitQcResponse {
    /// The payload bytes (gov5's `CommitQCResponse.Encode`).
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.qc.is_empty() || self.qc.len() > MAX_QC_BYTES {
            return Err(format!("syncwire: QC of {} bytes", self.qc.len()));
        }
        if self.headers.len() > MAX_COMMIT_QC_HEADERS {
            return Err(format!("syncwire: {} headers", self.headers.len()));
        }
        let mut out = Vec::with_capacity(6 + self.qc.len() + self.headers.iter().map(|h| h.len() + 4).sum::<usize>());
        out.extend_from_slice(&(self.qc.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.qc);
        out.extend_from_slice(&(self.headers.len() as u16).to_le_bytes());
        for header in &self.headers {
            if header.is_empty() || header.len() as u64 > MAX_HEADER_BYTES {
                return Err(format!("syncwire: header of {} bytes", header.len()));
            }
            out.extend_from_slice(&(header.len() as u32).to_le_bytes());
            out.extend_from_slice(header);
        }
        Ok(out)
    }

    /// Decodes a payload, shape only (gov5's `DecodeCommitQCResponse`).
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut rest = bytes;
        let mut take = |n: usize| -> Result<&[u8], String> {
            if rest.len() < n {
                return Err("syncwire: short message".to_owned());
            }
            let (head, tail) = rest.split_at(n);
            rest = tail;
            Ok(head)
        };
        let qc_len = u32::from_le_bytes(take(4)?.try_into().unwrap_or_default()) as usize;
        if qc_len == 0 || qc_len > MAX_QC_BYTES {
            return Err(format!("syncwire: QC length {qc_len}"));
        }
        let qc = take(qc_len)?.to_vec();
        let count = u16::from_le_bytes(take(2)?.try_into().unwrap_or_default()) as usize;
        if count > MAX_COMMIT_QC_HEADERS {
            return Err(format!("syncwire: {count} headers > {MAX_COMMIT_QC_HEADERS}"));
        }
        let mut headers = Vec::with_capacity(count);
        for i in 0..count {
            let len = u32::from_le_bytes(take(4)?.try_into().unwrap_or_default()) as u64;
            if len == 0 || len > MAX_HEADER_BYTES {
                return Err(format!("syncwire: header {i} length {len}"));
            }
            headers.push(Bytes::copy_from_slice(take(len as usize)?));
        }
        if !rest.is_empty() {
            return Err(format!("syncwire: {} trailing bytes", rest.len()));
        }
        Ok(Self { qc, headers })
    }
}

/// The QC a header's extra data embeds, as gov5's `ExtractHeaderQC` reads
/// it: QC then seal, or (legacy) a QC alone. `None` when there is none or it
/// does not decode.
pub fn header_qc(header: &N42Header) -> Option<H2QuorumCertificate> {
    let extra = n42_h2_consensus::HeaderExtra::decode(&header.extra_data).ok()?;
    if extra.qc.is_empty() {
        return None;
    }
    decode_h2_qc(&extra.qc)
        .or_else(|_| decode_h2_qc(header.extra_data.get(n42_h2_consensus::header_profile::EXTRA_MIN_LEN..).unwrap_or_default()))
        .ok()
}

/// What a `commit_qc/1` server reads: its committed head, its canonical
/// chain, its headers by hash and its persisted last commit QC, in one
/// consistent view.
pub trait CommitQcSource: Sync {
    /// The highest number the server counts as committed.
    fn committed_head(&self) -> u64;
    /// The canonical header at `number`.
    fn canonical_header(&self, number: u64) -> impl Future<Output = Option<N42Header>> + Send;
    /// A header by hash, canonical or not.
    fn header_by_hash(&self, hash: B256) -> impl Future<Output = Option<N42Header>> + Send;
    /// The persisted last commit QC (`None` before the first commit).
    fn last_committed_qc(&self) -> Option<H2QuorumCertificate>;
}

fn unavailable(message: &str) -> CodeError {
    CodeError { code: frame::CODE_RESOURCE_UNAVAILABLE, message: message.to_owned() }
}

fn server_error(message: String) -> CodeError {
    CodeError { code: frame::CODE_SERVER_ERROR, message }
}

/// Answers one request (gov5's `ServeCommitQC`): the SUCCESS payload, or
/// the error chunk's code and message.
pub async fn serve_commit_qc<S: CommitQcSource>(source: &S, request: CommitQcRequest) -> Result<Vec<u8>, CodeError> {
    let head = source.committed_head();
    let highest = request.is_highest();
    let canonical_hash = |number: u64| async move { source.canonical_header(number).await.map(|h| h.hash_slow()) };
    let mut target = request.number;
    if highest {
        target = 0;
    } else if request.hash != B256::ZERO {
        let Some(header) = source.header_by_hash(request.hash).await else {
            return Err(unavailable("unknown hash"));
        };
        target = header.number;
        if target > head || canonical_hash(target).await != Some(request.hash) {
            return Err(unavailable("hash is not committed"));
        }
    } else if target > head || canonical_hash(target).await.is_none() {
        return Err(unavailable("number is not committed"));
    }

    let mut best: Option<(H2QuorumCertificate, u64)> = None;
    // Whether `qc` names a committed block at or above the target, and is a
    // better pick: the lowest for a target, the highest for "highest".
    let consider = |qc: H2QuorumCertificate, best: Option<(H2QuorumCertificate, u64)>| async move {
        if qc.view == 0 {
            return best;
        }
        let Some(header) = source.header_by_hash(qc.block_hash).await else {
            return best;
        };
        let number = header.number;
        if number < target || number > head || canonical_hash(number).await != Some(qc.block_hash) {
            return best;
        }
        match &best {
            Some((_, at)) if (highest && number <= *at) || (!highest && number >= *at) => best,
            _ => Some((qc, number)),
        }
    };
    if !highest {
        // A header carries its leader's last commit QC, so embedded QCs grow
        // along the chain: the first that reaches the target is the lowest.
        // The scan may read canonical headers above the committed head: the
        // QC they carry names a committed block and verifies on its own.
        for number in target + 1..=target.saturating_add(COMMIT_QC_SCAN_LIMIT) {
            let Some(header) = source.canonical_header(number).await else {
                break;
            };
            let Some(qc) = header_qc(&header) else {
                continue;
            };
            best = consider(qc, best).await;
            if best.is_some() {
                break;
            }
        }
    }
    if let Some(qc) = source.last_committed_qc() {
        best = consider(qc, best).await;
    }
    if highest && let Some(qc) = source.canonical_header(head).await.as_ref().and_then(header_qc) {
        best = consider(qc, best).await;
    }
    let Some((qc, best_number)) = best else {
        return Err(unavailable("no commit QC reaches the block"));
    };
    let wire = encode_h2_qc(&qc).map_err(|_| server_error("encode QC".to_owned()))?;
    let mut response = CommitQcResponse { qc: wire, headers: Vec::new() };
    let low = if highest { best_number } else { target };
    if best_number - low < MAX_COMMIT_QC_HEADERS as u64 {
        for number in (low..=best_number).rev() {
            let Some(header) = source.canonical_header(number).await else {
                return Err(server_error(format!("canonical header {number} absent")));
            };
            response.headers.push(alloy_rlp::encode(&header).into());
        }
    }
    response.encode().map_err(server_error)
}

/// A reply whose shape checked: the QC decoded, the headers a descending
/// chain from the QC's block down to the requested block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedCommitQc {
    /// The QC, decoded (its signature not yet verified).
    pub qc: H2QuorumCertificate,
    /// Its wire form.
    pub qc_wire: Vec<u8>,
    /// The headers with their hashes, the QC's block first. Empty when the
    /// QC's block is more than 256 headers above the request.
    pub headers: Vec<(B256, N42Header)>,
}

impl CheckedCommitQc {
    /// The block the headers reach down to, `(number, hash)`: the requested
    /// one. `None` when the reply carries no headers.
    pub fn lowest(&self) -> Option<(u64, B256)> {
        self.headers.last().map(|(hash, header)| (header.number, *hash))
    }
}

/// gov5's `ReadCommitQC` checks of a SUCCESS payload: the QC decodes, the
/// first header is its block, each next header is the parent of the one
/// before, and (with headers) the lowest is the requested block. `Err` is a
/// provable fault of the server.
pub fn check_commit_qc(request: &CommitQcRequest, payload: &[u8]) -> Result<CheckedCommitQc, String> {
    let response = CommitQcResponse::decode(payload)?;
    let qc = decode_h2_qc(&response.qc).map_err(|e| format!("QC: {e}"))?;
    let mut headers: Vec<(B256, N42Header)> = Vec::with_capacity(response.headers.len());
    for (i, raw) in response.headers.iter().enumerate() {
        let mut cursor = &raw[..];
        let header = N42Header::decode(&mut cursor).map_err(|e| format!("header {i}: {e}"))?;
        if !cursor.is_empty() {
            return Err(format!("header {i}: trailing bytes"));
        }
        let hash = alloy_primitives::keccak256(raw);
        if i == 0 && hash != qc.block_hash {
            return Err(format!("first header {hash} is not the QC's block {}", qc.block_hash));
        }
        if let Some((_, above)) = headers.last()
            && (header.number.checked_add(1) != Some(above.number) || above.parent_hash != hash)
        {
            return Err(format!("header {i} does not link"));
        }
        headers.push((hash, header));
    }
    if let Some((hash, low)) = headers.last()
        && !request.is_highest()
    {
        if request.hash != B256::ZERO && *hash != request.hash {
            return Err(format!("lowest header {hash} is not the requested {}", request.hash));
        }
        if request.hash == B256::ZERO && low.number != request.number {
            return Err(format!("lowest header {} is not the requested {}", low.number, request.number));
        }
    }
    Ok(CheckedCommitQc { qc, qc_wire: response.qc, headers })
}

/// What a server reads off an inbound stream: the request, or gov5's
/// INVALID_REQUEST message.
pub type InboundCommitQc = Result<CommitQcRequest, String>;

/// A reply: the SUCCESS payload (unchecked on the read side), or the error
/// chunk.
pub type CommitQcReply = Result<Vec<u8>, CodeError>;

/// The wire bytes of a reply.
pub fn encode_commit_qc_reply(reply: &CommitQcReply) -> Vec<u8> {
    match reply {
        Ok(payload) => frame::chunk(frame::CODE_SUCCESS, None, payload),
        Err(err) => frame::error_chunk(err.code, &err.message),
    }
}

/// The request-response codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct CommitQcCodec;

impl request_response::Codec for CommitQcCodec {
    type Protocol = StreamProtocol;
    type Request = InboundCommitQc;
    type Response = CommitQcReply;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        Ok(match frame::read_request_checked(io, COMMIT_QC_REQUEST_LEN as u64).await? {
            Ok(payload) => CommitQcRequest::decode(&payload),
            Err(message) => Err(message),
        })
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        match frame::read_chunk(io, false, MAX_COMMIT_QC_PAYLOAD).await? {
            None => Err(io::ErrorKind::UnexpectedEof.into()),
            Some(chunk) if chunk.is_success() => Ok(Ok(chunk.payload)),
            Some(chunk) => Ok(Err(chunk.as_error())),
        }
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, request: Self::Request) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let request = request.map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        io.write_all(&frame::framed(&request.encode())).await?;
        io.close().await
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, reply: Self::Response) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&encode_commit_qc_reply(&reply)).await?;
        io.close().await
    }
}

/// The request-response behaviour.
pub type CommitQcBehaviour = request_response::Behaviour<CommitQcCodec>;

/// Requesting `commit_qc/1`, and serving it when `serve` (§6.2: 10 s).
pub fn commit_qc_behaviour(serve: bool) -> CommitQcBehaviour {
    let support = if serve { request_response::ProtocolSupport::Full } else { request_response::ProtocolSupport::Outbound };
    request_response::Behaviour::with_codec(
        CommitQcCodec,
        [(commit_qc_protocol(), support)],
        request_response::Config::default().with_request_timeout(frame::SMALL_REQUEST_TIMEOUT),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_v11::bodies::item_links;
    use crate::sync_v11::vectors;
    use futures::FutureExt;
    use std::collections::BTreeMap;

    /// gov5's vector server: the canonical headers 6..=10 (from the
    /// bodies_by_range/2 vectors), committed head 10, no persisted QC beyond
    /// what the headers embed.
    struct VectorSource {
        headers: BTreeMap<u64, N42Header>,
        head: u64,
        persisted: Option<H2QuorumCertificate>,
    }

    impl CommitQcSource for VectorSource {
        fn committed_head(&self) -> u64 {
            self.head
        }
        fn canonical_header(&self, number: u64) -> impl Future<Output = Option<N42Header>> + Send {
            std::future::ready(self.headers.get(&number).cloned())
        }
        fn header_by_hash(&self, hash: B256) -> impl Future<Output = Option<N42Header>> + Send {
            std::future::ready(self.headers.values().find(|h| h.hash_slow() == hash).cloned())
        }
        fn last_committed_qc(&self) -> Option<H2QuorumCertificate> {
            self.persisted.clone()
        }
    }

    fn vector_source() -> VectorSource {
        let file = vectors::load("bodies_by_range_2.json");
        let mut headers = BTreeMap::new();
        for case in file["cases"].as_array().unwrap() {
            let Ok(request) = crate::sync_v11::bodies::RangeV2Request::decode(&vectors::bytes(&case["request_payload"])) else {
                continue;
            };
            for chunk in vectors::listed_chunks(case).into_iter().filter(|c| c.code == frame::CODE_SUCCESS) {
                let links = item_links(&chunk.payload, request.headers_only()).unwrap();
                let raw = if request.headers_only() {
                    chunk.payload.clone()
                } else {
                    // The block's first item.
                    let mut rest = &chunk.payload[..];
                    let _ = alloy_rlp::Header::decode(&mut rest).unwrap();
                    let mut item = rest;
                    let inner = alloy_rlp::Header::decode(&mut item).unwrap();
                    rest[..rest.len() - item.len() + inner.payload_length].to_vec()
                };
                let header = N42Header::decode(&mut &raw[..]).unwrap();
                assert_eq!(header.hash_slow(), links.hash);
                assert_eq!(alloy_rlp::encode(&header), raw, "a header re-encodes to gov5's bytes");
                headers.insert(links.number, header);
            }
        }
        VectorSource { headers, head: 10, persisted: None }
    }

    #[test]
    fn every_vector_case_is_served_byte_for_byte() {
        let source = vector_source();
        assert_eq!(source.headers.keys().copied().collect::<Vec<_>>(), vec![6, 7, 8, 9, 10]);
        let file = vectors::load("commit_qc_1.json");
        for case in file["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let payload = frame::decode_request(&vectors::bytes(&case["request_wire"]), 40).unwrap();
            let request = CommitQcRequest::decode(&payload).unwrap();
            let fields = &case["request_fields"];
            assert_eq!(request.number, fields["number"].as_u64().unwrap(), "{name}");
            assert_eq!(request.hash.to_string(), fields["hash"].as_str().unwrap(), "{name}");
            assert_eq!(frame::framed(&request.encode()), vectors::bytes(&case["request_wire"]), "{name}: request encode");
            let reply = serve_commit_qc(&source, request).now_or_never().unwrap();
            assert_eq!(
                hex::encode(encode_commit_qc_reply(&reply)),
                hex::encode(vectors::bytes(&case["response_wire"])),
                "{name}: served reply"
            );
        }
    }

    #[test]
    fn every_vector_case_reads_and_checks_as_gov5_reads_it() {
        use libp2p::request_response::Codec as _;
        let file = vectors::load("commit_qc_1.json");
        let protocol = commit_qc_protocol();
        for case in file["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let wire = vectors::bytes(&case["request_wire"]);
            let request = futures::executor::block_on(CommitQcCodec.read_request(&protocol, &mut &wire[..])).unwrap().unwrap();
            let response = vectors::bytes(&case["response_wire"]);
            let reply = futures::executor::block_on(CommitQcCodec.read_response(&protocol, &mut &response[..])).unwrap();
            let listed = vectors::listed_chunks(case);
            match reply {
                Ok(payload) => {
                    assert_eq!(payload, listed[0].payload, "{name}");
                    let checked = check_commit_qc(&request, &payload).unwrap_or_else(|e| panic!("{name}: {e}"));
                    let (number, hash) = checked.lowest().unwrap();
                    assert_eq!(number, 9, "{name}");
                    assert_eq!(hash, checked.qc.block_hash, "{name}: the QC names block 9 itself");
                    assert_eq!(CommitQcResponse::decode(&payload).unwrap().encode().unwrap(), payload, "{name}");
                }
                Err(err) => {
                    assert_eq!(err.code, frame::CODE_RESOURCE_UNAVAILABLE, "{name}");
                    assert_eq!(err.message, case["response_chunks"][0]["error_message"].as_str().unwrap(), "{name}");
                }
            }
        }
    }

    #[test]
    fn a_target_below_the_qc_gets_the_headers_down_to_it() {
        let source = vector_source();
        let seven = source.headers[&7].hash_slow();
        let request = CommitQcRequest { number: 7, hash: seven };
        let payload = serve_commit_qc(&source, request).now_or_never().unwrap().unwrap();
        let checked = check_commit_qc(&request, &payload).unwrap();
        // Header 8 embeds the QC that reaches 7 (or one above it): the
        // headers run from that QC's block down to 7.
        assert_eq!(checked.lowest(), Some((7, seven)));
        assert_eq!(checked.headers[0].0, checked.qc.block_hash);
        assert!(!checked.headers.is_empty());
    }

    #[test]
    fn a_persisted_qc_answers_when_no_header_carries_one() {
        let mut source = vector_source();
        let ten = source.headers[&10].clone();
        // A persisted QC naming the head; no header above 10 is held.
        let mut qc = header_qc(&ten).unwrap();
        qc.block_hash = ten.hash_slow();
        qc.view += 1;
        source.persisted = Some(qc.clone());
        let request = CommitQcRequest { number: 10, hash: ten.hash_slow() };
        let payload = serve_commit_qc(&source, request).now_or_never().unwrap().unwrap();
        let checked = check_commit_qc(&request, &payload).unwrap();
        assert_eq!(checked.qc, qc);
        assert_eq!(checked.headers.len(), 1);
        // And it is the highest the server holds.
        let payload = serve_commit_qc(&source, CommitQcRequest::HIGHEST).now_or_never().unwrap().unwrap();
        assert_eq!(check_commit_qc(&CommitQcRequest::HIGHEST, &payload).unwrap().qc, qc);
    }

    #[test]
    fn a_reply_that_does_not_reach_the_request_is_a_fault() {
        let source = vector_source();
        let nine = source.headers[&9].hash_slow();
        let payload = serve_commit_qc(&source, CommitQcRequest { number: 9, hash: nine }).now_or_never().unwrap().unwrap();
        // Asked for 8 by hash, answered with the chain down to 9.
        let eight = CommitQcRequest { number: 8, hash: source.headers[&8].hash_slow() };
        assert!(check_commit_qc(&eight, &payload).is_err());
        assert!(check_commit_qc(&CommitQcRequest { number: 8, hash: B256::ZERO }, &payload).is_err());
        // A header that is not the QC's block.
        let mut response = CommitQcResponse::decode(&payload).unwrap();
        response.headers[0] = alloy_rlp::encode(&source.headers[&8]).into();
        assert!(check_commit_qc(&CommitQcRequest { number: 8, hash: B256::ZERO }, &response.encode().unwrap()).is_err());
        // Shape: trailing bytes, an empty QC.
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(CommitQcResponse::decode(&trailing).is_err());
        assert!(CommitQcResponse { qc: Vec::new(), headers: Vec::new() }.encode().is_err());
    }

    #[test]
    fn requests_are_forty_bytes() {
        let request = CommitQcRequest { number: 7, hash: B256::repeat_byte(3) };
        assert_eq!(CommitQcRequest::decode(&request.encode()), Ok(request));
        assert_eq!(CommitQcRequest::decode(&[0; 39]).unwrap_err(), "syncwire: wrong message length");
        assert!(CommitQcRequest::HIGHEST.is_highest());
    }
}
