// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Snappy, without a fresh codec per message.
//!
//! Every gov5 payload this side handles is snappy: gossip envelopes and block
//! bodies are raw blocks, RPC chunks (status, `block_by_hash`, a range reply's
//! thousand bodies) are the framing format. `snap` hands out codecs that own
//! their scratch — a raw [`snap::raw::Encoder`] grows a 32 KiB hash table for
//! anything past a few KiB, and a framed encoder or decoder zeroes 75–130 KiB
//! of block buffers on construction — so building one per call, as this crate
//! and `n42-h2-net` did, paid that allocation and memset on every message.
//! Erigon went through the same exercise this summer (a pool for its snappy
//! writers, then one for zstd). Here the scratch lives in a thread-local and
//! every call borrows it.
//!
//! The framing format is reimplemented over the raw codec rather than reusing
//! [`snap::write::FrameEncoder`]: that type writes its stream identifier once
//! per instance and offers no way to reset it, so it cannot be reused across
//! messages. The output is byte-identical to `snap`'s, which
//! [`tests::framed_output_is_byte_identical_to_snap`] pins across block
//! boundaries and both chunk kinds; the CRC32C is the same masked Castagnoli
//! sum, with the same SSE4.2 path on x86-64.

use std::cell::RefCell;

/// Largest uncompressed block in a snappy frame (`snap::MAX_BLOCK_SIZE`).
pub const MAX_BLOCK_SIZE: usize = 1 << 16;

/// `snap::frame::MAX_COMPRESS_BLOCK_SIZE`: `max_compress_len(MAX_BLOCK_SIZE)`.
const MAX_COMPRESS_BLOCK_SIZE: usize = 76490;

/// The stream identifier chunk that opens every framed stream.
pub const STREAM_IDENTIFIER: &[u8] = b"\xFF\x06\x00\x00sNaPpY";

/// Chunk types of the framing format.
const CHUNK_COMPRESSED: u8 = 0x00;
const CHUNK_UNCOMPRESSED: u8 = 0x01;
const CHUNK_PADDING: u8 = 0xfe;
const CHUNK_STREAM: u8 = 0xff;

/// Failures of the framed codec.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The raw block codec refused.
    #[error("snappy: {0}")]
    Snappy(#[from] snap::Error),
    /// The stream did not open with the identifier.
    #[error("snappy framing: stream does not start with the stream identifier")]
    MissingStreamIdentifier,
    /// A chunk type the format reserves for future, non-skippable use.
    #[error("snappy framing: reserved chunk type {0:#04x}")]
    ReservedChunkType(u8),
    /// A chunk longer than the format allows, or too short to carry its CRC.
    #[error("snappy framing: chunk of {0} bytes is outside the allowed range")]
    ChunkLength(usize),
    /// A chunk's CRC did not match its contents.
    #[error("snappy framing: checksum mismatch (expected {expected:#010x}, got {got:#010x})")]
    Checksum {
        /// The sum the chunk carried.
        expected: u32,
        /// The sum the contents have.
        got: u32,
    },
    /// The stream ended before the declared length was produced.
    #[error("snappy framing: stream ended {short} bytes short of the declared length")]
    Truncated {
        /// How many bytes were still expected.
        short: usize,
    },
}

/// Per-thread scratch: the raw encoder with its hash table, and a block-sized
/// output buffer for the framed paths.
struct Scratch {
    encoder: snap::raw::Encoder,
    block: Vec<u8>,
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch {
        encoder: snap::raw::Encoder::new(),
        block: Vec::new(),
    });
}

fn with_scratch<T>(f: impl FnOnce(&mut Scratch) -> T) -> T {
    SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        f(&mut scratch)
    })
}

/// Compresses `input` as one raw snappy block — the gossip form.
pub fn compress_raw(input: &[u8]) -> Result<Vec<u8>, snap::Error> {
    with_scratch(|scratch| scratch.encoder.compress_vec(input))
}

/// Decompresses one raw snappy block. The decoder carries no state, so there
/// is nothing to pool; this exists so callers have one place to go.
pub fn decompress_raw(input: &[u8]) -> Result<Vec<u8>, snap::Error> {
    snap::raw::Decoder::new().decompress_vec(input)
}

/// Frames `input` the way `snap::write::FrameEncoder` does for one
/// `write_all` followed by `into_inner`: nothing at all for an empty input,
/// otherwise the stream identifier and one chunk per 64 KiB block, each
/// compressed unless that saves less than an eighth.
pub fn frame(input: &[u8]) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::new();
    frame_into(&mut out, input)?;
    Ok(out)
}

/// [`frame`], appending to `out`.
pub fn frame_into(out: &mut Vec<u8>, input: &[u8]) -> Result<(), FrameError> {
    if input.is_empty() {
        return Ok(());
    }
    out.reserve(STREAM_IDENTIFIER.len() + input.len() + 8 * input.len().div_ceil(MAX_BLOCK_SIZE));
    out.extend_from_slice(STREAM_IDENTIFIER);
    with_scratch(|scratch| {
        let Scratch { encoder, block } = scratch;
        block.resize(MAX_COMPRESS_BLOCK_SIZE, 0);
        for src in input.chunks(MAX_BLOCK_SIZE) {
            let checksum = crc32c_masked(src);
            let compressed = encoder.compress(src, block)?;
            let (kind, body): (u8, &[u8]) = if compressed >= src.len() - src.len() / 8 {
                (CHUNK_UNCOMPRESSED, src)
            } else {
                (CHUNK_COMPRESSED, &block[..compressed])
            };
            let len = (4 + body.len()) as u32;
            out.push(kind);
            out.extend_from_slice(&len.to_le_bytes()[..3]);
            out.extend_from_slice(&checksum.to_le_bytes());
            out.extend_from_slice(body);
        }
        Ok(())
    })
}

/// Decodes a framed stream into exactly `len` bytes — what a
/// `snap::read::FrameDecoder` hands back for `read_exact` of that length:
/// chunks are consumed until `len` bytes are produced, a chunk that overshoots
/// is cut there, and bytes after that are not looked at. Every chunk used is
/// CRC-checked. A `len` of zero is satisfied by anything, an empty stream
/// included.
pub fn unframe(framed: &[u8], len: usize) -> Result<Vec<u8>, FrameError> {
    let mut out = vec![0u8; len];
    if len == 0 {
        return Ok(out);
    }
    let mut produced = 0usize;
    let mut cursor = 0usize;
    let mut seen_stream = false;
    with_scratch(|scratch| {
        let Scratch { block, .. } = scratch;
        block.resize(MAX_BLOCK_SIZE, 0);
        while produced < len {
            let Some(header) = framed.get(cursor..cursor + 4) else {
                return Err(FrameError::Truncated {
                    short: len - produced,
                });
            };
            let kind = header[0];
            let chunk_len = u32::from_le_bytes([header[1], header[2], header[3], 0]) as usize;
            if chunk_len > MAX_COMPRESS_BLOCK_SIZE {
                return Err(FrameError::ChunkLength(chunk_len));
            }
            if !seen_stream {
                if kind != CHUNK_STREAM {
                    return Err(FrameError::MissingStreamIdentifier);
                }
                seen_stream = true;
            }
            let body_start = cursor + 4;
            let Some(body) = framed.get(body_start..body_start + chunk_len) else {
                return Err(FrameError::Truncated {
                    short: len - produced,
                });
            };
            cursor = body_start + chunk_len;
            match kind {
                CHUNK_STREAM => {
                    if body != &STREAM_IDENTIFIER[4..] {
                        return Err(FrameError::MissingStreamIdentifier);
                    }
                }
                CHUNK_PADDING | 0x80..=0xfd => {}
                0x02..=0x7f => return Err(FrameError::ReservedChunkType(kind)),
                CHUNK_UNCOMPRESSED => {
                    if body.len() < 4 {
                        return Err(FrameError::ChunkLength(chunk_len));
                    }
                    let (sum, data) = body.split_at(4);
                    let expected = u32::from_le_bytes([sum[0], sum[1], sum[2], sum[3]]);
                    if data.len() > MAX_BLOCK_SIZE {
                        return Err(FrameError::ChunkLength(chunk_len));
                    }
                    let got = crc32c_masked(data);
                    if expected != got {
                        return Err(FrameError::Checksum { expected, got });
                    }
                    let take = data.len().min(len - produced);
                    out[produced..produced + take].copy_from_slice(&data[..take]);
                    produced += take;
                }
                CHUNK_COMPRESSED => {
                    if body.len() < 4 {
                        return Err(FrameError::ChunkLength(chunk_len));
                    }
                    let (sum, data) = body.split_at(4);
                    let expected = u32::from_le_bytes([sum[0], sum[1], sum[2], sum[3]]);
                    let n = snap::raw::decompress_len(data)?;
                    if n > MAX_BLOCK_SIZE {
                        return Err(FrameError::ChunkLength(n));
                    }
                    let mut decoder = snap::raw::Decoder::new();
                    if n <= len - produced {
                        // Straight into the output, no intermediate copy.
                        let dst = &mut out[produced..produced + n];
                        decoder.decompress(data, dst)?;
                        let got = crc32c_masked(dst);
                        if expected != got {
                            return Err(FrameError::Checksum { expected, got });
                        }
                        produced += n;
                    } else {
                        let dst = &mut block[..n];
                        decoder.decompress(data, dst)?;
                        let got = crc32c_masked(dst);
                        if expected != got {
                            return Err(FrameError::Checksum { expected, got });
                        }
                        let take = len - produced;
                        out[produced..].copy_from_slice(&dst[..take]);
                        produced = len;
                    }
                }
            }
        }
        Ok(())
    })?;
    Ok(out)
}

/// The masked CRC32C the framing format carries with every chunk.
pub fn crc32c_masked(data: &[u8]) -> u32 {
    let sum = crc32c(data);
    (sum.wrapping_shr(15) | sum.wrapping_shl(17)).wrapping_add(0xA282_EAD8)
}

/// CRC32C (Castagnoli), hardware-assisted where the CPU offers it.
pub fn crc32c(data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("sse4.2") {
            // SAFETY: the feature check above guarantees SSE4.2 is available.
            return unsafe { crc32c_sse42(data) };
        }
    }
    crc32c_table(data)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn crc32c_sse42(data: &[u8]) -> u32 {
    use std::arch::x86_64::{_mm_crc32_u8, _mm_crc32_u64};
    let mut crc = u64::from(!0u32);
    let (words, remainder) = data.as_chunks::<8>();
    for word in words {
        crc = _mm_crc32_u64(crc, u64::from_le_bytes(*word));
    }
    let mut tail = crc as u32;
    for &byte in remainder {
        tail = _mm_crc32_u8(tail, byte);
    }
    !tail
}

const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

fn crc32c_table(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc = CRC32C_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// Deterministic bytes that compress somewhat, like RLP does: runs of
    /// structure with noise mixed in.
    fn compressible(len: usize) -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let run = (state % 48) as usize + 1;
            let byte = if state & 0x100 == 0 {
                (state >> 9) as u8
            } else {
                0
            };
            for _ in 0..run {
                out.push(byte);
                if out.len() == len {
                    break;
                }
            }
            out.extend_from_slice(&state.to_le_bytes()[..(state % 5) as usize]);
        }
        out.truncate(len);
        out
    }

    /// Bytes that do not compress, to exercise the uncompressed chunk kind.
    fn incompressible(len: usize) -> Vec<u8> {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.extend_from_slice(&(state >> 11).to_le_bytes());
        }
        out.truncate(len);
        out
    }

    fn snap_frame(input: &[u8]) -> Vec<u8> {
        let mut encoder = snap::write::FrameEncoder::new(Vec::new());
        encoder.write_all(input).unwrap();
        encoder.into_inner().unwrap()
    }

    fn snap_unframe(framed: &[u8], len: usize) -> std::io::Result<Vec<u8>> {
        let mut out = vec![0u8; len];
        snap::read::FrameDecoder::new(framed).read_exact(&mut out)?;
        Ok(out)
    }

    fn sizes() -> Vec<usize> {
        vec![
            0,
            1,
            7,
            72,
            1000,
            MAX_BLOCK_SIZE - 1,
            MAX_BLOCK_SIZE,
            MAX_BLOCK_SIZE + 1,
            3 * MAX_BLOCK_SIZE + 17,
            1 << 20,
        ]
    }

    #[test]
    fn crc32c_known_answer() {
        // The check value of CRC-32C: crc32c("123456789") = 0xE3069283.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c_table(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0);
        // The hardware and table paths agree on odd lengths, where the
        // hardware path has a tail.
        for len in 0..40 {
            let data = incompressible(len);
            assert_eq!(crc32c(&data), crc32c_table(&data), "len {len}");
        }
        let big = compressible(100_003);
        assert_eq!(crc32c(&big), crc32c_table(&big));
    }

    #[test]
    fn framed_output_is_byte_identical_to_snap() {
        for len in sizes() {
            for (name, data) in [
                ("compressible", compressible(len)),
                ("incompressible", incompressible(len)),
            ] {
                assert_eq!(frame(&data).unwrap(), snap_frame(&data), "{name} {len}");
            }
        }
        // Both chunk kinds actually occurred.
        let mixed = frame(&incompressible(MAX_BLOCK_SIZE)).unwrap();
        assert_eq!(mixed[STREAM_IDENTIFIER.len()], CHUNK_UNCOMPRESSED);
        let packed = frame(&compressible(MAX_BLOCK_SIZE)).unwrap();
        assert_eq!(packed[STREAM_IDENTIFIER.len()], CHUNK_COMPRESSED);
    }

    #[test]
    fn unframe_reads_what_snap_wrote_and_snap_reads_what_unframe_accepts() {
        for len in sizes() {
            for data in [compressible(len), incompressible(len)] {
                let framed = snap_frame(&data);
                assert_eq!(unframe(&framed, len).unwrap(), data, "len {len}");
                assert_eq!(
                    snap_unframe(&frame(&data).unwrap(), len).unwrap(),
                    data,
                    "len {len}"
                );
            }
        }
    }

    #[test]
    fn unframe_stops_at_the_declared_length_and_ignores_what_follows() {
        let data = compressible(MAX_BLOCK_SIZE + 500);
        let mut framed = frame(&data).unwrap();
        framed.extend_from_slice(b"trailing garbage that must not be parsed");
        // Cut inside the second chunk.
        assert_eq!(
            unframe(&framed, MAX_BLOCK_SIZE + 3).unwrap(),
            &data[..MAX_BLOCK_SIZE + 3]
        );
        // Cut inside the first.
        assert_eq!(unframe(&framed, 10).unwrap(), &data[..10]);
        assert_eq!(snap_unframe(&framed, 10).unwrap(), &data[..10]);
    }

    #[test]
    fn a_corrupted_chunk_is_refused_by_its_checksum() {
        let data = compressible(4000);
        let mut framed = frame(&data).unwrap();
        // Flip a byte of the compressed body, past the header and CRC.
        let at = STREAM_IDENTIFIER.len() + 8 + 20;
        framed[at] ^= 0x55;
        let err = unframe(&framed, data.len()).unwrap_err();
        assert!(
            matches!(err, FrameError::Checksum { .. } | FrameError::Snappy(_)),
            "{err}"
        );
        assert!(snap_unframe(&framed, data.len()).is_err());

        // And a flipped CRC on an otherwise intact uncompressed chunk.
        let raw = incompressible(300);
        let mut framed = frame(&raw).unwrap();
        framed[STREAM_IDENTIFIER.len() + 4] ^= 0x01;
        assert!(matches!(
            unframe(&framed, raw.len()).unwrap_err(),
            FrameError::Checksum { .. }
        ));
    }

    #[test]
    fn a_stream_without_its_identifier_or_cut_short_is_refused() {
        let data = compressible(100);
        let framed = frame(&data).unwrap();
        assert!(matches!(
            unframe(&framed[STREAM_IDENTIFIER.len()..], data.len()).unwrap_err(),
            FrameError::MissingStreamIdentifier
        ));
        assert!(matches!(
            unframe(&framed[..framed.len() - 3], data.len()).unwrap_err(),
            FrameError::Truncated { .. } | FrameError::Snappy(_)
        ));
        assert!(unframe(&[], 0).unwrap().is_empty());
        assert!(matches!(
            unframe(&[], 1).unwrap_err(),
            FrameError::Truncated { short: 1 }
        ));
    }

    #[test]
    fn skippable_chunks_are_skipped_and_reserved_ones_refused() {
        let data = compressible(50);
        let framed = frame(&data).unwrap();
        let mut padded = framed[..STREAM_IDENTIFIER.len()].to_vec();
        padded.extend_from_slice(&[CHUNK_PADDING, 3, 0, 0, 9, 9, 9]);
        padded.extend_from_slice(&[0x80, 1, 0, 0, 7]);
        padded.extend_from_slice(&framed[STREAM_IDENTIFIER.len()..]);
        assert_eq!(unframe(&padded, data.len()).unwrap(), data);
        assert_eq!(snap_unframe(&padded, data.len()).unwrap(), data);

        let mut reserved = framed[..STREAM_IDENTIFIER.len()].to_vec();
        reserved.extend_from_slice(&[0x02, 1, 0, 0, 7]);
        reserved.extend_from_slice(&framed[STREAM_IDENTIFIER.len()..]);
        assert!(matches!(
            unframe(&reserved, data.len()).unwrap_err(),
            FrameError::ReservedChunkType(0x02)
        ));
    }

    #[test]
    fn raw_roundtrips_and_matches_a_fresh_encoder() {
        for len in sizes() {
            let data = compressible(len);
            let pooled = compress_raw(&data).unwrap();
            assert_eq!(
                pooled,
                snap::raw::Encoder::new().compress_vec(&data).unwrap(),
                "len {len}"
            );
            assert_eq!(decompress_raw(&pooled).unwrap(), data);
        }
    }

    /// Prints per-message timings of the pooled codecs against a fresh `snap`
    /// codec per call. Run with `--ignored --nocapture`.
    #[test]
    #[ignore = "timing, prints numbers; run with --ignored --nocapture"]
    fn timing_pooled_versus_fresh_codecs() {
        use std::time::Instant;
        fn bench(name: &str, iterations: u32, mut f: impl FnMut()) -> f64 {
            f();
            let start = Instant::now();
            for _ in 0..iterations {
                f();
            }
            let per = start.elapsed().as_secs_f64() * 1e6 / f64::from(iterations);
            println!("{name:<44} {per:>10.3} us/op");
            per
        }
        for (label, len, iterations) in [
            ("72 B", 72, 20_000),
            ("1 MiB", 1 << 20, 200),
            ("12 MiB", 12 << 20, 20),
        ] {
            let data = compressible(len);
            let framed = frame(&data).unwrap();
            let raw = compress_raw(&data).unwrap();
            println!("--- {label} ({} framed, {} raw)", framed.len(), raw.len());
            let a = bench(
                &format!("frame   fresh FrameEncoder {label}"),
                iterations,
                || {
                    std::hint::black_box(snap_frame(&data));
                },
            );
            let b = bench(&format!("frame   pooled {label}"), iterations, || {
                std::hint::black_box(frame(&data).unwrap());
            });
            println!("{:<44} {:>9.2}x", "  speedup", a / b);
            let a = bench(
                &format!("unframe fresh FrameDecoder {label}"),
                iterations,
                || {
                    std::hint::black_box(snap_unframe(&framed, len).unwrap());
                },
            );
            let b = bench(&format!("unframe pooled {label}"), iterations, || {
                std::hint::black_box(unframe(&framed, len).unwrap());
            });
            println!("{:<44} {:>9.2}x", "  speedup", a / b);
            let a = bench(
                &format!("raw     fresh Encoder {label}"),
                iterations,
                || {
                    std::hint::black_box(snap::raw::Encoder::new().compress_vec(&data).unwrap());
                },
            );
            let b = bench(&format!("raw     pooled {label}"), iterations, || {
                std::hint::black_box(compress_raw(&data).unwrap());
            });
            println!("{:<44} {:>9.2}x", "  speedup", a / b);
            bench(&format!("raw     decode {label}"), iterations, || {
                std::hint::black_box(decompress_raw(&raw).unwrap());
            });
        }
    }
}
