// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The sparse signer mask (`internal/mobileverify/mask.go`): `uvarint count`,
//! then one uvarint per index over the sorted set, the first raw and each
//! later one as `gap − 1`. Varints are Go's `encoding/binary` ones.

use crate::error::MobileVerifyError;
use crate::registry::MobileIndex;

/// Appends `v` as a Go `binary.AppendUvarint`.
pub fn put_uvarint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Go `binary.Uvarint`: `(value, n)` with `n > 0` bytes read, `n == 0` for a
/// short buffer, `n < 0` for an overflow. Non-minimal encodings are accepted,
/// as in Go.
pub fn uvarint(buf: &[u8]) -> (u64, isize) {
    let mut x = 0u64;
    let mut s = 0u32;
    for (i, b) in buf.iter().enumerate() {
        if i == 10 {
            return (0, -(i as isize + 1));
        }
        if *b < 0x80 {
            if i == 9 && *b > 1 {
                return (0, -(i as isize + 1));
            }
            return (x | (u64::from(*b) << s), i as isize + 1);
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
    }
    (0, 0)
}

/// Encodes a strictly ascending index set (gov5 `EncodeMask`).
pub fn encode_mask(sorted: &[MobileIndex]) -> Result<Vec<u8>, MobileVerifyError> {
    let mut out = Vec::with_capacity(1 + sorted.len() * 2);
    put_uvarint(&mut out, sorted.len() as u64);
    let mut prev = 0u64;
    for (i, idx) in sorted.iter().enumerate() {
        let v = u64::from(*idx);
        if i == 0 {
            put_uvarint(&mut out, v);
        } else {
            if v <= prev {
                return Err(MobileVerifyError::BadMask(format!(
                    "indices not strictly ascending ({v} after {prev})"
                )));
            }
            put_uvarint(&mut out, v - prev - 1);
        }
        prev = v;
    }
    Ok(out)
}

/// Decodes and validates a mask against `registry_bound` (gov5 `DecodeMask`).
pub fn decode_mask(data: &[u8], registry_bound: usize) -> Result<Vec<MobileIndex>, MobileVerifyError> {
    let bad = |s: String| MobileVerifyError::BadMask(s);
    let (count, n) = uvarint(data);
    if n <= 0 {
        return Err(bad("bad count".into()));
    }
    let mut p = &data[n as usize..];
    let bound = registry_bound as u64;
    if count > p.len() as u64 || count > bound {
        return Err(bad(format!(
            "count {count} implausible (bytes={} registry={registry_bound})",
            p.len()
        )));
    }
    let mut out = Vec::with_capacity(count as usize);
    let mut cur = 0u64;
    for i in 0..count {
        let (d, n) = uvarint(p);
        if n <= 0 {
            return Err(bad(format!("truncated at entry {i}")));
        }
        p = &p[n as usize..];
        if i == 0 {
            cur = d;
        } else {
            if d == u64::MAX {
                return Err(bad(format!("delta overflow at entry {i}")));
            }
            let next = cur.wrapping_add(d).wrapping_add(1);
            if next < cur {
                return Err(bad(format!("index overflow at entry {i}")));
            }
            cur = next;
        }
        if cur >= bound {
            return Err(bad(format!("index {cur} beyond registry size {registry_bound}")));
        }
        out.push(cur as MobileIndex);
    }
    if !p.is_empty() {
        return Err(bad(format!("{} trailing bytes", p.len())));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for set in [vec![], vec![0], vec![5], vec![0, 1, 2], vec![3, 200, 201, 70_000]] {
            let m = encode_mask(&set).unwrap();
            assert_eq!(decode_mask(&m, 100_000).unwrap(), set);
        }
        assert_eq!(encode_mask(&[]).unwrap(), vec![0]);
        assert_eq!(encode_mask(&[3, 5, 6]).unwrap(), vec![3, 3, 1, 0]);
        assert_eq!(encode_mask(&[300]).unwrap(), vec![1, 0xac, 0x02]);
    }

    #[test]
    fn rejections() {
        let msg = |r: Result<Vec<MobileIndex>, MobileVerifyError>| r.unwrap_err().to_string();
        assert_eq!(msg(decode_mask(&[], 10)), "mobileverify: malformed signer mask: bad count");
        assert_eq!(
            msg(decode_mask(&[3, 0, 0], 10)),
            "mobileverify: malformed signer mask: count 3 implausible (bytes=2 registry=10)"
        );
        assert_eq!(
            msg(decode_mask(&[2, 0, 0], 1)),
            "mobileverify: malformed signer mask: count 2 implausible (bytes=2 registry=1)"
        );
        assert_eq!(
            msg(decode_mask(&[1, 10], 10)),
            "mobileverify: malformed signer mask: index 10 beyond registry size 10"
        );
        assert_eq!(msg(decode_mask(&[1, 1, 7], 10)), "mobileverify: malformed signer mask: 1 trailing bytes");
        assert_eq!(msg(decode_mask(&[2, 1, 0x80], 10)), "mobileverify: malformed signer mask: truncated at entry 1");
        let mut max = vec![2, 0];
        max.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        assert_eq!(msg(decode_mask(&max, 100)), "mobileverify: malformed signer mask: delta overflow at entry 1");
        assert!(encode_mask(&[2, 2]).is_err());
        assert!(encode_mask(&[3, 1]).is_err());
    }

    #[test]
    fn go_uvarint_edges() {
        assert_eq!(uvarint(&[0x80, 0x00]), (0, 2));
        assert_eq!(uvarint(&[0x80]), (0, 0));
        let over = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert_eq!(uvarint(&over), (0, -10));
        let eleven = [0x80; 11];
        assert_eq!(uvarint(&eleven), (0, -11));
    }
}
