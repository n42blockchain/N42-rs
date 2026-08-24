//! Batched blake3 compressions: N-way (16 AVX-512 / 8 AVX2) in transposed (SoA)
//! form, for internal-node hashing AND leaf hashing.
//!
//! `hash_node(left, right) = blake3(left || right)` is a 64-byte input — exactly
//! one blake3 compression with `CV = IV`, `block_len = 64`, `flags = CHUNK_START |
//! CHUNK_END | ROOT`. `hash_leaf(key, value) = blake3(0x01 || key || value)` is a
//! 65..=128-byte input for our 32/72-byte values — a TWO-compression chain
//! (block 1: flags=CHUNK_START, output is the chaining value; block 2:
//! flags=CHUNK_END|ROOT). Both reduce to the same lane-parallel compression core
//! parameterized by (cv, message, block_len, flags), mirroring gov5's Go
//! `compressNodes16AVX512` / `hashLeaves16` kernels.
//!
//! Correctness: every kernel is verified byte-for-byte against the `blake3` crate
//! in unit tests (random inputs incl. length edge cases), and the gov5 end-to-end
//! cross-checks pin the whole pipeline. Runtime detection picks AVX-512 → AVX2 →
//! scalar; `TWIG_NO_SIMD=1` forces scalar (A/B measurement, non-x86 parity).

use crate::{Hash, hash_leaf, hash_node};

/// blake3 IV (also the CV for a single-chunk input).
#[cfg(target_arch = "x86_64")]
const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// Per-round message word schedule (round r uses `m[MSG_SCHEDULE[r][i]]`),
/// from the blake3 reference implementation.
#[cfg(target_arch = "x86_64")]
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

#[cfg(target_arch = "x86_64")]
const FLAG_CHUNK_START: u32 = 0x01;
#[cfg(target_arch = "x86_64")]
const FLAG_CHUNK_END_ROOT: u32 = 0x0A; // CHUNK_END | ROOT
#[cfg(target_arch = "x86_64")]
const FLAG_SINGLE: u32 = 0x0B; // CHUNK_START | CHUNK_END | ROOT

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kernel {
    Scalar,
    #[cfg(target_arch = "x86_64")]
    Avx2,
    #[cfg(target_arch = "x86_64")]
    Avx512,
}

fn kernel() -> Kernel {
    use std::sync::OnceLock;
    static K: OnceLock<u8> = OnceLock::new();
    let v = *K.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            if std::env::var_os("TWIG_NO_SIMD").is_none() {
                if std::arch::is_x86_feature_detected!("avx512f") {
                    return 2;
                }
                if std::arch::is_x86_feature_detected!("avx2") {
                    return 1;
                }
            }
        }
        0
    });
    match v {
        #[cfg(target_arch = "x86_64")]
        2 => Kernel::Avx512,
        #[cfg(target_arch = "x86_64")]
        1 => Kernel::Avx2,
        _ => Kernel::Scalar,
    }
}

/// Active kernel name (diagnostics / benches).
pub fn kernel_name() -> &'static str {
    match kernel() {
        Kernel::Scalar => "scalar",
        #[cfg(target_arch = "x86_64")]
        Kernel::Avx2 => "avx2-8way",
        #[cfg(target_arch = "x86_64")]
        Kernel::Avx512 => "avx512-16way",
    }
}

/// `nodes[p] = hash_node(nodes[2p], nodes[2p+1])` for every `p` in `parents`,
/// batched across SIMD lanes when available.
///
/// Callers MUST pass parents from a single heap level (no parent an ancestor of
/// another), so every read (children) is disjoint from every write (parents) —
/// both `Twig::recompute` (whole levels) and `Twig::fold_batch` (level-by-level)
/// satisfy this by construction.
pub(crate) fn hash_parents(nodes: &mut [Hash], parents: &[usize]) {
    match kernel() {
        #[cfg(target_arch = "x86_64")]
        Kernel::Avx512 => unsafe { x86::hash_parents_avx512(nodes, parents) },
        #[cfg(target_arch = "x86_64")]
        Kernel::Avx2 => unsafe { x86::hash_parents_avx2(nodes, parents) },
        Kernel::Scalar => hash_parents_scalar(nodes, parents),
    }
}

fn hash_parents_scalar(nodes: &mut [Hash], parents: &[usize]) {
    for &p in parents {
        nodes[p] = hash_node(&nodes[2 * p], &nodes[2 * p + 1]);
    }
}

/// Batched `hash_leaf`: `out[i] = blake3(0x01 || keys[i] || values[i])` for every
/// job. Jobs whose total input (33 + value_len) exceeds 128 bytes fall back to the
/// scalar path; our account (72 B) and storage (32 B) values are always ≤ 128.
pub(crate) fn hash_leaves(jobs: &[(&Hash, &[u8])], out: &mut [Hash]) {
    debug_assert_eq!(jobs.len(), out.len());
    match kernel() {
        #[cfg(target_arch = "x86_64")]
        Kernel::Avx512 => unsafe { x86::hash_leaves_avx512(jobs, out) },
        #[cfg(target_arch = "x86_64")]
        Kernel::Avx2 => unsafe { x86::hash_leaves_avx2(jobs, out) },
        Kernel::Scalar => {
            for (o, (k, v)) in out.iter_mut().zip(jobs) {
                *o = hash_leaf(k, v);
            }
        }
    }
}

/// Batched single-block blake3 over arbitrary ≤64-byte inputs: `out[i] =
/// blake3(&msgs[i].0[..msgs[i].1 as usize])`. Each job carries its zero-padded
/// 64-byte block plus the true input length (per-lane `block_len`). This is what
/// key derivation reduces to: `account_key` is a 32-byte single-block input,
/// `storage_key` exactly 64 — both batch 16-wide on AVX-512.
pub fn hash_singleblock_batch(msgs: &[([u8; 64], u32)], out: &mut [Hash]) {
    debug_assert_eq!(msgs.len(), out.len());
    debug_assert!(msgs.iter().all(|(_, l)| *l <= 64));
    match kernel() {
        #[cfg(target_arch = "x86_64")]
        Kernel::Avx512 => unsafe { x86::hash_singleblock_avx512(msgs, out) },
        #[cfg(target_arch = "x86_64")]
        Kernel::Avx2 => unsafe { x86::hash_singleblock_avx2(msgs, out) },
        Kernel::Scalar => hash_singleblock_scalar(msgs, out),
    }
}

fn hash_singleblock_scalar(msgs: &[([u8; 64], u32)], out: &mut [Hash]) {
    for (o, (buf, len)) in out.iter_mut().zip(msgs) {
        *o = *blake3::hash(&buf[..*len as usize]).as_bytes();
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::*;
    use core::arch::x86_64::*;

    /// Gather one lane's 64-byte block (two adjacent child hashes) into the
    /// word-major transposed message buffer: `msg_t[w * LANES + lane]`.
    #[inline(always)]
    unsafe fn fill_lane<const LANES: usize>(
        msg_t: &mut [u32],
        nodes: &[Hash],
        lane: usize,
        parent: usize,
    ) {
        unsafe {
            let src = nodes.as_ptr().add(2 * parent) as *const u32;
            for w in 0..16 {
                msg_t[w * LANES + lane] = src.add(w).read_unaligned();
            }
        }
    }

    /// Scatter one lane's 32-byte output hash back to `nodes[parent]`.
    #[inline(always)]
    unsafe fn store_lane<const LANES: usize>(
        out_t: &[u32],
        nodes: &mut [Hash],
        lane: usize,
        parent: usize,
    ) {
        unsafe {
            let dst = nodes.as_mut_ptr().add(parent) as *mut u32;
            for w in 0..8 {
                dst.add(w).write_unaligned(out_t[w * LANES + lane]);
            }
        }
    }

    /// Transpose one lane's 128-byte (2-block) leaf input `0x01 || key || value`
    /// into the two word-major message buffers.
    #[inline(always)]
    fn fill_leaf_lane<const LANES: usize>(
        m1_t: &mut [u32],
        m2_t: &mut [u32],
        lane: usize,
        key: &Hash,
        value: &[u8],
    ) {
        let mut buf = [0u8; 128];
        buf[0] = 0x01;
        buf[1..33].copy_from_slice(key);
        buf[33..33 + value.len()].copy_from_slice(value);
        for w in 0..16 {
            m1_t[w * LANES + lane] = u32::from_le_bytes(buf[4 * w..4 * w + 4].try_into().unwrap());
            m2_t[w * LANES + lane] =
                u32::from_le_bytes(buf[64 + 4 * w..64 + 4 * w + 4].try_into().unwrap());
        }
    }

    // ── AVX-512: 16 lanes ──

    /// One lane-parallel blake3 compression: state words live across 16 lanes.
    /// Returns the 8-word output (`v[i] ^ v[i+8]`), which doubles as the chaining
    /// value for multi-block inputs.
    #[target_feature(enable = "avx512f")]
    unsafe fn core16(
        cv: &[__m512i; 8],
        m: &[__m512i; 16],
        len: __m512i,
        flags: u32,
    ) -> [__m512i; 8] {
        {
            macro_rules! bc {
                ($x:expr) => {
                    _mm512_set1_epi32($x as i32)
                };
            }
            let mut v = [
                cv[0],
                cv[1],
                cv[2],
                cv[3],
                cv[4],
                cv[5],
                cv[6],
                cv[7],
                bc!(IV[0]),
                bc!(IV[1]),
                bc!(IV[2]),
                bc!(IV[3]),
                _mm512_setzero_si512(), // counter_lo
                _mm512_setzero_si512(), // counter_hi
                len,
                bc!(flags),
            ];
            // G mixes lanes-parallel; rotr(n) == rotl(32-n) (VPROLD is AVX-512F).
            macro_rules! G {
                ($a:literal,$b:literal,$c:literal,$d:literal,$mx:expr,$my:expr) => {
                    v[$a] = _mm512_add_epi32(_mm512_add_epi32(v[$a], v[$b]), $mx);
                    v[$d] = _mm512_rol_epi32::<16>(_mm512_xor_si512(v[$d], v[$a]));
                    v[$c] = _mm512_add_epi32(v[$c], v[$d]);
                    v[$b] = _mm512_rol_epi32::<20>(_mm512_xor_si512(v[$b], v[$c]));
                    v[$a] = _mm512_add_epi32(_mm512_add_epi32(v[$a], v[$b]), $my);
                    v[$d] = _mm512_rol_epi32::<24>(_mm512_xor_si512(v[$d], v[$a]));
                    v[$c] = _mm512_add_epi32(v[$c], v[$d]);
                    v[$b] = _mm512_rol_epi32::<25>(_mm512_xor_si512(v[$b], v[$c]));
                };
            }
            for s in MSG_SCHEDULE.iter() {
                G!(0, 4, 8, 12, m[s[0]], m[s[1]]);
                G!(1, 5, 9, 13, m[s[2]], m[s[3]]);
                G!(2, 6, 10, 14, m[s[4]], m[s[5]]);
                G!(3, 7, 11, 15, m[s[6]], m[s[7]]);
                G!(0, 5, 10, 15, m[s[8]], m[s[9]]);
                G!(1, 6, 11, 12, m[s[10]], m[s[11]]);
                G!(2, 7, 8, 13, m[s[12]], m[s[13]]);
                G!(3, 4, 9, 14, m[s[14]], m[s[15]]);
            }
            [
                _mm512_xor_si512(v[0], v[8]),
                _mm512_xor_si512(v[1], v[9]),
                _mm512_xor_si512(v[2], v[10]),
                _mm512_xor_si512(v[3], v[11]),
                _mm512_xor_si512(v[4], v[12]),
                _mm512_xor_si512(v[5], v[13]),
                _mm512_xor_si512(v[6], v[14]),
                _mm512_xor_si512(v[7], v[15]),
            ]
        }
    }

    #[target_feature(enable = "avx512f")]
    unsafe fn load16(msg_t: &[u32], base: usize) -> [__m512i; 16] {
        unsafe {
            let mut m = [_mm512_setzero_si512(); 16];
            for (w, mv) in m.iter_mut().enumerate() {
                *mv = _mm512_loadu_si512(msg_t.as_ptr().add(base + w * 16) as *const _);
            }
            m
        }
    }

    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn hash_parents_avx512(nodes: &mut [Hash], parents: &[usize]) {
        unsafe {
            let mut i = 0usize;
            let mut msg_t = [0u32; 16 * 16];
            let mut out_t = [0u32; 8 * 16];
            let iv = [
                _mm512_set1_epi32(IV[0] as i32),
                _mm512_set1_epi32(IV[1] as i32),
                _mm512_set1_epi32(IV[2] as i32),
                _mm512_set1_epi32(IV[3] as i32),
                _mm512_set1_epi32(IV[4] as i32),
                _mm512_set1_epi32(IV[5] as i32),
                _mm512_set1_epi32(IV[6] as i32),
                _mm512_set1_epi32(IV[7] as i32),
            ];
            let len64 = _mm512_set1_epi32(64);
            while i + 16 <= parents.len() {
                for l in 0..16 {
                    fill_lane::<16>(&mut msg_t, nodes, l, parents[i + l]);
                }
                let m = load16(&msg_t, 0);
                let o = core16(&iv, &m, len64, FLAG_SINGLE);
                for (w, ov) in o.iter().enumerate() {
                    _mm512_storeu_si512(out_t.as_mut_ptr().add(w * 16) as *mut _, *ov);
                }
                for l in 0..16 {
                    store_lane::<16>(&out_t, nodes, l, parents[i + l]);
                }
                i += 16;
            }
            hash_parents_scalar(nodes, &parents[i..]);
        }
    }

    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn hash_singleblock_avx512(msgs: &[([u8; 64], u32)], out: &mut [Hash]) {
        unsafe {
            let iv = [
                _mm512_set1_epi32(IV[0] as i32),
                _mm512_set1_epi32(IV[1] as i32),
                _mm512_set1_epi32(IV[2] as i32),
                _mm512_set1_epi32(IV[3] as i32),
                _mm512_set1_epi32(IV[4] as i32),
                _mm512_set1_epi32(IV[5] as i32),
                _mm512_set1_epi32(IV[6] as i32),
                _mm512_set1_epi32(IV[7] as i32),
            ];
            let mut msg_t = [0u32; 16 * 16];
            let mut lens = [0i32; 16];
            let mut out_t = [0u32; 8 * 16];
            let mut i = 0usize;
            while i + 16 <= msgs.len() {
                for l in 0..16 {
                    let (buf, len) = &msgs[i + l];
                    lens[l] = *len as i32;
                    for w in 0..16 {
                        msg_t[w * 16 + l] =
                            u32::from_le_bytes(buf[4 * w..4 * w + 4].try_into().unwrap());
                    }
                }
                let m = load16(&msg_t, 0);
                let len_v = _mm512_loadu_si512(lens.as_ptr() as *const _);
                let o = core16(&iv, &m, len_v, FLAG_SINGLE);
                for (w, ov) in o.iter().enumerate() {
                    _mm512_storeu_si512(out_t.as_mut_ptr().add(w * 16) as *mut _, *ov);
                }
                for l in 0..16 {
                    let dst = out.as_mut_ptr().add(i + l) as *mut u32;
                    for w in 0..8 {
                        dst.add(w).write_unaligned(out_t[w * 16 + l]);
                    }
                }
                i += 16;
            }
            hash_singleblock_scalar(&msgs[i..], &mut out[i..]);
        }
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn hash_singleblock_avx2(msgs: &[([u8; 64], u32)], out: &mut [Hash]) {
        unsafe {
            let iv = [
                _mm256_set1_epi32(IV[0] as i32),
                _mm256_set1_epi32(IV[1] as i32),
                _mm256_set1_epi32(IV[2] as i32),
                _mm256_set1_epi32(IV[3] as i32),
                _mm256_set1_epi32(IV[4] as i32),
                _mm256_set1_epi32(IV[5] as i32),
                _mm256_set1_epi32(IV[6] as i32),
                _mm256_set1_epi32(IV[7] as i32),
            ];
            let mut msg_t = [0u32; 16 * 8];
            let mut lens = [0i32; 8];
            let mut out_t = [0u32; 8 * 8];
            let mut i = 0usize;
            while i + 8 <= msgs.len() {
                for l in 0..8 {
                    let (buf, len) = &msgs[i + l];
                    lens[l] = *len as i32;
                    for w in 0..16 {
                        msg_t[w * 8 + l] =
                            u32::from_le_bytes(buf[4 * w..4 * w + 4].try_into().unwrap());
                    }
                }
                let m = load8(&msg_t, 0);
                let len_v = _mm256_loadu_si256(lens.as_ptr() as *const _);
                let o = core8(&iv, &m, len_v, FLAG_SINGLE);
                for (w, ov) in o.iter().enumerate() {
                    _mm256_storeu_si256(out_t.as_mut_ptr().add(w * 8) as *mut _, *ov);
                }
                for l in 0..8 {
                    let dst = out.as_mut_ptr().add(i + l) as *mut u32;
                    for w in 0..8 {
                        dst.add(w).write_unaligned(out_t[w * 8 + l]);
                    }
                }
                i += 8;
            }
            hash_singleblock_scalar(&msgs[i..], &mut out[i..]);
        }
    }

    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn hash_leaves_avx512(jobs: &[(&Hash, &[u8])], out: &mut [Hash]) {
        unsafe {
            let iv = [
                _mm512_set1_epi32(IV[0] as i32),
                _mm512_set1_epi32(IV[1] as i32),
                _mm512_set1_epi32(IV[2] as i32),
                _mm512_set1_epi32(IV[3] as i32),
                _mm512_set1_epi32(IV[4] as i32),
                _mm512_set1_epi32(IV[5] as i32),
                _mm512_set1_epi32(IV[6] as i32),
                _mm512_set1_epi32(IV[7] as i32),
            ];
            let len64 = _mm512_set1_epi32(64);
            let mut m1_t = [0u32; 16 * 16];
            let mut m2_t = [0u32; 16 * 16];
            let mut lens = [0i32; 16];
            let mut out_t = [0u32; 8 * 16];
            // Lane assignment for the current batch: indices of 2-block jobs.
            let mut lanes = [0usize; 16];
            let mut n = 0usize;
            let flush = |lanes: &[usize; 16],
                         n: usize,
                         m1_t: &mut [u32; 256],
                         m2_t: &mut [u32; 256],
                         lens: &mut [i32; 16],
                         out_t: &mut [u32; 128],
                         out: &mut [Hash]| {
                if n == 0 {
                    return;
                }
                // Pad unused lanes by reusing lane 0's input (results discarded).
                for l in n..16 {
                    for w in 0..16 {
                        m1_t[w * 16 + l] = m1_t[w * 16];
                        m2_t[w * 16 + l] = m2_t[w * 16];
                    }
                    lens[l] = lens[0];
                }
                let m1 = load16(&m1_t[..], 0);
                let cv = core16(&iv, &m1, len64, FLAG_CHUNK_START);
                let m2 = load16(&m2_t[..], 0);
                let len2 = _mm512_loadu_si512(lens.as_ptr() as *const _);
                let o = core16(&cv, &m2, len2, FLAG_CHUNK_END_ROOT);
                for (w, ov) in o.iter().enumerate() {
                    _mm512_storeu_si512(out_t.as_mut_ptr().add(w * 16) as *mut _, *ov);
                }
                for (l, &j) in lanes.iter().take(n).enumerate() {
                    let dst = out.as_mut_ptr().add(j) as *mut u32;
                    for w in 0..8 {
                        dst.add(w).write_unaligned(out_t[w * 16 + l]);
                    }
                }
            };
            for (j, (k, v)) in jobs.iter().enumerate() {
                let total = 33 + v.len();
                if total <= 64 || total > 128 {
                    out[j] = hash_leaf(k, v); // rare sizes: scalar
                    continue;
                }
                fill_leaf_lane::<16>(&mut m1_t, &mut m2_t, n, k, v);
                lens[n] = (total - 64) as i32;
                lanes[n] = j;
                n += 1;
                if n == 16 {
                    flush(&lanes, n, &mut m1_t, &mut m2_t, &mut lens, &mut out_t, out);
                    n = 0;
                }
            }
            flush(&lanes, n, &mut m1_t, &mut m2_t, &mut lens, &mut out_t, out);
        }
    }

    // ── AVX2: 8 lanes ──

    /// 8-lane variant of [`core16`] (AVX2 has no native rotate: shift+or).
    #[target_feature(enable = "avx2")]
    unsafe fn core8(
        cv: &[__m256i; 8],
        m: &[__m256i; 16],
        len: __m256i,
        flags: u32,
    ) -> [__m256i; 8] {
        {
            macro_rules! bc {
                ($x:expr) => {
                    _mm256_set1_epi32($x as i32)
                };
            }
            let mut v = [
                cv[0],
                cv[1],
                cv[2],
                cv[3],
                cv[4],
                cv[5],
                cv[6],
                cv[7],
                bc!(IV[0]),
                bc!(IV[1]),
                bc!(IV[2]),
                bc!(IV[3]),
                _mm256_setzero_si256(),
                _mm256_setzero_si256(),
                len,
                bc!(flags),
            ];
            macro_rules! rotr {
                ($x:expr, $r:literal, $l:literal) => {
                    _mm256_or_si256(_mm256_srli_epi32::<$r>($x), _mm256_slli_epi32::<$l>($x))
                };
            }
            macro_rules! G {
                ($a:literal,$b:literal,$c:literal,$d:literal,$mx:expr,$my:expr) => {
                    v[$a] = _mm256_add_epi32(_mm256_add_epi32(v[$a], v[$b]), $mx);
                    v[$d] = rotr!(_mm256_xor_si256(v[$d], v[$a]), 16, 16);
                    v[$c] = _mm256_add_epi32(v[$c], v[$d]);
                    v[$b] = rotr!(_mm256_xor_si256(v[$b], v[$c]), 12, 20);
                    v[$a] = _mm256_add_epi32(_mm256_add_epi32(v[$a], v[$b]), $my);
                    v[$d] = rotr!(_mm256_xor_si256(v[$d], v[$a]), 8, 24);
                    v[$c] = _mm256_add_epi32(v[$c], v[$d]);
                    v[$b] = rotr!(_mm256_xor_si256(v[$b], v[$c]), 7, 25);
                };
            }
            for s in MSG_SCHEDULE.iter() {
                G!(0, 4, 8, 12, m[s[0]], m[s[1]]);
                G!(1, 5, 9, 13, m[s[2]], m[s[3]]);
                G!(2, 6, 10, 14, m[s[4]], m[s[5]]);
                G!(3, 7, 11, 15, m[s[6]], m[s[7]]);
                G!(0, 5, 10, 15, m[s[8]], m[s[9]]);
                G!(1, 6, 11, 12, m[s[10]], m[s[11]]);
                G!(2, 7, 8, 13, m[s[12]], m[s[13]]);
                G!(3, 4, 9, 14, m[s[14]], m[s[15]]);
            }
            [
                _mm256_xor_si256(v[0], v[8]),
                _mm256_xor_si256(v[1], v[9]),
                _mm256_xor_si256(v[2], v[10]),
                _mm256_xor_si256(v[3], v[11]),
                _mm256_xor_si256(v[4], v[12]),
                _mm256_xor_si256(v[5], v[13]),
                _mm256_xor_si256(v[6], v[14]),
                _mm256_xor_si256(v[7], v[15]),
            ]
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn load8(msg_t: &[u32], base: usize) -> [__m256i; 16] {
        unsafe {
            let mut m = [_mm256_setzero_si256(); 16];
            for (w, mv) in m.iter_mut().enumerate() {
                *mv = _mm256_loadu_si256(msg_t.as_ptr().add(base + w * 8) as *const _);
            }
            m
        }
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn hash_parents_avx2(nodes: &mut [Hash], parents: &[usize]) {
        unsafe {
            let mut i = 0usize;
            let mut msg_t = [0u32; 16 * 8];
            let mut out_t = [0u32; 8 * 8];
            let iv = [
                _mm256_set1_epi32(IV[0] as i32),
                _mm256_set1_epi32(IV[1] as i32),
                _mm256_set1_epi32(IV[2] as i32),
                _mm256_set1_epi32(IV[3] as i32),
                _mm256_set1_epi32(IV[4] as i32),
                _mm256_set1_epi32(IV[5] as i32),
                _mm256_set1_epi32(IV[6] as i32),
                _mm256_set1_epi32(IV[7] as i32),
            ];
            let len64 = _mm256_set1_epi32(64);
            while i + 8 <= parents.len() {
                for l in 0..8 {
                    fill_lane::<8>(&mut msg_t, nodes, l, parents[i + l]);
                }
                let m = load8(&msg_t, 0);
                let o = core8(&iv, &m, len64, FLAG_SINGLE);
                for (w, ov) in o.iter().enumerate() {
                    _mm256_storeu_si256(out_t.as_mut_ptr().add(w * 8) as *mut _, *ov);
                }
                for l in 0..8 {
                    store_lane::<8>(&out_t, nodes, l, parents[i + l]);
                }
                i += 8;
            }
            hash_parents_scalar(nodes, &parents[i..]);
        }
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn hash_leaves_avx2(jobs: &[(&Hash, &[u8])], out: &mut [Hash]) {
        unsafe {
            let iv = [
                _mm256_set1_epi32(IV[0] as i32),
                _mm256_set1_epi32(IV[1] as i32),
                _mm256_set1_epi32(IV[2] as i32),
                _mm256_set1_epi32(IV[3] as i32),
                _mm256_set1_epi32(IV[4] as i32),
                _mm256_set1_epi32(IV[5] as i32),
                _mm256_set1_epi32(IV[6] as i32),
                _mm256_set1_epi32(IV[7] as i32),
            ];
            let len64 = _mm256_set1_epi32(64);
            let mut m1_t = [0u32; 16 * 8];
            let mut m2_t = [0u32; 16 * 8];
            let mut lens = [0i32; 8];
            let mut out_t = [0u32; 8 * 8];
            let mut lanes = [0usize; 8];
            let mut n = 0usize;
            let flush = |lanes: &[usize; 8],
                         n: usize,
                         m1_t: &mut [u32; 128],
                         m2_t: &mut [u32; 128],
                         lens: &mut [i32; 8],
                         out_t: &mut [u32; 64],
                         out: &mut [Hash]| {
                if n == 0 {
                    return;
                }
                for l in n..8 {
                    for w in 0..16 {
                        m1_t[w * 8 + l] = m1_t[w * 8];
                        m2_t[w * 8 + l] = m2_t[w * 8];
                    }
                    lens[l] = lens[0];
                }
                let m1 = load8(&m1_t[..], 0);
                let cv = core8(&iv, &m1, len64, FLAG_CHUNK_START);
                let m2 = load8(&m2_t[..], 0);
                let len2 = _mm256_loadu_si256(lens.as_ptr() as *const _);
                let o = core8(&cv, &m2, len2, FLAG_CHUNK_END_ROOT);
                for (w, ov) in o.iter().enumerate() {
                    _mm256_storeu_si256(out_t.as_mut_ptr().add(w * 8) as *mut _, *ov);
                }
                for (l, &j) in lanes.iter().take(n).enumerate() {
                    let dst = out.as_mut_ptr().add(j) as *mut u32;
                    for w in 0..8 {
                        dst.add(w).write_unaligned(out_t[w * 8 + l]);
                    }
                }
            };
            for (j, (k, v)) in jobs.iter().enumerate() {
                let total = 33 + v.len();
                if total <= 64 || total > 128 {
                    out[j] = hash_leaf(k, v);
                    continue;
                }
                fill_leaf_lane::<8>(&mut m1_t, &mut m2_t, n, k, v);
                lens[n] = (total - 64) as i32;
                lanes[n] = j;
                n += 1;
                if n == 8 {
                    flush(&lanes, n, &mut m1_t, &mut m2_t, &mut lens, &mut out_t, out);
                    n = 0;
                }
            }
            flush(&lanes, n, &mut m1_t, &mut m2_t, &mut lens, &mut out_t, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_nodes(n: usize) -> Vec<Hash> {
        let mut rng = rand::rng();
        let mut v = vec![[0u8; 32]; n];
        for h in &mut v {
            rng.fill_bytes(h);
        }
        v
    }

    /// Expected results straight from the blake3 crate (the scalar reference).
    fn expected(nodes: &[Hash], parents: &[usize]) -> Vec<Hash> {
        parents
            .iter()
            .map(|&p| hash_node(&nodes[2 * p], &nodes[2 * p + 1]))
            .collect()
    }

    fn check(parents_len: usize) {
        // Heap-like layout: parents in [1, 64), children at 2p / 2p+1 < 128.
        let nodes = random_nodes(128);
        let parents: Vec<usize> = (1..1 + parents_len).collect();
        let want = expected(&nodes, &parents);

        // Dispatcher (whatever this CPU picks).
        let mut got = nodes.clone();
        hash_parents(&mut got, &parents);
        for (i, &p) in parents.iter().enumerate() {
            assert_eq!(got[p], want[i], "dispatcher lane {i} (parent {p})");
        }

        // Force each wide kernel when the CPU supports it.
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                let mut got = nodes.clone();
                unsafe { x86::hash_parents_avx2(&mut got, &parents) };
                for (i, &p) in parents.iter().enumerate() {
                    assert_eq!(got[p], want[i], "avx2 lane {i} (parent {p})");
                }
            }
            if std::arch::is_x86_feature_detected!("avx512f") {
                let mut got = nodes.clone();
                unsafe { x86::hash_parents_avx512(&mut got, &parents) };
                for (i, &p) in parents.iter().enumerate() {
                    assert_eq!(got[p], want[i], "avx512 lane {i} (parent {p})");
                }
            }
        }
    }

    #[test]
    fn kernels_match_blake3_crate() {
        // Cover full batches, tails, and sub-width sizes across many random runs.
        for len in [1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 48, 63] {
            for _ in 0..50 {
                check(len);
            }
        }
    }

    #[test]
    fn all_zero_inputs_match() {
        // The all-null subtree case (null_level) must also agree.
        let nodes = vec![[0u8; 32]; 128];
        let parents: Vec<usize> = (1..33).collect();
        let want = expected(&nodes, &parents);
        let mut got = nodes.clone();
        hash_parents(&mut got, &parents);
        for (i, &p) in parents.iter().enumerate() {
            assert_eq!(got[p], want[i]);
        }
    }

    #[test]
    fn singleblock_kernels_match_blake3_crate() {
        let mut rng = rand::rng();
        // Key-derivation shapes: 32 B (account = domain+addr) and 64 B (storage),
        // plus odd lengths and batch sizes that exercise tails.
        for batch in [1usize, 7, 8, 9, 16, 17, 33, 50] {
            let mut msgs = Vec::new();
            for i in 0..batch {
                let mut buf = [0u8; 64];
                let len = [32u32, 64, 1, 20, 63, 12][i % 6];
                let mut tmp = vec![0u8; len as usize];
                rng.fill_bytes(&mut tmp);
                buf[..len as usize].copy_from_slice(&tmp);
                msgs.push((buf, len));
            }
            let want: Vec<Hash> = msgs
                .iter()
                .map(|(b, l)| *blake3::hash(&b[..*l as usize]).as_bytes())
                .collect();
            let mut got = vec![[0u8; 32]; batch];
            hash_singleblock_batch(&msgs, &mut got);
            assert_eq!(got, want, "dispatcher batch {batch}");

            #[cfg(target_arch = "x86_64")]
            {
                if std::arch::is_x86_feature_detected!("avx2") {
                    let mut got = vec![[0u8; 32]; batch];
                    unsafe { x86::hash_singleblock_avx2(&msgs, &mut got) };
                    assert_eq!(got, want, "avx2 batch {batch}");
                }
                if std::arch::is_x86_feature_detected!("avx512f") {
                    let mut got = vec![[0u8; 32]; batch];
                    unsafe { x86::hash_singleblock_avx512(&msgs, &mut got) };
                    assert_eq!(got, want, "avx512 batch {batch}");
                }
            }
        }
    }

    #[test]
    fn leaf_kernels_match_blake3_crate() {
        let mut rng = rand::rng();
        // Mixed value lengths incl. the real account (72) / storage (32) sizes and
        // boundary cases: ≤31 single-block scalar path, 95 = max 2-block, >95 scalar.
        let lens = [0usize, 1, 31, 32, 33, 63, 64, 72, 95, 96, 200];
        for batch in [1usize, 5, 8, 9, 16, 17, 40] {
            let mut keys = Vec::new();
            let mut vals = Vec::new();
            for i in 0..batch {
                let mut k = [0u8; 32];
                rng.fill_bytes(&mut k);
                keys.push(k);
                let mut v = vec![0u8; lens[i % lens.len()]];
                rng.fill_bytes(&mut v);
                vals.push(v);
            }
            let jobs: Vec<(&Hash, &[u8])> =
                keys.iter().zip(vals.iter().map(|v| v.as_slice())).collect();
            let want: Vec<Hash> = jobs.iter().map(|(k, v)| hash_leaf(k, v)).collect();
            let mut got = vec![[0u8; 32]; jobs.len()];
            hash_leaves(&jobs, &mut got);
            assert_eq!(got, want, "dispatcher leaves batch {batch}");

            #[cfg(target_arch = "x86_64")]
            {
                if std::arch::is_x86_feature_detected!("avx2") {
                    let mut got = vec![[0u8; 32]; jobs.len()];
                    unsafe { x86::hash_leaves_avx2(&jobs, &mut got) };
                    assert_eq!(got, want, "avx2 leaves batch {batch}");
                }
                if std::arch::is_x86_feature_detected!("avx512f") {
                    let mut got = vec![[0u8; 32]; jobs.len()];
                    unsafe { x86::hash_leaves_avx512(&jobs, &mut got) };
                    assert_eq!(got, want, "avx512 leaves batch {batch}");
                }
            }
        }
    }
}
