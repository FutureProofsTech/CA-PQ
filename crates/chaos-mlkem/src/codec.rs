//! Sampling, compression, and byte codec for ML-KEM-768.
//!
//! All routines are generic bit-exact transcriptions: LSB-first packing,
//! centered binomial sampling, rounded compression. ETA1 = ETA2 = 2, so only
//! CBD_2 exists here; encode widths used: 1, 4, 10, 12.

#![forbid(unsafe_code)]

use super::ntt::{N, Q};
use chaos_hash::Shake128;
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use chaos_hash::{shake128_squeeze_x4, shake256_squeeze_x4};

/// LSB-first pack of 256 coefficients, each `< 2^D`, into `32*D` bytes.
pub fn byte_encode<const D: usize, const OUT: usize>(f: &[i16; N]) -> [u8; OUT] {
    debug_assert_eq!(OUT, 32 * D);
    let mut out = [0u8; OUT];
    let mut bit = 0usize;
    for &c in f.iter() {
        let v = (c as u16) & ((1u16 << D) - 1);
        for b in 0..D {
            if (v >> b) & 1 == 1 {
                out[bit / 8] |= 1 << (bit % 8);
            }
            bit += 1;
        }
    }
    out
}

/// Inverse of [`byte_encode`].
pub fn byte_decode<const D: usize, const INP: usize>(b: &[u8; INP]) -> [i16; N] {
    debug_assert_eq!(INP, 32 * D);
    let mut f = [0i16; N];
    let mut bit = 0usize;
    for fv in f.iter_mut() {
        let mut v = 0u16;
        for bb in 0..D {
            if (b[bit / 8] >> (bit % 8)) & 1 == 1 {
                v |= 1 << bb;
            }
            bit += 1;
        }
        *fv = v as i16;
    }
    f
}

/// Compress_d: round(2^d/q * x) mod 2^d, exact integer half-up rounding.
pub fn compress<const D: usize>(f: &[i16; N]) -> [i16; N] {
    let mask = ((1u32 << D) - 1) as i16;
    let mut r = [0i16; N];
    for (i, o) in r.iter_mut().enumerate() {
        let t = (((f[i] as u32) << D) + (Q as u32 / 2)) / Q as u32;
        *o = (t as i16) & mask;
    }
    r
}

/// Decompress_d: round(q/2^d * y), exact integer half-up rounding.
pub fn decompress<const D: usize>(f: &[i16; N]) -> [i16; N] {
    let mut r = [0i16; N];
    for (i, o) in r.iter_mut().enumerate() {
        *o = (((Q as u32 * f[i] as u32) + (1u32 << (D - 1))) >> D) as i16;
    }
    r
}

/// Centered binomial distribution for eta = 2 or 3: `64*eta` bytes ->
/// 256 coeffs in [0,q). Bit-exact vs the old `cbd2` at eta = 2 (same bit
/// order, same modular fixup); eta = 3 is the ML-KEM-512 noise shape.
pub fn cbd_eta(eta: usize, b: &[u8]) -> [i16; N] {
    assert!(eta == 2 || eta == 3);
    assert_eq!(b.len(), 64 * eta);
    let mut f = [0i16; N];
    for i in 0..N {
        let mut a = 0i32;
        let mut bb = 0i32;
        for j in 0..eta {
            a += ((b[(2 * eta * i + j) / 8] >> ((2 * eta * i + j) % 8)) & 1) as i32;
            bb += ((b[(2 * eta * i + eta + j) / 8] >> ((2 * eta * i + eta + j) % 8)) & 1) as i32;
        }
        f[i] = (((a - bb) % Q + Q) % Q) as i16;
    }
    f
}

/// Sample a matrix entry directly in the NTT domain (rejection sampling).
/// Squeezes incrementally: average ~470 B, versus a fixed 2100 B buffer —
/// identical byte stream, ~4x less hashing. The refill cap (64 blocks) is
/// unreachable for real seeds; it only documents termination.
pub fn sample_ntt(seed: &[u8; 32], i: u8, j: u8) -> [i16; N] {
    let mut inp = [0u8; 34];
    inp[..32].copy_from_slice(seed);
    inp[32] = i;
    inp[33] = j;
    let mut s = Shake128::new();
    s.absorb(&inp);
    let mut sq = s.streamer();
    let mut buf = [0u8; 168];
    let mut valid = 0usize;
    let mut pos = 0usize;
    let mut refills = 0u32;
    let mut coeffs = [0i16; N];
    let mut n = 0usize;
    while n < N {
        if pos + 3 > valid {
            // Compact leftovers, then refill to a full block.
            let mut k = 0usize;
            while pos < valid {
                buf[k] = buf[pos];
                k += 1;
                pos += 1;
            }
            sq.squeeze(&mut buf[k..]);
            valid = 168;
            pos = 0;
            refills += 1;
            assert!(refills < 64, "SHAKE stream exhausted (impossible)");
        }
        let (b0, b1, b2) = (buf[pos] as i32, buf[pos + 1] as i32, buf[pos + 2] as i32);
        pos += 3;
        let d1 = b0 + 256 * (b1 % 16);
        let d2 = (b1 / 16) + 16 * b2;
        if d1 < Q && n < N {
            coeffs[n] = d1 as i16;
            n += 1;
        }
        if d2 < Q && n < N {
            coeffs[n] = d2 as i16;
            n += 1;
        }
    }
    coeffs
}

/// Four parallel `sample_ntt` streams (AVX2 builds only).
///
/// Each lane squeezes a FIXED 840 B (5 rate blocks) through the joint 4-way
/// XOF, then rejection-samples scalar. 840 B give 560 12-bit candidates at
/// accept probability 3329/4096: mean 455 accepts, ~9 sigma from the 256
/// needed — the scalar-restart fallback below is a termination safety net
/// that never triggers in practice, and when it does it returns the exact
/// same poly as the scalar path (same byte stream, same parse).
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub fn sample_ntt_x4(seed: &[u8; 32], ijs: [(u8, u8); 4]) -> [[i16; N]; 4] {
    const OUT: usize = 840;
    let mut inputs = [[0u8; 34]; 4];
    for (dst, &(i, j)) in inputs.iter_mut().zip(ijs.iter()) {
        dst[..32].copy_from_slice(seed);
        dst[32] = i;
        dst[33] = j;
    }
    let mut bufs = [[0u8; OUT]; 4];
    {
        let [b0, b1, b2, b3] = &mut bufs;
        shake128_squeeze_x4(
            [
                &inputs[0] as &[u8],
                &inputs[1] as &[u8],
                &inputs[2] as &[u8],
                &inputs[3] as &[u8],
            ],
            [&mut b0[..], &mut b1[..], &mut b2[..], &mut b3[..]],
        );
    }
    let mut out = [[0i16; N]; 4];
    for (lane, poly) in out.iter_mut().enumerate() {
        let buf = &bufs[lane];
        let mut n = 0usize;
        let mut pos = 0usize;
        while n < N && pos + 3 <= OUT {
            let (b0, b1, b2) = (buf[pos] as i32, buf[pos + 1] as i32, buf[pos + 2] as i32);
            pos += 3;
            let d1 = b0 + 256 * (b1 % 16);
            let d2 = (b1 / 16) + 16 * b2;
            if d1 < Q && n < N {
                poly[n] = d1 as i16;
                n += 1;
            }
            if d2 < Q && n < N {
                poly[n] = d2 as i16;
                n += 1;
            }
        }
        if n < N {
            // Safety net only (21-sigma event): exact scalar resample.
            *poly = sample_ntt(seed, ijs[lane].0, ijs[lane].1);
        }
    }
    out
}

/// Four parallel PRF streams (AVX2 builds only): same seed, four counter
/// bytes, 192 B each (covers eta = 3; eta = 2 callers use the 128 B prefix —
/// identical bytes to four scalar `prf_eta` calls, XOF prefix property).
/// Byte-exact; KATs pin both paths.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub fn prf_x4(s: &[u8; 32], ctrs: [u8; 4]) -> [[u8; 192]; 4] {
    let mut inputs = [[0u8; 33]; 4];
    for (dst, &b) in inputs.iter_mut().zip(ctrs.iter()) {
        dst[..32].copy_from_slice(s);
        dst[32] = b;
    }
    let mut out = [[0u8; 192]; 4];
    {
        let [o0, o1, o2, o3] = &mut out;
        shake256_squeeze_x4(
            [
                &inputs[0] as &[u8],
                &inputs[1] as &[u8],
                &inputs[2] as &[u8],
                &inputs[3] as &[u8],
            ],
            [&mut o0[..], &mut o1[..], &mut o2[..], &mut o3[..]],
        );
    }
    out
}

/// PRF_eta: SHAKE256(s || b) -> 64*eta bytes (eta = 2 or 3).
pub fn prf_eta(eta: usize, s: &[u8; 32], b: u8, out: &mut [u8]) {
    assert!(eta == 2 || eta == 3);
    assert_eq!(out.len(), 64 * eta);
    let mut inp = [0u8; 33];
    inp[..32].copy_from_slice(s);
    inp[32] = b;
    crate::shake256_raw(&inp, out);
}
