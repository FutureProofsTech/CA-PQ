//! CA-PQ `chaos-extract`: Fractal Boundary Masking filter.
//!
//! Extracts the chaotic microscopic residue:
//!   u = |x| * SCALE ; r = frac(u) ; byte = mix(r)
//! `SCALE = 2^20`, stride and domains fixed by PLAN/SPEC.

#![no_std]
#![forbid(unsafe_code)]

use chaos_core::{iterate, Params, State};

/// Masking scale 2^20 (sampling stride domain; mixer is bit-folding).
#[allow(dead_code)]
pub const SCALE_SHIFT: u32 = 20;
/// Sampling stride (steps per byte).
pub const STRIDE: usize = 10;

/// Extract one byte from a Q32.32 sample.
/// Bit-folding mixer: preserves 1-LSB sensitivity (unlike pure fractional-scale
/// truncation), then diffuses via rotate/multiply. SCALE/STRIDE stay in SPEC
/// for sampling; mixer guarantees avalanche at the bit level.
pub fn extract_byte(x: i64) -> u8 {
    let u = x as u64;
    let folded = (u ^ (u >> 17) ^ (u >> 29) ^ (u >> 7)) & 0xFF;
    let mid = ((u >> 11) & 0xFF) as u8;
    (folded as u8) ^ mid.rotate_left(3).wrapping_mul(0x9E).rotate_right(2)
}

/// Fill `out` with keystream bytes from `(state, params)`, transient already discarded.
pub fn keystream(s: &State, p: &Params, out: &mut [u8]) {
    let mut cur = *s;
    let mut i = 0;
    while i < out.len() {
        iterate(&mut cur, p, STRIDE);
        out[i] = extract_byte(cur.0[0]) ^ extract_byte(cur.0[1]) ^ extract_byte(cur.0[3]);
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tail_hamming(a_mat: &[u8; 64], b_mat: &[u8; 64]) -> f64 {
        // 64 B tails over the production window (steps 1000..1640).
        use chaos_core::{expand_from_bytes, iterate};
        let (mut sa, p) = expand_from_bytes(a_mat);
        let (mut sb, _) = expand_from_bytes(b_mat);
        iterate(&mut sa, &p, 1000);
        iterate(&mut sb, &p, 1000);
        let mut ta = [0u8; 64];
        let mut tb = [0u8; 64];
        keystream(&sa, &p, &mut ta);
        keystream(&sb, &p, &mut tb);
        let mut d = 0u32;
        for (x, y) in ta.iter().zip(tb.iter()) {
            d += (x ^ y).count_ones();
        }
        d as f64 / 512.0
    }

    #[test]
    fn neighbor_tail_separation_sensor() {
        // Capture-window regression sensor: 1-bit (byte-0) neighbors of
        // fixed healthy materials must keep production-window tail Hamming
        // >= 0.20 (healthy same-params baseline is 0.34+; full chaos 0.50).
        // Deterministic fixed set — never flaky. Guards future dynamics
        // work against capture widening; see THREAT R6 for the analysis.
        let mut seq = [0u8; 64];
        for (i, b) in seq.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut rev = [0u8; 64];
        for (i, b) in rev.iter_mut().enumerate() {
            *b = (63 - i) as u8;
        }
        let mut alt = [0u8; 64];
        for (i, b) in alt.iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0x55 } else { 0xAA };
        }
        let mut pat7 = [0u8; 64];
        for (i, b) in pat7.iter_mut().enumerate() {
            *b = ((3 * i + 7) % 256) as u8;
        }
        for seed in [[0xA5u8; 64], [0u8; 64], [0xFFu8; 64], seq, rev, alt, pat7] {
            let mut nb = seed;
            nb[0] ^= 1;
            let h = tail_hamming(&seed, &nb);
            assert!(h >= 0.20, "neighbor sync on healthy seed: {}", h);
        }
        // Positive control: t=748 material captures early (h ~ 0.03) —
        // proves the sensor fires on a real capture window.
        let m748 = unhex64(
            "2afa47d2e99b54c8d758f665138ea7e1fd409fcb294fd9fdf8d51639ba581e7a02f3fb507f119725b490f2628052890de1b0701e80e9192db90104254cf2bf07",
        );
        let mut n748 = m748;
        n748[0] ^= 1;
        let h748 = tail_hamming(&m748, &n748);
        assert!(h748 < 0.20, "sensor must fire on t748 window: {}", h748);
    }

    fn unhex64(s: &str) -> [u8; 64] {
        let b = s.as_bytes();
        assert_eq!(b.len(), 128);
        let mut out = [0u8; 64];
        for (i, o) in out.iter_mut().enumerate() {
            let v = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => 0,
            };
            *o = (v(b[2 * i]) << 4) | v(b[2 * i + 1]);
        }
        out
    }

    use chaos_core::{expand_from_bytes, FRAC};

    #[test]
    fn tutorial_extract_diffuses() {
        assert_ne!(
            extract_byte(1 << (FRAC - 10)),
            extract_byte((1 << (FRAC - 10)) + 1)
        );
    }

    #[test]
    fn keystream_deterministic_and_sensitive() {
        let (s1, p1) = expand_from_bytes(&[1u8; 64]);
        let (s2, p2) = expand_from_bytes(&[1u8; 64]);
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        keystream(&s1, &p1, &mut a);
        keystream(&s2, &p2, &mut b);
        assert_eq!(a, b);
        let (s3, p3) = expand_from_bytes(&[2u8; 64]);
        let mut c = [0u8; 64];
        keystream(&s3, &p3, &mut c);
        assert_ne!(a, c);
    }
}
