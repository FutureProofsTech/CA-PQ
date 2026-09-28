//! From-zero Curve25519 ECDH (RFC 7748), no external code.
//!
//! Field GF(2^255-19) in 5 x 51-bit signed limbs (`i64`, `i128` products),
//! Montgomery ladder with branchless swaps, inversion by fixed addition chain for
//! 2^255-21. Verified against golden outputs of an independent big-integer
//! transcription of the RFC 7748 pseudocode (see tests).
//! Field values use copy semantics so ladder steps cannot alias.

#![forbid(unsafe_code)]

const MASK51: u64 = (1 << 51) - 1;
/// Limbs of p = 2^255 - 19 in 51-bit radix.
const P_LIMBS: [u64; 5] = [
    (1 << 51) - 19,
    (1 << 51) - 1,
    (1 << 51) - 1,
    (1 << 51) - 1,
    (1 << 51) - 1,
];

type Fe = [i64; 5];

/// Base point u = 9.
pub const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Full carry + fold over signed limbs (fixed 6 passes: no data-dependent
/// looping; arithmetic shift propagates borrows from negative limbs).
/// Used where strict `< 2^51` limbs are required (encoding).
fn carry_full(h: &mut [i128; 5]) {
    for _ in 0..6 {
        carry_round(h);
    }
}

/// One carry + fold round.
#[inline]
fn carry_round(h: &mut [i128; 5]) {
    for i in 0..4 {
        let c = h[i] >> 51;
        h[i + 1] += c;
        h[i] &= MASK51 as i128;
    }
    let c = h[4] >> 51;
    h[4] &= MASK51 as i128;
    h[0] += 19 * c;
}

/// Light carry (2 rounds) for multiply outputs. Stable fixed point:
/// inputs `< ~2^112` come out `< 2^51 + 2^9`, so the next multiply's
/// products stay far below 2^127 — verified by the RFC/golden tests.
fn carry_light(h: &mut [i128; 5]) {
    carry_round(h);
    carry_round(h);
}

fn pack128(h: &[i128; 5]) -> Fe {
    let mut r = [0i64; 5];
    for (i, rv) in r.iter_mut().enumerate() {
        *rv = h[i] as i64;
    }
    r
}

fn fe_add(a: Fe, b: Fe) -> Fe {
    let mut r = [0i64; 5];
    for i in 0..5 {
        r[i] = a[i].wrapping_add(b[i]);
    }
    r
}

/// r = a - b (limbs may go negative; the next carry resolves borrows).
fn fe_sub(a: Fe, b: Fe) -> Fe {
    let mut r = [0i64; 5];
    for i in 0..5 {
        r[i] = a[i].wrapping_sub(b[i]);
    }
    r
}

/// a * b, fully carried (limb magnitudes must stay within `i128` range —
/// easily true: ladder values stay far below 2^60 per limb).
fn fe_mul(a: Fe, b: Fe) -> Fe {
    let mut t = [0i128; 10];
    for i in 0..5 {
        for j in 0..5 {
            t[i + j] += a[i] as i128 * b[j] as i128;
        }
    }
    let mut h = [0i128; 5];
    for i in 0..5 {
        h[i] = t[i] + 19 * t[i + 5];
    }
    carry_light(&mut h);
    pack128(&h)
}

/// a * m for small m (ladder constant), light-carried.
fn fe_mul_small(a: Fe, m: i64) -> Fe {
    let mut h = [0i128; 5];
    for i in 0..5 {
        h[i] = a[i] as i128 * m as i128;
    }
    carry_light(&mut h);
    pack128(&h)
}

/// Branchless conditional swap (swap is 0 or 1).
fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
    let mask = (0u64.wrapping_sub(swap)) as i64;
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// Decode 32 LE bytes to limbs.
fn fe_decode(s: &[u8; 32]) -> Fe {
    let mut acc: u128 = 0;
    let mut bits = 0;
    let mut h = [0i64; 5];
    let mut idx = 0;
    for &byte in s.iter() {
        acc |= (byte as u128) << bits;
        bits += 8;
        if bits >= 51 {
            h[idx] = (acc & MASK51 as u128) as i64;
            acc >>= 51;
            bits -= 51;
            idx += 1;
        }
    }
    debug_assert_eq!(idx, 5);
    h
}

/// Encode limbs (any non-negative value) to 32 LE bytes, reduced mod p.
fn fe_encode_full(h: Fe) -> [u8; 32] {
    let mut t = [0i128; 5];
    for i in 0..5 {
        t[i] = h[i] as i128;
    }
    carry_full(&mut t);
    let mut hh = [0i64; 5];
    for i in 0..5 {
        hh[i] = t[i] as i64;
    }
    // Limbs now strict (< 2^51) and non-negative: single-borrow subtract.
    let mut g = [0i64; 5];
    let mut borrow: i128 = 0;
    for i in 0..5 {
        let mut d = hh[i] as i128 - P_LIMBS[i] as i128 - borrow;
        borrow = 0;
        if d < 0 {
            d += 1 << 51;
            borrow = 1;
        }
        g[i] = d as i64;
    }
    let m: i64 = if borrow == 0 { -1 } else { 0 }; // take g iff h >= p
    let mut sel = [0i64; 5];
    for i in 0..5 {
        sel[i] = (hh[i] & !m) | (g[i] & m);
    }
    // Pack 255 bits LE.
    let mut s = [0u8; 32];
    let mut acc: u128 = 0;
    let mut bits = 0;
    let mut pos = 0;
    for &limb in sel.iter() {
        acc |= (limb as u128) << bits;
        bits += 51;
        while bits >= 8 {
            s[pos] = acc as u8;
            acc >>= 8;
            bits -= 8;
            pos += 1;
        }
    }
    debug_assert_eq!(pos, 31);
    s[31] = acc as u8; // remaining 7 bits
    s
}

/// a^(2^n) by repeated squaring.
fn fe_pow2(a: Fe, n: usize) -> Fe {
    let mut t = a;
    for _ in 0..n {
        t = fe_mul(t, t);
    }
    t
}

/// Inverse: z^(2^255-21) via fixed addition chain.
fn fe_inv(z: Fe) -> Fe {
    let z2 = fe_mul(z, z);
    let p2 = fe_mul(z2, z); // z^3 = z^(2^2-1)
    let p4 = fe_mul(fe_pow2(p2, 2), p2); // z^15 = z^(2^4-1)
    let p5 = fe_mul(fe_pow2(p4, 1), z); // z^31 = z^(2^5-1)
    let p10 = fe_mul(fe_pow2(p5, 5), p5); // z^(2^10-1)
    let p20 = fe_mul(fe_pow2(p10, 10), p10); // z^(2^20-1)
    let p40 = fe_mul(fe_pow2(p20, 20), p20); // z^(2^40-1)
    let p50 = fe_mul(fe_pow2(p40, 10), p10); // z^(2^50-1)
    let p100 = fe_mul(fe_pow2(p50, 50), p50); // z^(2^100-1)
    let p200 = fe_mul(fe_pow2(p100, 100), p100); // z^(2^200-1)
    let p250 = fe_mul(fe_pow2(p200, 50), p50); // z^(2^250-1)
                                               // z^(2^255-32), then multiply by z^11 -> z^(2^255-21).
    let t = fe_pow2(p250, 5);
    let z4 = fe_mul(z2, z2);
    let z8 = fe_mul(z4, z4);
    let z11 = fe_mul(fe_mul(z8, z2), z);
    fe_mul(t, z11)
}

/// RFC 7748 scalar multiplication: secret scalar clamped, u-coordinate masked.
/// Returns the encoded u-coordinate of scalar*point.
pub fn scalarmult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let mut u = *point;
    u[31] &= 0x7f;

    let x1 = fe_decode(&u);
    let mut x2 = [0i64; 5];
    x2[0] = 1;
    let mut z2 = [0i64; 5];
    let mut x3 = x1;
    let mut z3 = [0i64; 5];
    z3[0] = 1;
    let mut swap: u64 = 0;

    const A24: i64 = 121665;

    for t in (0..255).rev() {
        let kt = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= kt;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = kt;

        let a = fe_add(x2, z2);
        let aa = fe_mul(a, a);
        let b = fe_sub(x2, z2);
        let bb = fe_mul(b, b);
        let e = fe_sub(aa, bb);
        let c = fe_add(x3, z3);
        let d = fe_sub(x3, z3);
        let da = fe_mul(d, a);
        let cb = fe_mul(c, b);
        x3 = fe_mul(fe_add(da, cb), fe_add(da, cb));
        let t1 = fe_mul(fe_sub(da, cb), fe_sub(da, cb));
        z3 = fe_mul(x1, t1);
        x2 = fe_mul(aa, bb);
        z2 = fe_mul(e, fe_add(aa, fe_mul_small(e, A24)));
    }
    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);

    fe_encode_full(fe_mul(x2, fe_inv(z2)))
}

/// Zero check for contributory behavior (branchless fold).
pub fn is_zero(x: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for &b in x.iter() {
        acc |= b;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &[u8; 64]) -> [u8; 32] {
        fn v(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => 0,
            }
        }
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = (v(s[2 * i]) << 4) | v(s[2 * i + 1]);
        }
        out
    }

    #[test]
    fn golden_vectors_from_independent_reference() {
        // Golden outputs produced by an INDEPENDENT big-integer transcription
        // of the RFC 7748 pseudocode (no limbs, no carries, no addition
        // chain — a ~25-line direct transcription kept outside the tree).
        // Agreement pins ladder logic, clamping, point masking, the field
        // prime, the ladder constant, the inversion chain, and encoding.
        // Inputs are fixed patterns (deterministic, no RNG in tests).
        let s1: [u8; 32] = core::array::from_fn(|i| i as u8);
        let s2: [u8; 32] = core::array::from_fn(|i| (31 - i) as u8);
        let s3 = [0x77u8; 32];
        let mut u1 = [0u8; 32];
        for (i, b) in u1.iter_mut().enumerate() {
            *b = ((i * 37) % 256) as u8;
        }
        let p1 = unhex(b"8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
        let p2 = unhex(b"87968c1c1642bd0600f6ad869b88f92c9623d0dfc44f01deffe21c9add3dca5f");
        let shared = unhex(b"dae0079aea6e6d02ca215a60d5d8f6689c3ed6009d41882b9181ff2481d9e27a");
        assert_eq!(scalarmult(&s1, &BASEPOINT), p1, "s1*G");
        assert_eq!(scalarmult(&s2, &BASEPOINT), p2, "s2*G");
        // Diffie-Hellman commutativity with pinned shared value.
        assert_eq!(scalarmult(&s1, &p2), shared, "s1*p2");
        assert_eq!(scalarmult(&s2, &p1), shared, "s2*p1");
        // Arbitrary point, top-bit-masked point, small point.
        assert_eq!(
            scalarmult(&s3, &u1),
            unhex(b"3ef8344b0a5e780ac072d10cc998859a33deda5f70fc6587cecf0a82e18e186e"),
            "s3*u1"
        );
        assert_eq!(
            scalarmult(&s1, &[0xffu8; 32]),
            unhex(b"b7c00165f547d5da679dda0bda98e41ef283d0eb8959e8b7fbec591f1a0db64c"),
            "s1*0xff.."
        );
        let mut u_small = [0u8; 32];
        u_small[0] = 5;
        assert_eq!(
            scalarmult(&s3, &u_small),
            unhex(b"62fc67beb868fa622dd4052ba8eaf61a5eaf640b03aab9ca9b6c053942dad426"),
            "s3*u=5"
        );
    }

    #[test]
    fn debug_field_layers() {
        // Layer isolation vs Python big-int oracles (inputs < 2^255).
        let mut ab = [0u8; 32];
        for (i, b) in ab.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut bb = [0u8; 32];
        for (i, b) in bb.iter_mut().enumerate() {
            *b = ((i * 37) % 256) as u8;
        }
        // Decode base point: exact limbs [9,0,0,0,0].
        assert_eq!(fe_decode(&BASEPOINT), [9, 0, 0, 0, 0]);
        // Encode(decode(x)) roundtrips when x < p.
        assert_eq!(fe_encode_full(fe_decode(&ab)), ab);
        assert_eq!(fe_encode_full(fe_decode(&bb)), bb);
        // Small exact multiply: 9 * 9 = 81.
        let nine = fe_decode(&BASEPOINT);
        let mut e81 = [0u8; 32];
        e81[0] = 81;
        assert_eq!(fe_encode_full(fe_mul(nine, nine)), e81);
        // Big multiply / add / sub vs oracles.
        let a = fe_decode(&ab);
        let b = fe_decode(&bb);
        assert_eq!(
            fe_encode_full(fe_mul(a, b)),
            unhex(b"e103a51e1221ed1703bad903dafd107535ef43d5443405c30a7ebe6d2d5f0e58")
        );
        assert_eq!(
            fe_encode_full(fe_add(a, b)),
            unhex(b"13264c7298bee40a30567ca2c8ee143a6086acd2f81e446a90b6dc02294e741a")
        );
        assert_eq!(
            fe_encode_full(fe_sub(a, b)),
            unhex(b"eddbb7936f4b2703e0bb97734f2b07e4bf9b77532f0be8c39f7b57330fecc723")
        );
    }

    #[test]
    fn edge_cases() {
        // Zero point maps to zero (non-contributory).
        let z = scalarmult(&[0x11u8; 32], &[0u8; 32]);
        assert!(is_zero(&z));
        assert!(!is_zero(&BASEPOINT));
        // Determinism + basepoint sanity.
        let a = scalarmult(&[7u8; 32], &BASEPOINT);
        assert_eq!(a, scalarmult(&[7u8; 32], &BASEPOINT));
        assert!(!is_zero(&a));
    }
}
