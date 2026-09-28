//! Number-theoretic transform over R_q = Z_q\[x\]/(x^256+1), q = 3329.
//!
//! Deliberately PLAIN modular arithmetic (branchless conditional
//! add/sub, single `%` only in `mulmod`): a reference implementation
//! optimized for auditability, not speed. Twiddle tables are generated at
//! compile time from the primitive root 17, and the pair moduli order was
//! determined empirically (see `chaos-attack`-style notes in tests) then
//! pinned by roundtrip + homomorphism checks.
//!
//! The public entry points below dispatch to `chaos-simd` AVX2 kernels when
//! compiled with `target-feature=+avx2`, else to the scalar reference in
//! this file. The AVX2 broadcast-order zeta tables (`ZV_FWD`/`ZV_INV`) are
//! derived HERE from the same `ZETAS` source of truth, so no twiddle logic
//! is duplicated in the SIMD crate; differential tests pin kernel == scalar.

#![forbid(unsafe_code)]

pub const Q: i32 = 3329;
pub const N: usize = 256;
/// 128^{-1} mod q: deferred per-layer halvings are applied once, at the end.
pub const INV128: i32 = 3303;

const fn brv7(i: usize) -> usize {
    let mut r = 0;
    let mut k = 0;
    while k < 7 {
        r = (r << 1) | ((i >> k) & 1);
        k += 1;
    }
    r
}

const fn powmod(mut base: i32, mut exp: usize) -> i32 {
    let mut acc = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * base % Q;
        }
        base = base * base % Q;
        exp >>= 1;
    }
    acc
}

const fn gen_zetas() -> [i16; 128] {
    let mut z = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        z[i] = powmod(17, brv7(i)) as i16;
        i += 1;
    }
    z
}

const fn gen_zetas_inv() -> [i16; 128] {
    let z = gen_zetas();
    let mut zi = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        zi[i] = powmod(z[i] as i32, (Q - 2) as usize) as i16;
        i += 1;
    }
    zi
}

/// Per-pair modulus (128 pairs): even pairs take the base odd power, odd
/// pairs its negation (mod q). Order verified by homomorphism tests.
const fn gen_gamma_pair() -> [i16; 128] {
    let mut g = [0i16; 128];
    let mut p = 0;
    while p < 128 {
        let k = p / 2;
        let e = brv7(64 + k) + if p % 2 == 1 { 128 } else { 0 };
        g[p] = powmod(17, e) as i16;
        p += 1;
    }
    g
}

const ZETAS: [i16; 128] = gen_zetas();
const ZETAS_INV: [i16; 128] = gen_zetas_inv();
const GAMMA_PAIR: [i16; 128] = gen_gamma_pair();

/// 1-based twiddle consumption index for (layer length, group).
const fn fwd_idx(length: usize, g: usize) -> usize {
    256 / (2 * length) + g
}

/// AVX2 broadcast-order zeta tables: per layer (len 128..2), per 8-coeff
/// block, the group's zeta replicated 8x. Single source of truth: `ZETAS`.
/// AVX2 broadcast tables (plus the table test below) only.
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(target_arch = "aarch64", target_feature = "neon")
))]
const FWD_LENS: [usize; 7] = [128, 64, 32, 16, 8, 4, 2];
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
const fn gen_zv(base: [i16; 128]) -> [[[i32; 8]; 32]; 7] {
    let mut zv = [[[0i32; 8]; 32]; 7];
    let mut l = 0;
    while l < 7 {
        let len = FWD_LENS[l];
        let mut m = 0;
        while m < 32 {
            let mut k = 0;
            while k < 8 {
                // The len-2 layer packs two groups per 8-block: lanes 0..4
                // take the even group, lanes 4..8 the odd group. All other
                // layers share one zeta per block (broadcast).
                let g = if len == 2 {
                    2 * m + if k < 4 { 0 } else { 1 }
                } else {
                    (8 * m) / (2 * len)
                };
                zv[l][m][k] = base[fwd_idx(len, g)] as i32;
                k += 1;
            }
            m += 1;
        }
        l += 1;
    }
    zv
}
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
const ZV_FWD: [[[i32; 8]; 32]; 7] = gen_zv(ZETAS);
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
const ZV_INV: [[[i32; 8]; 32]; 7] = gen_zv(ZETAS_INV);
/// 4-wide broadcast tables for the SSE2/NEON tiers: per layer, per 4-coeff
/// block, the group's zeta replicated 4x. Same source of truth (`ZETAS`);
/// block `m` covers coefficients `4m..4m+4`, group `(4*m)/(2*len)`.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
const fn gen_zv4(base: [i16; 128]) -> [[[i32; 4]; 64]; 7] {
    let mut zv = [[[0i32; 4]; 64]; 7];
    let mut l = 0;
    while l < 7 {
        let len = FWD_LENS[l];
        let mut m = 0;
        while m < 64 {
            let z = base[fwd_idx(len, (4 * m) / (2 * len))] as i32;
            let mut k = 0;
            while k < 4 {
                zv[l][m][k] = z;
                k += 1;
            }
            m += 1;
        }
        l += 1;
    }
    zv
}
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
const ZV4_FWD: [[[i32; 4]; 64]; 7] = gen_zv4(ZETAS);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
const ZV4_INV: [[[i32; 4]; 64]; 7] = gen_zv4(ZETAS_INV);

#[inline]
#[cfg(any(
    test,
    not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    ))
))]
fn addmod(a: i16, b: i16) -> i16 {
    // Inputs are in [0, q) everywhere (entry polys are CBD/decompressed/
    // NTT-domain; intermediates stay reduced): sum < 2q, one conditional
    // subtract (cmov, no remainder). Replaces a full `%` magic-multiply.
    debug_assert!((0..Q).contains(&(a as i32)) && (0..Q).contains(&(b as i32)));
    let s = a as i32 + b as i32;
    (if s >= Q { s - Q } else { s }) as i16
}

#[inline]
#[cfg(any(
    test,
    not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    ))
))]
fn submod(a: i16, b: i16) -> i16 {
    // Same invariant: difference in (-q, q), one conditional add.
    debug_assert!((0..Q).contains(&(a as i32)) && (0..Q).contains(&(b as i32)));
    let d = a as i32 - b as i32;
    (if d < 0 { d + Q } else { d }) as i16
}

#[inline]
#[cfg(any(
    test,
    not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    ))
))]
fn mulmod(a: i16, b: i16) -> i16 {
    // Plain remainder: inputs are < q so the product is < 2^24 and the
    // compiler emits branchless magic-multiply code. A Barrett variant was
    // benchmarked and measured identical — the NTT is loop/memory-bound,
    // not ALU-bound — so the obvious version stays.
    ((a as i32 * b as i32) % Q) as i16
}

/// Forward NTT (natural order in and out; twiddle table absorbs permutation).
#[cfg(any(
    test,
    not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    ))
))]
fn ntt_scalar(f: &[i16; N]) -> [i16; N] {
    let mut r = *f;
    for v in r.iter_mut() {
        if *v >= Q as i16 {
            *v -= Q as i16;
        }
    }
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[fwd_idx(len, start / (2 * len))];
            let mut j = start;
            while j < start + len {
                let t = mulmod(zeta, r[j + len]);
                r[j + len] = submod(r[j], t);
                r[j] = addmod(r[j], t);
                j += 1;
            }
            start += 2 * len;
        }
        len /= 2;
    }
    r
}

/// Inverse NTT: mirrored loop, explicit inverse twiddles, single final scale.
#[cfg(any(
    test,
    not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    ))
))]
fn intt_scalar(f: &[i16; N]) -> [i16; N] {
    let mut r = *f;
    for v in r.iter_mut() {
        if *v >= Q as i16 {
            *v -= Q as i16;
        }
    }
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zi = ZETAS_INV[fwd_idx(len, start / (2 * len))];
            let mut j = start;
            while j < start + len {
                let t = r[j];
                r[j] = addmod(t, r[j + len]);
                r[j + len] = mulmod(zi, submod(t, r[j + len]));
                j += 1;
            }
            start += 2 * len;
        }
        len *= 2;
    }
    let mut out = [0i16; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = mulmod(r[i], INV128 as i16);
    }
    out
}

/// Multiply two NTT-domain polys (pointwise quadratic products).
#[cfg(any(
    test,
    not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    ))
))]
fn polymul_ntt_scalar(a: &[i16; N], b: &[i16; N]) -> [i16; N] {
    let mut r = [0i16; N];
    let mut p = 0;
    while p < 128 {
        let (a0, a1) = (a[2 * p], a[2 * p + 1]);
        let (b0, b1) = (b[2 * p], b[2 * p + 1]);
        let g = GAMMA_PAIR[p];
        let c0 = addmod(mulmod(a0, b0), mulmod(g, mulmod(a1, b1)));
        let c1 = addmod(mulmod(a0, b1), mulmod(a1, b0));
        r[2 * p] = c0;
        r[2 * p + 1] = c1;
        p += 1;
    }
    r
}

/// Forward NTT: AVX2 kernel when compiled in, NEON 4-wide on aarch64,
/// else the scalar reference. (An SSE2 NTT was prototyped and rejected:
/// without 32-bit multiply the emulation costs more than it saves.)
#[inline]
pub fn ntt(f: &[i16; N]) -> [i16; N] {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    return chaos_simd::ntt_avx2(f, &ZV_FWD);
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    return chaos_simd::ntt4_neon(f, &ZV4_FWD);
    #[cfg(not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    )))]
    return ntt_scalar(f);
}

/// Inverse NTT (incl. final 128^-1 scale): same dispatch.
#[inline]
pub fn intt(f: &[i16; N]) -> [i16; N] {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    return chaos_simd::intt_avx2(f, &ZV_INV, INV128);
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    return chaos_simd::intt4_neon(f, &ZV4_INV, INV128);
    #[cfg(not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    )))]
    return intt_scalar(f);
}

/// NTT-domain pointwise multiply: same dispatch.
#[inline]
pub fn polymul_ntt(a: &[i16; N], b: &[i16; N]) -> [i16; N] {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    return chaos_simd::polymul_ntt_avx2(a, b, &GAMMA_PAIR);
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    return chaos_simd::polymul4_neon(a, b, &GAMMA_PAIR);
    #[cfg(not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    )))]
    return polymul_ntt_scalar(a, b);
}

/// Coefficient-wise addition (NTT domain): same dispatch.
#[inline]
pub fn polyadd(a: &[i16; N], b: &[i16; N]) -> [i16; N] {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    return chaos_simd::polyadd_avx2(a, b);
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    return chaos_simd::polyadd4_neon(a, b);
    #[cfg(not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    )))]
    return polyadd_scalar(a, b);
}

/// Scalar coefficient-wise addition body (kept below for reference order).
#[cfg(any(
    test,
    not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    ))
))]
fn polyadd_scalar(a: &[i16; N], b: &[i16; N]) -> [i16; N] {
    let mut r = [0i16; N];
    for i in 0..N {
        r[i] = addmod(a[i], b[i]);
    }
    r
}

#[cfg(test)]
#[test]
fn zv_tables_match_source() {
    extern crate std;
    // Layer 0 (len 128): all 32 blocks must equal ZETAS[fwd_idx(128,0)] = ZETAS[1].
    let z0 = ZETAS[fwd_idx(128, 0)];
    std::println!(
        "ZETAS[1]={} ZV_FWD[0][0]={:?} ZV_FWD[0][17]={:?}",
        z0,
        ZV_FWD[0][0],
        ZV_FWD[0][17]
    );
    assert_eq!(ZV_FWD[0][0], [z0 as i32; 8]);
    assert_eq!(ZV_FWD[0][17], [z0 as i32; 8]);
    // Layer 4 (len 8): block m -> group m/2.
    let g = ZETAS[fwd_idx(8, 3)];
    std::println!("len8 block7 zeta={} table={:?}", g, ZV_FWD[4][7]);
    assert_eq!(ZV_FWD[4][7], [g as i32; 8]);
    // Layer 6 (len 2): split groups.
    let za = ZETAS[fwd_idx(2, 4)];
    let zb = ZETAS[fwd_idx(2, 5)];
    std::println!("len2 block2 za={} zb={} table={:?}", za, zb, ZV_FWD[6][2]);
    assert_eq!(&ZV_FWD[6][2][..4], &[za as i32; 4]);
    assert_eq!(&ZV_FWD[6][2][4..], &[zb as i32; 4]);
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[cfg(test)]
mod neon_tests {
    use super::*;

    /// Deterministic xorshift64* filler: full i16 range incl. q edges.
    fn fill(seed: u64, out: &mut [i16; N]) {
        let mut x = seed | 1;
        for v in out.iter_mut() {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x = x.wrapping_mul(0x2545F4914F6CDD1D);
            *v = (x >> 48) as i16;
        }
    }

    fn fill_modq(seed: u64, out: &mut [i16; N]) {
        fill(seed, out);
        for v in out.iter_mut() {
            let mut w = (*v as i32) % Q;
            if w < 0 {
                w += Q;
            }
            *v = w as i16;
        }
    }

    #[test]
    fn neon_ntt_matches_scalar() {
        for t in 0..8u64 {
            let mut f = [0i16; N];
            fill_modq(0x1234 + t * 0x9E37, &mut f);
            assert_eq!(
                chaos_simd::ntt4_neon(&f, &ZV4_FWD),
                ntt_scalar(&f),
                "ntt {}",
                t
            );
        }
        let mut e = [0i16; N];
        for (i, v) in e.iter_mut().enumerate() {
            *v = [0, 1, Q as i16 - 1, Q as i16 - 2][i % 4];
        }
        assert_eq!(chaos_simd::ntt4_neon(&e, &ZV4_FWD), ntt_scalar(&e));
        // Decode-range agreement (adversarial dk values reach the NTT).
        let mut w = [0i16; N];
        fill(0xDEAD, &mut w);
        for v in w.iter_mut() {
            *v = (*v as i32).rem_euclid(4096) as i16;
        }
        assert_eq!(chaos_simd::ntt4_neon(&w, &ZV4_FWD), ntt_scalar(&w));
    }

    #[test]
    fn neon_intt_matches_scalar() {
        for t in 0..8u64 {
            let mut f = [0i16; N];
            fill_modq(0xABCD + t * 0x51F3, &mut f);
            let h = ntt_scalar(&f);
            assert_eq!(
                chaos_simd::intt4_neon(&h, &ZV4_INV, INV128),
                intt_scalar(&h),
                "intt {}",
                t
            );
        }
        let mut f = [0i16; N];
        fill_modq(0x7777, &mut f);
        let rt = chaos_simd::intt4_neon(&chaos_simd::ntt4_neon(&f, &ZV4_FWD), &ZV4_INV, INV128);
        assert_eq!(rt, f);
    }

    #[test]
    fn neon_polymul_polyadd_match_scalar() {
        for t in 0..8u64 {
            let mut a = [0i16; N];
            let mut b = [0i16; N];
            fill_modq(0x1000 + t, &mut a);
            fill_modq(0x2000 + t * 3, &mut b);
            assert_eq!(
                chaos_simd::polymul4_neon(&a, &b, &GAMMA_PAIR),
                polymul_ntt_scalar(&a, &b),
                "mul {}",
                t
            );
            assert_eq!(
                chaos_simd::polyadd4_neon(&a, &b),
                polyadd_scalar(&a, &b),
                "add {}",
                t
            );
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[cfg(test)]
mod avx2_tests {
    use super::*;

    /// Deterministic xorshift64* filler: full i16 range incl. q edges.
    fn fill(seed: u64, out: &mut [i16; N]) {
        let mut x = seed | 1;
        for v in out.iter_mut() {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x = x.wrapping_mul(0x2545F4914F6CDD1D);
            *v = (x >> 48) as i16;
        }
    }

    fn fill_modq(seed: u64, out: &mut [i16; N]) {
        fill(seed, out);
        for v in out.iter_mut() {
            let mut w = (*v as i32) % Q;
            if w < 0 {
                w += Q;
            }
            *v = w as i16;
        }
    }

    #[test]
    fn avx2_ntt_matches_scalar() {
        for t in 0..8u64 {
            let mut f = [0i16; N];
            fill_modq(0x1234 + t * 0x9E37, &mut f);
            assert_eq!(
                chaos_simd::ntt_avx2(&f, &ZV_FWD),
                ntt_scalar(&f),
                "ntt {}",
                t
            );
        }
        // Edge values: 0, 1, q-1, q-2 everywhere + single spikes.
        let mut e = [0i16; N];
        for (i, v) in e.iter_mut().enumerate() {
            *v = [0, 1, Q as i16 - 1, Q as i16 - 2][i % 4];
        }
        assert_eq!(chaos_simd::ntt_avx2(&e, &ZV_FWD), ntt_scalar(&e));
        // Decode-range inputs [0, 4096): scalar entry loop and kernel entry
        // normalize must agree (adversarial dk values reach the NTT).
        let mut w = [0i16; N];
        fill(0xDEAD, &mut w);
        for v in w.iter_mut() {
            *v = (*v as i32).rem_euclid(4096) as i16;
        }
        assert_eq!(chaos_simd::ntt_avx2(&w, &ZV_FWD), ntt_scalar(&w));
        assert_eq!(chaos_simd::intt_avx2(&w, &ZV_INV, INV128), intt_scalar(&w));
    }

    #[test]
    fn avx2_intt_matches_scalar() {
        for t in 0..8u64 {
            let mut f = [0i16; N];
            fill_modq(0xABCD + t * 0x51F3, &mut f);
            let h = ntt_scalar(&f);
            assert_eq!(
                chaos_simd::intt_avx2(&h, &ZV_INV, INV128),
                intt_scalar(&h),
                "intt {}",
                t
            );
        }
        // Roundtrip through the kernel only.
        let mut f = [0i16; N];
        fill_modq(0x7777, &mut f);
        let rt = chaos_simd::intt_avx2(&chaos_simd::ntt_avx2(&f, &ZV_FWD), &ZV_INV, INV128);
        assert_eq!(rt, f);
    }

    #[test]
    fn avx2_polymul_polyadd_match_scalar() {
        for t in 0..8u64 {
            let mut a = [0i16; N];
            let mut b = [0i16; N];
            fill_modq(0x1000 + t, &mut a);
            fill_modq(0x2000 + t * 3, &mut b);
            assert_eq!(
                chaos_simd::polymul_ntt_avx2(&a, &b, &GAMMA_PAIR),
                polymul_ntt_scalar(&a, &b),
                "mul {}",
                t
            );
            assert_eq!(
                chaos_simd::polyadd_avx2(&a, &b),
                polyadd_scalar(&a, &b),
                "add {}",
                t
            );
        }
    }
}
