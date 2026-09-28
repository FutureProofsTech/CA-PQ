//! CA-PQ `chaos-simd`: vector kernels (AVX2 BLAKE3/Keccak/NTT, SSE2 + NEON BLAKE3 tiers).
//!
//! Eight independent BLAKE3 compressions evaluated in parallel, one 32-bit
//! lane per compression (`__m256i` row = word `r` across all 8 lanes); four
//! parallel Keccak-f permutations, one 64-bit lane per stream. Both match
//! their scalar twins lane-for-lane; differential tests in `chaos-hash` pin
//! them equal. Portable fallback lives in the callers (kernels are x86_64 +
//! AVX2 only). `no_std` compatible.
//!
//! Safety: the crate denies `unsafe_code`; each entry point carries an
//! item-scoped allow with justification (intrinsics are `unsafe fn` by
//! language rule, operating here only on register values and valid stack
//! slots, with no data-dependent behavior).

#![no_std]
#![deny(unsafe_code)]

/// Message schedule permutation. Must match `chaos-hash` MSG_PERMUTATION;
/// the differential tests pin all kernels against the same vectors.
/// Shared by the AVX2, SSE2, and NEON compression tiers.
#[cfg(any(
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2"
    ),
    all(target_arch = "aarch64", target_feature = "neon")
))]
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// Eight parallel compressions. Layout: `cvs[lane][word]`, etc.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[allow(unsafe_code)]
pub fn compress8_avx2(
    cvs: &[[u32; 8]; 8],
    blocks: &[[u32; 16]; 8],
    counters: &[u64; 8],
    lens: &[u32; 8],
    flags: &[u32; 8],
) -> [[u32; 16]; 8] {
    // SAFETY: every intrinsic below operates on __m256i values held in
    // registers, except two unaligned stores into valid 32-byte stack slots
    // (`tmp`). No raw-pointer reads, no aliasing, no data-dependent control
    // flow, no memory beyond the stack slots. Pure function of the inputs.
    use core::arch::x86_64::*;
    unsafe {
        // Row r = word r of all 8 lanes. _mm256_set_epi32 takes lane7 first.
        macro_rules! row8 {
            ($f:expr) => {
                _mm256_set_epi32($f(7), $f(6), $f(5), $f(4), $f(3), $f(2), $f(1), $f(0))
            };
        }
        let mut v = [_mm256_setzero_si256(); 16];
        for r in 0..8 {
            v[r] = row8!(|l: usize| cvs[l][r] as i32);
        }
        v[8] = _mm256_set1_epi32(0x6A09E667u32 as i32);
        v[9] = _mm256_set1_epi32(0xBB67AE85u32 as i32);
        v[10] = _mm256_set1_epi32(0x3C6EF372u32 as i32);
        v[11] = _mm256_set1_epi32(0xA54FF53Au32 as i32);
        v[12] = row8!(|l: usize| counters[l] as u32 as i32);
        v[13] = row8!(|l: usize| (counters[l] >> 32) as u32 as i32);
        v[14] = row8!(|l: usize| lens[l] as i32);
        v[15] = row8!(|l: usize| flags[l] as i32);
        // Keep the input chaining rows for feedforward.
        let mut cvv = [_mm256_setzero_si256(); 8];
        cvv.copy_from_slice(&v[..8]);
        let mut m = [_mm256_setzero_si256(); 16];
        for r in 0..16 {
            m[r] = row8!(|l: usize| blocks[l][r] as i32);
        }
        for _ in 0..7 {
            // Columns.
            let (a0, b0, c0, d0) = g8(v[0], v[4], v[8], v[12], m[0], m[1]);
            v[0] = a0;
            v[4] = b0;
            v[8] = c0;
            v[12] = d0;
            let (a1, b1, c1, d1) = g8(v[1], v[5], v[9], v[13], m[2], m[3]);
            v[1] = a1;
            v[5] = b1;
            v[9] = c1;
            v[13] = d1;
            let (a2, b2, c2, d2) = g8(v[2], v[6], v[10], v[14], m[4], m[5]);
            v[2] = a2;
            v[6] = b2;
            v[10] = c2;
            v[14] = d2;
            let (a3, b3, c3, d3) = g8(v[3], v[7], v[11], v[15], m[6], m[7]);
            v[3] = a3;
            v[7] = b3;
            v[11] = c3;
            v[15] = d3;
            // Diagonals.
            let (e0, f0, g0, h0) = g8(v[0], v[5], v[10], v[15], m[8], m[9]);
            v[0] = e0;
            v[5] = f0;
            v[10] = g0;
            v[15] = h0;
            let (e1, f1, g1, h1) = g8(v[1], v[6], v[11], v[12], m[10], m[11]);
            v[1] = e1;
            v[6] = f1;
            v[11] = g1;
            v[12] = h1;
            let (e2, f2, g2, h2) = g8(v[2], v[7], v[8], v[13], m[12], m[13]);
            v[2] = e2;
            v[7] = f2;
            v[8] = g2;
            v[13] = h2;
            let (e3, f3, g3, h3) = g8(v[3], v[4], v[9], v[14], m[14], m[15]);
            v[3] = e3;
            v[4] = f3;
            v[9] = g3;
            v[14] = h3;
            // Message permutation (same index map, lane-independent).
            let mut p = [_mm256_setzero_si256(); 16];
            for i in 0..16 {
                p[i] = m[MSG_PERMUTATION[i]];
            }
            m = p;
        }
        // Feedforward per lane.
        for r in 0..8 {
            v[r] = _mm256_xor_si256(v[r], v[r + 8]);
            v[r + 8] = _mm256_xor_si256(v[r + 8], cvv[r]);
        }
        // Store rows, then transpose rows->lanes in scalar code.
        let mut tmp = [[0u32; 8]; 16];
        for r in 0..16 {
            _mm256_storeu_si256(tmp[r].as_mut_ptr() as *mut __m256i, v[r]);
        }
        // Transpose rows->lanes in scalar code (a real transpose, not a
        // memcpy: clippy::manual_memcpy does not apply here).
        #[allow(clippy::manual_memcpy)]
        let mut out = [[0u32; 16]; 8];
        for lane in 0..8 {
            for r in 0..16 {
                out[lane][r] = tmp[r][lane];
            }
        }
        out
    }
}

/// One G mixing step over 8 lanes (value semantics: no aliasing possible).
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[allow(unsafe_code)]
#[inline(always)]
fn g8(
    a: core::arch::x86_64::__m256i,
    b: core::arch::x86_64::__m256i,
    c: core::arch::x86_64::__m256i,
    d: core::arch::x86_64::__m256i,
    mx: core::arch::x86_64::__m256i,
    my: core::arch::x86_64::__m256i,
) -> (
    core::arch::x86_64::__m256i,
    core::arch::x86_64::__m256i,
    core::arch::x86_64::__m256i,
    core::arch::x86_64::__m256i,
) {
    // SAFETY: intrinsics below operate on register values only.
    use core::arch::x86_64::*;
    unsafe {
        let a = _mm256_add_epi32(_mm256_add_epi32(a, b), mx);
        let d = _mm256_xor_si256(d, a);
        let d = _mm256_or_si256(_mm256_srli_epi32::<16>(d), _mm256_slli_epi32::<16>(d));
        let c = _mm256_add_epi32(c, d);
        let b = _mm256_xor_si256(b, c);
        let b = _mm256_or_si256(_mm256_srli_epi32::<12>(b), _mm256_slli_epi32::<20>(b));
        let a = _mm256_add_epi32(_mm256_add_epi32(a, b), my);
        let d = _mm256_xor_si256(d, a);
        let d = _mm256_or_si256(_mm256_srli_epi32::<8>(d), _mm256_slli_epi32::<24>(d));
        let c = _mm256_add_epi32(c, d);
        let b = _mm256_xor_si256(b, c);
        let b = _mm256_or_si256(_mm256_srli_epi32::<7>(b), _mm256_slli_epi32::<25>(b));
        (a, b, c, d)
    }
}

/// Four parallel Keccak-f[1600] permutations. Layout: `states[k][w]` is word
/// `w` of stream `k`; inside, lane `k` of every register holds stream `k`'s
/// word (`reg[w]` = words `w` of all 4 streams). All rotation amounts are
/// compile-time immediates (same FIPS 202 table for every lane), chi uses
/// native `andnot`; transpose in/out is scalar. Matches 4x scalar `keccak_f`
/// word-for-word; the differential test in `chaos-hash` pins equality.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[allow(unsafe_code)]
pub fn keccak_f_x4(states: &mut [[u64; 25]; 4]) {
    // SAFETY: same shape as `compress8_avx2` — intrinsics on register
    // values, plus unaligned loads/stores on valid stack-passed slots
    // (`states`, element-indexed, in bounds). No data-dependent behavior.
    use core::arch::x86_64::*;
    unsafe {
        // Word-major registers from state-major memory.
        macro_rules! load_w {
            ($s:expr, $w:expr) => {
                _mm256_set_epi64x(
                    $s[3][$w] as i64,
                    $s[2][$w] as i64,
                    $s[1][$w] as i64,
                    $s[0][$w] as i64,
                )
            };
        }
        // 64-bit left-rotate by an immediate amount.
        macro_rules! rol {
            ($v:expr, $r:expr) => {
                _mm256_or_si256(
                    _mm256_slli_epi64::<{ $r }>($v),
                    _mm256_srli_epi64::<{ 64 - $r }>($v),
                )
            };
        }
        let mut a = [_mm256_setzero_si256(); 25];
        for w in 0..25 {
            a[w] = load_w!(states, w);
        }
        // Round constants (same LFSR table as the scalar Keccak).
        const RC: [u64; 24] = [
            0x0000000000000001,
            0x0000000000008082,
            0x800000000000808a,
            0x8000000080008000,
            0x000000000000808b,
            0x0000000080000001,
            0x8000000080008081,
            0x8000000000008009,
            0x000000000000008a,
            0x0000000000000088,
            0x0000000080008009,
            0x000000008000000a,
            0x000000008000808b,
            0x800000000000008b,
            0x8000000000008089,
            0x8000000000008003,
            0x8000000000008002,
            0x8000000000000080,
            0x000000000000800a,
            0x800000008000000a,
            0x8000000080008081,
            0x8000000000008080,
            0x0000000080000001,
            0x8000000080008008,
        ];
        for &rc in RC.iter() {
            // θ
            let c0 = _mm256_xor_si256(
                _mm256_xor_si256(a[0], a[5]),
                _mm256_xor_si256(_mm256_xor_si256(a[10], a[15]), a[20]),
            );
            let c1 = _mm256_xor_si256(
                _mm256_xor_si256(a[1], a[6]),
                _mm256_xor_si256(_mm256_xor_si256(a[11], a[16]), a[21]),
            );
            let c2 = _mm256_xor_si256(
                _mm256_xor_si256(a[2], a[7]),
                _mm256_xor_si256(_mm256_xor_si256(a[12], a[17]), a[22]),
            );
            let c3 = _mm256_xor_si256(
                _mm256_xor_si256(a[3], a[8]),
                _mm256_xor_si256(_mm256_xor_si256(a[13], a[18]), a[23]),
            );
            let c4 = _mm256_xor_si256(
                _mm256_xor_si256(a[4], a[9]),
                _mm256_xor_si256(_mm256_xor_si256(a[14], a[19]), a[24]),
            );
            let d0 = _mm256_xor_si256(c4, rol!(c1, 1));
            let d1 = _mm256_xor_si256(c0, rol!(c2, 1));
            let d2 = _mm256_xor_si256(c1, rol!(c3, 1));
            let d3 = _mm256_xor_si256(c2, rol!(c4, 1));
            let d4 = _mm256_xor_si256(c3, rol!(c0, 1));
            // θ-apply + ρ + π into b (same destination map as scalar).
            let mut b = [_mm256_setzero_si256(); 25];
            b[0] = _mm256_xor_si256(a[0], d0);
            b[16] = rol!(_mm256_xor_si256(a[5], d0), 36);
            b[7] = rol!(_mm256_xor_si256(a[10], d0), 3);
            b[23] = rol!(_mm256_xor_si256(a[15], d0), 41);
            b[14] = rol!(_mm256_xor_si256(a[20], d0), 18);
            b[10] = rol!(_mm256_xor_si256(a[1], d1), 1);
            b[1] = rol!(_mm256_xor_si256(a[6], d1), 44);
            b[17] = rol!(_mm256_xor_si256(a[11], d1), 10);
            b[8] = rol!(_mm256_xor_si256(a[16], d1), 45);
            b[24] = rol!(_mm256_xor_si256(a[21], d1), 2);
            b[20] = rol!(_mm256_xor_si256(a[2], d2), 62);
            b[11] = rol!(_mm256_xor_si256(a[7], d2), 6);
            b[2] = rol!(_mm256_xor_si256(a[12], d2), 43);
            b[18] = rol!(_mm256_xor_si256(a[17], d2), 15);
            b[9] = rol!(_mm256_xor_si256(a[22], d2), 61);
            b[5] = rol!(_mm256_xor_si256(a[3], d3), 28);
            b[21] = rol!(_mm256_xor_si256(a[8], d3), 55);
            b[12] = rol!(_mm256_xor_si256(a[13], d3), 25);
            b[3] = rol!(_mm256_xor_si256(a[18], d3), 21);
            b[19] = rol!(_mm256_xor_si256(a[23], d3), 56);
            b[15] = rol!(_mm256_xor_si256(a[4], d4), 27);
            b[6] = rol!(_mm256_xor_si256(a[9], d4), 20);
            b[22] = rol!(_mm256_xor_si256(a[14], d4), 39);
            b[13] = rol!(_mm256_xor_si256(a[19], d4), 8);
            b[4] = rol!(_mm256_xor_si256(a[24], d4), 14);
            // χ row by row + ι.
            macro_rules! chi {
                ($y:expr) => {
                    a[5 * $y] = _mm256_xor_si256(
                        b[5 * $y],
                        _mm256_andnot_si256(b[5 * $y + 1], b[5 * $y + 2]),
                    );
                    a[5 * $y + 1] = _mm256_xor_si256(
                        b[5 * $y + 1],
                        _mm256_andnot_si256(b[5 * $y + 2], b[5 * $y + 3]),
                    );
                    a[5 * $y + 2] = _mm256_xor_si256(
                        b[5 * $y + 2],
                        _mm256_andnot_si256(b[5 * $y + 3], b[5 * $y + 4]),
                    );
                    a[5 * $y + 3] = _mm256_xor_si256(
                        b[5 * $y + 3],
                        _mm256_andnot_si256(b[5 * $y + 4], b[5 * $y]),
                    );
                    a[5 * $y + 4] = _mm256_xor_si256(
                        b[5 * $y + 4],
                        _mm256_andnot_si256(b[5 * $y], b[5 * $y + 1]),
                    );
                };
            }
            chi!(0);
            chi!(1);
            chi!(2);
            chi!(3);
            chi!(4);
            a[0] = _mm256_xor_si256(a[0], _mm256_set1_epi64x(rc as i64));
        }
        // Transpose back to state-major memory: store each word-register
        // then scatter lanes to their streams (a real transpose).
        #[allow(clippy::manual_memcpy)]
        for w in 0..25 {
            let mut tmp = [0u64; 4];
            _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, a[w]);
            for k in 0..4 {
                states[k][w] = tmp[k];
            }
        }
    }
}

/// 32-bit Barrett reduction for values `< 2^24` mod 3329, 8 lanes.
///
/// Derivation: split `v = hi*2^16 + lo` (`hi < 2^8` since `v < 2^24`;
/// `hi < q` needs no reduction). `2^16 mod 3329 = 2285`, so
/// `w = hi*2285 + lo < 648210` is congruent to `v` and under `2^20`.
/// With `MU = floor(2^20/3329) = 314`: `t = (w*MU) >> 20` underestimates
/// `floor(w/q)` by less than 1 for `w < 1076426` (gap analysis:
/// `w*(1/q - MU/2^20) < 1`), so `r = w - t*q` needs a single conditional
/// subtract. All intermediates fit 32 bits (`w*MU < 2^28`).
/// Pure function of the input register; no data-dependent behavior.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[allow(unsafe_code)]
#[inline(always)]
fn barrett24(v: core::arch::x86_64::__m256i) -> core::arch::x86_64::__m256i {
    // SAFETY: register-only arithmetic, no memory access.
    use core::arch::x86_64::*;
    unsafe {
        let hi = _mm256_srli_epi32::<16>(v);
        let lo = _mm256_and_si256(v, _mm256_set1_epi32(0xFFFF));
        let w = _mm256_add_epi32(_mm256_mullo_epi32(hi, _mm256_set1_epi32(2285)), lo);
        let t = _mm256_srli_epi32::<20>(_mm256_mullo_epi32(w, _mm256_set1_epi32(314)));
        let r = _mm256_sub_epi32(w, _mm256_mullo_epi32(t, _mm256_set1_epi32(3329)));
        // Single fixup: r in [0, 2q).
        let over = _mm256_cmpgt_epi32(r, _mm256_set1_epi32(3328));
        _mm256_blendv_epi8(r, _mm256_sub_epi32(r, _mm256_set1_epi32(3329)), over)
    }
}

/// Cooley-Tukey butterfly column (forward NTT): 8 lanes of
/// `(u, w) = (a + zeta*b, a - zeta*b)`, reduced to `[0, q)`.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[allow(unsafe_code)]
#[inline(always)]
fn bfly8_ct(
    a: core::arch::x86_64::__m256i,
    b: core::arch::x86_64::__m256i,
    z: core::arch::x86_64::__m256i,
) -> (core::arch::x86_64::__m256i, core::arch::x86_64::__m256i) {
    // SAFETY: register-only arithmetic.
    use core::arch::x86_64::*;
    unsafe {
        let q = _mm256_set1_epi32(3329);
        let t = barrett24(_mm256_mullo_epi32(z, b));
        let u = _mm256_add_epi32(a, t);
        let over = _mm256_cmpgt_epi32(u, _mm256_set1_epi32(3328));
        let u = _mm256_blendv_epi8(u, _mm256_sub_epi32(u, q), over);
        let d = _mm256_sub_epi32(a, t);
        let neg = _mm256_cmpgt_epi32(_mm256_setzero_si256(), d);
        let w = _mm256_blendv_epi8(d, _mm256_add_epi32(d, q), neg);
        (u, w)
    }
}

/// Gentleman-Sande butterfly column (inverse NTT): 8 lanes of
/// `(u, w) = (a+b, zeta*(a-b))`, all values reduced to `[0, q)`.
/// `z` holds the broadcast zeta.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[allow(unsafe_code)]
#[inline(always)]
fn bfly8(
    a: core::arch::x86_64::__m256i,
    b: core::arch::x86_64::__m256i,
    z: core::arch::x86_64::__m256i,
) -> (core::arch::x86_64::__m256i, core::arch::x86_64::__m256i) {
    // SAFETY: register-only arithmetic.
    use core::arch::x86_64::*;
    unsafe {
        let q = _mm256_set1_epi32(3329);
        let u = _mm256_add_epi32(a, b);
        let over = _mm256_cmpgt_epi32(u, _mm256_set1_epi32(3328));
        let u = _mm256_blendv_epi8(u, _mm256_sub_epi32(u, q), over);
        let d = _mm256_sub_epi32(a, b);
        let neg = _mm256_cmpgt_epi32(_mm256_setzero_si256(), d);
        let d = _mm256_blendv_epi8(d, _mm256_add_epi32(d, q), neg);
        let v = barrett24(_mm256_mullo_epi32(z, d));
        (u, v)
    }
}

/// Load 8 coefficients (widen to i32).
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[allow(unsafe_code)]
#[inline(always)]
fn load8(p: *const i16) -> core::arch::x86_64::__m256i {
    // SAFETY: caller guarantees 8 readable i16 at `p` (poly slices).
    use core::arch::x86_64::*;
    unsafe { _mm256_cvtepi16_epi32(_mm_loadu_si128(p as *const __m128i)) }
}

/// Reduce `[0, 2q)` lanes and narrow to 8 coefficients.
///
/// Narrowing caveat: AVX2 `packs_epi32` works per 128-bit lane
/// (`low128 = pack(a.lo, b.lo)`), so packing `(v, v)` would duplicate the
/// low half. Swap 128-bit halves first: `pack(v.lo, swapped.lo)` then
/// yields `[v0..v7]` in the low half, which is what gets stored.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[allow(unsafe_code)]
#[inline(always)]
fn store8(p: *mut i16, v: core::arch::x86_64::__m256i) {
    // SAFETY: caller guarantees 8 writable i16 at `p`; saturation never
    // fires (values `< 2q << 2^15` after the conditional subtract).
    use core::arch::x86_64::*;
    unsafe {
        let over = _mm256_cmpgt_epi32(v, _mm256_set1_epi32(3328));
        let v = _mm256_blendv_epi8(v, _mm256_sub_epi32(v, _mm256_set1_epi32(3329)), over);
        let swapped = _mm256_permute4x64_epi64::<0x4E>(v);
        let n = _mm256_packs_epi32(v, swapped);
        _mm_storeu_si128(p as *mut __m128i, _mm256_castsi256_si128(n));
    }
}

/// Forward NTT over 256 coefficients. `zv[layer][block]` holds the block's
/// zeta broadcast 8x (layer 6 holds `[zA x4, zB x4]` for the split groups).
/// Entry values must be `< 2q` (one conditional subtract normalizes; the
/// scalar reference accepts wider input, the dispatcher debug-asserts).
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[allow(unsafe_code)]
pub fn ntt_avx2(f: &[i16; 256], zv: &[[[i32; 8]; 32]; 7]) -> [i16; 256] {
    // SAFETY: all loads/stores are in-bounds poly vizualizations via
    // `load8`/`store8`; the rest is register arithmetic. Same input-output
    // contract as the scalar `ntt` (natural order in and out).
    use core::arch::x86_64::*;
    unsafe {
        let mut r = *f;
        // Entry normalize (REQUIRED, not just tidy): decode-range inputs
        // reach < 4096, and a single trailing condsub cannot reduce
        // layer-1 sums (up to 8190), while unreduced negative differences
        // would wrap the Barrett products to garbage. One compare+blend per
        // vector; no-op for honest < q inputs. Matches the scalar entry loop.
        for m in 0..32 {
            let v = load8(r.as_ptr().add(8 * m));
            let over = _mm256_cmpgt_epi32(v, _mm256_set1_epi32(3328));
            let v = _mm256_blendv_epi8(v, _mm256_sub_epi32(v, _mm256_set1_epi32(3329)), over);
            store8(r.as_mut_ptr().add(8 * m), v);
        }
        // Layers len = 128, 64, 32, 16, 8: full-width block pairs.
        for (l, len) in [128usize, 64, 32, 16, 8].iter().enumerate() {
            let len = *len;
            let step = len / 8; // partner block offset in blocks
            let period = len / 4; // low-block pattern repeats every `period` blocks
            for (m, zb) in zv[l].iter().enumerate() {
                if m % period < step {
                    let z = _mm256_loadu_si256(zb.as_ptr() as *const __m256i);
                    let a = load8(r.as_ptr().add(8 * m));
                    let b = load8(r.as_ptr().add(8 * (m + step)));
                    let (u, w) = bfly8_ct(a, b, z);
                    store8(r.as_mut_ptr().add(8 * m), u);
                    store8(r.as_mut_ptr().add(8 * (m + step)), w);
                }
            }
        }
        // Layer len = 4: pairs within each block (lo-half, hi-half).
        let idx_lo = _mm256_set_epi32(3, 2, 1, 0, 3, 2, 1, 0);
        let idx_hi = _mm256_set_epi32(7, 6, 5, 4, 7, 6, 5, 4);
        for (m, zb) in zv[5].iter().enumerate() {
            let z = _mm256_loadu_si256(zb.as_ptr() as *const __m256i);
            let v = load8(r.as_ptr().add(8 * m));
            let a = _mm256_permutevar8x32_epi32(v, idx_lo);
            let b = _mm256_permutevar8x32_epi32(v, idx_hi);
            let (u, w) = bfly8_ct(a, b, z);
            let out = _mm256_blend_epi32::<0xF0>(u, w);
            store8(r.as_mut_ptr().add(8 * m), out);
        }
        // Layer len = 2: pairs (0,2),(1,3) and (4,6),(5,7); z = [zA x4, zB x4].
        let idx_a = _mm256_set_epi32(5, 4, 5, 4, 1, 0, 1, 0);
        let idx_b = _mm256_set_epi32(7, 6, 7, 6, 3, 2, 3, 2);
        for (m, zb) in zv[6].iter().enumerate() {
            let z = _mm256_loadu_si256(zb.as_ptr() as *const __m256i);
            let v = load8(r.as_ptr().add(8 * m));
            let a = _mm256_permutevar8x32_epi32(v, idx_a);
            let b = _mm256_permutevar8x32_epi32(v, idx_b);
            let (u, w) = bfly8_ct(a, b, z);
            let out = _mm256_blend_epi32::<0xCC>(u, w);
            store8(r.as_mut_ptr().add(8 * m), out);
        }
        r
    }
}

/// Inverse NTT: mirrored layers (len 2..128), same block structure with the
/// inverse-zeta tables, then a final scale by `scale` (128^-1 mod q).
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[allow(unsafe_code)]
pub fn intt_avx2(f: &[i16; 256], zv: &[[[i32; 8]; 32]; 7], scale: i32) -> [i16; 256] {
    // SAFETY: as in `ntt_avx2`. The scalar `intt` applies `t = r[j]`,
    // `r[j] += r[j+len]`, `r[j+len] = zi*(t - r[j+len])` — replicated here
    // lane-wise with the same reductions.
    use core::arch::x86_64::*;
    unsafe {
        let mut r = *f;
        // Entry normalize: same requirement as the forward kernel.
        for m in 0..32 {
            let v = load8(r.as_ptr().add(8 * m));
            let over = _mm256_cmpgt_epi32(v, _mm256_set1_epi32(3328));
            let v = _mm256_blendv_epi8(v, _mm256_sub_epi32(v, _mm256_set1_epi32(3329)), over);
            store8(r.as_mut_ptr().add(8 * m), v);
        }
        // Layer len = 2 first (mirrors the scalar loop order). Table
        // index 6 holds the len-2 zetas (tables are stored len 128..2).
        let idx_a = _mm256_set_epi32(5, 4, 5, 4, 1, 0, 1, 0);
        let idx_b = _mm256_set_epi32(7, 6, 7, 6, 3, 2, 3, 2);
        for (m, zb) in zv[6].iter().enumerate() {
            let z = _mm256_loadu_si256(zb.as_ptr() as *const __m256i);
            let v = load8(r.as_ptr().add(8 * m));
            let t = _mm256_permutevar8x32_epi32(v, idx_a);
            let s = _mm256_permutevar8x32_epi32(v, idx_b);
            let (u, w) = bfly8(t, s, z);
            let out = _mm256_blend_epi32::<0xCC>(u, w);
            store8(r.as_mut_ptr().add(8 * m), out);
        }
        // Layer len = 4.
        let idx_lo = _mm256_set_epi32(3, 2, 1, 0, 3, 2, 1, 0);
        let idx_hi = _mm256_set_epi32(7, 6, 5, 4, 7, 6, 5, 4);
        for (m, zb) in zv[5].iter().enumerate() {
            let z = _mm256_loadu_si256(zb.as_ptr() as *const __m256i);
            let v = load8(r.as_ptr().add(8 * m));
            let t = _mm256_permutevar8x32_epi32(v, idx_lo);
            let s = _mm256_permutevar8x32_epi32(v, idx_hi);
            let (u, w) = bfly8(t, s, z);
            let out = _mm256_blend_epi32::<0xF0>(u, w);
            store8(r.as_mut_ptr().add(8 * m), out);
        }
        // Layers len = 8..128 (tables 4..0: stored order is 128..2).
        for (l, len) in [8usize, 16, 32, 64, 128].iter().enumerate() {
            let len = *len;
            let step = len / 8;
            let period = len / 4;
            for (m, zb) in zv[4 - l].iter().enumerate() {
                if m % period < step {
                    let z = _mm256_loadu_si256(zb.as_ptr() as *const __m256i);
                    let t = load8(r.as_ptr().add(8 * m));
                    let s = load8(r.as_ptr().add(8 * (m + step)));
                    let (u, w) = bfly8(t, s, z);
                    store8(r.as_mut_ptr().add(8 * m), u);
                    store8(r.as_mut_ptr().add(8 * (m + step)), w);
                }
            }
        }
        // Final scale by `scale` (values < q*scale < 2^24: Barrett-safe).
        let sc = _mm256_set1_epi32(scale);
        for m in 0..32 {
            let v = _mm256_mullo_epi32(load8(r.as_ptr().add(8 * m)), sc);
            store8(r.as_mut_ptr().add(8 * m), barrett24(v));
        }
        r
    }
}

/// NTT-domain pointwise multiply (4 pairs per iteration; gamma unpacked to
/// per-pair lanes). `g` holds the 128 per-pair moduli.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[allow(unsafe_code)]
pub fn polymul_ntt_avx2(a: &[i16; 256], b: &[i16; 256], g: &[i16; 128]) -> [i16; 256] {
    // SAFETY: as in `ntt_avx2`. Products are `< q^2 < 2^24` (inputs `< q`;
    // the dispatcher debug-asserts), so `barrett24` applies directly.
    use core::arch::x86_64::*;
    unsafe {
        let mut r = [0i16; 256];
        for p in (0..128).step_by(4) {
            let av = load8(a.as_ptr().add(2 * p));
            let bv = load8(b.as_ptr().add(2 * p));
            // [g0,g0,g1,g1 | g2,g2,g3,g3]: widen 4 gammas, duplicate to
            // both lanes, then per-lane shuffles. (An unpack-double does NOT
            // work: unpacks are lane-structured, so the high half would
            // repeat [g0,g0,g1,g1] instead of [g2,g2,g3,g3].)
            let g64 = core::ptr::read_unaligned(g.as_ptr().add(p) as *const u64);
            let g4 = _mm_cvtepi16_epi32(_mm_cvtsi64_si128(g64 as i64));
            let g8 = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(g4), g4);
            let glo = _mm256_shuffle_epi32::<0x50>(g8);
            let ghi = _mm256_shuffle_epi32::<0xFA>(g8);
            let gv = _mm256_blend_epi32::<0xF0>(glo, ghi);
            // Odd lanes hold a1/b1: shuffle pairs apart.
            let a1 = _mm256_shuffle_epi32::<0xB1>(av);
            let b1 = _mm256_shuffle_epi32::<0xB1>(bv);
            // c0 = a0*b0 + g*(a1*b1); c1 = a0*b1 + a1*b0.
            let p00 = barrett24(_mm256_mullo_epi32(av, bv));
            // (a1*b1) must be reduced BEFORE times-gamma: the raw product
            // times gamma reaches ~2^35, far past Barrett's 2^24 ceiling.
            let p11 = barrett24(_mm256_mullo_epi32(
                barrett24(_mm256_mullo_epi32(a1, b1)),
                gv,
            ));
            let p01 = barrett24(_mm256_mullo_epi32(av, b1));
            let p10 = barrett24(_mm256_mullo_epi32(a1, bv));
            let c0 = _mm256_add_epi32(p00, p11);
            let c1 = _mm256_add_epi32(p01, p10);
            // c0/c1 hold pair k's terms at lane 2k (lane 2k+1 duplicates).
            // Move c1_k to odd lanes, then blend with c0's even lanes:
            // [c0_0, c1_0, c0_1, c1_1, ...]. Even lanes of the shuffled
            // vector are never read (blend takes them from c0), so their
            // value under index 8 is irrelevant.
            let to_odd = _mm256_set_epi32(6, 8, 4, 8, 2, 8, 0, 8);
            let c1o = _mm256_permutevar8x32_epi32(c1, to_odd);
            let res = _mm256_blend_epi32::<0xAA>(c0, c1o);
            store8(r.as_mut_ptr().add(2 * p), res);
        }
        r
    }
}

/// Coefficient-wise addition, 8 lanes (sums `< 2q`, one fixup on store).
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[allow(unsafe_code)]
pub fn polyadd_avx2(a: &[i16; 256], b: &[i16; 256]) -> [i16; 256] {
    // SAFETY: as in `ntt_avx2`.
    use core::arch::x86_64::*;
    unsafe {
        let mut r = [0i16; 256];
        for m in 0..32 {
            let s = _mm256_add_epi32(load8(a.as_ptr().add(8 * m)), load8(b.as_ptr().add(8 * m)));
            store8(r.as_mut_ptr().add(8 * m), s);
        }
        r
    }
}

#[cfg(all(target_arch = "x86", target_feature = "sse2"))]
use core::arch::x86 as sse;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
use core::arch::x86_64 as sse;

/// Four parallel BLAKE3 compressions over SSE2 (`__m128i` rows, one 32-bit
/// lane per compression). Same lane-for-lane mapping as `compress8_avx2`
/// with 4 lanes; pure SSE2 (no SSE4.1: baseline-compatible with all x86
/// targets, which guarantee SSE2). Matches scalar `compress`; the
/// differential test in `chaos-hash` pins equality. `no_std` compatible.
///
/// Safety: item-scoped allow (intrinsics are `unsafe fn` by language rule);
/// register values plus two unaligned stores into valid 16-byte stack
/// slots only. No data-dependent behavior.
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
))]
#[allow(unsafe_code)]
pub fn compress4_sse2(
    cvs: &[[u32; 8]; 4],
    blocks: &[[u32; 16]; 4],
    counters: &[u64; 4],
    lens: &[u32; 4],
    flags: &[u32; 4],
) -> [[u32; 16]; 4] {
    use sse::*;
    unsafe {
        // Row r = word r of all 4 lanes. _mm_set_epi32 takes lane3 first.
        macro_rules! row4 {
            ($f:expr) => {
                _mm_set_epi32($f(3), $f(2), $f(1), $f(0))
            };
        }
        let mut v = [_mm_setzero_si128(); 16];
        for r in 0..8 {
            v[r] = row4!(|l: usize| cvs[l][r] as i32);
        }
        v[8] = _mm_set1_epi32(0x6A09E667u32 as i32);
        v[9] = _mm_set1_epi32(0xBB67AE85u32 as i32);
        v[10] = _mm_set1_epi32(0x3C6EF372u32 as i32);
        v[11] = _mm_set1_epi32(0xA54FF53Au32 as i32);
        v[12] = row4!(|l: usize| counters[l] as u32 as i32);
        v[13] = row4!(|l: usize| (counters[l] >> 32) as u32 as i32);
        v[14] = row4!(|l: usize| lens[l] as i32);
        v[15] = row4!(|l: usize| flags[l] as i32);
        let mut cvv = [_mm_setzero_si128(); 8];
        cvv.copy_from_slice(&v[..8]);
        let mut m = [_mm_setzero_si128(); 16];
        for r in 0..16 {
            m[r] = row4!(|l: usize| blocks[l][r] as i32);
        }
        for _ in 0..7 {
            let (a0, b0, c0, d0) = g4(v[0], v[4], v[8], v[12], m[0], m[1]);
            v[0] = a0;
            v[4] = b0;
            v[8] = c0;
            v[12] = d0;
            let (a1, b1, c1, d1) = g4(v[1], v[5], v[9], v[13], m[2], m[3]);
            v[1] = a1;
            v[5] = b1;
            v[9] = c1;
            v[13] = d1;
            let (a2, b2, c2, d2) = g4(v[2], v[6], v[10], v[14], m[4], m[5]);
            v[2] = a2;
            v[6] = b2;
            v[10] = c2;
            v[14] = d2;
            let (a3, b3, c3, d3) = g4(v[3], v[7], v[11], v[15], m[6], m[7]);
            v[3] = a3;
            v[7] = b3;
            v[11] = c3;
            v[15] = d3;
            let (e0, f0, g0, h0) = g4(v[0], v[5], v[10], v[15], m[8], m[9]);
            v[0] = e0;
            v[5] = f0;
            v[10] = g0;
            v[15] = h0;
            let (e1, f1, g1, h1) = g4(v[1], v[6], v[11], v[12], m[10], m[11]);
            v[1] = e1;
            v[6] = f1;
            v[11] = g1;
            v[12] = h1;
            let (e2, f2, g2, h2) = g4(v[2], v[7], v[8], v[13], m[12], m[13]);
            v[2] = e2;
            v[7] = f2;
            v[8] = g2;
            v[13] = h2;
            let (e3, f3, g3, h3) = g4(v[3], v[4], v[9], v[14], m[14], m[15]);
            v[3] = e3;
            v[4] = f3;
            v[9] = g3;
            v[14] = h3;
            let mut p = [_mm_setzero_si128(); 16];
            for i in 0..16 {
                p[i] = m[MSG_PERMUTATION[i]];
            }
            m = p;
        }
        for r in 0..8 {
            v[r] = _mm_xor_si128(v[r], v[r + 8]);
            v[r + 8] = _mm_xor_si128(v[r + 8], cvv[r]);
        }
        let mut tmp = [[0u32; 4]; 16];
        for r in 0..16 {
            _mm_storeu_si128(tmp[r].as_mut_ptr() as *mut __m128i, v[r]);
        }
        #[allow(clippy::manual_memcpy)]
        let mut out = [[0u32; 16]; 4];
        for lane in 0..4 {
            for r in 0..16 {
                out[lane][r] = tmp[r][lane];
            }
        }
        out
    }
}

/// One G mixing step over 4 lanes. Rotates via shift/or pairs (SSE2 has no
/// rotate instruction); all counts are immediates.
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
))]
#[allow(unsafe_code)]
#[inline(always)]
fn g4(
    a: sse::__m128i,
    b: sse::__m128i,
    c: sse::__m128i,
    d: sse::__m128i,
    mx: sse::__m128i,
    my: sse::__m128i,
) -> (sse::__m128i, sse::__m128i, sse::__m128i, sse::__m128i) {
    // SAFETY: register values only.
    use sse::*;
    unsafe {
        let a = _mm_add_epi32(_mm_add_epi32(a, b), mx);
        let d = _mm_xor_si128(d, a);
        let d = _mm_or_si128(_mm_srli_epi32::<16>(d), _mm_slli_epi32::<16>(d));
        let c = _mm_add_epi32(c, d);
        let b = _mm_xor_si128(b, c);
        let b = _mm_or_si128(_mm_srli_epi32::<12>(b), _mm_slli_epi32::<20>(b));
        let a = _mm_add_epi32(_mm_add_epi32(a, b), my);
        let d = _mm_xor_si128(d, a);
        let d = _mm_or_si128(_mm_srli_epi32::<8>(d), _mm_slli_epi32::<24>(d));
        let c = _mm_add_epi32(c, d);
        let b = _mm_xor_si128(b, c);
        let b = _mm_or_si128(_mm_srli_epi32::<7>(b), _mm_slli_epi32::<25>(b));
        (a, b, c, d)
    }
}

/// Four parallel BLAKE3 compressions over NEON (`uint32x4_t` rows, one lane
/// per compression). Same lane-for-lane mapping as the SSE2 tier; validated
/// under QEMU user-mode (see PLAN build log). `no_std` compatible.
///
/// Safety: item-scoped allow (intrinsics are `unsafe fn` by language rule);
/// register values plus unaligned stores into valid 16-byte stack slots
/// only. No data-dependent behavior.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
pub fn compress4_neon(
    cvs: &[[u32; 8]; 4],
    blocks: &[[u32; 16]; 4],
    counters: &[u64; 4],
    lens: &[u32; 4],
    flags: &[u32; 4],
) -> [[u32; 16]; 4] {
    use core::arch::aarch64::*;
    unsafe {
        // Row r = word r of all 4 lanes.
        macro_rules! row4 {
            ($f:expr) => {{
                let t = [$f(0), $f(1), $f(2), $f(3)];
                vld1q_u32(t.as_ptr())
            }};
        }
        let mut v = [vdupq_n_u32(0); 16];
        for r in 0..8 {
            v[r] = row4!(|l: usize| cvs[l][r]);
        }
        v[8] = vdupq_n_u32(0x6A09E667);
        v[9] = vdupq_n_u32(0xBB67AE85);
        v[10] = vdupq_n_u32(0x3C6EF372);
        v[11] = vdupq_n_u32(0xA54FF53A);
        v[12] = row4!(|l: usize| counters[l] as u32);
        v[13] = row4!(|l: usize| (counters[l] >> 32) as u32);
        v[14] = row4!(|l: usize| lens[l]);
        v[15] = row4!(|l: usize| flags[l]);
        let mut cvv = [vdupq_n_u32(0); 8];
        cvv.copy_from_slice(&v[..8]);
        let mut m = [vdupq_n_u32(0); 16];
        for r in 0..16 {
            m[r] = row4!(|l: usize| blocks[l][r]);
        }
        for _ in 0..7 {
            let (a0, b0, c0, d0) = g4n(v[0], v[4], v[8], v[12], m[0], m[1]);
            v[0] = a0;
            v[4] = b0;
            v[8] = c0;
            v[12] = d0;
            let (a1, b1, c1, d1) = g4n(v[1], v[5], v[9], v[13], m[2], m[3]);
            v[1] = a1;
            v[5] = b1;
            v[9] = c1;
            v[13] = d1;
            let (a2, b2, c2, d2) = g4n(v[2], v[6], v[10], v[14], m[4], m[5]);
            v[2] = a2;
            v[6] = b2;
            v[10] = c2;
            v[14] = d2;
            let (a3, b3, c3, d3) = g4n(v[3], v[7], v[11], v[15], m[6], m[7]);
            v[3] = a3;
            v[7] = b3;
            v[11] = c3;
            v[15] = d3;
            let (e0, f0, g0, h0) = g4n(v[0], v[5], v[10], v[15], m[8], m[9]);
            v[0] = e0;
            v[5] = f0;
            v[10] = g0;
            v[15] = h0;
            let (e1, f1, g1, h1) = g4n(v[1], v[6], v[11], v[12], m[10], m[11]);
            v[1] = e1;
            v[6] = f1;
            v[11] = g1;
            v[12] = h1;
            let (e2, f2, g2, h2) = g4n(v[2], v[7], v[8], v[13], m[12], m[13]);
            v[2] = e2;
            v[7] = f2;
            v[8] = g2;
            v[13] = h2;
            let (e3, f3, g3, h3) = g4n(v[3], v[4], v[9], v[14], m[14], m[15]);
            v[3] = e3;
            v[4] = f3;
            v[9] = g3;
            v[14] = h3;
            let mut p = [vdupq_n_u32(0); 16];
            for i in 0..16 {
                p[i] = m[MSG_PERMUTATION[i]];
            }
            m = p;
        }
        for r in 0..8 {
            v[r] = veorq_u32(v[r], v[r + 8]);
            v[r + 8] = veorq_u32(v[r + 8], cvv[r]);
        }
        let mut tmp = [[0u32; 4]; 16];
        for r in 0..16 {
            vst1q_u32(tmp[r].as_mut_ptr(), v[r]);
        }
        #[allow(clippy::manual_memcpy)]
        let mut out = [[0u32; 16]; 4];
        for lane in 0..4 {
            for r in 0..16 {
                out[lane][r] = tmp[r][lane];
            }
        }
        out
    }
}

/// 32-bit rotates by literal counts (one helper per count: NEON shift
/// intrinsics take literal immediates, and arithmetic on const-generic
/// parameters is still unstable, so no shared generic helper).
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
#[inline(always)]
fn ror16n(v: core::arch::aarch64::uint32x4_t) -> core::arch::aarch64::uint32x4_t {
    // SAFETY: register-only arithmetic.
    use core::arch::aarch64::*;
    unsafe { vorrq_u32(vshrq_n_u32::<16>(v), vshlq_n_u32::<16>(v)) }
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
#[inline(always)]
fn ror12n(v: core::arch::aarch64::uint32x4_t) -> core::arch::aarch64::uint32x4_t {
    // SAFETY: register-only arithmetic.
    use core::arch::aarch64::*;
    unsafe { vorrq_u32(vshrq_n_u32::<12>(v), vshlq_n_u32::<20>(v)) }
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
#[inline(always)]
fn ror8n(v: core::arch::aarch64::uint32x4_t) -> core::arch::aarch64::uint32x4_t {
    // SAFETY: register-only arithmetic.
    use core::arch::aarch64::*;
    unsafe { vorrq_u32(vshrq_n_u32::<8>(v), vshlq_n_u32::<24>(v)) }
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
#[inline(always)]
fn ror7n(v: core::arch::aarch64::uint32x4_t) -> core::arch::aarch64::uint32x4_t {
    // SAFETY: register-only arithmetic.
    use core::arch::aarch64::*;
    unsafe { vorrq_u32(vshrq_n_u32::<7>(v), vshlq_n_u32::<25>(v)) }
}

/// One G mixing step over 4 NEON lanes (value semantics).
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
#[inline(always)]
fn g4n(
    a: core::arch::aarch64::uint32x4_t,
    b: core::arch::aarch64::uint32x4_t,
    c: core::arch::aarch64::uint32x4_t,
    d: core::arch::aarch64::uint32x4_t,
    mx: core::arch::aarch64::uint32x4_t,
    my: core::arch::aarch64::uint32x4_t,
) -> (
    core::arch::aarch64::uint32x4_t,
    core::arch::aarch64::uint32x4_t,
    core::arch::aarch64::uint32x4_t,
    core::arch::aarch64::uint32x4_t,
) {
    // SAFETY: register values only.
    use core::arch::aarch64::*;
    unsafe {
        let a = vaddq_u32(vaddq_u32(a, b), mx);
        let d = ror16n(veorq_u32(d, a));
        let c = vaddq_u32(c, d);
        let b = ror12n(veorq_u32(b, c));
        let a = vaddq_u32(vaddq_u32(a, b), my);
        let d = ror8n(veorq_u32(d, a));
        let c = vaddq_u32(c, d);
        let b = ror7n(veorq_u32(b, c));
        (a, b, c, d)
    }
}

/// Two parallel Keccak-f[1600] permutations over SSE2 (`__m128i` = two
/// 64-bit lanes, lane k = stream k's word). Same round function as the AVX2
/// 4-way kernel, halved: all rotation amounts are immediates, chi uses
/// native `andnot`. Pure SSE2 (64-bit shifts/logic are baseline).
/// Matches 2x scalar `keccak_f`; the differential test in `chaos-hash`
/// pins equality. `no_std` compatible.
///
/// Safety: item-scoped allow; register values plus unaligned loads/stores
/// on the caller-passed state slots. No data-dependent behavior.
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
))]
#[allow(unsafe_code)]
pub fn keccak_f_x2(states: &mut [[u64; 25]; 2]) {
    use sse::*;
    unsafe {
        macro_rules! load_w {
            ($s:expr, $w:expr) => {
                _mm_set_epi64x($s[1][$w] as i64, $s[0][$w] as i64)
            };
        }
        // 64-bit rotate-left by immediate (split shift + or).
        macro_rules! rol64 {
            ($v:expr, $r:expr) => {
                _mm_or_si128(
                    _mm_slli_epi64::<{ $r }>($v),
                    _mm_srli_epi64::<{ 64 - $r }>($v),
                )
            };
        }
        let mut a = [_mm_setzero_si128(); 25];
        for w in 0..25 {
            a[w] = load_w!(states, w);
        }
        const RC: [u64; 24] = [
            0x0000000000000001,
            0x0000000000008082,
            0x800000000000808a,
            0x8000000080008000,
            0x000000000000808b,
            0x0000000080000001,
            0x8000000080008081,
            0x8000000000008009,
            0x000000000000008a,
            0x0000000000000088,
            0x0000000080008009,
            0x000000008000000a,
            0x000000008000808b,
            0x800000000000008b,
            0x8000000000008089,
            0x8000000000008003,
            0x8000000000008002,
            0x8000000000000080,
            0x000000000000800a,
            0x800000008000000a,
            0x8000000080008081,
            0x8000000000008080,
            0x0000000080000001,
            0x8000000080008008,
        ];
        for &rc in RC.iter() {
            let c0 = _mm_xor_si128(
                _mm_xor_si128(a[0], a[5]),
                _mm_xor_si128(_mm_xor_si128(a[10], a[15]), a[20]),
            );
            let c1 = _mm_xor_si128(
                _mm_xor_si128(a[1], a[6]),
                _mm_xor_si128(_mm_xor_si128(a[11], a[16]), a[21]),
            );
            let c2 = _mm_xor_si128(
                _mm_xor_si128(a[2], a[7]),
                _mm_xor_si128(_mm_xor_si128(a[12], a[17]), a[22]),
            );
            let c3 = _mm_xor_si128(
                _mm_xor_si128(a[3], a[8]),
                _mm_xor_si128(_mm_xor_si128(a[13], a[18]), a[23]),
            );
            let c4 = _mm_xor_si128(
                _mm_xor_si128(a[4], a[9]),
                _mm_xor_si128(_mm_xor_si128(a[14], a[19]), a[24]),
            );
            let d0 = _mm_xor_si128(c4, rol64!(c1, 1));
            let d1 = _mm_xor_si128(c0, rol64!(c2, 1));
            let d2 = _mm_xor_si128(c1, rol64!(c3, 1));
            let d3 = _mm_xor_si128(c2, rol64!(c4, 1));
            let d4 = _mm_xor_si128(c3, rol64!(c0, 1));
            let mut b = [_mm_setzero_si128(); 25];
            b[0] = _mm_xor_si128(a[0], d0);
            b[16] = rol64!(_mm_xor_si128(a[5], d0), 36);
            b[7] = rol64!(_mm_xor_si128(a[10], d0), 3);
            b[23] = rol64!(_mm_xor_si128(a[15], d0), 41);
            b[14] = rol64!(_mm_xor_si128(a[20], d0), 18);
            b[10] = rol64!(_mm_xor_si128(a[1], d1), 1);
            b[1] = rol64!(_mm_xor_si128(a[6], d1), 44);
            b[17] = rol64!(_mm_xor_si128(a[11], d1), 10);
            b[8] = rol64!(_mm_xor_si128(a[16], d1), 45);
            b[24] = rol64!(_mm_xor_si128(a[21], d1), 2);
            b[20] = rol64!(_mm_xor_si128(a[2], d2), 62);
            b[11] = rol64!(_mm_xor_si128(a[7], d2), 6);
            b[2] = rol64!(_mm_xor_si128(a[12], d2), 43);
            b[18] = rol64!(_mm_xor_si128(a[17], d2), 15);
            b[9] = rol64!(_mm_xor_si128(a[22], d2), 61);
            b[5] = rol64!(_mm_xor_si128(a[3], d3), 28);
            b[21] = rol64!(_mm_xor_si128(a[8], d3), 55);
            b[12] = rol64!(_mm_xor_si128(a[13], d3), 25);
            b[3] = rol64!(_mm_xor_si128(a[18], d3), 21);
            b[19] = rol64!(_mm_xor_si128(a[23], d3), 56);
            b[15] = rol64!(_mm_xor_si128(a[4], d4), 27);
            b[6] = rol64!(_mm_xor_si128(a[9], d4), 20);
            b[22] = rol64!(_mm_xor_si128(a[14], d4), 39);
            b[13] = rol64!(_mm_xor_si128(a[19], d4), 8);
            b[4] = rol64!(_mm_xor_si128(a[24], d4), 14);
            macro_rules! chi {
                ($y:expr) => {
                    a[5 * $y] =
                        _mm_xor_si128(b[5 * $y], _mm_andnot_si128(b[5 * $y + 1], b[5 * $y + 2]));
                    a[5 * $y + 1] = _mm_xor_si128(
                        b[5 * $y + 1],
                        _mm_andnot_si128(b[5 * $y + 2], b[5 * $y + 3]),
                    );
                    a[5 * $y + 2] = _mm_xor_si128(
                        b[5 * $y + 2],
                        _mm_andnot_si128(b[5 * $y + 3], b[5 * $y + 4]),
                    );
                    a[5 * $y + 3] =
                        _mm_xor_si128(b[5 * $y + 3], _mm_andnot_si128(b[5 * $y + 4], b[5 * $y]));
                    a[5 * $y + 4] =
                        _mm_xor_si128(b[5 * $y + 4], _mm_andnot_si128(b[5 * $y], b[5 * $y + 1]));
                };
            }
            chi!(0);
            chi!(1);
            chi!(2);
            chi!(3);
            chi!(4);
            a[0] = _mm_xor_si128(a[0], _mm_set_epi64x(rc as i64, rc as i64));
        }
        // Transpose back to state-major memory. (`_mm_cvtsi128_si64` would
        // do this in registers but is x86-64-only; a store keeps the kernel
        // compiling on 32-bit x86 too.)
        for w in 0..25 {
            let mut tmp = [0u64; 2];
            _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, a[w]);
            states[0][w] = tmp[0];
            states[1][w] = tmp[1];
        }
    }
}

/// 64-bit rotate-right helpers, one per literal count used by Keccak
/// (shift intrinsics take literal immediates; a macro stamps them out).
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
macro_rules! def_ror64 {
    ($name:ident, $r:literal, $s:literal) => {
        #[allow(unsafe_code)]
        #[inline(always)]
        fn $name(v: core::arch::aarch64::uint64x2_t) -> core::arch::aarch64::uint64x2_t {
            // SAFETY: register-only arithmetic.
            use core::arch::aarch64::*;
            unsafe { vorrq_u64(vshrq_n_u64::<$r>(v), vshlq_n_u64::<$s>(v)) }
        }
    };
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_1, 1, 63);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_2, 2, 62);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_3, 3, 61);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_6, 6, 58);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_8, 8, 56);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_10, 10, 54);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_14, 14, 50);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_15, 15, 49);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_18, 18, 46);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_20, 20, 44);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_21, 21, 43);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_25, 25, 39);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_27, 27, 37);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_28, 28, 36);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_36, 36, 28);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_39, 39, 25);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_41, 41, 23);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_43, 43, 21);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_44, 44, 20);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_45, 45, 19);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_55, 55, 9);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_56, 56, 8);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_61, 61, 3);
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
def_ror64!(ror64_62, 62, 2);

/// Two parallel Keccak-f[1600] permutations over NEON (`uint64x2_t` = two
/// 64-bit lanes). Same mapping as the SSE2 twin; validated under QEMU.
/// `no_std` compatible.
///
/// Safety: item-scoped allow; register values plus stores into the
/// caller-passed state slots. No data-dependent behavior.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
pub fn keccak_f_x2_neon(states: &mut [[u64; 25]; 2]) {
    use core::arch::aarch64::*;
    unsafe {
        macro_rules! load_w {
            ($s:expr, $w:expr) => {{
                let t = [$s[0][$w], $s[1][$w]];
                vld1q_u64(t.as_ptr())
            }};
        }
        let mut a = [vdupq_n_u64(0); 25];
        for w in 0..25 {
            a[w] = load_w!(states, w);
        }
        const RC: [u64; 24] = [
            0x0000000000000001,
            0x0000000000008082,
            0x800000000000808a,
            0x8000000080008000,
            0x000000000000808b,
            0x0000000080000001,
            0x8000000080008081,
            0x8000000000008009,
            0x000000000000008a,
            0x0000000000000088,
            0x0000000080008009,
            0x000000008000000a,
            0x000000008000808b,
            0x800000000000008b,
            0x8000000000008089,
            0x8000000000008003,
            0x8000000000008002,
            0x8000000000000080,
            0x000000000000800a,
            0x800000008000000a,
            0x8000000080008081,
            0x8000000000008080,
            0x0000000080000001,
            0x8000000080008008,
        ];
        for &rc in RC.iter() {
            let c0 = veorq_u64(
                veorq_u64(a[0], a[5]),
                veorq_u64(veorq_u64(a[10], a[15]), a[20]),
            );
            let c1 = veorq_u64(
                veorq_u64(a[1], a[6]),
                veorq_u64(veorq_u64(a[11], a[16]), a[21]),
            );
            let c2 = veorq_u64(
                veorq_u64(a[2], a[7]),
                veorq_u64(veorq_u64(a[12], a[17]), a[22]),
            );
            let c3 = veorq_u64(
                veorq_u64(a[3], a[8]),
                veorq_u64(veorq_u64(a[13], a[18]), a[23]),
            );
            let c4 = veorq_u64(
                veorq_u64(a[4], a[9]),
                veorq_u64(veorq_u64(a[14], a[19]), a[24]),
            );
            let d0 = veorq_u64(c4, ror64_1(c1));
            let d1 = veorq_u64(c0, ror64_1(c2));
            let d2 = veorq_u64(c1, ror64_1(c3));
            let d3 = veorq_u64(c2, ror64_1(c4));
            let d4 = veorq_u64(c3, ror64_1(c0));
            let mut b = [vdupq_n_u64(0); 25];
            b[0] = veorq_u64(a[0], d0);
            b[16] = ror64_36(veorq_u64(a[5], d0));
            b[7] = ror64_3(veorq_u64(a[10], d0));
            b[23] = ror64_41(veorq_u64(a[15], d0));
            b[14] = ror64_18(veorq_u64(a[20], d0));
            b[10] = ror64_1(veorq_u64(a[1], d1));
            b[1] = ror64_44(veorq_u64(a[6], d1));
            b[17] = ror64_10(veorq_u64(a[11], d1));
            b[8] = ror64_45(veorq_u64(a[16], d1));
            b[24] = ror64_2(veorq_u64(a[21], d1));
            b[20] = ror64_62(veorq_u64(a[2], d2));
            b[11] = ror64_6(veorq_u64(a[7], d2));
            b[2] = ror64_43(veorq_u64(a[12], d2));
            b[18] = ror64_15(veorq_u64(a[17], d2));
            b[9] = ror64_61(veorq_u64(a[22], d2));
            b[5] = ror64_28(veorq_u64(a[3], d3));
            b[21] = ror64_55(veorq_u64(a[8], d3));
            b[12] = ror64_25(veorq_u64(a[13], d3));
            b[3] = ror64_21(veorq_u64(a[18], d3));
            b[19] = ror64_56(veorq_u64(a[23], d3));
            b[15] = ror64_27(veorq_u64(a[4], d4));
            b[6] = ror64_20(veorq_u64(a[9], d4));
            b[22] = ror64_39(veorq_u64(a[14], d4));
            b[13] = ror64_8(veorq_u64(a[19], d4));
            b[4] = ror64_14(veorq_u64(a[24], d4));
            macro_rules! chi {
                ($y:expr) => {
                    a[5 * $y] = veorq_u64(b[5 * $y], vbicq_u64(b[5 * $y + 2], b[5 * $y + 1]));
                    a[5 * $y + 1] =
                        veorq_u64(b[5 * $y + 1], vbicq_u64(b[5 * $y + 3], b[5 * $y + 2]));
                    a[5 * $y + 2] =
                        veorq_u64(b[5 * $y + 2], vbicq_u64(b[5 * $y + 4], b[5 * $y + 3]));
                    a[5 * $y + 3] = veorq_u64(b[5 * $y + 3], vbicq_u64(b[5 * $y], b[5 * $y + 4]));
                    a[5 * $y + 4] = veorq_u64(b[5 * $y + 4], vbicq_u64(b[5 * $y + 1], b[5 * $y]));
                };
            }
            chi!(0);
            chi!(1);
            chi!(2);
            chi!(3);
            chi!(4);
            a[0] = veorq_u64(a[0], vdupq_n_u64(rc));
        }
        for w in 0..25 {
            states[0][w] = vgetq_lane_u64::<0>(a[w]);
            states[1][w] = vgetq_lane_u64::<1>(a[w]);
        }
    }
}

/// Widen 4 coefficients to a `uint32x4_t`: `vshll` (shift-and-widen)
/// preserves all four lanes (unlike `vmovl`, which halves them), so no
/// paired-block loading is needed and every vector stands alone.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
#[inline(always)]
fn load4n(p: *const i16) -> core::arch::aarch64::uint32x4_t {
    // SAFETY: caller guarantees 4 readable i16.
    use core::arch::aarch64::*;
    unsafe { vreinterpretq_u32_s32(vshll_n_s16::<0>(vld1_s16(p))) }
}

/// Narrow a `uint32x4_t` (`[0, 2q)` lanes) to 4 coefficients.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
#[inline(always)]
fn narrow4n(p: *mut i16, v: core::arch::aarch64::uint32x4_t) {
    // SAFETY: caller guarantees 4 writable i16. Saturation never fires
    // (values `< 2q << 2^15` after the conditional subtract).
    use core::arch::aarch64::*;
    unsafe {
        let over = vcgtq_u32(v, vdupq_n_u32(3328));
        let v = vbslq_u32(over, vsubq_u32(v, vdupq_n_u32(3329)), v);
        vst1_s16(p, vreinterpret_s16_u16(vqmovn_u32(v)));
    }
}

/// 32-bit Barrett reduction for values `< 2^24` mod 3329, 4 lanes (NEON).
/// Same split-range derivation as the 32-bit tiers (`v = hi*2^16+lo`,
/// `2^16 mod q = 2285`, `MU = floor(2^20/q) = 314`, single fixup for
/// `w < 1076426`). NEON has full 32-bit multiply (`vmulq_u32`, exact since
/// all intermediates fit 32 bits) plus bitwise select, so the reduction is
/// straight-line with no halves dance.
///
/// Safety: register-only arithmetic.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
#[inline(always)]
fn barrett2n(v: core::arch::aarch64::uint32x4_t) -> core::arch::aarch64::uint32x4_t {
    use core::arch::aarch64::*;
    unsafe {
        let hi = vshrq_n_u32::<16>(v);
        let lo = vandq_u32(v, vdupq_n_u32(0xFFFF));
        let w = vaddq_u32(vmulq_u32(hi, vdupq_n_u32(2285)), lo);
        let t = vshrq_n_u32::<20>(vmulq_u32(w, vdupq_n_u32(314)));
        let r = vsubq_u32(w, vmulq_u32(t, vdupq_n_u32(3329)));
        let over = vcgtq_u32(r, vdupq_n_u32(3328));
        vbslq_u32(over, vsubq_u32(r, vdupq_n_u32(3329)), r)
    }
}

/// One 4-lane butterfly column: `(u, w) = (a + z*b, a - z*b)` (forward) with
/// all values reduced to `[0, q)`. `z` holds the broadcast zeta.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
#[inline(always)]
fn bfly4n(
    a: core::arch::aarch64::uint32x4_t,
    b: core::arch::aarch64::uint32x4_t,
    z: core::arch::aarch64::uint32x4_t,
) -> (
    core::arch::aarch64::uint32x4_t,
    core::arch::aarch64::uint32x4_t,
) {
    // SAFETY: register-only arithmetic (z, b < q so products fit the
    // Barrett ceiling; differences pre-biased non-negative like `bfly8`).
    use core::arch::aarch64::*;
    unsafe {
        let q = vdupq_n_u32(3329);
        let t = barrett2n(vmulq_u32(z, b));
        let u = vaddq_u32(a, t);
        let over = vcgtq_u32(u, vdupq_n_u32(3328));
        let u = vbslq_u32(over, vsubq_u32(u, q), u);
        // a - t in (-q, q): computed unsigned it wraps, so the
        // negativity test reinterprets lanes as SIGNED (mask is bitwise).
        let d = vsubq_u32(a, t);
        // vbsl masks are same-width vectors (no u8 reinterpret needed).
        let neg = vcltq_s32(vreinterpretq_s32_u32(d), vdupq_n_s32(0));
        let w = vbslq_u32(neg, vaddq_u32(d, q), d);
        (u, w)
    }
}

/// vtbl index tables for the len-2 layer (byte lanes): duplicate halves for
/// the pair inputs, grouped output.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
const IDX4_A: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7];
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
const IDX4_B: [u8; 16] = [8, 9, 10, 11, 12, 13, 14, 15, 8, 9, 10, 11, 12, 13, 14, 15];
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
const IDX4_OU: [u8; 16] = [
    0, 1, 2, 3, 4, 5, 6, 7, 255, 255, 255, 255, 255, 255, 255, 255,
];
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
const IDX4_OW: [u8; 16] = [
    255, 255, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7,
];

/// Forward NTT over 256 coefficients, 4-wide NEON. `zv[layer][block]`
/// holds the block's zeta broadcast 4x (one zeta per 4-coeff block: every
/// layer's groups are block-aligned at this width, so no split layouts).
/// Entry values must be `< 2q` (normalized on load, matching scalar).
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
pub fn ntt4_neon(f: &[i16; 256], zv: &[[[i32; 4]; 64]; 7]) -> [i16; 256] {
    // SAFETY: loads/stores hit in-bounds poly blocks; the rest is register
    // arithmetic. Same contract as scalar `ntt` (natural order in and out).
    use core::arch::aarch64::*;
    unsafe {
        let mut r = *f;
        // Layers len = 128..8: strided block pairs, per-vector condition.
        for (l, len) in [128usize, 64, 32, 16, 8].iter().enumerate() {
            let len = *len;
            let step = len / 4;
            let period = len / 2;
            for m in 0..64 {
                if m % period < step {
                    let z = vld1q_s32(zv[l][m].as_ptr());
                    let zu = vreinterpretq_u32_s32(z);
                    let a = load4n(r.as_ptr().add(4 * m));
                    let b = load4n(r.as_ptr().add(4 * (m + step)));
                    let (u, w) = bfly4n(a, b, zu);
                    narrow4n(r.as_mut_ptr().add(4 * m), u);
                    narrow4n(r.as_mut_ptr().add(4 * (m + step)), w);
                }
            }
        }
        // Layer len = 4: adjacent pairs (2k, 2k+1), elementwise, one zeta.
        for k in 0..32 {
            let z = vld1q_s32(zv[5][2 * k].as_ptr());
            let zu = vreinterpretq_u32_s32(z);
            let a = load4n(r.as_ptr().add(8 * k));
            let b = load4n(r.as_ptr().add(8 * k + 4));
            let (u, w) = bfly4n(a, b, zu);
            narrow4n(r.as_mut_ptr().add(8 * k), u);
            narrow4n(r.as_mut_ptr().add(8 * k + 4), w);
        }
        // Layer len = 2: in-vector pairs (0,2),(1,3) via vtbl shuffles.
        let ia = vld1q_u8(IDX4_A.as_ptr());
        let ib = vld1q_u8(IDX4_B.as_ptr());
        let iou = vld1q_u8(IDX4_OU.as_ptr());
        let iow = vld1q_u8(IDX4_OW.as_ptr());
        for m in 0..64 {
            let z = vld1q_s32(zv[6][m].as_ptr());
            let zu = vreinterpretq_u32_s32(z);
            let v = load4n(r.as_ptr().add(4 * m));
            let vu8 = vreinterpretq_u8_u32(v);
            let a = vreinterpretq_u32_u8(vqtbl1q_u8(vu8, ia));
            let b = vreinterpretq_u32_u8(vqtbl1q_u8(vu8, ib));
            let (u, w) = bfly4n(a, b, zu);
            let uu8 = vreinterpretq_u8_u32(u);
            let wu8 = vreinterpretq_u8_u32(w);
            let out = vorrq_u8(vqtbl1q_u8(uu8, iou), vqtbl1q_u8(wu8, iow));
            narrow4n(r.as_mut_ptr().add(4 * m), vreinterpretq_u32_u8(out));
        }
        r
    }
}

/// Inverse NTT: mirrored layers (len 2..128), same block structure with the
/// inverse-zeta tables, then a final scale by `scale` (128^-1 mod q).
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
pub fn intt4_neon(f: &[i16; 256], zv: &[[[i32; 4]; 64]; 7], scale: i32) -> [i16; 256] {
    // SAFETY: as in `ntt4_neon`. The scalar `intt` applies `t = r[j]`,
    // `r[j] += r[j+len]`, `r[j+len] = zi*(t - r[j+len])` — replicated here
    // lane-wise (Gentleman-Sande shape, same as the inverse AVX2 path).
    use core::arch::aarch64::*;
    unsafe {
        let mut r = *f;
        let ia = vld1q_u8(IDX4_A.as_ptr());
        let ib = vld1q_u8(IDX4_B.as_ptr());
        let iou = vld1q_u8(IDX4_OU.as_ptr());
        let iow = vld1q_u8(IDX4_OW.as_ptr());
        // Layer len = 2 first.
        for m in 0..64 {
            let z = vld1q_s32(zv[6][m].as_ptr());
            let zu = vreinterpretq_u32_s32(z);
            let v = load4n(r.as_ptr().add(4 * m));
            let vu8 = vreinterpretq_u8_u32(v);
            let t = vreinterpretq_u32_u8(vqtbl1q_u8(vu8, ia));
            let s = vreinterpretq_u32_u8(vqtbl1q_u8(vu8, ib));
            let (u, w) = bfly4n_gs(t, s, zu);
            let uu8 = vreinterpretq_u8_u32(u);
            let wu8 = vreinterpretq_u8_u32(w);
            let out = vorrq_u8(vqtbl1q_u8(uu8, iou), vqtbl1q_u8(wu8, iow));
            narrow4n(r.as_mut_ptr().add(4 * m), vreinterpretq_u32_u8(out));
        }
        // Layer len = 4.
        for k in 0..32 {
            let z = vld1q_s32(zv[5][2 * k].as_ptr());
            let zu = vreinterpretq_u32_s32(z);
            let t = load4n(r.as_ptr().add(8 * k));
            let s = load4n(r.as_ptr().add(8 * k + 4));
            let (u, w) = bfly4n_gs(t, s, zu);
            narrow4n(r.as_mut_ptr().add(8 * k), u);
            narrow4n(r.as_mut_ptr().add(8 * k + 4), w);
        }
        // Layers len = 8..128.
        for (l, len) in [8usize, 16, 32, 64, 128].iter().enumerate() {
            let len = *len;
            let step = len / 4;
            let period = len / 2;
            for m in 0..64 {
                if m % period < step {
                    let z = vld1q_s32(zv[4 - l][m].as_ptr());
                    let zu = vreinterpretq_u32_s32(z);
                    let t = load4n(r.as_ptr().add(4 * m));
                    let s = load4n(r.as_ptr().add(4 * (m + step)));
                    let (u, w) = bfly4n_gs(t, s, zu);
                    narrow4n(r.as_mut_ptr().add(4 * m), u);
                    narrow4n(r.as_mut_ptr().add(4 * (m + step)), w);
                }
            }
        }
        // Final scale by `scale` (values < q*scale < 2^24: Barrett-safe).
        let sc = vdupq_n_u32(scale as u32);
        for m in 0..64 {
            let v = vmulq_u32(load4n(r.as_ptr().add(4 * m)), sc);
            narrow4n(r.as_mut_ptr().add(4 * m), barrett2n(v));
        }
        r
    }
}

/// Gentleman-Sande butterfly column (inverse NTT): `(u, w) = (a+b, z*(a-b))`.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
#[inline(always)]
fn bfly4n_gs(
    a: core::arch::aarch64::uint32x4_t,
    b: core::arch::aarch64::uint32x4_t,
    z: core::arch::aarch64::uint32x4_t,
) -> (
    core::arch::aarch64::uint32x4_t,
    core::arch::aarch64::uint32x4_t,
) {
    // SAFETY: register-only arithmetic.
    use core::arch::aarch64::*;
    unsafe {
        let q = vdupq_n_u32(3329);
        let u = vaddq_u32(a, b);
        let over = vcgtq_u32(u, vdupq_n_u32(3328));
        let u = vbslq_u32(over, vsubq_u32(u, q), u);
        let d = vsubq_u32(a, b);
        let neg = vcltq_s32(vreinterpretq_s32_u32(d), vdupq_n_s32(0));
        let d = vbslq_u32(neg, vaddq_u32(d, q), d);
        let v = barrett2n(vmulq_u32(z, d));
        (u, v)
    }
}

/// NTT-domain pointwise multiply (2 pairs per vector; gamma unpacked to
/// per-pair lanes). `g` holds the 128 per-pair moduli.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
pub fn polymul4_neon(a: &[i16; 256], b: &[i16; 256], g: &[i16; 128]) -> [i16; 256] {
    // SAFETY: as in `ntt4_neon`. Inner products are reduced before the
    // times-gamma multiply (same double-width guard as the AVX2 path).
    use core::arch::aarch64::*;
    unsafe {
        let mut r = [0i16; 256];
        for p in (0..128).step_by(2) {
            let av = load4n(a.as_ptr().add(2 * p));
            let bv = load4n(b.as_ptr().add(2 * p));
            // [g0,g0,g1,g1]: widen 2 gammas, duplicate adjacent.
            let g2 = vreinterpretq_u32_s32(vshll_n_s16::<0>(vld1_s16(g.as_ptr().add(p))));
            let gv = vzipq_u32(g2, g2).0;
            // Odd lanes hold a1/b1: reverse pairs within 64-bit halves.
            let a1 = vrev64q_u32(av);
            let b1 = vrev64q_u32(bv);
            let p00 = barrett2n(vmulq_u32(av, bv));
            let p11 = barrett2n(vmulq_u32(barrett2n(vmulq_u32(a1, b1)), gv));
            let p01 = barrett2n(vmulq_u32(av, b1));
            let p10 = barrett2n(vmulq_u32(a1, bv));
            let c0 = vaddq_u32(p00, p11);
            let c1 = vaddq_u32(p01, p10);
            // Interleave back to pair order: vtrn gives [c0_0,c1_0,c0_1,c1_1].
            let res = vtrnq_u32(c0, c1).0;
            narrow4n(r.as_mut_ptr().add(2 * p), res);
        }
        r
    }
}

/// Coefficient-wise addition, 4 lanes (sums `< 2q`, one fixup on store).
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[allow(unsafe_code)]
pub fn polyadd4_neon(a: &[i16; 256], b: &[i16; 256]) -> [i16; 256] {
    // SAFETY: as in `ntt4_neon`.
    use core::arch::aarch64::*;
    unsafe {
        let mut r = [0i16; 256];
        for m in 0..64 {
            let s = vaddq_u32(load4n(a.as_ptr().add(4 * m)), load4n(b.as_ptr().add(4 * m)));
            narrow4n(r.as_mut_ptr().add(4 * m), s);
        }
        r
    }
}

/// Regression tests for the two subtlest AVX2 details: the Barrett
/// constant derivation and the lane-structured pack in narrowing.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[cfg(test)]
mod ntt_unit_tests {
    use super::{barrett24, load8, store8};
    use core::arch::x86_64::*;

    #[test]
    #[allow(unsafe_code)]
    fn barrett24_known_answers() {
        extern crate std;
        unsafe {
            // Lanes (low to high): 1, q-1, 0, q^2 (->0), q (->0), q+1, 2q (->q), 100.
            let v = _mm256_set_epi32(100, 6658, 3330, 3329, 11082241, 0, 3328, 1);
            let r = barrett24(v);
            let mut out = [0i32; 8];
            _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, r);
            assert_eq!(out, [1, 3328, 0, 0, 0, 1, 0, 100]);
        }
    }

    #[test]
    fn narrow_roundtrip_no_half_dup() {
        // Distinct lanes: catches packs_epi32 lane-structure bugs that
        // duplicate the low half (all-duplicate inputs stay blind). No
        // unsafe here: load8/store8 are safe entry points.
        let src = [1i16, 2, 3, 4, 5, 6, 7, 8];
        let mut dst = [0i16; 8];
        store8(dst.as_mut_ptr(), load8(src.as_ptr()));
        assert_eq!(dst, src);
        // Reduction on store: 2q-1 entries land in [0, q).
        // Inputs honor the [0, 2q) contract (2q itself excluded).
        let big = [6657i16, 6656, 3329, 3328, 0, 1, 5000, 6000];
        let mut dst2 = [0i16; 8];
        store8(dst2.as_mut_ptr(), load8(big.as_ptr()));
        assert_eq!(dst2, [3328, 3327, 0, 3328, 0, 1, 1671, 2671]);
    }
}
