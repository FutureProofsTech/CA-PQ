//! CA-PQ `chaos-mlkem`: ML-KEM-768 from zero (FIPS 203 shape), no external code.
//!
//! Hybrid-ready lattice KEM: k = 3, q = 3329, Carter-Wegman-free plain
//! modular arithmetic (reference clarity over speed), SHAKE/SHA3 from the
//! in-tree Keccak code. Caller supplies all randomness (deterministic API):
//! `keygen(d, z)`, `encaps(ek, m)`, `decaps(dk, ct)`.
//!
//! Design notes (deliberate, documented):
//! - The matrix seed (rho) and noise seed (sigma) split from `SHA3-512(d)`:
//!   matrix from rho (public), noise from sigma (secret, wiped after use).
//! - NTT twiddle order and pair moduli verified by roundtrip + homomorphism
//!   checks; no interoperation claim with other implementations is made.
//! - Not constant-time beyond branchless field swaps and tag comparison;
//!   audit required before any use beyond experiments.

#![no_std]
#![forbid(unsafe_code)]

mod codec;
mod ntt;

use chaos_core::{burn, burn_words};
use chaos_hash::{sha3_256, sha3_512, shake256};
use codec::{byte_decode, byte_encode, compress, decompress};
use ntt::{intt, polyadd, polymul_ntt, N};

pub const K: usize = 3;
pub const ETA1: usize = 2;
pub const ETA2: usize = 2;
pub const DU: usize = 10;
pub const DV: usize = 4;

pub const EK_LEN: usize = 1184;
pub const DK_LEN: usize = 2400;
pub const CT_LEN: usize = 1088;
pub const SS_LEN: usize = 32;

/// Security-profile parameters shared by the generic KEM core. ML-KEM-512
/// (NIST level 1) and ML-KEM-768 (NIST level 3) differ only in K, the
/// noise width ETA1, and the resulting wire sizes; NTT, sampling XOF,
/// compression widths, and ETA2 are identical.
pub trait Profile {
    /// Module dimension.
    const K: usize;
    /// Noise width for s, e, y, e1 (2 for 768, 3 for 512).
    const ETA1: usize;
    /// Noise width for e2 (2 for both profiles).
    const ETA2: usize;
    /// Wire sizes in bytes.
    const EK_LEN: usize;
    const DK_LEN: usize;
    const CT_LEN: usize;
}

/// ML-KEM-768 parameters (NIST level 3). Top-level API below.
pub struct P768;
impl Profile for P768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const EK_LEN: usize = 1184;
    const DK_LEN: usize = 2400;
    const CT_LEN: usize = 1088;
}

/// ML-KEM-512 parameters (NIST level 1). See the `m512` module.
pub struct P512;
impl Profile for P512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const EK_LEN: usize = 800;
    const DK_LEN: usize = 1632;
    const CT_LEN: usize = 768;
}

/// Maximum module dimension across profiles; runtime `k` selects the prefix.
const KMAX: usize = 3;

type Poly = [i16; N];
type PolyVec = [Poly; KMAX];
type Matrix = [[Poly; KMAX]; KMAX];

/// SHAKE256 with caller-length output (PRF widths 128/192 for eta 2/3).
pub(crate) fn shake256_raw(data: &[u8], out: &mut [u8]) {
    shake256(data, out);
}

fn ntt_vec(k: usize, v: &[Poly]) -> PolyVec {
    let mut r = [[0i16; N]; KMAX];
    for i in 0..k {
        r[i] = ntt::ntt(&v[i]);
    }
    r
}

/// Matrix-vector product in the NTT domain: out[i] = sum_j A[i][j] (*) s[j].
fn mat_vec_mul(k: usize, a: &Matrix, s: &[Poly]) -> PolyVec {
    let mut out = [[0i16; N]; KMAX];
    for i in 0..k {
        let mut acc = [0i16; N];
        for j in 0..k {
            acc = polyadd(&acc, &polymul_ntt(&a[i][j], &s[j]));
        }
        out[i] = acc;
    }
    out
}

/// Inner product in the NTT domain: sum_j a[j] (*) b[j].
fn vec_dot(k: usize, a: &[Poly], b: &[Poly]) -> Poly {
    let mut acc = [0i16; N];
    for j in 0..k {
        acc = polyadd(&acc, &polymul_ntt(&a[j], &b[j]));
    }
    acc
}

fn sample_matrix(k: usize, rho: &[u8; 32], transpose: bool) -> Matrix {
    let mut a: Matrix = [[[0i16; N]; KMAX]; KMAX];
    // Positions in fill order with the transpose mapping applied.
    let mut pairs = [(0u8, 0u8); KMAX * KMAX];
    for i in 0..k {
        for j in 0..k {
            pairs[i * k + j] = if transpose {
                (j as u8, i as u8)
            } else {
                (i as u8, j as u8)
            };
        }
    }
    // Full 4-batches (joint XOF under AVX2) + scalar tail. Fill order is
    // unchanged, so the matrix is bit-identical to the scalar path
    // (k=3: 4+4+1; k=2: exactly one batch).
    let n = k * k;
    let mut t = 0;
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    while t + 4 <= n {
        let b = codec::sample_ntt_x4(rho, [pairs[t], pairs[t + 1], pairs[t + 2], pairs[t + 3]]);
        for q in 0..4 {
            a[(t + q) / k][(t + q) % k] = b[q];
        }
        t += 4;
    }
    while t < n {
        let (x, y) = pairs[t];
        a[t / k][t % k] = codec::sample_ntt(rho, x, y);
        t += 1;
    }
    a
}

/// Fill `out` with CBD polys from PRF(eta, seed, start..): 4-batches under
/// AVX2 (one `prf_x4` + prefix CBDs), scalar tail otherwise. Counter values
/// — and hence polys — identical either way.
fn sample_cbd_vec(eta: usize, seed: &[u8; 32], start: u8, out: &mut [Poly]) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        let n = out.len();
        let mut t = 0;
        let mut c = start;
        while t + 4 <= n {
            let b = codec::prf_x4(seed, [c, c + 1, c + 2, c + 3]);
            for q in 0..4 {
                out[t + q] = codec::cbd_eta(eta, &b[q][..64 * eta]);
            }
            t += 4;
            c += 4;
        }
        while t < n {
            let mut buf = [0u8; 192];
            codec::prf_eta(eta, seed, c, &mut buf[..64 * eta]);
            out[t] = codec::cbd_eta(eta, &buf[..64 * eta]);
            t += 1;
            c += 1;
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    {
        for (c, v) in (start..).zip(out.iter_mut()) {
            let mut buf = [0u8; 192];
            codec::prf_eta(eta, seed, c, &mut buf[..64 * eta]);
            *v = codec::cbd_eta(eta, &buf[..64 * eta]);
        }
    }
}

/// Split ek into decoded t-hat polys and rho (first k 384 B blocks + seed).
fn split_ek(k: usize, ek: &[u8]) -> (PolyVec, [u8; 32]) {
    let mut tv = [[0i16; N]; KMAX];
    for i in 0..k {
        let mut raw = [0u8; 384];
        raw.copy_from_slice(&ek[i * 384..(i + 1) * 384]);
        tv[i] = byte_decode::<12, 384>(&raw);
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[k * 384..k * 384 + 32]);
    (tv, rho)
}

fn message_poly(m: &[u8; 32]) -> Poly {
    let mut f = [0i16; N];
    for i in 0..N {
        if (m[i / 8] >> (i % 8)) & 1 == 1 {
            f[i] = 1665; // (q+1)/2
        }
    }
    f
}

/// K-PKE key generation: matrix from rho, noise from sigma.
/// Counters 0..2k-1 across (s, e); identical polys on every path.
fn pke_keygen<P: Profile>(rho: &[u8; 32], sigma: &[u8; 32]) -> (PolyVec, PolyVec) {
    let k = P::K;
    let a = sample_matrix(k, rho, false);
    let mut s = [[0i16; N]; KMAX];
    let mut e = [[0i16; N]; KMAX];
    sample_cbd_vec(P::ETA1, sigma, 0, &mut s[..k]);
    sample_cbd_vec(P::ETA1, sigma, k as u8, &mut e[..k]);
    let shat = ntt_vec(k, &s);
    let ehat = ntt_vec(k, &e);
    let mut that = mat_vec_mul(k, &a, &shat);
    for i in 0..k {
        that[i] = polyadd(&that[i], &ehat[i]);
    }
    for v in e.iter_mut().take(k) {
        burn_words(v);
    }
    (that, s)
}

/// Long-term keypair from caller randomness. Burns nothing owned by caller.
fn keygen_p<P: Profile>(d: &[u8; 32], z: &[u8; 32], ek: &mut [u8], dk: &mut [u8]) {
    let k = P::K;
    assert_eq!(ek.len(), P::EK_LEN);
    assert_eq!(dk.len(), P::DK_LEN);
    let mut h = sha3_512(d);
    let (rho, mut sigma): ([u8; 32], [u8; 32]) =
        (h[..32].try_into().unwrap(), h[32..].try_into().unwrap());
    burn(&mut h);
    let (that, mut s) = pke_keygen::<P>(&rho, &sigma);
    burn(&mut sigma);
    for i in 0..k {
        let enc: [u8; 384] = byte_encode::<12, 384>(&that[i]);
        ek[i * 384..(i + 1) * 384].copy_from_slice(&enc);
    }
    ek[k * 384..k * 384 + 32].copy_from_slice(&rho);
    for i in 0..k {
        let enc: [u8; 384] = byte_encode::<12, 384>(&s[i]);
        dk[i * 384..(i + 1) * 384].copy_from_slice(&enc);
    }
    for v in s.iter_mut().take(k) {
        burn_words(v);
    }
    let s_len = k * 384;
    dk[s_len..s_len + P::EK_LEN].copy_from_slice(ek);
    dk[s_len + P::EK_LEN..s_len + P::EK_LEN + 32].copy_from_slice(&sha3_256(ek));
    dk[s_len + P::EK_LEN + 32..].copy_from_slice(z);
}

/// Long-term keypair from caller randomness. Burns nothing owned by caller.
pub fn keygen(d: &[u8; 32], z: &[u8; 32]) -> ([u8; EK_LEN], [u8; DK_LEN]) {
    let mut ek = [0u8; EK_LEN];
    let mut dk = [0u8; DK_LEN];
    keygen_p::<P768>(d, z, &mut ek, &mut dk);
    (ek, dk)
}

/// K-PKE encryption of message bytes under ephemeral coins, with the
/// public matrix supplied precomputed (lets batch callers amortize the
/// 9-way `sample_matrix` across many encapsulations to the same `ek`).
fn pke_encrypt_mat<P: Profile>(
    that: &[Poly],
    a_t: &Matrix,
    m: &[u8; 32],
    r: &[u8; 32],
    ct: &mut [u8],
) {
    let k = P::K;
    assert_eq!(ct.len(), P::CT_LEN);
    // Coins 0..2k: y (k, ETA1), e1 (k, ETA1), e2 (1, ETA2). Same counter
    // values on every path (batched or scalar, AVX2 or portable).
    let mut y = [[0i16; N]; KMAX];
    let mut e1 = [[0i16; N]; KMAX];
    sample_cbd_vec(P::ETA1, r, 0, &mut y[..k]);
    sample_cbd_vec(P::ETA1, r, k as u8, &mut e1[..k]);
    let mut e2 = {
        let mut buf = [0u8; 192];
        codec::prf_eta(P::ETA2, r, 2 * k as u8, &mut buf[..64 * P::ETA2]);
        codec::cbd_eta(P::ETA2, &buf[..64 * P::ETA2])
    };
    let mut mu = message_poly(m);
    let rhat = ntt_vec(k, &y);
    let uhat = mat_vec_mul(k, a_t, &rhat);
    let mut u = [[0i16; N]; KMAX];
    for i in 0..k {
        let dec = intt(&uhat[i]);
        for p in 0..N {
            u[i][p] = ((dec[p] as i32 + e1[i][p] as i32) % ntt::Q) as i16;
        }
    }
    let vhat = vec_dot(k, that, &rhat);
    let vdec = intt(&vhat);
    let mut v = [0i16; N];
    for p in 0..N {
        v[p] = ((vdec[p] as i32 + e2[p] as i32 + mu[p] as i32) % ntt::Q) as i16;
    }
    for i in 0..k {
        let enc: [u8; 320] = byte_encode::<10, 320>(&compress::<DU>(&u[i]));
        ct[i * 320..(i + 1) * 320].copy_from_slice(&enc);
    }
    let enc: [u8; 128] = byte_encode::<4, 128>(&compress::<DV>(&v));
    ct[k * 320..].copy_from_slice(&enc);
    for v in y.iter_mut().take(k).chain(e1.iter_mut().take(k)) {
        burn_words(v);
    }
    burn_words(&mut e2);
    burn_words(&mut mu);
    for v in u.iter_mut().take(k) {
        burn_words(v);
    }
    burn_words(&mut v);
}

/// K-PKE decryption to message bytes.
fn pke_decrypt<P: Profile>(s: &[Poly], ct: &[u8]) -> [u8; 32] {
    let k = P::K;
    assert_eq!(ct.len(), P::CT_LEN);
    let mut u = [[0i16; N]; KMAX];
    for i in 0..k {
        let mut raw = [0u8; 320];
        raw.copy_from_slice(&ct[i * 320..(i + 1) * 320]);
        u[i] = decompress::<DU>(&byte_decode::<10, 320>(&raw));
    }
    let mut vraw = [0u8; 128];
    vraw.copy_from_slice(&ct[k * 320..]);
    let v = decompress::<DV>(&byte_decode::<4, 128>(&vraw));
    let shat = ntt_vec(k, s);
    let uhat = ntt_vec(k, &u);
    let mask = intt(&vec_dot(k, &shat, &uhat));
    let mut w = [0i16; N];
    for p in 0..N {
        w[p] = (((v[p] as i32 - mask[p] as i32) % ntt::Q + ntt::Q) % ntt::Q) as i16;
    }
    let bits = compress::<1>(&w);
    let m = byte_encode::<1, 32>(&bits);
    burn_words(&mut w);
    m
}

/// One encapsulation past the matrix: shared by scalar, batch, and decaps
/// re-encryption paths so all three agree by construction.
fn encaps_one_p<P: Profile>(
    tv: &[Poly],
    at: &Matrix,
    hek: &[u8; 32],
    m: &[u8; 32],
    ct_out: &mut [u8],
    ss_out: &mut [u8; SS_LEN],
) {
    let mut gin = [0u8; 64];
    gin[..32].copy_from_slice(m);
    gin[32..].copy_from_slice(hek);
    let mut g = sha3_512(&gin);
    burn(&mut gin);
    let (mut kbar, mut r): ([u8; 32], [u8; 32]) =
        (g[..32].try_into().unwrap(), g[32..].try_into().unwrap());
    burn(&mut g);
    pke_encrypt_mat::<P>(tv, at, m, &r, ct_out);
    burn(&mut r);
    let hct = sha3_256(ct_out);
    let mut kin = [0u8; 64];
    kin[..32].copy_from_slice(&kbar);
    kin[32..].copy_from_slice(&hct);
    shake256(&kin, ss_out);
    burn(&mut kin);
    burn(&mut kbar);
}

/// Encapsulate to `ek` with caller randomness `m`. Returns `(ct, ss)`.
fn encaps_p<P: Profile>(ek: &[u8], m: &[u8; 32], ct: &mut [u8], ss: &mut [u8; SS_LEN]) {
    assert_eq!(ek.len(), P::EK_LEN);
    let hek = sha3_256(ek);
    let (tv, rho) = split_ek(P::K, ek);
    let at = sample_matrix(P::K, &rho, true);
    encaps_one_p::<P>(&tv, &at, &hek, m, ct, ss);
}

/// Encapsulate to `ek` with caller randomness `m`. Returns `(ct, ss)`.
pub fn encaps(ek: &[u8; EK_LEN], m: &[u8; 32]) -> ([u8; CT_LEN], [u8; SS_LEN]) {
    let mut ct = [0u8; CT_LEN];
    let mut ss = [0u8; SS_LEN];
    encaps_p::<P768>(ek, m, &mut ct, &mut ss);
    (ct, ss)
}

/// Batch encapsulation to one `ek`: one scalar-equivalent `(ct, ss)` per
/// message in `ms`. The matrix `A` is sampled ONCE and shared by all `n`
/// elements, so per-element cost drops by the matrix share (~35% for
/// same-recipient bursts). Element `i` is BIT-IDENTICAL to scalar
/// `encaps(ek, ms[i])` (pinned by test) — no new crypto semantics, just
/// amortization. Lengths must agree. `no_std` compatible (caller-owned
/// slices, no allocation).
pub fn encaps_batch(
    ek: &[u8; EK_LEN],
    ms: &[[u8; 32]],
    cts_out: &mut [[u8; CT_LEN]],
    ss_out: &mut [[u8; SS_LEN]],
) {
    assert_eq!(ms.len(), cts_out.len());
    assert_eq!(ms.len(), ss_out.len());
    let hek = sha3_256(ek);
    let (tv, rho) = split_ek(P768::K, ek);
    let at = sample_matrix(P768::K, &rho, true);
    for (i, m) in ms.iter().enumerate() {
        encaps_one_p::<P768>(&tv, &at, &hek, m, &mut cts_out[i], &mut ss_out[i]);
    }
}

/// Decapsulate with implicit rejection. Always returns 32 bytes.
fn decaps_p<P: Profile>(dk: &[u8], ct: &[u8], ss_out: &mut [u8; SS_LEN]) {
    let k = P::K;
    assert_eq!(dk.len(), P::DK_LEN);
    assert_eq!(ct.len(), P::CT_LEN);
    let mut s = [[0i16; N]; KMAX];
    for i in 0..k {
        let mut raw = [0u8; 384];
        raw.copy_from_slice(&dk[i * 384..(i + 1) * 384]);
        s[i] = byte_decode::<12, 384>(&raw);
        burn(&mut raw);
    }
    let s_len = k * 384;
    let mut ek = [0u8; 1184];
    ek[..P::EK_LEN].copy_from_slice(&dk[s_len..s_len + P::EK_LEN]);
    let mut h = [0u8; 32];
    h.copy_from_slice(&dk[s_len + P::EK_LEN..s_len + P::EK_LEN + 32]);
    let mut z = [0u8; 32];
    z.copy_from_slice(&dk[s_len + P::EK_LEN + 32..]);
    let mut m2 = pke_decrypt::<P>(&s, ct);
    let mut gin = [0u8; 64];
    gin[..32].copy_from_slice(&m2);
    gin[32..].copy_from_slice(&h);
    let mut g = sha3_512(&gin);
    let (mut kbar2, mut r2): ([u8; 32], [u8; 32]) =
        (g[..32].try_into().unwrap(), g[32..].try_into().unwrap());
    burn(&mut g);
    let hct = sha3_256(ct);
    let mut kin = [0u8; 64];
    kin[..32].copy_from_slice(&kbar2);
    kin[32..].copy_from_slice(&hct);
    let mut k_candidate = [0u8; SS_LEN];
    shake256(&kin, &mut k_candidate);
    // Re-encrypt and compare (constant-time); implicit rejection otherwise.
    let (tv, rho) = split_ek(k, &ek[..P::EK_LEN]);
    let at = sample_matrix(k, &rho, true);
    let mut ct2 = [0u8; 1088];
    pke_encrypt_mat::<P>(&tv, &at, &m2, &r2, &mut ct2[..P::CT_LEN]);
    let mut diff = 0u8;
    for (a, b) in ct.iter().zip(ct2[..P::CT_LEN].iter()) {
        diff |= a ^ b;
    }
    let mut kin_rej = [0u8; 64];
    kin_rej[..32].copy_from_slice(&z);
    kin_rej[32..].copy_from_slice(&hct);
    let mut k_rej = [0u8; SS_LEN];
    shake256(&kin_rej, &mut k_rej);
    // Select without branching on the secret comparison.
    let mask = (diff as i16 - 1) >> 8; // diff==0 -> -1 (all ones), else 0
    let m8 = mask as u8;
    for i in 0..SS_LEN {
        ss_out[i] = (k_candidate[i] & m8) | (k_rej[i] & !m8);
    }
    burn(&mut kin);
    burn(&mut kin_rej);
    burn(&mut k_rej);
    burn(&mut k_candidate);
    burn(&mut kbar2);
    burn(&mut m2);
    burn(&mut r2);
    burn(&mut z);
    for v in s.iter_mut().take(k) {
        burn_words(v);
    }
}

/// Decapsulate with implicit rejection. Always returns 32 bytes.
pub fn decaps(dk: &[u8; DK_LEN], ct: &[u8; CT_LEN]) -> [u8; SS_LEN] {
    let mut ss = [0u8; SS_LEN];
    decaps_p::<P768>(dk, ct, &mut ss);
    ss
}

/// ML-KEM-512 (NIST level 1) from the same generic core: k = 2, ETA1 = 3,
/// ek 800 B, dk 1632 B, ct 768 B. Same wire shapes and FO transform as the
/// 768 API; KAT goldens below come from an independent FIPS-203
/// transcription (no interop claim, same stance as 768).
pub mod m512 {
    /// Encapsulation-key length (2 x 384 + 32).
    pub const EK_LEN: usize = 800;
    /// Decapsulation-key length (2 x 384 + 800 + 32 + 32).
    pub const DK_LEN: usize = 1632;
    /// Ciphertext length (2 x 320 + 128).
    pub const CT_LEN: usize = 768;
    /// Shared-secret length.
    pub const SS_LEN: usize = 32;

    use super::{decaps_p, encaps_one_p, encaps_p, keygen_p};
    use super::{sample_matrix, split_ek, Profile, P512};
    use chaos_hash::sha3_256;

    /// Long-term keypair from caller randomness. Burns nothing owned by caller.
    pub fn keygen(d: &[u8; 32], z: &[u8; 32]) -> ([u8; EK_LEN], [u8; DK_LEN]) {
        let mut ek = [0u8; EK_LEN];
        let mut dk = [0u8; DK_LEN];
        keygen_p::<P512>(d, z, &mut ek, &mut dk);
        (ek, dk)
    }

    /// Encapsulate to `ek` with caller randomness `m`. Returns `(ct, ss)`.
    pub fn encaps(ek: &[u8; EK_LEN], m: &[u8; 32]) -> ([u8; CT_LEN], [u8; SS_LEN]) {
        let mut ct = [0u8; CT_LEN];
        let mut ss = [0u8; SS_LEN];
        encaps_p::<P512>(ek, m, &mut ct, &mut ss);
        (ct, ss)
    }

    /// Batch encapsulation: element `i` is bit-identical to `encaps(ek, ms[i])`.
    pub fn encaps_batch(
        ek: &[u8; EK_LEN],
        ms: &[[u8; 32]],
        cts_out: &mut [[u8; CT_LEN]],
        ss_out: &mut [[u8; SS_LEN]],
    ) {
        assert_eq!(ms.len(), cts_out.len());
        assert_eq!(ms.len(), ss_out.len());
        let hek = sha3_256(ek);
        let (tv, rho) = split_ek(P512::K, ek);
        let at = sample_matrix(P512::K, &rho, true);
        for (i, m) in ms.iter().enumerate() {
            encaps_one_p::<P512>(&tv, &at, &hek, m, &mut cts_out[i], &mut ss_out[i]);
        }
    }

    /// Decapsulate with implicit rejection. Always returns 32 bytes.
    pub fn decaps(dk: &[u8; DK_LEN], ct: &[u8; CT_LEN]) -> [u8; SS_LEN] {
        let mut ss = [0u8; SS_LEN];
        decaps_p::<P512>(dk, ct, &mut ss);
        ss
    }
}

/// Wipe caller-owned decapsulation key material. Call when retiring a `dk`.
pub fn burn_dk(dk: &mut [u8; DK_LEN]) {
    burn(dk);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::byte_encode as enc;
    use crate::ntt::ntt as fwd;

    fn unhex<const N: usize>(s: &[u8]) -> [u8; N] {
        assert_eq!(s.len(), 2 * N, "golden literal length");
        fn v(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => 0,
            }
        }
        let mut out = [0u8; N];
        for (i, o) in out.iter_mut().enumerate() {
            *o = (v(s[2 * i]) << 4) | v(s[2 * i + 1]);
        }
        out
    }

    fn unhex16<const N: usize>(s: &[u8]) -> [i16; N] {
        assert_eq!(s.len(), 4 * N, "golden literal length");
        let mut out = [0i16; N];
        for (i, o) in out.iter_mut().enumerate() {
            let mut v = 0i16;
            for k in 0..4 {
                let c = s[4 * i + k];
                let d = match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    _ => 0,
                };
                v = v * 16 + d as i16;
            }
            *o = v;
        }
        out
    }

    #[test]
    fn ntt_golden_from_reference() {
        let mut poly = [0i16; 256];
        for (i, p) in poly.iter_mut().enumerate() {
            *p = ((i * 131 + 7) % 3329) as i16;
        }
        let want: [i16; 256] = unhex16(b"05f70ac7068800cf042803c504020ca701660b1801750b4d0bf2099e00820aad015e01dc0ac7084908b006f5041d0b310017086701890a0301cd07960a75005604ea04f804a001c901ff060204500c33082e01090be4060f037f01960af606850b7a09e4006608ae02cc0696095502eb08fd013b0420094607f2027809e80bde0a7e02d609aa0c7d01e706750a85008e00840a7800210b6b06ff07e204390ce20407066c06c60b11020d09370bf70b8402800b9109380c9e00710654054500e804ee081e085c0a9a00c6066600c008e20a270bd40c32025408060371002c0aef02ac0093052f0982031900a305600861086b09f907760a2c0a7407f900a209390114068400e8046901820cd3027a01f205ca03cf02a50621068d03400cb702d50557089b0ae3037d01a00c84036002b906de0cc307010267053904010266003c00c006230117093b061203b2065e0b540be3005b01da08b7093205ed0c010aa208cc01290758077b03c1067e03b707ca067f047b0bbf083709a407d709d4058103420252053d0bbd06ef02cf054001070c4206b10c7909b5080200c007800a1c0914018a07360a2504ed0bc8068001aa027b089f00e80aec07350b120a960b8e0bb509d90c61079e090e019a06a50c5c005007430cd702970b6101e4054705cf0cb60391008203dc08590c8806cc0b21091c017d01f8036108e1029f009b09d2");
        assert_eq!(fwd(&poly), want);
        // Inverse restores.
        assert_eq!(crate::ntt::intt(&want), poly);
    }

    #[test]
    fn cbd_and_compress_goldens() {
        let mut inp = [0u8; 128];
        for (i, b) in inp.iter_mut().enumerate() {
            *b = i as u8;
        }
        let want: [i16; 256] = unhex16(b"000000000001000000010000000200000d0000000000000000000000000100000d0000000000000000000000000100000cff00000d0000000d00000000000000000000010001000100010001000200010d0000010000000100000001000100010d0000010000000100000001000100010cff00010d0000010d00000100000001000000010001000100010001000200010d0000010000000100000001000100010d0000010000000100000001000100010cff00010d0000010d00000100000001000000020001000200010002000200020d0000020000000200000002000100020d0000020000000200000002000100020cff00020d0000020d0000020000000200000d0000010d0000010d0000020d000d000d0000000d0000000d0000010d000d000d0000000d0000000d0000010d000cff0d000d000d000d000d0000000d00000000000001000000010000000200000d0000000000000000000000000100000d0000000000000000000000000100000cff00000d0000000d00000000000000000000000001000000010000000200000d0000000000000000000000000100000d0000000000000000000000000100000cff00000d0000000d00000000000000000000010001000100010001000200010d0000010000000100000001000100010d0000010000000100000001000100010cff00010d0000010d00000100000001");
        assert_eq!(crate::codec::cbd_eta(2, &inp), want);
        let mut poly = [0i16; 256];
        for (i, p) in poly.iter_mut().enumerate() {
            *p = ((i * 131 + 7) % 3329) as i16;
        }
        let enc10: [u8; 320] = enc::<10, 320>(&crate::codec::compress::<10>(&poly));
        assert_eq!(
            &enc10[..16],
            &unhex::<16>(b"02a830c51ea330430f4745b555596fe6")
        );
    }

    #[test]
    fn kat_a_from_reference() {
        let d: [u8; 32] = core::array::from_fn(|i| (3 * i + 1) as u8);
        let z: [u8; 32] = core::array::from_fn(|i| (5 * i + 2) as u8);
        let m: [u8; 32] = core::array::from_fn(|i| (7 * i + 3) as u8);
        let (ek, dk) = keygen(&d, &z);
        let (ct, ss) = encaps(&ek, &m);
        assert_eq!(decaps(&dk, &ct), ss);
        assert_eq!(ek, unhex::<1184>(b"bff220baa193307c610fc5b4db7c46e5bc69618c87d45990cb1941b7218dfff8b9653072e63313981c41f3c78f80aa154ccab5f5d500f7953978ba389b0b250c01464e172f349491f815b63420994f0886f5e6720f9c6c304b8ce4134066417c53825cb74334ddb37098b41edad21c1690ca1f6bb008a2824b1b79c9033ad426c60170acf7c42e94e1a008454ab0407e6db325e8d55fce42cdcf0c8849a3baea5269b4310da531a434431824546f7cd808fe6167501ab68f96c513527836202f2d1c7070dca6fa914e16e70b800aa77ba88f72296da9c82647e95679fb465ab43f79c63413527c4fb93dfb0709211cbd2e7c37596690430645b0b5804ee383cb126a4b65065e3ba1fde465ac50a4465ba7dcc81f75f05e227b63d28c7d17570b3f8a99fd6b97974bce6c229abe5a864684b25ee41fc505b07fd92705f92c9691815191a36f7a3a34a898a30403bcf380512c9ac5fc7225f37fbe698f4e7ab5a2d36e2c134b0d075c270828132c4e2020c3dbcb27012c699c30b9d096505f222eee948387e363b0a65afc164b0cea0c54731869f408de2587d63c808dc2278f556262c1a744425cd3b5985f154e80800435ea09704cb902629fd8c9ca03c3b1ec78046a02129c39c6f4322a9c0b15c4b12bdb605bc1d8062cc3205d5c9d34e787aef4279bd134da56a2fa825345b19036ac7e15d1097c880bd5842d48604c8422981c88c23c814fd4488ff872a891f9bb3de1c2058016c16114a253b4d1a84104696fe873a0cada4df4f2b33b041c94a27b016c6116b988dab7038e0a239f3261f4f713d0a286336216b4f12e30455b0ec54f32e952ba503dd0e68053328346504731c40a78994360f47e95662e454661d7a95101c2c31ff1a291550e77860573764655b27e13c95bb760a528ba16aa19873589257a44081cb81394185817664390e28fa22a48edb630d02862d5130bc5a2b08a8117386942c882656806741d3c92eb00b7d7a38bc414af76175bba6ac585d470514138d5785543d9491250ca68d888dd8bbeafc54fac9a79c670a0a941a4b727ce5fd59d82644efa0a1377775935070b76ab5fed186a21101561d385633c677177723b321e1a2866a4cc2900913335a33b6bb654bf7187e530aa6cab6281f624c2a9287512902812226a4421df35862aa8888fc5c1ea26240f51942dcb69719343171cc265d46c75d1c1b5eb4bc98b93ed967ff2926c0e73a2fef7b2082b076b167a1c5c6e0b678bbf78252ad5903e5836152749bfbb4e77931be144ad98935d978003e580471ea628327493dac839ede8bcaa409220ac497bac3c34eb01fc593f75448fff115ff6b29bf19c39c641bfea159e9ce807ba1559c57a9024395483c045ad9125ab812e315546bb262255c75552f3192c762470c5a749000fd4b27acb54b814fc0b983c20536bb0d4445eafd3235afa724ff67eafcb2609a36d1bc4afc7037068073c08b4a43892302aa83c9789a400b4751b2a6e576688a97799706069445c348f340fcf859ec3db80e1bb572e8a6944c852dc5483065239b07c21f257b5492460554158d562be9409867096b5a3ab439b96a80a2b5f22ebcada09446cab9ccf53c51452c1ae7351a8da7bb6b85d9801d9fda26aa40b7986b0d7feef38e2baf98b964d6bef7c5c38"));
        assert_eq!(ct, unhex::<1088>(b"65c9d799fc3393c7d4d7fb8a9980b110753c13982e45c267ce1826bf0a47a8dc79aef91d8ddca657a64371fa0450020c514537588096cc1b94b5d789d564312d58c31c7a854ea0dc1733c73ae72b7be6ec6ca7bd19ecff28b4b69c4a6d92b03a3338ab9be98af30f8174ed4a00765d221fba287b98b21cfcf520d90008fc91e1f44a2cb68458de5b81daa10c5d2359152f8dcf917ff328bf88febd3190873965ce0ebd0083782c91bcef4bf5a23616cdb1a821748dd053938e10079b485beb512ab2b04f6dac15bbae178b25620133d19c0f3a78d3b25e3c71a44a97b40cbbecb160529a577b0081a71d5b764e43de00fdfdc41970b5477a8dae194a41da8a8ca68ca1c25f8443e179740da602e190d0bf5b28ba5fc65b6a3d86527b7933915dae3dfde5c4e7d562f32f9fdf1713a8deef936a0be07dcd6fb4a263621b070fb3e2200f3ee2cc2fee8be66c3147ac9a9637e3b4c3975228f97a3a45081a5b2046398afac90c5be8c840326af923c39ae45b18dde25cba309c292d48ec2ef25881481cb36afbd72c9e3b113548b9a46a7de43926b66ce9a534be06d51affb70c8dc907a5fe482e5984cb389c92f0529a7cfd047505929763e919eb9464ec99d21305739f43d6738924e95c7de4f286a2c1c58fc1e6604c437af70d7ad08f2964b4027ec8f4a138d0347f747ae490de4d8861e8d2ab9a1eede2d1cec8cd1a673eeb568e607ca8011aba765838807504f1b0a64c09e0a2e7f97f19cb99faa11edadb1441dd93582ace9b5bc758887b714244ffe4cb4a635ca71dffa349b4b0f9956b9bb9979448f2ffc1f33b4abe33585b9e77402ae9f5e87e5f75ed56340d26354f79ee627928af04cdddab1a95c1e041e4ecd5ab0a723b823fdbdf32769dfbd9a3a6dfebe2dddfaa1ada77a9c5dfca531bd62a1992e59522784b03961237d8f0122b883b024ec7cddb7c9f8ea47020110d98faf12e43a3f6856186cd636adf7b4ed14510d089b0d0b916eb5f527e1cdba35d3eb6766095b6e673ff40d510c9ac2671b0634228e7b7fafa1a90dfec451272ee9eaa14c02d4fe61e13cfa762d3b5bfeec20482d4cee11a7295440190336ed8040f4798d0e10d6e69f8c71ec5cef5daaea73f916deff0e9ec1595ae80e5d53d959a55ca556d32cba1cbee9d8cdd52baddcece856d95d0b25847dbf81daeeb9a8f1e307737e2cd3f8d3130182e4142254f205635d6d56a0e392b2aaa11384153694023062ef197e9f50827863619dd6d8fd2805860debae13ef297f5801eabe29196e9d20e7de00f55f1a9c079954c098c804de5c7f5e430309adadaae021d8cfedb7eab56c680d81f94f50c025157a2a5c9c6a7a7fd485444e2917f45c2ca49e6aba4e8165f4936e36b333d1770d3724beb0368bc2b4ba4c0a88603f1bd25c2eb2d85e072b8b043c3a9313bec6a25fa6034a89e52c82b6453360f7ac3a59c4ce78ebc2d69e0d53056ad2e89cca16db54fe19d0e07950cc58b3c19626c1e317c9835b6f8323101b4ba052bb30190f508"));
        assert_eq!(
            ss,
            unhex::<32>(b"65c68dba5f019b62c8795665f5335e3ccccf53e51245f6e26117ab4950da2205")
        );
    }

    #[test]
    fn kat_b_from_reference() {
        let d: [u8; 32] = core::array::from_fn(|i| (11 * i + 4) as u8);
        let z: [u8; 32] = core::array::from_fn(|i| (13 * i + 5) as u8);
        let m: [u8; 32] = core::array::from_fn(|i| (17 * i + 6) as u8);
        let (ek, dk) = keygen(&d, &z);
        let (ct, ss) = encaps(&ek, &m);
        assert_eq!(decaps(&dk, &ct), ss);
        assert_eq!(ek, unhex::<1184>(b"3202b5b307c3609b03e4c3c057a7b36c72cb6403a607977c4fc56defd60ef74b011b311c67565bf6a670b9ea30c3a3837b732ba3a57857f4b912d6b4935436a4a7a4fc58b042f76fa059b578c95b4fc081addc65e0ca32aebba6f4fa1ae0ac370aea78fd9796c9445349631638633b3f5cc32f041807b19c6f62baba8680b353a7adf997cb9619dee76ef288ce295b45e8cb66f19a854ad511ba57a861683326a320062c506f817daa058b89da1dd661090eb36a1f9b392d051769a348889b56d3d37581647c78432220dac0a484a1d30c0e4d3a6480e6ce6cfca59960b05755a837a64612531197c68da18abd26e5348bf8b5d24c6ab575546bbcc6caa7a408a331159296b4cc8be04b423ea920fe9ba0e46941ba920f5d073246126d9a95cb217b201f16679eb4658d0bb5c920a50321ad3a412bfd9720b4c5cee7883d9f8c4802342b4a7705c5041f268890ee1191e97b008bb29c27649313eb9f2cd2bc597c6ac31205e7b9b7fc5ab0dcd8bcc1035c73e64d8c911db6336b1a737713d021e8f553834abb40f482f14771dc7c0223d91c7cb1cbb7a52cbb06639f4c5664e1b24ac0a006991ec3922240068fe1c323cf0c30bd7bae123020fb571c72e319b0d5b85d0538d4e706349246d1e47aa3ba69dea9bd42e90313e1a439a084eac4539bf3c96308167ff9099b66272a39948fa709bfa2a5ae7b08bfd30e43894c8b8a3fb5b56f7005205ca63679f5bf2898afab70bed9c022027332096ba23a745ea340965183bf20379eaaab91d8e31ee623564c615b59d099ba741627f1b3e5e34bdf923d679078c005374ca7c9f1a348a73240a7b7abb9e21586353249fb780648be3d2bcf624486420ac38fc9883fe87c02741670f3b8ff12af2d6657ac97bdd75a653267ba0b6a2aa35460be48480d7b719de3a0f037253b9bc668bc66cc19987c50995d19a0c1dcc1f66a56cec567439a3708c4085d72265ae6674eb427f241ad716ccc486c612e31783bb276a8791871ea9807d15a569a034d379b0604725d7185fc66acac3cce8c8812c03a42be03a5155a9788aa49e6026bc5699a4fd5b6c9cc7b3423a79bf5298f6c7d78161fe927b649ab5b8433174adb24b4e6830077cb04c97c7ab4ad876cb41cf3944a6cbfe81acf67217c6226897f2126f580b68c640f943bb667cbca7cb53ed05781f7c402760c75af446ca18ca9454829e2ac0b3dd4161bd38b7357a8dd2ba4a3355039daa6c078c25037330a8090e6d79a2b228593a577d3526b9291b43727001c899ba432151de8b1770345c977c14ed79c0aec23f256cbc3b68794e17392554fa542bebf0ac8df1ab79d097db3f3b2676a0067242cdcb00ec413beea0aafb6d9985f0b462dc1bd72950f13d447b0da997494597825654dd8513d92c6348a62c367aaf18b7a77d49ade5cabef150213759bd2131a1e28b89008ce92530151d0a06a11097d792d7a14c9c8dc9cb9c6a14fa8b70d4921325b6109463e47f63ad482ba483507d137c99e3319ea84b860f03625e455c6261eb9616f3e5ac089a8bc4ac0874e9cb0be76aac57732bafb4d4e706a43698994baa9c31463a37436727b3d400285da4350055c34ebca0f7bc246fd0227f5d08aa84260a68c7f4df1b2747f2540f02156c69a374bffc121256ede749c04"));
        assert_eq!(ct, unhex::<1088>(b"846941748c13af2b6e44803bb1f5aae75db47fb13388996d18fb8ee17e7f5864872316930d78f2b5b047a8a8967f3fea72cfb7fa1892802fa849cbd6e55c87c7bbe91350bb26a966f3be48a9c4ff763f6a7cbfcac4c885150df4055b279cb6527b626c1d0cd3807adaeccde3374cd04b124a49bfe25c14dcfad1494397e32eea6890db2ac250b90e3f02ebef0de44764bae59eadfcec84b10e11e31ac177a708e7834abfe7ac214e81c28e01a53212700bea89c51f9f2e22720e181e6b28ce0b7e990ba76eb303dfceb9a510a292e72444203dc063c327431a053dfee79dd384fdf6f3dfdbb70fcb18b138a4ebaf486304d556891e94fd0d5062d165f7d80a18e9b9c3317d02c0f371446a504e52e2157a403a27c752af0d7f157df57733d5f92540285cab41bd5d4a42dab740ef2f708ed3b93078ae677ba3e367a681a03bd2fcc21bca51eaa156f36371b7ad6289ad297094216d59069a9b2f4fa5c4e6e01414babe87b73d31d9d345d900a01112e5f8c43cba9c8c2624e08858e723ba5c50fff8c30e2b4e2e2c80e27966dc50ddb60cc05036aa550cf9f9a1a35e2bbc436c2e5d6c6bb5cfc0fcc3704649080b393576aa0509af634bc98143d688e33349e8fe9bfef93031b8ccdc107a3541c6c5820cdb49cffb06a7512b0975265e249bad5aba6abc7ef7ecb4ab1e04883ebdeed5be91d0b4725c248c012cd694c0b599563ad8fa9e49f67be3c917be0b22f5a638da646b635f7bc3237be4832d6704e5a0075c44efa58a93e5b4b9baa33a458659c12910c587b438ddd7d31a654a7b1513262ffe8826b6823f11e4dc638c2b661a03d4b567ef98c376a7e6bbe1e7878e820b991c5381bab21ca53f755c17f91a00f5abc24ddd12e4d493c48c65298881e3772028820e5b19e3c08232e8957cf4d85bfba719a1185f9814b19725ffcaa001e9d080c697a76b869d67d145a1fccd5406789641d81e73f7465ac59e1bbc06ae5bb480e46983313d634a324a3a37508a51f94931ceb028497cde45a9459e28259544dcad6c8a6c36455cc1f2dff8404d07a02559279cf9e9dc690113bf973d03905b84cfdb3f6a7b030dc809754ae35628eaf3c0599f9c5f7344eeda396dcd396ccf21cd1f3a133d0374ac1d886eaa024a79fccbe646446064c4c150d7fc462831990b174e2b286de97c0e6dc4ccc6fc01f56352ccdd8a781ebb1e0305a6e063203c92b4d8cdd03d74e8fc955ce16b5a32f3bdbedadf16b1908aee14d51ef9ac19db8a1a67fbc461992f33853d392e9ff2b61297fc75f55abe8a8393dc1b9db27490ab98aa544eb7ed059904fb4d0e48a22e3fb828e6989820c1c89c7f22ec4f4dedba035fd8d09a1fdb6cebbcaacfd917850755941c7f68ae704ed3dbef8f97e9529a0473a3e5d69cdf010d15ac46543e4835bdfa0d84cc2446ed974f2a6eb5e5839a65aa47c37891d2e30339205b887d018fded4ee4bb3b64b5bbf193b54185d2163818f8e0e5671baae1074aff081392a382c479bd2664f246c2359f1f3d5"));
        assert_eq!(
            ss,
            unhex::<32>(b"7c05da2714a55af124e92f8971af12e51c18f01ab5eaf4551b2587bfe58b974c")
        );
    }

    #[test]
    fn batch_matches_scalar() {
        let d: [u8; 32] = core::array::from_fn(|i| (3 * i + 1) as u8);
        let z: [u8; 32] = core::array::from_fn(|i| (5 * i + 2) as u8);
        let (ek, dk) = keygen(&d, &z);
        let ms: [[u8; 32]; 5] =
            core::array::from_fn(|t| core::array::from_fn(|i| (7 * i as u8).wrapping_add(t as u8)));
        let mut cts = [[0u8; CT_LEN]; 5];
        let mut sss = [[0u8; SS_LEN]; 5];
        encaps_batch(&ek, &ms, &mut cts, &mut sss);
        for i in 0..5 {
            // Bit-identical to scalar encaps with the same message...
            let (ct1, ss1) = encaps(&ek, &ms[i]);
            assert_eq!(cts[i], ct1, "batch ct {}", i);
            assert_eq!(sss[i], ss1, "batch ss {}", i);
            // ...and decapsulates normally.
            assert_eq!(decaps(&dk, &cts[i]), sss[i], "batch roundtrip {}", i);
        }
        // Empty batch is a no-op.
        let mut cts0: [[u8; CT_LEN]; 0] = [];
        let mut sss0: [[u8; SS_LEN]; 0] = [];
        encaps_batch(&ek, &[], &mut cts0, &mut sss0);
    }

    #[test]
    fn adversarial_values_never_panic() {
        // All-0xFF keys/ciphertexts (decode-range extremes, coefficients up
        // to 4095): no panic in any profile (dev asserts included — the NTT
        // entry accepts [0, 4096)), and decaps either roundtrips (honest
        // pair) or implicitly rejects (mismatched/adversarial pair).
        for t in 0..2u8 {
            let ff = [0xFFu8; 32];
            let (ek, dk) = keygen(&ff, &ff);
            let m = [t; 32];
            let (ct, ss) = encaps(&ek, &m);
            assert_eq!(decaps(&dk, &ct), ss, "honest FF pair {}", t);
            let ctff = [0xFFu8; CT_LEN];
            let _ = decaps(&dk, &ctff);
            let dkff = [0xFFu8; DK_LEN];
            let _ = decaps(&dkff, &ct);
            let _ = decaps(&dkff, &ctff);
            // Encaps to a foreign (all-FF) ek, decaps under honest dk:
            // implicit rejection, never the encaps ss.
            let ekff = [0xFFu8; EK_LEN];
            let (ct2, ss2) = encaps(&ekff, &m);
            assert_ne!(decaps(&dk, &ct2), ss2, "foreign ek must reject {}", t);
        }
    }

    #[test]
    fn roundtrips_tamper_wrongkey() {
        for t in 0..12u8 {
            let d: [u8; 32] = core::array::from_fn(|i| (3 * i as u8).wrapping_add(t));
            let z: [u8; 32] = core::array::from_fn(|i| (5 * i as u8).wrapping_add(2 * t));
            let m: [u8; 32] = core::array::from_fn(|i| (7 * i as u8).wrapping_add(3 * t));
            let (ek, dk) = keygen(&d, &z);
            let (ct, ss) = encaps(&ek, &m);
            assert_eq!(decaps(&dk, &ct), ss, "roundtrip {}", t);
            // Tampered ct must not yield the real ss (implicit rejection).
            let mut bad = ct;
            bad[100] ^= 1;
            bad[1077] ^= 0x80;
            let rej = decaps(&dk, &bad);
            assert_ne!(rej, ss, "tamper accepted {}", t);
            // Deterministic rejection.
            assert_eq!(decaps(&dk, &bad), rej);
        }
        // Wrong recipient key.
        let (ek, _) = keygen(&[11u8; 32], &[12u8; 32]);
        let (_, dk2) = keygen(&[13u8; 32], &[14u8; 32]);
        let (ct, ss) = encaps(&ek, &[15u8; 32]);
        assert_ne!(decaps(&dk2, &ct), ss);
    }
}

#[cfg(test)]
mod packed_tests {
    use super::*;
    #[test]
    fn seed_packed_storage_roundtrip() {
        // Stored form is (d, z) = 64 B, not the 2400 B expanded dk.
        let (d, z) = ([0x5Au8; 32], [0x6Bu8; 32]);
        let (ek, _) = keygen(&d, &z);
        let (_, dk2) = keygen(&d, &z);
        let (ct, ss1) = encaps(&ek, &[0x7Cu8; 32]);
        assert_eq!(decaps(&dk2, &ct), ss1);
    }
}

#[cfg(test)]
mod m512_tests {
    use super::m512;
    use super::m512::{CT_LEN, DK_LEN, EK_LEN, SS_LEN};

    fn unhex<const N: usize>(s: &[u8]) -> [u8; N] {
        assert_eq!(s.len(), 2 * N, "golden literal length");
        fn v(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => 0,
            }
        }
        let mut out = [0u8; N];
        for (i, o) in out.iter_mut().enumerate() {
            *o = (v(s[2 * i]) << 4) | v(s[2 * i + 1]);
        }
        out
    }

    #[test]
    fn kat_a_from_reference() {
        // Goldens from the independent FIPS-203 transcription
        // (/tmp/opencode/mlkem512_ref.py, K=2/ETA1=3): d=(3i+1), z=(5i+2),
        // m=(7i+3). Agreement pins sampling, NTT, codec, and FO flows.
        let d: [u8; 32] = core::array::from_fn(|i| (3 * i + 1) as u8);
        let z: [u8; 32] = core::array::from_fn(|i| (5 * i + 2) as u8);
        let m: [u8; 32] = core::array::from_fn(|i| (7 * i + 3) as u8);
        let (ek, dk) = m512::keygen(&d, &z);
        let (ct, ss) = m512::encaps(&ek, &m);
        assert_eq!(m512::decaps(&dk, &ct), ss);
        assert_eq!(ek, unhex::<EK_LEN>(b"aca752b40616bae9186668326323b45b28400278c11703bce6b909792b3ccd8848176165288c5b4dabb705338e721bb5768b055910828073caeaf8a3b6144409f6c52f8208e0453d90b172c82147e8888677c2b5a910794ea4994ac50f8df5a0d821b59be8a8ce40b68193ad760a6043020ce7009a02a15bcec576775454c672af57f67d7e5a913165cd03d1965e079f07c110e374ac347acfb85c5c23c83f35e1c68641c33ac02231cb3c169b74addb550228b027f4bcc2e474d07285a741b5792cc6f327bddb4a9f7a750ca9407f0b65c819348355445def932ec12986066b3584b955c2ea2b2b5867dcb07af2789ac40182bfe71e8b65c4bab394d0eaab26e4784838caeea76da0043d29918c477abf3f94671007468f4a3ad600104ce97c51a5c6f931194cc9c8dd60a5f7d14a40b404b97a0553c371c552131f39045c85c52f965631062c9d4c2a40c17d7225b908f55ea0132e65bb5e3f2a51fb8b5417a17e6397654e57966a502cd97b2565eb68f7a59e82f546b4c5ca1fe8a33264ac26440a3610224e110f49b95d8c90bb5c4799c61c710017854ba7a00024c7392a166f003bf09135b16657797424462200ab12c65af66ed9b510caaa97f370616395809d922bdf5624c97a34cfb361a10a65f368026a6462c004905727b5588333b9b576e36a8f55d4806c1b4728583bfc1574dce2a19e399903243a26fa88885066fe51b190fc68e4c9787fa55804e38ad70b3402399d90dc8ea5b26ee9f2625ba82436350d9dd1137cd58ec0a9a5a4f4cd48f64293bbb590a163967c7f500b907f2950dc0b6028764d42673e30349a77da1dc875a63f690eabe73ef94a161c8176900bbc6c7087a6598e9275bc30599511735ec102c9c174507501a396d4c71f928be448a18eaa3a32c67a87136c48ac49b84abddf5c26c582b2cc43aeaec1cabbc2935c168f1d26c2d326bcb2a04f262ca5f917bf881439bf181236d02ab18a97201213cf6947decab181d82c808809e630c8a51b0016609aa54874b888ccb0d0500ea45b643c588550c1ce8b3bf9368f4e725bcd4674d1ea541c911df9d43da8da7bb6b85d9801d9fda26aa40b7986b0d7feef38e2baf98b964d6bef7c5c38"));
        assert_eq!(ct, unhex::<CT_LEN>(b"e79e602f3a99b7a809285ef49ca3b3777f583d6a2aaa5e126c222d305ab5cc7cfd6aa0fe60c8712aff255f713242f7e93786aec403810cf80919d803e2f491b71bd5975495353179810ddd08a9d8ddfbaddc0c2ba161c8b46535c603c3840b7ae2f3482130f0e066f87916af81eccb7f3b14a504c57f8d1e3561817ba4bd7154d131998204dac1fbba67a30968f25ff3a0dbd30d813864d177f349d3e31ea0abd6e8a4db5e98827c75eda1fcb041d0e2f483a34859466398b7ccab323dc989bcb8c88f6374b38b19b7384b9ce14224801be29a6b3caee625f946b55b1eec6fea425ce2ee052a151d79f165994089cdb50fa1ca1699da413ed9338e9b9ec298c08b60987436a5763f799daca77f62dbfb5627b0d0bc5f507d1c4e0582b40acd2779944238173f8321494a800c97e31f1c7cf4d83a7fccb052a12fc425446c5121f60e372e21dedbadf71cfdfc0df7e819f9fdcb90fd17b53693585f5b665c6cbc559718c7daad7d48ac3c300609d76e208f02a66fbb14301ceacc8a03a2ae578db3cd49009cb5840c7d8f8cc31674d5aadc02f60b1080c155a11ae1ead0837766d3dbe30569575e26bac178ded436d4bd3a1dd438529be2a4f4f539aeb9ac884428306a648dcd25803a37734a1be804cdc178ce0d5c290a5cad5236b51d3eeb74587b547b6879390a1e9cf2c0f8c676bd6674a357b53bbc6c5c4231da4b30570cf8daca51cf139472de102e93567bc30ff0e85fa14b1924b75ec94bcd61cdb464722b9ac4a7f71e3c7f72acf1811b40703febd78057a14917c19d4365be4c918c6dc3835765c59c04689868e2cf7bdb8d66f6be268fda0ea8a13dd420c3f61d2d197c9d5852e57c644b6f096d0c849d9d4c4b6fa6c610fad5c3d32daf1c834a53c90b05554e722a925d4bf2cf6a07d0d8046b2b0b3fc95024c5512cf38282580a20074ff4973fbad8abc47b97314238a728020aa61e29aac78719998396737644a26dc4b1baecd863dbe5679dc922f799cfd30a999a2b10872b586d735d517b3866660d8c05ed98318abf8c86a8ca6a0a4efcf2d344f54cfb7b64fd7fd187b1da"));
        assert_eq!(
            ss,
            unhex::<SS_LEN>(b"174f7a4576c9da86169826e9cc4981cbb1867a15609477edc9f1bcca6195eb5a")
        );
    }

    #[test]
    fn kat_b_from_reference() {
        // d=(11i+4), z=(13i+5), m=(17i+6).
        let d: [u8; 32] = core::array::from_fn(|i| (11 * i + 4) as u8);
        let z: [u8; 32] = core::array::from_fn(|i| (13 * i + 5) as u8);
        let m: [u8; 32] = core::array::from_fn(|i| (17 * i + 6) as u8);
        let (ek, dk) = m512::keygen(&d, &z);
        let (ct, ss) = m512::encaps(&ek, &m);
        assert_eq!(m512::decaps(&dk, &ct), ss);
        assert_eq!(ek, unhex::<EK_LEN>(b"1fb572c5cbb9f0abc8d617b5164b21279a2e56274559a52b0515bd45546eb5c01edaf8bdf7c276e46a3a05986d2e739bc8e348b1f24a4e623d783356f72a6a0e638ed29b5105bcb5228cbd4c3badadc107ee38101a404bceb4457fa12b36225dbba19feec4477d578368fa6c840a87d2696c0e0096c0dc023af184be46108be649762001ed7504c2095bd485b716dbb506e7255d694c7afaa9116bbf3b3b97de17839ec997aa5403156ac3354770c2f207a267021307c129546c53db4809761852e876729255988c096d6439899787518704e9f91efda034de357e3c3bc4622068c062c02090b86db43b75323eb0a20e754197a3295f80f33a04839376a4bd05a9b6abb5b664e62c9b7c9484a02bcec99cdd0965304b8963113814258a1be6462febc894e06ed1dac538300ff40b32f8eb64b3174ab285c77475cc23435f78266877c0c81d9a0a0e596ee58912c1d597b4460ac2a111f54730ea9419c4c52a866273a76941f2f324ec375ef4e6ad48d65f894c42f857cdb9362eb27a82b8c11c994327ac66253cb2abdcfa235004263220af4c109082697f16f7511e7a5ec57593f173325ce9925ce87b93d25d2364a7b79a1e87042b6ddc5019363881a53f27e9a5e39359b8f0a895f24f68a5bd50cc3b1b68997b6224ed3939a3a0b0233a493e8274f4d4239fba7740b1c237014b00338ce01558f6e2b9211688242b03801040071403525368a778900cd69de8cab7177c14f961bf4e3225fea3a53605330d5835934148aac24e71e28674425d88b684050c198d00422924115603a1ed8c011d7cc9aa90bbf251b594ec26e4bba9b2f89973ab4e4d991ff483950c1c4c190859039a2f2df3bbe54545bf0242d340302d6160861a9ad0f19a71b298a6c60389fc9b709c36214c23c445bd99f075061b0557d8a8b609618a6041deb923f44431d492629b168de8c5bc9ba99c37979735fab505e613bf45164ee5559303653db57502b29cf4e19d42481a66ab40c4a0c8852b8710a624b413a39d3b12d90b63ac6a309d8bc215d99ef04549425538e972182cb880a827487f2362a8d17aa8ac07f5d08aa84260a68c7f4df1b2747f2540f02156c69a374bffc121256ede749c04"));
        assert_eq!(ct, unhex::<CT_LEN>(b"7b6d7aa940ccb01158556010c64b8f8f0c918a585bfecc261ca239a168e937274346174ba3a995cddff7817a09fed29c0fa798acf6f56ae368468e34d0952f713eb797b60fdbd20581419fb87abdd2bef55a4938746bfa8c36c73cc19f292275522b37c8ae8771c0f53a91160ca78ebfba3f49236b4487e5ec235b4cfec98d96be7fa914a01a7229a37898cb8a5093f64d08ae34ec923413b0ef709a996876226efac3565d546806ebc5d5bf499f893449fd73c38f09ffbe92424465b4da9133ae6a097cc28d727c15a25e4b882e616e3fb1fdf19ae9a4f6edc5e5de6fb37153080319bcc2a46a8d7c268b29305edcea71831985dfdbc7a4cdb9f19c508371bf72ff7c1668ea9f53c5cf7f0a86b9728e041983929be7e36bb659d8031750708ec2fe84470dae9bf97cc1f199729d33316b6f631a3d5cea2c8da04afdec0ccbc3cf629bccfd6964de0fd124a5294a2f04d8214d5f672fa509f92d6f29b301ddb00b8ca82391b72b965eda7348b8e0c8cfb0abb806600f3442c64795fc536a70c0881270605a54d0dfafa480b083b640bb415d1b221850957b3b8fa71fe502b462bca104721bb20c1cab87f71d7be4d395147dfc315912d3131ab0e6db77807728a25591795b7080682357ba4a640d6c5d7d422bce2a9d714061a88cd8a40db80afb7c1c712ecd850071c39183ab6c9f9246dab4631496b2547357d14872609343dd108527429025c595108f4a97b060e9d40ba4ddce42e1621e0b12dcd3c32edf97a26574a3e44ed5d7138ce983bdf43216b0284b7d844a522c4afd9b53e6dcf49cf3d5b72b2800037e2150cc8d6707e833a3108e1982147308b214bfcdbde470aa9a66283fec124d55c35b2f49d42a580a2bfe961d5af929d3058c9779f7f46256e887e74c16727d2801895454e6dcac0d5eacbce8aaad267a97ff3dde36a6250f5b99255ebd18b2a0f8ad5bc932593469a0a47318750fe7077bd7d4c60a94f630ca916b6c0ed79f813544af67b7c9c8f857072687f15ab653f7eece4eca12a4879d838bbd85b722bc80ef3164cffe028810b805c2c79cc413be3b33705d9ecd"));
        assert_eq!(
            ss,
            unhex::<SS_LEN>(b"0e66e3f5a3e0ca94b89c8f05ef42dc522376bfd0ccbed75598b85c2cf88c2eae")
        );
    }

    #[test]
    fn roundtrips_tamper_batch() {
        for t in 0..6u8 {
            let d: [u8; 32] = core::array::from_fn(|i| (3 * i as u8).wrapping_add(t));
            let z: [u8; 32] = core::array::from_fn(|i| (5 * i as u8).wrapping_add(2 * t));
            let m: [u8; 32] = core::array::from_fn(|i| (7 * i as u8).wrapping_add(3 * t));
            let (ek, dk) = m512::keygen(&d, &z);
            let (ct, ss) = m512::encaps(&ek, &m);
            assert_eq!(m512::decaps(&dk, &ct), ss, "roundtrip {}", t);
            let mut bad = ct;
            bad[100] ^= 1;
            bad[757] ^= 0x80;
            let rej = m512::decaps(&dk, &bad);
            assert_ne!(rej, ss, "tamper accepted {}", t);
            assert_eq!(m512::decaps(&dk, &bad), rej);
        }
        // Batch equivalence on the 512 profile.
        let (ek, dk) = m512::keygen(&[11u8; 32], &[12u8; 32]);
        let ms: [[u8; 32]; 4] =
            core::array::from_fn(|t| core::array::from_fn(|i| (7 * i as u8).wrapping_add(t as u8)));
        let mut cts = [[0u8; CT_LEN]; 4];
        let mut sss = [[0u8; SS_LEN]; 4];
        m512::encaps_batch(&ek, &ms, &mut cts, &mut sss);
        for i in 0..4 {
            let (ct1, ss1) = m512::encaps(&ek, &ms[i]);
            assert_eq!(cts[i], ct1, "512 batch ct {}", i);
            assert_eq!(sss[i], ss1, "512 batch ss {}", i);
            assert_eq!(m512::decaps(&dk, &cts[i]), sss[i]);
        }
        // Wrong recipient key.
        let (_, dk2) = m512::keygen(&[13u8; 32], &[14u8; 32]);
        let (ct, ss) = m512::encaps(&ek, &[15u8; 32]);
        assert_ne!(m512::decaps(&dk2, &ct), ss);
        let _ = DK_LEN;
    }

    #[test]
    fn adversarial_values_never_panic_512() {
        let ff = [0xFFu8; 32];
        let (ek, dk) = m512::keygen(&ff, &ff);
        let (ct, ss) = m512::encaps(&ek, &[7u8; 32]);
        assert_eq!(m512::decaps(&dk, &ct), ss);
        let ctff = [0xFFu8; CT_LEN];
        let _ = m512::decaps(&dk, &ctff);
        let dkff = [0xFFu8; DK_LEN];
        let _ = m512::decaps(&dkff, &ct);
        let _ = m512::decaps(&dkff, &ctff);
    }
}
