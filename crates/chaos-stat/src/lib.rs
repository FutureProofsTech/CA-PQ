//! CA-PQ `chaos-stat`: NIST SP 800-22-style randomness tests, from zero.
//!
//! Analysis-only crate (platform floats are fine here — this never touches
//! key material, only measured bitstreams). Implements the special functions
//! (complementary error function, regularized upper incomplete gamma) and
//! seven tests: monobit, block frequency, runs, serial (m=3, both p-values),
//! approximate entropy (m=3), cumulative sums forward/backward.
//! Pass criterion per value: p >= 0.01. Gate test uses fixed seeds, so results
//! are deterministic (no flaky CI).

#![forbid(unsafe_code)]

use chaos_core::{expand_from_bytes, iterate, N_TRANSIENT};
use chaos_extract::keystream;

/// Complementary error function, Abramowitz-Stegun 7.1.26 (|eps| <= 1.5e-7).
pub fn erfc(x: f64) -> f64 {
    let ax = x.abs();
    let t = 1.0 / (1.0 + 0.3275911 * ax);
    let y = (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t
        + 0.254829592)
        * t;
    let e = y * (-ax * ax).exp();
    if x < 0.0 {
        2.0 - e
    } else {
        e
    }
}

/// Standard normal CDF via erfc (branch-free form, valid for all x).
fn normal_cdf(x: f64) -> f64 {
    if x < 0.0 {
        0.5 * erfc(-x / core::f64::consts::SQRT_2)
    } else {
        1.0 - 0.5 * erfc(x / core::f64::consts::SQRT_2)
    }
}

/// Natural log-gamma via Lanczos (NR gammln, g=5.5). Verified in tests:
///
/// gammln(1) = 0, gammln(0.5) = ln(sqrt(pi)), gammln(5) = ln(24).
pub fn gammln(x: f64) -> f64 {
    const COF: [f64; 6] = [
        76.18009172947146,
        -86.50532032961677,
        24.01409824083091,
        -1.231739572450155,
        0.1208650973866179e-2,
        -0.5395239384953e-5,
    ];
    let mut y = x;
    let mut tmp = x + 5.5;
    tmp -= (x + 0.5) * tmp.ln();
    let mut ser = 1.000000000190015;
    for c in COF {
        y += 1.0;
        ser += c / y;
    }
    -tmp + (2.5066282746310005 * ser / x).ln()
}

/// Regularized UPPER incomplete gamma Q(a, x) (Numerical Recipes gser/gcf).
/// Valid for a > 0, x >= 0.
pub fn igamc(a: f64, x: f64) -> f64 {
    const EPS: f64 = 1e-14;
    const FP_MIN: f64 = 1e-300;
    if x <= 0.0 {
        return 1.0;
    }
    debug_assert!(a > 0.0);
    let gln = gammln(a);
    if x < a + 1.0 {
        // Series representation -> P(a,x); return 1 - P.
        let mut ap = a;
        let mut del = 1.0 / a;
        let mut sum = del;
        for _ in 0..1000 {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if del.abs() < sum.abs() * EPS {
                break;
            }
        }
        let p = sum * (-x + a * x.ln() - gln).exp();
        (1.0 - p).clamp(0.0, 1.0)
    } else {
        // Continued fraction -> Q(a,x) directly.
        let mut b = x + 1.0 - a;
        let mut c = 1.0 / FP_MIN;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..1000 {
            let an = -(i as f64) * ((i as f64) - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < FP_MIN {
                d = FP_MIN;
            }
            c = b + an / c;
            if c.abs() < FP_MIN {
                c = FP_MIN;
            }
            d = 1.0 / d;
            let del = d * c;
            h *= del;
            if (del - 1.0).abs() < EPS {
                break;
            }
        }
        (h * (-x + a * x.ln() - gln).exp()).clamp(0.0, 1.0)
    }
}

/// Count ones in a 0/1-bit slice.
fn ones(bits: &[u8]) -> u64 {
    bits.iter().map(|&b| (b & 1) as u64).sum()
}

/// 1. Monobit frequency.
pub fn monobit(bits: &[u8]) -> f64 {
    let n = bits.len() as f64;
    let s = (2 * ones(bits)) as f64 - n;
    erfc((s.abs() / n.sqrt()) / core::f64::consts::SQRT_2)
}

/// 2. Block frequency, M-bit blocks.
pub fn block_frequency(bits: &[u8], m: usize) -> f64 {
    let nblocks = bits.len() / m;
    let mut chi2 = 0.0;
    for b in 0..nblocks {
        let pi = ones(&bits[b * m..(b + 1) * m]) as f64 / m as f64;
        chi2 += (pi - 0.5) * (pi - 0.5);
    }
    chi2 *= 4.0 * m as f64;
    igamc(nblocks as f64 / 2.0, chi2 / 2.0)
}

/// 3. Runs. Returns 0.0 if the monobit precondition fails (NIST behavior).
pub fn runs(bits: &[u8]) -> f64 {
    let n = bits.len() as f64;
    let pi = ones(bits) as f64 / n;
    let tau = 2.0 / n.sqrt();
    if (pi - 0.5).abs() >= tau {
        return 0.0;
    }
    let mut v = 1u64;
    for w in bits.windows(2) {
        if w[0] != w[1] {
            v += 1;
        }
    }
    let v = v as f64;
    let num = (v - 2.0 * n * pi * (1.0 - pi)).abs();
    let den = 2.0 * core::f64::consts::SQRT_2 * n.sqrt() * pi * (1.0 - pi);
    erfc(num / den)
}

fn psi2(bits: &[u8], m: usize) -> f64 {
    // Overlapping m-bit pattern counts with wraparound (append first m-1 bits).
    let n = bits.len();
    let mut ext = Vec::with_capacity(n + m);
    ext.extend_from_slice(bits);
    ext.extend_from_slice(&bits[..m - 1]);
    let mut counts = vec![0u64; 1 << m];
    for i in 0..n {
        let mut v = 0usize;
        for k in 0..m {
            v = (v << 1) | (ext[i + k] & 1) as usize;
        }
        counts[v] += 1;
    }
    let mut sum = 0.0;
    for c in counts {
        sum += (c as f64) * (c as f64);
    }
    ((1 << m) as f64) / n as f64 * sum - n as f64
}

/// 4. Serial, m = 3. Returns (p1, p2); both must pass.
pub fn serial(bits: &[u8]) -> (f64, f64) {
    let p3 = psi2(bits, 3);
    let p2 = psi2(bits, 2);
    let p1 = psi2(bits, 1);
    let d1 = p3 - p2;
    let d2 = p3 - 2.0 * p2 + p1;
    (igamc(2.0, d1 / 2.0), igamc(1.0, d2 / 2.0))
}

fn apen_phi(bits: &[u8], m: usize) -> (f64, f64) {
    let n = bits.len();
    let mut ext = Vec::with_capacity(n + m);
    ext.extend_from_slice(bits);
    ext.extend_from_slice(&bits[..m]);
    let mut counts = vec![0u64; 1 << (m + 1).min(16)];
    // Count (m+1)-bit patterns over n windows starting at 0..n with wrap.
    let mut ext2 = Vec::with_capacity(n + m);
    ext2.extend_from_slice(bits);
    ext2.extend_from_slice(&bits[..m]);
    for i in 0..n {
        let mut v = 0usize;
        for k in 0..=m {
            v = (v << 1) | (ext2[i + k] & 1) as usize;
        }
        counts[v] += 1;
    }
    // phi_m from m-bit marginals of the same counts.
    let mut phi_m = 0.0;
    let mut phi_m1 = 0.0;
    for i in 0..(1 << m) {
        let c = (counts[2 * i] + counts[2 * i + 1]) as f64 / n as f64;
        if c > 0.0 {
            phi_m += c * c.ln();
        }
    }
    for c in counts.iter().take(1 << (m + 1)) {
        let cc = *c as f64 / n as f64;
        if cc > 0.0 {
            phi_m1 += cc * cc.ln();
        }
    }
    (phi_m, phi_m1)
}

/// 5. Approximate entropy, m = 3.
pub fn apen(bits: &[u8], m: usize) -> f64 {
    let n = bits.len() as f64;
    let (phi_m, phi_m1) = apen_phi(bits, m);
    let apen = phi_m - phi_m1;
    let chi2 = 2.0 * n * (core::f64::consts::LN_2 - apen);
    igamc((1 << (m - 1)) as f64, chi2 / 2.0)
}

/// 6/7. Cumulative sums forward (false) / backward (true).
pub fn cusum(bits: &[u8], backward: bool) -> f64 {
    let n = bits.len();
    let seq: Vec<i64> = if backward {
        bits.iter().rev().map(|&b| (b & 1) as i64 * 2 - 1).collect()
    } else {
        bits.iter().map(|&b| (b & 1) as i64 * 2 - 1).collect()
    };
    let mut s = 0i64;
    let mut z = 0i64;
    for v in seq {
        s += v;
        if s.abs() > z {
            z = s.abs();
        }
    }
    if z == 0 {
        return 0.0;
    }
    let (n, z) = (n as f64, z as f64);
    let sqn = n.sqrt();
    let k1 = ((-n / z + 1.0) / 4.0).floor() as i64;
    let k2 = ((n / z - 1.0) / 4.0).floor() as i64;
    let k3 = ((-n / z - 3.0) / 4.0).floor() as i64;
    let k4 = ((n / z + 1.0) / 4.0).floor() as i64;
    let mut p = 0.0;
    for k in k1..=k2 {
        let kf = k as f64;
        p += normal_cdf((4.0 * kf + 1.0) * z / sqn) - normal_cdf((4.0 * kf - 1.0) * z / sqn);
    }
    // NOTE: the second sum is ADDED back (P = 1 - S1 + S2 per SP 800-22);
    // accumulating it with += here and returning 1 - p would negate it.
    for k in k3..=k4 {
        let kf = k as f64;
        p -= normal_cdf((4.0 * kf + 3.0) * z / sqn) - normal_cdf((4.0 * kf + 1.0) * z / sqn);
    }
    (1.0 - p).clamp(0.0, 1.0)
}

/// Full suite over a bit slice. Each entry: (name, p-value).
pub fn suite(bits: &[u8]) -> Vec<(&'static str, f64)> {
    let (s1, s2) = serial(bits);
    vec![
        ("monobit", monobit(bits)),
        ("block128", block_frequency(bits, 128)),
        ("runs", runs(bits)),
        ("serial-1", s1),
        ("serial-2", s2),
        ("apen-3", apen(bits, 3)),
        ("cusum-fwd", cusum(bits, false)),
        ("cusum-bwd", cusum(bits, true)),
    ]
}

/// Deterministic keystream bits: XOF-free, from fixed 64 B seed material.
pub fn keystream_bits(seed_material: &[u8; 64], nbits: usize) -> Vec<u8> {
    let (mut st, p) = expand_from_bytes(seed_material);
    iterate(&mut st, &p, N_TRANSIENT);
    let nbytes = nbits.div_ceil(8);
    let mut raw = vec![0u8; nbytes];
    keystream(&st, &p, &mut raw);
    let mut bits = Vec::with_capacity(nbits);
    for b in raw {
        for k in (0..8).rev() {
            if bits.len() >= nbits {
                break;
            }
            bits.push((b >> k) & 1);
        }
    }
    bits
}

/// Fixed seed materials (8): patterned, deterministic.
pub fn gate_seeds() -> [[u8; 64]; 8] {
    let mut out = [[0u8; 64]; 8];
    for (t, s) in out.iter_mut().enumerate() {
        for (i, b) in s.iter_mut().enumerate() {
            *b = ((i * 37 + t * 101) % 256) as u8;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_functions_sane() {
        // erfc reference points (A&S): erfc(0)=1, erfc(1)~0.1572992.
        assert!((erfc(0.0) - 1.0).abs() < 1e-9);
        assert!((erfc(1.0) - 0.1572992).abs() < 1e-6);
        assert!((erfc(-1.0) - 1.8427008).abs() < 1e-6);
        // igamc: Q(1,1) = e^-1; Q(a,0) = 1; chi-square sanity Q(1, 0.5).
        assert!((igamc(1.0, 1.0) - 0.3678794412).abs() < 1e-9);
        assert_eq!(igamc(3.0, 0.0), 1.0);
        assert!((igamc(1.0, 0.5) - 0.6065306597).abs() < 1e-6);
        // gammln: ln Gamma(1) = 0, ln Gamma(5) = ln 24, ln Gamma(0.5).
        assert!(gammln(1.0).abs() < 1e-9);
        assert!((gammln(5.0) - 3.1780538303).abs() < 1e-7);
        assert!((gammln(0.5) - 0.5723649429).abs() < 1e-7);
        // normal_cdf spot checks.
        assert!((normal_cdf(0.0) - 0.5).abs() < 1e-9);
        assert!((normal_cdf(1.96) - 0.9750021).abs() < 1e-5);
    }

    #[test]
    fn degenerate_inputs_fail() {
        // All-zero stream must fail randomness (guards inverted logic).
        let z = vec![0u8; 10_000];
        assert!(monobit(&z) < 0.01);
        assert!(runs(&z) < 0.01);
        assert!(cusum(&z, false) < 0.01);
        // Perfect alternating passes monobit but must fail runs structure-wise.
        let mut alt = vec![0u8; 10_000];
        for (i, b) in alt.iter_mut().enumerate() {
            *b = (i % 2) as u8;
        }
        assert!(monobit(&alt) >= 0.01);
        assert!(runs(&alt) < 0.01);
    }

    #[test]
    fn keystream_suite_gate() {
        // 8 fixed seeds x 100k bits; each test needs >= 7/8 passes at 0.01.
        // Fully deterministic: fixed seeds, no flaky CI.
        const NBITS: usize = 100_000;
        const ALPHA: f64 = 0.01;
        let mut tallies: [(&str, u32); 8] = [
            ("monobit", 0),
            ("block128", 0),
            ("runs", 0),
            ("serial-1", 0),
            ("serial-2", 0),
            ("apen-3", 0),
            ("cusum-fwd", 0),
            ("cusum-bwd", 0),
        ];
        for seed in gate_seeds() {
            let bits = keystream_bits(&seed, NBITS);
            for (i, (_, p)) in suite(&bits).iter().enumerate() {
                assert!(*p >= 0.0 && *p <= 1.0, "p out of range");
                if *p >= ALPHA {
                    tallies[i].1 += 1;
                }
            }
        }
        for (name, n) in tallies {
            eprintln!("gate {:10} {}/8 pass", name, n);
            assert!(n >= 7, "{} passed only {}/8", name, n);
        }
    }
}
