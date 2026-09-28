//! CA-PQ `chaos-attack`: red-team harness.
//!
//! Findings are asserted as tests so regressions scream:
//!
//! 1. Raw quantized `x` is a SLOW signal (lag-1 autocorr > 0.9 even at stride
//!    400). Publishing it as a "public key" leaks a predictable macro
//!    trajectory — return-map/delay-embedding family applies directly. Verdict:
//!    raw drive must NEVER go on the wire.
//! 2. Any two response slaves (different inits) fed the same public drive
//!    converge TO EACH OTHER — a third-party observer recovers exactly what
//!    the intended receiver recovers, so initial-state secrecy gives zero
//!    asymmetry. (And neither matches the sender's true hidden state once the
//!    drive is quantized, so true sync is dead as well.) Verdict: PKI must come
//!    from the hybrid (X25519 root), chaos is a local KDF/stream layer.
//! 3. Folded-low-bit keystream bytes ARE decorrelated (|r| < 0.1 at stride 10).
//!    Verdict: the local stream/DEM layer is sound.

#![forbid(unsafe_code)]

use chaos_core::{expand_from_bytes, iterate, quantize16, response_step, DT_Q, FRAC};

/// Dequantize a 16-bit drive sample back to Q32.32 (best reconstruction).
pub fn dequantize(q: i16) -> i64 {
    (q as i64) << (FRAC - 12)
}

/// Honest trajectory drive (quantized x).
pub fn honest_drive(material: &[u8; 64], stride: usize, n: usize) -> Vec<i16> {
    let (mut s, p) = expand_from_bytes(material);
    iterate(&mut s, &p, chaos_core::N_TRANSIENT);
    let mut drive = Vec::with_capacity(n);
    for _ in 0..n {
        iterate(&mut s, &p, stride);
        drive.push(quantize16(s.0[0]));
    }
    drive
}

/// Run a response slave from `init` over the drive with given params.
pub fn run_slave(
    drive: &[i16],
    p: &chaos_core::Params,
    init: chaos_core::State,
) -> chaos_core::State {
    let mut s = init;
    for &q in drive {
        response_step(dequantize(q), &mut s, p, DT_Q);
    }
    s
}

/// Lag-1 autocorrelation (f64 analysis only, never key material).
pub fn lag1_autocorr_f(xs: &[f64]) -> f64 {
    let n = xs.len() as f64;
    let mean: f64 = xs.iter().sum::<f64>() / n;
    let (mut num, mut den) = (0.0, 0.0);
    for w in xs.windows(2) {
        num += (w[0] - mean) * (w[1] - mean);
    }
    for &x in xs {
        den += (x - mean).powi(2);
    }
    if den == 0.0 {
        0.0
    } else {
        num / den
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaos_core::State;

    #[test]
    fn raw_drive_is_slow_predictable_signal() {
        // At the sampling density a sync scheme needs (stride 4), the macro
        // signal crawls (r ~ 0.97): publishing it leaks a predictable
        // trajectory — return-map/delay-embedding family applies directly.
        // (At stride 400 true chaos does decorrelate; sync can't use that.)
        let drive = honest_drive(&[0x77u8; 64], 4, 2048);
        let xs: Vec<f64> = drive.iter().map(|&x| x as f64).collect();
        let r = lag1_autocorr_f(&xs);
        eprintln!("raw drive lag-1 autocorr @stride4 = {:.3}", r);
        assert!(
            r > 0.5,
            "drive decorrelated?! (r={:.3}) — revisit masking analysis",
            r
        );
    }

    #[test]
    fn observer_matches_receiver_slave_state() {
        // The intended receiver and a third-party observer both run response
        // slaves from DIFFERENT inits on the same public drive. They converge
        // TO EACH OTHER — so whatever the receiver derives from the drive,
        // the observer derives too. Initial-state secrecy provides zero
        // protection. (Separately: neither matches the sender's true hidden
        // state once the drive is quantized — true sync is dead as well.)
        let material = [0x51u8; 64];
        let drive = honest_drive(&material, 4, 512);
        let (_, p) = expand_from_bytes(&material);
        let receiver = run_slave(&drive, &p, State([0, 0, 0, 0]));
        let (observer_init, _) = expand_from_bytes(&[0x99u8; 64]);
        let observer = run_slave(&drive, &p, observer_init);
        let err_units: Vec<i64> = receiver
            .0
            .iter()
            .zip(observer.0.iter())
            .map(|(x, y)| (x - y).abs() >> FRAC)
            .collect();
        eprintln!(
            "receiver-vs-observer slave error (int units): {:?}",
            err_units
        );
        for (i, e) in err_units.iter().enumerate() {
            assert!(
                e.abs() <= 4,
                "coordinate {}: observer did NOT match receiver (err {}) — asymmetry?! Re-open analysis",
                i,
                e
            );
        }
    }

    #[test]
    fn extracted_bytes_are_decorrelated() {
        //Defense check: folded-low-bit bytes at operational STRIDE=10.
        let (mut s, p) = expand_from_bytes(&[0x51u8; 64]);
        iterate(&mut s, &p, chaos_core::N_TRANSIENT);
        let mut ks = Vec::new();
        for _ in 0..2048 {
            iterate(&mut s, &p, chaos_extract::STRIDE);
            ks.push(((s.0[0] ^ s.0[1] ^ s.0[3]) & 0xFF) as f64);
        }
        let r = lag1_autocorr_f(&ks);
        eprintln!("keystream byte lag-1 autocorr = {:+.3}", r);
        assert!(
            r.abs() < 0.1,
            "keystream bytes correlated (r={:+.3}) — extractor broken",
            r
        );
    }
}
