//! Fuzz ML-KEM-768 roundtrips on arbitrary seeds: no panics, decaps always
//! matches encaps, output deterministic.
#![no_main]

use chaos_mlkem as pq;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
        return;
    }
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    let mut m = [0u8; 32];
    d.copy_from_slice(&data[..32]);
    z.copy_from_slice(&data[32..64]);
    m.copy_from_slice(&data[64..96]);
    let (ek, dk) = pq::keygen(&d, &z);
    let (ct, k1) = pq::encaps(&ek, &m);
    let k2 = pq::decaps(&dk, &ct);
    assert_eq!(k1, k2, "roundtrip must hold");
    let (ct_b, k1b) = pq::encaps(&ek, &m);
    assert_eq!(ct, ct_b, "deterministic ct");
    assert_eq!(k1, k1b, "deterministic ss");
    let _ = pq::burn_dk;
});
