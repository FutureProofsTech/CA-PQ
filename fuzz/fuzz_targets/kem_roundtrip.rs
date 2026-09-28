//! Fuzz X25519+chaos KEM roundtrips on arbitrary seeds/nonces: no panics,
//! decaps matches encaps, output deterministic.
#![no_main]

use chaos_kem as kem;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 76 {
        return;
    }
    let mut seed = [0u8; 32];
    let mut eph = [0u8; 32];
    let mut nonce = [0u8; kem::NONCE_LEN];
    seed.copy_from_slice(&data[..32]);
    eph.copy_from_slice(&data[32..64]);
    nonce.copy_from_slice(&data[64..64 + kem::NONCE_LEN]);
    let (sk, pk) = kem::keygen(seed);
    let Some((ct, ss1)) = kem::encaps(&pk, eph, nonce) else {
        return;
    };
    let ss2 = kem::decaps(&sk, &pk, &ct).expect("roundtrip must hold");
    assert_eq!(ss1, ss2);
    let Some((ct_b, ss1b)) = kem::encaps(&pk, eph, nonce) else {
        return;
    };
    assert_eq!(ct, ct_b, "deterministic ct");
    assert_eq!(ss1, ss1b, "deterministic ss");
});
