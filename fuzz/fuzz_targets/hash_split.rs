//! Differential fuzz: incremental absorb splits must equal one-shot digests
//! (plain + keyed + XOF), for arbitrary inputs and split patterns.
#![no_main]

use chaos_hash::{blake3, blake3_keyed, Hasher};
use libfuzzer_sys::fuzz_target;

fn splits(seed: u8) -> [usize; 4] {
    // Deterministic split points derived from input bytes (no `arbitrary` crate).
    let mut out = [0usize; 4];
    let mut s = seed as usize + 1;
    for o in out.iter_mut() {
        s = s.wrapping_mul(1103515245).wrapping_add(12345) >> 3 + 1;
        *o = s;
    }
    out
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 || data.is_empty() {
        return;
    }
    // Plain, split three ways.
    let ref_plain = blake3(data);
    for chunking in 0..3u8 {
        let mut h = Hasher::new();
        let mut pos = 0;
        let sp = splits(chunking);
        let mut si = 0;
        while pos < data.len() {
            let take = (sp[si % 4] % (data.len() - pos + 1)).max(1);
            h.update(&data[pos..pos + take]);
            pos += take;
            si += 1;
        }
        assert_eq!(h.finalize(), ref_plain);
    }
    // Keyed + XOF prefix consistency on the same splits.
    let key = [0x5Au8; 32];
    let mut kh = Hasher::new_keyed(&key);
    let mut pos = 0;
    while pos < data.len() {
        let take = ((pos * 7 + 13) % (data.len() - pos + 1)).max(1);
        kh.update(&data[pos..pos + take]);
        pos += take;
    }
    let kd = kh.finalize();
    assert_eq!(kd, blake3_keyed(&key, data));
    let mut xo = [0u8; 96];
    kh.finalize_xof(&mut xo);
    assert_eq!(&xo[..32], &kd);
});
