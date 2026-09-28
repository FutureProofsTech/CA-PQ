//! Differential fuzz: incremental SHAKE128 absorb splits and chunked streaming
//! squeeze must equal one-shot output, for arbitrary inputs.
#![no_main]

use chaos_hash::Shake128;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 2048 || data.is_empty() {
        return;
    }
    let mut refb = [0u8; 100];
    chaos_hash::shake128(data, &mut refb);
    // Odd absorb splits, one-shot finalize.
    let mut s = Shake128::new();
    let mut pos = 0;
    let mut step = 1usize;
    while pos < data.len() {
        let take = step.min(data.len() - pos);
        s.absorb(&data[pos..pos + take]);
        pos += take;
        step = step.wrapping_mul(3) % 997 + 1;
    }
    let mut o1 = [0u8; 100];
    s.finalize(&mut o1);
    assert_eq!(o1, refb, "split absorb must equal one-shot");
    // Odd absorb splits, chunked streaming squeeze.
    let mut s2 = Shake128::new();
    let mut pos = 0;
    let mut step = 2usize;
    while pos < data.len() {
        let take = step.min(data.len() - pos);
        s2.absorb(&data[pos..pos + take]);
        pos += take;
        step = step.wrapping_mul(7) % 521 + 1;
    }
    let mut sq = s2.streamer();
    let mut o2 = [0u8; 100];
    let mut p2 = 0;
    let mut c2 = 1usize;
    while p2 < 100 {
        let take = c2.min(100 - p2);
        sq.squeeze(&mut o2[p2..p2 + take]);
        p2 += take;
        c2 = c2.wrapping_mul(5) % 131 + 1;
    }
    assert_eq!(o2, refb, "chunked squeeze must equal one-shot");
});
