//! CA-PQ CLI: `ca-pq` — KAT vectors, end-to-end demo, attack summary, bench.
//!
//! Usage: `ca-pq [kat|demo|attack|bench|pq|hybrid]` (default: demo).

use chaos_aead as aead;
use chaos_attack as atk;
use chaos_core::{expand_from_bytes, health_check, iterate, kat_state};
use chaos_extract::keystream;
use chaos_hash::{Hash256, B3};
use chaos_hybrid as hybrid;
use chaos_kem as kem;
use chaos_mlkem as pq;
use std::time::Instant;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn kat() {
    // Core KAT: fixed material -> post-transient state + drive + keystream.
    let mut seed64 = [0u8; 64];
    B3::xof(&[0xA5u8; 32], b"ca-pq-kdf-v1", &mut seed64);
    let (state, drive) = kat_state(&seed64);
    let (mut st, params) = expand_from_bytes(&seed64);
    iterate(&mut st, &params, chaos_core::N_TRANSIENT);
    let mut ks = [0u8; 32];
    keystream(&st, &params, &mut ks);
    println!("kat_state_x={:?}", state);
    println!("kat_drive8={:?}", drive);
    println!("kat_keystream32={}", hex(&ks));
    println!("kat_health_ok={}", health_check(&seed64).ok());
    // KEM KAT.
    let (_, pk) = kem::keygen([11u8; 32]);
    let (ct, ss) = kem::encaps(&pk, [22u8; 32], [33u8; 12]).expect("encaps");
    println!("kat_pk_commit={}", hex(&pk.commit));
    println!("kat_x_eph_pk={}", hex(&ct.x_eph_pk));
    println!("kat_ss={}", hex(&ss));
}

fn demo() {
    let (sk, pk) = kem::keygen([11u8; 32]);
    let nonce = [33u8; 12];
    let (ct, ss1) = kem::encaps(&pk, [22u8; 32], nonce).expect("encaps");
    let ss2 = kem::decaps(&sk, &pk, &ct).expect("decaps");
    assert_eq!(ss1, ss2);
    println!("kem_ss={}", hex(&ss1));
    println!("x_eph_pk={}", hex(&ct.x_eph_pk[..8]));
    let (cbox, tag) = aead::seal(&ss1, &nonce, b"CA-PQ hello");
    let msg = aead::open(&ss1, &nonce, &cbox, &tag).expect("open");
    println!("dem_msg={}", String::from_utf8_lossy(&msg));
    println!("OK ca-pq demo");
}

fn attack() {
    // Mirrors chaos-attack findings with numbers.
    let drive = atk::honest_drive(&[0x77u8; 64], 400, 2048);
    let xs: Vec<f64> = drive.iter().map(|&x| x as f64).collect();
    println!(
        "attack raw-drive-r1-stride400={:+.3}",
        atk::lag1_autocorr_f(&xs)
    );
    let material = [0x51u8; 64];
    let drive = atk::honest_drive(&material, 4, 512);
    let (_, p) = expand_from_bytes(&material);
    let receiver = atk::run_slave(&drive, &p, chaos_core::State([0, 0, 0, 0]));
    let (observer_init, _) = expand_from_bytes(&[0x99u8; 64]);
    let observer = atk::run_slave(&drive, &p, observer_init);
    let err: Vec<i64> = receiver
        .0
        .iter()
        .zip(observer.0.iter())
        .map(|(x, y)| (x - y).abs() >> chaos_core::FRAC)
        .collect();
    println!("attack receiver-vs-observer-slave-err-int-units={:?}", err);
    println!("attack verdict=chaos-is-local-KDF-only-PKI-is-X25519");
}

fn bench() {
    use std::hint::black_box;
    // Cheap helper: run `n` iters of `f`, report per-op time + throughput.
    // Every output passes through black_box so the optimizer cannot delete
    // the measured work (discarded pure results would be dead code).
    fn timed(n: u32, mut f: impl FnMut(u32)) -> (std::time::Duration, u64) {
        let t = Instant::now();
        for i in 0..n {
            f(i);
        }
        let el = t.elapsed();
        // Integer tenths of ops/s: no float Display needed (saves ~12 KiB
        // of core::fmt float formatting in the binary).
        (el, (n as f64 / el.as_secs_f64() * 10.0).round() as u64)
    }
    let (mut st, p) = expand_from_bytes(&[0xA5u8; 64]);
    let (el, r) = timed(200_000, |_| {
        iterate(&mut st, &p, 1);
        black_box(st.0[0]);
    });
    println!(
        "bench core rk4-step: {:?} total ({} steps/s)",
        el,
        (r + 5) / 10
    );
    let mut ks = [0u8; 1024];
    let (el, r) = timed(200, |_| {
        chaos_extract::keystream(&st, &p, &mut ks);
        black_box(ks[0]);
        black_box(ks[1023]);
    });
    println!(
        "bench keystream 1KiB: {:?} total ({}.{} KiB/s)",
        el,
        r / 10,
        r % 10
    );
    let mut buf = [0u8; 1 << 20];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    let (el, r) = timed(20, |_| {
        black_box(chaos_hash::blake3(&buf));
    });
    println!(
        "bench blake3 1MiB: {:?} total ({}.{} MiB/s)",
        el,
        r / 10,
        r % 10
    );
    let key = [0x5Au8; 32];
    let (el, r) = timed(2000, |i| {
        let mut m = [0u8; 64];
        m[0] = i as u8;
        black_box(chaos_hash::blake3_keyed(&key, &m));
    });
    println!(
        "bench blake3-keyed 64B: {:?} total ({} ops/s)",
        el,
        (r + 5) / 10
    );
    let mut shbuf = [0u8; 65536];
    for (i, b) in shbuf.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    let mut shout = [0u8; 65536];
    let (el, r) = timed(20, |_| {
        chaos_hash::shake128(&shbuf, &mut shout);
        black_box(shout[0]);
        black_box(shout[65535]);
    });
    // 1 op = 64 KiB = 1/16 MiB: MiB/s in tenths = r / 160.
    println!(
        "bench shake128 64KiB: {:?} total ({}.{} MiB/s)",
        el,
        r / 160,
        (r % 160) / 16
    );
    let (sk, pk) = kem::keygen([1u8; 32]);
    let (el, r) = timed(50, |i| {
        let mut eph = [0u8; 32];
        eph[0] = i as u8;
        let (ct, ss) = kem::encaps(&pk, eph, [0u8; 12]).expect("encaps");
        let out = kem::decaps(&sk, &pk, &ct);
        black_box((&ct, ss, out));
    });
    println!(
        "bench kem encaps+decaps: {:?} total ({}.{} pairs/s)",
        el,
        r / 10,
        r % 10
    );
    let (el, r) = timed(50, |i| {
        let mut eph = [0u8; 32];
        eph[0] = i as u8;
        let (ct, ss) = kem::encaps(&pk, eph, [i as u8; 12]).expect("encaps");
        black_box(ct);
        black_box(ss);
    });
    println!(
        "bench kem encaps only: {:?} total ({}.{} ops/s)",
        el,
        r / 10,
        r % 10
    );
    let (ct0, _) = kem::encaps(&pk, [9u8; 32], [9u8; 12]).expect("encaps");
    let (el, r) = timed(50, |_| {
        black_box(kem::decaps(&sk, &pk, &ct0));
    });
    println!(
        "bench kem decaps only: {:?} total ({}.{} ops/s)",
        el,
        r / 10,
        r % 10
    );
    let (ek, dk) = pq::keygen(&[3u8; 32], &[4u8; 32]);
    let (el, r) = timed(20, |i| {
        let mut m = [0u8; 32];
        m[0] = i as u8;
        let (ct, ss) = pq::encaps(&ek, &m);
        black_box(ct);
        black_box(ss);
        black_box(pq::decaps(&dk, &ct));
    });
    println!(
        "bench pq encaps+decaps: {:?} total ({}.{} pairs/s)",
        el,
        r / 10,
        r % 10
    );
    let (el, r) = timed(20, |i| {
        let mut m = [0u8; 32];
        m[0] = i as u8;
        let (ct, ss) = pq::encaps(&ek, &m);
        black_box(ct);
        black_box(ss);
    });
    println!(
        "bench pq encaps only: {:?} total ({}.{} ops/s)",
        el,
        r / 10,
        r % 10
    );
    // Batch of 8 to one ek: per-element rate (matrix sampled once).
    let (el, r) = timed(20, |i| {
        let mut ms = [[0u8; 32]; 8];
        for (k, m) in ms.iter_mut().enumerate() {
            m[0] = i as u8;
            m[1] = k as u8;
        }
        let mut cts = [[0u8; pq::CT_LEN]; 8];
        let mut sss = [[0u8; pq::SS_LEN]; 8];
        pq::encaps_batch(&ek, &ms, &mut cts, &mut sss);
        black_box(cts);
        black_box(sss);
    });
    println!(
        "bench pq encaps batch8 per-el: {:?} total ({}.{} ops/s)",
        el,
        r * 8 / 10,
        (r * 8) % 10
    );
    let (ct0, _) = pq::encaps(&ek, &[9u8; 32]);
    let (el, r) = timed(20, |_| {
        black_box(pq::decaps(&dk, &ct0));
    });
    println!(
        "bench pq decaps only: {:?} total ({}.{} ops/s)",
        el,
        r / 10,
        r % 10
    );
    let (e512, d512) = pq::m512::keygen(&[3u8; 32], &[4u8; 32]);
    let (el, r) = timed(20, |i| {
        let mut m = [0u8; 32];
        m[0] = i as u8;
        let (ct, ss) = pq::m512::encaps(&e512, &m);
        black_box(ct);
        black_box(ss);
        black_box(pq::m512::decaps(&d512, &ct));
    });
    println!(
        "bench pq512 encaps+decaps: {:?} total ({}.{} pairs/s)",
        el,
        r / 10,
        r % 10
    );
    let (el, r) = timed(20, |i| {
        let mut m = [0u8; 32];
        m[0] = i as u8;
        let (ct, ss) = pq::m512::encaps(&e512, &m);
        black_box(ct);
        black_box(ss);
    });
    println!(
        "bench pq512 encaps only: {:?} total ({}.{} ops/s)",
        el,
        r / 10,
        r % 10
    );
    let (hs512, hp512) = hybrid::h512::keygen([5u8; 32]);
    let (el, r) = timed(10, |i| {
        let mut s = [0u8; 32];
        s[0] = i as u8;
        let (ct, ss) = hybrid::h512::encaps(&hp512, s, [6u8; 12]).expect("encaps");
        black_box((&ct, ss));
        black_box(hybrid::h512::decaps(&hs512, &hp512, &ct));
    });
    println!(
        "bench hybrid512 encaps+decaps: {:?} total ({}.{} pairs/s)",
        el,
        r / 10,
        r % 10
    );
    let (hsk, hpk) = hybrid::keygen([5u8; 32]);
    let (el, r) = timed(10, |i| {
        let mut s = [0u8; 32];
        s[0] = i as u8;
        let (ct, ss) = hybrid::encaps(&hpk, s, [6u8; 12]).expect("encaps");
        black_box((&ct, ss));
        black_box(hybrid::decaps(&hsk, &hpk, &ct));
    });
    println!(
        "bench hybrid encaps+decaps: {:?} total ({}.{} pairs/s)",
        el,
        r / 10,
        r % 10
    );
    let (el, r) = timed(20, |i| {
        let mut s = [0u8; 32];
        s[0] = i as u8;
        black_box(kem::keygen(s));
    });
    println!("bench kem keygen: {:?} total ({} ops/s)", el, (r + 5) / 10);
    let (el, r) = timed(10, |i| {
        let mut s = [0u8; 32];
        s[0] = i as u8;
        let mut z = [0u8; 32];
        z[0] = !i as u8;
        black_box(pq::keygen(&s, &z));
    });
    println!("bench pq keygen: {:?} total ({} ops/s)", el, (r + 5) / 10);
    let (el, r) = timed(10, |i| {
        let mut s = [0u8; 32];
        s[0] = i as u8;
        black_box(hybrid::keygen(s));
    });
    println!(
        "bench hybrid keygen: {:?} total ({} ops/s)",
        el,
        (r + 5) / 10
    );
}

fn pq() {
    // Post-quantum KEM demo (ML-KEM-768, from zero) with fixed seeds.
    let d = [0xD0u8; 32];
    let z = [0xE0u8; 32];
    let m = [0xF0u8; 32];
    let t = Instant::now();
    let (ek, dk) = pq::keygen(&d, &z);
    let kg = t.elapsed();
    let t = Instant::now();
    let (ct, k1) = pq::encaps(&ek, &m);
    let en = t.elapsed();
    let t = Instant::now();
    let k2 = pq::decaps(&dk, &ct);
    let de = t.elapsed();
    assert_eq!(k1, k2);
    println!(
        "pq sizes ek={} dk={} ct={} ss={}",
        ek.len(),
        dk.len(),
        ct.len(),
        k1.len()
    );
    println!("pq ss={}", hex(&k1));
    println!("pq times keygen={:?} encaps={:?} decaps={:?}", kg, en, de);
    println!("OK ca-pq pq");
}

fn hybrid() {
    // Flagship demo: X25519 + ML-KEM-768 + chaos tail under one transcript.
    let seed = [0xA0u8; 32];
    let eseed = [0xB0u8; 32];
    let nonce = [0xC0u8; 12];
    let t = Instant::now();
    let (hsk, hpk) = hybrid::keygen(seed);
    let kg = t.elapsed();
    let t = Instant::now();
    let (hct, ss1) = hybrid::encaps(&hpk, eseed, nonce).expect("encaps");
    let en = t.elapsed();
    let t = Instant::now();
    let ss2 = hybrid::decaps(&hsk, &hpk, &hct).expect("decaps");
    let de = t.elapsed();
    assert_eq!(ss1, ss2);
    let mut ctb = [0u8; hybrid::CT_LEN];
    ctb[..hybrid::XCT_LEN].copy_from_slice(&{
        let mut b = [0u8; hybrid::XCT_LEN];
        b[..12].copy_from_slice(&hct.ctx.nonce);
        b[12..44].copy_from_slice(&hct.ctx.x_eph_pk);
        b[44..].copy_from_slice(&hct.ctx.tag);
        b
    });
    ctb[hybrid::XCT_LEN..].copy_from_slice(&hct.ct_pq);
    println!(
        "hybrid sizes pk={} sk={} ct={} ss={}",
        hybrid::PK_LEN,
        hybrid::SK_LEN,
        ctb.len(),
        ss1.len()
    );
    println!("hybrid commit={}", hex(&hpk.commit));
    println!("hybrid ct={}", hex(&ctb));
    println!("hybrid ss={}", hex(&ss1));
    println!(
        "hybrid times keygen={:?} encaps={:?} decaps={:?}",
        kg, en, de
    );
    println!("OK ca-pq hybrid");
}

fn stream_dump() {
    // Raw keystream bytes to stdout: seed material + byte count from argv.
    // Used for independent statistical validation (ent/dieharder/etc).
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1 << 20);
    let t: u8 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut mat = [0u8; 64];
    for (i, b) in mat.iter_mut().enumerate() {
        *b = ((i * 37 + t as usize * 101) % 256) as u8;
    }
    use std::io::Write;
    let out = std::io::stdout();
    let mut lock = out.lock();
    // Stream in 1 MiB blocks to bound memory; state carried across blocks.
    let (mut st, p) = expand_from_bytes(&mat);
    iterate(&mut st, &p, chaos_core::N_TRANSIENT);
    let mut cur = st;
    let mut blk = [0u8; 1 << 20];
    let mut left = n;
    while left > 0 {
        let take = left.min(blk.len());
        {
            let b = &mut blk[..take];
            // replicate keystream() stepping manually for continuity
            for byte in b.iter_mut() {
                iterate(&mut cur, &p, chaos_extract::STRIDE);
                *byte = chaos_extract::extract_byte(cur.0[0])
                    ^ chaos_extract::extract_byte(cur.0[1])
                    ^ chaos_extract::extract_byte(cur.0[3]);
            }
        }
        lock.write_all(&blk[..take]).expect("stdout");
        left -= take;
    }
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("kat") => kat(),
        Some("attack") => attack(),
        Some("bench") => bench(),
        Some("pq") => pq(),
        Some("hybrid") => hybrid(),
        Some("stream") => stream_dump(),
        _ => demo(),
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    #[test]
    fn dump_path_matches_keystream() {
        // The stdout dump loop must emit exactly what keystream() yields.
        let mut mat = [0u8; 64];
        for (i, b) in mat.iter_mut().enumerate() {
            *b = ((i * 37) % 256) as u8;
        }
        let (mut st, p) = expand_from_bytes(&mat);
        iterate(&mut st, &p, chaos_core::N_TRANSIENT);
        let mut a = [0u8; 4096];
        keystream(&st, &p, &mut a);
        let mut cur = st;
        let mut b = [0u8; 4096];
        for byte in b.iter_mut() {
            iterate(&mut cur, &p, chaos_extract::STRIDE);
            *byte = chaos_extract::extract_byte(cur.0[0])
                ^ chaos_extract::extract_byte(cur.0[1])
                ^ chaos_extract::extract_byte(cur.0[3]);
        }
        assert_eq!(a, b);
    }
}
