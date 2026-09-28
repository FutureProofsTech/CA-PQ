//! CA-PQ flagship: X25519 + ML-KEM-768 + chaotic-stream hybrid KEM.
//!
//! Combiner: `ss = Hash(ss_x || ss_pq || tr_hash)` under a joint transcript
//! binding both ciphertexts, both public halves, and the nonce. Secure if
//! EITHER component KEM holds (classical ECDH today, lattice cover for the
//! quantum setting); the chaotic tail inside the X25519 leg adds a fast local
//! stream layer, never asymmetry. Deterministic API — caller supplies all
//! randomness. Zero third-party dependencies.

#![forbid(unsafe_code)]
#![no_std]

use chaos_core::burn;
use chaos_hash::{DefaultHash, Hash256};
use chaos_kem as kem;
use chaos_mlkem as pq;

pub const SYSID: [u8; 4] = *b"PQH2";
pub const SS_LEN: usize = 32;
pub const NONCE_LEN: usize = kem::NONCE_LEN;
/// X ct bytes: nonce(12) + eph_pk(32) + tag(16).
pub const XCT_LEN: usize = 12 + 32 + 16;

/// 68 (X pk) + 1184 (PQ ek) + 32 (commit).
pub const PK_LEN: usize = 68 + pq::EK_LEN + 32;
/// 64 (X sk) + 2400 (PQ dk).
pub const SK_LEN: usize = 64 + pq::DK_LEN;
/// 60 (X ct) + 1088 (PQ ct).
pub const CT_LEN: usize = XCT_LEN + pq::CT_LEN;

#[derive(Clone)]
pub struct HSecretKey {
    xsk: kem::SecretKey,
    pq_dk: [u8; pq::DK_LEN],
}

// Never Debug-print secret material.
impl core::fmt::Debug for HSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HSecretKey([redacted])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HPublicKey {
    pub xpk: kem::PublicKey,
    pub pq_ek: [u8; pq::EK_LEN],
    pub commit: [u8; 32],
    pub sysid: [u8; 4],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HCiphertext {
    pub ctx: kem::Ciphertext,
    pub ct_pq: [u8; pq::CT_LEN],
}

impl Drop for HSecretKey {
    fn drop(&mut self) {
        burn(&mut self.pq_dk);
    }
}

/// Canonical X-leg ciphertext bytes: nonce || eph_pk || tag (60 B).
fn ctx_bytes(ct: &kem::Ciphertext) -> [u8; XCT_LEN] {
    let mut b = [0u8; XCT_LEN];
    b[..NONCE_LEN].copy_from_slice(&ct.nonce);
    b[NONCE_LEN..NONCE_LEN + 32].copy_from_slice(&ct.x_eph_pk);
    b[NONCE_LEN + 32..].copy_from_slice(&ct.tag);
    b
}

/// Joint transcript hash: commit || ct_x || ct_pq || nonce.
fn transcript(hpk: &HPublicKey, hct: &HCiphertext, nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let xb = ctx_bytes(&hct.ctx);
    let mut tr = [0u8; 32 + XCT_LEN + pq::CT_LEN + NONCE_LEN];
    tr[..32].copy_from_slice(&hpk.commit);
    tr[32..32 + XCT_LEN].copy_from_slice(&xb);
    tr[32 + XCT_LEN..32 + XCT_LEN + pq::CT_LEN].copy_from_slice(&hct.ct_pq);
    tr[32 + XCT_LEN + pq::CT_LEN..].copy_from_slice(nonce);
    DefaultHash::hash(&tr, b"ca-pq-h-tr")
}

fn combine(ss_x: &[u8; SS_LEN], ss_pq: &[u8; SS_LEN], tr_hash: &[u8; 32]) -> [u8; SS_LEN] {
    let mut inp = [0u8; 96];
    inp[..32].copy_from_slice(ss_x);
    inp[32..64].copy_from_slice(ss_pq);
    inp[64..].copy_from_slice(tr_hash);
    let ss = DefaultHash::hash(&inp, b"ca-pq-h-ss");
    burn(&mut inp);
    ss
}

/// Long-term keypair from a 32-byte seed (caller supplies RNG).
pub fn keygen(seed: [u8; 32]) -> (HSecretKey, HPublicKey) {
    let sub_x = DefaultHash::hash(&seed, b"ca-pq-h-x");
    let sub_d = DefaultHash::hash(&seed, b"ca-pq-h-mlkem-d");
    let sub_z = DefaultHash::hash(&seed, b"ca-pq-h-mlkem-z");
    let (xsk, xpk) = kem::keygen(sub_x);
    let (pq_ek, pq_dk) = pq::keygen(&sub_d, &sub_z);
    let mut ci = [0u8; 32 + 4 + 32 + pq::EK_LEN];
    ci[..32].copy_from_slice(&xpk.commit);
    ci[32..36].copy_from_slice(&xpk.sysid);
    ci[36..68].copy_from_slice(&xpk.x_pk);
    ci[68..].copy_from_slice(&pq_ek);
    let commit = DefaultHash::hash(&ci, b"ca-pq-h-pk");
    (
        HSecretKey { xsk, pq_dk },
        HPublicKey {
            xpk,
            pq_ek,
            commit,
            sysid: SYSID,
        },
    )
}

/// Encapsulate: both legs under one transcript. `seed` must be fresh random
/// and `nonce` unique per encaps call.
/// Returns `None` only on X-leg contributory failure (effectively never).
pub fn encaps(
    hpk: &HPublicKey,
    seed: [u8; 32],
    nonce: [u8; NONCE_LEN],
) -> Option<(HCiphertext, [u8; SS_LEN])> {
    let mut eph_x = DefaultHash::hash(&seed, b"ca-pq-h-eph-x");
    let mut m_pq = DefaultHash::hash(&seed, b"ca-pq-h-eph-m");
    let (ctx, ss_x) = kem::encaps(&hpk.xpk, eph_x, nonce)?;
    let (ct_pq, ss_pq) = pq::encaps(&hpk.pq_ek, &m_pq);
    burn(&mut eph_x);
    burn(&mut m_pq);
    let hct = HCiphertext { ctx, ct_pq };
    let tr_hash = transcript(hpk, &hct, &nonce);
    let mut ss_xb = ss_x;
    let mut ss_pqb = ss_pq;
    let ss = combine(&ss_xb, &ss_pqb, &tr_hash);
    burn(&mut ss_xb);
    burn(&mut ss_pqb);
    Some((hct, ss))
}

/// Decapsulate. `None` iff the X leg fails (tampered X half / wrong X key);
/// a tampered PQ half yields a different ss via implicit rejection instead.
pub fn decaps(hsk: &HSecretKey, hpk: &HPublicKey, hct: &HCiphertext) -> Option<[u8; SS_LEN]> {
    let ss_x = kem::decaps(&hsk.xsk, &hpk.xpk, &hct.ctx)?;
    let ss_pq = pq::decaps(&hsk.pq_dk, &hct.ct_pq);
    let tr_hash = transcript(hpk, hct, &hct.ctx.nonce);
    let mut ss_xb = ss_x;
    let mut ss_pqb = ss_pq;
    let ss = combine(&ss_xb, &ss_pqb, &tr_hash);
    burn(&mut ss_xb);
    burn(&mut ss_pqb);
    Some(ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds(t: u8) -> ([u8; 32], [u8; 32], [u8; NONCE_LEN]) {
        (
            core::array::from_fn(|i| (3 * i as u8).wrapping_add(t)),
            core::array::from_fn(|i| (5 * i as u8).wrapping_add(2 * t)),
            core::array::from_fn(|i| (7 * i as u8).wrapping_add(3 * t)),
        )
    }

    #[test]
    fn roundtrip_and_determinism() {
        let (seed, enc_seed, nonce) = seeds(1);
        let (hsk, hpk) = keygen(seed);
        let (ct1, ss1) = encaps(&hpk, enc_seed, nonce).expect("encaps");
        let (ct2, ss2) = encaps(&hpk, enc_seed, nonce).expect("encaps");
        assert_eq!((&ct1, ss1), (&ct2, ss2), "deterministic from seed");
        assert_eq!(decaps(&hsk, &hpk, &ct1), Some(ss1));
    }

    #[test]
    fn tamper_x_half_fails_closed() {
        let (seed, enc_seed, nonce) = seeds(2);
        let (hsk, hpk) = keygen(seed);
        let (mut ct, _) = encaps(&hpk, enc_seed, nonce).expect("encaps");
        ct.ctx.nonce[0] ^= 1;
        assert!(decaps(&hsk, &hpk, &ct).is_none());
        let (mut ct2, _) = encaps(&hpk, enc_seed, nonce).expect("encaps");
        ct2.ctx.tag[0] ^= 1;
        assert!(decaps(&hsk, &hpk, &ct2).is_none());
        let (mut ct3, _) = encaps(&hpk, enc_seed, nonce).expect("encaps");
        ct3.ctx.x_eph_pk[0] ^= 1;
        assert!(decaps(&hsk, &hpk, &ct3).is_none());
    }

    #[test]
    fn tamper_pq_half_rejects_to_different_ss() {
        let (seed, enc_seed, nonce) = seeds(3);
        let (hsk, hpk) = keygen(seed);
        let (ct, ss) = encaps(&hpk, enc_seed, nonce).expect("encaps");
        let mut bad = ct.clone();
        bad.ct_pq[100] ^= 1;
        bad.ct_pq[1077] ^= 0x80;
        let rej = decaps(&hsk, &hpk, &bad).expect("decaps always returns");
        assert_ne!(rej, ss, "tampered PQ half must not yield real ss");
        assert_eq!(
            decaps(&hsk, &hpk, &bad),
            Some(rej),
            "rejection deterministic"
        );
    }

    #[test]
    fn zero_peer_point_fails_closed() {
        // Malicious zero ephemeral point: the X leg contributory gate
        // must fail the whole hybrid closed.
        let (seed, enc_seed, nonce) = seeds(6);
        let (hsk, hpk) = keygen(seed);
        let (mut hct, _) = encaps(&hpk, enc_seed, nonce).expect("encaps");
        hct.ctx.x_eph_pk = [0u8; 32];
        assert!(decaps(&hsk, &hpk, &hct).is_none());
    }

    #[test]
    fn wrong_recipient_fails() {
        let (seed, enc_seed, nonce) = seeds(4);
        let (_, hpk) = keygen(seed);
        let (hsk2, _) = keygen([9u8; 32]);
        let (ct, _) = encaps(&hpk, enc_seed, nonce).expect("encaps");
        assert!(decaps(&hsk2, &hpk, &ct).is_none());
    }

    #[test]
    fn combiner_mixes_both_legs() {
        // The final ss must differ from either leg's ss alone (else one leg
        // would be decorative). Recompute legs directly from the same inputs.
        let (seed, enc_seed, nonce) = seeds(5);
        let (hsk, hpk) = keygen(seed);
        let (hct, ss) = encaps(&hpk, enc_seed, nonce).expect("encaps");
        let eph_x = DefaultHash::hash(&enc_seed, b"ca-pq-h-eph-x");
        let (_, ss_x) = kem::encaps(&hpk.xpk, eph_x, nonce).expect("x leg");
        let m_pq = DefaultHash::hash(&enc_seed, b"ca-pq-h-eph-m");
        let (_, ss_pq) = pq::encaps(&hpk.pq_ek, &m_pq);
        assert_ne!(ss, ss_x, "ss must mix PQ leg in");
        assert_ne!(ss, ss_pq, "ss must mix X leg in");
        assert_eq!(decaps(&hsk, &hpk, &hct), Some(ss));
    }

    #[test]
    fn sizes_are_spec() {
        assert_eq!(PK_LEN, 68 + 1184 + 32);
        assert_eq!(SK_LEN, 64 + 2400);
        assert_eq!(CT_LEN, 60 + 1088);
        assert_eq!(SS_LEN, 32);
    }
}

#[cfg(test)]
mod kat_tests {
    use super::*;

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

    /// Full-stack KAT 1: independently computed by the Python reference
    /// (big-int X25519 + manual BLAKE3 compress + pip keyed/XOF + mlkem ref).
    /// Seeds: keygen 0xA0, encaps 0xB0, nonce 0xC0.
    #[test]
    fn kat_hybrid_a() {
        let (hsk, hpk) = keygen([0xA0u8; 32]);
        let (hct, ss) = encaps(&hpk, [0xB0u8; 32], [0xC0u8; 12]).expect("encaps");
        assert_eq!(decaps(&hsk, &hpk, &hct), Some(ss));
        assert_eq!(
            hpk.commit,
            unhex::<32>(b"cd7c456e3c1ea78b25951c2e49a379f35ef1eead3e84b5f115cb8e9eb19587ab")
        );
        let mut ctb = [0u8; CT_LEN];
        ctb[..XCT_LEN].copy_from_slice(&{
            let mut b = [0u8; XCT_LEN];
            b[..NONCE_LEN].copy_from_slice(&hct.ctx.nonce);
            b[NONCE_LEN..NONCE_LEN + 32].copy_from_slice(&hct.ctx.x_eph_pk);
            b[NONCE_LEN + 32..].copy_from_slice(&hct.ctx.tag);
            b
        });
        ctb[XCT_LEN..].copy_from_slice(&hct.ct_pq);
        assert_eq!(
            ctb,
            unhex::<1148>(b"c0c0c0c0c0c0c0c0c0c0c0c0d28737becd2c9a6fd102c7762027c385954140bb11673f0fe34003fd3732a579c7ef10bb99cf5b1f05df6e6a35ac126d633532fe77b503fc903708dc492b4d4a6f91a9b94ef4a4c83b00876ed4c050f756063d7c1b5d24389ee8cc64a99102f64f7acc05bb89c3fb13b8f95fa395e87a3190641c0f7ebcae11dcab100285e2c0bb3d98261f2c8b5e7492b1391b016261c0f91f99eaa49c33f4616aeea0b8a43d2d289a75d89844e650bedb00b2d029740f8fda08706eb944b9217bc2039f8cee1e1d574753025b37d51f40d25ebce703305c491637e96616939dcf48f9750a28d5e1f9bb2a900a1a1dc43d455f359f740a923afec60c111fc8e9cef058fae6fe7bed2141f1de8cccb7b79f591af4a74950307b89e3c623e99ed118252ecbc968f0672f64660aa4761923b84772dbd5b9e300107fdf46950b6b87a8346c37cd6d091323f9a39805b745190402593ee74b2fdbeab77807896d0226a64d5641e43160af4fb0888b35bbfc293f428cedf010a62fad427cefcd6c0572704af329acef7209b484bacf748909e5238bb572523d64dadda7019cc5e21117ee533194c0389382f5d50a2144b92f4da8554ecbcfff65a1c77e2444c4325b30f386a1de657711ed825859c6218eadcf76d1e7346d691b2f09d29c9e21e4c3c5f43ff52327b22e1a1f521076c5230ce1a2aef53767b348ba0d401499f58c4b274d51322c6cadf455af6819955c4bb4a831f74c4d0975113911c5bc2cb4350e3b5cad78d0ce08ec9be01e3b57d82475b1ef1d81e319cd5e97b92d78bbe9f49f9d900bcc7b25b49e1515aa811606830504e0b46a9f837342a3cf2aa0763eac8d31a9131e4a6a43d969d41d1ef8e307db8f8195f9bf0e7044a543af60399bf77a55c842c52ecc29dd8087fdf2ed138d2366b94ff5565b7ab4851bce7e1ad038de8ebdec17128524881699611fbc80817f287c3f6a902407f7dba2233749199d665ca5d9740d1fb5d9a93e4966dbbd18ee54e679f8482242b4fbdc7f06926692b8dbc2479740f468c659ad6bf7545384ccd5dc52c0453ae59ad60c4b229aa7102e8c5bbe586d76b5799a3136e3c558d3d19c2cafd670b91c410db2a2d1091ce57d8b2687acc5f45504c04b07335a12809011998a056f0a358c2bdcbd91fefdcc6e3ca8fc4cf3d68b180d08df952da0eecd265ac2947ffc34a80eecfd32fdc2e989e019b5ee64ae0b3decda519b60b22add582c784c3e10479f9753122ebbc171b7dc9a343cfe9703d3b4fc12d688464560c1ba27cf33b4ffce1892e7b98fdf8731b41bbeb3c5149d0e95b9a189489ace01797ed037723606d269266f00d979929ceba8d000da71d2551411201f1f5861fe3fadf2ad85adebf2795df9318e9f67c14534b13a54fe5d7e121810596d46051d781a247657bf5498d871218a7117b227e6f4c65d77376447ab39676b95c3fa54b23ca9a330339e9885cbf01ca2b8ef2095d8d0997a2499e56e88de220d1d47fdedb384c556c289d8015d45c1cb5ea243ef810bc13679babf50ca6fcea0e70345f7476af548cab6736c08d4197c42a0e16c087c648d0b64c1b504ede91ed9ec2bde207b3a28a740")
        );
        assert_eq!(
            ss,
            unhex::<32>(b"cf19cd367eebd8d669068a359c00a74f03f93fb4a02e4d3545c51e916866ee71")
        );
    }

    /// Full-stack KAT 2: keygen 0x11, encaps 0x22, nonce 0x33.
    #[test]
    fn kat_hybrid_b() {
        let (hsk, hpk) = keygen([0x11u8; 32]);
        let (hct, ss) = encaps(&hpk, [0x22u8; 32], [0x33u8; 12]).expect("encaps");
        assert_eq!(decaps(&hsk, &hpk, &hct), Some(ss));
        assert_eq!(
            hpk.commit,
            unhex::<32>(b"5c2960c389f2dcf4a0568f0f42c222189e0702d2f3ffaaf09779472752fbcda1")
        );
        let mut ctb = [0u8; CT_LEN];
        ctb[..XCT_LEN].copy_from_slice(&{
            let mut b = [0u8; XCT_LEN];
            b[..NONCE_LEN].copy_from_slice(&hct.ctx.nonce);
            b[NONCE_LEN..NONCE_LEN + 32].copy_from_slice(&hct.ctx.x_eph_pk);
            b[NONCE_LEN + 32..].copy_from_slice(&hct.ctx.tag);
            b
        });
        ctb[XCT_LEN..].copy_from_slice(&hct.ct_pq);
        assert_eq!(
            ctb,
            unhex::<1148>(b"333333333333333333333333e98d5156a051a3d8498ce31865fe13585178f56d293d1cb7a8254e59e3275c5f74f0f101f1e998270963cdf6af7d9693359d8edd39c983374e2df061e5b8984c3f73081f3fee2863ff7c1977c2baf37ec0ab4773ae1b223bbfe821804d996cd230c633c4a3cf153096e34615d2c4eb1a6eb36f95689b851c57cad05d6509b8840ff3c86c8a9d58a497bd015c7be9971d78922d28a0b355e4b9f8c0755e617c71c96212b3f71d54acce97fb9f4db481af83cd92d72175c5ad4028e9bb2dca60a54cd6d712c85afe9b2e3fca15aba4952e1da93243f456a48049d64985615a4efa2bd0d058f5f2d62ba387259238ef0623259a10950e1b1b813d68a989e00579562fcc1903e867d9abe933f4e53a3c92dd57f1707d5969b8df894890ef72998769ff284af35fe76dfa32ef43cb62903e7cfb271b2b384fb8a5c0a87f3ac09a7d3e9c9a439f4b5a9db3262b7fb1fe10595b4b1406b44f61cdd629fc8b1b1360a0378c4f486086d637e9b5e664213b713763545bbf18508be6d05065cb6cc72bd88669a7bb82d8de9d434ee96169ceef9a53f410fa14cbf0acaf790f5b72304c612004ac6bb0882412b77720164e884583a5baef09d7a0cfb79383a5f1c9b4f02e881afd6ab1971421b8adb8a16a5303df59543833e23b9d65c35d09018638819860f6e218258544bc01eb685a35dbb6c755352b03d1b0d662ac52caa091a16ae99acfee8d325a1014d4fc8cc8b3966da15bfb7fc9f2d5c0a2111008b07b100e995932aa91fd5b6e169057f5a2a9661029def1b4a121a3095702074ca5ade91400521aba0b4a7aa412e2a0e922dc89d2cd62d856b4cde9b1abd930c5a997c29e3e75f5f4cdd8ebf2117d358fc6544ad6a22a681dcde0b4472b0fed43f3c95750cc922ec35ba62836bfa6dba24c1d6be6245b8f364c3f53e45ced7219e04ade9d0c1914869a97120dc82c1b4a0bdd19862ee8f06e0e046ab67cb651a34a4b5650db921b5b89e13cb57e744f4219445ebfb6d0180864161c4b9fe9460762bcc2a69ba0f6fa79cc7fde621261b09c13f3df8ba744750097d5a6b4cafda3208843765137fff56cfd40dc979ee7e02d0ded9d1d16dc6fc7232df381ca1c688e4a18cc3cc878513433a188f8b920cc24ab63482994a6e263c433025b3bc029c386dab5ace7228e90690279e77185dd2cf560100a858f075bf9f0cf420f4372e4ce02ea5be42eee67cbfd0f42ad7251509445abeff450d62fcc2e4660642ac7488731a46ad526b95a6a72b22ea29a00a0aab63d45323ea0cdf52cc9e04d02e24547d19544171be6d06bbcbf9a5674943c8f64d4663ba65f533f7677b30eed29ef5b7bfd8c95b2b78b27ef8fe33899962d15c281e43506e755d772f34770b193c021c0a89b0cfbdda070526f5aae289b058114f92aa4064aae6b098265bdd00f5a0766d5ce6183e572a749aa5f4027b133439f365d75e44c4a335774c28350363a064e0cc3021c5c7c020b4bc660e8b61ea0b6399210886c22fe8522f241eeeea0be4a4bfb35b6efb733c7a2b586d980ecd4863b31d567f82eed163a58302cf305c6435e472b657e4ea21f5a93cae038b83f24242cb5")
        );
        assert_eq!(
            ss,
            unhex::<32>(b"4abd3980eba72bbd85a020c51a106b169b41c6310e26db339071fc48c5041958")
        );
    }
}

#[cfg(test)]
mod packed_tests {
    use super::*;
    #[test]
    fn seed_packed_storage_roundtrip() {
        // Stored form is seed32 (32 B, not 2464 B): re-derive on load.
        let stored = [0x5Au8; 32];
        let (_, hpk) = keygen(stored);
        let (_, hpk2) = keygen(stored);
        assert_eq!(hpk, hpk2, "re-derived pk must match");
        let (hsk2, _) = keygen(stored);
        let (hct, ss1) = encaps(&hpk, [0x6Bu8; 32], [0x7Cu8; NONCE_LEN]).expect("encaps");
        assert_eq!(decaps(&hsk2, &hpk2, &hct), Some(ss1));
    }
}

/// ML-KEM-512 hybrid combiner (NIST level 1 + X25519 + chaotic stream).
///
/// Same construction as the 768 flagship: `ss = Hash(ss_x || ss_pq || tr_hash)`
/// under a joint transcript, secure if EITHER leg holds. Differences from
/// the flagship, all load-bearing for domain separation:
/// - PQ leg is `chaos_mlkem::m512` (ek 800 / ct 768 B).
/// - sysid `PQH1` (flagship: `PQH2`).
/// - `ca-pq-h512-*` hash domains (flagship: `ca-pq-h-*`); the hashed inputs
///   already differ in length, this removes all cross-profile analysis.
///
/// Deterministic API — caller supplies all randomness.
pub mod h512 {
    use super::{ctx_bytes, NONCE_LEN, SS_LEN, XCT_LEN};
    use chaos_core::burn;
    use chaos_hash::{DefaultHash, Hash256};
    use chaos_kem as kem;
    use chaos_mlkem::m512 as pq;

    /// Profile sysid (flagship hybrid uses `PQH2`).
    pub const SYSID: [u8; 4] = *b"PQH1";
    /// 68 (X pk) + 800 (PQ ek) + 32 (commit).
    pub const PK_LEN: usize = 68 + pq::EK_LEN + 32;
    /// 64 (X sk) + 1632 (PQ dk). Informational: the struct form holds the
    /// same material; seed-packed storage stays 32 B (re-derive on load).
    pub const SK_LEN: usize = 64 + pq::DK_LEN;
    /// 60 (X ct) + 768 (PQ ct).
    pub const CT_LEN: usize = XCT_LEN + pq::CT_LEN;

    #[derive(Clone)]
    pub struct HSecretKey {
        xsk: kem::SecretKey,
        pq_dk: [u8; pq::DK_LEN],
    }

    // Never Debug-print secret material.
    impl core::fmt::Debug for HSecretKey {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("HSecretKey([redacted])")
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct HPublicKey {
        pub xpk: kem::PublicKey,
        pub pq_ek: [u8; pq::EK_LEN],
        pub commit: [u8; 32],
        pub sysid: [u8; 4],
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct HCiphertext {
        pub ctx: kem::Ciphertext,
        pub ct_pq: [u8; pq::CT_LEN],
    }

    impl Drop for HSecretKey {
        fn drop(&mut self) {
            burn(&mut self.pq_dk);
        }
    }

    /// Combiner: same shape as the flagship, own domain.
    fn combine(ss_x: &[u8; SS_LEN], ss_pq: &[u8; SS_LEN], tr_hash: &[u8; 32]) -> [u8; SS_LEN] {
        let mut inp = [0u8; 96];
        inp[..32].copy_from_slice(ss_x);
        inp[32..64].copy_from_slice(ss_pq);
        inp[64..].copy_from_slice(tr_hash);
        let ss = DefaultHash::hash(&inp, b"ca-pq-h512-ss");
        burn(&mut inp);
        ss
    }

    /// Joint transcript hash: commit || ct_x || ct_pq || nonce.
    fn transcript(hpk: &HPublicKey, hct: &HCiphertext, nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
        let xb = ctx_bytes(&hct.ctx);
        let mut tr = [0u8; 32 + XCT_LEN + pq::CT_LEN + NONCE_LEN];
        tr[..32].copy_from_slice(&hpk.commit);
        tr[32..32 + XCT_LEN].copy_from_slice(&xb);
        tr[32 + XCT_LEN..32 + XCT_LEN + pq::CT_LEN].copy_from_slice(&hct.ct_pq);
        tr[32 + XCT_LEN + pq::CT_LEN..].copy_from_slice(nonce);
        DefaultHash::hash(&tr, b"ca-pq-h512-tr")
    }

    /// Long-term keypair from a 32-byte seed (caller supplies RNG).
    pub fn keygen(seed: [u8; 32]) -> (HSecretKey, HPublicKey) {
        let sub_x = DefaultHash::hash(&seed, b"ca-pq-h512-x");
        let sub_d = DefaultHash::hash(&seed, b"ca-pq-h512-mlkem-d");
        let sub_z = DefaultHash::hash(&seed, b"ca-pq-h512-mlkem-z");
        let (xsk, xpk) = kem::keygen(sub_x);
        let (pq_ek, pq_dk) = pq::keygen(&sub_d, &sub_z);
        let mut ci = [0u8; 32 + 4 + 32 + pq::EK_LEN];
        ci[..32].copy_from_slice(&xpk.commit);
        ci[32..36].copy_from_slice(&xpk.sysid);
        ci[36..68].copy_from_slice(&xpk.x_pk);
        ci[68..].copy_from_slice(&pq_ek);
        let commit = DefaultHash::hash(&ci, b"ca-pq-h512-pk");
        (
            HSecretKey { xsk, pq_dk },
            HPublicKey {
                xpk,
                pq_ek,
                commit,
                sysid: SYSID,
            },
        )
    }

    /// Encapsulate: both legs under one transcript. `seed` must be fresh
    /// random and `nonce` unique per encaps call.
    /// Returns `None` only on X-leg contributory failure (effectively never).
    pub fn encaps(
        hpk: &HPublicKey,
        seed: [u8; 32],
        nonce: [u8; NONCE_LEN],
    ) -> Option<(HCiphertext, [u8; SS_LEN])> {
        let mut eph_x = DefaultHash::hash(&seed, b"ca-pq-h512-eph-x");
        let mut m_pq = DefaultHash::hash(&seed, b"ca-pq-h512-eph-m");
        let (ctx, ss_x) = kem::encaps(&hpk.xpk, eph_x, nonce)?;
        let (ct_pq, ss_pq) = pq::encaps(&hpk.pq_ek, &m_pq);
        burn(&mut eph_x);
        burn(&mut m_pq);
        let hct = HCiphertext { ctx, ct_pq };
        let tr_hash = transcript(hpk, &hct, &nonce);
        let mut ss_xb = ss_x;
        let mut ss_pqb = ss_pq;
        let ss = combine(&ss_xb, &ss_pqb, &tr_hash);
        burn(&mut ss_xb);
        burn(&mut ss_pqb);
        Some((hct, ss))
    }

    /// Decapsulate. `None` iff the X leg fails; a tampered PQ half yields a
    /// different ss via implicit rejection instead.
    pub fn decaps(hsk: &HSecretKey, hpk: &HPublicKey, hct: &HCiphertext) -> Option<[u8; SS_LEN]> {
        let ss_x = kem::decaps(&hsk.xsk, &hpk.xpk, &hct.ctx)?;
        let ss_pq = pq::decaps(&hsk.pq_dk, &hct.ct_pq);
        let tr_hash = transcript(hpk, hct, &hct.ctx.nonce);
        let mut ss_xb = ss_x;
        let mut ss_pqb = ss_pq;
        let ss = combine(&ss_xb, &ss_pqb, &tr_hash);
        burn(&mut ss_xb);
        burn(&mut ss_pqb);
        Some(ss)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn seeds(t: u8) -> ([u8; 32], [u8; 32], [u8; NONCE_LEN]) {
            (
                core::array::from_fn(|i| (3 * i as u8).wrapping_add(t)),
                core::array::from_fn(|i| (5 * i as u8).wrapping_add(2 * t)),
                core::array::from_fn(|i| (7 * i as u8).wrapping_add(3 * t)),
            )
        }

        #[test]
        fn roundtrip_and_determinism() {
            let (seed, enc_seed, nonce) = seeds(1);
            let (hsk, hpk) = keygen(seed);
            assert_eq!(hpk.sysid, *b"PQH1");
            let (ct1, ss1) = encaps(&hpk, enc_seed, nonce).expect("encaps");
            let (ct2, ss2) = encaps(&hpk, enc_seed, nonce).expect("encaps");
            assert_eq!((&ct1, ss1), (&ct2, ss2), "deterministic from seed");
            assert_eq!(decaps(&hsk, &hpk, &ct1), Some(ss1));
        }

        #[test]
        fn tamper_x_half_fails_closed() {
            let (seed, enc_seed, nonce) = seeds(2);
            let (hsk, hpk) = keygen(seed);
            let (mut ct, _) = encaps(&hpk, enc_seed, nonce).expect("encaps");
            ct.ctx.nonce[0] ^= 1;
            assert!(decaps(&hsk, &hpk, &ct).is_none());
            let (mut ct2, _) = encaps(&hpk, enc_seed, nonce).expect("encaps");
            ct2.ctx.tag[0] ^= 1;
            assert!(decaps(&hsk, &hpk, &ct2).is_none());
        }

        #[test]
        fn tamper_pq_half_rejects_to_different_ss() {
            let (seed, enc_seed, nonce) = seeds(3);
            let (hsk, hpk) = keygen(seed);
            let (ct, ss) = encaps(&hpk, enc_seed, nonce).expect("encaps");
            let mut bad = ct.clone();
            bad.ct_pq[100] ^= 1;
            bad.ct_pq[757] ^= 0x80;
            let rej = decaps(&hsk, &hpk, &bad).expect("decaps always returns");
            assert_ne!(rej, ss, "tampered PQ half must not yield real ss");
            assert_eq!(decaps(&hsk, &hpk, &bad), Some(rej));
        }

        #[test]
        fn zero_peer_point_fails_closed() {
            // Malicious zero ephemeral point: the X leg contributory gate
            // (clamped scalar x torsion = 0) must fail the whole hybrid
            // closed — the PQ leg never gets a chance to accept alone.
            let (seed, enc_seed, nonce) = seeds(6);
            let (hsk, hpk) = keygen(seed);
            let (mut hct, _) = encaps(&hpk, enc_seed, nonce).expect("encaps");
            hct.ctx.x_eph_pk = [0u8; 32];
            assert!(decaps(&hsk, &hpk, &hct).is_none());
        }

        #[test]
        fn wrong_recipient_fails() {
            let (seed, enc_seed, nonce) = seeds(4);
            let (_, hpk) = keygen(seed);
            let (hsk2, _) = keygen([9u8; 32]);
            let (ct, _) = encaps(&hpk, enc_seed, nonce).expect("encaps");
            assert!(decaps(&hsk2, &hpk, &ct).is_none());
        }

        #[test]
        fn combiner_mixes_both_legs() {
            let (seed, enc_seed, nonce) = seeds(5);
            let (hsk, hpk) = keygen(seed);
            let (hct, ss) = encaps(&hpk, enc_seed, nonce).expect("encaps");
            let eph_x = DefaultHash::hash(&enc_seed, b"ca-pq-h512-eph-x");
            let (_, ss_x) = kem::encaps(&hpk.xpk, eph_x, nonce).expect("x leg");
            let m_pq = DefaultHash::hash(&enc_seed, b"ca-pq-h512-eph-m");
            let (_, ss_pq) = pq::encaps(&hpk.pq_ek, &m_pq);
            assert_ne!(ss, ss_x, "ss must mix PQ leg in");
            assert_ne!(ss, ss_pq, "ss must mix X leg in");
            assert_eq!(decaps(&hsk, &hpk, &hct), Some(ss));
        }

        #[test]
        fn sizes_are_spec() {
            assert_eq!(PK_LEN, 68 + 800 + 32);
            assert_eq!(SK_LEN, 64 + 1632);
            assert_eq!(CT_LEN, 60 + 768);
            assert_eq!(SS_LEN, 32);
        }
    }

    #[cfg(test)]
    mod kat_tests_512 {
        use super::*;

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

        /// Full-stack KAT A from the independent Python reference
        /// (hybrid512_ref.py): keygen 0xA0, encaps 0xB0, nonce 0xC0.
        #[test]
        fn kat_h512_a() {
            let (hsk, hpk) = keygen([0xA0u8; 32]);
            let (hct, ss) = encaps(&hpk, [0xB0u8; 32], [0xC0u8; NONCE_LEN]).expect("encaps");
            assert_eq!(decaps(&hsk, &hpk, &hct), Some(ss));
            assert_eq!(
                hpk.commit,
                unhex::<32>(b"6ab60ba089d978c28a5409aeae847524c19d2f6e30f1085e323d059fe748d04c")
            );
            let mut ctb = [0u8; CT_LEN];
            ctb[..XCT_LEN].copy_from_slice(&{
                let mut b = [0u8; XCT_LEN];
                b[..NONCE_LEN].copy_from_slice(&hct.ctx.nonce);
                b[NONCE_LEN..NONCE_LEN + 32].copy_from_slice(&hct.ctx.x_eph_pk);
                b[NONCE_LEN + 32..].copy_from_slice(&hct.ctx.tag);
                b
            });
            ctb[XCT_LEN..].copy_from_slice(&hct.ct_pq);
            assert_eq!(
                ctb,
                unhex::<828>(b"c0c0c0c0c0c0c0c0c0c0c0c056210c738623dde75f85cb0ab6fdb6a3c8362e9022633124acf43bbb4f2f532df46ea660471a07f95cac3593cc729755f27e64720054f09ff1ed9632b606a7111890482014c16087cc1799d3c54facc388495de0c95ceb9a470cf7368fe6b7f2d493bd5b6fc6433ceda9f3ce861ee5d0c5f75263bd7baf6e55b4279302a285a7ea8338e4224bdbbed30ac6fbe4626516dc25a7ddeea119fb65c3b0c7dbfa201e595c33e309a80e92bd1c8a6354abc0ad41abf559bd4c966a4891f0a2544e488ad301913eb6a824167f64041a6370ffb4089827a21aa5781f645d287f8e09d72c347d827e6951d4c2a93776164cb1b3b2039be871556fbfcc16cb1ed9cc6e485f1c94ca4f990bf7390492eff2ec4e07bdf9997990fa90dfef4dcffe8a227db5c4b32ea6f448f5b61655d3a5155e5cb236134b2c977225d6c10ea3be3de94841af8645aa058314d5156fe28df21b11a588f2db2f4bc8c2820ba3e60ff62c183de5bef8e6b36e3601fc7aa527131e351be40759a5247ebbfe2bcceaa24e94013a1f1d668b6571e40065b5838b3e6c3d260e03adf7b674e679af18f95f4454537744919561e4b42b0f97a36ce7fbd1f47e05bc561e83cd7373aca7c43a803150e96ded88ca573483b92747a737f644d8b35aa9523edd85f457c879b77500e324099a8ec93208415f28a5c6304b1a0073a56715d1e09537bda4dd560b27b425d988db1d33c36768ca227e7ba0d0d65f28060d2f7cd685a60aff757d42a7e3a0663823587f0503699453b873d7281424986b68579ff831adf2693bb36678ee35f03a0ca6d1e6fd39c970b6eafbf1d0af1e8fcae58bdef88b7f0bbf16e156636cb7d0a42f6dacb26108bd272a7bc14ba8826ed64704a794ec61860c22e8c9fcecd960bf717f20840cd993391cdd9d69efcbc81bb4e3b6f392e89444000b4e41c0d082c5c0bee6214e501448aec99911ed202e666ed53ad2b19ade3890ac0fddfe6a2772999df9246e2241940a72ab9e83d06f7474a002b0f1f7de9617cda5bc457241d9fb25195439a899a2680a0e19ea2d8f6f297f68e5d12c12e1c957e4696a5c39830d087ac4508773d6f1be25c2e3881c1cc8a861f46e01fafd764cdb76110b6b849a94185af8a0e6933da21006b70e7593")
            );
            assert_eq!(
                ss,
                unhex::<32>(b"773c3b402b385e35f02385f1db19aacf86164f0e237d4a9bdb3c423f7f75ced4")
            );
        }

        /// Full-stack KAT B: keygen 0x11, encaps 0x22, nonce 0x33.
        #[test]
        fn kat_h512_b() {
            let (hsk, hpk) = keygen([0x11u8; 32]);
            let (hct, ss) = encaps(&hpk, [0x22u8; 32], [0x33u8; NONCE_LEN]).expect("encaps");
            assert_eq!(decaps(&hsk, &hpk, &hct), Some(ss));
            assert_eq!(
                hpk.commit,
                unhex::<32>(b"f3f92a47e9d247df4e32a6f769a3c4500688a6a2374286d1679e710cc56bb644")
            );
            let mut ctb = [0u8; CT_LEN];
            ctb[..XCT_LEN].copy_from_slice(&{
                let mut b = [0u8; XCT_LEN];
                b[..NONCE_LEN].copy_from_slice(&hct.ctx.nonce);
                b[NONCE_LEN..NONCE_LEN + 32].copy_from_slice(&hct.ctx.x_eph_pk);
                b[NONCE_LEN + 32..].copy_from_slice(&hct.ctx.tag);
                b
            });
            ctb[XCT_LEN..].copy_from_slice(&hct.ct_pq);
            assert_eq!(
                ctb,
                unhex::<828>(b"33333333333333333333333338ba26aee17c3b47eb59c1b0edaabef8ba4d0abe1684093b3f3be401c9921b3803fcad384c3a46484c11312668cc47a4441cacd109929593d980d7cc166422c7102993a8e72a901266398327ce1956ce8a22492857d2a0e1b5df0e37261f4ea3adb6aa12c8e51c380685ab8ede90f6b11b66f64a080ba2530a93530188405b0596b6c8246a230df7f7f288846c0c62545e46d86158462dfbb4c0181314f8a2bbd3fe633769dfce6037de75aacf90b888bd33656f8b35d01ab5a86cc57ff67014d14c4be0dca41bdbde7dec27c32c94f7f6ba3475569228032237672b2d16194649c9a11f0968cd257fd8287cc0dd4691ce0e07432d6066ef9727b53b9018ce53f9a980e3e794b4ebe91d24f850a811208eab11561776a51572f121817bb8e568608fd29452445233f6bb5e1dfdc068a8c55f61be810368fcf070c5f92246c56ca4421b0b6b581f642f94835aa02becb257133ae216f2a43c0e831faf40a12fab096453b01df7b55a138d64eb41c457a5bec54c33a6c93dacabd38ae5be733819a6d0443cd00dbec5ccc63174a1429803e0647ce84f923a3a091e7ef7308683bccd371e6e31e64d4810fe209324e542d0d71aeb063a4055f5ccc14a70aef592c7d410ed0f1664ea828bf619e30d7ab1ea9f611092f34a10e06ce0f6c06780800667cf75b0c8c3697b29104642ad19f0d7d850832e1ca0c116ac7fcc2fee107d9607941ba4e8144e6067ad02e493cb92eef332402357b2c214bb5551232c653c71a97e9cff92f87c845b29f66ad5b1ff19446e82defd5c6a335a1773c595d5ed71c53e246b4da82172981028513a792ffa5ecb69c158d660b794504e08cd25cbd8c2c2ebc6900a70af81a2ebdacbd9c4dfad2c092e8e54e679623a6452aa7e102bb83dffb4533c9e991df68734a0508813d56249293410792632d9c3b27e3e27e0c7831779e2b1c3d4261556d595b76dea88bfc3be3acd66b069207cba4b0307d3f7bd0fcbe0772a71a7145e88d6ee470162551b96275882966ecaf2c12c490be01d8742771b004043aaeabb2a03d3610d51f3668d7aad2b65acd9f9563c6414c559c1d2b5d79298343a6454e3306d21b3fbf51ce62d9179bf938cda3e8e354f6ba4626c5c0f8789766315a2024d8ba0e0")
            );
            assert_eq!(
                ss,
                unhex::<32>(b"a16a3ce4e74172e7308483a6c85c58fe5635fcbb8c10bd172cb534ac5dcede91")
            );
        }
    }
}
