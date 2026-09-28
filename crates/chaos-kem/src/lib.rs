//! CA-PQ `chaos-kem`: hybrid X25519 + chaotic-stream KEM.
//!
//! Security root: X25519 ECDH, implemented from zero in the private `x25519`
//! module (RFC 7748, verified against golden outputs of an independent
//! big-integer transcription of the pseudocode). The chaotic attractor is a
//! LOCAL deterministic KDF/stream expander (fast, integer-only, no floats) keyed by
//! the ECDH shared secret — it is never published and never relied on for
//! asymmetry. This design follows directly from `chaos-attack` findings:
//! raw drive is slow/structured and slaves offer no asymmetry.
//!
//! Wire: `ct = { nonce, x_eph_pk, tag }` — NO chaotic drive is transmitted.
//! * `encaps(pk)`: fresh ECDH ephemeral, shared -> chaos trajectory -> tail,
//!   `ss = Hash(tail || shared || transcript)`.
//! * `decaps(sk, pk, ct)`: recompute shared, verify MAC tag (transcript bind),
//!   recompute tail + ss. No ephemeral side-channel.
//!
//! Zero third-party dependencies: curve math, hashing, and wiping are all
//! CA-PQ code.

#![forbid(unsafe_code)]
#![no_std]

mod x25519;

use chaos_core::{burn, expand_from_bytes, iterate, N_TRANSIENT};
use chaos_extract::keystream;
use chaos_hash::{DefaultHash, Hash256};

pub const SEED_LEN: usize = 32;
/// 96-bit nonce: standard size for random nonces (cf. GCM); uniqueness bound
/// far exceeds any deployment lifetime. Saves 12 B per ct vs 192-bit.
pub const NONCE_LEN: usize = 12;
pub const SS_LEN: usize = 32;
/// 128-bit tag: standard forgery resistance (cf. GCM/Poly1305).
pub const TAG_LEN: usize = 16;

#[derive(Clone)]
pub struct SecretKey {
    chaos_seed: [u8; SEED_LEN],
    x_secret: [u8; SEED_LEN],
}

// Never Debug-print secret material.
impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey([redacted])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// Commitment to (sysid || chaos material || x25519 pk).
    pub commit: [u8; 32],
    pub sysid: [u8; 4],
    pub x_pk: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub nonce: [u8; NONCE_LEN],
    pub x_eph_pk: [u8; 32],
    /// MAC over transcript under key derived from shared secret.
    pub tag: [u8; TAG_LEN],
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        burn(&mut self.chaos_seed);
        burn(&mut self.x_secret);
    }
}

fn xof(data: &[u8], ctx: &[u8], out: &mut [u8]) {
    DefaultHash::xof(data, ctx, out);
}

/// Long-term keypair from a 32-byte seed (caller supplies RNG).
pub fn keygen(seed: [u8; 32]) -> (SecretKey, PublicKey) {
    let mut chaos_seed = [0u8; 32];
    let mut x_sec = [0u8; 32];
    xof(&seed, b"ca-pq-sk-chaos-v1", &mut chaos_seed);
    xof(&seed, b"ca-pq-sk-x-v1", &mut x_sec);
    let x_pk = x25519::scalarmult(&x_sec, &x25519::BASEPOINT);
    let mut mat = [0u8; 64];
    xof(&chaos_seed, b"ca-pq-kdf-v1", &mut mat);
    let mut pk_in = [0u8; 4 + 64 + 32];
    pk_in[..4].copy_from_slice(b"PQ04");
    pk_in[4..68].copy_from_slice(&mat);
    pk_in[68..].copy_from_slice(&x_pk);
    let commit = DefaultHash::hash(&pk_in, b"ca-pq-pk-v1");
    burn(&mut pk_in);
    burn(&mut mat);
    (
        SecretKey {
            chaos_seed,
            x_secret: x_sec,
        },
        PublicKey {
            commit,
            sysid: *b"PQ04",
            x_pk,
        },
    )
}

/// Transcript bound into MAC and ss: pk.commit || pk.x_pk || eph_pk || nonce.
fn transcript(pk: &PublicKey, eph_pk: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; 108] {
    let mut tr = [0u8; 32 + 32 + 32 + NONCE_LEN];
    tr[..32].copy_from_slice(&pk.commit);
    tr[32..64].copy_from_slice(&pk.x_pk);
    tr[64..96].copy_from_slice(eph_pk);
    tr[96..].copy_from_slice(nonce);
    tr
}

/// Chaos tail from shared secret: XOF(shared||transcript) -> trajectory -> 64B.
fn chaos_tail(shared: &[u8; 32], tr_hash: &[u8; 32]) -> [u8; 64] {
    let mut seed_in = [0u8; 64];
    seed_in[..32].copy_from_slice(shared);
    seed_in[32..].copy_from_slice(tr_hash);
    let mut mat = [0u8; 64];
    xof(&seed_in, b"ca-pq-chaos-v1", &mut mat);
    burn(&mut seed_in);
    let (mut st, params) = expand_from_bytes(&mat);
    burn(&mut mat);
    iterate(&mut st, &params, N_TRANSIENT);
    let mut tail = [0u8; 64];
    keystream(&st, &params, &mut tail);
    tail
}

/// Encapsulate to `pk`. `eph_seed` must be fresh random and `nonce` unique per
/// encaps call; `None` on contributory failure (honest keys: effectively never).
pub fn encaps(
    pk: &PublicKey,
    eph_seed: [u8; 32],
    nonce: [u8; NONCE_LEN],
) -> Option<(Ciphertext, [u8; SS_LEN])> {
    let mut eph_x = [0u8; 32];
    xof(&eph_seed, b"ca-pq-eph-x-v1", &mut eph_x);
    let eph_pk = x25519::scalarmult(&eph_x, &x25519::BASEPOINT);
    let mut shared_b = x25519::scalarmult(&eph_x, &pk.x_pk);
    if x25519::is_zero(&shared_b) {
        burn(&mut eph_x);
        burn(&mut shared_b);
        return None;
    }
    let tr = transcript(pk, &eph_pk, &nonce);
    let tr_hash = DefaultHash::hash(&tr, b"ca-pq-tr-v1");
    let mac_key = DefaultHash::hash(&shared_b, b"ca-pq-mac-v1");
    let full_tag = DefaultHash::mac(&mac_key, &tr, b"ca-pq-ct-v1");
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full_tag[..TAG_LEN]);
    let mut tail = chaos_tail(&shared_b, &tr_hash);
    let mut ss_in = [0u8; 64 + 32 + 32];
    ss_in[..64].copy_from_slice(&tail);
    ss_in[64..96].copy_from_slice(&shared_b);
    ss_in[96..].copy_from_slice(&tr_hash);
    let ss = DefaultHash::hash(&ss_in, b"ca-pq-sync-v1");
    burn(&mut ss_in);
    burn(&mut tail);
    burn(&mut shared_b);
    burn(&mut eph_x);
    Some((
        Ciphertext {
            nonce,
            x_eph_pk: eph_pk,
            tag,
        },
        ss,
    ))
}

/// Decapsulate. Returns `None` on bad tag / contributory failure.
pub fn decaps(sk: &SecretKey, pk: &PublicKey, ct: &Ciphertext) -> Option<[u8; SS_LEN]> {
    let mut shared_b = x25519::scalarmult(&sk.x_secret, &ct.x_eph_pk);
    if x25519::is_zero(&shared_b) {
        burn(&mut shared_b);
        return None;
    }
    let tr = transcript(pk, &ct.x_eph_pk, &ct.nonce);
    let mac_key = DefaultHash::hash(&shared_b, b"ca-pq-mac-v1");
    let full = DefaultHash::mac(&mac_key, &tr, b"ca-pq-ct-v1");
    let mut expect = [0u8; TAG_LEN];
    expect.copy_from_slice(&full[..TAG_LEN]);
    // Constant-time compare.
    let mut diff = 0u8;
    for (a, b) in expect.iter().zip(ct.tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        burn(&mut expect);
        burn(&mut shared_b);
        return None;
    }
    let tr_hash = DefaultHash::hash(&tr, b"ca-pq-tr-v1");
    let mut tail = chaos_tail(&shared_b, &tr_hash);
    let mut ss_in = [0u8; 64 + 32 + 32];
    ss_in[..64].copy_from_slice(&tail);
    ss_in[64..96].copy_from_slice(&shared_b);
    ss_in[96..].copy_from_slice(&tr_hash);
    let ss = DefaultHash::hash(&ss_in, b"ca-pq-sync-v1");
    burn(&mut ss_in);
    burn(&mut tail);
    burn(&mut shared_b);
    Some(ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commits_bind_distinct_keys() {
        // Regression: the commitment must differ per key (a burn-before-hash
        // ordering bug once made it constant — roundtrips still passed).
        let (_, pk1) = keygen([11u8; 32]);
        let (_, pk2) = keygen([12u8; 32]);
        assert_ne!(pk1.commit, pk2.commit);
        assert_ne!(pk1.x_pk, pk2.x_pk);
    }

    #[test]
    fn roundtrip() {
        let (sk, pk) = keygen([11u8; 32]);
        let (ct, ss1) = encaps(&pk, [22u8; 32], [33u8; 12]).expect("encaps");
        let ss2 = decaps(&sk, &pk, &ct).expect("decaps");
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn small_subgroup_fails_closed() {
        // u = 0 point (order <= 2, divides the cofactor 8): every DH scalar
        // in this crate is clamped (multiple of 8, pinned by RFC goldens),
        // so DH with ANY point of order dividing 8 is exactly zero, and the
        // contributory is_zero gate must fail closed on both sides.
        // Attacker-controlled malicious peer point on decaps...
        let (sk, pk) = keygen([7u8; 32]);
        let mut ct0 = Ciphertext {
            nonce: [1u8; NONCE_LEN],
            x_eph_pk: [0u8; 32],
            tag: [2u8; TAG_LEN],
        };
        assert!(decaps(&sk, &pk, &ct0).is_none(), "zero eph must fail");
        // ...and on encaps (malicious recipient pk).
        let pk0 = PublicKey {
            commit: pk.commit,
            sysid: pk.sysid,
            x_pk: [0u8; 32],
        };
        assert!(
            encaps(&pk0, [3u8; 32], [4u8; NONCE_LEN]).is_none(),
            "zero pk must fail"
        );
        // All-0xFF point (above p, twist-adjacent): must not panic; either
        // leg result is acceptable, panic is not.
        ct0.x_eph_pk = [0xFFu8; 32];
        let _ = decaps(&sk, &pk, &ct0);
        let pkf = PublicKey {
            commit: pk.commit,
            sysid: pk.sysid,
            x_pk: [0xFFu8; 32],
        };
        let _ = encaps(&pkf, [3u8; 32], [4u8; NONCE_LEN]);
    }

    #[test]
    fn wrong_recipient_fails() {
        let (_, pk) = keygen([11u8; 32]);
        let (sk2, _) = keygen([99u8; 32]);
        let (ct, _) = encaps(&pk, [22u8; 32], [33u8; 12]).expect("encaps");
        // sk2 does not match pk: shared differs -> tag check fails.
        assert!(decaps(&sk2, &pk, &ct).is_none());
    }

    #[test]
    fn tampered_ct_fails() {
        let (sk, pk) = keygen([11u8; 32]);
        let (mut ct, _) = encaps(&pk, [22u8; 32], [33u8; 12]).expect("encaps");
        ct.nonce[0] ^= 1;
        assert!(decaps(&sk, &pk, &ct).is_none());
        let (mut ct2, _) = encaps(&pk, [22u8; 32], [33u8; 12]).expect("encaps");
        ct2.tag[0] ^= 1;
        assert!(decaps(&sk, &pk, &ct2).is_none());
    }

    #[test]
    fn ss_bound_to_transcript() {
        let (_, pk) = keygen([11u8; 32]);
        let (_, ss1) = encaps(&pk, [22u8; 32], [33u8; 12]).expect("encaps");
        let (_, ss2) = encaps(&pk, [22u8; 32], [34u8; 12]).expect("encaps");
        assert_ne!(ss1, ss2, "different nonce must give different ss");
    }
}

#[cfg(test)]
mod packed_tests {
    use super::*;
    #[test]
    fn seed_packed_storage_roundtrip() {
        // Stored form is just seed32 (32 B, not 64 B): re-derive on load.
        let stored_seed = [0x5Au8; 32];
        let (sk, pk) = keygen(stored_seed);
        let (sk2, pk2) = keygen(stored_seed);
        assert_eq!(pk, pk2, "re-derived pk must match");
        let (ct, ss1) = encaps(&pk, [0x6Bu8; 32], [0x7Cu8; NONCE_LEN]).expect("encaps");
        assert_eq!(decaps(&sk2, &pk2, &ct), Some(ss1));
        let _ = sk;
    }
}
