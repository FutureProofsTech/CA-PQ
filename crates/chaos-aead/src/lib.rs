//! CA-PQ `chaos-aead`: thin DEM — XOR keystream + keyed MAC.
//! Keystream via keyed XOF over a length-framed nonce
//! (`ca-pq-dem-stream-v2`), tag via keyed hash (`ca-pq-dem-v1` framing).
//! v1 streams (`ss || nonce[..24]` zero-padded) are NOT compatible: they
//! collided distinct nonces into identical keystreams (see `stream`).
//!
//! `seal`/`open` use caller-provided buffers through `alloc` (heapless
//! `seal_into`/`open_into` need no allocator at all).

#![no_std]
#![forbid(unsafe_code)]

#[macro_use]
extern crate alloc;

use alloc::vec::Vec;

pub const TAG_LEN: usize = 16;

fn stream(ss: &[u8; 32], nonce: &[u8], out: &mut [u8]) {
    // Length-framed nonce through a keyed XOF: the full nonce is absorbed,
    // so there is no truncation and no zero-padding ambiguity.
    //
    // SECURITY FIX (was `ca-pq-dem-v1` over `ss || nonce[..24]` zero-padded
    // to 56 B): that scheme mapped distinct nonces to identical streams —
    // any nonce longer than 24 B collided with its 24 B prefix, and
    // `"abc"` collided with `"abc\\0"`. Both are silent catastrophic
    // keystream reuse. The v2 framing breaks those collisions (and wire
    // compat with v1 streams — documented in CHANGELOG).
    let mut h = chaos_hash::Hasher::new_keyed(ss);
    h.update(b"ca-pq-dem-stream-v2");
    h.update(&[0u8]);
    h.update(&(nonce.len() as u64).to_le_bytes());
    h.update(nonce);
    h.finalize_xof(out);
}

/// Seal into caller buffers (no allocator): ct_out = msg XOR stream,
/// returns MAC(ss, nonce||ct). Lengths must match.
pub fn seal_into<const N: usize>(
    ss: &[u8; 32],
    nonce: &[u8],
    msg: &[u8; N],
    ct_out: &mut [u8; N],
) -> [u8; TAG_LEN] {
    stream(ss, nonce, &mut ct_out[..]);
    for (c, m) in ct_out.iter_mut().zip(msg.iter()) {
        *c ^= *m;
    }
    mac_parts(ss, nonce, &ct_out[..])
}

/// Open from caller buffers (no allocator): verifies tag in constant time,
/// then decrypts into a fresh array.
pub fn open_into<const N: usize>(
    ss: &[u8; 32],
    nonce: &[u8],
    ct: &[u8; N],
    tag: &[u8; TAG_LEN],
) -> Option<[u8; N]> {
    let expect = mac_parts(ss, nonce, &ct[..]);
    // Constant-time compare.
    let mut diff = 0u8;
    for (a, b) in expect.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return None;
    }
    let mut msg = [0u8; N];
    stream(ss, nonce, &mut msg);
    for (m, c) in msg.iter_mut().zip(ct.iter()) {
        *m ^= *c;
    }
    Some(msg)
}

/// Keyed MAC over nonce||ct without allocating the concatenation.
/// Byte-identical to `B3::mac(ss, nonce||ct, "ca-pq-dem-v1")`: domain first,
// then separator, then message parts in order.
fn mac_parts(ss: &[u8; 32], nonce: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
    let mut h = chaos_hash::Hasher::new_keyed(ss);
    h.update(b"ca-pq-dem-v1");
    h.update(&[0u8]);
    h.update(nonce);
    h.update(ct);
    let full = h.finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

/// Seal: ct = msg XOR stream, tag = MAC(ss, nonce||ct).
pub fn seal(ss: &[u8; 32], nonce: &[u8], msg: &[u8]) -> (Vec<u8>, [u8; TAG_LEN]) {
    let mut ct = vec![0u8; msg.len()];
    stream(ss, nonce, &mut ct);
    for (c, m) in ct.iter_mut().zip(msg.iter()) {
        *c ^= *m;
    }
    let tag = mac_parts(ss, nonce, &ct);
    (ct, tag)
}

/// Open: verify tag (constant-time) then decrypt.
pub fn open(ss: &[u8; 32], nonce: &[u8], ct: &[u8], tag: &[u8; TAG_LEN]) -> Option<Vec<u8>> {
    let expect = mac_parts(ss, nonce, ct);
    // Constant-time compare.
    let mut diff = 0u8;
    for (a, b) in expect.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return None;
    }
    let mut msg = vec![0u8; ct.len()];
    stream(ss, nonce, &mut msg);
    for (m, c) in msg.iter_mut().zip(ct.iter()) {
        *m ^= *c;
    }
    Some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_tamper() {
        let ss = [9u8; 32];
        let (ct, tag) = seal(&ss, b"nonce-24-bytes-padding!!", b"hello ca-pq");
        assert_eq!(
            open(&ss, b"nonce-24-bytes-padding!!", &ct, &tag).unwrap(),
            b"hello ca-pq"
        );
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(open(&ss, b"nonce-24-bytes-padding!!", &ct, &bad).is_none());
    }

    #[test]
    fn nonce_framing_no_collisions() {
        // Red-team regression: v1 mapped these distinct nonces to identical
        // streams (24 B truncation + zero padding). v2 must separate all.
        let ss = [9u8; 32];
        const M: &[u8; 16] = b"0123456789abcdef";
        let mut ct = [0u8; 16];
        let t_short = seal_into(&ss, b"abc", M, &mut ct);
        let c_short = ct;
        let t_padded = seal_into(&ss, b"abc\0", M, &mut ct);
        let c_padded = ct;
        assert_ne!((c_short, t_short), (c_padded, t_padded), "prefix collision");
        let long = b"abcdefghijklmnopqrstuvwxyz0123456789";
        assert!(long.len() > 24);
        let t_long = seal_into(&ss, long, M, &mut ct);
        let c_long = ct;
        let t_trunc = seal_into(&ss, &long[..24], M, &mut ct);
        let c_trunc = ct;
        assert_ne!((c_long, t_long), (c_trunc, t_trunc), "truncation collision");
        // Empty message and empty nonce roundtrip (no panic, correct open).
        let tag_e = seal_into(&ss, b"", b"", &mut []);
        assert!(open_into(&ss, b"", b"", &tag_e).is_some());
        // Wrong key fails; determinism holds.
        assert!(open_into(&[8u8; 32], b"abc", &c_short, &t_short).is_none());
        let mut ct2 = [0u8; 16];
        assert_eq!(seal_into(&ss, b"abc", M, &mut ct2), t_short);
        assert_eq!(ct2, c_short);
    }

    #[test]
    fn heapless_roundtrip_and_tamper() {
        let ss = [9u8; 32];
        const MSG: &[u8; 11] = b"hello ca-pq";
        let mut ct = [0u8; 11];
        let tag = seal_into(&ss, b"nonce-12B", MSG, &mut ct);
        // Alloc API agrees bit-for-bit with the heapless path.
        let (ct2, tag2) = seal(&ss, b"nonce-12B", MSG);
        assert_eq!(ct.to_vec(), ct2);
        assert_eq!(tag, tag2);
        assert_eq!(open_into(&ss, b"nonce-12B", &ct, &tag).unwrap(), *MSG);
        let mut bad = tag;
        bad[15] ^= 1;
        assert!(open_into(&ss, b"nonce-12B", &ct, &bad).is_none());
        let mut badct = ct;
        badct[0] ^= 1;
        assert!(open_into(&ss, b"nonce-12B", &badct, &tag).is_none());
    }
}
