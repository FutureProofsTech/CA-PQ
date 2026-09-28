//! From-zero Keccak-f\[1600\] sponge: SHA3-256/512, SHAKE128/256.
//!
//! Hand-written from the public FIPS 202 construction: the 24 round constants
//! are generated at compile time by the specified LFSR (no magic table), rho
//! offsets and the θ/ρ/π/χ/ι steps follow the reference layout, pad10\*1 with
//! domain suffixes (0x06 SHA3, 0x1F SHAKE). Verified against an independent
//! oracle (Python `hashlib`, i.e. a separate Keccak codebase) in tests.
//! No third-party dependencies; `no_std` compatible.

#![forbid(unsafe_code)]

/// Compile-time round constants from the specified LFSR (poly x^8+x^6+x^5+x^4+1).
const fn gen_rc() -> [u64; 24] {
    let mut rc = [0u64; 24];
    let mut lfsr: u8 = 0x01;
    let mut round = 0;
    while round < 24 {
        let mut j = 0u32;
        while j <= 6 {
            let out = lfsr & 1;
            if lfsr & 0x80 != 0 {
                lfsr = (lfsr << 1) ^ 0x71;
            } else {
                lfsr <<= 1;
            }
            if out != 0 {
                rc[round] |= 1u64 << ((1u32 << j) - 1);
            }
            j += 1;
        }
        round += 1;
    }
    rc
}

const RC: [u64; 24] = gen_rc();

/// Rotation offsets r[x][y] are inlined as literals in `keccak_f` (same
/// FIPS 202 table that used to live here); keeping a second copy would
/// risk silent divergence, so the table was removed when unrolling.
const SHA3_256_RATE: usize = 136;
const SHA3_512_RATE: usize = 72;
const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

/// Rho rotation offsets r\[x\]\[y\].
const RHO: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

fn keccak_f(state: &mut [u64; 25]) {
    for &rc in RC.iter() {
        // θ
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }
        // ρ + π: B\[y, 2x+3y\] = ROT(A\[x,y\], r\[x\]\[y\])
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = state[x + 5 * y].rotate_left(RHO[x][y]);
            }
        }
        // χ
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // ι
        state[0] ^= rc;
    }
}

/// Incremental sponge. Absorb, then finalize once with a domain suffix.
pub struct Sponge {
    state: [u64; 25],
    buf: [u8; SHAKE128_RATE],
    used: usize,
    rate: usize,
}

impl Sponge {
    fn new(rate: usize) -> Self {
        debug_assert!(rate <= SHAKE128_RATE);
        Self {
            state: [0u64; 25],
            buf: [0u8; SHAKE128_RATE],
            used: 0,
            rate,
        }
    }

    fn xor_block(&mut self) {
        for (i, lane) in self.state.iter_mut().enumerate().take(self.rate / 8) {
            let o = 8 * i;
            *lane ^= u64::from_le_bytes([
                self.buf[o],
                self.buf[o + 1],
                self.buf[o + 2],
                self.buf[o + 3],
                self.buf[o + 4],
                self.buf[o + 5],
                self.buf[o + 6],
                self.buf[o + 7],
            ]);
        }
    }

    pub fn absorb(&mut self, mut data: &[u8]) {
        if self.used > 0 {
            let take = (self.rate - self.used).min(data.len());
            self.buf[self.used..self.used + take].copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used == self.rate {
                self.xor_block();
                keccak_f(&mut self.state);
                self.buf = [0u8; SHAKE128_RATE];
                self.used = 0;
            }
        }
        while data.len() >= self.rate {
            self.buf[..self.rate].copy_from_slice(&data[..self.rate]);
            self.xor_block();
            keccak_f(&mut self.state);
            self.buf = [0u8; SHAKE128_RATE];
            data = &data[self.rate..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.used = data.len();
        }
    }

    /// Apply pad10\*1 with the domain suffix, then squeeze `out` bytes.
    pub fn finalize_xof(mut self, suffix: u8, out: &mut [u8]) {
        self.buf[self.used] ^= suffix;
        self.buf[self.rate - 1] ^= 0x80;
        self.xor_block();
        keccak_f(&mut self.state);
        let mut s = Squeezer {
            state: self.state,
            rate: self.rate,
            pos: 0,
        };
        s.squeeze(out);
    }

    /// Pad and enter streaming squeeze mode: repeated `squeeze` calls extend
    /// the SAME output stream (prefix-identical to one-shot `finalize_xof`).
    pub fn streamer(mut self, suffix: u8) -> Squeezer {
        self.buf[self.used] ^= suffix;
        self.buf[self.rate - 1] ^= 0x80;
        self.xor_block();
        keccak_f(&mut self.state);
        Squeezer {
            state: self.state,
            rate: self.rate,
            pos: 0,
        }
    }
}

/// Streaming XOF reader over an already-padded sponge state.
pub struct Squeezer {
    state: [u64; 25],
    rate: usize,
    pos: usize, // bytes already squeezed from the current rate block
}

impl Squeezer {
    /// Fill `out` from the stream, permuting as needed. Output is exactly the
    /// continuation of the XOF byte stream (matches one-shot squeeze).
    pub fn squeeze(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            if self.pos == self.rate {
                keccak_f(&mut self.state);
                self.pos = 0;
            }
            let lane = self.state[self.pos / 8];
            let off = self.pos % 8;
            let b = lane.to_le_bytes();
            let n = (out.len() - done).min(8 - off).min(self.rate - self.pos);
            out[done..done + n].copy_from_slice(&b[off..off + n]);
            done += n;
            self.pos += n;
        }
    }
}

/// Four parallel Keccak-f permutations with exactly one dispatch point:
/// the AVX2 4-way kernel when compiled with `target-feature=+avx2`, else
/// four sequential scalar permutations. Outputs are bit-identical either
/// way (differential test below pins this); only the speed differs.
fn keccak_f_4(states: &mut [[u64; 25]; 4]) {
    // AVX2: one 4-way kernel. SSE2/NEON tiers: two 2-way kernels over each
    // half (same joint-XOF contract, narrower vectors). Elsewhere: scalar.
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    chaos_simd::keccak_f_x4(states);
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2",
        not(all(target_arch = "x86_64", target_feature = "avx2"))
    ))]
    {
        let (lo, hi) = states.split_at_mut(2);
        chaos_simd::keccak_f_x2(lo.try_into().unwrap());
        chaos_simd::keccak_f_x2(hi.try_into().unwrap());
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    {
        let (lo, hi) = states.split_at_mut(2);
        chaos_simd::keccak_f_x2_neon(lo.try_into().unwrap());
        chaos_simd::keccak_f_x2_neon(hi.try_into().unwrap());
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            target_feature = "sse2",
            not(all(target_arch = "x86_64", target_feature = "avx2"))
        ),
        all(target_arch = "aarch64", target_feature = "neon")
    )))]
    for s in states.iter_mut() {
        keccak_f(s);
    }
}

/// Four parallel SHAKE128 squeezes. Absorb + pad are scalar per lane (each
/// lane pads at its own length, so those permutations stay independent);
/// only the squeeze phase advances lockstep through `keccak_f_4`.
/// Over-squeezing a finished lane only permutes state whose bytes were
/// already written, so lanes may have different output lengths and the
/// bytes are identical to four independent one-shot `shake128` calls.
/// Four parallel SHAKE128 squeezes (see `squeeze_x4` for the contract).
pub fn shake128_squeeze_x4(inputs: [&[u8]; 4], outputs: [&mut [u8]; 4]) {
    squeeze_x4(SHAKE128_RATE, 0x1F, inputs, outputs);
}

/// Four parallel SHAKE256 squeezes: same joint-XOF construction as
/// `shake128_squeeze_x4`, only the rate differs (the permutation — and the
/// AVX2 kernel — is rate-independent).
pub fn shake256_squeeze_x4(inputs: [&[u8]; 4], outputs: [&mut [u8]; 4]) {
    squeeze_x4(SHAKE256_RATE, 0x1F, inputs, outputs);
}

fn squeeze_x4(rate: usize, suffix: u8, inputs: [&[u8]; 4], mut outputs: [&mut [u8]; 4]) {
    let mut sponges: [Sponge; 4] = core::array::from_fn(|_| Sponge::new(rate));
    for (s, inp) in sponges.iter_mut().zip(inputs.iter()) {
        s.absorb(inp);
    }
    let mut states = [[0u64; 25]; 4];
    for (dst, s) in states.iter_mut().zip(sponges.iter_mut()) {
        s.buf[s.used] ^= suffix;
        s.buf[s.rate - 1] ^= 0x80;
        s.xor_block();
        keccak_f(&mut s.state);
        *dst = s.state;
    }
    let mut done = [0usize; 4];
    let lens = [
        outputs[0].len(),
        outputs[1].len(),
        outputs[2].len(),
        outputs[3].len(),
    ];
    let mut block = 0usize;
    loop {
        // Serve every lane from the current rate block.
        for k in 0..4 {
            let out = &mut outputs[k];
            while done[k] < lens[k] && done[k] / rate == block {
                let off = done[k] % rate;
                // Whole-lane fast path when aligned.
                if off.is_multiple_of(8) && done[k] + 8 <= lens[k] && off + 8 <= rate {
                    out[done[k]..done[k] + 8].copy_from_slice(&states[k][off / 8].to_le_bytes());
                    done[k] += 8;
                } else {
                    out[done[k]] = states[k][off / 8].to_le_bytes()[off % 8];
                    done[k] += 1;
                }
            }
        }
        if done == lens {
            break;
        }
        // Every unfinished lane needs the next block: advance jointly.
        keccak_f_4(&mut states);
        block += 1;
    }
}

/// Incremental SHAKE128 writer.
pub struct Shake128(Sponge);
/// Incremental SHAKE256 writer.
pub struct Shake256(Sponge);

impl Shake128 {
    pub fn new() -> Self {
        Self(Sponge::new(SHAKE128_RATE))
    }
    pub fn absorb(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }
    pub fn finalize(self, out: &mut [u8]) {
        self.0.finalize_xof(0x1F, out);
    }
    /// Pad and return a streaming reader for incremental squeezing.
    pub fn streamer(self) -> Squeezer {
        self.0.streamer(0x1F)
    }
}

impl Shake256 {
    pub fn new() -> Self {
        Self(Sponge::new(SHAKE256_RATE))
    }
    pub fn absorb(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }
    pub fn finalize(self, out: &mut [u8]) {
        self.0.finalize_xof(0x1F, out);
    }
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

fn fixed(rate: usize, suffix: u8, data: &[u8], out: &mut [u8]) {
    let mut s = Sponge::new(rate);
    s.absorb(data);
    s.finalize_xof(suffix, out);
}

/// One-shot SHA3-256.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    fixed(SHA3_256_RATE, 0x06, data, &mut out);
    out
}

/// One-shot SHA3-512.
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    fixed(SHA3_512_RATE, 0x06, data, &mut out);
    out
}

/// One-shot SHAKE128.
pub fn shake128(data: &[u8], out: &mut [u8]) {
    fixed(SHAKE128_RATE, 0x1F, data, out);
}

/// One-shot SHAKE256.
pub fn shake256(data: &[u8], out: &mut [u8]) {
    fixed(SHAKE256_RATE, 0x1F, data, out);
}

#[cfg(test)]
mod oracle_tests {
    use super::*;

    /// Deterministic filler matching the oracle script: (i*37+11) % 256.
    fn fill(buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((i * 37 + 11) % 256) as u8;
        }
    }

    fn hex_of(bytes: &[u8]) -> [u8; 256] {
        const D: &[u8; 16] = b"0123456789abcdef";
        let mut s = [0u8; 256];
        for (i, &v) in bytes.iter().enumerate() {
            s[2 * i] = D[(v >> 4) as usize];
            s[2 * i + 1] = D[(v & 15) as usize];
        }
        s
    }

    fn check_hex(got: &[u8], want: &[u8]) {
        let h = hex_of(got);
        assert_eq!(&h[..want.len()], want);
    }

    #[test]
    fn sha3_256_oracle() {
        assert_eq!(
            &hex_of(&sha3_256(b""))[..64],
            b"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            &hex_of(&sha3_256(b"abc"))[..64],
            b"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        let mut p = [0u8; 1000];
        fill(&mut p);
        // Rate-boundary lengths (rate = 136) plus a long message.
        assert_eq!(
            &hex_of(&sha3_256(&p[..135]))[..64],
            b"3aa81a5b233ce753b2ab56b3c922338134eb11b8dc3d877d0bc8d19751684b76"
        );
        assert_eq!(
            &hex_of(&sha3_256(&p[..136]))[..64],
            b"9f065722983c1b643b3fabbed6e791f6d74f77e6cf5a2d38c07c124465ed5d9f"
        );
        assert_eq!(
            &hex_of(&sha3_256(&p[..137]))[..64],
            b"30efe517346c818828634cb8a3eb3538c14bc2f280132cf0261ed18a7dd85a8b"
        );
        assert_eq!(
            &hex_of(&sha3_256(&p))[..64],
            b"eb1fd0b44c01e5ed7d60ce15b72cc66ba960c5dde7aacdb269d3876107bdc801"
        );
    }

    #[test]
    fn sha3_512_oracle() {
        assert_eq!(
            &hex_of(&sha3_512(b""))[..128],
            b"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        let mut p = [0u8; 1000];
        fill(&mut p);
        assert_eq!(
            &hex_of(&sha3_512(&p))[..128],
            b"dad8ba327d2c53217e464613aa005388edc4fb8547f02395a36a6d318de3899f1eee5bf35067ff91ef94ac62990133a48fd9e78bd13a6ef9374811facf559e15"
        );
    }

    #[test]
    fn shake128_oracle() {
        let mut out = [0u8; 100];
        shake128(b"", &mut out[..32]);
        check_hex(
            &out[..32],
            b"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        );
        shake128(b"abc", &mut out);
        check_hex(
            &out,
            b"5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca5783789a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232a0294c85",
        );
        let mut p = [0u8; 1000];
        fill(&mut p);
        shake128(&p[..135], &mut out[..32]);
        check_hex(
            &out[..32],
            b"ad5ac71763cdcc32984e9d0b81f9bb2e5688dd8697109aa880c0a1144b50e67d",
        );
        shake128(&p[..136], &mut out[..32]);
        check_hex(
            &out[..32],
            b"c5c2d088bd2e20dda99724f9d95fe709958509b3ec69f2499a7a4aa92cb2a5d1",
        );
        shake128(&p[..137], &mut out[..32]);
        check_hex(
            &out[..32],
            b"1f5238c5edb360693fcd7dc98d3bf3b52a87fa15d385ed83a4e6e2cfbb50e9e5",
        );
        shake128(&p, &mut out[..64]);
        check_hex(
            &out[..64],
            b"0d21ac7b98ba41a07445782bff51a3d107de873ea5c4fec18410a19e516e69646ecf4d5204f3d2e6dea9a60448cde4ecb860780eec91bec3f08a63d26f9812d3",
        );
    }

    #[test]
    fn shake256_oracle() {
        let mut out = [0u8; 64];
        shake256(b"abc", &mut out);
        check_hex(
            &out,
            b"483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
        );
        let mut p = [0u8; 1000];
        fill(&mut p);
        shake256(&p, &mut out[..32]);
        check_hex(
            &out[..32],
            b"bf3b55688a8df1079ecdf5769e96579dc56f0ec2c956bdf5de963bfa4a223be5",
        );
    }

    #[test]
    fn squeeze_x4_matches_oneshot() {
        // Batched squeeze must equal four independent one-shots at every
        // length, including odd lengths across rate-block boundaries and
        // lanes of different lengths (over-squeeze must be harmless).
        let mut p = [0u8; 1024];
        fill(&mut p);
        for &len in &[0usize, 1, 7, 100, 167, 168, 169, 336, 500, 840] {
            let msgs: [&[u8]; 4] = [&p[..len], &p[..len + 1], &p[..len + 2], &p[..1]];
            // Vary per-lane output length.
            let mut o = [[0u8; 840]; 4];
            let lens = [len.min(840), 500, 840, 1];
            let [o0, o1, o2, o3] = &mut o;
            shake128_squeeze_x4(
                msgs,
                [
                    &mut o0[..lens[0]],
                    &mut o1[..lens[1]],
                    &mut o2[..lens[2]],
                    &mut o3[..lens[3]],
                ],
            );
            for k in 0..4 {
                let mut refb = [0u8; 840];
                shake128(msgs[k], &mut refb[..lens[k]]);
                assert_eq!(
                    &o[k][..lens[k]],
                    &refb[..lens[k]],
                    "lane {} len {:?}",
                    k,
                    lens
                );
            }
        }
    }

    #[test]
    fn squeeze256_x4_matches_oneshot() {
        // Same contract as the SHAKE128 batch, other rate: lanes of
        // different lengths, incl. sub-block and multi-block outputs.
        let mut p = [0u8; 300];
        fill(&mut p);
        let msgs: [&[u8]; 4] = [&p[..33], &p[..34], &p[..100], &p[..3]];
        let lens = [128, 200, 1, 0];
        let mut o = [[0u8; 200]; 4];
        let [o0, o1, o2, o3] = &mut o;
        shake256_squeeze_x4(
            msgs,
            [
                &mut o0[..lens[0]],
                &mut o1[..lens[1]],
                &mut o2[..lens[2]],
                &mut o3[..lens[3]],
            ],
        );
        for k in 0..4 {
            let mut refb = [0u8; 200];
            shake256(msgs[k], &mut refb[..lens[k]]);
            assert_eq!(&o[k][..lens[k]], &refb[..lens[k]], "sha256 lane {}", k);
        }
    }

    /// Random-state differential shared by the 2-way tiers.
    #[cfg(any(
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            target_feature = "sse2",
            not(all(target_arch = "x86_64", target_feature = "avx2"))
        ),
        all(target_arch = "aarch64", target_feature = "neon")
    ))]
    fn keccak_x2_check(run_twice: fn(&mut [[u64; 25]; 2])) {
        let mut states = [[0u64; 25]; 2];
        for (k, s) in states.iter_mut().enumerate() {
            for (w, v) in s.iter_mut().enumerate() {
                *v = ((k * 7919 + w * 104729 + 13) as u64).wrapping_mul(0x9E3779B97F4A7C15);
            }
        }
        let mut ref2 = states;
        for s in ref2.iter_mut() {
            keccak_f(s);
            keccak_f(s);
        }
        run_twice(&mut states);
        run_twice(&mut states);
        assert_eq!(states, ref2);
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2",
        not(all(target_arch = "x86_64", target_feature = "avx2"))
    ))]
    #[test]
    fn keccak_x2_sse2_matches_scalar() {
        keccak_x2_check(chaos_simd::keccak_f_x2);
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[test]
    fn keccak_x2_neon_matches_scalar() {
        keccak_x2_check(|s| chaos_simd::keccak_f_x2_neon(s));
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    #[test]
    fn keccak_x4_matches_scalar() {
        // AVX2 kernel must equal four scalar permutations, twice in a row
        // (catches state-carry/transpose bugs, not just one-shot output).
        let mut states = [[0u64; 25]; 4];
        for (k, s) in states.iter_mut().enumerate() {
            for (w, v) in s.iter_mut().enumerate() {
                *v = ((k * 7919 + w * 104729 + 13) as u64).wrapping_mul(0x9E3779B97F4A7C15);
            }
        }
        let mut ref4 = states;
        for s in ref4.iter_mut() {
            keccak_f(s);
            keccak_f(s);
        }
        keccak_f_4(&mut states);
        keccak_f_4(&mut states);
        assert_eq!(states, ref4);
    }

    #[test]
    fn incremental_matches_oneshot() {
        // Byte-at-a-time and odd splits must equal one-shot absorbs.
        let mut p = [0u8; 1000];
        fill(&mut p);
        for &len in &[0usize, 1, 135, 136, 137, 167, 168, 169, 500, 1000] {
            let msg = &p[..len];
            let mut ref64 = [0u8; 64];
            shake128(msg, &mut ref64);
            let mut s = Shake128::new();
            for chunk in msg.chunks(1) {
                s.absorb(chunk);
            }
            let mut o1 = [0u8; 64];
            s.finalize(&mut o1);
            assert_eq!(o1, ref64, "byte-split len {}", len);
            let mut s2 = Shake256::new();
            let mut pos = 0;
            let mut step = 1;
            while pos < len {
                let take = step.min(len - pos);
                s2.absorb(&msg[pos..pos + take]);
                pos += take;
                step = step.wrapping_mul(3) % 997 + 1;
            }
            let mut o2 = [0u8; 48];
            s2.finalize(&mut o2);
            let mut ref48 = [0u8; 48];
            shake256(msg, &mut ref48);
            assert_eq!(o2, ref48, "odd-split len {}", len);
        }
    }

    #[test]
    fn streamer_matches_oneshot() {
        // Streaming squeeze must equal one-shot output at every length,
        // including odd chunkings across rate-block boundaries.
        let mut p = [0u8; 600];
        fill(&mut p);
        for &len in &[0usize, 1, 100, 167, 168, 169, 336, 500] {
            let mut refb = [0u8; 500];
            shake128(&p[..len], &mut refb);
            for &step in &[1usize, 3, 100, 167, 168, 169, 500] {
                let mut s = Shake128::new();
                s.absorb(&p[..len]);
                let mut sq = s.streamer();
                let mut o = [0u8; 500];
                let mut pos = 0;
                while pos < 500 {
                    let take = step.min(500 - pos);
                    sq.squeeze(&mut o[pos..pos + take]);
                    pos += take;
                }
                assert_eq!(o, refb, "stream step {} len {}", step, len);
            }
        }
    }
}
