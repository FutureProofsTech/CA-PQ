//! CA-PQ `chaos-hash`: `Hash256` trait over hand-written BLAKE3.
//!
//! Every byte below is CA-PQ code: compression function, chunk state, tree
//! stack, plain/keyed/XOF/derive-key modes — written here from the public
//! BLAKE3 specification. Zero third-party dependencies in the whole tree.
//! Pinned against the official empty-input vector plus split-invariance,
//! determinism, and domain-separation tests.

#![no_std]
#![forbid(unsafe_code)]

pub mod shake;

pub use shake::{
    sha3_256, sha3_512, shake128, shake128_squeeze_x4, shake256, shake256_squeeze_x4, Shake128,
    Shake256, Squeezer,
};

/// 256-bit hash/XOF/MAC contract. All protocol hashing goes through this.
pub trait Hash256 {
    fn hash(data: &[u8], ctx: &[u8]) -> [u8; 32];
    fn xof(data: &[u8], ctx: &[u8], out: &mut [u8]);
    fn mac(key: &[u8; 32], msg: &[u8], ctx: &[u8]) -> [u8; 32];
}

// ---------------------------------------------------------------------------
// BLAKE3 parameters (spec constants)
// ---------------------------------------------------------------------------

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
const KEY_LEN: usize = 32;
/// Depth of the tree stack; covers inputs far beyond any protocol message.
const MAX_DEPTH: usize = 54;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
#[allow(dead_code)] // Reserved domain flag; context derivation uses CONTEXT above.
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

// ---------------------------------------------------------------------------
// Compression function
// ---------------------------------------------------------------------------

#[inline]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &[u32; 16]) -> [u32; 16] {
    let mut p = [0u32; 16];
    for (i, pv) in p.iter_mut().enumerate() {
        *pv = m[MSG_PERMUTATION[i]];
    }
    p
}

fn compress(
    cv: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [0u32; 16];
    state[..8].copy_from_slice(&cv);
    state[8..12].copy_from_slice(&IV[..4]);
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = block_len;
    state[15] = flags;
    let mut m = block_words;
    for _ in 0..7 {
        round(&mut state, &m);
        m = permute(&m);
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    state
}

fn words_of(block: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut w = [0u32; 16];
    for (i, wv) in w.iter_mut().enumerate() {
        let o = 4 * i;
        *wv = u32::from_le_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
    }
    w
}

/// Eight-way block compression with per-lane (cv, counter, len, flags).
/// Portable version: eight scalar compressions. The AVX2 kernel behind
/// `#[cfg]` implements the identical mapping with 8-wide vectors; a
/// differential test pins them equal. Used for full 8-chunk input groups.
/// Absent on the 4-wide tiers (SSE2/NEON use `compress4` instead).
#[cfg(not(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2",
        not(all(target_arch = "x86_64", target_feature = "avx2"))
    ),
    all(target_arch = "aarch64", target_feature = "neon")
)))]
fn compress8(
    cvs: &[[u32; 8]; 8],
    blocks: &[[u32; 16]; 8],
    counters: &[u64; 8],
    lens: &[u32; 8],
    flags: &[u32; 8],
) -> [[u32; 16]; 8] {
    // Compile-time dispatch (no_std compatible: no runtime CPU detection).
    // Build with RUSTFLAGS="-C target-feature=+avx2" for the 8-wide kernel.
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        chaos_simd::compress8_avx2(cvs, blocks, counters, lens, flags)
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    {
        let mut out = [[0u32; 16]; 8];
        for (i, o) in out.iter_mut().enumerate() {
            *o = compress(cvs[i], blocks[i], counters[i], lens[i], flags[i]);
        }
        out
    }
}

// Tier predicates: AVX2 (x86-64 only, opt-in), SSE2 (any x86 with the
// baseline feature, unless AVX2 takes precedence), NEON (aarch64).
// compress_group (8-wide) serves AVX2 + the scalar fallback; the 4-wide
// path below serves SSE2/NEON. Each item has exactly one cfg: no dead code
// on any target.

/// Four-way block compression with per-lane (cv, counter, len, flags).
/// SSE2/NEON kernels behind `#[cfg]` implement the identical mapping with
/// 4-wide vectors; a differential test per tier pins equality. Used for
/// full 4-chunk input groups.
#[cfg(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2",
        not(all(target_arch = "x86_64", target_feature = "avx2"))
    ),
    all(target_arch = "aarch64", target_feature = "neon")
))]
fn compress4(
    cvs: &[[u32; 8]; 4],
    blocks: &[[u32; 16]; 4],
    counters: &[u64; 4],
    lens: &[u32; 4],
    flags: &[u32; 4],
) -> [[u32; 16]; 4] {
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2",
        not(all(target_arch = "x86_64", target_feature = "avx2"))
    ))]
    {
        chaos_simd::compress4_sse2(cvs, blocks, counters, lens, flags)
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    {
        chaos_simd::compress4_neon(cvs, blocks, counters, lens, flags)
    }
}

// ---------------------------------------------------------------------------
// Output, chunk state, tree hasher
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Output {
    input_cv: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        let s = compress(
            self.input_cv,
            self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        );
        let mut cv = [0u32; 8];
        cv.copy_from_slice(&s[..8]);
        cv
    }

    fn root_bytes(&self, out: &mut [u8]) {
        // Root output emits all SIXTEEN words (64 bytes) per counter block,
        // not just the first eight: the chaining value is words[..8], but
        // XOF extension continues through words[8..] before incrementing.
        let mut counter = self.counter;
        let mut pos = 0;
        while pos < out.len() {
            let words = compress(
                self.input_cv,
                self.block_words,
                counter,
                self.block_len,
                self.flags | ROOT,
            );
            counter += 1;
            for &w in words.iter() {
                if pos >= out.len() {
                    break;
                }
                let b = w.to_le_bytes();
                let n = (out.len() - pos).min(4);
                out[pos..pos + n].copy_from_slice(&b[..n]);
                pos += n;
            }
        }
    }
}

struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    buf: [u8; BLOCK_LEN],
    blocks_compressed: u8,
    buf_len: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            cv: key_words,
            chunk_counter,
            buf: [0u8; BLOCK_LEN],
            blocks_compressed: 0,
            buf_len: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        self.blocks_compressed as usize * BLOCK_LEN + self.buf_len as usize
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) -> &mut Self {
        while !input.is_empty() {
            if self.buf_len as usize == BLOCK_LEN {
                let block_words = words_of(&self.buf);
                let s = compress(
                    self.cv,
                    block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                );
                self.cv[..8].copy_from_slice(&s[..8]);
                self.blocks_compressed += 1;
                self.buf = [0u8; BLOCK_LEN];
                self.buf_len = 0;
            }
            let want = BLOCK_LEN - self.buf_len as usize;
            let take = want.min(input.len());
            self.buf[self.buf_len as usize..][..take].copy_from_slice(&input[..take]);
            self.buf_len += take as u8;
            input = &input[take..];
        }
        self
    }

    fn output(&self) -> Output {
        Output {
            input_cv: self.cv,
            block_words: words_of(&self.buf),
            counter: self.chunk_counter,
            block_len: self.buf_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(left: [u32; 8], right: [u32; 8], key_words: [u32; 8], flags: u32) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left);
    block_words[8..].copy_from_slice(&right);
    Output {
        input_cv: key_words,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: flags | PARENT,
    }
}

/// Incremental BLAKE3 hasher (allocation-free; drives plain, keyed, and XOF use).
pub struct Hasher {
    chunk_state: ChunkState,
    key_words: [u32; 8],
    cv_stack: [[u32; 8]; MAX_DEPTH],
    cv_stack_len: u8,
    flags: u32,
}

impl Hasher {
    fn new_internal(key_words: [u32; 8], flags: u32) -> Self {
        Self {
            chunk_state: ChunkState::new(key_words, 0, flags),
            key_words,
            cv_stack: [[0u32; 8]; MAX_DEPTH],
            cv_stack_len: 0,
            flags,
        }
    }

    /// Plain hash mode.
    pub fn new() -> Self {
        Self::new_internal(IV, 0)
    }

    /// Keyed hash / MAC mode.
    pub fn new_keyed(key: &[u8; KEY_LEN]) -> Self {
        let mut words = [0u32; 8];
        for (i, w) in words.iter_mut().enumerate() {
            let o = 4 * i;
            *w = u32::from_le_bytes([key[o], key[o + 1], key[o + 2], key[o + 3]]);
        }
        Self::new_internal(words, KEYED_HASH)
    }

    pub fn update(&mut self, mut input: &[u8]) -> &mut Self {
        // Finish any partial chunk the scalar way first.
        if self.chunk_state.len() > 0 && self.chunk_state.len() < CHUNK_LEN {
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
            if self.chunk_state.len() == CHUNK_LEN && !input.is_empty() {
                self.push_completed_chunk();
            }
        }
        // Fast path: whole groups straight from input (no END flags; the
        // trailing partial chunk keeps scalar semantics at finalize).
        // STRICTLY-greater-than: every grouped chunk must be followed by more
        // input, mirroring the scalar rule that a chunk is pushed only when
        // the next byte arrives. An exact-multiple tail stays scalar so the
        // final chunk keeps its END flag at finalize. Group width is 8 on
        // AVX2/scalar builds, 4 on SSE2/NEON tiers (same rule, narrower step).
        #[cfg(not(any(
            all(
                any(target_arch = "x86", target_arch = "x86_64"),
                target_feature = "sse2",
                not(all(target_arch = "x86_64", target_feature = "avx2"))
            ),
            all(target_arch = "aarch64", target_feature = "neon")
        )))]
        while input.len() > 8 * CHUNK_LEN && self.chunk_state.len() == 0 {
            self.compress_group(&input[..8 * CHUNK_LEN]);
            input = &input[8 * CHUNK_LEN..];
        }
        #[cfg(any(
            all(
                any(target_arch = "x86", target_arch = "x86_64"),
                target_feature = "sse2",
                not(all(target_arch = "x86_64", target_feature = "avx2"))
            ),
            all(target_arch = "aarch64", target_feature = "neon")
        ))]
        while input.len() > 4 * CHUNK_LEN && self.chunk_state.len() == 0 {
            self.compress_group4(&input[..4 * CHUNK_LEN]);
            input = &input[4 * CHUNK_LEN..];
        }
        // Scalar remainder (original logic, unchanged).
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                self.push_completed_chunk();
            }
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
        self
    }

    /// Push the chaining value of a completed chunk (scalar path).
    fn push_completed_chunk(&mut self) {
        debug_assert_eq!(self.chunk_state.len(), CHUNK_LEN);
        let chunk_cv = self.chunk_state.output().chaining_value();
        let total_chunks = self.chunk_state.chunk_counter + 1;
        self.push_cv(chunk_cv, total_chunks);
        self.chunk_state = ChunkState::new(self.key_words, total_chunks, self.flags);
    }

    /// Compress 8 full chunks (8192 bytes) via batched 8-way compression.
    /// Produces exactly the 8 chaining values sequential hashing would
    /// (same counters, same CHUNK_START on every lane's first block, no END),
    /// pushed in order with the same totals — downstream logic is untouched.
    /// Serves the AVX2 build and the scalar fallback (never the 4-wide tiers).
    #[cfg(not(any(
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            target_feature = "sse2",
            not(all(target_arch = "x86_64", target_feature = "avx2"))
        ),
        all(target_arch = "aarch64", target_feature = "neon")
    )))]
    fn compress_group(&mut self, g: &[u8]) {
        debug_assert_eq!(g.len(), 8 * CHUNK_LEN);
        debug_assert_eq!(self.chunk_state.len(), 0);
        let base = self.chunk_state.chunk_counter;
        let mut cvs = [self.key_words; 8];
        let mut blocks = [[0u32; 16]; 8];
        let mut counters = [0u64; 8];
        let mut flags = [self.flags; 8];
        for (i, c) in counters.iter_mut().enumerate() {
            *c = base + i as u64;
        }
        let mut blk = [0u8; BLOCK_LEN];
        for s in 0..16 {
            for i in 0..8 {
                blk.copy_from_slice(&g[i * CHUNK_LEN + s * BLOCK_LEN..][..BLOCK_LEN]);
                blocks[i] = words_of(&blk);
                // Mirror ChunkState exactly: START on the first block, END on
                // the real last block (15). A zero-block END round here would
                // silently fork the tree (caught by cross-validation).
                flags[i] = self.flags
                    | if s == 0 { CHUNK_START } else { 0 }
                    | if s == 15 { CHUNK_END } else { 0 };
            }
            let out = compress8(&cvs, &blocks, &counters, &[BLOCK_LEN as u32; 8], &flags);
            for (dst, src) in cvs.iter_mut().zip(out.iter()) {
                dst.copy_from_slice(&src[..8]);
            }
        }
        for (i, cv) in cvs.iter().enumerate() {
            self.push_cv(*cv, base + i as u64 + 1);
        }
        self.chunk_state = ChunkState::new(self.key_words, base + 8, self.flags);
    }

    /// Compress 4 full chunks (4096 bytes) via batched 4-way compression.
    /// Same contract as `compress_group`, one group narrower: same counters
    /// (base+i), same per-lane flags, CVs pushed in order with the same
    /// totals. Serves the SSE2/NEON tiers only.
    #[cfg(any(
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            target_feature = "sse2",
            not(all(target_arch = "x86_64", target_feature = "avx2"))
        ),
        all(target_arch = "aarch64", target_feature = "neon")
    ))]
    fn compress_group4(&mut self, g: &[u8]) {
        debug_assert_eq!(g.len(), 4 * CHUNK_LEN);
        debug_assert_eq!(self.chunk_state.len(), 0);
        let base = self.chunk_state.chunk_counter;
        let mut cvs = [self.key_words; 4];
        let mut blocks = [[0u32; 16]; 4];
        let mut counters = [0u64; 4];
        let mut flags = [self.flags; 4];
        for (i, c) in counters.iter_mut().enumerate() {
            *c = base + i as u64;
        }
        let mut blk = [0u8; BLOCK_LEN];
        for s in 0..16 {
            for i in 0..4 {
                blk.copy_from_slice(&g[i * CHUNK_LEN + s * BLOCK_LEN..][..BLOCK_LEN]);
                blocks[i] = words_of(&blk);
                // Same ChunkState mirror as the 8-wide path: START on the
                // first block, END on the real last block (15).
                flags[i] = self.flags
                    | if s == 0 { CHUNK_START } else { 0 }
                    | if s == 15 { CHUNK_END } else { 0 };
            }
            let out = compress4(&cvs, &blocks, &counters, &[BLOCK_LEN as u32; 4], &flags);
            for (dst, src) in cvs.iter_mut().zip(out.iter()) {
                dst.copy_from_slice(&src[..8]);
            }
        }
        for (i, cv) in cvs.iter().enumerate() {
            self.push_cv(*cv, base + i as u64 + 1);
        }
        self.chunk_state = ChunkState::new(self.key_words, base + 4, self.flags);
    }

    fn push_cv(&mut self, cv: [u32; 8], chunk_counter: u64) {
        // Push FIRST, then merge: the stack must represent all completed
        // chunks (including this one) as popcount(total) subtrees. Merging
        // before pushing pairs the wrong nodes (proven by the 2049-byte
        // official vector: right-leaning vs spec left-leaning tree).
        self.cv_stack[self.cv_stack_len as usize] = cv;
        self.cv_stack_len += 1;
        self.merge_cv_stack(chunk_counter);
    }

    fn merge_cv_stack(&mut self, total_len: u64) {
        // Binary-counter maintenance: each merge pops two, pushes one, so
        // the count drops by exactly one toward popcount(total). No increment
        // of the target (that would strand subtrees, e.g. total=4 stops at 2).
        let post_merge = total_len.count_ones() as usize;
        while self.cv_stack_len as usize > post_merge {
            let right = self.cv_stack[self.cv_stack_len as usize - 1];
            let left = self.cv_stack[self.cv_stack_len as usize - 2];
            let parent = parent_output(left, right, self.key_words, self.flags);
            self.cv_stack[self.cv_stack_len as usize - 2] = parent.chaining_value();
            self.cv_stack_len -= 1;
        }
    }

    fn final_output(&self) -> Output {
        let mut output = self.chunk_state.output();
        let mut remaining = self.cv_stack_len;
        while remaining > 0 {
            remaining -= 1;
            let left = self.cv_stack[remaining as usize];
            output = parent_output(left, output.chaining_value(), self.key_words, self.flags);
        }
        output
    }

    /// Fixed 32-byte digest.
    pub fn finalize(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.final_output().root_bytes(&mut out);
        out
    }

    /// Extendable output of any length.
    pub fn finalize_xof(&self, out: &mut [u8]) {
        self.final_output().root_bytes(out);
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// One-shot helpers
// ---------------------------------------------------------------------------

/// Plain BLAKE3 digest.
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize()
}

/// Keyed BLAKE3 digest (the MAC primitive).
pub fn blake3_keyed(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new_keyed(key);
    h.update(data);
    h.finalize()
}

/// Context-key derivation: binds a domain string into a fresh 32-byte key.
pub fn derive_key(context: &[u8], key_material: &[u8]) -> [u8; 32] {
    // Context block is a single block; longer contexts are digested first.
    let (ctx_block, ctx_len): ([u8; BLOCK_LEN], u32) = if context.len() <= BLOCK_LEN {
        let mut b = [0u8; BLOCK_LEN];
        b[..context.len()].copy_from_slice(context);
        (b, context.len() as u32)
    } else {
        let d = blake3(context);
        let mut b = [0u8; BLOCK_LEN];
        b[..32].copy_from_slice(&d);
        (b, 32)
    };
    let mut iv_out = [0u8; 32];
    Output {
        input_cv: IV,
        block_words: words_of(&ctx_block),
        counter: 0,
        block_len: ctx_len,
        flags: DERIVE_KEY_CONTEXT,
    }
    .root_bytes(&mut iv_out);
    blake3_keyed(&iv_out, key_material)
}

// ---------------------------------------------------------------------------
// Protocol backend: domain-separated hash / XOF / MAC over BLAKE3
// ---------------------------------------------------------------------------

/// From-zero BLAKE3 backend implementing the protocol contract.
pub struct B3;

impl Hash256 for B3 {
    fn hash(data: &[u8], ctx: &[u8]) -> [u8; 32] {
        let mut dk = derive_key(ctx, b"CA-PQ hash domain v1");
        let mut h = Hasher::new_keyed(&dk);
        chaos_core::burn(&mut dk);
        h.update(data);
        h.finalize()
    }

    fn xof(data: &[u8], ctx: &[u8], out: &mut [u8]) {
        let mut dk = derive_key(ctx, b"CA-PQ hash domain v1");
        let mut h = Hasher::new_keyed(&dk);
        chaos_core::burn(&mut dk);
        h.update(data);
        h.finalize_xof(out);
    }

    fn mac(key: &[u8; 32], msg: &[u8], ctx: &[u8]) -> [u8; 32] {
        // Keyed hashing IS the MAC: domain prefix keeps MAC/key-derivation
        // domains apart even if a key were ever reused across them.
        let mut h = Hasher::new_keyed(key);
        h.update(ctx);
        h.update(&[0u8]);
        h.update(msg);
        h.finalize()
    }
}

/// Default backend alias (single backend: everything is from zero).
pub type DefaultHash = B3;

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> [u8; 64] {
        const D: &[u8; 16] = b"0123456789abcdef";
        let mut s = [0u8; 64];
        for (i, &v) in b.iter().enumerate() {
            s[2 * i] = D[(v >> 4) as usize];
            s[2 * i + 1] = D[(v & 15) as usize];
        }
        s
    }

    /// Deterministic filler (no RNG in tests): byte i of a length-n message.
    fn fill(buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i.wrapping_mul(31).wrapping_add(i / 7)) as u8;
        }
    }

    #[test]
    fn official_empty_vector() {
        // Published BLAKE3 test vector for the empty input.
        assert_eq!(
            &hex(&blake3(b"")),
            b"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn split_invariance_across_chunk_boundaries() {
        // One-shot vs byte-at-a-time vs odd splits must agree at every tree
        // depth transition: exercises block, chunk, and stack-merge paths.
        let mut backing = [0u8; 2050];
        fill(&mut backing);
        for &len in &[
            0usize, 1, 2, 63, 64, 65, 127, 128, 1023, 1024, 1025, 1536, 2048, 2049,
        ] {
            let msg = &backing[..len];
            let reference = blake3(msg);
            // Byte-at-a-time.
            let mut h = Hasher::new();
            for chunk in msg.chunks(1) {
                h.update(chunk);
            }
            assert_eq!(h.finalize(), reference, "byte-split len {}", len);
            // Split exactly on the chunk boundary.
            let mut h2 = Hasher::new();
            let cut = 1024.min(len);
            h2.update(&msg[..cut]);
            h2.update(&msg[cut..]);
            assert_eq!(h2.finalize(), reference, "chunk-split len {}", len);
            // Odd splits.
            let mut h3 = Hasher::new();
            let mut pos = 0;
            let mut step = 1;
            while pos < len {
                let take = step.min(len - pos);
                h3.update(&msg[pos..pos + take]);
                pos += take;
                step = step.wrapping_mul(3) % 997 + 1;
            }
            assert_eq!(h3.finalize(), reference, "odd-split len {}", len);
            // Keyed + XOF consistency at the same lengths.
            let key = [0x5Au8; 32];
            let mut kh = Hasher::new_keyed(&key);
            kh.update(msg);
            let kd = kh.finalize();
            assert_ne!(kd, reference, "keyed must differ len {}", len);
            let mut xo = [0u8; 64];
            kh.finalize_xof(&mut xo);
            assert_eq!(&xo[..32], &kd, "xof prefix must equal digest len {}", len);
        }
    }

    #[test]
    fn keyed_and_derive_domains() {
        let d1 = blake3_keyed(&[1u8; 32], b"msg");
        assert_eq!(d1, blake3_keyed(&[1u8; 32], b"msg"));
        assert_ne!(d1, blake3_keyed(&[2u8; 32], b"msg"));
        assert_ne!(d1, blake3(b"msg"));
        let k1 = derive_key(b"ctx-a", b"material");
        assert_eq!(k1, derive_key(b"ctx-a", b"material"));
        assert_ne!(k1, derive_key(b"ctx-b", b"material"));
        assert_ne!(k1, derive_key(b"ctx-a", b"other"));
        // Long contexts (> 1 block) take the digest-first path.
        let long = [0x77u8; 200];
        assert_eq!(derive_key(&long, b"m"), derive_key(&long, b"m"));
        assert_ne!(derive_key(&long, b"m"), derive_key(b"short", b"m"));
    }

    #[test]
    fn backend_contract() {
        let h1 = B3::hash(b"ca-pq", b"ca-pq-kdf-v1");
        assert_eq!(h1, B3::hash(b"ca-pq", b"ca-pq-kdf-v1"));
        assert_ne!(B3::hash(b"ca-pq", b"other-ctx"), h1);
        let mut o1 = [0u8; 96];
        let mut o2 = [0u8; 96];
        B3::xof(b"ca-pq", b"ca-pq-kdf-v1", &mut o1);
        B3::xof(b"ca-pq", b"ca-pq-kdf-v1", &mut o2);
        assert_eq!(o1, o2);
        assert_eq!(&o1[..32], &h1[..], "xof must extend the digest");
        let t = B3::mac(&[3u8; 32], b"m", b"ca-pq-dem-v1");
        assert_ne!(t, [0u8; 32]);
        assert_ne!(t, B3::mac(&[4u8; 32], b"m", b"ca-pq-dem-v1"));
        assert_ne!(t, B3::mac(&[3u8; 32], b"m", b"other-ctx"));
    }

    #[test]
    fn xof_multiblock_matches_reference() {
        // Root output emits all 16 words (64 bytes) per counter block; the
        // second block is where a first-8-words-only shortcut would diverge.
        fn unhex<const N: usize>(s: &[u8]) -> [u8; N] {
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
        let h = Hasher::new();
        let mut o64 = [0u8; 64];
        h.finalize_xof(&mut o64);
        assert_eq!(
            o64,
            unhex::<64>(b"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a")
        );
        let mut h2 = Hasher::new();
        h2.update(b"abc");
        let mut o96 = [0u8; 96];
        h2.finalize_xof(&mut o96);
        assert_eq!(
            o96,
            unhex::<96>(b"6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d851fb250ae7393f5d02813b65d521a0d492d9ba09cf7ce7f4cffd900f23374bf0bc08a1fb0b38ed276181ccbd9f7b7edbddf9f86404ad7929605f6ffa3fb1ac879")
        );
    }

    #[test]
    fn multichunk_official_vectors() {
        // Tree path (chunk chaining with flags, CV stack, parent nodes) pinned
        // against the independent reference at every depth transition.
        // Filler matches the oracle script: byte i = (i*37+11) % 256.
        fn fill_vec(buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = ((i * 37 + 11) % 256) as u8;
            }
        }
        // (len, plain, keyed[key=0..32), xof64-prefix)
        let cases: [(usize, &str, &str); 7] = [
            (
                1023,
                "95ac8f9f553470c9e6664e72723b5a45433ed383a76e31595bba557b02702aaf",
                "065cab1af4f3a08dbd396b676019566efe152d927a6df2180cf44103844a60d1",
            ),
            (
                1024,
                "85ab4b9d3259bbd3b0c44b2b0d91a0038fcda6ad3b568864326a7641a5044bb3",
                "57ad16332b2b1962730a2bd81de76baaed8d068e6e739865ad547edd29cb2149",
            ),
            (
                1025,
                "2b18fbf7ea84a1e68f198a382ba88d59d707ab1fcd16e899cda8ad7d534a07b5",
                "8de0bfd90d796aed3f0a802d600389473df66a8104d696ac4f631d33baf30b44",
            ),
            (
                2048,
                "fc9f9319bc751c15f1c2f24731d3b658b84f5c70de3fbda268b1da49144eaec7",
                "ce784931227a88d4c4c0ef2b9859c34762d662c2c19d5678c9621d184b5070e3",
            ),
            (
                2049,
                "cb6ed3da4a280446bac8205765eb2b48c8df68773a3684e20217d2e9de02f330",
                "0d1de5f084b1ba3db40d7633e8d9d790ec9929e466ff167c06b0e5e03c0d43e9",
            ),
            (
                4096,
                "ffcad60cfaaae98d9f040e4300370180c3f68851125d297b5ddfac639caa3265",
                "70dc1fc84d0933f214382a88724b993ba8690bb264f5e04ada5bfc8101df2539",
            ),
            (
                100000,
                "21b6f071c36e06728af8f2055a399af0d65f1f01f80d84676071632806a8d66e",
                "c14b4f8d437013329791af896e74a1361927780f7db35c53e40aa3ad284b224f",
            ),
        ];
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut backing = [0u8; 100_000];
        fill_vec(&mut backing);
        for (len, want_plain, want_keyed) in cases {
            let msg = &backing[..len];
            assert_eq!(
                &hex(&blake3(msg))[..],
                want_plain.as_bytes(),
                "plain len {}",
                len
            );
            let mut h = Hasher::new_keyed(&key);
            h.update(msg);
            assert_eq!(
                &hex(&h.finalize())[..],
                want_keyed.as_bytes(),
                "keyed len {}",
                len
            );
        }
    }
}

#[cfg(test)]
mod simd_tests {
    // SSE2 differential, active on plain x86 builds (no AVX2 flag): the
    // 4-way kernel must equal four scalar compressions lane-for-lane.
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2",
        not(all(target_arch = "x86_64", target_feature = "avx2"))
    ))]
    #[test]
    fn sse2_matches_scalar() {
        use super::*;
        let mut rng = 0x12345678u32;
        let mut next = || {
            rng = rng.wrapping_mul(1103515245).wrapping_add(12345) >> 3;
            rng
        };
        for _ in 0..24 {
            let mut cvs = [[0u32; 8]; 4];
            let mut blocks = [[0u32; 16]; 4];
            let mut counters = [0u64; 4];
            let mut lens = [0u32; 4];
            let mut flags = [0u32; 4];
            for lane in 0..4 {
                for w in cvs[lane].iter_mut() {
                    *w = next();
                }
                for w in blocks[lane].iter_mut() {
                    *w = next();
                }
                counters[lane] = ((next() as u64) << 32) | next() as u64;
                lens[lane] = next() % 65;
                flags[lane] = next() & 0x7F;
            }
            let got = chaos_simd::compress4_sse2(&cvs, &blocks, &counters, &lens, &flags);
            for lane in 0..4 {
                let want = compress(
                    cvs[lane],
                    blocks[lane],
                    counters[lane],
                    lens[lane],
                    flags[lane],
                );
                assert_eq!(got[lane], want, "lane {}", lane);
            }
        }
    }

    // NEON differential, runs on aarch64 (validated under QEMU user-mode —
    // see PLAN): the 4-way kernel must equal four scalar compressions.
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[test]
    fn neon_matches_scalar() {
        use super::*;
        let mut rng = 0x12345678u32;
        let mut next = || {
            rng = rng.wrapping_mul(1103515245).wrapping_add(12345) >> 3;
            rng
        };
        for _ in 0..24 {
            let mut cvs = [[0u32; 8]; 4];
            let mut blocks = [[0u32; 16]; 4];
            let mut counters = [0u64; 4];
            let mut lens = [0u32; 4];
            let mut flags = [0u32; 4];
            for lane in 0..4 {
                for w in cvs[lane].iter_mut() {
                    *w = next();
                }
                for w in blocks[lane].iter_mut() {
                    *w = next();
                }
                counters[lane] = ((next() as u64) << 32) | next() as u64;
                lens[lane] = next() % 65;
                flags[lane] = next() & 0x7F;
            }
            let got = chaos_simd::compress4_neon(&cvs, &blocks, &counters, &lens, &flags);
            for lane in 0..4 {
                let want = compress(
                    cvs[lane],
                    blocks[lane],
                    counters[lane],
                    lens[lane],
                    flags[lane],
                );
                assert_eq!(got[lane], want, "lane {}", lane);
            }
        }
    }

    // Differential test, compiled only when the AVX2 kernel is active:
    // kernel output must equal eight scalar compressions lane-for-lane,
    // across counters/flags/lengths including multi-block XOF tails.
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    #[test]
    fn avx2_matches_scalar() {
        use super::*;
        let mut rng = 0x12345678u32;
        let mut next = || {
            rng = rng.wrapping_mul(1103515245).wrapping_add(12345) >> 3;
            rng
        };
        for _ in 0..24 {
            let mut cvs = [[0u32; 8]; 8];
            let mut blocks = [[0u32; 16]; 8];
            let mut counters = [0u64; 8];
            let mut lens = [0u32; 8];
            let mut flags = [0u32; 8];
            for lane in 0..8 {
                for w in cvs[lane].iter_mut() {
                    *w = next();
                }
                for w in blocks[lane].iter_mut() {
                    *w = next();
                }
                counters[lane] = ((next() as u64) << 32) | next() as u64;
                lens[lane] = next() % 65;
                flags[lane] = next() & 0x7F;
            }
            let got = chaos_simd::compress8_avx2(&cvs, &blocks, &counters, &lens, &flags);
            for lane in 0..8 {
                let want = compress(
                    cvs[lane],
                    blocks[lane],
                    counters[lane],
                    lens[lane],
                    flags[lane],
                );
                assert_eq!(got[lane], want, "lane {}", lane);
            }
        }
    }
}
