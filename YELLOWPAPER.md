# CA-PQ Yellow Paper — Formal Specification

**Version 2.0.0 · Normative companion to code. Where this paper and code disagree, code governs and the paper is a bug — file it.**

Notation: `‖` is concatenation, bytes are little-endian unless stated, `H(c, ctx)` is keyed BLAKE3 (`DefaultHash::hash`), `XOF(data, ctx, n)` is keyed BLAKE3-XOF. All integers in key paths are exact (no floats anywhere). Test vectors live in-crate (`kat_*` tests) and in the independent Python transcriptions (`mlkem_ref.py`, `mlkem512_ref.py`, `hybrid_ref.py`, `hybrid512_ref.py` — kept outside the tree).

## 1. Conventions and sizes

- Security parameter: 256-bit seeds throughout; shared secrets 32 bytes.
- Wire integers: fixed sizes by type (no length prefixes on wire objects).
- sysids (4 bytes, bound into commits): X-KEM `PQ04`, hybrid-768 `PQH2`, hybrid-512 `PQH1`.

| Object | X-KEM | ML-KEM-768 | ML-KEM-512 | Hybrid-768 | Hybrid-512 |
|---|---|---|---|---|---|
| pk | 68 | 1 184 | 800 | 1 284 | 900 |
| sk | 64 (32 seed-packed) | 2 400 | 1 632 | 2 464 (32 seed-packed) | 1 696 (32 seed-packed) |
| ct | 60 = 12+32+16 | 1 088 | 768 | 1 148 | 828 |
| ss | 32 | 32 | 32 | 32 | 32 |

AEAD tag: 16 bytes. Nonce (KEM/hybrid): 12 bytes.

## 2. Chaotic engine (`chaos-core`, `chaos-extract`)

Fixed-point Q32.32 (`FRAC = 32`) in `i64`, `i128` intermediates. `DT_Q = 4294967` (round(0.001·2³²)), `N_TRANSIENT = 1000`, clamp bound `BOUND_Q = 256·2³²`, sampling `STRIDE = 10`, extractor scale `2^20`.

State `s = [x,y,z,w]`, params `p = [a,b,c,d]`, defaults `a=10, b=8/3, c=−1, d=28` (Lorenz-28 regime).

**Derivative.**
`dx = a·(y−x) + w/4`
`dy = d·x + c·y − x·z`
`dz = x·y − b·z`
`dw = y/8 − w/4 − x/16`
with `·` = `qmul(u,v) = (u·v) >> 32` (exact truncating) and `/n` the exact power-of-two shifts shown.

**RK4 step** (fixed `dt`): `k1 = f(s)`, `k2 = f(s + k1·dt/2)`, `k3 = f(s + k2·dt/2)`, `k4 = f(s + k3·dt)`, `s += qmul(div6(k1 + 2k2 + 2k3 + k4), dt)` where `div6` is bit-exact truncating `/6` (Granlund–Montgomery, range-checked `|v| < 2⁵⁰`). All advances clamped to ±BOUND_Q. `iterate(s, p, n)` applies `n` steps with `dt = DT_Q`.

**Expansion** (`expand_from_bytes`, 64 B → state + params): bytes `[0..32]` → `x0 ∈ [−10,10]` per coordinate via centered `u32`, Q-shift, `×10`, fractional mixing from bytes `[32..36]`/`[48..52]`; params = defaults jittered ±5% from bytes `[36..40]` (`delta = p·j/2560`, `j ∈ [−128,127]`). Bytes 16–31, 40–47, 52–63 are unused by the map (lossy, harmless — image space remains astronomical).

**Extraction**: `extract_byte(x)`: `u = x as u64`, `folded = (u ⊕ (u≫17) ⊕ (u≫29) ⊕ (u≫7)) & 0xFF`, `out = folded ⊕ rotl3((u≫11)&0xFF)·0x9E rotr2`. `keystream` emits `extract(x0) ⊕ extract(x1) ⊕ extract(x3)` every STRIDE steps (transient assumed discarded by caller).

**Health** (`health_check`, validation-only): 1000-step boundedness + movement (drift ≥ 2⁻⁸) + 1024-step 1-LSB divergence (≥ 8/128 low-word diffs).

## 3. Hashing (`chaos-hash`)

**BLAKE3**: standard IV, `MSG_PERMUTATION = [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8]`, 7-round compress, tree mode (`BLOCK_LEN = 64`, `CHUNK_LEN = 1024`, `MAX_DEPTH = 54`, chunk counter, `CHUNK_START/CHUNK_END/ROOT` flags). API: `Hasher::{new, new_keyed, update, finalize, finalize_xof}`, `blake3`, `blake3_keyed`, `derive_key`, `Hash256::{hash, xof, mac}` (default provider `B3`/`DefaultHash`).

**Keccak sponge** (FIPS 202): compile-time LFSR round constants, ρ/π/χ/ι reference layout, pad10*1, suffixes `0x06` (SHA3) / `0x1F` (SHAKE). Rates: SHA3-256/SHAKE256 136, SHA3-512 72, SHAKE128 168. API: `sha3_256/512`, `shake128/256` (one-shot + `Shake128/256` incremental + `Squeezer` streaming + 4-way batch squeezes).

**SIMD** (`chaos-simd`, compile-time dispatch, no runtime detection): BLAKE3 compress 8-way AVX2 / 4-way SSE2 / 4-way NEON; Keccak-f 4-way AVX2 / 2-way SSE2 / 2-way NEON; NTT 8-way AVX2 / 4-wide NEON (+ portable everywhere). Hasher groups narrow 8→4 chunks on SSE2/NEON tiers with identical tree semantics.

## 4. X25519 (`chaos-kem::x25519`)

Field GF(2²⁵⁵−19) in 5×51-bit signed `i64` limbs, `i128` products; full + light carry with 19-fold; schoolbook multiply; `fe_mul_small` for constants. Montgomery ladder (255 steps, branchless cswap), `A24 = 121665`, inversion `z^(2^255−21)` by fixed chain, full encode/decode with commit reduction. Scalar clamping (`&248`, `&127`, `|64`), point masking (`&0x7f`), all-zero contributory check.

## 5. X-KEM (`chaos-kem`, sysid `PQ04`)

- `keygen(seed32)`: `chaos_seed = XOF(seed, "ca-pq-sk-chaos-v1")`, `x_sec = XOF(seed, "ca-pq-sk-x-v1")`, `x_pk = scalarmult(x_sec, G)`, `mat = XOF(chaos_seed, "ca-pq-kdf-v1")`, `commit = H("PQ04" ‖ mat ‖ x_pk, "ca-pq-pk-v1")`.
- `encaps(pk, eph_seed32, nonce12)`: `eph_x = XOF(eph_seed, "ca-pq-eph-x-v1")`, `eph_pk`, `shared = DH(eph_x, pk.x_pk)` (None if zero), `tr = commit ‖ x_pk ‖ eph_pk ‖ nonce`, `tr_hash = H(tr, "ca-pq-tr-v1")`, `mac_key = H(shared, "ca-pq-mac-v1")`, `tag = MAC(mac_key, tr, "ca-pq-ct-v1")[..16]`, `tail = keystream(expand(XOF(shared ‖ tr_hash, "ca-pq-chaos-v1")), transient 1000, 64B)`, `ss = H(tail ‖ shared ‖ tr_hash, "ca-pq-sync-v1")`. ct = nonce ‖ eph_pk ‖ tag.
- `decaps(sk, pk, ct)`: recompute shared (None if zero), verify tag (abort → None), recompute tail + ss identically.

## 6. ML-KEM (`chaos-mlkem`)

Parameters: `n = 256`, `q = 3329`, `INV128 = 3303`; 768: `k = 3, eta1 = eta2 = 2`; 512: `k = 2, eta1 = 3, eta2 = 2`; both `du = 10, dv = 4`. Generic core over `Profile { K, ETA1, ETA2, EK_LEN, DK_LEN, CT_LEN }`.

**NTT**: 7 layers (`len` 128→2 fwd / 2→128 inv), twiddles `17^brv7(i)` (`brv7` = 7-bit reversal), `fwd_idx(len, g) = 256/(2·len) + g`, pair moduli `γ[p] = 17^(brv7(64+⌊p/2⌋) + 128·(p mod 2))`, single final ×3303 scale. Modular ops: branchless conditional add/sub on `[0,q)`, single-`%` mulmod; entry accepts `[0,4096)` (decode range) via one conditional subtract — scalar and vector paths agree bit-for-bit there.

**Codec**: LSB-first `byte_encode/decode`; `compress_d(x) = round(2^d/q·x) mod 2^d` / `decompress_d(y) = round(q/2^d·y)` (exact integer half-up); `cbd_eta` (eta = 2: 128 B, eta = 3: 192 B); `sample_ntt(seed, i, j)` = SHAKE128(`seed‖i‖j`) rejection sampling (3-byte parse, `d1 = b0+256·(b1 mod 16)`, `d2 = b1/16+16·b2`); `prf_eta` = SHAKE256(`s‖b`, 64·eta B).

**Flows** (FIPS-203 shape): `rho‖sigma = SHA3-512(d)`; matrix from rho, noise from sigma (counters `0..2k−1` eta1); `encaps`: coins `0..2k` eta1 + `e2` eta2, FO `K = H(m ‖ H(ek))`, `ss = SHAKE256(K ‖ H(ct))`; `decaps`: decrypt, re-encrypt, constant-time select vs `SHAKE256(z ‖ H(ct))` implicit rejection. `encaps_batch`: shared matrix, element `i` bit-identical to scalar encaps. Encode widths 12/10/4/1; `message_poly` maps bits to `(q+1)/2`.

## 7. Hybrid combiners (`chaos-hybrid`)

Both profiles: subseeds `H(seed, h-x / h-mlkem-d / h-mlkem-z)` (768: `ca-pq-h-*`, 512: `ca-pq-h512-*`); `commit = H(xpk.commit ‖ xpk.sysid ‖ x_pk ‖ pq_ek, h-pk)`; encaps derives `eph_x`, `m_pq` from seed, runs both legs, `tr = H(commit ‖ ct_x ‖ ct_pq ‖ nonce, h-tr)`, `ss = H(ss_x ‖ ss_pq ‖ tr, h-ss)`. Decaps: X failure → `None`; PQ tamper → unrelated `ss`. Fixed sizes per §1; sysids `PQH2`/`PQH1`.

## 8. AEAD (`chaos-aead`)

Stream: keyed XOF over length-framed nonce (`ca-pq-dem-stream-v2`: domain ‖ 0x00 ‖ le64(len) ‖ nonce — full nonce absorbed, no truncation). Tag: `MAC(ss, "ca-pq-dem-v1" ‖ 0x00 ‖ nonce ‖ ct)[..16]`, constant-time verify, verify-before-decrypt. v1 streams (`ss ‖ nonce[..24]` zero-padded) are incompatible by design (collided distinct nonces — see REDTEAM R1).

## 9. Domain registry

Each string is used for exactly one purpose (duplicates below are same-value-both-sides by construction):

- Key derivation/splitting: `ca-pq-sk-chaos-v1`, `ca-pq-sk-x-v1`, `ca-pq-kdf-v1`, `ca-pq-h-x`, `ca-pq-h-mlkem-d/z`, `ca-pq-h512-x/mlkem-d/mlkem-z`, `ca-pq-h-eph-x/m`, `ca-pq-h512-eph-x/m`
- Commits/transcripts/MACs: `ca-pq-pk-v1`, `ca-pq-tr-v1`, `ca-pq-mac-v1`, `ca-pq-ct-v1`, `ca-pq-sync-v1`, `ca-pq-chaos-v1`, `ca-pq-eph-x-v1`, `ca-pq-h-pk/tr/ss`, `ca-pq-h512-pk/tr/ss`
- DEM: `ca-pq-dem-stream-v2`, `ca-pq-dem-v1`
- ML-KEM internals use raw SHA3/SHAKE (FIPS-assigned roles, no custom domains)

## 10. KAT inventory

BLAKE3 official vectors + split/multi-block XOF tests (`chaos-hash`); SHA3/SHAKE oracle incl. rate boundaries; X25519 big-int goldens + field-layer goldens (`x25519::tests`); ML-KEM NTT/CBD/compress goldens + full `kat_a`/`kat_b` vs independent transcriptions (both profiles) + roundtrip/tamper/batch suites; hybrid `kat_hybrid_a/b` + `kat_h512_a/b` vs full-stack references; chaos `kat_state` + health/avalanche gates; AEAD roundtrip/tamper/framing tests; attack-suite gates (`chaos-attack`).

## 11. Conformance notes

Implementations must reproduce: exact fixed-point/RK4/div6 semantics (§2), NTT twiddle order and pair moduli (§6), FO domain flow, wire sizes (§1), and domain strings (§9). Deviating in constant-time hardening is allowed only where outputs are unaffected. No interoperation with other libraries is claimed; agreement is defined against the in-tree KATs and the independent Python transcriptions.
