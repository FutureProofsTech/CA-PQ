# Changelog

All notable changes to CA-PQ are documented here. Dates are release dates.

## [Unreleased]
- 2-way Keccak tiers (SSE2 `keccak_f_x2`, NEON `keccak_f_x2_neon`):
  joint-XOF batching on all targets; SSE2 pq encaps +8%, keygen +10%.
- NEON NTT family (QEMU-validated via full m512 KAT). SSE2 NTT evaluated
  and rejected (no 32-bit multiply; emulation ≈ parity with scalar).

## [2.0.0] — 2026-09-27

### BREAKING (security fix)
- AEAD stream domain `ca-pq-dem-v1` (`ss || nonce[..24]` zero-padded)
  replaced by length-framed `ca-pq-dem-stream-v2`: v1 mapped distinct
  nonces (`>24 B`, or zero-padded prefixes) to identical keystreams.
  Old ciphertexts do not decrypt under v2. MAC domain unchanged.
- 4-way batched SHAKE128 squeeze + AVX2 Keccak-f kernel (`chaos-simd`
  `keccak_f_x4`, third audited `unsafe`); ML-KEM matrix sampling 4+4+1
  batched under AVX2 — pq encaps/decaps +27–39%, keygen +17%, matrices
  proven bit-identical by the reference KATs. Portable path unchanged.
- `ca-pq bench` gains a `shake128 64KiB` line (~265 MiB/s portable).
- 4-way SHAKE256 PRF batching for CBD coins (AVX2 only): pq encaps/decaps
  +11–12% on top of v11 (+41–55% cumulative vs portable). All Keccak uses
  in `chaos-mlkem` are now joint-4-way under AVX2; portable paths unchanged.
- AVX2 NTT family (forward/inverse/pointwise/add) with split-range 32-bit
  Barrett; portable branchless field mod. AVX2 pq encaps +12%, decaps
  +19–30%, pair +17% on top of v12; portable pq +10–19%.
- Division-free RK4 (`/6` → exact multiply-shift): keystream +7%,
  kem/hybrid +8–14% portable.
- `chaos-mlkem::encaps_batch`: amortized same-recipient bursts (+18%
  portable, +26% AVX2 per-element at batch8), bit-identical to scalar.
- ML-KEM-512 profile (`chaos-mlkem::m512`, NIST level 1, 800/1632/768 B)
  from a generic K/ETA core; 768 API unchanged. Independent-transcription
  KATs for both; portable encaps ~22.4k/s, AVX2 ~25.4k/s.
- Level-1 hybrid combiner (`chaos-hybrid::h512`, sysid `PQH1`, pk 900 /
  ct 828 B) with `ca-pq-h512-*` domains; independent-reference KATs;
  pair ~2700/s (+16% over flagship).
- 4-wide BLAKE3 tiers: SSE2 (`compress4_sse2`, baseline x86, ~1480 MiB/s,
  +85% over scalar) and NEON (`compress4_neon`, validated under QEMU
  user-mode with a freestanding hash-level harness, ALL PASS). Hasher
  groups narrow to 4 chunks on those tiers; AVX2/scalar paths untouched.

## [1.0.0] — 2026-09-27

Initial release. Zero third-party dependencies; GPL-3.0-or-later.

### Cryptography
- `chaos-hash`: hand-written BLAKE3 (plain/keyed/XOF/derive-key) and
  Keccak sponge (SHA3-256/512, SHAKE128/256, streaming squeeze).
- `chaos-kem`: hybrid X25519 (hand-written, RFC 7748) + chaotic-stream KEM,
  sysid `PQ04`. X ct 60 B, pk 68 B.
- `chaos-mlkem`: ML-KEM-768 shape from zero (plain modular arithmetic).
- `chaos-hybrid`: flagship combiner (sysid `PQH2`), secure if either KEM leg
  holds. pk 1284 B, sk 2464 B (32 B seed-packed), ct 1148 B.
- `chaos-aead`: thin DEM with heapless `seal_into`/`open_into` API.
- `chaos-core`: deterministic Q32.32 fixed-point 4D chaotic flow
  (Lorenz-28 regime, `N_TRANSIENT = 1000`), health monitor, volatile wipe.

### Validation
- Official BLAKE3/SHA3/SHAKE vectors, independent big-int references for
  X25519 and ML-KEM, full-stack hybrid goldens from an independent Python
  reference, NIST SP 800-22-style suite gate (8/8 seeds, 7 tests).
- Measured largest Lyapunov exponent ~0.6-0.9 (Benettin, float twin).

### Known limitations (see THREAT.md)
- No external audit. No interop claims on hand-written primitives.
- Not constant-time beyond branchless swaps and tag comparison.
- PQ cover rests on the ML-KEM leg only; X25519/chaos layers are classical.
