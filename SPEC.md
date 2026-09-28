# CA-PQ SPEC v1 (frozen)

Changes to any parameter below require a version bump (`sysid`) and new KAT vectors.

## Core (`chaos-core`)

- Arithmetic: Q32.32 in `i64` (`FRAC=32`), `i128` intermediates, wrapping + clamp.
- System (per-unit-time derivatives, 4D quadratic chaotic flow):
  - `dx = a*(y-x) + w/4`
  - `dy = d*x + c*y - x*z`
  - `dz = x*y - b*z`
  - `dw = y/8 - w/4 - x/16`
- Default params (Q32.32): `a=10`, `b=8/3` (truncated `11453246122`), `c=-1`,
  `d=28` — classic chaotic Lorenz regime, ±~5% per-key jitter (corners soaked).
  Measured largest Lyapunov exponent ~0.6–0.9 (Benettin, float twin).
  Documented as chaotic, NOT hyperchaotic (single positive exponent).
- Integrator: fixed-step RK4, `DT = 0.001` (`DT_Q = 4294967`), `N_TRANSIENT = 1000`
  (seed-pair keystream Hamming saturates ~0.47 already at 250 steps, flat to
  4000; 1000 keeps 4x margin — see build log v6, re-confirmed at 0.500 flat
  from T=50 in build log v20). Known nuance: rare materials capture
  bit-exactly by step ~2000+ (periodic-window dynamics near x ~ -8.5);
  production tails (steps 1000..1640) plus unreachable related seeds plus
  unobservable outputs keep this INFO-level — see THREAT R6.
- Clamp bound: ±256.0 (`BOUND_Q`); normal attractor extent ≈ ±30.
- State expansion: 64 XOF bytes → `x0 ∈ [-10,10]` (bit-preserving map) + param jitter.
- Drive quant: `quantize16(x) = (x >> 20) & 0xFFFF` (internal/analysis only, never on wire).
- Resolution floor: sub-`0x100`-LSB state deltas may be absorbed by truncation short-term;
  byte-level seed sensitivity is the guaranteed property (see health/avalanche tests).
- Health gate: bounded && !fixed_point && diverging (0x100-LSB probe, 1024 steps).

## Hash (`chaos-hash`)

- `Hash256 { hash, xof, mac }` over **hand-written BLAKE3** (compression, chunk
  state, tree stack, plain/keyed/XOF/derive-key modes — all CA-PQ code, zero
  dependencies). Verified: official empty-input vector
  `af1349b9…f3262`, split-invariance across all chunk/stack boundaries
  (0–2049 B), XOF-prefix-equals-digest, keyed/domain separation tests.
- `shake` module: **hand-written Keccak-f\[1600\]** giving SHA3-256/512 and
  SHAKE128/256 (one-shot + incremental), groundwork for the ML-KEM roadmap.
  Verified against an independent oracle on rate-boundary lengths (135/136/137,
  167/168/169), multi-block squeezes (32/64/100 B), and incremental splits.
- Domain-separated contexts:
  `ca-pq-kdf-v1`, `ca-pq-pk-v1`, `ca-pq-tr-v1`, `ca-pq-sync-v1`, `ca-pq-dem-v1`,
  `ca-pq-sk-chaos-v1`, `ca-pq-sk-x-v1`, `ca-pq-eph-x-v1`, `ca-pq-chaos-v1`,
  `ca-pq-mac-v1`, `ca-pq-ct-v1`, `ca-pq-eph-v1` (reserved).
- `hash`/`xof` derive a per-context subkey (`derive_key`) then keyed mode;
  `mac` is keyed hashing over `ctx || 0x00 || msg`. Always 256-bit output.

## Extract (`chaos-extract`)

- `STRIDE = 10` steps/byte; byte = fold(`x0 ^ x1 ^ x3`) low-bit mixer.
- Measured: keystream byte lag-1 autocorr ≈ 0.0 at STRIDE=10 (gate: |r| < 0.1).

## KEM (`chaos-kem`, sysid `PQ04`; pk commit binds sysid)
- X25519 ECDH **hand-written from zero** (`x25519.rs`: 5×51-bit signed limbs,
  Montgomery ladder with branchless swaps, fixed addition-chain inversion).
  Verified: golden outputs of an independent big-int RFC 7748 transcription
  (DH commutativity pinned), field mul/add/sub vs big-int oracles, zero-point
  edge case. No curve crates.
- `keygen(seed32)`: chaos_seed=XOF(sk), x_secret=XOF(sk), x_pk=X25519(x_secret),
  commit=Hash(chaos_mat || x_pk).
- `encaps(pk, eph_seed32, nonce24) -> Option<(ct, ss32)>`:
  eph X25519 keypair from `eph_seed`; shared=DH; chaos_mat=XOF(shared||tr);
  trajectory → 64B tail; tag=MAC(Hash(shared), transcript);
  `ss=Hash(tail || shared || tr_hash)`. ct = nonce || x_eph_pk || tag (88 B).
- `decaps(sk, pk, ct) -> Option<ss32>`: recompute shared, constant-time tag verify,
  recompute tail + ss. Rejects: bad tag, non-contributory shared.
- Key sizes: sk 64 B (2×32), pk 68 B, ct 60 B (nonce 12 + eph 32 + tag 16), ss 32 B.

## PQ KEM (`chaos-mlkem`, ML-KEM-768/512 shapes)

- From-zero lattice KEM (FIPS 203 shape): n = 256, q = 3329, k = 3,
  eta1 = eta2 = 2, du = 10, dv = 4. Plain modular arithmetic throughout
  (reference clarity over Montgomery/Barrett speed); SHAKE/SHA3 from the
  in-tree Keccak code.
- NTT: iterative, twiddle table generated at compile time from the primitive
  root 17; pair moduli order verified by homomorphism checks. INTT mirrors
  with explicit inverse twiddles + single final ×3303 scale.
- Deliberate layout: matrix seed (rho, public) and noise seed (sigma, secret)
  split from `SHA3-512(d)`; K-PKE keygen takes both. No interop claim.
- `keygen(d32, z32) -> (ek, dk)`; `encaps(ek, m32) -> (ct, ss32)`;
  `decaps(dk, ct) -> ss32` with implicit rejection (constant-time select).
- Two profiles from one generic core (`Profile`: K, ETA1, wire sizes):
  ML-KEM-768 (NIST level 3, top-level API) and ML-KEM-512 (NIST level 1,
  `chaos-mlkem::m512`). NTT, sampling XOF, compression, and ETA2 shared.
  512 sizes: ek 800 / dk 1632 / ct 768 B (vs 1184 / 2400 / 1088 B).
  KAT goldens for both from independent FIPS-203 transcriptions.
- `encaps_batch(ek, ms, cts_out, ss_out)`: N scalar-equivalent encapsulations
  sharing one matrix sampling (server bursts; element `i` == `encaps(ek, ms[i])`).
- Key sizes: ek 1184 B, dk 2400 B, ct 1088 B, ss 32 B.

## Flagship hybrid (`chaos-hybrid`, sysid `PQH2`)

- Combiner: `ss = Hash(ss_x || ss_pq || tr_hash)` with joint transcript
  `commit || ct_x || ct_pq || nonce`. Secure if EITHER leg holds.
- `keygen(seed32)`: subseeds via B3 domains; X leg = `chaos-kem`, PQ leg =
  `chaos-mlkem`; commit over both public halves.
- `encaps(hpk, seed32, nonce24)`: ephemerals derived from seed; X leg
  fail-closed propagates `None`; PQ leg implicit rejection flows into ss.
- `decaps(hsk, hpk, hct)`: X-leg failure → `None`; PQ-leg tamper → different ss.
- Key sizes: pk 1284 B (68+1184+32), sk 2464 B (64+2400), ct 1148 B (60+1088), ss 32 B.
- Level-1 sibling (`chaos-hybrid::h512`, sysid `PQH1`): same combiner with
  the ML-KEM-512 leg (pk 900 / sk 1696 / ct 828 B) under `ca-pq-h512-*`
  hash domains. Two full-stack KATs byte-agree with an independent Python
  reference, same method as the flagship.
- Verified: two full-stack KATs byte-agree with an independent Python
  reference (big-int X25519 + manual BLAKE3 compress + pip keyed/XOF +
  FIPS-203 transcription); determinism, per-leg tamper behavior, combiner
  sensitivity (ss differs from either leg alone).
- Verified: full ek/ct/ss KATs from an independent big-int reference (2 seeds),
  NTT/CBD/compress goldens, 12 patterned roundtrips, tamper + wrong-key rejection.

## AEAD (`chaos-aead`)

- `seal(ss, nonce, msg)`: stream=XOF(ss||nonce), ct=XOR, tag=MAC(ss, nonce||ct).
- `open`: constant-time tag verify, then decrypt.

## KAT vectors (from `ca-pq kat`)

```text
kat_state_x=[-38685498686, -43613686480, 108975376730, 17517767218]
kat_drive8=[29908, 29714, 29524, 29338, 29156, 28980, 28808, 28642]
kat_keystream32=2813c01688e8e4251f6a7697572a9039a20d53611b1ffb91a0f1a5cbf757a2ef
kat_health_ok=true
kat_pk_commit=95b573644806a9bf53ca0906cd05294996959847404e820397d8693677d3a1ed
kat_x_eph_pk=de217777812c81b565070a700f2cab3db8c880f62890a3c096b8d3059b535c5a
kat_ss=a40896a5fa65b24e7041b905029a581bc2f5388eb4e5be76b2499c355d952d03
```

## Flagship hybrid KATs (from `ca-pq hybrid` + independent Python reference)

Seed set 1 — keygen `0xA0`, encaps `0xB0`, nonce `0xC0`:

```text
hybrid commit=cd7c456e3c1ea78b25951c2e49a379f35ef1eead3e84b5f115cb8e9eb19587ab
hybrid ss=cf19cd367eebd8d6b6c80de6875023a022e5b78dd299b470e9bac987582cac99
```

(ct is 1176 B; pinned byte-for-byte in `chaos-hybrid` KAT tests for both sets.)

Seed set 2 — keygen `0x11`, encaps `0x22`, nonce `0x33`:

```text
hybrid commit=5c2960c389f2dcf4f6f295e1bff493bccd0a36c2ae1a88e4b1b0f8feaa1ff19
hybrid ss=4abd3980eba72bbd154f3d8672a28b833ba21bb8dab433be6a03400a3952dfdab
```

## Reference performance (release, host — shared/virtualized runner, ±10% run variance)

| Op | Throughput | Per op |
|---|---|---|
| RK4 step (Q32.32) | ~29.0M steps/s | ~34 ns |
| Keystream (10 steps/B) | ~2.7 MB/s | ~370 ns/B |
| BLAKE3 1 MiB (portable) | ~800 MiB/s | — |
| BLAKE3 1 MiB (AVX2, `RUSTFLAGS="-C target-feature=+avx2"`) | ~2235 MiB/s | — |
| BLAKE3 1 MiB (SSE2 default x86 build, 4-wide groups) | ~1480 MiB/s | — |
| BLAKE3 (NEON tier) | validated under QEMU, no perf claim (emulation) | — |
| BLAKE3-keyed 64 B | ~11.7M ops/s | ~86 ns |
| kem keygen | ~21.5k ops/s | ~46 µs |
| kem encaps only | ~7513 ops/s | ~133 µs |
| kem decaps only | ~10.4k ops/s | ~96 µs |
| pq keygen | ~14.0k ops/s | ~71 µs |
| pq keygen (AVX2) | ~16.5k ops/s | ~61 µs |
| pq encaps only | ~13.1k ops/s | ~76 µs |
| pq encaps only (AVX2) | ~17.5k ops/s | ~57 µs |
| pq decaps only | ~14.0k ops/s | ~71 µs |
| pq decaps only (AVX2) | ~19.0k ops/s | ~53 µs |
| hybrid keygen | ~7.1k ops/s | ~141 µs |
| hybrid encaps+decaps pair | ~2421 pairs/s | ~413 µs |

Optimization history: X25519 delayed carry (~1.5× DH), SHAKE streaming
(~1.4× PQ encaps), transient 5000→1000 after saturation analysis, wire cuts
(nonce/tag/sysid). Combined hybrid pair: ~865 µs → ~457 µs (~1.9×).
See PLAN build logs v6–v7. Keccak-4x batching (v11): ML-KEM matrix sampling
through a joint 4-way XOF under AVX2 (portable path byte-identical,
reference KATs pin both) — pq encaps/decaps +27–39%, keygen +17% (v11);
plus 4-way SHAKE256 PRF batching (v12): pq encaps/decaps +11–12% on top,
cumulative +41–55% vs portable. Branchless field mod + AVX2 NTT family
(v13): portable pq +10–19%, AVX2 pq another +12–30% (cumulative encaps
+58%, decaps +100%, pair +54% vs pre-batch portable).

## Sizes

| Object | Bytes |
|---|---|
| X leg sk / pk / ct / ss (wire+memory) | 64 / 68 / 60 / 32 |
| X leg sk stored (seed-packed, re-derive on load) | 32 |
| PQ leg ek / dk / ct / ss (wire+memory) | 1184 / 2400 / 1088 / 32 |
| PQ leg dk stored (d, z pair, re-expand on load) | 64 |
| Hybrid pk / sk / ct / ss (wire+memory) | 1284 / 2464 / 1148 / 32 |
| Hybrid sk stored (single seed, re-derive on load) | 32 |
| `ca-pq` binary (release, strip+abort) | 536,224 |
| Tree: 15 files, 4,292 lines incl. tests, 0 external deps | — |

Wire-size rationale: 96-bit random nonces (GCM-standard uniqueness),
128-bit tags (GCM/Poly1305-standard forgery resistance), 4 B version tags
with domain-separated contexts. Commit stays 256-bit (conservative binding).
