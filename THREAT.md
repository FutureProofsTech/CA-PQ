# CA-PQ THREAT MODEL

## Trust assumptions (open-design principle: the attacker knows the system, only keys are secret)

- Attacker knows: all equations, integrator, filter, quantization, source code.
- Attacker sees: `pk` (commit, sysid, x25519 pk) and any number of `ct`
  (nonce, ephemeral x25519 pk, MAC tag). No chaotic values ever appear on the wire.
- Attacker capabilities: classical compute, network MitM, ct tampering, wrong-key
  decaps oracles (rate-limited by operator). Quantum attacker is IN SCOPE for
  the `chaos-mlkem` path only (lattice-based, reference-verified, unaudited);
  the X25519/chaos layers stay classical with no PQ claim.

## What we claim

- KEM IND-CCA-ish hygiene: ss bound to full transcript; ct tampering and
  wrong-recipient decaps fail closed (tested). Contributory checks on both sides.
- DEM: ciphertext integrity via constant-time MAC verify; nonce-misuse degrades to
  stream-XOR properties (documented, not resistant).
- Secrets zeroized on drop (`chaos-kem::SecretKey`, hybrid `HSecretKey`;
  ML-KEM dk arrays need caller `burn_dk` — plain arrays cannot self-wipe);
  `forbid(unsafe_code)`; no floats in key path;
  deterministic cross-platform fixed-point core.

## What we explicitly DO NOT claim

1. No chaos-based asymmetry. Proven by `chaos-attack`: the observer slave converges to
   the receiver slave (receiver-vs-observer err ≤ [0,0,0,2] int units), and raw drive
   at sync-relevant sampling is slow and predictable (lag-1 r ≈ 0.97 at stride 4) —
   directly observable macro-trajectory. Drive must never be published.
2. No NP-hardness, no hidden-subgroup-attack immunity, no 2^512 float state space. Seeds are 256-bit;
   target ≈ 128-bit classical security.
3. No ML-reconstruction resistance proof. Masking whitens bytes (measured |r|<0.1)
   but no formal statement is made.
4. Hand-written crypto is reviewed by tests + vectors only: BLAKE3 pinned to the
   official empty vector + split-invariance + multi-block XOF reference (a
   first-8-words-only XOF shortcut was caught and fixed during hybrid
   cross-validation); X25519 pinned to independent big-int reference outputs;
   ML-KEM pinned to full-KAT agreement with an independent FIPS-203
   transcription (no official-vector check — no interop claim); the flagship
   combiner pinned by two full-stack independent goldens. Fuzzed on this
   machine (libFuzzer+ASan, 4 differential targets, ~25M execs, zero crashes;
   corpus seeds committed under `fuzz/corpus`). All need external
   audit before any use. The tree has zero dependencies and exactly two
   audited `unsafe` confined to volatile wipe + vector kernels (AVX2 BLAKE3/Keccak/NTT; SSE2/NEON BLAKE3/Keccak tiers; NEON NTT; all NEON validated under QEMU). SSE2 NTT evaluated and rejected: without 32-bit multiply the emulation costs more than it saves (scalar stands).
5. Keystream randomness is validated three independent ways: the in-tree
   NIST-style gate (`chaos-stat`, 8/8 seeds), an independent `ent` run over
   2×32 MiB (entropy 7.99999, chi-square p ≈ 31–36%, Pi error ≤ 0.01%,
   serial correlation ≈ −0.0002), and the no-lock soak. None of these is a
   substitute for audit or a full TestU01/DIEHARDER campaign.

## Red-team gates (must keep passing)

- `raw_drive_is_slow_predictable_signal`: drive must stay structured (r > 0.5) —
  justifies never publishing drive. If it decorrelates, re-examine masking claims.
- `observer_matches_receiver_slave_state`: the observer must match the receiver (err ≤ 4) — justifies X25519
  root. If the observer ever fails while the receiver succeeds, re-open sync-based design.
- `extracted_bytes_are_decorrelated`: bytes must stay white (|r| < 0.1) —
  guards the stream layer. Failure means extractor is broken.

## Red-team audit v18 (2026-09-27, machine-assisted self-audit)

Method: subgroup-confinement proofs, all-FF adversarial sweep over every
public KEM/AEAD API (dev + release), full unwrap/assert/index inventory of
lib code, domain-string enumeration with call-site analysis, decaps timing
smoke, burn/Debug review. Findings below; each CLOSED item has a test.

CLOSED (fixed + tested):
- R1 AEAD keystream nonce truncation (HIGH): `stream()` hashed only
  `nonce[..24]` zero-padded — longer nonces collided with their prefix and
  `"abc"` collided with `"abc\\0"`: silent catastrophic stream reuse.
  Fixed with length-framed keyed XOF (`ca-pq-dem-stream-v2`); v1 streams
  incompatible by design (CHANGELOG). Regression tests pin separation.
  MAC path (`ca-pq-dem-v1`, full nonce) was never affected; unchanged.
- R2 small-subgroup confinement (MEDIUM, now proven closed): all DH scalars
  are clamped (multiple of 8, pinned by RFC goldens), so DH with any point
  of order dividing 8 is exactly zero, caught by the `is_zero` gate on BOTH
  encaps and decaps. Tests: zero peer point fails closed kem-encaps,
  kem-decaps, hybrid-768 and hybrid-512 decaps; 0xFF point panics nowhere.
  (A constructive order-8 vector was attempted via cofactor clearing but
  dropped: the basepoint has order q, not 8q, so `q*G = 0` trivially — the
  mechanism proof above does not need any specific point.)
- R3 NTT decode-range entry (LOW): `ntt` assumed `[0, q)` but
  `byte_decode<12>` yields `[0, 4096)`; adversarial dk values tripped dev
  asserts (release: FO rejection still held). Scalar + AVX2 entries now
  cond-sub to `[0, q)`; decode-range differential pins kernel == scalar;
  all-FF sweep passes dev and release on both profiles.
- R4 assert inventory (LOW): the only release asserts in lib code are
  internal-contract checks (CBD/PRF eta + lengths, batch slice agreement)
  and the sample_ntt 64-block refill cap. The cap is grinding-infeasible
  (~50-sigma per entry; finding one needs ~2^1000 trials) — fail-stop
  panic is the honest response, not silent fallback. No attacker-reachable
  panic or OOB index found (all indexing bounded by type or asserted
  length; `fe_decode`/`fe_encode_full` bounds traced exactly).
- R5 decaps timing (INFO): ML-KEM valid:tampered = 1:0.90–0.96 (same work,
  residual is div/branch data variance — no early exit; FO re-encrypt is
  unconditional). KEM bad-tag = 0.58x (explicit reject skips the chaos
  tail; the return value already reveals failure, so timing adds no
  oracle). No gate (shared-runner flakiness); numbers recorded here.

ACCEPTED RESIDUALS (documented, not fixed):
- A1 bit-level timing: u32/i64 divisions (`compress`), bit-test branches
  (CBD/codec), variable shifts (`message_poly`) depend on secret-adjacent
  values. Same stance as all unmasked implementations; masking is out of
  scope. No secret-dependent early exits or length leaks exist (verified).
- A2 ML-KEM dk is a plain array: no Drop wipe, Debug-printable. Callers
  must `burn_dk`; in-tree flows do (hybrid Drop, decaps locals).
- A3 deterministic API: caller RNG failures (zero/reused seeds) produce
  weak but functional keys. Caller's responsibility (documented in API).
- A4 KEM explicit reject (None) vs ML-KEM implicit reject coexist per leg;
  hybrid handles both (tested). No cross-leg oracle (outputs independent).

## Red-team finding R6 — capture windows (INFO, understood, sensor-pinned)

Independent re-analysis of the transient margin (transient2.py, second
implementation) confirms the documented claim and finds a nuance:
- Independent (random) seed pairs: keystream Hamming 0.500 flat from T=50
  to T=4000 (min 0.48, 12 pairs x 7 lengths). The "~0.47 at 250" claim
  holds conservatively. N_TRANSIENT=1000 stands with large margin.
- 1-bit neighbors (shared params): healthy Hamming is 0.34-0.43 over the
  production window (same-attractor partial correlation — expected, and
  the reason the documented metric uses independent pairs).
- Rare materials capture late: a constructed patterned case (t=4) and
  ~0.15-13% of random x-neighbors (position-dependent: byte-0 flips
  capture, byte-5 flips never did in 1000 trials) converge bit-exactly by
  step ~2000-8000, settling near a classical Lorenz fixed point (x ~ -8.5).
  Health passes these (chaos through the probe window); production tails
  (steps 1000-1640) are affected only for the earliest capturers.
- Disposition (why INFO, not VULN): (a) related materials are unreachable
  (mats are XOF outputs; crafting related pairs breaks the XOF);
  (b) tails are unobservable (hashes only, never published);
  (c) worst case reduces to the X25519/PQ roots per non-claim #1.
  Nothing in production reads chaos state past step 1640 (verified:
  tails max out at transient 1000 + 64x10). No code change warranted.
- Regression sensor (not a production gate — nothing calls health at
  runtime): `neighbor_tail_separation_sensor` pins production-window
  neighbor Hamming >= 0.20 on 7 fixed healthy seeds, with t=748 material
  as positive control (fires at ~0.03). Guards future dynamics work.

## Open risks / roadmap

- X25519/ML-KEM transcript binding reviewed by tests only; needs external audit.
- Known fixed-and-tested defects file: kem commitment burn-before-hash (roundtrips
  masked it; regression test pins distinct commits); BLAKE3 XOF first-half-only
  shortcut (32 B digests masked it; multi-block reference test pins full output);
  non-chaotic default params (14,43,-1,16) collapsing to fixed points — short-horizon
  tests (health, avalanche, small KATs) all passed while 100 KB streams locked to
  exact rational proportions. Fixed by moving to the Lorenz-28 regime, validated by
  measured positive Lyapunov exponent (~0.6–0.9), 200 KB no-lock soak incl. jitter
  corners, and the full NIST-style gate on long streams.
- Remaining: external audit (this v18 pass is self-audit, not a substitute);
  optimized (non-plain) field arithmetic; formal Kani proofs for sync bounds.
  (ML-KEM-512, hybrid-512, NIST-style suite, cross-arch CI, and no_std +
  heapless AEAD are done — see build logs.)
