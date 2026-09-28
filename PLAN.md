# CA-PQ — Chaotic-Attractor Asymmetric Post-Quantum Framework
## Unified Plan v0 (single document)

**Codename:** CA-PQ | **Stack:** Rust 2024, platinum standard | **Mode:** full control from 0
**Goal:** ultra-small keys (bytes), hardware-native speed, PQ-hypothesis with honest validation.

---

## 1. Vision and non-goals

Build an asymmetric framework where the secret lives in the topology of a high-dimensional
chaotic attractor (4D chaotic dissipative-flow family), not in a lattice/code/isogeny.
Private key = 32-byte seed expanded to initial state `X0=(x0,y0,z0,w0)` + control params
`theta=(a,b,c,d...)`. Public drive `x(t)` synchronizes a drive-response subsystem
`(y,z,w)` only for the holder of `theta_priv`.

Non-goals for v0: custom block cipher, production HSM, IETF draft.
Zero third-party dependencies: hash (BLAKE3), curve (X25519), and wiping are
hand-written CA-PQ code. Thin DEM (stream XOR + keyed MAC).

## 2. Threat model (open-design-first: the attacker knows the system, only keys are secret)

- Attacker knows: full equations, integrator, filter, drive quantization, source code.
- Attacker sees: `pk`, any number of `ct` = drive windows + nonces + DEM boxes.
- Attacker capabilities: classical + quantum (generic quantum-search counts; no immunity
  claim against hidden-subgroup attacks), ML-based state/parameter estimation, chosen-drive oracle (rate-limited).
- Honest parties: deterministic fixed-point execution, hedged ephemeral RNG, `zeroize`.
- Explicit non-claims (do not document as proven):
  1. `x(t)`-only hiding is NOT NP-hard. Delay-coordinate embedding / EKF / return-map / generalized-sync
     are in-scope attacks we must defeat in `attacks/`.
  2. No hidden-subgroup-immunity proof. No `2^512`-from-floats claim. Real entropy = seed entropy minus
     invalid/non-identifiable encodings. Target: 256-bit seed -> 128-bit PQ (quadratic quantum-search speedup halves effective strength).
  3. Fractal masking helps vs naive maps, does not prove ML-immunity.

Critical fix vs naive diagram: if sender/receiver share identical public equations, a third-party observer can run the
same slave and sync. Asymmetry requires long-term `pk = response commitment + sys-id`,
`sk = seed`, ephemeral `ct = drive block`. Spec below enforces this.

## 3. Math spec (frozen for v0, changes require SPEC bump)

### 3.1 Deterministic chaotic core
- System: reference 4D chaotic flow (Lorenz-28 regime, single positive Lyapunov
  exponent — documented as chaotic, not hyperchaotic). State `X in R^4` in fixed-point
  `Q64.64` (`i128` intermediate, `i64` stored). No `f64` in key path.
- Integrator: RK4, fixed `DT = 0.001` (stored as `DT_Q = round(0.001 * 2^64)`), transient
  discard `N0 = 5000` steps. All mults: `(a*b)>>64` with wrapping + saturation policy in spec.
- Health: reject fixed points / short cycles / non-positive finite-time Lyapunov estimate.
- KDF expansion: `seed(32B) -> keyed-BLAKE3-XOF(domain) -> x0[4] + theta[n]` range-checked
  into chaotic region (rejection resample with counter, constant-time where feasible).

### 3.2 Fractal Boundary Masking (extractor)
- `u = abs(x_q) * SCALE_Q`, `r = u - floor(u)` (fractional residue), `byte = floor(r*256)`.
- `SCALE = 2^20`, sampling stride `S=10` steps, 16-bit quantized drive `x_q` for sync,
  full-residue bytes for keystream. Domains separated from sync path.
- Must pass: NIST SP 800-22 (alpha 0.01), ENT, return-map plot shows no structure,
  avalanche 49-51% for 1-bit seed flip after N>=2000 steps.

### 3.3 Drive-response KEM (experimental v0 sketch; superseded by hybrid X25519 KEM)
- Split: drive `d = quant16(x)`, response `(y,z,w)` with conditional Lyapunov `< 0`.
- `KeyGen(): (sk=seed32, pk=commit(theta_pub)||sysid||ver)`
- `Encaps(pk): ephemeral seed_e, drive window W (e.g. 512 samples) + nonce24, secret = KDF(sync_tail || pk || ct || "ca-pq-sync-v1")`
- `Decaps(sk,ct): run slave on d, check sync err ||e|| < EPS within STEPS_MAX, recompute secret, transcript-binding re-encryption check before release`
- DEM: `cipher = msg XOR keystream(secret,nonce)`, `tag = MAC(secret,nonce||cipher)`.
- Hybrid (P0 credibility): `ss_final = Hash(ss_chaos || ss_mlkem768 || transcript)` — ML-KEM
  from-zero implementation, roadmap (no lattice code in tree yet).

## 4. Dual-hash: fast + ultra-light

Small inputs dominate (32B seeds, tags), so short-input latency + RAM/ROM dominate.

```rust
trait Hash256 {
  fn hash(data:&[u8], ctx:&[u8]) -> [u8;32];
  fn xof(data:&[u8], ctx:&[u8], out:&mut [u8]);
  fn mac(key:&[u8;32], msg:&[u8], ctx:&[u8]) -> [u8;32];
}
```

- Single hand-written BLAKE3 backend: plain/keyed/XOF/derive-key from the spec,
  no hash crates. Domains: `ca-pq-kdf-v1`, `ca-pq-sync-v1`, `ca-pq-dem-v1`, ….
- Always 256-bit output. `xxHash/Murmur` banned (non-crypto).
- Bench gate: 32B/64B/1KB/1MB + MAC + size report; CI fails on >5% regression.

## 5. Rust platinum rules

`edition2024, forbid(unsafe_code), clippy::pedantic+nrsery, rustfmt --check, cargo-deny/audit/vet,`
`no_std` for core/hash/extract/kem, `zeroize` secrets, constant-time tag compare,
`cargo-fuzz + proptest + criterion`, reproducible builds + SBOM, MSRV pinned.

## 6. Repo layout (CA-PQ)

```
PLAN.md  SPEC.md (extracted from §3)  THREAT.md
Cargo.toml (workspace)
crates/chaos-core/    # fixed-point, RK4, system step, health
crates/chaos-hash/    # Hash256 + blake3/ascon backends
crates/chaos-extract/ # masking filter + keystream
crates/chaos-kem/     # KeyGen/Encaps/Decaps + sync loop
crates/chaos-aead/    # DEM seal/open
crates/chaos-cli/     # vectors, bench, attack harness
tests/ benches/ attacks/ docs/
```

API sketch: `keygen()->(sk,pk)`, `encaps(pk, &mut rng)->(ct,ss)`,
`decaps(sk,ct)->ss`, `seal(ss,nonce,msg)->(ct_dem,tag)`, `open(...)`.

## 7. Validation + attack gates (must pass to release)

Correctness: cross-arch KAT (x86_64/aarch64/riscv32/thumbv6m), sync success honest,
hard fail on 1-LSB wrong theta, avalanche 49-51%.
Randomness: NIST STS + ENT + return-map.
Perf: cycles/byte, keygen/encaps/decaps latency, sk/pk/ct bytes vs ML-KEM ref.
Attacks (all must FAIL to break): return-map/delay-embedding observer, EKF parameter-ID,
generalized-sync observer, Transformer recon on `d(t)`. Any success = redesign, no ship.

## 8. Build order

0. SPEC freeze + KAT vector format. 1. core (fixed-point RK4). 2. hash dual.
3. extract filter. 4. kem sync loop. 5. aead DEM. 6. cli + benches.
7. attacks/ red-team. 8. hybrid ML-KEM + audit prep.

Top ideas baked in: hybrid PQ, misuse-resistant API, agility via versioned param sets
(CHAOS-A-128s light / CHAOS-B-256f server), streaming zero-copy, integer-only HW-friendly
core, continuous health tests, supply-chain hardening.

---

## Build log v1 (executed)

- Core: first-order method -> RK4 (fixed-step, deterministic). Damping retuned after probe showed
  scaled-coupling blow-up (attractor now O(30), bound ±256 safety). Added `Health`
  monitor (bounded/fixed-point/divergence with Q32 quantization-floor note) + `kat_state`.
- Honest correction: 1-LSB state tweaks sit below the fixed-point resolution floor;
  guaranteed property is byte-level seed sensitivity (avalanche test) + whitened bytes.
- `chaos-attack` (new): raw drive slow (r~0.9), observer==receiver slaves, bytes white (|r|<0.1).
  Consequence: NO drive on wire; chaos is local KDF/stream only.
- `chaos-kem` rewritten: hybrid X25519 + chaos. ct = nonce + eph_pk + tag (88 B);
  `decaps(sk,pk,ct)` needs no ephemeral side-channel. sysid `CA-PQ-02`.
- CLI: `kat|demo|attack|bench`. Docs: README/SPEC/THREAT. CI: fmt+clippy+test+light+kat+attack.
- Status: 15 tests green, clippy -D warnings clean (all targets), fmt clean.
- NOT done: PQ (needs ML-KEM hybrid), audit, NIST STS full suite, cross-arch CI, no_std embedded.

---

## Build log v2 — zero dependencies, BLAKE3 from zero (executed)

- `chaos-hash` rewritten: hand-written BLAKE3 (compress, chunk state, tree stack,
  plain/keyed/XOF/derive-key). Official empty vector `af1349b9…f3262` passes;
  split-invariance across all chunk/stack boundaries (0–2049 B). Old SHA-256 code removed.
- `chaos-kem/x25519.rs` (new): from-zero X25519, 5×51-bit signed limbs. A biased-limb
  subtraction bug was caught by cross-validation against an independent big-int
  RFC 7748 transcription; fixed with signed `i128` carry. Golden DH outputs pinned.
- `chaos-burn` (new): volatile wipe, the single audited `unsafe` in the tree
  (`deny` + item-scoped allow with SAFETY note; atomics-from-`&mut` unavailable).
- `zeroize`, `x25519-dalek`, and all transitive deps removed. `Cargo.lock` holds
  only the 8 workspace crates. `zeroize` call sites now use `chaos_core::burn`.
- Status: 23 tests green, clippy `-D warnings` clean (all targets), fmt clean.
- NOT done: ML-KEM from zero (PQ), audit, NIST STS full suite, cross-arch CI.

---

## Build log v3 — from-zero Keccak sponge (executed)

- `chaos-hash/shake.rs` (new): hand-written Keccak-f\[1600\] with compile-time
  LFSR round constants, SHA3-256/512 + SHAKE128/256 (one-shot and incremental).
  Verified against an independent oracle (separate Keccak codebase) on
  rate-boundary lengths, multi-block squeezes, and incremental splits — all pass
  first run. Purpose: standard XOF/MAC groundwork for the from-zero ML-KEM next.
- Status: 28 tests green, clippy `-D warnings` clean (all targets), fmt clean.
- NOT done: ML-KEM from zero (PQ), audit, NIST STS full suite, cross-arch CI.

---

## Build log v4 — from-zero ML-KEM-768 (executed)

- `chaos-mlkem` (new): ML-KEM-768 shape (n=256, q=3329, k=3, eta=2, du=10, dv=4),
  plain modular arithmetic, matrix seed (rho, public) / noise seed (sigma,
  secret) split from SHA3-512(d). Deterministic API: keygen(d,z),
  encaps(ek,m), decaps(dk,ct) with implicit rejection. Sizes 1184/2400/1088/32.
- Verification (independent Python FIPS-203 transcription, kept outside tree):
  full ek/ct/ss KAT agreement (2 seeds), NTT/CBD/compress goldens, 12 patterned
  roundtrips, tamper + wrong-key rejection. Notable catches along the way: an
  INTT sign error and an empirically-derived pair-moduli order, both settled by
  roundtrip + homomorphism checks. No official-vector check: no interop claim.
- CLI `pq` demo; SPEC/THREAT/README updated; quantum attacker now in scope for
  the mlkem path only.
- Status: 33 tests green, clippy `-D warnings` clean (all targets), fmt clean.
- NOT done: flagship X25519+ML-KEM+chaos hybrid, audit, NIST STS, cross-arch CI.

---

## Build log v5 — flagship hybrid + two caught defects (executed)

- `chaos-hybrid` (new, sysid CA-PQ-H1): X25519 + ML-KEM-768 + chaos tail under
  one transcript, `ss = Hash(ss_x || ss_pq || tr_hash)`. Sizes 1288/2464/1176/32.
  Verified: two full-stack KATs byte-agree with an independent Python reference
  (big-int X25519 + manual BLAKE3 compress + pip keyed/XOF + FIPS-203
  transcription); determinism, per-leg tamper behavior, combiner sensitivity.
- DEFECT 1 (fixed): kem keygen hashed the commitment buffer AFTER wiping it —
  every key shared one constant commitment while roundtrips stayed green.
  Regression test pins distinct commits; SPEC kem KATs regenerated.
- DEFECT 2 (fixed): BLAKE3 `root_bytes` emitted 8 words/block instead of 16 —
  invisible to all 32 B digest tests, caught only by 64 B XOF cross-check.
  Regression test pins 64/96 B reference outputs.
- Corresponding hygiene: mlkem secret temps (h/g/r/m2) now wiped; golden
  literals carry length asserts so paste corruption fails loudly.
- Status: 41 tests green, clippy `-D warnings` clean (all targets), fmt clean.
- NOT done: audit, NIST STS full suite, cross-arch KAT CI, optimized field arithmetic.

---

## Build log v6 — optimization pass (executed)

Phase 0 (measure): black_box-hardened split benches (prior pair numbers were
partly DCE-deflated); component probes showed X encaps ≈ 60% DH + 35% tail,
PQ encaps dominated by matrix sampling (~4:1 over NTT arithmetic), hashing ~1%.
Binary audit: float Display (~12 KiB), unwind tables, syms were the fat.

Phase 1 (speed, all behavior-preserving, KATs green throughout):
- X25519 2-round delayed carry (bounds-verified fixed point): ~1.5x DH.
- SHAKE streaming squeezer (prefix-identical output): ~1.4x PQ encaps.
- Barrett NTT tried, measured null (loop/memory-bound, not ALU), reverted.
- Transient 5000 -> 1000 after saturation analysis (Hamming ~0.47 from step
  250, flat to 4000; 4x margin; all health/avalanche gates re-run green):
  ~1.9x tails. Full KAT regen + Python cross-check redone.
- Combined hybrid pair: ~865 us -> ~407 us (~2.1x).

Phase 2 (sizes): strip + panic=abort + float-Display purge: 604 KB -> 524 KB
(-13%), .text -21 KiB. Heapless AEAD + ML-KEM-512 profile deferred (minor gain,
separate turns). sysids bumped (CA-PQ-03/H2); kem commit now binds sysid.
Skipped with reason: transcript-hash caching (~1 us, not worth churn),
BLAKE3 SIMD (bulk-only win; KEM hashing is ~1% — revisit if bulk matters).

Status: 44 tests green, clippy -D warnings clean (all targets), fmt clean.
NOT done: audit, NIST STS full suite, cross-arch KAT CI.

---

## Build log v7 — wire-size cuts + seed-packed storage (executed)

- X wire: nonce 24->12 (96-bit random nonces, GCM-standard), tag 32->16
  (128-bit, GCM/Poly1305-standard), sysid 8->4 B; kem commit now binds sysid.
  X pk 72->68, ct 88->60 (-32%); hybrid pk 1288->1284, ct 1176->1148.
  Commit stays 256-bit (conservative binding, explicitly kept).
- Seed-packed storage (no API change — keygen IS the expander): X sk 64->32,
  PQ dk 2400->64 (d, z), hybrid sk 2464->32; re-derive-on-load roundtrips tested.
- Full re-validation: Python port updated (widths/sysids/layouts), full-stack
  agreement re-established on both KAT sets, all KAT literals refreshed,
  SPEC KATs regenerated (kem commit/ss, hybrid sets).
- Status: 47 tests green, clippy -D warnings clean (all targets), fmt clean.

---

## Build log v8 — v1.0.0 final product push (executed)

- Self-audit: secret hygiene completed (burn mat/tail/shared/expect in kem;
  poly wipes via new `burn_words`; redacted Debug on both secret-key structs;
  `burn_dk` helper for caller-owned ML-KEM keys). Audit also caught and fixed
  an edit-introduced duplication (KATs caught it instantly).
- NIST-style suite (`chaos-stat`, new): erfc/igamc/gammln from zero, 7 tests
  (monobit, block128, runs, serial x2, apen, cusum x2). Two suite bugs found
  by degenerate inputs: missing -lnGamma normalization (block -> -inf),
  cusum second-sum sign (everything -> ~0). Both fixed; gate passes 8/8 seeds
  (block128 7/8, exactly per proportion rule).
- CRITICAL dynamics fix: long-stream analysis proved the original params
  collapsed to fixed points (exact 5/8, 3/8 proportions; float twin confirmed
  regime, not arithmetic). Re-parameterized to Lorenz-28 (10, 8/3, -1, 28):
  measured Lyapunov exponent ~0.6-0.9, 200 KB no-lock soak incl. jitter
  corners, full NIST gate green. Language corrected (chaotic, not hyperchaotic).
  Attack test re-anchored to operational stride (r ~ 0.97 at stride 4).
- Heapless AEAD (`seal_into`/`open_into`, byte-identical MAC construction);
  no_std across all 8 lib crates, verified on thumbv7em + wasm32 (CI gated).
- Release: GPL-3.0-or-later (LICENSE), CHANGELOG, version 1.0.0, crate
  descriptions + versioned path-deps, `cargo publish --dry-run` clean
  (leaf-first order), `cargo doc` warning-free, CI gains cross-target job.
- Status: 51 tests green, clippy -D warnings clean (all targets), fmt clean.
- NOT done: external audit; ML-KEM-512 profile; optimized field arithmetic.

---

## Build log v9 — independent validation on this machine (executed)

- `ent` (Fourmilab, built from source) over 2x32 MiB keystream: entropy
  7.99999 bits/byte, chi-square p 31-36%, mean 127.50, Monte Carlo Pi error
  <= 0.01%, serial correlation ~-0.0002. Textbook pass on both seeds.
- libFuzzer + ASan (nightly) differential fuzzing, 4 targets, ~25M execs,
  zero crashes: hash_split (~5.6M), shake_stream (~19M), mlkem_roundtrip
  (~220k), kem_roundtrip (~276k). `ca-pq stream` subcommand added for dump
  generation (equivalence with keystream() pinned by test). Seed corpus
  committed under fuzz/ (detached workspace; main lockfile stays clean).
- Machine notes: 16-core i5-14400F (AVX2/BMI2, no AVX-512), 31 GB RAM;
  valgrind + perf present; no node/wasm runner, no ent/dieharder packages
  (ent built from source instead); fuzzing needed a space-free tree copy
  (libfuzzer chokes on the space in this workspace path).
- Deferred, needs heavier iron or humans: full TestU01/DIEHARDER campaign,
  external audit, ML-KEM-512 profile.

---

## Build log v10 — BLAKE3 AVX2 + multi-chunk tree fix (executed)

- New `chaos-simd` crate: 8-way AVX2 compression kernel (per-lane rows in
  YMM registers, no shuffles in the hot path), compile-time opt-in
  (`RUSTFLAGS="-C target-feature=+avx2"`, no_std-safe — no runtime CPU
  detection), portable fallback otherwise. Second audited `unsafe` site
  (intrinsics on register values + valid stack slots only); rest of tree
  stays `forbid(unsafe_code)`.
- Hasher batches full 8-chunk groups through `compress8` (unconditional —
  one code path, tested everywhere); small inputs take the unchanged scalar
  path with zero added overhead. Measured bulk: ~800 MiB/s -> ~2235 MiB/s
  (~2.8x) on i5-14400F. KEM paths unaffected by design (inputs < 8 KiB).
- DEFECT found by the new multi-chunk official vectors: the tree stack merged
  BEFORE pushing (pairing wrong nodes) with a stray target increment — produced
  right-leaning trees past 2 chunks while all small-input tests stayed green.
  Fixed to push-first + popcount target (binary-counter maintenance); proven by
  official vectors at 1023-100000. Lesson logged: self-consistency tests
  (split-invariance) cannot catch tree-shape bugs — only external vectors can.
- CI gains an AVX2 job (differential kernel-vs-scalar test + full hash suite
  under the AVX2 cfg); cross job covers the new crate on thumbv7em.
- Status: 53 tests green default (+13 under AVX2 cfg incl. differential),
  clippy clean under both cfgs, fmt clean.
- NOT done: external audit; ML-KEM-512 profile; BLAKE3 NEON/SSE2 tiers.

---

## Build log v11 — Keccak-4x batched matrix sampling (executed)

- New joint 4-way SHAKE128 squeeze (`shake128_squeeze_x4` in `chaos-hash`):
  scalar per-lane absorb/pad (exact), lockstep squeeze through one dispatch
  point (`keccak_f_4` → `chaos-simd::keccak_f_x4` under AVX2, else 4x scalar).
  Over-squeezing a finished lane is harmless (bytes already written), so
  lanes may differ in length; a differential test pins batch == 4x one-shot
  at 10 lengths incl. rate boundaries, under both cfgs.
- `chaos-simd::keccak_f_x4`: 4 parallel Keccak-f in AVX2 (64-bit lanes,
  immediate rotates, native andnot, scalar transpose), third audited `unsafe`
  site, same justification shape as the BLAKE3 kernel. Pinned by an AVX2-only
  differential test (two consecutive perms vs scalar, catches carry bugs).
- ML-KEM `sample_matrix` batches its 9 `sample_ntt` streams 4+4+1 under AVX2:
  fixed 840 B (5 blocks) per stream + scalar rejection, with an exact scalar
  restart as the termination safety net (21-sigma event, never observed).
  Fill order unchanged → matrix bit-identical; proven by the full-length
  reference KATs (`kat_a`, `kat_b`) passing under the AVX2 cfg. Portable path
  is the untouched scalar streamer (zero regression risk, measured neutral).
- Deliberate revert inside this log: an unrolled portable `keccak_f` was
  written, measured (+0.9% bulk, noise), and reverted — LLVM already owns
  that shape; the hand derivation only cost auditability. Lesson logged:
  measure before keeping clever code.
- Measured (i5-14400F, back-to-back, same session): pq encaps +27%,
  pq decaps +39%, pq pair +17%, pq keygen +17%, hybrid pair +2–16% (X25519 +
  chaos tail dominate there). SHAKE128 bulk unchanged by design.
- CI AVX2 job extended to `-p chaos-hash -p chaos-simd -p chaos-mlkem`.
- Status: 54 tests green portable (+2 under AVX2 cfg incl. both
  differentials), clippy `-D warnings` clean under both cfgs, fmt clean,
  thumbv7em + wasm32 checks clean.
- NOT done: external audit; ML-KEM-512 profile; BLAKE3 NEON/SSE2 tiers.

---

## Build log v12 — SHAKE256 PRF batching + NTT cost-share probe (executed)

- Measured first: temporary in-crate probe (since removed) timed NTT
  2.9 µs, INTT 2.7 µs, pointwise-mul 0.5 µs → NTT work is ~36% of a ~70 µs
  pq encaps (~25 µs: 3 NTT + 12 polymuls + 4 INTTs). That number justifies
  an AVX2 NTT as the next big lever (3–4x on that share ≈ +35% encaps);
  it is deliberately NOT in this log — shuffle-heavy NTT deserves its own
  session with fresh differential tests.
- Quick win shipped: `squeeze_x4` generalized over rate/suffix
  (`shake256_squeeze_x4` added, same contract + tests), `codec::prf2_x4`
  batches the CBD coin PRFs (keygen 4+2, encrypt 4+3, AVX2 only; portable
  loops untouched). Pinned by the SHAKE256 batch test + the full-length
  reference KATs under both cfgs (same counters → identical polys).
- Measured (same machine, back-to-back): AVX2 pq encaps +11%, decaps +12%,
  pair +12% on top of v11; cumulative vs portable: encaps +41%, decaps
  +55%, pair +32%. Portable neutral (code path untouched). Keygen flat
  (PRF share small there — Amdahl at work, documented not chased).
- Keccak batching is now complete: every Keccak use in `chaos-mlkem`
  (matrix SHAKE128 + coin SHAKE256) runs joint-4-way under AVX2.
- Status: 55 tests portable / 57 AVX2, zero failures; clippy `-D warnings`
  both cfgs; fmt; thumbv7em + wasm32; kat/attack/pq/hybrid green.
- NOT done: external audit; AVX2 NTT (justified, queued); ML-KEM-512
  profile; BLAKE3 NEON/SSE2 tiers.

---

## Build log v13 — AVX2 NTT family + portable branchless mod (executed)

- Portable first: `addmod`/`submod` went from full-`%` magic-multiplies to
  single conditional add/sub (the `[0, q)` invariant holds by construction
  — entry polys are CBD/decompressed/NTT-domain — and is now
  `debug_assert`ed, so dev-profile tests enforce it). NTT 3.5→1.3 µs
  (2.8x), INTT 2.4→1.4 µs. Portable pq ops +10–19%, zero API change.
- AVX2 NTT family in `chaos-simd` (4 new entry points, same audited-`unsafe`
  justification shape): forward (Cooley-Tukey), inverse (Gentleman-Sande +
  final 128^-1 scale), pointwise multiply, polyadd. 32-bit Barrett with a
  split-range derivation (`v = hi*2^16+lo`, `2^16 mod q = 2285`,
  `MU = floor(2^20/q) = 314`, single fixup proven for `w < 1076426`) —
  8 lanes, no 64-bit intermediates. Zeta tables derived in `ntt.rs` from
  the same `ZETAS` source of truth (incl. the len-2 split-group layout);
  the SIMD crate holds no twiddle logic. Portable scalar bodies kept
  verbatim as reference + differential baseline.
- Debugging record (kept because it paid for itself twice): three real
  defects, all caught by differential tests, none by reasoning —
  (1) CT-vs-GS butterfly confusion in the forward path (the inverse shape
  was implemented for both); (2) INTT table index mirroring; (3) a
  double-width gamma product in polymul; plus two AVX2 lane-structure
  traps: `packs_epi32` and `unpacklo_epi32` are per-128-bit-lane (store
  duplicated halves; gamma high half repeated low). Permanent regression
  tests added for the Barrett constants and the pack narrowing, with
  distinct-lane vectors (constant-lane inputs are blind to this bug
  class — the first bisect probe proved it).
- Measured (same machine, back-to-back, two runs): AVX2 pq encaps
  15.7k→17.5k, decaps 16.0k→19.0k, pair 7.2k→8.4k, keygen 13.6k→16.5k,
  hybrid pair 2.3k→2.5k. Portable: encaps 11.2k→13.1k, keygen
  11.7k→14.0k. SHAKE/X25519/chaos paths untouched.
- Status: 56 tests portable (+2 AVX2-unit) / 62 AVX2 incl. 4 NTT
  differentials + full-length KAT goldens under both cfgs; clippy
  `-D warnings` both cfgs (scalar/table items precisely cfg-gated, no
  `allow(dead_code)`); fmt; dev-profile asserts green; thumbv7em +
  wasm32; kat/attack/pq/hybrid green; lockfile still zero third-party.
- NOT done: external audit; ML-KEM-512 profile; BLAKE3 NEON/SSE2 tiers.

---

## Build log v14 — division-free RK4 + batch encapsulation (executed)

- Decomposition first (temporary kem probe, since removed): ladder ~52 µs,
  chaos_tail ~39 µs per encaps — i.e. hybrid cost is ~55% X25519 leg,
  ~30% PQ leg. Both attacked in cost order below; X25519 field code
  reviewed and deliberately left alone (5x51-bit schoolbook + minimal
  carries is already near-optimal; carry reduction would break the
  documented i128 bound).
- RK4 `/6` killer: the accumulator's `sum / 6` was a 64-bit division
  (~20-40 cycles x4 per step). Replaced with exact Granlund-Montgomery
  (`M = ceil(2^64/6)`, `(a*M)>>64`, symmetric sign) valid for the
  `|sum| < 2^50` range (debug-asserted); differential test sweeps 2.25M
  values + edges vs `/`. Bit-exact by construction, KATs confirm.
  Keystream +7%, kem encaps +8–14%, hybrid pair +11% portable.
- `chaos-mlkem::encaps_batch`: N messages to one `ek`, matrix sampled
  once. Element `i` is BIT-IDENTICAL to scalar `encaps(ek, ms[i])`
  (test-pinned, incl. empty batch) — amortization only, zero new crypto
  semantics. (A coins-mixing variant was written first, then REVERTED:
  it would break FO re-encryption on decaps. Lesson logged: batch must
  share deterministic state only, never randomness.)
- Measured per-element batch8: portable 14.9k→17.6k (+18%), AVX2
  17.6k→22.2k (+26%). `ca-pq bench` gains a batch8 line.
- Status: 58 tests portable / 65 AVX2, zero failures (dev profile too);
  clippy `-D warnings` both cfgs; fmt; thumbv7em + wasm32; kat/attack/pq/
  hybrid green; lockfile zero third-party.
- NOT done: external audit; ML-KEM-512 profile; BLAKE3 NEON/SSE2 tiers;
  transient-length re-analysis (margin stays 4x, untouched).

---

## Build log v15 — ML-KEM-512 profile (executed)

- Generic core over a `Profile` trait (K, ETA1, ETA2, wire sizes; KMAX=3
  buffers, runtime-k loops): CBD/PRF generalized by eta (`cbd_eta`,
  `prf_eta`; single 192 B `prf_x4` for both — eta-2 callers use the XOF
  prefix, one code path), matrix/PRF batching reworked as chunks-of-4 +
  scalar tail (k=3: 4+4+1 as before; k=2: exactly one batch). 768 top-level
  API byte-identical (all existing KATs green untouched); `m512` module
  exposes keygen/encaps/decaps/encaps_batch with 800/1632/768 B sizes.
- Dead helpers removed in passing (`prf2`, `shake256_128`, `cbd2` — the
  golden test now calls `cbd_eta` directly). One self-inflicted splice bug
  (a block replacement ate the `prf_eta` definition) caught immediately
  by `cargo check` — lesson re-logged: verify after every mechanical edit.
- 512 KATs from a fresh independent transcription (`mlkem512_ref.py`,
  K=2/ETA1=3, 5 roundtrips + tampers green): kat_a/kat_b full-length
  goldens + roundtrips/tamper/batch/wrong-key suite, passing under BOTH
  cfgs (AVX2 single-batch matrix shape proven identical).
- Measured: 512 portable encaps ~22.4k/s (1.6x 768), AVX2 ~25.4k/s.
  `ca-pq bench` gains pq512 lines.
- Status: 61 tests portable / 65 AVX2 (delta +3 m512 tests each), zero
  failures; clippy `-D warnings` both cfgs; fmt; cross targets; CLI green.
- NOT done: external audit; hybrid-512 combiner (deliberately out of
  scope — flagship stays 768); BLAKE3 NEON/SSE2 tiers.

---

## Build log v16 — hybrid-512 combiner (executed)

- `chaos-hybrid::h512`: X25519 + ML-KEM-512 + chaotic stream under sysid
  `PQH1` (flagship stays `PQH2`/768, zero changes to its path). Same
  combiner shape; `ca-pq-h512-*` hash domains throughout (lengths already
  differ — defense in depth, removes all cross-profile domain analysis).
  Sizes: pk 900 / sk 1696 (seed-packed 32) / ct 828 B. Shares the
  size-independent `combine`/`ctx_bytes` helpers; own transcript fn.
- Real defect caught by the new KATs (not by review): the first draft
  shared `super::combine`, which hardcodes the 768 domain — commit and ct
  matched, ss diverged. Fixed with an h512-local combiner; both full-stack
  KATs now byte-agree with the independent reference (`hybrid512_ref.py`).
  Lesson re-logged: shared helpers with baked-in domains are a trap;
  profile-specific hashing must be profile-local.
- Tests mirror the flagship (roundtrip/determinism, 2x X-tamper, PQ tamper
  at [100]/[757], wrong key, leg-mixing, sizes) + kat_h512_a/b.
- Measured: h512 pair portable ~2699/s, AVX2 ~2669/s (X-leg dominated;
  +16% over the 768 flagship). `ca-pq bench` gains a hybrid512 line.
- Drive-by doc fix: SPEC sysids/sizes had drifted from code (CA-PQ-03 vs
  PQ04, 72/88 vs 68/60) — corrected where touched.
- Status: 67 tests portable / 74 AVX2, zero failures; clippy `-D warnings`
  both cfgs; fmt; cross targets; CLI green; lockfile zero third-party.
- NOT done: external audit; BLAKE3 NEON/SSE2 tiers; transient re-analysis.

---

## Build log v17 — BLAKE3 SSE2 + NEON tiers (executed)

- 4-wide compression tiers in `chaos-simd`: `compress4_sse2` (pure SSE2,
  no SSE4.1 — baseline-compatible with all x86 targets) and
  `compress4_neon` (uint32x4_t, literal-count rotates — arithmetic on
  const-generic params is still unstable, so one helper per count).
  Hasher groups narrow to 4 chunks on those tiers (`compress_group4`,
  same ChunkState mirror + push-first/END rules); AVX2/scalar builds keep
  the proven 8-wide path. Each item has exactly one cfg — no dead code on
  any target (thumbv7em/wasm/aarch64/i686 checked).
- SSE2 proven on-host: lane differential (24 random vectors incl. XOF-tail
  lens/flags) + the full official-vector suite through the 4-wide groups.
  Measured bulk: scalar ~800 → SSE2 ~1480 MiB/s (+85%); AVX2 ~2215
  unchanged (untouched path).
- NEON proven under QEMU user-mode (qemu-aarch64 10.2, real validation,
  not compile-only): a freestanding no-std/no-libc aarch64 binary
  (raw SVC write/exit + hand memset/memcpy/bcmp, static, `-nostdlib`,
  kept in /tmp/opencode/neonq — scaffold, not product) checks empty,
  100 KiB bulk, XOF-100, 7-byte-split 5 KiB, and group-boundary 8193 B
  hashes against x86-computed goldens: ALL PASS, exit 0. In-tree
  `neon_matches_scalar` unit test covers native aarch64 runs/CI.
- Native aarch64 toolchain notes: no cross linker/sysroot on this box
  (cross-gcc present but sysroot-less; musl link needs musl-gcc) — hence
  the freestanding route, which needs neither. Reproduce:
  `RUSTFLAGS="-C linker=aarch64-linux-gnu-gcc -C link-arg=-nostdlib
  -C link-arg=-static" cargo build --release --target
  aarch64-unknown-linux-gnu` in neonq, then `qemu-aarch64 <binary>`.
- Status: 70 tests default (SSE2 tier active) / 70 dev / 76 AVX2, zero
  failures; clippy `-D warnings` default + AVX2 (incl. a new
  items-after-test-module move: test mods live at EOF now); fmt;
  thumbv7em + wasm32 + i686 + aarch64 checks; CLI green; CI gains an
  aarch64 check job; lockfile zero third-party.
- NOT done: external audit; transient re-analysis; SSE2/NEON Keccak/NTT
  tiers (deliberately out — BLAKE3 was the queued item; Keccak/NTT stay
  AVX2+portable).

---

## Build log v18 — red-team audit + closures (executed)

- Subgroup confinement proven closed: clamped scalars (RFC goldens) x
  cofactor-torsion = 0, `is_zero` fails closed on kem-encaps, kem-decaps,
  hybrid-768 and hybrid-512 decaps (zero-point tests); 0xFF points panic
  nowhere. Dead end logged: cofactor-clearing `q*P` cannot mint an order-8
  point from the basepoint (it has order q, so `q*G = 0` trivially) — the
  mechanism proof needs no specific point.
- Panic sweep green: all-0xFF ek/ct/dk through mlkem-768/512 (dev AND
  release), zero/0xFF peer points through kem/hybrid, empty + hostile
  AEAD inputs. Forced one real fix: NTT entry now total on [0, 4096)
  (scalar cond-sub loop + matching AVX2 entry behavior, decode-range
  differential) — adversarial dk tripped dev asserts before.
- R1 fixed: AEAD stream nonce truncation/padding collisions → length-framed
  `ca-pq-dem-stream-v2` (wire-breaking, CHANGELOG-noted); MAC untouched.
  Domain enumeration: all 27 context strings audited, every duplicate is
  same-use-both-sides or test/demo — no cross-purpose reuse.
- Assert/index inventory: only internal-contract + grinding-infeasible
  refill-cap asserts remain in lib code; all indexing traced bounded.
- Timing: ML-KEM 0.90–0.96x (no early exit), KEM bad-tag 0.58x (explicit
  reject skips tail; return value already reveals — no added oracle).
- THREAT.md gains the full findings file (R1–R5 closed, A1–A4 accepted);
  stale "zeroized on drop" narrowed to types that self-wipe; unsafe-count
  line already current.
- Status: full gates below; no performance delta expected (entry cond-sub
  is a no-op on honest inputs; AEAD stream re-framed, same cost class).

---

## Build log v19 — release 2.0.0 cut (executed)

- Semver call: 2.0.0, not 1.1.0 — the AEAD stream re-framing (R1) breaks
  v1 ciphertext compat, so a major bump is the honest number. Workspace
  version + all 28 path-dep requirements bumped; README header; CHANGELOG
  `[Unreleased]` headed `[2.0.0] — 2026-09-27` (breaking section kept).
- Release verification, honestly scoped: `cargo publish --dry-run` is
  STRUCTURALLY blocked for path-dependency graphs (registry must already
  contain each dep version — true of any unpublished workspace, including
  at v1.0.0; the v8 "dry-run clean" note is corrected by this log).
  Verified instead: `cargo package --list` file inventory per crate,
  `cargo doc --workspace --no-deps` warning-free, full test/clippy/fmt
  gates, lockfile zero third-party. Real publish must go leaf-first
  (burn/core → extract/hash/simd → kem/aead/attack/stat → mlkem →
  hybrid → cli) with a crates.io token — not done here.
- Status: 76 tests green; release cut, not yet published.

---

## Build log v20 — transient re-analysis + capture windows (executed)

- Re-measured the saturation knee independently (transient2.py): random
  pairs give Hamming 0.500 flat from T=50 (min 0.48) — the documented
  "~0.47 at 250" holds conservatively. N_TRANSIENT=1000 stands; no KAT
  churn, no code change to the core.
- Methodology trap logged: the first attempt measured 1-bit neighbors
  (shared params) and got 0.34 — a DIFFERENT metric (same-attractor
  partial correlation), plus two script bugs of mine (stale helper
  signature, `[0]` on bytes) caught by type errors, not by review.
- Red-team finding R6 (honest surprise, fully chased): rare materials
  capture bit-exactly by step ~2000-8000 near x ~ -8.5 (classical Lorenz
  fixed point; likely quantization-assisted — C± are saddles in
  continuous math). Frequency is flip-position-dependent (byte-0 ~13-27%,
  byte-5 ~0% in 2300 trials); early-deep tail correlation ~0.15%.
  Production horizon (<=1640 steps) + unreachable related seeds +
  unobservable tails + asymmetric roots = INFO, not VULN (THREAT R6 has
  the full argument). New deterministic regression sensor
  (`neighbor_tail_separation_sensor`, 7 fixed seeds >= 0.20 plus t=748
  positive control at ~0.03) guards future dynamics work. Health gate
  untouched (validation-only; catching windows there would protect
  nothing real, and its total-lock purpose is intact).
- Also noted (no action): expand() ignores 28 of 64 material bytes
  (16-31, 40-47, 52-63) — lossy but harmless (image still astronomical;
  XOF collision-resistance carries seed separation).
- Status: sensor green dev + release; full gates below.

---

## Build log v21 — Keccak x2 + NEON NTT tiers (executed)

- Keccak 2-way tiers: `keccak_f_x2` (SSE2, 64-bit lanes) and
  `keccak_f_x2_neon` (uint64x2_t, macro-stamped literal rotates — const
  arithmetic on generic params is unstable). `keccak_f_4` dispatches
  AVX2-x4 / 2x2-way / scalar; mlkem batch paths inherit automatically.
  Measured x2 kernel: exactly 2.00x scalar (transpose amortized).
  SSE2-tier pq: encaps +8%, keygen +10%. One-shot bulk unchanged by design.
- NEON NTT family (4-wide, `ntt4/intt4/polymul4/polyadd4_neon`): split-range
  32-bit Barrett via native `vmulq` + `vbsl` selects; `vshll` widening
  (preserves all four lanes — the `vmovl` halves them); `vqtbl1q_u8` (not
  `vtbl1q`, which is the 64-bit form) and `vZIP/vTRN` interleave. Shared
  4-wide zeta tables from the same `ZETAS` truth (single zeta per 4-block;
  narrower vectors need no split layouts). First-try green under QEMU:
  full m512 KAT_A (ek/ct/ss/decaps) passes on ARM — table design paid off.
- SSE2 NTT verdict: NOT BUILT, with quantitative justification. Pure SSE2
  lacks 32-bit multiply; emulating Barrett-32 costs ~14-20 instrs per 4
  products ≈ scalar parity (scalar post-branchless does ~4/product), and
  the 8-wide-16-bit alternative needs lane recombination of the same
  order. Scalar stands on old x86 (already 2.8x via branchless). An SSE4.1
  tier would work (~2x) if anyone cares — noted, not built.
- Debugging record: three NEON type-system corrections (signed-bias
  compare, `vbsl` same-width masks, `vqtbl` naming) — all caught by
  `cargo check`, zero runtime debugging needed on ARM. One self-inflicted
  file-surgery deletion (`barrett2n` eaten by an over-broad cut) caught by
  the next compile; lesson re-logged.
- QEMU harness extended (shake840 + determinism + m512 KAT_A): ALL PASS,
  exit 0. `target_feature="neon"` confirmed default-on for aarch64 (the
  validated binary really ran the NEON paths).
- Status: 78 tests portable / 83 AVX2, zero failures (dev too); clippy
  `-D warnings` default + AVX2 + aarch64; fmt; thumbv7em + wasm32 + i686
  + aarch64 checks; i686 test binaries EXECUTED green (16 hash tests:
  SSE2 tier validated on 32-bit x86 too, after fixing an x86-64-only
  `cvtsi128_si64` store-back); CLI green; lockfile zero third-party.
- NOT done: external audit; transient re-analysis. (Item 3 fully done:
  every SIMD tier that pays for itself is built; SSE2 NTT explicitly
  rejected with numbers.)

---

## Build log v22 — professional docs package (executed)

- README rewritten for GitHub (features, real benchmark tables from
  `ca-pq bench` logs captured this session, sizes, stance, API sketch).
- New WHITEPAPER.md (vision/architecture/analysis, no invented external
  benchmarks — only measured in-tree numbers + public standard facts) and
  YELLOWPAPER.md (formal spec: parameters, equations, flows, wire formats,
  all 28 domains, KAT inventory — verified against code).
- New REDTEAM.md consolidating the v18 audit (R1–R6, A1–A4, vector table);
  THREAT.md stays the living model. All metrics cross-checked against
  bench logs and test runs before writing; no URLs invented.

---

## Build log v23 — papers in LaTeX + PDF (executed)

- `papers/whitepaper.tex` + `papers/yellowpaper.tex` (article class,
  TeX Live 2026, `pdflatex` clean zero-error): 5 + 5 pages,
  `papers/whitepaper.pdf` (247 KB) + `papers/yellowpaper.pdf` (307 KB),
  text-extracted to verify rendering (title/abstract/TOC/all sections).
  Content ported faithfully from the .md originals (one real fix on the
  way: `xcolor` was missing for hyperref link colors — first PDFs shipped
  with broken link styling; caught on log review, fixed, recompiled).
  README documents table links both formats.

---

## Build log v24 — fuzzing document + fresh campaign (executed)

- New FUZZING.md: 4 targets with per-target properties, ASan method,
  space-free-copy quirk, corpus/artifacts policy, historical (~25 M) +
  fresh (~9 M) campaign tables, honest scope limits, roadmap (hybrid/aead
  targets, m512 leg, overnight pre-release runs).
- Fresh nightly+ASan runs (space-free copy, committed corpus as seeds):
  hash_split 2.28 M, shake_stream 6.62 M, mlkem_roundtrip 61 k,
  kem_roundtrip 70 k execs — all DONE, zero crashes/panics/reports.
  `fuzz/artifacts/` still empty everywhere.
- README documents table links FUZZING.md.

---

## Build log v25 — ePrint LNCS papers (executed)

- `papers/eprint/whitepaper.tex` + `yellowpaper.tex` in Springer LNCS
  (`llncs.cls` from CTAN, kept local in `papers/eprint/` — no system
  changes): author block with contact email in both PDFs
  (ePrint requirement), abstracts, keywords, real bibliography (FIPS
  203/202, RFC 7748, BLAKE3, Curve25519, SP 800-22), 4 + 4 pages A4,
  zero-error compiles. Fixed on the way: missing `texlive-aliascnt`
  (installed via dnf), A4 paper option (default came out letter).
- ePrint submission checklist for the author: category
  `Public-key cryptography`; keywords from the papers (each <= 40 chars);
  license choice required at submit (paper license is separate from the
  GPL code license — CC BY is the common pick); PDF includes email; A4.
  README links both ePrint PDFs.
