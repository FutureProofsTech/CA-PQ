# CA-PQ Red-Team Report — Self-Audit v18 + Dynamics Review

**Scope**: full tree at v2.0.0 (`chaos-*/src`), machine-assisted self-audit (not a substitute for external audit).
**Method**: subgroup-confinement analysis, all-0xFF adversarial sweep over every public KEM/AEAD API (dev + release), complete unwrap/assert/index inventory of library code, domain-string enumeration with call-site analysis, decaps timing smoke, burn/Debug review, transient-margin re-measurement, capture-window characterization.
**Result**: 5 closed findings (R1–R5, fixed + tested), 1 INFO dynamics finding (R6, sensor-pinned), 4 accepted residuals (A1–A4).
**Gates at sign-off**: 78 dev / 78 portable / 83 AVX2 tests, zero failures; clippy `-D warnings` (default + AVX2 + aarch64); fmt; cross-compile (thumbv7em, wasm32, i686, aarch64); QEMU execution (aarch64 user-mode, ALL PASS); i686 execution green.

## R1 — AEAD keystream nonce truncation [HIGH, FIXED]

**Vector**: `chaos-aead::stream()` hashed `ss ‖ nonce[..24]` zero-padded to 56 B. Any nonce longer than 24 B collided with its 24 B prefix; `"abc"` collided with `"abc\0"`. Both are silent catastrophic keystream reuse — worse than documented nonce-misuse (the caller believes nonces differ).
**Fix**: length-framed keyed XOF (`ca-pq-dem-stream-v2`: domain ‖ `0x00` ‖ le64(len) ‖ full nonce). Wire-breaking by necessity (colliding pairs must diverge); CHANGELOG-noted. MAC path (full nonce absorbed) was never affected and is unchanged.
**Tests**: `nonce_framing_no_collisions` (prefix + truncation pairs separate; empty/empty roundtrips; wrong-key fails; determinism).

## R2 — Small-subgroup confinement [MEDIUM, PROVEN CLOSED]

**Vector**: malicious peer sends a low-order X25519 point; a non-clamped DH would leak an enumerable shared secret.
**Analysis**: every DH scalar in-tree is clamped (multiple of 8 — pinned by RFC goldens, which require exact clamping to match), so DH with any point of order dividing 8 is exactly zero. The `is_zero` contributory gate fires on **both** encaps and decaps.
**Tests**: zero peer point fails closed on kem-encaps, kem-decaps, hybrid-768 and hybrid-512 decaps; `0xFF` points panic nowhere. (A constructive order-8 vector was attempted via cofactor clearing and dropped on a soundness technicality: the basepoint has order q, so `q·G = 0` trivially — the mechanism proof needs no specific point.)

## R3 — NTT decode-range entry [LOW, FIXED]

**Vector**: `byte_decode<12>` yields `[0, 4096)` but `ntt` assumed `[0, q)` — adversarial dk values tripped dev asserts (release still failed safe via FO rejection).
**Fix**: scalar + AVX2 entries conditional-subtract into `[0, q)`; decode-range differential pins kernel == scalar; all-0xFF sweep passes dev and release on both ML-KEM profiles.

## R4 — Assert/index inventory [LOW, CLOSED BY REVIEW]

The only release asserts in library code are internal-contract checks (CBD/PRF shapes, batch slice agreement) and the `sample_ntt` 64-block refill cap. The cap is grinding-infeasible (~50σ per entry; finding a violator needs ~2¹⁰⁰⁰ trials) — fail-stop panic is the honest response. Every index expression traced bounded by type or asserted length (`fe_decode`/`fe_encode_full` bounds checked exactly; sponge/squeeze/NTT/table indices likewise).

## R5 — Decaps timing [INFO, NO ORACLE]

Measured: ML-KEM valid:tampered ≈ 1:0.90–0.96 (identical work — FO re-encryption is unconditional; residual is divider/branch data variance). X-KEM bad-tag ≈ 0.58× (explicit reject skips the chaos tail, but the return value already reveals failure — timing adds no oracle). No gate (shared-runner flakiness); numbers recorded.

## R6 — Capture windows [INFO, UNDERSTOOD + SENSOR-PINNED]

Re-measurement (second implementation) confirms the transient margin — independent pairs: Hamming **0.500 flat from T=50** (min 0.48) — and characterizes a nuance: rare materials (flip-position-dependent; byte-0 neighbors up to ~13–27%, byte-5 ~0% in 2 300 trials) converge bit-exactly by step ~2000–8000 near the classical Lorenz fixed point (x ≈ −8.5), passing health (chaos through the probe window). Early-deep tail correlation ≈ 0.15% of trials.
**Why INFO, not VULN**: (a) related materials are unreachable (XOF outputs); (b) tails are unobservable (hashes only); (c) worst case reduces to the X25519/PQ roots (non-claim #1); (d) nothing in production reads chaos state past step 1640. Guard: deterministic `neighbor_tail_separation_sensor` (7 fixed healthy seeds ≥ 0.20, t=748 positive control at ~0.03).

## Accepted residuals

- **A1 — bit-level timing.** u32/i64 divisions, bit-test branches, variable shifts depend on secret-adjacent values. Same stance as all unmasked implementations; masking out of scope. Verified: no secret-dependent early exits or length leaks.
- **A2 — ML-KEM dk arrays.** Plain arrays: no Drop wipe, Debug-printable. Callers must `burn_dk`; in-tree flows do (hybrid Drop, decaps locals).
- **A3 — deterministic API.** Caller RNG failures give weak-but-functional keys. Caller contract, documented.
- **A4 — reject philosophies.** Explicit reject (X) coexists with implicit reject (PQ); hybrids handle both (tested). No cross-leg oracle.

## Attack vectors tested and closed

| Vector | Where tested | Result |
|---|---|---|
| Zero/low-order peer point | kem ×2, hybrid-768, hybrid-512 | `None` everywhere |
| Oversize/invalid field element (`0xFF…`) | kem, hybrids | no panic, sane fail |
| All-`0xFF` ek/ct/dk (both ML-KEM profiles) | mlkem suites, dev + release | no panic; honest roundtrips, foreign rejects |
| X-half tamper (nonce/eph/tag) | kem, hybrids | `None` |
| PQ-half tamper | mlkem, hybrids | unrelated `ss`, deterministic |
| Wrong recipient key | all KEMs | fail / reject |
| Tag forgery, ct flip, wrong key (AEAD) | aead suites | `None` |
| Nonce prefix/truncation collision (AEAD) | `nonce_framing_no_collisions` | separated |
| Cross-profile confusion (512↔768) | types + KATs | impossible by type; separated by sysid/domains |
| Timing (decaps valid vs tampered) | smoke probes | no early-exit oracle |

## Open (for external auditors)

External audit itself; transient-margin maintenance; Kani proofs; TestU01/DIEHARDER campaign; SSE4.1 NTT tier (evaluated path, unbuilt). THREAT.md holds the living model; PLAN.md v1–v21 holds methods and raw numbers.
