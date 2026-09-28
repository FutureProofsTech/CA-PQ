# CA-PQ — Post-Quantum Hybrid KEM Framework

**X25519 + ML-KEM + chaotic-stream hybrids, written from zero in Rust. Zero dependencies. No floats in the key path.**

CA-PQ v2.0.0 is a from-scratch asymmetric cryptography framework: classical ECDH (hand-written X25519), post-quantum cover (hand-written ML-KEM-512/768 shapes), and a deterministic chaotic-stream layer — combined under one transcript so the hybrid holds if *either* KEM leg holds. Every primitive (BLAKE3, SHA3/SHAKE, X25519, ML-KEM, NTT, RNG-free DRBG-free deterministic APIs) is hand-written in-tree. There is nothing to `cargo add`.

- License: **GPL-3.0-or-later** · Rust 2021 · `no_std`-compatible core · zero third-party dependencies (verified in `Cargo.lock`)
- Status: research/experimental — independently vector-tested and self-red-teamed (see [REDTEAM.md](REDTEAM.md)), **not externally audited — do not deploy in production**

---

## Contents

- [Why CA-PQ](#why-ca-pq)
- [What is inside](#what-is-inside)
- [Quickstart](#quickstart)
- [Benchmarks](#benchmarks)
- [Sizes](#sizes)
- [Security stance](#security-stance)
- [Validation](#validation)
- [Crate layout](#crate-layout)
- [API sketch](#api-sketch)
- [Documents](#documents)
- [SIMD tiers](#simd-tiers)
- [Contributing and audit](#contributing-and-audit)

## Why CA-PQ

Most post-quantum migration paths force a choice: keep fast classical ECDH, or jump to larger PQ KEMs with new code bases full of dependencies. CA-PQ does both at once, in one auditable tree:

1. **Hybrid by construction.** The flagship combiner binds X25519, ML-KEM, and a chaotic-stream tail under a joint transcript. Break one leg and the other still protects the session — classical safety today, lattice cover for the quantum setting.
2. **Two PQ profiles.** ML-KEM-768 (NIST level 3, default) and ML-KEM-512 (NIST level 1, smaller/faster), plus a matching level-1 hybrid — all from one generic, KAT-pinned core.
3. **Zero-trust supply chain.** Hash, sponge, curve, lattice math, and memory wiping are hand-written. `cargo build` touches no network after the toolchain. The lockfile contains only `chaos-*` crates.
4. **Deterministic APIs.** The caller supplies all randomness (`keygen(seed)`, `encaps(pk, coins, nonce)`). No RNG to backdoor, no hidden state — every output is reproducible and test-vector friendly.
5. **Honest crypto.** No inflated claims: the chaotic layer is a local stream expander, never asymmetry (proven in-tree by red-team gates); 256-bit seeds target ~128-bit classical security; timing and audit limits are documented, not footnoted.

## What is inside

| Component | Description |
|---|---|
| `chaos-hybrid` | Flagship combiner X25519 + ML-KEM-768 + chaos tail (sysid `PQH2`); level-1 sibling `h512` with ML-KEM-512 (sysid `PQH1`) |
| `chaos-kem` | X25519 ECDH KEM (hand-written RFC 7748) wrapped with chaotic-stream tail, sysid `PQ04` |
| `chaos-mlkem` | ML-KEM-768 + ML-KEM-512 from one generic core (plain + AVX2/NEON NTT, batched sampling, batch encaps API) |
| `chaos-hash` | Hand-written BLAKE3 (plain/keyed/XOF/derive-key) + Keccak sponge (SHA3-256/512, SHAKE128/256, streaming) |
| `chaos-core` | Deterministic Q32.32 fixed-point 4D chaotic flow (Lorenz-28 regime), RK4 integrator, health monitor |
| `chaos-extract` | Bit-folding masking filter + keystream sampler (STRIDE=10) |
| `chaos-aead` | Thin DEM: XOR stream + 16-byte keyed MAC, heapless `seal_into`/`open_into`, constant-time verify |
| `chaos-simd` | Vector kernels: AVX2 (BLAKE3/Keccak/NTT), SSE2 + NEON BLAKE3/Keccak tiers, NEON NTT |
| `chaos-attack` · `chaos-stat` | Red-team gates (drive structure, observer convergence, decorrelation) + NIST SP 800-22-style suite |
| `chaos-cli` | `ca-pq [kat\|demo\|attack\|bench\|pq\|hybrid\|stream]` — vectors, demo, attack summary, benchmarks |

## Quickstart

```sh
cargo test --workspace          # 78 tests (default) / 83 with AVX2, incl. full-length KATs
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p chaos-cli -- demo     # end-to-end hybrid demo
cargo run -p chaos-cli -- kat      # known-answer vectors
cargo run -p chaos-cli -- attack   # red-team gate summary
cargo run -p chaos-cli -- bench    # throughput table (below)
```

AVX2 build (opt-in, x86-64):

```sh
RUSTFLAGS="-C target-feature=+avx2" cargo test -p chaos-hash -p chaos-simd -p chaos-mlkem
RUSTFLAGS="-C target-feature=+avx2" cargo run -p chaos-cli -- bench
```

Cross targets (compile-gated in CI): `thumbv7em-none-eabihf`, `wasm32-unknown-unknown`, `aarch64-unknown-linux-gnu` (NEON validated under QEMU user-mode — see PLAN build log v17).

## Benchmarks

Measured on Intel i5-14400F, release profile, `ca-pq bench` (this machine is shared/virtualized — expect ±10–20% run variance; table rounded from repeated runs):

**Portable build** (default x86-64: SSE2 BLAKE3 tier + scalar Keccak/NTT):

| Operation | Throughput |
|---|---|
| BLAKE3 1 MiB | ~1 500 MiB/s |
| BLAKE3-keyed 64 B | ~11 M ops/s |
| SHAKE128 bulk | ~260 MiB/s |
| Keystream (chaotic) | ~3.3 MiB/s |
| X25519-KEM encaps / decaps | ~7.4k / ~11k ops/s |
| ML-KEM-768 encaps / decaps | ~14.4k / ~14.1k ops/s |
| ML-KEM-768 batch-8 (per element) | ~18.3k ops/s |
| ML-KEM-512 encaps | ~21.7k ops/s |
| Hybrid-768 pair | ~2.6k pairs/s |
| Hybrid-512 pair | ~3.0k pairs/s |

**AVX2 build** (`RUSTFLAGS="-C target-feature=+avx2"`):

| Operation | Throughput |
|---|---|
| BLAKE3 1 MiB | ~2 000–2 500 MiB/s |
| ML-KEM-768 encaps / decaps | ~17.1k / ~18.7k ops/s |
| ML-KEM-768 batch-8 (per element) | ~21.6k ops/s |
| ML-KEM-512 encaps | ~25.4k ops/s |
| Hybrid-768 pair | ~2.7k pairs/s |

Cumulative AVX2-vs-original-portable gains on the PQ path: encaps +58%, decaps +100%, pair +54% (build logs v11–v13). The X25519 leg is SIMD-untouched by design (identical both builds).

## Sizes

Wire sizes in bytes (fixed by type — no parsing, no length oracle):

| Object | X-KEM | ML-KEM-768 | ML-KEM-512 | Hybrid-768 | Hybrid-512 |
|---|---|---|---|---|---|
| Public key | 68 | 1 184 | 800 | 1 284 | 900 |
| Secret key (stored) | 64 (32 seed) | 2 400 | 1 632 | 2 464 (32 seed) | 1 696 (32 seed) |
| Ciphertext | 60 | 1 088 | 768 | 1 148 | 828 |
| Shared secret | 32 | 32 | 32 | 32 | 32 |

AEAD tag: 16 bytes. Release CLI binary: ~631 KiB portable / ~683 KiB AVX2 (LTO, stripped). Tree: ~8 200 lines of Rust, zero dependencies.

## Security stance

- **Asymmetry comes only from X25519 ECDH and (for PQ cover) the ML-KEM leg.** The chaotic attractor is a local deterministic KDF/stream expander — fast, float-free — never published, never trusted for asymmetry. `chaos-attack` proves it: raw drive is a slow predictable signal and every slave converges to every other slave on the same drive (observer == receiver).
- **Hybrid combiner**: `ss = Hash(ss_x || ss_pq || transcript)` — secure if *either* leg holds. Per-leg tamper behavior tested (X fails closed, PQ implicitly rejects).
- **No post-quantum claim on X25519/chaos paths** (classical). PQ cover rests on the ML-KEM leg only.
- **No inflated hardness claims.** No "NP-hard phase space", no hidden-subgroup immunity, no 2⁵¹²-float state spaces. 256-bit seeds, ~128-bit classical target.
- **Known limits (see [THREAT.md](THREAT.md))**: hand-written crypto reviewed by vectors + self-red-team only — **no external audit**; not constant-time beyond branchless swaps and tag comparison; deterministic API puts RNG responsibility on the caller; ML-KEM dk arrays need `burn_dk` (plain arrays can't self-wipe).

## Validation

- **Official vectors**: BLAKE3 (empty + multi-block XOF + split-invariance), SHA3/SHAKE vs independent oracle incl. rate boundaries.
- **Independent transcriptions**: big-int RFC 7748 (X25519 goldens), FIPS-203 (ML-KEM-768/512 full KATs), full-stack hybrid goldens (Python reference, both profiles).
- **Randomness, three ways**: in-tree NIST SP 800-22-style gate (8/8 seeds), independent `ent` over 2×32 MiB (entropy 7.99999, χ² p ≈ 31–36%), 200 KB no-lock soak.
- **Differential fuzzing**: libFuzzer + ASan, 4 targets, ~34 M execs total, zero crashes — see [FUZZING.md](FUZZING.md):

| Target | Property fuzzed | Execs (all-time) |
|---|---|---|
| `hash_split` | split absorb == one-shot digests/XOF | ~7.9 M |
| `shake_stream` | split absorb + streaming squeeze == one-shot | ~25.6 M |
| `mlkem_roundtrip` | roundtrip + determinism, no panics | ~281 k |
| `kem_roundtrip` | roundtrip + determinism, no panics | ~346 k |

  Corpus in `fuzz/corpus/`; `fuzz/artifacts/` empty (no crasher ever found).
- **Cross-arch execution**: NEON tiers proven under QEMU user-mode (freestanding hash + full m512-KAT harness, ALL PASS); i686 test binaries executed green.
- **Red-team audit v18**: subgroup confinement, adversarial-value sweeps, assert/index inventory, domain audit, timing smoke — findings R1–R6 in [THREAT.md](THREAT.md), consolidated in [REDTEAM.md](REDTEAM.md).

## Crate layout

```text
crates/
  chaos-burn      volatile secret wipe (audited unsafe #1)
  chaos-core      Q32.32 chaotic engine, RK4, health monitor
  chaos-hash      BLAKE3 + Keccak sponge
  chaos-simd      AVX2/SSE2/NEON kernels (audited unsafe, one justification shape)
  chaos-extract   masking filter + keystream
  chaos-kem       X25519 KEM + chaos tail (+ x25519.rs field arithmetic)
  chaos-mlkem     ML-KEM-768/512 (+ ntt.rs, codec.rs)
  chaos-hybrid    flagship + h512 combiners
  chaos-aead      DEM (seal/open, heapless variants)
  chaos-attack    red-team gates
  chaos-stat      randomness suite
  chaos-cli       ca-pq binary
fuzz/             libFuzzer targets (detached workspace) + seed corpus
```

## API sketch

```rust
// Flagship hybrid (deterministic: caller supplies seed, coins, nonce).
let (hsk, hpk) = chaos_hybrid::keygen(seed32);
let (hct, ss1) = chaos_hybrid::encaps(&hpk, coins32, nonce12)?;
let ss2 = chaos_hybrid::decaps(&hsk, &hpk, &hct)?;   // None iff X leg fails
assert_eq!(ss1, ss2);

// Level-1 sibling: same shape, smaller/faster.
let (hsk, hpk) = chaos_hybrid::h512::keygen(seed32);

// Raw PQ leg with server-side batching (element i == scalar encaps).
chaos_mlkem::encaps_batch(&ek, &ms, &mut cts, &mut sss);
```

## Documents

| Document | Contents |
|---|---|
| [WHITEPAPER.md](WHITEPAPER.md) ([papers/whitepaper.pdf](papers/whitepaper.pdf)) | Vision, architecture, security analysis, performance story |
| [YELLOWPAPER.md](YELLOWPAPER.md) ([papers/yellowpaper.pdf](papers/yellowpaper.pdf)) | Formal specification: parameters, equations, wire formats, domains |
| [THREAT.md](THREAT.md) | Threat model, claims, non-claims, red-team gates |
| [REDTEAM.md](REDTEAM.md) | Consolidated audit report R1–R6 + accepted residuals A1–A4 |
| [SPEC.md](SPEC.md) | Frozen parameters and flows (normative, code-adjacent) |
| [PLAN.md](PLAN.md) | Full build history v1–v21 with measurements and lessons |
| [CHANGELOG.md](CHANGELOG.md) | Release history (v2.0.0 current) |
| [FUZZING.md](FUZZING.md) | Differential fuzzing: targets, method, campaigns |

## SIMD tiers

Compile-time dispatch (no runtime CPU detection, `no_std`-safe):

| Primitive | AVX2 (x86-64 opt-in) | SSE2 (x86 baseline) | NEON (aarch64) | Portable |
|---|---|---|---|---|
| BLAKE3 compress | 8-way (~2.2 GiB/s) | 4-way (~1.5 GiB/s) | 4-way (QEMU-proven) | scalar (~0.8 GiB/s) |
| Keccak-f batch | 4-way | 2×2-way | 2×2-way (QEMU-proven) | 4× scalar |
| NTT family | 8-way + Barrett | scalar (rejected w/ numbers) | 4-wide (QEMU KAT-proven) | scalar + branchless mod |

`unsafe` lives only in `chaos-burn` (one wipe) and `chaos-simd` (register-only kernels); everything else is `forbid(unsafe_code)`.

## Contributing and audit

Issues and PRs welcome. What helps most, in order:

1. **External audit** — the single most valuable contribution. Start at [YELLOWPAPER.md](YELLOWPAPER.md) (spec), [THREAT.md](THREAT.md) (model), [REDTEAM.md](REDTEAM.md) (what self-review already covered).
2. Reproduction: `PLAN.md` build logs record exact methods, including the QEMU harness recipes.
3. Benchmarks on other hardware (report CPU + flags + ranges; runner variance is real).

## License

CA-PQ is free software under the **GNU General Public License v3.0 or later (GPLv3+)** — see [LICENSE](LICENSE). You may use, study, share, and modify it; derivatives must stay GPL-compatible.
