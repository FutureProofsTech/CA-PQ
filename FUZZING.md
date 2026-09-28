# CA-PQ Fuzzing Document

Differential fuzzing with libFuzzer + AddressSanitizer: what runs, what each target proves, how to reproduce, and what the campaigns found. Complements the unit/KAT suites (exact vectors) and the red-team audit ([REDTEAM.md](REDTEAM.md)) with randomized differential pressure plus memory-safety instrumentation.

## Setup

- Toolchain: **nightly** Rust + `cargo-fuzz 0.13.x` (`libfuzzer-sys 0.4`).
- Sanitizer: **AddressSanitizer** (`--sanitizer address`) on every run — catches OOB reads/writes, use-after-free, overflows that assertions would miss.
- Layout: `fuzz/` is a **detached workspace** (`ca-pq-fuzz`, `publish = false`) so the main `Cargo.lock` stays dependency-free. It path-depends on `chaos-core`, `chaos-hash`, `chaos-mlkem`, `chaos-kem` only.
- Quirk: libFuzzer chokes on the space in this workspace's path — fuzz from a **space-free tree copy**:
  ```sh
  cp -r crates Cargo.toml Cargo.lock fuzz /tmp/fuzzrun/
  cd /tmp/fuzzrun/fuzz
  cargo +nightly fuzz run <target> --sanitizer address -- -max_total_time=60
  ```
- Seed corpus: `fuzz/corpus/<target>/` (committed). Crashers would land in `fuzz/artifacts/<target>/` — **all empty** (no crash has ever been found).

## Targets and the properties they pin

| Target | Input (capped) | Property asserted |
|---|---|---|
| `hash_split` | ≤ 4096 B | Incremental absorb splits == one-shot digest (plain, 3 chunkings); keyed finalize == `blake3_keyed`; XOF prefix consistency |
| `shake_stream` | ≤ 2048 B | Odd-split absorbs + chunked streaming squeeze == one-shot `shake128` |
| `mlkem_roundtrip` | ≥ 96 B (`d‖z‖m`) | `decaps(encaps) == ss`; ct/ss deterministic across calls |
| `kem_roundtrip` | ≥ 76 B (`seed‖eph‖nonce`) | `decaps(encaps) == ss` (unless contributory `None`); ct/ss deterministic |

Notes on scope: the KEM targets fuzz **honest flows** (roundtrip + determinism + no-panic under ASan). Adversarial *tamper* behavior (bit flips, wrong keys, zero points, all-`0xFF` values) is covered by deterministic unit tests instead (see REDTEAM.md R2–R4) — fuzzing random mutations would almost never produce a *valid* tag/ct to exercise the accept path. No targets yet for `m512`, hybrids, or AEAD (roadmap below).

## Results

### Historical campaign (PLAN build log v9, this machine)

~25 M execs total, zero crashes, zero ASan reports:

| Target | Execs |
|---|---|
| `hash_split` | ~5.6 M |
| `shake_stream` | ~19 M |
| `mlkem_roundtrip` | ~220 k |
| `kem_roundtrip` | ~276 k |

### Fresh confirmation campaign (v2.0.0 tree, i5-14400F, ASan)

| Target | Execs | Time | Rate | Verdict |
|---|---|---|---|---|
| `hash_split` | 2 280 240 | 60 s | ~37 k/s | DONE, clean |
| `shake_stream` | 6 615 706 | 60 s | ~108 k/s | DONE, clean |
| `mlkem_roundtrip` | 61 334 | 90 s | ~674/s | DONE, clean |
| `kem_roundtrip` | 70 304 | 90 s | ~772/s | DONE, clean |

~9 M further execs, zero crashes, zero panics, zero sanitizer reports. Corpus grew (new coverage units merged into `fuzz/corpus/` in the run copy).

## Interpreting results (honestly)

- **What this proves**: no panics, no memory unsafety, and differential self-consistency (split == one-shot, roundtrip, determinism) across ~34 M randomized inputs on the covered paths.
- **What it does not prove**: acceptance of *malicious* inputs (covered by unit tests), cryptographic strength (covered by KATs/vectors/analysis), or absence of bugs on unfuzzed paths (512 profile, hybrids, AEAD, SIMD kernels — covered by differentials + KATs instead).
- Coverage counters (`cov`/`ft` in DONE lines) rise across runs; the corpus files are the regression asset — `cargo test` does not replay them (libFuzzer-format), so keep them committed.

## Roadmap

1. Add `hybrid_roundtrip` + `aead_tamper` targets (deterministic-acceptance + tag-forgery resistance under mutation).
2. Add an `m512` leg to `mlkem_roundtrip` (or a dedicated target).
3. Longer campaigns before each major release (overnight KEM runs; hash targets saturate fast).
4. Keep `fuzz/artifacts/` empty — any crasher file appearing here is a P0 bug: minimize, add as unit test, fix, document in THREAT.md.
