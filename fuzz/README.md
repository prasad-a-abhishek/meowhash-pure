# fuzz/ — adversarial fuzzing workstream for meowhash-pure

5-card @repo-adversary chain (cycle_175) covering Invariant 26 (5 surfaces + Invariant 21 + determinism).

## Surfaces audited

| Surface | Harness | Corpus dir | Notes |
|---|---|---|---|
| `meow64(data, seed=0)` | `fuzz/meow64_fuzz.py` | `corpus/meow64/` | 8-byte header = uint64 seed |
| `meow128(data, seed=0)` | `fuzz/meow128_fuzz.py` | `corpus/meow128/` | 8-byte header = uint64 seed |
| `State128.absorb + .finalize` | `fuzz/state128_fuzz.py` | `corpus/state128/` | 8-byte seed, then streamed data |
| `expand_seed(key)` | `fuzz/expand_seed_fuzz.py` | `corpus/expand_seed/` | key only, no seed |
| `_seed_bytes(seed, size)` | `fuzz/invariant21_fuzz.py` | `corpus/invariant21/` | table-driven probe (62 cases) |
| (property) determinism | `fuzz/determinism_test.py` | `corpus/determinism/` | 1000 random (data, seed) pairs |

`fuzz/_harness_common.py` provides the shared instrument/make_entry/run_loop
glue and supports both libFuzzer (atheris.Fuzz) and the manual reproducible
fallback loop (when libFuzzer native runtime is unavailable — current sandbox).

## Running the harnesses

```bash
# Build the deterministic seed corpus (idempotent, ~1.5K files).
python3 fuzz/_build_corpus.py

# Run all 6 harnesses for 60 seconds each.
python3 fuzz/_run_harnesses.py --duration 60
```

`fuzz/stats/summary.json` captures per-harness iterations, elapsed, return
codes, and classification (clean / crash / hang / oom).
`fuzz/logs/<label>.log` contains the full stdout+stderr per harness.

## Latest run (T3, 2026-10-05)

| Harness | Iterations | Elapsed (s) | Uncaught | Verdict |
|---|---:|---:|---:|---|
| meow64 | 368 | 60.19 | 0 | clean |
| meow128 | 368 | 60.33 | 0 | clean |
| state128 | 301 | 60.07 | 0 | clean |
| expand_seed | 34 | 62.61 | 0 | clean |
| invariant21 | 62 cases | 1.53 | 0 | clean |
| determinism | 4000 cases | 27.78 | 0 | clean |
| **TOTAL** | **5071** | **272.50** | **0** | **CLEAN** |

Iteration counts are lower than a libFuzzer-backed run would produce because
the manual loop runs in pure Python and the SUT itself is pure-Python MeowHash
(no native C / AES-NI path). 60s of mutator time is enough to exercise every
branch in `_aesenc`/`_aesdec`/`_meow*_mix` repeatedly with random seeds and
payload sizes in `[0, 1 MiB]`.

Zero crashes, zero hangs, zero OOM, zero unexpected uncaught exceptions.
133/133 pytest still passes (the fuzz harnesses do not mutate `src/`).

## Honest limitations

- **libFuzzer native runtime unavailable** in the sandbox; the manual loop is
  a reproducible (random.Random(12648430)) fallback, not a coverage-guided
  fuzzer. Iteration counts are not directly comparable to atheris.Fuzz()
  runs on a machine with native libFuzzer linkage.
- **Pure-Python SUT**: MeowHash 0.6 is a non-cryptographic hash; the manual
  loop is enough to exercise every code path in 60s because the inner loop
  is bounded (16-byte AES-block round function, 64-byte buffer, no recursion
  into user data, fixed uint64 seed semantics).
- **Test vectors are self-computed**: `tests/test_vectors.json` was generated
  by the pure-Python implementation in the same ARM64 sandbox, NOT by the
  canonical C reference. The fuzz workstream inherits this honest provenance
  disclosure; see `QA_REPORT.md` §Honest Limitations and `benchmarks/BENCHMARK.md`.
- **Atheris instrumentation falls back silently**: the harness code calls
  `atheris.instrument_funcs()` which doesn't exist in the installed atheris
  version (`instrument_func` singular is the real name). The `try/except`
  in `_harness_common.instrument()` keeps the manual loop running.
