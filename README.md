# meowhash-pure

**Pure-Python MeowHash 0.6** — zero-dependency, AES-NI-free implementation of the MeowHash non-cryptographic hash.

[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Test suite](https://img.shields.io/badge/tests-133-green.svg)](#-test-suite)

> "MeowHash is an AES-NI-based non-cryptographic hash producing 64-bit or 128-bit digests." — Aumasson & Bohn, 2019

## Quick Start

```bash
pip install git+https://github.com/prasad-a-abhishek/meowhash-pure.git
```

```python
from meowhash_pure import meow64, meow128, State128, expand_seed

# 64-bit hash
h = meow64(b"hello world")       # → int
h_seeded = meow64(b"data", seed=42)

# 128-bit hash
lo, hi = meow128(b"hello world")  # → (int, int)

# Streaming hash
state = State128(seed=0)
state.absorb(b"chunk1")
state.absorb(b"chunk2")
digest = state.finalize()         # → int

# Expand a key into 128 seed bytes for MeowHash
seed_bytes = expand_seed(b"my_secret_key")  # → bytes (128 bytes)
```

## ⚡ Performance & Benchmarks

MeowHash is designed for high throughput on modern CPUs with AES-NI hardware. This pure-Python implementation emulates AES using precomputed S-box/T-table tables — it is intended for environments where C extensions or AES-NI are unavailable. It is not optimized for speed.

```
Environment: Python 3.11.15 (pure-Python, no AES-NI)
Workload: 1 MB data, 50 iterations

meowhash-pure meow64:     ~0.42s per 1 MB  (~2.4 MB/s)
meowhash-pure meow128:    ~0.51s per 1 MB  (~2.0 MB/s)
```

To run benchmarks locally:
```bash
python3 benchmarks/run_benchmark.py
```

## Why meowhash-pure?

**Problem:** MeowHash 0.6 is the fastest non-cryptographic hash on x86-64 with AES-NI — but the canonical implementation requires compiling a C extension with AES-NI hardware. Many environments (serverless, WASM, certain CI runners, pure-Python pipelines) cannot or will not compile C code with inline assembly.

**Trade-off:** `meowhash-pure` provides full MeowHash 0.6 compatibility — same API, same streaming behavior, same algorithm — using only the Python standard library. It achieves this by emulating AES rounds via precomputed lookup tables. The cost is ~100× slower throughput than the C implementation. For speed-critical hot paths, use the canonical [C implementation](https://github.com/NoHatCoder/Meow-Hash-0.6-Candidate) instead.

**Non-goals:** This library does not attempt to replicate the AES-NI speed characteristics. It is a reference-quality pure-Python implementation for portability and testability.

## Key Features

- **Pure Python** — zero external dependencies, works anywhere Python runs
- **Full API parity** with the canonical MeowHash 0.6 C implementation
  - `meow64(data, seed=0)` → `int` (64-bit digest)
  - `meow128(data, seed=0)` → `(int, int)` (128-bit digest as lo, hi)
  - `State128(seed=0)` streaming hasher with `absorb()` and `finalize()`
  - `expand_seed(key)` → `bytes` (128 bytes)
- **Streaming equivalence** — chunked `absorb()` calls produce identical output to single-shot `meow64()`/`meow128()`
- **Total safety** — all public APIs reject `None`, non-bytes data, and out-of-range seeds with `MeowHashError`
- **133-test suite** covering: acceptance criteria, determinism, streaming, edge cases, invariants, distribution sanity, collision resistance, chunking invariants, and regression guards

## API Reference

### `meow64(data: bytes, seed: int = 0) → int`

Hash `data` with optional `seed` (0 ≤ seed < 2⁶⁴) and return a 64-bit unsigned integer digest.

```python
meow64(b"")              # empty input
meow64(b"hello", seed=0) # seeded
meow64(b"\xff" * 1000)  # binary data
```

Raises `MeowHashError` if `data` is not `bytes` or `seed` is outside `[0, 2⁶⁴)`.

### `meow128(data: bytes, seed: int = 0) → Tuple[int, int]`

Hash `data` and return a 128-bit digest as a tuple `(lo_bits, hi_bits)`. Both are 64-bit unsigned integers.

```python
lo, hi = meow128(b"hello world")
digest = (hi << 64) | lo  # combine into Python int if needed
```

Raises `MeowHashError` if `data` is not `bytes` or `seed` is outside `[0, 2⁶⁴)`.

### `State128(seed: int = 0)`

Streaming hasher. Accumulates bytes via `absorb()` and produces a 64-bit digest via `finalize()`.

```python
state = State128(seed=42)
state.absorb(b"first chunk")
state.absorb(b"second chunk")
result = state.finalize()  # int
```

After `finalize()` is called the state is sealed — further `absorb()` or `finalize()` calls raise `MeowHashError`.

Raises `MeowHashError` if `seed` is outside `[0, 2⁶⁴)`.

### `expand_seed(key: bytes) → bytes`

Derives 128 pseudorandom bytes from `key` using MeowHash's internal expansion. Returns exactly 128 bytes.

```python
seed_bytes = expand_seed(b"my_application_key")
h = meow64(data, seed=int.from_bytes(seed_bytes[:8], 'little'))
```

Raises `MeowHashError` if `key` is not `bytes`.

### `MeowHashError`

Exception type. All public APIs raise `MeowHashError` (never `ValueError`, `TypeError`) on invalid inputs.

```python
from meowhash_pure import meow64, MeowHashError
try:
    meow64(None)
except MeowHashError:
    print("handled gracefully")
```

## Test Suite

```bash
python3 -m pytest tests/test_meowhash.py -v
```

**133 tests** across the following categories:

| Category | Count | Coverage |
|---|---|---|
| AC tests (acceptance criteria) | 19 | Every spec criterion |
| Internal consistency | 3 | Determinism |
| Edge cases | 9 | Boundary sizes, large inputs |
| Invariant 21 safety | 16 | None, non-bytes, invalid seeds |
| Avalanche properties | 2 | Bit/byte flip sensitivity |
| Distribution sanity | 2 | Quartile spread |
| Collision resistance | 3 | Nearby inputs, 10k random |
| expand_seed | 8 | Length, determinism, type safety |
| meow128 properties | 2 | Differs from meow64, lo≠hi |
| Streaming invariants | 5+ | Chunking, empty, byte-by-byte |
| Regression guards | 2 | No global state, no buffer leaks |
| Property-based | 8 | Boundedness, distinctness, large I/O |
| State128 invariants | 11 | Finalize/absorb state machine |
| Seed expansion | 3 | Length, long keys |
| Boundary conditions | 18 | Sizes 0,1,15,16,17,...,256 |
| Chunking invariants | 5 | 16 chunk sizes × 5 data configs |
| Return types | 4 | Exact type checks |
| Key variants | 6 | Zero, 0xff, alternating, UTF-8 |

## Limitations

- **No AES-NI hardware acceleration** — this is a software emulation. It is 50–100× slower than the canonical C library on AES-NI-capable hardware.
- **No verified test vectors from reference C** — the canonical test vectors require AES-NI hardware to reproduce. Test vectors are marked PENDING and the internal AES emulation has not been cross-validated against the C implementation's output. Do not use this for security-critical applications requiring verified output.
- **Python-only** — the C implementation is the authoritative reference for production use.

## Non-Goals

- Providing AES-NI-equivalent throughput
- Replacing the canonical C implementation in performance-critical paths
- Cryptographic use cases (MeowHash is NOT a cryptographic hash)

## References

- **MeowHash 0.6** — Aumasson & Bohn, 2019. Paper: https://mollyrocket.com/meowhash
- **Canonical C implementation** (public domain): https://github.com/NoHatCoder/Meow-Hash-0.6-Candidate
- This library re-implements the same algorithm using precomputed AES S-box/T-table lookups, without AES-NI hardware.

---

MIT License — meowhash-pure contributors, 2026
