"""Build seed corpus for meowhash-pure fuzz harnesses.

Produces deterministic, reproducible seed files in fuzz/corpus/<surface>/.
Run from repo root: `python3 fuzz/_build_corpus.py`

All random samples use random.Random(0) so the corpus is byte-for-byte
reproducible across runs.

Surfaces:
  - meow64, meow128, state128, expand_seed, invariant21, determinism
"""
from __future__ import annotations

import json
import os
import random
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = REPO_ROOT / "fuzz" / "corpus"
TEST_VECTORS = REPO_ROOT / "tests" / "test_vectors.json"


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _build_boundary(name: str, size: int) -> bytes:
    """Generate a boundary-sized payload with a recognizable pattern.

    Uses an LCG-ish step so files differ at the byte level (0, 1, 2, ..., 255, 0, 1, ...).
    """
    return bytes(i & 0xFF for i in range(size))


def _build_test_vector_bytes(name: str) -> bytes:
    """Map a test_vectors.json `name` to the actual input payload bytes."""
    if name == "empty":
        return b""
    if name == "a":
        return b"a"
    if name == "abc":
        return b"abc"
    if name == "hello_world":
        return b"hello world"
    if name == "64bytes":
        return b"x" * 64
    if name == "65bytes":
        return b"x" * 65
    raise ValueError(f"unknown test vector name: {name}")


def build_meow64_corpus() -> int:
    """meow64 harness splits the first 8 bytes as a uint64 seed, the rest as data.

    For test vectors, prepend a zero seed (8 little-endian zero bytes) so the
    decoded seed=0 matches the documented test vector seed.
    For random samples, prepend a deterministic uint64 from random.Random(0).
    """
    rng = random.Random(0)
    out = CORPUS_ROOT / "meow64"
    count = 0

    # Test vectors with seed=0 (matches tests/test_vectors.json).
    vectors = json.loads(TEST_VECTORS.read_text())
    for v in vectors:
        body = _build_test_vector_bytes(v["name"])
        _write(out / f"seed_{v['name']}.bin", struct.pack("<Q", 0) + body)
        count += 1

    # Boundary cases: empty, 1B, 63B, 64B, 65B, 1024B, 1MB.
    boundaries = {
        "empty": 0,
        "one_byte": 1,
        "63_bytes": 63,
        "64_bytes": 64,
        "65_bytes": 65,
        "1024_bytes": 1024,
        "1MB": 1024 * 1024,
    }
    for label, size in boundaries.items():
        _write(out / f"{label}.bin", struct.pack("<Q", 0) + _build_boundary(label, size))
        count += 1

    # 100 random samples: 8-byte seed (from RNG) + variable-length body (from RNG).
    sizes = [0, 1, 2, 8, 16, 64, 128, 256, 512, 1024, 4096]
    for i in range(100):
        seed = rng.randint(0, (1 << 64) - 1)
        size = rng.choice(sizes)
        body = bytes(rng.getrandbits(8) for _ in range(size))
        _write(out / f"random_sample_{i:03d}.bin", struct.pack("<Q", seed) + body)
        count += 1

    return count


def build_meow128_corpus() -> int:
    """meow128 has the same input shape as meow64 (first 8 bytes = uint64 seed)."""
    rng = random.Random(0)
    out = CORPUS_ROOT / "meow128"
    count = 0

    vectors = json.loads(TEST_VECTORS.read_text())
    for v in vectors:
        body = _build_test_vector_bytes(v["name"])
        _write(out / f"seed_{v['name']}.bin", struct.pack("<Q", 0) + body)
        count += 1

    boundaries = {
        "empty": 0,
        "one_byte": 1,
        "63_bytes": 63,
        "64_bytes": 64,
        "65_bytes": 65,
        "1024_bytes": 1024,
        "1MB": 1024 * 1024,
    }
    for label, size in boundaries.items():
        _write(out / f"{label}.bin", struct.pack("<Q", 0) + _build_boundary(label, size))
        count += 1

    sizes = [0, 1, 2, 8, 16, 64, 128, 256, 512, 1024, 4096]
    for i in range(100):
        seed = rng.randint(0, (1 << 64) - 1)
        size = rng.choice(sizes)
        body = bytes(rng.getrandbits(8) for _ in range(size))
        _write(out / f"random_sample_{i:03d}.bin", struct.pack("<Q", seed) + body)
        count += 1

    return count


def build_state128_corpus() -> int:
    """State128 harness: first 8 bytes = uint64 seed, rest = data, with a chunked
    absorb path (4 chunks of 1, 7, 64, 128 bytes respectively)."""
    rng = random.Random(0)
    out = CORPUS_ROOT / "state128"
    count = 0

    vectors = json.loads(TEST_VECTORS.read_text())
    for v in vectors:
        body = _build_test_vector_bytes(v["name"])
        _write(out / f"seed_{v['name']}.bin", struct.pack("<Q", 0) + body)
        count += 1

    boundaries = {
        "empty": 0,
        "one_byte": 1,
        "63_bytes": 63,
        "64_bytes": 64,
        "65_bytes": 65,
        "1024_bytes": 1024,
    }
    for label, size in boundaries.items():
        _write(out / f"{label}.bin", struct.pack("<Q", 0) + _build_boundary(label, size))
        count += 1

    # Streaming variants: 64-byte payload split across N chunks.
    payload64 = _build_boundary("streaming", 64)
    for n in (2, 4, 8, 16):
        _write(out / f"multi_chunk_{n}.bin", struct.pack("<Q", 0) + payload64)
        count += 1
    _write(out / "single_chunk.bin", struct.pack("<Q", 0) + payload64)
    count += 1

    sizes = [0, 1, 8, 64, 128, 512, 1024]
    for i in range(100):
        seed = rng.randint(0, (1 << 64) - 1)
        size = rng.choice(sizes)
        body = bytes(rng.getrandbits(8) for _ in range(size))
        _write(out / f"random_sample_{i:03d}.bin", struct.pack("<Q", seed) + body)
        count += 1

    return count


def build_expand_seed_corpus() -> int:
    """expand_seed takes a single bytes key (no seed). Input is just the key bytes."""
    rng = random.Random(0)
    out = CORPUS_ROOT / "expand_seed"
    count = 0

    # Boundary keys: empty, 16, 32, 64, 1024.
    keys = {
        "empty": b"",
        "16_bytes": _build_boundary("16", 16),
        "32_bytes": _build_boundary("32", 32),
        "64_bytes": _build_boundary("64", 64),
        "1024_bytes": _build_boundary("1024", 1024),
    }
    for label, body in keys.items():
        _write(out / f"{label}.bin", body)
        count += 1

    # 100 random samples.
    for i in range(100):
        size = rng.choice([0, 1, 8, 16, 32, 64, 128, 256, 1024])
        body = bytes(rng.getrandbits(8) for _ in range(size))
        _write(out / f"random_sample_{i:03d}.bin", body)
        count += 1

    return count


def build_invariant21_corpus() -> int:
    """Invariant 21 isn't a byte-mutator surface; we still seed it with documented
    boundary text files that mirror the table-driven probe in invariant21_fuzz.py."""
    out = CORPUS_ROOT / "invariant21"
    count = 0

    # These are human-readable notes for the corpus README, not inputs to a
    # mutator harness. The actual probe uses inline literals in the source.
    cases = [
        ("none.txt", b"None"),
        ("int_42.txt", b"42"),
        ("str_hello.txt", b"hello"),
        ("float_3.14.txt", b"3.14"),
        ("seed_neg1.txt", b"-1"),
        ("seed_2pow64.txt", b"18446744073709551616"),
    ]
    for name, body in cases:
        _write(out / name, body)
        count += 1

    return count


def build_determinism_corpus() -> int:
    """1000 deterministic (data, seed) inputs via random.Random(0).

    Each file is the raw data bytes; the determinism test pairs each with a
    random uint64 seed drawn at runtime from the same RNG.
    """
    rng = random.Random(0)
    out = CORPUS_ROOT / "determinism"
    count = 0

    sizes = [0, 1, 2, 8, 64, 128, 256, 1024, 4096, 65536]
    for i in range(1000):
        size = rng.choice(sizes)
        data = bytes(rng.getrandbits(8) for _ in range(size))
        # 8-byte header = uint64 seed, rest = data (matches other harness shape).
        seed = rng.randint(0, (1 << 64) - 1)
        _write(out / f"det_{i:04d}.bin", struct.pack("<Q", seed) + data)
        count += 1

    return count


def main() -> None:
    counts = {
        "meow64":       build_meow64_corpus(),
        "meow128":      build_meow128_corpus(),
        "state128":     build_state128_corpus(),
        "expand_seed":  build_expand_seed_corpus(),
        "invariant21":  build_invariant21_corpus(),
        "determinism":  build_determinism_corpus(),
    }
    total = sum(counts.values())
    summary = {
        "corpus_root": str(CORPUS_ROOT.relative_to(REPO_ROOT)),
        "counts": counts,
        "total": total,
    }
    out = REPO_ROOT / "fuzz" / "corpus" / "summary.json"
    out.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"[corpus] {total} files written across {len(counts)} surfaces: {counts}")
    print(f"[corpus] summary -> {out.relative_to(REPO_ROOT)}")
    return None


if __name__ == "__main__":
    sys.exit(main() or 0)
