"""Fuzz harness for meowhash_pure.meow64.

Surface: meow64(data: bytes, seed: int = 0) -> int
Covers T1 audit surface #1 + Invariant 21 total-over-arbitrary-input contract.

TestOneInput(payload) splits the first 8 bytes as a uint64 seed and the rest as
data. Asserts: result is int in [0, 2**64), and that calling meow64 again with
the same (data, seed) returns the same value (determinism).
"""
from __future__ import annotations

import struct
import sys

# Bootstrap: install coverage hooks BEFORE importing the SUT.
from fuzz._harness_common import instrument, make_entry  # noqa: E402

instrument()


def _decode_seed(payload: bytes) -> tuple[int, bytes]:
    """Take up to 8 bytes from the front of payload as a uint64 seed.
    Deterministic: returns (0, payload[8:]) for payload shorter than 8 bytes."""
    if len(payload) < 8:
        return 0, payload
    seed = struct.unpack_from("<Q", payload, 0)[0]
    return seed, payload[8:]


def TestOneInput(data: bytes) -> None:
    """Single atheris iteration: deterministic split + property checks."""
    seed, body = _decode_seed(data)
    # Lazily import inside the function so coverage hooks are active.
    from meowhash_pure import meow64, MeowHashError  # type: ignore

    # First call.
    try:
        a = meow64(body, seed=seed)
    except MeowHashError:
        return  # Contract-documented rejection; not a finding.
    # Type/shape contract.
    assert isinstance(a, int), f"meow64 returned non-int: {type(a).__name__}"
    assert 0 <= a < (1 << 64), f"meow64 out of uint64 range: {a}"

    # Determinism: same input -> same output.
    b = meow64(body, seed=seed)
    assert a == b, f"meow64 non-deterministic: {a} != {b} for seed={seed}"


def main() -> None:
    """CLI entrypoint. Default 30s, --libfuzzer for native libFuzzer mode."""
    import meowhash_pure  # noqa: F401  (instrumented import)
    entry = make_entry(TestOneInput, seed=0xC0FFEE, default_duration=30.0)
    entry()


if __name__ == "__main__":
    main()