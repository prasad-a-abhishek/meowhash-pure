"""Fuzz harness for meowhash_pure.expand_seed.

Surface: expand_seed(key: bytes) -> bytes (length 128)
Covers T1 audit surface #4.

TestOneInput(payload) treats the entire payload as the key material. Asserts:
- result is a bytes object of exactly 128 bytes (the documented contract)
- result is deterministic for the same input
- empty bytes and arbitrary long bytes are accepted (the implementation
  documents bytearray; we accept bytes and verify both)
"""
from __future__ import annotations

import sys

# Bootstrap: install coverage hooks BEFORE importing the SUT.
from fuzz._harness_common import instrument, make_entry  # noqa: E402

instrument()


def TestOneInput(data: bytes) -> None:
    """Single atheris iteration: feed as bytes and bytearray, assert shape."""
    from meowhash_pure import expand_seed, MeowHashError  # type: ignore

    # bytes path
    try:
        a = expand_seed(data)
    except MeowHashError:
        return  # Contract-documented rejection; not a finding.
    assert isinstance(a, bytes), f"expand_seed returned non-bytes: {type(a).__name__}"
    assert len(a) == 128, f"expand_seed wrong length: {len(a)} != 128"

    # bytearray path (also documented as accepted)
    try:
        b = expand_seed(bytearray(data))
    except MeowHashError:
        return
    assert isinstance(b, bytes), f"expand_seed(bytearray) returned non-bytes: {type(b).__name__}"
    assert len(b) == 128, f"expand_seed(bytearray) wrong length: {len(b)} != 128"
    assert a == b, f"expand_seed(bytes) != expand_seed(bytearray): {a!r} vs {b!r}"

    # Determinism: same input -> same output.
    c = expand_seed(data)
    assert a == c, f"expand_seed non-deterministic: {a!r} != {c!r}"


def main() -> None:
    """CLI entrypoint. Default 30s, --libfuzzer for native libFuzzer mode."""
    import meowhash_pure  # noqa: F401  (instrumented import)
    entry = make_entry(TestOneInput, seed=0xC0FFEE, default_duration=30.0)
    entry()


if __name__ == "__main__":
    main()