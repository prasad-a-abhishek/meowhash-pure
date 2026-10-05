"""Fuzz harness for meowhash_pure.meow128.

Surface: meow128(data: bytes, seed: int = 0) -> tuple[int, int]
Covers T1 audit surface #2 + Invariant 21 total-over-arbitrary-input contract.

TestOneInput splits payload into (seed: uint64, data: rest). Asserts the
result is a 2-tuple of ints in [0, 2**64) and that the function is deterministic.
"""
from __future__ import annotations

import struct
import sys

from fuzz._harness_common import instrument, make_entry  # noqa: E402

instrument()


def _decode_seed(payload: bytes) -> tuple[int, bytes]:
    if len(payload) < 8:
        return 0, payload
    seed = struct.unpack_from("<Q", payload, 0)[0]
    return seed, payload[8:]


def TestOneInput(data: bytes) -> None:
    """Single atheris iteration: split + shape + determinism checks."""
    seed, body = _decode_seed(data)
    from meowhash_pure import meow128, MeowHashError  # type: ignore

    try:
        a = meow128(body, seed=seed)
    except MeowHashError:
        return
    assert isinstance(a, tuple), f"meow128 returned non-tuple: {type(a).__name__}"
    assert len(a) == 2, f"meow128 tuple wrong arity: {len(a)}"
    lo, hi = a
    assert isinstance(lo, int), f"meow128[0] non-int: {type(lo).__name__}"
    assert isinstance(hi, int), f"meow128[1] non-int: {type(hi).__name__}"
    assert 0 <= lo < (1 << 64), f"meow128[0] out of uint64: {lo}"
    assert 0 <= hi < (1 << 64), f"meow128[1] out of uint64: {hi}"

    b = meow128(body, seed=seed)
    assert a == b, f"meow128 non-deterministic: {a} != {b} for seed={seed}"


def main() -> None:
    import meowhash_pure  # noqa: F401
    entry = make_entry(TestOneInput, seed=0xC0FFEE, default_duration=30.0)
    entry()


if __name__ == "__main__":
    main()