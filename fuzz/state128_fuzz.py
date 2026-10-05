"""Fuzz harness for meowhash_pure.State128 streaming.

Surface: State128(seed=0) -> .absorb(bytes) -> .finalize() -> int
Covers T1 audit surface #3.

TestOneInput splits the payload into chunks (separated by 0xFF byte markers)
and feeds each chunk to .absorb() on a fresh state. Asserts:
- finalize() returns an int in [0, 2**64)
- Streaming absorption equals single-shot meow64 on the concatenated input
  (this is the algorithmic streaming-equivalence property).
- finalize() called twice raises MeowHashError (documented contract).
"""
from __future__ import annotations

import struct
import sys

from fuzz._harness_common import instrument, make_entry  # noqa: E402

instrument()


def _chunks(payload: bytes, max_splits: int = 32) -> list[bytes]:
    """Split payload at 0xFF byte markers (a la FuzzedDataProvider).

    Each non-marker byte becomes part of the current chunk; every 0xFF starts
    a new chunk AND is preserved as the FIRST byte of the new chunk (so the
    concatenation of chunks exactly equals the input payload — a critical
    invariant for the streaming-equals-single-shot property test).

    The last (possibly empty) chunk is always included.
    """
    out = []
    cur = bytearray()
    splits = 0
    for b in payload:
        if b == 0xFF and splits < max_splits:
            # Close current chunk; 0xFF becomes the first byte of the next chunk.
            out.append(bytes(cur))
            cur = bytearray([0xFF])
            splits += 1
        else:
            cur.append(b)
    out.append(bytes(cur))
    return out


def TestOneInput(data: bytes) -> None:
    """Stream arbitrary bytes through State128 and check single-shot equivalence."""
    seed, body = (struct.unpack_from("<Q", data, 0)[0], data[8:]) if len(data) >= 8 else (0, data)
    from meowhash_pure import State128, MeowHashError, meow64  # type: ignore

    state = State128(seed=seed)
    parts = _chunks(body)
    for chunk in parts:
        try:
            state.absorb(chunk)
        except MeowHashError:
            return  # Contracted rejection.
    try:
        streamed = state.finalize()
    except MeowHashError:
        return
    assert isinstance(streamed, int), f"finalize returned non-int: {type(streamed).__name__}"
    assert 0 <= streamed < (1 << 64), f"finalize out of uint64: {streamed}"

    # Property: streamed == single-shot on the concatenation.
    single = meow64(body, seed=seed)
    assert streamed == single, (
        f"streaming != single-shot: streamed={streamed} single={single} "
        f"seed={seed} body_len={len(body)} chunks={len(parts)}"
    )

    # Contract: finalize() twice raises MeowHashError.
    try:
        state.finalize()
        raise AssertionError("finalize() second call did NOT raise MeowHashError")
    except MeowHashError:
        pass


def main() -> None:
    import meowhash_pure  # noqa: F401
    entry = make_entry(TestOneInput, seed=0xC0FFEE, default_duration=30.0)
    entry()


if __name__ == "__main__":
    main()