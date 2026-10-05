"""Determinism property test for all hash entrypoints.

Drives 1000 random (data, seed) inputs through a fixed RNG (random.Random(0)),
then re-hashes it. Each pair must produce identical outputs.

Surfaces covered: meow64, meow128, State128, expand_seed.

This is NOT a libFuzzer-style mutator harness — it's a deterministic property
test. Invariant 21's MeowHashError branch is allowed (e.g. bool seed); we
simply require that whatever a surface returns is reproducible.
"""
from __future__ import annotations

import random
import sys
from typing import Tuple

from fuzz._harness_common import instrument  # noqa: E402

instrument()


def main() -> None:
    import meowhash_pure  # noqa: F401
    from meowhash_pure import meow64, meow128, State128, expand_seed  # type: ignore

    rng = random.Random(0)
    N = 1000
    seed_max = 1 << 64  # inclusive [0, 2**64)

    mismatches = 0
    cases_run = 0
    cases_skipped = 0

    for i in range(N):
        # Mix of empty, medium, large payloads.
        size = rng.choice([0, 1, 2, 8, 64, 128, 256, 1024, 4096, 65536])
        data = bytes(rng.getrandbits(8) for _ in range(size))
        # Mostly valid uint64, but include some that should be rejected
        # so we exercise both branches.
        seed = rng.randint(-2, seed_max + 1)

        cases_run += 1
        # meow64 determinism
        from meowhash_pure import MeowHashError  # type: ignore
        try:
            a = meow64(data, seed=seed)
            b = meow64(data, seed=seed)
            if a != b:
                mismatches += 1
                print(f"[det] meow64 mismatch @ {i}: seed={seed} size={size}",
                      file=sys.stderr)
        except MeowHashError:
            cases_skipped += 1

        cases_run += 1
        # meow128 determinism
        try:
            a = meow128(data, seed=seed)
            b = meow128(data, seed=seed)
            if a != b:
                mismatches += 1
                print(f"[det] meow128 mismatch @ {i}: seed={seed} size={size}",
                      file=sys.stderr)
        except MeowHashError:
            cases_skipped += 1

        cases_run += 1
        # State128 determinism: streamed == single-shot meow64 on concat.
        try:
            st = State128(seed=seed)
            # Split data into a few chunks.
            chunks = []
            cursor = 0
            while cursor < len(data):
                cl = rng.choice([1, 7, 64, 128])
                chunks.append(data[cursor:cursor + cl])
                cursor += cl
            for ch in chunks:
                st.absorb(ch)
            streamed = st.finalize()
            single = meow64(data, seed=seed)
            if streamed != single:
                mismatches += 1
                print(
                    f"[det] State128 streaming mismatch @ {i}: "
                    f"streamed={streamed} single={single} seed={seed} "
                    f"size={size} chunks={len(chunks)}",
                    file=sys.stderr,
                )
        except MeowHashError:
            cases_skipped += 1

        cases_run += 1
        # expand_seed determinism — seed is the key, no separate seed arg.
        try:
            a = expand_seed(data)
            b = expand_seed(data)
            if a != b:
                mismatches += 1
                print(f"[det] expand_seed mismatch @ {i}: size={size}",
                      file=sys.stderr)
        except MeowHashError:
            cases_skipped += 1

    print(
        f"[det] {cases_run} cases, {cases_skipped} contracted rejections, "
        f"{mismatches} mismatches — "
        + ("PASS" if mismatches == 0 else "FAIL"),
        file=sys.stderr,
    )
    if mismatches > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()