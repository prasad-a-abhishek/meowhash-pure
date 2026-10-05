"""Fuzz harness enforcing Invariant 21 (total-over-arbitrary-input).

Surfaces covered: meow64, meow128, State128, expand_seed, _seed_bytes.

This is NOT a libFuzzer-style byte-mutator harness. It's an explicit,
table-driven probe that walks the documented rejection contract:

  None, "", b"", non-bytes (str/list/dict/int/float/bool/None), oversized
  (5MB), invalid seed (-1, 2**64, -2**63), boundary data lengths
  (0, 1, 63, 64, 65, 1023, 1024, 1025).

The contract: every entry must either return a structurally-valid result or
raise MeowHashError. Anything else is a real finding (uncaught TypeError,
ValueError, OverflowError, AttributeError, etc.).
"""
from __future__ import annotations

import sys
from typing import Any

from fuzz._harness_common import instrument  # noqa: E402

instrument()


# Each row: (label, surface_callable_factory, payload_arg, seed_arg)
# Some surfaces don't take a seed (expand_seed), some take only seed (_seed_bytes).
_NON_BYTES_VALUES: list[tuple[str, Any]] = [
    ("None",  None),
    ("str",   "hello"),
    ("list",  [1, 2, 3]),
    ("dict",  {"a": 1}),
    ("int",   42),
    ("float", 3.14),
    ("bool_t", True),
    ("bool_f", False),
]
_BOUNDARY_LENGTHS: list[int] = [0, 1, 63, 64, 65, 1023, 1024, 1025]
_INVALID_SEEDS: list[int] = [-1, 1 << 64, -(1 << 63)]


def _check(label: str, fn) -> None:
    """Invoke fn() and assert the only acceptable outcome is MeowHashError or
    a structurally-valid result."""
    from meowhash_pure import MeowHashError  # type: ignore
    try:
        result = fn()
    except MeowHashError:
        return  # Contractually documented rejection — not a finding.
    except Exception as e:  # noqa: BLE001
        # Uncaught non-MeowHashError is the finding Invariant 21 forbids.
        raise AssertionError(
            f"[Invariant21] UNCAUGHT in {label}: {type(e).__name__}: {e}"
        ) from e
    # If we got a result, do a coarse shape check based on the function name.
    name = fn.__name__ if hasattr(fn, "__name__") else str(fn)
    if name in ("<lambda>_meow64",) or "meow64(" in label:
        assert isinstance(result, int) and 0 <= result < (1 << 64), (
            f"[Invariant21] meow64 shape violated in {label}: {result!r}"
        )
    elif "meow128(" in label:
        assert isinstance(result, tuple) and len(result) == 2, (
            f"[Invariant21] meow128 arity violated in {label}: {result!r}"
        )
        lo, hi = result
        assert isinstance(lo, int) and 0 <= lo < (1 << 64), (
            f"[Invariant21] meow128[0] shape violated in {label}: {lo!r}"
        )
        assert isinstance(hi, int) and 0 <= hi < (1 << 64), (
            f"[Invariant21] meow128[1] shape violated in {label}: {hi!r}"
        )
    elif "expand_seed(" in label:
        assert isinstance(result, bytes) and len(result) == 128, (
            f"[Invariant21] expand_seed shape violated in {label}: "
            f"{type(result).__name__} len={len(result) if hasattr(result, '__len__') else '?'}"
        )


def main() -> None:
    import meowhash_pure  # noqa: F401
    from meowhash_pure import (  # type: ignore
        meow64, meow128, State128, expand_seed, _seed_bytes,
    )

    failures = 0
    cases = 0

    # --- non-bytes data on bytes-typed surfaces ---
    for label, val in _NON_BYTES_VALUES:
        cases += 1
        try:
            _check(f"meow64({label})", lambda v=val: meow64(v, seed=0))
        except AssertionError:
            failures += 1
            raise
        cases += 1
        try:
            _check(f"meow128({label})", lambda v=val: meow128(v, seed=0))
        except AssertionError:
            failures += 1
            raise
        cases += 1
        try:
            _check(
                f"expand_seed({label})",
                lambda v=val: expand_seed(v),
            )
        except AssertionError:
            failures += 1
            raise

    # --- oversized (5MB) on meow64 / meow128 ---
    big = b"\x00" * (5 * 1024 * 1024)
    cases += 1
    try:
        _check("meow64(5MB)", lambda: meow64(big, seed=0))
    except AssertionError:
        failures += 1
        raise
    cases += 1
    try:
        _check("meow128(5MB)", lambda: meow128(big, seed=0))
    except AssertionError:
        failures += 1
        raise

    # --- invalid seeds on surfaces that take a seed ---
    for s in _INVALID_SEEDS:
        for surf_name, call in (
            ("meow64", lambda s=s: meow64(b"x", seed=s)),
            ("meow128", lambda s=s: meow128(b"x", seed=s)),
        ):
            cases += 1
            try:
                _check(f"{surf_name}(seed={s})", call)
            except AssertionError:
                failures += 1
                raise
        # State128 also takes a seed in __init__.
        cases += 1
        try:
            _check(f"State128(seed={s})", lambda s=s: State128(seed=s))
        except AssertionError:
            failures += 1
            raise

    # --- boundary data lengths (b"") ---
    for ln in _BOUNDARY_LENGTHS:
        body = b"\x00" * ln
        cases += 1
        try:
            _check(f"meow64(len={ln})", lambda b=body: meow64(b, seed=0))
        except AssertionError:
            failures += 1
            raise
        cases += 1
        try:
            _check(f"meow128(len={ln})", lambda b=body: meow128(b, seed=0))
        except AssertionError:
            failures += 1
            raise

    # --- _seed_bytes direct: invalid seed & invalid size ---
    cases += 1
    try:
        # size=0 must be accepted (bytearray(0).digest() loop doesn't run).
        _check("_seed_bytes(0, 0)", lambda: _seed_bytes(0, 0))
    except AssertionError:
        failures += 1
        raise
    cases += 1
    try:
        # size=-1 must produce a MeowHashError or a clear rejection.
        _check("_seed_bytes(0, -1)", lambda: _seed_bytes(0, -1))
    except AssertionError:
        failures += 1
        raise
    cases += 1
    try:
        # seed=-1 must produce a MeowHashError (F-005 documented leak).
        _check("_seed_bytes(-1, 16)", lambda: _seed_bytes(-1, 16))
    except AssertionError:
        failures += 1
        raise

    # --- State128.absorb with non-bytes ---
    for label, val in _NON_BYTES_VALUES:
        cases += 1
        try:
            def _absorb_non_bytes(v=val):
                fresh = State128(seed=0)
                fresh.absorb(v)
                return None
            _check(f"State128.absorb({label})", _absorb_non_bytes)
        except AssertionError:
            failures += 1
            raise

    print(f"[invariant21] {cases} cases, {failures} uncaught — PASS",
          file=sys.stderr)
    if failures > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()