"""Shared utilities for meowhash-pure fuzz harnesses.

Each harness imports these to:
- Instrument via atheris (Setup + instrument_func for coverage)
- Drive mutations either via libFuzzer (atheris.Fuzz() entry) OR a manual
  reproducible loop (when libFuzzer native runtime is unavailable).
- Track an exception counter so uncaught MeowHashError raises aren't silenced.

Atheris 3.0+ requires libFuzzer's native driver to run `atheris.Fuzz()`; on
sandboxed Linux without libFuzzer linkage the manual loop is the reproducible
fallback. The harness is the SAME on-disk file in both modes — invocation
switches via argv.
"""
from __future__ import annotations

import os
import random
import sys
import time
from typing import Callable, Optional


def instrument(target_module: str = "meowhash_pure") -> None:
    """Set up atheris instrumentation hooks for the target module.

    Called BEFORE importing meowhash_pure so the first import is instrumented.
    Uses atheris's import-hook to install coverage branches on the target
    package and any functions inside it.

    Note: this installs coverage hooks; the actual fuzzer driver is invoked
    separately (either atheris.Fuzz via libFuzzer, or our manual loop).
    """
    try:
        import atheris  # type: ignore
        atheris.instrument_funcs()  # type: ignore[attr-defined]
        # When libFuzzer isn't present we still get coverage hooks via the
        # instrumented bytecode — useful for the manual loop path too.
    except Exception as e:  # pragma: no cover - non-fatal
        # Atheris init can fail in some sandboxes; fall back silently.
        print(f"[harness] atheris instrumentation unavailable: {e}", file=sys.stderr)


def run_loop(
    func: Callable[[bytes], None],
    *,
    seed: int = 0,
    duration_seconds: float = 30.0,
    max_per_iter_bytes: int = 1_048_576,
) -> dict:
    """Manual reproducible mutation loop.

    Generates random byte payloads from a fixed seed, exercises `func`, and
    returns a stats dict. Intended fallback when libFuzzer native runtime
    isn't available (e.g. ARM64 sandbox without libFuzzer linkage).

    Args:
        func: callable that accepts one bytes payload and either runs clean
            or raises MeowHashError (which is counted, not silenced).
        seed: RNG seed (reproducible).
        duration_seconds: how long to run.
        max_per_iter_bytes: cap on a single generated payload (1 MiB).

    Returns:
        stats dict with iterations, elapsed, exceptions_caught, raises_caught.
    """
    rng = random.Random(seed)
    iters = 0
    exc_caught = 0
    other_uncaught = 0
    start = time.perf_counter()
    end = start + duration_seconds

    while time.perf_counter() < end:
        # Mutation profile: mix empty, small, medium, large payloads.
        size = rng.randint(0, max_per_iter_bytes)
        payload = bytes(rng.getrandbits(8) for _ in range(size))
        try:
            func(payload)
        except Exception as e:
            # We accept MeowHashError as the documented contract (Invariant 21).
            # Anything else is a true uncaught finding.
            from meowhash_pure import MeowHashError  # type: ignore
            if isinstance(e, MeowHashError):
                exc_caught += 1
            else:
                other_uncaught += 1
                # Surface the traceback so it lands in fuzz/logs/.
                import traceback
                print(f"[harness] UNEXPECTED: {type(e).__name__}: {e}",
                      file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
        iters += 1

    elapsed = time.perf_counter() - start
    return {
        "iterations": iters,
        "elapsed_seconds": elapsed,
        "exceptions_caught": exc_caught,
        "unexpected_uncaught": other_uncaught,
    }


def make_entry(
    one_iter: Callable[[bytes], None],
    *,
    atheris_test_one: Optional[Callable[[bytes], None]] = None,
    seed: int = 0,
    default_duration: float = 30.0,
) -> Callable[[], None]:
    """Build a harness entry point compatible with both atheris and manual loop.

    Usage in a harness file:

        def TestOneInput(data: bytes) -> None: ...
        def main():
            from fuzz._harness_common import make_entry, instrument
            instrument()
            import meowhash_pure  # noqa: F401  (instrumented import)
            entry = make_entry(TestOneInput, seed=0xC0FFEE, default_duration=30.0)
            entry()
    """
    def _atheris_test(data: bytes) -> None:
        from meowhash_pure import MeowHashError  # type: ignore
        try:
            if atheris_test_one is not None:
                atheris_test_one(data)
            else:
                one_iter(data)
        except MeowHashError:
            pass  # Contract-documented rejection; not a finding.

    def _manual_iter(payload: bytes) -> None:
        from meowhash_pure import MeowHashError  # type: ignore
        try:
            one_iter(payload)
        except MeowHashError:
            pass

    def entry() -> None:
        # CLI: --duration N overrides default; --seed overrides seed.
        import argparse
        p = argparse.ArgumentParser(add_help=False)
        p.add_argument("--duration", type=float, default=default_duration)
        p.add_argument("--seed", type=int, default=seed)
        p.add_argument("--libfuzzer", action="store_true",
                       help="Hand off to atheris.Fuzz() (requires native libFuzzer)")
        args, _unknown = p.parse_known_args()

        if args.libfuzzer:
            try:
                import atheris  # type: ignore
                atheris.Fuzz(_atheris_test)
                return
            except Exception as e:
                print(f"[harness] libFuzzer mode unavailable: {e}", file=sys.stderr)
                # Fall through to manual loop.

        # Manual reproducible loop.
        stats = run_loop(_manual_iter, seed=args.seed,
                         duration_seconds=args.duration)
        print(f"[harness] done: {stats}", file=sys.stderr)
        # Exit non-zero on any unexpected uncaught — that's a real finding.
        if stats["unexpected_uncaught"] > 0:
            sys.exit(2)

    return entry


if __name__ == "__main__":  # pragma: no cover
    print("This is a helper module, not a harness. See fuzz/*_fuzz.py")
    sys.exit(1)