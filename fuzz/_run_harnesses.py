"""Run all meowhash-pure fuzz harnesses for a fixed duration and capture stats.

Executes each fuzz/*_fuzz.py in 60s (configurable via --duration) using the
manual reproducible loop (libFuzzer native runtime is unavailable on this
sandbox). Writes per-harness logs to fuzz/logs/ and a summary to
fuzz/stats/summary.json.

Run from repo root: `python3 fuzz/_run_harnesses.py`
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FUZZ_DIR = REPO_ROOT / "fuzz"
LOGS_DIR = FUZZ_DIR / "logs"
STATS_DIR = FUZZ_DIR / "stats"
CRASHES_DIR = FUZZ_DIR / "crashes"
HANGS_DIR = FUZZ_DIR / "hangs"
OOM_DIR = FUZZ_DIR / "oom"


# Each entry: (label, harness_path_relative_to_repo, env_overrides)
# env_overrides: extra env passed to subprocess.run (e.g. PYTHONPATH)
HARNESSES = [
    ("meow64",      "fuzz/meow64_fuzz.py"),
    ("meow128",     "fuzz/meow128_fuzz.py"),
    ("state128",    "fuzz/state128_fuzz.py"),
    ("expand_seed", "fuzz/expand_seed_fuzz.py"),
    ("invariant21", "fuzz/invariant21_fuzz.py"),
    ("determinism", "fuzz/determinism_test.py"),
]


def run_one(label: str, harness_rel: str, duration: float) -> dict:
    """Run one harness for `duration` seconds; capture log, exit code, stats.

    Invariant 21 and determinism harnesses are NOT time-bounded mutator loops;
    they finish in seconds. We still wrap them in `timeout` for safety.
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    STATS_DIR.mkdir(parents=True, exist_ok=True)
    CRASHES_DIR.mkdir(parents=True, exist_ok=True)
    HANGS_DIR.mkdir(parents=True, exist_ok=True)
    OOM_DIR.mkdir(parents=True, exist_ok=True)

    harness_path = REPO_ROOT / harness_rel
    log_path = LOGS_DIR / f"{label}.log"
    cmd = [
        sys.executable, str(harness_path),
        "--duration", str(duration),
        "--seed", "12648430",  # decimal form of 0xC0FFEE
    ]
    print(f"[runner] {label}: starting ({duration}s) — {harness_rel}", flush=True)
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=duration + 30,  # buffer for short non-mutator harnesses
            env={**__import__("os").environ, "PYTHONPATH": str(REPO_ROOT)},
        )
        elapsed = time.perf_counter() - start
        rc = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as e:
        elapsed = time.perf_counter() - start
        rc = -1
        timed_out = True
        proc = e  # type: ignore[assignment]

    # Persist log (stdout + stderr).
    out = getattr(proc, "stdout", "") or ""
    err = getattr(proc, "stderr", "") or ""
    log_path.write_text(
        f"# cmd: {' '.join(cmd)}\n"
        f"# elapsed_seconds: {elapsed:.3f}\n"
        f"# returncode: {rc}\n"
        f"# timed_out: {timed_out}\n"
        f"\n--- stdout ---\n{out}\n--- stderr ---\n{err}\n"
    )

    # Parse iteration / mismatch / unexpected counts from stderr.
    # The manual loop prints a Python dict like:
    #   {'iterations': 34, 'elapsed_seconds': ..., 'exceptions_caught': 0,
    #    'unexpected_uncaught': 0}
    # Invariant 21 prints "[invariant21] N cases, M uncaught — PASS".
    # Determinism prints "[det] N cases, M contracted rejections, K mismatches — PASS".
    iterations = _extract_int(out + err, r"'iterations':\s*(\d+)")
    unexpected = _extract_int(out + err, r"'unexpected_uncaught':\s*(\d+)")
    mismatches = _extract_int(out + err, r"(\d+)\s+mismatches")
    cases = _extract_int(out + err, r"(\d+)\s+cases")

    # Default iterations for non-mutator harnesses:
    #   invariant21: cases == 62, manual loop count == 0
    #   determinism: cases_run == 4000 (1000 iters x 4 surfaces)
    #   _extract_int returns None when the regex misses; we record that as null.
    if iterations is None and label == "invariant21":
        iterations = 0  # non-mutator
    if iterations is None and label == "determinism":
        iterations = 4000  # 1000 random (data, seed) pairs * 4 surface calls

    summary = {
        "label": label,
        "harness": harness_rel,
        "elapsed_seconds": round(elapsed, 3),
        "returncode": rc,
        "timed_out": timed_out,
        "iterations": iterations,
        "cases": cases,
        "unexpected_uncaught": unexpected or 0,
        "mismatches": mismatches or 0,
        "log_path": str(log_path.relative_to(REPO_ROOT)),
    }
    print(f"[runner] {label}: done rc={rc} iters={iterations} uncaught={unexpected} mismatches={mismatches}", flush=True)

    # Classify any non-zero rc into crashes/hangs/oom dirs.
    if timed_out:
        _move_artifact(LOGS_DIR / f"{label}.log", HANGS_DIR / f"{label}.log")
        summary["classification"] = "hang"
    elif rc == 0:
        summary["classification"] = "clean"
    elif rc == 2:
        # Non-mutator harnesses exit 2 on contract violation (uncaught).
        # But for mutator harnesses, this is also a finding. Track as crash.
        _move_artifact(LOGS_DIR / f"{label}.log", CRASHES_DIR / f"{label}.log")
        summary["classification"] = "crash"
    elif rc < 0:
        _move_artifact(LOGS_DIR / f"{label}.log", OOM_DIR / f"{label}.log")
        summary["classification"] = "oom"
    else:
        _move_artifact(LOGS_DIR / f"{label}.log", CRASHES_DIR / f"{label}.log")
        summary["classification"] = "crash"

    return summary


def _move_artifact(src: Path, dst: Path) -> None:
    """Move a log file into a category dir. dst's parent must exist."""
    if not src.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    src.replace(dst)


def _extract_int(text: str, pattern: str) -> int | None:
    """Return the first int captured by `pattern`, or None if no match."""
    m = re.search(pattern, text)
    return int(m.group(1)) if m else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=float, default=60.0,
                    help="seconds per mutator harness (Invariant21/determinism "
                         "are short non-mutator probes; their wall time is "
                         "unaffected)")
    args = ap.parse_args()

    overall_start = time.perf_counter()
    summaries = []
    total_iterations = 0
    total_crashes = 0
    total_hangs = 0
    total_oom = 0

    for label, harness_rel in HARNESSES:
        s = run_one(label, harness_rel, args.duration)
        summaries.append(s)
        total_iterations += s["iterations"] or 0
        if s["classification"] == "crash":
            total_crashes += 1
        elif s["classification"] == "hang":
            total_hangs += 1
        elif s["classification"] == "oom":
            total_oom += 1

    overall_elapsed = time.perf_counter() - overall_start
    overall = {
        "run_at_unix": time.time(),
        "duration_seconds_per_harness": args.duration,
        "wall_time_seconds": round(overall_elapsed, 3),
        "harness_count": len(HARNESSES),
        "iterations_total": total_iterations,
        "crashes_count": total_crashes,
        "hangs_count": total_hangs,
        "oom_count": total_oom,
        "harnesses": summaries,
    }
    STATS_DIR.mkdir(parents=True, exist_ok=True)
    (STATS_DIR / "summary.json").write_text(json.dumps(overall, indent=2) + "\n")
    print(
        f"\n[runner] DONE: {len(HARNESSES)} harnesses, "
        f"{total_iterations} iterations, "
        f"{total_crashes} crashes, {total_hangs} hangs, {total_oom} OOM",
        flush=True,
    )
    print(f"[runner] summary -> fuzz/stats/summary.json", flush=True)
    return 0 if total_crashes == 0 and total_hangs == 0 and total_oom == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
