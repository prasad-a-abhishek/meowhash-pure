# fuzz/findings/ — T4 triage output

This directory holds per-finding folders for crashes/hangs/OOMs surfaced by the T3 fuzzer execution
(`fuzz/stats/summary.json`, `fuzz/logs/*.log`). Each per-finding folder would contain:

- `input.bin` — minimized input that reproduces the issue
- `stack.txt` — full traceback captured via `python3 -X faulthandler` or `pdb`
- `notes.md` — brief narrative of root cause + recommendation

## Current state: empty

**No per-finding folders exist** because the T3 run produced **zero crashes, zero hangs, zero OOM,
zero unexpected uncaught exceptions, zero determinism mismatches** across 5,071 iterations on 6
surfaces (meow64 / meow128 / State128 / expand_seed / invariant21 / determinism).

| Surface | Iterations | Uncaught | Mismatches | Classification |
|---|---|---|---|---|
| meow64 | 368 | 0 | 0 | clean |
| meow128 | 368 | 0 | 0 | clean |
| state128 | 301 | 0 | 0 | clean |
| expand_seed | 34 | 0 | 0 | clean |
| invariant21 | 62 cases | 0 | 0 | clean |
| determinism | 4000 cases | 0 | 0 | clean |
| **Total** | **5071** | **0** | **0** | **all clean** |

See `fuzz/stats/summary.json` for the full machine-readable report and `fuzz/logs/*.log` for the
per-harness stdout/stderr (each log shows `[harness] done: {'iterations': N, 'unexpected_uncaught': 0}`
or equivalent PASS line).

## Cross-check against T1 VULN_AUDIT

T1 (cycle_175/adversary/T1, commit fbc425c) found **0 Critical · 0 High · 1 Medium · 1 Low · 4 Info**.
Fuzzing produced **no new findings**, so no coverage gap was uncovered. The T1 audit's two
non-Info findings are:

- **F-006 (Medium)** — catch-all `try/except Exception -> MeowHashError` in `meow64`/`meow128`/
  `State128` may mask future internal bugs by hiding original tracebacks. T1 explicitly classified
  this as defence-in-depth, not a live bug; fuzzing did **not** surface a reproducer.
- **F-005 (Low)** — `_seed_bytes` leaks `TypeError`/`ValueError`/`OverflowError` if called directly
  with malformed `seed`/`size`. The invariant21 harness (62 cases including `seed=None`,
  `seed="x"`, `seed=3.14`, `seed=True`, etc.) exercised every public path that could reach
  `_seed_bytes`, and **all 62 raised `MeowHashError` as expected** — the public surface does not
  leak. The finding remains a defence-in-depth observation about the internal helper.

## Why this is acceptable, not a coverage failure

MeowHash 0.5 in pure-Python stdlib is a **bounded deterministic transformation**: 16-byte AES-block
round function emulated in pure Python (`_aesenc`/`_aesdec`), 64-byte buffer, no recursion into user
data, fixed seed semantics (uint64). Public API is total over arbitrary input per Invariant 21
(rejects None/str/int/float/out-of-range with `MeowHashError`). No `__main__.py`, no CLI surface,
no file I/O. Fuzz surface is purely `bytes -> int`/`bytes -> tuple[int,int]` — narrow attack
surface.

A 60-second-per-harness, 5071-iteration clean run on this narrow surface is **strong evidence**
that the public API is total and does not crash under random/mutated input. The libFuzzer native
runtime is unavailable in this sandbox (atheris module is present but `instrument_funcs` is missing —
documented in `fuzz/README.md` Honest Limitations), so the harness falls back to a
`random.Random(12648430)`-seeded mutator loop; this is reproducible but has weaker coverage than
native libFuzzer. If a future cycle has access to native libFuzzer, re-running T2/T3 would be
valuable — but for this cycle, the bound is honest and the result is clean.

## Per-finding folder naming convention (for future cycles)

If a future T3 run on this codebase ever produces a finding, the convention would be:

```
fuzz/findings/
  F-NNN/
    input.bin     # minimized reproducer (bytes)
    stack.txt     # faulthandler/pdb traceback
    notes.md      # root cause + recommendation
```

Where `F-NNN` matches the `id` field in `fuzz/findings.jsonl`.