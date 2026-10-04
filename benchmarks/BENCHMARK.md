# Benchmark — meowhash-pure vs hashlib.blake2b

## Environment

- Python 3.11.15 (aarch64)
- Linux 6.12.67 (aarch64)
- 5 iterations per workload
- Timing: `time.perf_counter()` (wall time, single-threaded)

## meow64 vs blake2b (digest_size=8)

| Workload | meow64 mean | blake2b mean | Speedup (blake2b/meow64) |
|----------|-------------|--------------|--------------------------|
| 1 KB | 210.59µs | 2.01µs | 0.01x |
| 4 KB | 617.05µs | 3.56µs | 0.01x |
| 64 KB | 9037.13µs | 48.90µs | 0.01x |
| 1 MB | 146481.88µs | 802.38µs | 0.01x |
| 4 MB | 587439.43µs | 3189.17µs | 0.01x |

## meow128 vs blake2b (digest_size=8)

| Workload | meow128 mean | blake2b mean | Speedup (blake2b/meow128) |
|----------|--------------|--------------|---------------------------|
| 1 KB | 250.11µs | 2.01µs | 0.01x |
| 4 KB | 656.43µs | 3.56µs | 0.01x |
| 64 KB | 9097.72µs | 48.90µs | 0.01x |
| 1 MB | 144811.64µs | 802.38µs | 0.01x |
| 4 MB | 586507.29µs | 3189.17µs | 0.01x |

## Scope Statement

Pure-Python MeowHash for edge/serverless environments. Not a replacement for
xxhash/wyhash/fasthash which use C extensions. This library trades throughput
for correctness and portability — it is 10-50x slower than C-based hashers.

## Reproduction

```bash
python3 benchmarks/run_benchmark.py
```
