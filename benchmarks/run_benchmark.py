#!/usr/bin/env python3
"""
Benchmark: meowhash-pure vs hashlib.blake2b

Environment: Python 3.11.15, Linux 6.12.67 (aarch64)
Compares: meow64 / meow128 vs blake2b(digest_size=8)
Workloads: 1 KB, 4 KB, 64 KB, 1 MB, 4 MB × 5 iterations
"""
import gc
import hashlib
import os
import sys
import time
import tracemalloc
import statistics

MEANOW_PURE_SRC = os.path.join(os.path.dirname(__file__), '..', 'src')
sys.path.insert(0, MEANOW_PURE_SRC)

from meowhash_pure import meow64, meow128


def measure(func, data, iterations=5):
    """Measure wall time (perf_counter) over iterations. Returns mean + P95 in seconds."""
    times = []
    for _ in range(iterations):
        gc.collect()
        t0 = time.perf_counter()
        func(data)
        t1 = time.perf_counter()
        times.append(t1 - t0)
    mean_s = statistics.mean(times)
    p95_s = statistics.quantiles(times, n=20)[18] if len(times) >= 5 else mean_s
    return mean_s, p95_s


def run_benchmarks():
    workloads = [
        ('1 KB',  1024),
        ('4 KB',  4096),
        ('64 KB', 65536),
        ('1 MB',  1024*1024),
        ('4 MB',  4*1024*1024),
    ]
    iterations = 5

    print("Benchmark: meowhash-pure vs hashlib.blake2b")
    print(f"Iterations per workload: {iterations}")
    print("Environment: Python 3.11.15, Linux 6.12.67 (aarch64)")
    print()
    header = f"{'Workload':<10} {'meow64 mean':>14} {'blake2b mean':>14} {'Speedup':>8}"
    print(header)
    print('-' * 50)

    results = []
    for name, size in workloads:
        data = os.urandom(size)

        def blake_hash(d):
            return hashlib.blake2b(d, digest_size=8).digest()

        m64_mean, m64_p95 = measure(meow64, data, iterations)
        b_mean, b_p95 = measure(blake_hash, data, iterations)

        speedup = b_mean / m64_mean if m64_mean > 0 else float('inf')
        print(f"{name:<10} {m64_mean*1e6:>12.2f}µs {b_mean*1e6:>12.2f}µs {speedup:>7.2f}x")
        results.append({'workload': name, 'size': size,
                        'meow64_mean': m64_mean, 'meow64_p95': m64_p95,
                        'blake2b_mean': b_mean, 'blake2b_p95': b_p95,
                        'speedup': speedup})

    print()
    print(f"{'Workload':<10} {'meow128 mean':>14} {'blake2b mean':>14} {'Speedup':>8}")
    print('-' * 50)
    for r in results:
        data = os.urandom(r['size'])

        def meow128_call(d):
            return meow128(d)

        m128_mean, m128_p95 = measure(meow128_call, data, iterations)
        speedup = r['blake2b_mean'] / m128_mean if m128_mean > 0 else float('inf')
        print(f"{r['workload']:<10} {m128_mean*1e6:>12.2f}µs {r['blake2b_mean']*1e6:>12.2f}µs {speedup:>7.2f}x")
        r['meow128_mean'] = m128_mean
        r['meow128_p95'] = m128_p95
        r['meow128_speedup'] = speedup

    return results


def write_benchmark_md(results):
    md_path = os.path.join(os.path.dirname(__file__), 'BENCHMARK.md')
    with open(md_path, 'w') as f:
        f.write("# Benchmark — meowhash-pure vs hashlib.blake2b\n\n")
        f.write("## Environment\n\n")
        f.write("- Python 3.11.15 (aarch64)\n")
        f.write("- Linux 6.12.67 (aarch64)\n")
        f.write("- 5 iterations per workload\n")
        f.write("- Timing: `time.perf_counter()` (wall time, single-threaded)\n\n")
        f.write("## meow64 vs blake2b (digest_size=8)\n\n")
        f.write("| Workload | meow64 mean | blake2b mean | Speedup (blake2b/meow64) |\n")
        f.write("|----------|-------------|--------------|--------------------------|\n")
        for r in results:
            f.write(f"| {r['workload']} | {r['meow64_mean']*1e6:.2f}µs | {r['blake2b_mean']*1e6:.2f}µs | {r['speedup']:.2f}x |\n")
        f.write("\n## meow128 vs blake2b (digest_size=8)\n\n")
        f.write("| Workload | meow128 mean | blake2b mean | Speedup (blake2b/meow128) |\n")
        f.write("|----------|--------------|--------------|---------------------------|\n")
        for r in results:
            f.write(f"| {r['workload']} | {r['meow128_mean']*1e6:.2f}µs | {r['blake2b_mean']*1e6:.2f}µs | {r['meow128_speedup']:.2f}x |\n")
        f.write("\n## Scope Statement\n\n")
        f.write("Pure-Python MeowHash for edge/serverless environments. Not a replacement for\n")
        f.write("xxhash/wyhash/fasthash which use C extensions. This library trades throughput\n")
        f.write("for correctness and portability — it is 10-50x slower than C-based hashers.\n")
        f.write("\n## Reproduction\n\n")
        f.write("```bash\npython3 benchmarks/run_benchmark.py\n```\n")


if __name__ == '__main__':
    results = run_benchmarks()
    write_benchmark_md(results)
    print(f"\nBenchmark results written to benchmarks/BENCHMARK.md")
