#!/usr/bin/env python3
import argparse
import statistics
import time

from dns_engine import FilterEngine


def percentile(values, pct):
    if not values:
        return 0.0
    values = sorted(values)
    idx = min(len(values) - 1, int(len(values) * pct / 100))
    return values[idx]


def measure(fn, samples):
    timings = []
    for sample in samples:
        start = time.perf_counter()
        fn(sample)
        timings.append((time.perf_counter() - start) * 1000)
    return {
        "p50": percentile(timings, 50),
        "p95": percentile(timings, 95),
        "p99": percentile(timings, 99),
    }


def main():
    parser = argparse.ArgumentParser(description="Benchmark PyGuardDNS filter engine with generated rules.")
    parser.add_argument("--rules", type=int, default=100_000)
    parser.add_argument("--samples", type=int, default=5_000)
    args = parser.parse_args()

    engine = FilterEngine()
    start = time.perf_counter()
    for idx in range(args.rules):
        if idx % 10 == 0:
            engine.add_rule(f"/regex{idx}\\.bench\\.example/", "block", list_name="benchmark")
        elif idx % 2 == 0:
            engine.add_rule(f"exact{idx}.bench.example", "block", list_name="benchmark")
        else:
            engine.add_rule(f"||suffix{idx}.bench.example^", "block", list_name="benchmark")
    build_time = time.perf_counter() - start

    exact_samples = [f"exact{(i * 2) % max(2, args.rules)}.bench.example" for i in range(args.samples)]
    suffix_samples = [f"www.suffix{((i * 2) + 1) % max(2, args.rules)}.bench.example" for i in range(args.samples)]
    regex_samples = [f"regex{(i * 10) % max(10, args.rules)}.bench.example" for i in range(max(1, args.samples // 10))]

    exact = measure(engine.check, exact_samples)
    suffix = measure(engine.check, suffix_samples)
    regex = measure(engine.check, regex_samples)

    print(f"Rules: {args.rules:,}")
    print(f"Build time: {build_time:.3f}s")
    print(f"Exact match p50/p95/p99: {exact['p50']:.4f}/{exact['p95']:.4f}/{exact['p99']:.4f} ms")
    print(f"Suffix match p50/p95/p99: {suffix['p50']:.4f}/{suffix['p95']:.4f}/{suffix['p99']:.4f} ms")
    print(f"Regex match p50/p95/p99: {regex['p50']:.4f}/{regex['p95']:.4f}/{regex['p99']:.4f} ms")


if __name__ == "__main__":
    main()
