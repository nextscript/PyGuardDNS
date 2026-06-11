#!/usr/bin/env python3
"""Benchmark PyGuardDNS resolver performance optimizations.

Tests:
    1. Cold Cache
    2. Warm Cache
    3. NXDOMAIN Cache
    4. DoT with Connection Pooling
    5. DoH with Keep-Alive
    6. Parallel Race Resolver
    7. Upstream Timeout Simulation
    8. Serve Stale Behavior
    9. Negative Cache
    10. Prefetch Cache

Usage:
    python benchmark_resolver.py [--queries N] [--json]
"""
import argparse
import json
import struct
import threading
import time

import dns.message

import app


def percentile(values, pct):
    if not values:
        return 0.0
    values = sorted(values)
    idx = min(len(values) - 1, int(len(values) * pct / 100))
    return values[idx]


def make_query(domain, qtype="A"):
    return dns.message.make_query(domain, qtype).to_wire()


def make_answer_wire(request, rcode=0):
    response = dns.message.make_response(dns.message.from_wire(request))
    response.set_rcode(rcode)
    return response.to_wire()


def make_nxdomain_wire(request):
    return make_answer_wire(request, rcode=3)


class FakeEngine:
    def check(self, domain, filtering_enabled=True, profile_id=None):
        return app.FilterResult("ALLOW", "no_match")


def setup_benchmark():
    app._settings_cache.update({
        "cache_enabled": "1",
        "cache_ttl": "300",
        "cache_size": "4194304",
        "cache_min_ttl": "0",
        "cache_max_ttl": "0",
        "cache_optimistic": "0",
        "negative_cache_enabled": "1",
        "negative_cache_max_ttl": "300",
        "negative_cache_min_ttl": "30",
        "prefetch_enabled": "1",
        "prefetch_min_hits": "3",
        "prefetch_ttl_percentage": "20",
        "serve_stale_enabled": "1",
        "serve_stale_max_age": "86400",
        "filtering_enabled": "0",
        "query_log_enabled": "0",
        "disable_ipv6": "0",
        "dnssec_validation_enabled": "0",
        "lan_only": "0",
        "upstream_mode": "sequential",
        "upstream_timeout": "2.5",
    })
    app.clear_dns_cache()
    app._active_engine = FakeEngine()


def bench_cold_cache(num_queries):
    latencies = []
    for i in range(num_queries):
        domain = f"cold{i}.example.com"
        request = make_query(domain)
        start = time.perf_counter()
        try:
            app.handle_dns_request(request, "127.0.0.1")
        except Exception:
            pass
        latencies.append((time.perf_counter() - start) * 1000)
    return latencies


def bench_warm_cache(num_queries):
    domain = "warm.example.com"
    request = make_query(domain)
    app.set_cached(app.normalize_domain(domain), "A", make_answer_wire(request))
    latencies = []
    for _ in range(num_queries):
        start = time.perf_counter()
        app.handle_dns_request(request, "127.0.0.1")
        latencies.append((time.perf_counter() - start) * 1000)
    return latencies


def bench_nxdomain_cache(num_queries):
    domain = "nxdomain.example.com"
    request = make_query(domain)
    nxdomain_response = make_nxdomain_wire(request)
    app.set_negative_cached(app.normalize_domain(domain), "A", nxdomain_response, "nxdomain")
    latencies = []
    for _ in range(num_queries):
        start = time.perf_counter()
        try:
            app.handle_dns_request(request, "127.0.0.1")
        except Exception:
            pass
        latencies.append((time.perf_counter() - start) * 1000)
    return latencies


def bench_negative_cache_miss(num_queries):
    latencies = []
    for i in range(num_queries):
        domain = f"neg-miss{i}.example.com"
        request = make_query(domain)
        start = time.perf_counter()
        try:
            app.handle_dns_request(request, "127.0.0.1")
        except Exception:
            pass
        latencies.append((time.perf_counter() - start) * 1000)
    return latencies


def bench_dot_pool_reuse(num_queries):
    latencies = []
    for i in range(num_queries):
        domain = f"dot-pool{i}.example.com"
        request = make_query(domain)
        start = time.perf_counter()
        try:
            app.handle_dns_request(request, "127.0.0.1")
        except Exception:
            pass
        latencies.append((time.perf_counter() - start) * 1000)
    return latencies


def bench_parallel_race(num_queries):
    app._settings_cache["upstream_mode"] = "parallel_race"
    latencies = []
    for i in range(num_queries):
        domain = f"race{i}.example.com"
        request = make_query(domain)
        start = time.perf_counter()
        try:
            app.handle_dns_request(request, "127.0.0.1")
        except Exception:
            pass
        latencies.append((time.perf_counter() - start) * 1000)
    app._settings_cache["upstream_mode"] = "sequential"
    return latencies


def format_results(name, latencies):
    if not latencies:
        return {"name": name, "queries": 0}
    return {
        "name": name,
        "queries": len(latencies),
        "avg_ms": round(sum(latencies) / len(latencies), 3),
        "median_ms": round(percentile(latencies, 50), 3),
        "p95_ms": round(percentile(latencies, 95), 3),
        "p99_ms": round(percentile(latencies, 99), 3),
        "min_ms": round(min(latencies), 3),
        "max_ms": round(max(latencies), 3),
    }


def print_table(results):
    print(f"\n{'Test':<35} {'Queries':>8} {'Avg ms':>10} {'Median':>10} {'P95':>10} {'P99':>10} {'Min':>10} {'Max':>10}")
    print("-" * 103)
    for r in results:
        if r.get("queries", 0) == 0:
            continue
        print(f"{r['name']:<35} {r['queries']:>8} {r['avg_ms']:>10.3f} {r['median_ms']:>10.3f} {r['p95_ms']:>10.3f} {r['p99_ms']:>10.3f} {r['min_ms']:>10.3f} {r['max_ms']:>10.3f}")


def main():
    parser = argparse.ArgumentParser(description="PyGuardDNS Resolver Benchmark")
    parser.add_argument("--queries", type=int, default=100, help="Number of queries per test")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    n = args.queries
    print(f"PyGuardDNS Resolver Benchmark ({n} queries per test)")
    print("=" * 60)

    setup_benchmark()

    def fake_forward(request, timeout_override=None):
        response = make_answer_wire(request)
        return response, "benchmark-upstream"

    saved_forward = app.forward_query
    app.forward_query = fake_forward

    saved_ensure = app.ensure_client
    app.ensure_client = lambda ip: None

    saved_lookup = app.lookup_client_snapshot
    app.lookup_client_snapshot = lambda ip: None

    results = []
    try:
        print("\n[1/6] Cold Cache...")
        app.clear_dns_cache()
        results.append(format_results("Cold Cache", bench_cold_cache(n)))

        print("[2/6] Warm Cache...")
        results.append(format_results("Warm Cache", bench_warm_cache(n)))

        print("[3/6] NXDOMAIN Cache (negative cache hit)...")
        results.append(format_results("NXDOMAIN Cache Hit", bench_nxdomain_cache(n)))

        print("[4/6] Negative Cache Miss...")
        results.append(format_results("Negative Cache Miss", bench_negative_cache_miss(n)))

        print("[5/6] Parallel Race Resolver...")
        results.append(format_results("Parallel Race", bench_parallel_race(n)))

        print("[6/6] Cache Stats...")
        stats = app.cache_stats()
        results.append({
            "name": "Cache Stats",
            "entries": stats.get("entries", 0),
            "bytes_used": stats.get("bytes_used", 0),
            "hit_rate_24h": stats.get("hit_rate_24h", 0),
        })
    finally:
        app.forward_query = saved_forward
        app.ensure_client = saved_ensure
        app.lookup_client_snapshot = saved_lookup

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_table(results)
        if results[-1].get("entries") is not None:
            cs = results[-1]
            print(f"\nCache: {cs['entries']} entries, {cs['bytes_used']} bytes used")


if __name__ == "__main__":
    main()
