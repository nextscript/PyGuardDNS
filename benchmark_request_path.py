#!/usr/bin/env python3
"""Benchmark the hot DNS request-handling path (handle_dns_request) for cache
hits, at increasing concurrency, to reveal lock contention around the shared
SQLite connection (db_lock / get_setting / client_manager lookups)."""
import argparse
import statistics
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


def warm_cache(domain, qtype="A"):
    request = make_query(domain, qtype)
    response = dns.message.make_response(dns.message.from_wire(request))
    response.set_rcode(0)
    app.set_cached(app.normalize_domain(domain), qtype, response.to_wire())


def run_concurrent(domain, qtype, client_ips, n_threads, n_per_thread):
    request = make_query(domain, qtype)
    latencies = []
    lock = threading.Lock()
    barrier = threading.Barrier(n_threads)

    def worker(idx):
        client_ip = client_ips[idx % len(client_ips)]
        barrier.wait()
        local = []
        for _ in range(n_per_thread):
            t0 = time.perf_counter()
            app.handle_dns_request(request, client_ip, "UDP")
            local.append((time.perf_counter() - t0) * 1000)
        with lock:
            latencies.extend(local)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    wall_start = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - wall_start
    return latencies, wall


def main():
    parser = argparse.ArgumentParser(description="Benchmark PyGuardDNS handle_dns_request hot path.")
    parser.add_argument("--domain", default="benchmark-cache-hit.example.test")
    parser.add_argument("--per-thread", type=int, default=300)
    parser.add_argument("--clients", type=int, default=8)
    parser.add_argument("--levels", default="1,2,4,8,16", help="comma separated thread counts")
    args = parser.parse_args()

    app.init_db()
    warm_cache(args.domain)
    client_ips = [f"10.20.{i // 256}.{i % 256}" for i in range(args.clients)]
    for ip in client_ips:
        app.ensure_client(ip)

    print(f"Domain: {args.domain} (pre-warmed cache hit)")
    print(f"Clients: {len(client_ips)}  |  Requests per thread: {args.per_thread}")
    print()
    print(f"{'threads':>8} | {'reqs':>6} | {'wall_s':>7} | {'req/s':>8} | {'p50_ms':>8} | {'p95_ms':>8} | {'p99_ms':>8} | {'max_ms':>8}")
    print("-" * 78)
    for n in [int(x) for x in args.levels.split(",")]:
        latencies, wall = run_concurrent(args.domain, "A", client_ips, n, args.per_thread)
        total = len(latencies)
        print(
            f"{n:>8} | {total:>6} | {wall:>7.3f} | {total / wall:>8.1f} | "
            f"{percentile(latencies, 50):>8.3f} | {percentile(latencies, 95):>8.3f} | "
            f"{percentile(latencies, 99):>8.3f} | {max(latencies):>8.3f}"
        )


if __name__ == "__main__":
    main()
