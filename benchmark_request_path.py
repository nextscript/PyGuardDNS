#!/usr/bin/env python3
"""Benchmark the hot DNS request-handling path (handle_dns_request) under
different traffic shapes and concurrency levels, to verify that the
RAM-snapshot / async-logging architecture keeps DNS latency stable and scales
with thread count instead of being limited by SQLite/global-lock contention.

Modes:
    cache-hit       every query is a pre-warmed cache hit (single domain)
    cache-hit-many  pre-warmed cache hits spread across many distinct domains
                    (exercises the sharded DNS cache instead of one shard)
    clean-miss      every query is a cache miss resolved by a faked upstream
    blocked         every query matches a (faked) filter-engine block rule
    regex-heavy     clean-miss traffic against a FilterEngine loaded with a
                    large regex_block index (candidate-filter + fallback)
    mixed           round-robins across cache-hit/clean-miss/blocked above

--query-logging {on,off} controls whether query_log_enabled is turned on (and
the real async db_writer thread started) for the run, so the log_drop/q_size
columns reflect realistic sustained-load behaviour.

--simulate-slow-db swaps the async query-log writer for a stand-in that still
drains the write queue but sleeps instead of touching SQLite, to demonstrate
that a slow persistence layer barely affects DNS response latency.
"""
import argparse
import threading
import time

import dns.message

import app
from dns_engine import FilterEngine


def percentile(values, pct):
    if not values:
        return 0.0
    values = sorted(values)
    idx = min(len(values) - 1, int(len(values) * pct / 100))
    return values[idx]


def make_query(domain, qtype="A"):
    return dns.message.make_query(domain, qtype).to_wire()


def make_answer_wire(request):
    response = dns.message.make_response(dns.message.from_wire(request))
    response.set_rcode(0)
    return response.to_wire()


def warm_cache(domain, qtype="A"):
    request = make_query(domain, qtype)
    app.set_cached(app.normalize_domain(domain), qtype, make_answer_wire(request))


class FakeBlockEngine:
    """FilterEngine stand-in that blocks exactly one domain and allows the rest,
    so --mode blocked/mixed can exercise the block path without touching real filter rules."""

    def __init__(self, blocked_domain):
        self._blocked = app.normalize_domain(blocked_domain)

    def check(self, domain, filtering_enabled=True, profile_id=None):
        if filtering_enabled and app.normalize_domain(domain) == self._blocked:
            return app.FilterResult("BLOCK", "benchmark_block", domain, matched_rule=domain, list_name="benchmark")
        return app.FilterResult("ALLOW", "no_match")

    def regex_index_stats(self):
        return {"regex_rules": 0, "regex_fallback_rules": 0, "regex_fallback_ratio": 0.0}


def build_regex_heavy_engine(n_indexed, n_fallback):
    """A FilterEngine with a large regex_block index: n_indexed rules carry a
    unique literal token (land in literal_buckets, so the candidate filter
    skips them for unrelated domains) and n_fallback rules use alternation
    (no extractable literal, so they're always evaluated - the "fallback"
    path the regex candidate filter can't avoid)."""
    engine = FilterEngine()
    for i in range(n_indexed):
        engine.add_pg_rule("br::", rf"adtrack{i:04d}-tracker\.invalid", "benchmark-regex")
    for i in range(n_fallback):
        engine.add_pg_rule("br::", rf"^(foo|bar){i:02d}\.fallbacktest\.invalid$", "benchmark-regex-fallback")
    return engine


class SlowQueryLogWriter:
    """Drains db_write_queue exactly like the real writer thread, but sleeps
    instead of touching SQLite - simulates a slow disk without writing to the DB."""

    def __init__(self, delay_seconds):
        self._delay = delay_seconds
        self._stop = threading.Event()
        self._thread = None

    def _loop(self):
        while not self._stop.is_set():
            batch = []
            with app.db_write_lock:
                if app.db_write_queue:
                    batch = app.db_write_queue[:500]
                    del app.db_write_queue[:500]
            if not batch:
                time.sleep(0.05)
                continue
            time.sleep(self._delay)

    def start(self):
        self._thread = threading.Thread(target=self._loop, name="benchmark-slow-db-writer", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)


def setup_mode(mode, domains, cache_many_domains=None, regex_engine=None, regex_miss_domain=None):
    """Install the monkeypatches `mode` needs on the app module; returns a restore() callback."""
    cache_domain, miss_domain, blocked_domain = domains
    saved = {}

    def patch(name, value):
        saved[name] = getattr(app, name)
        setattr(app, name, value)

    if mode in ("cache-hit", "mixed"):
        warm_cache(cache_domain)

    if mode == "cache-hit-many":
        for d in cache_many_domains:
            warm_cache(d)

    if mode in ("clean-miss", "mixed", "regex-heavy"):
        def fake_forward_query(request, timeout_override=None):
            return make_answer_wire(request), "benchmark-upstream"
        patch("forward_query", fake_forward_query)

        # Without this, the first miss would populate the cache and every
        # following query for the same domain would turn into a cache hit -
        # bypass caching for the miss-domain(s) so every query stays a
        # genuine "clean miss" while --mode mixed's cache-domain still caches normally.
        # The fake upstream answer has ancount=0, which is_negative_response()
        # classifies as "nodata" - bypass the negative cache too, or the first
        # miss would turn every later one into a negative-cache hit.
        bypass_keys = {app.normalize_domain(miss_domain)}
        if regex_miss_domain:
            bypass_keys.add(app.normalize_domain(regex_miss_domain))
        real_get_cached = app.get_cached
        real_set_cached = app.set_cached
        real_get_negative_cached = app.get_negative_cached
        real_set_negative_cached = app.set_negative_cached

        def fake_get_cached(domain, qtype_name):
            if app.normalize_domain(domain) in bypass_keys:
                return None
            return real_get_cached(domain, qtype_name)

        def fake_set_cached(domain, qtype_name, response):
            if app.normalize_domain(domain) in bypass_keys:
                return
            return real_set_cached(domain, qtype_name, response)

        def fake_get_negative_cached(domain, qtype_name):
            if app.normalize_domain(domain) in bypass_keys:
                return None
            return real_get_negative_cached(domain, qtype_name)

        def fake_set_negative_cached(domain, qtype_name, response, neg_type="nxdomain"):
            if app.normalize_domain(domain) in bypass_keys:
                return
            return real_set_negative_cached(domain, qtype_name, response, neg_type)

        patch("get_cached", fake_get_cached)
        patch("set_cached", fake_set_cached)
        patch("get_negative_cached", fake_get_negative_cached)
        patch("set_negative_cached", fake_set_negative_cached)

    if mode in ("blocked", "mixed"):
        fake_engine = FakeBlockEngine(blocked_domain)
        patch("get_filter_engine", lambda: fake_engine)

    if mode == "regex-heavy":
        patch("get_filter_engine", lambda: regex_engine)

    def restore():
        for name, original in saved.items():
            setattr(app, name, original)

    return restore


def domain_sequence(mode, domains, cache_many_domains=None, regex_miss_domain=None):
    cache_domain, miss_domain, blocked_domain = domains
    if mode == "cache-hit":
        return [cache_domain]
    if mode == "cache-hit-many":
        return cache_many_domains
    if mode == "clean-miss":
        return [miss_domain]
    if mode == "blocked":
        return [blocked_domain]
    if mode == "regex-heavy":
        return [regex_miss_domain]
    return [cache_domain, miss_domain, blocked_domain]


def run_concurrent(domain_seq, qtype, client_ips, n_threads, n_per_thread):
    requests = [make_query(d, qtype) for d in domain_seq]
    latencies = []
    lock = threading.Lock()
    barrier = threading.Barrier(n_threads)

    def worker(idx):
        client_ip = client_ips[idx % len(client_ips)]
        barrier.wait()
        local = []
        for i in range(n_per_thread):
            request = requests[i % len(requests)]
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
    parser.add_argument("--mode", choices=["cache-hit", "cache-hit-many", "clean-miss", "blocked", "regex-heavy", "mixed"], default="cache-hit")
    parser.add_argument("--cache-domain", default="benchmark-cache-hit.example.test")
    parser.add_argument("--miss-domain", default="benchmark-clean-miss.example.test")
    parser.add_argument("--blocked-domain", default="benchmark-blocked.example.test")
    parser.add_argument("--cache-hit-domains", type=int, default=200,
                        help="number of distinct domains pre-warmed for --mode cache-hit-many")
    parser.add_argument("--regex-rules", type=int, default=250,
                        help="number of literal-indexable regex_block rules for --mode regex-heavy")
    parser.add_argument("--regex-fallback-rules", type=int, default=50,
                        help="number of non-indexable (fallback) regex_block rules for --mode regex-heavy")
    parser.add_argument("--per-thread", type=int, default=300)
    parser.add_argument("--clients", type=int, default=8)
    parser.add_argument("--levels", default="1,2,4,8,16,32", help="comma separated thread counts")
    parser.add_argument("--query-logging", choices=["on", "off"], default="on",
                        help="on: enable query_log_enabled and start the real async db writer; "
                             "off: disable query logging entirely (for the 'logging on vs off' comparison)")
    parser.add_argument("--simulate-slow-db", action="store_true",
                        help="replace the query-log writer with a slow stand-in to prove DNS latency stays stable")
    parser.add_argument("--slow-db-delay", type=float, default=0.05,
                        help="seconds the simulated slow DB writer sleeps per drained batch")
    args = parser.parse_args()

    app.init_db()
    app.set_setting("query_log_enabled", "1" if args.query_logging == "on" else "0")
    if args.query_logging == "on" and not args.simulate_slow_db:
        app.start_db_writer()

    domains = (args.cache_domain, args.miss_domain, args.blocked_domain)
    cache_many_domains = [f"benchmark-cache-many-{i}.example.test" for i in range(args.cache_hit_domains)]
    regex_miss_domain = "benchmark-regex-clean.example.com"
    regex_engine = None
    if args.mode == "regex-heavy":
        regex_engine = build_regex_heavy_engine(args.regex_rules, args.regex_fallback_rules)

    client_ips = [f"10.20.{i // 256}.{i % 256}" for i in range(args.clients)]
    for ip in client_ips:
        app.ensure_client(ip)

    restore = setup_mode(args.mode, domains, cache_many_domains=cache_many_domains,
                          regex_engine=regex_engine, regex_miss_domain=regex_miss_domain)
    slow_writer = None
    try:
        if args.simulate_slow_db:
            slow_writer = SlowQueryLogWriter(args.slow_db_delay)
            slow_writer.start()
            print(f"Simulating slow query-log writer: {args.slow_db_delay * 1000:.0f} ms per drained batch")

        domain_seq = domain_sequence(args.mode, domains, cache_many_domains=cache_many_domains,
                                      regex_miss_domain=regex_miss_domain)
        domain_label = f"{len(domain_seq)} domains" if len(domain_seq) > 5 else ", ".join(domain_seq)
        print(f"Mode: {args.mode}  |  Domains: {domain_label}  |  Query logging: {args.query_logging}")
        print(f"Clients: {len(client_ips)}  |  Requests per thread: {args.per_thread}")
        if regex_engine is not None:
            print(f"Regex index: {regex_engine.regex_index_stats()}")
        print()
        header = (
            f"{'threads':>8} | {'reqs':>6} | {'wall_s':>7} | {'req/s':>8} | "
            f"{'p50_ms':>8} | {'p95_ms':>8} | {'p99_ms':>8} | {'max_ms':>8} | "
            f"{'hit%':>6} | {'log_drop':>8} | {'q_size':>6}"
        )
        print(header)
        print("-" * len(header))
        for n in [int(x) for x in args.levels.split(",")]:
            before = app.get_runtime_metrics()
            latencies, wall = run_concurrent(domain_seq, "A", client_ips, n, args.per_thread)
            after = app.get_runtime_metrics()
            total = len(latencies)
            hits = after["dns_cache_hits_total"] - before["dns_cache_hits_total"]
            misses = after["dns_cache_misses_total"] - before["dns_cache_misses_total"]
            hit_ratio = (hits / (hits + misses) * 100) if (hits + misses) else 0.0
            dropped = after["query_log_dropped_total"] - before["query_log_dropped_total"]
            print(
                f"{n:>8} | {total:>6} | {wall:>7.3f} | {total / wall:>8.1f} | "
                f"{percentile(latencies, 50):>8.3f} | {percentile(latencies, 95):>8.3f} | "
                f"{percentile(latencies, 99):>8.3f} | {max(latencies):>8.3f} | "
                f"{hit_ratio:>5.1f}% | {dropped:>8} | {after['query_log_queue_size']:>6}"
            )
    finally:
        if slow_writer:
            slow_writer.stop()
        restore()


if __name__ == "__main__":
    main()
