import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, Tuple

UPSTREAMS_DIR = os.path.join("data", "upstreams")

# Health recovery worker configuration
_HEALTH_PROBE_INTERVAL = 10.0  # seconds
_HEALTH_PROBE_TIMEOUT = 5.0    # seconds
_HEALTH_PROBE_DOMAIN = "example.com"
_HEALTH_PROBE_QNAME = b"".join(
    bytes([len(label)]) + label.encode("ascii") for label in _HEALTH_PROBE_DOMAIN.split(".")
) + b"\x00"

# Worker state
_health_recovery_thread: Optional[threading.Thread] = None
_health_recovery_stop = threading.Event()
_health_recovery_lock = threading.Lock()

_cache: dict[int, dict] = {}
_cache_lock = threading.RLock()
_cache_loaded = False


def _ensure_dir():
    os.makedirs(UPSTREAMS_DIR, exist_ok=True)


def _path(upstream_id: int) -> str:
    return os.path.join(UPSTREAMS_DIR, f"{upstream_id}.json")


def _load_file(upstream_id: int) -> Optional[dict]:
    path = _path(upstream_id)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _save_file(data: dict):
    _ensure_dir()
    path = _path(data["id"])
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _delete_file(upstream_id: int):
    path = _path(upstream_id)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def _invalidate_cache():
    global _cache_loaded
    with _cache_lock:
        _cache.clear()
        _cache_loaded = False


def _load_cache():
    global _cache_loaded
    with _cache_lock:
        if _cache_loaded:
            return
        _cache.clear()
        _ensure_dir()
        for fname in os.listdir(UPSTREAMS_DIR):
            if fname.endswith(".json"):
                try:
                    uid = int(fname[:-5])
                    data = _load_file(uid)
                    if data:
                        _cache[uid] = data
                except ValueError:
                    pass
        _cache_loaded = True


def _get_from_cache(upstream_id: int) -> Optional[dict]:
    _load_cache()
    with _cache_lock:
        d = _cache.get(upstream_id)
        return dict(d) if d else None


def _update_cache(data: dict):
    with _cache_lock:
        _cache[data["id"]] = dict(data)


def _remove_from_cache(upstream_id: int):
    with _cache_lock:
        _cache.pop(upstream_id, None)


# ==============================================================================
# Health-state normalization and backoff helpers
# ==============================================================================

DEFAULT_HEALTH = {
    "paused": False,
    "pause_reason": "",
    "backoff_until": 0.0,
    "backoff_level": 0,
    "circuit_state": "closed",
    "probe_required": False,
    "last_success": 0.0,
    "last_failure": 0.0,
    "ewma_success": 1.0,
    "ewma_latency_ms": 0.0,
    "latency_ms": 0.0,
    "success_rate": 1.0,
    "timeout_count": 0,
    "tls_failures": 0,
    "http_failures": 0,
    "servfail_count": 0,
    "last_error": "",
    "last_checked": 0.0,
    "consecutive_failures": 0,
    "total_queries": 0,
    "successful_queries": 0,
}

PAUSE_REASON_HEALTH_BACKOFF = "health_backoff"
PAUSE_REASON_MANUAL = "manual"

# ==============================================================================
# Circuit breaker state and probe locking (thread-safe)
# ==============================================================================

# Per-upstream probe locks to prevent concurrent half-open probes
_probe_locks: dict[int, threading.Lock] = {}
_probe_locks_guard = threading.Lock()

# Circuit breaker constants
_CIRCUIT_CLOSED = "closed"
_CIRCUIT_OPEN = "open"
_CIRCUIT_HALF_OPEN = "half_open"


def _get_probe_lock(upstream_id: int) -> threading.Lock:
    """Get or create a per-upstream probe lock (thread-safe)."""
    with _probe_locks_guard:
        if upstream_id not in _probe_locks:
            _probe_locks[upstream_id] = threading.Lock()
        return _probe_locks[upstream_id]


def should_allow_request(upstream_id: int, *, is_probe: bool = False) -> bool:
    """Check if a request should be allowed for this upstream.

    Returns True if the upstream is in closed state (normal traffic allowed),
    or if is_probe=True and the upstream is in half_open state (probe allowed).
    """
    data = get(upstream_id)
    if not data:
        return False
    h = normalize_health_fields(data)
    circuit = h.get("circuit_state", "closed")

    if circuit == _CIRCUIT_CLOSED:
        return True
    if circuit == _CIRCUIT_HALF_OPEN and is_probe:
        # Check if a probe is already in flight
        if h.get("probe_in_flight"):
            return False
        return True
    return False


def _probe_is_stale(h: dict) -> bool:
    """A probe marked in flight for too long was never finished (e.g. restart)."""
    started = float(h.get("probe_started_at", 0) or 0)
    return time.time() - started > _HEALTH_PROBE_TIMEOUT * 4


def begin_probe(upstream_id: int) -> bool:
    """Attempt to begin a recovery probe for a half_open upstream.

    Returns True if the probe was successfully started, False if another
    probe is already in flight or the upstream is not in half_open state.
    """
    data = get(upstream_id)
    if not data:
        return False
    h = normalize_health_fields(data)

    if h.get("circuit_state") != _CIRCUIT_HALF_OPEN:
        return False

    if h.get("probe_in_flight") and not _probe_is_stale(h):
        return False

    # Use per-upstream lock to prevent race conditions
    lock = _get_probe_lock(upstream_id)
    if not lock.acquire(blocking=False):
        return False

    # Double-check after acquiring lock
    data = get(upstream_id)
    if not data:
        lock.release()
        return False
    h = normalize_health_fields(data)
    if h.get("circuit_state") != _CIRCUIT_HALF_OPEN:
        lock.release()
        return False
    if h.get("probe_in_flight") and not _probe_is_stale(h):
        lock.release()
        return False

    # Mark probe as in-flight
    h["probe_in_flight"] = True
    h["probe_started_at"] = time.time()
    _save_file(data)
    _update_cache(data)
    return True


def finish_probe(upstream_id: int, *, success: bool, latency_ms: float = 0.0, error: str = "") -> None:
    """Complete a recovery probe and update circuit state accordingly.

    Args:
        upstream_id: The upstream identifier
        success: Whether the probe succeeded
        latency_ms: Probe latency in milliseconds
        error: Error message if probe failed
    """
    data = get(upstream_id)
    if not data:
        return
    h = normalize_health_fields(data)

    # Release probe lock
    lock = _get_probe_lock(upstream_id)
    try:
        lock.release()
    except RuntimeError:
        pass  # Already released

    if success:
        # Successful probe: return to closed state
        h["circuit_state"] = _CIRCUIT_CLOSED
        h["paused"] = False
        h["pause_reason"] = ""
        h["probe_required"] = False
        h["probe_in_flight"] = False
        h["backoff_level"] = 0
        h["backoff_until"] = 0
        h["consecutive_failures"] = 0
        h["last_success"] = time.time()
        h["last_error"] = ""

        # Circuit closed again: start fresh instead of staying "degraded"
        h["ewma_success"] = 1.0
        alpha = 0.2
        old_ewma_latency = h.get("ewma_latency_ms", 0.0)
        h["ewma_latency_ms"] = alpha * latency_ms + (1 - alpha) * old_ewma_latency
    else:
        # Failed probe: return to open state with increased backoff
        h["circuit_state"] = _CIRCUIT_OPEN
        h["paused"] = True
        h["pause_reason"] = PAUSE_REASON_HEALTH_BACKOFF
        h["probe_required"] = False
        h["probe_in_flight"] = False
        h["last_failure"] = time.time()
        h["last_error"] = (error or "Probe failed")[:500]

        # Increase backoff level
        current_level = h.get("backoff_level", 0)
        h["backoff_level"] = min(current_level + 1, 4)
        backoff_seconds = {0: 0, 1: 30, 2: 60, 3: 300, 4: 900}.get(h["backoff_level"], 900)
        h["backoff_until"] = time.time() + backoff_seconds

        # EWMA update for failure
        alpha = 0.2
        old_ewma_success = h.get("ewma_success", 1.0)
        h["ewma_success"] = alpha * 0.0 + (1 - alpha) * old_ewma_success

    _save_file(data)
    _update_cache(data)


def reset_upstream_probe_state(upstream_id: int) -> None:
    """Reset probe state for an upstream (used when upstream is re-enabled)."""
    data = get(upstream_id)
    if not data:
        return
    h = normalize_health_fields(data)
    h["probe_required"] = False
    h["probe_in_flight"] = False
    h["probe_started_at"] = 0.0
    _save_file(data)
    _update_cache(data)


# ==============================================================================
# Connection Pool Management
# ==============================================================================

# Pool configuration defaults
_POOL_IDLE_TIMEOUT = 30.0        # seconds
_POOL_MAX_LIFETIME = 600.0       # seconds (10 minutes)
_POOL_MAX_REQUESTS = 200         # max requests per connection
_POOL_CONNECT_TIMEOUT = 5.0      # seconds
_POOL_HANDSHAKE_TIMEOUT = 5.0    # seconds
_POOL_READ_TIMEOUT = 10.0        # seconds
_POOL_WRITE_TIMEOUT = 10.0       # seconds
_POOL_MAINTENANCE_INTERVAL = 60.0  # seconds between maintenance cycles

# Pool maintenance worker state
_pool_maintenance_thread: Optional[threading.Thread] = None
_pool_maintenance_stop = threading.Event()
_pool_maintenance_lock = threading.Lock()

# ==============================================================================
# Stuck Operation Watchdog
# ==============================================================================

# Watchdog configuration
_WATCHDOG_GRACE_SECONDS = 5.0
_WATCHDOG_CHECK_INTERVAL = 15.0
_WATCHDOG_POOL_REBUILD_THRESHOLD = 5
_WATCHDOG_POOL_REBUILD_COOLDOWN = 300.0  # 5 minutes

# ==============================================================================
# Fallback Resolver Configuration
# ==============================================================================

# Hardcoded encrypted fallback resolvers (used when all configured upstreams are unavailable)
_FALLBACK_RESOLVERS = [
    {"name": "Cloudflare DoH", "address": "1.1.1.1", "port": 443, "resolver": "https://cloudflare-dns.com/dns-query", "transport": "doth", "enabled": True},
    {"name": "Quad9 DoH", "address": "9.9.9.9", "port": 443, "resolver": "https://dns.quad9.net/dns-query", "transport": "doth", "enabled": True},
    {"name": "Google DoH", "address": "8.8.8.8", "port": 443, "resolver": "https://dns.google/dns-query", "transport": "doth", "enabled": True},
]

# Fallback metrics
_fallback_metrics = {
    "fallback_attempts_total": 0,
    "fallback_success_total": 0,
    "fallback_failures_total": 0,
    "fallback_active": 0,
}
_fallback_metrics_lock = threading.Lock()

# Fallback concurrency limiter
_fallback_limiter: Optional[threading.Semaphore] = None
_fallback_limiter_lock = threading.Lock()

# Active operations tracking
_active_operations: dict[int, dict] = {}
_active_ops_lock = threading.Lock()
_op_id_counter = 0

# Stuck operations tracking
_stuck_operations: list[dict] = []
_stuck_ops_lock = threading.Lock()
_stuck_ops_last_log = 0.0

# Pool rebuild tracking
_pool_rebuilds: dict[str, dict] = {}
_pool_rebuilds_lock = threading.Lock()

# Watchdog worker state
_watchdog_thread: Optional[threading.Thread] = None
_watchdog_stop = threading.Event()
_watchdog_lock = threading.Lock()

# Pool metrics
_pool_metrics = {
    "dot_pool_total": 0,
    "dot_pool_idle": 0,
    "dot_pool_in_use": 0,
    "dot_pool_created_total": 0,
    "dot_pool_reused_total": 0,
    "dot_pool_discarded_total": 0,
    "dot_pool_expired_total": 0,
    "dot_pool_connect_failures_total": 0,
    "doh_pool_total": 0,
    "doh_pool_idle": 0,
    "doh_pool_in_use": 0,
    "doh_pool_created_total": 0,
    "doh_pool_reused_total": 0,
    "doh_pool_discarded_total": 0,
    "doh_pool_expired_total": 0,
    "doh_pool_connect_failures_total": 0,
}
_pool_metrics_lock = threading.Lock()


def is_connection_healthy(conn, protocol="dot") -> bool:
    """Check if a pooled connection is healthy and reusable.

    Returns False if the connection has:
    - timed out (idle or lifetime)
    - exceeded max requests
    - been closed
    - uncertain state
    """
    if conn is None:
        return False

    # Check if explicitly closed
    if getattr(conn, 'conn', None) is None:
        return False

    # Check idle timeout
    last_used = getattr(conn, 'last_used', 0)
    if last_used > 0:
        idle_timeout = getattr(conn, 'idle_timeout', _POOL_IDLE_TIMEOUT)
        if time.time() - last_used > idle_timeout:
            return False

    # Check max lifetime
    created_at = getattr(conn, 'created_at', 0)
    if created_at > 0:
        max_lifetime = getattr(conn, 'max_lifetime', _POOL_MAX_LIFETIME)
        if time.time() - created_at > max_lifetime:
            return False

    # Check max requests
    max_requests = getattr(conn, 'max_requests', _POOL_MAX_REQUESTS)
    requests_served = getattr(conn, 'reuse_count', 0) + getattr(conn, 'handshake_count', 0)
    if max_requests > 0 and requests_served >= max_requests:
        return False

    return True


def discard_connection(conn, protocol="dot") -> None:
    """Safely discard a connection and remove from pool."""
    try:
        if hasattr(conn, 'close'):
            conn.close()
    except Exception:
        pass

    with _pool_metrics_lock:
        key = f"{protocol}_pool_discarded_total"
        _pool_metrics[key] = _pool_metrics.get(key, 0) + 1


def record_pool_metric(protocol: str, metric: str, value: int = 1) -> None:
    """Record a pool metric."""
    key = f"{protocol}_pool_{metric}"
    with _pool_metrics_lock:
        _pool_metrics[key] = _pool_metrics.get(key, 0) + value


def get_pool_metrics() -> dict:
    """Return current pool metrics."""
    with _pool_metrics_lock:
        return dict(_pool_metrics)


# ==============================================================================
# Pool Maintenance Worker
# ==============================================================================

def _pool_maintenance_worker() -> None:
    """Background worker that periodically maintains connection pools.

    Removes expired idle connections, connections beyond max lifetime,
    and closed/invalid sessions. Records pool size and discarded metrics.
    """
    while not _pool_maintenance_stop.is_set():
        try:
            _perform_pool_maintenance()
        except Exception:
            pass  # Ignore worker-level errors

        # Wait for next cycle or stop signal
        _pool_maintenance_stop.wait(_POOL_MAINTENANCE_INTERVAL)


def _app_module():
    """Return the loaded app module that owns the connection pools.

    "import app" would load app.py a second time when it runs as __main__
    (python app.py), so look the module up in sys.modules instead.
    """
    import sys
    for name in ("__main__", "app"):
        mod = sys.modules.get(name)
        if mod is not None and hasattr(mod, "dot_pools"):
            return mod
    return None


def _perform_pool_maintenance() -> None:
    """Perform pool maintenance: remove expired/invalid connections."""
    app_module = _app_module()
    if app_module is None:
        return

    discarded = {"dot": 0, "doh": 0}
    for proto, conn_cls in (("dot", "DotConnection"), ("doh", "DohConnection")):
        pools = getattr(app_module, f"{proto}_pools", None)
        pools_lock = getattr(app_module, f"{proto}_pools_lock", None)
        if pools is None or pools_lock is None:
            continue
        with pools_lock:
            for key, pool in list(pools.items()):
                for idx, conn in enumerate(pool):
                    # Skip connections that are busy with a query instead of
                    # blocking every pool lookup while holding pools_lock.
                    if not conn.lock.acquire(blocking=False):
                        continue
                    try:
                        # Never-used connections have no socket yet; leave them.
                        if conn.conn is None and not conn.closed:
                            continue
                        if conn.is_reusable():
                            continue
                        conn.close()
                        discarded[proto] += 1
                        record_pool_metric(proto, "expired_total")
                        pool[idx] = getattr(app_module, conn_cls)(conn.upstream)
                        record_pool_metric(proto, "created_total")
                    except Exception:
                        pass
                    finally:
                        conn.lock.release()

    for proto, count in discarded.items():
        if count > 0:
            record_pool_metric(proto, "discarded_total", count)


def start_pool_maintenance_worker() -> None:
    """Start the pool maintenance background worker thread."""
    with _pool_maintenance_lock:
        global _pool_maintenance_thread
        if _pool_maintenance_thread is not None and _pool_maintenance_thread.is_alive():
            return
        _pool_maintenance_stop.clear()
        _pool_maintenance_thread = threading.Thread(
            target=_pool_maintenance_worker,
            name="PyGuardDNS-PoolMaintenance",
            daemon=True,
        )
        _pool_maintenance_thread.start()


def stop_pool_maintenance_worker() -> None:
    """Stop the pool maintenance background worker thread."""
    _pool_maintenance_stop.set()
    with _pool_maintenance_lock:
        global _pool_maintenance_thread
        if _pool_maintenance_thread is not None:
            _pool_maintenance_thread.join(timeout=5.0)
            _pool_maintenance_thread = None


def get_pool_maintenance_status() -> dict:
    """Return the current status of the pool maintenance worker."""
    with _pool_maintenance_lock:
        thread_alive = _pool_maintenance_thread is not None and _pool_maintenance_thread.is_alive()
    return {
        "running": thread_alive,
        "interval_seconds": _POOL_MAINTENANCE_INTERVAL,
        "stop_requested": _pool_maintenance_stop.is_set(),
    }


# ==============================================================================
# Stuck Operation Watchdog Functions
# ==============================================================================

def _next_op_id() -> int:
    global _op_id_counter
    _op_id_counter += 1
    return _op_id_counter


def register_operation(upstream_id: int, protocol: str, deadline: float) -> int:
    """Register an active upstream operation."""
    op_id = _next_op_id()
    with _active_ops_lock:
        _active_operations[op_id] = {
            "operation_id": op_id,
            "upstream_id": upstream_id,
            "protocol": protocol,
            "started_monotonic": time.monotonic(),
            "deadline": deadline,
            "thread_or_task_id": threading.get_ident(),
        }
    return op_id


def complete_operation(op_id: int) -> None:
    """Mark an operation as completed."""
    with _active_ops_lock:
        _active_operations.pop(op_id, None)


def get_active_operations() -> list[dict]:
    """Return current active operations."""
    with _active_ops_lock:
        return list(_active_operations.values())


def get_stuck_operations() -> list[dict]:
    """Return currently stuck operations."""
    with _stuck_ops_lock:
        return list(_stuck_operations)


def _check_stuck_operations() -> None:
    """Check for stuck operations and record them."""
    global _stuck_ops_last_log
    now = time.monotonic()
    stuck = []

    with _active_ops_lock:
        for op_id, op in list(_active_operations.items()):
            elapsed = now - op["started_monotonic"]
            if elapsed > (op["deadline"] + _WATCHDOG_GRACE_SECONDS):
                stuck.append({
                    **op,
                    "elapsed_seconds": round(elapsed, 2),
                    "deadline_exceeded_by": round(elapsed - op["deadline"], 2),
                })

    if stuck:
        with _stuck_ops_lock:
            _stuck_operations.extend(stuck)
            # Rate-limit logging
            if now - _stuck_ops_last_log > 30:
                _stuck_ops_last_log = now
                for s in stuck:
                    import logging
                    log = logging.getLogger("PyGuardDNS.watchdog")
                    log.warning(
                        "UPSTREAM_OPERATION_STUCK: upstream_id=%d protocol=%s elapsed=%.1fs deadline=%.1fs",
                        s["upstream_id"], s["protocol"], s["elapsed_seconds"], s["deadline"],
                    )


def _watchdog_worker() -> None:
    """Background worker that checks for stuck operations."""
    while not _watchdog_stop.is_set():
        try:
            _check_stuck_operations()
        except Exception:
            pass

        _watchdog_stop.wait(_WATCHDOG_CHECK_INTERVAL)


def start_watchdog() -> None:
    """Start the stuck-operation watchdog worker."""
    with _watchdog_lock:
        global _watchdog_thread
        if _watchdog_thread is not None and _watchdog_thread.is_alive():
            return
        _watchdog_stop.clear()
        _watchdog_thread = threading.Thread(
            target=_watchdog_worker,
            name="PyGuardDNS-Watchdog",
            daemon=True,
        )
        _watchdog_thread.start()


def stop_watchdog() -> None:
    """Stop the stuck-operation watchdog worker."""
    _watchdog_stop.set()
    with _watchdog_lock:
        global _watchdog_thread
        if _watchdog_thread is not None:
            _watchdog_thread.join(timeout=5.0)
            _watchdog_thread = None


def get_watchdog_status() -> dict:
    """Return the current status of the watchdog."""
    with _watchdog_lock:
        thread_alive = _watchdog_thread is not None and _watchdog_thread.is_alive()
    with _stuck_ops_lock:
        stuck_count = len(_stuck_operations)
    with _active_ops_lock:
        active_count = len(_active_operations)
    return {
        "running": thread_alive,
        "check_interval_seconds": _WATCHDOG_CHECK_INTERVAL,
        "grace_seconds": _WATCHDOG_GRACE_SECONDS,
        "active_operations": active_count,
        "stuck_operations": stuck_count,
    }


# ==============================================================================
# Fallback Resolver Functions
# ==============================================================================

def _get_fallback_limiter() -> threading.Semaphore:
    """Get or create the fallback concurrency limiter."""
    global _fallback_limiter
    with _fallback_limiter_lock:
        if _fallback_limiter is None:
            _fallback_limiter = threading.Semaphore(5)  # Max 5 concurrent fallback queries
        return _fallback_limiter


def record_fallback_metric(metric: str, value: int = 1) -> None:
    """Record a fallback metric."""
    with _fallback_metrics_lock:
        _fallback_metrics[metric] = _fallback_metrics.get(metric, 0) + value


def get_fallback_metrics() -> dict:
    """Return current fallback metrics."""
    with _fallback_metrics_lock:
        return dict(_fallback_metrics)


def get_fallback_resolvers() -> list[dict]:
    """Return configured fallback resolvers."""
    return [dict(r) for r in _FALLBACK_RESOLVERS if r.get("enabled", True)]


def query_fallback_upstream(request: bytes, timeout: float = 5.0) -> Optional[tuple[bytes, str]]:
    """Query a fallback resolver when all configured upstreams are unavailable.

    Returns:
        Tuple of (response_bytes, resolver_name) on success, None on failure.
    """
    app_module = _app_module()
    if app_module is None:
        return None

    limiter = _get_fallback_limiter()
    if not limiter.acquire(timeout=2.0):
        record_fallback_metric("fallback_attempts_total")
        record_fallback_metric("fallback_failures_total")
        return None

    try:
        record_fallback_metric("fallback_attempts_total")
        record_fallback_metric("fallback_active", 1)

        for resolver in get_fallback_resolvers():
            try:
                # Use DoT/DoH directly, not through PyGuardDNS (avoid recursion)
                if resolver.get("transport") == "doth":
                    response = app_module.query_doh_upstream_once_fallback(
                        resolver, request, timeout=timeout
                    )
                    if response:
                        record_fallback_metric("fallback_success_total")
                        return (response, resolver["name"])
            except Exception:
                continue

        # All fallbacks failed
        record_fallback_metric("fallback_failures_total")
        return None
    finally:
        record_fallback_metric("fallback_active", -1)
        limiter.release()


def rebuild_pool(protocol: str, reason: str = "manual") -> None:
    """Rebuild a connection pool for a given protocol.

    Detaches the current pools so new queries lazily create fresh ones,
    gives in-flight queries a grace period, then closes the old connections.
    Rate-limited to prevent loops.
    """
    app_module = _app_module()
    if app_module is None:
        return

    now = time.time()
    rebuild_key = f"{protocol}_pool_rebuilds"

    with _pool_rebuilds_lock:
        last_rebuild = _pool_rebuilds.get(rebuild_key, {}).get("timestamp", 0)
        if now - last_rebuild < _WATCHDOG_POOL_REBUILD_COOLDOWN:
            return  # Too soon, skip

    pools = getattr(app_module, f"{protocol}_pools", None)
    pool_lock = getattr(app_module, f"{protocol}_pools_lock", None)
    if pools is None or pool_lock is None:
        return  # Pool not configured
    counters = getattr(app_module, f"{protocol}_pool_counters", {})

    with pool_lock:
        old_connections = [conn for pool in pools.values() for conn in pool]
        pools.clear()
        counters.clear()

    grace_end = time.monotonic() + 5.0
    for conn in old_connections:
        remaining = max(0.0, grace_end - time.monotonic())
        acquired = conn.lock.acquire(timeout=remaining) if hasattr(conn, "lock") else False
        try:
            conn.close()
        except Exception:
            pass
        finally:
            if acquired:
                conn.lock.release()

    with _pool_rebuilds_lock:
        _pool_rebuilds[rebuild_key] = {
            "timestamp": now,
            "reason": reason,
            "protocol": protocol,
        }

    import logging
    log = logging.getLogger("PyGuardDNS.pool_rebuild")
    log.info("UPSTREAM_POOL_REBUILT: protocol=%s reason=%s", protocol, reason)


def normalize_health_fields(data: dict) -> dict:
    """Normalize health fields for backward compatibility with old JSON files."""
    h = data.setdefault("health", {})
    for key, default in DEFAULT_HEALTH.items():
        if key not in h:
            h[key] = default
    # Ensure pause_reason is set
    if not h.get("pause_reason"):
        if h.get("paused"):
            h["pause_reason"] = PAUSE_REASON_HEALTH_BACKOFF
        else:
            h["pause_reason"] = ""
    # Ensure circuit_state is set
    if not h.get("circuit_state"):
        h["circuit_state"] = "closed"
    return h


def refresh_backoff_state(data: dict, now: Optional[float] = None) -> Tuple[dict, bool]:
    """Check if a resolver's health backoff has expired and transition to half-open.

    Returns:
        Tuple of (updated data dict, changed flag)
    """
    if now is None:
        now = time.time()

    h = normalize_health_fields(data)

    paused = bool(h.get("paused", False))
    backoff_until = float(h.get("backoff_until", 0) or 0)
    pause_reason = h.get("pause_reason", "")

    # Only health_backoff pauses can expire automatically
    if paused and pause_reason == PAUSE_REASON_HEALTH_BACKOFF and backoff_until > 0 and now >= backoff_until:
        h["paused"] = False
        h["circuit_state"] = "half_open"
        h["probe_required"] = True
        h["probe_in_flight"] = False
        h["last_backoff_expired"] = now
        h["pause_reason"] = ""
        return data, True

    return data, False


def _next_id() -> int:
    _ensure_dir()
    max_id = 0
    for fname in os.listdir(UPSTREAMS_DIR):
        if fname.endswith(".json"):
            try:
                mid = int(fname[:-5])
                if mid > max_id:
                    max_id = mid
            except ValueError:
                pass
    return max_id + 1


def load_all() -> list[dict]:
    _load_cache()
    with _cache_lock:
        return [dict(v) for v in _cache.values()]


def get(upstream_id: int) -> Optional[dict]:
    return _get_from_cache(upstream_id) or _load_file(upstream_id)


def get_all() -> list[dict]:
    return load_all()


def create(name: str, address: str, port: int = 53, resolver: str = "",
           resolver_type: str = "plain_udp", transport: str = "udp",
           dnscrypt_relay: str = "", enabled: bool = True,
           latency_ms=None, last_error: str = "", created_at: str = "") -> int:
    now = created_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    uid = _next_id()
    data = {
        "id": uid,
        "name": name,
        "address": address,
        "port": port,
        "resolver": resolver,
        "resolver_type": resolver_type,
        "transport": transport,
        "dnscrypt_relay": dnscrypt_relay,
        "enabled": enabled,
        "latency_ms": latency_ms,
        "last_error": last_error,
        "created_at": now,
        "health": {
            "latency_ms": 0.0,
            "success_rate": 1.0,
            "timeout_count": 0,
            "tls_failures": 0,
            "http_failures": 0,
            "servfail_count": 0,
            "last_error": "",
            "last_checked": 0.0,
            "consecutive_failures": 0,
            "backoff_level": 0,
            "paused": False,
            "total_queries": 0,
            "successful_queries": 0,
        },
    }
    _save_file(data)
    _update_cache(data)
    return uid


def update(upstream_id: int, **kwargs) -> bool:
    data = _load_file(upstream_id)
    if not data:
        return False
    for key, val in kwargs.items():
        if key in ("id", "health", "created_at"):
            continue
        if key == "enabled":
            val = bool(val)
        data[key] = val
    _save_file(data)
    _update_cache(data)
    return True


def delete(upstream_id: int):
    _delete_file(upstream_id)
    _remove_from_cache(upstream_id)


def set_enabled(upstream_id: int, enabled: bool) -> bool:
    return update(upstream_id, enabled=enabled)


def update_health(upstream_id: int, success: bool, latency_ms: float = 0.0, error: str = "") -> bool:
    data = _load_file(upstream_id)
    if not data:
        return False

    # Capture a single timestamp for this update
    now = time.time()
    data["last_checked"] = now

    h = normalize_health_fields(data)

    # Preserve manual pause - never overwrite it automatically
    is_manual_pause = h.get("pause_reason") == PAUSE_REASON_MANUAL and h.get("paused", False)

    h["total_queries"] = h.get("total_queries", 0) + 1
    h["successful_queries"] = h.get("successful_queries", 0) + (1 if success else 0)
    h["timeout_count"] = h.get("timeout_count", 0) + (0 if success else 1)

    error_lower = (error or "").lower()
    if "tls" in error_lower or "ssl" in error_lower or "certificate" in error_lower:
        h["tls_failures"] = h.get("tls_failures", 0) + 1
    if "http" in error_lower or "status" in error_lower:
        h["http_failures"] = h.get("http_failures", 0) + 1
    if "servfail" in error_lower:
        h["servfail_count"] = h.get("servfail_count", 0) + 1

    total = h["total_queries"]
    h["success_rate"] = h["successful_queries"] / total if total > 0 else 1.0

    was_paused = h.get("paused", False)

    if success:
        h["consecutive_failures"] = 0
        h["latency_ms"] = latency_ms
        h["last_error"] = ""
        h["last_success"] = now

        # EWMA update: alpha = 0.2
        alpha = 0.2
        old_ewma_success = h.get("ewma_success", 1.0)
        h["ewma_success"] = alpha * 1.0 + (1 - alpha) * old_ewma_success

        old_ewma_latency = h.get("ewma_latency_ms", 0.0)
        h["ewma_latency_ms"] = alpha * latency_ms + (1 - alpha) * old_ewma_latency

        # Only reset if not manually paused
        if not is_manual_pause:
            if was_paused or h.get("circuit_state") in (_CIRCUIT_OPEN, _CIRCUIT_HALF_OPEN):
                # Recovered from an automatic pause: the old failure streak
                # must not keep the resolver in "degraded"/"down".
                h["ewma_success"] = 1.0
            h["paused"] = False
            h["pause_reason"] = ""
            h["backoff_level"] = 0
            h["backoff_until"] = 0
            h["circuit_state"] = "closed"
            h["probe_required"] = False
            h["probe_in_flight"] = False
    else:
        h["last_failure"] = now
        h["last_error"] = (error or "")[:500]
        cf = h["consecutive_failures"] + 1
        h["consecutive_failures"] = cf

        # EWMA update for failure (success = 0)
        alpha = 0.2
        old_ewma_success = h.get("ewma_success", 1.0)
        h["ewma_success"] = alpha * 0.0 + (1 - alpha) * old_ewma_success

        # Only apply backoff if not manually paused
        if not is_manual_pause:
            if cf == 1:
                h["backoff_level"] = 0
            elif cf >= 10:
                h["backoff_level"] = 4
            elif cf >= 7:
                h["backoff_level"] = 3
            elif cf >= 4:
                h["backoff_level"] = 2

            backoff_seconds = {0: 0, 1: 30, 2: 60, 3: 300, 4: 900}.get(h.get("backoff_level", 0), 0)
            if backoff_seconds:
                h["backoff_until"] = now + backoff_seconds
                h["paused"] = True
                if not h.get("pause_reason") or h.get("pause_reason") == PAUSE_REASON_HEALTH_BACKOFF:
                    h["pause_reason"] = PAUSE_REASON_HEALTH_BACKOFF
                # Transition to open circuit
                h["circuit_state"] = "open"
            else:
                h["backoff_until"] = 0
                h["paused"] = False
        else:
            h["paused"] = True
            h["pause_reason"] = PAUSE_REASON_MANUAL

    data["latency_ms"] = h["latency_ms"] if success else data.get("latency_ms")
    data["last_error"] = h["last_error"]
    _save_file(data)
    _update_cache(data)
    return h.get("paused", False) and not was_paused


def get_health(upstream_id: int) -> dict:
    data = get(upstream_id)
    if data:
        return data.get("health", {})
    return {"upstream_id": upstream_id}


def set_health_paused(upstream_id: int, paused: bool, reason: str = PAUSE_REASON_MANUAL) -> bool:
    """Set manual pause for an upstream. Never use for health backoff (use update_health instead)."""
    data = _load_file(upstream_id)
    if not data:
        return False
    h = normalize_health_fields(data)
    h["paused"] = bool(paused)
    if paused:
        h["pause_reason"] = reason
        h["circuit_state"] = "open"
    else:
        h["pause_reason"] = ""
        h["circuit_state"] = "closed"
    _save_file(data)
    _update_cache(data)
    return True


def _health_score(data: dict) -> float:
    h = normalize_health_fields(data)
    # Circuit state has the strongest effect
    circuit = h.get("circuit_state", "closed")
    if circuit == "open":
        return 0.0
    if circuit == "half_open":
        return 50.0  # Half score for half-open

    # Use EWMA success rate (more accurate than cumulative success_rate)
    ewma_success = h.get("ewma_success", 1.0)
    base = ewma_success * 100.0

    # Use smoothed latency
    latency = h.get("ewma_latency_ms", data.get("latency_ms") or 999999)
    latency_score = max(0.0, 100.0 - latency * 0.5)

    # Consecutive failures matter more than lifetime failures
    consecutive = h.get("consecutive_failures", 0)
    failure_penalty = consecutive * 5.0

    # Lifetime counters kept as telemetry only, small penalty
    timeout_penalty = min(h.get("timeout_count", 0), 20) * 0.5
    tls_penalty = min(h.get("tls_failures", 0), 10) * 1.0

    score = base + latency_score - failure_penalty - timeout_penalty - tls_penalty
    return max(0.0, min(100.0, score))


def health_state(data: dict) -> str:
    h = normalize_health_fields(data)
    circuit = h.get("circuit_state", "closed")
    pause_reason = h.get("pause_reason", "")

    # Manual pause always returns down
    if h.get("paused", False) and pause_reason == PAUSE_REASON_MANUAL:
        return "down"

    # Circuit state
    if circuit == "open":
        return "down"
    if circuit == "half_open":
        return "recovering"

    cf = h.get("consecutive_failures", 0)
    ewma_success = h.get("ewma_success", 1.0)
    latency = h.get("ewma_latency_ms", data.get("latency_ms") or 0)
    total = h.get("total_queries", 0)
    if total < 3:
        return "healthy"
    if cf >= 7 or ewma_success < 0.3:
        return "down"
    if cf >= 4 or ewma_success < 0.6:
        return "degraded"
    if latency > 500 or ewma_success < 0.9:
        return "slow"
    return "healthy"


def active_upstreams() -> list[dict]:
    """Return only resolvers that are safe for normal production traffic.

    Excludes manually paused, open circuit, and half-open resolvers.
    Automatically recovers expired health_backoff pauses.
    """
    _load_cache()
    now = time.time()
    result = []
    with _cache_lock:
        for uid, data in list(_cache.items()):
            if not data.get("enabled", False):
                continue
            if data.get("resolver_type") == "dnscrypt_relay":
                continue

            h = normalize_health_fields(data)

            # Check for expired health backoff and recover
            data, changed = refresh_backoff_state(data, now)
            if changed:
                _save_file(data)
                _update_cache(data)

            # Re-read health after potential refresh
            h = data.get("health", {})

            # Exclude manual pauses
            if h.get("paused", False) and h.get("pause_reason") == PAUSE_REASON_MANUAL:
                continue

            # Exclude open circuits
            if h.get("circuit_state") == "open":
                continue

            # Exclude half-open circuits from production traffic
            if h.get("circuit_state") == "half_open":
                continue

            result.append({
                **data,
                "health_paused": h.get("paused", False),
                "pause_reason": h.get("pause_reason", ""),
                "circuit_state": h.get("circuit_state", "closed"),
                "success_rate": h.get("success_rate", 1.0),
                "ewma_success": h.get("ewma_success", 1.0),
                "ewma_latency_ms": h.get("ewma_latency_ms", 0.0),
                "timeout_count": h.get("timeout_count", 0),
                "consecutive_failures": h.get("consecutive_failures", 0),
                "last_checked": h.get("last_checked", 0),
                "last_success": h.get("last_success", 0),
                "last_failure": h.get("last_failure", 0),
                "total_queries": h.get("total_queries", 0),
                "successful_queries": h.get("successful_queries", 0),
                "backoff_until": h.get("backoff_until", 0),
                "health_score": _health_score(data),
                "health_state": health_state(data),
            })
    result.sort(key=lambda x: (
        0 if not x.get("last_error") else 1,
        -(x.get("health_score") or 0),
        x.get("ewma_latency_ms") or x.get("latency_ms") or 999999,
        x.get("id", 0),
    ))
    return result


def recoverable_upstreams() -> list[dict]:
    """Return enabled resolvers eligible for a recovery probe.

    Includes half_open circuits and health_backoff paused resolvers whose
    backoff has expired but not yet been recovered.
    """
    _load_cache()
    now = time.time()
    result = []
    with _cache_lock:
        for uid, data in list(_cache.items()):
            if not data.get("enabled", False):
                continue
            if data.get("resolver_type") == "dnscrypt_relay":
                continue

            h = normalize_health_fields(data)

            # Skip manual pauses
            if h.get("pause_reason") == PAUSE_REASON_MANUAL:
                continue

            # Skip closed circuits (already active)
            if h.get("circuit_state") == "closed":
                continue

            # Include half_open
            if h.get("circuit_state") == "half_open":
                result.append({
                    **data,
                    "circuit_state": h.get("circuit_state", "closed"),
                    "pause_reason": h.get("pause_reason", ""),
                    "backoff_until": h.get("backoff_until", 0),
                    "probe_required": h.get("probe_required", False),
                })
                continue

            # Check for expired health_backoff that hasn't been transitioned yet
            if h.get("paused") and h.get("pause_reason") == PAUSE_REASON_HEALTH_BACKOFF:
                backoff_until = float(h.get("backoff_until", 0) or 0)
                if backoff_until > 0 and now >= backoff_until:
                    result.append({
                        **data,
                        "circuit_state": "expired_backoff",
                        "pause_reason": PAUSE_REASON_HEALTH_BACKOFF,
                        "backoff_until": backoff_until,
                        "probe_required": True,
                    })
                    continue

    return result


def active_dnscrypt_relays() -> list[dict]:
    _load_cache()
    result = []
    with _cache_lock:
        for uid, data in list(_cache.items()):
            if not data.get("enabled", False):
                continue
            if data.get("resolver_type") != "dnscrypt_relay":
                continue
            h = data.get("health", {})
            if h.get("paused", False):
                continue
            result.append(dict(data))
    return result


def maybe_update_latency(upstream_id: int, latency_ms: float, error: str = ""):
    data = _load_file(upstream_id)
    if not data:
        return
    if error:
        data["latency_ms"] = None
        data["last_error"] = (error or "")[:500]
    else:
        old = data.get("latency_ms")
        if old is not None:
            data["latency_ms"] = old * 0.65 + latency_ms * 0.35
        else:
            data["latency_ms"] = latency_ms
        data["last_error"] = ""
    _save_file(data)
    _update_cache(data)


# ==============================================================================
# Health Recovery Worker
# ==============================================================================

def run_recovery_probe(upstream: dict) -> Optional[bool]:
    """Run one recovery probe for a recoverable upstream.

    Moves an expired health backoff to half_open first, then executes the
    probe and always completes it with finish_probe(). Returns the probe
    result, or None if no probe was started (not recoverable / already running).
    """
    uid = upstream["id"]
    data = get(uid)
    if not data:
        return None
    data, changed = refresh_backoff_state(data)
    if changed:
        _save_file(data)
        _update_cache(data)
        upstream = {**upstream, **data}
    if not begin_probe(uid):
        return None
    try:
        probe_success = _execute_health_probe(upstream)
    except Exception:
        finish_probe(uid, success=False, latency_ms=0.0, error="Health probe exception")
        return False
    finish_probe(
        uid,
        success=probe_success,
        latency_ms=0.0,
        error="" if probe_success else "Health probe failed",
    )
    return probe_success


def _health_recovery_worker() -> None:
    """Background worker that periodically checks and recovers unavailable upstreams.

    Runs in a separate thread. Checks recoverable upstreams every _HEALTH_PROBE_INTERVAL
    seconds, executes exactly one bounded health probe per upstream, and updates circuit
    state based on probe results.
    """
    while not _health_recovery_stop.is_set():
        try:
            for upstream in recoverable_upstreams():
                if _health_recovery_stop.is_set():
                    break
                run_recovery_probe(upstream)
        except Exception:
            pass  # Ignore worker-level errors

        # Wait for next interval or stop signal
        _health_recovery_stop.wait(_HEALTH_PROBE_INTERVAL)


# Optional probe callback registered by the app. It queries an upstream through
# the real resolver code path, so every transport (DoT, DoH, DoQ, ...) is covered.
_probe_function = None


def set_probe_function(fn) -> None:
    """Register fn(upstream: dict) -> bool used for recovery probes."""
    global _probe_function
    _probe_function = fn


def _execute_health_probe(upstream: dict) -> bool:
    """Execute a bounded health probe for an upstream.

    Uses a fixed domain (example.com) with strict timeout, no DNS cache,
    no filtering, no recursive use of PyGuardDNS itself.
    """
    if _probe_function is not None:
        try:
            return bool(_probe_function(upstream))
        except Exception:
            return False

    import socket
    import struct

    address = upstream.get("address", "")
    port = int(upstream.get("port", 53) or 0)
    transport = upstream.get("transport", "udp")

    if not address or port == 0:
        return False
    if transport not in ("udp", "plain_udp", "tcp"):
        # Encrypted transports need the app's resolver code (set_probe_function).
        return False

    # Build a simple DNS query for example.com A record
    txn_id = os.urandom(2)
    query_header = txn_id + struct.pack("!HHHHHH", 0x0100, 1, 1, 0, 0, 0)
    qname = _HEALTH_PROBE_QNAME
    query = query_header + qname + struct.pack("!HH", 1, 1)  # A record, IN class
    family = socket.AF_INET6 if ":" in address else socket.AF_INET

    try:
        if transport == "tcp":
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(_HEALTH_PROBE_TIMEOUT)
                sock.connect((address, port))
                sock.sendall(len(query).to_bytes(2, "big") + query)
                len_bytes = sock.recv(2)
                if len(len_bytes) != 2:
                    return False
                response_len = int.from_bytes(len_bytes, "big")
                response = b""
                while len(response) < response_len:
                    chunk = sock.recv(response_len - len(response))
                    if not chunk:
                        return False
                    response += chunk
        else:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(_HEALTH_PROBE_TIMEOUT)
                sock.sendto(query, (address, port))
                response, _ = sock.recvfrom(4096)
    except Exception:
        return False

    if len(response) < 12 or response[:2] != txn_id:
        return False
    resp_flags = struct.unpack("!H", response[2:4])[0]
    qr = (resp_flags >> 15) & 1
    rcode = resp_flags & 0x0F
    return qr == 1 and rcode == 0


def start_health_recovery_worker() -> None:
    """Start the health recovery background worker thread."""
    with _health_recovery_lock:
        global _health_recovery_thread
        if _health_recovery_thread is not None and _health_recovery_thread.is_alive():
            return
        _health_recovery_stop.clear()
        _health_recovery_thread = threading.Thread(
            target=_health_recovery_worker,
            name="PyGuardDNS-HealthRecovery",
            daemon=True,
        )
        _health_recovery_thread.start()


def stop_health_recovery_worker() -> None:
    """Stop the health recovery background worker thread."""
    _health_recovery_stop.set()
    with _health_recovery_lock:
        global _health_recovery_thread
        if _health_recovery_thread is not None:
            _health_recovery_thread.join(timeout=5.0)
            _health_recovery_thread = None


def get_health_recovery_status() -> dict:
    """Return the current status of the health recovery worker."""
    with _health_recovery_lock:
        thread_alive = _health_recovery_thread is not None and _health_recovery_thread.is_alive()
    return {
        "running": thread_alive,
        "interval_seconds": _HEALTH_PROBE_INTERVAL,
        "probe_timeout_seconds": _HEALTH_PROBE_TIMEOUT,
        "probe_domain": _HEALTH_PROBE_DOMAIN,
        "stop_requested": _health_recovery_stop.is_set(),
    }


# ==============================================================================
# Upstream Worker Slot Context Managers (guaranteed release)
# ==============================================================================

class UpstreamCapacityError(Exception):
    """Raised when upstream worker capacity is exhausted."""
    pass


@contextmanager
def upstream_worker_slot(limiter, timeout: float = 10.0, upstream_id: int = 0):
    """Context manager that guarantees worker slot release on every code path.

    Usage:
        with upstream_worker_slot(limiter, timeout=10.0, upstream_id=1):
            # Do work here - slot is guaranteed to be released
            pass
    """
    acquired = limiter.acquire(timeout=timeout)
    if not acquired:
        raise UpstreamCapacityError(
            f"Upstream worker capacity exhausted for upstream {upstream_id} "
            f"(timeout={timeout}s)"
        )
    try:
        yield
    finally:
        limiter.release()


async def async_upstream_worker_slot(limiter, timeout: float = 10.0, upstream_id: int = 0):
    """Async context manager for worker slot acquisition.

    Usage:
        async with async_upstream_worker_slot(limiter, timeout=10.0, upstream_id=1) as acquired:
            if acquired:
                # Do work here
                pass
    """
    import asyncio

    acquired = False

    def _acquire():
        nonlocal acquired
        acquired = limiter.acquire(timeout=timeout)
        if not acquired:
            raise UpstreamCapacityError(
                f"Upstream worker capacity exhausted for upstream {upstream_id} "
                f"(timeout={timeout}s)"
            )

    # Run acquire in thread pool to avoid blocking
    await asyncio.get_event_loop().run_in_executor(None, _acquire)
    try:
        yield True
    finally:
        if acquired:
            await asyncio.get_event_loop().run_in_executor(None, limiter.release)


def normalize_dnscrypt_relay():
    for up in get_all():
        resolver = (up.get("resolver") or "").strip()
        if not resolver.startswith("sdns://"):
            continue
        try:
            from app import detect_dns_stamp_type, parse_dnscrypt_relay_stamp
            stamp_type = detect_dns_stamp_type(resolver)
            if stamp_type == "dnscrypt_relay":
                info = parse_dnscrypt_relay_stamp(resolver)
                update(up["id"],
                       address=info["address"],
                       port=info["port"],
                       resolver_type="dnscrypt_relay",
                       transport="dnscrypt-relay",
                       dnscrypt_relay="")
        except Exception:
            pass


def migrate_from_sqlite(db):
    rows = db.execute("SELECT * FROM upstreams ORDER BY id ASC").fetchall()
    for row in rows:
        r = dict(row)
        uid = r.pop("id")
        health_row = db.execute(
            "SELECT * FROM upstream_health WHERE upstream_id=?", (uid,)
        ).fetchone()
        health = dict(health_row) if health_row else {}
        data = {
            "id": uid,
            "name": r.get("name", ""),
            "address": r.get("address", ""),
            "port": r.get("port", 53),
            "resolver": r.get("resolver", ""),
            "resolver_type": r.get("resolver_type", "plain_udp"),
            "transport": r.get("transport", "udp"),
            "dnscrypt_relay": r.get("dnscrypt_relay", ""),
            "enabled": bool(r.get("enabled", 1)),
            "latency_ms": r.get("latency_ms"),
            "last_error": r.get("last_error", ""),
            "created_at": r.get("created_at", ""),
            "health": {
                "latency_ms": health.get("latency_ms", 0.0),
                "success_rate": health.get("success_rate", 1.0),
                "timeout_count": health.get("timeout_count", 0),
                "last_error": health.get("last_error", ""),
                "last_checked": health.get("last_checked", 0.0),
                "consecutive_failures": health.get("consecutive_failures", 0),
                "paused": bool(health.get("paused", 0)),
                "pause_reason": PAUSE_REASON_HEALTH_BACKOFF if health.get("paused") else "",
                "backoff_until": health.get("backoff_until", 0.0),
                "backoff_level": health.get("backoff_level", 0),
                "circuit_state": "closed",
                "probe_required": False,
                "last_success": 0.0,
                "last_failure": 0.0,
                "ewma_success": 1.0,
                "ewma_latency_ms": 0.0,
                "total_queries": health.get("total_queries", 0),
                "successful_queries": health.get("successful_queries", 0),
                "tls_failures": health.get("tls_failures", 0),
                "http_failures": health.get("http_failures", 0),
                "servfail_count": health.get("servfail_count", 0),
            },
        }
        _save_file(data)
        _update_cache(data)
    _invalidate_cache()
