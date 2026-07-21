# PyGuardDNS Long-Running Resolver Stability Fix

## Objective

Fix the condition where PyGuardDNS works normally after startup but eventually stops resolving DNS queries until the server is restarted.

The fix must address the actual runtime lifecycle problems instead of adding a periodic full-process restart.

Primary targets:

- paused upstreams that never return automatically
- exhausted or leaked upstream worker slots
- stale DoT, DoH, DoH3, DoQ, TCP, and DNSCrypt connections
- resolver pools that remain broken after transient network failures
- inaccurate upstream worker monitoring
- missing automatic recovery when every configured upstream is unavailable
- insufficient regression tests for long-running operation

Do not remove existing resolver protocols, filtering features, DNSSEC validation, badges, dashboard features, or forwarding modes.

---

## Confirmed Critical Bug

`upstream_manager.update_health()` stores:

```python
health["paused"] = True
health["backoff_until"] = current_time + backoff_seconds
```

However, `active_upstreams()` currently skips every paused resolver unconditionally:

```python
if h.get("paused", False):
    continue
```

It does not check whether `backoff_until` has expired.

This creates a self-locking state:

1. An upstream experiences several temporary failures.
2. It is marked as paused.
3. `active_upstreams()` stops returning it.
4. It no longer receives normal requests.
5. It cannot produce a successful request that would reset its health state.
6. The resolver can remain excluded indefinitely.

Implement automatic backoff expiry and controlled recovery probing.

---

# Required Changes

## 1. Fix upstream backoff expiration

Modify `upstream_manager.py`.

Add a helper with behavior equivalent to:

```python
def refresh_backoff_state(data: dict, now: float | None = None) -> tuple[dict, bool]:
    now = time.time() if now is None else now
    health = data.setdefault("health", {})

    paused = bool(health.get("paused", False))
    backoff_until = float(health.get("backoff_until", 0) or 0)

    if paused and backoff_until > 0 and now >= backoff_until:
        health["paused"] = False
        health["probe_required"] = True
        health["probe_in_flight"] = False
        health["last_backoff_expired"] = now
        return data, True

    return data, False
```

Requirements:

- Expired temporary backoff must not remain permanently paused.
- Manual administrative disablement must remain separate from health backoff.
- `enabled=False` must never be changed automatically.
- Do not interpret `paused=True` without a backoff deadline as automatically recoverable unless it is explicitly marked as a health pause.
- Add a field such as:

```python
health["pause_reason"] = "health_backoff"
```

Supported pause reasons should include at least:

```text
health_backoff
manual
```

Only `health_backoff` may expire automatically.

Update `update_health()` so that it:

- writes `pause_reason="health_backoff"` when automatic backoff is activated
- clears `pause_reason`, `paused`, `backoff_until`, and `probe_required` after success
- does not overwrite a manual pause
- stores a bounded error string
- uses a single captured timestamp per update
- maintains backward compatibility with existing JSON files that do not contain the new fields

---

## 2. Recover expired upstreams safely

Do not immediately send unlimited production traffic to a resolver whose backoff just expired.

Implement a half-open circuit-breaker state.

Suggested health states:

```text
closed     = normal traffic allowed
open       = temporarily paused
half_open  = one controlled probe allowed
```

Store the state as:

```python
health["circuit_state"]
```

Required behavior:

### Closed

- Normal requests are allowed.
- A success resets consecutive failures.
- Repeated failures transition the resolver to `open`.

### Open

- Production requests are rejected for this upstream.
- The resolver stays open until `backoff_until`.
- When the deadline expires, transition to `half_open`.

### Half-open

- Permit only one probe at a time.
- Do not allow many concurrent client requests to probe the same resolver.
- A successful probe returns the resolver to `closed`.
- A failed probe returns it to `open` with the next backoff level.

Use an in-memory per-upstream probe lock or guarded flag. Do not rely only on a JSON boolean because concurrent threads can race.

Example runtime structure:

```python
_probe_locks: dict[int, threading.Lock] = {}
_probe_locks_guard = threading.Lock()
```

Add helper methods such as:

```python
def should_allow_request(upstream_id: int, *, is_probe: bool = False) -> bool:
    ...

def begin_probe(upstream_id: int) -> bool:
    ...

def finish_probe(
    upstream_id: int,
    *,
    success: bool,
    latency_ms: float = 0.0,
    error: str = "",
) -> None:
    ...
```

The exact names may differ, but the behavior must be thread-safe.

---

## 3. Add a dedicated health recovery worker

Add a lightweight background worker that periodically checks temporarily unavailable upstreams.

Suggested interval:

```text
5–15 seconds
```

The worker must:

1. Load enabled upstreams.
2. Ignore manually paused and administratively disabled entries.
3. Detect expired `health_backoff`.
4. Transition them to half-open.
5. Execute exactly one bounded health probe.
6. Restore the resolver after success.
7. Reopen the circuit after failure.
8. Never block the DNS request path.
9. Stop cleanly during application shutdown.

The probe must use a fixed, configurable domain, for example:

```text
example.com
```

Use an `A` query with:

- a strict total timeout
- no DNS cache
- no filtering
- no recursive use of PyGuardDNS itself
- no automatic retry loop across the same failed transport

Do not create a recursive bootstrap dependency.

---

## 4. Make active upstream selection backoff-aware

Update `active_upstreams()`.

Before filtering an upstream:

- normalize missing legacy health fields
- check whether automatic backoff expired
- persist the transition only when data changed
- exclude manual pauses
- exclude open circuits
- include closed circuits
- include half-open circuits only for controlled probes, not unrestricted production traffic

Prefer separate methods:

```python
active_upstreams()
recoverable_upstreams()
```

`active_upstreams()` must return only resolvers that are safe for normal traffic.

`recoverable_upstreams()` should return enabled resolvers eligible for a recovery probe.

Avoid writing the JSON file on every call when nothing changed.

---

## 5. Fix health-score degradation

The current health score uses cumulative failure counters such as `timeout_count` as an unbounded penalty. A resolver that had many historical failures can remain permanently disadvantaged even after recovery.

Change scoring so that:

- current circuit state has the strongest effect
- consecutive failures matter more than lifetime failures
- recent success rate uses a rolling window or exponentially weighted moving average
- cumulative counters remain available only as telemetry
- latency is smoothed
- successful recovery gradually restores the resolver score

Add fields similar to:

```python
health["ewma_success"]
health["ewma_latency_ms"]
health["last_success"]
health["last_failure"]
```

Suggested update:

```python
alpha = 0.2
ewma_success = alpha * current_success + (1 - alpha) * old_value
```

Do not reset lifetime counters when the application restarts.

---

## 6. Guarantee upstream worker release

Locate every acquisition of the upstream concurrency limiter, semaphore, executor slot, connection pool lease, or equivalent resource.

Every successful acquisition must have one guaranteed release path:

```python
acquired = limiter.acquire(timeout=...)
if not acquired:
    ...

try:
    ...
finally:
    limiter.release()
```

Audit all branches, including:

- success
- DNS timeout
- TCP timeout
- TLS handshake failure
- HTTP status error
- malformed DNS response
- DNSSEC failure
- task cancellation
- client disconnect
- exception while recording health
- exception while writing metrics
- parallel-race losing tasks
- fallback resolver paths

Never release a slot that was not acquired.

Add a context manager to reduce future mistakes:

```python
@contextmanager
def upstream_worker_slot(...):
    acquired = limiter.acquire(...)
    if not acquired:
        raise UpstreamCapacityError(...)
    try:
        yield
    finally:
        limiter.release()
```

For asynchronous code, provide an async context manager instead.

---

## 7. Add a real upstream worker limiter

If upstream concurrency currently uses only a raw semaphore, wrap it in a class that exposes an atomic snapshot.

Required metrics:

```text
base_limit
max_limit
active
waiters
peak_active
acquire_timeouts_total
rejected_total
completed_total
failed_total
oldest_active_seconds
last_completion_time
```

Track active operations with monotonic timestamps.

The limiter must:

- reject or time out predictably
- never exceed its configured limit
- detect underflow on release
- expose a thread-safe snapshot
- support configuration reload without replacing a live limiter unsafely

Do not confuse upstream errors with active workers.

---

## 8. Correct the System Monitor metrics

The System Monitor must not use `dns_upstream_errors_total` as the value for active upstream workers.

Replace any mapping equivalent to:

```python
"active": runtime_metrics.get("dns_upstream_errors_total", 0)
```

with the real upstream limiter snapshot:

```python
snapshot = upstream_worker_limiter.snapshot()

"upstream_workers": {
    "max_limit": snapshot.max_limit,
    "active": snapshot.active,
    "waiters": snapshot.waiters,
    "peak_active": snapshot.peak_active,
    "acquire_timeouts_total": snapshot.acquire_timeouts_total,
    "rejected_total": snapshot.rejected_total,
    "oldest_active_seconds": snapshot.oldest_active_seconds,
}
```

Keep `dns_upstream_errors_total` as a separate error metric.

Expose the corrected values through:

```text
/api/runtime_metrics
/metrics
System Monitor UI
```

Prometheus names should be explicit:

```text
pyguarddns_upstream_workers_active
pyguarddns_upstream_workers_waiters
pyguarddns_upstream_workers_limit
pyguarddns_upstream_worker_acquire_timeouts_total
pyguarddns_upstream_worker_rejected_total
pyguarddns_upstream_oldest_active_seconds
pyguarddns_upstream_recovery_attempts_total
pyguarddns_upstream_recovery_success_total
pyguarddns_upstream_recovery_failures_total
pyguarddns_upstream_circuits_open
pyguarddns_upstream_circuits_half_open
```

---

## 9. Invalidate broken pooled connections

Audit all persistent connection implementations:

- `DotConnection`
- `DohConnection`
- DoH3 sessions
- DoQ sessions
- TCP pools
- DNSCrypt connections or sessions

A pooled connection must be destroyed and not returned to the reusable pool after:

- read timeout
- write timeout
- EOF
- connection reset
- broken pipe
- TLS alert
- TLS handshake error
- invalid HTTP response
- HTTP connection shutdown
- malformed DNS frame
- protocol mismatch
- QUIC connection termination
- cancellation while an operation is in progress
- uncertain connection state

Implement a lease pattern:

```python
connection = pool.acquire(...)
healthy = False

try:
    response = connection.query(...)
    healthy = True
    return response
finally:
    if healthy and connection.is_reusable():
        pool.release(connection)
    else:
        pool.discard(connection)
```

`discard()` must close the socket/session safely.

Do not return a connection to the pool from an exception handler unless its protocol state is known to be reusable.

---

## 10. Add idle and lifetime limits to connection pools

Each pooled connection/session must track:

```text
created_at
last_used_at
requests_served
in_use
closed
```

Add configurable limits:

```text
idle_timeout
max_lifetime
max_requests_per_connection
connect_timeout
handshake_timeout
read_timeout
write_timeout
```

Before reuse, reject a connection when:

```python
now - last_used_at > idle_timeout
now - created_at > max_lifetime
requests_served >= max_requests_per_connection
connection.closed
```

Suggested conservative defaults:

```text
idle timeout: 15–30 seconds
maximum lifetime: 5–10 minutes
maximum requests: 100–500
```

Do not hardcode these values if equivalent settings already exist.

---

## 11. Add periodic pool maintenance

Implement a maintenance worker that runs independently of incoming DNS traffic.

It must:

- remove expired idle connections
- remove connections beyond maximum lifetime
- remove closed or invalid sessions
- clean stale in-use bookkeeping entries when the owning task is confirmed finished
- record pool size and discarded connection metrics
- never close a connection actively being used
- stop cleanly at shutdown

Expose per-protocol metrics:

```text
pool_total
pool_idle
pool_in_use
pool_created_total
pool_reused_total
pool_discarded_total
pool_expired_total
pool_connect_failures_total
```

---

## 12. Add a stuck-operation watchdog

Track each active upstream operation:

```python
operation_id
upstream_id
protocol
started_monotonic
thread_or_task_id
deadline
```

A watchdog should report an operation as stuck when it exceeds:

```text
configured request timeout + small grace period
```

Do not forcibly release a live semaphore from another thread. That can corrupt concurrency accounting.

Instead:

- log the full stuck-operation details
- cancel the owning async task when cancellation is safe
- close/discard its associated connection
- increment a metric
- allow the normal `finally` block to release the worker slot
- rebuild the affected protocol pool if repeated stuck operations exceed a threshold

Suggested metrics:

```text
pyguarddns_upstream_stuck_operations
pyguarddns_upstream_stuck_operations_total
pyguarddns_upstream_pool_rebuilds_total
```

Rate-limit identical warnings.

---

## 13. Add protocol-pool self-recovery

Provide a controlled pool rebuild function per protocol.

Example:

```python
def rebuild_pool(protocol: str, reason: str) -> None:
    ...
```

Requirements:

- atomically swap in a new pool
- mark the old pool as draining
- do not hand out new leases from the old pool
- allow active operations a short grace period
- close remaining old connections afterward
- do not restart the entire application
- rate-limit rebuilds to prevent loops
- expose the rebuild reason and timestamp in diagnostics

Trigger a rebuild only when justified, for example:

- repeated connection-state errors
- no successful completion for a defined interval while requests are pending
- multiple stuck operations
- pool accounting inconsistency
- all connections fail validation

---

## 14. Improve fallback behavior

When all configured upstreams are unavailable:

- use the existing hardcoded encrypted fallback resolvers
- give fallback requests their own bounded concurrency protection
- do not route fallback through a permanently exhausted configured-upstream pool
- do not permanently mark user-configured resolvers as failed because the fallback failed
- avoid recursive bootstrap through PyGuardDNS
- record whether a response came from fallback

Do not create an infinite configured-upstream → fallback → configured-upstream loop.

Add metrics:

```text
fallback_attempts_total
fallback_success_total
fallback_failures_total
fallback_active
```

---

## 15. Prevent parallel-race task leaks

Audit these forwarding modes:

```text
sequential
parallel_fastest
parallel_race
fastest_address
strict_order
load_balancing
```

For parallel modes:

- cancel losing tasks after the first acceptable answer
- await cancellation completion
- ensure every task releases its worker slot
- discard any connection whose request was cancelled mid-protocol
- do not leave futures in an executor queue
- enforce a total request deadline, not a full timeout per resolver multiplied by resolver count
- do not update a resolver as failed merely because it lost a successful race

Use structured cleanup such as:

```python
tasks = [...]
try:
    ...
finally:
    for task in tasks:
        if not task.done():
            task.cancel()
    await gather(*tasks, return_exceptions=True)
```

Adapt this safely for synchronous thread-pool code.

---

## 16. Bound all queues

Every runtime queue must have a finite maximum size.

At minimum inspect:

- DNS request queue
- upstream work queue
- query-log queue
- unknown-client queue
- health-probe queue
- connection creation queue
- executor work queue

When a queue is full:

- do not block forever
- return a controlled DNS failure or use stale cache when allowed
- increment a dedicated dropped/rejected metric
- log a rate-limited warning
- keep the process responsive

Do not silently create unbounded pending futures.

---

## 17. Serve stale cache during temporary upstream failure

When configured and safe:

- return an expired positive cache entry during a temporary upstream outage
- mark it internally as stale
- trigger at most one background refresh per cache key
- apply a maximum stale age
- do not serve stale entries for locally blocked or rewritten records incorrectly
- do not bypass DNSSEC policy without an explicit setting

This is resilience behavior, not a replacement for repairing upstream recovery.

---

## 18. Add a diagnostics endpoint

Add an authenticated endpoint:

```text
GET /api/diagnostics/resolver-runtime
```

Return structured data similar to:

```json
{
  "timestamp": 0,
  "upstream_workers": {},
  "active_operations": [],
  "stuck_operations": [],
  "pools": {},
  "circuits": [],
  "fallback": {},
  "last_successful_upstream_response": 0,
  "last_pool_rebuild": {},
  "warnings": []
}
```

Do not expose credentials, API tokens, private keys, complete DNS payloads, or client-sensitive query content.

Also add a button to the System Monitor:

```text
Download Resolver Diagnostics
```

The downloaded JSON should help diagnose the server before it is restarted.

---

## 19. Add manual recovery actions

Add authenticated administrative actions:

```text
Reset upstream health
Probe all upstreams
Rebuild resolver pools
Clear stuck-operation diagnostics
```

These actions must not require a full process restart.

They must be protected by:

- authentication
- CSRF validation
- audit logging
- rate limiting where appropriate

“Reset upstream health” must not enable resolvers that the administrator disabled.

---

## 20. Improve shutdown cleanup

Application shutdown must:

1. stop accepting new DNS work
2. stop health and maintenance workers
3. cancel pending resolver tasks
4. wait for active tasks for a bounded grace period
5. close all pools and sockets
6. shut down executors with cancellation where supported
7. flush metrics/log queues
8. persist final health state safely

Do not allow background threads to keep the process hanging indefinitely.

---

# Data Migration

Existing files under:

```text
data/upstreams/*.json
```

may not contain the new fields.

Implement a normalization helper that supplies defaults without breaking old files:

```python
{
    "paused": False,
    "pause_reason": "",
    "backoff_until": 0.0,
    "backoff_level": 0,
    "circuit_state": "closed",
    "probe_required": False,
    "last_success": 0.0,
    "last_failure": 0.0,
    "ewma_success": 1.0,
    "ewma_latency_ms": 0.0
}
```

Migration requirements:

- preserve resolver IDs
- preserve enabled/disabled state
- preserve addresses, protocols, stamps, and relay configuration
- preserve cumulative telemetry where possible
- write atomically with `os.replace`
- tolerate malformed optional health fields
- do not rewrite every file continuously

---

# Configuration

Add settings with safe defaults:

```text
upstream_health_probe_interval
upstream_health_probe_timeout
upstream_backoff_initial
upstream_backoff_max
upstream_half_open_max_probes
upstream_operation_grace_seconds
upstream_pool_maintenance_interval
upstream_pool_max_lifetime
upstream_pool_max_requests
upstream_pool_rebuild_threshold
upstream_pool_rebuild_cooldown
upstream_stale_cache_max_age
```

Validate all values.

Invalid values must fall back safely and produce a clear warning.

Do not require users to edit source code.

---

# Logging

Add structured, rate-limited log events for:

```text
UPSTREAM_CIRCUIT_OPEN
UPSTREAM_CIRCUIT_HALF_OPEN
UPSTREAM_CIRCUIT_CLOSED
UPSTREAM_BACKOFF_EXPIRED
UPSTREAM_PROBE_SUCCESS
UPSTREAM_PROBE_FAILURE
UPSTREAM_WORKER_EXHAUSTED
UPSTREAM_OPERATION_STUCK
UPSTREAM_CONNECTION_DISCARDED
UPSTREAM_POOL_REBUILT
UPSTREAM_FALLBACK_USED
UPSTREAM_ALL_UNAVAILABLE
```

Include:

```text
upstream_id
upstream_name
protocol
error_class
elapsed_ms
consecutive_failures
backoff_until
active_workers
waiters
```

Do not repeatedly log the same error for every DNS packet.

---

# Tests

Add deterministic tests. Do not depend on public DNS servers.

Use fake clocks, mock transports, local test servers, and injected failures.

## Required unit tests

### Backoff expiry

1. Resolver fails enough times to open the circuit.
2. `active_upstreams()` excludes it.
3. Advance fake time beyond `backoff_until`.
4. Resolver becomes eligible for one recovery probe.
5. Successful probe closes the circuit.
6. Resolver returns to normal active selection.

### Failed half-open probe

1. Circuit is open.
2. Backoff expires.
3. Exactly one half-open probe is allowed.
4. Probe fails.
5. Circuit opens again.
6. New backoff deadline is set.
7. Concurrent production traffic is not allowed through the half-open resolver.

### Manual pause

1. Resolver is manually paused.
2. Advance time by several hours.
3. It remains paused.
4. Recovery worker does not probe it.

### Worker release

Inject an exception at every important stage:

```text
connect
TLS handshake
send
receive
parse
DNSSEC
metrics update
health update
cancellation
```

After each case assert:

```python
snapshot.active == 0
snapshot.waiters == 0
```

### Connection discard

A timed-out or malformed pooled connection must:

- be closed
- be removed from the pool
- never be reused

### Parallel race cleanup

After one resolver wins:

- every loser is completed or cancelled
- no upstream workers remain active
- no connection lease remains in use
- no background future remains pending

### Metrics correctness

Create:

- two active upstream operations
- one waiter
- three historical upstream errors

Assert:

```text
upstream_workers.active == 2
upstream_workers.waiters == 1
dns_upstream_errors_total == 3
```

These values must not be mixed.

### Pool rebuild

Simulate repeated stale-connection failures and verify:

- one rebuild occurs
- new requests use the new pool
- old pool drains
- rebuild cooldown prevents a tight loop

### Fallback

When every configured resolver is open:

- fallback is attempted once within the total deadline
- a valid fallback response is returned
- no recursion occurs
- fallback metrics are updated

---

## Required long-running simulation

Add a test that simulates at least 100,000 DNS requests without public network access.

Inject:

- intermittent timeouts
- stale pooled connections
- TLS failures
- temporary total upstream outage
- resolver recovery
- cancelled parallel-race tasks
- queue pressure

At the end assert:

```text
active upstream workers == 0
waiters == 0
no leaked pool leases
no unbounded queue growth
at least one upstream recovered automatically
DNS service still answers requests
no process restart was required
```

---

# Acceptance Criteria

The change is complete only when all criteria below pass.

1. An automatically paused resolver returns after its backoff expires.
2. A manually paused or disabled resolver is never enabled automatically.
3. Only one half-open recovery probe runs per upstream.
4. Every acquired worker slot is released on every code path.
5. A failed pooled connection is discarded and never reused.
6. Pool maintenance removes expired connections.
7. Parallel resolver races leave no tasks or worker slots behind.
8. The System Monitor shows real active upstream workers.
9. Historical error totals are not shown as active workers.
10. The server can recover from a temporary loss of all upstreams without restart.
11. The server can rebuild a broken protocol pool without restarting the process.
12. Health recovery does not block the DNS request path.
13. Existing upstream JSON data is migrated safely.
14. Existing protocol support remains functional.
15. Existing DNSSEC, filtering, cache, profile, and dashboard behavior remains intact.
16. All new tests pass.
17. Existing tests pass.
18. No periodic full-process restart is introduced as the primary fix.

---

# Implementation Order

Implement in this order:

1. Add health-state normalization.
2. Fix expired backoff handling.
3. Implement circuit states and per-upstream half-open probe locking.
4. Add the health recovery worker.
5. Audit and fix upstream worker release paths.
6. Add accurate upstream worker snapshots and metrics.
7. Fix System Monitor metric mapping.
8. Harden connection leasing and invalidation.
9. Add pool maintenance and bounded lifetime.
10. Fix parallel-race cleanup.
11. Add fallback isolation.
12. Add watchdog and pool rebuild support.
13. Add diagnostics and manual recovery actions.
14. Add migration logic.
15. Add tests and long-running simulation.
16. Update README and configuration documentation.

---

# Deliverables

Provide:

- modified source files
- new tests
- migration logic
- updated configuration UI
- updated `/metrics`
- updated `/api/runtime_metrics`
- new resolver diagnostics endpoint
- updated System Monitor
- README documentation
- a concise changelog

In the final implementation report, list:

1. root causes found
2. files changed
3. concurrency leaks fixed
4. pool invalidation rules added
5. metrics corrected
6. recovery scenarios tested
7. remaining known limitations

Do not claim the problem is solved unless the long-running simulation and all worker/pool leak assertions pass.
