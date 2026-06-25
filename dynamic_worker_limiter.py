from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)

_RATE_LIMIT_INTERVAL = 10.0


@dataclass(frozen=True)
class WorkerLimiterSnapshot:
    base_limit: int
    max_limit: int
    current_limit: int
    active_workers: int
    peak_active_workers: int
    recent_peak: int
    waiters: int
    rejected_total: int
    burst_expansions_total: int
    shrink_total: int
    last_overload_time: float
    last_activity_time: float
    rejected_udp: int
    rejected_tcp: int
    rejected_dot: int


class DynamicDNSWorkerLimiter:
    def __init__(
        self,
        base_limit: int,
        max_limit: int,
        shrink_after: float,
    ) -> None:
        if base_limit < 1:
            raise ValueError("base_limit must be at least 1")
        if max_limit < base_limit:
            raise ValueError("max_limit must be >= base_limit")
        if shrink_after < 1:
            raise ValueError("shrink_after must be at least 1 second")

        self.base_limit = int(base_limit)
        self.max_limit = int(max_limit)
        self.current_limit = int(base_limit)
        self.shrink_after = float(shrink_after)

        self.active_workers = 0
        self.peak_active_workers = 0
        self._recent_peak = 0
        self.waiters = 0

        self.rejected_total = 0
        self.burst_expansions_total = 0
        self.shrink_total = 0

        self.rejected_udp = 0
        self.rejected_tcp = 0
        self.rejected_dot = 0

        now = time.monotonic()
        self.last_overload_time = 0.0
        self.last_activity_time = now

        self._condition = threading.Condition()

        self._last_burst_log = 0.0
        self._last_shrink_log = 0.0
        self._last_exhausted_log = 0.0

    def acquire(self, timeout: float = 0.0) -> bool:
        timeout = max(0.0, float(timeout))
        deadline = time.monotonic() + timeout

        with self._condition:
            self._shrink_locked()

            while self.active_workers >= self.current_limit:
                if self.current_limit < self.max_limit:
                    self.current_limit += 1
                    self.burst_expansions_total += 1
                    self.last_overload_time = time.monotonic()
                    now = time.monotonic()
                    if now - self._last_burst_log >= _RATE_LIMIT_INTERVAL:
                        self._last_burst_log = now
                        log.warning(
                            "DNS worker burst limit increased: current=%d base=%d max=%d active=%d",
                            self.current_limit, self.base_limit, self.max_limit, self.active_workers,
                        )
                    break

                if timeout <= 0:
                    self.rejected_total += 1
                    self._log_exhausted()
                    return False

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.rejected_total += 1
                    self._log_exhausted()
                    return False

                self.waiters += 1
                try:
                    self._condition.wait(timeout=remaining)
                finally:
                    self.waiters -= 1

                self._shrink_locked()

            self.active_workers += 1
            self.last_activity_time = time.monotonic()

            if self.active_workers > self.peak_active_workers:
                self.peak_active_workers = self.active_workers
            if self.active_workers > self._recent_peak:
                self._recent_peak = self.active_workers

            return True

    def release(self) -> None:
        with self._condition:
            if self.active_workers <= 0:
                raise RuntimeError(
                    "DynamicDNSWorkerLimiter.release() called without active worker"
                )
            self.active_workers -= 1
            self.last_activity_time = time.monotonic()
            self._shrink_locked()
            self._condition.notify()

    def maintenance(self) -> None:
        with self._condition:
            self._shrink_locked()

    def snapshot(self, reset_recent_peak: bool = False) -> WorkerLimiterSnapshot:
        with self._condition:
            self._shrink_locked()
            recent = max(self._recent_peak, self.active_workers)
            if reset_recent_peak:
                self._recent_peak = self.active_workers
            return WorkerLimiterSnapshot(
                base_limit=self.base_limit,
                max_limit=self.max_limit,
                current_limit=self.current_limit,
                active_workers=self.active_workers,
                peak_active_workers=self.peak_active_workers,
                recent_peak=recent,
                waiters=self.waiters,
                rejected_total=self.rejected_total,
                burst_expansions_total=self.burst_expansions_total,
                shrink_total=self.shrink_total,
                last_overload_time=self.last_overload_time,
                last_activity_time=self.last_activity_time,
                rejected_udp=self.rejected_udp,
                rejected_tcp=self.rejected_tcp,
                rejected_dot=self.rejected_dot,
            )

    def record_rejection(self, protocol: str) -> None:
        with self._condition:
            if protocol == "udp":
                self.rejected_udp += 1
            elif protocol == "tcp":
                self.rejected_tcp += 1
            elif protocol == "dot":
                self.rejected_dot += 1

    def update_limits(
        self,
        base_limit: int,
        max_limit: int,
        shrink_after: float,
    ) -> None:
        if base_limit < 1:
            raise ValueError("base_limit must be at least 1")
        if max_limit < base_limit:
            raise ValueError("max_limit must be >= base_limit")
        if shrink_after < 1:
            raise ValueError("shrink_after must be at least 1 second")

        with self._condition:
            self.base_limit = int(base_limit)
            self.max_limit = int(max_limit)
            self.shrink_after = float(shrink_after)
            if self.current_limit > self.max_limit:
                self.current_limit = self.max_limit
            if self.current_limit < self.base_limit:
                self.current_limit = self.base_limit
            if self.current_limit > self.base_limit and self.active_workers <= self.base_limit:
                self.current_limit = self.base_limit

    def reset_statistics(self) -> None:
        with self._condition:
            self.peak_active_workers = self.active_workers
            self._recent_peak = self.active_workers
            self.rejected_total = 0
            self.burst_expansions_total = 0
            self.shrink_total = 0
            self.rejected_udp = 0
            self.rejected_tcp = 0
            self.rejected_dot = 0

    def _shrink_locked(self) -> None:
        if self.current_limit <= self.base_limit:
            return
        if self.active_workers > self.base_limit:
            return

        now = time.monotonic()

        if now - self.last_overload_time < self.shrink_after:
            return

        old_limit = self.current_limit
        self.current_limit = self.base_limit
        self.shrink_total += 1

        if now - self._last_shrink_log >= _RATE_LIMIT_INTERVAL:
            self._last_shrink_log = now
            log.warning(
                "DNS worker burst limit reset: current=%d base=%d active=%d (was %d)",
                self.current_limit, self.base_limit, self.active_workers, old_limit,
            )

    def _log_exhausted(self) -> None:
        now = time.monotonic()
        if now - self._last_exhausted_log >= _RATE_LIMIT_INTERVAL:
            self._last_exhausted_log = now
            log.warning(
                "DNS worker capacity exhausted: active=%d current=%d max=%d",
                self.active_workers, self.current_limit, self.max_limit,
            )
