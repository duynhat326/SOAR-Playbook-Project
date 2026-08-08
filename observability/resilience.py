from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic, sleep
from typing import Any, Callable, TypeVar

from observability.runtime import observability

T = TypeVar("T")


class CircuitOpenError(RuntimeError):
    pass


class DownstreamTimeoutError(TimeoutError):
    pass


@dataclass(frozen=True)
class DownstreamGuardConfig:
    timeout_ms: int = 5000
    max_retries: int = 2
    retry_backoff_ms: int = 250
    rate_limit_per_second: float = 20.0
    circuit_failure_threshold: int = 3
    circuit_reset_seconds: float = 30.0

    @classmethod
    def from_env(cls) -> "DownstreamGuardConfig":
        return cls(
            timeout_ms=max(100, int(os.getenv("SOAR_DOWNSTREAM_TIMEOUT_MS", "5000"))),
            max_retries=max(0, int(os.getenv("SOAR_DOWNSTREAM_MAX_RETRIES", "2"))),
            retry_backoff_ms=max(0, int(os.getenv("SOAR_DOWNSTREAM_RETRY_BACKOFF_MS", "250"))),
            rate_limit_per_second=max(0.1, float(os.getenv("SOAR_DOWNSTREAM_RATE_LIMIT_PER_SECOND", "20"))),
            circuit_failure_threshold=max(1, int(os.getenv("SOAR_DOWNSTREAM_CIRCUIT_FAILURE_THRESHOLD", "3"))),
            circuit_reset_seconds=max(1.0, float(os.getenv("SOAR_DOWNSTREAM_CIRCUIT_RESET_SECONDS", "30"))),
        )


class _TokenBucket:
    def __init__(self, rate_limit_per_second: float) -> None:
        self._rate = rate_limit_per_second
        self._capacity = max(1.0, rate_limit_per_second)
        self._tokens = self._capacity
        self._last_refill = monotonic()

    def acquire(self) -> None:
        while True:
            now = monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            self._last_refill = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            wait_seconds = (1.0 - self._tokens) / self._rate
            sleep(min(wait_seconds, 0.05))


class _CircuitState:
    def __init__(self, reset_seconds: float) -> None:
        self.state = "closed"
        self.failure_count = 0
        self.opened_at_monotonic: float | None = None
        self.opened_at_iso: str | None = None
        self.half_open_probe = False
        self._reset_seconds = reset_seconds

    def allow_request(self) -> bool:
        if self.state == "closed":
            return True
        if self.state == "open":
            if self.opened_at_monotonic is None:
                return False
            if monotonic() - self.opened_at_monotonic >= self._reset_seconds:
                self.state = "half_open"
                self.half_open_probe = False
                return True
            return False
        if self.state == "half_open" and not self.half_open_probe:
            self.half_open_probe = True
            return True
        return False

    def mark_success(self) -> None:
        self.state = "closed"
        self.failure_count = 0
        self.opened_at_monotonic = None
        self.opened_at_iso = None
        self.half_open_probe = False

    def mark_failure(self, threshold: int) -> None:
        self.failure_count += 1
        if self.state == "half_open" or self.failure_count >= threshold:
            self.state = "open"
            self.opened_at_monotonic = monotonic()
            self.opened_at_iso = datetime.now(UTC).isoformat()
            self.half_open_probe = False


class DownstreamGuard:
    def __init__(self, *, config: DownstreamGuardConfig | None = None) -> None:
        self._config = config or DownstreamGuardConfig.from_env()
        self._lock = threading.Lock()
        self._buckets: dict[str, _TokenBucket] = {}
        self._circuits: dict[str, _CircuitState] = {}

    def call(
        self,
        *,
        provider: str,
        operation: str,
        func: Callable[[], T],
    ) -> T:
        key = f"{provider}:{operation}"
        bucket = self._bucket(key)
        circuit = self._circuit(key)

        with self._lock:
            if not circuit.allow_request():
                observability.metrics.incr(
                    "downstream.circuit_open_total",
                    provider=provider,
                    operation=operation,
                )
                observability.update_circuit_state(
                    name=operation,
                    provider=provider,
                    state=circuit.state,
                    failure_count=circuit.failure_count,
                    opened_at=circuit.opened_at_iso,
                    half_open_probe=circuit.half_open_probe,
                )
                raise CircuitOpenError(
                    f"Circuit for provider '{provider}' operation '{operation}' is open."
                )

        bucket.acquire()
        observability.metrics.incr(
            "downstream.calls_total",
            provider=provider,
            operation=operation,
        )

        last_error: Exception | None = None
        for attempt in range(1, self._config.max_retries + 2):
            started = monotonic()
            try:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(func)
                    result = future.result(timeout=self._config.timeout_ms / 1000)
                elapsed_ms = (monotonic() - started) * 1000
                with self._lock:
                    circuit.mark_success()
                    observability.update_circuit_state(
                        name=operation,
                        provider=provider,
                        state=circuit.state,
                        failure_count=circuit.failure_count,
                        opened_at=circuit.opened_at_iso,
                        half_open_probe=circuit.half_open_probe,
                    )
                observability.metrics.observe(
                    "downstream.latency_ms",
                    elapsed_ms,
                    provider=provider,
                    operation=operation,
                    outcome="success",
                )
                return result
            except FutureTimeoutError as exc:
                last_error = DownstreamTimeoutError(
                    f"Timed out calling provider '{provider}' operation '{operation}'."
                )
                self._record_failure(
                    provider=provider,
                    operation=operation,
                    circuit=circuit,
                    error=last_error,
                )
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                self._record_failure(
                    provider=provider,
                    operation=operation,
                    circuit=circuit,
                    error=exc,
                )

            if attempt <= self._config.max_retries:
                observability.metrics.incr(
                    "downstream.retries_total",
                    provider=provider,
                    operation=operation,
                )
                sleep((self._config.retry_backoff_ms / 1000) * attempt)

        assert last_error is not None
        raise last_error

    def _record_failure(
        self,
        *,
        provider: str,
        operation: str,
        circuit: _CircuitState,
        error: Exception,
    ) -> None:
        with self._lock:
            circuit.mark_failure(self._config.circuit_failure_threshold)
            observability.update_circuit_state(
                name=operation,
                provider=provider,
                state=circuit.state,
                failure_count=circuit.failure_count,
                opened_at=circuit.opened_at_iso,
                half_open_probe=circuit.half_open_probe,
            )
        observability.metrics.incr(
            "downstream.failures_total",
            provider=provider,
            operation=operation,
            error=error.__class__.__name__,
        )

    def _bucket(self, key: str) -> _TokenBucket:
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _TokenBucket(self._config.rate_limit_per_second)
                self._buckets[key] = bucket
            return bucket

    def _circuit(self, key: str) -> _CircuitState:
        with self._lock:
            circuit = self._circuits.get(key)
            if circuit is None:
                circuit = _CircuitState(self._config.circuit_reset_seconds)
                self._circuits[key] = circuit
            return circuit

    def reset_for_tests(self) -> None:
        with self._lock:
            self._buckets.clear()
            self._circuits.clear()


downstream_guard = DownstreamGuard()
