from __future__ import annotations

from time import sleep

import pytest

from observability import (
    CircuitOpenError,
    DownstreamGuard,
    DownstreamGuardConfig,
    DownstreamTimeoutError,
    observability,
)


def _counter_value(name: str, **labels: str) -> float:
    snapshot = observability.snapshot()
    for counter in snapshot["metrics"]["counters"]:
        if counter["name"] != name:
            continue
        if all(counter["labels"].get(key) == str(value) for key, value in labels.items()):
            return float(counter["value"])
    return 0.0


def _timer_count(name: str, **labels: str) -> int:
    snapshot = observability.snapshot()
    for timer in snapshot["metrics"]["timers"]:
        if timer["name"] != name:
            continue
        if all(timer["labels"].get(key) == str(value) for key, value in labels.items()):
            return int(timer["count"])
    return 0


def _circuit_state(provider: str, name: str) -> dict[str, object] | None:
    snapshot = observability.snapshot()
    for circuit in snapshot["circuits"]:
        if circuit["provider"] == provider and circuit["name"] == name:
            return circuit
    return None


def test_downstream_guard_retries_and_records_metrics():
    attempts = {"count": 0}
    guard = DownstreamGuard(
        config=DownstreamGuardConfig(
            timeout_ms=250,
            max_retries=1,
            retry_backoff_ms=0,
            rate_limit_per_second=1000,
            circuit_failure_threshold=3,
            circuit_reset_seconds=60,
        )
    )

    def flaky_call() -> str:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("transient failure")
        return "ok"

    assert guard.call(
        provider="pytest-intel",
        operation="threat_intel.lookup_hash",
        func=flaky_call,
    ) == "ok"
    assert attempts["count"] == 2
    assert _counter_value(
        "downstream.calls_total",
        provider="pytest-intel",
        operation="threat_intel.lookup_hash",
    ) == 1.0
    assert _counter_value(
        "downstream.retries_total",
        provider="pytest-intel",
        operation="threat_intel.lookup_hash",
    ) == 1.0
    assert _counter_value(
        "downstream.failures_total",
        provider="pytest-intel",
        operation="threat_intel.lookup_hash",
        error="RuntimeError",
    ) == 1.0
    assert _timer_count(
        "downstream.latency_ms",
        provider="pytest-intel",
        operation="threat_intel.lookup_hash",
        outcome="success",
    ) == 1


def test_downstream_guard_opens_circuit_after_threshold():
    attempts = {"count": 0}
    guard = DownstreamGuard(
        config=DownstreamGuardConfig(
            timeout_ms=250,
            max_retries=0,
            retry_backoff_ms=0,
            rate_limit_per_second=1000,
            circuit_failure_threshold=1,
            circuit_reset_seconds=60,
        )
    )

    def always_fail() -> str:
        attempts["count"] += 1
        raise RuntimeError("permanent failure")

    with pytest.raises(RuntimeError):
        guard.call(
            provider="pytest-ticketing",
            operation="ticketing.create_ticket",
            func=always_fail,
        )

    with pytest.raises(CircuitOpenError):
        guard.call(
            provider="pytest-ticketing",
            operation="ticketing.create_ticket",
            func=always_fail,
        )

    assert attempts["count"] == 1
    assert _counter_value(
        "downstream.circuit_open_total",
        provider="pytest-ticketing",
        operation="ticketing.create_ticket",
    ) == 1.0
    circuit = _circuit_state("pytest-ticketing", "ticketing.create_ticket")
    assert circuit is not None
    assert circuit["state"] == "open"
    assert circuit["failure_count"] == 1


def test_downstream_guard_raises_timeout_and_records_failure():
    guard = DownstreamGuard(
        config=DownstreamGuardConfig(
            timeout_ms=10,
            max_retries=0,
            retry_backoff_ms=0,
            rate_limit_per_second=1000,
            circuit_failure_threshold=3,
            circuit_reset_seconds=60,
        )
    )

    def slow_call() -> str:
        sleep(0.05)
        return "late"

    with pytest.raises(DownstreamTimeoutError):
        guard.call(
            provider="pytest-cmdb",
            operation="cmdb.lookup_criticality",
            func=slow_call,
        )

    assert _counter_value(
        "downstream.failures_total",
        provider="pytest-cmdb",
        operation="cmdb.lookup_criticality",
        error="DownstreamTimeoutError",
    ) == 1.0
