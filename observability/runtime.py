from __future__ import annotations

import json
import os
import threading
from collections import deque
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any, Iterator, Optional
from uuid import uuid4


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _normalize_labels(labels: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    normalized: list[tuple[str, str]] = []
    for key, value in sorted(labels.items()):
        normalized.append((str(key), str(value)))
    return tuple(normalized)


def _label_key(name: str, labels: dict[str, Any]) -> str:
    if not labels:
        return name
    rendered = ",".join(f"{key}={value}" for key, value in _normalize_labels(labels))
    return f"{name}|{rendered}"


@dataclass
class CounterMetric:
    name: str
    labels: dict[str, str]
    value: float = 0.0
    updated_at: str = field(default_factory=lambda: _utc_now().isoformat())


@dataclass
class GaugeMetric:
    name: str
    labels: dict[str, str]
    value: float = 0.0
    updated_at: str = field(default_factory=lambda: _utc_now().isoformat())


@dataclass
class TimerMetric:
    name: str
    labels: dict[str, str]
    count: int = 0
    total_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0
    last_ms: float = 0.0
    updated_at: str = field(default_factory=lambda: _utc_now().isoformat())

    def observe(self, value_ms: float) -> None:
        self.count += 1
        self.total_ms += value_ms
        self.last_ms = value_ms
        self.min_ms = value_ms if self.count == 1 else min(self.min_ms, value_ms)
        self.max_ms = value_ms if self.count == 1 else max(self.max_ms, value_ms)
        self.updated_at = _utc_now().isoformat()

    @property
    def average_ms(self) -> float:
        if self.count == 0:
            return 0.0
        return self.total_ms / self.count


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, CounterMetric] = {}
        self._gauges: dict[str, GaugeMetric] = {}
        self._timers: dict[str, TimerMetric] = {}

    def incr(self, name: str, amount: float = 1.0, **labels: Any) -> None:
        metric_key = _label_key(name, labels)
        with self._lock:
            metric = self._counters.get(metric_key)
            if metric is None:
                metric = CounterMetric(
                    name=name,
                    labels={key: value for key, value in _normalize_labels(labels)},
                )
                self._counters[metric_key] = metric
            metric.value += amount
            metric.updated_at = _utc_now().isoformat()

    def set_gauge(self, name: str, value: float, **labels: Any) -> None:
        metric_key = _label_key(name, labels)
        with self._lock:
            metric = self._gauges.get(metric_key)
            if metric is None:
                metric = GaugeMetric(
                    name=name,
                    labels={key: value for key, value in _normalize_labels(labels)},
                )
                self._gauges[metric_key] = metric
            metric.value = value
            metric.updated_at = _utc_now().isoformat()

    def observe(self, name: str, value_ms: float, **labels: Any) -> None:
        metric_key = _label_key(name, labels)
        with self._lock:
            metric = self._timers.get(metric_key)
            if metric is None:
                metric = TimerMetric(
                    name=name,
                    labels={key: value for key, value in _normalize_labels(labels)},
                )
                self._timers[metric_key] = metric
            metric.observe(value_ms)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            counters = [
                {
                    "name": metric.name,
                    "labels": metric.labels,
                    "value": metric.value,
                    "updated_at": metric.updated_at,
                }
                for metric in self._counters.values()
            ]
            gauges = [
                {
                    "name": metric.name,
                    "labels": metric.labels,
                    "value": metric.value,
                    "updated_at": metric.updated_at,
                }
                for metric in self._gauges.values()
            ]
            timers = [
                {
                    "name": metric.name,
                    "labels": metric.labels,
                    "count": metric.count,
                    "total_ms": round(metric.total_ms, 3),
                    "average_ms": round(metric.average_ms, 3),
                    "min_ms": round(metric.min_ms, 3),
                    "max_ms": round(metric.max_ms, 3),
                    "last_ms": round(metric.last_ms, 3),
                    "updated_at": metric.updated_at,
                }
                for metric in self._timers.values()
            ]
        return {
            "counters": sorted(counters, key=lambda item: (item["name"], json.dumps(item["labels"], sort_keys=True))),
            "gauges": sorted(gauges, key=lambda item: (item["name"], json.dumps(item["labels"], sort_keys=True))),
            "timers": sorted(timers, key=lambda item: (item["name"], json.dumps(item["labels"], sort_keys=True))),
        }

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._timers.clear()


@dataclass
class SpanRecord:
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    started_at: str
    ended_at: Optional[str] = None
    duration_ms: Optional[float] = None
    status: str = "running"
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class TraceRecord:
    trace_id: str
    root_name: str
    started_at: str
    attributes: dict[str, Any] = field(default_factory=dict)
    ended_at: Optional[str] = None
    status: str = "running"
    spans: list[SpanRecord] = field(default_factory=list)


class StructuredEventSink:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, payload: dict[str, Any]) -> None:
        with self._lock:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    @property
    def path(self) -> Path:
        return self._path

    def truncate(self) -> None:
        with self._lock:
            self._path.write_text("", encoding="utf-8")


class ObservabilityRuntime:
    def __init__(self) -> None:
        log_path = Path(
            os.getenv(
                "SOAR_OBSERVABILITY_LOG_PATH",
                str(Path("output") / "observability.jsonl"),
            )
        )
        self._started_at = _utc_now()
        self._metrics = MetricsRegistry()
        self._sink = StructuredEventSink(log_path)
        self._recent_traces: deque[TraceRecord] = deque(
            maxlen=max(10, int(os.getenv("SOAR_OBSERVABILITY_TRACE_BUFFER", "100")))
        )
        self._lock = threading.Lock()
        self._trace_id: ContextVar[str | None] = ContextVar("observability_trace_id", default=None)
        self._span_id: ContextVar[str | None] = ContextVar("observability_span_id", default=None)
        self._trace_record: ContextVar[TraceRecord | None] = ContextVar("observability_trace_record", default=None)
        self._context_fields: ContextVar[dict[str, Any]] = ContextVar("observability_context_fields", default={})
        self._circuit_states: dict[str, dict[str, Any]] = {}

    @property
    def metrics(self) -> MetricsRegistry:
        return self._metrics

    @property
    def log_path(self) -> Path:
        return self._sink.path

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            traces = [
                {
                    "trace_id": trace.trace_id,
                    "root_name": trace.root_name,
                    "started_at": trace.started_at,
                    "ended_at": trace.ended_at,
                    "status": trace.status,
                    "attributes": trace.attributes,
                    "spans": [
                        {
                            "trace_id": span.trace_id,
                            "span_id": span.span_id,
                            "parent_span_id": span.parent_span_id,
                            "name": span.name,
                            "started_at": span.started_at,
                            "ended_at": span.ended_at,
                            "duration_ms": span.duration_ms,
                            "status": span.status,
                            "attributes": span.attributes,
                        }
                        for span in trace.spans
                    ],
                }
                for trace in list(self._recent_traces)
            ]
            circuits = [
                dict(state)
                for _, state in sorted(self._circuit_states.items(), key=lambda item: item[0])
            ]
        uptime_seconds = max((_utc_now() - self._started_at).total_seconds(), 0.0)
        return {
            "started_at": self._started_at.isoformat(),
            "uptime_seconds": round(uptime_seconds, 3),
            "structured_log_path": str(self._sink.path),
            "metrics": self._metrics.snapshot(),
            "traces": {
                "buffer_size": self._recent_traces.maxlen,
                "recent": traces,
            },
            "circuits": circuits,
        }

    def reset_for_tests(self, *, truncate_logs: bool = True) -> None:
        self._metrics.reset()
        with self._lock:
            self._started_at = _utc_now()
            self._recent_traces.clear()
            self._circuit_states.clear()
        self._trace_id.set(None)
        self._span_id.set(None)
        self._trace_record.set(None)
        self._context_fields.set({})
        if truncate_logs:
            self._sink.truncate()

    def update_circuit_state(
        self,
        *,
        name: str,
        provider: str,
        state: str,
        failure_count: int,
        opened_at: Optional[str],
        half_open_probe: bool,
    ) -> None:
        payload = {
            "name": name,
            "provider": provider,
            "state": state,
            "failure_count": failure_count,
            "opened_at": opened_at,
            "half_open_probe": half_open_probe,
            "updated_at": _utc_now().isoformat(),
        }
        with self._lock:
            self._circuit_states[f"{provider}:{name}"] = payload

    def emit_event(
        self,
        level: str,
        event: str,
        *,
        message: str = "",
        **fields: Any,
    ) -> None:
        payload = {
            "timestamp": _utc_now().isoformat(),
            "level": level,
            "event": event,
            "message": message,
            "trace_id": self._trace_id.get(),
            "span_id": self._span_id.get(),
            **self._context_fields.get(),
            **fields,
        }
        self._sink.write(payload)

    @contextmanager
    def bind_context(self, **fields: Any) -> Iterator[None]:
        current = dict(self._context_fields.get())
        current.update({key: value for key, value in fields.items() if value is not None})
        token = self._context_fields.set(current)
        try:
            yield
        finally:
            self._context_fields.reset(token)

    @contextmanager
    def trace(self, name: str, **attributes: Any) -> Iterator[str]:
        trace_id = uuid4().hex
        span_id = uuid4().hex
        trace = TraceRecord(
            trace_id=trace_id,
            root_name=name,
            started_at=_utc_now().isoformat(),
            attributes={key: value for key, value in attributes.items() if value is not None},
        )
        root_span = SpanRecord(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=None,
            name=name,
            started_at=trace.started_at,
            attributes=dict(trace.attributes),
        )
        trace.spans.append(root_span)
        trace_token = self._trace_id.set(trace_id)
        span_token = self._span_id.set(span_id)
        record_token = self._trace_record.set(trace)
        context_token = self._context_fields.set(
            {
                **self._context_fields.get(),
                **trace.attributes,
                "trace_id": trace_id,
            }
        )
        started = perf_counter()
        self.emit_event("info", "trace.started", message=name, trace_name=name)
        try:
            yield trace_id
            root_span.status = "ok"
            trace.status = "ok"
        except Exception as exc:
            root_span.status = "error"
            trace.status = "error"
            root_span.attributes["error"] = exc.__class__.__name__
            trace.attributes["error"] = exc.__class__.__name__
            self.emit_event(
                "error",
                "trace.failed",
                message=name,
                trace_name=name,
                error=exc.__class__.__name__,
            )
            raise
        finally:
            elapsed_ms = (perf_counter() - started) * 1000
            ended_at = _utc_now().isoformat()
            root_span.ended_at = ended_at
            root_span.duration_ms = round(elapsed_ms, 3)
            trace.ended_at = ended_at
            self._metrics.incr("workflow.requests_total", trace_name=name, status=trace.status)
            self._metrics.observe("workflow.request_latency_ms", elapsed_ms, trace_name=name, status=trace.status)
            self.emit_event(
                "info",
                "trace.finished",
                message=name,
                trace_name=name,
                status=trace.status,
                duration_ms=round(elapsed_ms, 3),
            )
            with self._lock:
                self._recent_traces.appendleft(trace)
            self._context_fields.reset(context_token)
            self._trace_record.reset(record_token)
            self._span_id.reset(span_token)
            self._trace_id.reset(trace_token)

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[str]:
        trace_id = self._trace_id.get()
        if trace_id is None:
            with self.trace(name, **attributes) as root_trace_id:
                yield root_trace_id
            return

        parent_span_id = self._span_id.get()
        span_id = uuid4().hex
        started_at = _utc_now().isoformat()
        span = SpanRecord(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            name=name,
            started_at=started_at,
            attributes={key: value for key, value in attributes.items() if value is not None},
        )
        trace = self._trace_record.get()
        if trace is not None:
            trace.spans.append(span)
        token = self._span_id.set(span_id)
        context_token: Optional[Token] = None
        if attributes:
            current = dict(self._context_fields.get())
            current.update({key: value for key, value in attributes.items() if value is not None})
            context_token = self._context_fields.set(current)
        started = perf_counter()
        self.emit_event("debug", "span.started", message=name, span_name=name)
        try:
            yield span_id
            span.status = "ok"
        except Exception as exc:
            span.status = "error"
            span.attributes["error"] = exc.__class__.__name__
            self.emit_event(
                "error",
                "span.failed",
                message=name,
                span_name=name,
                error=exc.__class__.__name__,
            )
            raise
        finally:
            elapsed_ms = (perf_counter() - started) * 1000
            span.ended_at = _utc_now().isoformat()
            span.duration_ms = round(elapsed_ms, 3)
            self._metrics.observe("span.duration_ms", elapsed_ms, span_name=name, status=span.status)
            self.emit_event(
                "debug",
                "span.finished",
                message=name,
                span_name=name,
                status=span.status,
                duration_ms=round(elapsed_ms, 3),
            )
            if context_token is not None:
                self._context_fields.reset(context_token)
            self._span_id.reset(token)


observability = ObservabilityRuntime()
