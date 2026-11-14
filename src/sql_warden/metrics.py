"""What a running server has done, for Prometheus to scrape at /metrics.

Written out by hand in Prometheus's text format rather than with a client library: a few
counters, one gauge and two histograms need no dependency. Every label's values are bounded
(profiles from the config, checks and codes from the code), so no caller can grow the set:
an identity is never a label.
"""

import math
import threading
from collections.abc import Iterable, Sequence

from sql_warden import __version__
from sql_warden.models import Decision

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
LATENCY_BUCKETS_S = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
COST_BUCKETS = tuple(10.0**power for power in range(0, 13))
"""Powers of ten from 1 to 10^12: Postgres's planner units and Snowflake's bytes both fit."""

Labels = tuple[str, ...]


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(names: Sequence[str], values: Sequence[str], extra: str = "") -> str:
    pairs = [f'{name}="{_escape(value)}"' for name, value in zip(names, values, strict=True)]
    if extra:
        pairs.append(extra)
    return "{" + ",".join(pairs) + "}" if pairs else ""


def _number(value: float) -> str:
    if value == math.inf:
        return "+Inf"
    return str(int(value)) if float(value).is_integer() else repr(float(value))


class _Metric:
    kind = ""

    def __init__(self, name: str, help_: str, labelnames: Sequence[str] = ()) -> None:
        self.name = name
        self.help = help_
        self.labelnames = tuple(labelnames)
        self._lock = threading.Lock()

    def _key(self, labels: dict[str, str]) -> Labels:
        if set(labels) != set(self.labelnames):
            raise ValueError(f"{self.name} takes the labels {', '.join(self.labelnames)}")
        return tuple(str(labels[name]) for name in self.labelnames)

    def header(self) -> list[str]:
        return [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} {self.kind}"]

    def lines(self) -> list[str]:
        raise NotImplementedError


class Counter(_Metric):
    kind = "counter"

    def __init__(self, name: str, help_: str, labelnames: Sequence[str] = ()) -> None:
        super().__init__(name, help_, labelnames)
        self._values: dict[Labels, float] = {} if labelnames else {(): 0.0}

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        if amount < 0:
            raise ValueError("a counter only goes up")
        key = self._key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def value(self, **labels: str) -> float:
        with self._lock:
            return self._values.get(self._key(labels), 0.0)

    def lines(self) -> list[str]:
        with self._lock:
            values = sorted(self._values.items())
        return [f"{self.name}{_labels(self.labelnames, k)} {_number(v)}" for k, v in values]


class Gauge(_Metric):
    kind = "gauge"

    def __init__(self, name: str, help_: str) -> None:
        super().__init__(name, help_)
        self._value = 0.0

    def add(self, amount: float) -> None:
        with self._lock:
            self._value += amount

    def set(self, value: float) -> None:
        with self._lock:
            self._value = value

    @property
    def value(self) -> float:
        with self._lock:
            return self._value

    def lines(self) -> list[str]:
        return [f"{self.name} {_number(self.value)}"]


class Histogram(_Metric):
    kind = "histogram"

    def __init__(
        self, name: str, help_: str, labelnames: Sequence[str], buckets: Iterable[float]
    ) -> None:
        super().__init__(name, help_, labelnames)
        self.buckets = (*sorted(buckets), math.inf)
        self._counts: dict[Labels, list[int]] = {}
        self._sums: dict[Labels, float] = {}

    def observe(self, value: float, **labels: str) -> None:
        key = self._key(labels)
        with self._lock:
            counts = self._counts.setdefault(key, [0] * len(self.buckets))
            for index, bound in enumerate(self.buckets):
                if value <= bound:
                    counts[index] += 1  # cumulative: every bucket it fits in
            self._sums[key] = self._sums.get(key, 0.0) + value

    def count(self, **labels: str) -> int:
        with self._lock:
            counts = self._counts.get(self._key(labels))
            return 0 if counts is None else counts[-1]

    def lines(self) -> list[str]:
        with self._lock:
            series = sorted(
                (key, list(counts), self._sums[key]) for key, counts in self._counts.items()
            )
        lines = []
        for key, counts, total in series:
            for bound, count in zip(self.buckets, counts, strict=True):
                le = f'le="{_number(bound)}"'
                lines.append(f"{self.name}_bucket{_labels(self.labelnames, key, le)} {count}")
            lines.append(f"{self.name}_sum{_labels(self.labelnames, key)} {_number(total)}")
            lines.append(f"{self.name}_count{_labels(self.labelnames, key)} {counts[-1]}")
        return lines


class Metrics:
    """Every metric a server keeps. One per process, shared by every profile's Warden."""

    def __init__(self) -> None:
        self.info = Gauge("sql_warden_info", f"sql-warden is running; version {__version__}")
        self.info.set(1)
        self.requests = Counter(
            "sql_warden_requests_total",
            "Requests answered, by profile, kind (query or check) and decision.",
            ("profile", "kind", "decision"),
        )
        self.refusals = Counter(
            "sql_warden_refusals_total",
            "Requests refused, by profile, the check that refused them, and its code.",
            ("profile", "check", "code"),
        )
        self.duration = Histogram(
            "sql_warden_request_duration_seconds",
            "How long requests took, checks, planning and running included.",
            ("profile", "kind"),
            LATENCY_BUCKETS_S,
        )
        self.cost = Histogram(
            "sql_warden_estimated_cost",
            "The planner's estimate for each query it planned, in its own units.",
            ("profile",),
            COST_BUCKETS,
        )
        self.rows = Counter(
            "sql_warden_rows_returned_total", "Rows returned to callers.", ("profile",)
        )
        self.audit_failures = Counter(
            "sql_warden_audit_write_failures_total",
            "Requests whose audit record could not be written: answered AUDIT_UNAVAILABLE.",
        )
        self.auth_refusals = Counter(
            "sql_warden_auth_refusals_total",
            "HTTP requests turned away before reaching a profile, by code.",
            ("code",),
        )
        self.in_flight = Gauge(
            "sql_warden_requests_in_flight", "Requests being checked or run right now."
        )
        self._all: tuple[_Metric, ...] = (
            self.info,
            self.requests,
            self.refusals,
            self.duration,
            self.cost,
            self.rows,
            self.audit_failures,
            self.auth_refusals,
            self.in_flight,
        )

    def observe(
        self,
        decision: Decision,
        *,
        profile: str,
        dry_run: bool,
        duration_s: float,
        rows: int | None,
        failed: bool,
    ) -> None:
        """One request, as it was answered."""
        kind = "check" if dry_run else "query"
        refused = decision.refused_by
        outcome = "refused" if refused is not None else "failed" if failed else "allowed"
        self.requests.inc(profile=profile, kind=kind, decision=outcome)
        if refused is not None and refused.refusal is not None:
            self.refusals.inc(profile=profile, check=refused.check, code=refused.refusal.code)
        self.duration.observe(duration_s, profile=profile, kind=kind)
        if decision.cost is not None:
            self.cost.observe(max(decision.cost.total_cost, 0.0), profile=profile)
        if rows:
            self.rows.inc(rows, profile=profile)

    def render(self) -> str:
        lines: list[str] = []
        for metric in self._all:
            lines += metric.header()
            lines += metric.lines()
        return "\n".join(lines) + "\n"
