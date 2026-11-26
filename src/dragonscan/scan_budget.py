"""Per-invocation admission limits; never shared by scans on a reused scanner."""

import math
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

from dragonscan.models import Diagnostic, Finding, ScanReport
from dragonscan.risk import summarize


@dataclass(frozen=True)
class ScanLimits:
    max_artifacts: int = 4096
    max_bytes: int = 64 * 1024 * 1024
    max_regions: int = 128
    max_views: int = 256
    max_findings: int = 4096
    max_diagnostics: int = 512
    timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        for n in (
            self.max_artifacts,
            self.max_bytes,
            self.max_regions,
            self.max_views,
            self.max_findings,
            self.max_diagnostics,
        ):
            if type(n) is not int or n < 1:
                raise ValueError("scan budgets must be positive integers")
        if self.timeout_seconds is not None and (
            not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0
        ):
            raise ValueError("scan timeout must be finite and positive")


class ScanStopped(Exception):
    """Cooperative stop between two already-bounded operations."""


class ScanBudget:
    def __init__(self, limits: ScanLimits, cancelled: Callable[[], bool] | None):
        self.limits = limits
        self.cancelled = cancelled
        self.deadline = (
            time.monotonic() + limits.timeout_seconds
            if limits.timeout_seconds is not None
            else None
        )
        self.bytes_read = 0
        self.reason: str | None = None

    def running(self) -> bool:
        if self.reason is None:
            if self.cancelled is not None and self.cancelled():
                self.reason = "scan cancelled"
            elif self.deadline is not None and time.monotonic() >= self.deadline:
                self.reason = "scan deadline reached"
        return self.reason is None

    def checkpoint(self) -> None:
        if not self.running():
            raise ScanStopped

    def finish(self, report: ScanReport) -> ScanReport:
        # Optional providers have independent bounded batches. Enforce the same
        # public finding ceiling before admission to the next stage.
        if len(report.findings) > self.limits.max_findings:
            self.reason = self.reason or "scan finding budget reached"
            findings = report.findings[: self.limits.max_findings]
            risk, counts = summarize(findings)
            report = replace(report, findings=findings, counts=counts, risk=risk)
        if self.running() or report.coverage.get("budget_stopped"):
            return report
        assert self.reason is not None
        diagnostics = report.diagnostics
        if not any(self.reason == d.message for d in diagnostics):
            diagnostics = (*diagnostics, Diagnostic("coverage", self.reason))
        coverage = dict(report.coverage)
        coverage["budget_stopped"] = 1
        coverage["partially_analyzed"] += coverage["fully_analyzed"]
        coverage["fully_analyzed"] = 0
        return replace(report, diagnostics=diagnostics, coverage=coverage)


class BudgetBuffer[T](list[T]):
    """Consume at most the remaining allowance plus one witness of overflow."""

    def __init__(self, budget: ScanBudget, limit: int, reason: str):
        super().__init__()
        self.budget = budget
        self.limit = limit
        self.reason = reason

    def append(self, finding: T) -> None:
        if len(self) < self.limit:
            super().append(finding)
        elif self.budget.reason is None:
            self.budget.reason = self.reason

    def consume(self, values: Iterable[T]) -> None:
        # A yielding rule may do substantial work on each call to next().
        iterator = iter(values)
        while self.budget.running():
            try:
                item = next(iterator)
            except StopIteration:
                return
            self.append(item)

    def extend(self, values: Iterable[T]) -> None:
        for finding in values:
            if len(self) >= self.limit:
                self.budget.reason = self.budget.reason or self.reason
                break
            super().append(finding)


class FindingBuffer(BudgetBuffer[Finding]):
    def __init__(self, budget: ScanBudget, limit: int):
        super().__init__(budget, limit, "scan finding budget reached")
