"""Explainable aggregate risk, separate from rules and reporting."""

from collections import Counter

from dragonscan.models import Finding, Severity

ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def summarize(findings: tuple[Finding, ...]) -> tuple[Severity | None, dict[str, int]]:
    counts = Counter(finding.severity for finding in findings)
    return next((level for level in ORDER if counts[level]), None), {
        level.value: counts[level] for level in ORDER
    }


def meets_threshold(severity: Severity | None, threshold: Severity) -> bool:
    return severity is not None and ORDER.index(severity) <= ORDER.index(threshold)
