"""Single CI policy decision shared by all output formats and the CLI."""

from dataclasses import asdict, dataclass

from dragonscan.models import ScanReport, Severity
from dragonscan.risk import meets_threshold


@dataclass(frozen=True)
class PolicyResult:
    status: str  # pass, policy_violation, incomplete, scan_error
    scan_status: str  # complete, partial, failed
    reason: str
    triggering_findings: tuple[str, ...]
    incomplete: tuple[str, ...]
    execution_errors: bool

    @property
    def exit_code(self) -> int:
        return {"pass": 0, "policy_violation": 1, "incomplete": 3, "scan_error": 3}[self.status]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def evaluate(
    report: ScanReport, fail_on: Severity | None = None, *, fail_on_incomplete: bool = False
) -> PolicyResult:
    """Execution failure wins over incomplete coverage, which wins over findings."""
    errors = bool(report.errors) or report.acquisition_status in {"blocked", "failed"}
    incomplete = tuple(
        name
        for name, partial in (
            ("acquisition", report.acquisition_status == "partial"),
            ("vulnerability", report.vulnerability_status == "partial"),
            ("intelligence", report.intelligence_status == "partial"),
            ("semantic", report.semantic_status == "partial"),
            ("dynamic_mcp", report.dynamic_status in {"blocked", "partial", "failed"}),
            (
                "installed_agents",
                any(item.status == "diagnostic" for item in report.installed_environments)
                or (
                    fail_on_incomplete
                    and any(item.resolution == "partial" for item in report.installed_environments)
                ),
            ),
            (
                "semantic_budget",
                fail_on_incomplete
                and report.semantic_status != "disabled"
                and report.semantic_candidates_analyzed < report.semantic_candidates_selected,
            ),
        )
        if partial
    )
    triggers = (
        tuple(
            sorted(
                {f.detection_id for f in report.findings if meets_threshold(f.severity, fail_on)}
            )
        )
        if fail_on is not None
        else ()
    )
    if errors:
        return PolicyResult(
            "scan_error", "failed", "Scanner or acquisition error", triggers, incomplete, True
        )
    if incomplete:
        return PolicyResult(
            "incomplete", "partial", "Required analysis incomplete", triggers, incomplete, False
        )
    if triggers:
        return PolicyResult(
            "policy_violation",
            "complete",
            "Finding severity threshold reached",
            triggers,
            (),
            False,
        )
    return PolicyResult(
        "pass", "complete", "Scan complete; policy threshold not reached", (), (), False
    )
