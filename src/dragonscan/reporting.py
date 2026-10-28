"""Pure terminal and JSON formatting of scan reports."""

import json
import textwrap
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from dragonscan.models import ArtifactKind, Finding, ScanReport
from dragonscan.policy import PolicyResult, evaluate
from dragonscan.report_context import INTERPRETATION, context_data, context_rows
from dragonscan.risk import summarize
from dragonscan.sarif import sarif_report as sarif_report


def json_report(report: ScanReport, policy: PolicyResult | None = None) -> str:
    policy = policy or evaluate(report)
    data = asdict(report)
    data["scan_status"] = policy.scan_status
    data["policy"] = policy.as_dict()
    data["target"] = str(report.target)
    data["diagnostics"] = [
        {**asdict(item), "artifact": str(item.artifact) if item.artifact is not None else None}
        for item in report.diagnostics
    ]
    data["artifacts"] = [
        {
            "path": str(artifact.path),
            "kind": artifact.kind.value,
            "source_format": artifact.source_format.value,
            "ecosystem": artifact.ecosystem,
        }
        for artifact in report.artifacts
    ]
    data["findings"] = []
    for finding in report.findings:
        item = {**asdict(finding), "artifact": str(finding.artifact)}
        item.update(context_data(finding))
        if not finding.path:
            item.pop("path")
            item.pop("taint")
        if finding.signature is None:
            item.pop("signature")
        if finding.dependency is None:
            item.pop("dependency")
        if finding.vulnerability is None:
            item.pop("vulnerability")
        if finding.intelligence is None:
            item.pop("intelligence")
        if finding.evasion is None:
            item.pop("evasion")
        if finding.semantic is None:
            item.pop("semantic")
        if finding.flow is None:
            item.pop("flow")
        data["findings"].append(item)
    for key in tuple(data):
        if key.startswith("semantic_"):
            data.pop(key)
        if key.startswith("dynamic_"):
            data.pop(key)
    data.pop("installed_environments")
    data.pop("artifact_origins")
    data.pop("mcp_inventory")
    data.pop("mcp_scope_hints")
    data.pop("installed_mcp_servers")
    for key in ("intelligence_status", "intelligence_feeds", "intelligence_diagnostics"):
        data.pop(key)
    if report.intelligence_status != "disabled":
        data["threat_intelligence"] = {
            "status": report.intelligence_status,
            "feeds": [
                {"feed_id": feed_id, "version": version, "records_loaded": count}
                for feed_id, version, count in report.intelligence_feeds
            ],
            "matches": sum(item.intelligence is not None for item in report.findings),
            "diagnostics": report.intelligence_diagnostics,
        }
    for key in (
        "acquisition_status",
        "acquisition_kind",
        "acquisition_source",
        "acquisition_diagnostics",
        "acquisition_resolved_source",
        "acquisition_source_sha256",
        "acquisition_source_bytes",
    ):
        data.pop(key)
    if report.acquisition_status != "not_required":
        data["acquisition"] = {
            "status": report.acquisition_status,
            "kind": report.acquisition_kind,
            "source": report.acquisition_source,
            "diagnostics": report.acquisition_diagnostics,
        }
        if report.acquisition_resolved_source is not None:
            data["acquisition"]["resolved_source"] = report.acquisition_resolved_source
        if report.acquisition_source_sha256 is not None:
            data["acquisition"]["source_sha256"] = report.acquisition_source_sha256
        if report.acquisition_source_bytes is not None:
            data["acquisition"]["source_bytes"] = report.acquisition_source_bytes
    if report.installed_environments:
        data["installed_agents"] = {
            "environments": [
                {
                    "agent": item.agent,
                    "root": str(item.root),
                    "source": item.source,
                    "artifact_roots": [str(root) for root in item.artifact_roots],
                    "status": item.status,
                    "diagnostic": item.diagnostic,
                    "scope": item.scope,
                    "evidence": item.evidence,
                    "installation_evidence": item.installation_evidence,
                    "resolution": item.resolution,
                }
                for item in report.installed_environments
            ],
            "artifacts": [
                {
                    "artifact": str(item.artifact),
                    "scanned_artifact": (
                        str(item.scanned_artifact) if item.scanned_artifact is not None else None
                    ),
                    "provenance": item.provenance,
                    "agent": item.agent,
                    "environment": str(item.environment) if item.environment else None,
                    "source": item.source,
                    "scope": item.scope,
                }
                for item in report.artifact_origins
            ],
            "mcp_servers": [
                {
                    "config": str(item.config),
                    "server": item.server,
                    "transport": item.transport,
                    "agent": item.agent,
                    "scope": item.scope,
                    "source": item.source,
                }
                for item in report.installed_mcp_servers
            ],
        }
    if report.semantic_status != "disabled":
        data["semantic"] = {
            "enabled": True,
            "status": report.semantic_status,
            "provider": report.semantic_provider,
            "model": report.semantic_model,
            "candidates_selected": report.semantic_candidates_selected,
            "candidates_analyzed": report.semantic_candidates_analyzed,
            "findings": sum(f.semantic is not None for f in report.findings),
            "diagnostics": report.semantic_diagnostics,
        }
    if report.dynamic_status != "not_requested":
        data["dynamic_mcp"] = {
            "status": report.dynamic_status,
            "isolation": (
                "not_executed"
                if report.dynamic_status == "blocked"
                else "process_only; no OS filesystem or network sandbox"
            ),
            "mode": report.dynamic_mode,
            "capabilities": report.dynamic_capabilities,
            "timings_ms": report.dynamic_timings_ms,
            "diagnostics": report.dynamic_diagnostics,
            "observations": [
                {**asdict(item), "artifact": str(item.artifact)}
                for item in report.dynamic_observations
            ],
        }
    # JSON consumers get identical decoded values, but no live bidi/control glyphs.
    return json.dumps(data, indent=2, ensure_ascii=True)


_COLORS = {
    "critical": "1;91",
    "high": "31",
    "medium": "38;5;208",
    "low": "34",
    "info": "36",
    "pass": "32",
    "policy_violation": "31",
    "incomplete": "33",
    "scan_error": "31",
    "complete": "32",
    "partial": "33",
    "failed": "31",
    "error": "31",
    "warning": "33",
    "coverage": "36",
    "check": "1;36",
    "false_positive": "1;35",
    "fix": "1;32",
}


def _style(label: str, kind: str, color: bool) -> str:
    """Only style trusted labels; never interpret content as terminal markup."""
    code = _COLORS.get(kind)
    return f"\x1b[{code}m{label}\x1b[0m" if color and code else label


def _safe(value: str) -> str:
    """ASCII-escape untrusted text without repr's surrounding quotes."""
    return ascii(value)[1:-1]


_BOX_WIDTH = 80


def _box_top(title: str, *, section: bool = False) -> str:
    left, right, bar = ("╔═ ", " ╗", "═") if section else ("┌─ ", " ┐", "─")
    return left + title + bar * (_BOX_WIDTH - len(left + title + right)) + right


def _box_bottom(*, section: bool = False) -> str:
    left, right, bar = ("╚", "╝", "═") if section else ("└", "┘", "─")
    return left + bar * (_BOX_WIDTH - 2) + right


def _box_row(label: str, value: str, color: bool, kind: str = "") -> list[str]:
    prefix = f"{label + ':':<16}" if label else ""
    wrapped = textwrap.wrap(value, _BOX_WIDTH - 4 - len(prefix), break_on_hyphens=False)
    result = []
    for index, chunk in enumerate(wrapped or [""]):
        leading = (
            _style(label + ":", kind, color) + prefix[len(label) + 1 :]
            if index == 0 and label
            else " " * len(prefix)
        )
        raw = prefix + chunk
        result.append("│ " + leading + chunk + " " * (_BOX_WIDTH - 4 - len(raw)) + " │")
    return result


def _review_guidance(finding: Finding) -> tuple[str, str]:
    """Terminal-only review prompts; do not infer an incident or a new finding."""
    if finding.detection_id == "DRAGON-MCP-001":
        return (
            "Inspect the cited server command and args; verify the package "
            "or image version or digest and whether launch can resolve it.",
            "The cited entry may be documentation or an inactive server; "
            "confirm its effective runtime configuration.",
        )
    if finding.detection_id == "DRAGON-CRED-001":
        return (
            "Read the full instruction around this line; confirm it directs access "
            "to a secret, rather than prohibiting access or disclosure.",
            "Negated/quoted guidance or an authorized test workflow can change "
            "the interpretation; a mention is not a secret read.",
        )
    if finding.detection_id == "DRAGON-MCP-011":
        return (
            "Check the header reference, endpoint owner and credential scope "
            "in the cited configuration; no request is proven.",
            "An intentional scoped authentication header is normal; its "
            "presence alone is not credential leakage.",
        )
    if finding.detection_id == "DRAGON-MCP-003":
        return (
            "Inspect the cited configuration entry locally; verify whether it "
            "holds a literal secret without copying its value.",
            "A non-secret placeholder can resemble a credential; the scanner "
            "did not validate the value.",
        )
    if finding.category == "data-exfiltration":
        return (
            "Check whether the cited source and destination refer to the same data "
            "in an actionable instruction; no transfer was observed.",
            "Quoted examples, negations and unrelated transfers should not be "
            "treated as a data flow.",
        )
    if finding.category == "mcp-security":
        return (
            "Review the named MCP configuration or tool metadata in the cited "
            "artifact; confirm whether it is active and authorized.",
            "A declared capability or setting alone does not prove a request, "
            "execution or compromise.",
        )
    return (
        "Inspect the cited artifact and surrounding context; verify the stated "
        "behavior and trust boundary before acting.",
        "Quoted, prohibited or benign authorized behavior can change the "
        "interpretation of a static match.",
    )


def _diagnostic_summary(
    lines: list[str], report: ScanReport, color: bool, json_saved: bool
) -> None:
    partial_roots = sum(
        item.status == "discovered" and item.resolution == "partial"
        for item in report.installed_environments
    )
    if not report.errors and not report.diagnostics and not partial_roots:
        return
    lines.append("")
    lines.append(_box_top("Scan coverage & diagnostics", section=True))
    lines.append("║ " + "Operational limits; not security findings".ljust(_BOX_WIDTH - 4) + " ║")
    lines.append(_box_bottom(section=True))
    errors = len(report.errors)
    coverage = sum(d.level == "coverage" for d in report.diagnostics)
    warnings = sum(d.level == "warning" for d in report.diagnostics)
    parts = []
    if errors:
        parts.append(f"{errors:,} error{'s' if errors != 1 else ''}")
    if coverage:
        parts.append(f"{coverage:,} limited {'analyses' if coverage != 1 else 'analysis'}")
    if warnings:
        parts.append(f"{warnings:,} warning{'s' if warnings != 1 else ''}")
    if partial_roots:
        parts.append(f"{partial_roots:,} partial agent root{'s' if partial_roots != 1 else ''}")
    lines.append(f"Coverage    {_style('; '.join(parts), 'coverage', color)}")
    if report.errors:
        lines.append(f"Cause       {_safe(report.errors[0])[:200]}")
    lines.append(
        "Details     See the JSON report for affected artifacts and limits."
        if json_saved
        else "Details     Use --format json --output PATH for affected artifacts and limits."
    )


_KIND_LABELS = {
    ArtifactKind.SKILL: "Skills",
    ArtifactKind.MCP_CONFIG: "MCP configs",
    ArtifactKind.INSTRUCTIONS: "instructions",
    ArtifactKind.MEMORY: "memory",
    ArtifactKind.SOUL: "soul",
    ArtifactKind.AGENT_CONFIG: "agent configs",
    ArtifactKind.PLUGIN_METADATA: "plugins",
    ArtifactKind.HOOK_CONFIG: "hooks",
    ArtifactKind.SCRIPT: "scripts",
    ArtifactKind.DEPENDENCY_MANIFEST: "dependency manifests",
    ArtifactKind.STRUCTURED_CONFIG: "structured configs",
}


def _summary_list(lines: list[str], label: str, text: str) -> None:
    lines.extend(textwrap.wrap(f"{label:<12}{text}", width=100, subsequent_indent=" " * 12))


def risk_label(report: ScanReport, policy: PolicyResult) -> str:
    """A failed scan without findings has no trustworthy clean risk assessment."""
    if policy.scan_status == "failed" and not report.findings:
        return "not assessed"
    risk = report.risk or summarize(report.findings)[0]
    return risk.value if risk else "none"


def terminal_report(
    report: ScanReport,
    policy: PolicyResult | None = None,
    *,
    color: bool = False,
    installed_scan: bool = False,
    report_path: Path | None = None,
    json_saved: bool = False,
) -> str:
    policy = policy or evaluate(report)
    status = policy.scan_status.upper()
    risk = risk_label(report, policy)
    lines = [
        "Dragons Scan",
        f"Target      {ascii(str(report.target))}",
    ]
    if installed_scan or report.installed_environments:
        agents = sorted(
            {item.agent for item in report.installed_environments if item.status == "discovered"}
        )
        partial = sum(
            item.status == "discovered" and item.resolution == "partial"
            for item in report.installed_environments
        )
        detail = f"{len(agents)} found"
        if partial:
            detail += f"; {partial} partial root{'s' if partial != 1 else ''}"
        _summary_list(
            lines,
            "Agents",
            f"{', '.join(_safe(name) for name in agents) or 'None found'} ({detail})",
        )
    kinds = Counter(artifact.kind for artifact in report.artifacts)
    _summary_list(
        lines,
        "Scanned",
        ", ".join(f"{label} {kinds[kind]:,}" for kind, label in _KIND_LABELS.items() if kinds[kind])
        or "No supported artifacts",
    )
    if report_path is not None:
        lines.append(f"Report      {ascii(str(report_path))}")
    if report.coverage:
        _summary_list(
            lines,
            "Coverage",
            f"{report.coverage['attempted']:,} attempted; "
            f"{report.coverage['parsed']:,} parsed; "
            f"{report.coverage['fully_analyzed']:,} fully analyzed; "
            f"{report.coverage['partially_analyzed']:,} partial; "
            f"{report.coverage['failed']:,} failed",
        )
    lines.extend(
        [
            f"Artifacts   {len(report.artifacts):,}",
            f"Status      {_style(status, policy.scan_status, color)}",
            f"Risk        {_style(risk.upper(), risk, color)}",
            f"Findings    {len(report.findings):,}",
            "Severities  "
            + ", ".join(
                f"{_style(level.upper(), level, color)} {report.counts.get(level, 0):,}"
                for level in ("critical", "high", "medium", "low", "info")
            ),
            f"Policy      {_style(policy.status.upper(), policy.status, color)}",
            f"Reason      {_safe(policy.reason)}",
        ]
    )
    lines.extend(
        (
            "",
            _box_top(f"Findings ({len(report.findings):,})", section=True),
            "║ "
            + "Static signals; confidence is evidence strength, not incident probability".ljust(
                _BOX_WIDTH - 4
            )
            + " ║",
            _box_bottom(section=True),
        )
    )
    if not report.findings:
        lines.append("Findings    None")
    for finding in sorted(
        report.findings,
        key=lambda item: ("critical", "high", "medium", "low", "info").index(item.severity.value),
    ):
        location = f":{finding.line}" if finding.line else ""
        rows = [
            ("", _safe(finding.title), ""),
            ("Rule", _safe(finding.detection_id), ""),
            ("Category", _safe(finding.category), ""),
            ("Confidence", finding.confidence.value.upper(), ""),
            ("File", f"{ascii(str(finding.artifact))}{location}", ""),
            ("Evidence", ascii(finding.evidence), ""),
            ("Reason", _safe(finding.explanation), ""),
        ]
        if finding.signature is not None:
            info = finding.signature
            version = f" v{info.version}" if info.version else ""
            rows.append(
                (
                    "Signature",
                    f"{ascii(info.signature_id)} ({ascii(info.signature_type)}) "
                    f"from {ascii(info.pack)}{ascii(version)}; context={ascii(info.context)}",
                    "",
                )
            )
        if finding.intelligence is not None:
            for source in finding.intelligence.sources:
                rows.append(
                    (
                        "Intelligence",
                        f"{ascii(source.feed_id)} v{ascii(source.feed_version)} "
                        f"record={ascii(source.record_id)}; "
                        f"classification={ascii(source.classification)}; "
                        f"source={ascii(source.source)}; "
                        f"source_version={ascii(source.source_version or 'unknown')}; "
                        f"published={ascii(source.published or 'unknown')}; "
                        f"updated={ascii(source.updated or 'unknown')}; "
                        f"feed_confidence={ascii(source.confidence or 'unknown')}; "
                        f"trust={ascii(source.trust or 'unknown')}; "
                        f"provenance={ascii(source.provenance or 'unknown')}; "
                        f"feed_sha256={ascii(source.feed_sha256 or 'unknown')}",
                        "",
                    )
                )
        if finding.semantic is not None:
            semantic_info = finding.semantic
            rows.append(
                (
                    "SEMANTIC",
                    f"{ascii(semantic_info.category)} {ascii(semantic_info.verdict)}; "
                    f"candidate={ascii(semantic_info.candidate_id)}; "
                    f"evidence={ascii(', '.join(semantic_info.evidence_ids))}; "
                    f"provider={ascii(semantic_info.provider)}; model={ascii(semantic_info.model)}",
                    "",
                )
            )
            rows.append(("Model opinion", ascii(semantic_info.rationale), ""))
        if finding.evasion is not None:
            evasion = finding.evasion
            rows.append(
                (
                    "Static view",
                    f"{ascii(' > '.join(evasion.chain))}; "
                    f"depth={evasion.depth}; source={ascii(evasion.source_kind)}; "
                    f"range={evasion.source_start}-{evasion.source_end}; "
                    f"confidence={evasion.confidence.value}; "
                    f"original={ascii(evasion.original_excerpt)}; "
                    f"canonical={ascii(evasion.canonical_excerpt)}",
                    "",
                )
            )
        if finding.dependency is not None:
            dep = finding.dependency
            rows.append(
                (
                    "Dependency",
                    f"{ascii(dep.ecosystem)}:{ascii(dep.package)} "
                    f"[{ascii(dep.pinning)}, {ascii(dep.source)}, {ascii(dep.manager)}; "
                    f"{ascii(dep.mechanism)}]",
                    "",
                )
            )
        if finding.vulnerability is not None:
            vuln = finding.vulnerability
            rows.append(
                (
                    "OSV",
                    f"{ascii(vuln.vulnerability_id)} "
                    f"aliases={ascii(', '.join(vuln.aliases))}; "
                    f"upstream severity={ascii(vuln.upstream_severity or 'unknown')}; "
                    f"fixed={ascii(', '.join(vuln.fixed_versions) or 'not provided')}",
                    "",
                )
            )
        rows.extend(
            (label, ascii(value) if label in {"Source", "Sink"} else _safe(value), "")
            for label, value in context_rows(finding)
        )
        rows.append(("Interpretation", INTERPRETATION, ""))
        check, false_positive = _review_guidance(finding)
        rows.extend(
            (
                ("Check", check, "check"),
                ("False positive", false_positive, "false_positive"),
                ("Fix", _safe(finding.remediation), "fix"),
            )
        )
        lines.append("")
        severity = finding.severity.value.upper()
        lines.append(
            _box_top(severity).replace(severity, _style(severity, finding.severity.value, color), 1)
        )
        for label, value, kind in rows:
            lines.extend(_box_row(label, value, color, kind))
        lines.append(_box_bottom())
    _diagnostic_summary(lines, report, color, json_saved)
    if report.acquisition_status != "not_required":
        lines.append(f"Acquisition: {report.acquisition_status} ({report.acquisition_kind})")
        for diagnostic in report.acquisition_diagnostics:
            lines.append(f"ACQUISITION DIAGNOSTIC: {ascii(diagnostic)}")

    if report.vulnerability_status != "disabled":
        lines.append(f"Vulnerability intelligence: {report.vulnerability_status}")
    for diagnostic in report.vulnerability_diagnostics:
        lines.append(f"VULN DIAGNOSTIC: {ascii(diagnostic)}")
    if report.intelligence_status != "disabled":
        lines.append(
            f"Threat intelligence: {report.intelligence_status}; "
            f"matches={sum(item.intelligence is not None for item in report.findings)}"
        )
        for feed_id, version, count in report.intelligence_feeds:
            lines.append(f"  Feed: {ascii(feed_id)} v{ascii(version)}; records loaded: {count}")
        for diagnostic in report.intelligence_diagnostics:
            lines.append(f"  INTEL DIAGNOSTIC: {ascii(diagnostic)}")
    if report.semantic_status != "disabled":
        provider = ascii(report.semantic_provider)
        model = ascii(report.semantic_model)
        lines.append(
            f"Semantic Analysis: {report.semantic_status}; provider={provider}; "
            f"model={model}; candidates={report.semantic_candidates_selected}; "
            f"analyzed={report.semantic_candidates_analyzed}; "
            f"findings={sum(f.semantic is not None for f in report.findings)}"
        )
    for diagnostic in report.semantic_diagnostics:
        lines.append(f"SEMANTIC DIAGNOSTIC: {ascii(diagnostic)}")
    if report.dynamic_status != "not_requested":
        lines.append(
            f"Dynamic MCP: {report.dynamic_status}; mode={report.dynamic_mode}; "
            "NO OS filesystem/network sandbox"
        )
        lines.append(
            "  Isolation capabilities: "
            + ", ".join(f"{name}={status}" for name, status in report.dynamic_capabilities.items())
        )
    for observation in report.dynamic_observations:
        lines.append(
            f"Observed MCP server: {ascii(observation.server)} "
            f"in {ascii(str(observation.artifact))}"
        )
        for kind in ("tools", "prompts", "resources"):
            for item in getattr(observation, kind):
                lines.append(f"  Observed {kind}: {ascii(item.name)}")
    for diagnostic in report.dynamic_diagnostics:
        lines.append(f"DYNAMIC DIAGNOSTIC: {ascii(diagnostic)}")
    return "\n".join(lines)
