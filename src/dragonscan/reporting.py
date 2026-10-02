"""Pure terminal and JSON formatting of scan reports."""

import json
from dataclasses import asdict

from dragonscan.models import ScanReport
from dragonscan.policy import PolicyResult, evaluate
from dragonscan.sarif import sarif_report as sarif_report


def json_report(report: ScanReport, policy: PolicyResult | None = None) -> str:
    policy = policy or evaluate(report)
    data = asdict(report)
    data["scan_status"] = policy.scan_status
    data["policy"] = policy.as_dict()
    data["target"] = str(report.target)
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
        if finding.path:
            item["path"] = [
                {**asdict(step), "artifact": str(step.artifact)} for step in finding.path
            ]
        else:
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
        else:
            item["flow"]["artifacts"] = [str(path) for path in finding.flow.artifacts]
            item["flow"]["locations"] = [
                {**asdict(ref), "path": str(ref.path)} for ref in finding.flow.locations
            ]
        data["findings"].append(item)
    for key in tuple(data):
        if key.startswith("semantic_"):
            data.pop(key)
        if key.startswith("dynamic_"):
            data.pop(key)
    data.pop("installed_environments")
    data.pop("artifact_origins")
    data.pop("mcp_inventory")
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


def terminal_report(report: ScanReport, policy: PolicyResult | None = None) -> str:
    policy = policy or evaluate(report)
    lines = [
        f"Target: {ascii(str(report.target))}",
        f"Artifacts: {len(report.artifacts)}",
        f"Risk: {report.risk.value if report.risk else 'none'}",
        f"Scan: {policy.scan_status}",
        f"Findings: {len(report.findings)}",
        f"Policy: {policy.status}",
        f"Reason: {policy.reason}",
    ]
    if report.findings:
        lines.append(
            "Findings by severity: "
            + ", ".join(
                f"{severity}: {count}" for severity, count in report.counts.items() if count
            )
        )
    for finding in report.findings:
        location = f":{finding.line}" if finding.line else ""
        lines.extend(
            (
                f"[{finding.severity.value}/{finding.confidence.value}] "
                f"{finding.detection_id} {finding.title}",
                f"  {ascii(str(finding.artifact))}{location} | {ascii(finding.evidence)}",
                f"  {finding.explanation}",
            )
        )
        if finding.signature is not None:
            info = finding.signature
            version = f" v{info.version}" if info.version else ""
            lines.append(
                f"  Signature: {ascii(info.signature_id)} ({ascii(info.signature_type)}) "
                f"from {ascii(info.pack)}{ascii(version)}; context={ascii(info.context)}"
            )
        if finding.intelligence is not None:
            for source in finding.intelligence.sources:
                lines.append(
                    f"  Intelligence: {ascii(source.feed_id)} v{ascii(source.feed_version)} "
                    f"record={ascii(source.record_id)}; "
                    f"classification={ascii(source.classification)}; "
                    f"source={ascii(source.source)}"
                )
        if finding.semantic is not None:
            semantic_info = finding.semantic
            lines.append(
                f"  SEMANTIC: {ascii(semantic_info.category)} {ascii(semantic_info.verdict)}; "
                f"candidate={ascii(semantic_info.candidate_id)}; "
                f"evidence={ascii(', '.join(semantic_info.evidence_ids))}; "
                f"provider={ascii(semantic_info.provider)}; model={ascii(semantic_info.model)}"
            )
            lines.append(f"  Rationale (model opinion): {ascii(semantic_info.rationale)}")
        if finding.evasion is not None:
            evasion = finding.evasion
            lines.append(
                f"  Static view: {ascii(' > '.join(evasion.chain))}; "
                f"depth={evasion.depth}; source={ascii(evasion.source_kind)}; "
                f"range={evasion.source_start}-{evasion.source_end}; "
                f"confidence={evasion.confidence.value}; "
                f"original={ascii(evasion.original_excerpt)}; "
                f"canonical={ascii(evasion.canonical_excerpt)}"
            )
        if finding.dependency is not None:
            dep = finding.dependency
            lines.append(
                f"  Dependency: {ascii(dep.ecosystem)}:{ascii(dep.package)} "
                f"[{ascii(dep.pinning)}, {ascii(dep.source)}, {ascii(dep.manager)}; "
                f"{ascii(dep.mechanism)}]"
            )
        if finding.vulnerability is not None:
            vuln = finding.vulnerability
            lines.append(
                f"  OSV: {ascii(vuln.vulnerability_id)} "
                f"aliases={ascii(', '.join(vuln.aliases))}; "
                f"upstream severity={ascii(vuln.upstream_severity or 'unknown')}; "
                f"fixed={ascii(', '.join(vuln.fixed_versions) or 'not provided')}"
            )
        if finding.path:
            lines.append(f"  Source: {ascii(finding.source or 'unknown')}")
            lines.append(f"  Sink: {ascii(finding.sink or 'unknown')}")
            if finding.flow is not None:
                flow = finding.flow
                lines.append(
                    f"  Static flow: {ascii(flow.source_type)} -> {ascii(flow.sink_type)}; "
                    f"confidence={flow.confidence.value}; "
                    f"boundaries={ascii(', '.join(flow.boundaries) or 'none')}"
                )
            lines.append("  Path:")
            for step in finding.path:
                location = f":{step.line}" if step.line is not None else ""
                lines.append(
                    f"    {ascii(str(step.artifact))}{location} "
                    f"--{step.edge}--> {ascii(step.target)}"
                )
    for error in report.errors:
        lines.append(f"ERROR: {ascii(error)}")
    for static_diagnostic in report.diagnostics:
        lines.append(f"{static_diagnostic.level.upper()}: {ascii(static_diagnostic.message)}")
    if report.acquisition_status != "not_required":
        lines.append(f"Acquisition: {report.acquisition_status} ({report.acquisition_kind})")
        for diagnostic in report.acquisition_diagnostics:
            lines.append(f"ACQUISITION DIAGNOSTIC: {ascii(diagnostic)}")
    if report.installed_environments:
        lines.append("Installed agent environments (local evidence, not binary proof):")
        for item in report.installed_environments:
            lines.append(
                f"  {ascii(item.agent)}: {item.status}/{item.resolution} "
                f"scope={item.scope} evidence={','.join(item.evidence) or 'none'} "
                f"installation={item.installation_evidence} [{ascii(item.source)}] "
                f"root={ascii(str(item.root))}"
            )
            if item.diagnostic:
                lines.append(f"    DIAGNOSTIC: {ascii(item.diagnostic)}")
        lines.append(
            f"Installed artifact roots: "
            f"{sum(len(item.artifact_roots) for item in report.installed_environments)}; "
            f"discovered artifact origins: "
            f"{sum(item.provenance == 'installed_agent' for item in report.artifact_origins)}"
        )
        lines.append(f"Static MCP server associations: {len(report.installed_mcp_servers)}")
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
