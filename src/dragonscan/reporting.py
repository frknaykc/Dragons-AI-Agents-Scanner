"""Pure terminal and JSON formatting of scan reports."""

import json
from dataclasses import asdict

from dragonscan.models import ScanReport


def json_report(report: ScanReport) -> str:
    data = asdict(report)
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
        data["findings"].append(item)
    return json.dumps(data, indent=2, ensure_ascii=False)


def terminal_report(report: ScanReport) -> str:
    lines = [
        f"Target: {ascii(str(report.target))}",
        f"Artifacts: {len(report.artifacts)}",
        f"Risk: {report.risk.value if report.risk else 'none'}",
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
        if finding.path:
            lines.append(f"  Source: {ascii(finding.source or 'unknown')}")
            lines.append(f"  Sink: {ascii(finding.sink or 'unknown')}")
            lines.append("  Path:")
            for step in finding.path:
                location = f":{step.line}" if step.line is not None else ""
                lines.append(
                    f"    {ascii(str(step.artifact))}{location} "
                    f"--{step.edge}--> {ascii(step.target)}"
                )
    for error in report.errors:
        lines.append(f"ERROR: {ascii(error)}")
    return "\n".join(lines)
