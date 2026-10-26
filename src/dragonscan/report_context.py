"""Presentation-only, redacted static relationships shared by report formats."""

from dataclasses import asdict
from pathlib import Path
from typing import Any

from dragonscan.models import Finding
from dragonscan.semantic import redact

INTERPRETATION = (
    "Severity = potential impact; confidence = evidence strength. "
    "Static evidence, not execution or proof of a successful attack."
)


def _clean(value: Any) -> Any:
    if isinstance(value, Path):
        value = str(value)
    if isinstance(value, str):
        cleaned = redact(value)
        return cleaned if cleaned is not None else "[redacted: unsafe or oversized context]"
    if isinstance(value, dict):
        return {key: _clean(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(item) for item in value]
    return value


def context_data(finding: Finding) -> dict[str, Any]:
    """Keep JSON's existing shape; never infer a missing source, sink or route."""
    return {
        "source": _clean(finding.source),
        "sink": _clean(finding.sink),
        "path": _clean([asdict(step) for step in finding.path]),
        "flow": _clean(asdict(finding.flow)) if finding.flow is not None else None,
    }


def context_rows(finding: Finding) -> list[tuple[str, str]]:
    data = context_data(finding)
    rows = [
        ("Source", data["source"] or "not established"),
        ("Sink", data["sink"] or "not established"),
    ]
    flow = data["flow"]
    if flow is not None:
        rows.append(
            (
                "Static flow",
                f"{ascii(flow['source_type'])} -> {ascii(flow['sink_type'])}; "
                f"confidence={flow['confidence']}",
            )
        )
        for label, key in (
            ("Boundaries", "boundaries"),
            ("Capabilities", "capabilities"),
            ("Transforms", "transformations"),
        ):
            if flow[key]:
                rows.append((label, ", ".join(flow[key])))
    if not data["path"]:
        rows.append(("Static path", "not established"))
    else:
        rows.append(("Static path", "Supported by static evidence; not runtime verification"))
    for index, step in enumerate(data["path"], 1):
        location = str(step["artifact"])
        if step["line"] is not None:
            location += f":{step['line']}"
        rows.append(
            (
                "Path",
                f"{index}. {step['source']} --{step['edge']}--> "
                f"{step['target']}; {location}; origin={step['origin']}; "
                f"confidence={step['confidence']}",
            )
        )
    return rows
