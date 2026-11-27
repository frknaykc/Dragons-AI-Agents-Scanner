"""Presentation-only, redacted static relationships shared by report formats."""

import re
from dataclasses import asdict, fields, is_dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any

from dragonscan.models import Finding
from dragonscan.semantic import redact, redact_secrets

INTERPRETATION = (
    "Severity = potential impact; confidence = evidence strength. "
    "Static evidence, not execution or proof of a successful attack."
)


# Logical remote artifact IDs travel through pathlib: https:// becomes https:/
# (or uses backslashes on Windows). Check userinfo before URI encoding it.
_PATH_USERINFO = re.compile(r"\b(https?:[/\\]{1,2})[^\s/@:\\]+:[^\s/@\\]+@", re.I)


def redact_report_text(text: str, *, strip_controls: bool = False) -> str | None:
    cleaned = redact(text) if strip_controls else redact_secrets(text)
    if cleaned is None:
        return None
    return _PATH_USERINFO.sub(r"\g<1><REDACTED_URL_CREDENTIAL>@", cleaned)


def evidence_kind(finding: Finding) -> str:
    if finding.detection_id == "DRAGON-SECRET-001":
        return "static_declared"
    if finding.intelligence or finding.vulnerability:
        return "intel_match"
    if finding.semantic and finding.category == "semantic":
        return "model_opinion"
    if finding.dependency and not finding.path and not finding.flow:
        return "static_declared"
    return "static_inferred"


def mask_fields(value: Any) -> Any:
    """Mask individual fields before presentation; preserve enum and structural types."""
    if isinstance(value, Enum):
        return value
    if isinstance(value, str):
        cleaned = redact_report_text(value)
        return cleaned if cleaned is not None else "<redacted>"
    if isinstance(value, Path):
        return Path(mask_fields(str(value)))
    if isinstance(value, tuple):
        return tuple(mask_fields(v) for v in value)
    if isinstance(value, list):
        return [mask_fields(v) for v in value]
    if isinstance(value, dict):
        return {mask_fields(k): mask_fields(v) for k, v in value.items()}
    if is_dataclass(value) and not isinstance(value, type):
        return replace(
            value, **{f.name: mask_fields(getattr(value, f.name)) for f in fields(value)}
        )
    return value


def _clean(value: Any) -> Any:
    if isinstance(value, Path):
        value = str(value)
    if isinstance(value, str):
        cleaned = redact_report_text(value, strip_controls=True)
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
