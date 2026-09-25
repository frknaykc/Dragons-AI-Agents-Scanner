"""Bounded extraction of explicit MCP tool references from actionable Markdown blocks.

Names are lookup keys only; graph output uses fixed labels and source locations.
"""

import re
from dataclasses import dataclass

from dragonscan.models import Document, SourceRef

_NAME = r"[A-Za-z_](?:[\w.-]{0,78}[\w-])?"
_REF = rf"(?P<prefix>MCP\s+tool\s+)?`?(?P<name>{_NAME})`?"
_TRANSFER = re.compile(
    rf"^\s*pass\s+the\s+(?:result|output)\s+(?:of|from)\s+{_REF}"
    rf"\s+to\s+(?P<target_prefix>MCP\s+tool\s+)?`?(?P<target>{_NAME})`?\s*[.!]?\s*$",
    re.I,
)
_CALL = re.compile(rf"^\s*(?:call|invoke)\s+{_REF}\s*[.!]?\s*$", re.I)
_USE = re.compile(
    rf"^\s*use\s+the\s+`?(?P<tool>{_NAME})`?\s+tool\s+from\s+the\s+"
    rf"`?(?P<server>{_NAME})`?\s+MCP\s+server\s*[.!]?\s*$",
    re.I,
)


@dataclass(frozen=True)
class ToolReference:
    source: str
    target: str | None
    location: SourceRef


def extract(document: Document) -> tuple[ToolReference, ...]:
    """Reject fenced, quoted, HTML, and descriptive text; do not interpret it."""
    result: list[ToolReference] = []
    for block in document.blocks:
        if block.kind not in {"paragraph", "list_item"} or len(result) >= 256:
            continue
        # Retain inline-code names but never treat code blocks or links as commands.
        text = "".join(span.text for span in block.spans if span.kind in {"text", "inline_code"})
        if not text or len(text) > 4096:
            continue
        text = " ".join(text.split())
        transfer = _TRANSFER.fullmatch(text)
        if (
            transfer
            and ("." in transfer["name"] or transfer["prefix"])
            and ("." in transfer["target"] or transfer["target_prefix"])
        ):
            result.append(ToolReference(transfer["name"], transfer["target"], block.location))
            continue
        use = _USE.fullmatch(text)
        if use:
            result.append(ToolReference(f"{use['server']}.{use['tool']}", None, block.location))
            continue
        call = _CALL.fullmatch(text)
        if call and ("." in call["name"] or call["prefix"]):
            result.append(ToolReference(call["name"], None, block.location))
    return tuple(result)
