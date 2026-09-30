"""Observe security behavior once per normalized document, without executing content."""

import re
from dataclasses import replace

from dragonscan.detection import Observation
from dragonscan.models import Document, SourceRef

_INSTRUCTION_KINDS = frozenset({"instructions", "skill", "memory", "soul"})
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])|\n+|;\s*")
_NEGATED = re.compile(
    r"^(?:never|do not|don't|must not|avoid|should not|please do not|"
    r"ensure (?:you )?(?:do not|never))\b",
    re.I,
)
_IMPERATIVE = re.compile(
    r"^(?:(?:you must|always|please|then|first|immediately|next)\s+)?"
    r"(?:read|cat|open|load|copy|extract|export|send|upload|post|transmit|"
    r"run|execute|fetch|download|retrieve|follow|obey|use|ignore|disregard|"
    r"override|disable|bypass|turn off|write|append|modify|edit|overwrite|replace)\b",
    re.I,
)
_SOURCE_PATTERNS = (
    ("SSH private key", re.compile(r"(?:~?/)?\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)\b", re.I)),
    (
        "cloud credentials",
        re.compile(r"(?:~?/)?\.aws/credentials\b|\b(?:cloud|aws) credentials\b", re.I),
    ),
    (
        "environment secrets",
        re.compile(r"(?:~?/)?\.env(?![\w.])|\benvironment (?:secret|variable|token)s?\b", re.I),
    ),
    ("API token", re.compile(r"\b(?:api|auth|access) (?:key|token)s?\b", re.I)),
    ("private key", re.compile(r"\bprivate keys?\b", re.I)),
    ("wallet secret", re.compile(r"\b(?:wallet (?:seed|secret|key)|seed phrase)\b", re.I)),
    ("agent memory", re.compile(r"\bMEMORY\.md\b|\bagent memory\b", re.I)),
)
_ACCESS = re.compile(r"\b(?:read|cat|open|load|copy|extract|export|dump|print)\b", re.I)
_TRANSFER = re.compile(r"\b(?:send|upload|post|transmit|exfiltrate)\b", re.I)
_HTTP = re.compile(r"\bhttps?://[^\s<>)]+", re.I)
_PRONOUN = re.compile(
    r"\b(?:it|its|their|them|the (?:file|contents|secrets?|keys?|credentials?|tokens?|data))\b",
    re.I,
)
_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|override)\b.{0,60}\b(?:previous|prior|system|developer)\b.{0,40}\b(?:instructions?|rules?|directives?|prompts?)\b",
    re.I,
)
_BYPASS = re.compile(
    r"\b(?:disable|bypass|turn off)\b.{0,50}"
    r"\b(?:safety|security|guardrails?|checks?|protections?)\b",
    re.I,
)
_PERSIST_WRITE = re.compile(
    r"\b(?:write|append|modify|edit|overwrite|replace)\b.{0,100}\b(?:AGENTS|SOUL|MEMORY|CLAUDE|SKILL)\.md\b",
    re.I,
)
_PERSIST_INTENT = re.compile(
    r"\b(?:agent|instructions?|rules?|policy|behavior|future|sessions?|always|persist)\b", re.I
)
_CONFIG_WRITE = re.compile(
    r"\b(?:write|append|modify|edit|overwrite|replace)\b.{0,120}"
    r"(?:\.{1,2}/|[\w.-]+/)*(?:\.mcp|mcp|settings|config)\.(?:json|yaml|yml|toml)\b",
    re.I,
)
_REMOTE_FETCH = re.compile(r"\b(?:fetch|download|retrieve|load|use)\b", re.I)
_REMOTE_AUTHORITY = re.compile(
    r"\b(?:follow|obey|treat|use)\b.{0,80}\b(?:instructions?|rules?|policy)\b", re.I
)
_FETCH_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^\n|]{0,300}https?://[^\s|]+[^\n|]{0,300}\|\s*(?:sh|bash|zsh)\b", re.I
)
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")


def segment_text(text: str, index: int) -> str:
    """Use the same sentence boundaries as behavior extraction."""
    parts = _SENTENCE.split(text)
    return parts[index].strip() if 0 <= index < len(parts) else ""


def fetch_shell_url(text: str) -> str | None:
    """Bind the remote endpoint to the same observed fetch-to-shell command."""
    command = _FETCH_SHELL.search(text)
    url = re.search(r"https?://[^\s<>|)]+", command.group(), re.I) if command else None
    return url.group() if url else None


def write_target(text: str, kind: str) -> str | None:
    """Return the sole named write target, never guess between several paths."""
    directive = (_PERSIST_WRITE if kind == "persistence" else _CONFIG_WRITE).search(text)
    if directive is None:
        return None
    pattern = (
        r"(?:\.{1,2}/|[\w.-]+/)*\b(?:AGENTS|SKILL|SOUL|MEMORY|CLAUDE)\.md\b"
        if kind == "persistence"
        else r"(?:\.{1,2}/|[\w.-]+/)*(?:\.mcp|mcp|settings|config)\.(?:json|yaml|yml|toml)\b"
    )
    targets = re.findall(pattern, text[directive.start() :], re.I)
    return targets[0] if len(targets) == 1 else None


def collect(document: Document) -> tuple[Observation, ...]:
    """Only actionable prose is promoted; code, quotations and references remain data."""
    if document.artifact.kind not in _INSTRUCTION_KINDS:
        return ()
    observed: list[Observation] = []
    for index, instruction in enumerate(document.instructions):
        # Markdown inline/fenced code and blockquotes are excluded by the parser.
        start = 0
        parts: list[tuple[str, int]] = []
        for match in _SENTENCE.finditer(instruction.text):
            parts.append((instruction.text[start : match.start()], start))
            start = match.end()
        parts.append((instruction.text[start:], start))
        for segment, (sentence, offset) in enumerate(parts):
            sentence = sentence.strip()
            if not sentence or _NEGATED.search(sentence) or not _IMPERATIVE.search(sentence):
                continue
            line = instruction.line + instruction.text[:offset].count("\n")
            location = replace(instruction.location, line=line)

            def add(
                kind: str,
                label: str,
                *capabilities: str,
                location: SourceRef = location,
                index: int = index,
                segment: int = segment,
            ) -> None:
                observed.append(Observation(kind, label, location, index, segment, capabilities))

            if _OVERRIDE.search(sentence):
                add("override", "prior instructions", "instruction-override")
            if _BYPASS.search(sentence):
                add("bypass", "security controls", "security-control-bypass")
            if _ACCESS.search(sentence):
                for label, pattern in _SOURCE_PATTERNS:
                    if pattern.search(sentence):
                        add("sensitive_access", label, "file-read", "secret-read")
                        break
            transfer = _TRANSFER.search(sentence)
            if transfer and _HTTP.search(sentence):
                add("external_transfer", "external HTTP(S) endpoint", "network-egress")
                object_text = sentence[transfer.end() :]
                named = [
                    label for label, pattern in _SOURCE_PATTERNS if pattern.search(object_text)
                ]
                if named:
                    for label in named:
                        add("named_transfer", label, "network-egress")
                elif _PRONOUN.search(object_text):
                    add("linked_transfer", "previously read data", "network-egress")
                elif re.match(r"\s+to\s+https?://", object_text, re.I):
                    add("implicit_transfer", "previously read data", "network-egress")
            if _FETCH_SHELL.search(sentence) and re.search(r"\b(?:run|execute)\b", sentence, re.I):
                add(
                    "remote_execution",
                    "download piped to shell",
                    "network-fetch",
                    "command-execution",
                )
            if _PERSIST_WRITE.search(sentence) and _PERSIST_INTENT.search(sentence):
                add(
                    "persistence",
                    "agent instruction file",
                    "persistence-write",
                    "configuration-modification",
                )
            if _CONFIG_WRITE.search(sentence):
                add("config_write", "agent configuration", "configuration-modification")
            if (
                _HTTP.search(sentence)
                and _REMOTE_FETCH.search(sentence)
                and _REMOTE_AUTHORITY.search(sentence)
                and not re.search(
                    r"\b(?:not to|never|without)\s+(?:follow|obey|use)\b", sentence, re.I
                )
            ):
                add("remote_trust", "external instructions", "external-instruction-fetch")
            if _BIDI.search(sentence):
                add("bidi", "bidirectional format control", "hidden-instruction")
    return tuple(observed)


def related_transfer(
    source: Observation, observations: tuple[Observation, ...]
) -> Observation | None:
    """Correlate a read with an explicit or implicit transfer, never by keyword proximity alone."""
    if source.location.line is None:
        return None
    sources = [item for item in observations if item.kind == "sensitive_access"]
    for sink in observations:
        if sink.kind != "external_transfer" or sink.location.line is None:
            continue
        if not 0 <= sink.location.line - source.location.line <= 2:
            continue
        if source.context > sink.context or (
            source.context == sink.context and source.segment > sink.segment
        ):
            continue
        markers = [
            item
            for item in observations
            if item.context == sink.context and item.segment == sink.segment
        ]
        named = {item.label for item in markers if item.kind == "named_transfer"}
        if named:
            if source.label in named and (
                source.context == sink.context or source.context + 1 == sink.context
            ):
                return sink
            continue
        same_segment = source.context == sink.context and source.segment == sink.segment
        adjacent = (source.context == sink.context and sink.segment == source.segment + 1) or (
            sink.context == source.context + 1 and sink.segment == 0
        )
        if not (same_segment or adjacent):
            continue
        if not any(item.kind in {"linked_transfer", "implicit_transfer"} for item in markers):
            continue
        # A pronoun cannot refer to every earlier credential in a document.
        closest = [
            item for item in sources if (item.context, item.segment) <= (sink.context, sink.segment)
        ]
        if not closest:
            continue
        last_position = max((item.context, item.segment) for item in closest)
        antecedents = {
            item.label for item in closest if (item.context, item.segment) == last_position
        }
        if (source.context, source.segment) == last_position and antecedents == {source.label}:
            return sink
    return None
