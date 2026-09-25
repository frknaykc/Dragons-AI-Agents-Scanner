"""Static, non-executing signature matching over selected normalized artifact contexts."""

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

from dragonscan.models import (
    ArtifactKind,
    Classification,
    Confidence,
    Document,
    Finding,
    Severity,
    SignatureEvidence,
    SourceRef,
)
from dragonscan.signature_ioc import collect_candidates, public_label
from dragonscan.signature_models import IndicatorType, Signature, SignatureHit, SignatureType

MAX_DECODED_BYTES = 4096
MAX_DECODE_ATTEMPTS = 32
MAX_DECODE_DEPTH = 1
MAX_HITS = 256
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,5460}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32,8192}(?![0-9a-fA-F])")
_POWERSHELL = re.compile(r"\bpowershell(?:\.exe)?\b[^\n]{0,120}\s-(?:encodedcommand|enc)\b", re.I)
_ACTIVE = {"mcp_endpoint", "remote_endpoint", "executable_command"}

BUILTIN_SIGNATURES = (
    Signature(
        "DRAGON-SIG-001",
        "PowerShell encoded-command invocation",
        "A PowerShell encoded-command argument hides executable instructions.",
        SignatureType.CONTENT,
        "obfuscated-execution",
        Severity.MEDIUM,
        Confidence.HIGH,
        Classification.SUSPICIOUS,
        ("powershell", "obfuscation"),
        (ArtifactKind.MCP_CONFIG, ArtifactKind.AGENT_CONFIG),
        None,
        "powershell-encoded-command",  # Fixed structural matcher, not a user regex.
        ("executable_command",),
        (),
        "Inspect the command's source before trusting the server.",
        "Dragons Built-in",
        "1",
    ),
)


@dataclass(frozen=True)
class Region:
    context: str
    text: str
    location: SourceRef
    encoding: str | None = None


def regions(document: Document) -> tuple[Region, ...]:
    result: list[Region] = []
    for server in document.servers:
        if server.url:
            result.append(Region("mcp_endpoint", server.url, server.location))
        if server.command:
            command = " ".join((server.command, *server.args))
            result.append(Region("executable_command", command, server.location))
    for relation in document.relationships:
        if relation.kind == "references_url" and relation.subject is None:
            instructions = (
                instruction.text.lower()
                for instruction in document.instructions
                if instruction.location == relation.location
            )
            actionable = any(
                re.search(r"\b(?:connect|send|post|upload|fetch|curl|wget)\b", text)
                and not re.search(
                    r"\b(?:do not|never|avoid)\s+(?:connect|send|post|upload|fetch)\b", text
                )
                for text in instructions
            )
            result.append(
                Region(
                    "remote_endpoint" if actionable else "documentation",
                    relation.target,
                    relation.location,
                )
            )
    for block in document.blocks:
        if block.kind == "code":
            result.append(Region("code_block", block.text, block.location))
        elif block.kind == "quote":
            result.append(Region("documentation", block.text, block.location))
        elif block.kind in {"paragraph", "list_item", "heading"}:
            # The Markdown parser has already excluded inline code/quotes from instructions.
            for instruction in document.instructions:
                if instruction.location == block.location:
                    result.append(Region("instruction", instruction.text, instruction.location))
                    break
    return tuple(result)


def _decoded(region: Region, remaining: list[int]) -> tuple[Region, ...]:
    if region.encoding is not None or MAX_DECODE_DEPTH < 1:
        return ()
    output: list[Region] = []
    for encoding, matches in (
        ("base64", _BASE64.finditer(region.text)),
        ("hex", _HEX.finditer(region.text)),
    ):
        for match in matches:
            if remaining[0] <= 0:
                return tuple(output)
            token = match.group()
            if encoding == "base64" and len(token) % 4:
                continue
            if encoding == "hex" and len(token) % 2:
                continue
            remaining[0] -= 1
            try:
                raw = (
                    base64.b64decode(token, validate=True)
                    if encoding == "base64"
                    else bytes.fromhex(token)
                )
                if len(raw) > MAX_DECODED_BYTES or len(raw) < 8:
                    continue
                decoded = raw.decode("utf-8")
                if not all(char.isprintable() or char in "\r\n\t" for char in decoded):
                    continue
                output.append(Region(region.context, decoded, region.location, encoding))
            except (ValueError, UnicodeError, binascii.Error):
                continue
    return tuple(output)


class SignatureEngine:
    def __init__(self, signatures: tuple[Signature, ...] = BUILTIN_SIGNATURES):
        identifiers = [signature.detection_id for signature in signatures]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("duplicate signature ID")
        self.signatures = signatures
        self.limit_reason: str | None = None

    def detect(
        self, document: Document, text: str, *, include_artifact_hash: bool = True
    ) -> tuple[Finding, ...]:
        self.limit_reason = None
        output: list[Finding] = []
        seen: set[tuple[str, str, int | None, str]] = set()
        selected = regions(document)
        remaining = [MAX_DECODE_ATTEMPTS]
        decoded_cache: dict[int, tuple[Region, ...]] = {}
        ioc_cache: dict[tuple[int, IndicatorType], tuple[str, ...]] = {}
        hashes = {}
        if include_artifact_hash and any(
            "artifact_hash" in sig.contexts for sig in self.signatures
        ):
            data = text.encode("utf-8")
            hashes = {
                IndicatorType.SHA256: hashlib.sha256(data).hexdigest(),
                IndicatorType.SHA1: hashlib.sha1(data).hexdigest(),
                IndicatorType.MD5: hashlib.md5(data, usedforsecurity=False).hexdigest(),
            }
        for signature in self.signatures:
            if document.artifact.kind not in signature.artifact_types:
                continue
            if (
                signature.signature_type == SignatureType.IOC
                and signature.indicator_type in hashes
                and "artifact_hash" in signature.contexts
            ):
                if signature.pattern == hashes[signature.indicator_type]:
                    self._add(
                        output,
                        seen,
                        SignatureHit(
                            signature,
                            SourceRef(document.artifact.path, document.artifact.source_format),
                            "artifact_hash",
                            signature.pattern,
                        ),
                    )
            for region in selected:
                if region.context not in signature.contexts:
                    continue
                matches: list[SignatureHit] = []
                if signature.signature_type == SignatureType.IOC:
                    kind = signature.indicator_type
                    assert kind is not None  # Signature validates IOC indicator types.
                    key = (id(region), kind)
                    if key not in ioc_cache:
                        ioc_cache[key], limited = collect_candidates(kind, region.text)
                        if limited:
                            self.limit_reason = "IOC candidate limit reached"
                    if signature.pattern in ioc_cache[key]:
                        matches.append(
                            SignatureHit(
                                signature,
                                region.location,
                                region.context,
                                public_label(kind, signature.pattern),
                            )
                        )
                elif signature.signature_type == SignatureType.CONTENT:
                    if (
                        signature.pattern == "powershell-encoded-command"
                        and signature.source == "Dragons Built-in"
                    ):
                        found = _POWERSHELL.search(region.text) is not None
                    else:
                        found = signature.pattern.casefold() in region.text.casefold()
                    if found:
                        matches.append(
                            SignatureHit(
                                signature,
                                region.location,
                                region.context,
                                "content pattern matched",
                            )
                        )
                elif signature.signature_type == SignatureType.ENCODED:
                    key_id = id(region)
                    if key_id not in decoded_cache:
                        decoded_cache[key_id] = _decoded(region, remaining)
                    for decoded in decoded_cache[key_id]:
                        if signature.pattern.casefold() in decoded.text.casefold():
                            matches.append(
                                SignatureHit(
                                    signature,
                                    region.location,
                                    region.context,
                                    "decoded content pattern matched",
                                    encoded=True,
                                    representation=f"{decoded.encoding}; depth 1",
                                )
                            )
                for hit in matches:
                    self._add(output, seen, hit)
                    if len(output) >= MAX_HITS:
                        self.limit_reason = "signature hit limit reached"
                        return tuple(output)
        if remaining[0] == 0:
            self.limit_reason = "encoded-content inspection limit reached"
        return tuple(output)

    @staticmethod
    def _add(
        output: list[Finding], seen: set[tuple[str, str, int | None, str]], hit: SignatureHit
    ) -> None:
        sig = hit.signature
        key = (sig.detection_id, str(hit.location.path), hit.location.line, hit.context)
        if key in seen:
            return
        seen.add(key)
        severity = sig.severity if hit.context in _ACTIVE else Severity.LOW
        classification = (
            sig.classification if hit.context in _ACTIVE else Classification.INFORMATIONAL
        )
        indicator = hit.matched
        if sig.signature_type == SignatureType.IOC and sig.indicator_type is not None:
            # Always use public endpoint form, not a URL path or raw decoded bytes.
            indicator = public_label(sig.indicator_type, hit.matched)
        output.append(
            Finding(
                detection_id=sig.detection_id,
                category=(
                    "signature-indicator"
                    if sig.signature_type == SignatureType.IOC
                    else "signature-content"
                ),
                title="Static signature match",
                severity=severity,
                confidence=sig.confidence,
                classification=classification,
                artifact=hit.location.path,
                line=hit.location.line,
                explanation=(
                    f"{sig.signature_type.value} match in {hit.context}; presence is not proof "
                    "of execution or compromise."
                ),
                evidence=(
                    f"{sig.indicator_type.value if sig.indicator_type else 'content'}: {indicator}"
                ),
                remediation="Review the matched artifact and signature source before trusting it.",
                detector="signature_engine",
                references=sig.references,
                signature=SignatureEvidence(
                    sig.detection_id,
                    sig.signature_type.value,
                    sig.indicator_type.value if sig.indicator_type else None,
                    indicator,
                    sig.source,
                    hit.context,
                    sig.version,
                    hit.representation,
                ),
            )
        )
