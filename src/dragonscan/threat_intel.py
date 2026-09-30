"""Explicit, untrusted versioned intelligence: bounded data, exact static matches."""

import hashlib
import json
import os
import re
import stat
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dragonscan.models import (
    ArtifactKind,
    Classification,
    Confidence,
    Document,
    Finding,
    IntelligenceEvidence,
    IntelligenceSource,
    Severity,
    SourceRef,
)
from dragonscan.semantic import redact
from dragonscan.signature_ioc import collect_candidates, normalize, public_label
from dragonscan.signature_models import IndicatorType
from dragonscan.signatures import regions
from dragonscan.target_acquisition import AcquisitionError, _download

MAX_FEED_BYTES = 1_048_576
MAX_RECORDS = 512
MAX_MATCHES = 256
STORE_NAME = "intel.json"
INTELLIGENCE_IDS = frozenset({"DRAGON-TI-001"})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_SOURCE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9 ._-]{0,127}\Z", re.ASCII)
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", re.ASCII)
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,2}\Z", re.ASCII)
_PACKAGE = re.compile(r"(?:@?[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
_ECOSYSTEMS = frozenset({"npm", "PyPI"})
_ALLOWED = frozenset(
    {
        "id",
        "indicator_type",
        "value",
        "classification",
        "source",
        "description",
        "reference",
        "ecosystem",
        "version",
        "artifact_kind",
    }
)
_ACTIVE = frozenset({"mcp_endpoint", "remote_endpoint", "executable_command"})


class FeedError(ValueError):
    """Invalid optional intelligence or unsuccessful explicit update."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key, value in pairs:
        if key in data:
            raise FeedError("duplicate JSON key")
        data[key] = value
    return data


def _label(value: object, name: str, limit: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= limit
        or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value)
    ):
        raise FeedError(f"invalid {name}")
    return value


def _public_source(value: str) -> str:
    # Source is an untrusted display label, never a reference URL or credential.
    cleaned = redact(value)
    if cleaned != value or not _SOURCE_NAME.fullmatch(value) or _AWS_KEY.search(value):
        return "<redacted>"
    return value


def _public_id(value: str) -> bool:
    return bool(_ID.fullmatch(value) and not _AWS_KEY.search(value) and redact(value) == value)


@dataclass(frozen=True)
class Record:
    id: str
    kind: str
    value: str
    classification: str
    source: str
    ecosystem: str | None = None
    version: str | None = None
    artifact_kind: ArtifactKind | None = None


@dataclass(frozen=True)
class Feed:
    id: str
    version: str
    records: tuple[Record, ...]


def parse_feed(raw: bytes) -> Feed:
    """Fail closed on size/schema/identity; metadata cannot grant any authority."""
    if len(raw) > MAX_FEED_BYTES:
        raise FeedError("feed size limit exceeded")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise FeedError(f"invalid feed JSON ({type(exc).__name__})") from None
    if not isinstance(data, dict) or data.keys() - {
        "schema_version",
        "feed_id",
        "feed_version",
        "records",
    }:
        raise FeedError("invalid feed fields")
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise FeedError("unsupported feed schema version")
    feed_id = _label(data.get("feed_id"), "feed ID", 64)
    version = _label(data.get("feed_version"), "feed version", 32)
    if not _public_id(feed_id) or not _VERSION.fullmatch(version):
        raise FeedError("invalid feed identity or version")
    items = data.get("records")
    if not isinstance(items, list) or len(items) > MAX_RECORDS:
        raise FeedError("invalid feed record count")
    records: list[Record] = []
    ids: set[str] = set()
    indicators: set[tuple[str, str, str | None, str | None, ArtifactKind | None]] = set()
    for item in items:
        if not isinstance(item, dict) or item.keys() - _ALLOWED:
            raise FeedError("invalid record fields")
        record_id = _label(item.get("id"), "record ID", 64)
        if not _public_id(record_id) or record_id in ids:
            raise FeedError("duplicate or invalid record ID")
        kind = _label(item.get("indicator_type"), "indicator type", 32)
        classification = _label(item.get("classification"), "classification", 16)
        if classification not in {"malicious", "suspicious"}:
            raise FeedError("unsupported classification")
        source = _public_source(_label(item.get("source"), "source", 128))
        if "description" in item:
            _label(item["description"], "description")
        if "reference" in item:
            reference = _label(item["reference"], "reference")
            if not reference.startswith("https://") or len(reference) > 256:
                raise FeedError("invalid reference")
        value = _label(item.get("value"), "indicator", 512)
        ecosystem: str | None = None
        version_value: str | None = None
        artifact_kind: ArtifactKind | None = None
        if kind == "package":
            ecosystem = _label(item.get("ecosystem"), "ecosystem", 16)
            version_value = _label(item.get("version"), "package version", 64)
            if (
                ecosystem not in _ECOSYSTEMS
                or not _PACKAGE.fullmatch(value)
                or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._+!-]{0,63}", version_value)
            ):
                raise FeedError("invalid package identity")
            if ecosystem == "PyPI":
                value = re.sub(r"[-_.]+", "-", value.lower())
            if "artifact_kind" in item:
                raise FeedError("invalid package scope")
        else:
            if "ecosystem" in item or "version" in item:
                raise FeedError("invalid IOC scope")
            try:
                indicator = IndicatorType(kind)
                if indicator in {IndicatorType.SHA1, IndicatorType.MD5}:
                    raise FeedError("only SHA-256 artifact hashes are supported")
                value = normalize(indicator, value)
                if "artifact_kind" in item:
                    if indicator != IndicatorType.SHA256:
                        raise FeedError("artifact kind requires sha256")
                    artifact_kind = ArtifactKind(_label(item["artifact_kind"], "artifact kind", 32))
            except ValueError as exc:
                raise FeedError("invalid indicator type or value") from exc
        key = (kind, value, ecosystem, version_value, artifact_kind)
        if key in indicators:
            raise FeedError("duplicate indicator")
        ids.add(record_id)
        indicators.add(key)
        records.append(
            Record(
                record_id,
                kind,
                value,
                classification,
                source,
                ecosystem,
                version_value,
                artifact_kind,
            )
        )
    return Feed(feed_id, version, tuple(sorted(records, key=lambda item: item.id)))


def _read(path: Path) -> bytes:
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise FeedError("feed symlink not allowed")
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FEED_BYTES:
            raise FeedError("feed is not a bounded regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                before.st_dev,
                before.st_ino,
            ):
                raise FeedError("feed changed during load")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_FEED_BYTES + 1)
        finally:
            os.close(fd)
    except OSError as exc:
        raise FeedError(f"feed unavailable ({type(exc).__name__})") from None
    return raw


def load_feeds(paths: tuple[Path, ...]) -> tuple[tuple[Feed, ...], tuple[str, ...]]:
    feeds: dict[str, Feed] = {}
    errors: list[str] = []
    for path in sorted(set(paths))[:16]:
        try:
            loaded = parse_feed(_read(path))
            if loaded.id in feeds:
                raise FeedError("duplicate feed ID")
            feeds[loaded.id] = loaded
        except FeedError as exc:
            errors.append(f"intelligence feed unavailable: {exc}")
    if len(set(paths)) > 16:
        errors.append("intelligence feed file limit exceeded")
    return tuple(feeds[key] for key in sorted(feeds)), tuple(errors)


def update_feed(url: str, expected_sha256: str, store: Path) -> Feed:
    """User-authorized HTTPS download; digest + validation precede atomic replacement."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise FeedError("invalid SHA-256 digest")
    if store.is_symlink() or (store.exists() and not store.is_dir()):
        raise FeedError("invalid intelligence store")
    # Do not follow existing store ancestors into another user-selected path.
    if any(parent.is_symlink() for parent in (store, *store.parents)):
        raise FeedError("store symlink not allowed")
    try:
        store.mkdir(mode=0o700, parents=True, exist_ok=True)
        if store.stat().st_mode & 0o022:
            raise FeedError("store must not be group/world writable")
        destination = store / STORE_NAME
        if destination.is_symlink() or (destination.exists() and not destination.is_file()):
            raise FeedError("invalid installed feed")
        with tempfile.TemporaryDirectory(prefix=".intel-", dir=store) as workspace:
            candidate = Path(workspace) / "feed.json"
            _download(url, candidate, max_bytes=MAX_FEED_BYTES)
            candidate.chmod(0o600)
            raw = _read(candidate)
            if hashlib.sha256(raw).hexdigest() != expected_sha256.lower():
                raise FeedError("feed digest mismatch")
            feed = parse_feed(raw)
            if destination.exists():
                if destination.is_symlink():
                    raise FeedError("invalid installed feed")
                installed = parse_feed(_read(destination))
                if installed.id != feed.id:
                    raise FeedError("installed feed identity mismatch")
                old = tuple(int(part) for part in installed.version.split("."))
                new = tuple(int(part) for part in feed.version.split("."))
                width = max(len(old), len(new))
                if new + (0,) * (width - len(new)) < old + (0,) * (width - len(old)):
                    raise FeedError("feed version downgrade blocked")
            with candidate.open("rb") as handle:
                os.fsync(handle.fileno())
            os.replace(candidate, destination)
            return feed
    except (OSError, AcquisitionError) as exc:
        raise FeedError(f"intelligence update failed ({type(exc).__name__})") from None


class Matcher:
    """Index exact records once, then inspect the existing bounded IOC regions."""

    def __init__(self, feeds: tuple[Feed, ...]):
        self.feeds = feeds
        self.diagnostics: list[str] = []
        self.index: dict[
            tuple[str, str, str | None, str | None, ArtifactKind | None], list[IntelligenceSource]
        ] = {}
        for feed in feeds:
            for record in feed.records:
                key = (
                    record.kind,
                    record.value,
                    record.ecosystem,
                    record.version,
                    record.artifact_kind,
                )
                self.index.setdefault(key, []).append(
                    IntelligenceSource(
                        feed.id, feed.version, record.id, record.source, record.classification
                    )
                )
        for sources in self.index.values():
            sources.sort(key=lambda item: (item.feed_id, item.record_id))

    def detect(self, document: Document, artifact_sha256: str) -> tuple[Finding, ...]:
        self.diagnostics = []
        if not self.index:
            return ()
        matches: dict[
            tuple[str, str, int | None], tuple[SourceRef, str, list[IntelligenceSource]]
        ] = {}

        def priority(name: str) -> tuple[bool, bool, str]:
            return name == "artifact_hash", name in _ACTIVE, name

        def add(
            kind: str,
            value: str,
            location: SourceRef,
            context: str,
            scope: tuple[str | None, str | None, ArtifactKind | None] = (None, None, None),
        ) -> None:
            sources = self.index.get((kind, value, *scope), ())
            if not sources:
                return
            key = (kind, value, location.line)
            if key not in matches:
                matches[key] = (location, context, [])
            previous_location, previous_context, previous_sources = matches[key]
            # The same URL can appear in overlapping parsed regions on one line.
            # Retain its strongest observed context without multiplying the fact.
            if priority(context) > priority(previous_context):
                matches[key] = (location, context, previous_sources)
            previous_sources.extend(sources)

        selected = regions(document)
        kinds = {IndicatorType(kind) for kind, _, _, _, _ in self.index if kind != "package"}
        for region in selected:
            for indicator_kind in sorted(kinds):
                if indicator_kind in {IndicatorType.SHA256, IndicatorType.SHA1, IndicatorType.MD5}:
                    continue  # Hashes identify the artifact, not arbitrary prose tokens.
                tokens, limited = collect_candidates(indicator_kind, region.text)
                if limited and "intelligence IOC candidate limit reached" not in self.diagnostics:
                    self.diagnostics.append("intelligence IOC candidate limit reached")
                for token in tokens:
                    add(indicator_kind.value, token, region.location, region.context)
        location = SourceRef(document.artifact.path, document.artifact.source_format)
        if IndicatorType.SHA256 in kinds:
            add("sha256", artifact_sha256, location, "artifact_hash")
            add(
                "sha256",
                artifact_sha256,
                location,
                "artifact_hash",
                (None, None, document.artifact.kind),
            )
        mcp_packages = {
            (
                "PyPI" if server.runtime == "uvx" else "npm",
                server.package.lower(),
                server.package_version.removeprefix("=="),
                server.location.line,
            )
            for server in document.servers
            if server.package
            and server.package_version
            and server.pinning == "exact"
            and server.runtime in {"npx", "npx.cmd", "npm", "npm.cmd", "uvx"}
        }
        for dependency in document.dependencies:
            if dependency.source != "registry" or dependency.exact_version is None:
                continue
            ecosystem = {"node": "npm", "python": "PyPI"}.get(dependency.ecosystem)
            if (
                ecosystem
                and (ecosystem, dependency.name, dependency.exact_version, dependency.location.line)
                not in mcp_packages
            ):
                add(
                    "package",
                    dependency.name,
                    dependency.location,
                    "dependency",
                    (ecosystem, dependency.exact_version, None),
                )
        for server in document.servers:
            if (
                server.package
                and server.package_version
                and server.pinning == "exact"
                and server.runtime in {"npx", "npx.cmd", "npm", "npm.cmd", "uvx"}
            ):
                ecosystem = "PyPI" if server.runtime == "uvx" else "npm"
                version = server.package_version.removeprefix("==")
                name = (
                    re.sub(r"[-_.]+", "-", server.package.lower())
                    if ecosystem == "PyPI"
                    else server.package.lower()
                )
                add("package", name, server.location, "mcp_package", (ecosystem, version, None))
        findings: list[Finding] = []
        for kind, value, line in sorted(matches, key=lambda key: (key[0], key[1], key[2] or 0)):
            location, context, sources = matches[(kind, value, line)]
            if len(findings) >= MAX_MATCHES:
                self.diagnostics.append("intelligence hit limit reached")
                break
            sources = sorted(set(sources), key=lambda item: (item.feed_id, item.record_id))
            # Feed classification/confidence never sets severity; active context or exact
            # artifact hash determines impact. Multiple feeds do not escalate.
            severity = (
                Severity.HIGH
                if context == "artifact_hash"
                else Severity.MEDIUM
                if context in _ACTIVE | {"dependency", "mcp_package"}
                else Severity.LOW
            )
            indicator = public_label(IndicatorType(kind), value) if kind != "package" else value
            findings.append(
                Finding(
                    detection_id="DRAGON-TI-001",
                    category="threat-intelligence",
                    title="Threat intelligence indicator match",
                    severity=severity,
                    confidence=Confidence.HIGH if context == "artifact_hash" else Confidence.MEDIUM,
                    classification=Classification.SUSPICIOUS,
                    artifact=document.artifact.path,
                    line=line,
                    explanation=(
                        "An extracted identity matches an explicitly loaded intelligence record; "
                        "this is not proof of malicious behavior."
                    ),
                    evidence=f"{kind}: {indicator}",
                    remediation=(
                        "Verify the feed and artifact evidence before trusting the artifact."
                    ),
                    detector="threat_intel",
                    intelligence=IntelligenceEvidence(kind, indicator, context, tuple(sources)),
                )
            )
        return tuple(findings)
