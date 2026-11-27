"""Explicit, untrusted versioned intelligence: bounded data, exact static matches."""

import hashlib
import json
import re
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from dragonscan.intel_authority import ACTIVE_INTEL_CONTEXTS
from dragonscan.intel_store import FeedError as FeedError
from dragonscan.intel_store import atomic_write, check_version, locked_store, read_bounded
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
from dragonscan.package_identity import public_package
from dragonscan.scan_budget import ScanBudget
from dragonscan.semantic import redact
from dragonscan.signature_ioc import collect_candidates, normalize, public_label
from dragonscan.signature_models import IndicatorType
from dragonscan.signatures import regions
from dragonscan.target_acquisition import AcquisitionError, _download

MAX_FEED_BYTES = 1_048_576
MAX_RECORDS = 512
MAX_MATCHES = 256
STORE_NAME = "intel.json"
INTELLIGENCE_IDS = frozenset({"DRAGON-TI-001", "DRAGON-SC-010"})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_SOURCE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9 ._-]{0,127}\Z", re.ASCII)
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", re.ASCII)
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,2}\Z", re.ASCII)
_PACKAGE = re.compile(r"(?:@?[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
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
        "sha256",
        "locator",
        "withdrawn",
        "registry",
        "source_version",
        "published",
        "updated",
        "confidence",
        "trust",
        "provenance",
    }
)
_ACTIVE = ACTIVE_INTEL_CONTEXTS


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


def _metadata(item: dict[str, Any], key: str, limit: int = 128) -> str | None:
    if key not in item:
        return None
    value = _label(item[key], key, limit)
    valid = _ID.fullmatch(value) if key == "source_version" else _SOURCE_NAME.fullmatch(value)
    if not valid or value.lower().startswith("bearer ") or redact(value) != value:
        raise FeedError(f"invalid {key}")
    return value


def _timestamp(item: dict[str, Any], key: str) -> str | None:
    if key not in item:
        return None
    value = _label(item[key], key, 20)
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            date.fromisoformat(value)
        elif re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            raise ValueError("unsupported timestamp")
    except ValueError:
        raise FeedError(f"invalid {key}") from None
    return value


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
    qualifier: str | None = None
    source_version: str | None = None
    published: str | None = None
    updated: str | None = None
    confidence: str | None = None
    trust: str | None = None
    provenance: str | None = None


@dataclass(frozen=True)
class Feed:
    id: str
    version: str
    records: tuple[Record, ...]
    sha256: str = ""
    expires: datetime | None = None
    signer: str | None = None


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
        "expires",
        "records",
    }:
        raise FeedError("invalid feed fields")
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise FeedError("unsupported feed schema version")
    feed_id = _label(data.get("feed_id"), "feed ID", 64)
    version = _label(data.get("feed_version"), "feed version", 32)
    if not _public_id(feed_id) or not _VERSION.fullmatch(version):
        raise FeedError("invalid feed identity or version")
    expires = None
    if "expires" in data:
        stamp = _timestamp(data, "expires")
        if not stamp or not stamp.endswith("Z"):
            raise FeedError("expiry must be a UTC timestamp")
        expires = datetime.fromisoformat(stamp)
    items = data.get("records")
    if not isinstance(items, list) or len(items) > MAX_RECORDS:
        raise FeedError("invalid feed record count")
    records: list[Record] = []
    ids: set[str] = set()
    indicators: set[tuple[str, str, str | None, str | None, ArtifactKind | None, str | None]] = (
        set()
    )
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
        source_version = _metadata(item, "source_version", 64)
        published = _timestamp(item, "published")
        updated = _timestamp(item, "updated")
        confidence = _metadata(item, "confidence", 16)
        trust = _metadata(item, "trust", len("operator_reviewed"))
        provenance = _metadata(item, "provenance")
        if confidence is not None and confidence not in {"low", "medium", "high"}:
            raise FeedError("invalid confidence")
        if trust is not None and trust not in {"unverified", "operator_reviewed"}:
            raise FeedError("invalid trust")
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
        qualifier: str | None = None
        withdrawn = _timestamp(item, "withdrawn")
        if "registry" in item and kind != "package":
            raise FeedError("registry requires package identity")
        if kind == "package":
            ecosystem = _label(item.get("ecosystem"), "ecosystem", 16)
            version_value = _label(item.get("version"), "package version", 64)
            if (
                ecosystem not in _ECOSYSTEMS
                or not _PACKAGE.fullmatch(value)
                or (ecosystem == "PyPI" and "/" in value)
                or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._+!-]{0,63}", version_value)
            ):
                raise FeedError("invalid package identity")
            default = "https://pypi.org" if ecosystem == "PyPI" else "https://registry.npmjs.org"
            if item.get("registry", default) != default:
                raise FeedError("unsupported package registry")
            if ecosystem == "PyPI":
                value = re.sub(r"[-_.]+", "-", value.lower())
            if {"artifact_kind", "sha256", "locator"} & item.keys():
                raise FeedError("invalid package scope")
        elif kind in {"skill", "plugin", "mcp_server"}:
            if {"ecosystem", "version", "artifact_kind"} & item.keys():
                raise FeedError("invalid named identity scope")
            if kind == "skill":
                if not _NAME.fullmatch(value) or "locator" in item:
                    raise FeedError("invalid skill identity")
            elif kind == "plugin":
                if (
                    len(value) > 256
                    or len(value.split("/")) != 2
                    or not all(_NAME.fullmatch(part) for part in value.split("/"))
                    or "locator" in item
                ):
                    raise FeedError("invalid plugin identity")
            elif not _NAME.fullmatch(value) or "sha256" in item:
                raise FeedError("invalid MCP identity")
            if kind == "mcp_server":
                try:
                    qualifier = normalize(
                        IndicatorType.URL, _label(item.get("locator"), "locator", 256)
                    )
                except ValueError as exc:
                    raise FeedError("invalid MCP locator") from exc
                if not qualifier.startswith("https://"):
                    raise FeedError("MCP locator requires HTTPS")
            else:
                try:
                    qualifier = normalize(
                        IndicatorType.SHA256, _label(item.get("sha256"), "sha256", 64)
                    )
                except ValueError as exc:
                    raise FeedError("invalid named artifact hash") from exc
        else:
            if {"ecosystem", "version", "sha256", "locator"} & item.keys():
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
        key = (kind, value, ecosystem, version_value, artifact_kind, qualifier)
        if withdrawn:
            ids.add(record_id)
            continue
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
                qualifier,
                source_version,
                published,
                updated,
                confidence,
                trust,
                provenance,
            )
        )
    return Feed(
        feed_id,
        version,
        tuple(sorted(records, key=lambda item: item.id)),
        hashlib.sha256(raw).hexdigest(),
        expires,
    )


def _read(path: Path) -> bytes:
    return read_bounded(path, MAX_FEED_BYTES)


def load_feeds(
    paths: tuple[Path, ...], *, trust_path: Path | None = None
) -> tuple[tuple[Feed, ...], tuple[str, ...]]:
    from dragonscan.signed_intel import read_release

    feeds: dict[str, Feed] = {}
    errors: list[str] = []
    for path in sorted(set(paths))[:16]:
        try:
            loaded = read_release(path, trust_path)
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
    with locked_store(store):
        destination = store / STORE_NAME
        try:
            with tempfile.TemporaryDirectory(prefix=".intel-", dir=store) as workspace:
                candidate = Path(workspace) / "feed.json"
                _download(url, candidate, max_bytes=MAX_FEED_BYTES)
                raw = _read(candidate)
            if hashlib.sha256(raw).hexdigest() != expected_sha256.lower():
                raise FeedError("feed digest mismatch")
            feed = parse_feed(raw)
            if feed.expires and feed.expires <= datetime.now(UTC):
                raise FeedError("feed expired")
            if destination.exists() or destination.is_symlink():
                # A legacy update may never overwrite an authenticated envelope.
                installed = parse_feed(_read(destination))
                if installed.id != feed.id:
                    raise FeedError("installed feed identity mismatch")
                check_version(installed.version, feed.version, installed.sha256, feed.sha256)
            atomic_write(destination, raw)
            return feed
        except AcquisitionError as exc:
            raise FeedError(f"intelligence update failed ({type(exc).__name__})") from None


class Matcher:
    """Index exact records once, then inspect the existing bounded IOC regions."""

    def __init__(self, feeds: tuple[Feed, ...], *, budget: ScanBudget | None = None):
        self.budget = budget
        self.remaining = budget.limits.max_findings if budget else MAX_MATCHES
        self.feeds = feeds
        self.diagnostics: list[str] = []
        self.index: dict[
            tuple[str, str, str | None, str | None, ArtifactKind | None, str | None],
            list[IntelligenceSource],
        ] = {}
        for feed in feeds:
            if feed.expires and feed.expires <= datetime.now(UTC):
                continue
            for record in feed.records:
                key = (
                    record.kind,
                    record.value,
                    record.ecosystem,
                    record.version,
                    record.artifact_kind,
                    record.qualifier,
                )
                self.index.setdefault(key, []).append(
                    IntelligenceSource(
                        feed.id,
                        feed.version,
                        record.id,
                        record.source,
                        record.classification,
                        record.source_version or feed.version,
                        record.published,
                        record.updated,
                        record.confidence,
                        "authenticated_reviewed"
                        if feed.signer and record.trust == "operator_reviewed"
                        else "authenticated"
                        if feed.signer
                        else "unverified",
                        f"OpenSSH signer {feed.signer}" if feed.signer else record.provenance,
                        feed.sha256,
                    )
                )
        for sources in self.index.values():
            sources.sort(key=lambda item: (item.feed_id, item.record_id))

    def detect(self, document: Document, artifact_sha256: str) -> tuple[Finding, ...]:
        self.diagnostics = []
        if self.budget and not self.budget.running():
            self.diagnostics.append(self.budget.reason or "scan stopped")
            return ()
        if not self.index:
            return ()
        limit = min(MAX_MATCHES, self.remaining) if self.budget else MAX_MATCHES
        matches: dict[
            tuple[str, str, int | None, str], tuple[SourceRef, str, set[IntelligenceSource]]
        ] = {}

        def priority(name: str) -> tuple[bool, bool, str]:
            return name == "artifact_hash", name in _ACTIVE, name

        def add(
            kind: str,
            value: str,
            location: SourceRef,
            context: str,
            scope: tuple[str | None, str | None, ArtifactKind | None, str | None] = (
                None,
                None,
                None,
                None,
            ),
            *,
            public_origin_observed: bool = False,
        ) -> None:
            sources: tuple[IntelligenceSource, ...] | list[IntelligenceSource] = self.index.get(
                (kind, value, *scope), ()
            )
            if kind == "package" and not public_origin_observed:
                # Keep existing advisory-only default-registry matches. Do not let
                # an inferred registry authorize authenticated package decisions.
                sources = [src for src in sources if src.trust == "unverified"]
            if not sources:
                return
            identity = f"{scope[0]}:{value}@{scope[1]}" if kind == "package" else ""
            key = (kind, value, location.line, identity)
            if key not in matches:
                if len(matches) >= limit:
                    reason = "intelligence hit limit reached"
                    if self.budget and self.remaining <= MAX_MATCHES:
                        self.budget.reason = "scan finding budget reached"
                        reason = self.budget.reason
                    if reason not in self.diagnostics:
                        self.diagnostics.append(reason)
                    return
                matches[key] = (location, context, set())
            previous_location, previous_context, previous_sources = matches[key]
            # The same URL can appear in overlapping parsed regions on one line.
            # Retain its strongest observed context without multiplying the fact.
            if priority(context) > priority(previous_context):
                matches[key] = (location, context, previous_sources)
            previous_sources.update(sources)

        selected = regions(document)
        kinds = {
            IndicatorType(kind)
            for kind, _, _, _, _, _ in self.index
            if kind not in {"package", "skill", "plugin", "mcp_server"}
        }
        for region in selected:
            if self.budget and not self.budget.running():
                break
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
                (None, None, document.artifact.kind, None),
            )
        if (
            document.artifact.kind == ArtifactKind.SKILL
            and document.artifact.path.name.lower() == "skill.md"
        ):
            skill_name = document.artifact.path.parent.name
            if (
                _NAME.fullmatch(skill_name)
                and document.artifact.path.parent.parent.name.lower() == "skills"
            ):
                add(
                    "skill",
                    skill_name,
                    location,
                    "artifact_hash",
                    (None, None, None, artifact_sha256),
                )
        if document.artifact.kind == ArtifactKind.PLUGIN_METADATA:
            fields = {
                entry.key_path: entry.value for entry in document.entries if entry.kind == "string"
            }
            name, publisher = fields.get(("name",)), fields.get(("publisher",))
            if (
                isinstance(name, str)
                and isinstance(publisher, str)
                and _NAME.fullmatch(name)
                and _NAME.fullmatch(publisher)
            ):
                add(
                    "plugin",
                    f"{publisher}/{name}",
                    location,
                    "artifact_hash",
                    (None, None, None, artifact_sha256),
                )
        for dependency in document.dependencies:
            if self.budget and not self.budget.running():
                break
            identity = public_package(dependency, document)
            if identity is not None:
                add(
                    "package",
                    identity.name,
                    dependency.location,
                    "mcp_package"
                    if dependency.group == "mcp"
                    else "runtime_package"
                    if dependency.mechanism == "runtime-execution"
                    else "dependency",
                    (identity.ecosystem, identity.version, None, None),
                    public_origin_observed=dependency.registry == identity.registry,
                )
        for server in document.servers:
            if self.budget and not self.budget.running():
                break
            if server.url and server.url_identity_exact and _NAME.fullmatch(server.name):
                # Parsed identity is exact only when the raw endpoint carried no
                # opaque route, credentials, query, or fragment.
                if server.url.startswith("https://"):
                    try:
                        endpoint = normalize(IndicatorType.URL, server.url)
                    except ValueError:
                        continue
                    add(
                        "mcp_server",
                        server.name,
                        server.location,
                        "mcp_endpoint",
                        (None, None, None, endpoint),
                    )
        findings: list[Finding] = []
        for kind, value, line, identity_text in sorted(
            matches, key=lambda key: (key[0], key[1], key[2] or 0, key[3])
        ):
            location, context, sources = matches[(kind, value, line, identity_text)]
            ordered_sources = sorted(sources, key=lambda item: (item.feed_id, item.record_id))
            # Feed classification/confidence never sets severity; active context or exact
            # artifact hash determines impact. Multiple feeds do not escalate.
            severity = (
                Severity.HIGH
                if context == "artifact_hash"
                else Severity.MEDIUM
                if context in _ACTIVE | {"dependency", "mcp_package"}
                else Severity.LOW
            )
            malicious_package = (
                kind == "package"
                and context in {"mcp_package", "runtime_package"}
                and any(
                    src.trust in {"authenticated", "authenticated_reviewed"}
                    and src.classification == "malicious"
                    for src in ordered_sources
                )
            )
            indicator = (
                public_label(IndicatorType(kind), value)
                if kind not in {"package", "skill", "plugin", "mcp_server"}
                else value
            )
            findings.append(
                Finding(
                    detection_id="DRAGON-SC-010" if malicious_package else "DRAGON-TI-001",
                    category="threat-intelligence",
                    title="Authenticated malicious package advisory in runtime declaration"
                    if malicious_package
                    else "Threat intelligence indicator match",
                    severity=Severity.HIGH if malicious_package else severity,
                    confidence=Confidence.HIGH if context == "artifact_hash" else Confidence.MEDIUM,
                    classification=Classification.SUSPICIOUS,
                    artifact=document.artifact.path,
                    line=line,
                    explanation=(
                        "An extracted identity matches an explicitly loaded intelligence record; "
                        "this is not proof of malicious behavior."
                    ),
                    evidence=f"{kind}: {identity_text or indicator}",
                    remediation=(
                        "Verify the feed and artifact evidence before trusting the artifact."
                    ),
                    detector="threat_intel",
                    intelligence=IntelligenceEvidence(
                        kind, indicator, context, tuple(ordered_sources)
                    ),
                )
            )
        if self.budget:
            self.remaining -= len(findings)
            if not self.budget.running() and self.budget.reason not in self.diagnostics:
                self.diagnostics.append(self.budget.reason or "scan stopped")
        return tuple(findings)
