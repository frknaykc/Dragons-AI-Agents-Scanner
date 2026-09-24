"""Shared domain models; no I/O or presentation dependencies."""

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class ArtifactKind(StrEnum):
    INSTRUCTIONS = "instructions"
    SKILL = "skill"
    MEMORY = "memory"
    SOUL = "soul"
    MCP_CONFIG = "mcp_config"
    AGENT_CONFIG = "agent_config"
    PLUGIN_METADATA = "plugin_metadata"
    HOOK_CONFIG = "hook_config"
    SCRIPT = "script"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    STRUCTURED_CONFIG = "structured_config"


class SourceFormat(StrEnum):
    MARKDOWN = "markdown"
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Classification(StrEnum):
    MALICIOUS = "malicious"
    EXPLOITABLE = "exploitable"
    RISKY = "risky"
    SUSPICIOUS = "suspicious"
    INFORMATIONAL = "informational"


@dataclass(frozen=True)
class Target:
    path: Path


@dataclass(frozen=True)
class Artifact:
    path: Path
    kind: ArtifactKind
    source_format: SourceFormat
    ecosystem: str | None = None


@dataclass(frozen=True)
class SourceRef:
    path: Path
    source_format: SourceFormat
    line: int | None = None
    end_line: int | None = None


@dataclass(frozen=True)
class Span:
    kind: str
    text: str
    location: SourceRef
    destination: str | None = None


@dataclass(frozen=True)
class MarkdownBlock:
    kind: str
    text: str
    location: SourceRef
    spans: tuple[Span, ...] = ()
    language: str | None = None


@dataclass(frozen=True)
class ConfigEntry:
    key_path: tuple[str | int, ...]
    kind: str
    value: str | int | float | bool | None
    location: SourceRef


@dataclass(frozen=True)
class Relationship:
    kind: str
    target: str
    location: SourceRef
    subject: str | None = None


@dataclass(frozen=True)
class Instruction:
    text: str
    line: int
    location: SourceRef


@dataclass(frozen=True)
class McpServer:
    name: str
    command: str
    args: tuple[str, ...]
    location: SourceRef
    transport: str | None = None
    env_names: tuple[str, ...] = ()
    url: str | None = None
    runtime: str | None = None
    package: str | None = None


@dataclass(frozen=True)
class Document:
    artifact: Artifact
    instructions: tuple[Instruction, ...] = ()
    servers: tuple[McpServer, ...] = ()
    blocks: tuple[MarkdownBlock, ...] = ()
    entries: tuple[ConfigEntry, ...] = ()
    relationships: tuple[Relationship, ...] = ()


@dataclass(frozen=True)
class Finding:
    detection_id: str
    category: str
    title: str
    severity: Severity
    confidence: Confidence
    classification: Classification
    artifact: Path
    explanation: str
    evidence: str
    remediation: str
    detector: str
    line: int | None = None
    source: str | None = None
    sink: str | None = None
    capabilities: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanReport:
    target: Path
    artifacts: tuple[Artifact, ...]
    findings: tuple[Finding, ...]
    # Problems are distinct from findings: an unreadable target cannot be assessed.
    errors: tuple[str, ...] = ()
    risk: Severity | None = None
    counts: dict[str, int] = field(default_factory=dict)
