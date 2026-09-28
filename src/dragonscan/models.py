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
    TEXT = "text"


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
class McpSecretRef:
    name: str
    origin: str  # reference, literal, or unknown; the value is never retained here
    sensitive: bool
    location: SourceRef


@dataclass(frozen=True)
class McpTool:
    name: str
    description: str
    instructions: str
    schema_fields: tuple[str, ...]
    location: SourceRef


@dataclass(frozen=True)
class McpContent:
    name: str
    description: str
    location: SourceRef
    url: str | None = None  # Public HTTP(S) location only; no opaque path or query
    uri_scheme: str | None = None


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
    url_has_credentials: bool = False
    cwd: str | None = None
    package_version: str | None = None
    pinning: str | None = None
    environment: tuple[McpSecretRef, ...] = ()
    headers: tuple[McpSecretRef, ...] = ()
    tools: tuple[McpTool, ...] = ()
    resources: tuple[McpContent, ...] = ()
    prompts: tuple[McpContent, ...] = ()
    mutable_tools_url: str | None = None


@dataclass(frozen=True)
class Dependency:
    """Public, normalized static evidence; raw credentials are never retained."""

    ecosystem: str
    name: str
    requested: str | None
    exact_version: str | None
    pinning: str
    source: str
    manager: str
    mechanism: str
    group: str
    location: SourceRef
    registry: str | None = None
    lockfile: Path | None = None
    integrity: bool = False
    provenance: str = "manifest"
    path_status: str | None = None


@dataclass(frozen=True)
class Document:
    artifact: Artifact
    instructions: tuple[Instruction, ...] = ()
    servers: tuple[McpServer, ...] = ()
    blocks: tuple[MarkdownBlock, ...] = ()
    entries: tuple[ConfigEntry, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    dependencies: tuple[Dependency, ...] = ()
    diagnostics: tuple[str, ...] = ()
    registry: str | None = None
    registry_scopes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class PathStep:
    edge: str
    source: str
    target: str
    artifact: Path
    line: int | None
    origin: str
    confidence: Confidence


@dataclass(frozen=True)
class FlowEvidence:
    """Structured static route context, without raw instruction bodies or secrets."""

    source_type: str
    sink_type: str
    nodes: tuple[str, ...]
    edges: tuple[str, ...]
    artifacts: tuple[Path, ...]
    boundaries: tuple[str, ...]
    capabilities: tuple[str, ...]
    transformations: tuple[str, ...]
    enrichments: tuple[str, ...]
    confidence: Confidence
    locations: tuple[SourceRef, ...]
    source: str | None = None
    sink: str | None = None


@dataclass(frozen=True)
class SignatureEvidence:
    signature_id: str
    signature_type: str
    indicator_type: str | None
    matched_indicator: str
    pack: str
    context: str
    version: str | None = None
    representation: str | None = None


@dataclass(frozen=True)
class DependencyEvidence:
    ecosystem: str
    package: str
    requested: str | None
    pinning: str
    source: str
    manager: str
    mechanism: str
    group: str
    integrity_metadata: bool
    provenance: str
    lockfile: str | None
    path_status: str | None
    registry: str | None = None


@dataclass(frozen=True)
class VulnerabilityEvidence:
    provider: str
    vulnerability_id: str
    aliases: tuple[str, ...]
    ecosystem: str
    package: str
    version: str
    summary: str
    upstream_severity: str | None
    cvss: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    affected_ranges: tuple[str, ...]
    references: tuple[str, ...]
    published: str | None
    modified: str | None
    provenance: str
    query_status: str


@dataclass(frozen=True)
class EvasionEvidence:
    """Bounded provenance of a static analysis view, never executable content."""

    chain: tuple[str, ...]
    depth: int
    source_kind: str
    source_start: int | None
    source_end: int | None
    original_excerpt: str
    confidence: Confidence
    canonical_excerpt: str = ""


@dataclass(frozen=True)
class SemanticEvidence:
    """Validated model opinion; never a deterministic source, edge or proof."""

    candidate_id: str
    provider: str
    model: str
    task: str
    analyzer_version: str
    category: str
    verdict: str
    evidence_ids: tuple[str, ...]
    rationale: str
    transformed: bool = False
    transformation_confidence: Confidence | None = None


@dataclass(frozen=True)
class DynamicMcpItem:
    name: str
    description_sha256: str  # Never retain server-controlled descriptions or URI bodies.


@dataclass(frozen=True)
class DynamicMcpObservation:
    artifact: Path
    server: str
    provenance: str = "dynamic_observation"
    tools: tuple[DynamicMcpItem, ...] = ()
    prompts: tuple[DynamicMcpItem, ...] = ()
    resources: tuple[DynamicMcpItem, ...] = ()


@dataclass(frozen=True)
class InstalledEnvironment:
    agent: str
    root: Path
    source: str
    artifact_roots: tuple[Path, ...]
    status: str  # discovered, not_found, or diagnostic; not binary installation proof
    diagnostic: str | None = None


@dataclass(frozen=True)
class ArtifactOrigin:
    artifact: Path
    provenance: str  # explicit_target or installed_agent
    agent: str | None = None
    environment: Path | None = None
    source: str | None = None
    scanned_artifact: Path | None = None


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
    path: tuple[PathStep, ...] = ()
    taint: tuple[str, ...] = ()
    signature: SignatureEvidence | None = None
    dependency: DependencyEvidence | None = None
    vulnerability: VulnerabilityEvidence | None = None
    evasion: EvasionEvidence | None = None
    flow: FlowEvidence | None = None
    semantic: SemanticEvidence | None = None


@dataclass(frozen=True)
class ScanReport:
    target: Path
    artifacts: tuple[Artifact, ...]
    findings: tuple[Finding, ...]
    # Problems are distinct from findings: an unreadable target cannot be assessed.
    errors: tuple[str, ...] = ()
    risk: Severity | None = None
    counts: dict[str, int] = field(default_factory=dict)
    vulnerability_status: str = "disabled"
    vulnerability_diagnostics: tuple[str, ...] = ()
    semantic_status: str = "disabled"
    semantic_provider: str | None = None
    semantic_model: str | None = None
    semantic_candidates_selected: int = 0
    semantic_candidates_analyzed: int = 0
    semantic_diagnostics: tuple[str, ...] = ()
    dynamic_status: str = "not_requested"
    dynamic_diagnostics: tuple[str, ...] = ()
    dynamic_observations: tuple[DynamicMcpObservation, ...] = ()
    installed_environments: tuple[InstalledEnvironment, ...] = ()
    artifact_origins: tuple[ArtifactOrigin, ...] = ()
    acquisition_status: str = "not_required"
    acquisition_kind: str | None = None
    acquisition_source: str | None = None
    acquisition_diagnostics: tuple[str, ...] = ()
