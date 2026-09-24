"""Typed, presentation-independent boundary for static detection engines."""

import re
from dataclasses import dataclass
from typing import Protocol

from dragonscan.models import (
    ArtifactKind,
    Classification,
    Confidence,
    Document,
    Finding,
    Severity,
    SourceRef,
)

_ID = re.compile(r"DRAGON-(?:PI|CRED|EXFIL|EXEC|PERSIST|TRUST|OBF|MCP)-[0-9]{3}\Z")


@dataclass(frozen=True)
class DetectionMetadata:
    detection_id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    classification: Classification
    artifact_types: tuple[str, ...]
    description: str
    remediation: str
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.detection_id):
            raise ValueError("invalid Dragons detection ID")
        if not all((self.title, self.category, self.description, self.remediation)):
            raise ValueError(
                "detection metadata requires title, category, description and remediation"
            )
        valid_kinds = {kind.value for kind in ArtifactKind}
        if not self.artifact_types or any(kind not in valid_kinds for kind in self.artifact_types):
            raise ValueError("detection metadata requires known applicable artifact types")
        if len(set(self.artifact_types)) != len(self.artifact_types):
            raise ValueError("duplicate applicable artifact type")
        if not isinstance(self.severity, Severity) or not isinstance(self.confidence, Confidence):
            raise ValueError("invalid severity or confidence")
        if not isinstance(self.classification, Classification):
            raise ValueError("invalid classification")


@dataclass(frozen=True)
class Observation:
    """A bounded, non-secret behavior fact; context indexes a Markdown instruction."""

    kind: str
    label: str
    location: SourceRef
    context: int
    segment: int
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class DetectionContext:
    document: Document
    observations: tuple[Observation, ...]
    prior_findings: tuple[Finding, ...] = ()


class EngineDetector(Protocol):
    @property
    def metadata(self) -> DetectionMetadata: ...

    def detect(self, context: DetectionContext) -> tuple[Finding, ...]: ...


def finding(
    metadata: DetectionMetadata,
    document: Document,
    location: SourceRef,
    evidence: str,
    detector: str,
    capabilities: tuple[str, ...],
    source: str | None = None,
    sink: str | None = None,
) -> Finding:
    return Finding(
        detection_id=metadata.detection_id,
        category=metadata.category,
        title=metadata.title,
        severity=metadata.severity,
        confidence=metadata.confidence,
        classification=metadata.classification,
        artifact=document.artifact.path,
        line=location.line,
        evidence=evidence,
        explanation=metadata.description,
        remediation=metadata.remediation,
        detector=detector,
        source=source,
        sink=sink,
        capabilities=capabilities,
        references=metadata.references,
    )
