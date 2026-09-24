"""Scanner orchestration; independent from CLI and report format."""

from collections.abc import Sequence
from pathlib import Path

from dragonscan.attack_graph import GraphLimitError, build_graph
from dragonscan.behavior import collect
from dragonscan.correlation import correlate
from dragonscan.detection import DetectionContext, EngineDetector, Observation
from dragonscan.detectors import BUILTIN_DETECTORS, SourceSinkDetector
from dragonscan.discovery import discover
from dragonscan.loading import LoadError, load_text
from dragonscan.mcp_correlation import correlate_mcp
from dragonscan.models import Artifact, Document, Finding, ScanReport, Target
from dragonscan.parse_errors import ParseError
from dragonscan.parsing import parse
from dragonscan.risk import summarize
from dragonscan.rules import BUILTIN_RULES, Rule


class Scanner:
    def __init__(
        self,
        rules: Sequence[Rule] | None = None,
        detectors: Sequence[EngineDetector] | None = None,
    ):
        # An explicit legacy rule selection keeps the old selection semantics.
        self.rules = tuple(BUILTIN_RULES if rules is None else rules)
        self.enable_correlation = rules is None
        self.detectors = tuple(
            BUILTIN_DETECTORS if detectors is None and rules is None else detectors or ()
        )
        identifiers = [rule.detection_id for rule in self.rules]
        identifiers.extend(detector.metadata.detection_id for detector in self.detectors)
        identifiers.extend(
            detector.access_metadata.detection_id
            for detector in self.detectors
            if isinstance(detector, SourceSinkDetector)
        )
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("duplicate rule ID")

    def scan(self, target: Target) -> ScanReport:
        artifacts = discover(target)
        normalized: list[Artifact] = []
        documents: list[Document] = []
        observations_by_path: dict[Path, tuple[Observation, ...]] = {}
        findings: list[Finding] = []
        errors: list[str] = []
        for artifact in artifacts:
            try:
                document = parse(artifact, load_text(artifact.path))
            except (LoadError, ParseError) as exc:
                errors.append(f"{artifact.path}: {exc}")
                normalized.append(artifact)
                continue
            normalized.append(document.artifact)
            documents.append(document)
            document_findings: list[Finding] = []
            for rule in self.rules:
                document_findings.extend(rule.detect(document))
            observations = collect(document)
            observations_by_path[document.artifact.path] = observations
            for detector in self.detectors:
                document_findings.extend(
                    detector.detect(
                        DetectionContext(document, observations, tuple(document_findings))
                    )
                )
            findings.extend(document_findings)
        if self.enable_correlation:
            try:
                graph = build_graph(target.path.absolute(), tuple(documents), observations_by_path)
                findings.extend(
                    correlate(graph, tuple(documents), observations_by_path, tuple(findings))
                )
                findings.extend(correlate_mcp(graph, tuple(documents), tuple(findings)))
            except GraphLimitError as exc:
                errors.append(str(exc))
        results = tuple(findings)
        risk, counts = summarize(results)
        return ScanReport(target.path, tuple(normalized), results, tuple(errors), risk, counts)


def scan(path: Target) -> ScanReport:
    return Scanner().scan(path)
