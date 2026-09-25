"""Scanner orchestration; independent from CLI and report format."""

from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from dragonscan.attack_graph import AttackGraph, GraphLimitError, build_graph
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
from dragonscan.signature_graph import annotate, enrich_correlations
from dragonscan.signature_packs import load_pack
from dragonscan.signatures import BUILTIN_SIGNATURES, SignatureEngine
from dragonscan.supply_chain import analyze as analyze_dependencies
from dragonscan.vulnerability import VULNERABILITY_IDS, IntelligenceProvider
from dragonscan.vulnerability import enrich as enrich_vulnerabilities


class Scanner:
    def __init__(
        self,
        rules: Sequence[Rule] | None = None,
        detectors: Sequence[EngineDetector] | None = None,
        signature_pack: Path | None = None,
        vulnerability_provider: IntelligenceProvider | None = None,
    ):
        # An explicit legacy rule selection keeps the old selection semantics.
        self.rules = tuple(BUILTIN_RULES if rules is None else rules)
        self.vulnerability_provider = vulnerability_provider
        self.graph: AttackGraph | None = None
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
        reserved = (
            set(identifiers)
            | {signature.detection_id for signature in BUILTIN_SIGNATURES}
            | VULNERABILITY_IDS
        )
        loaded, self.pack_diagnostics = (
            load_pack(signature_pack, reserved) if signature_pack is not None else ((), ())
        )
        builtins = BUILTIN_SIGNATURES if rules is None else ()
        self.signature_engine = (
            SignatureEngine((*builtins, *loaded)) if builtins or loaded else None
        )

    def scan(self, target: Target) -> ScanReport:
        artifacts = discover(target)
        normalized: list[Artifact] = []
        documents: list[Document] = []
        observations_by_path: dict[Path, tuple[Observation, ...]] = {}
        findings: list[Finding] = []
        graph = None
        errors: list[str] = list(self.pack_diagnostics)
        for artifact in artifacts:
            try:
                text = load_text(artifact.path)
                document = parse(artifact, text)
            except (LoadError, ParseError) as exc:
                errors.append(f"{artifact.path}: {exc}")
                normalized.append(artifact)
                continue
            normalized.append(document.artifact)
            documents.append(document)
            errors.extend(f"{artifact.path}: {diagnostic}" for diagnostic in document.diagnostics)
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
            if self.signature_engine is not None:
                document_findings.extend(self.signature_engine.detect(document, text))
                if self.signature_engine.limit_reason:
                    errors.append(f"{artifact.path}: {self.signature_engine.limit_reason}")
            findings.extend(
                replace(finding, capabilities=(*finding.capabilities, "remote-installer"))
                if finding.detection_id in {"DRAGON-EXEC-001", "DAAS-002"}
                and "remote-installer" not in finding.capabilities
                else finding
                for finding in document_findings
            )
        if self.enable_correlation:
            analyzed, supply_findings, supply_errors = analyze_dependencies(
                target, tuple(documents)
            )
            documents = list(analyzed)
            findings.extend(supply_findings)
            errors.extend(supply_errors)
        if self.enable_correlation:
            try:
                graph = build_graph(target.path.absolute(), tuple(documents), observations_by_path)
                graph = annotate(graph, tuple(documents), tuple(findings))
                correlated = (
                    *correlate(graph, tuple(documents), observations_by_path, tuple(findings)),
                    *correlate_mcp(graph, tuple(documents), tuple(findings)),
                )
                findings.extend(enrich_correlations(graph, correlated))
            except GraphLimitError as exc:
                errors.append(str(exc))
        results = tuple(findings)
        risk, counts = summarize(results)
        report = ScanReport(target.path, tuple(normalized), results, tuple(errors), risk, counts)
        if self.vulnerability_provider is not None:
            report, graph = enrich_vulnerabilities(
                report, tuple(documents), graph, self.vulnerability_provider
            )
        self.graph = graph
        return report


def scan(path: Target) -> ScanReport:
    return Scanner().scan(path)
