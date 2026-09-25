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
from dragonscan.evasion import views
from dragonscan.evasion_graph import annotate_views
from dragonscan.loading import LoadError, load_text
from dragonscan.mcp_correlation import correlate_mcp
from dragonscan.models import (
    Artifact,
    Classification,
    Confidence,
    Document,
    Finding,
    Instruction,
    ScanReport,
    Severity,
    Target,
)
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
            # Derived views are evidence only; never add their observations or
            # dependencies to the graph or vulnerability query plan.
            derived, diagnostics = views(document)
            errors.extend(f"{artifact.path}: {item}" for item in diagnostics)
            seen = {
                (
                    f.detection_id,
                    f.line,
                    f.source,
                    f.sink,
                    f.signature.context if f.signature else None,
                )
                for f in document_findings
            }
            if document.artifact.path.name == "package.json":
                seen.update(
                    (
                        f.detection_id,
                        f.line,
                        f.source,
                        f.sink,
                        None,
                    )
                    for f in analyze_dependencies(target, (document,))[1]
                )
            for view in derived:
                candidates: list[Finding] = []
                if "hidden-html" in view.evidence.chain:
                    hidden = replace(
                        view.document,
                        instructions=(
                            Instruction(view.text, view.location.line or 1, view.location),
                        ),
                    )
                    for rule in self.rules:
                        candidates.extend(rule.detect(hidden))
                    hidden_observations = collect(hidden)
                    for detector in self.detectors:
                        candidates.extend(
                            detector.detect(
                                DetectionContext(hidden, hidden_observations, tuple(candidates))
                            )
                        )
                if view.context == "lifecycle-script":
                    candidates.extend(analyze_dependencies(target, (view.document,))[1])
                for rule in self.rules:
                    candidates.extend(rule.detect(view.document))
                observations_view = collect(view.document)
                for detector in self.detectors:
                    candidates.extend(
                        detector.detect(
                            DetectionContext(view.document, observations_view, tuple(candidates))
                        )
                    )
                if self.signature_engine is not None:
                    candidates.extend(
                        self.signature_engine.detect(
                            view.document, text, include_artifact_hash=False
                        )
                    )
                    if self.signature_engine.limit_reason:
                        errors.append(f"{artifact.path}: {self.signature_engine.limit_reason}")
                for candidate in candidates:
                    if candidate.line not in {None, view.location.line}:
                        continue
                    key = (
                        candidate.detection_id,
                        candidate.line,
                        candidate.source,
                        candidate.sink,
                        candidate.signature.context if candidate.signature else None,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    confidence = (
                        Confidence.LOW
                        if view.evidence.confidence == Confidence.LOW
                        else Confidence.MEDIUM
                        if candidate.confidence == Confidence.HIGH
                        else candidate.confidence
                    )
                    document_findings.append(
                        replace(
                            candidate,
                            line=view.location.line,
                            severity=(
                                Severity.LOW
                                if "hidden-html" in view.evidence.chain
                                else candidate.severity
                            ),
                            classification=(
                                Classification.INFORMATIONAL
                                if "hidden-html" in view.evidence.chain
                                else candidate.classification
                            ),
                            confidence=confidence,
                            taint=(),
                            path=(),
                            evasion=view.evidence,
                        )
                    )
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
                graph = annotate(
                    graph,
                    tuple(documents),
                    tuple(f for f in findings if f.evasion is None),
                )
                graph = annotate_views(graph, tuple(documents), tuple(findings))
                original_findings = tuple(f for f in findings if f.evasion is None)
                correlated = (
                    *correlate(graph, tuple(documents), observations_by_path, original_findings),
                    *correlate_mcp(graph, tuple(documents), original_findings),
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
