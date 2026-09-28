"""Scanner orchestration; independent from CLI and report format."""

from collections.abc import Sequence
from dataclasses import fields, is_dataclass, replace
from enum import Enum
from pathlib import Path

from dragonscan.attack_graph import AttackGraph, GraphLimitError, build_graph, node_id
from dragonscan.behavior import collect
from dragonscan.correlation import correlate
from dragonscan.detection import DetectionContext, EngineDetector, Observation
from dragonscan.detectors import BUILTIN_DETECTORS, SourceSinkDetector
from dragonscan.discovery import DiscoveryError, discover
from dragonscan.dynamic_mcp import DynamicPolicy, DynamicResult
from dragonscan.dynamic_mcp import inspect as inspect_mcp
from dragonscan.evasion import views
from dragonscan.evasion_graph import annotate_views
from dragonscan.flow import correlate_flows, describe_existing_flow
from dragonscan.installed_agents import discover_installed
from dragonscan.loading import LoadError, load_text
from dragonscan.mcp_correlation import correlate_mcp
from dragonscan.models import (
    Artifact,
    ArtifactOrigin,
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
from dragonscan.semantic import SemanticLimits, SemanticProvider
from dragonscan.semantic import enrich as enrich_semantic
from dragonscan.signature_graph import annotate, enrich_correlations
from dragonscan.signature_packs import load_pack
from dragonscan.signatures import BUILTIN_SIGNATURES, SignatureEngine
from dragonscan.supply_chain import analyze as analyze_dependencies
from dragonscan.target_acquisition import AcquiredTarget
from dragonscan.vulnerability import VULNERABILITY_IDS, IntelligenceProvider
from dragonscan.vulnerability import enrich as enrich_vulnerabilities


class Scanner:
    def __init__(
        self,
        rules: Sequence[Rule] | None = None,
        detectors: Sequence[EngineDetector] | None = None,
        signature_pack: Path | None = None,
        vulnerability_provider: IntelligenceProvider | None = None,
        semantic_provider: SemanticProvider | None = None,
        semantic_limits: SemanticLimits | None = None,
        dynamic_policy: DynamicPolicy | None = None,
    ):
        # An explicit legacy rule selection keeps the old selection semantics.
        self.rules = tuple(BUILTIN_RULES if rules is None else rules)
        self.vulnerability_provider = vulnerability_provider
        self.semantic_provider = semantic_provider
        self.semantic_limits = semantic_limits or SemanticLimits()
        self.dynamic_policy = dynamic_policy or DynamicPolicy()
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

    def scan(
        self,
        target: Target,
        *,
        artifacts: tuple[Artifact, ...] | None = None,
        boundaries: dict[Path, Path] | None = None,
        reference_boundaries: dict[Path, Path] | None = None,
    ) -> ScanReport:
        if artifacts is None:
            artifacts = discover(target)

        def boundary_for(path: Path) -> Target:
            return Target(boundaries[path]) if boundaries is not None else target

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
                    for f in analyze_dependencies(
                        boundary_for(document.artifact.path), (document,)
                    )[1]
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
                    candidates.extend(
                        analyze_dependencies(
                            boundary_for(view.document.artifact.path), (view.document,)
                        )[1]
                    )
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
            if boundaries is None:
                analyzed, supply_findings, supply_errors = analyze_dependencies(
                    target, tuple(documents)
                )
                documents = list(analyzed)
                findings.extend(
                    describe_existing_flow(f, tuple(documents)) for f in supply_findings
                )
                errors.extend(supply_errors)
            else:
                groups: dict[Path, list[Document]] = {}
                for document in documents:
                    groups.setdefault(boundaries[document.artifact.path], []).append(document)
                documents = []
                for boundary, group in groups.items():
                    analyzed, supply_findings, supply_errors = analyze_dependencies(
                        Target(boundary), tuple(group)
                    )
                    documents.extend(analyzed)
                    findings.extend(
                        describe_existing_flow(f, tuple(analyzed)) for f in supply_findings
                    )
                    errors.extend(supply_errors)
        if self.enable_correlation:
            try:
                graph = build_graph(
                    target.path.absolute(),
                    tuple(documents),
                    observations_by_path,
                    reference_boundaries=reference_boundaries,
                )
                graph = annotate(
                    graph,
                    tuple(documents),
                    tuple(f for f in findings if f.evasion is None),
                    self.signature_engine.signatures if self.signature_engine is not None else (),
                )
                graph = annotate_views(graph, tuple(documents), tuple(findings))
                original_findings = tuple(f for f in findings if f.evasion is None)
                correlated = (
                    *correlate(graph, tuple(documents), observations_by_path, original_findings),
                    *correlate_mcp(graph, tuple(documents), original_findings),
                )
                findings.extend(
                    describe_existing_flow(finding, tuple(documents))
                    for finding in enrich_correlations(graph, correlated)
                )
                flow_findings, flow_diagnostics = correlate_flows(graph, tuple(documents))
                findings.extend(enrich_correlations(graph, flow_findings))
                errors.extend(flow_diagnostics)
            except GraphLimitError as exc:
                errors.append(str(exc))
        results = tuple(findings)
        risk, counts = summarize(results)
        report = ScanReport(target.path, tuple(normalized), results, tuple(errors), risk, counts)
        if self.vulnerability_provider is not None:
            report, graph = enrich_vulnerabilities(
                report, tuple(documents), graph, self.vulnerability_provider
            )
        if self.semantic_provider is not None:
            report = enrich_semantic(
                report, tuple(documents), self.semantic_provider, self.semantic_limits
            )
        if self.dynamic_policy.requested:
            dynamic = (
                DynamicResult("blocked", ("static scan incomplete; MCP launch skipped",))
                if report.errors
                else inspect_mcp(tuple(documents), self.dynamic_policy)
            )
            report = replace(
                report,
                dynamic_status=dynamic.status,
                dynamic_diagnostics=dynamic.diagnostics,
                dynamic_observations=dynamic.observations,
            )
        self.graph = graph
        return report

    def scan_installed(
        self, target: Target | None = None, *, home: Path | None = None, platform: str | None = None
    ) -> ScanReport:
        if self.dynamic_policy.requested:
            raise DiscoveryError("dynamic MCP is unavailable during installed-agent discovery")
        discovered = discover_installed(home=home, platform=platform)
        explicit = discover(target) if target is not None else ()
        all_artifacts = (*explicit, *discovered.artifacts)
        origins = (
            *(ArtifactOrigin(artifact.path, "explicit_target") for artifact in explicit),
            *discovered.origins,
        )
        unique: list[Artifact] = []
        resolved_origins: list[ArtifactOrigin] = []
        boundaries: dict[Path, Path] = {}
        reference_boundaries: dict[Path, Path] = {}
        seen: dict[tuple[object, ...], Path] = {}
        for artifact, origin in zip(all_artifacts, origins, strict=True):
            try:
                info = artifact.path.lstat()
                identity: tuple[object, ...] = (info.st_dev, info.st_ino)
            except OSError:
                identity = ("missing", str(artifact.path))
            if identity in seen:
                resolved_origins.append(replace(origin, scanned_artifact=seen[identity]))
                continue
            seen[identity] = artifact.path
            resolved_origins.append(replace(origin, scanned_artifact=artifact.path))
            unique.append(artifact)
            boundaries[artifact.path] = (
                target.path
                if origin.provenance == "explicit_target" and target is not None
                else origin.environment or artifact.path.parent
            )
        for origin in resolved_origins:
            if origin.provenance == "installed_agent" and origin.scanned_artifact is not None:
                reference_boundaries[origin.scanned_artifact] = (home or Path.home()).absolute()
        report = self.scan(
            target or Target((home or Path.home()).absolute()),
            artifacts=tuple(unique),
            boundaries=boundaries,
            reference_boundaries=reference_boundaries,
        )
        return replace(
            report,
            installed_environments=discovered.environments,
            artifact_origins=tuple(resolved_origins),
        )

    def scan_acquired(self, acquired: AcquiredTarget) -> ScanReport:
        """Run the existing static pipeline and replace ephemeral paths in public results."""
        if self.dynamic_policy.requested:
            raise DiscoveryError("dynamic MCP is unavailable for acquired targets")
        source = Path(acquired.source)
        if acquired.path is None:
            return ScanReport(
                source,
                (),
                (),
                (),
                acquisition_status=acquired.status,
                acquisition_kind=acquired.kind,
                acquisition_source=acquired.source,
                acquisition_diagnostics=acquired.diagnostics,
            )
        report = self.scan(Target(acquired.path))
        physical = acquired.root or acquired.path
        logical = Path(acquired.source + "!") if acquired.root else source
        # Graph identifiers are derived from physical artifact paths. Re-key them
        # before releasing the workspace so flow evidence is stable across scans.
        identifiers = (
            {
                node.id: node_id(
                    node.kind,
                    f"{index}:{node.label.replace(str(physical), str(logical))}",
                )
                for index, node in enumerate(self.graph.nodes)
            }
            if self.graph is not None
            else {}
        )

        def rebase(value: object) -> object:
            if isinstance(value, Enum):
                return value
            if isinstance(value, Path):
                if value == physical:
                    return logical
                if value.is_relative_to(physical):
                    return logical / value.relative_to(physical)
                return value
            if isinstance(value, str):
                return identifiers.get(value, value.replace(str(physical), str(logical)))
            if isinstance(value, tuple):
                return tuple(rebase(item) for item in value)
            if isinstance(value, list):
                return [rebase(item) for item in value]
            if isinstance(value, dict):
                return {key: rebase(item) for key, item in value.items()}
            if is_dataclass(value) and not isinstance(value, type):
                return replace(
                    value,
                    **{field.name: rebase(getattr(value, field.name)) for field in fields(value)},
                )
            return value

        rebased = rebase(report)
        assert isinstance(rebased, ScanReport)
        self.graph = rebase(self.graph)  # type: ignore[assignment]
        return replace(
            rebased,
            target=source,
            acquisition_status=acquired.status,
            acquisition_kind=acquired.kind,
            acquisition_source=acquired.source,
            acquisition_diagnostics=acquired.diagnostics,
        )


def scan(path: Target) -> ScanReport:
    return Scanner().scan(path)
