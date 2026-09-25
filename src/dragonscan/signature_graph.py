"""Evidence-backed signature graph annotation; annotations never propagate taint."""

from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from dragonscan.attack_graph import (
    MAX_EDGES,
    MAX_NODES,
    AttackGraph,
    GraphEdge,
    GraphLimitError,
    GraphNode,
    node_id,
)
from dragonscan.models import Confidence, Document, Finding, SourceRef
from dragonscan.signature_ioc import candidates
from dragonscan.signature_models import IndicatorType, Signature


def annotate(
    graph: AttackGraph,
    documents: tuple[Document, ...],
    findings: tuple[Finding, ...],
    signatures: tuple[Signature, ...] = (),
) -> AttackGraph:
    nodes = {node.id: node for node in graph.nodes}
    edges = list(graph.edges)
    formats = {document.artifact.path: document.artifact.source_format for document in documents}
    url_patterns = {
        signature.detection_id: signature.pattern
        for signature in signatures
        if signature.indicator_type == IndicatorType.URL
    }
    urls: dict[tuple[Path, int | None, str], set[str]] = {}
    if url_patterns:
        for document in documents:
            for reference in document.relationships:
                if reference.kind == "references_url":
                    key = (
                        reference.location.path,
                        reference.location.line,
                        node_id("external_resource", reference.target),
                    )
                    urls.setdefault(key, set()).update(
                        candidates(IndicatorType.URL, reference.target)
                    )
    for finding in findings:
        info = finding.signature
        if info is None or info.context not in {
            "mcp_endpoint",
            "remote_endpoint",
            "executable_command",
        }:
            continue
        if info.indicator_type == "url" and info.signature_id not in url_patterns:
            # Public labels omit URL paths; never infer an exact hit from its host.
            continue
        origins: set[str] = set()
        if (
            info.indicator_type in {"url", "domain", "hostname", "ipv4", "ipv6"}
            and info.context != "executable_command"
        ):
            hostname = (
                urlsplit(info.matched_indicator).hostname
                if info.indicator_type == "url"
                else info.matched_indicator
            )
            if hostname is None:
                continue
            for edge in graph.edges:
                remote = nodes[edge.target]
                if (
                    edge.resolution == "external"
                    and edge.location.path == finding.artifact
                    and edge.location.line == finding.line
                    and remote.kind == "external_resource"
                    and remote.label == f"external HTTP(S) endpoint ({hostname[:80]})"
                    and (
                        info.indicator_type != "url"
                        or url_patterns[info.signature_id]
                        in urls.get((edge.location.path, edge.location.line, edge.target), set())
                    )
                ):
                    origins.add(remote.id)
        elif info.context == "executable_command":
            for edge in graph.edges:
                if (
                    edge.kind in {"invokes", "executes"}
                    and edge.location.path == finding.artifact
                    and edge.location.line == finding.line
                    and nodes[edge.target].kind == "command"
                ):
                    origins.add(edge.target)
        if not origins:
            # An active IOC without a corresponding graph edge is not a proven path.
            continue
        for origin in origins:
            if origin not in nodes:
                continue
            identifier = node_id(
                "signature_hit",
                f"{finding.artifact}:{finding.line}:{info.signature_id}:{info.context}",
            )
            if identifier not in nodes:
                if len(nodes) >= MAX_NODES:
                    raise GraphLimitError("graph node limit exceeded")
                nodes[identifier] = GraphNode(identifier, "signature_hit", info.signature_id)
            location = SourceRef(finding.artifact, formats[finding.artifact], finding.line)
            relation = GraphEdge(
                origin,
                identifier,
                "indicates",
                location,
                "signature_engine:url" if info.indicator_type == "url" else "signature_engine",
                Confidence.HIGH,
            )
            if relation not in edges:
                if len(edges) >= MAX_EDGES:
                    raise GraphLimitError("graph edge limit exceeded")
                edges.append(relation)
    return AttackGraph(tuple(nodes.values()), tuple(edges))


def enrich_correlations(graph: AttackGraph, correlated: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Enrich only unambiguous external nodes participating in a proven path."""
    nodes = {node.id: node for node in graph.nodes}
    routes: dict[tuple[str, str, str, Path, int | None, str, Confidence], set[tuple[str, str]]] = {}
    indicated: dict[str, set[str]] = {}
    for edge in graph.edges:
        if (
            edge.kind == "indicates"
            and edge.origin in {"signature_engine", "signature_engine:url"}
            and nodes[edge.source].kind == "external_resource"
        ):
            indicated.setdefault(edge.source, set()).add(nodes[edge.target].label)
        elif edge.kind != "indicates":
            key = (
                edge.kind,
                nodes[edge.source].label,
                nodes[edge.target].label,
                edge.location.path,
                edge.location.line,
                edge.origin,
                edge.confidence,
            )
            routes.setdefault(key, set()).add((edge.source, edge.target))
    result: list[Finding] = []
    for finding in correlated:
        matches: set[str] = set()
        for step in finding.path:
            key = (
                step.edge,
                step.source,
                step.target,
                step.artifact,
                step.line,
                step.origin,
                step.confidence,
            )
            resolved = routes.get(key, set())
            # Public labels omit URL paths; ambiguous equal-label routes cannot
            # establish which exact URL was traversed.
            if len(resolved) == 1:
                source, target = next(iter(resolved))
                matches.update(indicated.get(source, set()))
                matches.update(indicated.get(target, set()))
        if matches:
            references = tuple(dict.fromkeys((*finding.references, *sorted(matches))))
            flow = (
                replace(finding.flow, enrichments=references) if finding.flow is not None else None
            )
            finding = replace(finding, references=references, flow=flow)
        result.append(finding)
    return tuple(result)
