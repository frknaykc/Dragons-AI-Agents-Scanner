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


def annotate(
    graph: AttackGraph, documents: tuple[Document, ...], findings: tuple[Finding, ...]
) -> AttackGraph:
    nodes = {node.id: node for node in graph.nodes}
    edges = list(graph.edges)
    formats = {document.artifact.path: document.artifact.source_format for document in documents}
    for finding in findings:
        info = finding.signature
        if info is None or info.context not in {
            "mcp_endpoint",
            "remote_endpoint",
            "executable_command",
        }:
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
    """Add only a reference when a proven path ends at an indicated endpoint."""
    nodes = {node.id: node for node in graph.nodes}
    outgoing: dict[tuple[str, Path, int | None], set[str]] = {}
    for edge in graph.edges:
        if (
            edge.kind == "indicates"
            and edge.origin == "signature_engine"
            and nodes[edge.source].kind == "external_resource"
        ):
            key = (nodes[edge.source].label, edge.location.path, edge.location.line)
            outgoing.setdefault(key, set()).add(nodes[edge.target].label)
    result: list[Finding] = []
    for finding in correlated:
        if finding.path:
            last = finding.path[-1]
            matches = outgoing.get((last.target, last.artifact, last.line))
        else:
            matches = None
        if matches:
            references = tuple(dict.fromkeys((*finding.references, *sorted(matches))))
            finding = replace(finding, references=references)
        result.append(finding)
    return tuple(result)
