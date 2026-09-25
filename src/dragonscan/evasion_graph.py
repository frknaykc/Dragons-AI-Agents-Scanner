"""Non-propagating graph provenance for findings revealed by static views."""

from dragonscan.attack_graph import (
    MAX_EDGES,
    MAX_NODES,
    AttackGraph,
    GraphEdge,
    GraphLimitError,
    GraphNode,
    node_id,
)
from dragonscan.models import Document, Finding, SourceRef


def annotate_views(
    graph: AttackGraph, documents: tuple[Document, ...], findings: tuple[Finding, ...]
) -> AttackGraph:
    nodes = {node.id: node for node in graph.nodes}
    edges = dict.fromkeys(graph.edges)
    formats = {document.artifact.path: document.artifact.source_format for document in documents}
    for finding in findings:
        evidence = finding.evasion
        if evidence is None:
            continue
        parent = node_id("artifact", str(finding.artifact))
        if parent not in nodes:
            continue
        identifier = node_id(
            "evasion_view",
            f"{finding.artifact}:{evidence.source_start}:{evidence.source_kind}:"
            f"{'/'.join(evidence.chain)}",
        )
        if identifier not in nodes:
            if len(nodes) >= MAX_NODES:
                raise GraphLimitError("graph node limit exceeded")
            nodes[identifier] = GraphNode(identifier, "evasion_view", "static transformed view")
        location = SourceRef(
            finding.artifact, formats[finding.artifact], evidence.source_start, evidence.source_end
        )
        edge = GraphEdge(
            parent,
            identifier,
            "reveals_static_view",
            location,
            "evasion_analysis",
            evidence.confidence,
            "derived",
        )
        if edge not in edges and len(edges) >= MAX_EDGES:
            raise GraphLimitError("graph edge limit exceeded")
        edges[edge] = None
    return AttackGraph(tuple(nodes.values()), tuple(edges))
