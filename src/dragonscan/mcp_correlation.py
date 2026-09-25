"""Correlate only explicit, ordered MCP metadata flows through the bounded graph."""

from dragonscan.attack_graph import AttackGraph, GraphEdge, GraphLimitError, node_id
from dragonscan.flow import FlowEngine, FlowKind
from dragonscan.mcp_security import linked_sensitive_transfer
from dragonscan.models import Classification, Confidence, Document, Finding, PathStep, Severity

MAX_CORRELATED_MCP = 256


def correlate_mcp(
    graph: AttackGraph, documents: tuple[Document, ...], prior: tuple[Finding, ...]
) -> tuple[Finding, ...]:
    nodes = {node.id: node for node in graph.nodes}
    links: dict[tuple[str, str, str], GraphEdge] = {
        (edge.source, edge.target, edge.kind): edge
        for edge in graph.edges
        if edge.resolution == "observed"
    }
    engine = FlowEngine(graph)
    eligible = {finding.artifact for finding in prior if finding.detection_id == "DRAGON-MCP-010"}
    results: list[Finding] = []
    for doc in documents:
        if doc.artifact.path not in eligible:
            continue
        path = doc.artifact.path
        artifact = node_id("artifact", str(path))
        for server in doc.servers:
            server_node = node_id("mcp_server", f"{path}:{server.name}")
            for tool in server.tools:
                if not linked_sensitive_transfer(tool):
                    continue
                tool_node = node_id("mcp_tool", f"{path}:{server.name}:tool:{tool.name}")
                credential = node_id(
                    "mcp_capability", f"{path}:{server.name}:{tool.name}:credential-access"
                )
                egress = node_id(
                    "mcp_capability", f"{path}:{server.name}:{tool.name}:network-egress"
                )
                keys = (
                    (artifact, server_node, "defines"),
                    (server_node, tool_node, "exposes"),
                    (tool_node, credential, "defines"),
                    (credential, egress, "sends_to"),
                )
                if any(key not in links for key in keys):
                    continue
                if not engine.paths(FlowKind.SENSITIVE_DATA, credential, egress, max_depth=1):
                    continue
                if len(results) >= MAX_CORRELATED_MCP:
                    raise GraphLimitError("MCP correlated path count limit exceeded")
                steps = tuple(
                    PathStep(
                        edge.kind,
                        nodes[edge.source].label,
                        nodes[edge.target].label,
                        edge.location.path,
                        edge.location.line,
                        edge.origin,
                        edge.confidence,
                    )
                    for edge in (links[key] for key in keys)
                )
                results.append(
                    Finding(
                        detection_id="DRAGON-MCP-012",
                        category="mcp-security",
                        title="Linked MCP credential read and external transfer instruction",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        classification=Classification.SUSPICIOUS,
                        artifact=path,
                        line=tool.location.line,
                        evidence="one MCP tool instruction links a sensitive read "
                        "to an external transfer",
                        explanation="The declared instruction provides an ordered static path; "
                        "no MCP tool was invoked and no data transfer was observed.",
                        source="sensitive local data",
                        sink="network egress capability",
                        capabilities=("credential-access", "network-egress"),
                        references=("DRAGON-MCP-010",),
                        remediation="Remove the transfer instruction and review "
                        "the tool definition.",
                        detector="mcp_correlation",
                        path=steps,
                        taint=("credential",),
                    )
                )
    return tuple(results)
