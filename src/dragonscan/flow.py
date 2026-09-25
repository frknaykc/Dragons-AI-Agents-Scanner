"""Bounded static toxic-flow traversal over the existing evidence graph.

Only explicitly eligible edges propagate. Graph annotations and artifact
coexistence cannot grant data, control, or execution authority.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

from dragonscan.attack_graph import AttackGraph, GraphEdge, GraphLimitError, GraphNode, node_id
from dragonscan.mcp_security import tool_signals
from dragonscan.models import (
    Classification,
    Confidence,
    Document,
    Finding,
    FlowEvidence,
    PathStep,
    Severity,
    SourceRef,
)

MAX_FLOW_DEPTH = 8
MAX_FLOW_PATHS = 256
MAX_FLOW_PER_SOURCE = 32
MAX_FLOW_BRANCH = 32
MAX_FLOW_NODES = 50_000
MAX_FLOW_EDGES = 100_000
MAX_FLOW_STATES = 16_384
_CONFIDENCE = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
_PRIVILEGED = frozenset(
    {"persistent-configuration-write", "repository-write", "process-execution", "credential-access"}
)


class FlowKind(StrEnum):
    SENSITIVE_DATA = "sensitive_data"
    UNTRUSTED_CONTENT = "untrusted_content"
    INSTRUCTION_CONTROL = "instruction_control"
    EXECUTION = "execution_influence"


class EdgeRole(StrEnum):
    DATA = "data-propagating"
    CONTROL = "control-propagating"
    EXECUTION = "execution-propagating"
    CAPABILITY = "capability-only"
    PROVENANCE = "provenance-only"
    METADATA = "metadata-only"
    NON_PROPAGATING = "non-propagating"


# Edge names have fixed roles, but a role does not authorize traversal.
_EDGE_ROLES = {
    "loads": EdgeRole.CONTROL,
    "passes_to": EdgeRole.DATA,
    "sends_to": EdgeRole.DATA,
    "influences": EdgeRole.CONTROL,
    "executes": EdgeRole.EXECUTION,
    "fetches": EdgeRole.EXECUTION,
    "installs": EdgeRole.EXECUTION,
    "reads": EdgeRole.CAPABILITY,
    "writes": EdgeRole.CAPABILITY,
    "modifies": EdgeRole.CAPABILITY,
    "invokes": EdgeRole.CAPABILITY,
    "defines": EdgeRole.CAPABILITY,
    "exposes": EdgeRole.CAPABILITY,
    "authenticates_with": EdgeRole.CAPABILITY,
    "references": EdgeRole.METADATA,
    "depends_on": EdgeRole.METADATA,
    "sourced_from": EdgeRole.METADATA,
    "affected_by": EdgeRole.PROVENANCE,
    "indicates": EdgeRole.PROVENANCE,
    "reveals_static_view": EdgeRole.PROVENANCE,
    "observed_version": EdgeRole.PROVENANCE,
}


def edge_role(kind: str) -> EdgeRole:
    return _EDGE_ROLES.get(kind, EdgeRole.NON_PROPAGATING)


@dataclass(frozen=True)
class FlowState:
    kind: FlowKind
    source: str  # graph identifier, never scanned content
    current: str
    edges: tuple[GraphEdge, ...]
    confidence: Confidence
    boundaries: tuple[str, ...]
    capabilities: tuple[str, ...]
    transformations: tuple[str, ...]
    source_evidence: SourceRef | None


@dataclass(frozen=True)
class FlowPath:
    kind: FlowKind
    edges: tuple[GraphEdge, ...]
    confidence: Confidence
    state: FlowState | None = None


def _quality(path: FlowPath) -> tuple[int, int, int]:
    return (
        _CONFIDENCE[path.confidence],
        -sum(edge.confidence == Confidence.LOW for edge in path.edges),
        -len(path.edges),
    )


class FlowEngine:
    """Index and traverse only graph edges whose provenance authorizes a flow.

    This is static evidence of instructions/configuration, not an observation
    that a command, tool, or package actually ran.
    """

    def __init__(
        self,
        graph: AttackGraph,
        *,
        max_nodes: int = MAX_FLOW_NODES,
        max_edges: int = MAX_FLOW_EDGES,
    ) -> None:
        self.nodes: dict[str, GraphNode] = {node.id: node for node in graph.nodes}
        self.adjacency: dict[str, list[GraphEdge]] = defaultdict(list)
        self.incoming_loads: dict[str, list[GraphEdge]] = defaultdict(list)
        self.diagnostics: list[str] = []
        self.states = 0
        self.blocked = len(graph.nodes) > max_nodes or len(graph.edges) > max_edges
        if len(graph.nodes) > max_nodes:
            self.diagnostics.append("graph node limit reached")
        if len(graph.edges) > max_edges:
            self.diagnostics.append("graph edge limit reached")
        if not self.blocked:
            for edge in dict.fromkeys(graph.edges):
                if edge.source not in self.nodes or edge.target not in self.nodes:
                    self.diagnostics.append("graph edge with missing endpoint blocked")
                    continue
                if edge.kind == "loads" and edge.resolution in {
                    "ambiguous",
                    "missing",
                    "outside",
                    "unsafe",
                }:
                    reason = "ambiguous" if edge.resolution == "ambiguous" else "unresolved"
                    if f"{reason} relationship blocked" not in self.diagnostics:
                        self.diagnostics.append(f"{reason} relationship blocked")
                self.adjacency[edge.source].append(edge)
                if edge.kind == "loads" and edge.resolution == "resolved":
                    self.incoming_loads[edge.target].append(edge)
            for edges in self.adjacency.values():
                edges.sort(
                    key=lambda item: (
                        item.kind,
                        item.target,
                        -_CONFIDENCE[item.confidence],
                        str(item.location.path),
                        item.location.line or 0,
                        item.origin,
                    )
                )

    def _eligible(self, edge: GraphEdge, kind: FlowKind) -> bool:
        source, target = self.nodes[edge.source], self.nodes[edge.target]
        if kind == FlowKind.UNTRUSTED_CONTENT:
            return (
                edge.kind == "loads"
                and edge.resolution == "resolved"
                and edge.origin == edge.location.source_format.value
                and source.kind == target.kind == "artifact"
            ) or (
                edge.kind == "loads"
                and edge.resolution == "observed"
                and edge.origin == "behavior"
                and source.kind == "external_resource"
                and target.kind == "instruction"
            )
        if kind == FlowKind.INSTRUCTION_CONTROL:
            return (
                edge.kind == "influences"
                and edge.resolution == "observed"
                and edge.origin == "mcp_metadata"
                and source.kind == target.kind == "mcp_tool"
            )
        if kind == FlowKind.SENSITIVE_DATA:
            return (
                edge.kind in {"passes_to", "sends_to"}
                and edge.resolution == "observed"
                and edge.origin in {"mcp_metadata", "instruction_reference"}
                and (
                    (edge.kind == "passes_to" and source.kind == target.kind == "mcp_tool")
                    or (
                        edge.kind == "sends_to"
                        and edge.origin == "mcp_metadata"
                        and source.kind == target.kind == "mcp_capability"
                    )
                )
            )
        return (
            edge.kind == "executes"
            and edge.resolution == "observed"
            and edge.origin == "dependency_parser"
            and source.kind == "package"
            and target.kind == "command"
        ) or (
            edge.kind == "fetches"
            and edge.resolution == "observed"
            and edge.origin in {"behavior", "mcp_parser"}
            and source.kind == "external_resource"
            and target.kind == "command"
        )

    def paths(
        self,
        kind: FlowKind,
        start: str,
        end: str,
        *,
        max_depth: int = MAX_FLOW_DEPTH,
        max_paths: int = MAX_FLOW_PER_SOURCE,
        max_branch: int = MAX_FLOW_BRANCH,
    ) -> tuple[FlowPath, ...]:
        if self.blocked or start not in self.nodes or end not in self.nodes:
            return ()
        pending: deque[tuple[FlowState, frozenset[str]]] = deque(
            [
                (
                    FlowState(kind, start, start, (), Confidence.HIGH, (), (), (), None),
                    frozenset({start}),
                )
            ]
        )
        result: dict[tuple[tuple[str, str, str], ...], FlowPath] = {}
        while pending:
            if self.states >= MAX_FLOW_STATES:
                self.diagnostics.append("flow traversal state limit reached")
                break
            self.states += 1
            state, visited = pending.popleft()
            if state.current == end and state.edges:
                key = tuple((edge.source, edge.target, edge.kind) for edge in state.edges)
                candidate = FlowPath(kind, state.edges, state.confidence, state)
                previous = result.get(key)
                if previous is None or _quality(candidate) > _quality(previous):
                    result[key] = candidate
                if previous is None and len(result) >= max_paths:
                    self.diagnostics.append("path count limit reached")
                    break
                continue
            candidates = [
                edge
                for edge in self.adjacency[state.current]
                if edge.target not in visited and self._eligible(edge, kind)
            ]
            if len(state.edges) >= max_depth:
                if candidates:
                    self.diagnostics.append("depth limit reached")
                continue
            if len(candidates) > max_branch:
                self.diagnostics.append("branching limit reached")
            for edge in candidates[:max_branch]:
                boundary = (
                    "local-instruction-load"
                    if edge.kind == "loads" and edge.resolution == "resolved"
                    else "remote-content-to-instruction"
                    if edge.kind == "loads"
                    else "mcp-tool-transfer"
                    if edge.kind == "passes_to"
                    else "mcp-tool-control"
                    if edge.kind == "influences"
                    else "package-to-process"
                    if edge.kind == "executes"
                    else None
                )
                next_state = FlowState(
                    kind,
                    state.source,
                    edge.target,
                    (*state.edges, edge),
                    min(state.confidence, edge.confidence, key=_CONFIDENCE.__getitem__),
                    (*state.boundaries, boundary) if boundary else state.boundaries,
                    state.capabilities,
                    state.transformations,
                    state.source_evidence or edge.location,
                )
                pending.append((next_state, visited | {edge.target}))
        return tuple(result.values())

    def control_paths(
        self, start: str, end: str, *, max_depth: int = MAX_FLOW_DEPTH
    ) -> tuple[FlowPath, ...]:
        return self.paths(FlowKind.INSTRUCTION_CONTROL, start, end, max_depth=max_depth)

    def local_routes(self, endpoints: set[str]) -> dict[str, list[tuple[GraphEdge, ...]]]:
        """Legacy PATH reachability: reverse-walk only resolved local loads.

        Retain the old depth/path failure semantics and ordering for stable
        DRAGON-PATH IDs and JSON paths, while sharing the edge validation index.
        """
        routes: dict[str, list[tuple[GraphEdge, ...]]] = defaultdict(list)
        count = 0
        for endpoint in (node for node in self.nodes if node in endpoints):
            pending: deque[tuple[str, tuple[GraphEdge, ...], frozenset[str]]] = deque(
                [(endpoint, (), frozenset({endpoint}))]
            )
            while pending:
                current, path, visited = pending.popleft()
                if len(path) >= MAX_FLOW_DEPTH:
                    if any(edge.source not in visited for edge in self.incoming_loads[current]):
                        raise GraphLimitError("attack path depth limit exceeded")
                    continue
                for edge in self.incoming_loads[current]:
                    if edge.source in visited:
                        continue
                    next_path = (edge, *path)
                    if count >= MAX_FLOW_PATHS:
                        raise GraphLimitError("attack path count limit exceeded")
                    routes[endpoint].append(next_path)
                    count += 1
                    pending.append((edge.source, next_path, visited | {edge.source}))
        return routes


def _steps(edges: tuple[GraphEdge, ...], nodes: dict[str, GraphNode]) -> tuple[PathStep, ...]:
    return tuple(
        PathStep(
            edge.kind,
            nodes[edge.source].label,
            nodes[edge.target].label,
            edge.location.path,
            edge.location.line,
            edge.origin,
            edge.confidence,
        )
        for edge in edges
    )


def describe_existing_flow(finding: Finding, documents: tuple[Document, ...]) -> Finding:
    """Add structured context to proven legacy routes without changing their IDs."""
    if not finding.path or finding.flow is not None:
        return finding
    formats = {doc.artifact.path: doc.artifact.source_format for doc in documents}
    kinds = {
        "DRAGON-PATH-001": ("sensitive_local_resource", "external_endpoint"),
        "DRAGON-PATH-002": ("remote_executable_content", "shell_execution"),
        "DRAGON-PATH-003": ("remote_instruction", "persistent_instruction_file"),
        "DRAGON-PATH-004": ("remote_instruction", "agent_configuration"),
        "DRAGON-MCP-012": ("sensitive_local_resource", "network_egress_capability"),
        "DRAGON-SC-003": ("mutable_runtime_package", "process_execution"),
        "DRAGON-SC-006": ("remote_package", "process_execution"),
    }
    if finding.detection_id not in kinds:
        return finding
    nodes = tuple(
        dict.fromkeys(label for step in finding.path for label in (step.source, step.target))
    )
    transitions = {
        "sends_to": "sensitive-local-to-external",
        "fetches": "remote-content-to-execution",
        "modifies": "external-instruction-to-persistence",
        "executes": "package-to-process",
    }
    boundaries = tuple(
        dict.fromkeys(
            "remote-content-to-instruction"
            if step.edge == "loads" and step.origin == "behavior"
            else "local-instruction-load"
            if step.edge == "loads"
            else transitions[step.edge]
            for step in finding.path
            if step.edge == "loads" or step.edge in transitions
        )
    )
    return replace(
        finding,
        flow=FlowEvidence(
            *kinds[finding.detection_id],
            nodes,
            tuple(step.edge for step in finding.path),
            tuple(dict.fromkeys(step.artifact for step in finding.path)),
            boundaries,
            finding.capabilities,
            finding.evasion.chain if finding.evasion else (),
            finding.references,
            finding.confidence,
            tuple(
                SourceRef(step.artifact, formats[step.artifact], step.line)
                for step in finding.path
                if step.artifact in formats
            ),
            finding.source,
            finding.sink,
        ),
    )


def correlate_flows(
    graph: AttackGraph, documents: tuple[Document, ...]
) -> tuple[tuple[Finding, ...], tuple[str, ...]]:
    """Emit only new categories supported by resolved and observed graph evidence."""
    engine = FlowEngine(graph)
    # Routine unresolved references already retain graph provenance; they are
    # not scan errors. Keep explicit diagnostics available to engine callers.
    engine.diagnostics = [
        note
        for note in engine.diagnostics
        if note not in {"ambiguous relationship blocked", "unresolved relationship blocked"}
    ]
    if engine.blocked:
        return (), tuple(engine.diagnostics)
    findings: list[Finding] = []
    observed = {
        (edge.source, edge.target, edge.kind): edge
        for edges in engine.adjacency.values()
        for edge in edges
        if edge.resolution == "observed"
    }
    seen: set[tuple[str, Path, int | None, str, str, str, str]] = set()

    def emit(
        identifier: str,
        artifact: Path,
        line: int | None,
        source: str,
        sink: str,
        edges: tuple[GraphEdge, ...],
        taint: FlowKind,
        title: str,
        explanation: str,
        severity: Severity,
        confidence: Confidence,
    ) -> None:
        key = (identifier, artifact, line, source, sink, edges[1].target, edges[-1].source)
        if key in seen:
            return
        if len(findings) >= MAX_FLOW_PATHS:
            engine.diagnostics.append("total flow finding limit reached")
            return
        seen.add(key)
        boundaries = (
            (
                ("local-instruction-to-mcp-tool",)
                if any(edge.kind == "invokes" for edge in edges)
                else ()
            )
            + ("local-sensitive-to-mcp-tool", "mcp-tool-to-network-capability")
            if taint == FlowKind.SENSITIVE_DATA
            else ("mcp-metadata-to-tool-control", "tool-control-to-privileged-capability")
        )
        capabilities = tuple(dict.fromkeys(edge.kind for edge in edges))
        findings.append(
            Finding(
                identifier,
                "static-toxic-flow",
                title,
                severity,
                confidence,
                Classification.SUSPICIOUS,
                artifact,
                explanation,
                "linked static graph edges; no action was executed",
                "Remove the unsafe instruction and review each linked artifact.",
                "flow_engine",
                line=line,
                source=source,
                sink=sink,
                path=_steps(edges, engine.nodes),
                taint=(taint.value,),
                capabilities=capabilities,
                flow=FlowEvidence(
                    (
                        "mcp_sensitive_result"
                        if taint == FlowKind.SENSITIVE_DATA
                        else "mcp_instruction"
                    ),
                    "network_egress_capability"
                    if taint == FlowKind.SENSITIVE_DATA
                    else "privileged_mcp_capability",
                    tuple(engine.nodes[edge.source].label for edge in edges)
                    + (engine.nodes[edges[-1].target].label,),
                    tuple(edge.kind for edge in edges),
                    tuple(dict.fromkeys(edge.location.path for edge in edges)),
                    boundaries,
                    capabilities,
                    (),
                    (),
                    confidence,
                    tuple(edge.location for edge in edges),
                    source,
                    sink,
                ),
            )
        )

    for doc in documents:
        artifact = doc.artifact.path
        for server in doc.servers:
            server_id = node_id("mcp_server", f"{artifact}:{server.name}")
            artifact_id = node_id("artifact", str(artifact))
            definition = observed.get((artifact_id, server_id, "defines"))
            if definition is None:
                continue
            privileged_targets = {
                tool.name for tool in server.tools if tool_signals(tool) & _PRIVILEGED
            }
            egress_targets = {
                tool.name for tool in server.tools if "network-egress" in tool_signals(tool)
            }
            for source_tool in server.tools:
                source_id = node_id("mcp_tool", f"{artifact}:{server.name}:tool:{source_tool.name}")
                expose = observed.get((server_id, source_id, "exposes"))
                if expose is None:
                    continue
                kinds = {edge.kind for edge in engine.adjacency[source_id]}
                if not kinds & {"influences", "passes_to"}:
                    continue
                sensitive_source = "credential-access" in tool_signals(source_tool)
                for target_tool in server.tools:
                    if engine.states >= MAX_FLOW_STATES:
                        break
                    if target_tool is source_tool:
                        continue
                    control = "influences" in kinds and target_tool.name in privileged_targets
                    data = (
                        "passes_to" in kinds
                        and sensitive_source
                        and target_tool.name in egress_targets
                    )
                    if not control and not data:
                        continue
                    target_id = node_id(
                        "mcp_tool", f"{artifact}:{server.name}:tool:{target_tool.name}"
                    )
                    paths = engine.control_paths(source_id, target_id) if control else ()
                    for route in paths:
                        # An influence edge alone does not imply a privileged action.
                        for capability in sorted(_PRIVILEGED):
                            cap_id = node_id(
                                "mcp_capability",
                                f"{artifact}:{server.name}:{target_tool.name}:{capability}",
                            )
                            sink_edge = observed.get((target_id, cap_id, "defines"))
                            if sink_edge is None:
                                continue
                            chain = (definition, expose, *route.edges, sink_edge)
                            emit(
                                "DRAGON-FLOW-001",
                                artifact,
                                source_tool.location.line,
                                "MCP tool instruction",
                                capability,
                                chain,
                                FlowKind.INSTRUCTION_CONTROL,
                                "MCP tool instruction influences a privileged tool",
                                "One tool directs another with a declared privileged "
                                "capability; no tool was invoked or data transfer observed.",
                                Severity.MEDIUM,
                                min(
                                    (edge.confidence for edge in chain), key=_CONFIDENCE.__getitem__
                                ),
                            )
                    if not data:
                        continue
                    for route in engine.paths(FlowKind.SENSITIVE_DATA, source_id, target_id):
                        if any(edge.origin != "mcp_metadata" for edge in route.edges):
                            continue
                        source_cap = node_id(
                            "mcp_capability",
                            f"{artifact}:{server.name}:{source_tool.name}:credential-access",
                        )
                        sink_cap = node_id(
                            "mcp_capability",
                            f"{artifact}:{server.name}:{target_tool.name}:network-egress",
                        )
                        read = observed.get((source_id, source_cap, "defines"))
                        send = observed.get((target_id, sink_cap, "defines"))
                        if read is None or send is None:
                            continue
                        chain = (definition, expose, read, *route.edges, send)
                        emit(
                            "DRAGON-FLOW-002",
                            artifact,
                            source_tool.location.line,
                            "sensitive MCP tool result",
                            "MCP network egress capability",
                            chain,
                            FlowKind.SENSITIVE_DATA,
                            "Explicit MCP result transfer to network-capable tool",
                            "MCP metadata directs a sensitive result to a network-capable tool; "
                            "no tool was called and no network transfer was observed.",
                            Severity.HIGH,
                            min((edge.confidence for edge in chain), key=_CONFIDENCE.__getitem__),
                        )
    # A parsed instruction must explicitly invoke a uniquely resolved tool.
    # Tool capability and an unrelated instruction in another document cannot
    # be spliced together to manufacture a result transfer.
    tool_records = {
        node_id("mcp_tool", f"{doc.artifact.path}:{server.name}:tool:{tool.name}"): tool
        for doc in documents
        for server in doc.servers
        for tool in server.tools
    }
    network_targets = {
        identifier
        for identifier, tool in tool_records.items()
        if "network-egress" in tool_signals(tool)
    }
    reference_states = 0
    for edges in engine.adjacency.values():
        for invocation in edges:
            if (
                invocation.kind != "invokes"
                or invocation.origin != "instruction_reference"
                or invocation.resolution != "resolved"
            ):
                continue
            invoked_tool = tool_records.get(invocation.target)
            if invoked_tool is None or "credential-access" not in tool_signals(invoked_tool):
                continue
            artifact_id = node_id("artifact", str(invocation.location.path))
            defined = observed.get((artifact_id, invocation.source, "defines"))
            read_id = next(
                (
                    edge.target
                    for edge in engine.adjacency[invocation.target]
                    if edge.kind == "defines"
                    and engine.nodes[edge.target].kind == "mcp_capability"
                    and engine.nodes[edge.target].label == "credential-access"
                ),
                None,
            )
            read = observed.get((invocation.target, read_id, "defines")) if read_id else None
            if defined is None or read is None:
                continue
            # Select only reachable transfer sinks before asking the bounded
            # engine for paths; do not compare every invocation to every tool.
            pending: deque[tuple[str, int]] = deque([(invocation.target, 0)])
            reached = {invocation.target}
            candidates: set[str] = set()
            while pending:
                if reference_states >= MAX_FLOW_STATES:
                    engine.diagnostics.append("flow traversal state limit reached")
                    return tuple(findings), tuple(dict.fromkeys(engine.diagnostics))
                reference_states += 1
                current, depth = pending.popleft()
                if depth >= MAX_FLOW_DEPTH:
                    continue
                transfers = [
                    edge
                    for edge in engine.adjacency[current]
                    if edge.kind == "passes_to"
                    and edge.resolution == "observed"
                    and edge.origin in {"mcp_metadata", "instruction_reference"}
                    and (
                        edge.origin != "instruction_reference"
                        or edge.location == invocation.location
                    )
                ]
                if len(transfers) > MAX_FLOW_BRANCH:
                    engine.diagnostics.append("branching limit reached")
                for transfer in transfers[:MAX_FLOW_BRANCH]:
                    if transfer.target in reached:
                        continue
                    reached.add(transfer.target)
                    pending.append((transfer.target, depth + 1))
                    if transfer.target in network_targets:
                        candidates.add(transfer.target)
            for target_id in sorted(candidates):
                for route in engine.paths(FlowKind.SENSITIVE_DATA, invocation.target, target_id):
                    if any(
                        edge.origin == "instruction_reference"
                        and edge.location != invocation.location
                        for edge in route.edges
                    ):
                        continue
                    send_id = next(
                        (
                            edge.target
                            for edge in engine.adjacency[target_id]
                            if edge.kind == "defines"
                            and engine.nodes[edge.target].kind == "mcp_capability"
                            and engine.nodes[edge.target].label == "network-egress"
                        ),
                        None,
                    )
                    send = observed.get((target_id, send_id, "defines")) if send_id else None
                    if send is None:
                        continue
                    chain = (defined, invocation, read, *route.edges, send)
                    emit(
                        "DRAGON-FLOW-002",
                        invocation.location.path,
                        invocation.location.line,
                        "sensitive MCP tool result",
                        "MCP network egress capability",
                        chain,
                        FlowKind.SENSITIVE_DATA,
                        "Explicit instruction transfers MCP result to network-capable tool",
                        "An instruction links a sensitive tool result to a network-capable tool; "
                        "no tool call or network transfer was observed.",
                        Severity.HIGH,
                        min((edge.confidence for edge in chain), key=_CONFIDENCE.__getitem__),
                    )
    return tuple(findings), tuple(dict.fromkeys(engine.diagnostics))
