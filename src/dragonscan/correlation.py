"""Bounded, deterministic correlation of evidence-supported agent-artifact paths."""

from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from dragonscan.attack_graph import AttackGraph, GraphEdge, GraphLimitError, GraphNode, node_id
from dragonscan.behavior import related_transfer
from dragonscan.detection import Observation
from dragonscan.flow import FlowEngine, FlowKind
from dragonscan.models import (
    Classification,
    Confidence,
    Document,
    Finding,
    PathStep,
    Severity,
)

MAX_DEPTH = 8
MAX_PATHS = 256
_CONFIDENCE = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


class TaintClass(StrEnum):
    CREDENTIAL = "credential"
    SECRET = "secret"
    PRIVATE_KEY = "private_key"
    SSH_MATERIAL = "ssh_material"
    CLOUD_CREDENTIAL = "cloud_credential"
    API_TOKEN = "api_token"
    WALLET_SECRET = "wallet_secret"
    ENVIRONMENT_SECRET = "environment_secret"
    SENSITIVE_FILE = "sensitive_local_file"
    EXTERNAL_WEB = "external_web_content"
    REMOTE_INSTRUCTION = "remote_instruction"
    EXTERNAL_INSTRUCTION = "externally_supplied_instruction"
    AGENT_POLICY = "agent_policy"
    PERSISTENT_INSTRUCTION = "persistent_instruction"


@dataclass(frozen=True)
class TaintFlow:
    """A source and sink connected by explicit transformations, not co-occurrence."""

    classes: tuple[TaintClass, ...]
    source: str
    sink: str
    transforms: tuple[GraphEdge, ...]
    confidence: Confidence


def _confidence(*levels: Confidence) -> Confidence:
    return min(levels, key=_CONFIDENCE.__getitem__)


def _source_taint(label: str) -> tuple[TaintClass, ...]:
    kinds = {
        "SSH private key": (TaintClass.CREDENTIAL, TaintClass.PRIVATE_KEY, TaintClass.SSH_MATERIAL),
        "cloud credentials": (TaintClass.CREDENTIAL, TaintClass.CLOUD_CREDENTIAL),
        "environment secrets": (TaintClass.SECRET, TaintClass.ENVIRONMENT_SECRET),
        "API token": (TaintClass.CREDENTIAL, TaintClass.API_TOKEN),
        "private key": (TaintClass.CREDENTIAL, TaintClass.PRIVATE_KEY),
        "wallet secret": (TaintClass.SECRET, TaintClass.WALLET_SECRET),
        "agent memory": (TaintClass.SENSITIVE_FILE,),
    }
    return kinds.get(label, (TaintClass.SENSITIVE_FILE,))


def _step(edge: GraphEdge, nodes: dict[str, GraphNode]) -> PathStep:
    return PathStep(
        edge.kind,
        nodes[edge.source].label,
        nodes[edge.target].label,
        edge.location.path,
        edge.location.line,
        edge.origin,
        edge.confidence,
    )


def correlate(
    graph: AttackGraph,
    documents: tuple[Document, ...],
    observations: dict[Path, tuple[Observation, ...]],
    prior: tuple[Finding, ...],
) -> tuple[Finding, ...]:
    nodes = {node.id: node for node in graph.nodes}
    by_path = {document.artifact.path: document for document in documents}
    by_source: dict[str, list[GraphEdge]] = defaultdict(list)
    for edge in graph.edges:
        by_source[edge.source].append(edge)
    endpoints = {
        node_id("artifact", str(document.artifact.path))
        for document in documents
        if any(
            item.kind == "remote_execution" for item in observations.get(document.artifact.path, ())
        )
        or any(
            item.kind == "sensitive_access"
            and related_transfer(item, observations.get(document.artifact.path, ())) is not None
            for item in observations.get(document.artifact.path, ())
        )
        or any(f.artifact == document.artifact.path and f.detection_id == "DAAS-002" for f in prior)
    }
    engine = FlowEngine(graph)
    routes = engine.local_routes(endpoints)
    found: list[Finding] = []
    seen: set[tuple[str, Path, Path, tuple[GraphEdge, ...]]] = set()

    def matching(
        source: str, kind: str, line: int | None = None, target_kind: str | None = None
    ) -> GraphEdge | None:
        return next(
            (
                edge
                for edge in by_source[source]
                if edge.kind == kind
                and (line is None or edge.location.line == line)
                and (target_kind is None or nodes[edge.target].kind == target_kind)
            ),
            None,
        )

    def emit(
        identifier: str,
        origin: Path,
        path: tuple[GraphEdge, ...],
        flow: TaintFlow,
        title: str,
        severity: Severity,
        explanation: str,
        related: Path,
    ) -> None:
        if not path:
            return
        key = (identifier, origin, related, path)
        if key in seen:
            return
        if len(found) >= MAX_PATHS:
            raise GraphLimitError("correlated finding limit exceeded")
        seen.add(key)
        steps = tuple(_step(edge, nodes) for edge in path)
        confidence = _confidence(flow.confidence, *(edge.confidence for edge in path))
        related_lines = {edge.location.line for edge in path if edge.location.path == related}
        references = tuple(
            sorted(
                {
                    finding.detection_id
                    for finding in prior
                    if finding.artifact == related
                    and finding.line in related_lines
                    and finding.detection_id
                    in {
                        "DAAS-001",
                        "DAAS-002",
                        "DRAGON-EXFIL-001",
                        "DRAGON-EXEC-001",
                        "DRAGON-PERSIST-001",
                        "DRAGON-TRUST-001",
                    }
                }
            )
        )
        found.append(
            Finding(
                detection_id=identifier,
                category="cross-artifact-path",
                title=title,
                severity=severity,
                confidence=confidence,
                classification=Classification.SUSPICIOUS,
                artifact=origin,
                line=path[0].location.line,
                evidence="explicit local relationship and linked security behaviors",
                explanation=explanation,
                remediation="Review the linked artifacts and remove the unsafe instruction chain.",
                detector="correlation",
                source=flow.source,
                sink=flow.sink,
                capabilities=tuple(dict.fromkeys(edge.kind for edge in path)),
                references=references,
                path=steps,
                taint=tuple(kind.value for kind in flow.classes),
            )
        )

    for document in documents:
        artifact = document.artifact.path
        obs = observations.get(artifact, ())
        artifact_id = node_id("artifact", str(artifact))
        if artifact_id not in nodes:
            continue

        def instruction_definition(
            item: Observation, *, artifact: Path = artifact, artifact_id: str = artifact_id
        ) -> GraphEdge | None:
            expected = node_id("instruction", f"{artifact}:{item.context}:{item.segment}")
            return next(
                (
                    edge
                    for edge in by_source[artifact_id]
                    if edge.kind == "defines" and edge.target == expected
                ),
                None,
            )

        for source in (item for item in obs if item.kind == "sensitive_access"):
            sink = related_transfer(source, obs)
            if sink is None:
                continue
            definition = instruction_definition(source)
            if definition is None:
                continue
            access = matching(
                definition.target, "reads", source.location.line, "sensitive_resource"
            )
            send_definition = instruction_definition(sink)
            if send_definition is None:
                continue
            sending = matching(
                send_definition.target, "sends_to", sink.location.line, "external_resource"
            )
            if access is None or sending is None:
                continue
            flow = TaintFlow(
                _source_taint(source.label),
                source.label,
                sink.label,
                (access, sending),
                Confidence.MEDIUM,
            )
            for route in routes.get(artifact_id, ()):
                start = nodes[route[0].source].artifact
                if start is not None:
                    chain = (*route, definition, access)
                    if send_definition != definition:
                        chain += (send_definition,)
                    emit(
                        "DRAGON-PATH-001",
                        start,
                        (*chain, sending),
                        flow,
                        "Linked credential-to-network instruction path",
                        Severity.HIGH,
                        "A loaded artifact instructs reading sensitive material and "
                        "sending that data externally; no transfer was executed or observed.",
                        artifact,
                    )

        for instruction in (item for item in obs if item.kind == "remote_execution"):
            definition = instruction_definition(instruction)
            if definition is None:
                continue
            execute = matching(definition.target, "executes", instruction.location.line, "command")
            if execute is None:
                continue
            fetch = next(
                (
                    edge
                    for edge in graph.edges
                    if edge.kind == "fetches" and edge.target == execute.target
                ),
                None,
            )
            if fetch is None or not engine.paths(
                FlowKind.EXECUTION, fetch.source, fetch.target, max_depth=1
            ):
                continue
            flow = TaintFlow(
                (TaintClass.EXTERNAL_WEB,),
                "remote content",
                "shell execution",
                (fetch, execute),
                Confidence.HIGH,
            )
            for route in routes.get(artifact_id, ()):
                start = nodes[route[0].source].artifact
                if start is not None:
                    emit(
                        "DRAGON-PATH-002",
                        start,
                        (*route, definition, *flow.transforms),
                        flow,
                        "Loaded remote execution instruction",
                        Severity.HIGH,
                        "A locally loaded artifact directs a remote download into a shell; "
                        "the scanner did not download or execute it.",
                        artifact,
                    )

        if any(item.artifact == artifact and item.detection_id == "DAAS-002" for item in prior):
            for server_definition in (
                edge
                for edge in by_source[artifact_id]
                if edge.kind == "defines" and nodes[edge.target].kind == "mcp_server"
            ):
                execution = matching(server_definition.target, "executes", target_kind="command")
                capability = matching(
                    server_definition.target, "defines", target_kind="mcp_capability"
                )
                if execution is None or capability is None:
                    continue
                fetch = next(
                    (
                        edge
                        for edge in graph.edges
                        if edge.kind == "fetches" and edge.target == execution.target
                    ),
                    None,
                )
                if fetch is None or not engine.paths(
                    FlowKind.EXECUTION, fetch.source, fetch.target, max_depth=1
                ):
                    continue
                flow = TaintFlow(
                    (TaintClass.EXTERNAL_WEB,),
                    "remote content",
                    "shell execution",
                    (fetch, execution),
                    Confidence.HIGH,
                )
                for route in routes.get(artifact_id, ()):
                    start = nodes[route[0].source].artifact
                    if start is not None:
                        emit(
                            "DRAGON-PATH-002",
                            start,
                            (*route, server_definition, fetch, execution, capability),
                            flow,
                            "Loaded MCP fetch-to-shell configuration",
                            Severity.HIGH,
                            "A loaded local configuration declares an MCP server that pipes a "
                            "remote download into a shell; it was not started.",
                            artifact,
                        )

        # Untrusted instructions can influence a local target only when the same
        # actionable segment explicitly accepts them AND modifies a resolved artifact.
        for trust in (item for item in obs if item.kind == "remote_trust"):
            definition = instruction_definition(trust)
            if definition is None:
                continue
            incoming = next(
                (
                    edge
                    for edge in graph.edges
                    if edge.kind == "loads"
                    and edge.target == definition.target
                    and nodes[edge.source].kind == "external_resource"
                ),
                None,
            )
            if incoming is None or not engine.paths(
                FlowKind.UNTRUSTED_CONTENT, incoming.source, incoming.target
            ):
                continue
            for write in (
                item
                for item in obs
                if item.kind in {"persistence", "config_write"}
                and (item.context, item.segment) == (trust.context, trust.segment)
            ):
                modification = matching(
                    definition.target, "modifies", write.location.line, "artifact"
                )
                if modification is None or modification.resolution != "resolved":
                    continue
                destination = nodes[modification.target].artifact
                if destination is None or destination not in by_path:
                    continue
                is_config = write.kind == "config_write"
                if is_config and by_path[destination].artifact.kind not in {
                    "agent_config",
                    "mcp_config",
                }:
                    continue
                if not is_config and by_path[destination].artifact.kind not in {
                    "memory",
                    "instructions",
                    "soul",
                    "skill",
                }:
                    continue
                flow = TaintFlow(
                    (TaintClass.REMOTE_INSTRUCTION, TaintClass.EXTERNAL_INSTRUCTION),
                    "remote instructions",
                    "agent configuration" if is_config else "persistent instruction",
                    (incoming, modification),
                    Confidence.MEDIUM,
                )
                emit(
                    "DRAGON-PATH-004" if is_config else "DRAGON-PATH-003",
                    artifact,
                    (incoming, definition, modification),
                    flow,
                    "Remote instruction targets agent configuration"
                    if is_config
                    else "Remote instruction targets persistent guidance",
                    Severity.HIGH if is_config else Severity.MEDIUM,
                    "The same actionable instruction accepts remote policy and directs a change "
                    "to a resolved local agent artifact; no remote content was fetched or applied.",
                    artifact,
                )
    return tuple(found)
