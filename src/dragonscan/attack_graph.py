"""Bounded, evidence-backed graph of normalized agent artifacts; never visits references."""

import hashlib
import ntpath
import os
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from dragonscan.behavior import fetch_shell_url, segment_text, write_target
from dragonscan.detection import Observation
from dragonscan.mcp_security import linked_sensitive_transfer, shadow_target, tool_signals
from dragonscan.models import Confidence, Document, SourceRef
from dragonscan.parse_errors import ParseError
from dragonscan.parse_helpers import safe_url

MAX_NODES = 50_000
MAX_EDGES = 100_000
_URL = re.compile(r"https?://[^\s<>|)]+", re.I)


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    label: str
    artifact: Path | None = None


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    kind: str
    location: SourceRef
    origin: str
    confidence: Confidence
    resolution: str = "observed"


@dataclass(frozen=True)
class AttackGraph:
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]

    def node(self, identifier: str) -> GraphNode:
        return next(node for node in self.nodes if node.id == identifier)


@dataclass(frozen=True)
class Resolution:
    status: str
    path: Path | None = None


class GraphLimitError(ValueError):
    """The graph exceeds the static analysis safety budget."""


def resolve_local(
    boundary: Path,
    source: Path,
    reference: str,
    known: frozenset[Path],
    case_counts: Mapping[str, int] | None = None,
) -> Resolution:
    """Resolve only selected, regular, non-symlink artifacts inside the target."""
    if (
        not reference
        or "\x00" in reference
        or "\\" in reference
        or "%" in reference
        or reference.startswith(("/", "~"))
        or ntpath.isabs(reference)
        or ":" in reference.split("/")[0]
    ):
        return Resolution("unsafe")
    root = boundary.resolve()
    lexical = Path(os.path.normpath(source.parent / reference))
    if not lexical.is_relative_to(root):
        return Resolution("outside")
    current = root
    if root.is_symlink():
        return Resolution("unsafe")
    for part in lexical.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            return Resolution("unsafe")
    # Do not guess how a case-insensitive filesystem might choose between spellings.
    counts = (
        case_counts if case_counts is not None else Counter(str(path).casefold() for path in known)
    )
    if counts.get(str(lexical).casefold(), 0) > 1:
        return Resolution("ambiguous")
    if lexical not in known:
        return Resolution("missing")
    if not lexical.is_file():
        return Resolution("missing")
    return Resolution("resolved", lexical)


def node_id(kind: str, key: str) -> str:
    return kind + ":" + hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:20]


def build_graph(
    boundary: Path,
    documents: tuple[Document, ...],
    observations: dict[Path, tuple[Observation, ...]],
) -> AttackGraph:
    nodes: dict[str, GraphNode] = {}
    edges: dict[GraphEdge, None] = {}
    known = frozenset(doc.artifact.path for doc in documents)
    case_counts = Counter(str(path).casefold() for path in known)
    root = boundary if boundary.is_dir() else boundary.parent

    def node(kind: str, key: str, label: str, artifact: Path | None = None) -> str:
        identifier = node_id(kind, key)
        if identifier not in nodes:
            if len(nodes) >= MAX_NODES:
                raise GraphLimitError("graph node limit exceeded")
            nodes[identifier] = GraphNode(
                identifier, kind, label if kind == "artifact" else label[:120], artifact
            )
        return identifier

    def edge(
        source: str,
        target: str,
        kind: str,
        location: SourceRef,
        origin: str,
        confidence: Confidence = Confidence.HIGH,
        resolution: str = "observed",
    ) -> None:
        item = GraphEdge(source, target, kind, location, origin, confidence, resolution)
        if item not in edges and len(edges) >= MAX_EDGES:
            raise GraphLimitError("graph edge limit exceeded")
        edges[item] = None

    def artifact_node(path: Path) -> str:
        return node("artifact", str(path), str(path), path)

    def external(raw: str) -> str | None:
        try:
            clean = safe_url(raw.rstrip(".,;"))
        except ParseError:
            return None
        if clean is None:
            return None
        hostname = urlsplit(clean).hostname or "unknown"
        return node("external_resource", clean, f"external HTTP(S) endpoint ({hostname[:80]})")

    def local(source: Path, target: str) -> tuple[str, Resolution]:
        resolved = resolve_local(root, source, target, known, case_counts)
        if resolved.path is not None:
            return artifact_node(resolved.path), resolved
        return (
            node("unresolved_resource", str(source) + ":" + target, "unresolved local reference"),
            resolved,
        )

    for document in documents:
        path = document.artifact.path
        source = artifact_node(path)
        for relation in document.relationships:
            if relation.kind in {"references_file", "loads_file"}:
                dest, resolution = local(path, relation.target)
                edge(
                    source,
                    dest,
                    "loads" if relation.kind == "loads_file" else "references",
                    relation.location,
                    document.artifact.source_format.value,
                    resolution=resolution.status,
                )
            elif relation.kind == "references_url":
                remote_id = external(relation.target)
                if remote_id is not None:
                    owner = source
                    if relation.subject is not None:
                        owner = node("mcp_server", str(path) + ":" + relation.subject, "MCP server")
                    edge(
                        owner,
                        remote_id,
                        "references",
                        relation.location,
                        "parser",
                        resolution="external",
                    )
            elif relation.kind == "defines_server":
                server_id = node("mcp_server", str(path) + ":" + relation.target, "MCP server")
                edge(source, server_id, "defines", relation.location, "mcp_parser")
            elif relation.kind in {"invokes_runtime", "invokes_package"}:
                server_id = node(
                    "mcp_server", str(path) + ":" + str(relation.subject), "MCP server"
                )
                kind = "command" if relation.kind == "invokes_runtime" else "package"
                dest = node(kind, str(path) + ":" + relation.target, kind)
                edge(
                    server_id,
                    dest,
                    "invokes" if kind == "command" else "depends_on",
                    relation.location,
                    "mcp_parser",
                )
            elif relation.kind == "references_dependency":
                if not document.dependencies:
                    dest = node("package", relation.target, "dependency package")
                    edge(source, dest, "depends_on", relation.location, "manifest_parser")
        for dependency in document.dependencies:
            package = node(
                "package",
                dependency.ecosystem + ":" + dependency.name,
                dependency.ecosystem + ":" + dependency.name,
            )
            action = (
                "installs"
                if dependency.mechanism
                in {
                    "installation",
                    "install-and-execute",
                    "runtime-execution",
                }
                else "depends_on"
            )
            edge(source, package, action, dependency.location, "dependency_parser")
            if dependency.mechanism in {"runtime-execution", "install-and-execute"}:
                command = node("command", dependency.manager, dependency.manager)
                edge(package, command, "executes", dependency.location, "dependency_parser")
            if dependency.registry is not None:
                registry = node(
                    "registry",
                    dependency.registry,
                    "configured dependency registry",
                )
                edge(
                    package,
                    registry,
                    "sourced_from",
                    dependency.location,
                    "dependency_parser",
                    resolution="external",
                )
            elif dependency.source in {
                "git",
                "git-commit",
                "git-branch",
                "git-tag",
                "git-ref",
                "url",
            }:
                dependency_source_id = node(
                    "dependency_source",
                    f"{path}:{dependency.location.line}:{dependency.name}:{dependency.source}",
                    dependency.source,
                )
                edge(
                    package,
                    dependency_source_id,
                    "sourced_from",
                    dependency.location,
                    "dependency_parser",
                    resolution="external",
                )
        for server in document.servers:
            server_id = node("mcp_server", str(path) + ":" + server.name, "MCP server")
            if server.mutable_tools_url:
                remote_id = external(server.mutable_tools_url)
                if remote_id is not None:
                    edge(
                        server_id,
                        remote_id,
                        "references",
                        server.location,
                        "mcp_metadata",
                        resolution="external",
                    )
            tool_ids: dict[str, str] = {}
            for tool in server.tools:
                tool_id = node("mcp_tool", f"{path}:{server.name}:tool:{tool.name}", "MCP tool")
                tool_ids[tool.name] = tool_id
                edge(server_id, tool_id, "exposes", tool.location, "mcp_metadata")
                for capability in sorted(tool_signals(tool)):
                    cap_id = node(
                        "mcp_capability",
                        f"{path}:{server.name}:{tool.name}:{capability}",
                        capability,
                    )
                    edge(
                        tool_id, cap_id, "defines", tool.location, "mcp_metadata", Confidence.MEDIUM
                    )
                if linked_sensitive_transfer(tool):
                    credential = node_id(
                        "mcp_capability", f"{path}:{server.name}:{tool.name}:credential-access"
                    )
                    egress = node_id(
                        "mcp_capability", f"{path}:{server.name}:{tool.name}:network-egress"
                    )
                    if credential in nodes and egress in nodes:
                        edge(
                            credential,
                            egress,
                            "sends_to",
                            tool.location,
                            "mcp_metadata",
                            Confidence.MEDIUM,
                        )
            for tool in server.tools:
                target_tool = shadow_target(server, tool)
                if target_tool is not None:
                    edge(
                        tool_ids[tool.name],
                        tool_ids[target_tool.name],
                        "influences",
                        tool.location,
                        "mcp_metadata",
                    )
            for kind, items in (("mcp_prompt", server.prompts), ("mcp_resource", server.resources)):
                for item in items:
                    item_id = node(
                        kind, f"{path}:{server.name}:{kind}:{item.name}", kind.replace("_", " ")
                    )
                    edge(server_id, item_id, "exposes", item.location, "mcp_metadata")
                    if item.url:
                        external_id = external(item.url)
                        if external_id is not None:
                            edge(
                                item_id,
                                external_id,
                                "references",
                                item.location,
                                "mcp_metadata",
                                resolution="external",
                            )
            if server.url and server.transport != "stdio":
                for header in server.headers:
                    if header.sensitive and header.origin == "reference":
                        ref = node(
                            "sensitive_resource",
                            f"{path}:{server.name}:header:{header.name}",
                            "credential reference",
                        )
                        edge(ref, server_id, "authenticates_with", header.location, "mcp_metadata")
            if (
                server.runtime not in {"sh", "bash", "zsh"}
                or len(server.args) < 2
                or server.args[0] not in {"-c", "-lc"}
            ):
                continue
            remote = external(fetch_shell_url(server.args[1]) or "")
            if remote is None:
                continue
            server_id = node("mcp_server", str(path) + ":" + server.name, "MCP server")
            command = node("command", str(path) + ":" + server.name + ":shell", "shell command")
            capability = node(
                "mcp_capability", str(path) + ":" + server.name + ":exec", "shell execution"
            )
            edge(server_id, command, "executes", server.location, "mcp_parser")
            edge(remote, command, "fetches", server.location, "mcp_parser")
            edge(server_id, capability, "defines", server.location, "mcp_parser")
        for obs in observations.get(path, ()):
            if obs.context >= len(document.instructions):
                continue
            text = segment_text(document.instructions[obs.context].text, obs.segment)
            instruction = node(
                "instruction",
                f"{path}:{obs.context}:{obs.segment}",
                "actionable instruction",
                path,
            )
            edge(source, instruction, "defines", obs.location, "behavior")
            if obs.kind == "sensitive_access":
                secret = node("sensitive_resource", obs.label, obs.label)
                edge(instruction, secret, "reads", obs.location, "behavior")
            elif obs.kind in {"external_transfer", "remote_trust", "remote_execution"}:
                urls = [match.group() for match in _URL.finditer(text)]
                endpoint = (
                    fetch_shell_url(text)
                    if obs.kind == "remote_execution"
                    else (urls[0] if len(urls) == 1 else None)
                )
                remote = external(endpoint or "")
                if remote is None:
                    continue
                if obs.kind == "external_transfer":
                    edge(instruction, remote, "sends_to", obs.location, "behavior")
                elif obs.kind == "remote_trust":
                    edge(remote, instruction, "loads", obs.location, "behavior", Confidence.MEDIUM)
                else:
                    command = node(
                        "command",
                        f"{path}:{obs.context}:{obs.segment}:shell",
                        "shell command",
                    )
                    edge(remote, command, "fetches", obs.location, "behavior")
                    edge(instruction, command, "executes", obs.location, "behavior")
            elif obs.kind in {"persistence", "config_write"}:
                target = write_target(text, obs.kind)
                if target:
                    dest, resolved = local(path, target)
                    edge(
                        instruction,
                        dest,
                        "modifies",
                        obs.location,
                        "behavior",
                        Confidence.MEDIUM,
                        resolved.status,
                    )
    return AttackGraph(tuple(nodes.values()), tuple(edges))
