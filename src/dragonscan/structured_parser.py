"""Bounded, non-executing structured config parsing and MCP normalization."""

import json
import tomllib
from dataclasses import replace
from datetime import date, datetime, time
from pathlib import PurePath
from typing import Any, cast
from urllib.parse import urlsplit

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, SequenceNode

from dragonscan.mcp_normalization import (
    invocation,
    metadata,
    mutable_url,
    safe_mcp_url,
    secret_refs,
)
from dragonscan.mcp_normalization import transport as mcp_transport
from dragonscan.models import (
    Artifact,
    ArtifactKind,
    ConfigEntry,
    Document,
    McpContent,
    McpServer,
    McpTool,
    Relationship,
    SourceFormat,
    SourceRef,
)
from dragonscan.parse_errors import ParseError
from dragonscan.parse_helpers import safe_url

_MAX_DEPTH = 64
_MAX_NODES = 20_000
_PRIVATE_KEYS = frozenset(
    {
        "env",
        "environment",
        "headers",
        "httpheaders",
        "authorization",
        "token",
        "password",
        "secret",
        "api_key",
        "apikey",
    }
)


class BoundedSafeLoader(yaml.SafeLoader):
    """Reject aliases and expensive nesting rather than expanding untrusted graphs."""

    def __init__(self, stream: str):
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0

    def compose_node(self, parent: Node | None, index: int) -> Node | None:
        if self.check_event(AliasEvent):
            raise ParseError("YAML aliases are not supported")
        self._depth += 1
        self._nodes += 1
        if self._depth > _MAX_DEPTH or self._nodes > _MAX_NODES:
            raise ParseError("YAML exceeds parser complexity limit")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in result:
                    raise ParseError("duplicate YAML mapping key")
                result[key] = self.construct_object(value_node, deep=deep)
            except TypeError as exc:
                raise ParseError("invalid YAML mapping key") from exc
        return result


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ParseError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ParseError("non-finite JSON number")


def _load(artifact: Artifact, text: str) -> tuple[Any, Node | None]:
    fmt = artifact.source_format
    try:
        if fmt == SourceFormat.JSON:
            return json.loads(
                text, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant
            ), None
        if fmt == SourceFormat.TOML:
            return tomllib.loads(text), None
        if fmt == SourceFormat.YAML:
            loader = BoundedSafeLoader(text)
            try:
                node = loader.get_single_node()
                return loader.construct_document(node) if node is not None else None, node
            finally:
                loader.dispose()
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON at line {exc.lineno}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ParseError("invalid TOML") from exc
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = f" at line {mark.line + 1}" if mark is not None else ""
        raise ParseError(f"invalid YAML{line}") from exc
    except (RecursionError, OverflowError, TypeError, ValueError) as exc:
        if isinstance(exc, ParseError):
            raise
        raise ParseError("structured input exceeds parser limits or has invalid values") from exc
    raise ParseError("unsupported source format")


def _location(artifact: Artifact, node: Node | None) -> SourceRef:
    return SourceRef(
        artifact.path,
        artifact.source_format,
        node.start_mark.line + 1 if node is not None else None,
        node.end_mark.line + 1 if node is not None else None,
    )


def _entries(
    artifact: Artifact, data: dict[str, Any], node: Node | None
) -> tuple[ConfigEntry, ...]:
    output: list[ConfigEntry] = []
    stack: list[tuple[tuple[str | int, ...], Any, Node | None, Node | None, int]] = [
        ((), data, node, None, 0)
    ]
    while stack:
        path, value, current, key_node, depth = stack.pop()
        if depth > _MAX_DEPTH or len(output) + len(stack) > _MAX_NODES:
            raise ParseError("structured input exceeds parser complexity limit")
        private = any(str(part).lower() in _PRIVATE_KEYS for part in path)
        if isinstance(value, dict):
            if not all(isinstance(key, str) for key in value):
                raise ParseError("structured config requires string keys")
            kind = "object"
        elif isinstance(value, list):
            kind = "array"
        elif isinstance(value, str):
            kind = "string"
        elif isinstance(value, bool):
            kind = "boolean"
        elif isinstance(value, (int, float)):
            kind = "number"
        elif value is None:
            kind = "null"
        elif isinstance(value, (datetime, date, time)):
            kind = "datetime"
        else:
            raise ParseError("unsupported structured value type")
        if path:
            normalized = None if private or kind in {"object", "array"} else value
            if kind == "datetime" and not private:
                normalized = value.isoformat()
            if path[-1] in {"url", "endpoint"} and isinstance(normalized, str):
                public = safe_url(normalized)
                normalized = (
                    public if public is not None else (None if "://" in normalized else normalized)
                )
            location = _location(artifact, current)
            if key_node is not None:
                location = replace(location, line=key_node.start_mark.line + 1)
            output.append(ConfigEntry(path, kind, normalized, location))
        if isinstance(value, dict):
            if len(value) + len(stack) + len(output) > _MAX_NODES:
                raise ParseError("structured input exceeds parser complexity limit")
            nodes: dict[str, tuple[Node, Node]] = {}
            if isinstance(current, MappingNode):
                nodes = {str(key.value): (key, child) for key, child in current.value}
            stack.extend(
                (
                    path + (str(key),),
                    child,
                    nodes[str(key)][1] if str(key) in nodes else None,
                    nodes[str(key)][0] if str(key) in nodes else None,
                    depth + 1,
                )
                for key, child in reversed(tuple(value.items()))
            )
        elif isinstance(value, list):
            if len(value) + len(stack) + len(output) > _MAX_NODES:
                raise ParseError("structured input exceeds parser complexity limit")
            children = current.value if isinstance(current, SequenceNode) else []
            stack.extend(
                (
                    path + (index,),
                    child,
                    children[index] if index < len(children) else None,
                    None,
                    depth + 1,
                )
                for index, child in reversed(tuple(enumerate(value)))
            )
    return tuple(output)


def _servers(
    artifact: Artifact, data: dict[str, Any], locations: dict[tuple[str | int, ...], SourceRef]
) -> tuple[tuple[McpServer, ...], tuple[Relationship, ...]]:
    if "mcpServers" not in data:
        if artifact.kind == ArtifactKind.MCP_CONFIG:
            raise ParseError("MCP config requires an mcpServers object")
        return (), ()
    definitions = data["mcpServers"]
    if not isinstance(definitions, dict):
        raise ParseError("MCP config requires an mcpServers object")
    servers: list[McpServer] = []
    relations: list[Relationship] = []
    for name, config in definitions.items():
        if not isinstance(name, str) or not isinstance(config, dict):
            raise ParseError("invalid MCP server entry")
        location = locations.get(("mcpServers", name), _location(artifact, None))
        command = config.get("command", "")
        args = config.get("args", [])
        env = config.get("env", {})
        url = config.get("url")
        transport = config.get("type")
        if (
            not isinstance(command, str)
            or not isinstance(args, list)
            or not all(isinstance(arg, str) for arg in args)
            or not isinstance(env, dict)
            or not all(isinstance(key, str) for key in env)
            or (url is not None and not isinstance(url, str))
            or (transport is not None and not isinstance(transport, str))
        ):
            raise ParseError("invalid MCP server metadata")
        safe = safe_mcp_url(url) if url is not None else None
        if url is not None and safe is None:
            raise ParseError("invalid MCP URL")
        argv = tuple(args)
        runtime, package, version, pinning = invocation(command, argv)
        cwd = config.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ParseError("invalid MCP working directory")
        prefix: tuple[str | int, ...] = ("mcpServers", name)
        tools = cast(
            tuple[McpTool, ...], metadata(config.get("tools"), location, locations, prefix, "tools")
        )
        resources = cast(
            tuple[McpContent, ...],
            metadata(config.get("resources"), location, locations, prefix, "resources"),
        )
        prompts = cast(
            tuple[McpContent, ...],
            metadata(config.get("prompts"), location, locations, prefix, "prompts"),
        )
        server = McpServer(
            name,
            command,
            argv,
            location,
            transport=mcp_transport(transport, command, safe),
            env_names=tuple(env),
            url=safe,
            runtime=runtime,
            package=package,
            url_has_credentials=(
                bool(urlsplit(url).username or urlsplit(url).password) if url is not None else False
            ),
            cwd=cwd,
            package_version=version,
            pinning=pinning,
            environment=secret_refs(env, locations.get((*prefix, "env"), location)),
            headers=secret_refs(
                config.get("headers"), locations.get((*prefix, "headers"), location), headers=True
            ),
            tools=tools,
            resources=resources,
            prompts=prompts,
            mutable_tools_url=mutable_url(config),
        )
        servers.append(server)
        relations.append(Relationship("defines_server", name, location))
        if runtime is not None:
            relations.append(Relationship("invokes_runtime", runtime, location, name))
        if package is not None:
            relations.append(Relationship("invokes_package", package, location, name))
        if safe is not None:
            url_location = locations.get(("mcpServers", name, "url"), location)
            relations.append(Relationship("references_url", safe, url_location, name))
    return tuple(servers), tuple(relations)


def parse_structured(artifact: Artifact, text: str) -> Document:
    data, node = _load(artifact, text)
    if not isinstance(data, dict) or not all(isinstance(key, str) for key in data):
        raise ParseError("structured config requires an object with string keys")
    if artifact.kind == ArtifactKind.STRUCTURED_CONFIG and isinstance(data.get("mcpServers"), dict):
        artifact = replace(artifact, kind=ArtifactKind.MCP_CONFIG)
    entries = _entries(artifact, data, node)
    if isinstance(data.get("mcpServers"), dict):
        entries = tuple(
            replace(entry, value="[redacted]")
            if len(entry.key_path) >= 3
            and entry.key_path[0] == "mcpServers"
            and entry.key_path[2]
            in {"env", "headers", "args", "tools", "prompts", "resources", "url", "toolsUrl"}
            and isinstance(entry.value, str)
            else entry
            for entry in entries
        )
    locations = {entry.key_path: entry.location for entry in entries}
    servers, relationships = _servers(artifact, data, locations)
    relations = list(relationships)
    for entry in entries:
        key = entry.key_path[-1]
        if (
            isinstance(key, str)
            and key.lower() in {"skillfile", "instructionfile", "agentsfile", "configfile"}
            and isinstance(entry.value, str)
            and PurePath(entry.value).suffix.lower() in {".md", ".json", ".yaml", ".yml", ".toml"}
        ):
            relations.append(Relationship("loads_file", entry.value, entry.location))
        if (
            len(entry.key_path) == 2
            and entry.key_path[0] == "skills"
            and isinstance(key, int)
            and isinstance(entry.value, str)
            and PurePath(entry.value).suffix.lower() == ".md"
        ):
            relations.append(Relationship("loads_file", entry.value, entry.location))
        if len(entry.key_path) == 3 and entry.key_path[0] == "mcpServers":
            continue
        if entry.key_path[-1] in {"url", "endpoint"} and isinstance(entry.value, str):
            url = safe_url(entry.value)
            if url is not None:
                relations.append(Relationship("references_url", url, entry.location))
    if artifact.kind == ArtifactKind.DEPENDENCY_MANIFEST:
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(field)
            if isinstance(deps, dict):
                for package in deps:
                    if isinstance(package, str):
                        location = locations.get((field, package), _location(artifact, None))
                        relations.append(Relationship("references_dependency", package, location))
    return Document(
        artifact, servers=servers, entries=entries, relationships=tuple(dict.fromkeys(relations))
    )
