"""Bounded, non-executing structured config parsing and MCP normalization."""

import json
import re
import tomllib
from dataclasses import replace
from datetime import date, datetime, time
from pathlib import Path, PurePath
from typing import Any, cast
from urllib.parse import urlsplit

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, SequenceNode

from dragonscan.dependencies import structured_dependencies
from dragonscan.jsonc import load_jsonc
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
    McpSecretRef,
    McpServer,
    McpTool,
    Relationship,
    SourceFormat,
    SourceRef,
)
from dragonscan.parse_errors import ParseError
from dragonscan.parse_helpers import safe_url
from dragonscan.semantic import redact

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
        zed_settings = (
            fmt == SourceFormat.JSON
            and artifact.ecosystem == "Zed Agent"
            and artifact.kind == ArtifactKind.AGENT_CONFIG
            and artifact.path.name.lower() == "settings.json"
        )
        if fmt == SourceFormat.JSONC or zed_settings:
            if fmt == SourceFormat.JSONC and (
                artifact.ecosystem != "Kilo Code" or artifact.path.name.lower() != "kilo.jsonc"
            ):
                raise ParseError("unsupported JSONC configuration")
            data, sanitized = load_jsonc(text, _unique_pairs, _reject_constant)
            if any(char in sanitized for char in "\u0085\u2028\u2029"):
                # YAML and JSON disagree on these characters' line-break semantics.
                return data, None
            # JSON was already validated. Use the bounded composer for source positions only;
            # never construct YAML values from JSONC or treat comments as evidence.
            loader = BoundedSafeLoader(sanitized)
            try:
                return data, loader.get_single_node()
            except yaml.YAMLError as exc:
                raise ParseError("JSONC source location mapping unavailable") from exc
            finally:
                loader.dispose()
        if fmt == SourceFormat.JSON:
            data = json.loads(
                text, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant
            )
            # Reuse the bounded JSONC position mapper, never YAML value construction.
            # Valid JSON outside its syntax/budget retains unknown source positions.
            if any(char in text for char in "\u0085\u2028\u2029"):
                return data, None
            loader = BoundedSafeLoader(text)
            try:
                return data, loader.get_single_node()
            except (yaml.YAMLError, ParseError):
                return data, None
            finally:
                loader.dispose()
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
) -> tuple[tuple[McpServer, ...], tuple[Relationship, ...], tuple[str, ...]]:
    definitions = data.get("mcpServers")
    if definitions is not None and not isinstance(definitions, dict):
        raise ParseError("MCP config requires an mcpServers object")
    if not isinstance(definitions, dict):
        return _parse_servers_strict(artifact, data, locations)
    servers: list[McpServer] = []
    relations: list[Relationship] = []
    diagnostics: list[str] = []
    for name, config in definitions.items():
        try:
            parsed, related, warnings = _parse_servers_strict(
                artifact, {"mcpServers": {name: config}}, locations
            )
        except ParseError:
            diagnostics.append("invalid MCP server entry; server skipped")
        else:
            servers.extend(parsed)
            relations.extend(related)
            diagnostics.extend(warnings)
    if not servers and diagnostics:
        raise ParseError("invalid MCP server entry")
    return tuple(servers), tuple(relations), tuple(diagnostics)


def _parse_servers_strict(
    artifact: Artifact, data: dict[str, Any], locations: dict[tuple[str | int, ...], SourceRef]
) -> tuple[tuple[McpServer, ...], tuple[Relationship, ...], tuple[str, ...]]:
    if "mcpServers" not in data:
        if artifact.kind == ArtifactKind.MCP_CONFIG:
            return (), (), ("unsupported MCP metadata schema; server analysis skipped",)
        return (), (), ()
    definitions = data["mcpServers"]
    if not isinstance(definitions, dict):
        raise ParseError("MCP config requires an mcpServers object")
    servers: list[McpServer] = []
    relations: list[Relationship] = []
    diagnostics: list[str] = []
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
        optional: dict[str, Any] = {}
        for kind in ("tools", "resources", "prompts"):
            value = config.get(kind)
            if isinstance(value, dict):
                diagnostics.append(
                    f"unsupported MCP metadata schema ({kind} object); metadata skipped"
                )
                optional[kind] = None
            else:
                optional[kind] = value
        tools = cast(
            tuple[McpTool, ...], metadata(optional["tools"], location, locations, prefix, "tools")
        )
        resources = cast(
            tuple[McpContent, ...],
            metadata(optional["resources"], location, locations, prefix, "resources"),
        )
        prompts = cast(
            tuple[McpContent, ...],
            metadata(optional["prompts"], location, locations, prefix, "prompts"),
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
            url_identity_exact=(
                url is not None
                and safe is not None
                and urlsplit(url).query == ""
                and urlsplit(url).fragment == ""
                and urlsplit(url).username is None
                and urlsplit(url).password is None
                and safe_url(url) == safe
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
    return tuple(servers), tuple(relations), tuple(diagnostics)


def _kilo_servers(
    artifact: Artifact, data: dict[str, Any], locations: dict[tuple[str | int, ...], SourceRef]
) -> tuple[tuple[McpServer, ...], tuple[Relationship, ...], tuple[str, ...]]:
    """Normalize only Kilo's documented top-level mcp schema, never mcpServers."""
    if "mcp" not in data:
        return (), (), ()
    definitions = data["mcp"]
    if not isinstance(definitions, dict):
        return (), (), ("unsupported Kilo MCP schema; server analysis skipped",)
    servers: list[McpServer] = []
    relations: list[Relationship] = []
    diagnostics: list[str] = []
    for name, config in definitions.items():
        if not isinstance(config, dict) or not isinstance(name, str):
            diagnostics.append("unsupported Kilo MCP server schema; server skipped")
            continue
        if config.get("enabled") is False:
            continue
        kind = config.get("type")
        command = config.get("command")
        url = config.get("url")
        env = config.get("environment", {})
        if (
            not isinstance(kind, str)
            or config.get("enabled", True) is not True
            or not isinstance(env, dict)
            or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in env.items()
            )
            or (
                kind == "local"
                and (
                    not isinstance(command, list)
                    or not command
                    or not all(isinstance(v, str) for v in command)
                    or url is not None
                )
            )
            or (kind == "remote" and (not isinstance(url, str) or command is not None))
            or kind not in {"local", "remote"}
        ):
            diagnostics.append("unsupported Kilo MCP server schema; server skipped")
            continue
        argv = cast(list[str], command) if kind == "local" else []
        normalized = {
            "command": argv[0] if kind == "local" else "",
            "args": argv[1:] if kind == "local" else [],
            "url": url if kind == "remote" else None,
            "env": env,
            "headers": config.get("headers") if kind == "remote" else None,
            "type": "stdio" if kind == "local" else "http",
        }
        prefix = ("mcpServers", name)
        translated: dict[tuple[str | int, ...], SourceRef] = {
            prefix: locations.get(("mcp", name), _location(artifact, None)),
            (*prefix, "env"): locations.get(
                ("mcp", name, "environment"), _location(artifact, None)
            ),
            (*prefix, "headers"): locations.get(
                ("mcp", name, "headers"), _location(artifact, None)
            ),
            (*prefix, "url"): locations.get(("mcp", name, "url"), _location(artifact, None)),
        }
        try:
            selected, edges, notes = _servers(
                artifact, {"mcpServers": {name: normalized}}, translated
            )
        except ParseError:
            diagnostics.append("unsupported Kilo MCP server metadata; server skipped")
            continue
        servers.extend(selected)
        relations.extend(edges)
        diagnostics.extend(notes)
    return tuple(servers), tuple(relations), tuple(diagnostics)


def _zed_servers(
    artifact: Artifact, data: dict[str, Any], locations: dict[tuple[str | int, ...], SourceRef]
) -> tuple[tuple[McpServer, ...], tuple[Relationship, ...], tuple[str, ...]]:
    """Map only Zed's documented stdio/HTTP context server shapes."""
    if "context_servers" not in data:
        return (), (), ()
    definitions = data["context_servers"]
    if not isinstance(definitions, dict):
        return (), (), ("unsupported Zed context_servers schema; server analysis skipped",)
    servers: list[McpServer] = []
    relations: list[Relationship] = []
    diagnostics: list[str] = []
    local_fields = {"command", "args", "env", "enabled", "remote", "timeout"}
    http_fields = {"url", "headers", "enabled", "timeout", "oauth"}
    for name, config in definitions.items():
        if not isinstance(name, str) or not name or not isinstance(config, dict):
            diagnostics.append("unsupported Zed context server shape; server skipped")
            continue
        if config.get("enabled") is False:
            diagnostics.append("disabled Zed context server; not in active inventory")
            continue
        if config.get("enabled", True) is not True:
            diagnostics.append("unsupported Zed context server enabled value; server skipped")
            continue
        if "settings" in config and "command" not in config and "url" not in config:
            diagnostics.append("Zed extension context server not statically resolvable; skipped")
            continue
        command, url = config.get("command"), config.get("url")
        local = "command" in config and "url" not in config
        remote = "url" in config and "command" not in config
        if not local and not remote and "command" not in config and "url" not in config:
            diagnostics.append("Zed context server missing command or url; server skipped")
            continue
        env = config.get("env")
        headers = config.get("headers")
        oauth = config.get("oauth")
        timeout = config.get("timeout")
        valid_oauth = oauth is None or (
            isinstance(oauth, dict)
            and set(oauth) <= {"client_id", "client_secret"}
            and isinstance(oauth.get("client_id"), str)
            and ("client_secret" not in oauth or isinstance(oauth["client_secret"], str))
        )
        if (
            (not local and not remote)
            or not set(config) <= (local_fields if local else http_fields)
            or ("timeout" in config and (type(timeout) is not int or timeout < 0))
            or (
                local
                and (
                    not isinstance(command, str)
                    or not command.strip()
                    or not isinstance(config.get("args", []), list)
                    or not all(isinstance(arg, str) for arg in config.get("args", []))
                    or (
                        env is not None
                        and (
                            not isinstance(env, dict)
                            or not all(
                                isinstance(k, str) and isinstance(v, str) for k, v in env.items()
                            )
                        )
                    )
                    or type(config.get("remote", False)) is not bool
                )
            )
            or (
                remote
                and (
                    not isinstance(url, str)
                    or not url.strip()
                    or (
                        headers is not None
                        and (
                            not isinstance(headers, dict)
                            or not all(
                                isinstance(k, str) and isinstance(v, str)
                                for k, v in headers.items()
                            )
                        )
                    )
                    or not valid_oauth
                )
            )
        ):
            diagnostics.append("unsupported Zed context server shape; server skipped")
            continue
        prefix = ("mcpServers", name)
        origin = ("context_servers", name)
        translated: dict[tuple[str | int, ...], SourceRef] = {
            prefix: locations.get(origin, _location(artifact, None)),
            (*prefix, "env"): locations.get((*origin, "env"), _location(artifact, None)),
            (*prefix, "headers"): locations.get((*origin, "headers"), _location(artifact, None)),
            (*prefix, "url"): locations.get((*origin, "url"), _location(artifact, None)),
        }
        normalized = (
            {"command": command, "args": config.get("args", []), "env": env or {}, "type": "stdio"}
            if local
            else {"url": url, "headers": headers or {}, "type": "http"}
        )
        try:
            selected, edges, notes = _servers(
                artifact, {"mcpServers": {name: normalized}}, translated
            )
        except ParseError:
            diagnostics.append("unsupported Zed context server metadata; server skipped")
            continue
        servers.extend(selected)
        relations.extend(edges)
        diagnostics.extend(notes)
    return tuple(servers), tuple(relations), tuple(diagnostics)


def _goose_servers(
    artifact: Artifact, data: dict[str, Any], locations: dict[tuple[str | int, ...], SourceRef]
) -> tuple[tuple[McpServer, ...], tuple[Relationship, ...], tuple[str, ...]]:
    """Inventory only active, external Goose MCP extensions in its config.yaml."""
    if "extensions" not in data:
        return (), (), ()
    definitions = data["extensions"]
    if not isinstance(definitions, dict):
        return (), (), ("unsupported Goose extensions schema; server analysis skipped",)
    servers: list[McpServer] = []
    relations: list[Relationship] = []
    diagnostics: list[str] = []
    seen_names: set[str] = set()
    for key, config in definitions.items():
        if not key or not isinstance(config, dict):
            diagnostics.append("unsupported Goose extension schema; server skipped")
            continue
        if config.get("enabled") is False:
            diagnostics.append("disabled Goose extension; not in active inventory")
            continue
        kind = config.get("type")
        if not isinstance(kind, str):
            diagnostics.append("unsupported Goose extension type; server skipped")
            continue
        if kind in {"builtin", "platform"}:
            diagnostics.append("non-MCP Goose extension; not in external server inventory")
            continue
        if kind not in {"stdio", "streamable_http"}:
            diagnostics.append("unsupported Goose extension type; server skipped")
            continue
        name = config.get("name")
        envs = config.get("envs", config.get("env", {}))
        keys = config.get("env_keys", [])
        args = config.get("args", [])
        headers = config.get("headers", {})
        cmd, uri = config.get("cmd"), config.get("uri")
        allowed = {
            "type",
            "name",
            "enabled",
            "bundled",
            "display_name",
            "description",
            "timeout",
            "available_tools",
            "envs",
            "env_keys",
        }
        allowed |= {"cmd", "args", "cwd", "env"} if kind == "stdio" else {"uri", "headers"}
        if (
            config.get("enabled") is not True
            or not isinstance(name, str)
            or not name.strip()
            or not set(config) <= allowed
            or "env" in config
            and "envs" in config
            or not isinstance(envs, dict)
            or not all(isinstance(k, str) and isinstance(v, str) for k, v in envs.items())
            or not isinstance(keys, list)
            or not all(isinstance(k, str) and k for k in keys)
            or not isinstance(args, list)
            or not all(isinstance(arg, str) for arg in args)
            or not isinstance(headers, dict)
            or not all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items())
            or (kind == "stdio" and "args" not in config)
            or (kind == "stdio" and (not isinstance(cmd, str) or not cmd.strip()))
            or (kind == "streamable_http" and (not isinstance(uri, str) or not uri.strip()))
        ):
            diagnostics.append("unsupported Goose extension schema; server skipped")
            continue
        if name in seen_names:
            diagnostics.append("duplicate Goose extension identity; server skipped")
            continue
        origin = ("extensions", key)
        prefix = ("mcpServers", key)
        translated = {
            prefix: locations.get(origin, _location(artifact, None)),
            (*prefix, "env"): locations.get(
                (*origin, "envs"), locations.get((*origin, "env"), _location(artifact, None))
            ),
            (*prefix, "headers"): locations.get((*origin, "headers"), _location(artifact, None)),
            (*prefix, "url"): locations.get((*origin, "uri"), _location(artifact, None)),
        }
        normalized = (
            {"command": cmd, "args": args, "env": envs, "cwd": config.get("cwd"), "type": "stdio"}
            if kind == "stdio"
            else {"url": uri, "headers": headers, "type": "streamable_http"}
        )
        try:
            selected, edges, notes = _servers(
                artifact, {"mcpServers": {key: normalized}}, translated
            )
        except ParseError:
            diagnostics.append("unsupported Goose extension metadata; server skipped")
            continue
        if not selected:
            diagnostics.extend(notes or ("unsupported Goose MCP server; skipped",))
            continue
        seen_names.add(name)
        if keys:
            key_location = locations.get((*origin, "env_keys"), translated[prefix])
            selected = tuple(
                replace(
                    server,
                    env_names=tuple(dict.fromkeys((*server.env_names, *keys))),
                    environment=(
                        *server.environment,
                        *(
                            McpSecretRef(key, "reference", True, key_location)
                            for key in keys
                            if key not in envs
                        ),
                    ),
                )
                for server in selected
            )
        servers.extend(selected)
        relations.extend(edges)
        diagnostics.extend(notes)
    return tuple(servers), tuple(relations), tuple(diagnostics)


_SENSITIVE_ARG = re.compile(
    r"^--?(?:api[-_]?key|token|password|secret|authorization|auth|header|credential)$",
    re.I,
)


def _safe_agent_args(args: list[str]) -> list[str]:
    """Keep invocation evidence without retaining credential-bearing flag values."""
    cleaned: list[str] = []
    previous_sensitive = False
    for argument in args:
        flag, separator, value = argument.partition("=")
        sensitive = bool(_SENSITIVE_ARG.fullmatch(flag))
        if previous_sensitive:
            cleaned.append("[redacted]")
        elif sensitive and separator:
            cleaned.append(f"{flag}=[redacted]")
        elif separator and value.startswith(("http://", "https://")):
            cleaned.append(f"{flag}={safe_mcp_url(value) or '[redacted]'}")
        elif argument.startswith(("http://", "https://")):
            cleaned.append(safe_mcp_url(argument) or "[redacted]")
        else:
            cleaned.append(redact(argument) or "[redacted]")
        previous_sensitive = sensitive and not separator
    return cleaned


def _agent_mcp_servers(
    artifact: Artifact,
    data: dict[str, Any],
    locations: dict[tuple[str | int, ...], SourceRef],
    field: str,
) -> tuple[tuple[McpServer, ...], tuple[Relationship, ...], tuple[str, ...]]:
    """Validate documented agent shapes before reusing the generic MCP normalizer."""
    if field not in data:
        return (), (), ()
    definitions = data[field]
    agent = artifact.ecosystem or "agent"
    if not isinstance(definitions, dict):
        return (), (), (f"unsupported {agent} MCP schema; server analysis skipped",)
    selected: dict[str, dict[str, Any]] = {}
    mapped: dict[tuple[str | int, ...], SourceRef] = {}
    diagnostics: list[str] = []
    for name, config in definitions.items():
        if not isinstance(name, str) or not name or not isinstance(config, dict):
            diagnostics.append(f"unsupported {agent} MCP server schema; server skipped")
            continue
        if config.get("enabled") is False and agent in {"Hermes Agent", "Codex"}:
            continue
        command, url = config.get("command"), config.get("url")
        args, env = config.get("args", []), config.get("env", {})
        headers = config.get("headers", config.get("http_headers", {}))
        transport = config.get("transport", config.get("type"))
        remote_types = {"http", "streamable-http", "sse"} if agent == "Claude Code" else {None}
        local_types = {None, "stdio"} if agent == "Claude Code" else {None}
        valid = (
            (transport is None or isinstance(transport, str))
            and type(config.get("enabled", True)) is bool
            and type(config.get("disabled", False)) is bool
            and isinstance(args, list)
            and all(isinstance(item, str) for item in args)
            and isinstance(env, dict)
            and all(isinstance(key, str) and isinstance(value, str) for key, value in env.items())
            and isinstance(headers, dict)
            and all(
                isinstance(key, str) and isinstance(value, str) for key, value in headers.items()
            )
            and (
                (
                    isinstance(command, str)
                    and bool(command.strip())
                    and url is None
                    and transport in local_types
                    and not headers
                )
                or (
                    command is None
                    and isinstance(url, str)
                    and bool(url)
                    and transport in remote_types
                    and not args
                    and not env
                )
            )
        )
        if "disabled" in config:
            valid = False
        if agent == "Codex" and ("type" in config or "transport" in config):
            valid = False
        if agent == "Hermes Agent" and ("type" in config or "transport" in config):
            valid = False
        if agent == "Claude Code" and ("transport" in config or "enabled" in config):
            valid = False
        if isinstance(url, str) and safe_mcp_url(url) is None:
            valid = False
        if not valid:
            diagnostics.append(f"unsupported {agent} MCP server schema; server skipped")
            continue
        prefix = (field, name)
        for key_path, location in locations.items():
            if key_path[:2] == prefix:
                mapped[("mcpServers", *key_path[1:])] = location
        selected[name] = {
            "command": (redact(command) or "[redacted]") if command else "",
            "args": _safe_agent_args(args),
            "env": env,
            "url": url,
            "type": "http"
            if transport == "streamable-http"
            else transport or ("http" if url is not None else "stdio"),
            "headers": headers,
        }
    servers, edges, notes = _servers(artifact, {"mcpServers": selected}, mapped)
    uncertain = {
        server.name
        for server in servers
        if server.package is not None and "redacted" in server.package.lower()
    }
    if uncertain:
        servers = tuple(
            replace(server, package=None, package_version=None, pinning=None)
            if server.name in uncertain
            else server
            for server in servers
        )
        edges = tuple(
            edge
            for edge in edges
            if not (edge.kind == "invokes_package" and edge.subject in uncertain)
        )
    if agent == "Codex":
        updated: list[McpServer] = []
        for server in servers:
            config = definitions[server.name]
            bearer = config.get("bearer_token_env_var")
            header_vars = config.get("env_http_headers", {})
            if (bearer is not None and (not isinstance(bearer, str) or not bearer)) or (
                not isinstance(header_vars, dict)
                or not all(
                    isinstance(k, str) and isinstance(v, str) for k, v in header_vars.items()
                )
            ):
                diagnostics.append("unsupported Codex MCP authentication schema; server skipped")
                continue
            headers = (
                (McpSecretRef("Authorization", "reference", True, server.location),)
                if bearer
                else ()
            )
            headers += tuple(
                McpSecretRef(k, "reference", True, server.location) for k in header_vars
            )
            variables = (
                *((bearer,) if isinstance(bearer, str) else ()),
                *header_vars.values(),
            )
            updated.append(
                replace(
                    server,
                    headers=(*server.headers, *headers),
                    env_names=tuple(dict.fromkeys((*server.env_names, *variables))),
                )
            )
        servers = tuple(updated)
        edges = tuple(
            edge
            for edge in edges
            if edge.subject is None or any(s.name == edge.subject for s in servers)
        )
    return servers, edges, (*diagnostics, *notes)


def _toml_mcp_locations(
    artifact: Artifact, text: str, locations: dict[tuple[str | int, ...], SourceRef]
) -> None:
    for line_number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s*\[mcp_servers\.([A-Za-z0-9_-]+)\]\s*(?:#.*)?$", line)
        if match:
            locations[("mcp_servers", match.group(1))] = SourceRef(
                artifact.path, artifact.source_format, line_number, line_number
            )


def parse_structured(
    artifact: Artifact,
    text: str,
    *,
    allow_bare_mcp: bool = True,
    claude_project: Path | None = None,
) -> Document:
    data, node = _load(artifact, text)
    if not isinstance(data, dict) or not all(isinstance(key, str) for key in data):
        raise ParseError("structured config requires an object with string keys")
    kilo = artifact.ecosystem == "Kilo Code" and artifact.path.name.lower() in {
        "kilo.json",
        "kilo.jsonc",
    }
    zed = (
        artifact.ecosystem == "Zed Agent"
        and artifact.kind == ArtifactKind.AGENT_CONFIG
        and artifact.path.name.lower() == "settings.json"
    )
    goose = (
        artifact.ecosystem == "Goose"
        and artifact.kind == ArtifactKind.AGENT_CONFIG
        and artifact.path.name == "config.yaml"
    )
    hermes = artifact.ecosystem == "Hermes Agent" and artifact.path.name == "config.yaml"
    codex = artifact.ecosystem == "Codex" and artifact.path.name == "config.toml"
    claude = artifact.ecosystem == "Claude Code" and artifact.path.name in {
        ".mcp.json",
        ".claude.json",
    }
    claude_settings = artifact.ecosystem == "Claude Code" and artifact.path.name.startswith(
        "settings"
    )
    claude_local_names: set[str] = set()
    claude_scope_diagnostics: tuple[str, ...] = ()
    if artifact.path.name == ".claude.json" and claude:
        # Project-local MCP state shares an auth-bearing file with user servers.
        # Project identity is exact and explicit: never inventory other projects.
        user_servers = data.get("mcpServers")
        projected: dict[str, Any] = {"mcpServers": user_servers} if "mcpServers" in data else {}
        projects = data.get("projects")
        if claude_project is not None and isinstance(projects, dict):
            local = projects.get(str(claude_project.absolute()))
            if isinstance(local, dict) and "mcpServers" in local:
                definitions = local["mcpServers"]
                if isinstance(definitions, dict) and isinstance(user_servers, dict):
                    projected["mcpServers"] = {**user_servers, **definitions}
                elif isinstance(definitions, dict) and user_servers is None:
                    projected["mcpServers"] = definitions
                else:
                    claude_scope_diagnostics = (
                        "unsupported Claude Code local MCP schema; ignored",
                    )
                if not claude_scope_diagnostics:
                    claude_local_names = {name for name in definitions if isinstance(name, str)}
        elif claude_project is not None and projects is not None:
            claude_scope_diagnostics = ("unsupported Claude Code project scope schema; ignored",)
        data = projected
    if claude_settings and "mcpServers" in data:
        data = {key: value for key, value in data.items() if key != "mcpServers"}
    if (
        allow_bare_mcp
        and not kilo
        and not zed
        and not goose
        and artifact.kind == ArtifactKind.MCP_CONFIG
        and "mcpServers" not in data
        and data
        and all(
            isinstance(server, dict) and ("command" in server or "url" in server)
            for server in data.values()
        )
    ):
        # Some agent/plugin configs use a bare server-name map rather than mcpServers.
        data = {"mcpServers": data}
    if (
        not kilo
        and not zed
        and artifact.kind == ArtifactKind.STRUCTURED_CONFIG
        and isinstance(data.get("mcpServers"), dict)
    ):
        artifact = replace(artifact, kind=ArtifactKind.MCP_CONFIG)
    entries = _entries(artifact, data, node)
    if zed:
        entries = tuple(
            replace(entry, value="[redacted]")
            if entry.key_path
            and entry.key_path[0] in {"context_servers", "mcpServers"}
            and isinstance(entry.value, str)
            else entry
            for entry in entries
        )
    if kilo:
        entries = tuple(
            replace(entry, value="[redacted]")
            if entry.key_path
            and entry.key_path[0] in {"mcp", "mcpServers"}
            and any(
                part in {"environment", "headers", "command", "url", "args"}
                for part in entry.key_path
                if isinstance(part, str)
            )
            and isinstance(entry.value, str)
            else entry
            for entry in entries
        )
    if goose:
        entries = tuple(
            replace(entry, value="[redacted]")
            if entry.key_path
            and entry.key_path[0] in {"extensions", "mcpServers"}
            and isinstance(entry.value, str)
            else entry
            for entry in entries
        )
    if hermes or codex or claude:
        field = "mcp_servers" if hermes or codex else "mcpServers"
        entries = tuple(
            replace(entry, value="[redacted]")
            if entry.key_path and entry.key_path[0] == field and isinstance(entry.value, str)
            else entry
            for entry in entries
        )
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
    if codex:
        _toml_mcp_locations(artifact, text, locations)
    servers, relationships, mcp_diagnostics = (
        _agent_mcp_servers(artifact, data, locations, "mcp_servers")
        if hermes or codex
        else _agent_mcp_servers(artifact, data, locations, "mcpServers")
        if claude
        else _goose_servers(artifact, data, locations)
        if goose
        else _kilo_servers(artifact, data, locations)
        if kilo
        else _zed_servers(artifact, data, locations)
        if zed
        else _servers(artifact, data, locations)
    )
    relations = list(relationships)
    if claude and artifact.path.name == ".claude.json":
        servers = tuple(
            replace(server, config_scope="local" if server.name in claude_local_names else "user")
            for server in servers
        )
    for entry in entries:
        key = entry.key_path[-1]
        if (
            (goose and entry.key_path and entry.key_path[0] in {"extensions", "mcpServers"})
            or ((hermes or codex) and entry.key_path and entry.key_path[0] == "mcp_servers")
            or (claude and entry.key_path and entry.key_path[0] == "mcpServers")
            or (kilo and entry.key_path and entry.key_path[0] in {"mcp", "mcpServers"})
            or (zed and entry.key_path and entry.key_path[0] in {"context_servers", "mcpServers"})
        ):
            continue
        if (
            kilo
            and len(entry.key_path) == 2
            and entry.key_path[0] == "instructions"
            and isinstance(key, int)
            and isinstance(entry.value, str)
            and not PurePath(entry.value).is_absolute()
            and ".." not in PurePath(entry.value).parts
            and PurePath(entry.value).suffix.lower() == ".md"
        ):
            relations.append(Relationship("loads_file", entry.value, entry.location))
        if kilo or zed or goose:
            continue
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
    dependencies, diagnostics = (
        structured_dependencies(artifact, data, locations)
        if artifact.kind == ArtifactKind.DEPENDENCY_MANIFEST
        else ((), ())
    )
    return Document(
        artifact,
        servers=servers,
        entries=entries,
        relationships=tuple(dict.fromkeys(relations)),
        dependencies=dependencies,
        diagnostics=(
            *diagnostics,
            *claude_scope_diagnostics,
            *mcp_diagnostics,
            *(
                ("unsupported Goose mcpServers schema; ignored",)
                if goose and "mcpServers" in data
                else ()
            ),
            *(
                ("unsupported Zed mcpServers schema; ignored",)
                if zed and "mcpServers" in data
                else ()
            ),
            *(
                ("unsupported Kilo mcpServers schema; ignored",)
                if kilo and "mcpServers" in data
                else ()
            ),
        ),
    )
