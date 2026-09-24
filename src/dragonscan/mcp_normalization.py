"""Static MCP metadata normalization; no server, command, or URL is contacted."""

import re
from pathlib import PurePath
from typing import Any
from urllib.parse import urlsplit

from dragonscan.models import McpContent, McpSecretRef, McpTool, SourceRef
from dragonscan.parse_errors import ParseError
from dragonscan.parse_helpers import safe_url

_REFERENCE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$env:[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%"
)
_SENSITIVE = re.compile(
    r"(?i)(?:token|secret|password|passwd|api[_-]?key|credential|auth|private|ssh)"
)
_EXACT = re.compile(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?\Z")


def safe_mcp_url(value: str) -> str | None:
    """Retain origin and common public MCP route, never opaque bearer paths."""
    normalized = safe_url(value)
    if normalized is None:
        return None
    parts = urlsplit(normalized)
    public_path = parts.path if parts.path in {"/mcp", "/sse", "/api/mcp", "/v1/mcp"} else ""
    return f"{parts.scheme}://{parts.netloc}{public_path}"


def secret_refs(
    values: Any, location: SourceRef, *, headers: bool = False
) -> tuple[McpSecretRef, ...]:
    if values is None:
        return ()
    if not isinstance(values, dict) or not all(isinstance(key, str) for key in values):
        raise ParseError("invalid MCP environment or headers")
    result: list[McpSecretRef] = []
    for key, value in values.items():
        if not isinstance(value, str):
            raise ParseError("invalid MCP environment or header value")
        reference = bool(_REFERENCE.search(value))
        # Do not store the value, even when it appears harmless.
        origin = (
            "reference"
            if reference and _REFERENCE.fullmatch(value.strip().removeprefix("Bearer "))
            else "literal"
        )
        result.append(McpSecretRef(key, origin, bool(_SENSITIVE.search(key)), location))
    return tuple(result)


def invocation(
    command: str, args: tuple[str, ...]
) -> tuple[str | None, str | None, str | None, str | None]:
    runtime = PurePath(command.replace("\\", "/")).name.lower() or None
    package: str | None = None
    tokens = args
    if runtime in {"npx", "npx.cmd", "uvx", "pipx", "pipx.exe"}:
        package = next((arg for arg in args if not arg.startswith("-")), None)
    elif runtime in {"npm", "pnpm", "yarn", "npm.cmd", "pnpm.cmd", "yarn.cmd"}:
        if args and args[0] in {"exec", "dlx"}:
            tokens = args[1:]
            package = next((arg for arg in tokens if not arg.startswith("-")), None)
    elif runtime in {"python", "python3", "python.exe", "python3.exe"}:
        if len(args) > 1 and args[0] == "-m":
            package = args[1]
    elif runtime in {"docker", "podman", "nerdctl", "docker.exe", "podman.exe"}:
        if args and args[0] == "run":
            index = 1
            value_flags = {
                "-e",
                "--env",
                "-v",
                "--volume",
                "-w",
                "--workdir",
                "--name",
                "--network",
                "-p",
                "--publish",
                "-u",
                "--user",
            }
            while index < len(args):
                if args[index] in value_flags:
                    index += 2
                elif args[index].startswith("-"):
                    index += 1
                else:
                    package = args[index]
                    break
    if package is None:
        return runtime, None, None, None
    if runtime in {"docker", "podman", "nerdctl", "docker.exe", "podman.exe"}:
        if "@sha256:" in package:
            return runtime, package.split("@sha256:", 1)[0], "sha256 digest", "digest"
        image, sep, tag = package.rpartition(":")
        if sep and tag and "/" not in tag:
            return runtime, image, tag, "tag"
        return runtime, package, None, "unversioned"
    # Scoped npm packages use their last @ as the version delimiter.
    base, separator, version = package.rpartition("@")
    if separator and base and version:
        return runtime, base, version, "exact" if _EXACT.fullmatch(version) else "range"
    if runtime in {"python", "python3", "python.exe", "python3.exe"}:
        return runtime, package, None, "module"
    if any(mark in package for mark in ("==", ">=", "<=")):
        base = re.split(r"[<>=!]", package, maxsplit=1)[0]
        version = package[len(base) :]
        pinning = "exact" if version.startswith("==") and _EXACT.fullmatch(version[2:]) else "range"
        return runtime, base, version, pinning
    return runtime, package, None, "unversioned"


def _metadata(
    items: Any,
    location: SourceRef,
    locations: dict[tuple[str | int, ...], SourceRef],
    prefix: tuple[str | int, ...],
    kind: str,
) -> tuple[McpTool | McpContent, ...]:
    if items is None:
        return ()
    if not isinstance(items, list):
        raise ParseError("invalid MCP metadata list")
    if len(items) > 4096:
        raise ParseError("MCP metadata list exceeds static analysis limit")
    result: list[McpTool | McpContent] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ParseError("invalid MCP metadata entry")
        name = item["name"]
        if not name or name in seen:
            raise ParseError("duplicate or empty MCP metadata name")
        seen.add(name)
        description = item.get("description", "")
        if not isinstance(description, str):
            raise ParseError("invalid MCP metadata description")
        ref = locations.get((*prefix, kind, index), location)
        if kind == "tools":
            instructions = item.get("instructions", "")
            schema = item.get("inputSchema", {})
            if not isinstance(instructions, str) or not isinstance(schema, dict):
                raise ParseError("invalid MCP tool metadata")
            fields = schema.get("properties", {})
            if not isinstance(fields, dict) or not all(isinstance(k, str) for k in fields):
                raise ParseError("invalid MCP tool input schema")
            result.append(
                McpTool(name, description[:4096], instructions[:4096], tuple(fields), ref)
            )
        else:
            uri = item.get("uri")
            if uri is not None and not isinstance(uri, str):
                raise ParseError("invalid MCP content URI")
            try:
                scheme = urlsplit(uri).scheme.lower() if uri else ""
            except ValueError as exc:
                raise ParseError("invalid MCP content URI") from exc
            result.append(
                McpContent(
                    name,
                    description[:4096],
                    ref,
                    safe_mcp_url(uri) if uri and scheme in {"http", "https"} else None,
                    scheme if scheme in {"http", "https", "file"} else "other" if uri else None,
                )
            )
    return tuple(result)


def metadata(
    items: Any,
    location: SourceRef,
    locations: dict[tuple[str | int, ...], SourceRef],
    prefix: tuple[str | int, ...],
    kind: str,
) -> tuple[McpTool | McpContent, ...]:
    return _metadata(items, location, locations, prefix, kind)


def mutable_url(config: dict[str, Any]) -> str | None:
    value = config.get("toolsUrl")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ParseError("invalid MCP tool metadata URL")
    result = safe_mcp_url(value)
    if result is None:
        raise ParseError("invalid MCP tool metadata URL")
    return result


def transport(value: str | None, command: str, url: str | None) -> str:
    if value is not None:
        known = {
            "stdio": "stdio",
            "http": "http",
            "sse": "sse",
            "streamable-http": "streamable_http",
            "streamable_http": "streamable_http",
        }
        return known.get(value.lower(), "unknown")
    if command:
        return "stdio"
    if url:
        return "http"
    return "unknown"
