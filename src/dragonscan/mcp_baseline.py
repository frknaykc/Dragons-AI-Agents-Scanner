"""Local, explicitly approved MCP declaration inventories (no runtime or network I/O)."""

import hashlib
import json
import math
import os
import re
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from decimal import Decimal, DecimalException
from pathlib import Path
from typing import Any

_LIMIT = 512 * 1024
_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_STORE = ".dragonscan-mcp-approvals"


class BaselineError(ValueError):
    """Only locally generated diagnostics safe to display."""


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise BaselineError(reason)


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _digest(obj: Any) -> str:
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _decode(raw: bytes) -> dict[str, Any]:
    def bounded_float(token: str) -> float:
        value = float(token)
        _require(
            math.isfinite(value) and Decimal(token) == Decimal(str(value)),
            "unsupported numeric precision in metadata",
        )
        return value

    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_float=bounded_float)
        pending = [(data, 0)]
        count = 0
        while pending:
            value, depth = pending.pop()
            count += 1
            _require(count <= 32768 and depth <= 48, "metadata complexity limit exceeded")
            if isinstance(value, dict):
                pending.extend((v, depth + 1) for v in value.values())
            elif isinstance(value, list):
                pending.extend((v, depth + 1) for v in value)
        _canonical(data)  # Reject non-finite numbers, including overflow.
    except BaselineError:
        raise
    except (ValueError, UnicodeError, RecursionError, DecimalException):
        raise BaselineError("invalid JSON metadata") from None
    if not isinstance(data, dict):
        raise BaselineError("expected a JSON object")
    return data


@contextmanager
def _directory(path: Path, *, protected: bool = False) -> Iterator[int]:
    _require(
        os.name == "posix" and path.is_absolute() and ".." not in path.parts,
        "a local POSIX path without traversal is required",
    )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for name in path.parts[1:]:
            child = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            if protected:
                st = os.fstat(fd)
                _require(
                    st.st_uid in (0, os.getuid())
                    and (
                        not st.st_mode & 0o022 or st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)
                    ),
                    "approval store has an unsafe ancestor",
                )
        yield fd
    finally:
        os.close(fd)


def _read(parent: int, name: str, *, protected: bool = False) -> dict[str, Any]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(fd)
        _require(stat.S_ISREG(st.st_mode) and st.st_size <= _LIMIT, "invalid metadata file")
        if protected:
            _require(
                st.st_uid == os.getuid() and st.st_nlink == 1 and not st.st_mode & 0o077,
                "approval file must be private and owner-controlled",
            )
        raw = stream.read(_LIMIT + 1)
        _require(len(raw) <= _LIMIT, "metadata byte limit exceeded")
    return _decode(raw)


def _name(value: Any) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise BaselineError("unsupported server or tool identifier")
    return value


def inventory(config: Path) -> dict[str, Any]:
    path = config.absolute()
    _require(path.name not in (".", "..") and _STORE not in path.parts, "invalid source path")
    with _directory(path.parent) as parent:
        data = _read(parent, path.name)
    servers = data.get("mcpServers")
    if not isinstance(servers, dict) or len(servers) > 128:
        raise BaselineError("expected bounded mcpServers map")
    entries: dict[str, Any] = {}
    count = 0
    for key, server in servers.items():
        name = _name(key)
        _require(
            isinstance(server, dict) and isinstance(server.get("tools"), list),
            "explicit inline tools inventory required for every server",
        )
        tools: dict[str, Any] = {}
        for tool in server["tools"]:
            count += 1
            _require(count <= 1024 and isinstance(tool, dict), "invalid tool inventory")
            tool_name = _name(tool.get("name"))
            _require(
                tool_name not in tools and isinstance(tool.get("inputSchema"), dict),
                "ambiguous tool identity or missing input schema",
            )
            tools[tool_name] = {
                "schema": _digest(tool["inputSchema"]),
                "metadata": _digest(
                    {k: v for k, v in tool.items() if k not in ("inputSchema", "name")}
                ),
            }
        entries[name] = {
            "declaration": _digest({k: v for k, v in server.items() if k != "tools"}),
            "tools": tools,
        }
    return {"version": 1, "source": _digest(str(path)), "servers": entries}


@contextmanager
def _store(*, create: bool) -> Iterator[int]:
    home = Path.home()
    with _directory(home, protected=True) as parent:
        st = os.fstat(parent)
        _require(st.st_uid == os.getuid() and not st.st_mode & 0o022, "unsafe approval store home")
        if create:
            try:
                os.mkdir(_STORE, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        fd = os.open(_STORE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            st = os.fstat(fd)
            _require(
                st.st_uid == os.getuid() and not st.st_mode & 0o077,
                "approval directory must be private and owner-controlled",
            )
            yield fd
        finally:
            os.close(fd)


def _approved(fd: int, source: str) -> dict[str, Any]:
    saved = _read(fd, source + ".json", protected=True)
    old = saved.get("inventory")
    if not isinstance(old, dict) or old.get("version") != 1 or old.get("source") != source:
        raise BaselineError("invalid approval version or source")
    _require(saved.get("digest") == _digest(old), "approval digest mismatch")
    servers = old.get("servers")
    if not isinstance(servers, dict):
        raise BaselineError("invalid approved server inventory")
    for name, server in servers.items():
        _name(name)
        if not isinstance(server, dict) or not isinstance(server.get("tools"), dict):
            raise BaselineError("invalid approved server")
        _require(
            bool(_HASH.fullmatch(str(server.get("declaration")))), "invalid declaration digest"
        )
        for toolname, tool in server["tools"].items():
            _name(toolname)
            _require(
                isinstance(tool, dict)
                and all(
                    isinstance(tool.get(k), str) and _HASH.fullmatch(tool[k])
                    for k in ("schema", "metadata")
                ),
                "invalid approved tool digest",
            )
    return old


def _diff(old: dict[str, Any], new: dict[str, Any]) -> list[dict[str, str]]:
    result = []
    for name in sorted(old.keys() | new.keys()):
        if name not in old or name not in new:
            result.append(
                {"server": name, "change": "server_added" if name in new else "server_removed"}
            )
            continue
        before, after = old[name], new[name]
        if before["declaration"] != after["declaration"]:
            result.append({"server": name, "change": "server_changed"})
        a, b = before["tools"], after["tools"]
        for tool in sorted(a.keys() | b.keys()):
            key = {"server": name, "tool": tool}
            if tool not in a or tool not in b:
                result.append({**key, "change": "tool_added" if tool in b else "tool_removed"})
            else:
                for field in ("schema", "metadata"):
                    if a[tool][field] != b[tool][field]:
                        result.append({**key, "change": field + "_changed"})
    return result


def baseline(action: str, config: Path, expected: str = "") -> dict[str, Any]:
    current = inventory(config)
    digest = _digest(current)
    record = {"inventory": current, "digest": digest}
    if action == "review":
        return {"status": "candidate", **record}
    source = current["source"]
    approve = action == "approve"
    _require(approve or action == "compare", "invalid operation")
    if approve:
        _require(expected == digest, "candidate no longer matches reviewed digest")
    with _store(create=approve) as fd:
        try:
            old = _approved(fd, source)
        except FileNotFoundError:
            if not approve:
                raise BaselineError("approved snapshot missing") from None
            old = {}
        if not approve:
            changes = _diff(old["servers"], current["servers"])
            result: dict[str, Any] = {
                "status": "changed" if changes else "unchanged",
                "source": source,
                "approved_digest": _digest(old),
                "current_digest": digest,
                "changes": changes,
            }
            if changes:
                result["rule_id"] = "DRAGON-MCP-013"
            return result
        temp = ".pending-" + secrets.token_hex(16)
        temp_fd = os.open(
            temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
        )
        try:
            with os.fdopen(temp_fd, "wb") as stream:
                content = _canonical(record)
                _require(len(content) <= _LIMIT, "snapshot byte limit exceeded")
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, source + ".json", src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            try:
                os.unlink(temp, dir_fd=fd)
            except FileNotFoundError:
                pass
    return {"status": "approved", "source": source, "digest": digest}
