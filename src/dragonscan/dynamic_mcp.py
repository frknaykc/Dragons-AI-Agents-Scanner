"""Explicitly authorized, bounded POSIX stdio MCP metadata inspection.

Process groups and a private cwd are not OS filesystem or network sandboxes.
"""

import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from dragonscan.models import (
    Document,
    DynamicMcpComparison,
    DynamicMcpItem,
    DynamicMcpObservation,
    McpServer,
)

_STARTUP_SECONDS = 2.0
_SESSION_SECONDS = 5.0
_STDOUT_BYTES = 128 * 1024
_STDERR_BYTES = 32 * 1024
_MESSAGE_BYTES = 32 * 1024
_MAX_MESSAGES = 32
_MAX_ITEMS = 32
_MAX_NODES = 2048
_MAX_DEPTH = 20
_LIST_METHODS = ("tools/list", "prompts/list", "resources/list")
_BLOCKED_EXECUTABLES = {
    "npx",
    "uvx",
    "pipx",
    "bunx",
    "npm",
    "pnpm",
    "yarn",
    "sh",
    "bash",
    "zsh",
    "fish",
    "docker",
    "podman",
    "node",
    "python",
    "python3",
    "ruby",
    "perl",
    "curl",
    "wget",
}


@dataclass(frozen=True)
class DynamicPolicy:
    requested: bool = False
    allow_uncontained: bool = False
    server: str | None = None
    executable: Path | None = None


@dataclass(frozen=True)
class DynamicResult:
    status: str
    diagnostics: tuple[str, ...] = ()
    observations: tuple[DynamicMcpObservation, ...] = ()
    mode: str = "required_isolation"
    capabilities: dict[str, str] | None = None
    timings_ms: dict[str, float] | None = None


def available_capabilities() -> dict[str, str]:
    """What this implementation can enforce, not a claim about the current target."""
    posix = os.name == "posix"
    return {
        "environment_filtering": "available" if posix else "unsupported",
        "private_cwd": "available" if posix else "unsupported",
        "shell_free_launch": "available" if posix else "unsupported",
        "wall_timeout": "available" if posix else "unsupported",
        "output_and_protocol_limits": "available" if posix else "unsupported",
        "process_group_cleanup": "available" if posix else "unsupported",
        "filesystem_read_write": "unsupported",
        "network_denial": "unsupported",
        "cpu_memory_process_file_limits": "unsupported",
    }


class _SessionError(Exception):
    pass


def _validate(policy: DynamicPolicy, documents: tuple[Document, ...]) -> tuple[Document, McpServer]:
    if not policy.allow_uncontained:
        raise ValueError(
            "required isolation unavailable: filesystem read/write and network denial; "
            "uncontained execution requires separate legacy consent"
        )
    if not policy.server or policy.executable is None:
        raise ValueError("uncontained execution requires server name and executable")
    if os.name != "posix":
        raise ValueError("process groups and pipe multiplexing unavailable on this platform")
    matches = [
        (doc, server) for doc in documents for server in doc.servers if server.name == policy.server
    ]
    if len(matches) != 1:
        raise ValueError("server selection must match exactly one parsed MCP declaration")
    doc, server = matches[0]
    path = policy.executable
    if (
        server.transport != "stdio"
        or server.url is not None
        or server.args
        or server.env_names
        or server.cwd is not None
        or server.headers
        or server.package is not None
    ):
        raise ValueError("only local stdio without args, env, cwd or URL is supported")
    if not path.is_absolute() or not doc.artifact.path.is_absolute() or ".." in path.parts:
        raise ValueError("executable must be an absolute path without traversal")
    if path != Path(server.command) or not path.is_relative_to(doc.artifact.path.parent):
        raise ValueError("executable must match declared path inside config directory")
    if path.name.lower() in _BLOCKED_EXECUTABLES or path.suffix.lower() in {
        ".sh",
        ".bat",
        ".cmd",
        ".ps1",
    }:
        raise ValueError("shells and package or interpreter runners are unsupported")
    try:
        for part in (path, *path.parents):
            if stat.S_ISLNK(part.lstat().st_mode):
                raise ValueError("symlinked executable path is unsupported")
        info = path.stat()
    except OSError:
        raise ValueError("executable unavailable") from None
    if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        raise ValueError("executable must be a regular executable file")
    return doc, server


def _check_structure(root: Any) -> None:
    pending = [(root, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > _MAX_NODES or depth > _MAX_DEPTH:
            raise _SessionError("protocol complexity limit exceeded")
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)


def _items(result: dict[str, Any], kind: str) -> tuple[DynamicMcpItem, ...]:
    values = result.get(kind)
    if (
        not isinstance(values, list)
        or len(values) > _MAX_ITEMS
        or result.get("nextCursor") is not None
    ):
        raise _SessionError("metadata count or pagination limit exceeded")
    seen: set[str] = set()
    items: list[DynamicMcpItem] = []
    for value in values:
        if not isinstance(value, dict):
            raise _SessionError("invalid metadata entry")
        name, description = value.get("name"), value.get("description", "")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 128
            or name in seen
            or not isinstance(description, str)
            or len(description) > 2048
        ):
            raise _SessionError("invalid metadata name or description")
        if kind == "tools" and not isinstance(value.get("inputSchema"), dict):
            raise _SessionError("invalid tool schema")
        if kind == "resources" and (
            not isinstance(value.get("uri"), str) or len(value["uri"]) > 2048
        ):
            raise _SessionError("invalid resource URI")
        seen.add(name)
        try:
            digest = hashlib.sha256(description.encode()).hexdigest()
        except UnicodeError:
            raise _SessionError("invalid metadata description encoding") from None
        items.append(DynamicMcpItem(name, digest))
    return tuple(sorted(items, key=lambda item: item.name))


def _observation(
    doc: Document,
    server: McpServer,
    observed: dict[str, tuple[DynamicMcpItem, ...]],
    session_id: str = "",
) -> DynamicMcpObservation:
    comparison: list[DynamicMcpComparison] = []
    for kind in ("tools", "prompts", "resources"):
        static_names = tuple(item.name for item in getattr(server, kind))
        # No declared inventory is not an empty declared inventory; partial lists
        # cannot be compared to a complete static declaration either. Only
        # individual completed list methods appear in `observed`.
        if static_names and len(set(static_names)) == len(static_names) and kind in observed:
            comparison.extend(_compare_inventory(kind, static_names, observed[kind]))
    return DynamicMcpObservation(
        doc.artifact.path,
        server.name,
        session_id=session_id,
        observed_methods=("initialize", *(f"{kind}/list" for kind in observed)),
        tools=observed.get("tools", ()),
        prompts=observed.get("prompts", ()),
        resources=observed.get("resources", ()),
        inventory_comparison=tuple(comparison),
    )


def _compare_inventory(
    kind: str, declared: tuple[str, ...], observed: tuple[DynamicMcpItem, ...]
) -> tuple[DynamicMcpComparison, ...]:
    static, runtime = set(declared), {item.name for item in observed}
    return tuple(
        DynamicMcpComparison(
            kind,
            name,
            "declared_and_observed"
            if name in static and name in runtime
            else "declared_only"
            if name in static
            else "observed_only",
        )
        for name in sorted(static | runtime)
    )


class _Session:
    def __init__(self, process: subprocess.Popen[bytes]):
        self.process = process
        self.selector = selectors.DefaultSelector()
        self.stdout = bytearray()
        self.stdout_total = 0
        self.stderr_total = 0
        self.messages = 0
        self.session_deadline = time.monotonic() + _SESSION_SECONDS
        assert process.stdout is not None
        assert process.stderr is not None
        assert process.stdin is not None
        for pipe in (process.stdout, process.stderr):
            os.set_blocking(pipe.fileno(), False)
            self.selector.register(pipe, selectors.EVENT_READ)
        os.set_blocking(process.stdin.fileno(), False)

    def close(self) -> None:
        self.selector.close()

    def exchange(self, method: str, request_id: int, *, startup: bool = False) -> dict[str, Any]:
        assert self.process.stdin is not None and self.process.stdout is not None
        if (method, startup) != ("initialize", True) and (startup or method not in _LIST_METHODS):
            raise _SessionError("MCP method not allowed")
        deadline = (
            min(self.session_deadline, time.monotonic() + _STARTUP_SECONDS)
            if startup
            else self.session_deadline
        )
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if startup:
            message["params"] = {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "dragonscan", "version": "0"},
            }
        body = json.dumps(message).encode() + b"\n"
        self._write(body, deadline)
        return self._receive(request_id, deadline)

    def notify_initialized(self) -> None:
        self._write(
            b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
            self.session_deadline,
        )

    def _write(self, body: bytes, deadline: float) -> None:
        assert self.process.stdin is not None
        position = 0
        while position < len(body):
            if time.monotonic() >= deadline:
                raise _SessionError("session timeout")
            try:
                position += os.write(self.process.stdin.fileno(), body[position:])
            except BlockingIOError:
                self._pump(deadline)
            except (BrokenPipeError, OSError):
                raise _SessionError("server early exit") from None

    def _pump(self, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _SessionError("session timeout")
        for key, _ in self.selector.select(min(remaining, 0.1)):
            stream = key.fileobj
            try:
                chunk = os.read(key.fd, 4096)
            except OSError:
                raise _SessionError("server pipe failure") from None
            if not chunk:
                self.selector.unregister(stream)
                continue
            if stream is self.process.stdout:
                self.stdout_total += len(chunk)
                if self.stdout_total > _STDOUT_BYTES:
                    raise _SessionError("stdout limit exceeded")
                self.stdout.extend(chunk)
                if (
                    len(self.stdout) > _MESSAGE_BYTES
                    and b"\n" not in self.stdout[: _MESSAGE_BYTES + 1]
                ):
                    raise _SessionError("message size limit exceeded")
            else:
                self.stderr_total += len(chunk)
                if self.stderr_total > _STDERR_BYTES:
                    raise _SessionError("stderr limit exceeded")

    def _receive(self, request_id: int, deadline: float) -> dict[str, Any]:
        while True:
            boundary = self.stdout.find(b"\n")
            if boundary >= 0:
                if boundary > _MESSAGE_BYTES:
                    raise _SessionError("message size limit exceeded")
                line = bytes(self.stdout[:boundary])
                del self.stdout[: boundary + 1]
                self.messages += 1
                if self.messages > _MAX_MESSAGES:
                    raise _SessionError("protocol message count exceeded")
                try:
                    response = json.loads(line)
                except (ValueError, UnicodeError, RecursionError):
                    raise _SessionError("malformed protocol response") from None
                _check_structure(response)
                if (
                    not isinstance(response, dict)
                    or response.get("jsonrpc") != "2.0"
                    or type(response.get("id")) is not int
                    or response["id"] != request_id
                    or "error" in response
                    or not isinstance(response.get("result"), dict)
                ):
                    raise _SessionError("invalid protocol response or ID")
                return cast(dict[str, Any], response["result"])
            if not self.selector.get_map():
                raise _SessionError("server early exit")
            self._pump(deadline)


def _run(doc: Document, server: McpServer, executable: Path) -> DynamicResult:
    started = time.monotonic()
    timings: dict[str, float] = {}
    with tempfile.TemporaryDirectory(
        prefix="dragonscan-mcp-", dir=os.environ.get("TMPDIR")
    ) as workspace:
        # No shell, inherited env, target cwd, output accumulation or package resolution.
        try:
            process = subprocess.Popen(
                [str(executable)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=workspace,
                env={"PATH": "/usr/bin:/bin"},
                shell=False,
                start_new_session=True,
                close_fds=True,
            )
        except OSError:
            return DynamicResult("failed", ("server launch failed",), timings_ms=timings)
        timings["startup"] = round((time.monotonic() - started) * 1000, 3)
        session: _Session | None = None
        session_id = uuid.uuid4().hex
        observed: dict[str, tuple[DynamicMcpItem, ...]] = {}
        try:
            session = _Session(process)
            phase = time.monotonic()
            init = session.exchange("initialize", 1, startup=True)
            timings["initialize"] = round((time.monotonic() - phase) * 1000, 3)
            capabilities = init.get("capabilities")
            server_info = init.get("serverInfo")
            if (
                init.get("protocolVersion") != "2025-03-26"
                or not isinstance(capabilities, dict)
                or not isinstance(server_info, dict)
                or any(
                    not isinstance(server_info.get(key), str)
                    or not 0 < len(server_info[key]) <= 128
                    for key in ("name", "version")
                )
            ):
                raise _SessionError("invalid initialize response")
            session.notify_initialized()
            for index, kind in enumerate(("tools", "prompts", "resources"), start=2):
                if kind in capabilities:
                    if not isinstance(capabilities[kind], dict):
                        raise _SessionError("invalid capability declaration")
                    phase = time.monotonic()
                    observed[kind] = _items(session.exchange(f"{kind}/list", index), kind)
                    timings[f"{kind}/list"] = round((time.monotonic() - phase) * 1000, 3)
            result = DynamicResult(
                "completed",
                observations=(_observation(doc, server, observed, session_id),),
                timings_ms=timings,
            )
        except _SessionError as exc:
            # No raw stdout/stderr, environment, executable path or exception detail.
            result = DynamicResult(
                "partial" if observed else "failed",
                (str(exc),),
                (_observation(doc, server, observed, session_id),) if observed else (),
                timings_ms=timings,
            )
        finally:
            try:
                if session is not None:
                    session.close()
            finally:
                cleaned = _terminate(process)
                timings["total"] = round((time.monotonic() - started) * 1000, 3)
        if not cleaned:
            return DynamicResult(
                "partial" if result.observations else "failed",
                (*result.diagnostics, "process group cleanup not confirmed"),
                result.observations,
                timings_ms=timings,
            )
        return result


def _terminate(process: subprocess.Popen[bytes]) -> bool:
    group_signalled = True
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass  # The group has already gone away.
    except OSError:
        group_signalled = False
        # The process may already have exited. A fallback kill must survive that race.
        try:
            if process.poll() is None:
                process.kill()
        except OSError:
            group_signalled = False
    for pipe in (process.stdin, process.stdout, process.stderr):
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass
    reaped = True
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        reaped = False
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1)
            reaped = True
        except subprocess.TimeoutExpired:
            # An uninterruptible child must not hang the static scan indefinitely.
            pass
    return group_signalled and reaped


def inspect(documents: tuple[Document, ...], policy: DynamicPolicy) -> DynamicResult:
    """Only this lower-layer gate may launch a process; config cannot grant consent."""
    if not policy.requested:
        return DynamicResult("not_requested")
    mode = "legacy_uncontained" if policy.allow_uncontained else "required_isolation"
    capabilities = available_capabilities()
    try:
        doc, server = _validate(policy, documents)
    except ValueError as exc:
        return DynamicResult("blocked", (str(exc),), mode=mode, capabilities=capabilities)
    assert policy.executable is not None
    try:
        result = _run(doc, server, policy.executable)
        return DynamicResult(
            result.status,
            result.diagnostics,
            result.observations,
            mode,
            capabilities,
            result.timings_ms,
        )
    except (OSError, ValueError):
        return DynamicResult(
            "failed",
            ("dynamic inspection infrastructure failed",),
            mode=mode,
            capabilities=capabilities,
        )
