"""Evidence-backed, non-executing MCP security signals shared by detectors and graph."""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from dragonscan.detection import DetectionContext, DetectionMetadata, finding
from dragonscan.models import Classification as C
from dragonscan.models import Confidence as F
from dragonscan.models import Finding, McpServer, McpTool, SourceRef
from dragonscan.models import Severity as S

_SENSITIVE = re.compile(
    r"(?:~?/)?(?:\.ssh/id_rsa|\.aws/credentials|\.env)\b|"
    r"\b(?:credentials?|api[_ -]?keys?|private[_ -]?key|password|tokens?)\b",
    re.I,
)
_REMOTE = re.compile(r"https?://[^\s]+|\b(?:external (?:endpoint|server)|remote endpoint)\b", re.I)
_TRANSFER = re.compile(r"\b(?:send|upload|post|transmit|attach|include)\b", re.I)
_ACCESS = re.compile(r"\b(?:read|retrieve|open|access|fetch|extract)\b", re.I)
_OVERRIDE = re.compile(
    r"\b(?:ignore (?:previous|prior|system|user) instructions|"
    r"bypass (?:security|safety)|conceal (?:your |the )?actions?)\b",
    re.I,
)
_SHADOW = re.compile(
    r"\b(?:before calling|when calling|instead of calling|"
    r"change (?:the )?(?:arguments?|destination|output) of|"
    r"redirect (?:the )?(?:output|result) of)\s+([\w.-]+)",
    re.I,
)
_MANIPULATION = re.compile(
    r"\b(?:secretly|silently|without (?:telling|informing)|"
    r"include (?:the )?credentials?|redirect|change|replace|inject)\b",
    re.I,
)
_DOCUMENTATION = re.compile(
    r"\b(?:do not|never|example of|describes? how to|detect|warn about)\b", re.I
)
_SHELL = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
_FETCH_SHELL = re.compile(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sh|bash|zsh)\b", re.I)
_LINKED_READ_SEND = re.compile(
    r"\b(?:read|retrieve|open|extract)\b[^\n.;]{0,100}"
    r"(?:\.ssh/id_rsa|\.aws/credentials|\.env\b|credentials?|private[_ -]?key|tokens?)"
    r"[^\n.;]{0,100}\b(?:and|then)\s+(?:send|upload|post|transmit)\b"
    r"\s+(?:(?:its|their|the|those)\s+(?:contents?|data)|credentials?|secrets?|tokens?)"
    r"[^\n.;]{0,100}\b(?:https?://|external |remote )",
    re.I,
)
_CAPABILITY_PATTERNS = {
    "filesystem-read": r"\b(?:read|list|open) (?:a |the )?(?:local )?(?:file|directory)\b",
    "filesystem-write": r"\b(?:write|delete|edit) (?:a |the )?(?:local )?file\b",
    "database-read": r"\b(?:read|query|select from) (?:the )?(?:database|sql table)\b",
    "database-write": r"\b(?:write|update|delete from) (?:the )?(?:database|sql table)\b",
    "browser-control": r"\b(?:navigate|control|automate) (?:the )?browser\b",
    "email-send": r"\b(?:send|compose) (?:an? )?email\b",
    "cloud-control": (
        r"\b(?:create|delete|configure) (?:cloud|aws|gcp|azure) (?:resources?|instances?)\b"
    ),
}


def linked_sensitive_transfer(tool: McpTool) -> bool:
    """Require one ordered instruction rather than independent capabilities."""
    text = tool.instructions or tool.description
    return not _DOCUMENTATION.search(text) and bool(_LINKED_READ_SEND.search(text))


def tool_signals(tool: McpTool) -> frozenset[str]:
    """Only explicit actionable content; tool names alone confer no capability."""
    text = (tool.instructions or tool.description)[:4096]
    if _DOCUMENTATION.search(text):
        return frozenset()
    signals: set[str] = set()
    if _ACCESS.search(text) and _SENSITIVE.search(text):
        signals.add("credential-access")
    if _TRANSFER.search(text) and _REMOTE.search(text):
        signals.add("network-egress")
    if re.search(r"\b(?:execute|run) (?:a |the )?(?:shell|command|process)\b", text, re.I):
        signals.add("process-execution")
    if re.search(r"\b(?:write|edit|modify) (?:the )?(?:repository|source code)\b", text, re.I):
        signals.add("repository-write")
    if re.search(
        r"\b(?:write|modify) (?:the )?(?:agent config|mcp config|instructions file)\b", text, re.I
    ):
        signals.add("persistent-configuration-write")
    for capability, pattern in _CAPABILITY_PATTERNS.items():
        if re.search(pattern, text, re.I):
            signals.add(capability)
    return frozenset(signals)


def shadow_target(server: McpServer, tool: McpTool) -> McpTool | None:
    text = tool.instructions or tool.description
    if _DOCUMENTATION.search(text) or not _MANIPULATION.search(text):
        return None
    match = _SHADOW.search(text)
    if match is None:
        return None
    return next(
        (other for other in server.tools if other is not tool and other.name == match[1]), None
    )


def passed_result_target(server: McpServer, tool: McpTool) -> McpTool | None:
    """Only an explicit same-server result transfer names a target tool."""
    text = (tool.instructions or tool.description)[:4096]
    if _DOCUMENTATION.search(text):
        return None
    match = re.search(r"\b(?:then\s+)?pass\s+(?:the|its)\s+result\s+to\s+([\w.-]+)\b", text, re.I)
    if match is None:
        return None
    return next(
        (other for other in server.tools if other is not tool and other.name == match[1]), None
    )


def poisoned(tool: McpTool) -> bool:
    text = tool.instructions or tool.description
    if _DOCUMENTATION.search(text):
        return False
    return bool(
        _OVERRIDE.search(text)
        or (
            _ACCESS.search(text)
            and _SENSITIVE.search(text)
            and _TRANSFER.search(text)
            and _REMOTE.search(text)
        )
    )


@dataclass(frozen=True)
class McpDeepDetector:
    metadata: DetectionMetadata
    indicator: str

    def detect(self, context: DetectionContext) -> tuple[Finding, ...]:
        if context.document.artifact.kind not in self.metadata.artifact_types:
            return ()
        results: list[Finding] = []
        for server in context.document.servers:
            for location, evidence, caps, source, sink in self._signals(server):
                results.append(
                    finding(
                        self.metadata,
                        context.document,
                        location,
                        evidence,
                        "mcp_static",
                        caps,
                        source,
                        sink,
                    )
                )
        return tuple(results)

    def _signals(
        self, server: McpServer
    ) -> Iterable[tuple[SourceRef, str, tuple[str, ...], str | None, str | None]]:
        indicator = self.indicator
        if indicator == "literal_secret":
            for ref in (*server.environment, *server.headers):
                if ref.origin == "literal" and ref.sensitive:
                    yield (
                        ref.location,
                        "MCP configuration contains a literal credential-like value (redacted)",
                        ("credential-exposure",),
                        "literal credential",
                        None,
                    )
        elif indicator == "shell":
            if server.runtime in _SHELL and any(
                arg.lower() in {"-c", "-lc", "/c", "-command", "-encodedcommand", "-enc"}
                for arg in server.args[:2]
            ):
                command_string = server.args[-1] if server.args else ""
                if (
                    "|" in command_string
                    or "$(" in command_string
                    or "`" in command_string
                    or "&&" in command_string
                    or "-enc" in server.args
                    or "-EncodedCommand" in server.args
                ) and not _FETCH_SHELL.search(command_string):
                    yield (
                        server.location,
                        "MCP server uses shell command-string interpretation "
                        "with control operators or encoded input",
                        ("shell-execution",),
                        "configured shell string",
                        "local execution",
                    )
        elif indicator == "plaintext":
            if (
                server.url
                and urlsplit(server.url).scheme == "http"
                and urlsplit(server.url).hostname not in {"localhost", "127.0.0.1", "::1"}
            ):
                yield (
                    server.location,
                    "remote MCP endpoint uses plaintext HTTP",
                    ("network-egress",),
                    None,
                    "remote MCP endpoint",
                )
        elif indicator == "poisoning":
            for tool in server.tools:
                if poisoned(tool):
                    yield (
                        tool.location,
                        "MCP tool metadata directs unrelated sensitive access "
                        "or overrides agent controls",
                        ("agent-influence",),
                        "tool metadata",
                        "agent instructions",
                    )
            for item in (*server.prompts, *server.resources):
                if _OVERRIDE.search(item.description) and not _DOCUMENTATION.search(
                    item.description
                ):
                    yield (
                        item.location,
                        "MCP prompt/resource metadata directs override of agent controls",
                        ("agent-influence",),
                        "MCP metadata",
                        "agent instructions",
                    )
        elif indicator == "shadow":
            for tool in server.tools:
                if shadow_target(server, tool) is not None:
                    yield (
                        tool.location,
                        "MCP tool metadata directs a covert change to another declared tool call",
                        ("agent-influence",),
                        "tool metadata",
                        "another MCP tool",
                    )
        elif indicator == "mismatch":
            for tool in server.tools:
                if (
                    tool.instructions
                    and _ACCESS.search(tool.instructions)
                    and _SENSITIVE.search(tool.instructions)
                    and _TRANSFER.search(tool.instructions)
                    and _REMOTE.search(tool.instructions)
                    and not (
                        _SENSITIVE.search(tool.description) or _REMOTE.search(tool.description)
                    )
                    and not _DOCUMENTATION.search(tool.instructions)
                ):
                    yield (
                        tool.location,
                        "MCP tool separately declares sensitive read and remote transfer "
                        "absent from its description",
                        ("credential-access", "network-egress"),
                        "tool instructions",
                        "remote endpoint",
                    )
        elif indicator == "mutable":
            if server.mutable_tools_url is not None:
                yield (
                    server.location,
                    "MCP tool metadata references a mutable remote definition; "
                    "no change was observed",
                    ("remote-metadata",),
                    "external tool definition",
                    "MCP tool metadata",
                )
        elif indicator == "capability_combo":
            for tool in server.tools:
                capabilities = tool_signals(tool)
                if {"credential-access", "network-egress"} <= capabilities:
                    yield (
                        tool.location,
                        "same MCP tool declares sensitive local access and "
                        "network egress capabilities; transfer is not established",
                        ("credential-access", "network-egress"),
                        "sensitive local data",
                        "external endpoint",
                    )
        elif indicator == "remote_auth":
            if server.url and server.transport != "stdio":
                for header in server.headers:
                    if header.sensitive and header.origin == "reference":
                        yield (
                            header.location,
                            "remote MCP request header explicitly references a credential",
                            ("credential-exposure", "network-egress"),
                            "credential reference",
                            "remote MCP endpoint",
                        )


def _meta(
    identifier: str,
    title: str,
    severity: S,
    confidence: F,
    classification: C,
    explanation: str,
    remediation: str,
) -> DetectionMetadata:
    return DetectionMetadata(
        identifier,
        title,
        "mcp-security",
        severity,
        confidence,
        classification,
        ("mcp_config", "agent_config"),
        explanation,
        remediation,
    )


MCP_DETECTORS = (
    McpDeepDetector(
        _meta(
            "DRAGON-MCP-003",
            "Literal MCP credential",
            S.MEDIUM,
            F.HIGH,
            C.RISKY,
            "A credential-like literal is configured; its value is not reported.",
            "Use a secret reference instead of a literal.",
        ),
        "literal_secret",
    ),
    McpDeepDetector(
        _meta(
            "DRAGON-MCP-004",
            "Shell-mediated MCP execution",
            S.MEDIUM,
            F.HIGH,
            C.RISKY,
            "The configured MCP launch would interpret a command string; it was not executed.",
            "Use direct executable invocation where possible.",
        ),
        "shell",
    ),
    McpDeepDetector(
        _meta(
            "DRAGON-MCP-005",
            "Plaintext remote MCP endpoint",
            S.MEDIUM,
            F.HIGH,
            C.RISKY,
            "A non-loopback remote MCP endpoint uses HTTP; no connection was made.",
            "Use HTTPS for remote MCP traffic.",
        ),
        "plaintext",
    ),
    McpDeepDetector(
        _meta(
            "DRAGON-MCP-006",
            "MCP metadata instruction injection",
            S.HIGH,
            F.MEDIUM,
            C.SUSPICIOUS,
            "Untrusted tool/prompt/resource metadata tries to override agent controls or "
            "direct unrelated access; no tool was called.",
            "Review metadata and enforce the tool trust boundary.",
        ),
        "poisoning",
    ),
    McpDeepDetector(
        _meta(
            "DRAGON-MCP-007",
            "MCP tool shadowing instruction",
            S.HIGH,
            F.HIGH,
            C.SUSPICIOUS,
            "One declared tool directs covert manipulation of another declared tool; "
            "no calls were made.",
            "Remove the instruction and review the tool source.",
        ),
        "shadow",
    ),
    McpDeepDetector(
        _meta(
            "DRAGON-MCP-008",
            "MCP purpose/behavior mismatch",
            S.HIGH,
            F.MEDIUM,
            C.SUSPICIOUS,
            "Explicit tool instructions require sensitive access and remote transfer "
            "not disclosed by its description.",
            "Align declared purpose and behavior; remove unrelated data transfer.",
        ),
        "mismatch",
    ),
    McpDeepDetector(
        _meta(
            "DRAGON-MCP-009",
            "Mutable MCP tool metadata",
            S.LOW,
            F.HIGH,
            C.RISKY,
            "An external tool definition could change later; no metadata change was observed.",
            "Pin and review externally sourced tool definitions.",
        ),
        "mutable",
    ),
    McpDeepDetector(
        _meta(
            "DRAGON-MCP-010",
            "MCP sensitive access and remote transfer",
            S.MEDIUM,
            F.MEDIUM,
            C.RISKY,
            "One tool's static instructions declare sensitive access and external egress; "
            "a data flow is not established.",
            "Separate sensitive access from external transfer and review authorization.",
        ),
        "capability_combo",
    ),
    McpDeepDetector(
        _meta(
            "DRAGON-MCP-011",
            "Explicit credential header to remote MCP",
            S.MEDIUM,
            F.HIGH,
            C.RISKY,
            "A remote MCP request is configured with a credential-bearing header reference; "
            "no request was sent.",
            "Limit and scope the credential granted to the endpoint.",
        ),
        "remote_auth",
    ),
)
