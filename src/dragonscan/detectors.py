"""Declarative, behavioral, source/sink and indicator detectors over normalized IR."""

from dataclasses import dataclass

from dragonscan.behavior import (
    related_transfer,
    shell_accesses,
    shell_command_string,
    shell_executions,
)
from dragonscan.command_semantics import (
    POWERSHELL,
    literal_encoded_pipeline,
    selected_command,
    selected_powershell_execution,
)
from dragonscan.detection import DetectionContext, DetectionMetadata, EngineDetector, finding
from dragonscan.mcp_security import MCP_DETECTORS
from dragonscan.models import Classification as C
from dragonscan.models import Confidence as F
from dragonscan.models import Finding
from dragonscan.models import Severity as S

_MARKDOWN = ("instructions", "skill", "memory", "soul", "agent_config")
_MCP = ("mcp_config", "agent_config")
_OBSERVATION_KINDS = frozenset(
    {
        "override",
        "bypass",
        "remote_execution",
        "remote_python_execution",
        "powershell_execution",
        "persistence",
        "os_persistence",
        "remote_trust",
        "sensitive_access",
        "external_transfer",
        "bidi",
    }
)


def _meta(
    identifier: str,
    title: str,
    category: str,
    severity: S,
    confidence: F,
    classification: C,
    kinds: tuple[str, ...],
    explanation: str,
    remediation: str,
) -> DetectionMetadata:
    return DetectionMetadata(
        identifier,
        title,
        category,
        severity,
        confidence,
        classification,
        kinds,
        explanation,
        remediation,
    )


@dataclass(frozen=True)
class DeclarativeDetector:
    """A validated exact observation condition, not a custom regex language."""

    metadata: DetectionMetadata
    observation_kind: str
    evidence: str

    def __post_init__(self) -> None:
        if self.observation_kind not in _OBSERVATION_KINDS or not self.evidence:
            raise ValueError("declarative condition requires a known action and evidence")

    def detect(self, context: DetectionContext) -> tuple[Finding, ...]:
        if context.document.artifact.kind not in self.metadata.artifact_types:
            return ()
        return tuple(
            finding(
                self.metadata,
                context.document,
                observation.location,
                self.evidence,
                "declarative",
                observation.capabilities,
            )
            for observation in context.observations
            if observation.kind == self.observation_kind
        )


def _fenced_execution_findings(
    context: DetectionContext, metadata: DetectionMetadata, kind: str
) -> tuple[Finding, ...]:
    if kind not in {
        "remote_execution",
        "remote_python_execution",
        "literal_encoded_execution",
        "powershell_execution",
    }:
        return ()
    return tuple(
        finding(
            metadata,
            context.document,
            execution.location,
            f"explicit run directive links {execution.source} to {execution.sink} "
            "in a shell code block",
            "behavioral",
            execution.capabilities,
            execution.source,
            execution.sink,
        )
        for execution in shell_executions(context.document)
        if execution.kind == kind
    )


@dataclass(frozen=True)
class BehavioralDetector:
    metadata: DetectionMetadata
    observation_kind: str
    evidence: str
    source: str | None = None
    sink: str | None = None

    def __post_init__(self) -> None:
        if self.observation_kind not in _OBSERVATION_KINDS or not self.evidence:
            raise ValueError("behavioral detector requires a known action and evidence")

    def detect(self, context: DetectionContext) -> tuple[Finding, ...]:
        if context.document.artifact.kind not in self.metadata.artifact_types:
            return ()
        return tuple(
            finding(
                self.metadata,
                context.document,
                observation.location,
                self.evidence,
                "behavioral",
                observation.capabilities,
                self.source,
                observation.label
                if self.observation_kind in {"persistence", "os_persistence"}
                else self.sink,
            )
            for observation in context.observations
            if observation.kind == self.observation_kind
        ) + _fenced_execution_findings(context, self.metadata, self.observation_kind)


@dataclass(frozen=True)
class PowerShellDetector(BehavioralDetector):
    def detect(self, context: DetectionContext) -> tuple[Finding, ...]:
        results = super().detect(context)
        return results + tuple(
            finding(
                self.metadata,
                context.document,
                server.location,
                self.evidence,
                "behavioral",
                ("network-fetch", "command-execution"),
                self.source,
                self.sink,
            )
            for server in context.document.servers
            if server.runtime in POWERSHELL
            and (command := selected_command(server.runtime, server.args))
            and selected_powershell_execution(command)
        )


@dataclass(frozen=True)
class EncodedExecutionDetector:
    metadata: DetectionMetadata

    def detect(self, context: DetectionContext) -> tuple[Finding, ...]:
        if context.document.artifact.kind not in self.metadata.artifact_types:
            return ()
        return tuple(
            finding(
                self.metadata,
                context.document,
                observation.location,
                "literal encoded input is decoded and piped to an interpreter",
                "behavioral",
                observation.capabilities,
                "literal encoded input",
                observation.label,
            )
            for observation in context.observations
            if observation.kind == "literal_encoded_execution"
        ) + _fenced_execution_findings(context, self.metadata, "literal_encoded_execution")


@dataclass(frozen=True)
class SourceSinkDetector:
    metadata: DetectionMetadata
    access_metadata: DetectionMetadata

    def detect(self, context: DetectionContext) -> tuple[Finding, ...]:
        if context.document.artifact.kind not in self.metadata.artifact_types:
            return ()
        results: list[Finding] = []
        for link in (item for item in context.observations if item.kind == "credential_link"):
            results.append(
                finding(
                    self.metadata,
                    context.document,
                    link.location,
                    f"instruction places {link.label} in an external link query; "
                    "following the link would disclose the value",
                    "source_sink",
                    link.capabilities,
                    link.label,
                    "external HTTP(S) endpoint",
                )
            )
        sources = (item for item in context.observations if item.kind == "sensitive_access")
        for source in sources:
            # The older ID retains its finding for the already-covered source/sink case.
            if any(
                f.detection_id == "DAAS-001" and f.line == source.location.line
                for f in context.prior_findings
            ):
                continue
            sink = related_transfer(source, context.observations)
            if sink is not None:
                results.append(
                    finding(
                        self.metadata,
                        context.document,
                        source.location,
                        f"instruction accesses {source.label} and transfers that data "
                        "to an external HTTP(S) endpoint",
                        "source_sink",
                        (*source.capabilities, *sink.capabilities),
                        source.label,
                        sink.label,
                    )
                )
            elif source.label != "agent memory":
                # Memory remains a transfer source, but its name alone is not
                # evidence of credentials. Explicit secret sources still match.
                results.append(
                    finding(
                        self.access_metadata,
                        context.document,
                        source.location,
                        f"instruction directs access to {source.label} without a proven transfer",
                        "source_sink",
                        source.capabilities,
                        source.label,
                    )
                )
        for access in shell_accesses(context.document):
            results.append(
                finding(
                    self.metadata if access.transferred else self.access_metadata,
                    context.document,
                    access.location,
                    access.evidence,
                    "source_sink",
                    ("secret-read", "network-egress") if access.transferred else ("secret-read",),
                    access.source,
                    "external HTTP(S) endpoint" if access.transferred else None,
                )
            )
        return tuple(results)


@dataclass(frozen=True)
class SignatureDetector:
    metadata: DetectionMetadata
    indicator: str

    def __post_init__(self) -> None:
        if self.indicator not in {"bidi", "encoded_shell"}:
            raise ValueError("unsupported signature indicator")

    def detect(self, context: DetectionContext) -> tuple[Finding, ...]:
        if context.document.artifact.kind not in self.metadata.artifact_types:
            return ()
        if self.indicator == "bidi":
            return tuple(
                finding(
                    self.metadata,
                    context.document,
                    item.location,
                    "actionable instruction contains bidirectional format control characters",
                    "signature",
                    item.capabilities,
                )
                for item in context.observations
                if item.kind == "bidi"
            )
        if self.indicator == "encoded_shell":
            return tuple(
                finding(
                    self.metadata,
                    context.document,
                    server.location,
                    "MCP server decodes Base64 data and pipes it to a shell",
                    "signature",
                    ("encoded-command", "command-execution"),
                    "encoded data",
                    "shell execution",
                )
                for server in context.document.servers
                if server.runtime in {"sh", "bash", "zsh"}
                and (command_text := shell_command_string(server.args)) is not None
                and literal_encoded_pipeline(command_text) == "shell execution"
            )
        raise ValueError("unsupported signature indicator")


@dataclass(frozen=True)
class McpDetector:
    metadata: DetectionMetadata
    indicator: str

    def __post_init__(self) -> None:
        if self.indicator not in {"unpinned_package", "url_credentials"}:
            raise ValueError("unsupported MCP indicator")

    def detect(self, context: DetectionContext) -> tuple[Finding, ...]:
        if context.document.artifact.kind not in self.metadata.artifact_types:
            return ()
        results: list[Finding] = []
        for server in context.document.servers:
            if self.indicator == "unpinned_package":
                if (
                    server.runtime
                    not in {
                        "npx",
                        "npx.cmd",
                        "uvx",
                        "pnpm",
                        "pnpm.cmd",
                        "npm",
                        "npm.cmd",
                        "yarn",
                        "yarn.cmd",
                        "pipx",
                        "pipx.exe",
                        "docker",
                        "docker.exe",
                        "podman",
                        "podman.exe",
                        "nerdctl",
                    }
                    or not server.package
                    or "--no-install" in server.args
                    or "--offline" in server.args
                    or server.pinning in {"exact", "digest"}
                ):
                    continue
                evidence = "MCP server invokes a mutable package or container image reference"
                capabilities: tuple[str, ...] = ("runtime-execution",)
                source, sink = "mutable runtime reference", "process execution"
            elif self.indicator == "url_credentials":
                if not server.url_has_credentials:
                    continue
                evidence = "remote MCP endpoint embeds authentication material in its URL"
                capabilities = ("credential-exposure", "network-egress")
                source, sink = "URL credentials", "remote MCP endpoint"
            else:
                raise ValueError("unsupported MCP indicator")
            results.append(
                finding(
                    self.metadata,
                    context.document,
                    server.location,
                    evidence,
                    "behavioral",
                    capabilities,
                    source,
                    sink,
                )
            )
        return tuple(results)


@dataclass(frozen=True)
class LiteralCredentialDetector:
    metadata: DetectionMetadata

    def detect(self, context: DetectionContext) -> tuple[Finding, ...]:
        return tuple(
            finding(
                self.metadata,
                context.document,
                relation.location,
                f"MCP {relation.subject} field contains a literal matching the "
                f"{relation.target} format (value redacted)",
                "declarative",
                ("credential-exposure",),
                f"MCP {relation.subject} declaration",
            )
            for relation in context.document.relationships
            if relation.kind == "declares_literal_credential"
        )


BUILTIN_DETECTORS: tuple[EngineDetector, ...] = (
    LiteralCredentialDetector(
        _meta(
            "DRAGON-SECRET-001",
            "Literal credential in MCP configuration",
            "credential-exposure",
            S.MEDIUM,
            F.HIGH,
            C.RISKY,
            _MCP,
            "A credential field contains a provider-shaped literal. "
            "Validity, use and transfer were not established.",
            "Remove the literal, use a secret reference, and rotate the credential if it is real.",
        ),
    ),
    DeclarativeDetector(
        _meta(
            "DRAGON-PI-001",
            "Prior instruction override",
            "prompt-manipulation",
            S.HIGH,
            F.HIGH,
            C.SUSPICIOUS,
            _MARKDOWN,
            "An actionable instruction attempts to replace prior guidance; "
            "intent is not execution.",
            "Remove the override and verify the artifact's author and trust boundary.",
        ),
        "override",
        "instruction directs the agent to disregard prior instructions",
    ),
    DeclarativeDetector(
        _meta(
            "DRAGON-PI-002",
            "Security control bypass",
            "prompt-manipulation",
            S.HIGH,
            F.HIGH,
            C.SUSPICIOUS,
            _MARKDOWN,
            "An actionable instruction attempts to disable agent security controls.",
            "Keep security controls enabled and reject untrusted bypass requests.",
        ),
        "bypass",
        "instruction directs disabling safety or security controls",
    ),
    SourceSinkDetector(
        _meta(
            "DRAGON-EXFIL-001",
            "Sensitive data to external endpoint",
            "data-exfiltration",
            S.HIGH,
            F.MEDIUM,
            C.SUSPICIOUS,
            _MARKDOWN,
            "A linked sensitive read and transfer, or an instructed credential-bearing "
            "external link, is present; no data was sent by the scanner.",
            "Remove the transfer instruction and review the artifact's origin.",
        ),
        _meta(
            "DRAGON-CRED-001",
            "Sensitive data access instruction",
            "credential-access",
            S.MEDIUM,
            F.HIGH,
            C.RISKY,
            _MARKDOWN,
            "An actionable instruction requests sensitive material; no transfer is established.",
            "Limit sensitive-file access to explicitly trusted tasks.",
        ),
    ),
    BehavioralDetector(
        _meta(
            "DRAGON-EXEC-001",
            "Remote download executed by shell",
            "dangerous-execution",
            S.HIGH,
            F.HIGH,
            C.RISKY,
            _MARKDOWN,
            "An instruction directs fetching remote content and running it with a shell.",
            "Do not pipe remote content to a shell; inspect and verify it offline first.",
        ),
        "remote_execution",
        "instruction directs a remote download piped to a shell",
        "remote content",
        "shell execution",
    ),
    BehavioralDetector(
        _meta(
            "DRAGON-EXEC-002",
            "Remote download directed to Python interpreter",
            "dangerous-execution",
            S.HIGH,
            F.HIGH,
            C.RISKY,
            _MARKDOWN,
            "An instruction links an HTTP(S) download to Python stdin; "
            "no remote code was executed by the scanner.",
            "Do not run downloaded code; inspect and verify it offline first.",
        ),
        "remote_python_execution",
        "instruction directs an HTTP(S) download piped to Python stdin",
        "remote HTTP(S) code source",
        "Python interpreter execution",
    ),
    PowerShellDetector(
        _meta(
            "DRAGON-EXEC-004",
            "Remote content directed to PowerShell execution",
            "dangerous-execution",
            S.HIGH,
            F.HIGH,
            C.RISKY,
            (*_MARKDOWN, "mcp_config"),
            "The static command directs remote HTTP(S) content to PowerShell execution; "
            "no content was retrieved or run.",
            "Review the remote source offline before authorizing execution.",
        ),
        "powershell_execution",
        "PowerShell command links downloaded content to an execution operand",
        "remote HTTP(S) content",
        "PowerShell execution",
    ),
    EncodedExecutionDetector(
        _meta(
            "DRAGON-EXEC-003",
            "Literal encoded input decoded into an interpreter",
            "dangerous-execution",
            S.HIGH,
            F.HIGH,
            C.RISKY,
            _MARKDOWN,
            "An active instruction links literal encoded input through a decoder to shell or "
            "Python stdin; the scanner does not run or retain the decoded content.",
            "Inspect the encoded source and remove the decode-to-interpreter pipeline.",
        ),
    ),
    BehavioralDetector(
        _meta(
            "DRAGON-PERSIST-001",
            "Persistent agent instruction modification",
            "persistence",
            S.MEDIUM,
            F.MEDIUM,
            C.RISKY,
            _MARKDOWN,
            "An actionable instruction targets an agent instruction, configuration or hook file "
            "to change future behavior.",
            "Review and approve persistent agent instruction changes separately.",
        ),
        "persistence",
        "instruction directs modifying a persistent agent file to influence future behavior",
    ),
    BehavioralDetector(
        _meta(
            "DRAGON-PERSIST-002",
            "Unapproved startup execution directive",
            "persistence",
            S.HIGH,
            F.MEDIUM,
            C.SUSPICIOUS,
            _MARKDOWN,
            "An instruction names an OS startup target and requests execution without operator "
            "approval. No change was observed.",
            "Verify the startup target and require separate operator approval before changing it.",
        ),
        "os_persistence",
        "instruction directs writing an OS startup file to run a task without approval",
    ),
    BehavioralDetector(
        _meta(
            "DRAGON-TRUST-001",
            "External instructions promoted to authority",
            "remote-instruction-trust",
            S.MEDIUM,
            F.MEDIUM,
            C.RISKY,
            _MARKDOWN,
            "An instruction promotes mutable remote content into agent policy; "
            "the URL was not fetched.",
            "Pin and review the external content; do not treat it as authoritative by default.",
        ),
        "remote_trust",
        "instruction directs fetching external content and following it as policy",
        "external instructions",
        "agent policy",
    ),
    SignatureDetector(
        _meta(
            "DRAGON-OBF-001",
            "Bidirectional control in actionable instruction",
            "hidden-content",
            S.LOW,
            F.HIGH,
            C.SUSPICIOUS,
            _MARKDOWN,
            "A bidirectional control could obscure the displayed instruction; "
            "normal Unicode alone is not flagged.",
            "Remove format controls and review the visible and raw text.",
        ),
        "bidi",
    ),
    SignatureDetector(
        _meta(
            "DRAGON-OBF-002",
            "Encoded command piped to shell",
            "obfuscated-execution",
            S.HIGH,
            F.HIGH,
            C.SUSPICIOUS,
            _MCP,
            "An MCP command decodes Base64 into a shell; the scanner does not decode or run it.",
            "Remove the decode-to-shell pipeline and inspect the command source.",
        ),
        "encoded_shell",
    ),
    McpDetector(
        _meta(
            "DRAGON-MCP-001",
            "Unpinned MCP runtime package",
            "mcp-supply-chain",
            S.MEDIUM,
            F.MEDIUM,
            C.RISKY,
            _MCP,
            "Launching the MCP server may resolve a mutable package version; "
            "no package was fetched.",
            "Pin the exact package version and review its provenance.",
        ),
        "unpinned_package",
    ),
    McpDetector(
        _meta(
            "DRAGON-MCP-002",
            "Credentials in remote MCP URL",
            "mcp-credential-exposure",
            S.MEDIUM,
            F.HIGH,
            C.RISKY,
            _MCP,
            "A remote MCP URL embeds credentials that may leak in logs or history; "
            "values are not retained.",
            "Use a secure credential mechanism instead of URL userinfo.",
        ),
        "url_credentials",
    ),
    *MCP_DETECTORS,
)
