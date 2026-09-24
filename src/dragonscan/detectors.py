"""Declarative, behavioral, source/sink and indicator detectors over normalized IR."""

import re
from dataclasses import dataclass

from dragonscan.behavior import related_transfer
from dragonscan.detection import DetectionContext, DetectionMetadata, EngineDetector, finding
from dragonscan.models import Classification as C
from dragonscan.models import Confidence as F
from dragonscan.models import Finding
from dragonscan.models import Severity as S

_MARKDOWN = ("instructions", "skill", "memory", "soul")
_MCP = ("mcp_config", "agent_config")
_OBSERVATION_KINDS = frozenset(
    {
        "override",
        "bypass",
        "remote_execution",
        "persistence",
        "remote_trust",
        "sensitive_access",
        "external_transfer",
        "bidi",
    }
)
_PIN = re.compile(r"@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\Z")
_ENCODED_SHELL = re.compile(
    r"\bbase64\s+(?:-d|--decode)\b[^\n|]{0,100}\|\s*(?:sh|bash|zsh)\b",
    re.I,
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
                self.sink,
            )
            for observation in context.observations
            if observation.kind == self.observation_kind
        )


@dataclass(frozen=True)
class SourceSinkDetector:
    metadata: DetectionMetadata
    access_metadata: DetectionMetadata

    def detect(self, context: DetectionContext) -> tuple[Finding, ...]:
        if context.document.artifact.kind not in self.metadata.artifact_types:
            return ()
        results: list[Finding] = []
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
            else:
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
                and len(server.args) >= 2
                and server.args[0] in {"-c", "-lc"}
                and _ENCODED_SHELL.search(server.args[1])
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
                    server.runtime not in {"npx", "npx.cmd", "uvx"}
                    or not server.package
                    or "--no-install" in server.args
                    or "--offline" in server.args
                    or _PIN.search(server.package)
                ):
                    continue
                evidence = "MCP server invokes a runtime package without an exact version pin"
                capabilities = ("package-installation", "command-execution")
                source, sink = "unversioned package", "process execution"
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


BUILTIN_DETECTORS: tuple[EngineDetector, ...] = (
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
            "A sensitive read and a linked external transfer are directed by "
            "the artifact; no data was sent.",
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
            "DRAGON-PERSIST-001",
            "Persistent agent instruction modification",
            "persistence",
            S.MEDIUM,
            F.MEDIUM,
            C.RISKY,
            _MARKDOWN,
            "An actionable instruction targets a persistent agent file to change future behavior.",
            "Review and approve persistent agent instruction changes separately.",
        ),
        "persistence",
        "instruction directs modifying agent behavior in a persistent instruction file",
        sink="agent instruction file",
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
)
