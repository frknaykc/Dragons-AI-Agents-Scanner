"""Community-extensible Python rule registry over normalized documents."""

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import PurePath

from dragonscan.behavior import collect, related_transfer
from dragonscan.models import (
    Classification,
    Confidence,
    Document,
    Finding,
    Severity,
)

Detector = Callable[[Document], Iterable[Finding]]


@dataclass(frozen=True)
class Rule:
    detection_id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    artifact_types: tuple[str, ...]
    detector: Detector
    description: str
    remediation: str
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    def detect(self, document: Document) -> tuple[Finding, ...]:
        if document.artifact.kind not in self.artifact_types:
            return ()
        return tuple(self.detector(document))


_SENSITIVE = re.compile(
    r"(?:~?/)?(?:\.ssh/id_rsa|\.aws/credentials)\b|(?:~?/)?\.env(?![\w.])", re.I
)

_FETCH_PIPE_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^\n|]{0,500}https?://[^\s|]+[^\n|]{0,500}\|\s*"
    r"(?:sh|bash|zsh)\b",
    re.I,
)


def credential_exfiltration(document: Document) -> Iterable[Finding]:
    observations = collect(document)
    for observation in observations:
        if observation.kind != "sensitive_access" or observation.label not in {
            "SSH private key",
            "cloud credentials",
            "environment secrets",
        }:
            continue
        source = _SENSITIVE.search(document.instructions[observation.context].text)
        if source is None or related_transfer(observation, observations) is None:
            continue
        yield Finding(
            detection_id="DAAS-001",
            category="data-exfiltration",
            title="Instruction to send a credential file to an external endpoint",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            classification=Classification.SUSPICIOUS,
            artifact=document.artifact.path,
            line=observation.location.line,
            evidence=f"instruction reads {source.group()} and directs transfer to an external URL",
            explanation="An instruction combines a sensitive-file read with an external transfer; "
            "the scanner does not execute it or assert that exfiltration occurred.",
            source="credential file",
            sink="external URL",
            capabilities=("file-read", "network-send"),
            remediation="Remove the transfer instruction and review the artifact's origin.",
            detector="credential_exfiltration",
        )


def mcp_fetch_to_shell(document: Document) -> Iterable[Finding]:
    for server in document.servers:
        executable = PurePath(server.command.replace("\\", "/")).name.lower()
        if executable not in {"sh", "bash", "zsh"} or not server.args:
            continue
        # Only shell commands with an explicit command-string flag are assessed here.
        if server.args[0] not in {"-c", "-lc"}:
            continue
        command_text = server.args[1] if len(server.args) > 1 else ""
        if not _FETCH_PIPE_SHELL.search(command_text):
            continue
        yield Finding(
            detection_id="DAAS-002",
            category="remote-code-execution",
            title="MCP server command pipes a download into a shell",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            classification=Classification.RISKY,
            artifact=document.artifact.path,
            evidence="MCP server command uses a fetch-to-shell pipeline",
            explanation="Launching this configured server would execute downloaded code; "
            "the scanner does not launch it.",
            source="remote download",
            sink="shell execution",
            capabilities=("network-fetch", "shell-execution"),
            remediation="Review the remote source; replace the pipeline with a verified, "
            "pinned package.",
            detector="mcp_fetch_to_shell",
        )


BUILTIN_RULES = (
    Rule(
        "DAAS-001",
        "Credential exfiltration instruction",
        "data-exfiltration",
        Severity.HIGH,
        Confidence.MEDIUM,
        ("instructions", "skill", "memory", "soul"),
        credential_exfiltration,
        "Sensitive-file read and external send in adjacent instructions.",
        "Remove the instruction and review its origin.",
        tags=("credentials", "exfiltration"),
    ),
    Rule(
        "DAAS-002",
        "MCP download piped to shell",
        "remote-code-execution",
        Severity.HIGH,
        Confidence.HIGH,
        ("mcp_config", "agent_config"),
        mcp_fetch_to_shell,
        "MCP command starts a shell with a download pipeline.",
        "Use a verified, pinned package instead.",
        tags=("mcp", "execution"),
    ),
)
