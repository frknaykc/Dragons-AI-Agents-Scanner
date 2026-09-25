"""Validated static signature definitions and secret-safe match provenance."""

from dataclasses import dataclass
from enum import StrEnum

from dragonscan.models import ArtifactKind, Classification, Confidence, Severity, SourceRef


class SignatureType(StrEnum):
    IOC = "ioc"
    CONTENT = "content"
    ENCODED = "encoded-content"
    YARA = "yara"


class IndicatorType(StrEnum):
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"


CONTEXTS = frozenset(
    {
        "mcp_endpoint",
        "remote_endpoint",
        "executable_command",
        "instruction",
        "code_block",
        "documentation",
        "artifact_hash",
    }
)


@dataclass(frozen=True)
class Signature:
    detection_id: str
    name: str
    description: str
    signature_type: SignatureType
    category: str
    severity: Severity
    confidence: Confidence
    classification: Classification
    tags: tuple[str, ...]
    artifact_types: tuple[ArtifactKind, ...]
    indicator_type: IndicatorType | None
    pattern: str
    contexts: tuple[str, ...]
    references: tuple[str, ...]
    remediation: str
    source: str
    version: str | None = None

    def __post_init__(self) -> None:
        suffix = self.detection_id.rsplit("-", 1)[-1]
        if (
            not self.detection_id.startswith(("DRAGON-IOC-", "DRAGON-SIG-"))
            or not suffix.isdigit()
            or len(suffix) != 3
        ):
            raise ValueError("invalid signature ID")
        if not all((self.name, self.description, self.category, self.remediation, self.source)):
            raise ValueError("incomplete signature metadata")
        if (
            not self.artifact_types
            or not self.contexts
            or any(c not in CONTEXTS for c in self.contexts)
        ):
            raise ValueError("invalid signature scope")
        if self.signature_type == SignatureType.IOC and self.indicator_type is None:
            raise ValueError("IOC requires an indicator type")
        if self.signature_type != SignatureType.IOC and self.indicator_type is not None:
            raise ValueError("non-IOC cannot have an indicator type")
        if self.signature_type == SignatureType.YARA:
            raise ValueError("YARA backend is not available")
        if not self.pattern or len(self.pattern) > 4096:
            raise ValueError("invalid signature pattern")


@dataclass(frozen=True)
class SignatureHit:
    signature: Signature
    location: SourceRef
    context: str
    matched: str  # normalized public IOC or fixed, non-secret label only
    encoded: bool = False
    representation: str | None = None
