"""Optional YARA adapter contract; no YARA rule loader is installed by default.

A future adapter must validate metadata and confine rule compilation and matching
before returning inert SignatureHit objects. The scanner never imports pack code.
"""

from typing import Protocol

from dragonscan.models import Document
from dragonscan.signature_models import SignatureHit


class YaraAdapter(Protocol):
    """Controlled, optional backend for bounded already-loaded artifact bytes."""

    def match(self, document: Document, data: bytes) -> tuple[SignatureHit, ...]: ...
