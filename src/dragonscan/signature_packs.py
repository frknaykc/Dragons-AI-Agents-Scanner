"""Explicit, bounded local JSON signature packs; no code or rule execution."""

import json
import os
import re
import stat
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from dragonscan.models import ArtifactKind, Classification, Confidence, Severity
from dragonscan.signature_ioc import normalize
from dragonscan.signature_models import IndicatorType, Signature, SignatureType

MAX_PACK_FILES = 64
MAX_PACK_BYTES = 1_048_576
MAX_SIGNATURES = 1024
FIELDS = frozenset(
    {
        "id",
        "name",
        "description",
        "type",
        "category",
        "severity",
        "confidence",
        "classification",
        "tags",
        "artifact_types",
        "indicator_type",
        "pattern",
        "contexts",
        "references",
        "remediation",
    }
)


class PackError(ValueError):
    """A user pack is not a valid static signature set."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key, value in pairs:
        if key in data:
            raise PackError("duplicate JSON key")
        data[key] = value
    return data


def _strings(raw: Any) -> tuple[str, ...]:
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise PackError("expected string list")
    if len(raw) > 32 or any(len(item) > 256 for item in raw):
        raise PackError("signature list limit exceeded")
    return tuple(raw)


def _label(raw: Any, label: str) -> str:
    if (
        not isinstance(raw, str)
        or not 1 <= len(raw) <= 256
        or any(ord(char) < 32 or ord(char) == 127 for char in raw)
    ):
        raise PackError(f"invalid {label}")
    return raw


def _references(raw: Any) -> tuple[str, ...]:
    result = []
    for reference in _strings(raw):
        try:
            parsed = urlsplit(reference)
            if parsed.scheme != "https" or not parsed.hostname or "@" in parsed.netloc:
                raise PackError("invalid signature reference")
            hostname = parsed.hostname
            host = f"[{hostname}]" if ":" in hostname else hostname
            port = f":{parsed.port}" if parsed.port is not None else ""
            result.append(f"https://{host}{port}")  # Never publish userinfo, paths or queries.
        except ValueError as exc:
            raise PackError("invalid signature reference") from exc
    return tuple(result)


def _signature(raw: Any, source: str, version: str | None) -> Signature:
    if not isinstance(raw, dict):
        raise PackError("invalid signature definition")
    if raw.keys() - FIELDS:
        raise PackError("unsupported signature fields")
    try:
        identifier = raw["id"]
        if not isinstance(identifier, str) or not re.fullmatch(
            r"DRAGON-(?:IOC|SIG)-\d{3}", identifier
        ):
            raise PackError("invalid signature ID")
        pattern = raw["pattern"]
        if not isinstance(pattern, str) or len(pattern) > 4096:
            raise PackError("invalid signature pattern")
        signature_type = SignatureType(raw["type"])
        if signature_type == SignatureType.YARA:
            raise PackError("YARA backend unavailable; rule not loaded")
        indicator = (
            IndicatorType(raw["indicator_type"]) if signature_type == SignatureType.IOC else None
        )
        if signature_type == SignatureType.IOC:
            if not identifier.startswith("DRAGON-IOC-") or indicator is None:
                raise PackError("IOC namespace/type mismatch")
            pattern = normalize(indicator, pattern)
        elif not identifier.startswith("DRAGON-SIG-") or "indicator_type" in raw:
            raise PackError("signature namespace/type mismatch")
        if signature_type != SignatureType.IOC and len(pattern.strip()) < 5:
            raise PackError("content pattern too short")
        return Signature(
            identifier,
            _label(raw["name"], "signature name"),
            _label(raw["description"], "signature description"),
            signature_type,
            _label(raw["category"], "signature category"),
            Severity(raw["severity"]),
            Confidence(raw["confidence"]),
            Classification(raw["classification"]),
            _strings(raw.get("tags", [])),
            tuple(ArtifactKind(kind) for kind in _strings(raw["artifact_types"])),
            indicator,
            pattern,
            _strings(raw["contexts"]),
            _references(raw.get("references", [])),
            _label(raw["remediation"], "signature remediation"),
            source,
            version,
        )
    except PackError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PackError(f"invalid signature definition ({type(exc).__name__})") from exc


def load_pack(directory: Path, reserved: set[str]) -> tuple[tuple[Signature, ...], tuple[str, ...]]:
    """Read only immediate regular JSON files; fail closed on symlinks and limits."""
    if directory.is_symlink() or not directory.is_dir():
        return (), ("signature pack directory is not a regular local directory",)
    signatures: list[Signature] = []
    diagnostics: list[str] = []
    try:
        files: list[Path] = []
        for path in directory.iterdir():
            if len(files) >= MAX_PACK_FILES:
                return (), ("signature pack file limit exceeded",)
            files.append(path)
        files.sort()
    except OSError:
        return (), ("cannot list signature pack directory",)
    for path in files:
        if path.suffix.lower() in {".yar", ".yara"}:
            diagnostics.append(f"{path.name}: YARA backend unavailable; rule not loaded")
            continue
        if path.is_symlink() or not path.is_file() or path.suffix.lower() != ".json":
            diagnostics.append(f"{path.name}: only regular JSON files are allowed")
            continue
        try:
            before = path.lstat()
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            flags |= getattr(os, "O_NONBLOCK", 0)
            fd = os.open(path, flags)
            try:
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    opened = os.fstat(stream.fileno())
                    if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                        before.st_dev,
                        before.st_ino,
                    ):
                        raise PackError("pack file changed during load")
                    if opened.st_size > MAX_PACK_BYTES:
                        raise PackError("pack file size limit exceeded")
                    data = stream.read(MAX_PACK_BYTES + 1)
            finally:
                os.close(fd)
            if len(data) > MAX_PACK_BYTES:
                raise PackError("pack file size limit exceeded")
            pack = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
            if not isinstance(pack, dict) or not isinstance(pack.get("signatures"), list):
                raise PackError("pack requires signatures array")
            if pack.keys() - {"name", "version", "signatures"}:
                raise PackError("unsupported pack fields")
            name = pack.get("name")
            version = pack.get("version")
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
                raise PackError("invalid pack name")
            if version is not None and (
                not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", version)
            ):
                raise PackError("invalid pack version")
            if len(pack["signatures"]) + len(signatures) > MAX_SIGNATURES:
                raise PackError("signature count limit exceeded")
            for index, item in enumerate(pack["signatures"]):
                try:
                    signature = _signature(item, f"User Pack: {name}", version)
                    if signature.detection_id in reserved:
                        raise PackError("duplicate or reserved signature ID")
                    reserved.add(signature.detection_id)
                    signatures.append(signature)
                except PackError as exc:
                    diagnostics.append(f"{path.name}: signature {index}: {exc}")
        except (OSError, UnicodeError, ValueError) as exc:
            diagnostics.append(f"{path.name}: invalid pack ({type(exc).__name__})")
    return tuple(signatures), tuple(diagnostics)
