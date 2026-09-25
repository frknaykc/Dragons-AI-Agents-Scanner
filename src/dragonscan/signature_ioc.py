"""Offline IOC normalization and bounded extraction from selected text contexts."""

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from dragonscan.signature_models import IndicatorType

_URL = re.compile(r"https?://[^\s<>()'\"|]+", re.I)
_HOST = re.compile(r"(?<![\w@.-])(?:[a-z0-9-]+\.)+[a-z]{2,63}(?![\w.-])", re.I)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])\[?[0-9a-f:]{3,45}\]?(?![\w:])", re.I)
_HASH = {IndicatorType.MD5: 32, IndicatorType.SHA1: 40, IndicatorType.SHA256: 64}


def normalize(kind: IndicatorType, raw: str) -> str:
    value = raw.strip()
    if kind in {IndicatorType.DOMAIN, IndicatorType.HOSTNAME}:
        value = value.rstrip(".").lower()
        if (
            len(value) > 253
            or not _HOST.fullmatch(value)
            or any(
                len(part) > 63 or part.startswith("-") or part.endswith("-")
                for part in value.split(".")
            )
        ):
            raise ValueError("invalid hostname indicator")
        return value
    if kind == IndicatorType.URL:
        try:
            parsed = urlsplit(value)
            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not parsed.hostname
                or "@" in parsed.netloc
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("invalid URL indicator")
            host = parsed.hostname.lower()
            host = f"[{host}]" if ":" in host else host
            port = f":{parsed.port}" if parsed.port is not None else ""
            return urlunsplit((parsed.scheme.lower(), f"{host}{port}", parsed.path, "", ""))
        except ValueError as exc:
            raise ValueError("invalid URL indicator") from exc
    if kind in {IndicatorType.IPV4, IndicatorType.IPV6}:
        try:
            address = ipaddress.ip_address(value.strip("[]"))
        except ValueError as exc:
            raise ValueError("invalid IP indicator") from exc
        if address.version != (4 if kind == IndicatorType.IPV4 else 6):
            raise ValueError("wrong IP version")
        return address.compressed
    if kind in _HASH and len(value) == _HASH[kind] and re.fullmatch(r"[0-9a-fA-F]+", value):
        return value.lower()
    raise ValueError("invalid hash indicator")


def collect_candidates(kind: IndicatorType, text: str) -> tuple[tuple[str, ...], bool]:
    def sanitized(match: re.Match[str]) -> str:
        try:
            url = urlsplit(match.group().rstrip(".,;"))
            if url.hostname is None:
                return ""
            host = f"[{url.hostname}]" if ":" in url.hostname else url.hostname
            port = f":{url.port}" if url.port is not None else ""
            return urlunsplit((url.scheme, f"{host}{port}", url.path, "", ""))
        except ValueError:
            return ""

    def public_host(match: re.Match[str]) -> str:
        parsed = urlsplit(sanitized(match))
        return f"{parsed.scheme}://{parsed.netloc}" if parsed.hostname else ""

    # Credentials in URL userinfo must not become independent IOC candidates.
    clean = _URL.sub(public_host, text)
    if kind == IndicatorType.URL:
        tokens = (sanitized(match) for match in _URL.finditer(text))
    elif kind in {IndicatorType.DOMAIN, IndicatorType.HOSTNAME}:
        tokens = (match.group() for match in _HOST.finditer(clean))
    elif kind == IndicatorType.IPV4:
        tokens = (match.group() for match in _IPV4.finditer(clean))
    elif kind == IndicatorType.IPV6:
        tokens = (match.group() for match in _IPV6.finditer(clean))
    else:
        tokens = (match.group() for match in re.finditer(r"\b[0-9a-fA-F]{32,64}\b", clean))
    output: list[str] = []
    for token in tokens:
        try:
            normalized = normalize(kind, token)
        except ValueError:
            continue
        if normalized not in output:
            output.append(normalized)
        if len(output) >= 128:
            return tuple(output), True
    return tuple(output), False


def candidates(kind: IndicatorType, text: str) -> tuple[str, ...]:
    """Return bounded public IOC candidates; prefer collect_candidates for diagnostics."""
    return collect_candidates(kind, text)[0]


def public_label(kind: IndicatorType, value: str) -> str:
    """Never emit URL paths, queries or userinfo from untrusted content."""
    if kind == IndicatorType.URL:
        parsed = urlsplit(value)
        return f"{parsed.scheme}://{parsed.netloc}"
    return value
