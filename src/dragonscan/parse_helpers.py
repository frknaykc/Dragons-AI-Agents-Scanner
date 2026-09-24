"""Shared static reference normalization; no URL is fetched or file is opened."""

from urllib.parse import urlsplit, urlunsplit

from dragonscan.parse_errors import ParseError


def safe_url(value: str) -> str | None:
    """Retain only public HTTP(S) location, never credentials/query/fragment."""
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
        return urlunsplit((parsed.scheme.lower(), f"{host}{port}", parsed.path, "", ""))
    except ValueError as exc:
        raise ParseError("invalid URL in configuration") from exc
