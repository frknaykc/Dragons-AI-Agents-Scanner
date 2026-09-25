"""Bounded OSV-only HTTPS adapter; never accepts a URL from scan input."""

import json
import re
import time
import unicodedata
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from dragonscan.vulnerability import IntelligenceProvider, ProviderResult, Query, Vulnerability

_ENDPOINT = "https://api.osv.dev"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z", re.ASCII)
MAX_RESPONSE = 1_048_576
MAX_RECORDS = 32
BATCH_SIZE = 32


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any
    ) -> None:
        return None


class OSVClient:
    def __init__(self, request: Callable[[str, bytes | None], bytes] | None = None) -> None:
        self._request = request or self._https_request

    @staticmethod
    def _https_request(path: str, body: bytes | None) -> bytes:
        # Only hard-coded paths or validated advisory IDs reach here; no redirects.
        if not (
            path == "/v1/querybatch"
            or path.startswith("/v1/vulns/")
            and _ID.fullmatch(path.removeprefix("/v1/vulns/"))
        ):
            raise ValueError("invalid OSV path")
        request = urllib.request.Request(
            _ENDPOINT + path,
            data=body,
            headers={
                "User-Agent": "Dragons-AI-Agent-Scanner/0.1.0",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST" if body is not None else "GET",
        )
        # urllib honors the user's standard HTTPS proxy environment. Proxy auth is
        # not sourced from scan content; only this fixed OSV host is contacted.
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=5) as response:
            if response.status != 200:
                raise ValueError("unexpected OSV HTTP status")
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise ValueError("OSV response exceeds limit")
            return bytes(raw)

    def json(self, path: str, body: dict[str, object] | None = None) -> object:
        raw = self._request(path, json.dumps(body).encode() if body is not None else None)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("OSV response exceeds limit")
        return json.loads(raw)


def _short(value: object, limit: int = 160) -> str | None:
    if not isinstance(value, str) or len(value) > limit:
        return None
    # Never print remote control characters or escape sequences in any output.
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        return None
    return value


def _text_list(values: object, limit: int, size: int = 160) -> tuple[str, ...]:
    if not isinstance(values, list):
        return ()
    return tuple(item for raw in values[:limit] if (item := _short(raw, size)))


def _package_matches(package: object, key: Query) -> bool:
    if not isinstance(package, dict) or package.get("ecosystem") != key.ecosystem:
        return False
    name = package.get("name")
    if not isinstance(name, str):
        return False
    normalized = re.sub(r"[-_.]+", "-", name.lower()) if key.ecosystem == "PyPI" else name.lower()
    return normalized == key.package


def _record(raw: object, key: Query, expected_id: str) -> Vulnerability:
    if not isinstance(raw, dict) or raw.get("id") != expected_id:
        raise ValueError("OSV advisory identity mismatch")
    affected = raw.get("affected")
    if (
        not isinstance(affected, list)
        or len(affected) > 256
        or not any(
            isinstance(entry, dict) and _package_matches(entry.get("package"), key)
            for entry in affected
        )
    ):
        raise ValueError("OSV advisory package mismatch")
    fixed: list[str] = []
    ranges: list[str] = []
    upstream: str | None = None
    for entry in affected:
        if not isinstance(entry, dict) or not _package_matches(entry.get("package"), key):
            continue
        ecosystem_specific = entry.get("ecosystem_specific")
        if isinstance(ecosystem_specific, dict):
            upstream = upstream or _short(ecosystem_specific.get("severity"), 32)
        if isinstance(entry.get("ranges"), list):
            for item in entry["ranges"][:16]:
                if not isinstance(item, dict) or item.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                    continue
                events = item.get("events")
                if isinstance(events, list):
                    for event in events[:32]:
                        if isinstance(event, dict):
                            value = _short(event.get("fixed"), 80)
                            if value:
                                fixed.append(value)
                            introduced = _short(event.get("introduced"), 80)
                            if introduced:
                                ranges.append("introduced: " + introduced)
    severity = raw.get("severity")
    if not isinstance(severity, list):
        severity = []
    refs = raw.get("references")
    if not isinstance(refs, list):
        refs = []
    cvss = tuple(
        score
        for item in severity[:8]
        if isinstance(item, dict) and (score := _short(item.get("score"), 160))
    )
    references = tuple(
        url
        for item in refs[:16]
        if isinstance(item, dict)
        and (url := _short(item.get("url"), 240))
        and url.startswith("https://")
        and "@" not in url.split("/", 3)[2]
    )
    return Vulnerability(
        "OSV",
        expected_id,
        _text_list(raw.get("aliases"), 16, 100),
        _short(raw.get("summary"), 240) or "OSV advisory",
        upstream,
        cvss,
        tuple(dict.fromkeys(fixed[:16])),
        tuple(dict.fromkeys(ranges[:16])),
        references,
        _short(raw.get("published"), 40),
        _short(raw.get("modified"), 40),
    )


class OSVProvider(IntelligenceProvider):
    identity = "OSV"

    def __init__(self, client: OSVClient | None = None) -> None:
        self.client = client or OSVClient()

    def query(self, queries: tuple[Query, ...]) -> ProviderResult:
        matches: dict[Query, tuple[Vulnerability, ...]] = {}
        diagnostics: list[str] = []
        incomplete = False
        details: dict[str, object] = {}
        deadline = time.monotonic() + 30

        def load(path: str, body: dict[str, object] | None = None) -> object:
            if time.monotonic() >= deadline:
                raise TimeoutError("OSV time budget exhausted")
            return self.client.json(path, body)

        for start in range(0, len(queries), BATCH_SIZE):
            batch = queries[start : start + BATCH_SIZE]
            payload: dict[str, object] = {
                "queries": [
                    {
                        "package": {"ecosystem": key.ecosystem, "name": key.package},
                        "version": key.version,
                    }
                    for key in batch
                ]
            }
            try:
                response = load("/v1/querybatch", payload)
                if (
                    not isinstance(response, dict)
                    or not isinstance(response.get("results"), list)
                    or len(response["results"]) != len(batch)
                ):
                    raise ValueError("invalid OSV batch results")
                for key, item in zip(batch, response["results"], strict=True):
                    if not isinstance(item, dict) or not isinstance(item.get("vulns", []), list):
                        raise ValueError("invalid OSV query result")
                    if item.get("next_page_token") or len(item.get("vulns", [])) > MAX_RECORDS:
                        diagnostics.append("OSV result truncated or paginated; query incomplete")
                        incomplete = True
                        continue
                    ids: list[str] = []
                    for vuln in item.get("vulns", []):
                        identifier = vuln.get("id") if isinstance(vuln, dict) else None
                        if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
                            raise ValueError("invalid OSV vulnerability ID")
                        ids.append(identifier)
                    if len(details) + len(set(ids) - details.keys()) > MAX_RECORDS:
                        diagnostics.append("OSV advisory limit reached")
                        incomplete = True
                        continue
                    records: list[Vulnerability] = []
                    for identifier in dict.fromkeys(ids):
                        if identifier not in details:
                            details[identifier] = load("/v1/vulns/" + identifier)
                        records.append(_record(details[identifier], key, identifier))
                    matches[key] = tuple(records)
            except (OSError, ValueError, TypeError) as exc:
                reason = (
                    "rate limited"
                    if isinstance(exc, urllib.error.HTTPError) and exc.code == 429
                    else "unavailable or malformed response"
                )
                diagnostics.append(f"OSV {reason}; enrichment incomplete")
                incomplete = True
        return ProviderResult(matches, tuple(dict.fromkeys(diagnostics)), incomplete)
