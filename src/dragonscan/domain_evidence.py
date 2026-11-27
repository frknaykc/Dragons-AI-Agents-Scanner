"""Domain identity and optional registration evidence. No target DNS or HTTP requests."""

import hashlib
import ipaddress
import json
import re
import tempfile
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dragonscan.loading import load_text, load_text_with_bytes
from dragonscan.target_acquisition import AcquisitionError, AcquisitionTimeout, download_bounded

# Fixed registry routes, not a public resolver/proxy or a URL supplied by content.
_REGISTRIES = {"com": "https://rdap.verisign.com/com/v1", "net": "https://rdap.verisign.com/net/v1"}
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class EvidenceError(ValueError):
    """A capture or identifier cannot be interpreted safely."""


def object_json(text: str) -> dict[str, Any]:
    def unique(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise EvidenceError("duplicate JSON key")
            out[k] = v
        return out

    def invalid(_: str) -> None:
        raise EvidenceError("invalid JSON constant")

    try:
        value = json.loads(text, object_pairs_hook=unique, parse_constant=invalid)
    except (ValueError, RecursionError):
        raise EvidenceError("invalid or ambiguous JSON capture") from None
    if not isinstance(value, dict):
        raise EvidenceError("expected a JSON object")
    return value


def hostname(raw: object) -> str:
    if not isinstance(raw, str) or not 1 <= len(raw) <= 254:
        raise EvidenceError("invalid DNS hostname")
    labels = unicodedata.normalize("NFC", raw.removesuffix(".").lower()).split(".")
    result = []
    for label in labels:
        try:
            ascii_label = label.encode("idna").decode("ascii")
            unicode_label = ascii_label.encode("ascii").decode("idna")
        except UnicodeError:
            raise EvidenceError("invalid IDNA label") from None
        if not _LABEL.fullmatch(ascii_label) or (not label.isascii() and unicode_label != label):
            raise EvidenceError("invalid or lossy IDNA label")
        result.append(ascii_label)
    name = ".".join(result)
    if len(result) < 2 or result[-1].isdecimal() or len(name) > 253:
        raise EvidenceError("expected a fully qualified domain name, not an address")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise EvidenceError("expected a domain, not an address")


def _registrable(host: str, psl: Path | None) -> str | None:
    # RDAP queries ICANN registry units, not private hosting tenants. No guessed default '*'.
    labels = host.split(".")
    if psl is None:
        return ".".join(labels[-2:]) if labels[-1] in _REGISTRIES else None
    text = load_text(psl)
    begin, end = "// ===BEGIN ICANN DOMAINS===", "// ===END ICANN DOMAINS==="
    if text.count(begin) != 1 or text.count(end) != 1 or text.index(end) < text.index(begin):
        raise EvidenceError("expected a PSL snapshot with an ICANN section")
    suffixes = {".".join(labels[i:]): len(labels) - i for i in range(len(labels))}
    length = exception = 0
    for line in text.split(begin)[1].split(end)[0].splitlines():
        rule = line.strip()
        if not rule or rule.startswith("//"):
            continue
        plain = rule.removeprefix("!").removeprefix("*.")
        try:
            key = plain.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise EvidenceError("invalid PSL rule") from None
        n = suffixes.get(key)
        if n is None:
            continue
        if rule.startswith("!"):
            exception = max(exception, n - 1)
        elif rule.startswith("*."):
            if len(labels) > n:
                length = max(length, n + 1)
        else:
            length = max(length, n)
    length = exception or length
    return ".".join(labels[-length - 1 :]) if length and len(labels) > length else None


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError("missing observation timestamp")
    try:
        date = datetime.fromisoformat(value)
        if date.tzinfo is None or date > datetime.now(UTC):
            raise ValueError
        return date.astimezone(UTC)
    except (OverflowError, ValueError):
        raise EvidenceError("expected an observed, timezone-qualified timestamp") from None


def _record(path: Path, domain: str | None) -> tuple[dict[str, Any], dict[str, str]]:
    text, raw = load_text_with_bytes(path)
    data = object_json(text)
    if hostname(data.get("domain")) != domain:
        raise EvidenceError("record identity does not match the requested domain")
    return data, {
        "source": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "observed_at": _time(data.get("observed_at")).isoformat(),
    }


def _rdap(domain: str) -> dict[str, str]:
    base = _REGISTRIES[domain.rsplit(".", 1)[-1]]
    url = f"{base}/domain/{domain}"

    def authorize(candidate: str) -> None:
        if candidate not in {url, url + "/"}:
            raise AcquisitionError("RDAP redirect outside authorized resource")

    evidence = {"source": url}
    try:
        with tempfile.TemporaryDirectory(prefix="dragonscan-rdap-") as directory:
            path = Path(directory) / "record.json"
            final, status = download_bounded(
                url,
                path,
                max_bytes=256 * 1024,
                authorize=authorize,
                statuses=(200, 404),
                accept="application/rdap+json",
            )
            text, raw = load_text_with_bytes(path)
        evidence.update(
            source=final,
            sha256=hashlib.sha256(raw).hexdigest(),
            observed_at=datetime.now(UTC).isoformat(),
        )
        record = object_json(text)
        if status == 404:
            if (
                type(record.get("errorCode")) is int
                and record["errorCode"] == 404
                and isinstance(record.get("rdapConformance"), list)
                and "rdap_level_0" in record["rdapConformance"]
            ):
                return {**evidence, "status": "unregistered"}
            raise EvidenceError("not a registry RDAP error")
        if record.get("objectClassName") != "domain" or hostname(record.get("ldhName")) != domain:
            raise EvidenceError("mismatched RDAP response")
        result = {**evidence, "status": "registered"}
        events = record.get("events")
        if isinstance(events, list):
            dates = [
                e.get("eventDate")
                for e in events
                if isinstance(e, dict) and e.get("eventAction") == "registration"
            ]
            if len(dates) == 1:
                try:
                    result["registered_at"] = _time(dates[0]).isoformat()
                except EvidenceError:
                    pass  # Identity is confirmed; the registration epoch is unknown.
        return result
    except AcquisitionTimeout:
        return {**evidence, "status": "timeout"}
    except (ValueError, OSError):
        return {**evidence, "status": "unknown"}


def inspect_domain(
    raw: str,
    *,
    consent: bool = False,
    dns_record: Path | None = None,
    history: Path | None = None,
    psl: Path | None = None,
) -> dict[str, Any]:
    host = hostname(raw)
    domain = _registrable(host, psl)
    dns = {"status": "not_supplied"}
    past = {"status": "not_supplied"}
    if dns_record:
        data, origin = _record(dns_record, host)
        rcode = data.get("rcode")
        if rcode not in ("NXDOMAIN", "NOERROR", "SERVFAIL", "TIMEOUT"):
            raise EvidenceError("unsupported recorded DNS status")
        dns = {**origin, "status": rcode.lower()}
    if history:
        data, origin = _record(history, domain)
        previous = _time(data.get("registered_at"))
        if previous > _time(origin["observed_at"]):
            raise EvidenceError("history registration postdates observation")
        past = {**origin, "status": "not_comparable", "registered_at": previous.isoformat()}
    rdap = {"status": "not_requested"}
    if consent:
        rdap = (
            _rdap(domain)
            if domain and domain.count(".") == 1 and domain.rsplit(".", 1)[-1] in _REGISTRIES
            else {"status": "unsupported"}
        )
    if history and rdap.get("registered_at"):
        current = _time(rdap["registered_at"])
        if current > _time(past["observed_at"]):
            past["status"] = "registration_epoch_changed"
        elif current == _time(past["registered_at"]):
            past["status"] = "same_registration_epoch"
    return {"domain": host, "registrable_domain": domain, "dns": dns, "rdap": rdap, "history": past}
