"""Inspect explicit saved registry observations. No resolution, lookup or package installation."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from dragonscan.package_identity import PUBLIC, PackageIdentity


@dataclass(frozen=True)
class RegistryResult:
    status: str
    evidence: str
    review_id: str | None = None  # advisory only, never an independent policy trigger


def _identity(value: object) -> PackageIdentity | None:
    if (
        not isinstance(value, dict)
        or value.keys() != {"ecosystem", "name", "version", "registry"}
        or not all(isinstance(v, str) for v in value.values())
    ):
        return None
    try:
        return PackageIdentity(**value)
    except ValueError:
        return None


def _near_name(a: str, b: str) -> bool:
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    # Do not classify a legitimate fork under a different npm scope as a typo.
    if a.rpartition("/")[0] != b.rpartition("/")[0]:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (
            len(diff) == 2
            and diff[1] == diff[0] + 1
            and a[diff[0]] == b[diff[1]]
            and a[diff[1]] == b[diff[0]]
        )
    shorter, longer = (a, b) if len(a) < len(b) else (b, a)
    return any(shorter == longer[:i] + longer[i + 1 :] for i in range(len(longer)))


def package_endpoint(query: PackageIdentity) -> str:
    name = quote(query.name, safe="@")
    if query.ecosystem == "PyPI":
        return f"{query.registry}/pypi/{name}/json"
    return f"{query.registry}/{name}"


def _http_status(query: PackageIdentity, observation: dict[str, object]) -> str:
    # Only a captured package-level GET can establish package absence. A 404
    # from a version URL, redirect, proxy/auth error, or different host cannot.
    if observation.get("url") != package_endpoint(query) or observation.get("method") != "GET":
        return "unknown"
    code = observation.get("http_status")
    if type(code) is not int:
        return "unknown"
    if code == 404:
        return "package_missing"
    body = observation.get("body")
    if code != 200 or not isinstance(body, dict):
        return "unknown"
    info = body.get("info") if query.ecosystem == "PyPI" else body
    name = info.get("name") if isinstance(info, dict) else None
    versions = body.get("releases" if query.ecosystem == "PyPI" else "versions")
    if not isinstance(name, str) or not isinstance(versions, dict):
        return "unknown"
    try:
        returned = PackageIdentity(query.ecosystem, name, query.version, query.registry)
    except ValueError:
        return "unknown"
    if query != returned:
        return "unknown"
    return "version_present" if query.version in versions else "version_missing"


def inspect_registry(
    query: PackageIdentity,
    observation: object,
    *,
    intended: PackageIdentity | None = None,
    resolved: PackageIdentity | None = None,
    now: datetime | None = None,
) -> RegistryResult:
    """Inspect a specific public request. A missing version is not a missing package."""
    unknown = RegistryResult("unknown", "No usable current observation for this public identity.")
    if query.registry != PUBLIC[query.ecosystem] or not isinstance(observation, dict):
        return unknown
    if (
        observation.keys() != {"identity", "observed_at", "method", "url", "http_status", "body"}
        or _identity(observation["identity"]) != query
    ):
        return unknown
    stamp = observation["observed_at"]
    if not isinstance(stamp, str) or not stamp.endswith("Z") or len(stamp) != 20:
        return unknown
    try:
        capture = datetime.fromisoformat(stamp)
        age = (now or datetime.now(UTC)) - capture
    except (TypeError, ValueError):
        return unknown
    if not timedelta(0) <= age <= timedelta(days=1):
        return unknown
    status = _http_status(query, observation)
    if status == "package_missing":
        return RegistryResult(
            "package_missing",
            "The registry observation reports no such package. This does not establish malice.",
            "DRAGON-SC-008",
        )
    if status == "version_missing":
        return RegistryResult(
            "version_missing", "The package was reported present but not this version."
        )
    if status != "version_present":
        return unknown
    if (
        resolved == query
        and intended
        and intended.ecosystem == query.ecosystem
        and intended.version == query.version
    ):
        if (intended.registry == query.registry and _near_name(intended.name, query.name)) or (
            intended.name == query.name and intended.registry != query.registry
        ):
            return RegistryResult(
                "version_present",
                "Resolved and intended identities differ. Review the lock provenance; "
                "this does not establish malice.",
                "DRAGON-SC-009",
            )
    return RegistryResult(
        "version_present", "The saved registry observation reports this exact version present."
    )
