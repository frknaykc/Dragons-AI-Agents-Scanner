"""Exact supported public registry identities. A declaration is not evidence of installation."""

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from dragonscan.models import Dependency, Document

PUBLIC = {"PyPI": "https://pypi.org", "npm": "https://registry.npmjs.org"}
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*(?:[-+][a-zA-Z0-9.]+)?\Z", re.ASCII)


_NPM_EXACT = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:[-+][A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)?\Z",
    re.ASCII,
)


@dataclass(frozen=True)
class PackageIdentity:
    ecosystem: str
    name: str
    version: str
    registry: str

    def __post_init__(self) -> None:
        if (
            self.ecosystem not in PUBLIC
            or len(self.version) > 64
            or not _VERSION.fullmatch(self.version)
            or (self.ecosystem == "npm" and not _NPM_EXACT.fullmatch(self.version))
        ):
            raise ValueError("unsupported ecosystem or non-exact package version")
        name = self.name.lower() if self.ecosystem == "PyPI" else self.name
        parts = name.split("/")
        if self.ecosystem == "npm" and len(parts) == 2 and parts[0].startswith("@"):
            parts[0] = parts[0][1:]
        elif len(parts) != 1:
            raise ValueError("invalid package name")
        if not all(_NAME.fullmatch(part) for part in parts):
            raise ValueError("invalid package name")
        if self.ecosystem == "PyPI":
            object.__setattr__(self, "name", re.sub(r"[-_.]+", "-", name))
        if not re.fullmatch(r"https://[a-z0-9.-]{1,253}(?::[0-9]{1,5})?", self.registry):
            raise ValueError("registry must be a credential-free HTTPS origin")


def registry_label(
    raw: object, ecosystem: str, *, tarball: str | None = None, version: object = None
) -> str:
    """Public identity requires the conventional origin/path, not a redacted lookalike."""
    if not isinstance(raw, str):
        return "unknown-registry"
    try:
        url = urlsplit(raw)
        hostname = url.hostname or ""
        origin = f"{url.scheme}://{url.netloc.lower()}"
        clean = not (url.query or url.fragment or url.username or url.password or url.port)
        if origin == PUBLIC[ecosystem] and clean:
            if tarball is not None:
                filename = tarball.rpartition("/")[2]
                if (
                    isinstance(version, str)
                    and _VERSION.fullmatch(version)
                    and url.path == f"/{tarball}/-/{filename}-{version}.tgz"
                ):
                    return origin
            elif url.path.rstrip("/") in ({"", "/simple"} if ecosystem == "PyPI" else {""}):
                return origin
        if re.fullmatch(r"[a-z0-9.-]{1,253}", hostname) and hostname not in {
            "pypi.org",
            "registry.npmjs.org",
        }:
            return (
                f"{url.scheme}://{hostname}"
                if url.scheme in {"http", "https"}
                else "unknown-registry"
            )
    except ValueError:
        pass
    return "unknown-registry"


def public_package(dep: Dependency, document: Document) -> PackageIdentity | None:
    ecosystem = {"node": "npm", "python": "PyPI"}.get(dep.ecosystem)
    if (
        ecosystem is None
        or dep.source != "registry"
        or dep.pinning != "exact"
        or not dep.exact_version
        or dep.name == "direct-dependency"
        or dep.registry not in {None, PUBLIC[ecosystem]}
        or any(
            "multiple registries" in note
            or "unsupported requirement option" in note
            or "nested requirement" in note
            for note in document.diagnostics
        )
    ):
        return None
    try:
        return PackageIdentity(ecosystem, dep.name, dep.exact_version, PUBLIC[ecosystem])
    except ValueError:
        return None
