"""Deterministic supply-chain findings from normalized, already-loaded documents."""

import re
from dataclasses import replace
from pathlib import Path

from dragonscan.dependencies import local_status
from dragonscan.models import (
    Classification,
    Confidence,
    Dependency,
    DependencyEvidence,
    Document,
    Finding,
    PathStep,
    Severity,
    Target,
)

_MUTABLE = frozenset(
    {
        "latest",
        "wildcard",
        "unversioned",
        "unbounded-range",
        "git-branch",
        "git-ref-unknown",
        "mutable-url",
    }
)
_REMOTE_INSTALLER = re.compile(r"\b(?:curl|wget)\b[^\n|;]{1,1024}\|\s*(?:sh|bash)\b", re.I)
_DANGEROUS_HOOK = re.compile(
    r"\b(?:curl|wget)\b[^\n|;]{1,1024}\|\s*(?:sh|bash)\b|"
    r"\b(?:curl|wget)\b[^\n]{1,1024}\b(?:sh|bash|node|python)\b|"
    r"\b(?:bash|sh)\s+-c\b|\b(?:eval|base64\s+-d)\b|"
    r"(?:\.aws/credentials|\.ssh/id_|/etc/cron\.)",
    re.I,
)
_HOOKS = frozenset({"preinstall", "install", "postinstall", "prepare", "prepublish"})


def _finding(
    dep: Dependency,
    identifier: str,
    title: str,
    severity: Severity,
    explanation: str,
    evidence: str,
    remediation: str,
    *,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    chain = dep.mechanism in {"runtime-execution", "install-and-execute"}
    path = (
        (
            PathStep(
                "installs",
                str(dep.location.path),
                dep.name,
                dep.location.path,
                dep.location.line,
                "dependency_parser",
                confidence,
            ),
            PathStep(
                "executes",
                dep.name,
                dep.manager,
                dep.location.path,
                dep.location.line,
                "dependency_parser",
                confidence,
            ),
        )
        if chain
        else ()
    )
    return Finding(
        detection_id=identifier,
        category="supply-chain",
        title=title,
        severity=severity,
        confidence=confidence,
        classification=Classification.RISKY,
        artifact=dep.location.path,
        line=dep.location.line,
        evidence=evidence,
        explanation=explanation,
        remediation=remediation,
        detector="supply_chain",
        source=f"{dep.ecosystem} dependency {dep.name}",
        sink=dep.mechanism if dep.mechanism != "declaration" else None,
        capabilities=(dep.mechanism,) if dep.mechanism != "declaration" else (),
        path=path,
        dependency=DependencyEvidence(
            dep.ecosystem,
            dep.name,
            dep.requested,
            dep.pinning,
            dep.source,
            dep.manager,
            dep.mechanism,
            dep.group,
            dep.integrity,
            dep.provenance,
            dep.lockfile.name if dep.lockfile else None,
            dep.path_status if dep.source == "local" else None,
            dep.registry,
        ),
    )


def analyze(
    target: Target, documents: tuple[Document, ...]
) -> tuple[tuple[Document, ...], tuple[Finding, ...], tuple[str, ...]]:
    """Reconcile local provenance without resolving or loading dependency paths."""
    registries = {
        doc.artifact.path.parent: (doc.registry, dict(doc.registry_scopes))
        for doc in documents
        if doc.artifact.path.name == ".npmrc"
    }

    def node_registry(dep: Dependency) -> str | None:
        default, scopes = registries.get(dep.location.path.parent, (None, {}))
        scope = dep.name.split("/", 1)[0] if dep.name.startswith("@") else ""
        return scopes.get(scope, default)

    normalized = tuple(
        replace(
            doc,
            dependencies=tuple(
                local_status(
                    replace(dep, registry=dep.registry or node_registry(dep))
                    if dep.ecosystem == "node" and dep.source == "registry"
                    else dep,
                    target.path,
                )
                for dep in doc.dependencies
            ),
        )
        for doc in documents
    )
    locked: dict[tuple[Path, str, str], set[str]] = {}
    for doc in normalized:
        for dep in doc.dependencies:
            if dep.provenance == "lockfile" and dep.exact_version is not None:
                key = (dep.location.path.parent, dep.ecosystem, dep.name)
                locked.setdefault(key, set()).add(dep.exact_version)

    findings: list[Finding] = []
    diagnostics: list[str] = []
    for doc in normalized:
        duplicates: set[tuple[str, str, str]] = set()
        seen: set[tuple[str, str, str]] = set()
        for dep in doc.dependencies:
            group_key = (dep.ecosystem, dep.name, dep.group)
            if dep.provenance != "lockfile":
                if group_key in seen:
                    duplicates.add(group_key)
                seen.add(group_key)
        if duplicates:
            diagnostics.append(f"{doc.artifact.path}: duplicate dependency definitions")
        for dep in doc.dependencies:
            if (dep.ecosystem, dep.name, dep.group) in duplicates:
                continue
            lock_versions = locked.get((dep.location.path.parent, dep.ecosystem, dep.name), set())
            if (
                dep.provenance != "lockfile"
                and dep.exact_version
                and lock_versions
                and (dep.exact_version not in lock_versions)
            ):
                diagnostics.append(
                    f"{dep.location.path}: conflicting manifest and lockfile metadata"
                )
                continue
            if dep.source == "local" and dep.path_status in {"outside", "symlink", "unsafe"}:
                findings.append(
                    _finding(
                        dep,
                        "DRAGON-SC-005",
                        "Local dependency crosses a trust boundary",
                        Severity.MEDIUM,
                        "A declared local dependency cannot be established as a regular path "
                        "inside the scan boundary.",
                        f"local dependency {dep.name}: {dep.path_status}",
                        "Inspect the referenced path without following it during the scan.",
                    )
                )
            if dep.provenance == "lockfile":
                continue
            locked_registry = dep.source == "registry" and len(lock_versions) == 1
            if dep.source in {"url", "git-branch", "git-ref", "git"} and not dep.integrity:
                findings.append(
                    _finding(
                        dep,
                        "DRAGON-SC-002",
                        "Mutable remote dependency source",
                        Severity.LOW if dep.mechanism == "declaration" else Severity.MEDIUM,
                        "A remote dependency is not tied to an evidenced immutable commit "
                        "or artifact hash.",
                        f"{dep.ecosystem} package {dep.name} uses {dep.source}",
                        "Pin to an immutable commit or record independently verifiable "
                        "artifact integrity.",
                    )
                )
            if dep.mechanism == "install-and-execute" and dep.source in {
                "url",
                "git",
                "git-branch",
                "git-ref",
            }:
                findings.append(
                    _finding(
                        dep,
                        "DRAGON-SC-006",
                        "Remote dependency installed and executed",
                        Severity.HIGH,
                        "The same actionable instruction installs a remote dependency "
                        "then invokes a process.",
                        f"remote {dep.source} dependency {dep.name} installed before execution",
                        "Inspect the source and pin the artifact before executing it.",
                    )
                )
            if dep.mechanism == "declaration":
                if dep.pinning in _MUTABLE and dep.source == "registry" and not locked_registry:
                    findings.append(
                        _finding(
                            dep,
                            "DRAGON-SC-001",
                            "Mutable dependency declaration",
                            Severity.LOW,
                            "The declared package version may change on a later installation; "
                            "this is not proof of compromise.",
                            f"{dep.ecosystem} package {dep.name}: {dep.pinning}",
                            "Consider a reproducible lock and retain integrity/provenance "
                            "evidence.",
                        )
                    )
            elif (
                dep.group != "mcp"
                and dep.mechanism == "runtime-execution"
                and dep.pinning in _MUTABLE
            ):
                findings.append(
                    _finding(
                        dep,
                        "DRAGON-SC-003",
                        "Mutable runtime package execution",
                        Severity.MEDIUM,
                        "An actionable instruction runs a package through a runtime manager "
                        "without an evidenced immutable pin.",
                        f"{dep.manager} invokes {dep.name}: {dep.pinning}",
                        "Pin the runtime package and review the command before running it.",
                    )
                )
        if doc.artifact.path.name == "package.json":
            for entry in doc.entries:
                if (
                    len(entry.key_path) == 2
                    and entry.key_path[0] == "scripts"
                    and entry.key_path[1] in _HOOKS
                    and isinstance(entry.value, str)
                    and _DANGEROUS_HOOK.search(entry.value)
                ):
                    name = str(entry.key_path[1])
                    findings.append(
                        Finding(
                            detection_id="DRAGON-SC-004",
                            category="supply-chain",
                            title="Security-sensitive package lifecycle script",
                            severity=Severity.HIGH
                            if _REMOTE_INSTALLER.search(entry.value)
                            else Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            classification=Classification.RISKY,
                            artifact=doc.artifact.path,
                            line=entry.location.line,
                            evidence=(
                                f"{name} lifecycle script contains a remote execution or "
                                "sensitive-operation pattern"
                            ),
                            explanation=(
                                "Package lifecycle scripts may run during install; "
                                "the scanner has not run this one."
                            ),
                            remediation=(
                                "Review the script and disable or isolate untrusted install hooks."
                            ),
                            detector="supply_chain",
                        )
                    )
        if doc.artifact.path.name == "pyproject.toml":
            backend_path = any(
                entry.key_path[:2] == ("build-system", "backend-path") for entry in doc.entries
            )
            if backend_path:
                findings.append(
                    Finding(
                        detection_id="DRAGON-SC-007",
                        category="supply-chain",
                        title="Project-local build backend configured",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        classification=Classification.RISKY,
                        artifact=doc.artifact.path,
                        evidence="build-system.backend-path configures locally supplied build code",
                        explanation=(
                            "Installing/building this project may execute local backend code; "
                            "it was not executed during the scan."
                        ),
                        remediation="Review the local backend before building this project.",
                        detector="supply_chain",
                    )
                )
    return normalized, tuple(findings), tuple(dict.fromkeys(diagnostics))
