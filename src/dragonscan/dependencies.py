"""Bounded, offline dependency normalization from already-loaded local data."""

import ntpath
import os
import re
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from dragonscan.models import Artifact, Dependency, Document, SourceRef

MAX_DEPENDENCIES = 4096
_NAME = re.compile(r"(?:@[-\w.]+/)?[-\w.]+\Z", re.ASCII)
_PYTHON = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[([\w.,-]+)\])?(.*)\Z", re.ASCII)
_VERSION = re.compile(r"\d+(?:\.\d+)*(?:[-+][\w.]+)?\Z", re.ASCII)
_COMMIT = re.compile(r"[0-9a-fA-F]{40}\Z")
_INSTALL = re.compile(
    r"\b(?:python(?:3)?\s+-m\s+pip|pip(?:3)?|uv\s+pip)\s+install\s+([^\s;&|]+)", re.I
)
_RUNTIME = re.compile(
    r"\b(npx|bunx|uvx|pipx(?:\s+run)?|npm\s+exec|pnpm\s+dlx|yarn\s+dlx)\s+(?:--yes\s+|-y\s+)?([^\s;&|]+)",
    re.I,
)
_EXEC = re.compile(r"(?:&&|;)\s*(?:python(?:3)?|node|npx|uvx|sh|bash|\./[\w.-]+)\b", re.I)


def _name(value: str, ecosystem: str) -> str | None:
    if len(value) > 128 or not _NAME.fullmatch(value):
        return None
    return re.sub(r"[-_.]+", "-", value.lower()) if ecosystem == "python" else value.lower()


def _public_url(raw: str) -> str | None:
    """Only expose a valid scheme and host, never userinfo, path, query, or fragment."""
    try:
        parsed = urlsplit(raw.removeprefix("git+"))
        if parsed.scheme not in {"http", "https", "ssh"} or not parsed.hostname:
            return None
        host = parsed.hostname.lower()
        if not re.fullmatch(r"[a-z0-9.:-]{1,253}", host, re.I):
            return None
        return f"{parsed.scheme}://{host}"
    except ValueError:
        return None


def _git(raw: str) -> tuple[str, str]:
    # git+https://host/repo@revision and git+https://host/repo#revision
    try:
        path = urlsplit(raw.removeprefix("git+")).path
    except ValueError as exc:
        raise ValueError("invalid Git dependency URL") from exc
    fragment = raw.rsplit("#", 1)[1] if "#" in raw else ""
    revision = fragment or (path.rsplit("@", 1)[1] if "@" in path else "")
    if _COMMIT.fullmatch(revision):
        return "git-commit", "git-commit"
    if revision.startswith("refs/heads/"):
        return "git-branch", "git-branch"
    if revision.startswith("refs/tags/"):
        return "git-tag", "git-tag"
    if revision and re.fullmatch(r"[A-Za-z0-9._/-]{1,80}", revision):
        if revision.lower() in {"main", "master", "dev", "develop", "head"}:
            return "git-branch", "git-branch"
        return "git-ref", "git-ref-unknown"  # tags and branches are indistinguishable
    return "git", "unversioned"


def _classify(value: str, ecosystem: str) -> tuple[str, str, str | None, str | None, str | None]:
    """Return source, pinning, safe requested label, exact version, safe registry."""
    raw = value.strip()
    if len(raw) > 4096:
        raise ValueError("dependency specifier exceeds limit")
    if raw.startswith(("file:", "./", "../", "/")) or raw == ".":
        return "local", "local-path", None, None, None
    if "/" in raw and not raw.startswith(("@", "http", "git", "github:", "npm:")):
        return "local", "local-path", None, None, None
    if raw.startswith("workspace:"):
        return "workspace", "workspace", None, None, None
    if raw.startswith(("git+", "github:", "git@")):
        source, pin = (
            _git(raw)
            if raw.startswith("git+")
            else (
                ("git-commit", "git-commit")
                if _COMMIT.fullmatch(raw.rsplit("#", 1)[-1])
                else ("git", "git-ref-unknown")
            )
        )
        return source, pin, _public_url(raw) or "Git reference", None, None
    if raw.startswith(("http://", "https://")):
        public = _public_url(raw)
        if public is None:
            raise ValueError("invalid dependency URL")
        return "url", "mutable-url", public, None, None
    if raw.lower() in {"latest", "next"}:
        return "registry", "latest", raw.lower(), None, None
    if raw in {"", "*"}:
        return "registry", "wildcard" if raw == "*" else "unversioned", raw or None, None, None
    if ecosystem == "python":
        if re.fullmatch(r"[~^]\d+(?:\.\d+)*", raw):
            return "registry", "bounded-range", raw, None, None
        if raw.startswith("==") and _VERSION.fullmatch(raw[2:]):
            return "registry", "exact", raw, raw[2:], None
        if raw.startswith("==") and "*" in raw:
            return "registry", "wildcard", raw, None, None
        if re.fullmatch(r"(?:[!<>=~]=?\s*[\w.*+-]+\s*,?\s*)+", raw):
            return "registry", "bounded-range" if "<" in raw else "unbounded-range", raw, None, None
    else:
        if _VERSION.fullmatch(raw):
            return "registry", "exact", raw, raw, None
        if re.fullmatch(r"[~^]\d+(?:\.\d+)*", raw):
            return "registry", "bounded-range", raw, None, None
        if "*" in raw or raw.lower() == "x":
            return "registry", "wildcard", raw[:80], None, None
        if re.fullmatch(r"[<>]=?\d+(?:\.\d+)*(?:\s+\S+)?", raw):
            return "registry", "bounded-range" if "<" in raw else "unbounded-range", raw, None, None
    raise ValueError("unsupported dependency specifier")


def _make(
    artifact: Artifact,
    name: str,
    value: str,
    group: str,
    line: int | None = None,
    *,
    manager: str | None = None,
    mechanism: str = "declaration",
    provenance: str = "manifest",
    integrity: bool = False,
) -> Dependency:
    ecosystem = artifact.ecosystem or (
        "node" if artifact.path.name.lower() == "package.json" else "python"
    )
    normalized = _name(name, ecosystem)
    if normalized is None:
        raise ValueError("invalid package name")
    source, pinning, requested, exact, registry = _classify(value, ecosystem)
    return Dependency(
        ecosystem,
        normalized,
        requested,
        exact,
        pinning,
        source,
        manager or ("npm" if ecosystem == "node" else "pip"),
        mechanism,
        group,
        SourceRef(artifact.path, artifact.source_format, line),
        registry,
        artifact.path if provenance == "lockfile" else None,
        integrity,
        provenance,
        value.removeprefix("file:") if source == "local" else None,
    )


def _append(output: list[Dependency], item: Dependency) -> None:
    if len(output) >= MAX_DEPENDENCIES:
        raise ValueError("dependency count exceeds limit")
    output.append(item)


def parse_requirements(artifact: Artifact, text: str) -> Document:
    output: list[Dependency] = []
    diagnostics: list[str] = []
    registry: str | None = None
    indexes: set[str] = set()
    for line, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if value.startswith(("--index-url ", "--extra-index-url ")):
            configured = _public_url(value.split(None, 1)[1])
            if configured is None:
                diagnostics.append(f"line {line}: invalid registry URL")
            else:
                indexes.add(configured)
                if len(indexes) > 1:
                    if registry is not None:
                        diagnostics.append(
                            f"line {line}: multiple registries; package origin ambiguous"
                        )
                    registry = None
                else:
                    registry = configured
            continue
        if value.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            diagnostics.append(f"line {line}: nested requirement files are not followed")
            continue
        if value.startswith(("-e ", "--editable ")):
            value = value.split(None, 1)[1].strip()
            name = re.search(r"(?:[#&]egg=)([\w.-]+)", value)
            package = name.group(1) if name else Path(value).name or "local-project"
            if value in {".", "./", "../"} or value.startswith(("../", "./")):
                package = "local-project" if package in {".", ".."} else package
            spec = value.split("#egg=", 1)[0]
        elif value.startswith("-"):
            diagnostics.append(f"line {line}: unsupported requirement option")
            continue
        else:
            # Comments are stripped only when preceded by whitespace.
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
            direct = re.fullmatch(r"([\w.-]+)\s*@\s*(\S+)", value)
            if direct:
                package, spec = direct.groups()
            elif value.startswith(("git+", "http://", "https://", "./", "../", "/")) or (
                "/" in value and " " not in value and not value.startswith("@")
            ):
                package, spec = "direct-dependency", value
            else:
                match = _PYTHON.fullmatch(value)
                if match is None:
                    diagnostics.append(f"line {line}: invalid requirement")
                    continue
                package, _, spec = match.groups()
                spec = spec.strip().split(";", 1)[0].strip()
        try:
            item = _make(
                artifact,
                package,
                spec,
                "requirements",
                line,
                mechanism="editable"
                if raw.strip().startswith(("-e ", "--editable "))
                else "declaration",
            )
            _append(output, replace(item, registry=registry))
        except ValueError:
            diagnostics.append(f"line {line}: invalid requirement or dependency limit exceeded")
            if len(output) >= MAX_DEPENDENCIES:
                break
    if len(indexes) > 1:
        output = [replace(dep, registry=None) for dep in output]
    return Document(
        artifact, dependencies=tuple(output), diagnostics=tuple(diagnostics), registry=registry
    )


def parse_npmrc(artifact: Artifact, text: str) -> Document:
    # Registry metadata only: never retain token-bearing lines or auth credentials.
    diagnostics: list[str] = []
    registry: str | None = None
    scopes: dict[str, str] = {}
    for line, raw in enumerate(text.splitlines(), 1):
        key, sep, value = raw.partition("=")
        option = key.strip().lower()
        if sep and (option == "registry" or re.fullmatch(r"@[\w.-]+:registry", option)):
            origin = _public_url(value.strip())
            if origin is None:
                diagnostics.append(f"line {line}: invalid registry URL")
            elif option == "registry":
                registry = origin
            else:
                scopes[option.removesuffix(":registry")] = origin
    return Document(
        artifact,
        diagnostics=tuple(diagnostics),
        registry=registry,
        registry_scopes=tuple(scopes.items()),
    )


def parse_yarn(artifact: Artifact, text: str) -> Document:
    # Yarn v1 selectors are not JSON/YAML. Parse only ordinary quoted selectors.
    if text.lstrip().startswith(("__metadata:", "# yarn lockfile v2")):
        return Document(artifact, diagnostics=("unsupported Yarn Berry lockfile version",))
    output: list[Dependency] = []
    diagnostics: list[str] = []
    selectors: list[str] = []
    for line, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        if not raw.startswith(" ") and raw.endswith(":"):
            selectors = [part.strip().strip('"') for part in raw[:-1].split(",")]
        elif raw.startswith("  version ") and selectors:
            version = raw.strip().partition(" ")[2].strip('"')
            for selector in selectors:
                match = re.fullmatch(r"(@[^/]+/[^@]+|[^@]+)@.+", selector)
                if match:
                    try:
                        _append(
                            output,
                            _make(
                                artifact,
                                match.group(1),
                                version,
                                "locked",
                                line,
                                manager="yarn",
                                provenance="lockfile",
                            ),
                        )
                    except ValueError:
                        diagnostics.append(f"line {line}: invalid Yarn lock entry")
            selectors = []
    return Document(artifact, dependencies=tuple(output), diagnostics=tuple(diagnostics))


def structured_dependencies(
    artifact: Artifact, data: dict[str, Any], locations: dict[tuple[str | int, ...], SourceRef]
) -> tuple[tuple[Dependency, ...], tuple[str, ...]]:
    name = artifact.path.name.lower()
    output: list[Dependency] = []
    diagnostics: list[str] = []

    def add(
        package: object,
        spec: object,
        group: str,
        key: tuple[str | int, ...],
        *,
        manager: str | None = None,
        provenance: str = "manifest",
        integrity: bool = False,
    ) -> None:
        line = locations[key].line if key in locations else None
        try:
            if not isinstance(package, str) or not isinstance(spec, str):
                raise ValueError("invalid dependency definition")
            _append(
                output,
                _make(
                    artifact,
                    package,
                    spec,
                    group,
                    line,
                    manager=manager,
                    provenance=provenance,
                    integrity=integrity,
                ),
            )
        except ValueError:
            diagnostics.append(
                f"dependency at line {line or 'unknown'}: unsupported or malformed definition"
            )

    if name == "pyproject.toml":
        project = data.get("project", {})
        if isinstance(project, dict):
            for group, specs in (("runtime", project.get("dependencies", [])),):
                if isinstance(specs, list):
                    for i, spec in enumerate(specs):
                        _add_python(spec, group, ("project", "dependencies", i), add)
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for group, specs in optional.items():
                    if isinstance(specs, list):
                        for i, spec in enumerate(specs):
                            _add_python(
                                spec,
                                f"optional:{group}",
                                ("project", "optional-dependencies", group, i),
                                add,
                            )
        groups = data.get("dependency-groups", {})
        if isinstance(groups, dict):
            for group, specs in groups.items():
                if isinstance(specs, list):
                    for i, spec in enumerate(specs):
                        _add_python(spec, f"group:{group}", ("dependency-groups", group, i), add)
        tool = data.get("tool", {})
        poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        if isinstance(poetry, dict):
            deps = poetry.get("dependencies", {})
            if isinstance(deps, dict):
                for pkg, spec in deps.items():
                    if pkg == "python":
                        continue
                    if isinstance(spec, dict):
                        if isinstance(spec.get("path"), str):
                            spec = spec["path"]
                        elif isinstance(spec.get("url"), str):
                            spec = spec["url"]
                        elif isinstance(spec.get("git"), str):
                            revision = spec.get("rev", spec.get("branch", spec.get("tag", "")))
                            spec = "git+" + spec["git"] + (f"#{revision}" if revision else "")
                        else:
                            spec = spec.get("version", "")
                    add(
                        pkg,
                        spec,
                        "runtime",
                        ("tool", "poetry", "dependencies", pkg),
                        manager="poetry",
                    )
    elif name == "uv.lock":
        packages = data.get("package", [])
        if not isinstance(packages, list):
            diagnostics.append("invalid uv lock package list")
        else:
            for i, entry in enumerate(packages[: MAX_DEPENDENCIES + 1]):
                if not isinstance(entry, dict):
                    diagnostics.append(f"uv lock entry {i}: invalid package")
                    continue
                source = entry.get("source", {})
                spec = entry.get("version")
                if isinstance(source, dict) and "git" in source:
                    spec = source["git"]
                elif isinstance(source, dict) and "url" in source:
                    spec = source["url"]
                elif isinstance(source, dict) and ("directory" in source or "editable" in source):
                    spec = source.get("directory", source.get("editable"))
                artifacts = entry.get("wheels", [])
                sdist = entry.get("sdist")
                integrity = (
                    isinstance(artifacts, list)
                    and bool(artifacts)
                    and all(
                        isinstance(wheel, dict) and isinstance(wheel.get("hash"), str)
                        for wheel in artifacts
                    )
                ) or (isinstance(sdist, dict) and isinstance(sdist.get("hash"), str))
                add(
                    entry.get("name"),
                    spec,
                    "locked",
                    ("package", i),
                    manager="uv",
                    provenance="lockfile",
                    integrity=integrity,
                )
    elif name == "package.json":
        for group in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            packages = data.get(group, {})
            if not isinstance(packages, dict):
                diagnostics.append(f"invalid {group} mapping")
                continue
            for package, spec in packages.items():
                add(package, spec, group, (group, package))
    elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
        version = data.get("lockfileVersion")
        if version not in {2, 3}:
            diagnostics.append("unsupported npm lockfile version (supported: 2, 3)")
        else:
            packages = data.get("packages", {})
            if not isinstance(packages, dict):
                diagnostics.append("invalid npm lock packages")
            else:
                for path, entry in packages.items():
                    if (
                        not isinstance(path, str)
                        or "node_modules/" not in path
                        or not isinstance(entry, dict)
                    ):
                        continue
                    package = path.rsplit("node_modules/", 1)[-1]
                    spec = (
                        entry.get("resolved")
                        if isinstance(entry.get("resolved"), str)
                        and entry["resolved"].startswith(("git+", "file:"))
                        else entry.get("version")
                    )
                    add(
                        package,
                        spec,
                        "locked",
                        ("packages", path),
                        provenance="lockfile",
                        integrity=isinstance(entry.get("integrity"), str),
                    )
    elif name == "pnpm-lock.yaml":
        version = str(data.get("lockfileVersion", "")).strip("'\"")
        if not version.startswith(("6.", "9.")):
            diagnostics.append("unsupported pnpm lockfile version (supported: 6, 9)")
        else:
            packages = data.get("packages", {})
            if isinstance(packages, dict):
                for path, entry in packages.items():
                    if not isinstance(path, str) or not isinstance(entry, dict):
                        continue
                    match = re.fullmatch(r"/?(@[^/]+/[^@/]+|[^/@]+)@([^()]+)(?:\(.*\))?", path)
                    if match:
                        add(
                            match.group(1),
                            match.group(2),
                            "locked",
                            ("packages", path),
                            manager="pnpm",
                            provenance="lockfile",
                            integrity=bool(entry.get("resolution", {}).get("integrity"))
                            if isinstance(entry.get("resolution"), dict)
                            else False,
                        )
            else:
                diagnostics.append("invalid pnpm lock packages")
    if name == "pyproject.toml":
        tool = data.get("tool")
        uv = tool.get("uv") if isinstance(tool, dict) else None
        if isinstance(uv, dict) and isinstance(uv.get("index-url"), str):
            registry = _public_url(uv["index-url"])
            if registry is None:
                diagnostics.append("invalid uv index URL")
            else:
                output = [
                    replace(dep, registry=registry) if dep.source == "registry" else dep
                    for dep in output
                ]
    return tuple(output), tuple(diagnostics)


def _add_python(spec: object, group: str, key: tuple[str | int, ...], add: Any) -> None:
    if not isinstance(spec, str) or len(spec) > 4096:
        add("", "", group, key)
        return
    direct = re.fullmatch(r"\s*([\w.-]+)\s*@\s*(\S+)\s*", spec)
    if direct:
        add(direct.group(1), direct.group(2), group, key)
        return
    match = _PYTHON.fullmatch(spec.strip())
    if match:
        add(match.group(1), match.group(3).split(";", 1)[0].strip(), group, key)
    else:
        add("", "", group, key)


def _command_context(text: str, start: int, end: int) -> bool:
    """Only treat a runtime mention as an invocation in a command-shaped clause."""
    before = text[:start].rsplit("\n", 1)[-1].rstrip()
    after = text[end:].split("\n", 1)[0]
    if re.search(r"(?:^|[;&|])\s*(?:[$>]\s*)?$", before):
        # A command line, not a phrase introducing a possible use of the tool.
        return True
    if before.endswith("`") and "`" in after:
        return True
    return bool(re.search(r"\b(?:run|execute|invoke)\s*$", before, re.I))


def runtime_dependencies(document: Document) -> tuple[Dependency, ...]:
    artifact = document.artifact
    output: list[Dependency] = []
    for server in document.servers:
        if (
            not server.package
            or not server.runtime
            or server.runtime
            in {
                "docker",
                "podman",
                "nerdctl",
                "python",
                "python3",
                "python.exe",
            }
        ):
            continue
        # Reuse MCP's package identity/version, not a separate MCP-only scanner model.
        python_runtime = server.runtime in {"uvx", "pipx", "pipx.exe"}
        spec = server.package + (
            ("" if python_runtime else "@") + server.package_version
            if server.package_version
            else ""
        )
        dep = _runtime_package(artifact, spec, server.runtime, server.location.line, "mcp")
        if dep:
            output.append(dep)
    for block in document.blocks:
        if block.kind in {"quote", "code", "heading"}:
            continue
        for match in _RUNTIME.finditer(block.text):
            if not _command_context(block.text, match.start(), match.end()):
                continue
            dep = _runtime_package(
                artifact,
                match.group(2).rstrip(".,"),
                match.group(1),
                block.location.line,
                "instruction",
            )
            if dep:
                output.append(dep)
        for match in _INSTALL.finditer(block.text):
            dep = _runtime_package(
                artifact,
                match.group(1).rstrip(".,"),
                "pip",
                block.location.line,
                "instruction-install"
                if _EXEC.search(block.text[match.end() :])
                else "instruction-setup",
            )
            if dep:
                output.append(dep)
    return tuple(output[:MAX_DEPENDENCIES])


def _runtime_package(
    artifact: Artifact, token: str, manager: str, line: int | None, group: str
) -> Dependency | None:
    ecosystem = "python" if manager.split()[0] in {"uvx", "pipx", "pip"} else "node"
    package_artifact = replace(artifact, ecosystem=ecosystem)
    if token.startswith("-") or len(token) > 4096:
        return None
    if ecosystem == "python":
        if token.startswith(("git+", "http://", "https://")):
            name, spec = "direct-dependency", token
        else:
            match = _PYTHON.fullmatch(token)
            if match is None:
                return None
            name, _, spec = match.groups()
    else:
        name, sep, version = token.rpartition("@")
        if not sep or not name:
            name, spec = token, ""
        else:
            spec = version
    try:
        mechanism = (
            "install-and-execute"
            if group == "instruction-install"
            else "installation"
            if group == "instruction-setup"
            else "runtime-execution"
        )
        return _make(
            package_artifact, name, spec, group, line, manager=manager, mechanism=mechanism
        )
    except ValueError:
        return None


def local_status(dependency: Dependency, boundary: Path) -> Dependency:
    if dependency.source != "local" or dependency.path_status is None:
        return dependency
    reference = dependency.path_status
    if (
        "\x00" in reference
        or "%" in reference
        or "\\" in reference
        or ntpath.isabs(reference)
        or reference.startswith("~")
        or ":" in reference.split("/")[0]
    ):
        return replace(dependency, path_status="unsafe")
    root = boundary.absolute() if boundary.is_dir() else boundary.absolute().parent
    lexical = Path(os.path.normpath(dependency.location.path.parent / reference))
    if not lexical.is_relative_to(root):
        return replace(dependency, path_status="outside")
    current = root
    for part in lexical.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            return replace(dependency, path_status="symlink")
    return replace(dependency, path_status="inside" if lexical.exists() else "missing")


def install_then_execute(text: str) -> bool:
    return bool(_INSTALL.search(text) and _EXEC.search(text))
