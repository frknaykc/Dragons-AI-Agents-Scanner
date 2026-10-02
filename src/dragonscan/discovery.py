"""Static artifact discovery. Never follow symlinks or inspect arbitrary files."""

import heapq
import os
import stat
from pathlib import Path

from dragonscan.models import Artifact, ArtifactKind, SourceFormat, Target

INSTRUCTION_NAMES = frozenset({"skill.md", "agents.md", "soul.md", "memory.md", "claude.md"})
MCP_NAMES = frozenset({"mcp.json", ".mcp.json", "mcp-config.json", "claude_desktop_config.json"})
SKIP_DIRS = frozenset({".git", ".venv", "node_modules", "__pycache__"})
MAX_FILES = 10_000
MAX_INSTALLED_PROJECT_ARTIFACTS = 256
ECOSYSTEM_DIRS = {
    ".claude": "claude-code",
    ".claude-plugin": "claude-code",
    ".codex": "codex",
    ".cursor": "cursor",
    ".gemini": "gemini-cli",
    ".windsurf": "windsurf",
    ".openclaw": "openclaw",
}
FORMATS = {
    ".md": SourceFormat.MARKDOWN,
    ".json": SourceFormat.JSON,
    ".yaml": SourceFormat.YAML,
    ".yml": SourceFormat.YAML,
    ".toml": SourceFormat.TOML,
}
DEPENDENCY_FILES = {
    "pyproject.toml": ("python", SourceFormat.TOML),
    "uv.lock": ("python", SourceFormat.TOML),
    "package.json": ("node", SourceFormat.JSON),
    "package-lock.json": ("node", SourceFormat.JSON),
    "npm-shrinkwrap.json": ("node", SourceFormat.JSON),
    "pnpm-lock.yaml": ("node", SourceFormat.YAML),
    "yarn.lock": ("node", SourceFormat.TEXT),
    ".npmrc": ("node", SourceFormat.TEXT),
}
CONFIG_STEMS = frozenset({"config", "settings"})


class DiscoveryError(ValueError):
    """The target cannot be safely discovered."""


def classify(
    path: Path, *, explicit: bool = False, installed_project: bool = False
) -> Artifact | None:
    name = path.name.lower()
    dependency = DEPENDENCY_FILES.get(name)
    if dependency is None and (
        name in {"requirements.txt", "requirements.in"}
        or (name.startswith("requirements-") and name.endswith((".txt", ".in")))
    ):
        dependency = ("python", SourceFormat.TEXT)
    if dependency is not None:
        dep_ecosystem, dep_format = dependency
        ecosystem: str | None = dep_ecosystem
        # Preserve the established ecosystem classification for skill metadata.
        if name == "package.json" and "skills" in (p.lower() for p in path.parent.parts):
            ecosystem = None
        return Artifact(path, ArtifactKind.DEPENDENCY_MANIFEST, dep_format, ecosystem)
    source_format = FORMATS.get(path.suffix.lower())
    if source_format is None:
        return None
    ecosystem = next(
        (
            ECOSYSTEM_DIRS[part.lower()]
            for part in reversed(path.parent.parts)
            if part.lower() in ECOSYSTEM_DIRS
        ),
        None,
    )
    if name in INSTRUCTION_NAMES or (
        installed_project and name == "gemini.md" and ecosystem == "gemini-cli"
    ):
        kind = {
            "skill.md": ArtifactKind.SKILL,
            "memory.md": ArtifactKind.MEMORY,
            "soul.md": ArtifactKind.SOUL,
        }.get(name, ArtifactKind.INSTRUCTIONS)
    elif name in MCP_NAMES:
        kind = ArtifactKind.MCP_CONFIG
    elif path.parent.name.lower() == ".claude-plugin" and name == "plugin.json":
        kind = ArtifactKind.PLUGIN_METADATA
    elif name == "hooks.json" and ecosystem is not None:
        kind = ArtifactKind.HOOK_CONFIG
    elif installed_project and name == "openclaw.json" and ecosystem == "openclaw":
        kind = ArtifactKind.AGENT_CONFIG
    elif path.stem.lower() in CONFIG_STEMS or name in {"settings.local.json", "claude.json"}:
        if ecosystem is None and not explicit:
            return None
        kind = (
            ArtifactKind.AGENT_CONFIG if ecosystem is not None else ArtifactKind.STRUCTURED_CONFIG
        )
    else:
        return None
    return Artifact(path, kind, source_format, ecosystem)


def discover(target: Target, *, installed_project: bool = False) -> tuple[Artifact, ...]:
    path = target.path.absolute()
    if path.is_symlink():
        raise DiscoveryError("symlink target is not supported")
    if path.is_file():
        artifact = classify(path, explicit=True, installed_project=installed_project)
        if artifact is None:
            raise DiscoveryError("unsupported file type")
        return (artifact,)
    if not path.is_dir():
        raise DiscoveryError("target does not exist or is not a regular file/directory")

    artifacts: list[Artifact] = []
    entries = 0

    def on_error(error: OSError) -> None:
        raise DiscoveryError(f"directory traversal failed: {error.strerror}")

    for root, dirs, files in os.walk(path, followlinks=False, onerror=on_error):
        if installed_project:
            entries += len(dirs) + len(files)
            if entries > 8192:
                raise DiscoveryError("project agent discovery entry limit exceeded")
        dirs[:] = sorted(
            d for d in dirs if d not in SKIP_DIRS and not (Path(root) / d).is_symlink()
        )
        if installed_project and dirs and len(Path(root).relative_to(path).parts) >= 8:
            raise DiscoveryError("project agent discovery depth limit exceeded")
        for name in sorted(files):
            candidate = Path(root) / name
            artifact = classify(candidate, installed_project=installed_project)
            if artifact is None:
                continue
            if installed_project:
                try:
                    mode = candidate.lstat().st_mode
                except OSError as exc:
                    raise DiscoveryError(
                        f"project agent artifact inaccessible: {type(exc).__name__}"
                    ) from None
                if stat.S_ISLNK(mode):
                    continue
                if not stat.S_ISREG(mode):
                    raise DiscoveryError("project agent artifact is not a regular file")
            elif candidate.is_symlink():
                continue
            artifacts.append(artifact)
            if installed_project and len(artifacts) > MAX_INSTALLED_PROJECT_ARTIFACTS:
                raise DiscoveryError("project agent artifact limit exceeded")
            if len(artifacts) > MAX_FILES:
                raise DiscoveryError("artifact count exceeds limit")
    return tuple(artifacts)


def discover_bounded(
    target: Target, *, max_depth: int, max_entries: int, max_artifacts: int
) -> tuple[Artifact, ...]:
    """Reuse classification with strict directory/entry budgets for known agent roots.

    A limit failure discards the root instead of silently omitting candidates.
    """
    path = target.path.absolute()
    if path.is_symlink() or not path.is_dir():
        raise DiscoveryError("agent root is not a regular directory")
    pending = [(path, 0)]
    entries = 0
    artifacts: list[Artifact] = []
    while pending:
        root, depth = pending.pop()
        try:
            if not stat.S_ISDIR(root.lstat().st_mode):
                raise DiscoveryError("agent directory changed during traversal")
            with os.scandir(root) as stream:
                names = []
                for entry in stream:
                    entries += 1
                    if entries > max_entries:
                        raise DiscoveryError("agent discovery entry limit exceeded")
                    names.append(entry.name)
        except OSError as exc:
            raise DiscoveryError(f"agent directory inaccessible: {type(exc).__name__}") from None
        for name in sorted(names, reverse=True):
            candidate = root / name
            try:
                mode = candidate.lstat().st_mode
            except OSError as exc:
                raise DiscoveryError(f"agent entry inaccessible: {type(exc).__name__}") from None
            if stat.S_ISDIR(mode):
                if name not in SKIP_DIRS:
                    if depth >= max_depth:
                        raise DiscoveryError("agent discovery depth limit exceeded")
                    pending.append((candidate, depth + 1))
            elif stat.S_ISREG(mode):
                artifact = classify(candidate)
                if artifact is not None:
                    artifacts.append(artifact)
                    if len(artifacts) > max_artifacts:
                        raise DiscoveryError("agent discovery artifact limit exceeded")
    return tuple(sorted(artifacts, key=lambda item: str(item.path)))


# Installed discovery only: do not change explicit project scanning or its limits.
_SECONDARY_DIRS = frozenset(
    {"cache", "vendor_imports", "extensions", "projects", "sessions", "file-history"}
)
_EPHEMERAL_DIRS = frozenset({".tmp", ".staging", "tmp", "session-env", "paste-cache"})


def discover_installed_bounded(
    target: Target, *, max_depth: int, max_entries: int, max_artifacts: int
) -> tuple[tuple[Artifact, ...], str | None]:
    """Scan known roots by active-first breadth, retaining evidence on budget exhaustion.

    Cache/staging are lower priority, not silently ignored. Each visited entry
    still counts against the same per-root budget, including unclassified files.
    """
    path = target.path.absolute()
    if path.is_symlink() or not path.is_dir():
        raise DiscoveryError("agent root is not a regular directory")
    pending: list[tuple[int, int, str, Path]] = [(0, 0, str(path), path)]
    entries = 0
    artifacts: list[Artifact] = []
    diagnostic: str | None = None
    while pending:
        priority, depth, _, root = heapq.heappop(pending)
        exhausted = False
        try:
            if not stat.S_ISDIR(root.lstat().st_mode):
                raise DiscoveryError("agent directory changed during traversal")
            with os.scandir(root) as stream:
                names = []
                for entry in stream:
                    entries += 1
                    if entries > max_entries:
                        exhausted = True
                        break
                    names.append(entry.name)
        except OSError as exc:
            raise DiscoveryError(f"agent directory inaccessible: {type(exc).__name__}") from None
        for name in sorted(names):
            candidate = root / name
            try:
                mode = candidate.lstat().st_mode
            except OSError as exc:
                raise DiscoveryError(f"agent entry inaccessible: {type(exc).__name__}") from None
            if stat.S_ISDIR(mode) and name not in SKIP_DIRS:
                if depth >= max_depth:
                    diagnostic = "agent discovery depth limit exceeded"
                    continue
                lower = name.lower()
                rank = (
                    2
                    if lower in _EPHEMERAL_DIRS or lower.startswith("marketplace-upgrade-")
                    else (1 if lower in _SECONDARY_DIRS else 0)
                )
                next_priority = max(priority, rank)
                heapq.heappush(pending, (next_priority, depth + 1, str(candidate), candidate))
            elif stat.S_ISREG(mode):
                artifact = classify(candidate)
                if artifact is not None:
                    if len(artifacts) >= max_artifacts:
                        return tuple(artifacts), "agent discovery artifact limit exceeded"
                    artifacts.append(artifact)
        if exhausted:
            return tuple(artifacts), "agent discovery entry limit exceeded"
    return tuple(artifacts), diagnostic
