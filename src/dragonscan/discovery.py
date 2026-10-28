"""Static artifact discovery. Never follow symlinks or inspect arbitrary files."""

import heapq
import os
import stat
from collections.abc import Callable
from pathlib import Path

from dragonscan.models import Artifact, ArtifactKind, SourceFormat, Target

INSTRUCTION_NAMES = frozenset({"skill.md", "agents.md", "soul.md", "memory.md", "claude.md"})
MCP_NAMES = frozenset({"mcp.json", ".mcp.json", "mcp-config.json", "claude_desktop_config.json"})
SKIP_DIRS = frozenset({".git", ".venv", "node_modules", "__pycache__"})
# Optional policy override; no cumulative artifact cap by default.
MAX_FILES: int | None = None
# Bounds on traversal working memory, not cumulative tree size.
MAX_ENTRIES = 100_000
MAX_PENDING_DIRS = 8192
MAX_DEPTH = 64
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
    ".jsonc": SourceFormat.JSONC,
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
    # Imported here because installed discovery also uses this module's bounded walk.
    from dragonscan.installed_agents import classify_agent_config

    known_config = classify_agent_config(path)
    if known_config is not None:
        return known_config
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
    elif name == "settings.json" and path.parent.name == ".zed":
        kind = ArtifactKind.AGENT_CONFIG
        ecosystem = "Zed Agent"
    elif name == "kilo.jsonc" or name == "kilo.json":
        kind = ArtifactKind.AGENT_CONFIG
        ecosystem = "Kilo Code"
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


def discover(
    target: Target,
    *,
    installed_project: bool = False,
    known_artifact: Callable[[Path], Artifact | None] | None = None,
    max_artifacts: int | None = None,
    max_depth: int | None = None,
    limit_diagnostics: list[str] | None = None,
) -> tuple[Artifact, ...]:
    if max_artifacts is not None and max_artifacts < 1:
        raise ValueError("artifact budget must be positive")
    if max_depth is not None and max_depth < 1:
        raise ValueError("directory depth must be positive")
    artifact_limit = max_artifacts if max_artifacts is not None else MAX_FILES
    path = target.path.absolute()
    if path.is_symlink():
        raise DiscoveryError("symlink target is not supported")
    if path.is_file():
        artifact = (known_artifact(path) if known_artifact is not None else None) or classify(
            path, explicit=True, installed_project=installed_project
        )
        if artifact is None:
            raise DiscoveryError("unsupported file type")
        return (artifact,)
    if not path.is_dir():
        raise DiscoveryError("target does not exist or is not a regular file/directory")

    bounded_artifacts, diagnostic = discover_installed_bounded(
        target,
        max_depth=max_depth if max_depth is not None else (8 if installed_project else MAX_DEPTH),
        max_entries=None,
        max_directory_entries=8192 if installed_project else MAX_ENTRIES,
        max_artifacts=artifact_limit,
        known_artifact=known_artifact,
        installed_project=installed_project,
    )
    if diagnostic is not None:
        if "artifact limit" in diagnostic:
            raise DiscoveryError("artifact count exceeds limit")
        message = diagnostic.replace("agent discovery", "project discovery")
        if limit_diagnostics is None:
            raise DiscoveryError(message)
        limit_diagnostics.append(message)
    return tuple(
        sorted(
            bounded_artifacts,
            key=lambda item: (item.path.parent.relative_to(path).parts, item.path.name),
        )
    )


def discover_bounded(
    target: Target, *, max_depth: int, max_entries: int, max_artifacts: int
) -> tuple[Artifact, ...]:
    """Reuse classification with strict directory/entry budgets for known agent roots.

    A limit failure discards the root instead of silently omitting candidates.
    """
    artifacts, diagnostic = discover_installed_bounded(
        target, max_depth=max_depth, max_entries=max_entries, max_artifacts=max_artifacts
    )
    if diagnostic is not None:
        raise DiscoveryError(diagnostic)
    return tuple(sorted(artifacts, key=lambda item: str(item.path)))


# Active artifacts precede caches in the shared bounded traversal.
_SECONDARY_DIRS = frozenset(
    {"cache", "vendor_imports", "extensions", "projects", "sessions", "file-history"}
)
_EPHEMERAL_DIRS = frozenset({".tmp", ".staging", "tmp", "session-env", "paste-cache"})


def discover_installed_bounded(
    target: Target,
    *,
    max_depth: int,
    max_entries: int | None,
    max_artifacts: int | None,
    known_artifact: Callable[[Path], Artifact | None] | None = None,
    descend: Callable[[Path], bool] | None = None,
    strict_artifact: bool = False,
    max_directory_entries: int = MAX_ENTRIES,
    max_pending_dirs: int = MAX_PENDING_DIRS,
    installed_project: bool = False,
) -> tuple[tuple[Artifact, ...], str | None]:
    """Scan roots active-first and depth-first, retaining evidence on exhaustion.

    Cache/staging are lower priority, not silently ignored. Optional total budgets
    count unclassified entries too. Directory buffers, pending directories and
    depth are bounded independently of total tree size. An oversized directory is
    omitted as a unit: a filesystem-order prefix cannot be selected deterministically.
    Previously discovered evidence and unrelated subtrees are retained on failure.
    """
    path = target.path.absolute()
    if path.is_symlink() or not path.is_dir():
        raise DiscoveryError("agent root is not a regular directory")
    pending: list[tuple[int, int, str, Path]] = [(0, 0, str(path), path)]
    entries = 0
    artifacts: list[Artifact] = []
    diagnostics: list[str] = []

    def diagnose(message: str) -> None:
        if message not in diagnostics:
            diagnostics.append(message)

    while pending:
        priority, negative_depth, _, root = heapq.heappop(pending)
        depth = -negative_depth
        oversized = False
        try:
            if not stat.S_ISDIR(root.lstat().st_mode):
                diagnose("agent directory changed during traversal")
                continue
            with os.scandir(root) as stream:
                names: list[str] = []
                for entry in stream:
                    entries += 1
                    if max_entries is not None and entries > max_entries:
                        diagnose("agent discovery entry limit exceeded")
                        return tuple(artifacts), "; ".join(diagnostics)
                    if len(names) >= max_directory_entries:
                        oversized = True
                        break
                    names.append(entry.name)
        except OSError as exc:
            diagnose(f"agent directory inaccessible: {type(exc).__name__}")
            continue
        if oversized:
            diagnose("agent discovery directory entry limit exceeded")
            continue
        for name in sorted(names):
            candidate = root / name
            try:
                mode = candidate.lstat().st_mode
            except OSError as exc:
                diagnose(f"agent entry inaccessible: {type(exc).__name__}")
                continue
            if stat.S_ISDIR(mode) and name not in SKIP_DIRS:
                if descend is not None and not descend(candidate):
                    continue
                if depth >= max_depth:
                    diagnose("agent discovery depth limit exceeded")
                    continue
                if len(pending) >= max_pending_dirs:
                    diagnose("agent discovery frontier limit exceeded")
                    continue
                lower = name.lower()
                rank = (
                    2
                    if lower in _EPHEMERAL_DIRS or lower.startswith("marketplace-upgrade-")
                    else (1 if lower in _SECONDARY_DIRS else 0)
                )
                next_priority = max(priority, rank)
                heapq.heappush(pending, (next_priority, -(depth + 1), str(candidate), candidate))
            elif stat.S_ISREG(mode):
                artifact = known_artifact(candidate) if known_artifact is not None else None
                if artifact is None and not strict_artifact:
                    artifact = classify(candidate, installed_project=installed_project)
                if artifact is not None:
                    if max_artifacts is not None and len(artifacts) >= max_artifacts:
                        diagnose("agent discovery artifact limit exceeded")
                        return tuple(artifacts), "; ".join(diagnostics)
                    artifacts.append(artifact)
            elif installed_project and not stat.S_ISLNK(mode):
                artifact = known_artifact(candidate) if known_artifact is not None else None
                if artifact is not None or classify(candidate, installed_project=True) is not None:
                    diagnose("project agent artifact is not a regular file")
    return tuple(artifacts), "; ".join(diagnostics) or None
