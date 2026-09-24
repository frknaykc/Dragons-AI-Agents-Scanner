"""Static artifact discovery. Never follow symlinks or inspect arbitrary files."""

import os
from pathlib import Path

from dragonscan.models import Artifact, ArtifactKind, SourceFormat, Target

INSTRUCTION_NAMES = frozenset({"skill.md", "agents.md", "soul.md", "memory.md", "claude.md"})
MCP_NAMES = frozenset({"mcp.json", ".mcp.json", "mcp-config.json", "claude_desktop_config.json"})
SKIP_DIRS = frozenset({".git", ".venv", "node_modules", "__pycache__"})
MAX_FILES = 10_000
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
CONFIG_STEMS = frozenset({"config", "settings"})


class DiscoveryError(ValueError):
    """The target cannot be safely discovered."""


def classify(path: Path, *, explicit: bool = False) -> Artifact | None:
    name = path.name.lower()
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
    if name in INSTRUCTION_NAMES:
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
    elif name == "package.json" and "skills" in (p.lower() for p in path.parent.parts):
        kind = ArtifactKind.DEPENDENCY_MANIFEST
    elif path.stem.lower() in CONFIG_STEMS or name in {"settings.local.json", "claude.json"}:
        if ecosystem is None and not explicit:
            return None
        kind = (
            ArtifactKind.AGENT_CONFIG if ecosystem is not None else ArtifactKind.STRUCTURED_CONFIG
        )
    else:
        return None
    return Artifact(path, kind, source_format, ecosystem)


def discover(target: Target) -> tuple[Artifact, ...]:
    path = target.path.absolute()
    if path.is_symlink():
        raise DiscoveryError("symlink target is not supported")
    if path.is_file():
        artifact = classify(path, explicit=True)
        if artifact is None:
            raise DiscoveryError("unsupported file type")
        return (artifact,)
    if not path.is_dir():
        raise DiscoveryError("target does not exist or is not a regular file/directory")

    artifacts: list[Artifact] = []

    def on_error(error: OSError) -> None:
        raise DiscoveryError(f"directory traversal failed: {error.strerror}")

    for root, dirs, files in os.walk(path, followlinks=False, onerror=on_error):
        dirs[:] = sorted(
            d for d in dirs if d not in SKIP_DIRS and not (Path(root) / d).is_symlink()
        )
        for name in sorted(files):
            candidate = Path(root) / name
            artifact = classify(candidate)
            if artifact is not None and not candidate.is_symlink():
                artifacts.append(artifact)
                if len(artifacts) > MAX_FILES:
                    raise DiscoveryError("artifact count exceeds limit")
    return tuple(artifacts)
