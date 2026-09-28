"""Opt-in, offline discovery of bounded, known agent configuration locations."""

import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from dragonscan.discovery import DiscoveryError, discover_bounded
from dragonscan.models import (
    Artifact,
    ArtifactKind,
    ArtifactOrigin,
    InstalledEnvironment,
    SourceFormat,
    Target,
)

MAX_ENVIRONMENTS = 12
MAX_ARTIFACTS = 256
MAX_ENTRIES_PER_ROOT = 2048
MAX_DEPTH = 4


@dataclass(frozen=True)
class Location:
    relative: str
    markers: tuple[str, ...]
    extra: tuple[tuple[str, ArtifactKind, SourceFormat], ...] = ()


@dataclass(frozen=True)
class AgentSpec:
    kind: str
    locations: tuple[Location, ...]


SPECS = (
    AgentSpec("Claude Code", (Location(".claude", ("settings.json", "CLAUDE.md", "skills")),)),
    AgentSpec("Codex", (Location(".codex", ("config.toml", "AGENTS.md", "skills")),)),
    AgentSpec("Cursor", (Location(".cursor", ("mcp.json", "settings.json", "rules")),)),
    AgentSpec(
        "Gemini CLI",
        (
            Location(
                ".gemini",
                ("settings.json", "GEMINI.md"),
                (("GEMINI.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),),
            ),
        ),
    ),
    AgentSpec(
        "Windsurf",
        (
            Location(
                ".codeium/windsurf",
                ("mcp_config.json",),
                (("mcp_config.json", ArtifactKind.MCP_CONFIG, SourceFormat.JSON),),
            ),
            Location(".windsurf", ("settings.json", "mcp.json")),
        ),
    ),
    AgentSpec(
        "OpenClaw",
        (
            Location(
                ".openclaw",
                ("openclaw.json", "AGENTS.md", "SOUL.md"),
                (("openclaw.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
            ),
        ),
    ),
)

PLATFORM_LOCATIONS = {
    "darwin": {
        "Cursor": (
            Location(
                "Library/Application Support/Cursor/User",
                ("settings.json",),
                (("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
            ),
        ),
        "Windsurf": (
            Location(
                "Library/Application Support/Windsurf/User",
                ("settings.json",),
                (("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
            ),
        ),
    },
    "linux": {
        "Cursor": (
            Location(
                ".config/Cursor/User",
                ("settings.json",),
                (("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
            ),
        ),
        "Windsurf": (
            Location(
                ".config/Windsurf/User",
                ("settings.json",),
                (("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
            ),
        ),
    },
    "win32": {
        "Cursor": (
            Location(
                "AppData/Roaming/Cursor/User",
                ("settings.json",),
                (("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
            ),
        ),
        "Windsurf": (
            Location(
                "AppData/Roaming/Windsurf/User",
                ("settings.json",),
                (("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
            ),
        ),
    },
}


@dataclass(frozen=True)
class InstalledDiscovery:
    environments: tuple[InstalledEnvironment, ...]
    artifacts: tuple[Artifact, ...]
    origins: tuple[ArtifactOrigin, ...]


def _safe_mode(path: Path, home: Path) -> int | None:
    """Stat only lexical descendants, rejecting symlink components before traversal."""
    if not path.is_relative_to(home) or ".." in path.parts:
        raise DiscoveryError("agent location outside home boundary")
    current = home
    try:
        mode = current.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise DiscoveryError("home is not a regular directory")
        for part in path.relative_to(home).parts:
            current /= part
            mode = current.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise DiscoveryError("agent location contains a symlink")
        return mode
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise DiscoveryError(f"agent location inaccessible: {type(exc).__name__}") from None


def discover_installed(
    *, home: Path | None = None, platform: str | None = None
) -> InstalledDiscovery:
    base = (home or Path.home()).absolute()
    system = platform or sys.platform
    environments: list[InstalledEnvironment] = []
    artifacts: list[Artifact] = []
    origins: list[ArtifactOrigin] = []
    counted_paths: set[Path] = set()
    for spec in SPECS:
        for location in (*spec.locations, *PLATFORM_LOCATIONS.get(system, {}).get(spec.kind, ())):
            if len(environments) >= MAX_ENVIRONMENTS:
                raise DiscoveryError("agent environment limit exceeded")
            root = base / location.relative
            source = f"known-home-location:{location.relative}"
            status, diagnostic = "not_found", None
            found: tuple[Artifact, ...] = ()
            try:
                mode = _safe_mode(root, base)
                if mode is not None:
                    if not stat.S_ISDIR(mode):
                        raise DiscoveryError("agent root is not a directory")
                    markers = tuple(_safe_mode(root / marker, base) for marker in location.markers)
                    if any(marker is not None for marker in markers):
                        found = discover_bounded(
                            Target(root),
                            max_depth=MAX_DEPTH,
                            max_entries=MAX_ENTRIES_PER_ROOT,
                            max_artifacts=MAX_ARTIFACTS,
                        )
                        extras = []
                        for name, kind, source_format in location.extra:
                            extra_mode = _safe_mode(root / name, base)
                            if extra_mode is not None and stat.S_ISREG(extra_mode):
                                extras.append(Artifact(root / name, kind, source_format, spec.kind))
                        paths = {artifact.path for artifact in found}
                        found = (*found, *(item for item in extras if item.path not in paths))
                        new_paths = {artifact.path for artifact in found}
                        if len(counted_paths | new_paths) > MAX_ARTIFACTS:
                            raise DiscoveryError("agent discovery artifact limit exceeded")
                        counted_paths.update(new_paths)
                        status = "discovered"
            except DiscoveryError as exc:
                status, diagnostic = "diagnostic", str(exc)
            environments.append(
                InstalledEnvironment(
                    spec.kind,
                    root,
                    source,
                    (root,) if status == "discovered" else (),
                    status,
                    diagnostic,
                )
            )
            for artifact in found if status == "discovered" else ():
                artifacts.append(artifact)
                origins.append(
                    ArtifactOrigin(artifact.path, "installed_agent", spec.kind, root, source)
                )
    return InstalledDiscovery(tuple(environments), tuple(artifacts), tuple(origins))
