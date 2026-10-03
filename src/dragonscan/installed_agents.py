"""Opt-in, offline discovery of bounded, known agent configuration locations."""

import stat
import sys
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from dragonscan.discovery import DiscoveryError, discover_installed_bounded
from dragonscan.models import (
    Artifact,
    ArtifactKind,
    ArtifactOrigin,
    InstalledEnvironment,
    SourceFormat,
    Target,
)

# Fixed known roots only; per-root and global artifact budgets stay unchanged.
MAX_ENVIRONMENTS = 32
MAX_ARTIFACTS = 256
MAX_ENTRIES_PER_ROOT = 2048
MAX_DEPTH = 4


@dataclass(frozen=True)
class Location:
    relative: str
    markers: tuple[str, ...]
    extra: tuple[tuple[str, ArtifactKind, SourceFormat], ...] = ()
    project: bool = True
    user: bool = True
    instruction_dirs: tuple[str, ...] = ()
    memory_dirs: tuple[str, ...] = ()
    profiled: bool = False
    project_dirs: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()
    scan_without_marker: bool = False
    require_artifact: bool = False
    strict_user: bool = False
    allowed_dirs: tuple[str, ...] = ()
    max_depth: int = MAX_DEPTH
    max_artifacts: int = MAX_ARTIFACTS


@dataclass(frozen=True)
class AgentSpec:
    kind: str
    locations: tuple[Location, ...]
    project_files: tuple[tuple[str, ArtifactKind, SourceFormat], ...] = ()
    project_at_root_only: bool = False
    strict_project: bool = False


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
                ("openclaw.json", "AGENTS.md", "SOUL.md", "workspace", "skills"),
                extra=(
                    ("openclaw.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                    ("workspace/TOOLS.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),
                    ("workspace/IDENTITY.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),
                    ("workspace/USER.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),
                    ("workspace/HEARTBEAT.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),
                ),
                memory_dirs=("workspace/memory",),
            ),
        ),
    ),
    AgentSpec(
        "OpenCode",
        (
            Location(
                ".config/opencode",
                ("opencode.json", "skills", "agents", "commands"),
                (("opencode.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
                project=False,
                instruction_dirs=("agents", "commands"),
            ),
            Location(
                ".opencode",
                (),
                user=False,
                instruction_dirs=("agents", "commands"),
            ),
        ),
        (("opencode.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
        project_at_root_only=True,
    ),
    AgentSpec(
        "Qwen Code",
        (
            Location(
                ".qwen",
                ("settings.json", "QWEN.md", "skills"),
                (
                    ("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                    ("QWEN.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),
                ),
            ),
        ),
        project_at_root_only=True,
    ),
    AgentSpec(
        "Kiro",
        (
            Location(
                ".kiro",
                ("settings/cli.json", "settings/mcp.json", "steering", "agents"),
                (("settings/cli.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
                project=False,
                instruction_dirs=("steering", "prompts"),
            ),
            Location(".kiro", (), user=False, instruction_dirs=("steering", "prompts")),
        ),
        project_at_root_only=True,
    ),
    AgentSpec(
        "Continue",
        (
            Location(
                ".continue",
                ("config.yaml", "config.json", "rules"),
                (
                    ("config.yaml", ArtifactKind.AGENT_CONFIG, SourceFormat.YAML),
                    ("config.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                ),
                instruction_dirs=("rules",),
            ),
        ),
        ((".continuerc.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
        project_at_root_only=True,
    ),
    AgentSpec(
        "Cline",
        (
            Location(
                ".cline",
                ("mcp.json", "rules", "skills"),
                instruction_dirs=("rules",),
            ),
            Location(".clinerules", (), user=False, instruction_dirs=(".",)),
        ),
        project_at_root_only=True,
    ),
    AgentSpec(
        "Hermes Agent",
        (
            Location(
                ".hermes",
                ("config.yaml", "SOUL.md", "skills", "memories", "profiles", "cron/jobs.json"),
                (
                    ("config.yaml", ArtifactKind.AGENT_CONFIG, SourceFormat.YAML),
                    ("SOUL.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),
                    ("cron/jobs.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                ),
                project=False,
                memory_dirs=("memories",),
                profiled=True,
                require_artifact=True,
                strict_user=True,
                allowed_dirs=("profiles", "skills", "memories", "cron"),
                max_depth=6,
                max_artifacts=64,
            ),
        ),
    ),
    AgentSpec(
        "Pi Agent",
        (
            Location(
                ".pi/agent",
                (
                    "settings.json",
                    "mcp.json",
                    "AGENTS.md",
                    "SYSTEM.md",
                    "skills",
                    "prompts",
                ),
                (
                    ("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                    ("SYSTEM.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),
                    ("APPEND_SYSTEM.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),
                    ("AGENTS.override.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),
                    ("models.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                ),
                project=False,
                instruction_dirs=("prompts",),
            ),
            Location(
                ".pi",
                (),
                (
                    ("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                    ("mcp.json", ArtifactKind.MCP_CONFIG, SourceFormat.JSON),
                    ("SYSTEM.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),
                    ("APPEND_SYSTEM.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),
                ),
                user=False,
                instruction_dirs=("prompts",),
                project_dirs=("skills", "extensions"),
            ),
        ),
        project_at_root_only=True,
        strict_project=True,
    ),
    AgentSpec(
        "Kilo Code",
        (
            Location(
                ".config/kilo",
                ("kilo.jsonc", "kilo.json"),
                (("kilo.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
                project=False,
                unsupported=("kilo.jsonc",),
            ),
            Location(
                ".kilo",
                (),
                (("kilo.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
                user=False,
                instruction_dirs=("rules",),
            ),
        ),
        (("kilo.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
        project_at_root_only=True,
        strict_project=True,
    ),
    AgentSpec(
        "Command Code",
        (
            Location(
                ".commandcode",
                ("config.json", "settings.json", "mcp.json", "providers.json", "cron", "skills"),
                (
                    ("config.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                    ("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                    ("providers.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                    ("cron/jobs.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                ),
                project=False,
            ),
            Location(
                ".commandcode",
                (),
                (
                    ("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                    ("settings.local.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),
                ),
                user=False,
            ),
        ),
        project_at_root_only=True,
        strict_project=True,
    ),
    AgentSpec(
        "Goose",
        (
            Location(
                ".config/goose",
                ("config.yaml",),
                (("config.yaml", ArtifactKind.AGENT_CONFIG, SourceFormat.YAML),),
                project=False,
                platforms=("darwin", "linux"),
            ),
        ),
    ),
    AgentSpec(
        "Roo Code",
        (
            Location(
                ".roo",
                ("rules", "skills"),
                project=False,
                instruction_dirs=("rules", "rules-*"),
                scan_without_marker=True,
                require_artifact=True,
            ),
            Location(
                ".roo",
                (),
                (("mcp.json", ArtifactKind.MCP_CONFIG, SourceFormat.JSON),),
                user=False,
                instruction_dirs=("rules", "rules-*"),
                project_dirs=("skills", "skills-*"),
            ),
        ),
        ((".roomodes", ArtifactKind.AGENT_CONFIG, SourceFormat.YAML),),
        project_at_root_only=True,
        strict_project=True,
    ),
    AgentSpec(
        "Zed Agent",
        (
            Location(
                ".config/zed",
                ("settings.json", "AGENTS.md"),
                (("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
                project=False,
                platforms=("darwin", "linux"),
            ),
            Location(
                ".zed",
                ("settings.json",),
                (("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
                project=False,
                platforms=("darwin",),
            ),
            Location(
                ".zed",
                (),
                (("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
                user=False,
            ),
        ),
        project_at_root_only=True,
        strict_project=True,
    ),
    AgentSpec(
        "ZCode",
        (Location(".zcode", ("skills",), project=False),),
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
        "Goose": (
            Location(
                "AppData/Roaming/Block/goose/config",
                ("config.yaml",),
                (("config.yaml", ArtifactKind.AGENT_CONFIG, SourceFormat.YAML),),
                project=False,
            ),
        ),
        "Zed Agent": (
            Location(
                "AppData/Roaming/Zed",
                ("settings.json", "AGENTS.md"),
                (("settings.json", ArtifactKind.AGENT_CONFIG, SourceFormat.JSON),),
                project=False,
            ),
        ),
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


def _spec_artifact(path: Path, root: Path, spec: AgentSpec, location: Location) -> Artifact | None:
    """Classify only documented aliases inside a selected, product-specific root."""
    relative = path.relative_to(root)
    if location.profiled and len(relative.parts) > 2 and relative.parts[0] == "profiles":
        relative = Path(*relative.parts[2:])
    for name, kind, source_format in location.extra:
        if relative == Path(name):
            return Artifact(path, kind, source_format, spec.kind)
    if path.name == "SKILL.md" and relative.is_relative_to("skills"):
        return Artifact(path, ArtifactKind.SKILL, SourceFormat.MARKDOWN, spec.kind)
    if path.suffix.lower() != ".md":
        return None
    if any(relative.is_relative_to(directory) for directory in location.memory_dirs):
        return Artifact(path, ArtifactKind.MEMORY, SourceFormat.MARKDOWN, spec.kind)
    if any(
        relative.is_relative_to(directory)
        or (
            directory == "rules-*"
            and len(relative.parts) > 1
            and relative.parts[0].startswith("rules-")
        )
        for directory in location.instruction_dirs
    ):
        return Artifact(path, ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN, spec.kind)
    return None


def classify_project_artifact(target: Target, path: Path) -> Artifact | None:
    """Opt-in aliases; generic AGENTS.md/MCP files confer no agent identity."""
    base = target.path.absolute()
    project = base if base.is_dir() else base.parent
    roots = {location.relative for spec in SPECS for location in spec.locations if location.project}
    if project.name in roots:
        project = project.parent
    if path.parent == project:
        for spec in SPECS:
            for name, kind, source_format in spec.project_files:
                if path.name == name:
                    return Artifact(path, kind, source_format, spec.kind)
    for spec in SPECS:
        for location in spec.locations:
            if not location.project:
                continue
            root = project / location.relative
            if path.is_relative_to(root):
                artifact = _spec_artifact(path, root, spec, location)
                if artifact is not None:
                    return artifact
    return None


def _allowed_user_directory(path: Path, *, root: Path, location: Location) -> bool:
    parts = path.relative_to(root).parts
    if location.profiled and parts[0] == "profiles":
        if len(parts) <= 2:
            return True
        parts = parts[2:]
    return parts[0] in location.allowed_dirs and parts[0] != "profiles"


def _evidence(artifacts: tuple[Artifact, ...]) -> tuple[str, ...]:
    kinds = {item.kind for item in artifacts}
    return tuple(
        label
        for label, present in (
            ("configuration", bool(kinds & {ArtifactKind.AGENT_CONFIG, ArtifactKind.MCP_CONFIG})),
            ("artifact", bool(kinds - {ArtifactKind.AGENT_CONFIG, ArtifactKind.MCP_CONFIG})),
        )
        if present
    )


def discover_project(target: Target, artifacts: tuple[Artifact, ...]) -> InstalledDiscovery:
    """Annotate already discovered project artifacts, without another traversal.

    Only exact, repository-supported root names provide agent-specific identity.
    Generic AGENTS.md and MCP configurations retain their explicit, shared origin.
    """
    base = target.path.absolute()
    project = base if base.is_dir() else base.parent
    known_roots = {
        location.relative
        for spec in SPECS
        for location in spec.locations
        if location.project and "/" not in location.relative
    }
    if project.name in known_roots:
        project = project.parent
    environments: list[InstalledEnvironment] = []
    selected: list[Artifact] = []
    origins: list[ArtifactOrigin] = []
    for spec in SPECS:
        for location in spec.locations:
            # User-only paths do not establish project identity.
            if not location.project or "/" in location.relative:
                continue
            groups: dict[Path, list[Artifact]] = {}
            for artifact in artifacts:
                if not artifact.path.is_relative_to(project):
                    continue
                relative = artifact.path.relative_to(project)
                parts = relative.parts
                if location.relative not in parts[:-1]:
                    continue
                if spec.project_at_root_only and parts[0] != location.relative:
                    continue
                index = parts.index(location.relative)
                root = project.joinpath(*parts[: index + 1])
                if spec.strict_project:
                    member = artifact.path.relative_to(root)
                    product_file = _spec_artifact(artifact.path, root, spec, location)
                    product_dir = artifact.kind in {
                        ArtifactKind.SKILL,
                        ArtifactKind.INSTRUCTIONS,
                    } and any(
                        member.is_relative_to(directory)
                        or (
                            directory.endswith("-*")
                            and len(member.parts) > 1
                            and member.parts[0].startswith(directory[:-1])
                        )
                        for directory in location.project_dirs
                    )
                    if product_file is None and not product_dir:
                        continue
                groups.setdefault(root, []).append(artifact)
            if spec.kind == "Claude Code":
                direct = project / "CLAUDE.md"
                if direct in (artifact.path for artifact in artifacts):
                    groups.setdefault(project, []).extend(
                        item for item in artifacts if item.path == direct
                    )
            for root, group in sorted(groups.items()):
                items = tuple(group)
                source = f"known-project-location:{location.relative}"
                environments.append(
                    InstalledEnvironment(
                        spec.kind,
                        root,
                        source,
                        (root,),
                        "discovered",
                        scope="project",
                        evidence=_evidence(items),
                        resolution="complete",
                    )
                )
                for artifact in items:
                    selected.append(artifact)
                    origins.append(
                        ArtifactOrigin(
                            artifact.path,
                            "installed_agent",
                            spec.kind,
                            root,
                            source,
                            scope="project",
                        )
                    )
        for name, _, _ in spec.project_files:
            direct = project / name
            for artifact in artifacts:
                if artifact.path != direct:
                    continue
                source = f"known-project-file:{name}"
                environments.append(
                    InstalledEnvironment(
                        spec.kind,
                        project,
                        source,
                        (project,),
                        "discovered",
                        scope="project",
                        evidence=_evidence((artifact,)),
                        resolution="complete",
                    )
                )
                selected.append(artifact)
                origins.append(
                    ArtifactOrigin(
                        direct, "installed_agent", spec.kind, project, source, scope="project"
                    )
                )
    return InstalledDiscovery(tuple(environments), tuple(selected), tuple(origins))


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
            if not location.user or (location.platforms and system not in location.platforms):
                continue
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
                    if location.scan_without_marker or any(
                        marker is not None and (stat.S_ISREG(marker) or stat.S_ISDIR(marker))
                        for marker in markers
                    ):
                        found, diagnostic = discover_installed_bounded(
                            Target(root),
                            max_depth=location.max_depth,
                            max_entries=MAX_ENTRIES_PER_ROOT,
                            max_artifacts=min(
                                location.max_artifacts, MAX_ARTIFACTS - len(counted_paths)
                            ),
                            known_artifact=partial(
                                _spec_artifact, root=root, spec=spec, location=location
                            ),
                            descend=(
                                partial(_allowed_user_directory, root=root, location=location)
                                if location.allowed_dirs
                                else None
                            ),
                            strict_artifact=location.strict_user,
                        )
                        extras = []
                        for name, kind, source_format in location.extra:
                            extra_mode = _safe_mode(root / name, base)
                            if extra_mode is not None and stat.S_ISREG(extra_mode):
                                extras.append(Artifact(root / name, kind, source_format, spec.kind))
                        paths = {artifact.path for artifact in found}
                        found = (*found, *(item for item in extras if item.path not in paths))
                        available = MAX_ARTIFACTS - len(counted_paths)
                        if len(found) > available:
                            found = found[:available]
                            diagnostic = "agent discovery artifact limit exceeded"
                        counted_paths.update(artifact.path for artifact in found)
                        if any(
                            (unsupported_mode := _safe_mode(root / name, base)) is not None
                            and stat.S_ISREG(unsupported_mode)
                            for name in location.unsupported
                        ):
                            diagnostic = (
                                f"{diagnostic}; unsupported JSONC configuration omitted"
                                if diagnostic
                                else "unsupported JSONC configuration omitted"
                            )
                        status = (
                            "discovered"
                            if found
                            else "diagnostic"
                            if diagnostic
                            else "not_found"
                            if location.require_artifact
                            else "discovered"
                        )
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
                    evidence=_evidence(found) or (("location",) if status == "discovered" else ()),
                    resolution=(
                        "partial"
                        if diagnostic
                        else "complete"
                        if status == "discovered"
                        else "not_found"
                    ),
                )
            )
            for artifact in found if status == "discovered" else ():
                artifacts.append(artifact)
                origins.append(
                    ArtifactOrigin(
                        artifact.path, "installed_agent", spec.kind, root, source, scope="user"
                    )
                )
    return InstalledDiscovery(tuple(environments), tuple(artifacts), tuple(origins))
