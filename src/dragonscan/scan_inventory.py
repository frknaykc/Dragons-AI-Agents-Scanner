"""Use the existing bounded walker without changing standalone discovery policy."""

from collections.abc import Callable
from pathlib import Path

from dragonscan import discovery
from dragonscan.models import Artifact, Target
from dragonscan.scan_budget import ScanBudget


class _InventoryStopped(Exception):
    """Unwind a directory walk at its next admission callback."""


def scan_inventory(
    target: Target,
    budget: ScanBudget,
    diagnostics: list[str],
    *,
    max_artifacts: int | None = None,
    installed_project: bool = False,
    known_artifact: Callable[[Path], Artifact | None] | None = None,
) -> tuple[Artifact, ...]:
    if max_artifacts is not None and max_artifacts < 1:
        raise ValueError("artifact budget must be positive")
    if not budget.running():
        return ()
    if not target.path.is_dir() or target.path.is_symlink():
        return discovery.discover(
            target, installed_project=installed_project, known_artifact=known_artifact
        )
    user_limit = max_artifacts if max_artifacts is not None else discovery.MAX_FILES
    limit = budget.limits.max_artifacts

    def admit(_: Path) -> bool:
        if not budget.running():
            raise _InventoryStopped
        return True

    def known(path: Path) -> Artifact | None:
        admit(path)
        return known_artifact(path) if known_artifact else None

    try:
        artifacts, message = discovery.discover_installed_bounded(
            target,
            max_depth=8 if installed_project else discovery.MAX_DEPTH,
            max_entries=250_000,
            max_directory_entries=8192 if installed_project else discovery.MAX_ENTRIES,
            max_artifacts=min(limit, user_limit) if user_limit is not None else limit,
            known_artifact=known,
            descend=admit,
            installed_project=installed_project,
        )
    except _InventoryStopped:
        # No file has been opened. Do not treat an unfinished walk as a complete inventory.
        return ()
    if message:
        if "artifact limit" in message and user_limit is not None and user_limit <= limit:
            raise discovery.DiscoveryError("artifact count exceeds limit")
        diagnostics.append(message.replace("agent discovery", "project discovery"))
    root = target.path.absolute()
    return tuple(
        sorted(artifacts, key=lambda a: (a.path.parent.relative_to(root).parts, a.path.name))
    )
