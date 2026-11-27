"""Replay the measured Codex user/project precedence matrix, not a live configuration."""

import json
import os
import stat
import tomllib
from pathlib import Path
from typing import Any, Literal, TypedDict

import click

_VERSION = "0.146.0"
_KEY = "features.computer_use"
_MAX_CONFIG_BYTES = 16 * 1024


class ConfigResolution(TypedDict):
    key: str
    effective: bool | Literal["unknown"]
    source: Literal["user", "project", "unknown"]
    reason: str


def _unknown(reason: str) -> ConfigResolution:
    return {"key": _KEY, "effective": "unknown", "source": "unknown", "reason": reason}


def _read_config(path: Path) -> dict[str, Any]:
    """Pin every ancestor by descriptor. Never open a link, FIFO or oversized file."""
    if ".." in path.parts or path.parts[-2:] != (".codex", "config.toml"):
        raise ValueError("unsupported configuration path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_CONFIG_BYTES:
            raise ValueError("unsupported input")
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb", buffering=0) as stream:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ValueError("input changed")
        if opened.st_size > _MAX_CONFIG_BYTES:
            raise ValueError("input too large")
        data = stream.read(_MAX_CONFIG_BYTES + 1)
        if len(data) != opened.st_size or os.fstat(fd).st_ctime_ns != opened.st_ctime_ns:
            raise ValueError("input changed")
    return tomllib.loads(data.decode("utf-8"))


def _flag(config: dict[str, Any]) -> bool | None:
    features = config.get("features")
    if isinstance(features, dict) and features.keys() == {"computer_use"}:
        flag = features["computer_use"]
        if isinstance(flag, bool):
            return flag
    return None


def resolve_codex_config(
    user_config: Path, project: Path, codex_version: str, *, overrides_present: bool = False
) -> ConfigResolution:
    """Return the conditional two-file result for an explicitly identified project root."""
    if codex_version != _VERSION:
        return _unknown("unsupported Codex version")
    if overrides_present:
        return _unknown("other configuration layers or overrides are present")
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        return _unknown("no safe descriptor-relative reader on this platform")
    project = project.absolute()
    try:
        user = _read_config(user_config.absolute())
        local = _read_config(project / ".codex" / "config.toml")
    except (OSError, ValueError, RecursionError):
        # Parse errors can contain private values. Never include raw exception text.
        return _unknown("configuration missing, unreadable, oversized or invalid")
    if user.keys() != {"projects", "features"} or local.keys() != {"features"}:
        return _unknown("configuration contains missing or unverified layers")
    projects = user["projects"]
    if not isinstance(projects, dict) or projects.keys() != {str(project)}:
        return _unknown("project trust not verified for this exact root")
    trust = projects[str(project)]
    user_flag, project_flag = _flag(user), _flag(local)
    if user_flag is None or project_flag is None or user_flag == project_flag:
        return _unknown("feature declarations do not match a captured case")
    if trust == {"trust_level": "trusted"}:
        return {"key": _KEY, "effective": project_flag, "source": "project", "reason": "trusted"}
    if trust == {"trust_level": "untrusted"}:
        return {"key": _KEY, "effective": user_flag, "source": "user", "reason": "untrusted"}
    return _unknown("project trust not verified for this exact root")


@click.command("config-effective")
@click.option(
    "--user-config", required=True, type=click.Path(path_type=Path), help="User .codex/config.toml."
)
@click.option(
    "--project", required=True, type=click.Path(path_type=Path), help="Exact project root."
)
@click.option(
    "--codex-version", required=True, help="Exact CLI version; no local binary is probed."
)
@click.option(
    "--overrides-present", is_flag=True, help="Other layers or runtime overrides may apply."
)
def config_effective(
    user_config: Path, project: Path, codex_version: str, overrides_present: bool
) -> None:
    """Report the fixture-backed two-file result for features.computer_use as JSON."""
    result = resolve_codex_config(
        user_config, project, codex_version, overrides_present=overrides_present
    )
    click.echo(json.dumps(result, indent=2))
