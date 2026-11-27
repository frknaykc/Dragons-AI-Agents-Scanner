"""Offline scope, fail-closed inputs and direct/project/installed scan parity."""

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

from dragonscan.config_effective import resolve_codex_config
from dragonscan.models import Target
from dragonscan.scanner import Scanner


@pytest.fixture
def configs(tmp_path: Path) -> tuple[Path, Path, Path]:
    project = tmp_path / "project"
    local = project / ".codex" / "config.toml"
    user = tmp_path / "fake-home" / ".codex" / "config.toml"
    for path in (user, local):
        path.parent.mkdir(parents=True)
    user.write_text(
        f'[projects.{json.dumps(str(project))}]\ntrust_level="trusted"\n'
        "[features]\ncomputer_use=false\n",
        encoding="utf-8",
    )
    local.write_text("[features]\ncomputer_use=true\n", encoding="utf-8")
    return user, project, local


@pytest.mark.parametrize(
    "text",
    [
        "[profiles.unused.features]\ncomputer_use=true",
        "[features]\ncomputer_use=true\n[profiles.other.features]\ncomputer_use=false",
        'profile="inactive"\n[features]\ncomputer_use=true',
        "[features]\ncomputer_use=false",  # Same polarity has no differential observation.
        '[features]\ncomputer_use="true"',
        "[features]\ncomputer_use=1",
        "[features]\ncomputer_use=true\nother_flag=false",
        "[features",
        "",
        "#" * (16 * 1024) + "\n[features]\ncomputer_use=true",
    ],
)
def test_unknown_local_forms(configs: tuple[Path, Path, Path], text: str) -> None:
    user, project, local = configs
    local.write_text(text, encoding="utf-8")
    result = resolve_codex_config(user, project, "0.146.0")
    assert result["effective"] == result["source"] == "unknown"


def test_no_implicit_trust_or_override(configs: tuple[Path, Path, Path]) -> None:
    user, project, _ = configs
    assert (
        resolve_codex_config(user, project, "0.146.0", overrides_present=True)["effective"]
        == "unknown"
    )
    original = user.read_text()
    for text in [
        original.replace(str(project), str(project.parent)),
        original.replace('"trusted"', '"other"'),
        original.replace('"trusted"', "false"),
        "profile='other'\n" + original,
        original + "\n[unknown_layer]\nmarker='private-input-placeholder'",
    ]:
        user.write_text(text, encoding="utf-8")
        result = resolve_codex_config(user, project, "0.146.0")
        assert result["effective"] == "unknown"
        assert "private-input-placeholder" not in repr(result)
    user.unlink()
    assert resolve_codex_config(user, project, "0.146.0")["effective"] == "unknown"


@pytest.mark.skipif(os.name != "posix", reason="POSIX links and FIFO")
@pytest.mark.parametrize("layer", ["user", "user-dir", "project", "local-dir", "local", "fifo"])
def test_unsafe_input_is_unknown(configs: tuple[Path, Path, Path], layer: str) -> None:
    user, project, local = configs
    component = {
        "user": user,
        "user-dir": user.parent.parent,
        "project": project,
        "local-dir": local.parent,
        "local": local,
        "fifo": local,
    }[layer]
    other = component.with_name("displaced")
    component.rename(other)
    if layer == "fifo":
        os.mkfifo(component)
    else:
        component.symlink_to(other, target_is_directory=other.is_dir())
    assert resolve_codex_config(user, project, "0.146.0")["effective"] == "unknown"


def test_codex_scan_mode_parity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Use the same file in each discovery scope so path, evidence and line equality is meaningful.
    home = tmp_path / "synthetic-home"
    path = home / ".codex" / "config.toml"
    path.parent.mkdir(parents=True)
    path.write_text(
        '[features]\ncomputer_use=true\n[mcp_servers.local]\nurl="http://example.invalid/mcp"\n'
    )
    monkeypatch.setattr(Path, "home", lambda: home)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("static resolution attempted to execute or connect")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    direct = Scanner().scan(Target(path))
    project = Scanner().scan(Target(home))
    installed = Scanner().scan_installed(home=home, agent="Codex", platform="linux")
    assert [item.path for item in direct.artifacts] == [path]
    assert any(f.detection_id == "DRAGON-MCP-005" for f in direct.findings)
    for report in (direct, project, installed):
        assert report.artifacts == direct.artifacts
        assert not report.errors
        assert report.findings == direct.findings
        assert report.risk == direct.risk
        assert report.dynamic_status == "not_requested"
    assert any(
        o.scope == "user" and o.agent == "Codex" and o.artifact == path
        for o in installed.artifact_origins
    )
