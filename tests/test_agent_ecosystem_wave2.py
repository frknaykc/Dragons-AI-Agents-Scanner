"""Wave 2 installed-agent layouts are inert local data, never executable fixtures."""

import json
import socket
import subprocess
from pathlib import Path

import pytest

from dragonscan.installed_agents import discover_installed
from dragonscan.models import ArtifactKind, Target
from dragonscan.reporting import json_report
from dragonscan.scanner import Scanner


def _write(root: Path, name: str, text: str = "ordinary guidance\n") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


@pytest.mark.parametrize(
    "agent,root,marker,artifact,kind",
    [
        ("Hermes Agent", ".hermes", "config.yaml", "memories/journal.md", ArtifactKind.MEMORY),
        ("Pi Agent", ".pi/agent", "settings.json", "prompts/review.md", ArtifactKind.INSTRUCTIONS),
        ("Kilo Code", ".config/kilo", "kilo.json", "kilo.json", ArtifactKind.AGENT_CONFIG),
        (
            "Command Code",
            ".commandcode",
            "config.json",
            "cron/jobs.json",
            ArtifactKind.AGENT_CONFIG,
        ),
        ("Goose", ".config/goose", "config.yaml", "config.yaml", ArtifactKind.AGENT_CONFIG),
        ("Roo Code", ".roo", "rules/team.md", "rules-code/review.md", ArtifactKind.INSTRUCTIONS),
        ("Zed Agent", ".config/zed", "settings.json", "settings.json", ArtifactKind.AGENT_CONFIG),
        ("ZCode", ".zcode", "skills/review/SKILL.md", "skills/review/SKILL.md", ArtifactKind.SKILL),
        ("OpenClaw", ".openclaw", "openclaw.json", "workspace/memory/day.md", ArtifactKind.MEMORY),
    ],
)
def test_verified_user_surfaces(
    tmp_path: Path, agent: str, root: str, marker: str, artifact: str, kind: ArtifactKind
) -> None:
    user = tmp_path / root
    marker_file = _write(user, marker, "{}" if marker.endswith(".json") else "name: inert\n")
    selected = (
        marker_file
        if artifact == marker
        else _write(user, artifact, "{}" if artifact.endswith(".json") else "ordinary guidance\n")
    )
    report = Scanner().scan_installed(home=tmp_path, platform="linux")
    assert any(item.path == selected and item.kind == kind for item in report.artifacts)
    assert any(
        origin.artifact == selected and origin.agent == agent and origin.scope == "user"
        for origin in report.artifact_origins
    )
    assert any(
        env.agent == agent and env.scope == "user" and env.status == "discovered"
        for env in report.installed_environments
    )
    assert not report.errors


def test_hermes_profile_and_openclaw_workspace_do_not_scan_secret_files(tmp_path: Path) -> None:
    profile = tmp_path / ".hermes/profiles/coder"
    profile_config = _write(profile, "config.yaml", "mcp: {}\n")
    profile_memory = _write(profile, "memories/USER.md", "user preferences\n")
    cron = _write(profile, "cron/jobs.json", '{"jobs": []}')
    _write(profile, ".env", "SECRET_CANARY=unused\n")
    _write(profile, "state.db", "unused")
    _write(tmp_path, ".hermes/config.yaml", "model: inert\n")
    _write(tmp_path, ".openclaw/openclaw.json", "{}")
    tool = _write(tmp_path, ".openclaw/workspace/TOOLS.md", "local conventions\n")
    report = Scanner().scan_installed(home=tmp_path)
    assert {profile_config, profile_memory, cron, tool} <= {a.path for a in report.artifacts}
    assert not {profile / ".env", profile / "state.db"} & {a.path for a in report.artifacts}
    assert any(a.path == profile_memory and a.kind == ArtifactKind.MEMORY for a in report.artifacts)
    assert all(a.path != profile / ".env" for a in report.artifacts)
    assert not report.errors


@pytest.mark.parametrize(
    "agent,artifact,kind",
    [
        ("Pi Agent", ".pi/settings.json", ArtifactKind.AGENT_CONFIG),
        ("Pi Agent", ".pi/mcp.json", ArtifactKind.MCP_CONFIG),
        ("Kilo Code", ".kilo/rules/team.md", ArtifactKind.INSTRUCTIONS),
        ("Kilo Code", "kilo.json", ArtifactKind.AGENT_CONFIG),
        ("Command Code", ".commandcode/settings.local.json", ArtifactKind.AGENT_CONFIG),
        ("Roo Code", ".roo/rules-code/team.md", ArtifactKind.INSTRUCTIONS),
        ("Roo Code", ".roomodes", ArtifactKind.AGENT_CONFIG),
        ("Zed Agent", ".zed/settings.json", ArtifactKind.AGENT_CONFIG),
    ],
)
def test_documented_project_surface_attribution(
    tmp_path: Path, agent: str, artifact: str, kind: ArtifactKind
) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    text = (
        "{}"
        if artifact.endswith(".json")
        else "modes: []\n"
        if artifact == ".roomodes"
        else "safe guidance\n"
    )
    selected = _write(project, artifact, text)
    report = Scanner().scan_installed(Target(project), home=home, platform="linux")
    assert any(a.path == selected and a.kind == kind for a in report.artifacts)
    assert any(
        origin.artifact == selected and origin.agent == agent and origin.scope == "project"
        for origin in report.artifact_origins
    )
    assert not report.errors


def test_generic_files_and_unsupported_names_do_not_create_product_identity(
    tmp_path: Path,
) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    generic = [
        _write(project, f"{root}/AGENTS.md")
        for root in (".pi", ".kilo", ".roo", ".zed", ".commandcode")
    ]
    _write(project, "AGENTS.md")
    _write(project, ".agents/skills/shared/SKILL.md")
    _write(home, ".zcode/unknown.json", "{}")
    _write(home, ".config/goose/unknown.json", "{}")
    _write(home, ".config/kilo/unknown.json", "{}")
    _write(home, ".roo/unknown.json", "{}")
    report = Scanner().scan_installed(Target(project), home=home)
    assert not any(
        origin.artifact in generic and origin.provenance == "installed_agent"
        for origin in report.artifact_origins
    )
    assert not any(
        env.scope == "project"
        and env.agent in {"Pi Agent", "Kilo Code", "Roo Code", "Zed Agent", "Command Code"}
        for env in report.installed_environments
    )
    assert all(env.status == "not_found" for env in discover_installed(home=home).environments)


def test_mode_specific_roo_root_and_empty_hermes_profile_are_distinct(tmp_path: Path) -> None:
    _write(tmp_path, ".roo/rules-code/team.md")
    (tmp_path / ".hermes/profiles/empty").mkdir(parents=True)
    result = discover_installed(home=tmp_path)
    assert any(
        env.agent == "Roo Code" and env.status == "discovered" for env in result.environments
    )
    assert any(
        env.agent == "Hermes Agent" and env.status == "not_found" for env in result.environments
    )


def test_jsonc_is_reported_as_partial_not_treated_as_json(tmp_path: Path) -> None:
    unsupported = _write(tmp_path, ".config/kilo/kilo.jsonc", '{ // comment\n "mcp": {}\n}')
    result = discover_installed(home=tmp_path)
    kilo = next(env for env in result.environments if env.agent == "Kilo Code")
    assert kilo.status == "diagnostic"
    assert kilo.resolution == "partial"
    assert "JSONC" in (kilo.diagnostic or "")
    assert unsupported not in {artifact.path for artifact in result.artifacts}


def test_static_mcp_and_no_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project, ".pi/mcp.json", '{"mcpServers": {"pi": {"command": "never-run"}}}')
    _write(project, ".roo/mcp.json", '{"mcpServers": {"roo": {"command": "never-run"}}}')
    _write(
        tmp_path, ".commandcode/mcp.json", '{"mcpServers": {"command": {"command": "never-run"}}}'
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("executable or network touched")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    report = Scanner().scan_installed(Target(project), home=tmp_path)
    assert {item.agent for item in report.installed_mcp_servers} >= {
        "Pi Agent",
        "Roo Code",
        "Command Code",
    }
    assert report.dynamic_status == "not_requested"
    assert not report.errors
    payload = json.loads(json_report(report))
    assert all("command" not in item for item in payload["installed_agents"]["mcp_servers"])


def test_hermes_profile_does_not_crawl_unrelated_worktree(tmp_path: Path) -> None:
    selected = _write(tmp_path, ".hermes/profiles/demo/skills/sample/SKILL.md")
    _write(tmp_path, ".hermes/profiles/demo/worktree/uv.lock", "x" * 1_100_000)
    result = discover_installed(home=tmp_path)
    assert any(a.path == selected and a.ecosystem == "Hermes Agent" for a in result.artifacts)
    assert all(a.path.name != "uv.lock" for a in result.artifacts)
    assert any(
        env.agent == "Hermes Agent" and env.resolution == "complete" for env in result.environments
    )


def test_zed_macos_user_location(tmp_path: Path) -> None:
    selected = _write(tmp_path, ".zed/settings.json", "{}")
    mac = discover_installed(home=tmp_path, platform="darwin")
    assert any(a.path == selected and a.ecosystem == "Zed Agent" for a in mac.artifacts)
    assert selected not in {
        a.path for a in discover_installed(home=tmp_path, platform="linux").artifacts
    }


def test_platform_location_and_symlink_boundary(tmp_path: Path) -> None:
    zed = _write(tmp_path, "AppData/Roaming/Zed/settings.json", "{}")
    goose = _write(tmp_path, "AppData/Roaming/Block/goose/config/config.yaml", "name: inert\n")
    on_windows = discover_installed(home=tmp_path, platform="win32")
    assert {zed, goose} <= {a.path for a in on_windows.artifacts}
    assert not {zed, goose} & {
        a.path for a in discover_installed(home=tmp_path, platform="linux").artifacts
    }
    escaped = tmp_path / "outside.md"
    escaped.write_text("ordinary guidance")
    (tmp_path / ".zcode/skills/fake").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / ".zcode/skills/fake").symlink_to(escaped)
    assert escaped not in {a.path for a in discover_installed(home=tmp_path).artifacts}
