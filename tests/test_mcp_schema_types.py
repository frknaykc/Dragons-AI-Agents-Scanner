"""Malformed discriminator values are inert data, never executable MCP targets."""

import json
from pathlib import Path

import pytest

from dragonscan.models import Target
from dragonscan.scanner import Scanner


@pytest.mark.parametrize("agent", ["kilo", "codex", "hermes", "claude"])
@pytest.mark.parametrize("value", [[], {}, True, 17, "unknown"])
@pytest.mark.parametrize("remote", [False, True])
def test_invalid_mcp_discriminators_preserve_other_artifacts(
    tmp_path: Path, agent: str, value: object, remote: bool
) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    sibling = project / "AGENTS.md"
    sibling.write_text("ordinary local guidance")
    config: dict[str, object] = (
        {"url": "https://example.invalid/mcp"} if remote else {"command": "inert-placeholder"}
    )
    if agent == "kilo":
        path = project / "kilo.json"
        config["type"] = value
        text = json.dumps({"mcp": {"demo": config}})
    elif agent == "claude":
        path = project / ".mcp.json"
        config["type"] = value
        text = json.dumps({"mcpServers": {"demo": config}})
    elif agent == "hermes":
        path = home / ".hermes/config.yaml"
        config["transport"] = value
        text = json.dumps({"mcp_servers": {"demo": config}})
    else:
        path = home / ".codex/config.toml"
        text = "[mcp_servers.demo]\n" + "\n".join(
            f"{key} = {json.dumps(item)}" for key, item in config.items()
        )
        text += "\ntransport = " + json.dumps(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)

    report = Scanner().scan_installed(Target(project), home=home)

    assert not report.errors
    assert {artifact.path for artifact in report.artifacts} == {path, sibling}
    assert report.coverage["parsed"] == 2
    assert report.coverage["fully_analyzed"] == 1
    assert report.coverage["partially_analyzed"] == 1
    assert not report.mcp_inventory
    assert not report.findings
    assert any(
        str(path) in item.message and "unsupported" in item.message and item.incomplete
        for item in report.diagnostics
    )


@pytest.mark.parametrize("value", [[], {}, True, 17])
def test_unrelated_type_metadata_is_not_a_mcp_error(tmp_path: Path, value: object) -> None:
    path = tmp_path / "kilo.json"
    path.write_text(json.dumps({"metadata": {"type": value}, "mcp": {}}))
    report = Scanner().scan(Target(path))
    assert not report.findings and not report.diagnostics
    assert report.coverage["fully_analyzed"] == 1
