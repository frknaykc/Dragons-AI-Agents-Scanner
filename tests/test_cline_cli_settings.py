"""Synthetic Cline CLI settings discovery; user data is never a fixture."""

from pathlib import Path

from dragonscan.installed_agents import discover_installed
from dragonscan.models import ArtifactKind
from dragonscan.scanner import Scanner


def test_cline_cli_settings_and_mcp_provenance(tmp_path: Path) -> None:
    settings = tmp_path / ".cline/data/settings"
    settings.mkdir(parents=True)
    mcp = settings / "cline_mcp_settings.json"
    mcp.write_text('{"mcpServers":{"local":{"command":"node","args":["safe.js"]}}}')
    (settings / "global-settings.json").write_text("{}")
    report = Scanner().scan_installed(home=tmp_path, platform="darwin")
    assert not report.errors
    assert {(a.path, a.kind) for a in report.artifacts if a.ecosystem == "Cline"} == {
        (mcp, ArtifactKind.MCP_CONFIG),
        (settings / "global-settings.json", ArtifactKind.AGENT_CONFIG),
    }
    assert {(s.config, s.server, s.agent, s.scope) for s in report.installed_mcp_servers} == {
        (mcp, "local", "Cline", "user")
    }
    assert not report.findings


def test_cline_settings_reject_sibling_and_symlink(tmp_path: Path) -> None:
    path = tmp_path / ".cline/data/settings"
    path.mkdir(parents=True)
    (path / "providers.json").write_text('{"private":"not-a-scanned-file"}')
    (path / "random.json").write_text("{}")
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (path / "cline_mcp_settings.json").symlink_to(outside)
    result = discover_installed(home=tmp_path, platform="darwin")
    assert not [a for a in result.artifacts if a.ecosystem == "Cline"]


def test_cline_cli_malformed_mcp_is_diagnostic_not_inventory(tmp_path: Path) -> None:
    settings = tmp_path / ".cline/data/settings"
    settings.mkdir(parents=True)
    (settings / "cline_mcp_settings.json").write_text('{"mcpServers": {"broken": {')
    report = Scanner().scan_installed(home=tmp_path, platform="darwin")
    assert not report.installed_mcp_servers and not report.findings
    assert any("invalid JSON" in item.message for item in report.diagnostics)
