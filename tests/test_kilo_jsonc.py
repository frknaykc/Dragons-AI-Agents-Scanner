"""Kilo JSONC fixtures are inert input: never expand references or run servers."""

import socket
import subprocess
from pathlib import Path

import pytest

from dragonscan.discovery import classify
from dragonscan.models import ArtifactKind, SourceFormat, Target
from dragonscan.parsing import parse
from dragonscan.reporting import json_report
from dragonscan.scanner import Scanner


def _write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "relative,scope",
    [
        (".config/kilo/kilo.jsonc", "user"),
        ("kilo.jsonc", "project"),
        (".kilo/kilo.jsonc", "project"),
    ],
)
def test_known_kilo_locations(tmp_path: Path, relative: str, scope: str) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    root = home if scope == "user" else project
    selected = _write(root, relative, '{"mcp": {}}')
    report = Scanner().scan_installed(Target(project), home=home)
    assert any(
        a.path == selected
        and a.kind == ArtifactKind.AGENT_CONFIG
        and a.source_format == SourceFormat.JSONC
        for a in report.artifacts
    )
    assert any(
        o.artifact == selected and o.agent == "Kilo Code" and o.scope == scope
        for o in report.artifact_origins
    )
    assert not report.errors


def test_coexisting_files_preserve_individual_provenance(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    files = [
        _write(project, relative, '{"mcp": {}}')
        for relative in ("kilo.json", "kilo.jsonc", ".kilo/kilo.json", ".kilo/kilo.jsonc")
    ]
    report = Scanner().scan_installed(Target(project), home=tmp_path)
    assert {a.path for a in report.artifacts} >= set(files)
    assert not report.errors


def test_jsonc_comments_strings_locations_and_no_false_findings(tmp_path: Path) -> None:
    config = _write(
        tmp_path,
        "kilo.jsonc",
        """// curl https://evil.invalid and API_KEY=example
{
  "instructions": [".kilo/rules/style.md",],
  /* powershell -enc NOT_ACTIONABLE */
  "metadata": {"url": "https://example.org/a//b/*x*/", "quoted": "a\\\"b", "unicode": "☃",},
  "mcp": {
    "disabled": {"type": "local", "command": ["npx", "-y", "safe-package"],
                 "enabled": false, "environment": {"API_KEY": "{env:TEST_TOKEN}"}},
    "local": {"type": "local", "command": ["node", "server.js"],
              "environment": {"CONFIG_MODE": "safe"},},
    "remote": {"type": "remote", "url": "https://example.org/mcp",
               "headers": {"Accept": "application/json"},},
  },
}""",
    )
    artifact = classify(config, explicit=True)
    assert artifact is not None
    document = parse(artifact, config.read_text())
    values = {entry.key_path: entry.value for entry in document.entries}
    assert values[("metadata", "quoted")] == 'a"b'
    assert values[("metadata", "unicode")] == "☃"
    assert values[("metadata", "url")] == "https://example.org/a//b/*x*/"
    assert {server.name for server in document.servers} == {"local", "remote"}
    local = next(s for s in document.servers if s.name == "local")
    assert (local.command, local.args, local.transport) == ("node", ("server.js",), "stdio")
    assert local.location.path == config and local.location.line == 9
    assert local.env_names == ("CONFIG_MODE",)
    assert next(s for s in document.servers if s.name == "remote").url == "https://example.org/mcp"
    assert any(
        r.kind == "loads_file" and r.target == ".kilo/rules/style.md"
        for r in document.relationships
    )
    report = Scanner().scan(Target(config))
    assert not report.errors and not report.findings
    assert {(name, transport) for _, name, transport in report.mcp_inventory} == {
        ("local", "stdio"),
        ("remote", "http"),
    }
    assert "{env:TEST_TOKEN}" not in json_report(report)


@pytest.mark.parametrize(
    "content,expected",
    [
        ('{"mcp": {} /* open', "JSONC"),
        ('{"mcp": {"x": "unterminated}', "JSONC"),
        ('{"mcp": {}, "mcp": {}}', "duplicate"),
        ('{"mcp": [1,,]}', "JSONC"),
        ("// only a comment", "empty"),
        ('{"mcp": {"x": {"type": "local", "command": ["npx"]},}, "nested": {"mcp": {}}}', ""),
    ],
)
def test_parse_diagnostics_are_nonfatal(tmp_path: Path, content: str, expected: str) -> None:
    path = _write(tmp_path, "kilo.jsonc", content)
    report = Scanner().scan(Target(path))
    assert not report.errors
    if expected:
        assert any(
            expected.lower() in item.message.lower() and item.level == "warning"
            for item in report.diagnostics
        )
    else:
        assert not report.diagnostics


def test_schema_limitation_does_not_invent_servers(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "kilo.jsonc",
        '{"mcp": {"bad": {"command": "npx"}}, "mcpServers": {"fake": {"command": "fake"}}}',
    )
    report = Scanner().scan(Target(path))
    assert not report.errors and not report.installed_mcp_servers
    assert any(item.level == "coverage" for item in report.diagnostics)


def test_invalid_bytes_limits_and_symlink(tmp_path: Path) -> None:
    path = tmp_path / "kilo.jsonc"
    path.write_bytes(b"{\xff}")
    report = Scanner().scan(Target(path))
    assert not report.errors and report.diagnostics
    path.write_text("{" * 70 + "0" + "}" * 70)
    assert Scanner().scan(Target(path)).diagnostics
    path.write_bytes(b" " * (1_048_576 + 1))
    assert Scanner().scan(Target(path)).diagnostics
    path.unlink()
    outside = _write(tmp_path, "outside.json", "{}")
    path.symlink_to(outside)
    from dragonscan.discovery import DiscoveryError

    with pytest.raises(DiscoveryError):
        Scanner().scan(Target(path))


def test_no_execution_network_or_reference_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project,
        "kilo.jsonc",
        '{"instructions": ["../outside.md"], "mcp": {"x": {"type": "local", '
        '"command": ["never-run"], "environment": {"TOKEN": "{file:../outside.md}"}}}}',
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("untrusted config executed or contacted network")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    report = Scanner().scan_installed(Target(project), home=tmp_path)
    assert not report.errors
    selected = project / "kilo.jsonc"
    artifact = classify(selected, explicit=True)
    assert artifact is not None
    document = parse(artifact, selected.read_text())
    assert not any(r.target == "../outside.md" for r in document.relationships)
    assert not any(f.path for f in report.findings)


def test_json_regression_and_unrelated_jsonc(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "kilo.json",
        '{"mcp": {"ok": {"type": "local", "command": ["node", "server.js"]}}}',
    )
    report = Scanner().scan(Target(path))
    assert not report.errors
    artifact = classify(path, explicit=True)
    assert artifact is not None
    assert len(parse(artifact, path.read_text()).servers) == 1
    unrelated = _write(tmp_path, "unrelated.jsonc", '{"mcp": {}}')
    assert classify(unrelated, explicit=True) is None
    assert unrelated not in {a.path for a in Scanner().scan(Target(tmp_path)).artifacts}
