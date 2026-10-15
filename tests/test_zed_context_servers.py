"""Zed settings fixtures are inert; only documented configuration becomes inventory."""

import json
import socket
import subprocess
from pathlib import Path

import pytest

from dragonscan.discovery import classify
from dragonscan.installed_agents import discover_installed
from dragonscan.models import ArtifactKind, Target
from dragonscan.parsing import parse
from dragonscan.reporting import json_report
from dragonscan.sarif import sarif_report
from dragonscan.scanner import Scanner


def _write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


@pytest.mark.parametrize(
    "relative,scope,platform",
    [
        (".config/zed/settings.json", "user", "darwin"),
        (".config/zed/settings.json", "user", "linux"),
        ("AppData/Roaming/Zed/settings.json", "user", "win32"),
        (".zed/settings.json", "project", "linux"),
    ],
)
def test_installed_settings_identity_scope_and_inventory(
    tmp_path: Path, relative: str, scope: str, platform: str
) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    root = home if scope == "user" else project
    path = _write(
        root, relative, '{"context_servers": {"local": {"command": "node", "args": ["app.js"]}}}'
    )
    report = Scanner().scan_installed(Target(project), home=home, platform=platform)
    assert any(
        a.path == path and a.kind == ArtifactKind.AGENT_CONFIG and a.source_format.value == "json"
        for a in report.artifacts
    )
    assert any(
        o.artifact == path and o.agent == "Zed Agent" and o.scope == scope
        for o in report.artifact_origins
    )
    assert any(s.server == "local" and s.config == path for s in report.installed_mcp_servers)
    assert (path, "local", "stdio") in report.mcp_inventory
    assert not report.errors


def test_zed_settings_not_arbitrary_settings(tmp_path: Path) -> None:
    _write(tmp_path, "settings.json", '{"context_servers": {"bad": {"command": "npx"}}}')
    _write(tmp_path, "other/settings.json", '{"context_servers": {"bad": {"command": "npx"}}}')
    _write(tmp_path, ".zed/other.json", '{"context_servers": {"bad": {"command": "npx"}}}')
    report = Scanner().scan(Target(tmp_path))
    assert not report.mcp_inventory
    assert not report.installed_mcp_servers


def test_local_remote_comments_and_precise_locations(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        ".zed/settings.json",
        """// "context_servers": {"commented": {"command": "powershell -enc hidden"}}
{
  /* "context_servers": {"commented2": {"url": "http://bad.invalid"}} */
  "context_servers": {
    "local": {"command": "npx", "args": ["-y", "@sample/safe@1.0.0"],
              "env": {"TOKEN": "${MCP_TOKEN}"},},
    "remote": {"url": "https://example.org/mcp",
               "headers": {"Authorization": "Bearer ${MCP_TOKEN}"}},
    "quoted\\\"name": {"command": "node", "args": ["https://example.org/a//b/*c*/"]},
  },
}""",
    )
    artifact = classify(path)
    assert artifact is not None and artifact.ecosystem == "Zed Agent"
    document = parse(artifact, path.read_text())
    assert {s.name for s in document.servers} == {"local", "remote", 'quoted"name'}
    assert [(s.name, s.location.line) for s in document.servers] == [
        ("local", 5),
        ("remote", 7),
        ('quoted"name', 9),
    ]
    local, remote, quoted = document.servers
    assert (local.command, local.args, local.runtime, local.package) == (
        "npx",
        ("-y", "@sample/safe@1.0.0"),
        "npx",
        "@sample/safe",
    )
    assert local.environment[0].origin == "reference"
    assert (remote.transport, remote.url, remote.headers[0].origin) == (
        "http",
        "https://example.org/mcp",
        "reference",
    )
    assert quoted.args == ("https://example.org/a//b/*c*/",)
    assert {r.kind for r in document.relationships} <= {
        "defines_server",
        "invokes_runtime",
        "invokes_package",
        "references_url",
    }
    assert all(r.subject is not None or r.kind == "defines_server" for r in document.relationships)
    report = Scanner().scan(Target(tmp_path))
    assert not report.errors
    assert {f.detection_id for f in report.findings} == {"DRAGON-MCP-011"}
    assert len(report.mcp_inventory) == 3
    assert "${MCP_TOKEN}" not in json_report(report)
    assert "${MCP_TOKEN}" not in sarif_report(report)


@pytest.mark.parametrize(
    "server,diagnostic",
    [
        ({"command": "npx", "enabled": False}, "disabled"),
        ({"settings": {"token": "dummy"}, "enabled": True}, "extension"),
        ({"command": "npx", "url": "http://example.org"}, "unsupported"),
        ({"command": ["npx", "server"]}, "unsupported"),
        ({"command": ""}, "unsupported"),
        ({"args": ["server.js"]}, "missing"),
        ({"enabled": True}, "missing"),
        ({"command": "node", "transport": "websocket"}, "unsupported"),
        ({"url": "ftp://example.org/mcp"}, "unsupported"),
        ({"command": "node", "type": "stdio"}, "unsupported"),
        ({"command": "node", "args": [2]}, "unsupported"),
        ({"url": "https://example.org/mcp", "headers": {"Authorization": 4}}, "unsupported"),
        ({"command": "node", "enabled": "false"}, "unsupported"),
        ({"command": "node", "remote": "false"}, "unsupported"),
    ],
)
def test_non_active_or_unsupported_has_no_server_or_graph(
    tmp_path: Path, server: object, diagnostic: str
) -> None:
    path = _write(
        tmp_path, ".zed/settings.json", json.dumps({"context_servers": {"example": server}})
    )
    report = Scanner().scan(Target(path))
    assert not report.errors and not report.mcp_inventory and not report.findings
    assert any(diagnostic in d.message for d in report.diagnostics)


def test_mixed_shapes_and_benign_development_servers(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        ".zed/settings.json",
        json.dumps(
            {
                "context_servers": {
                    "local": {
                        "command": "node",
                        "args": ["server.js"],
                        "env": {"MODE": "development"},
                    },
                    "remote": {"url": "https://example.org/mcp"},
                    "disabled": {"command": "npx", "enabled": False},
                    "unsupported": {"transport": "sse", "url": "https://example.org/sse"},
                    "extension": {"settings": {"example": True}},
                }
            }
        ),
    )
    report = Scanner().scan(Target(path))
    assert not report.errors and not report.findings
    assert {name for _, name, _ in report.mcp_inventory} == {"local", "remote"}
    assert {item.level for item in report.diagnostics} == {"coverage", "warning"}


def test_duplicate_names_across_scopes_keep_source_identity(tmp_path: Path) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    user = _write(
        home, ".config/zed/settings.json", '{"context_servers": {"shared": {"command": "node"}}}'
    )
    local = _write(
        project,
        ".zed/settings.json",
        '{"context_servers": {"shared": {"url": "https://example.org/mcp"}}}',
    )
    report = Scanner().scan_installed(Target(project), home=home, platform="linux")
    assert {
        (item.config, item.server, item.scope)
        for item in report.installed_mcp_servers
        if item.server == "shared"
    } == {(user, "shared", "user"), (local, "shared", "project")}
    assert not report.errors


@pytest.mark.parametrize(
    "content,marker",
    [
        ('{"context_servers": [1]}', "unsupported"),
        ('{"mcpServers": {"fake": {"command": "npx"}}}', "unsupported"),
        (
            '{"context_servers": {"dup": {"command": "node"}, "dup": {"command": "npx"}}}',
            "duplicate",
        ),
        ('{"context_servers": {"bad": ', "invalid"),
        ('{"context_servers": {}} /* open', "invalid"),
    ],
)
def test_invalid_settings_are_diagnostic_not_server(
    tmp_path: Path, content: str, marker: str
) -> None:
    path = _write(tmp_path, ".zed/settings.json", content)
    report = Scanner().scan(Target(path))
    assert not report.mcp_inventory
    assert not report.errors or report.errors == ("no supported artifact could be parsed",)
    assert any(marker in item.message for item in report.diagnostics)


def test_settings_bounds_utf8_and_symlink(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    path = _write(project, ".zed/settings.json", "{" * 65 + "}" * 65)
    report = Scanner().scan(Target(path))
    assert any("nesting" in d.message for d in report.diagnostics)
    path.write_bytes(b"\xff")
    report = Scanner().scan(Target(path))
    assert not report.mcp_inventory and (report.errors or report.diagnostics)
    path.write_text(" " * 1_048_577)
    report = Scanner().scan(Target(path))
    assert not report.mcp_inventory and (report.errors or report.diagnostics)
    outside = _write(tmp_path, "outside.json", '{"context_servers": {"bad": {"command": "npx"}}}')
    path.unlink()
    path.symlink_to(outside)
    result = discover_installed(home=tmp_path, platform="linux")
    assert path not in {item.path for item in result.artifacts}


def test_static_security_no_execution_network_or_secret_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(
        tmp_path,
        ".zed/settings.json",
        json.dumps(
            {
                "context_servers": {
                    "unsafe": {
                        "command": "powershell",
                        "args": ["-enc", "example"],
                        "env": {"API_KEY": "private-canary"},
                    },
                    "disabled": {
                        "command": "powershell",
                        "args": ["-enc", "ignored"],
                        "enabled": False,
                    },
                    "remote": {"url": "http://example.org/mcp?token=opaque-canary"},
                }
            }
        ),
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("target execution or network use")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    report = Scanner().scan(Target(path))
    assert {name for _, name, _ in report.mcp_inventory} == {"unsafe", "remote"}
    assert {"DRAGON-MCP-004", "DRAGON-MCP-005"} <= {f.detection_id for f in report.findings}
    assert all(f.artifact == path and f.line is not None for f in report.findings)
    for output in (json_report(report), sarif_report(report)):
        assert "private-canary" not in output and "opaque-canary" not in output
        assert "ignored" not in output
    assert report.dynamic_status == "not_requested"
