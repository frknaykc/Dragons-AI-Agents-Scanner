"""Inert Goose extension configuration fixtures; no extension is executed."""

import socket
import subprocess
from pathlib import Path

import pytest

from dragonscan.installed_agents import discover_installed
from dragonscan.models import Target
from dragonscan.parsing import parse
from dragonscan.reporting import json_report
from dragonscan.sarif import sarif_report
from dragonscan.scanner import Scanner


def _config(root: Path, text: str) -> Path:
    path = root / ".config/goose/config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_local_remote_multiple_provenance_and_secret_redaction(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    path = _config(
        home,
        """extensions:
  local:
    type: stdio
    name: Local
    enabled: true
    cmd: npx
    args: ['-y', '@example/safe@1.0.0']
    envs: {API_KEY: opaque-canary}
    env_keys: [OTHER_TOKEN]
  remote:
    type: streamable_http
    name: Remote
    enabled: true
    uri: https://example.org/mcp?token=remote-canary
    headers: {Authorization: bearer-canary}
  disabled:
    type: stdio
    name: Disabled
    enabled: false
    cmd: npx
  builtin:
    type: builtin
    name: Developer
    enabled: true
  platform:
    type: platform
    name: Controller
    enabled: true
""",
    )
    report = Scanner().scan_installed(home=home, platform="linux")
    assert not report.errors
    assert {(s.server, s.transport, s.agent, s.scope) for s in report.installed_mcp_servers} == {
        ("local", "stdio", "Goose", "user"),
        ("remote", "streamable_http", "Goose", "user"),
    }
    assert all(s.config == path for s in report.installed_mcp_servers)
    artifact = next(a for a in report.artifacts if a.path == path)
    assert artifact.ecosystem == "Goose"
    document = parse(artifact, path.read_text())
    local, remote = document.servers
    assert local.location.line == 2 and remote.location.line == 10
    assert (local.command, local.args, local.env_names) == (
        "npx",
        ("-y", "@example/safe@1.0.0"),
        ("API_KEY", "OTHER_TOKEN"),
    )
    assert (remote.url, remote.headers[0].origin) == ("https://example.org/mcp", "literal")
    assert {r.kind for r in document.relationships} <= {
        "defines_server",
        "invokes_runtime",
        "invokes_package",
        "references_url",
    }
    for output in (json_report(report), sarif_report(report)):
        for canary in ("opaque-canary", "remote-canary", "bearer-canary"):
            assert canary not in output


@pytest.mark.parametrize(
    "text,diagnostic",
    [
        ("extensions: []", "unsupported"),
        ("extensions: {bad: {type: stdio, name: Bad, enabled: true}}", "unsupported"),
        (
            "extensions: {bad: {type: sse, name: Bad, enabled: true, "
            "uri: 'https://example.org/sse'}}",
            "unsupported",
        ),
        (
            "extensions: {bad: {type: stdio, name: Bad, enabled: true, cmd: node, transport: sse}}",
            "unsupported",
        ),
        ("extensions: {bad: {type: stdio, name: Bad, enabled: false, cmd: node}}", "disabled"),
        ("extensions: {bad: {type: stdio, name: Bad, enabled: true, cmd: node}}", "unsupported"),
        ("extensions: {bad: {type: stdio, name: Bad, cmd: node}}", "unsupported"),
        (
            "extensions: {bad: {type: streamable_http, name: Bad, "
            "enabled: true, uri: 'ftp://example.org'}}",
            "unsupported",
        ),
        (
            "extensions: {bad: {type: streamable_http, name: Bad, "
            "enabled: true, uri: 'https://example.org', socket: '/tmp/sock'}}",
            "unsupported",
        ),
        ("extensions: {bad: {type: [stdio], name: Bad, enabled: true, cmd: node}}", "unsupported"),
        (
            "extensions: {bad: {type: stdio, name: Bad, enabled: true, cmd: node, envs: {X: 4}}}",
            "unsupported",
        ),
        (
            "extensions: {dup: {type: stdio, name: A, enabled: true, cmd: node}, "
            "dup: {type: stdio, name: B, enabled: true, cmd: node}}",
            "duplicate",
        ),
        ("extensions: {bad: [", "invalid"),
        ("mcpServers: {fake: {command: node}}", "unsupported"),
    ],
)
def test_unsupported_disabled_malformed_or_duplicate_no_fake_inventory(
    tmp_path: Path, text: str, diagnostic: str
) -> None:
    _config(tmp_path, text)
    report = Scanner().scan_installed(home=tmp_path, platform="linux")
    assert not report.mcp_inventory and not report.findings
    assert any(diagnostic in d.message for d in report.diagnostics)


def test_multiple_identity_across_separate_files_and_benign_negative(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    path = _config(
        home,
        "extensions: {shared: {type: stdio, name: Shared, enabled: true, cmd: node, args: []}}",
    )
    _config(
        tmp_path / "other",
        "extensions: {shared: {type: streamable_http, name: Shared, "
        "enabled: true, uri: 'https://example.org/mcp'}}",
    )
    for root in (home, tmp_path / "other"):
        report = Scanner().scan_installed(home=root, platform="linux")
        assert len(report.mcp_inventory) == 1 and not report.findings
    arbitrary = tmp_path / "project" / "config.yaml"
    arbitrary.parent.mkdir()
    arbitrary.write_text(path.read_text())
    assert not Scanner().scan(Target(arbitrary)).mcp_inventory


def test_duplicate_declared_name_and_malformed_sibling_stay_isolated(tmp_path: Path) -> None:
    _config(
        tmp_path,
        """extensions:
  first: {type: stdio, name: Shared, enabled: true, cmd: node, args: [], env_keys: [ACCESS_TOKEN]}
  second: {type: stdio, name: Shared, enabled: true, cmd: node, args: []}
  broken: {type: streamable_http, name: Broken, enabled: true, uri: not-a-url}
""",
    )
    report = Scanner().scan_installed(home=tmp_path, platform="linux")
    assert [item.server for item in report.installed_mcp_servers] == ["first"]
    assert any("duplicate Goose" in item.message for item in report.diagnostics)
    assert any("unsupported Goose" in item.message for item in report.diagnostics)
    assert not report.findings


def test_bounded_symlink_no_execution_or_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    path = _config(
        home, "extensions: {safe: {type: stdio, name: Safe, enabled: true, cmd: node, args: []}}"
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("unexpected execution/network")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    assert len(Scanner().scan_installed(home=home, platform="linux").installed_mcp_servers) == 1
    path.write_text("extensions:\n" + "  x:\n" * 70)
    assert not Scanner().scan_installed(home=home, platform="linux").mcp_inventory
    outside = tmp_path / "outside.yaml"
    outside.write_text("extensions: {}")
    path.unlink()
    path.symlink_to(outside)
    assert path not in {a.path for a in discover_installed(home=home, platform="linux").artifacts}
