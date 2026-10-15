"""Synthetic P1 layouts: no agent, MCP server, or fixture command is executed."""

import json
from pathlib import Path

import pytest

from dragonscan.markdown_parser import parse_markdown
from dragonscan.models import Artifact, ArtifactKind, SourceFormat, Target
from dragonscan.parse_errors import ParseError
from dragonscan.reporting import json_report
from dragonscan.scanner import Scanner
from dragonscan.structured_parser import parse_structured


def _config(tmp_path: Path, agent: str, filename: str, text: str, fmt: SourceFormat):
    artifact = Artifact(tmp_path / filename, ArtifactKind.AGENT_CONFIG, fmt, agent)
    return parse_structured(artifact, text)


def test_hermes_mcp_shapes_and_secrets(tmp_path: Path) -> None:
    document = _config(
        tmp_path,
        "Hermes Agent",
        "config.yaml",
        """mcp_servers:
  local:
    command: npx
    args: ["-y", "safe-package"]
    env: {TOKEN: secret-placeholder}
  remote:
    url: https://example.org/mcp?token=secret-placeholder
    headers: {Authorization: secret-placeholder}
  disabled_server:
    command: unsafe
    enabled: false
  bad:
    transport: websocket
    url: https://example.org/ws
""",
        SourceFormat.YAML,
    )
    assert {server.name for server in document.servers} == {"local", "remote"}
    assert {edge.target for edge in document.relationships if edge.kind == "defines_server"} == {
        "local",
        "remote",
    }
    assert {s.transport for s in document.servers} == {"stdio", "http"}
    assert document.servers[0].location.line == 2
    assert document.servers[1].headers[0].name == "Authorization"
    assert "secret-placeholder" not in repr(document)
    assert any("unsupported Hermes" in item for item in document.diagnostics)


def test_codex_toml_servers_not_every_table(tmp_path: Path) -> None:
    document = _config(
        tmp_path,
        "Codex",
        "config.toml",
        """model = "example"
[mcp_servers.local]
command = "npx"
args = ["-y", "safe-package"]
env = { TOKEN = "secret-placeholder" }
[mcp_servers.remote]
url = "https://example.org/mcp?token=secret-placeholder"
bearer_token_env_var = "MCP_TOKEN"
[mcp_servers.off]
command = "unsafe"
enabled = false
[mcp_servers.bad]
url = 42
""",
        SourceFormat.TOML,
    )
    assert {server.name for server in document.servers} == {"local", "remote"}
    assert document.servers[0].location.path == tmp_path / "config.toml"
    assert document.servers[1].headers[0].name == "Authorization"
    assert "secret-placeholder" not in repr(document)
    assert document.diagnostics


def test_claude_project_mcp_and_user_settings_not_servers(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / ".claude").mkdir(parents=True)
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"project": {"type": "http", "url": "https://example.org/mcp"}}})
    )
    (project / ".claude" / "settings.json").write_text(
        json.dumps({"mcpServers": {"fake": {"command": "unsafe"}}})
    )
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude.json").write_text(
        json.dumps(
            {
                "mcpServers": {"personal": {"command": "npx", "args": ["safe-package"]}},
                "oauthAccount": {"accessToken": "private-secret"},
            }
        )
    )
    report = Scanner().scan_installed(Target(project), home=home, platform="linux")
    assert {name for _, name, _ in report.mcp_inventory} == {"project", "personal"}
    assert {origin.scope for origin in report.installed_mcp_servers} == {"project", "user"}
    assert "private-secret" not in repr(report)
    assert any("private state excluded" in item.message for item in report.diagnostics)


def test_claude_project_local_scope_is_filtered_and_attributed(tmp_path: Path) -> None:
    project = tmp_path / "workspace"
    project.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude.json").write_text(
        json.dumps(
            {
                "mcpServers": {"shared": {"command": "user-version"}},
                "projects": {
                    str(project): {
                        "mcpServers": {
                            "shared": {"command": "local-version"},
                            "local-only": {"type": "http", "url": "https://example.org/mcp"},
                        }
                    },
                    str(tmp_path / "other"): {"mcpServers": {"other-only": {"command": "other"}}},
                },
                "oauthAccount": {"accessToken": "not-for-export"},
            }
        )
    )
    report = Scanner().scan_installed(Target(project), home=home, platform="linux")
    assert {name for _, name, _ in report.mcp_inventory} == {"shared", "local-only"}
    assert {origin.scope for origin in report.installed_mcp_servers} == {"local"}
    assert "not-for-export" not in repr(report)
    assert "mcp_scope_hints" not in json_report(report)
    no_project = Scanner().scan_installed(home=home, platform="linux")
    assert {name for _, name, _ in no_project.mcp_inventory} == {"shared"}
    assert {origin.scope for origin in no_project.installed_mcp_servers} == {"user"}


def test_claude_bad_local_scope_is_diagnostic_without_fake_server(tmp_path: Path) -> None:
    project = tmp_path / "project"
    artifact = Artifact(
        tmp_path / ".claude.json", ArtifactKind.MCP_CONFIG, SourceFormat.JSON, "Claude Code"
    )
    document = parse_structured(
        artifact,
        json.dumps(
            {
                "mcpServers": {"user": {"command": "safe"}},
                "projects": {str(project): {"mcpServers": ["not-a-map"]}},
            }
        ),
        claude_project=project,
    )
    assert [server.name for server in document.servers] == ["user"]
    assert any("local MCP schema" in item for item in document.diagnostics)


def test_cursor_mdc_and_skills_but_not_shared_identity(tmp_path: Path) -> None:
    project = tmp_path / "project"
    rule = project / ".cursor" / "rules" / "security.mdc"
    rule.parent.mkdir(parents=True)
    rule.write_text(
        "---\ndescription: Reviewing\nalwaysApply: false\n---\n\n# Rule\nRead docs before edits.\n"
    )
    skill = project / ".cursor" / "skills" / "review" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text(
        "---\nname: review\ndescription: A review skill\n---\n\n# Review\nRead tests first.\n"
    )
    shared = project / ".agents" / "skills" / "shared" / "SKILL.md"
    shared.parent.mkdir(parents=True)
    shared.write_text("# Shared")
    report = Scanner().scan_installed(Target(project), home=tmp_path / "home", platform="linux")
    assert any(a.path == rule and a.ecosystem == "Cursor" for a in report.artifacts)
    assert any(a.path == skill and a.ecosystem == "Cursor" for a in report.artifacts)
    assert not any(o.artifact == shared and o.agent == "Cursor" for o in report.artifact_origins)


def test_agent_environment_references_and_remote_auth(tmp_path: Path) -> None:
    claude = _config(
        tmp_path,
        "Claude Code",
        ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "local": {"type": "stdio", "command": "npx", "env": {"TOKEN": "${TOKEN}"}},
                    "remote": {
                        "type": "streamable-http",
                        "url": "https://example.org/mcp?secret=fake",
                        "headers": {"Authorization": "Bearer ${TOKEN}"},
                    },
                }
            }
        ),
        SourceFormat.JSON,
    )
    assert {server.name for server in claude.servers} == {"local", "remote"}
    assert claude.servers[0].environment[0].origin == "reference"
    assert claude.servers[1].url == "https://example.org/mcp"
    assert claude.servers[1].headers[0].origin == "reference"
    codex = _config(
        tmp_path,
        "Codex",
        "config.toml",
        """[mcp_servers.remote]
url = "https://example.org/mcp"
env_http_headers = { Authorization = "AUTH_VAR" }
bearer_token_env_var = "TOKEN_VAR"
""",
        SourceFormat.TOML,
    )
    assert set(codex.servers[0].env_names) == {"AUTH_VAR", "TOKEN_VAR"}
    assert "AUTH_VAR" not in {ref.name for ref in codex.servers[0].headers}


def test_cursor_frontmatter_not_instructions_and_invalid_is_diagnostic(tmp_path: Path) -> None:
    artifact = Artifact(
        tmp_path / "rule.mdc", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN, "Cursor"
    )
    document = parse_markdown(
        artifact,
        (
            "---\ndescription: Sample instructions\nglobs: '*.py'\n"
            "alwaysApply: false\n---\n\n# Body\nRead tests first.\n"
        ),
    )
    assert [(entry.key_path, entry.value) for entry in document.entries] == [
        (("description",), "Sample instructions"),
        (("globs",), "*.py"),
        (("alwaysApply",), False),
    ]
    assert all(
        item.location.line is not None and item.location.line >= 6 for item in document.instructions
    )
    assert any("Read tests first" in item.text for item in document.instructions)
    malformed = parse_markdown(artifact, "---\nalwaysApply: [broken\n---\n\n# Body\nBenign body.\n")
    assert malformed.diagnostics
    assert not malformed.entries
    assert all(
        item.location.line is not None and item.location.line >= 5
        for item in malformed.instructions
    )


def test_claude_unsupported_transport_and_disabled_setting(tmp_path: Path) -> None:
    document = _config(
        tmp_path,
        "Claude Code",
        ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "good": {"type": "sse", "url": "https://example.org/sse"},
                    "bad": {"type": "websocket", "url": "https://example.org/ws"},
                    "off": {"command": "npx", "disabled": True},
                }
            }
        ),
        SourceFormat.JSON,
    )
    assert [server.name for server in document.servers] == ["good"]
    assert document.diagnostics


def test_agent_config_bounds_and_no_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import socket
    import subprocess

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("static scan must not execute or connect")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text('[mcp_servers.safe]\ncommand = "unused"\n')
    report = Scanner().scan_installed(home=home, platform="linux")
    assert any(
        item.agent == "Codex" and item.scope == "user" for item in report.installed_mcp_servers
    )


def test_sensitive_launch_arguments_are_not_exported(tmp_path: Path) -> None:
    document = _config(
        tmp_path,
        "Hermes Agent",
        "config.yaml",
        """mcp_servers:
  guarded:
    command: npx
    args: ["package", "--api-key", "synthetic-value-only", "--url=https://user:pass@example.org/mcp?key=fake"]
""",
        SourceFormat.YAML,
    )
    assert len(document.servers) == 1
    assert "synthetic-value-only" not in repr(document)
    assert "user:pass" not in repr(document)
    assert "key=fake" not in repr(document)
    no_package = _config(
        tmp_path,
        "Codex",
        "config.toml",
        '[mcp_servers.hidden]\ncommand = "npx"\nargs = ["--token", "opaque-value"]\n',
        SourceFormat.TOML,
    )
    assert no_package.servers[0].package is None
    assert not any(edge.kind == "invokes_package" for edge in no_package.relationships)


def test_duplicate_hermes_identity_is_not_normalized(tmp_path: Path) -> None:
    with pytest.raises(ParseError, match="duplicate YAML mapping key"):
        _config(
            tmp_path,
            "Hermes Agent",
            "config.yaml",
            """mcp_servers:
  repeated: {command: safe}
  repeated: {command: unsafe}
""",
            SourceFormat.YAML,
        )


def test_codex_invalid_remote_preserves_valid_sibling(tmp_path: Path) -> None:
    document = _config(
        tmp_path,
        "Codex",
        "config.toml",
        """[mcp_servers.good]
command = "safe"
[mcp_servers.bad]
url = "file:///private/secret"
""",
        SourceFormat.TOML,
    )
    assert [server.name for server in document.servers] == ["good"]
    assert document.diagnostics


def test_cursor_symlink_rule_rejected_and_benign_body(tmp_path: Path) -> None:
    project = tmp_path / "project"
    rules = project / ".cursor" / "rules"
    rules.mkdir(parents=True)
    external = tmp_path / "outside.mdc"
    external.write_text("---\ndescription: Docs\n---\n# Reference\nExample: do not run a server.\n")
    (rules / "linked.mdc").symlink_to(external)
    report = Scanner().scan_installed(Target(project), home=tmp_path / "home", platform="linux")
    assert not any(item.path == rules / "linked.mdc" for item in report.artifacts)
    assert not report.installed_mcp_servers


def test_codex_project_scope_is_distinct(tmp_path: Path) -> None:
    project = tmp_path / "project"
    config = project / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[mcp_servers.local]\ncommand = "safe"\n')
    report = Scanner().scan_installed(Target(project), home=tmp_path / "home", platform="linux")
    assert any(
        origin.config == config and origin.scope == "project" and origin.agent == "Codex"
        for origin in report.installed_mcp_servers
    )


@pytest.mark.parametrize(
    "filename,body",
    [("config.yaml", "mcp_servers: [invalid]"), ("config.toml", "mcp_servers = []")],
)
def test_bad_mcp_root_no_fake_server(tmp_path: Path, filename: str, body: str) -> None:
    agent = "Hermes Agent" if filename.endswith("yaml") else "Codex"
    fmt = SourceFormat.YAML if filename.endswith("yaml") else SourceFormat.TOML
    document = _config(tmp_path, agent, filename, body, fmt)
    assert not document.servers
    assert document.diagnostics
