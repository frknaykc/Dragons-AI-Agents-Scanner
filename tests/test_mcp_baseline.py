"""Approved metadata is local data; none of these commands may launch a process."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from dragonscan.mcp_baseline_cli import mcp_baseline

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX private store")


def test_baseline_lifecycle(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(mode=0o700)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: pytest.fail("must not launch"))
    config = tmp_path / "mcp.json"
    schema = {"type": "object", "properties": {"q": {"type": "string"}}}
    tool = {"name": "read", "inputSchema": schema}
    config_data = {"mcpServers": {s: {"command": "example", "tools": [dict(tool)]} for s in "ab"}}
    config.write_text(json.dumps(config_data))
    runner = CliRunner()

    def run(*args):
        result = runner.invoke(mcp_baseline, [args[0], str(config), *args[1:]])
        return result.exit_code, json.loads(result.output)

    assert run("compare")[0] == 3
    assert not list((tmp_path / "home").iterdir())
    digest = run("review")[1]["digest"]
    assert run("approve", "--digest", "1" * 64)[0] == 3
    assert run("approve", "--digest", digest)[0] == 0
    assert run("compare")[1]["status"] == "unchanged"
    clone = tmp_path / "copy.json"
    clone.write_bytes(config.read_bytes())
    missing = runner.invoke(mcp_baseline, ["compare", str(clone)])
    assert missing.exit_code == 3  # Same server and tool names, different source.
    store = tmp_path / "home" / ".dragonscan-mcp-approvals"
    approved = next(store.iterdir())
    original = approved.read_bytes()
    config.write_text(json.dumps(config_data, sort_keys=True, indent=4))
    assert run("review")[1]["digest"] == digest
    entry = config_data["mcpServers"]["a"]
    entry["tools"][0]["inputSchema"] = {"type": "string"}
    entry["command"] = "unit-SYNTHETIC-secret"
    config.write_text(json.dumps(config_data))
    code, diff = run("compare")
    assert code == 1
    assert [(x["server"], x.get("tool"), x["change"]) for x in diff["changes"]] == [
        ("a", None, "server_changed"),
        ("a", "read", "schema_changed"),
    ]
    assert "unit-SYNTHETIC-secret" not in json.dumps(diff)
    assert diff["rule_id"] == "DRAGON-MCP-013"
    assert approved.read_bytes() == original
    assert not approved.stat().st_mode & 0o077 and not store.stat().st_mode & 0o077
    assert run("approve", "--digest", digest)[0] == 3
    assert run("approve", "--digest", run("review")[1]["digest"])[0] == 0
    assert run("compare")[0] == 0
    approved.chmod(0o644)
    assert run("compare")[0] == 3
    approved.unlink()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_bytes(original)
    approved.symlink_to(elsewhere)
    assert run("compare")[0] == 3
    assert run("approve", "--digest", run("review")[1]["digest"])[0] == 3
    assert hashlib.sha256(elsewhere.read_bytes()).digest() == hashlib.sha256(original).digest()


@pytest.mark.parametrize(
    "raw",
    [
        '{"mcpServers":{"a":{"tools":[],"tools":[]}}}',
        '{"mcpServers":{"a":{"command":"local"}}}',
        '{"mcpServers":{"a":{"tools":[{"name":"read"}]}}}',
        '{"mcpServers":{"a":{"tools":[{"name":"read","inputSchema":NaN}]}}}',
        '{"mcpServers":{"a":{"tools":[],"value":1.0000000000000000001}}}',
        '{"mcpServers":{"a":{"tools":[{"name":"a","inputSchema":{}},{"name":"a","inputSchema":{}}]}}}',
    ],
)
def test_unknown_not_empty(tmp_path, raw):
    config = tmp_path / "mcp.json"
    config.write_text(raw)
    result = CliRunner().invoke(mcp_baseline, ["review", str(config)])
    assert result.exit_code == 3
    assert json.loads(result.output)["status"] == "partial"
