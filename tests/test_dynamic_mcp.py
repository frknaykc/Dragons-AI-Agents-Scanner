"""Only controlled, inert local process fixtures are launched by these tests."""

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from dragonscan import dynamic_mcp
from dragonscan.cli import main
from dragonscan.dynamic_mcp import DynamicPolicy
from dragonscan.models import Target
from dragonscan.reporting import json_report, terminal_report
from dragonscan.scanner import Scanner
from dragonscan.semantic import SemanticProvider


def setup_server(tmp_path: Path, body: str) -> tuple[Path, Path]:
    script = tmp_path / "fake_server.py"
    script.write_text("#!/usr/bin/env python3\n" + body)
    script.chmod(0o700)
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"test": {"command": str(script)}}}))
    return config, script


def policy(script: Path) -> DynamicPolicy:
    return DynamicPolicy(True, True, "test", script)


@pytest.mark.parametrize("semantic", [False, True])
def test_default_does_not_execute(tmp_path: Path, semantic: bool) -> None:
    marker = tmp_path / "ran"
    config, _ = setup_server(tmp_path, f"open({str(marker)!r}, 'w').close()\n")
    scanner = Scanner()
    if semantic:

        class LocalProvider:
            identity = "test"
            model = "test"

            def analyze(
                self, request: dict[str, object], timeout: float, max_response: int
            ) -> bytes:
                return b'{"results":[]}'

        provider: SemanticProvider = LocalProvider()
        scanner = Scanner(semantic_provider=provider)
        assert scanner.scan(Target(config)).dynamic_status == "not_requested"
    else:
        assert "dynamic_mcp" not in json_report(scanner.scan(Target(config)))
    assert not marker.exists()


def test_policy_fail_closed_and_static_preserved(tmp_path: Path) -> None:
    config, script = setup_server(tmp_path, "pass\n")
    baseline = Scanner().scan(Target(config))
    for requested, consent, executable in [
        (False, True, script),
        (True, False, script),
        (True, True, tmp_path / "other"),
    ]:
        result = Scanner(dynamic_policy=DynamicPolicy(requested, consent, "test", executable)).scan(
            Target(config)
        )
        assert result.dynamic_status == ("blocked" if requested else "not_requested")
        assert result.findings == baseline.findings
    config.write_text(
        json.dumps({"mcpServers": {"test": {"command": str(script), "args": ["-c", "run"]}}})
    )
    assert Scanner(dynamic_policy=policy(script)).scan(Target(config)).dynamic_status == "blocked"
    config.write_text(json.dumps({"mcpServers": {"test": {"command": "sh -c 'id'"}}}))
    assert Scanner(dynamic_policy=policy(script)).scan(Target(config)).dynamic_status == "blocked"


def test_static_scan_errors_prevent_dynamic_launch(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    _, script = setup_server(tmp_path, f"open({str(marker)!r}, 'w').close()\n")
    (tmp_path / "AGENTS.md").write_bytes(b"\x00")
    baseline = Scanner().scan(Target(tmp_path))
    assert baseline.errors
    report = Scanner(dynamic_policy=policy(script)).scan(Target(tmp_path))
    assert report.dynamic_status == "blocked"
    assert report.dynamic_diagnostics == ("static scan incomplete; MCP launch skipped",)
    assert report.findings == baseline.findings
    assert report.errors == baseline.errors
    assert not marker.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink support required")
def test_ambiguous_or_symlink_executable_never_runs(tmp_path: Path) -> None:
    config, script = setup_server(tmp_path, "pass\n")
    alias = tmp_path / "alias.py"
    alias.symlink_to(script)
    config.write_text(json.dumps({"mcpServers": {"test": {"command": str(alias)}}}))
    assert Scanner(dynamic_policy=policy(alias)).scan(Target(config)).dynamic_status == "blocked"
    other = tmp_path / "mcp.json"
    other.write_text(json.dumps({"mcpServers": {"test": {"command": str(script)}}}))
    config.write_text(other.read_text())
    assert Scanner(dynamic_policy=policy(script)).scan(Target(tmp_path)).dynamic_status == "blocked"


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
def test_early_exit_reaps_process(tmp_path: Path) -> None:
    marker = tmp_path / "pid.txt"
    config, script = setup_server(
        tmp_path, f"import os\nopen({str(marker)!r}, 'w').write(str(os.getpid()))\n"
    )
    result = Scanner(dynamic_policy=policy(script)).scan(Target(config))
    assert result.dynamic_status == "failed"
    with pytest.raises(ProcessLookupError):
        os.kill(int(marker.read_text()), 0)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
def test_stdout_cumulative_limit_without_newline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, script = setup_server(
        tmp_path, "import sys\nsys.stdout.write('x'*20000)\nsys.stdout.flush()\n"
    )
    monkeypatch.setattr(dynamic_mcp, "_STDOUT_BYTES", 8192)
    result = Scanner(dynamic_policy=policy(script)).scan(Target(config))
    assert result.dynamic_status == "failed"
    assert result.dynamic_diagnostics == ("stdout limit exceeded",)


SERVER = """import json, sys, os

def send(id, result):
    print(json.dumps({"jsonrpc": "2.0", "id": id, "result": result}), flush=True)

for line in sys.stdin:
    req = json.loads(line)
    if req.get("method") == "initialize":
        send(req["id"], {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
            "serverInfo": {"name": "demo", "version": "1"},
        })
    elif req.get("method") == "tools/list":
        keys = {"DRAGONS_TEST_SECRET", "DRAGONSCAN_SEMANTIC_API_KEY"}
        send(req["id"], {"tools": [{
            "name": "safe\\u001b[31m" if not keys & os.environ.keys() else "leaked",
            "description": "observed",
            "inputSchema": {"type": "object"},
        }]})
    elif req.get("method") == "prompts/list":
        send(req["id"], {"prompts": [{"name": "hello", "description": "hello"}]})
    elif req.get("method") == "resources/list":
        send(req["id"], {"resources": [{"name": "data", "uri": "file:///etc/passwd"}]})
    elif req.get("method") in ("tools/call", "resources/read", "prompts/get"):
        raise RuntimeError("forbidden invocation")
"""


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
def test_observed_metadata_no_invocations_or_secret_inheritance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, script = setup_server(tmp_path, SERVER)
    monkeypatch.setenv("DRAGONS_TEST_SECRET", "should-not-leak")
    monkeypatch.setenv("DRAGONSCAN_SEMANTIC_API_KEY", "should-not-leak")
    report = Scanner(dynamic_policy=policy(script)).scan(Target(config))
    assert report.dynamic_status == "completed"
    assert [item.name for item in report.dynamic_observations[0].tools] == ["safe\x1b[31m"]
    assert report.dynamic_observations[0].resources[0].name == "data"
    assert "\x1b" not in terminal_report(report)
    assert "should-not-leak" not in json_report(report)
    assert '"provenance": "dynamic_observation"' in json_report(report)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
def test_semantic_and_dynamic_independent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config, script = setup_server(tmp_path, SERVER)
    monkeypatch.setenv("DRAGONSCAN_SEMANTIC_API_KEY", "should-not-leak")

    class LocalProvider:
        identity = "test"
        model = "test"

        def analyze(self, request: dict[str, object], timeout: float, max_response: int) -> bytes:
            return b'{"results":[]}'

    provider: SemanticProvider = LocalProvider()
    result = Scanner(semantic_provider=provider, dynamic_policy=policy(script)).scan(Target(config))
    assert result.dynamic_status == "completed"
    assert result.dynamic_observations[0].tools[0].name == "safe\x1b[31m"
    assert "should-not-leak" not in json_report(result)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
def test_duplicate_response_id_rejected(tmp_path: Path) -> None:
    duplicate = SERVER.replace(
        '    elif req.get("method") == "tools/list":',
        '        send(req["id"], {"capabilities": {}})\n'
        '    elif req.get("method") == "tools/list":',
    )
    config, script = setup_server(tmp_path, duplicate)
    result = Scanner(dynamic_policy=policy(script)).scan(Target(config))
    assert result.dynamic_status == "failed"
    assert "protocol response or ID" in result.dynamic_diagnostics[0]


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
def test_deep_json_cannot_crash_static_scan(tmp_path: Path) -> None:
    body = (
        'print(\'{"jsonrpc":"2.0","id":1,"result":\' + '
        "'['*8000 + '0' + ']'*8000 + '}', flush=True)\n"
    )
    config, script = setup_server(tmp_path, body)
    baseline = Scanner().scan(Target(config))
    report = Scanner(dynamic_policy=policy(script)).scan(Target(config))
    assert report.dynamic_status == "failed"
    assert report.findings == baseline.findings
    assert report.dynamic_diagnostics == ("protocol complexity limit exceeded",)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
def test_partial_preserves_observed_metadata_and_static_result(tmp_path: Path) -> None:
    broken = SERVER.replace(
        '        send(req["id"], {"prompts": [{"name": "hello", "description": "hello"}]})',
        "        print('invalid', flush=True)",
    )
    config, script = setup_server(tmp_path, broken)
    baseline_scanner = Scanner()
    baseline = baseline_scanner.scan(Target(config))
    dynamic_scanner = Scanner(dynamic_policy=policy(script))
    report = dynamic_scanner.scan(Target(config))
    assert report.dynamic_status == "partial"
    assert report.dynamic_observations[0].provenance == "dynamic_observation"
    assert [tool.name for tool in report.dynamic_observations[0].tools] == ["safe\x1b[31m"]
    assert report.findings == baseline.findings
    assert dynamic_scanner.graph == baseline_scanner.graph
    assert json.loads(json_report(report))["dynamic_mcp"]["status"] == "partial"
    cli = CliRunner().invoke(
        main,
        [
            "scan",
            str(config),
            "--dynamic-mcp",
            "--allow-uncontained-mcp",
            "--dynamic-mcp-server",
            "test",
            "--dynamic-mcp-executable",
            str(script),
            "--format",
            "json",
        ],
    )
    assert cli.exit_code == 3
    assert json.loads(cli.output)["dynamic_mcp"]["status"] == "partial"


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
@pytest.mark.parametrize("field", ["protocolVersion", "serverInfo"])
def test_invalid_initialize_is_not_completed(tmp_path: Path, field: str) -> None:
    original = (
        '"protocolVersion": "2025-03-26"'
        if field == "protocolVersion"
        else '"serverInfo": {"name": "demo", "version": "1"}'
    )
    broken = SERVER.replace(original, f'"{field}": None')
    config, script = setup_server(tmp_path, broken)
    report = Scanner(dynamic_policy=policy(script)).scan(Target(config))
    assert report.dynamic_status == "failed"
    assert report.dynamic_observations == ()
    assert report.dynamic_diagnostics == ("invalid initialize response",)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
@pytest.mark.parametrize(
    "body,reason",
    [
        ("import time; time.sleep(20)\n", "timeout"),
        ("import sys; sys.stdout.write('x'*200000); sys.stdout.flush()\n", "message"),
        ("import sys; sys.stderr.write('x'*200000); sys.stderr.flush()\n", "stderr"),
        ("print('not json', flush=True)\n", "protocol"),
        (
            "import json; print(json.dumps({'jsonrpc':'2.0','id':999,'result':{}}),flush=True)\n",
            "protocol",
        ),
        (
            "import json; print(json.dumps({'jsonrpc':'2.0','id':True,'result':{}}),flush=True)\n",
            "protocol",
        ),
        (
            "import json; print(json.dumps({'jsonrpc':'2.0','id':1,'result':"
            "{'capabilities':{},'protocolVersion':'x'*60000}}),flush=True)\n",
            "message",
        ),
        ("pass\n", "exit"),
    ],
)
def test_failure_is_diagnostic_only(tmp_path: Path, body: str, reason: str) -> None:
    config, script = setup_server(tmp_path, body)
    baseline = Scanner().scan(Target(config))
    result = Scanner(dynamic_policy=policy(script)).scan(Target(config))
    assert result.dynamic_status in ("failed", "partial")
    assert reason in " ".join(result.dynamic_diagnostics)
    assert result.findings == baseline.findings


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
def test_cli_requires_stronger_consent(tmp_path: Path) -> None:
    config, script = setup_server(tmp_path, SERVER)
    args = [
        "scan",
        str(config),
        "--dynamic-mcp",
        "--dynamic-mcp-server",
        "test",
        "--dynamic-mcp-executable",
        str(script),
        "--format",
        "json",
    ]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 3
    assert json.loads(result.output)["dynamic_mcp"]["status"] == "blocked"
    result = CliRunner().invoke(main, [*args, "--allow-uncontained-mcp"])
    assert result.exit_code == 0
    assert json.loads(result.output)["dynamic_mcp"]["status"] == "completed"
