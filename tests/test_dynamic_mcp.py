"""Only controlled, inert local process fixtures are launched by these tests."""

import json
import os
import signal
import socket
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from dragonscan import dynamic_mcp
from dragonscan.cli import main
from dragonscan.dynamic_mcp import DynamicPolicy
from dragonscan.models import (
    Artifact,
    ArtifactKind,
    Document,
    DynamicMcpItem,
    McpServer,
    McpTool,
    SourceFormat,
    SourceRef,
    Target,
)
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
    assert report.dynamic_observations[0].transport == "stdio"
    assert len(report.dynamic_observations[0].session_id) == 32
    assert report.dynamic_observations[0].observed_methods == (
        "initialize",
        "tools/list",
        "prompts/list",
        "resources/list",
    )
    assert report.dynamic_observations[0].inventory_comparison == ()
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
    assert report.dynamic_diagnostics[0] == "protocol complexity limit exceeded"


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


def test_isolation_policy_reports_unavailable_capabilities_without_launch(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    config, script = setup_server(tmp_path, f"open({str(marker)!r}, 'w').close()\n")
    report = Scanner(dynamic_policy=DynamicPolicy(True, False, "test", script)).scan(Target(config))
    dynamic = json.loads(json_report(report))["dynamic_mcp"]
    assert dynamic["status"] == "blocked"
    assert dynamic["isolation"] == "not_executed"
    assert dynamic["mode"] == "required_isolation"
    assert dynamic["capabilities"]["filesystem_read_write"] == "unsupported"
    assert dynamic["capabilities"]["network_denial"] == "unsupported"
    assert "required isolation" in dynamic["diagnostics"][0]
    assert not marker.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX legacy process groups required")
def test_legacy_mode_reports_limits_and_phase_timings(tmp_path: Path) -> None:
    config, script = setup_server(tmp_path, SERVER)
    report = Scanner(dynamic_policy=policy(script)).scan(Target(config))
    dynamic = json.loads(json_report(report))["dynamic_mcp"]
    assert dynamic["mode"] == "legacy_uncontained"
    assert dynamic["capabilities"]["environment_filtering"] == "available"
    assert dynamic["capabilities"]["process_group_cleanup"] == "available"
    assert dynamic["capabilities"]["filesystem_read_write"] == "unsupported"
    assert dynamic["capabilities"]["network_denial"] == "unsupported"
    assert set(dynamic["timings_ms"]) == {
        "startup",
        "initialize",
        "tools/list",
        "prompts/list",
        "resources/list",
        "total",
    }
    assert all(value >= 0 for value in dynamic["timings_ms"].values())


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
def test_temporary_cwd_removed_after_success_and_protocol_failure(tmp_path: Path) -> None:
    marker = tmp_path / "cwd"
    for body, expected in [
        (f"import os\nopen({str(marker)!r}, 'w').write(os.getcwd())\n" + SERVER, "completed"),
        (
            f"import os\nopen({str(marker)!r}, 'w').write(os.getcwd())\nprint('bad', flush=True)",
            "failed",
        ),
    ]:
        config, script = setup_server(tmp_path, body)
        assert (
            Scanner(dynamic_policy=policy(script)).scan(Target(config)).dynamic_status == expected
        )
        assert Path(marker.read_text()).name.startswith("dragonscan-mcp-")
        assert not Path(marker.read_text()).exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
def test_same_group_child_is_stopped_even_when_parent_exits(tmp_path: Path) -> None:
    marker = tmp_path / "child-ran"
    pid_file = tmp_path / "child-pid"
    body = (
        "import subprocess, sys\n"
        f"child = subprocess.Popen([sys.executable, '-c', "
        f'"import time, pathlib; time.sleep(4); pathlib.Path({str(marker)!r}).touch()"])\n'
        f"open({str(pid_file)!r}, 'w').write(str(child.pid))\n"
    )
    config, script = setup_server(tmp_path, body)
    try:
        report = Scanner(dynamic_policy=policy(script)).scan(Target(config))
        assert report.dynamic_status == "failed"
        assert "timeout" in report.dynamic_diagnostics[0]
        assert pid_file.exists()
        time.sleep(0.3)
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)
        assert not marker.exists()
    finally:
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
@pytest.mark.parametrize(
    "body,diagnostic",
    [
        ("import sys\nsys.stderr.write('x'*40000)\nsys.stderr.flush()\n", "stderr limit"),
        (
            'for _ in range(40): print(\'{"jsonrpc":"2.0","method":"ping"}\', flush=True)\n',
            "invalid protocol response",
        ),
        (
            "import sys\nsys.stdout.buffer.write(b'\\xff\\n')\nsys.stdout.flush()\n",
            "malformed protocol",
        ),
    ],
)
def test_hostile_streams_fail_without_raw_output(
    tmp_path: Path, body: str, diagnostic: str
) -> None:
    config, script = setup_server(tmp_path, body)
    report = Scanner(dynamic_policy=policy(script)).scan(Target(config))
    assert report.dynamic_status == "failed"
    assert diagnostic in report.dynamic_diagnostics[0]
    assert "'x'*40000" not in json_report(report)


def test_inventory_comparison_requires_explicit_declaration_and_finished_list(
    tmp_path: Path,
) -> None:
    path = tmp_path / ".mcp.json"
    source = SourceRef(path, SourceFormat.JSON, 2)
    artifact = Artifact(path, ArtifactKind.MCP_CONFIG, SourceFormat.JSON)
    tool = McpTool("declared", "", "", (), source)
    server = McpServer("test", "/tmp/server", (), source, tools=(tool,))
    document = Document(artifact, servers=(server,))
    item = DynamicMcpItem("runtime", "0" * 64)
    assert dynamic_mcp._observation(document, server, {}).inventory_comparison == ()
    comparison = dynamic_mcp._observation(document, server, {"tools": (item,)})
    assert [(entry.name, entry.status) for entry in comparison.inventory_comparison] == [
        ("declared", "declared_only"),
        ("runtime", "observed_only"),
    ]
    assert comparison.provenance == "dynamic_observation"
    no_inventory = McpServer("test", "/tmp/server", (), source)
    assert (
        dynamic_mcp._observation(document, no_inventory, {"tools": (item,)}).inventory_comparison
        == ()
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
def test_cleanup_uncertainty_cannot_be_reported_as_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, script = setup_server(tmp_path, SERVER)
    terminate = dynamic_mcp._terminate

    def uncertain(process: dynamic_mcp.subprocess.Popen[bytes]) -> bool:
        terminate(process)
        return False

    monkeypatch.setattr(dynamic_mcp, "_terminate", uncertain)
    report = Scanner(dynamic_policy=policy(script)).scan(Target(config))
    assert report.dynamic_status == "partial"
    assert report.dynamic_observations
    assert report.dynamic_diagnostics == ("process group cleanup not confirmed",)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
@pytest.mark.parametrize(
    "replacement,reason",
    [
        (
            '        send(req["id"], {"tools": [{"name": str(i), "inputSchema": {}} '
            "for i in range(33)]})",
            "metadata count",
        ),
        (
            '        send(req["id"], {"tools": [{"name": "duplicate", "inputSchema": {}} '
            "for _ in range(2)]})",
            "invalid metadata",
        ),
        (
            '        send(req["id"], {"tools": [{"name": "large", "description": "x"*3000, '
            '"inputSchema": {}}]})',
            "invalid metadata",
        ),
    ],
)
def test_metadata_abuse_is_not_a_complete_observation(
    tmp_path: Path, replacement: str, reason: str
) -> None:
    original = '        keys = {"DRAGONS_TEST_SECRET", "DRAGONSCAN_SEMANTIC_API_KEY"}'
    body = SERVER.replace(
        original,
        replacement + "\n        continue\n" + original,
    )
    config, script = setup_server(tmp_path, body)
    report = Scanner(dynamic_policy=policy(script)).scan(Target(config))
    assert report.dynamic_status == "failed"
    assert reason in report.dynamic_diagnostics[0]
    assert report.dynamic_observations == ()


@pytest.mark.skipif(os.name != "posix", reason="POSIX legacy process groups required")
def test_legacy_has_no_host_file_or_loopback_network_isolation(tmp_path: Path) -> None:
    source = tmp_path / "synthetic-public-input"
    destination = tmp_path / "synthetic-output"
    source.write_text("dummy")
    with socket.socket() as listener:
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
        except OSError:
            pytest.skip("loopback unavailable on this host")
        port = listener.getsockname()[1]
        original = '        keys = {"DRAGONS_TEST_SECRET", "DRAGONSCAN_SEMANTIC_API_KEY"}'
        injected = (
            f"        with open({str(source)!r}) as read: value = read.read()\n"
            f'        with open({str(destination)!r}, "w") as write: write.write(value)\n'
            f'        with socket.create_connection(("127.0.0.1", {port}), timeout=0.5) '
            'as connection: connection.sendall(b"x")\n'
        )
        body = SERVER.replace(original, injected + original).replace(
            "import json, sys, os", "import json, sys, os, socket"
        )
        config, script = setup_server(tmp_path, body)
        blocked = Scanner(dynamic_policy=DynamicPolicy(True, False, "test", script)).scan(
            Target(config)
        )
        assert blocked.dynamic_status == "blocked"
        assert not destination.exists()
        observed = Scanner(dynamic_policy=policy(script)).scan(Target(config))
        assert observed.dynamic_status == "completed"
        assert observed.dynamic_capabilities["network_denial"] == "unsupported"
        listener.settimeout(1)
        connection, _ = listener.accept()
        with connection:
            assert connection.recv(1) == b"x"
    assert destination.read_text() == "dummy"


def test_second_snapshot_metadata_drift_is_not_claimed_by_single_observation() -> None:
    declared = ("stable",)
    first = dynamic_mcp._compare_inventory("tools", declared, (DynamicMcpItem("stable", ""),))
    second = dynamic_mcp._compare_inventory(
        "tools", declared, (DynamicMcpItem("stable", ""), DynamicMcpItem("new", ""))
    )
    assert len(first) == 1
    assert [(item.name, item.status) for item in second] == [
        ("new", "observed_only"),
        ("stable", "declared_and_observed"),
    ]
    # Production intentionally takes one snapshot, so it cannot claim temporal drift.
