"""Isolated inspector contract. Live acceptance is an explicit local-engine opt-in."""

import json
import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

import pytest

from dragonscan import dynamic_mcp, mcp_sandbox
from dragonscan.dynamic_mcp import DynamicPolicy
from dragonscan.models import Target
from dragonscan.reporting import json_report, terminal_report
from dragonscan.scanner import Scanner

IMAGE = "sha256:" + "0" * 64


def _fixture(root: Path) -> tuple[Path, Path]:
    executable = root / "harmless-fixture"
    executable.write_text("""#!/usr/local/bin/python3 -I
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    method = request["method"]
    if method == "initialize":
        data = {"protocolVersion":"2025-03-26", "serverInfo":{"name":"fixture","version":"1"},
                "capabilities":{"tools":{}}}
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        data = {"tools":[{"name":"inert", "inputSchema":{"type":"object"}}]}
    else:
        sys.exit(2)
    print(json.dumps({"jsonrpc":"2.0", "id":request["id"], "result":data}), flush=True)
""")
    executable.chmod(0o700)
    config = root / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"fixture": {"command": str(executable)}}}))
    return config, executable


@pytest.mark.parametrize(
    "case", ["not_requested", "mixed_modes", "unsupported", "preflight", "partial"]
)
def test_gate_never_dispatches_target(tmp_path, monkeypatch, case):
    config, executable = _fixture(tmp_path)
    if case == "partial":
        (tmp_path / "AGENTS.md").write_bytes(b"\x00")
    target = Mock(side_effect=AssertionError("target must not run"))
    monkeypatch.setattr(dynamic_mcp, "_run", target)
    if case == "preflight":
        monkeypatch.setattr(mcp_sandbox, "platform_check", lambda _: None)
        probe = Mock(side_effect=mcp_sandbox.IsolationError("synthetic failed quota probe"))
        monkeypatch.setattr(mcp_sandbox.DockerSandbox, "probe", probe)
    else:
        monkeypatch.setattr(mcp_sandbox.sys, "platform", "darwin")
        probe = Mock(side_effect=AssertionError("no probe on this path"))
        monkeypatch.setattr(mcp_sandbox.DockerSandbox, "probe", probe)
    report = Scanner(
        dynamic_policy=DynamicPolicy(
            case != "not_requested", case == "mixed_modes", "fixture", executable, IMAGE
        )
    ).scan(Target(tmp_path if case == "partial" else config))
    assert report.dynamic_status == ("not_requested" if case == "not_requested" else "blocked")
    assert not report.dynamic_observations
    if case != "not_requested":
        assert json.loads(json_report(report))["dynamic_mcp"]["isolation"] == "not_executed"
        assert "not_executed" in terminal_report(report)
    assert probe.call_count == int(case == "preflight" and os.name == "posix")
    target.assert_not_called()


@pytest.mark.skipif(os.name != "posix", reason="POSIX staging")
def test_staging_copies_one_regular_file_refuses_symlinks_and_large_inputs(tmp_path, monkeypatch):
    source = tmp_path / "src"
    source.mkdir()
    executable = source / "selected"
    executable.write_bytes(b"original")
    executable.chmod(0o700)
    staged = tmp_path / "copy"
    mcp_sandbox._copy_executable(executable, staged)
    executable.write_bytes(b"changed")
    assert staged.read_bytes() == b"original" and stat.S_IMODE(staged.stat().st_mode) == 0o555
    alias = tmp_path / "alias"
    alias.symlink_to(source, target_is_directory=True)
    with pytest.raises(OSError):
        mcp_sandbox._copy_executable(alias / "selected", tmp_path / "never")
    monkeypatch.setattr(mcp_sandbox, "_LIMIT", 1)
    with pytest.raises(mcp_sandbox.IsolationError):
        mcp_sandbox._copy_executable(executable, tmp_path / "never")
    assert not (tmp_path / "never").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX executable dispatch")
def test_verified_dispatch_uses_only_backend_target(tmp_path, monkeypatch):
    config, executable = _fixture(tmp_path)
    backend = Mock()
    backend.target.side_effect = OSError("synthetic target launch failure")

    @contextmanager
    def prepared(image):
        assert image == IMAGE
        yield backend

    monkeypatch.setattr(mcp_sandbox, "prepared", prepared)
    monkeypatch.setattr(
        dynamic_mcp.subprocess, "Popen", lambda *a, **kw: pytest.fail("host launch")
    )
    report = Scanner(dynamic_policy=DynamicPolicy(True, False, "fixture", executable, IMAGE)).scan(
        Target(config)
    )
    assert report.dynamic_status == "failed" and report.dynamic_mode == "isolated_docker"
    isolation = json.loads(json_report(report))["dynamic_mcp"]["isolation"]
    assert isolation == "docker; boundary probe passed"
    assert isolation in terminal_report(report)
    backend.target.assert_called_once_with(executable)


def test_engine_contract_never_pulls_or_inherits_host_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://invalid.example:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "untrusted")
    backend = mcp_sandbox.DockerSandbox(IMAGE, tmp_path)
    assert backend.prefix[-1] == "unix:///var/run/docker.sock"
    assert set(backend.env) == {"PATH", "HOME"}
    args = mcp_sandbox._create_args(IMAGE, tmp_path / "staged", "fixture")
    assert args.count("--mount") == 1
    assert f"type=bind,source={tmp_path}/staged,target=/dragonscan-target,readonly" in args
    assert {
        "--pull=never",
        "--network=none",
        "--read-only",
        "--log-driver=none",
        "--cap-drop=ALL",
        "--pids-limit=16",
        "--memory=96m",
        "--cpus=0.5",
        "--memory-swap=96m",
        "--no-healthcheck",
        "--user=65534:65534",
        "--rm",
    } <= set(args)
    assert args[args.index(IMAGE) + 1] == "-i"
    assert str(tmp_path) not in args


@pytest.mark.skipif(
    sys.platform != "linux" or not os.getenv("DRAGONSCAN_TEST_DOCKER_IMAGE"),
    reason="requires explicit reviewed local image and authorized native Linux Docker",
)
def test_live_isolated_inspector_and_boundary_probe(tmp_path: Path) -> None:
    """Production gate itself checks host marker, loopback denial, quotas and dead descendants."""
    config, executable = _fixture(tmp_path)
    report = Scanner(
        dynamic_policy=DynamicPolicy(
            True, False, "fixture", executable, os.environ["DRAGONSCAN_TEST_DOCKER_IMAGE"]
        )
    ).scan(Target(config))
    assert report.dynamic_status == "completed", report.dynamic_diagnostics
    assert report.dynamic_mode == "isolated_docker"
    assert report.dynamic_capabilities["network_denial"] == "verified_by_probe"
    assert [item.name for item in report.dynamic_observations[0].tools] == ["inert"]
