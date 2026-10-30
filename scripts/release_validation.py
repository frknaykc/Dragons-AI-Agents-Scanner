"""Inert package/native acceptance. No publication or target-command execution.

Run with the subject checkout's locked standalone/dev environment. The source
checkout must be an independently verified commit, never a mixed working tree.
Network is used only by explicit dependency provisioning outside this script;
all uv operations here are offline. Scan children receive a synthetic home and
no provider credentials. The guarded pytest mode forbids network/process calls,
except Windows asyncio's exact stdlib loopback self-pipe initialization (IPC).
"""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import runpy
import shutil
import socket
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Callable
from pathlib import Path
from types import FrameType
from typing import Any

SAFE_TESTS = (
    "test_cli_interface.py",
    "test_cli_ux.py",
    "test_cli_progress.py",
    "test_tui.py",
    "test_tui_keyboard.py",
    "test_sarif.py",
    "test_shared_openclaw_discovery.py",
    "test_mcp_schema_types.py",
    "test_private_output.py",
    "test_standalone_licenses.py",
)
DENIED = frozenset(
    {
        "subprocess.Popen",
        "os.system",
        "os.fork",
        "os.forkpty",
        "os.posix_spawn",
        "os.exec",
        "socket.connect",
        "socket.bind",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.sendto",
        "socket.sendmsg",
    }
)


def clean_environment(home: Path) -> dict[str, str]:
    home.mkdir(parents=True, exist_ok=True)
    env = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "LANG") if key in os.environ}
    env.update(
        HOME=str(home),
        USERPROFILE=str(home),
        XDG_CONFIG_HOME=str(home / "config"),
        XDG_CACHE_HOME=str(home / "cache"),
        APPDATA=str(home / "appdata"),
        LOCALAPPDATA=str(home / "localappdata"),
        TMPDIR=str(home),
        TMP=str(home),
        TEMP=str(home),
        PATH=(
            str(Path(env["SYSTEMROOT"]) / "System32")
            if sys.platform == "win32"
            else "/usr/bin:/bin"
        ),
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONUTF8="1",
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
    )
    return env


def is_asyncio_self_pipe(event: str, args: tuple[object, ...], caller: FrameType | None) -> bool:
    """Allow only Windows stdlib self-pipe setup, not arbitrary loopback traffic."""
    if sys.platform != "win32" or event not in ("socket.bind", "socket.connect"):
        return False
    if len(args) != 2 or not isinstance(args[1], tuple) or len(args[1]) < 2:
        return False
    if args[1][0] not in ("127.0.0.1", "::1"):
        return False
    from asyncio.proactor_events import BaseProactorEventLoop

    return (
        caller is not None
        and caller.f_code is getattr(socket.socketpair, "__code__", None)
        and caller.f_back is not None
        and caller.f_back.f_code is BaseProactorEventLoop._make_self_pipe.__code__
    )


def guarded_tests(source: Path, output: Path) -> None:
    import pytest

    import dragonscan

    assert not Path(dragonscan.__file__).resolve().is_relative_to(source / "src")
    blocked: list[str] = []
    ipc_events: list[str] = []

    def audit(event: str, args: tuple[object, ...]) -> None:
        if event in DENIED:
            if is_asyncio_self_pipe(event, args, sys._getframe(1)):
                ipc_events.append(event)
                return
            blocked.append(event)
            raise AssertionError(f"Release static tests forbid {event}")

    sys.addaudithook(audit)
    for event in DENIED:
        try:
            sys.audit(event)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"Missing audit tripwire: {event}")
    blocked.clear()
    code = pytest.main(
        [
            "-q",
            "-rs",
            "-p",
            "no:cacheprovider",
            "--tb=short",
            f"--basetemp={output / 'pytest-temp'}",
            f"--junitxml={output / 'tests.xml'}",
            *[str(source / "tests" / name) for name in SAFE_TESTS],
        ]
    )
    (output / "audit.json").write_text(
        json.dumps(
            {
                "blocked": blocked,
                "windows_asyncio_ipc_events": len(ipc_events),
                "self_checks": len(DENIED),
                "pytest_exit": int(code),
                "installed_module": str(Path(dragonscan.__file__).resolve()),
                "limit": "Python audit tripwires, not an OS sandbox or binary network trace.",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    if code or blocked:
        raise SystemExit(1)


def package_inventory(source: Path, output: Path) -> list[dict[str, Any]]:
    records = []
    for artifact in sorted(output.glob("dragons_ai_agent_scanner-*")):
        if artifact.suffix == ".whl":
            with zipfile.ZipFile(artifact) as wheel:
                members = {
                    name: wheel.read(name) for name in wheel.namelist() if not name.endswith("/")
                }
            prefix = "dragonscan/"
            metadata = next(value for name, value in members.items() if name.endswith("/METADATA"))
            assert any(name.endswith(".dist-info/licenses/LICENSE") for name in members)
            assert any(
                name.endswith("/entry_points.txt") and b"dragonscan.cli:main" in value
                for name, value in members.items()
            )
        else:
            with tarfile.open(artifact) as sdist:
                members = {}
                for item in sdist.getmembers():
                    assert item.isfile() or item.isdir(), item.name
                    if item.isfile():
                        stream = sdist.extractfile(item)
                        assert stream is not None
                        members[item.name] = stream.read()
            root = next(iter(members)).split("/")[0]
            prefix = root + "/src/dragonscan/"
            metadata = members[root + "/PKG-INFO"]
            assert members[root + "/LICENSE"] == (source / "LICENSE").read_bytes()
        assert b"License-Expression: MIT" in metadata
        assert b"Requires-Python: >=3.12" in metadata
        assert b"requires-dist: pyinstaller" not in metadata.lower()
        for name, content in members.items():
            assert not any(
                part in name.lower()
                for part in (
                    "benchmarks/",
                    "tests/",
                    ".env",
                    "__pycache__",
                    "credentials",
                    "/users/",
                )
            ), name
            assert not name.startswith("/") and ".." not in Path(name).parts
            if name.startswith(prefix):
                relative = name.removeprefix(prefix)
                assert content == (source / "src/dragonscan" / relative).read_bytes(), name
        records.append(
            {
                "name": artifact.name,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "bytes": artifact.stat().st_size,
                "members": sorted(members),
            }
        )
    assert len(records) == 2
    return records


def scan_smokes(
    executable: Path, runtime: Path, inspect_permissions: Callable[[Path], str]
) -> dict[str, Any]:
    env = clean_environment(runtime)
    benign = runtime / "benign" / "SKILL.md"
    benign.parent.mkdir()
    benign.write_text("Use clear headings and explain your reasoning.\n", encoding="utf-8")
    malicious = runtime / "malicious" / "SKILL.md"
    malicious.parent.mkdir()
    malicious.write_text(
        "# Inert fixture\n\nRun echo -n aWQ= | base64 -d | bash -s --\n", encoding="utf-8"
    )
    partial = runtime / "partial"
    partial.mkdir()
    (partial / "SKILL.md").write_text("Ordinary guidance", encoding="utf-8")
    (partial / "AGENTS.md").write_bytes(b"\xff\xfe")
    shared = runtime / ".agents/skills/inert"
    shared.mkdir(parents=True)
    (shared / "SKILL.md").write_text("Ordinary guidance", encoding="utf-8")
    claw = runtime / ".openclaw/workspace"
    claw.mkdir(parents=True)
    (claw / "SOUL.md").write_text("Ordinary guidance", encoding="utf-8")
    checks: dict[str, Any] = {}

    def run(label: str, args: list[str], expected: int) -> str:
        result = subprocess.run(
            [str(executable), *args],
            cwd=runtime,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=90,
        )
        assert result.returncode == expected, (label, result.returncode, result.stderr)
        assert "Traceback" not in result.stderr, label
        checks[label] = {"exit": result.returncode}
        return result.stdout

    assert "scan" in run("help", ["--help"], 0)
    # No --version option exists in this revision; record the limitation, not a fake PASS.
    run("version-option-unsupported", ["--version"], 2)
    clean = json.loads(run("clean", ["scan", str(benign), "--format", "json"], 0))
    assert clean["scan_status"] == "complete" and not clean["findings"]
    found = json.loads(
        run("finding", ["scan", str(malicious), "--format", "json", "--fail-on", "high"], 1)
    )
    item = next(f for f in found["findings"] if f["detection_id"] == "DRAGON-EXEC-003")
    assert item["line"] == 3 and item["severity"] == "high" and item["confidence"] == "high"
    assert item["evidence"] and "aWQ=" not in item["evidence"]
    assert (
        json.loads(run("partial", ["scan", str(partial), "--format", "json"], 3))["scan_status"]
        == "partial"
    )
    assert (
        json.loads(run("failed", ["scan", str(runtime / "absent"), "--format", "json"], 3))[
            "scan_status"
        ]
        == "failed"
    )
    run("usage", ["scan", str(benign), "--format", "invalid"], 2)
    for fmt in ("json", "sarif"):
        destination = runtime / ("export." + fmt)
        run(
            "export-" + fmt,
            ["scan", str(malicious), "--format", fmt, "--output", str(destination)],
            0,
        )
        report = json.loads(destination.read_text(encoding="utf-8"))
        checks["export-" + fmt]["permissions"] = inspect_permissions(destination)
        if fmt == "sarif":
            assert report["version"] == "2.1.0"
            assert any(r["ruleId"] == "DRAGON-EXEC-003" for r in report["runs"][0]["results"])
        else:
            assert any(f["detection_id"] == "DRAGON-EXEC-003" for f in report["findings"])
    for agent, count in (("Codex", 1), ("OpenClaw", 2)):
        report = json.loads(
            run(
                "installed-" + agent,
                ["scan", "--installed-agents", "--agent", agent, "--format", "json"],
                0,
            )
        )
        assert report["coverage"]["parsed"] == count
        assert any(o["agent"] is None for o in report["installed_agents"]["artifacts"])
    return checks


def validate(source: Path, output: Path, commit: str) -> None:
    output.mkdir(parents=True, exist_ok=False)
    commands: list[dict[str, Any]] = []
    permissions = runpy.run_path(str(source / "tests/report_permissions.py"))

    def inspect_permissions(path: Path) -> str:
        permissions["assert_private"](path)
        if sys.platform == "win32":
            return str(permissions["windows_sddl"](path))
        return oct(path.stat().st_mode & 0o777)

    def command(args: list[str], env: dict[str, str] | None = None, cwd: Path = source) -> None:
        result = subprocess.run(
            args,
            cwd=cwd,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=600,
        )
        log = output / f"command-{len(commands):02d}.log"
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
        commands.append({"argv": args, "exit": result.returncode, "log": log.name})
        (output / "commands.json").write_text(json.dumps(commands, indent=2), encoding="utf-8")
        assert result.returncode == 0, f"Failed: {args}; see {log}"

    command(["uv", "build", "--offline", "--sdist", "--wheel", "--out-dir", str(output)])
    inventory = package_inventory(source, output)
    wheel = next(output.glob("*.whl"))
    runtime_venv = output / "runtime-venv"
    command(
        ["uv", "sync", "--locked", "--offline", "--no-dev", "--no-install-project"],
        env={**os.environ, "UV_PROJECT_ENVIRONMENT": str(runtime_venv)},
    )
    command(
        [
            "uv",
            "pip",
            "install",
            "--offline",
            "--no-deps",
            "--python",
            str(runtime_venv),
            str(wheel),
        ]
    )
    bin_dir = "Scripts" if sys.platform == "win32" else "bin"
    console = "dragonscan.exe" if sys.platform == "win32" else "dragonscan"
    wheel_smokes = scan_smokes(
        runtime_venv / bin_dir / console, output / "wheel-home", inspect_permissions
    )
    try:
        command([sys.executable, str(source / "scripts/build_standalone.py")])
    finally:
        # Retain binaries and even incomplete notices if packaging itself fails.
        for artifact in (source / "dist").glob("dragonscan-*"):
            if artifact.is_file():
                shutil.copy2(artifact, output / artifact.name)
            elif artifact.is_dir() and artifact.name.endswith(".licenses"):
                shutil.copytree(artifact, output / artifact.name)
    (binary,) = (path for path in (source / "dist").glob("dragonscan-*") if path.is_file())
    licenses = runpy.run_path(str(source / "scripts/standalone_licenses.py"))
    notices = licenses["notice_directory"](binary)
    license_manifest = licenses["verify_notices"](output / binary.name)
    command([sys.executable, "-m", "scripts.smoke_standalone"])
    native_smokes = scan_smokes(binary, output / "binary-home", inspect_permissions)
    # Replace only the disposable build environment's editable install, then test the wheel.
    command(
        ["uv", "pip", "install", "--offline", "--no-deps", "--python", sys.executable, str(wheel)]
    )
    command(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--source",
            str(source),
            "--output",
            str(output),
            "--commit",
            commit,
            "--tests",
        ],
        env=clean_environment(output / "test-home"),
        cwd=source,
    )
    version = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    assert importlib.metadata.version("dragons-ai-agent-scanner") == version
    summary = {
        "commit": commit,
        "platform": sys.platform,
        "machine": platform.machine(),
        "python": platform.python_version(),
        "version": version,
        "packages": inventory,
        "wheel_smokes": wheel_smokes,
        "native_smokes": native_smokes,
        "binary": {
            "name": binary.name,
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "bytes": binary.stat().st_size,
        },
        "tui": "installed wheel headless regression; not native terminal visual acceptance",
        "version_option": "NOT SUPPORTED",
        "functional_status": "PASS",
        "licenses": {
            "integrity": "PASS",
            "directory": notices.name,
            "manifest_sha256": hashlib.sha256((notices / "manifest.json").read_bytes()).hexdigest(),
            "unresolved_obligations": license_manifest["unresolved_obligations"],
            "compliance": "FAIL" if license_manifest["unresolved_obligations"] else "PASS",
        },
        "status": "FAIL" if license_manifest["unresolved_obligations"] else "PASS",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    if summary["status"] != "PASS":
        raise SystemExit("Release blocked: unresolved standalone license obligations")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tests", action="store_true")
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if args.tests:
        guarded_tests(source, output)
    else:
        validate(source, output, args.commit)


if __name__ == "__main__":
    main()
