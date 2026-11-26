"""Wheel-only acceptance of an immutable source and shared package pair; never publish.

Dependency provisioning is an explicit outer step. Locked installs and scans here
are offline. Reuse the reviewed inert smoke and installed-wheel audit tripwires;
never call standalone construction or treat its license gate as a wheel gate.
"""

import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
import platform
import runpy
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path
from typing import Any

TESTS = (
    "test_cli_interface.py",
    "test_cli_ux.py",
    "test_cli_progress.py",
    "test_tui.py",
    "test_tui_keyboard.py",
    "test_tui_safety.py",
    "test_sarif.py",
    "test_shared_openclaw_discovery.py",
    "test_mcp_schema_types.py",
    "test_private_output.py",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_packages(source: Path, packages: Path, commit: str) -> dict[str, Any]:
    """Require exact source membership, metadata, license and wheel RECORD hashes."""
    project = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    (wheel,) = packages.glob("*.whl")
    (sdist,) = packages.glob("*.tar.gz")
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names)), "duplicate wheel members"
        members = {name: archive.read(name) for name in names}
    dist = f"dragons_ai_agent_scanner-{version}.dist-info"
    sources = {
        f"dragonscan/{p.relative_to(source / 'src/dragonscan').as_posix()}": p
        for p in (source / "src/dragonscan").rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
    }
    expected = set(sources) | {
        f"{dist}/METADATA",
        f"{dist}/WHEEL",
        f"{dist}/RECORD",
        f"{dist}/entry_points.txt",
        f"{dist}/licenses/LICENSE",
    }
    assert set(members) == expected, sorted(set(members) ^ expected)
    for name, path in sources.items():
        assert members[name].replace(b"\r\n", b"\n") == path.read_bytes().replace(b"\r\n", b"\n")
        assert path.suffix == ".py", f"Review new non-Python material: {name}"
    for needed in ("dragonscan/cli.py", "dragonscan/tui.py", "dragonscan/scanner.py"):
        assert needed in members
    license_text = (source / "LICENSE").read_bytes().replace(b"\r\n", b"\n")
    assert members[f"{dist}/licenses/LICENSE"].replace(b"\r\n", b"\n") == license_text
    assert b"MIT License" in license_text and b"NaxoziwuS" in license_text
    assert b"dragonscan = dragonscan.cli:main" in members[f"{dist}/entry_points.txt"]
    assert b"Root-Is-Purelib: true" in members[f"{dist}/WHEEL"]
    assert b"Tag: py3-none-any" in members[f"{dist}/WHEEL"]
    metadata = BytesParser().parsebytes(members[f"{dist}/METADATA"])
    assert metadata["Name"] == project["name"] and metadata["Version"] == version
    assert metadata["Requires-Python"] == project["requires-python"]
    assert metadata["License-Expression"] == "MIT" and metadata["License-File"] == "LICENSE"
    assert metadata.get_content_type() == "text/plain"
    assert metadata["Description-Content-Type"] == "text/markdown"
    payload = metadata.get_payload(decode=True)
    assert isinstance(payload, bytes)
    assert (
        payload.decode("utf-8").strip()
        == (source / "README.md").read_text(encoding="utf-8").strip()
    )
    rows = list(csv.reader(io.StringIO(members[f"{dist}/RECORD"].decode())))
    assert len(rows) == len(members) and {row[0] for row in rows} == set(members)
    for name, encoded, size in rows:
        if name == f"{dist}/RECORD":
            assert not encoded and not size
        else:
            expected_hash = base64.urlsafe_b64encode(hashlib.sha256(members[name]).digest())
            assert encoded == "sha256=" + expected_hash.decode().rstrip("=")
            assert int(size) == len(members[name])
    with tarfile.open(sdist) as archive:
        items = archive.getmembers()
        assert all(item.isfile() for item in items), "unexpected link/directory in sdist"
        assert len(items) == len({item.name for item in items})
        root = f"dragons_ai_agent_scanner-{version}"
        allowed = {f"{root}/src/{name}" for name in sources} | {
            f"{root}/{name}"
            for name in (
                "pyproject.toml",
                "README.md",
                "IDEA.md",
                "LICENSE",
                "PKG-INFO",
                ".gitignore",
            )
        }
        assert {item.name for item in items} == allowed
        for item in items:
            stream = archive.extractfile(item)
            assert stream is not None
            data = stream.read()
            if item.name.endswith("/PKG-INFO"):
                assert BytesParser().parsebytes(data)["License-Expression"] == "MIT"
            else:
                path = source / item.name.removeprefix(root + "/")
                assert data.replace(b"\r\n", b"\n") == path.read_bytes().replace(b"\r\n", b"\n")
    return {
        "source_commit": commit,
        "version": version,
        "python": project["requires-python"],
        "dependencies": metadata.get_all("Requires-Dist"),
        "optional_extras": metadata.get_all("Provides-Extra", []),
        "entry_point": project["scripts"],
        "license": "MIT",
        "readme": "embedded in wheel METADATA; standalone file in sdist",
        "wheel_members": sorted(members),
        "sdist_members": sorted(allowed),
        "native_binaries": [],
        "bundled_runtime": False,
        "artifacts": [
            {"name": p.name, "sha256": digest(p), "bytes": p.stat().st_size} for p in (wheel, sdist)
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--mode", choices=("inspect", "install", "tests"), required=True)
    args = parser.parse_args()
    source, packages, output = args.source.resolve(), args.packages.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if args.mode != "tests":
        actual = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=source, text=True
        ).strip()
        assert actual == args.commit and len(actual) == 40
        assert not subprocess.check_output(
            [
                "git",
                "diff",
                "HEAD",
                "--",
                "src",
                "pyproject.toml",
                "uv.lock",
                "README.md",
                "LICENSE",
                "IDEA.md",
            ],
            cwd=source,
        )
        inventory = inspect_packages(source, packages, args.commit)
        (output / "package-report.json").write_text(
            json.dumps(inventory, indent=2), encoding="utf-8"
        )
        (output / "SHA256SUMS").write_text(
            "".join(f"{p['sha256']}  {p['name']}\n" for p in inventory["artifacts"]),
            encoding="utf-8",
        )
        if args.mode == "inspect":
            return
    spec = importlib.util.spec_from_file_location(
        "acceptance", source / "scripts/release_validation.py"
    )
    assert spec and spec.loader
    acceptance: Any = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(acceptance)
    if args.mode == "tests":
        acceptance.SAFE_TESTS = TESTS
        acceptance.guarded_tests(source, output)
        return
    commands: list[dict[str, Any]] = []

    def command(argv: list[str], env: dict[str, str] | None = None) -> str:
        result = subprocess.run(
            argv,
            cwd=source,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
        log = output / f"command-{len(commands):02d}.log"
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
        commands.append({"argv": argv, "exit": result.returncode, "log": log.name})
        (output / "commands.json").write_text(json.dumps(commands, indent=2), encoding="utf-8")
        assert result.returncode == 0, f"Failed command; see {log}"
        return result.stdout

    runtime = output / "runtime-venv"
    assert not runtime.exists(), "use a fresh output directory"
    command(
        [
            "uv",
            "sync",
            "--locked",
            "--offline",
            "--no-dev",
            "--no-install-project",
            "--python",
            sys.executable,
        ],
        env={**os.environ, "UV_PROJECT_ENVIRONMENT": str(runtime)},
    )
    (wheel,) = packages.glob("*.whl")
    command(
        ["uv", "pip", "install", "--offline", "--no-deps", "--python", str(runtime), str(wheel)]
    )
    bin_dir = "Scripts" if sys.platform == "win32" else "bin"
    console = runtime / bin_dir / ("dragonscan.exe" if sys.platform == "win32" else "dragonscan")
    dependencies = json.loads(
        command(["uv", "pip", "list", "--python", str(runtime), "--format", "json"])
    )
    assert not {p["name"] for p in dependencies} & {"pytest", "pyinstaller", "mypy", "ruff"}
    permissions = runpy.run_path(str(source / "tests/report_permissions.py"))

    def private(path: Path) -> str:
        permissions["assert_private"](path)
        return (
            str(permissions["windows_sddl"](path))
            if sys.platform == "win32"
            else oct(path.stat().st_mode & 0o777)
        )

    smokes = acceptance.scan_smokes(console, output / "scan-home", private)
    command(
        ["uv", "pip", "install", "--offline", "--no-deps", "--python", sys.executable, str(wheel)]
    )
    command(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--source",
            str(source),
            "--packages",
            str(packages),
            "--output",
            str(output),
            "--commit",
            args.commit,
            "--mode",
            "tests",
        ],
        env=acceptance.clean_environment(output / "test-home"),
    )
    summary = {
        "source_commit": args.commit,
        "platform": sys.platform,
        "machine": platform.machine(),
        "python": platform.python_version(),
        "wheel_sha256": digest(wheel),
        "dependencies": dependencies,
        "smokes": smokes,
        "status": "PASS",
        "installation": "fresh locked runtime environment; no editable project or dev dependencies",
        "network": "provisioning requires index/cache; acceptance install is offline",
        "tui": "installed-wheel headless keyboard/mouse/resize and target-details regressions",
        "manual_terminal_visual_acceptance": "NOT VERIFIED",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
