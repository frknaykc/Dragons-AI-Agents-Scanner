"""Offline native binary smoke: normal scans stay execution-free and local."""

import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

from scripts.build_standalone import ARCHITECTURES, ROOT, artifact_name


def check_native_binary(binary: Path, target: str) -> None:
    """Reject a wrong-format or wrong-architecture executable, not just its filename."""
    with binary.open("rb") as file:
        header = file.read(4096)
    valid = False
    if target == "linux-x86_64":
        valid = (
            len(header) >= 20
            and header[:6] == b"\x7fELF\x02\x01"
            and struct.unpack_from("<H", header, 18)[0] == 62
        )
    elif target.startswith("macos-"):
        machine = 0x0100000C if target == "macos-arm64" else 0x01000007
        valid = (
            len(header) >= 8
            and header[:4] == b"\xcf\xfa\xed\xfe"
            and struct.unpack_from("<I", header, 4)[0] == machine
        )
    elif target == "windows-x86_64" and len(header) >= 64 and header[:2] == b"MZ":
        offset = struct.unpack_from("<I", header, 60)[0]
        valid = (
            offset + 26 <= len(header)
            and header[offset : offset + 4] == b"PE\0\0"
            and struct.unpack_from("<H", header, offset + 4)[0] == 0x8664
            and struct.unpack_from("<H", header, offset + 24)[0] == 0x20B
        )
    if not valid:
        raise ValueError(f"not a native executable for {target}: {binary.name}")


def runtime_environment(source: dict[str, str], system: str) -> dict[str, str]:
    """Run the copied binary without the build venv, source path or Python on PATH."""
    if system == "win32":
        root = source["SYSTEMROOT"]
        path = os.pathsep.join((str(Path(root) / "System32"), root))
        return {"PATH": path, "SYSTEMROOT": root, "WINDIR": root}
    env = {"PATH": "/usr/bin:/bin"}
    for key in ("LANG", "LC_ALL"):
        if key in source:
            env[key] = source[key]
    return env


def matches_sarif_location(uri: str, fixture: Path, system: str) -> bool:
    if uri == fixture.name:
        return True
    if system != "win32":
        return False
    parsed = urlsplit(uri)
    if parsed.scheme != "file" or parsed.netloc or parsed.query or parsed.fragment:
        return False
    candidate = Path(unquote(parsed.path).lstrip("/"))
    return candidate.is_file() and candidate.samefile(fixture)


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("usage: python scripts/smoke_standalone.py")
    import tomllib

    with (ROOT / "pyproject.toml").open("rb") as file:
        version = tomllib.load(file)["project"]["version"]
    target = ARCHITECTURES[(sys.platform.lower(), platform.machine().lower())]
    runner_arch = os.environ.get("RUNNER_ARCH")
    if runner_arch is not None:
        assert runner_arch == ("ARM64" if target == "macos-arm64" else "X64")
    runner_os = os.environ.get("RUNNER_OS")
    if runner_os is not None:
        assert runner_os == {"linux": "Linux", "darwin": "macOS", "win32": "Windows"}[sys.platform]
    binary = ROOT / "dist" / artifact_name(sys.platform, platform.machine(), version)
    assert binary.is_file(), binary
    check_native_binary(binary, target)
    if sys.platform != "win32":
        assert os.access(binary, os.X_OK)
    with tempfile.TemporaryDirectory(prefix="dragons-standalone-smoke-") as directory:
        runtime = Path(directory)
        executable = runtime / binary.name
        shutil.copy2(binary, executable)
        check_native_binary(executable, target)
        clean_fixture = runtime / "AGENTS.md"
        finding_fixture = runtime / "SKILL.md"
        shutil.copyfile(ROOT / "benchmarks/corpus/benign-credential-guide/AGENTS.md", clean_fixture)
        shutil.copyfile(
            ROOT / "benchmarks/corpus/quality-instruction-safety-bypass/SKILL.md",
            finding_fixture,
        )
        env = runtime_environment(dict(os.environ), sys.platform)
        env["HOME" if sys.platform != "win32" else "USERPROFILE"] = str(runtime)
        env["TMPDIR" if sys.platform != "win32" else "TEMP"] = str(runtime)

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [str(executable), *args],
                cwd=runtime,
                env=env,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
                timeout=90,
            )

        help_result = run("--help")
        assert help_result.returncode == 0 and "scan" in help_result.stdout
        assert "Traceback" not in help_result.stderr
        scan_help = run("scan", "--help")
        assert scan_help.returncode == 0
        for flag in ("--format", "--fail-on", "--installed-agents", "--dynamic-mcp"):
            assert flag in scan_help.stdout
        clean = run("scan", "AGENTS.md", "--format", "json")
        clean_report = json.loads(clean.stdout)
        assert clean.returncode == 0
        assert clean_report["findings"] == [] and clean_report["errors"] == []
        assert clean_report["scan_status"] == "complete"
        assert clean_report["policy"]["status"] == "pass"
        finding = run("scan", "SKILL.md", "--format", "json")
        report = json.loads(finding.stdout)
        assert finding.returncode == 0 and report["scan_status"] == "complete"
        assert report["errors"] == [] and len(report["findings"]) == 1
        item = report["findings"][0]
        assert item["detection_id"] == "DRAGON-PI-002"
        assert item["severity"] == "high" and item["line"] == 3
        assert Path(item["artifact"]).resolve() == finding_fixture.resolve()
        assert item["evidence"] and len(item["evidence"]) < 512
        assert "BEGIN PRIVATE KEY" not in item["evidence"]
        policy = run("scan", "SKILL.md", "--format", "json", "--fail-on", "high")
        policy_report = json.loads(policy.stdout)
        assert policy.returncode == 1 and policy_report["policy"]["status"] == "policy_violation"
        assert policy_report["findings"] == report["findings"]
        invalid = run("scan", "missing/SKILL.md", "--format", "json")
        invalid_report = json.loads(invalid.stdout)
        assert invalid.returncode == 3 and invalid_report["errors"]
        assert "Traceback" not in invalid.stderr
        usage = run("scan", "--format", "invalid-format", "SKILL.md")
        assert usage.returncode == 2 and "Traceback" not in usage.stderr
        sarif = run("scan", "SKILL.md", "--format", "sarif")
        sarif_report = json.loads(sarif.stdout)
        assert sarif.returncode == 0 and sarif_report["version"] == "2.1.0"
        sarif_run = sarif_report["runs"][0]
        assert sarif_run["tool"]["driver"]["name"] == "Dragons AI Agent Scanner"
        assert [rule["id"] for rule in sarif_run["tool"]["driver"]["rules"]] == ["DRAGON-PI-002"]
        assert len(sarif_run["results"]) == 1
        sarif_result = sarif_run["results"][0]
        assert sarif_result["ruleId"] == "DRAGON-PI-002"
        assert sarif_result["level"] == "error"
        location = sarif_result["locations"][0]["physicalLocation"]
        uri = location["artifactLocation"]["uri"]
        assert matches_sarif_location(uri, finding_fixture, sys.platform), uri
        assert location["region"]["startLine"] == 3
        assert len(sarif_result["message"]["text"]) < 1000
    digest = hashlib.sha256()
    with binary.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    print(
        "Standalone smoke PASS: "
        + json.dumps(
            {
                "artifact": binary.name,
                "platform": target,
                "runner_os": runner_os,
                "runner_arch": runner_arch,
                "bytes": binary.stat().st_size,
                "sha256": digest.hexdigest(),
                "commit": os.environ.get("GITHUB_SHA"),
                "bundler": f"PyInstaller {importlib.metadata.version('pyinstaller')}",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
