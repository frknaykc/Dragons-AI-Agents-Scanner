"""Build a native-host standalone CLI from the locked build-only PyInstaller group."""

import os
import platform
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURES = {
    ("linux", "x86_64"): "linux-x86_64",
    ("darwin", "arm64"): "macos-arm64",
    ("darwin", "x86_64"): "macos-x86_64",
    ("win32", "amd64"): "windows-x86_64",
}


def artifact_name(system: str, machine: str, version: str) -> str:
    """Use names only for build hosts explicitly supported by the release matrix."""
    platform_name = ARCHITECTURES.get((system.lower(), machine.lower()))
    if platform_name is None:
        raise ValueError(f"unsupported build platform: {system}/{machine}")
    suffix = ".exe" if system.lower() == "win32" else ""
    return f"dragonscan-{version}-{platform_name}{suffix}"


def validate_tag(version: str, ref_type: str, ref_name: str) -> None:
    """A tagged staging run must match the package's single version source."""
    if ref_type == "tag" and ref_name != f"v{version}":
        raise ValueError(f"tag does not match package version {version}")


def main() -> None:
    with (ROOT / "pyproject.toml").open("rb") as file:
        version = tomllib.load(file)["project"]["version"]
    validate_tag(
        version, os.environ.get("GITHUB_REF_TYPE", ""), os.environ.get("GITHUB_REF_NAME", "")
    )
    name = artifact_name(sys.platform, platform.machine(), version)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--onefile",
            "--noconfirm",
            "--clean",
            "--name",
            name.removesuffix(".exe"),
            "--paths",
            str(ROOT / "src"),
            "--distpath",
            str(ROOT / "dist"),
            "--workpath",
            str(ROOT / "build" / "standalone"),
            "--specpath",
            str(ROOT / "build" / "standalone"),
            str(ROOT / "scripts" / "standalone.py"),
        ],
        cwd=ROOT,
        check=True,
    )
    if not (ROOT / "dist" / name).is_file():
        raise RuntimeError(f"bundler did not produce expected artifact: {name}")
    print(f"Built dist/{name}")


if __name__ == "__main__":
    main()
