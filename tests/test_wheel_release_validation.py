"""Inert archive-level checks for the wheel-only acceptance harness."""

import base64
import hashlib
import importlib
import io
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
inspect_packages = importlib.import_module("scripts.wheel_release_validation").inspect_packages


@pytest.fixture
def packages(tmp_path: Path) -> tuple[Path, Path]:
    source, output = tmp_path / "source", tmp_path / "packages"
    (source / "src/dragonscan").mkdir(parents=True)
    output.mkdir()
    metadata = (
        "Metadata-Version: 2.4\nName: dragons-ai-agent-scanner\nVersion: 0.1.0\n"
        "Requires-Python: >=3.12\nLicense-Expression: MIT\nLicense-File: LICENSE\n"
        "Description-Content-Type: text/markdown\n\n# Sample: Aykaç\n"
    ).encode()
    files = {
        "pyproject.toml": '[project]\nname="dragons-ai-agent-scanner"\nversion="0.1.0"\n'
        'requires-python=">=3.12"\n[project.scripts]\ndragonscan="dragonscan.cli:main"\n',
        "README.md": "# Sample: Aykaç\n",
        "IDEA.md": "Proposals only\n",
        ".gitignore": "__pycache__/\n",
        "LICENSE": "MIT License\nNaxoziwuS\n",
        **{f"src/dragonscan/{name}.py": "# Inert module\n" for name in ("cli", "tui", "scanner")},
    }
    for name, content in files.items():
        (source / name).write_text(content, encoding="utf-8")
    dist = "dragons_ai_agent_scanner-0.1.0.dist-info"
    members = {
        name.removeprefix("src/"): value.encode()
        for name, value in files.items()
        if name.startswith("src/")
    }
    members.update(
        {
            f"{dist}/METADATA": metadata,
            f"{dist}/WHEEL": b"Root-Is-Purelib: true\nTag: py3-none-any\n",
            f"{dist}/entry_points.txt": b"[console_scripts]\ndragonscan = dragonscan.cli:main\n",
            f"{dist}/licenses/LICENSE": files["LICENSE"].encode(),
        }
    )
    record = (
        "".join(
            f"{name},sha256={base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')},{len(data)}\n"
            for name, data in members.items()
        )
        + f"{dist}/RECORD,,\n"
    )
    members[f"{dist}/RECORD"] = record.encode()
    with zipfile.ZipFile(output / "sample.whl", "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    with tarfile.open(output / "sample.tar.gz", "w:gz") as archive:
        for name, data in {
            **{k: v.encode() for k, v in files.items()},
            "PKG-INFO": metadata,
        }.items():
            info = tarfile.TarInfo(f"dragons_ai_agent_scanner-0.1.0/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return source, output


def test_exact_package_pair_passes(packages: tuple[Path, Path]) -> None:
    source, output = packages
    report = inspect_packages(source, output, "a" * 40)
    assert report["bundled_runtime"] is False
    assert len(report["artifacts"]) == 2


@pytest.mark.parametrize("name", ["benchmarks/private.json", "python312.dll", "../escape", ".env"])
def test_extra_wheel_content_is_rejected(packages: tuple[Path, Path], name: str) -> None:
    source, output = packages
    with zipfile.ZipFile(output / "sample.whl", "a") as archive:
        archive.writestr(name, b"inert")
    with pytest.raises(AssertionError):
        inspect_packages(source, output, "a" * 40)


def test_missing_source_module_is_rejected(packages: tuple[Path, Path]) -> None:
    source, output = packages
    (source / "src/dragonscan/extra.py").write_text("# inert\n")
    with pytest.raises(AssertionError):
        inspect_packages(source, output, "a" * 40)


def test_modified_source_is_rejected(packages: tuple[Path, Path]) -> None:
    source, output = packages
    (source / "src/dragonscan/tui.py").write_text("# changed\n")
    with pytest.raises(AssertionError):
        inspect_packages(source, output, "a" * 40)
