"""Inert Windows build policy regressions; no executable or fixture is launched."""

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
build = importlib.import_module("scripts.build_standalone")
dlls = importlib.import_module("scripts.windows_system_dlls")


def test_exact_system_dll_inventory_and_required_runtime_retention():
    names = dlls.WINDOWS_SYSTEM_DLLS
    assert len(names) == 43
    assert "ucrtbase.dll" in names
    assert sum(n.startswith("api-ms-win-crt-") for n in names) == 13
    assert sum(n.startswith("api-ms-win-core-") for n in names) == 29
    for name in ("VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "python312.dll", "libffi-8.dll"):
        assert name.lower() not in names
    assert "api-ms-win-core-unreviewed-l1-1-0.dll" not in names


@pytest.mark.parametrize("platform", ["win32", "darwin", "linux"])
def test_spec_filters_only_reviewed_windows_system_files(platform, monkeypatch):
    monkeypatch.setattr(build.sys, "platform", platform)
    monkeypatch.setattr(build.platform, "machine", lambda: "AMD64")
    removed = [(name.upper(), "unused", "BINARY") for name in dlls.WINDOWS_SYSTEM_DLLS]
    retained = [
        ("VCRUNTIME140.dll", "unused", "BINARY"),
        ("VCRUNTIME140_1.dll", "unused", "BINARY"),
        ("python312.dll", "unused", "BINARY"),
        ("libffi-8.dll", "unused", "BINARY"),
        ("api-ms-win-core-unreviewed-l1-1-0.dll", "unused", "BINARY"),
        ("vendor/ucrtbase.dll", "unused", "BINARY"),
    ]
    analysis = SimpleNamespace(binaries=removed + retained, pure=[], scripts=[], datas=[])
    calls = []
    root = Path(__file__).resolve().parents[1]
    spec = root / "scripts/standalone_windows.spec"
    namespace = {
        "SPECPATH": str(root / "scripts"),
        "Analysis": lambda *a, **kw: analysis,
        "PYZ": lambda *a: None,
        "EXE": lambda *a, **kw: calls.append((a, kw)),
    }
    if platform != "win32":
        with pytest.raises(ValueError, match="Windows-only"):
            exec(compile(spec.read_text(), str(spec), "exec"), namespace)
        assert not calls
        assert analysis.binaries == removed + retained
    else:
        exec(compile(spec.read_text(), str(spec), "exec"), namespace)
        assert analysis.binaries == retained
        assert calls[0][0][2] == retained
        assert calls[0][1]["console"] is True
