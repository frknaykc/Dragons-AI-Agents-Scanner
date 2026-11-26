# Windows 10/11 x64 and Server 2016+: use the OS UCRT, not SDK app-local shims.
import platform
import sys
import tomllib
from pathlib import Path

if sys.platform != "win32":
    raise ValueError("Windows-only standalone spec")

root = Path(SPECPATH).parent
sys.path.insert(0, str(root))
from scripts.build_standalone import artifact_name
from scripts.windows_system_dlls import WINDOWS_SYSTEM_DLLS

version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
name = artifact_name(sys.platform, platform.machine(), version).removesuffix(".exe")
a = Analysis(
    [str(root / "scripts" / "standalone.py")],
    pathex=[str(root / "src")],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
# Deliberately exact root-level names. Retain VCRUNTIME and unknown/nested DLLs.
a.binaries = [entry for entry in a.binaries if entry[0].lower() not in WINDOWS_SYSTEM_DLLS]
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
