"""Generate sorted SHA256SUMS for native binaries and their verified notice files."""

import hashlib
import os
import sys
import tomllib
from pathlib import Path

from scripts.build_standalone import ARCHITECTURES, ROOT
from scripts.standalone_licenses import notice_directory, verify_notices


def checksums(directory: Path, version: str, *, require_all: bool = False) -> str:
    allowed = {
        f"dragonscan-{version}-{name}{'.exe' if name.startswith('windows-') else ''}"
        for name in ARCHITECTURES.values()
    }
    artifacts = sorted(path for path in directory.iterdir() if path.name != "SHA256SUMS")
    binaries = [path for path in artifacts if path.name in allowed]
    if not binaries:
        raise ValueError("no release binaries found")
    if require_all and {path.name for path in binaries} != allowed:
        missing = sorted(allowed - {path.name for path in binaries})
        if missing:
            raise ValueError(f"missing release binaries: {', '.join(missing)}")
    expected = {path.name for path in binaries} | {notice_directory(path).name for path in binaries}
    for path in artifacts:
        if path.name not in expected or path.is_symlink():
            raise ValueError(f"unexpected release artifact: {path.name}")
    files = []
    for binary in binaries:
        if not binary.is_file():
            raise ValueError(f"unexpected release artifact: {binary.name}")
        manifest = verify_notices(binary)
        notices = notice_directory(binary)
        files.extend([binary, notices / "manifest.json"])
        files.extend(notices / name for name in manifest["files"])
    lines = []
    for path in sorted(files):
        digest = hashlib.sha256()
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
        lines.append(f"{digest.hexdigest()}  {path.relative_to(directory).as_posix()}\n")
    return "".join(lines)


def main() -> None:
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--require-all"):
        raise SystemExit("usage: python -m scripts.checksums DIRECTORY [--require-all]")
    directory = Path(sys.argv[1]).resolve()
    with (ROOT / "pyproject.toml").open("rb") as file:
        version = tomllib.load(file)["project"]["version"]
    content = checksums(directory, version, require_all=len(sys.argv) == 3)
    temporary = directory / "SHA256SUMS.tmp"
    try:
        with temporary.open("w", encoding="ascii", newline="\n") as file:
            file.write(content)
        os.replace(temporary, directory / "SHA256SUMS")
    finally:
        temporary.unlink(missing_ok=True)
    print(f"Checksummed {len(content.splitlines())} binary/notice files")


if __name__ == "__main__":
    main()
