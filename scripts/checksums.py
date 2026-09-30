"""Generate sorted SHA256SUMS for the exact native binaries in a release staging directory."""

import hashlib
import os
import sys
import tomllib
from pathlib import Path

from scripts.build_standalone import ARCHITECTURES, ROOT


def checksums(directory: Path, version: str, *, require_all: bool = False) -> str:
    allowed = {
        f"dragonscan-{version}-{name}{'.exe' if name.startswith('windows-') else ''}"
        for name in ARCHITECTURES.values()
    }
    artifacts = sorted(path for path in directory.iterdir() if path.name != "SHA256SUMS")
    if not artifacts:
        raise ValueError("no release binaries found")
    if require_all and {path.name for path in artifacts} != allowed:
        missing = sorted(allowed - {path.name for path in artifacts})
        if missing:
            raise ValueError(f"missing release binaries: {', '.join(missing)}")
    lines = []
    for path in artifacts:
        if path.name not in allowed or path.is_symlink() or not path.is_file():
            raise ValueError(f"unexpected release artifact: {path.name}")
        digest = hashlib.sha256()
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
        lines.append(f"{digest.hexdigest()}  {path.name}\n")
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
    print(f"Checksummed {len(content.splitlines())} binaries")


if __name__ == "__main__":
    main()
