"""Stage exactly one native executable after its local smoke test."""

import platform
import shutil
import sys
import tomllib

from scripts.build_standalone import ROOT, artifact_name


def main() -> None:
    with (ROOT / "pyproject.toml").open("rb") as file:
        version = tomllib.load(file)["project"]["version"]
    name = artifact_name(sys.platform, platform.machine(), version)
    source = ROOT / "dist" / name
    destination = ROOT / "release-staging"
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"missing native executable: {name}")
    destination.mkdir(exist_ok=False)
    shutil.copy2(source, destination / name)
    print(f"Staged {name}")


if __name__ == "__main__":
    main()
